use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{ambient_authority, DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir as CapDir, File as CapFile, Metadata as CapMetadata, OpenOptions};
use cap_std::time::SystemTime;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zip::ZipArchive;

use crate::file_identity::{
    capture_stable_file_identity, is_windows_reparse_point_cap, StableFileIdentity,
};
use crate::validation::strip_leading_current_dir;
use crate::{GkrmError, Result, Sha256Digest};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
struct TargetedPathHook {
    target: PathBuf,
    hook: Box<dyn FnOnce(&Path) + Send>,
}

#[cfg(test)]
struct TargetedHook {
    target: PathBuf,
    hook: Box<dyn FnOnce() + Send>,
}

#[cfg(test)]
type BeforePackageOpenHook = Box<dyn FnOnce(&Path) + Send>;

#[cfg(test)]
thread_local! {
    static BEFORE_PACKAGE_OPEN_HOOK: RefCell<Option<BeforePackageOpenHook>> =
        const { RefCell::new(None) };
    static AFTER_SNAPSHOT_CREATED_HOOK: RefCell<Option<TargetedPathHook>> =
        const { RefCell::new(None) };
    static AFTER_TEMPFILE_CREATED_HOOK: RefCell<Option<TargetedPathHook>> =
        const { RefCell::new(None) };
    static AFTER_SNAPSHOT_COPY_CHUNK_HOOK: RefCell<Option<TargetedHook>> =
        const { RefCell::new(None) };
}

/// Immutable private copy of an incoming package.
///
/// This type is constructed only after no-follow source opening, source metadata
/// capture, bounded streaming copy, and source revalidation. The temporary file
/// is unnamed from the public API and is deleted automatically on drop.
#[derive(Debug)]
pub(crate) struct PackageSnapshot {
    source_path: PathBuf,
    file: NamedTempFile,
    /// Trusted SHA-256 of the full snapshotted ZIP bytes.
    fingerprint: Sha256Digest,
}

#[derive(Debug)]
struct SourceSnapshot {
    handle: CapFile,
    size: u64,
    modified: SystemTime,
    identity: StableFileIdentity,
}

impl PackageSnapshot {
    pub(crate) fn create(path: &Path, max_archive_size: u64) -> Result<Self> {
        let mut source = open_package_source(path)?;
        if source.size > max_archive_size {
            return Err(GkrmError::ComparisonArchiveSizeLimitExceeded {
                path: path.to_path_buf(),
                limit: max_archive_size,
                actual: source.size,
            });
        }

        let mut snapshot_file =
            NamedTempFile::new().map_err(|source| GkrmError::ComparisonPackageOpen {
                path: path.to_path_buf(),
                cause: source,
            })?;
        run_after_tempfile_created_hook(path, snapshot_file.path());
        let source_digest =
            copy_source_to_snapshot(path, &mut source, snapshot_file.as_file_mut())?;
        verify_source_handle_matches(path, &source)?;

        let reopened = open_and_hash_package(path)?;
        verify_source_snapshot_matches(
            path,
            source.size,
            source.modified,
            &source.identity,
            &reopened.0,
        )?;
        if source_digest != reopened.1 {
            return Err(GkrmError::ComparisonPackageChanged {
                path: path.to_path_buf(),
                reason: "full archive digest changed while creating private snapshot".to_owned(),
            });
        }

        snapshot_file.as_file_mut().flush().map_err(|source| {
            GkrmError::ComparisonPackageHashRead {
                path: path.to_path_buf(),
                cause: source,
            }
        })?;
        snapshot_file
            .as_file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|source| GkrmError::ComparisonPackageHashRead {
                path: path.to_path_buf(),
                cause: source,
            })?;

        let snapshot = Self {
            source_path: path.to_path_buf(),
            file: snapshot_file,
            fingerprint: source_digest,
        };
        run_after_snapshot_created_hook(path, snapshot.temp_path());

        Ok(snapshot)
    }

    pub(crate) fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Trusted SHA-256 of the immutable snapshotted archive bytes (never a temp path).
    pub(crate) fn fingerprint(&self) -> &Sha256Digest {
        &self.fingerprint
    }

    pub(crate) fn open_zip_archive(&self) -> Result<ZipArchive<std::fs::File>> {
        let file = self
            .file
            .reopen()
            .map_err(|source| GkrmError::ZipPackageOpen {
                path: self.source_path.clone(),
                cause: source,
            })?;

        ZipArchive::new(file).map_err(|source| GkrmError::ZipArchiveRead {
            path: self.source_path.clone(),
            cause: source,
        })
    }

    #[cfg(test)]
    pub(crate) fn temp_path(&self) -> &Path {
        self.file.path()
    }

    #[cfg(not(test))]
    fn temp_path(&self) -> &Path {
        self.file.path()
    }
}

fn open_and_hash_package(path: &Path) -> Result<(SourceSnapshot, Sha256Digest)> {
    let mut snapshot = open_package_source(path)?;
    let digest = hash_package_archive(path, &mut snapshot.handle, snapshot.size)?;
    Ok((snapshot, digest))
}

fn copy_source_to_snapshot(
    path: &Path,
    source: &mut SourceSnapshot,
    snapshot_file: &mut std::fs::File,
) -> Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    let mut bytes_copied = 0_u64;

    loop {
        let read = source.handle.read(&mut buffer).map_err(|source| {
            GkrmError::ComparisonPackageHashRead {
                path: path.to_path_buf(),
                cause: source,
            }
        })?;
        if read == 0 {
            break;
        }
        bytes_copied = bytes_copied.checked_add(read as u64).ok_or_else(|| {
            GkrmError::ComparisonPackageArchiveSizeMismatch {
                path: path.to_path_buf(),
                expected: source.size,
                actual: u64::MAX,
            }
        })?;
        if bytes_copied > source.size {
            return Err(GkrmError::ComparisonPackageArchiveSizeMismatch {
                path: path.to_path_buf(),
                expected: source.size,
                actual: bytes_copied,
            });
        }
        hasher.update(&buffer[..read]);
        snapshot_file.write_all(&buffer[..read]).map_err(|source| {
            GkrmError::ComparisonPackageHashRead {
                path: path.to_path_buf(),
                cause: source,
            }
        })?;
        run_after_snapshot_copy_chunk_hook(path);
        verify_source_handle_matches(path, source)?;
    }

    if bytes_copied != source.size {
        return Err(GkrmError::ComparisonPackageArchiveSizeMismatch {
            path: path.to_path_buf(),
            expected: source.size,
            actual: bytes_copied,
        });
    }

    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn open_package_source(path: &Path) -> Result<SourceSnapshot> {
    run_before_package_open_hook(path);
    let file_name = path
        .file_name()
        .ok_or_else(|| GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "package path has no final component",
            ),
        })?;
    let parent = open_package_parent_dir(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let handle = parent
        .open_with(single_component_path(file_name), &options)
        .map_err(|source| GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: source,
        })?;
    snapshot_source_handle(path, handle)
}

fn open_package_parent_dir(path: &Path) -> Result<CapDir> {
    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut dir, remaining_components) = open_path_anchor(parent_path)?;

    for component in remaining_components {
        let Component::Normal(name) = component else {
            return Err(GkrmError::ComparisonPackageOpen {
                path: path.to_path_buf(),
                cause: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "package parent path contains an unsupported component",
                ),
            });
        };
        dir = dir
            .open_dir_nofollow(single_component_path(name))
            .map_err(|source| GkrmError::ComparisonPackageOpen {
                path: path.to_path_buf(),
                cause: source,
            })?;
        let metadata =
            dir.dir_metadata()
                .map_err(|source| GkrmError::ComparisonPackageMetadata {
                    path: path.to_path_buf(),
                    cause: source,
                })?;
        if metadata.file_type().is_symlink() {
            return Err(GkrmError::ComparisonPackageSymlink {
                path: path.to_path_buf(),
            });
        }
        if is_windows_reparse_point_cap(&metadata) {
            return Err(GkrmError::ComparisonPackageReparsePoint {
                path: path.to_path_buf(),
            });
        }
        if !metadata.file_type().is_dir() {
            return Err(GkrmError::ComparisonPackageOpen {
                path: path.to_path_buf(),
                cause: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "package parent component is not a directory",
                ),
            });
        }
    }

    Ok(dir)
}

fn open_path_anchor<'a>(path: &'a Path) -> Result<(CapDir, Vec<Component<'a>>)> {
    let components = path.components().collect::<Vec<_>>();
    if path.is_relative() {
        let anchor =
            CapDir::open_ambient_dir(Path::new("."), ambient_authority()).map_err(|source| {
                GkrmError::ComparisonPackageOpen {
                    path: path.to_path_buf(),
                    cause: source,
                }
            })?;
        return Ok((anchor, strip_leading_current_dir(components)));
    }

    open_absolute_path_anchor(path, components)
}

#[cfg(unix)]
fn open_absolute_path_anchor<'a>(
    path: &'a Path,
    components: Vec<Component<'a>>,
) -> Result<(CapDir, Vec<Component<'a>>)> {
    if !matches!(components.first(), Some(Component::RootDir)) {
        return Err(GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "absolute package path has unsupported prefix",
            ),
        });
    }

    let anchor =
        CapDir::open_ambient_dir(Path::new("/"), ambient_authority()).map_err(|source| {
            GkrmError::ComparisonPackageOpen {
                path: path.to_path_buf(),
                cause: source,
            }
        })?;
    Ok((anchor, components.into_iter().skip(1).collect()))
}

#[cfg(windows)]
fn open_absolute_path_anchor<'a>(
    path: &'a Path,
    components: Vec<Component<'a>>,
) -> Result<(CapDir, Vec<Component<'a>>)> {
    let Some(Component::Prefix(prefix)) = components.first().copied() else {
        return Err(GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "absolute package path has unsupported prefix",
            ),
        });
    };
    if !matches!(components.get(1), Some(Component::RootDir)) {
        return Err(GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "absolute package path has unsupported prefix",
            ),
        });
    }

    let anchor = windows_anchor_from_prefix(path, prefix)?;
    let dir = CapDir::open_ambient_dir(&anchor, ambient_authority()).map_err(|source| {
        GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: source,
        }
    })?;
    Ok((dir, components.into_iter().skip(2).collect()))
}

#[cfg(windows)]
fn windows_anchor_from_prefix(
    path: &Path,
    prefix: std::path::PrefixComponent<'_>,
) -> Result<PathBuf> {
    use std::path::Prefix;

    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            Ok(PathBuf::from(format!("{}:\\", letter as char)))
        }
        _ => Err(GkrmError::ComparisonPackageOpen {
            path: path.to_path_buf(),
            cause: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "absolute package path has unsupported prefix",
            ),
        }),
    }
}

fn snapshot_source_handle(path: &Path, handle: CapFile) -> Result<SourceSnapshot> {
    let metadata = handle
        .metadata()
        .map_err(|source| GkrmError::ComparisonPackageMetadata {
            path: path.to_path_buf(),
            cause: source,
        })?;
    verify_package_file_type(path, &metadata)?;
    let modified =
        metadata
            .modified()
            .map_err(|source| GkrmError::ComparisonPackageTimestampUnavailable {
                path: path.to_path_buf(),
                cause: source,
            })?;
    let identity = capture_stable_file_identity(&handle).map_err(|source| {
        GkrmError::ComparisonPackageIdentityUnavailable {
            path: path.to_path_buf(),
            cause: source,
        }
    })?;

    Ok(SourceSnapshot {
        handle,
        size: metadata.len(),
        modified,
        identity,
    })
}

fn verify_package_file_type(path: &Path, metadata: &CapMetadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(GkrmError::ComparisonPackageSymlink {
            path: path.to_path_buf(),
        });
    }
    if is_windows_reparse_point_cap(metadata) {
        return Err(GkrmError::ComparisonPackageReparsePoint {
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(GkrmError::ComparisonPackageNotFile {
            path: path.to_path_buf(),
        });
    }

    Ok(())
}

fn hash_package_archive(
    path: &Path,
    handle: &mut CapFile,
    expected_size: u64,
) -> Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
    let mut bytes_read = 0_u64;

    loop {
        let read =
            handle
                .read(&mut buffer)
                .map_err(|source| GkrmError::ComparisonPackageHashRead {
                    path: path.to_path_buf(),
                    cause: source,
                })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.checked_add(read as u64).ok_or_else(|| {
            GkrmError::ComparisonPackageArchiveSizeMismatch {
                path: path.to_path_buf(),
                expected: expected_size,
                actual: u64::MAX,
            }
        })?;
        if bytes_read > expected_size {
            return Err(GkrmError::ComparisonPackageArchiveSizeMismatch {
                path: path.to_path_buf(),
                expected: expected_size,
                actual: bytes_read,
            });
        }
        hasher.update(&buffer[..read]);
    }

    if bytes_read != expected_size {
        return Err(GkrmError::ComparisonPackageArchiveSizeMismatch {
            path: path.to_path_buf(),
            expected: expected_size,
            actual: bytes_read,
        });
    }

    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn verify_source_handle_matches(path: &Path, expected: &SourceSnapshot) -> Result<()> {
    let handle =
        expected
            .handle
            .try_clone()
            .map_err(|source| GkrmError::ComparisonPackageOpen {
                path: path.to_path_buf(),
                cause: source,
            })?;
    let actual = snapshot_source_handle(path, handle)?;
    verify_source_snapshot_matches(
        path,
        expected.size,
        expected.modified,
        &expected.identity,
        &actual,
    )
}

fn verify_source_snapshot_matches(
    path: &Path,
    expected_size: u64,
    expected_modified: SystemTime,
    expected_identity: &StableFileIdentity,
    actual: &SourceSnapshot,
) -> Result<()> {
    if expected_size != actual.size {
        return Err(GkrmError::ComparisonPackageChanged {
            path: path.to_path_buf(),
            reason: "size changed".to_owned(),
        });
    }
    if expected_modified != actual.modified {
        return Err(GkrmError::ComparisonPackageChanged {
            path: path.to_path_buf(),
            reason: "modification time changed".to_owned(),
        });
    }
    if *expected_identity != actual.identity {
        return Err(GkrmError::ComparisonPackageChanged {
            path: path.to_path_buf(),
            reason: "stable file identity changed".to_owned(),
        });
    }

    Ok(())
}

fn single_component_path(component: &OsStr) -> &Path {
    Path::new(component)
}

#[cfg(test)]
pub(crate) struct PackageSourceHookGuard;

#[cfg(test)]
impl Drop for PackageSourceHookGuard {
    fn drop(&mut self) {
        clear_package_source_hooks();
    }
}

#[cfg(test)]
fn clear_package_source_hooks() {
    BEFORE_PACKAGE_OPEN_HOOK.with(|cell| *cell.borrow_mut() = None);
    AFTER_SNAPSHOT_CREATED_HOOK.with(|cell| *cell.borrow_mut() = None);
    AFTER_TEMPFILE_CREATED_HOOK.with(|cell| *cell.borrow_mut() = None);
    AFTER_SNAPSHOT_COPY_CHUNK_HOOK.with(|cell| *cell.borrow_mut() = None);
}

/// RAII scope for package-source test hooks; clears on Drop (panic-safe).
#[cfg(test)]
pub(crate) fn package_source_hook_guard() -> PackageSourceHookGuard {
    clear_package_source_hooks();
    PackageSourceHookGuard
}

#[cfg(test)]
pub(crate) fn set_before_package_open_hook(hook: impl FnOnce(&Path) + Send + 'static) {
    BEFORE_PACKAGE_OPEN_HOOK.with(|cell| *cell.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_before_package_open_hook(path: &Path) {
    let hook = BEFORE_PACKAGE_OPEN_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_before_package_open_hook(_path: &Path) {}

#[cfg(test)]
pub(crate) fn set_after_snapshot_created_hook(
    target: &Path,
    hook: impl FnOnce(&Path) + Send + 'static,
) {
    AFTER_SNAPSHOT_CREATED_HOOK.with(|cell| {
        *cell.borrow_mut() = Some(TargetedPathHook {
            target: target.to_path_buf(),
            hook: Box::new(hook),
        });
    });
}

#[cfg(test)]
fn run_after_snapshot_created_hook(source: &Path, snapshot_path: &Path) {
    let targeted = AFTER_SNAPSHOT_CREATED_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(targeted) = targeted {
        if targeted.target == source {
            (targeted.hook)(snapshot_path);
        } else {
            AFTER_SNAPSHOT_CREATED_HOOK.with(|cell| {
                *cell.borrow_mut() = Some(targeted);
            });
        }
    }
}

#[cfg(not(test))]
fn run_after_snapshot_created_hook(_source: &Path, _snapshot_path: &Path) {}

#[cfg(test)]
fn set_after_tempfile_created_hook(target: &Path, hook: impl FnOnce(&Path) + Send + 'static) {
    AFTER_TEMPFILE_CREATED_HOOK.with(|cell| {
        *cell.borrow_mut() = Some(TargetedPathHook {
            target: target.to_path_buf(),
            hook: Box::new(hook),
        });
    });
}

#[cfg(test)]
fn run_after_tempfile_created_hook(source: &Path, snapshot_path: &Path) {
    let targeted = AFTER_TEMPFILE_CREATED_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(targeted) = targeted {
        if targeted.target == source {
            (targeted.hook)(snapshot_path);
        } else {
            AFTER_TEMPFILE_CREATED_HOOK.with(|cell| {
                *cell.borrow_mut() = Some(targeted);
            });
        }
    }
}

#[cfg(not(test))]
fn run_after_tempfile_created_hook(_source: &Path, _snapshot_path: &Path) {}

#[cfg(test)]
pub(crate) fn set_after_snapshot_copy_chunk_hook(
    target: &Path,
    hook: impl FnOnce() + Send + 'static,
) {
    AFTER_SNAPSHOT_COPY_CHUNK_HOOK.with(|cell| {
        *cell.borrow_mut() = Some(TargetedHook {
            target: target.to_path_buf(),
            hook: Box::new(hook),
        });
    });
}

#[cfg(test)]
fn run_after_snapshot_copy_chunk_hook(source: &Path) {
    let targeted = AFTER_SNAPSHOT_COPY_CHUNK_HOOK.with(|cell| cell.borrow_mut().take());
    if let Some(targeted) = targeted {
        if targeted.target == source {
            (targeted.hook)();
        } else {
            AFTER_SNAPSHOT_COPY_CHUNK_HOOK.with(|cell| {
                *cell.borrow_mut() = Some(targeted);
            });
        }
    }
}

#[cfg(not(test))]
fn run_after_snapshot_copy_chunk_hook(_source: &Path) {}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use tempfile::tempdir;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::{
        discover_zip_resources, inspect_installation_update,
        manifest::parse_zip_resource_manifests_from_snapshot, zip_package::inspect_zip_snapshot,
        InspectionOptions, ManifestLimits, PackageLimits,
    };

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("zip should be created");
        let mut writer = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

        for (name, contents) in entries {
            writer
                .start_file(*name, options)
                .expect("file should start");
            writer
                .write_all(contents)
                .expect("file contents should be written");
        }

        writer.finish().expect("zip should finish");
    }

    fn package_limits() -> PackageLimits {
        PackageLimits {
            max_entries: 20,
            max_entry_uncompressed_size: 4096,
            max_total_uncompressed_size: 32 * 1024,
            max_compression_ratio: 200,
        }
    }

    fn manifest_limits() -> ManifestLimits {
        ManifestLimits {
            max_manifest_size: 4096,
            max_tokens: 1024,
        }
    }

    #[test]
    fn symlinked_package_is_rejected_where_supported() {
        let temp = tempdir().expect("temp dir should be created");
        let target = temp.path().join("target.zip");
        let link = temp.path().join("link.zip");
        write_zip(
            &target,
            &[("resource/fxmanifest.lua", b"fx_version 'cerulean'")],
        );
        if !try_symlink_file(&target, &link) {
            return;
        }

        let err = PackageSnapshot::create(&link, 1024).expect_err("symlink should fail");

        assert!(matches!(
            err,
            GkrmError::ComparisonPackageOpen { .. } | GkrmError::ComparisonPackageSymlink { .. }
        ));
    }

    #[test]
    fn symlinked_parent_component_is_rejected_where_supported() {
        let temp = tempdir().expect("temp dir should be created");
        let real_parent = temp.path().join("real");
        let link_parent = temp.path().join("link");
        fs::create_dir(&real_parent).expect("real parent should be created");
        if !try_symlink_dir(&real_parent, &link_parent) {
            return;
        }
        let package = real_parent.join("package.zip");
        write_zip(
            &package,
            &[("resource/fxmanifest.lua", b"fx_version 'cerulean'")],
        );

        let err = PackageSnapshot::create(&link_parent.join("package.zip"), 1024)
            .expect_err("parent symlink should fail");

        assert!(matches!(
            err,
            GkrmError::ComparisonPackageOpen { .. } | GkrmError::ComparisonPackageSymlink { .. }
        ));
    }

    #[test]
    fn snapshot_inspection_and_manifest_parsing_ignore_later_live_replacement() {
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[(
                "resource/fxmanifest.lua",
                b"fx_version 'cerulean'\nclient_script 'old.lua'",
            )],
        );
        let snapshot = PackageSnapshot::create(&package, 4096).expect("snapshot should be created");

        write_zip(
            &package,
            &[(
                "resource/fxmanifest.lua",
                b"fx_version 'cerulean'\nclient_script 'new.lua'",
            )],
        );

        let inspection =
            inspect_zip_snapshot(&snapshot, package_limits()).expect("snapshot should inspect");
        let discovery = discover_zip_resources(&inspection).expect("resource should discover");
        let manifests = parse_zip_resource_manifests_from_snapshot(
            &snapshot,
            &inspection,
            &discovery,
            manifest_limits(),
        )
        .expect("snapshot manifest should parse");

        assert_eq!(
            manifests.resources[0].manifest.client_scripts[0].value,
            "old.lua"
        );
    }

    #[test]
    fn full_pipeline_uses_original_snapshot_after_live_replacement() {
        let _guard = package_source_hook_guard();
        let temp = tempdir().expect("temp dir should be created");
        let installed = temp.path().join("gksphone");
        fs::create_dir_all(&installed).expect("installed dir should be created");
        fs::write(installed.join("fxmanifest.lua"), b"fx_version 'cerulean'")
            .expect("installed manifest should be written");
        fs::write(installed.join("client.lua"), b"old").expect("installed file should be written");

        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("gksphone/fxmanifest.lua", b"fx_version 'cerulean'"),
                ("gksphone/client.lua", b"old"),
            ],
        );
        let snapshot_path = Arc::new(Mutex::new(None::<PathBuf>));
        set_after_snapshot_created_hook(&package, {
            let package = package.clone();
            let snapshot_path = Arc::clone(&snapshot_path);
            move |path| {
                *snapshot_path
                    .lock()
                    .expect("snapshot path mutex should not be poisoned") =
                    Some(path.to_path_buf());
                write_zip(
                    &package,
                    &[
                        ("gksphone/fxmanifest.lua", b"fx_version 'cerulean'"),
                        ("gksphone/client.lua", b"new"),
                    ],
                );
            }
        });

        let report =
            inspect_installation_update(&installed, &package, InspectionOptions::default())
                .expect("inspection should use original snapshot");

        assert_eq!(
            report.comparison().matched_resources[0].files[0].status,
            crate::FileComparisonStatus::Unchanged
        );
        let temp_path = snapshot_path
            .lock()
            .expect("snapshot path mutex should not be poisoned")
            .clone()
            .expect("snapshot path should be captured");
        assert!(!format!("{report:?}").contains(&temp_path.display().to_string()));
        assert!(!temp_path.exists());
    }

    #[test]
    fn temporary_snapshot_is_deleted_after_success() {
        let _guard = package_source_hook_guard();
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[("resource/fxmanifest.lua", b"fx_version 'cerulean'")],
        );
        let snapshot_path = Arc::new(Mutex::new(None::<PathBuf>));
        set_after_snapshot_created_hook(&package, {
            let snapshot_path = Arc::clone(&snapshot_path);
            move |path| {
                *snapshot_path
                    .lock()
                    .expect("snapshot path mutex should not be poisoned") =
                    Some(path.to_path_buf());
            }
        });

        let snapshot = PackageSnapshot::create(&package, 4096).expect("snapshot should be created");
        let path = snapshot_path
            .lock()
            .expect("snapshot path mutex should not be poisoned")
            .clone()
            .expect("snapshot path should be captured");
        assert!(path.exists());
        drop(snapshot);

        assert!(!path.exists());
    }

    #[test]
    fn temporary_snapshot_is_deleted_after_failure() {
        let _guard = package_source_hook_guard();
        let temp = tempdir().expect("temp dir should be created");
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[("resource/fxmanifest.lua", b"fx_version 'cerulean'")],
        );
        let snapshot_path = Arc::new(Mutex::new(None::<PathBuf>));
        set_after_tempfile_created_hook(&package, {
            let snapshot_path = Arc::clone(&snapshot_path);
            move |path| {
                *snapshot_path
                    .lock()
                    .expect("snapshot path mutex should not be poisoned") =
                    Some(path.to_path_buf());
            }
        });
        set_after_snapshot_copy_chunk_hook(&package, {
            let package = package.clone();
            move || {
                write_zip(&package, &[("resource/fxmanifest.lua", b"changed")]);
            }
        });

        let err = PackageSnapshot::create(&package, 4096).expect_err("mutation should fail");

        assert!(matches!(err, GkrmError::ComparisonPackageChanged { .. }));
        let path = snapshot_path
            .lock()
            .expect("snapshot path mutex should not be poisoned")
            .clone()
            .expect("snapshot path should be captured");
        assert!(!path.exists());
    }

    #[cfg(unix)]
    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    #[cfg(unix)]
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }
}
