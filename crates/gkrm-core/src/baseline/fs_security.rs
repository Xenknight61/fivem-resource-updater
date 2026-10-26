use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{ambient_authority, DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir as CapDir, File as CapFile, Metadata as CapMetadata, OpenOptions};

use crate::baseline::key::SafeResourceKey;
use crate::file_identity::{
    capture_stable_dir_identity, capture_stable_file_identity, is_windows_reparse_point_cap,
    is_windows_reparse_point_std, StableFileIdentity,
};
use crate::validation::strip_leading_current_dir;
use crate::{GkrmError, Result};

#[cfg(unix)]
use crate::file_identity::file_link_count;

#[cfg(windows)]
use crate::file_identity::file_link_count_from_handle;

pub(crate) struct OpenStoreRoot {
    /// Caller-supplied path retained only for reopening the same store; never used for publish.
    pub path: PathBuf,
    pub dir: CapDir,
}

pub(crate) struct OpenBaselineCatalogResource {
    #[allow(dead_code)]
    pub store: OpenStoreRoot,
    pub key_dir: CapDir,
    pub key_identity: StableFileIdentity,
}

/// Open an existing store root without creating directories.
pub(crate) fn open_existing_store_root(store_root: &Path) -> Result<OpenStoreRoot> {
    open_existing_directory(store_root, "store-root")
}

/// Open `<store-root>/baselines/<safe-resource-key>` for read-only cataloging.
///
/// Missing store, `baselines`, or resource-key directories are represented as
/// `Ok(None)` so catalog callers can return an empty read-only snapshot without
/// creating anything.
pub(crate) fn open_baseline_catalog_resource(
    store_root: &Path,
    resource_key: &SafeResourceKey,
) -> Result<Option<OpenBaselineCatalogResource>> {
    let store = match open_existing_store_root(store_root) {
        Ok(store) => store,
        Err(error) if is_missing_store_component(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let baselines = match try_open_child_dir(&store.dir, "baselines") {
        Ok(Some(dir)) => dir,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error),
    };
    let key_dir = match try_open_child_dir(&baselines, resource_key.as_str()) {
        Ok(Some(dir)) => dir,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error),
    };
    let key_identity = dir_identity(&key_dir, "baseline-resource-key")?;
    Ok(Some(OpenBaselineCatalogResource {
        store,
        key_dir,
        key_identity,
    }))
}

/// Open or create a store root for write using component-by-component no-follow creation.
pub(crate) fn open_or_create_store_root_for_write(store_root: &Path) -> Result<OpenStoreRoot> {
    create_store_root_components(store_root)?;
    open_existing_directory(store_root, "store-root")
}

pub(crate) fn open_existing_directory(path: &Path, label: &str) -> Result<OpenStoreRoot> {
    reject_std_symlink_or_reparse(path, label)?;
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    if !metadata.file_type().is_dir() {
        return Err(GkrmError::BaselineStoreUnexpectedType {
            component: label.to_owned(),
        });
    }

    let dir = open_path_nofollow(path, label)?;
    let dir_metadata = dir
        .dir_metadata()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    reject_cap_symlink_or_reparse(&dir_metadata, label)?;
    if !dir_metadata.file_type().is_dir() {
        return Err(GkrmError::BaselineStoreUnexpectedType {
            component: label.to_owned(),
        });
    }

    Ok(OpenStoreRoot {
        path: path.to_path_buf(),
        dir,
    })
}

pub(crate) fn dir_identity(dir: &CapDir, label: &'static str) -> Result<StableFileIdentity> {
    capture_stable_dir_identity(dir).map_err(|source| GkrmError::BaselineStoreIo {
        component: label.to_owned(),
        cause: source,
    })
}

pub(crate) fn ensure_child_dir(parent: &CapDir, name: &str) -> Result<CapDir> {
    validate_single_component(name)?;
    match parent.create_dir(name) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(GkrmError::BaselineStoreIo {
                component: name.to_owned(),
                cause: source,
            });
        }
    }
    open_child_dir(parent, name)
}

pub(crate) fn open_child_dir(parent: &CapDir, name: &str) -> Result<CapDir> {
    validate_single_component(name)?;
    let child = parent
        .open_dir_nofollow(name)
        .map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => GkrmError::BaselineStoreMissing {
                component: name.to_owned(),
            },
            _ => GkrmError::BaselineStoreIo {
                component: name.to_owned(),
                cause: source,
            },
        })?;
    let metadata = child
        .dir_metadata()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: name.to_owned(),
            cause: source,
        })?;
    reject_cap_symlink_or_reparse(&metadata, name)?;
    if !metadata.file_type().is_dir() {
        return Err(GkrmError::BaselineStoreUnexpectedType {
            component: name.to_owned(),
        });
    }
    Ok(child)
}

pub(crate) fn try_open_child_dir(parent: &CapDir, name: &str) -> Result<Option<CapDir>> {
    match open_child_dir(parent, name) {
        Ok(dir) => Ok(Some(dir)),
        Err(GkrmError::BaselineStoreMissing { .. }) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn create_new_child_dir(parent: &CapDir, name: &str) -> Result<CapDir> {
    validate_single_component(name)?;
    parent
        .create_dir(name)
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: name.to_owned(),
            cause: source,
        })?;
    open_child_dir(parent, name)
}

pub(crate) fn open_file_nofollow(parent: &CapDir, name: &str) -> Result<CapFile> {
    validate_single_component(name)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let file = parent
        .open_with(name, &options)
        .map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound => GkrmError::BaselineStoreMissing {
                component: name.to_owned(),
            },
            _ => GkrmError::BaselineStoreIo {
                component: name.to_owned(),
                cause: source,
            },
        })?;
    verify_regular_file(&file, name)?;
    Ok(file)
}

pub(crate) fn create_new_file(parent: &CapDir, name: &str) -> Result<CapFile> {
    validate_single_component(name)?;
    let mut options = OpenOptions::new();
    options.write(true);
    options.create_new(true);
    options.follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_fs_ext::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = parent
        .open_with(name, &options)
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: name.to_owned(),
            cause: source,
        })?;
    verify_regular_file(&file, name)?;
    Ok(file)
}

pub(crate) fn verify_regular_file(file: &CapFile, name: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: name.to_owned(),
            cause: source,
        })?;
    reject_cap_symlink_or_reparse(&metadata, name)?;
    if !metadata.file_type().is_file() {
        return Err(GkrmError::BaselineStoreUnexpectedType {
            component: name.to_owned(),
        });
    }
    reject_hard_link(file, &metadata, name)?;
    Ok(())
}

pub(crate) fn reject_hard_link(file: &CapFile, metadata: &CapMetadata, name: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let links = file_link_count(metadata).map_err(|source| GkrmError::BaselineStoreIo {
            component: name.to_owned(),
            cause: source,
        })?;
        if links > 1 {
            return Err(GkrmError::BaselineStoreHardLink {
                component: name.to_owned(),
            });
        }
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        let links =
            file_link_count_from_handle(file).map_err(|source| GkrmError::BaselineStoreIo {
                component: name.to_owned(),
                cause: source,
            })?;
        if links > 1 {
            return Err(GkrmError::BaselineStoreHardLink {
                component: name.to_owned(),
            });
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, metadata);
    }
    Ok(())
}

pub(crate) fn capture_file_identity(file: &CapFile, name: &str) -> Result<StableFileIdentity> {
    capture_stable_file_identity(file).map_err(|source| GkrmError::BaselineStoreIo {
        component: name.to_owned(),
        cause: source,
    })
}

pub(crate) fn validate_single_component(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.chars().any(|character| character.is_control())
    {
        return Err(GkrmError::BaselineStoreUnsafeComponent {
            component: name.to_owned(),
        });
    }
    crate::installed_path::validate_relative_component(name, name).map_err(|_| {
        GkrmError::BaselineStoreUnsafeComponent {
            component: name.to_owned(),
        }
    })
}

pub(crate) fn reject_link_like_metadata(metadata: &CapMetadata, label: &str) -> Result<()> {
    reject_cap_symlink_or_reparse(metadata, label)
}

fn is_missing_store_component(error: &GkrmError) -> bool {
    match error {
        GkrmError::BaselineStoreMissing { .. } => true,
        GkrmError::BaselineStoreIo { cause: source, .. } => {
            source.kind() == std::io::ErrorKind::NotFound
        }
        _ => false,
    }
}

/// Remove a private temporary baseline child relative to `.tmp` without ambient paths.
pub(crate) fn remove_temp_child_nofollow(tmp_root: &CapDir, temp_name: &str) -> Result<()> {
    validate_single_component(temp_name)?;
    let Some(temp_dir) = try_open_child_dir(tmp_root, temp_name)? else {
        return Ok(());
    };
    clear_temp_bundle_contents(&temp_dir)?;
    drop(temp_dir);
    tmp_root
        .remove_dir(temp_name)
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: ".tmp".to_owned(),
            cause: source,
        })?;
    Ok(())
}

/// Remove a private capture spool child (digest / temporary `.p-*` files) under `.tmp`.
pub(crate) fn remove_capture_spool_nofollow(tmp_root: &CapDir, spool_name: &str) -> Result<()> {
    validate_single_component(spool_name)?;
    let Some(spool_dir) = try_open_child_dir(tmp_root, spool_name)? else {
        return Ok(());
    };
    clear_capture_spool_contents(&spool_dir)?;
    drop(spool_dir);
    tmp_root
        .remove_dir(spool_name)
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: ".tmp".to_owned(),
            cause: source,
        })?;
    Ok(())
}

fn clear_capture_spool_contents(spool_dir: &CapDir) -> Result<()> {
    let entries = spool_dir
        .entries()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "spool".to_owned(),
            cause: source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| GkrmError::BaselineStoreIo {
            component: "spool".to_owned(),
            cause: source,
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            GkrmError::BaselineStoreUnsafeComponent {
                component: "spool-entry".to_owned(),
            }
        })?;
        validate_single_component(&name)?;
        let metadata = entry
            .metadata()
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: name.clone(),
                cause: source,
            })?;
        reject_cap_symlink_or_reparse(&metadata, &name)?;
        if metadata.file_type().is_dir() {
            return Err(GkrmError::BaselineStoreUnexpectedType { component: name });
        }
        if !metadata.file_type().is_file() {
            return Err(GkrmError::BaselineStoreUnexpectedType { component: name });
        }
        let file = open_file_nofollow(spool_dir, &name)?;
        drop(file);
        spool_dir
            .remove_file(&name)
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: name,
                cause: source,
            })?;
    }
    Ok(())
}

fn clear_temp_bundle_contents(temp_dir: &CapDir) -> Result<()> {
    let entries = temp_dir
        .entries()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: ".tmp".to_owned(),
            cause: source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| GkrmError::BaselineStoreIo {
            component: ".tmp".to_owned(),
            cause: source,
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            GkrmError::BaselineStoreUnsafeComponent {
                component: "temp-entry".to_owned(),
            }
        })?;
        validate_single_component(&name)?;
        let metadata = entry
            .metadata()
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: name.clone(),
                cause: source,
            })?;
        reject_cap_symlink_or_reparse(&metadata, &name)?;
        if metadata.file_type().is_dir() {
            if name != "blobs" {
                return Err(GkrmError::BaselineUnexpectedBlob { name });
            }
            let blobs = open_child_dir(temp_dir, &name)?;
            clear_blobs_dir(&blobs)?;
            drop(blobs);
            temp_dir
                .remove_dir(&name)
                .map_err(|source| GkrmError::BaselineStoreIo {
                    component: "blobs".to_owned(),
                    cause: source,
                })?;
        } else if metadata.file_type().is_file() {
            if name != "baseline.json" {
                return Err(GkrmError::BaselineUnexpectedBlob { name });
            }
            let file = open_file_nofollow(temp_dir, &name)?;
            drop(file);
            temp_dir
                .remove_file(&name)
                .map_err(|source| GkrmError::BaselineStoreIo {
                    component: "baseline.json".to_owned(),
                    cause: source,
                })?;
        } else {
            return Err(GkrmError::BaselineStoreUnexpectedType { component: name });
        }
    }
    Ok(())
}

fn clear_blobs_dir(blobs: &CapDir) -> Result<()> {
    let entries = blobs
        .entries()
        .map_err(|source| GkrmError::BaselineStoreIo {
            component: "blobs".to_owned(),
            cause: source,
        })?;
    for entry in entries {
        let entry = entry.map_err(|source| GkrmError::BaselineStoreIo {
            component: "blobs".to_owned(),
            cause: source,
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            GkrmError::BaselineStoreUnsafeComponent {
                component: "blob-entry".to_owned(),
            }
        })?;
        validate_single_component(&name)?;
        let metadata = entry
            .metadata()
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: name.clone(),
                cause: source,
            })?;
        reject_cap_symlink_or_reparse(&metadata, &name)?;
        if !metadata.file_type().is_file() {
            return Err(GkrmError::BaselineStoreUnexpectedType { component: name });
        }
        let file = open_file_nofollow(blobs, &name)?;
        drop(file);
        blobs
            .remove_file(&name)
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: "blobs".to_owned(),
                cause: source,
            })?;
    }
    Ok(())
}

pub fn ensure_baseline_store_disjoint_from_installed(
    store_root: &Path,
    installed_root: &Path,
) -> Result<()> {
    let store = open_existing_directory(store_root, "store-root")?;
    let installed = open_existing_directory(installed_root, "installed-root")?;

    let store_id = dir_identity(&store.dir, "store-root")?;
    let installed_id = dir_identity(&installed.dir, "installed-root")?;

    if store_id == installed_id {
        return Err(GkrmError::BaselineStoreInstallOverlap);
    }

    let store_chain = ancestor_chain(store_root)?;
    let installed_chain = ancestor_chain(installed_root)?;

    if store_chain.contains(&installed_id) || installed_chain.contains(&store_id) {
        return Err(GkrmError::BaselineStoreInstallOverlap);
    }

    Ok(())
}

fn ancestor_chain(path: &Path) -> Result<HashSet<StableFileIdentity>> {
    let mut identities = HashSet::new();
    let mut current = path.to_path_buf();
    loop {
        // Reject mount/junction/reparse ancestors rather than walking through them.
        reject_std_symlink_or_reparse(&current, "ancestor")?;
        let opened = open_existing_directory(&current, "ancestor")?;
        let identity = dir_identity(&opened.dir, "ancestor")?;
        identities.insert(identity);

        if !current.pop() {
            break;
        }
        if current.as_os_str().is_empty() {
            break;
        }
        let components = current.components().collect::<Vec<_>>();
        if components.is_empty()
            || matches!(
                components.as_slice(),
                [Component::RootDir]
                    | [Component::Prefix(_)]
                    | [Component::Prefix(_), Component::RootDir]
            )
        {
            if let Ok(opened) = open_existing_directory(&current, "ancestor-root") {
                if let Ok(identity) = dir_identity(&opened.dir, "ancestor-root") {
                    identities.insert(identity);
                }
            }
            break;
        }
    }
    Ok(identities)
}

fn create_store_root_components(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .map(|meta| meta.file_type().is_dir() && !meta.file_type().is_symlink())
        .unwrap_or(false)
    {
        reject_std_symlink_or_reparse(path, "store-root")?;
        return Ok(());
    }

    let (mut dir, remaining) = open_path_anchor(path, "store-root")?;
    for component in remaining {
        let Component::Normal(name) = component else {
            return Err(GkrmError::BaselineStoreUnsafeComponent {
                component: "store-root".to_owned(),
            });
        };
        let name = component_to_str(name)?;
        validate_single_component(name)?;
        match dir.open_dir_nofollow(name) {
            Ok(child) => {
                let metadata =
                    child
                        .dir_metadata()
                        .map_err(|source| GkrmError::BaselineStoreIo {
                            component: "store-root".to_owned(),
                            cause: source,
                        })?;
                reject_cap_symlink_or_reparse(&metadata, "store-root")?;
                if !metadata.file_type().is_dir() {
                    return Err(GkrmError::BaselineStoreUnexpectedType {
                        component: "store-root".to_owned(),
                    });
                }
                dir = child;
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                match dir.create_dir(name) {
                    Ok(()) => {}
                    Err(create_source)
                        if create_source.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_source) => {
                        return Err(GkrmError::BaselineStoreIo {
                            component: "store-root".to_owned(),
                            cause: create_source,
                        });
                    }
                }
                dir = open_child_dir(&dir, name)?;
            }
            Err(source) => {
                return Err(GkrmError::BaselineStoreIo {
                    component: "store-root".to_owned(),
                    cause: source,
                });
            }
        }
    }
    Ok(())
}

fn open_path_nofollow(path: &Path, label: &str) -> Result<CapDir> {
    let (mut dir, remaining) = open_path_anchor(path, label)?;
    for component in remaining {
        let Component::Normal(name) = component else {
            return Err(GkrmError::BaselineStoreUnsafeComponent {
                component: label.to_owned(),
            });
        };
        let name = component_to_str(name)?;
        dir = dir
            .open_dir_nofollow(name)
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: label.to_owned(),
                cause: source,
            })?;
        let metadata = dir
            .dir_metadata()
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: label.to_owned(),
                cause: source,
            })?;
        reject_cap_symlink_or_reparse(&metadata, label)?;
        if !metadata.file_type().is_dir() {
            return Err(GkrmError::BaselineStoreUnexpectedType {
                component: label.to_owned(),
            });
        }
    }
    Ok(dir)
}

fn open_path_anchor<'a>(path: &'a Path, label: &str) -> Result<(CapDir, Vec<Component<'a>>)> {
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(GkrmError::BaselineStoreUnsafeComponent {
            component: label.to_owned(),
        });
    }

    if path.is_relative() {
        let anchor =
            CapDir::open_ambient_dir(Path::new("."), ambient_authority()).map_err(|source| {
                GkrmError::BaselineStoreIo {
                    component: label.to_owned(),
                    cause: source,
                }
            })?;
        return Ok((anchor, strip_leading_current_dir(components)));
    }

    open_absolute_path_anchor(path, components, label)
}

#[cfg(unix)]
fn open_absolute_path_anchor<'a>(
    path: &'a Path,
    components: Vec<Component<'a>>,
    label: &str,
) -> Result<(CapDir, Vec<Component<'a>>)> {
    let _ = path;
    if !matches!(components.first(), Some(Component::RootDir)) {
        return Err(GkrmError::BaselineStoreUnsafeComponent {
            component: label.to_owned(),
        });
    }
    let anchor =
        CapDir::open_ambient_dir(Path::new("/"), ambient_authority()).map_err(|source| {
            GkrmError::BaselineStoreIo {
                component: label.to_owned(),
                cause: source,
            }
        })?;
    Ok((anchor, components.into_iter().skip(1).collect()))
}

#[cfg(windows)]
fn open_absolute_path_anchor<'a>(
    path: &'a Path,
    components: Vec<Component<'a>>,
    label: &str,
) -> Result<(CapDir, Vec<Component<'a>>)> {
    let Some(Component::Prefix(prefix)) = components.first().copied() else {
        return Err(GkrmError::BaselineStoreUnsafeComponent {
            component: label.to_owned(),
        });
    };
    if !matches!(components.get(1), Some(Component::RootDir)) {
        return Err(GkrmError::BaselineStoreUnsafeComponent {
            component: label.to_owned(),
        });
    }

    let anchor = windows_anchor_from_prefix(prefix, label)?;
    let _ = path;
    let dir = CapDir::open_ambient_dir(&anchor, ambient_authority()).map_err(|source| {
        GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        }
    })?;
    Ok((dir, components.into_iter().skip(2).collect()))
}

#[cfg(windows)]
fn windows_anchor_from_prefix(
    prefix: std::path::PrefixComponent<'_>,
    label: &str,
) -> Result<PathBuf> {
    use std::path::Prefix;

    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            Ok(PathBuf::from(format!("{}:\\", letter as char)))
        }
        _ => Err(GkrmError::BaselineStoreUnsafeComponent {
            component: label.to_owned(),
        }),
    }
}

fn component_to_str(component: &OsStr) -> Result<&str> {
    component
        .to_str()
        .ok_or_else(|| GkrmError::BaselineStoreUnsafeComponent {
            component: "non-utf8".to_owned(),
        })
}

fn reject_std_symlink_or_reparse(path: &Path, label: &str) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|source| GkrmError::BaselineStoreIo {
            component: label.to_owned(),
            cause: source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(GkrmError::BaselineStoreSymlink {
            component: label.to_owned(),
        });
    }
    if is_windows_reparse_point_std(&metadata) {
        return Err(GkrmError::BaselineStoreReparsePoint {
            component: label.to_owned(),
        });
    }
    Ok(())
}

fn reject_cap_symlink_or_reparse(metadata: &CapMetadata, label: &str) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(GkrmError::BaselineStoreSymlink {
            component: label.to_owned(),
        });
    }
    if is_windows_reparse_point_cap(metadata) {
        return Err(GkrmError::BaselineStoreReparsePoint {
            component: label.to_owned(),
        });
    }
    Ok(())
}
