use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use cap_fs_ext::{ambient_authority, DirEntryExt, DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir as CapDir, File as CapFile, Metadata as CapMetadata, OpenOptions};
use cap_std::time::SystemTime;
use sha2::{Digest, Sha256};

use crate::{
    file_identity::{
        capture_stable_file_identity, is_windows_reparse_point_cap, is_windows_reparse_point_std,
        StableFileIdentity,
    },
    installed_path::case_collision_key,
    validation::strip_leading_current_dir,
    GkrmError, InstallationRelativePath, ResourceRelativePath, Result, Sha256Digest,
};

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::thread::ThreadId;

#[cfg(test)]
pub(crate) static INSTALLED_SCAN_HASH_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
static HASH_HOOK_OWNER: Mutex<Option<ThreadId>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    /// Per-test hash-start counter; only incremented while counting is armed on this thread.
    static LOCAL_HASH_STARTS: Cell<usize> = const { Cell::new(0) };
    /// When true, `note_hash_started` records for this thread only.
    static LOCAL_HASH_COUNTING: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
static AFTER_ROOT_VALIDATION_HOOK: Mutex<Option<Box<dyn FnOnce() + Send>>> = Mutex::new(None);

#[cfg(test)]
type HashPassReadyHook = Box<dyn FnMut(HashVerificationPass, &str) + Send>;

#[cfg(test)]
type HashProgressHook = Box<dyn FnMut(HashVerificationPass, u64) + Send>;

#[cfg(test)]
type BetweenHashPassesHook = Box<dyn FnOnce(&str) + Send>;

#[cfg(test)]
static HASH_PASS_READY_HOOK: Mutex<Option<HashPassReadyHook>> = Mutex::new(None);

#[cfg(test)]
static HASH_PROGRESS_HOOK: Mutex<Option<HashProgressHook>> = Mutex::new(None);

#[cfg(test)]
static BETWEEN_HASH_PASSES_HOOK: Mutex<Option<BetweenHashPassesHook>> = Mutex::new(None);

#[cfg(test)]
static METADATA_CHECK_INTERVAL_OVERRIDE: Mutex<Option<u64>> = Mutex::new(None);

const DEFAULT_METADATA_CHECK_INTERVAL_BYTES: u64 = 8 * 1024 * 1024;

/// Configurable hard limits for read-only installed resource scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstalledScanLimits {
    pub max_resources: usize,
    pub max_files_per_resource: usize,
    pub max_total_files: usize,
    pub max_total_entries: usize,
    pub max_directories: usize,
    pub max_file_size: u64,
    pub max_total_size: u64,
    pub max_directory_depth: usize,
}

/// Complete inventory of resources discovered below the selected installation root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledInstallationScan {
    pub root: PathBuf,
    pub resources: Vec<InstalledResourceScan>,
    pub warnings: Vec<InstalledScanWarning>,
}

/// Inventory for one discovered installed FiveM resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledResourceScan {
    pub name: String,
    pub root: InstalledResourceRoot,
    pub manifest_relative_path: InstallationRelativePath,
    pub files: Vec<InstalledFileInfo>,
}

/// The selected root resource is represented explicitly instead of as an empty path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstalledResourceRoot {
    Root,
    Path(InstallationRelativePath),
}

/// Hash and size metadata for one regular file inside an installed resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledFileInfo {
    pub relative_path: ResourceRelativePath,
    pub size: u64,
    pub sha256: Sha256Digest,
}

/// Stable identity captured from metadata on an opened no-follow file handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledFileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },

    #[cfg(windows)]
    Windows { volume_serial: u64, file_index: u64 },
}

/// Informational scan warnings. Task 6 treats incomplete inventories as hard errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstalledScanWarning {
    Informational { message: String },
}

struct DirectoryToVisit {
    dir: CapDir,
    relative_path: Option<InstallationRelativePath>,
    components: Vec<OsString>,
    depth: usize,
}

struct ChildDirectory {
    dir: CapDir,
    relative_path: InstallationRelativePath,
    components: Vec<OsString>,
    depth: usize,
}

struct DirectoryEntryCandidate {
    relative_path: InstallationRelativePath,
    file_name: OsString,
    metadata: CapMetadata,
}

struct FileCandidate {
    parent_dir: CapDir,
    file_name: OsString,
    relative_path: InstallationRelativePath,
}

struct ResourceBuilder {
    name: String,
    root: InstalledResourceRoot,
    manifest_relative_path: InstallationRelativePath,
    files: Vec<FileCandidate>,
}

struct PreflightedResource {
    name: String,
    root: InstalledResourceRoot,
    manifest_relative_path: InstallationRelativePath,
    files: Vec<PreflightedFile>,
}

struct PreflightedFile {
    parent_dir: CapDir,
    file_name: OsString,
    installation_relative_path: InstallationRelativePath,
    resource_relative_path: ResourceRelativePath,
    size: u64,
    modified: SystemTime,
    identity: InstalledFileIdentity,
}

struct OpenedFileSnapshot {
    handle: CapFile,
    size: u64,
    modified: SystemTime,
    identity: InstalledFileIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashVerificationPass {
    First,
    Second,
}

impl Default for InstalledScanLimits {
    fn default() -> Self {
        Self {
            max_resources: 128,
            max_files_per_resource: 20_000,
            max_total_files: 100_000,
            max_total_entries: 120_000,
            max_directories: 20_000,
            max_file_size: 512 * 1024 * 1024,
            max_total_size: 4 * 1024 * 1024 * 1024,
            max_directory_depth: 32,
        }
    }
}

/// Scan installed FiveM resources below `root` without modifying the installation.
///
/// Traversal is handle-based after opening the selected root: child directories
/// are opened from their already-open parent with no-follow behavior, and files
/// are opened from their parent directory without following the final path
/// component. Each file is hashed twice with fixed-size streaming reads. Both
/// passes verify file identity, size, and modification time before and after
/// hashing, and the first pass also checks opened-handle metadata periodically
/// while streaming. Matching two-pass hashes plus identity and metadata checks
/// provide strong practical detection for concurrently changing files.
///
/// No normal userspace scanner can provide an absolute snapshot guarantee on
/// every live writable filesystem without filesystem snapshots or exclusive
/// write prevention. Callers should scan while the FiveM resource is not being
/// modified or updated.
pub fn scan_installed_resources(
    root: &Path,
    limits: InstalledScanLimits,
) -> Result<InstalledInstallationScan> {
    limits.validate()?;
    validate_scan_root(root)?;
    run_after_root_validation_hook();

    let root_dir = open_selected_root_dir(root)?;

    let inventory = collect_installation_entries(root_dir, limits)?;
    let mut resources = build_resource_builders(root, &inventory.resource_roots)?;

    if resources.is_empty() {
        return Err(GkrmError::InstalledNoResourcesFound);
    }

    assign_files_to_resources(&mut resources, &inventory.files)?;
    let preflighted = preflight_assigned_resources(resources, limits)?;
    hash_preflighted_resources(root, preflighted)
}

pub(crate) fn scan_installed_resource_from_capability(
    selected_resource_dir: &CapDir,
    resource_name: &str,
    selected_resource_root: InstalledResourceRoot,
    limits: InstalledScanLimits,
) -> Result<InstalledResourceScan> {
    limits.validate()?;
    let root_dir =
        selected_resource_dir
            .try_clone()
            .map_err(|source| GkrmError::InstalledDirectoryRead {
                path: ".".to_owned(),
                cause: source,
            })?;
    let inventory = collect_installation_entries(root_dir, limits)?;
    if !inventory
        .resource_roots
        .contains_key(&InstalledResourceRoot::Root)
    {
        return Err(GkrmError::InstalledNoResourcesFound);
    }

    let mut resources = inventory
        .resource_roots
        .iter()
        .map(|(root, manifest_relative_path)| ResourceBuilder {
            name: match root {
                InstalledResourceRoot::Root => resource_name.to_owned(),
                InstalledResourceRoot::Path(path) => path.file_name().to_owned(),
            },
            root: root.clone(),
            manifest_relative_path: manifest_relative_path.clone(),
            files: Vec::new(),
        })
        .collect::<Vec<_>>();
    resources.sort_by(|left, right| left.root.cmp(&right.root));

    assign_files_to_resources(&mut resources, &inventory.files)?;
    let preflighted = preflight_assigned_resources(resources, limits)?;
    let scan = hash_preflighted_resources(Path::new(resource_name), preflighted)?;
    let mut selected = scan
        .resources
        .into_iter()
        .find(|resource| resource.root == InstalledResourceRoot::Root)
        .ok_or(GkrmError::InstalledNoResourcesFound)?;
    selected.name = resource_name.to_owned();
    selected.root = selected_resource_root;
    Ok(selected)
}

#[cfg(test)]
fn hash_hooks_owned_by_current_thread() -> bool {
    HASH_HOOK_OWNER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .is_some_and(|owner| owner == std::thread::current().id())
}

#[cfg(test)]
fn note_hash_started() {
    // Record only for the RAII-armed owning test thread — never a process-global counter.
    LOCAL_HASH_COUNTING.with(|armed| {
        if armed.get() {
            LOCAL_HASH_STARTS.with(|starts| starts.set(starts.get().saturating_add(1)));
        }
    });
}

#[cfg(not(test))]
fn note_hash_started() {}

#[cfg(test)]
fn reset_hash_started_count() {
    LOCAL_HASH_STARTS.with(|starts| starts.set(0));
}

#[cfg(test)]
fn hash_started_count() -> usize {
    LOCAL_HASH_STARTS.with(|starts| starts.get())
}

#[cfg(test)]
fn set_after_root_validation_hook(hook: impl FnOnce() + Send + 'static) {
    *AFTER_ROOT_VALIDATION_HOOK
        .lock()
        .expect("root validation hook mutex should not be poisoned") = Some(Box::new(hook));
}

#[cfg(test)]
fn run_after_root_validation_hook() {
    if !hash_hooks_owned_by_current_thread() {
        return;
    }
    if let Some(hook) = AFTER_ROOT_VALIDATION_HOOK
        .lock()
        .expect("root validation hook mutex should not be poisoned")
        .take()
    {
        hook();
    }
}

#[cfg(not(test))]
fn run_after_root_validation_hook() {}

#[cfg(test)]
fn set_hash_pass_ready_hook(hook: impl FnMut(HashVerificationPass, &str) + Send + 'static) {
    *HASH_PASS_READY_HOOK
        .lock()
        .expect("hash pass ready hook mutex should not be poisoned") = Some(Box::new(hook));
}

#[cfg(test)]
fn run_hash_pass_ready_hook(pass: HashVerificationPass, path: &str) {
    if !hash_hooks_owned_by_current_thread() {
        return;
    }
    if let Some(hook) = HASH_PASS_READY_HOOK
        .lock()
        .expect("hash pass ready hook mutex should not be poisoned")
        .as_mut()
    {
        hook(pass, path);
    }
}

#[cfg(not(test))]
fn run_hash_pass_ready_hook(_pass: HashVerificationPass, _path: &str) {}

#[cfg(test)]
fn set_hash_progress_hook(hook: impl FnMut(HashVerificationPass, u64) + Send + 'static) {
    *HASH_PROGRESS_HOOK
        .lock()
        .expect("hash progress hook mutex should not be poisoned") = Some(Box::new(hook));
}

#[cfg(test)]
fn run_hash_progress_hook(pass: HashVerificationPass, bytes_read: u64) {
    if !hash_hooks_owned_by_current_thread() {
        return;
    }
    if let Some(hook) = HASH_PROGRESS_HOOK
        .lock()
        .expect("hash progress hook mutex should not be poisoned")
        .as_mut()
    {
        hook(pass, bytes_read);
    }
}

#[cfg(not(test))]
fn run_hash_progress_hook(_pass: HashVerificationPass, _bytes_read: u64) {}

#[cfg(test)]
fn set_between_hash_passes_hook(hook: impl FnOnce(&str) + Send + 'static) {
    *BETWEEN_HASH_PASSES_HOOK
        .lock()
        .expect("between hash passes hook mutex should not be poisoned") = Some(Box::new(hook));
}

#[cfg(test)]
fn run_between_hash_passes_hook(path: &str) {
    if !hash_hooks_owned_by_current_thread() {
        return;
    }
    if let Some(hook) = BETWEEN_HASH_PASSES_HOOK
        .lock()
        .expect("between hash passes hook mutex should not be poisoned")
        .take()
    {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_between_hash_passes_hook(_path: &str) {}

#[cfg(test)]
fn set_metadata_check_interval_override(interval: u64) {
    *METADATA_CHECK_INTERVAL_OVERRIDE
        .lock()
        .expect("metadata check interval mutex should not be poisoned") = Some(interval);
}

#[cfg(test)]
fn clear_hash_test_hooks() {
    *AFTER_ROOT_VALIDATION_HOOK
        .lock()
        .expect("root validation hook mutex should not be poisoned") = None;
    *HASH_PASS_READY_HOOK
        .lock()
        .expect("hash pass ready hook mutex should not be poisoned") = None;
    *HASH_PROGRESS_HOOK
        .lock()
        .expect("hash progress hook mutex should not be poisoned") = None;
    *BETWEEN_HASH_PASSES_HOOK
        .lock()
        .expect("between hash passes hook mutex should not be poisoned") = None;
    *METADATA_CHECK_INTERVAL_OVERRIDE
        .lock()
        .expect("metadata check interval mutex should not be poisoned") = None;
}

fn metadata_check_interval_bytes() -> u64 {
    #[cfg(test)]
    if let Some(interval) = *METADATA_CHECK_INTERVAL_OVERRIDE
        .lock()
        .expect("metadata check interval mutex should not be poisoned")
    {
        return interval.max(1);
    }

    DEFAULT_METADATA_CHECK_INTERVAL_BYTES
}

impl InstalledScanLimits {
    pub(crate) fn validate(self) -> Result<()> {
        for (limit, value) in [
            ("max_resources", self.max_resources),
            ("max_files_per_resource", self.max_files_per_resource),
            ("max_total_files", self.max_total_files),
            ("max_total_entries", self.max_total_entries),
            ("max_directories", self.max_directories),
            ("max_directory_depth", self.max_directory_depth),
        ] {
            if value == 0 {
                return Err(GkrmError::InstalledScanZeroLimit { limit });
            }
        }

        if self.max_file_size == 0 {
            return Err(GkrmError::InstalledScanZeroLimit {
                limit: "max_file_size",
            });
        }
        if self.max_total_size == 0 {
            return Err(GkrmError::InstalledScanZeroLimit {
                limit: "max_total_size",
            });
        }

        Ok(())
    }
}

fn validate_scan_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(|source| match source.kind() {
        ErrorKind::NotFound => GkrmError::InstalledPathMissing {
            path: root.to_path_buf(),
        },
        _ => GkrmError::InstalledPathMetadata {
            path: root.to_path_buf(),
            cause: source,
        },
    })?;

    if metadata.file_type().is_symlink() {
        return Err(GkrmError::InstalledRootSymlink {
            path: root.to_path_buf(),
        });
    }
    if is_windows_reparse_point_std(&metadata) {
        return Err(GkrmError::InstalledEntryReparsePoint {
            path: ".".to_owned(),
        });
    }
    if !metadata.file_type().is_dir() {
        return Err(GkrmError::InstalledPathNotDirectory {
            path: root.to_path_buf(),
        });
    }

    Ok(())
}

fn open_selected_root_dir(root: &Path) -> Result<CapDir> {
    let (mut root_dir, remaining_components) = open_root_anchor(root)?;

    for component in remaining_components {
        let Component::Normal(name) = component else {
            return Err(match component {
                Component::CurDir => GkrmError::InstalledPathCurrentDirectory {
                    path: root.display().to_string(),
                },
                Component::ParentDir => GkrmError::InstalledPathParentTraversal {
                    path: root.display().to_string(),
                },
                Component::Prefix(_) | Component::RootDir => {
                    GkrmError::InstalledRootUnsupportedPrefix {
                        path: root.to_path_buf(),
                    }
                }
                Component::Normal(_) => unreachable!(),
            });
        };

        root_dir = root_dir
            .open_dir_nofollow(single_component_path(name))
            .map_err(|source| GkrmError::InstalledRootCanonicalize {
                path: root.to_path_buf(),
                cause: source,
            })?;
        let metadata =
            root_dir
                .dir_metadata()
                .map_err(|source| GkrmError::InstalledPathMetadata {
                    path: root.to_path_buf(),
                    cause: source,
                })?;
        if !metadata.file_type().is_dir() {
            return Err(GkrmError::InstalledPathNotDirectory {
                path: root.to_path_buf(),
            });
        }
        if is_windows_reparse_point_cap(&metadata) {
            return Err(GkrmError::InstalledEntryReparsePoint {
                path: root.display().to_string(),
            });
        }
    }

    let metadata = root_dir
        .dir_metadata()
        .map_err(|source| GkrmError::InstalledPathMetadata {
            path: root.to_path_buf(),
            cause: source,
        })?;
    if !metadata.file_type().is_dir() {
        return Err(GkrmError::InstalledPathNotDirectory {
            path: root.to_path_buf(),
        });
    }
    if is_windows_reparse_point_cap(&metadata) {
        return Err(GkrmError::InstalledEntryReparsePoint {
            path: ".".to_owned(),
        });
    }

    Ok(root_dir)
}

fn open_root_anchor<'a>(root: &'a Path) -> Result<(CapDir, Vec<Component<'a>>)> {
    let components = root.components().collect::<Vec<_>>();
    if components.is_empty() {
        return Err(GkrmError::InstalledPathEmpty {
            path: root.display().to_string(),
        });
    }

    if root.is_relative() {
        let anchor =
            CapDir::open_ambient_dir(Path::new("."), ambient_authority()).map_err(|source| {
                GkrmError::InstalledRootCanonicalize {
                    path: root.to_path_buf(),
                    cause: source,
                }
            })?;
        return Ok((anchor, strip_leading_current_dir(components)));
    }

    open_absolute_root_anchor(root, components)
}

#[cfg(unix)]
fn open_absolute_root_anchor<'a>(
    root: &'a Path,
    components: Vec<Component<'a>>,
) -> Result<(CapDir, Vec<Component<'a>>)> {
    if !matches!(components.first(), Some(Component::RootDir)) {
        return Err(GkrmError::InstalledRootUnsupportedPrefix {
            path: root.to_path_buf(),
        });
    }

    let anchor =
        CapDir::open_ambient_dir(Path::new("/"), ambient_authority()).map_err(|source| {
            GkrmError::InstalledRootCanonicalize {
                path: root.to_path_buf(),
                cause: source,
            }
        })?;
    Ok((anchor, components.into_iter().skip(1).collect()))
}

#[cfg(windows)]
fn open_absolute_root_anchor<'a>(
    root: &'a Path,
    components: Vec<Component<'a>>,
) -> Result<(CapDir, Vec<Component<'a>>)> {
    let Some(Component::Prefix(prefix)) = components.first().copied() else {
        return Err(GkrmError::InstalledRootUnsupportedPrefix {
            path: root.to_path_buf(),
        });
    };
    if !matches!(components.get(1), Some(Component::RootDir)) {
        return Err(GkrmError::InstalledRootUnsupportedPrefix {
            path: root.to_path_buf(),
        });
    }

    let anchor = windows_anchor_from_prefix(root, prefix)?;
    let dir = CapDir::open_ambient_dir(&anchor, ambient_authority()).map_err(|source| {
        GkrmError::InstalledRootCanonicalize {
            path: root.to_path_buf(),
            cause: source,
        }
    })?;
    Ok((dir, components.into_iter().skip(2).collect()))
}

#[cfg(windows)]
fn windows_anchor_from_prefix(
    root: &Path,
    prefix: std::path::PrefixComponent<'_>,
) -> Result<PathBuf> {
    use std::path::Prefix;

    match prefix.kind() {
        Prefix::Disk(disk) | Prefix::VerbatimDisk(disk) => {
            let drive = char::from(disk);
            Ok(PathBuf::from(format!("{drive}:\\")))
        }
        _ => Err(GkrmError::InstalledRootUnsupportedPrefix {
            path: root.to_path_buf(),
        }),
    }
}

struct InstallationInventory {
    resource_roots: BTreeMap<InstalledResourceRoot, InstallationRelativePath>,
    files: Vec<FileCandidate>,
}

fn collect_installation_entries(
    root_dir: CapDir,
    limits: InstalledScanLimits,
) -> Result<InstallationInventory> {
    let mut pending = vec![DirectoryToVisit {
        dir: root_dir,
        relative_path: None,
        components: Vec::new(),
        depth: 0,
    }];
    let mut resource_roots = BTreeMap::<InstalledResourceRoot, InstallationRelativePath>::new();
    let mut files = Vec::<FileCandidate>::new();
    let mut exact_paths = BTreeMap::<String, ()>::new();
    let mut case_paths = BTreeMap::<String, String>::new();
    let mut total_entries = 0_usize;
    let mut directories = 1_usize;

    if directories > limits.max_directories {
        return Err(GkrmError::InstalledDirectoryCountLimitExceeded {
            limit: limits.max_directories,
            actual: directories,
        });
    }

    while let Some(directory) = pending.pop() {
        let directory_label = directory_label(directory.relative_path.as_ref());
        let read_dir = directory
            .dir
            .entries()
            .map_err(|source| match source.kind() {
                ErrorKind::NotFound => GkrmError::InstalledDirectoryDisappeared {
                    path: directory_label.clone(),
                },
                _ => GkrmError::InstalledDirectoryRead {
                    path: directory_label.clone(),
                    cause: source,
                },
            })?;

        let mut entries = Vec::new();
        for entry in read_dir {
            total_entries = checked_increment_entries(total_entries, limits.max_total_entries)?;

            let entry = entry.map_err(|source| GkrmError::InstalledDirectoryEntryRead {
                path: directory_label.clone(),
                cause: source,
            })?;
            let mut components = directory.components.clone();
            let file_name = entry.file_name();
            components.push(file_name.clone());
            let relative_path = InstallationRelativePath::from_components(&components)?;
            reject_duplicate_path(&mut exact_paths, &mut case_paths, &relative_path)?;
            let metadata =
                entry
                    .full_metadata()
                    .map_err(|source| GkrmError::InstalledEntryMetadata {
                        path: relative_path.to_string(),
                        cause: source,
                    })?;

            entries.push(DirectoryEntryCandidate {
                relative_path,
                file_name,
                metadata,
            });
        }

        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let mut child_directories = Vec::new();

        for entry in entries {
            reject_link_like_entry(&entry.relative_path, &entry.metadata)?;
            let file_type = entry.metadata.file_type();

            if file_type.is_dir() {
                let child_depth = directory.depth.checked_add(1).ok_or(
                    GkrmError::InstalledDirectoryDepthLimitExceeded {
                        path: entry.relative_path.to_string(),
                        limit: limits.max_directory_depth,
                        actual: usize::MAX,
                    },
                )?;

                if child_depth > limits.max_directory_depth {
                    return Err(GkrmError::InstalledDirectoryDepthLimitExceeded {
                        path: entry.relative_path.to_string(),
                        limit: limits.max_directory_depth,
                        actual: child_depth,
                    });
                }

                directories = checked_increment_directories(directories, limits.max_directories)?;
                let child_dir = directory
                    .dir
                    .open_dir_nofollow(single_component_path(&entry.file_name))
                    .map_err(|source| match source.kind() {
                        ErrorKind::NotFound => GkrmError::InstalledDirectoryDisappeared {
                            path: entry.relative_path.to_string(),
                        },
                        _ => GkrmError::InstalledDirectoryRead {
                            path: entry.relative_path.to_string(),
                            cause: source,
                        },
                    })?;
                let opened_metadata = child_dir.dir_metadata().map_err(|source| {
                    GkrmError::InstalledEntryMetadata {
                        path: entry.relative_path.to_string(),
                        cause: source,
                    }
                })?;
                if !opened_metadata.file_type().is_dir()
                    || metadata_modified_optional(&entry.metadata)
                        != metadata_modified_optional(&opened_metadata)
                {
                    return Err(GkrmError::InstalledFileChanged {
                        path: entry.relative_path.to_string(),
                    });
                }
                if is_windows_reparse_point_cap(&opened_metadata) {
                    return Err(GkrmError::InstalledEntryReparsePoint {
                        path: entry.relative_path.to_string(),
                    });
                }

                child_directories.push(ChildDirectory {
                    dir: child_dir,
                    relative_path: entry.relative_path,
                    components: {
                        let mut components = directory.components.clone();
                        components.push(entry.file_name);
                        components
                    },
                    depth: child_depth,
                });
            } else if file_type.is_file() {
                if entry.relative_path.file_name() == "fxmanifest.lua" {
                    let root = entry
                        .relative_path
                        .parent()
                        .map_or(InstalledResourceRoot::Root, InstalledResourceRoot::Path);
                    if resource_roots
                        .insert(root, entry.relative_path.clone())
                        .is_none()
                        && resource_roots.len() > limits.max_resources
                    {
                        return Err(GkrmError::InstalledResourceCountLimitExceeded {
                            limit: limits.max_resources,
                            actual: resource_roots.len(),
                        });
                    }
                }

                files.push(FileCandidate {
                    parent_dir: directory.dir.try_clone().map_err(|source| {
                        GkrmError::InstalledDirectoryRead {
                            path: directory_label.clone(),
                            cause: source,
                        }
                    })?,
                    file_name: entry.file_name,
                    relative_path: entry.relative_path,
                });
            } else {
                return Err(GkrmError::InstalledUnsupportedEntryType {
                    path: entry.relative_path.to_string(),
                });
            }
        }

        child_directories.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        for child in child_directories.into_iter().rev() {
            pending.push(DirectoryToVisit {
                dir: child.dir,
                relative_path: Some(child.relative_path),
                components: child.components,
                depth: child.depth,
            });
        }
    }

    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    Ok(InstallationInventory {
        resource_roots,
        files,
    })
}

fn checked_increment_entries(actual: usize, limit: usize) -> Result<usize> {
    let actual = actual
        .checked_add(1)
        .ok_or(GkrmError::InstalledTotalEntriesLimitExceeded {
            limit,
            actual: usize::MAX,
        })?;
    if actual > limit {
        return Err(GkrmError::InstalledTotalEntriesLimitExceeded { limit, actual });
    }
    Ok(actual)
}

fn checked_increment_directories(actual: usize, limit: usize) -> Result<usize> {
    let actual = actual
        .checked_add(1)
        .ok_or(GkrmError::InstalledDirectoryCountLimitExceeded {
            limit,
            actual: usize::MAX,
        })?;
    if actual > limit {
        return Err(GkrmError::InstalledDirectoryCountLimitExceeded { limit, actual });
    }
    Ok(actual)
}

fn single_component_path(component: &OsStr) -> PathBuf {
    PathBuf::from(component)
}

fn reject_link_like_entry(path: &InstallationRelativePath, metadata: &CapMetadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return if path.file_name() == "fxmanifest.lua" {
            Err(GkrmError::InstalledFxManifestSymlink {
                path: path.to_string(),
            })
        } else {
            Err(GkrmError::InstalledEntrySymlink {
                path: path.to_string(),
            })
        };
    }
    if is_windows_reparse_point_cap(metadata) {
        return Err(GkrmError::InstalledEntryReparsePoint {
            path: path.to_string(),
        });
    }
    Ok(())
}

fn reject_duplicate_path(
    exact_paths: &mut BTreeMap<String, ()>,
    case_paths: &mut BTreeMap<String, String>,
    relative_path: &InstallationRelativePath,
) -> Result<()> {
    let path = relative_path.to_string();
    if exact_paths.insert(path.clone(), ()).is_some() {
        return Err(GkrmError::InstalledPathDuplicate { path });
    }

    let case_key = case_collision_key(&path);
    if let Some(first) = case_paths.insert(case_key, path.clone()) {
        return Err(GkrmError::InstalledPathCaseInsensitiveCollision {
            first,
            second: path,
        });
    }

    Ok(())
}

fn build_resource_builders(
    selected_root: &Path,
    resource_roots: &BTreeMap<InstalledResourceRoot, InstallationRelativePath>,
) -> Result<Vec<ResourceBuilder>> {
    let mut builders = resource_roots
        .iter()
        .map(|(root, manifest_relative_path)| {
            Ok(ResourceBuilder {
                name: resource_name(selected_root, root)?,
                root: root.clone(),
                manifest_relative_path: manifest_relative_path.clone(),
                files: Vec::new(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    builders.sort_by(|left, right| left.root.cmp(&right.root));
    Ok(builders)
}

fn resource_name(selected_root: &Path, root: &InstalledResourceRoot) -> Result<String> {
    match root {
        InstalledResourceRoot::Root => selected_root
            .file_name()
            .map(|name| {
                name.to_str().map(str::to_owned).ok_or_else(|| {
                    GkrmError::InstalledRootNameNonUtf8 {
                        path: selected_root.to_path_buf(),
                    }
                })
            })
            .unwrap_or_else(|| Ok("root".to_owned())),
        InstalledResourceRoot::Path(path) => Ok(path.file_name().to_owned()),
    }
}

fn assign_files_to_resources(
    resources: &mut [ResourceBuilder],
    files: &[FileCandidate],
) -> Result<()> {
    for file in files {
        let resource_index = resources
            .iter()
            .enumerate()
            .filter(|(_, resource)| resource.root.contains(&file.relative_path))
            .max_by_key(|(_, resource)| resource.root.depth())
            .map(|(index, _)| index)
            .ok_or_else(|| GkrmError::InstalledFileOutsideResource {
                path: file.relative_path.to_string(),
            })?;

        resources[resource_index].files.push(file.try_clone()?);
    }

    for resource in resources {
        resource
            .files
            .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    }

    Ok(())
}

fn preflight_assigned_resources(
    resources: Vec<ResourceBuilder>,
    limits: InstalledScanLimits,
) -> Result<Vec<PreflightedResource>> {
    let mut total_files = 0_usize;
    let mut total_size = 0_u64;
    let mut preflighted_resources = Vec::with_capacity(resources.len());

    for resource in resources {
        let mut files = Vec::with_capacity(resource.files.len());

        for file in resource.files {
            total_files =
                total_files
                    .checked_add(1)
                    .ok_or(GkrmError::InstalledTotalFilesLimitExceeded {
                        limit: limits.max_total_files,
                        actual: usize::MAX,
                    })?;
            if total_files > limits.max_total_files {
                return Err(GkrmError::InstalledTotalFilesLimitExceeded {
                    limit: limits.max_total_files,
                    actual: total_files,
                });
            }

            let opened =
                open_and_snapshot_file(&file.parent_dir, &file.file_name, &file.relative_path)?;
            if opened.size > limits.max_file_size {
                return Err(GkrmError::InstalledFileSizeLimitExceeded {
                    path: file.relative_path.to_string(),
                    limit: limits.max_file_size,
                    actual: opened.size,
                });
            }

            total_size = total_size.checked_add(opened.size).ok_or(
                GkrmError::InstalledTotalSizeLimitExceeded {
                    limit: limits.max_total_size,
                    actual: u64::MAX,
                },
            )?;
            if total_size > limits.max_total_size {
                return Err(GkrmError::InstalledTotalSizeLimitExceeded {
                    limit: limits.max_total_size,
                    actual: total_size,
                });
            }

            drop(opened.handle);

            files.push(PreflightedFile {
                parent_dir: file.parent_dir,
                file_name: file.file_name,
                resource_relative_path: ResourceRelativePath::from_installation_path(
                    &resource.root,
                    &file.relative_path,
                )?,
                installation_relative_path: file.relative_path,
                size: opened.size,
                modified: opened.modified,
                identity: opened.identity,
            });

            let actual = files.len();
            if actual > limits.max_files_per_resource {
                return Err(GkrmError::InstalledFilesPerResourceLimitExceeded {
                    resource: resource.root.sort_key(),
                    limit: limits.max_files_per_resource,
                    actual,
                });
            }
        }

        files.sort_by(|left, right| {
            left.resource_relative_path
                .cmp(&right.resource_relative_path)
        });
        preflighted_resources.push(PreflightedResource {
            name: resource.name,
            root: resource.root,
            manifest_relative_path: resource.manifest_relative_path,
            files,
        });
    }

    preflighted_resources.sort_by(|left, right| left.root.cmp(&right.root));
    Ok(preflighted_resources)
}

fn hash_preflighted_resources(
    selected_root: &Path,
    resources: Vec<PreflightedResource>,
) -> Result<InstalledInstallationScan> {
    let mut scanned_resources = Vec::with_capacity(resources.len());
    let mut buffer = vec![0_u8; 64 * 1024];

    for resource in resources {
        let mut files = Vec::with_capacity(resource.files.len());

        for file in resource.files {
            let hashed = hash_preflighted_file(&file, &mut buffer)?;

            files.push(InstalledFileInfo {
                relative_path: file.resource_relative_path,
                size: file.size,
                sha256: hashed,
            });
        }

        files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        scanned_resources.push(InstalledResourceScan {
            name: resource.name,
            root: resource.root,
            manifest_relative_path: resource.manifest_relative_path,
            files,
        });
    }

    scanned_resources.sort_by(|left, right| left.root.cmp(&right.root));

    Ok(InstalledInstallationScan {
        root: selected_root.to_path_buf(),
        resources: scanned_resources,
        warnings: Vec::new(),
    })
}

impl FileCandidate {
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            parent_dir: self.parent_dir.try_clone().map_err(|source| {
                GkrmError::InstalledDirectoryRead {
                    path: parent_label(&self.relative_path),
                    cause: source,
                }
            })?,
            file_name: self.file_name.clone(),
            relative_path: self.relative_path.clone(),
        })
    }
}

fn hash_preflighted_file(file: &PreflightedFile, buffer: &mut [u8]) -> Result<Sha256Digest> {
    note_hash_started();

    let first = hash_verified_pass(file, buffer, HashVerificationPass::First)?;
    run_between_hash_passes_hook(file.installation_relative_path.as_str());
    let second = hash_verified_pass(file, buffer, HashVerificationPass::Second)?;

    if first != second {
        return Err(GkrmError::InstalledFileContentChanged {
            path: file.installation_relative_path.to_string(),
        });
    }

    Ok(first)
}

fn hash_verified_pass(
    file: &PreflightedFile,
    buffer: &mut [u8],
    pass: HashVerificationPass,
) -> Result<Sha256Digest> {
    let mut opened = reopen_preflighted_file(file)?;
    run_hash_pass_ready_hook(pass, file.installation_relative_path.as_str());

    let digest = hash_opened_file_exact(file, pass, &mut opened.handle, buffer)?;
    verify_opened_handle_matches_preflight(file, &opened.handle)?;
    drop(opened.handle);

    let reopened = reopen_preflighted_file(file)?;
    drop(reopened.handle);

    Ok(digest)
}

fn reopen_preflighted_file(file: &PreflightedFile) -> Result<OpenedFileSnapshot> {
    let opened = open_and_snapshot_file(
        &file.parent_dir,
        &file.file_name,
        &file.installation_relative_path,
    )?;
    verify_snapshot_matches_preflight(file, &opened)?;
    Ok(opened)
}

fn open_and_snapshot_file(
    parent: &CapDir,
    name: &OsStr,
    path: &InstallationRelativePath,
) -> Result<OpenedFileSnapshot> {
    let handle = open_file_nofollow(parent, name, path)?;
    let snapshot = snapshot_opened_file(&handle, path)?;
    Ok(OpenedFileSnapshot { handle, ..snapshot })
}

fn snapshot_opened_file(
    handle: &CapFile,
    path: &InstallationRelativePath,
) -> Result<OpenedFileSnapshot> {
    let metadata = handle
        .metadata()
        .map_err(|source| GkrmError::InstalledFileMetadata {
            path: path.to_string(),
            cause: source,
        })?;
    verify_opened_file_type(path, &metadata)?;

    Ok(OpenedFileSnapshot {
        handle: handle
            .try_clone()
            .map_err(|source| GkrmError::InstalledFileOpen {
                path: path.to_string(),
                cause: source,
            })?,
        size: metadata.len(),
        modified: metadata_modified(path, &metadata)?,
        identity: capture_file_identity(handle, path)?,
    })
}

fn open_file_nofollow(
    parent: &CapDir,
    name: &OsStr,
    path: &InstallationRelativePath,
) -> Result<CapFile> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    parent
        .open_with(single_component_path(name), &options)
        .map_err(|source| match source.kind() {
            ErrorKind::NotFound => GkrmError::InstalledFileDisappeared {
                path: path.to_string(),
            },
            _ => GkrmError::InstalledFileOpen {
                path: path.to_string(),
                cause: source,
            },
        })
}

fn verify_opened_file_type(path: &InstallationRelativePath, opened: &CapMetadata) -> Result<()> {
    if opened.file_type().is_symlink() {
        return Err(GkrmError::InstalledEntrySymlink {
            path: path.to_string(),
        });
    }
    if is_windows_reparse_point_cap(opened) {
        return Err(GkrmError::InstalledEntryReparsePoint {
            path: path.to_string(),
        });
    }
    if !opened.file_type().is_file() {
        return Err(GkrmError::InstalledOpenedFileNotRegular {
            path: path.to_string(),
        });
    }

    Ok(())
}

fn verify_snapshot_matches_preflight(
    preflighted: &PreflightedFile,
    current: &OpenedFileSnapshot,
) -> Result<()> {
    if preflighted.size != current.size
        || preflighted.modified != current.modified
        || preflighted.identity != current.identity
    {
        return Err(GkrmError::InstalledFileChanged {
            path: preflighted.installation_relative_path.to_string(),
        });
    }

    Ok(())
}

fn capture_file_identity(
    file: &CapFile,
    path: &InstallationRelativePath,
) -> Result<InstalledFileIdentity> {
    let identity = capture_stable_file_identity(file).map_err(|source| {
        GkrmError::InstalledFileIdentityUnavailable {
            path: path.to_string(),
            cause: source,
        }
    })?;
    Ok(match identity {
        #[cfg(unix)]
        StableFileIdentity::Unix { device, inode } => InstalledFileIdentity::Unix { device, inode },
        #[cfg(windows)]
        StableFileIdentity::Windows {
            volume_serial,
            file_index,
        } => InstalledFileIdentity::Windows {
            volume_serial,
            file_index,
        },
    })
}

fn metadata_modified(
    path: &InstallationRelativePath,
    metadata: &CapMetadata,
) -> Result<SystemTime> {
    metadata
        .modified()
        .map_err(|source| GkrmError::InstalledFileTimestampUnavailable {
            path: path.to_string(),
            cause: source,
        })
}

fn metadata_modified_optional(metadata: &CapMetadata) -> Option<SystemTime> {
    metadata.modified().ok()
}

fn hash_opened_file_exact(
    file: &PreflightedFile,
    pass: HashVerificationPass,
    handle: &mut CapFile,
    buffer: &mut [u8],
) -> Result<Sha256Digest> {
    let path = file.installation_relative_path.as_str();
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let check_interval = metadata_check_interval_bytes();
    let mut next_metadata_check = check_interval;

    loop {
        let read = handle
            .read(buffer)
            .map_err(|source| GkrmError::InstalledFileHashRead {
                path: path.to_owned(),
                cause: source,
            })?;
        if read == 0 {
            break;
        }

        bytes_read =
            bytes_read
                .checked_add(read as u64)
                .ok_or(GkrmError::InstalledFileSizeMismatch {
                    path: path.to_owned(),
                    expected: file.size,
                    actual: u64::MAX,
                })?;
        if bytes_read > file.size {
            return Err(GkrmError::InstalledFileSizeMismatch {
                path: path.to_owned(),
                expected: file.size,
                actual: bytes_read,
            });
        }

        hasher.update(&buffer[..read]);
        run_hash_progress_hook(pass, bytes_read);

        if bytes_read >= next_metadata_check {
            verify_opened_handle_matches_preflight(file, handle)?;
            while next_metadata_check <= bytes_read {
                next_metadata_check = next_metadata_check.saturating_add(check_interval);
                if next_metadata_check == u64::MAX {
                    break;
                }
            }
        }
    }

    if bytes_read != file.size {
        return Err(GkrmError::InstalledFileSizeMismatch {
            path: path.to_owned(),
            expected: file.size,
            actual: bytes_read,
        });
    }

    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn verify_opened_handle_matches_preflight(file: &PreflightedFile, handle: &CapFile) -> Result<()> {
    let current = snapshot_opened_file(handle, &file.installation_relative_path)?;
    verify_snapshot_matches_preflight(file, &current)
}

#[cfg(test)]
fn hash_reader_exact<R: Read>(
    reader: &mut R,
    expected_size: u64,
    buffer: &mut [u8],
    path: &str,
) -> Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;

    loop {
        let read = reader
            .read(buffer)
            .map_err(|source| GkrmError::InstalledFileHashRead {
                path: path.to_owned(),
                cause: source,
            })?;
        if read == 0 {
            break;
        }

        bytes_read =
            bytes_read
                .checked_add(read as u64)
                .ok_or(GkrmError::InstalledFileSizeMismatch {
                    path: path.to_owned(),
                    expected: expected_size,
                    actual: u64::MAX,
                })?;
        if bytes_read > expected_size {
            return Err(GkrmError::InstalledFileSizeMismatch {
                path: path.to_owned(),
                expected: expected_size,
                actual: bytes_read,
            });
        }

        hasher.update(&buffer[..read]);
    }

    if bytes_read != expected_size {
        return Err(GkrmError::InstalledFileSizeMismatch {
            path: path.to_owned(),
            expected: expected_size,
            actual: bytes_read,
        });
    }

    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn directory_label(path: Option<&InstallationRelativePath>) -> String {
    path.map_or_else(|| ".".to_owned(), ToString::to_string)
}

fn parent_label(path: &InstallationRelativePath) -> String {
    path.parent()
        .map_or_else(|| ".".to_owned(), |parent| parent.to_string())
}

impl InstalledResourceRoot {
    fn contains(&self, path: &InstallationRelativePath) -> bool {
        match self {
            InstalledResourceRoot::Root => true,
            InstalledResourceRoot::Path(root) => {
                path == root
                    || path
                        .as_str()
                        .strip_prefix(root.as_str())
                        .is_some_and(|suffix| suffix.as_bytes().first() == Some(&b'/'))
            }
        }
    }

    fn depth(&self) -> usize {
        match self {
            InstalledResourceRoot::Root => 0,
            InstalledResourceRoot::Path(path) => path.depth(),
        }
    }

    fn sort_key(&self) -> String {
        match self {
            InstalledResourceRoot::Root => ".".to_owned(),
            InstalledResourceRoot::Path(path) => path.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::*;
    use tempfile::tempdir;

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn exact_reader_hashes_known_value() {
        let mut reader = Cursor::new(b"abc");
        let mut buffer = [0_u8; 2];
        let digest =
            hash_reader_exact(&mut reader, 3, &mut buffer, "file").expect("hash should succeed");

        assert_eq!(
            digest.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn exact_reader_rejects_short_reads() {
        let mut reader = Cursor::new(b"ab");
        let mut buffer = [0_u8; 8];
        let err = hash_reader_exact(&mut reader, 3, &mut buffer, "file")
            .expect_err("short read should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledFileSizeMismatch {
                expected: 3,
                actual: 2,
                ..
            }
        ));
    }

    #[test]
    fn exact_reader_rejects_long_reads() {
        let mut reader = Cursor::new(b"abc");
        let mut buffer = [0_u8; 8];
        let err = hash_reader_exact(&mut reader, 2, &mut buffer, "file")
            .expect_err("long read should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledFileSizeMismatch {
                expected: 2,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn pre_hash_revalidation_rejects_replaced_file_identity() {
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        fs::write(root.join("file.lua"), b"before").expect("file should be written");
        let dir = CapDir::open_ambient_dir(root, ambient_authority()).expect("dir should open");
        let path = InstallationRelativePath::from_path(Path::new("file.lua"))
            .expect("relative path should be valid");
        let snapshot =
            open_and_snapshot_file(&dir, OsStr::new("file.lua"), &path).expect("file preflights");
        let preflighted = PreflightedFile {
            parent_dir: dir.try_clone().expect("dir should clone"),
            file_name: OsString::from("file.lua"),
            installation_relative_path: path.clone(),
            resource_relative_path: ResourceRelativePath::from_installation_path(
                &InstalledResourceRoot::Root,
                &path,
            )
            .expect("resource path should derive"),
            size: snapshot.size,
            modified: snapshot.modified,
            identity: snapshot.identity,
        };
        drop(snapshot.handle);
        fs::remove_file(root.join("file.lua")).expect("file should be removed");
        fs::write(root.join("file.lua"), b"before").expect("replacement should be written");

        let err = match reopen_preflighted_file(&preflighted) {
            Ok(_) => panic!("identity change should fail"),
            Err(err) => err,
        };

        assert!(matches!(err, GkrmError::InstalledFileChanged { .. }));
    }

    #[test]
    fn two_pass_hashes_stable_file() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        fs::write(root.join("file.lua"), b"stable").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let mut buffer = [0_u8; 4];

        let digest =
            hash_preflighted_file(&preflighted, &mut buffer).expect("stable file should hash");

        assert_eq!(
            digest.to_string(),
            "f379ccb92b9116442dc65bdc35648a85d3786b34779db7f704a901fa07b00cb6"
        );
    }

    #[test]
    fn two_pass_hashes_empty_file() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        fs::write(root.join("file.lua"), b"").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let mut buffer = [0_u8; 4];

        let digest =
            hash_preflighted_file(&preflighted, &mut buffer).expect("empty file should hash");

        assert_eq!(
            digest.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn two_pass_hashes_large_file() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        let contents = vec![b'x'; 128];
        fs::write(root.join("file.lua"), &contents).expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let mut buffer = [0_u8; 7];
        set_metadata_check_interval_override(16);

        let digest =
            hash_preflighted_file(&preflighted, &mut buffer).expect("large file should hash");

        assert_eq!(
            digest.as_bytes().as_slice(),
            Sha256::digest(&contents).as_slice()
        );
    }

    #[test]
    fn detects_in_place_content_modification_during_first_hash_pass() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        let file = root.join("file.lua");
        fs::write(&file, b"aaaaaaaaaaaaaaaa").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let mut buffer = [0_u8; 4];
        set_metadata_check_interval_override(4);
        set_hash_progress_hook({
            let file = file.clone();
            let mut changed = false;
            move |pass, bytes_read| {
                if pass == HashVerificationPass::First && bytes_read >= 4 && !changed {
                    fs::write(&file, b"bbbbbbbbbbbbbbbb").expect("file should be changed");
                    changed = true;
                }
            }
        });

        let err = hash_preflighted_file(&preflighted, &mut buffer)
            .expect_err("in-place change should fail");

        assert!(matches!(err, GkrmError::InstalledFileChanged { .. }));
    }

    #[test]
    fn detects_same_size_replacement_with_restored_modified_time() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        let file = root.join("file.lua");
        fs::write(&file, b"aaaaaaaa").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let original_modified = preflighted.modified;
        let mut buffer = [0_u8; 4];
        set_between_hash_passes_hook({
            let root = root.to_path_buf();
            move |_| {
                fs::remove_file(root.join("file.lua")).expect("old file should be removed");
                fs::write(root.join("file.lua"), b"bbbbbbbb")
                    .expect("replacement should be written");
                restore_mtime(&root, "file.lua", original_modified);
            }
        });

        let err =
            hash_preflighted_file(&preflighted, &mut buffer).expect_err("replacement should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledFileChanged { .. } | GkrmError::InstalledFileContentChanged { .. }
        ));
    }

    #[test]
    fn detects_content_changing_between_hash_passes() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        let file = root.join("file.lua");
        fs::write(&file, b"aaaaaaaa").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let original_modified = preflighted.modified;
        let mut buffer = [0_u8; 4];
        set_between_hash_passes_hook({
            let root = root.to_path_buf();
            move |_| {
                fs::write(root.join("file.lua"), b"bbbbbbbb").expect("file should be changed");
                restore_mtime(&root, "file.lua", original_modified);
            }
        });

        let err = hash_preflighted_file(&preflighted, &mut buffer)
            .expect_err("digest mismatch should fail");

        assert!(matches!(err, GkrmError::InstalledFileContentChanged { .. }));
    }

    #[test]
    fn exact_byte_count_is_validated_on_first_hash_pass() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        let file = root.join("file.lua");
        fs::write(&file, b"abcdef").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let mut buffer = [0_u8; 4];
        set_hash_pass_ready_hook({
            let file = file.clone();
            let mut changed = false;
            move |pass, _| {
                if pass == HashVerificationPass::First && !changed {
                    fs::write(&file, b"abc").expect("file should be truncated");
                    changed = true;
                }
            }
        });

        let err = hash_preflighted_file(&preflighted, &mut buffer)
            .expect_err("short first pass should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledFileSizeMismatch {
                expected: 6,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn exact_byte_count_is_validated_on_second_hash_pass() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path();
        let file = root.join("file.lua");
        fs::write(&file, b"abcdef").expect("file should be written");
        let preflighted = preflight_test_file(root, "file.lua");
        let mut buffer = [0_u8; 4];
        set_hash_pass_ready_hook({
            let file = file.clone();
            let mut changed = false;
            move |pass, _| {
                if pass == HashVerificationPass::Second && !changed {
                    fs::write(&file, b"abc").expect("file should be truncated");
                    changed = true;
                }
            }
        });

        let err = hash_preflighted_file(&preflighted, &mut buffer)
            .expect_err("short second pass should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledFileSizeMismatch {
                expected: 6,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn total_size_limit_fails_before_hashing_starts() {
        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path().join("resource");
        fs::create_dir_all(&root).expect("root should be created");
        fs::write(root.join("fxmanifest.lua"), b"manifest").expect("manifest should be written");
        fs::write(root.join("large.bin"), [b'x'; 64]).expect("large file should be written");

        reset_hash_started_count();
        let err = scan_installed_resources(
            &root,
            InstalledScanLimits {
                max_resources: 4,
                max_files_per_resource: 10,
                max_total_files: 10,
                max_total_entries: 20,
                max_directories: 10,
                max_file_size: 1024,
                max_total_size: 8,
                max_directory_depth: 4,
            },
        )
        .expect_err("total size should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledTotalSizeLimitExceeded { .. }
        ));
        assert_eq!(hash_started_count(), 0);
    }

    #[test]
    fn hash_start_counter_ignores_concurrent_foreign_scans() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let _hooks = lock_hash_test_hooks();
        let temp = tempdir().expect("temp dir should be created");

        let limit_root = temp.path().join("limit-resource");
        fs::create_dir_all(&limit_root).expect("limit root");
        fs::write(limit_root.join("fxmanifest.lua"), b"manifest").expect("manifest");
        fs::write(limit_root.join("large.bin"), [b'x'; 64]).expect("large");

        let busy_root = temp.path().join("busy-resource");
        fs::create_dir_all(&busy_root).expect("busy root");
        fs::write(busy_root.join("fxmanifest.lua"), b"manifest").expect("busy manifest");
        fs::write(busy_root.join("ok.bin"), b"abcdef").expect("busy file");

        let stop = Arc::new(AtomicBool::new(false));
        let mut joiners = Vec::new();
        for i in 0..4 {
            let stop = Arc::clone(&stop);
            let busy_root = busy_root.clone();
            joiners.push(thread::spawn(move || {
                let limits = InstalledScanLimits {
                    max_resources: 4,
                    max_files_per_resource: 10,
                    max_total_files: 10,
                    max_total_entries: 20,
                    max_directories: 10,
                    max_file_size: 1024,
                    max_total_size: 4096,
                    max_directory_depth: 4,
                };
                while !stop.load(Ordering::SeqCst) {
                    let _ = scan_installed_resources(&busy_root, limits);
                    // Yield without sleep-based synchronization of the assertion.
                    if i % 2 == 0 {
                        thread::yield_now();
                    }
                }
            }));
        }

        // Give workers a chance to start hashing without timing assertions.
        for _ in 0..32 {
            thread::yield_now();
        }

        reset_hash_started_count();
        let err = scan_installed_resources(
            &limit_root,
            InstalledScanLimits {
                max_resources: 4,
                max_files_per_resource: 10,
                max_total_files: 10,
                max_total_entries: 20,
                max_directories: 10,
                max_file_size: 1024,
                max_total_size: 8,
                max_directory_depth: 4,
            },
        )
        .expect_err("total size should fail before hashing");
        assert!(matches!(
            err,
            GkrmError::InstalledTotalSizeLimitExceeded { .. }
        ));
        assert_eq!(
            hash_started_count(),
            0,
            "foreign concurrent scans must not mutate this test's hash counter"
        );

        stop.store(true, Ordering::SeqCst);
        for j in joiners {
            j.join().expect("worker join");
        }
    }

    #[test]
    fn relative_single_component_root_swap_to_symlink_is_rejected_where_supported() {
        let _hooks = lock_hash_test_hooks();
        let _cwd_lock = CWD_LOCK.lock().expect("cwd lock should not be poisoned");
        let temp = tempdir().expect("temp dir should be created");
        let root = temp.path().join("resource");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).expect("root should be created");
        fs::write(root.join("fxmanifest.lua"), b"manifest").expect("manifest should be written");
        fs::create_dir_all(&outside).expect("outside should be created");
        fs::write(outside.join("fxmanifest.lua"), b"outside").expect("outside should be written");

        let probe = temp.path().join("probe-link");
        if !try_symlink_dir(&outside, &probe) {
            return;
        }
        fs::remove_dir(&probe).expect("probe link should be removed");

        let original_cwd = std::env::current_dir().expect("cwd should read");
        std::env::set_current_dir(temp.path()).expect("cwd should change");
        let _guard = CurrentDirGuard(original_cwd);

        set_after_root_validation_hook({
            let root = root.clone();
            let outside = outside.clone();
            move || {
                fs::remove_dir_all(&root).expect("root should be removed");
                assert!(try_symlink_dir(&outside, &root));
            }
        });

        let err = scan_installed_resources(
            Path::new("resource"),
            InstalledScanLimits {
                max_resources: 4,
                max_files_per_resource: 10,
                max_total_files: 10,
                max_total_entries: 20,
                max_directories: 10,
                max_file_size: 1024,
                max_total_size: 4096,
                max_directory_depth: 4,
            },
        )
        .expect_err("swapped root symlink should fail");

        assert!(matches!(
            err,
            GkrmError::InstalledRootCanonicalize { .. }
                | GkrmError::InstalledEntryReparsePoint { .. }
                | GkrmError::InstalledRootSymlink { .. }
        ));
    }

    struct CurrentDirGuard(PathBuf);

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    struct HashHookGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for HashHookGuard {
        fn drop(&mut self) {
            clear_hash_test_hooks();
            LOCAL_HASH_COUNTING.with(|armed| armed.set(false));
            LOCAL_HASH_STARTS.with(|starts| starts.set(0));
            *HASH_HOOK_OWNER.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
    }

    fn lock_hash_test_hooks() -> HashHookGuard {
        let guard = super::INSTALLED_SCAN_HASH_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        clear_hash_test_hooks();
        *HASH_HOOK_OWNER.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(std::thread::current().id());
        LOCAL_HASH_STARTS.with(|starts| starts.set(0));
        LOCAL_HASH_COUNTING.with(|armed| armed.set(true));
        HashHookGuard { _guard: guard }
    }

    fn preflight_test_file(root: &Path, file_name: &str) -> PreflightedFile {
        let dir = CapDir::open_ambient_dir(root, ambient_authority()).expect("dir should open");
        let path = InstallationRelativePath::from_path(Path::new(file_name))
            .expect("relative path should be valid");
        let snapshot = open_and_snapshot_file(&dir, OsStr::new(file_name), &path)
            .expect("file should preflight");
        let preflighted = PreflightedFile {
            parent_dir: dir,
            file_name: OsString::from(file_name),
            installation_relative_path: path.clone(),
            resource_relative_path: ResourceRelativePath::from_installation_path(
                &InstalledResourceRoot::Root,
                &path,
            )
            .expect("resource path should derive"),
            size: snapshot.size,
            modified: snapshot.modified,
            identity: snapshot.identity,
        };
        drop(snapshot.handle);
        preflighted
    }

    fn restore_mtime(root: &Path, file_name: &str, modified: SystemTime) {
        let dir = CapDir::open_ambient_dir(root, ambient_authority()).expect("dir should open");
        dir.set_mtime(
            Path::new(file_name),
            cap_fs_ext::SystemTimeSpec::Absolute(modified),
        )
        .expect("mtime should be restored");
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
