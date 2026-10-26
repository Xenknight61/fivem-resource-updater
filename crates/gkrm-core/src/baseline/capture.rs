//! Official baseline capture from one immutable package snapshot (Task 12).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::baseline::blob_provider::{VerifiedBaselineBlobProvider, VerifiedBlobReader};
use crate::baseline::fs_security::{
    capture_file_identity, create_new_file, dir_identity,
    ensure_baseline_store_disjoint_from_installed, ensure_child_dir, open_child_dir,
    open_file_nofollow, open_or_create_store_root_for_write, remove_capture_spool_nofollow,
    validate_single_component, OpenStoreRoot,
};
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::{
    make_file_record, BaselineCounts, BaselineEscrowClass, BaselineFileRecord, BaselineStoreLimits,
    StoredBaselineLocator, ValidatedBaselineBundle,
};
use crate::baseline::store::write_baseline_bundle;
use crate::baseline::BaselineId;
use crate::escrow_classification::{
    classify_selected_zip_resource_escrow, ClassifiedResourceFile, ClassifiedZipResource,
    EscrowFileClassification,
};
use crate::manifest::{
    parse_selected_zip_resource_manifest_from_snapshot, FxManifest, ManifestLimits,
};
use crate::package_limits::PackageLimits;
use crate::package_source::PackageSnapshot;
use crate::resource_discovery::{
    discover_zip_resources, DiscoveredZipResource, ZipResourceDiscovery, ZipResourceName,
    ZipResourceRoot,
};
use crate::zip_package::{inspect_zip_snapshot, ZipEntryInfo, ZipEntryKind, ZipInspection};
use crate::zip_path::ZipRelativePath;
use crate::{
    acquire_trusted_update_workspace_publication_lock,
    enforce_trusted_update_workspace_capacity_for_reservation, BaselineCaptureBlobSpoolStage,
    GkrmError, PackageSourceCommitment, ResourceRelativePath, Result, Sha256Digest,
    TrustedUpdateWorkspace, TrustedUpdateWorkspaceOptions, TrustedUpdateWorkspaceReservation,
};

const HASH_BUFFER_SIZE: usize = 64 * 1024;
/// The most of one escrow-unsupported file worth keeping so a later merge can read it.
///
/// A merge reads at most this much of a single document, so a larger one could not be combined
/// even if it were held — and the files that exceed it are wallpapers, bundled scripts, and sound,
/// which are answered whole or not at all. Matching the merge's own ceiling keeps the store to
/// what is actually usable rather than to everything a package happens to ship.
const MAX_MERGEABLE_BLOB_BYTES: u64 = 1024 * 1024;
const TRUSTED_UPDATE_WORKSPACE_MARKER: &str = ".gkrm-trusted-update-workspace";
const TRUSTED_UPDATE_WORKSPACE_BASELINES_DIR: &str = "baselines";

/// How to select exactly one incoming ZIP resource for capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingResourceSelector {
    AutoSingle,
    ManifestPackagePath(ZipRelativePath),
}

/// Deterministic capture warnings (not stored in baseline.json).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineCaptureWarning {
    RootResourceSelected,
    ManifestVersionUnavailable,
}

/// Validated capture options (opaque after construction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCaptureOptions {
    package_limits: PackageLimits,
    manifest_limits: ManifestLimits,
    baseline_store_limits: BaselineStoreLimits,
    max_selected_files: usize,
    max_selected_uncompressed_bytes: u64,
    max_archive_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandaloneBaselineStore {
    root: PathBuf,
}

impl StandaloneBaselineStore {
    pub fn root(&self) -> &Path {
        &self.root
    }
}

pub fn resolve_standalone_baseline_store(root: &Path) -> Result<StandaloneBaselineStore> {
    reject_path_alias_to_managed_store(root)?;
    let opened = open_or_create_store_root_for_write(root).map_err(redact_capture_error)?;
    drop(opened);
    let canonical = root
        .canonicalize()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    reject_managed_workspace_baseline_root(&canonical)?;
    Ok(StandaloneBaselineStore { root: canonical })
}

fn reject_path_alias_to_managed_store(root: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(root);
    #[cfg(windows)]
    if let Ok(metadata) = &metadata {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    #[cfg(unix)]
    if metadata.is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(())
}

impl Default for BaselineCaptureOptions {
    fn default() -> Self {
        Self {
            package_limits: PackageLimits::default(),
            manifest_limits: ManifestLimits::default(),
            baseline_store_limits: BaselineStoreLimits::default(),
            max_selected_files: 20_000,
            max_selected_uncompressed_bytes: 2 * 1024 * 1024 * 1024,
            max_archive_size: 2 * 1024 * 1024 * 1024,
        }
    }
}

impl BaselineCaptureOptions {
    pub fn try_new(
        package_limits: PackageLimits,
        manifest_limits: ManifestLimits,
        baseline_store_limits: BaselineStoreLimits,
        max_selected_files: usize,
        max_selected_uncompressed_bytes: u64,
        max_archive_size: u64,
    ) -> Result<Self> {
        let options = Self {
            package_limits,
            manifest_limits,
            baseline_store_limits,
            max_selected_files,
            max_selected_uncompressed_bytes,
            max_archive_size,
        };
        options.validate()?;
        Ok(options)
    }

    fn validate(&self) -> Result<()> {
        self.baseline_store_limits.validate()?;
        if self.max_selected_files == 0 {
            return Err(GkrmError::BaselineCaptureOptionsInvalid {
                limit: "max_selected_files",
            });
        }
        if self.max_selected_uncompressed_bytes == 0 {
            return Err(GkrmError::BaselineCaptureOptionsInvalid {
                limit: "max_selected_uncompressed_bytes",
            });
        }
        if self.max_archive_size == 0 {
            return Err(GkrmError::BaselineCaptureOptionsInvalid {
                limit: "max_archive_size",
            });
        }
        if self.package_limits.max_entries == 0
            || self.package_limits.max_entry_uncompressed_size == 0
            || self.package_limits.max_total_uncompressed_size == 0
            || self.package_limits.max_compression_ratio == 0
        {
            return Err(GkrmError::BaselineCaptureOptionsInvalid {
                limit: "package_limits",
            });
        }
        if self.manifest_limits.max_manifest_size == 0 || self.manifest_limits.max_tokens == 0 {
            return Err(GkrmError::BaselineCaptureOptionsInvalid {
                limit: "manifest_limits",
            });
        }
        Ok(())
    }

    pub fn package_limits(&self) -> PackageLimits {
        self.package_limits
    }

    pub fn manifest_limits(&self) -> ManifestLimits {
        self.manifest_limits
    }

    pub fn baseline_store_limits(&self) -> BaselineStoreLimits {
        self.baseline_store_limits
    }

    pub fn max_selected_files(&self) -> usize {
        self.max_selected_files
    }

    pub fn max_selected_uncompressed_bytes(&self) -> u64 {
        self.max_selected_uncompressed_bytes
    }

    pub fn max_archive_size(&self) -> u64 {
        self.max_archive_size
    }
}

/// Opaque capture request.
#[derive(Debug)]
pub struct BaselineCaptureRequest<'a> {
    installed_root: &'a Path,
    store_root: &'a Path,
    package_path: &'a Path,
    resource_key: SafeResourceKey,
    resource_selector: IncomingResourceSelector,
    options: BaselineCaptureOptions,
}

/// Opaque managed-workspace capture request with mandatory inspection binding.
#[derive(Debug)]
pub struct ExpectedPackageBaselineCaptureRequest<'a> {
    installed_root: &'a Path,
    package_path: &'a Path,
    expected_package_commitment: PackageSourceCommitment,
    resource_key: SafeResourceKey,
    resource_selector: IncomingResourceSelector,
    options: BaselineCaptureOptions,
}

impl<'a> BaselineCaptureRequest<'a> {
    pub fn try_new(
        installed_root: &'a Path,
        store_root: &'a Path,
        package_path: &'a Path,
        resource_key: SafeResourceKey,
        resource_selector: IncomingResourceSelector,
        options: BaselineCaptureOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            installed_root,
            store_root,
            package_path,
            resource_key,
            resource_selector,
            options,
        })
    }
}

impl<'a> ExpectedPackageBaselineCaptureRequest<'a> {
    pub fn try_new(
        installed_root: &'a Path,
        package_path: &'a Path,
        expected_package_commitment: PackageSourceCommitment,
        resource_key: SafeResourceKey,
        resource_selector: IncomingResourceSelector,
        options: BaselineCaptureOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            installed_root,
            package_path,
            expected_package_commitment,
            resource_key,
            resource_selector,
            options,
        })
    }
}

#[derive(Debug)]
struct BaselineCaptureStoreRequest<'a> {
    installed_root: &'a Path,
    store_root: &'a Path,
    package_path: &'a Path,
    resource_key: SafeResourceKey,
    resource_selector: IncomingResourceSelector,
    options: BaselineCaptureOptions,
}

impl<'a> BaselineCaptureStoreRequest<'a> {
    fn bind_store(store_root: &'a Path, request: BaselineCaptureRequest<'a>) -> Self {
        Self {
            installed_root: request.installed_root,
            store_root,
            package_path: request.package_path,
            resource_key: request.resource_key,
            resource_selector: request.resource_selector,
            options: request.options,
        }
    }
}

/// Opaque capture result with read-only accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCaptureResult {
    locator: StoredBaselineLocator,
    resource_label: String,
    resource_version: Option<String>,
    source_package_fingerprint: Sha256Digest,
    counts: BaselineCounts,
    warnings: Vec<BaselineCaptureWarning>,
}

impl BaselineCaptureResult {
    pub fn locator(&self) -> &StoredBaselineLocator {
        &self.locator
    }

    pub fn baseline_id(&self) -> &BaselineId {
        self.locator.baseline_id()
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        self.locator.resource_key()
    }

    pub fn resource_label(&self) -> &str {
        &self.resource_label
    }

    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    pub fn source_package_fingerprint(&self) -> &Sha256Digest {
        &self.source_package_fingerprint
    }

    pub fn counts(&self) -> &BaselineCounts {
        &self.counts
    }

    pub fn unique_blob_count(&self) -> u64 {
        self.counts.blobs()
    }

    pub fn total_unique_blob_bytes(&self) -> u64 {
        self.counts.total_blob_bytes()
    }

    pub fn warnings(&self) -> &[BaselineCaptureWarning] {
        &self.warnings
    }
}

pub fn capture_official_baseline_in_standalone_store(
    store: &StandaloneBaselineStore,
    request: BaselineCaptureRequest<'_>,
) -> Result<BaselineCaptureResult> {
    let request_store = request
        .store_root
        .canonicalize()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if request_store != store.root {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let request = BaselineCaptureStoreRequest::bind_store(store.root(), request);
    capture_official_baseline_in_standalone_store_inner(request, None)
}

pub fn capture_official_baseline_in_workspace(
    workspace: &TrustedUpdateWorkspace,
    installed_root: &Path,
    package_path: &Path,
    resource_key: SafeResourceKey,
    resource_selector: IncomingResourceSelector,
    options: BaselineCaptureOptions,
    workspace_options: TrustedUpdateWorkspaceOptions,
) -> Result<BaselineCaptureResult> {
    let request = BaselineCaptureRequest::try_new(
        installed_root,
        workspace.baseline_store(),
        package_path,
        resource_key,
        resource_selector,
        options,
    )?;
    capture_official_baseline_from_package_in_trusted_update_workspace(
        request,
        workspace,
        workspace_options,
    )
}

/// Capture one official resource only when the capture-time package snapshot
/// matches a commitment produced by trusted package inspection.
///
/// The expected commitment is compared with the single immutable
/// [`PackageSnapshot`] that is subsequently consumed for discovery, manifest
/// parsing, blob extraction, and publication. The package path is not reopened
/// for package contents after that snapshot has been verified.
pub fn capture_official_baseline_in_workspace_with_expected_package_commitment(
    workspace: &TrustedUpdateWorkspace,
    request: ExpectedPackageBaselineCaptureRequest<'_>,
    workspace_options: TrustedUpdateWorkspaceOptions,
) -> Result<BaselineCaptureResult> {
    let expected_package_commitment = request.expected_package_commitment;
    let request = BaselineCaptureRequest::try_new(
        request.installed_root,
        workspace.baseline_store(),
        request.package_path,
        request.resource_key,
        request.resource_selector,
        request.options,
    )?;
    capture_official_baseline_from_package_in_trusted_update_workspace_inner(
        request,
        workspace,
        workspace_options,
        Some(expected_package_commitment),
    )
}

/// Capture one official incoming resource into a core-resolved trusted update workspace.
///
/// This entry point is for writers that publish into `TrustedUpdateWorkspace::baseline_store`.
/// It uses the same workspace publication lock and capacity preflight as planning artifacts.
/// Standalone baseline stores remain supported through `capture_official_baseline_in_standalone_store`.
pub fn capture_official_baseline_from_package_in_trusted_update_workspace(
    request: BaselineCaptureRequest<'_>,
    workspace: &TrustedUpdateWorkspace,
    workspace_options: TrustedUpdateWorkspaceOptions,
) -> Result<BaselineCaptureResult> {
    capture_official_baseline_from_package_in_trusted_update_workspace_inner(
        request,
        workspace,
        workspace_options,
        None,
    )
}

fn capture_official_baseline_from_package_in_trusted_update_workspace_inner(
    request: BaselineCaptureRequest<'_>,
    workspace: &TrustedUpdateWorkspace,
    workspace_options: TrustedUpdateWorkspaceOptions,
    expected_package_commitment: Option<PackageSourceCommitment>,
) -> Result<BaselineCaptureResult> {
    request.options.validate()?;
    let request = BaselineCaptureStoreRequest::bind_store(workspace.baseline_store(), request);
    let _publication_lock = acquire_trusted_update_workspace_publication_lock(workspace)?;
    let reservation = baseline_capture_workspace_reservation(&request.options)?;
    enforce_trusted_update_workspace_capacity_for_reservation(
        workspace,
        workspace_options,
        reservation,
    )?;
    capture_official_baseline_in_standalone_store_inner(request, expected_package_commitment)
}

fn capture_official_baseline_in_standalone_store_inner(
    request: BaselineCaptureStoreRequest<'_>,
    expected_package_commitment: Option<PackageSourceCommitment>,
) -> Result<BaselineCaptureResult> {
    request.options.validate()?;
    ensure_baseline_store_disjoint_from_installed(request.store_root, request.installed_root)
        .map_err(redact_capture_error)?;

    let store =
        open_or_create_store_root_for_write(request.store_root).map_err(redact_capture_error)?;
    let tmp_root = ensure_child_dir(&store.dir, ".tmp").map_err(redact_capture_error)?;
    let spool = CaptureSpoolGuard::create(&tmp_root).map_err(redact_capture_error)?;
    let capture_result =
        capture_with_spool(&request, &store, spool.dir(), expected_package_commitment);
    spool.finish(capture_result)
}

fn baseline_capture_workspace_reservation(
    options: &BaselineCaptureOptions,
) -> Result<TrustedUpdateWorkspaceReservation> {
    let limits = options.baseline_store_limits();
    let spool_bytes =
        temporary_spool_budget(limits.max_total_blob_bytes(), limits.max_blob_bytes())?;
    let regular_file_bytes = spool_bytes
        .checked_add(limits.max_total_blob_bytes())
        .and_then(|value| value.checked_add(limits.max_manifest_bytes()))
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    let directory_entries = limits
        .max_files()
        .checked_mul(2)
        .and_then(|value| value.checked_add(16))
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    TrustedUpdateWorkspaceReservation::new(regular_file_bytes, directory_entries, 0, 0)
}

/// Retain a verified standalone baseline under the same content identity. Only
/// verified official blobs are copied; no installed customer bytes are captured.
pub(crate) fn retain_stored_baseline_in_workspace(
    workspace: &TrustedUpdateWorkspace,
    installed: &Path,
    baseline: &crate::baseline::StoredBaseline,
) -> Result<BaselineId> {
    use crate::baseline::blob_provider::VerifiedBlobReader;
    use crate::baseline::model::ValidatedBaselineBundle;
    let options = BaselineCaptureOptions::default();
    let limits = options.baseline_store_limits();
    let bundle = ValidatedBaselineBundle::try_from_parts(
        baseline.resource_key().clone(),
        baseline.resource_name().to_owned(),
        baseline.resource_version().map(str::to_owned),
        baseline.source_package_fingerprint().copied(),
        baseline.files().to_vec(),
        baseline
            .files()
            .iter()
            .filter_map(|file| file.blob_sha256().map(|id| (*id, file.size())))
            .collect(),
        limits,
    )?;
    if bundle.baseline_id() != baseline.baseline_id() {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    struct Source<'a>(&'a crate::baseline::StoredBaseline, BaselineStoreLimits);
    impl VerifiedBaselineBlobProvider for Source<'_> {
        fn open_verified_blob(&self, digest: &Sha256Digest) -> Result<VerifiedBlobReader> {
            let bytes = self.0.read_verified_blob(digest, &self.1)?;
            Ok(VerifiedBlobReader::from_memory(
                *digest,
                bytes.len() as u64,
                bytes,
            ))
        }
    }
    ensure_baseline_store_disjoint_from_installed(workspace.baseline_store(), installed)?;
    let _lock = acquire_trusted_update_workspace_publication_lock(workspace)?;
    enforce_trusted_update_workspace_capacity_for_reservation(
        workspace,
        TrustedUpdateWorkspaceOptions::default(),
        baseline_capture_workspace_reservation(&options)?,
    )?;
    write_baseline_bundle(
        workspace.baseline_store(),
        &bundle,
        &Source(baseline, limits),
        limits,
    )?;
    Ok(bundle.baseline_id().clone())
}

fn reject_managed_workspace_baseline_root(root: &Path) -> Result<()> {
    let Some(parent) = root.parent() else {
        return Ok(());
    };
    let Some(name) = root.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    if name != TRUSTED_UPDATE_WORKSPACE_BASELINES_DIR {
        return Ok(());
    }
    let marker = parent.join(TRUSTED_UPDATE_WORKSPACE_MARKER);
    if marker.exists() {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod task29_workspace_capture_tests {
    use super::*;
    use crate::{
        enforce_trusted_update_workspace_capacity, resolve_trusted_update_workspace,
        BaselineStoreLimits, IncomingResourceSelector, PackageLimits,
        TrustedUpdateWorkspaceOptions,
    };
    use std::{fs, io::Write};
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter};

    const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\n";

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let mut writer = ZipWriter::new(file);
        let options =
            zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, contents) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    fn small_capture_options() -> BaselineCaptureOptions {
        BaselineCaptureOptions::try_new(
            PackageLimits::default(),
            ManifestLimits::default(),
            BaselineStoreLimits::new(4096, 32, 1024, 4096).unwrap(),
            32,
            4096,
            1024 * 1024,
        )
        .unwrap()
    }

    #[test]
    fn managed_baseline_capture_uses_workspace_quota_and_preserves_store_on_rejection() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("gksphone/fxmanifest.lua", MANIFEST),
                ("gksphone/client.lua", b"client"),
            ],
        );
        let err = capture_official_baseline_from_package_in_trusted_update_workspace(
            BaselineCaptureRequest::try_new(
                &installed,
                workspace.baseline_store(),
                &package,
                SafeResourceKey::parse("gksphone").unwrap(),
                IncomingResourceSelector::AutoSingle,
                small_capture_options(),
            )
            .unwrap(),
            &workspace,
            TrustedUpdateWorkspaceOptions {
                max_regular_file_bytes: 1,
                ..TrustedUpdateWorkspaceOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
        ));
        let usage = enforce_trusted_update_workspace_capacity(
            &workspace,
            TrustedUpdateWorkspaceOptions::default(),
        )
        .unwrap();
        assert_eq!(usage.plan_artifacts(), 0);
        assert_eq!(usage.regular_file_bytes(), 0);
    }

    #[test]
    fn managed_baseline_capture_binds_store_from_workspace_capability() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).unwrap();
        let package = temp.path().join("package.zip");
        write_zip(
            &package,
            &[
                ("gksphone/fxmanifest.lua", MANIFEST),
                ("gksphone/client.lua", b"client"),
            ],
        );
        let result = capture_official_baseline_from_package_in_trusted_update_workspace(
            BaselineCaptureRequest::try_new(
                &installed,
                workspace.baseline_store(),
                &package,
                SafeResourceKey::parse("gksphone").unwrap(),
                IncomingResourceSelector::AutoSingle,
                small_capture_options(),
            )
            .unwrap(),
            &workspace,
            TrustedUpdateWorkspaceOptions::default(),
        )
        .unwrap();
        assert_eq!(result.resource_key().as_str(), "gksphone");
    }

    #[test]
    fn standalone_resolver_rejects_managed_workspace_baseline_root() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let err = resolve_standalone_baseline_store(workspace.baseline_store()).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn standalone_resolver_rejects_canonical_alias_to_managed_baseline_root() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let alias = workspace.baseline_store().join("..").join("baselines");
        let err = resolve_standalone_baseline_store(&alias).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[cfg(unix)]
    #[test]
    fn standalone_resolver_rejects_symlink_alias_to_managed_baseline_root() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let alias_parent = temp.path().join("alias-parent");
        fs::create_dir(&alias_parent).unwrap();
        let alias = alias_parent.join("baselines");
        symlink(workspace.baseline_store(), &alias).unwrap();
        let err = resolve_standalone_baseline_store(&alias).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[cfg(windows)]
    #[test]
    fn standalone_resolver_rejects_junction_alias_to_managed_baseline_root() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let alias_parent = temp.path().join("alias-parent");
        fs::create_dir(&alias_parent).unwrap();
        let alias = alias_parent.join("baselines");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&alias)
            .arg(workspace.baseline_store())
            .status()
            .expect("run mklink");
        assert!(status.success());
        let err = resolve_standalone_baseline_store(&alias).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn standalone_resolver_accepts_store_outside_managed_workspace() {
        let temp = tempdir().unwrap();
        let _workspace = resolve_trusted_update_workspace(&temp.path().join("managed")).unwrap();
        let standalone = temp.path().join("standalone-store");
        let store = resolve_standalone_baseline_store(&standalone).unwrap();
        assert_eq!(store.root(), standalone.canonicalize().unwrap());
    }
}

/// Private capture spool directory with cleanup ownership from first create.
struct CaptureSpoolGuard {
    tmp_root: cap_std::fs::Dir,
    name: String,
    dir: Option<cap_std::fs::Dir>,
    /// Explicit `finish` already performed cleanup (or setup cleanup).
    finished: bool,
    /// Private child may exist and must be cleaned unless `finished`.
    cleanup_required: bool,
}

enum SpoolCreateAttempt {
    Created(CaptureSpoolGuard),
    NameCollision,
}

impl CaptureSpoolGuard {
    fn create(tmp_root: &cap_std::fs::Dir) -> Result<Self> {
        for _ in 0..64_u32 {
            let name = generate_capture_spool_name();
            match Self::try_create_named(tmp_root, &name)? {
                SpoolCreateAttempt::Created(guard) => return Ok(guard),
                SpoolCreateAttempt::NameCollision => continue,
            }
        }
        Err(spool_io_failure(
            BaselineCaptureBlobSpoolStage::Allocate,
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "capture spool name allocation exhausted",
            ),
        ))
    }

    fn try_create_named(tmp_root: &cap_std::fs::Dir, name: &str) -> Result<SpoolCreateAttempt> {
        record_spool_name_attempt();
        validate_single_component(name).map_err(|error| {
            map_spool_boundary_error(BaselineCaptureBlobSpoolStage::Create, error)
        })?;
        if force_spool_create_collision_for_tests() {
            return Ok(SpoolCreateAttempt::NameCollision);
        }
        match tmp_root.create_dir(name) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                return Ok(SpoolCreateAttempt::NameCollision);
            }
            Err(source) => {
                return Err(spool_io_failure(
                    BaselineCaptureBlobSpoolStage::Create,
                    source,
                ));
            }
        }

        // Cleanup ownership begins immediately after successful create_dir.
        let tmp_owned = match tmp_root.try_clone() {
            Ok(dir) => dir,
            Err(source) => {
                let setup_error = spool_io_failure(BaselineCaptureBlobSpoolStage::Create, source);
                return Err(cleanup_created_spool_after_setup_failure(
                    tmp_root,
                    name,
                    setup_error,
                ));
            }
        };

        let mut guard = Self {
            tmp_root: tmp_owned,
            name: name.to_owned(),
            dir: None,
            finished: false,
            cleanup_required: true,
        };
        run_after_spool_child_created_hook(&guard.tmp_root, &guard.name);

        match open_and_validate_capture_spool(&guard.tmp_root, &guard.name) {
            Ok(dir) => {
                guard.dir = Some(dir);
                Ok(SpoolCreateAttempt::Created(guard))
            }
            Err(setup_error) => Err(guard.fail_setup(setup_error)),
        }
    }

    fn dir(&self) -> &cap_std::fs::Dir {
        self.dir
            .as_ref()
            .expect("capture spool guard always holds an open directory after successful create")
    }

    fn finish(
        mut self,
        capture_result: Result<BaselineCaptureResult>,
    ) -> Result<BaselineCaptureResult> {
        self.dir = None;
        run_before_spool_cleanup_hook(&self.tmp_root, &self.name);
        let cleanup_result = self.cleanup_once();
        self.finished = true;
        self.cleanup_required = false;
        match (capture_result, cleanup_result) {
            (Ok(result), Ok(())) => Ok(result),
            (Ok(_result), Err(cleanup_error)) => Err(map_cleanup_error(cleanup_error)),
            (Err(primary), Ok(())) => Err(redact_capture_error(primary)),
            (Err(primary), Err(cleanup_error)) => {
                Err(GkrmError::BaselineCaptureFailedWithCleanupFailure {
                    primary: Box::new(redact_capture_error(primary)),
                    cleanup: Box::new(map_cleanup_error(cleanup_error)),
                })
            }
        }
    }

    fn fail_setup(mut self, setup_error: GkrmError) -> GkrmError {
        self.dir = None;
        let cleanup_result = self.cleanup_once();
        self.finished = true;
        self.cleanup_required = false;
        let primary = redact_capture_error(setup_error);
        match cleanup_result {
            Ok(()) => primary,
            Err(cleanup_error) => GkrmError::BaselineCaptureFailedWithCleanupFailure {
                primary: Box::new(primary),
                cleanup: Box::new(map_cleanup_error(cleanup_error)),
            },
        }
    }

    fn cleanup_once(&mut self) -> Result<()> {
        if !self.cleanup_required {
            return Ok(());
        }
        record_spool_cleanup_attempt();
        let result = remove_capture_spool_nofollow(&self.tmp_root, &self.name);
        self.cleanup_required = false;
        result
    }
}

impl Drop for CaptureSpoolGuard {
    fn drop(&mut self) {
        if self.finished || !self.cleanup_required {
            return;
        }
        self.dir = None;
        record_spool_cleanup_attempt();
        let _ = remove_capture_spool_nofollow(&self.tmp_root, &self.name);
        self.cleanup_required = false;
    }
}

fn generate_capture_spool_name() -> String {
    static CAPTURE_SEQ: AtomicU64 = AtomicU64::new(1);
    if let Some(forced) = take_forced_spool_name_for_tests() {
        return forced;
    }
    let mut seed = [0_u8; 24];
    let attempt = CAPTURE_SEQ.fetch_add(1, Ordering::Relaxed);
    seed[0..8].copy_from_slice(&attempt.to_le_bytes());
    seed[8..16].copy_from_slice(
        &std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    seed[16..24].copy_from_slice(&(attempt.wrapping_mul(0x85eb_ca6b)).to_le_bytes());
    let digest = Sha256::digest(seed);
    format!(
        "capture-{}",
        digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn cleanup_created_spool_after_setup_failure(
    tmp_root: &cap_std::fs::Dir,
    name: &str,
    setup_error: GkrmError,
) -> GkrmError {
    record_spool_cleanup_attempt();
    let primary = redact_capture_error(setup_error);
    match remove_capture_spool_nofollow(tmp_root, name) {
        Ok(()) => primary,
        Err(cleanup_error) => GkrmError::BaselineCaptureFailedWithCleanupFailure {
            primary: Box::new(primary),
            cleanup: Box::new(map_cleanup_error(cleanup_error)),
        },
    }
}

fn open_and_validate_capture_spool(
    tmp_root: &cap_std::fs::Dir,
    name: &str,
) -> Result<cap_std::fs::Dir> {
    let dir = open_child_dir(tmp_root, name)
        .map_err(|error| map_spool_boundary_error(BaselineCaptureBlobSpoolStage::Open, error))?;
    let identity = dir_identity(&dir, "spool").map_err(|error| {
        map_spool_boundary_error(BaselineCaptureBlobSpoolStage::Validate, error)
    })?;
    drop(dir);

    run_during_spool_validation_hook(tmp_root, name)?;

    let again = open_child_dir(tmp_root, name).map_err(|error| {
        map_spool_boundary_error(BaselineCaptureBlobSpoolStage::Validate, error)
    })?;
    let identity_again = dir_identity(&again, "spool").map_err(|error| {
        map_spool_boundary_error(BaselineCaptureBlobSpoolStage::Validate, error)
    })?;
    if identity != identity_again || force_spool_identity_mismatch_for_tests() {
        return Err(spool_io_failure(
            BaselineCaptureBlobSpoolStage::Validate,
            std::io::Error::other("capture spool identity changed during setup validation"),
        ));
    }
    Ok(again)
}

fn map_cleanup_error(error: GkrmError) -> GkrmError {
    match error {
        already @ GkrmError::BaselineCaptureSpoolCleanupFailed { .. } => already,
        other => {
            let staged = match other {
                GkrmError::BaselineCaptureBlobSpoolFailure {
                    stage: BaselineCaptureBlobSpoolStage::Cleanup,
                    ..
                } => other,
                other => map_spool_boundary_error(BaselineCaptureBlobSpoolStage::Cleanup, other),
            };
            GkrmError::BaselineCaptureSpoolCleanupFailed {
                source: Box::new(redact_capture_error(staged)),
            }
        }
    }
}

fn capture_with_spool(
    request: &BaselineCaptureStoreRequest<'_>,
    _store: &OpenStoreRoot,
    spool_dir: &cap_std::fs::Dir,
    expected_package_commitment: Option<PackageSourceCommitment>,
) -> Result<BaselineCaptureResult> {
    let snapshot = PackageSnapshot::create(request.package_path, request.options.max_archive_size)
        .map_err(redact_capture_error)?;
    run_after_snapshot_created_for_capture(request.package_path);
    let fingerprint = *snapshot.fingerprint();
    let capture_commitment = PackageSourceCommitment::from_package_fingerprint(fingerprint);
    if expected_package_commitment.is_some_and(|expected| expected != capture_commitment) {
        return Err(GkrmError::BaselineCapturePackageChanged);
    }

    let inspection = inspect_zip_snapshot(&snapshot, request.options.package_limits)
        .map_err(redact_capture_error)?;
    let discovery = discover_zip_resources(&inspection).map_err(redact_capture_error)?;
    let (selected, mut warnings) = select_resource(
        &discovery,
        &request.resource_selector,
        &request.resource_key,
    )?;

    let parsed = parse_selected_zip_resource_manifest_from_snapshot(
        &snapshot,
        &inspection,
        selected,
        request.options.manifest_limits,
    )
    .map_err(redact_capture_error)?;
    let (resource_version, version_warning) = extract_manifest_version(&parsed.manifest);
    if let Some(warning) = version_warning {
        warnings.push(warning);
    }

    let classified = classify_selected_zip_resource_escrow(&inspection, selected, &parsed)
        .map_err(redact_capture_error)?;

    let resource_label = resource_display_label(selected, &request.resource_key);
    let (files, blob_sizes, spool_provider) = inventory_hash_and_spool(
        &snapshot,
        &inspection,
        selected,
        &classified,
        spool_dir,
        &request.options,
    )?;

    let bundle = ValidatedBaselineBundle::try_from_parts(
        request.resource_key.clone(),
        resource_label.clone(),
        resource_version.clone(),
        Some(fingerprint),
        files,
        blob_sizes,
        request.options.baseline_store_limits,
    )
    .map_err(|source| {
        redact_capture_error(GkrmError::BaselineCaptureBundleConstruction {
            source: Box::new(source),
        })
    })?;

    run_before_publish_hook()?;

    let locator = write_baseline_bundle(
        request.store_root,
        &bundle,
        &spool_provider,
        request.options.baseline_store_limits,
    )
    .map_err(redact_capture_error)?;

    Ok(BaselineCaptureResult {
        locator,
        resource_label,
        resource_version,
        source_package_fingerprint: fingerprint,
        counts: bundle.counts().clone(),
        warnings,
    })
}

fn select_resource<'a>(
    discovery: &'a ZipResourceDiscovery,
    selector: &IncomingResourceSelector,
    resource_key: &SafeResourceKey,
) -> Result<(&'a DiscoveredZipResource, Vec<BaselineCaptureWarning>)> {
    match selector {
        IncomingResourceSelector::AutoSingle => match discovery.resources.as_slice() {
            [] => Err(GkrmError::BaselineCaptureNoResources),
            [single] => {
                let mut warnings = Vec::new();
                if matches!(single.name, ZipResourceName::ZipRoot) {
                    warnings.push(BaselineCaptureWarning::RootResourceSelected);
                    let _ = resource_key;
                }
                Ok((single, warnings))
            }
            _many => Err(GkrmError::BaselineCaptureAmbiguousResources),
        },
        IncomingResourceSelector::ManifestPackagePath(path) => {
            let matches: Vec<_> = discovery
                .resources
                .iter()
                .filter(|resource| resource.manifest_path.as_str() == path.as_str())
                .collect();
            match matches.as_slice() {
                [] => Err(GkrmError::BaselineCaptureResourceNotFound),
                [single] => {
                    let mut warnings = Vec::new();
                    if matches!(single.name, ZipResourceName::ZipRoot) {
                        warnings.push(BaselineCaptureWarning::RootResourceSelected);
                    }
                    Ok((*single, warnings))
                }
                _ => Err(GkrmError::BaselineCaptureResourceAmbiguous),
            }
        }
    }
}

fn resource_display_label(resource: &DiscoveredZipResource, key: &SafeResourceKey) -> String {
    match &resource.name {
        ZipResourceName::Directory(name) => name.clone(),
        ZipResourceName::ZipRoot => key.as_str().to_owned(),
    }
}

fn extract_manifest_version(
    manifest: &FxManifest,
) -> (Option<String>, Option<BaselineCaptureWarning>) {
    match manifest.versions.as_slice() {
        [single] => (Some(single.value.clone()), None),
        [] => (
            None,
            Some(BaselineCaptureWarning::ManifestVersionUnavailable),
        ),
        _ => (
            None,
            Some(BaselineCaptureWarning::ManifestVersionUnavailable),
        ),
    }
}

struct SpoolBlobProvider {
    spool_dir: cap_std::fs::Dir,
    sizes: BTreeMap<Sha256Digest, u64>,
}

impl VerifiedBaselineBlobProvider for SpoolBlobProvider {
    fn open_verified_blob(&self, digest: &Sha256Digest) -> Result<VerifiedBlobReader> {
        run_before_provider_open_hook(digest)?;
        let size = self
            .sizes
            .get(digest)
            .copied()
            .ok_or(GkrmError::BaselineCaptureIgnoredBlobMissing)?;
        let name = digest.to_string();
        let file = open_file_nofollow(&self.spool_dir, &name).map_err(|error| match error {
            GkrmError::BaselineStoreMissing { .. } => GkrmError::BaselineCaptureIgnoredBlobMissing,
            GkrmError::BaselineStoreIo { cause, .. } => {
                GkrmError::BaselineCaptureStoreFailure { kind: cause.kind() }
            }
            other => redact_capture_error(other),
        })?;
        let identity = capture_file_identity(&file, &name)?;
        Ok(VerifiedBlobReader::from_cap_file(
            *digest, size, file, identity, name,
        ))
    }
}

fn inventory_hash_and_spool(
    snapshot: &PackageSnapshot,
    inspection: &ZipInspection,
    resource: &DiscoveredZipResource,
    classified: &ClassifiedZipResource,
    spool_dir: &cap_std::fs::Dir,
    options: &BaselineCaptureOptions,
) -> Result<(
    Vec<BaselineFileRecord>,
    BTreeMap<Sha256Digest, u64>,
    SpoolBlobProvider,
)> {
    let class_by_package: BTreeMap<&str, &ClassifiedResourceFile> = classified
        .files
        .iter()
        .map(|file| (file.package_path.as_str(), file))
        .collect();

    let mut seen_paths = BTreeSet::new();
    let mut seen_indexes = BTreeSet::new();
    let mut selected_entries: Vec<(&ZipEntryInfo, &ClassifiedResourceFile)> = Vec::new();
    let mut total_bytes = 0_u64;

    for entry in &resource.entries {
        if entry.kind != ZipEntryKind::File {
            continue;
        }
        if !seen_indexes.insert(entry.archive_index) {
            return Err(GkrmError::BaselineCaptureDuplicateArchiveEntry);
        }
        let inspected = inspection
            .entries
            .iter()
            .find(|candidate| candidate.archive_index == entry.archive_index)
            .ok_or(GkrmError::BaselineCaptureDuplicateArchiveEntry)?;
        if inspected.path != entry.path
            || inspected.uncompressed_size != entry.uncompressed_size
            || inspected.crc32 != entry.crc32
        {
            return Err(GkrmError::BaselineCaptureInconsistentEscrowClassification);
        }
        let classified_file = class_by_package
            .get(entry.path.as_str())
            .ok_or(GkrmError::BaselineCaptureMissingEscrowClassification)?;
        let relative = resource_relative_path(&resource.root, entry)?;
        if !seen_paths.insert(relative.as_str().to_owned()) {
            return Err(GkrmError::BaselineCaptureDuplicateFilePath);
        }
        total_bytes = total_bytes.checked_add(entry.uncompressed_size).ok_or(
            GkrmError::BaselineCaptureSelectedByteLimit {
                limit: options.max_selected_uncompressed_bytes,
                actual: u64::MAX,
            },
        )?;
        selected_entries.push((entry, *classified_file));
    }

    if selected_entries.is_empty() {
        return Err(GkrmError::BaselineCaptureEmptyResource);
    }
    if selected_entries.len() > options.max_selected_files {
        return Err(GkrmError::BaselineCaptureSelectedFileLimit {
            limit: options.max_selected_files,
            actual: selected_entries.len(),
        });
    }
    if total_bytes > options.max_selected_uncompressed_bytes {
        return Err(GkrmError::BaselineCaptureSelectedByteLimit {
            limit: options.max_selected_uncompressed_bytes,
            actual: total_bytes,
        });
    }
    if classified.files.len() != selected_entries.len() {
        return Err(GkrmError::BaselineCaptureInconsistentEscrowClassification);
    }

    selected_entries.sort_by(|left, right| {
        left.1
            .resource_relative_path
            .cmp(&right.1.resource_relative_path)
    });

    let mut archive = snapshot.open_zip_archive().map_err(redact_capture_error)?;
    let mut files = Vec::with_capacity(selected_entries.len());
    let mut blob_sizes = BTreeMap::new();
    let mut unique_blob_bytes = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_SIZE];
    let spool_budget = temporary_spool_budget(
        options.baseline_store_limits.max_total_blob_bytes(),
        options.baseline_store_limits.max_blob_bytes(),
    )?;

    for (entry, classified_file) in selected_entries {
        let relative =
            ResourceRelativePath::try_from_slash_str(&classified_file.resource_relative_path)?;
        let escrow = map_escrow(&classified_file.classification);
        // Escrow cannot encrypt this file, so the operator may well have edited it — a settings
        // JSON, an app icon they swapped. What the official package held of it is the only thing
        // that can later tell their edit from the developer's, and for a document a line merge
        // cannot line up it is the only thing that can combine the two at all. Kept only up to
        // what a merge will ever read of one file: past that it is weight for nothing.
        let retain_unsupported = escrow == BaselineEscrowClass::NotSupported
            && entry.uncompressed_size <= MAX_MERGEABLE_BLOB_BYTES;
        let (digest, size) = match escrow {
            BaselineEscrowClass::Protected => {
                let digest = hash_zip_entry_exact(&mut archive, entry, &mut buffer)?;
                (digest, entry.uncompressed_size)
            }
            BaselineEscrowClass::NotSupported if !retain_unsupported => {
                let digest = hash_zip_entry_exact(&mut archive, entry, &mut buffer)?;
                (digest, entry.uncompressed_size)
            }
            BaselineEscrowClass::Ignored | BaselineEscrowClass::NotSupported => {
                let (digest, size) = hash_and_spool_zip_entry(
                    &mut archive,
                    entry,
                    &relative,
                    spool_dir,
                    &mut buffer,
                    options.baseline_store_limits.max_blob_bytes(),
                    options.baseline_store_limits.max_total_blob_bytes(),
                    spool_budget,
                    &blob_sizes,
                    &mut unique_blob_bytes,
                )?;
                blob_sizes.insert(digest, size);
                (digest, size)
            }
        };
        if size != entry.uncompressed_size {
            return Err(GkrmError::BaselineCaptureEntrySizeMismatch {
                expected: entry.uncompressed_size,
                actual: size,
            });
        }
        let blob_sha256 = match escrow {
            BaselineEscrowClass::Ignored => Some(digest),
            BaselineEscrowClass::NotSupported if retain_unsupported => Some(digest),
            BaselineEscrowClass::Protected | BaselineEscrowClass::NotSupported => None,
        };
        files.push(make_file_record(
            relative,
            size,
            digest,
            escrow,
            blob_sha256,
        ));
    }

    note_production_blob_map_shape(&blob_sizes);

    let provider = SpoolBlobProvider {
        spool_dir: spool_dir
            .try_clone()
            .map_err(|source| spool_io_failure(BaselineCaptureBlobSpoolStage::Open, source))?,
        sizes: blob_sizes.clone(),
    };
    Ok((files, blob_sizes, provider))
}

/// Peak temporary spool bytes while one ignored entry is in flight:
/// `max_total_blob_bytes + max_blob_bytes`.
fn temporary_spool_budget(max_total: u64, max_blob: u64) -> Result<u64> {
    max_total
        .checked_add(max_blob)
        .ok_or(GkrmError::BaselineCaptureSpoolBudgetExceeded {
            limit: u64::MAX,
            actual: u64::MAX,
        })
}

fn map_escrow(classification: &EscrowFileClassification) -> BaselineEscrowClass {
    match classification {
        EscrowFileClassification::Protected => BaselineEscrowClass::Protected,
        EscrowFileClassification::Ignored { .. } => BaselineEscrowClass::Ignored,
        EscrowFileClassification::NotSupported { .. } => BaselineEscrowClass::NotSupported,
    }
}

fn resource_relative_path(
    root: &ZipResourceRoot,
    entry: &ZipEntryInfo,
) -> Result<ResourceRelativePath> {
    let relative = match root {
        ZipResourceRoot::Root => entry.path.as_str().to_owned(),
        ZipResourceRoot::Path(root_path) => entry
            .path
            .as_str()
            .strip_prefix(root_path.as_str())
            .and_then(|suffix| suffix.strip_prefix('/'))
            .filter(|suffix| !suffix.is_empty())
            .map(str::to_owned)
            .ok_or(GkrmError::BaselineCaptureUnsafeResourceIdentity)?,
    };
    ResourceRelativePath::try_from_slash_str(&relative)
}

fn hash_zip_entry_exact<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    expected: &ZipEntryInfo,
    buffer: &mut [u8],
) -> Result<Sha256Digest> {
    verify_zip_entry_metadata(archive, expected)?;
    record_zip_entry_open(expected.archive_index);
    let mut entry = archive.by_index(expected.archive_index).map_err(|source| {
        GkrmError::BaselineCaptureEntryReadFailure {
            kind: std::io::Error::other(source).kind(),
        }
    })?;
    stream_hash_exact(
        &mut entry,
        expected.uncompressed_size,
        buffer,
        expected.path.as_str(),
    )
}

#[allow(clippy::too_many_arguments)]
fn hash_and_spool_zip_entry<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    expected: &ZipEntryInfo,
    _relative_path: &ResourceRelativePath,
    spool_dir: &cap_std::fs::Dir,
    buffer: &mut [u8],
    max_blob_bytes: u64,
    max_total_blob_bytes: u64,
    spool_budget: u64,
    existing: &BTreeMap<Sha256Digest, u64>,
    unique_blob_bytes: &mut u64,
) -> Result<(Sha256Digest, u64)> {
    if expected.uncompressed_size > max_blob_bytes {
        return Err(GkrmError::BaselineCaptureBlobSizeLimitExceeded {
            limit: max_blob_bytes,
            actual: expected.uncompressed_size,
        });
    }
    verify_zip_entry_metadata(archive, expected)?;
    record_zip_entry_open(expected.archive_index);
    let mut entry = archive.by_index(expected.archive_index).map_err(|source| {
        GkrmError::BaselineCaptureEntryReadFailure {
            kind: std::io::Error::other(source).kind(),
        }
    })?;

    run_ignored_entry_open_hook(expected.archive_index)?;
    run_before_partial_spool_create_hook()?;

    let (temp_name, mut file) = create_partial_spool_file(spool_dir)?;

    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    loop {
        let read =
            entry
                .read(buffer)
                .map_err(|source| GkrmError::BaselineCaptureEntryReadFailure {
                    kind: source.kind(),
                })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.checked_add(read as u64).ok_or(
            GkrmError::BaselineCaptureEntrySizeMismatch {
                expected: expected.uncompressed_size,
                actual: u64::MAX,
            },
        )?;
        if bytes_read > expected.uncompressed_size {
            let _ = spool_dir.remove_file(&temp_name);
            return Err(GkrmError::BaselineCaptureEntrySizeMismatch {
                expected: expected.uncompressed_size,
                actual: bytes_read,
            });
        }
        let projected = unique_blob_bytes.checked_add(bytes_read).ok_or(
            GkrmError::BaselineCaptureSpoolBudgetExceeded {
                limit: spool_budget,
                actual: u64::MAX,
            },
        )?;
        if projected > spool_budget {
            let _ = spool_dir.remove_file(&temp_name);
            return Err(GkrmError::BaselineCaptureSpoolBudgetExceeded {
                limit: spool_budget,
                actual: projected,
            });
        }
        hasher.update(&buffer[..read]);
        file.write_all(&buffer[..read]).map_err(|source| {
            let _ = spool_dir.remove_file(&temp_name);
            spool_io_failure(BaselineCaptureBlobSpoolStage::Write, source)
        })?;
        run_during_ignored_spool_write_hook()?;
    }
    if bytes_read != expected.uncompressed_size {
        let _ = spool_dir.remove_file(&temp_name);
        return Err(GkrmError::BaselineCaptureEntrySizeMismatch {
            expected: expected.uncompressed_size,
            actual: bytes_read,
        });
    }
    file.flush().map_err(|source| {
        let _ = spool_dir.remove_file(&temp_name);
        spool_io_failure(BaselineCaptureBlobSpoolStage::Flush, source)
    })?;
    drop(file);

    let digest = Sha256Digest::new(hasher.finalize().into());
    if let Some(existing_size) = existing.get(&digest) {
        if *existing_size != bytes_read {
            let _ = spool_dir.remove_file(&temp_name);
            return Err(GkrmError::BaselineCaptureIgnoredBlobSizeMismatch {
                expected: *existing_size,
                actual: bytes_read,
            });
        }
        let _ = spool_dir.remove_file(&temp_name);
        run_after_ignored_spooled_hook(&digest, spool_dir)?;
        return Ok((digest, bytes_read));
    }

    let next_unique = unique_blob_bytes.checked_add(bytes_read).ok_or(
        GkrmError::BaselineCaptureTotalBlobLimitExceeded {
            limit: max_total_blob_bytes,
            actual: u64::MAX,
        },
    )?;
    if next_unique > max_total_blob_bytes {
        let _ = spool_dir.remove_file(&temp_name);
        return Err(GkrmError::BaselineCaptureTotalBlobLimitExceeded {
            limit: max_total_blob_bytes,
            actual: next_unique,
        });
    }

    let final_name = digest.to_string();
    match spool_dir.rename(&temp_name, spool_dir, &final_name) {
        Ok(()) => {
            *unique_blob_bytes = next_unique;
            run_after_ignored_spooled_hook(&digest, spool_dir)?;
            Ok((digest, bytes_read))
        }
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = spool_dir.remove_file(&temp_name);
            verify_existing_spool_blob(spool_dir, &digest, bytes_read, buffer)?;
            if next_unique > max_total_blob_bytes {
                return Err(GkrmError::BaselineCaptureTotalBlobLimitExceeded {
                    limit: max_total_blob_bytes,
                    actual: next_unique,
                });
            }
            if !existing.contains_key(&digest) {
                *unique_blob_bytes = next_unique;
            }
            run_after_ignored_spooled_hook(&digest, spool_dir)?;
            Ok((digest, bytes_read))
        }
        Err(source) => {
            let _ = spool_dir.remove_file(&temp_name);
            Err(spool_io_failure(
                BaselineCaptureBlobSpoolStage::Rename,
                source,
            ))
        }
    }
}

/// Create a private spool temp file with an unpredictable capability-local name.
///
/// Names never embed archive indexes, ZIP paths, digests, or ambient paths.
fn create_partial_spool_file(spool_dir: &cap_std::fs::Dir) -> Result<(String, cap_std::fs::File)> {
    static PARTIAL_SEQ: AtomicU64 = AtomicU64::new(1);

    for attempt in 0..64_u32 {
        let mut seed = [0_u8; 24];
        seed[0..4].copy_from_slice(&attempt.to_le_bytes());
        seed[4..12].copy_from_slice(
            &std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos() as u64)
                .unwrap_or(0)
                .to_le_bytes(),
        );
        seed[12..20].copy_from_slice(&PARTIAL_SEQ.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        seed[20..24].copy_from_slice(&attempt.wrapping_mul(0xc2b2_ae35).to_le_bytes());
        let digest = Sha256::digest(seed);
        let name = format!(
            ".p-{}",
            digest
                .iter()
                .take(8)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        match create_new_file(spool_dir, &name) {
            Ok(file) => return Ok((name, file)),
            Err(GkrmError::BaselineStoreIo { cause: source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(error) => {
                return Err(map_spool_boundary_error(
                    BaselineCaptureBlobSpoolStage::Create,
                    error,
                ));
            }
        }
    }
    Err(spool_io_failure(
        BaselineCaptureBlobSpoolStage::Create,
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "capture spool temporary name allocation exhausted",
        ),
    ))
}

fn verify_existing_spool_blob(
    spool_dir: &cap_std::fs::Dir,
    digest: &Sha256Digest,
    expected_size: u64,
    buffer: &mut [u8],
) -> Result<()> {
    let name = digest.to_string();
    let mut file = open_file_nofollow(spool_dir, &name)
        .map_err(|_| GkrmError::BaselineCaptureSpoolVerificationFailure)?;
    let before = capture_file_identity(&file, &name)?;
    let meta = file
        .metadata()
        .map_err(|source| spool_io_failure(BaselineCaptureBlobSpoolStage::Open, source))?;
    if meta.len() != expected_size {
        return Err(GkrmError::BaselineCaptureIgnoredBlobSizeMismatch {
            expected: expected_size,
            actual: meta.len(),
        });
    }

    run_during_existing_spool_verify_hook(digest, spool_dir)?;

    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    loop {
        let read = file
            .read(buffer)
            .map_err(|source| spool_io_failure(BaselineCaptureBlobSpoolStage::Open, source))?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.checked_add(read as u64).ok_or(
            GkrmError::BaselineCaptureIgnoredBlobSizeMismatch {
                expected: expected_size,
                actual: u64::MAX,
            },
        )?;
        if bytes_read > expected_size {
            return Err(GkrmError::BaselineCaptureIgnoredBlobSizeMismatch {
                expected: expected_size,
                actual: bytes_read,
            });
        }
        hasher.update(&buffer[..read]);
    }
    if bytes_read != expected_size {
        return Err(GkrmError::BaselineCaptureIgnoredBlobSizeMismatch {
            expected: expected_size,
            actual: bytes_read,
        });
    }

    let after = capture_file_identity(&file, &name)?;
    if before != after {
        return Err(GkrmError::BaselineCaptureSpoolIdentityChanged);
    }

    let actual = Sha256Digest::new(hasher.finalize().into());
    if actual != *digest {
        return Err(GkrmError::BaselineCaptureSpoolVerificationFailure);
    }
    Ok(())
}

fn verify_zip_entry_metadata<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    expected: &ZipEntryInfo,
) -> Result<()> {
    let entry = archive
        .by_index_raw(expected.archive_index)
        .map_err(|source| GkrmError::BaselineCaptureEntryReadFailure {
            kind: std::io::Error::other(source).kind(),
        })?;
    let actual_path = ZipRelativePath::new(expected.archive_index, entry.name_raw())
        .map_err(|_| GkrmError::BaselineCaptureUnsafeResourceIdentity)?;
    let actual_kind = if entry.is_dir() {
        ZipEntryKind::Directory
    } else {
        ZipEntryKind::File
    };
    if actual_path != expected.path
        || actual_kind != expected.kind
        || entry.compressed_size() != expected.compressed_size
        || entry.size() != expected.uncompressed_size
        || entry.crc32() != expected.crc32
        || entry.compression() != expected.compression_method
        || entry.encrypted() != expected.encrypted
        || entry.unix_mode() != expected.unix_mode
    {
        return Err(GkrmError::BaselineCaptureInconsistentEscrowClassification);
    }
    Ok(())
}

fn stream_hash_exact<R: Read>(
    reader: &mut R,
    expected_size: u64,
    buffer: &mut [u8],
    _path: &str,
) -> Result<Sha256Digest> {
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    loop {
        let read =
            reader
                .read(buffer)
                .map_err(|source| GkrmError::BaselineCaptureEntryReadFailure {
                    kind: source.kind(),
                })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.checked_add(read as u64).ok_or(
            GkrmError::BaselineCaptureEntrySizeMismatch {
                expected: expected_size,
                actual: u64::MAX,
            },
        )?;
        if bytes_read > expected_size {
            return Err(GkrmError::BaselineCaptureEntrySizeMismatch {
                expected: expected_size,
                actual: bytes_read,
            });
        }
        hasher.update(&buffer[..read]);
    }
    if bytes_read != expected_size {
        return Err(GkrmError::BaselineCaptureEntrySizeMismatch {
            expected: expected_size,
            actual: bytes_read,
        });
    }
    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn spool_io_failure(stage: BaselineCaptureBlobSpoolStage, source: std::io::Error) -> GkrmError {
    GkrmError::BaselineCaptureBlobSpoolFailure {
        stage,
        kind: source.kind(),
    }
}

/// Map any private-spool boundary failure to a path-free capture spool error.
fn map_spool_boundary_error(stage: BaselineCaptureBlobSpoolStage, error: GkrmError) -> GkrmError {
    match error {
        already @ GkrmError::BaselineCaptureBlobSpoolFailure { .. } => already,
        GkrmError::BaselineStoreIo { cause: source, .. } => spool_io_failure(stage, source),
        other => spool_io_failure(stage, std::io::Error::other(other)),
    }
}

fn is_private_capture_spool_component(component: &str) -> bool {
    component.starts_with(".p-")
        || component.starts_with(".partial-")
        || component.starts_with("capture-")
}

fn redact_capture_error(error: GkrmError) -> GkrmError {
    // redact_capture_error intentionally uses an exhaustive match.
    // Adding a GkrmError variant must require an explicit capture-redaction decision.
    // Do not add a wildcard fallback.
    use crate::BaselineCaptureArchiveLimitKind as LimitKind;
    use crate::BaselineCaptureUnsafeEntryKind as UnsafeKind;

    match error {
        // --- Private spool-component boundary failures ---
        GkrmError::BaselineStoreIo {
            cause: source,
            component,
        } if is_private_capture_spool_component(&component) => {
            spool_io_failure(BaselineCaptureBlobSpoolStage::Create, source)
        }
        GkrmError::BaselineStoreUnexpectedType { component }
            if is_private_capture_spool_component(&component) =>
        {
            map_spool_boundary_error(
                BaselineCaptureBlobSpoolStage::Create,
                GkrmError::BaselineStoreUnexpectedType { component },
            )
        }
        GkrmError::BaselineStoreHardLink { component }
            if is_private_capture_spool_component(&component) =>
        {
            map_spool_boundary_error(
                BaselineCaptureBlobSpoolStage::Create,
                GkrmError::BaselineStoreHardLink { component },
            )
        }
        GkrmError::BaselineStoreSymlink { component }
            if is_private_capture_spool_component(&component) =>
        {
            map_spool_boundary_error(
                BaselineCaptureBlobSpoolStage::Create,
                GkrmError::BaselineStoreSymlink { component },
            )
        }
        GkrmError::BaselineStoreReparsePoint { component }
            if is_private_capture_spool_component(&component) =>
        {
            map_spool_boundary_error(
                BaselineCaptureBlobSpoolStage::Create,
                GkrmError::BaselineStoreReparsePoint { component },
            )
        }
        GkrmError::BaselineStoreUnsafeComponent { component }
            if is_private_capture_spool_component(&component) =>
        {
            map_spool_boundary_error(
                BaselineCaptureBlobSpoolStage::Create,
                GkrmError::BaselineStoreUnsafeComponent { component },
            )
        }
        GkrmError::BaselineStoreMissing { component }
            if is_private_capture_spool_component(&component) =>
        {
            map_spool_boundary_error(
                BaselineCaptureBlobSpoolStage::Create,
                GkrmError::BaselineStoreMissing { component },
            )
        }

        // --- Package / ZIP / comparison archive failures ---
        GkrmError::ComparisonPackageOpen { cause: source, .. }
        | GkrmError::ComparisonPackageMetadata { cause: source, .. }
        | GkrmError::ComparisonPackageHashRead { cause: source, .. }
        | GkrmError::ComparisonPackageTimestampUnavailable { cause: source, .. }
        | GkrmError::ComparisonPackageIdentityUnavailable { cause: source, .. }
        | GkrmError::ZipPackageOpen { cause: source, .. }
        | GkrmError::ManifestZipOpen { cause: source, .. }
        | GkrmError::PackagePathMetadata { cause: source, .. } => {
            GkrmError::BaselineCapturePackageOpen {
                kind: source.kind(),
            }
        }
        GkrmError::ZipEntryStream { cause: source, .. }
        | GkrmError::ManifestRead { cause: source, .. }
        | GkrmError::ComparisonZipEntryStream { cause: source, .. } => {
            GkrmError::BaselineCaptureArchiveEntryStream {
                kind: source.kind(),
            }
        }
        GkrmError::ZipArchiveRead { .. }
        | GkrmError::ManifestZipArchiveRead { .. }
        | GkrmError::ComparisonZipArchiveRead { .. } => GkrmError::BaselineCaptureArchiveInvalid,
        GkrmError::ZipEntryRead { .. }
        | GkrmError::ManifestZipEntryRead { .. }
        | GkrmError::ComparisonZipEntryRead { .. } => GkrmError::BaselineCaptureArchiveEntryRead,
        GkrmError::ComparisonZipEntryStreamSizeMismatch {
            expected, actual, ..
        }
        | GkrmError::ZipEntryStreamSizeMismatch {
            expected, actual, ..
        } => GkrmError::BaselineCaptureArchiveEntrySizeMismatch { expected, actual },
        GkrmError::ComparisonDuplicateIncomingArchiveIndex { .. } => {
            GkrmError::BaselineCaptureDuplicateArchiveEntry
        }
        GkrmError::ZipEntryDuplicatePath { .. } => GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: UnsafeKind::DuplicatePath,
        },
        GkrmError::ComparisonPackageSymlink { .. } => GkrmError::BaselineCapturePackageSymlink,
        GkrmError::ComparisonPackageReparsePoint { .. } => {
            GkrmError::BaselineCapturePackageReparsePoint
        }
        GkrmError::ComparisonPackageNotFile { .. }
        | GkrmError::PackagePathMissing { .. }
        | GkrmError::PackagePathNotFile { .. }
        | GkrmError::PackagePathNotZip { .. } => GkrmError::BaselineCapturePackagePathInvalid,
        GkrmError::ComparisonPackageChanged { .. }
        | GkrmError::ComparisonPackageArchiveSizeMismatch { .. } => {
            GkrmError::BaselineCapturePackageChanged
        }
        GkrmError::ComparisonArchiveSizeLimitExceeded { limit, actual, .. }
        | GkrmError::BaselineCaptureArchiveSizeLimit { limit, actual } => {
            GkrmError::BaselineCaptureArchiveLimitExceeded {
                kind: LimitKind::ArchiveFileSize,
                limit,
                actual,
            }
        }
        GkrmError::ZipEntrySymlink { .. } => GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: UnsafeKind::Symlink,
        },
        GkrmError::ZipEntryEncrypted { .. } => GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: UnsafeKind::Encrypted,
        },
        GkrmError::ZipEntryUnsupportedCompression { .. } => {
            GkrmError::BaselineCaptureUnsafeZipEntry {
                kind: UnsafeKind::UnsupportedCompression,
            }
        }
        GkrmError::ZipEntryParentTraversal { .. } => GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: UnsafeKind::ParentTraversal,
        },
        GkrmError::ZipEntryUnixAbsolutePath { .. }
        | GkrmError::ZipEntryWindowsDrivePath { .. }
        | GkrmError::ZipEntryUncPath { .. }
        | GkrmError::ZipEntryWindowsRootPath { .. } => GkrmError::BaselineCaptureUnsafeZipEntry {
            kind: UnsafeKind::AbsoluteOrDrivePath,
        },
        GkrmError::ZipEntryControlCharacter { .. }
        | GkrmError::ZipEntryEmptyComponent { .. }
        | GkrmError::ZipEntryCurrentDirectory { .. }
        | GkrmError::ZipEntryWindowsInvalidCharacter { .. }
        | GkrmError::ZipEntryWindowsTrailingDotOrSpace { .. }
        | GkrmError::ZipEntryWindowsReservedName { .. } => {
            GkrmError::BaselineCaptureUnsafeZipEntry {
                kind: UnsafeKind::InvalidPath,
            }
        }
        GkrmError::ZipEntryNameInvalidUtf8 { .. } | GkrmError::ZipEntryPathEmpty { .. } => {
            GkrmError::BaselineCaptureUnsafeZipEntry {
                kind: UnsafeKind::EmptyOrInvalidName,
            }
        }
        GkrmError::ZipEntryCaseInsensitiveCollision { .. } => {
            GkrmError::BaselineCaptureUnsafeZipEntry {
                kind: UnsafeKind::CaseInsensitiveCollision,
            }
        }
        GkrmError::ZipDirectoryEntryNonZeroSize { .. } => {
            GkrmError::BaselineCaptureUnsafeZipEntry {
                kind: UnsafeKind::DirectoryNonZeroSize,
            }
        }
        GkrmError::ZipEntryCountLimitExceeded { limit, actual } => {
            GkrmError::BaselineCaptureArchiveLimitExceeded {
                kind: LimitKind::EntryCount,
                limit: limit as u64,
                actual: actual as u64,
            }
        }
        GkrmError::ZipEntrySizeLimitExceeded { limit, actual, .. } => {
            GkrmError::BaselineCaptureArchiveEntryLimitExceeded {
                kind: LimitKind::EntryUncompressedSize,
                limit,
                actual,
            }
        }
        GkrmError::ZipTotalSizeLimitExceeded { limit, actual } => {
            GkrmError::BaselineCaptureArchiveLimitExceeded {
                kind: LimitKind::TotalUncompressedSize,
                limit,
                actual,
            }
        }
        GkrmError::ZipCompressionRatioLimitExceeded {
            limit,
            uncompressed_size,
            ..
        } => GkrmError::BaselineCaptureArchiveEntryLimitExceeded {
            kind: LimitKind::CompressionRatio,
            limit,
            actual: uncompressed_size,
        },
        GkrmError::ManifestZipEntryChanged { .. }
        | GkrmError::ComparisonZipEntryChanged { .. }
        | GkrmError::ZipResourceDuplicateManifest { .. } => {
            GkrmError::BaselineCaptureArchiveEntryInconsistent
        }

        // --- Escrow / manifest / baseline identity mappings ---
        GkrmError::EscrowManifestMissing { .. } => GkrmError::BaselineCaptureEscrowManifestInvalid,
        GkrmError::EscrowManifestDuplicate { .. } => {
            GkrmError::BaselineCaptureEscrowManifestInvalid
        }
        GkrmError::EscrowManifestRootMismatch { .. } => {
            GkrmError::BaselineCaptureEscrowManifestInvalid
        }
        GkrmError::EscrowManifestPathMismatch { .. } => {
            GkrmError::BaselineCaptureEscrowManifestInvalid
        }
        GkrmError::EscrowResourceRelativePath { .. } => {
            GkrmError::BaselineCaptureEscrowResourcePathInvalid
        }
        GkrmError::EscrowDiscoveryEntryMismatch { .. } => {
            GkrmError::BaselineCaptureArchiveEntryInconsistent
        }
        GkrmError::EscrowGlobUnsafe { .. } => GkrmError::BaselineCaptureEscrowGlobInvalid,
        GkrmError::EscrowGlobTrailingSlash { .. } => GkrmError::BaselineCaptureEscrowGlobInvalid,
        GkrmError::EscrowGlobMalformed { .. } => GkrmError::BaselineCaptureEscrowGlobInvalid,
        GkrmError::BaselineUnsafeRelativePath { .. } => GkrmError::BaselineCaptureBundlePathInvalid,
        GkrmError::BaselineDuplicateFilePath { .. } => GkrmError::BaselineCaptureBundlePathInvalid,
        GkrmError::BaselineInvalidOrdering { .. } => {
            GkrmError::BaselineCaptureBundleOrderingInvalid
        }
        GkrmError::BaselineUnexpectedBlob { .. } => GkrmError::BaselineCaptureBundleBlobInvalid,
        GkrmError::BaselineBlobLimitExceeded { .. } => GkrmError::BaselineCaptureBundleBlobInvalid,
        GkrmError::BaselineInvalidHash { .. } => GkrmError::BaselineCaptureBundleBlobInvalid,
        GkrmError::BaselineInvalidId { .. } => GkrmError::BaselineCaptureBundleIdentityMismatch,
        GkrmError::BaselineIdMismatch { .. } => GkrmError::BaselineCaptureBundleIdentityMismatch,
        GkrmError::BaselineRequestedIdMismatch { .. } => {
            GkrmError::BaselineCaptureBundleIdentityMismatch
        }
        GkrmError::BaselineUnsafeResourceKey { .. } => {
            GkrmError::BaselineCaptureBundleIdentityMismatch
        }
        GkrmError::BaselineResourceKeyMismatch { .. } => {
            GkrmError::BaselineCaptureBundleIdentityMismatch
        }
        GkrmError::ManifestLuaSyntax { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestInvalidStringEscape { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestInvalidUtf8 { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestEntryMissing { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestEntryNotFile { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestSizeLimitExceeded { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestTokenLimitExceeded { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::ManifestParserPanic { .. } => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::BaselineExistingConflict { .. } => GkrmError::BaselineCaptureBaselineConflict,
        GkrmError::BaselineSelectedBaselineNotFound { .. } => {
            GkrmError::BaselineCaptureBaselineConflict
        }
        GkrmError::BaselineMultipleValidBaselinesRequireExactSelection { .. } => {
            GkrmError::BaselineCaptureBaselineConflict
        }
        GkrmError::BaselineMissingBlob { .. } => GkrmError::BaselineCaptureBlobVerificationFailed,
        GkrmError::BaselineBlobDigestMismatch { .. } => {
            GkrmError::BaselineCaptureBlobVerificationFailed
        }
        GkrmError::BaselineBlobSizeMismatch { .. } => {
            GkrmError::BaselineCaptureBlobVerificationFailed
        }
        GkrmError::BaselineInconsistentEscrowBlob { .. } => {
            GkrmError::BaselineCaptureBlobVerificationFailed
        }
        GkrmError::BaselineIncompleteBundle { .. } => {
            GkrmError::BaselineCaptureBlobVerificationFailed
        }

        GkrmError::BaselineStoreIo { cause: source, .. } => {
            GkrmError::BaselineCaptureStoreFailure {
                kind: source.kind(),
            }
        }
        GkrmError::BaselineStoreUnexpectedType { .. }
        | GkrmError::BaselineStoreHardLink { .. }
        | GkrmError::BaselineStoreSymlink { .. }
        | GkrmError::BaselineStoreReparsePoint { .. }
        | GkrmError::BaselineStoreUnsafeComponent { .. }
        | GkrmError::BaselineStoreMissing { .. } => GkrmError::BaselineCaptureStoreFailure {
            kind: std::io::ErrorKind::Other,
        },
        GkrmError::BaselineAtomicPublishFailure { cause } => {
            GkrmError::BaselineCapturePublicationFailed { kind: cause.kind() }
        }

        // --- Nested GkrmError wrappers ---
        GkrmError::BaselineCaptureBundleConstruction { source } => {
            GkrmError::BaselineCaptureBundleConstruction {
                source: Box::new(redact_capture_error(*source)),
            }
        }
        GkrmError::BaselineCaptureSpoolCleanupFailed { source } => {
            GkrmError::BaselineCaptureSpoolCleanupFailed {
                source: Box::new(redact_capture_error(*source)),
            }
        }
        GkrmError::BaselineCaptureFailedWithCleanupFailure { primary, cleanup } => {
            GkrmError::BaselineCaptureFailedWithCleanupFailure {
                primary: Box::new(redact_capture_error(*primary)),
                cleanup: Box::new(redact_capture_error(*cleanup)),
            }
        }
        GkrmError::BaselineVerifiedBlobCallbackAndVerificationFailed {
            primary,
            verification,
        } => {
            // Capture publication maps verification compounds to a category-only outcome.
            let _ = (primary, verification);
            GkrmError::BaselineCaptureBlobVerificationFailed
        }
        GkrmError::BaselineSecuredCatalogEnumerationFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureBaselineConflict
        }
        GkrmError::BaselineSelectedBaselineValidationFailed { source, .. } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureBaselineConflict
        }
        GkrmError::TrustedStagingCleanupFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::TrustedStagingFailedWithCleanupFailure { primary, cleanup } => {
            let _ = (
                redact_capture_error(*primary),
                redact_capture_error(*cleanup),
            );
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::TrustedStagingWriteFailure { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::TrustedStagingPostPublishVerificationFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::TrustedTransactionalApplyExecutionFailedCompound {
            primary,
            rollback,
            journal,
            cleanup,
        } => {
            let _ = (
                redact_capture_error(*primary),
                redact_capture_error(*rollback),
                redact_capture_error(*journal),
                redact_capture_error(*cleanup),
            );
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery {
            primary,
            recovery_journal,
        } => {
            let _ = (
                redact_capture_error(*primary),
                redact_capture_error(*recovery_journal),
            );
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ThreeWayMergeAnalysisBaselineBlobVerificationFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ThreeWayTextDiffBaselineBlobVerificationFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ThreeWayMergeSynthesisBaselineBlobVerificationFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ThreeWayMergedBytesBaselineBlobVerificationFailed { source } => {
            let _ = redact_capture_error(*source);
            GkrmError::BaselineCaptureForeignFailure
        }
        // --- Sensitive non-capture domain failures ---
        GkrmError::InstalledPathMetadata { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathMissing { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathNotDirectory { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledRootCanonicalize { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledRootUnsupportedPrefix { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledRootSymlink { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledRootNameNonUtf8 { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledDirectoryRead { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledDirectoryEntryRead { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledDirectoryDisappeared { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileDisappeared { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledEntryMetadata { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledEntrySymlink { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFxManifestSymlink { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledEntryReparsePoint { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledUnsupportedEntryType { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathEmpty { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathAbsolute { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathNonUtf8 { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathControlCharacter { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathEmptyComponent { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathCurrentDirectory { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathParentTraversal { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathWindowsInvalidCharacter { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledPathWindowsTrailingDotOrSpace { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledPathWindowsReservedName { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledPathDuplicate { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledPathCaseInsensitiveCollision { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledFilesPerResourceLimitExceeded { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledFileSizeLimitExceeded { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledDirectoryDepthLimitExceeded { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledFileOutsideResource { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledResourceRelativePath { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledContainmentViolation { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileOpen { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileMetadata { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileTimestampUnavailable { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledFileIdentityUnavailable { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::InstalledOpenedFileNotRegular { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileChanged { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileContentChanged { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileHashRead { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::InstalledFileSizeMismatch { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::ComparisonDuplicateInstalledRoot { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonDuplicateInstalledName { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonDuplicateIncomingRoot { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonDuplicateIncomingName { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonDuplicateInstalledFile { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonInconsistentReport { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::ComparisonInstalledNameMismatch { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonIncomingNameMismatch { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonDuplicateIncomingPackagePath { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonDuplicateIncomingRelativePath { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::ComparisonIncomingFileSizeLimitExceeded { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::UpdatePlanMissingIncomingClassification { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::UpdatePlanUnexpectedIncomingClassification { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::UpdatePlanDuplicateFilePath { .. } => GkrmError::BaselineCaptureForeignFailure,
        GkrmError::UpdatePlanDuplicateInstalledResourceMatch { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        GkrmError::UpdatePlanDuplicateIncomingResourceMatch { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        // --- Explicitly safe / already category-only variants ---
        safe @ GkrmError::InstalledScanZeroLimit { .. } => safe,
        GkrmError::InstalledNoResourcesFound => GkrmError::InstalledNoResourcesFound,
        safe @ GkrmError::InstalledResourceCountLimitExceeded { .. } => safe,
        safe @ GkrmError::InstalledTotalFilesLimitExceeded { .. } => safe,
        safe @ GkrmError::InstalledTotalEntriesLimitExceeded { .. } => safe,
        safe @ GkrmError::InstalledDirectoryCountLimitExceeded { .. } => safe,
        safe @ GkrmError::InstalledTotalSizeLimitExceeded { .. } => safe,
        safe @ GkrmError::ComparisonZeroLimit { .. } => safe,
        safe @ GkrmError::ComparisonIncomingFileCountLimitExceeded { .. } => safe,
        safe @ GkrmError::ComparisonIncomingTotalSizeLimitExceeded { .. } => safe,
        safe @ GkrmError::UpdatePlanInvalidFileSides { .. } => safe,
        safe @ GkrmError::UpdatePlanCountMismatch { .. } => safe,
        safe @ GkrmError::BaselineUnsupportedSchema { .. } => safe,
        safe @ GkrmError::BaselineManifestLimitExceeded { .. } => safe,
        safe @ GkrmError::BaselineFileCountLimitExceeded { .. } => safe,
        safe @ GkrmError::BaselineTotalBlobLimitExceeded { .. } => safe,
        safe @ GkrmError::BaselineStoreZeroLimit { .. } => safe,
        safe @ GkrmError::BaselineCountMismatch { .. } => safe,
        GkrmError::BaselineStoreInstallOverlap => GkrmError::BaselineStoreInstallOverlap,
        GkrmError::BaselineIncompleteTemporary => GkrmError::BaselineIncompleteTemporary,
        GkrmError::BaselineUnsupportedNoReplacePublish => {
            GkrmError::BaselineUnsupportedNoReplacePublish
        }
        safe @ GkrmError::BaselineStoreIdentityChanged { .. } => safe,
        safe @ GkrmError::BaselineResolutionOptionsInvalid { .. } => safe,
        safe @ GkrmError::BaselineCatalogEntryLimitExceeded { .. } => safe,
        GkrmError::BaselineNoStoredBaselines => GkrmError::BaselineNoStoredBaselines,
        safe @ GkrmError::BaselineAutoSingleBlockedByCatalogIssues { .. } => safe,
        GkrmError::BaselineCatalogChangedDuringResolution => {
            GkrmError::BaselineCatalogChangedDuringResolution
        }
        safe @ GkrmError::ThreeWayPlannerOptionsInvalid { .. } => safe,
        GkrmError::ThreeWayBaselineInstalledResourceMismatch => {
            GkrmError::ThreeWayBaselineInstalledResourceMismatch
        }
        GkrmError::ThreeWayBaselineIncomingResourceMismatch => {
            GkrmError::ThreeWayBaselineIncomingResourceMismatch
        }
        GkrmError::ThreeWayInstalledIncomingResourceMismatch => {
            GkrmError::ThreeWayInstalledIncomingResourceMismatch
        }
        GkrmError::ThreeWayIncomingRootIdentityUnavailable => {
            GkrmError::ThreeWayIncomingRootIdentityUnavailable
        }
        GkrmError::ThreeWayIncomingResourceIdentityInconsistent => {
            GkrmError::ThreeWayIncomingResourceIdentityInconsistent
        }
        GkrmError::ThreeWaySelectedInstalledResourceMissing => {
            GkrmError::ThreeWaySelectedInstalledResourceMissing
        }
        GkrmError::ThreeWaySelectedInstalledResourceAmbiguous => {
            GkrmError::ThreeWaySelectedInstalledResourceAmbiguous
        }
        GkrmError::ThreeWaySelectedIncomingResourceMissing => {
            GkrmError::ThreeWaySelectedIncomingResourceMissing
        }
        GkrmError::ThreeWaySelectedIncomingResourceAmbiguous => {
            GkrmError::ThreeWaySelectedIncomingResourceAmbiguous
        }
        GkrmError::ThreeWayUnsupportedTrustedSnapshotVersion => {
            GkrmError::ThreeWayUnsupportedTrustedSnapshotVersion
        }
        GkrmError::ThreeWayDuplicateBaselinePath => GkrmError::ThreeWayDuplicateBaselinePath,
        GkrmError::ThreeWayDuplicateInstalledPath => GkrmError::ThreeWayDuplicateInstalledPath,
        GkrmError::ThreeWayDuplicateIncomingPath => GkrmError::ThreeWayDuplicateIncomingPath,
        safe @ GkrmError::ThreeWayPlanEntryLimitExceeded { .. } => safe,
        GkrmError::ThreeWayArithmeticOverflow => GkrmError::ThreeWayArithmeticOverflow,
        GkrmError::ThreeWayMissingRequiredDigest => GkrmError::ThreeWayMissingRequiredDigest,
        GkrmError::ThreeWayIncomingPackageFingerprintUnavailable => {
            GkrmError::ThreeWayIncomingPackageFingerprintUnavailable
        }
        GkrmError::ThreeWayInconsistentIgnoredBaselineBlobPolicy => {
            GkrmError::ThreeWayInconsistentIgnoredBaselineBlobPolicy
        }
        GkrmError::ThreeWaySnapshotFingerprintFailure => {
            GkrmError::ThreeWaySnapshotFingerprintFailure
        }
        GkrmError::ThreeWayInternalInvariant => GkrmError::ThreeWayInternalInvariant,
        GkrmError::ThreeWayReviewPlanIdMismatch => GkrmError::ThreeWayReviewPlanIdMismatch,
        GkrmError::ThreeWayReviewDuplicateDecisionPath => {
            GkrmError::ThreeWayReviewDuplicateDecisionPath
        }
        GkrmError::ThreeWayReviewDecisionPathNotInPlan => {
            GkrmError::ThreeWayReviewDecisionPathNotInPlan
        }
        GkrmError::ThreeWayReviewDecisionForNoDecisionEntry => {
            GkrmError::ThreeWayReviewDecisionForNoDecisionEntry
        }
        GkrmError::ThreeWayReviewRecommendationUnavailable => {
            GkrmError::ThreeWayReviewRecommendationUnavailable
        }
        GkrmError::ThreeWayReviewMergeAnalysisNotAllowed => {
            GkrmError::ThreeWayReviewMergeAnalysisNotAllowed
        }
        GkrmError::ThreeWayReviewChoiceNotAllowed => GkrmError::ThreeWayReviewChoiceNotAllowed,
        GkrmError::ThreeWayReviewPolicyAcknowledgementRequired => {
            GkrmError::ThreeWayReviewPolicyAcknowledgementRequired
        }
        GkrmError::ThreeWayReviewPolicyAcknowledgementUnnecessary => {
            GkrmError::ThreeWayReviewPolicyAcknowledgementUnnecessary
        }
        GkrmError::ThreeWayReviewDecisionCountExceedsPlanEntryCount => {
            GkrmError::ThreeWayReviewDecisionCountExceedsPlanEntryCount
        }
        GkrmError::ThreeWayReviewArithmeticOverflow => GkrmError::ThreeWayReviewArithmeticOverflow,
        GkrmError::ThreeWayReviewEntryCountMismatch => GkrmError::ThreeWayReviewEntryCountMismatch,
        GkrmError::ThreeWayReviewSummaryInvariant => GkrmError::ThreeWayReviewSummaryInvariant,
        GkrmError::ThreeWayReviewStatusInvariant => GkrmError::ThreeWayReviewStatusInvariant,
        GkrmError::ThreeWayReviewIdEncodingFailure => GkrmError::ThreeWayReviewIdEncodingFailure,
        safe @ GkrmError::ThreeWayMergeAnalysisOptionsInvalid { .. } => safe,
        GkrmError::ThreeWayMergeAnalysisPlanReviewBindingMismatch => {
            GkrmError::ThreeWayMergeAnalysisPlanReviewBindingMismatch
        }
        GkrmError::ThreeWayMergeAnalysisReviewStructuralMismatch => {
            GkrmError::ThreeWayMergeAnalysisReviewStructuralMismatch
        }
        GkrmError::ThreeWayMergeAnalysisBaselineMismatch => {
            GkrmError::ThreeWayMergeAnalysisBaselineMismatch
        }
        GkrmError::ThreeWayMergeAnalysisNoQueuedCandidates => {
            GkrmError::ThreeWayMergeAnalysisNoQueuedCandidates
        }
        safe @ GkrmError::ThreeWayMergeAnalysisCandidateLimitExceeded { .. } => safe,
        GkrmError::ThreeWayMergeAnalysisQueuedEntryNotMergeCandidate => {
            GkrmError::ThreeWayMergeAnalysisQueuedEntryNotMergeCandidate
        }
        GkrmError::ThreeWayMergeAnalysisQueuedPolicyTransition => {
            GkrmError::ThreeWayMergeAnalysisQueuedPolicyTransition
        }
        GkrmError::ThreeWayMergeAnalysisMissingStateOrDigest => {
            GkrmError::ThreeWayMergeAnalysisMissingStateOrDigest
        }
        GkrmError::ThreeWayMergeAnalysisNonDivergentHashes => {
            GkrmError::ThreeWayMergeAnalysisNonDivergentHashes
        }
        GkrmError::ThreeWayMergeAnalysisInvalidEscrowClass => {
            GkrmError::ThreeWayMergeAnalysisInvalidEscrowClass
        }
        GkrmError::ThreeWayMergeAnalysisBaselineBlobUnavailable => {
            GkrmError::ThreeWayMergeAnalysisBaselineBlobUnavailable
        }
        GkrmError::ThreeWayMergeAnalysisBaselineBlobMetadataMismatch => {
            GkrmError::ThreeWayMergeAnalysisBaselineBlobMetadataMismatch
        }
        GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch => {
            GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisInstalledPostFingerprintMismatch => {
            GkrmError::ThreeWayMergeAnalysisInstalledPostFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid => {
            GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged => {
            GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged
        }
        safe @ GkrmError::ThreeWayMergeAnalysisTotalHashBudgetExceeded { .. } => safe,
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergeAnalysisArithmeticOverflow
        }
        GkrmError::ThreeWayMergeAnalysisSummaryInvariant => {
            GkrmError::ThreeWayMergeAnalysisSummaryInvariant
        }
        GkrmError::ThreeWayMergeAnalysisStatusInvariant => {
            GkrmError::ThreeWayMergeAnalysisStatusInvariant
        }
        GkrmError::ThreeWayMergeAnalysisIdEncodingFailure => {
            GkrmError::ThreeWayMergeAnalysisIdEncodingFailure
        }
        safe @ GkrmError::ThreeWayTextDiffOptionsInvalid { .. } => safe,
        GkrmError::ThreeWayTextDiffPlanReviewBindingMismatch => {
            GkrmError::ThreeWayTextDiffPlanReviewBindingMismatch
        }
        GkrmError::ThreeWayTextDiffPlanAnalysisBindingMismatch => {
            GkrmError::ThreeWayTextDiffPlanAnalysisBindingMismatch
        }
        GkrmError::ThreeWayTextDiffReviewAnalysisBindingMismatch => {
            GkrmError::ThreeWayTextDiffReviewAnalysisBindingMismatch
        }
        GkrmError::ThreeWayTextDiffReviewStructuralMismatch => {
            GkrmError::ThreeWayTextDiffReviewStructuralMismatch
        }
        GkrmError::ThreeWayTextDiffAnalysisStructuralMismatch => {
            GkrmError::ThreeWayTextDiffAnalysisStructuralMismatch
        }
        GkrmError::ThreeWayTextDiffBaselineMismatch => GkrmError::ThreeWayTextDiffBaselineMismatch,
        GkrmError::ThreeWayTextDiffNoReadyCandidates => {
            GkrmError::ThreeWayTextDiffNoReadyCandidates
        }
        safe @ GkrmError::ThreeWayTextDiffCandidateLimitExceeded { .. } => safe,
        GkrmError::ThreeWayTextDiffInvalidCandidateInvariant => {
            GkrmError::ThreeWayTextDiffInvalidCandidateInvariant
        }
        GkrmError::ThreeWayTextDiffInstalledPreFingerprintMismatch => {
            GkrmError::ThreeWayTextDiffInstalledPreFingerprintMismatch
        }
        GkrmError::ThreeWayTextDiffInstalledPostFingerprintMismatch => {
            GkrmError::ThreeWayTextDiffInstalledPostFingerprintMismatch
        }
        GkrmError::ThreeWayTextDiffInstalledResourceChanged => {
            GkrmError::ThreeWayTextDiffInstalledResourceChanged
        }
        GkrmError::ThreeWayTextDiffInstalledCandidateInvalid => {
            GkrmError::ThreeWayTextDiffInstalledCandidateInvalid
        }
        GkrmError::ThreeWayTextDiffIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayTextDiffIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayTextDiffIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayTextDiffIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayTextDiffIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayTextDiffIncomingResourceIdentityMismatch
        }
        GkrmError::ThreeWayTextDiffIncomingCandidateInvalid => {
            GkrmError::ThreeWayTextDiffIncomingCandidateInvalid
        }
        GkrmError::ThreeWayTextDiffSourceIdentityChanged => {
            GkrmError::ThreeWayTextDiffSourceIdentityChanged
        }
        GkrmError::ThreeWayTextDiffTask16MetadataMismatch => {
            GkrmError::ThreeWayTextDiffTask16MetadataMismatch
        }
        safe @ GkrmError::ThreeWayTextDiffTotalSourceByteLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayTextDiffTotalLineLimitExceeded { .. } => safe,
        GkrmError::ThreeWayTextDiffMalformedLogicalText => {
            GkrmError::ThreeWayTextDiffMalformedLogicalText
        }
        GkrmError::ThreeWayTextDiffInvalidPrimitiveScript => {
            GkrmError::ThreeWayTextDiffInvalidPrimitiveScript
        }
        GkrmError::ThreeWayTextDiffInvalidHunk => GkrmError::ThreeWayTextDiffInvalidHunk,
        GkrmError::ThreeWayTextDiffSameSideHunkOverlap => {
            GkrmError::ThreeWayTextDiffSameSideHunkOverlap
        }
        GkrmError::ThreeWayTextDiffInvalidOverlapComponent => {
            GkrmError::ThreeWayTextDiffInvalidOverlapComponent
        }
        GkrmError::ThreeWayTextDiffSummaryInvariant => GkrmError::ThreeWayTextDiffSummaryInvariant,
        GkrmError::ThreeWayTextDiffStatusInvariant => GkrmError::ThreeWayTextDiffStatusInvariant,
        GkrmError::ThreeWayTextDiffIdEncodingFailure => {
            GkrmError::ThreeWayTextDiffIdEncodingFailure
        }
        GkrmError::ThreeWayTextDiffArithmeticOverflow => {
            GkrmError::ThreeWayTextDiffArithmeticOverflow
        }
        safe @ GkrmError::ThreeWayMergeSynthesisOptionsInvalid { .. } => safe,
        GkrmError::ThreeWayMergeSynthesisPlanReviewBindingMismatch => {
            GkrmError::ThreeWayMergeSynthesisPlanReviewBindingMismatch
        }
        GkrmError::ThreeWayMergeSynthesisPlanAnalysisBindingMismatch => {
            GkrmError::ThreeWayMergeSynthesisPlanAnalysisBindingMismatch
        }
        GkrmError::ThreeWayMergeSynthesisPlanTextDiffBindingMismatch => {
            GkrmError::ThreeWayMergeSynthesisPlanTextDiffBindingMismatch
        }
        GkrmError::ThreeWayMergeSynthesisReviewAnalysisBindingMismatch => {
            GkrmError::ThreeWayMergeSynthesisReviewAnalysisBindingMismatch
        }
        GkrmError::ThreeWayMergeSynthesisReviewTextDiffBindingMismatch => {
            GkrmError::ThreeWayMergeSynthesisReviewTextDiffBindingMismatch
        }
        GkrmError::ThreeWayMergeSynthesisAnalysisTextDiffBindingMismatch => {
            GkrmError::ThreeWayMergeSynthesisAnalysisTextDiffBindingMismatch
        }
        GkrmError::ThreeWayMergeSynthesisReviewStructuralMismatch => {
            GkrmError::ThreeWayMergeSynthesisReviewStructuralMismatch
        }
        GkrmError::ThreeWayMergeSynthesisAnalysisStructuralMismatch => {
            GkrmError::ThreeWayMergeSynthesisAnalysisStructuralMismatch
        }
        GkrmError::ThreeWayMergeSynthesisTextDiffStructuralMismatch => {
            GkrmError::ThreeWayMergeSynthesisTextDiffStructuralMismatch
        }
        GkrmError::ThreeWayMergeSynthesisBaselineMismatch => {
            GkrmError::ThreeWayMergeSynthesisBaselineMismatch
        }
        GkrmError::ThreeWayMergeSynthesisNoReadyCandidates => {
            GkrmError::ThreeWayMergeSynthesisNoReadyCandidates
        }
        safe @ GkrmError::ThreeWayMergeSynthesisCandidateLimitExceeded { .. } => safe,
        GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant => {
            GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant
        }
        GkrmError::ThreeWayMergeSynthesisInstalledPreFingerprintMismatch => {
            GkrmError::ThreeWayMergeSynthesisInstalledPreFingerprintMismatch
        }
        GkrmError::ThreeWayMergeSynthesisInstalledPostFingerprintMismatch => {
            GkrmError::ThreeWayMergeSynthesisInstalledPostFingerprintMismatch
        }
        GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged => {
            GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeSynthesisInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergeSynthesisInstalledCandidateInvalid
        }
        GkrmError::ThreeWayMergeSynthesisIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayMergeSynthesisIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayMergeSynthesisIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayMergeSynthesisIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayMergeSynthesisIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayMergeSynthesisIncomingResourceIdentityMismatch
        }
        GkrmError::ThreeWayMergeSynthesisIncomingCandidateInvalid => {
            GkrmError::ThreeWayMergeSynthesisIncomingCandidateInvalid
        }
        GkrmError::ThreeWayMergeSynthesisSourceIdentityChanged => {
            GkrmError::ThreeWayMergeSynthesisSourceIdentityChanged
        }
        GkrmError::ThreeWayMergeSynthesisTask16MetadataMismatch => {
            GkrmError::ThreeWayMergeSynthesisTask16MetadataMismatch
        }
        GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch => {
            GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch
        }
        safe @ GkrmError::ThreeWayMergeSynthesisTotalSourceByteLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayMergeSynthesisSourceByteLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayMergeSynthesisTotalLineLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayMergeSynthesisSourceLineLimitExceeded { .. } => safe,
        GkrmError::ThreeWayMergeSynthesisMalformedLogicalText => {
            GkrmError::ThreeWayMergeSynthesisMalformedLogicalText
        }
        GkrmError::ThreeWayMergeSynthesisScheduleInvariant => {
            GkrmError::ThreeWayMergeSynthesisScheduleInvariant
        }
        GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup => {
            GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup
        }
        GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan => {
            GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan
        }
        GkrmError::ThreeWayMergeSynthesisReplayInvariant => {
            GkrmError::ThreeWayMergeSynthesisReplayInvariant
        }
        GkrmError::ThreeWayMergeSynthesisSummaryInvariant => {
            GkrmError::ThreeWayMergeSynthesisSummaryInvariant
        }
        GkrmError::ThreeWayMergeSynthesisStatusInvariant => {
            GkrmError::ThreeWayMergeSynthesisStatusInvariant
        }
        GkrmError::ThreeWayMergeSynthesisIdEncodingFailure => {
            GkrmError::ThreeWayMergeSynthesisIdEncodingFailure
        }
        GkrmError::ThreeWayMergeSynthesisArithmeticOverflow => {
            GkrmError::ThreeWayMergeSynthesisArithmeticOverflow
        }
        safe @ GkrmError::ThreeWayMergedBytesOptionsInvalid { .. } => safe,
        GkrmError::ThreeWayMergedBytesPlanReviewBindingMismatch => {
            GkrmError::ThreeWayMergedBytesPlanReviewBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesPlanAnalysisBindingMismatch => {
            GkrmError::ThreeWayMergedBytesPlanAnalysisBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesPlanTextDiffBindingMismatch => {
            GkrmError::ThreeWayMergedBytesPlanTextDiffBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesPlanSynthesisBindingMismatch => {
            GkrmError::ThreeWayMergedBytesPlanSynthesisBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesReviewAnalysisBindingMismatch => {
            GkrmError::ThreeWayMergedBytesReviewAnalysisBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesReviewTextDiffBindingMismatch => {
            GkrmError::ThreeWayMergedBytesReviewTextDiffBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesReviewSynthesisBindingMismatch => {
            GkrmError::ThreeWayMergedBytesReviewSynthesisBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesAnalysisTextDiffBindingMismatch => {
            GkrmError::ThreeWayMergedBytesAnalysisTextDiffBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesAnalysisSynthesisBindingMismatch => {
            GkrmError::ThreeWayMergedBytesAnalysisSynthesisBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesTextDiffSynthesisBindingMismatch => {
            GkrmError::ThreeWayMergedBytesTextDiffSynthesisBindingMismatch
        }
        GkrmError::ThreeWayMergedBytesReviewStructuralMismatch => {
            GkrmError::ThreeWayMergedBytesReviewStructuralMismatch
        }
        GkrmError::ThreeWayMergedBytesAnalysisStructuralMismatch => {
            GkrmError::ThreeWayMergedBytesAnalysisStructuralMismatch
        }
        GkrmError::ThreeWayMergedBytesTextDiffStructuralMismatch => {
            GkrmError::ThreeWayMergedBytesTextDiffStructuralMismatch
        }
        GkrmError::ThreeWayMergedBytesSynthesisStructuralMismatch => {
            GkrmError::ThreeWayMergedBytesSynthesisStructuralMismatch
        }
        GkrmError::ThreeWayMergedBytesBaselineMismatch => {
            GkrmError::ThreeWayMergedBytesBaselineMismatch
        }
        GkrmError::ThreeWayMergedBytesNoReadyCandidates => {
            GkrmError::ThreeWayMergedBytesNoReadyCandidates
        }
        safe @ GkrmError::ThreeWayMergedBytesCandidateLimitExceeded { .. } => safe,
        GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant => {
            GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant
        }
        GkrmError::ThreeWayMergedBytesInstalledPreFingerprintMismatch => {
            GkrmError::ThreeWayMergedBytesInstalledPreFingerprintMismatch
        }
        GkrmError::ThreeWayMergedBytesInstalledPostFingerprintMismatch => {
            GkrmError::ThreeWayMergedBytesInstalledPostFingerprintMismatch
        }
        GkrmError::ThreeWayMergedBytesInstalledResourceChanged => {
            GkrmError::ThreeWayMergedBytesInstalledResourceChanged
        }
        GkrmError::ThreeWayMergedBytesInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergedBytesInstalledCandidateInvalid
        }
        GkrmError::ThreeWayMergedBytesIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayMergedBytesIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayMergedBytesIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayMergedBytesIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayMergedBytesIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayMergedBytesIncomingResourceIdentityMismatch
        }
        GkrmError::ThreeWayMergedBytesIncomingCandidateInvalid => {
            GkrmError::ThreeWayMergedBytesIncomingCandidateInvalid
        }
        GkrmError::ThreeWayMergedBytesSourceIdentityChanged => {
            GkrmError::ThreeWayMergedBytesSourceIdentityChanged
        }
        GkrmError::ThreeWayMergedBytesTask16MetadataMismatch => {
            GkrmError::ThreeWayMergedBytesTask16MetadataMismatch
        }
        GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch => {
            GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch
        }
        GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch => {
            GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch
        }
        safe @ GkrmError::ThreeWayMergedBytesTotalSourceByteLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayMergedBytesSourceByteLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayMergedBytesTotalLineLimitExceeded { .. } => safe,
        safe @ GkrmError::ThreeWayMergedBytesSourceLineLimitExceeded { .. } => safe,
        GkrmError::ThreeWayMergedBytesMalformedLogicalText => {
            GkrmError::ThreeWayMergedBytesMalformedLogicalText
        }
        GkrmError::ThreeWayMergedBytesScheduleInvariant => {
            GkrmError::ThreeWayMergedBytesScheduleInvariant
        }
        GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup => {
            GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup
        }
        GkrmError::ThreeWayMergedBytesInvalidEnvelope => {
            GkrmError::ThreeWayMergedBytesInvalidEnvelope
        }
        GkrmError::ThreeWayMergedBytesReplayInvariant => {
            GkrmError::ThreeWayMergedBytesReplayInvariant
        }
        GkrmError::ThreeWayMergedBytesEncodeInvariant => {
            GkrmError::ThreeWayMergedBytesEncodeInvariant
        }
        GkrmError::ThreeWayMergedBytesSummaryInvariant => {
            GkrmError::ThreeWayMergedBytesSummaryInvariant
        }
        GkrmError::ThreeWayMergedBytesStatusInvariant => {
            GkrmError::ThreeWayMergedBytesStatusInvariant
        }
        GkrmError::ThreeWayMergedBytesIdEncodingFailure => {
            GkrmError::ThreeWayMergedBytesIdEncodingFailure
        }
        GkrmError::ThreeWayMergedBytesArithmeticOverflow => {
            GkrmError::ThreeWayMergedBytesArithmeticOverflow
        }
        safe @ GkrmError::TrustedStagingOptionsInvalid { .. } => safe,
        GkrmError::TrustedStagingPlanReviewBindingMismatch => {
            GkrmError::TrustedStagingPlanReviewBindingMismatch
        }
        GkrmError::TrustedStagingMergeChainBindingMismatch => {
            GkrmError::TrustedStagingMergeChainBindingMismatch
        }
        GkrmError::TrustedStagingMergeChainPresenceMismatch => {
            GkrmError::TrustedStagingMergeChainPresenceMismatch
        }
        GkrmError::TrustedStagingBaselineMismatch => GkrmError::TrustedStagingBaselineMismatch,
        GkrmError::TrustedStagingReviewUnresolved => GkrmError::TrustedStagingReviewUnresolved,
        GkrmError::TrustedStagingFinalTreeRejected => GkrmError::TrustedStagingFinalTreeRejected,
        GkrmError::TrustedStagingMissingMergedArtifact => {
            GkrmError::TrustedStagingMissingMergedArtifact
        }
        GkrmError::TrustedStagingManualMergeResult => GkrmError::TrustedStagingManualMergeResult,
        GkrmError::TrustedStagingSourceUnavailable => GkrmError::TrustedStagingSourceUnavailable,
        GkrmError::TrustedStagingRootOverlap => GkrmError::TrustedStagingRootOverlap,
        GkrmError::TrustedStagingRootReplaced => GkrmError::TrustedStagingRootReplaced,
        GkrmError::TrustedStagingDestinationExists => GkrmError::TrustedStagingDestinationExists,
        GkrmError::TrustedStagingUnsafeFilesystemObject => {
            GkrmError::TrustedStagingUnsafeFilesystemObject
        }
        safe @ GkrmError::TrustedStagingIo { .. } => safe,
        GkrmError::TrustedStagingDigestLengthMismatch => {
            GkrmError::TrustedStagingDigestLengthMismatch
        }
        GkrmError::TrustedStagingManifestTreeMismatch => {
            GkrmError::TrustedStagingManifestTreeMismatch
        }
        safe @ GkrmError::TrustedStagingLimitExceeded { .. } => safe,
        GkrmError::TrustedStagingArithmeticOverflow => GkrmError::TrustedStagingArithmeticOverflow,
        GkrmError::TrustedStagingIdEncodingFailure => GkrmError::TrustedStagingIdEncodingFailure,
        safe @ GkrmError::TrustedApplyPlanningOptionsInvalid { .. } => safe,
        GkrmError::TrustedApplyPlanningPlanReviewBindingMismatch => {
            GkrmError::TrustedApplyPlanningPlanReviewBindingMismatch
        }
        GkrmError::TrustedApplyPlanningMergeChainBindingMismatch => {
            GkrmError::TrustedApplyPlanningMergeChainBindingMismatch
        }
        GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch => {
            GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch
        }
        GkrmError::TrustedApplyPlanningBaselineMismatch => {
            GkrmError::TrustedApplyPlanningBaselineMismatch
        }
        GkrmError::TrustedApplyPlanningReviewUnresolved => {
            GkrmError::TrustedApplyPlanningReviewUnresolved
        }
        GkrmError::TrustedApplyPlanningManualMergeResult => {
            GkrmError::TrustedApplyPlanningManualMergeResult
        }
        GkrmError::TrustedApplyPlanningMissingMergedArtifact => {
            GkrmError::TrustedApplyPlanningMissingMergedArtifact
        }
        GkrmError::TrustedApplyPlanningBundleStatusInvalid => {
            GkrmError::TrustedApplyPlanningBundleStatusInvalid
        }
        GkrmError::TrustedApplyPlanningBundleBindingMismatch => {
            GkrmError::TrustedApplyPlanningBundleBindingMismatch
        }
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed => {
            GkrmError::TrustedApplyPlanningStagingRevalidationFailed
        }
        GkrmError::TrustedApplyPlanningInstalledStale => {
            GkrmError::TrustedApplyPlanningInstalledStale
        }
        GkrmError::TrustedApplyPlanningUnexpectedOrMissingEntry => {
            GkrmError::TrustedApplyPlanningUnexpectedOrMissingEntry
        }
        GkrmError::TrustedApplyPlanningPathTypeConflict => {
            GkrmError::TrustedApplyPlanningPathTypeConflict
        }
        GkrmError::TrustedApplyPlanningDuplicateOperation => {
            GkrmError::TrustedApplyPlanningDuplicateOperation
        }
        GkrmError::TrustedApplyPlanningIncompleteCoverage => {
            GkrmError::TrustedApplyPlanningIncompleteCoverage
        }
        safe @ GkrmError::TrustedApplyPlanningLimitExceeded { .. } => safe,
        GkrmError::TrustedApplyPlanningArithmeticOverflow => {
            GkrmError::TrustedApplyPlanningArithmeticOverflow
        }
        GkrmError::TrustedApplyPlanningIdEncodingFailure => {
            GkrmError::TrustedApplyPlanningIdEncodingFailure
        }
        GkrmError::TrustedApplyPlanningSummaryInvariant => {
            GkrmError::TrustedApplyPlanningSummaryInvariant
        }
        safe @ GkrmError::TrustedApplyPlanningIo { .. } => safe,
        safe @ GkrmError::TrustedTransactionalApplyPlanningOptionsInvalid { .. } => safe,
        GkrmError::TrustedTransactionalApplyPlanningBindingMismatch => {
            GkrmError::TrustedTransactionalApplyPlanningBindingMismatch
        }
        GkrmError::TrustedTransactionalApplyPlanningStatusInvalid => {
            GkrmError::TrustedTransactionalApplyPlanningStatusInvalid
        }
        GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch => {
            GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch
        }
        GkrmError::TrustedTransactionalApplyPlanningStagingRevalidationFailed => {
            GkrmError::TrustedTransactionalApplyPlanningStagingRevalidationFailed
        }
        GkrmError::TrustedTransactionalApplyPlanningInstalledStale => {
            GkrmError::TrustedTransactionalApplyPlanningInstalledStale
        }
        GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch => {
            GkrmError::TrustedTransactionalApplyPlanningPreconditionMismatch
        }
        GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete => {
            GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete
        }
        GkrmError::TrustedTransactionalApplyPlanningBackupSetMismatch => {
            GkrmError::TrustedTransactionalApplyPlanningBackupSetMismatch
        }
        GkrmError::TrustedTransactionalApplyPlanningJournalInvalid => {
            GkrmError::TrustedTransactionalApplyPlanningJournalInvalid
        }
        GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid => {
            GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid
        }
        GkrmError::TrustedTransactionalApplyPlanningRecoveryInvalid => {
            GkrmError::TrustedTransactionalApplyPlanningRecoveryInvalid
        }
        safe @ GkrmError::TrustedTransactionalApplyPlanningLimitExceeded { .. } => safe,
        GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow => {
            GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow
        }
        GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure => {
            GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure
        }
        GkrmError::TrustedTransactionalApplyPlanningSummaryInvariant => {
            GkrmError::TrustedTransactionalApplyPlanningSummaryInvariant
        }
        safe @ GkrmError::TrustedTransactionalApplyPlanningIo { .. } => safe,
        safe @ GkrmError::TrustedTransactionalApplyExecutionOptionsInvalid { .. } => safe,
        GkrmError::TrustedTransactionalApplyExecutionBindingMismatch => {
            GkrmError::TrustedTransactionalApplyExecutionBindingMismatch
        }
        GkrmError::TrustedTransactionalApplyExecutionStatusInvalid => {
            GkrmError::TrustedTransactionalApplyExecutionStatusInvalid
        }
        GkrmError::TrustedTransactionalApplyExecutionPlanIntegrityMismatch => {
            GkrmError::TrustedTransactionalApplyExecutionPlanIntegrityMismatch
        }
        GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed => {
            GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed
        }
        GkrmError::TrustedTransactionalApplyExecutionInstalledStale => {
            GkrmError::TrustedTransactionalApplyExecutionInstalledStale
        }
        GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch => {
            GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch
        }
        GkrmError::TrustedTransactionalApplyExecutionRootOverlap => {
            GkrmError::TrustedTransactionalApplyExecutionRootOverlap
        }
        GkrmError::TrustedTransactionalApplyExecutionRootReplaced => {
            GkrmError::TrustedTransactionalApplyExecutionRootReplaced
        }
        GkrmError::TrustedTransactionalApplyExecutionTransactionExists => {
            GkrmError::TrustedTransactionalApplyExecutionTransactionExists
        }
        GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete => {
            GkrmError::TrustedTransactionalApplyExecutionBackupIncomplete
        }
        GkrmError::TrustedTransactionalApplyExecutionBackupSealMismatch => {
            GkrmError::TrustedTransactionalApplyExecutionBackupSealMismatch
        }
        GkrmError::TrustedTransactionalApplyExecutionJournalInvalid => {
            GkrmError::TrustedTransactionalApplyExecutionJournalInvalid
        }
        GkrmError::TrustedTransactionalApplyExecutionForwardFailed => {
            GkrmError::TrustedTransactionalApplyExecutionForwardFailed
        }
        GkrmError::TrustedTransactionalApplyExecutionVerificationFailed => {
            GkrmError::TrustedTransactionalApplyExecutionVerificationFailed
        }
        GkrmError::TrustedTransactionalApplyExecutionRollbackFailed => {
            GkrmError::TrustedTransactionalApplyExecutionRollbackFailed
        }
        GkrmError::TrustedTransactionalApplyExecutionRecoveryRequired => {
            GkrmError::TrustedTransactionalApplyExecutionRecoveryRequired
        }
        safe @ GkrmError::TrustedTransactionalApplyExecutionLimitExceeded { .. } => safe,
        GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow => {
            GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow
        }
        GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure => {
            GkrmError::TrustedTransactionalApplyExecutionIdEncodingFailure
        }
        GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject => {
            GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject
        }
        safe @ GkrmError::TrustedTransactionalApplyExecutionIo { .. } => safe,
        GkrmError::TrustedTransactionalApplyExecutionLockContention => {
            GkrmError::TrustedTransactionalApplyExecutionLockContention
        }
        GkrmError::TrustedTransactionalApplyExecutionLockBindingMismatch => {
            GkrmError::TrustedTransactionalApplyExecutionLockBindingMismatch
        }
        GkrmError::TrustedTransactionalApplyExecutionLockUnsupported => {
            GkrmError::TrustedTransactionalApplyExecutionLockUnsupported
        }
        safe @ GkrmError::TrustedTransactionRecoveryOptionsInvalid { .. } => safe,
        GkrmError::TrustedTransactionRecoveryBindingMismatch => {
            GkrmError::TrustedTransactionRecoveryBindingMismatch
        }
        GkrmError::TrustedTransactionRecoveryCandidateInvalid => {
            GkrmError::TrustedTransactionRecoveryCandidateInvalid
        }
        GkrmError::TrustedTransactionRecoveryScanUnsafe => {
            GkrmError::TrustedTransactionRecoveryScanUnsafe
        }
        safe @ GkrmError::TrustedTransactionRecoveryLimitExceeded { .. } => safe,
        GkrmError::TrustedTransactionRecoveryIdEncodingFailure => {
            GkrmError::TrustedTransactionRecoveryIdEncodingFailure
        }
        GkrmError::TrustedTransactionRecoveryJournalInvalid => {
            GkrmError::TrustedTransactionRecoveryJournalInvalid
        }
        GkrmError::TrustedTransactionRecoveryRevalidationFailed => {
            GkrmError::TrustedTransactionRecoveryRevalidationFailed
        }
        GkrmError::TrustedTransactionRecoveryConflict => {
            GkrmError::TrustedTransactionRecoveryConflict
        }
        safe @ GkrmError::TrustedTransactionRecoveryIo { .. } => safe,
        safe @ GkrmError::TrustedCliUpdateOptionsInvalid { .. } => safe,
        GkrmError::TrustedCliUpdateResourceSelectionRequired => {
            GkrmError::TrustedCliUpdateResourceSelectionRequired
        }
        GkrmError::TrustedCliUpdateResourceNotFound => GkrmError::TrustedCliUpdateResourceNotFound,
        GkrmError::TrustedCliUpdateResourceAmbiguous => {
            GkrmError::TrustedCliUpdateResourceAmbiguous
        }
        GkrmError::TrustedCliUpdateRecoveryRequired => GkrmError::TrustedCliUpdateRecoveryRequired,
        GkrmError::TrustedCliUpdateDecisionsInvalid => GkrmError::TrustedCliUpdateDecisionsInvalid,
        GkrmError::TrustedCliUpdateDecisionsPlanMismatch => {
            GkrmError::TrustedCliUpdateDecisionsPlanMismatch
        }
        GkrmError::TrustedCliUpdateArtifactInvalid => GkrmError::TrustedCliUpdateArtifactInvalid,
        GkrmError::TrustedCliUpdateArtifactVersionUnsupported => {
            GkrmError::TrustedCliUpdateArtifactVersionUnsupported
        }
        GkrmError::TrustedCliUpdateBindingMismatch => GkrmError::TrustedCliUpdateBindingMismatch,
        GkrmError::TrustedUpdateSourceChanged => GkrmError::TrustedUpdateSourceChanged,
        GkrmError::TrustedCliUpdateDestinationExists => {
            GkrmError::TrustedCliUpdateDestinationExists
        }
        GkrmError::TrustedCliUpdatePathOverlap => GkrmError::TrustedCliUpdatePathOverlap,
        GkrmError::TrustedCliUpdateOperatorMergeInvalid => {
            GkrmError::TrustedCliUpdateOperatorMergeInvalid
        }
        GkrmError::TrustedCliUpdateOperatorMergeNotRequired => {
            GkrmError::TrustedCliUpdateOperatorMergeNotRequired
        }
        GkrmError::TrustedCliUpdateCandidateNotFound => {
            GkrmError::TrustedCliUpdateCandidateNotFound
        }
        GkrmError::TrustedCliUpdateCandidateAmbiguous => {
            GkrmError::TrustedCliUpdateCandidateAmbiguous
        }
        GkrmError::TrustedCliUpdateTransactionAlreadyPublished => {
            GkrmError::TrustedCliUpdateTransactionAlreadyPublished
        }
        GkrmError::TrustedCliUpdateIdEncodingFailure => {
            GkrmError::TrustedCliUpdateIdEncodingFailure
        }
        safe @ GkrmError::TrustedCliUpdateLimitExceeded { .. } => safe,
        safe @ GkrmError::TrustedCliUpdateIo { .. } => safe,
        GkrmError::TrustedCliUpdateSecurityRejection => {
            GkrmError::TrustedCliUpdateSecurityRejection
        }
        GkrmError::BaselineCaptureNoResources => GkrmError::BaselineCaptureNoResources,
        GkrmError::BaselineCaptureAmbiguousResources => {
            GkrmError::BaselineCaptureAmbiguousResources
        }
        GkrmError::BaselineCaptureResourceNotFound => GkrmError::BaselineCaptureResourceNotFound,
        GkrmError::BaselineCaptureResourceAmbiguous => GkrmError::BaselineCaptureResourceAmbiguous,
        GkrmError::BaselineCaptureUnsafeResourceIdentity => {
            GkrmError::BaselineCaptureUnsafeResourceIdentity
        }
        GkrmError::BaselineCaptureEmptyResource => GkrmError::BaselineCaptureEmptyResource,
        GkrmError::BaselineCaptureDuplicateFilePath => GkrmError::BaselineCaptureDuplicateFilePath,
        GkrmError::BaselineCaptureDuplicateArchiveEntry => {
            GkrmError::BaselineCaptureDuplicateArchiveEntry
        }
        GkrmError::BaselineCaptureMissingEscrowClassification => {
            GkrmError::BaselineCaptureMissingEscrowClassification
        }
        GkrmError::BaselineCaptureInconsistentEscrowClassification => {
            GkrmError::BaselineCaptureInconsistentEscrowClassification
        }
        safe @ GkrmError::BaselineCaptureSelectedFileLimit { .. } => safe,
        safe @ GkrmError::BaselineCaptureSelectedByteLimit { .. } => safe,
        safe @ GkrmError::BaselineCaptureEntrySizeMismatch { .. } => safe,
        safe @ GkrmError::BaselineCaptureEntryReadFailure { .. } => safe,
        GkrmError::BaselineCaptureIgnoredBlobMissing => {
            GkrmError::BaselineCaptureIgnoredBlobMissing
        }
        safe @ GkrmError::BaselineCaptureIgnoredBlobSizeMismatch { .. } => safe,
        GkrmError::BaselineCaptureIgnoredBlobDigestMismatch => {
            GkrmError::BaselineCaptureIgnoredBlobDigestMismatch
        }
        safe @ GkrmError::BaselineCaptureBlobSpoolFailure { .. } => safe,
        safe @ GkrmError::BaselineCaptureOptionsInvalid { .. } => safe,
        safe @ GkrmError::BaselineCapturePackageOpen { .. } => safe,
        safe @ GkrmError::BaselineCapturePackageRead { .. } => safe,
        GkrmError::BaselineCaptureArchiveInvalid => GkrmError::BaselineCaptureArchiveInvalid,
        GkrmError::BaselineCapturePackageSymlink => GkrmError::BaselineCapturePackageSymlink,
        GkrmError::BaselineCapturePackageReparsePoint => {
            GkrmError::BaselineCapturePackageReparsePoint
        }
        GkrmError::BaselineCapturePackagePathInvalid => {
            GkrmError::BaselineCapturePackagePathInvalid
        }
        GkrmError::BaselineCapturePackageChanged => GkrmError::BaselineCapturePackageChanged,
        safe @ GkrmError::BaselineCaptureBlobSizeLimitExceeded { .. } => safe,
        safe @ GkrmError::BaselineCaptureTotalBlobLimitExceeded { .. } => safe,
        safe @ GkrmError::BaselineCaptureSpoolBudgetExceeded { .. } => safe,
        GkrmError::BaselineCaptureSpoolVerificationFailure => {
            GkrmError::BaselineCaptureSpoolVerificationFailure
        }
        GkrmError::BaselineCaptureSpoolIdentityChanged => {
            GkrmError::BaselineCaptureSpoolIdentityChanged
        }
        safe @ GkrmError::BaselineCaptureUnsafeZipEntry { .. } => safe,
        safe @ GkrmError::BaselineCaptureArchiveLimitExceeded { .. } => safe,
        safe @ GkrmError::BaselineCaptureArchiveEntryLimitExceeded { .. } => safe,
        GkrmError::BaselineCaptureArchiveEntryRead => GkrmError::BaselineCaptureArchiveEntryRead,
        safe @ GkrmError::BaselineCaptureArchiveEntryStream { .. } => safe,
        GkrmError::BaselineCaptureArchiveEntryInconsistent => {
            GkrmError::BaselineCaptureArchiveEntryInconsistent
        }
        safe @ GkrmError::BaselineCaptureArchiveEntrySizeMismatch { .. } => safe,
        GkrmError::BaselineCaptureManifestInvalid => GkrmError::BaselineCaptureManifestInvalid,
        GkrmError::BaselineCaptureEscrowGlobInvalid => GkrmError::BaselineCaptureEscrowGlobInvalid,
        GkrmError::BaselineCaptureEscrowManifestInvalid => {
            GkrmError::BaselineCaptureEscrowManifestInvalid
        }
        GkrmError::BaselineCaptureEscrowResourcePathInvalid => {
            GkrmError::BaselineCaptureEscrowResourcePathInvalid
        }
        GkrmError::BaselineCaptureBaselineConflict => GkrmError::BaselineCaptureBaselineConflict,
        GkrmError::BaselineCaptureBlobVerificationFailed => {
            GkrmError::BaselineCaptureBlobVerificationFailed
        }
        GkrmError::BaselineCaptureBundlePathInvalid => GkrmError::BaselineCaptureBundlePathInvalid,
        GkrmError::BaselineCaptureBundleOrderingInvalid => {
            GkrmError::BaselineCaptureBundleOrderingInvalid
        }
        GkrmError::BaselineCaptureBundleBlobInvalid => GkrmError::BaselineCaptureBundleBlobInvalid,
        GkrmError::BaselineCaptureBundleIdentityMismatch => {
            GkrmError::BaselineCaptureBundleIdentityMismatch
        }
        safe @ GkrmError::BaselineCapturePublicationFailed { .. } => safe,
        GkrmError::BaselineCaptureForeignFailure => GkrmError::BaselineCaptureForeignFailure,
        safe @ GkrmError::BaselineCaptureStoreFailure { .. } => safe,
        // Two-way planning never runs during a capture; if one of its errors ever reaches here
        // it carries no capture content, only its own category.
        GkrmError::TwoWayPlanSnapshotMismatch => GkrmError::TwoWayPlanSnapshotMismatch,
        GkrmError::TwoWayPlanDuplicatePath => GkrmError::TwoWayPlanDuplicatePath,
        GkrmError::TwoWayPlanInvariant => GkrmError::TwoWayPlanInvariant,
        GkrmError::TwoWayMergeChoiceCountMismatch => GkrmError::TwoWayMergeChoiceCountMismatch,
        GkrmError::TwoWayPlanIdEncodingFailure => GkrmError::TwoWayPlanIdEncodingFailure,
        GkrmError::TwoWayBaselineResourceMismatch => GkrmError::TwoWayBaselineResourceMismatch,
        GkrmError::JsonMergeResultInvalid => GkrmError::JsonMergeResultInvalid,
        GkrmError::TwoWayPlanChangedSincePreview => GkrmError::TwoWayPlanChangedSincePreview,
        GkrmError::TwoWayDuplicateFileChoice => GkrmError::TwoWayDuplicateFileChoice,
        GkrmError::TrustedUpdateWorkspaceInvalid => GkrmError::TrustedUpdateWorkspaceInvalid,
        // Carries no capture content, no path, and no identity: it reports only that the
        // workspace parent uses the recognized pre-release layout.
        GkrmError::TrustedUpdateWorkspaceLegacyUnsupported => {
            GkrmError::TrustedUpdateWorkspaceLegacyUnsupported
        }
        GkrmError::TrustedUpdateWorkspaceCapacityReached => {
            GkrmError::TrustedUpdateWorkspaceCapacityReached
        }
        GkrmError::TrustedRecoveryAuthorityInvalid
        | GkrmError::TrustedRecoveryAuthorityVersionUnsupported
        | GkrmError::TrustedRecoveryAuthorityDerivationUnsupported
        | GkrmError::TrustedRecoveryAuthorityBindingMismatch
        | GkrmError::TrustedRecoveryAuthorityLimitExceeded { .. }
        | GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported
        | GkrmError::TrustedRecoveryAuthorityArithmeticOverflow
        | GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound
        | GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous
        | GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
        | GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch
        | GkrmError::TrustedTerminalEvidenceRetirementAcknowledgementRequired
        | GkrmError::TrustedTerminalEvidenceRetirementBlocked
        | GkrmError::TrustedTerminalEvidenceRetirementInvalid
        | GkrmError::TrustedTerminalEvidenceRetirementVersionUnsupported
        | GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded { .. } => {
            GkrmError::BaselineCaptureForeignFailure
        }
        #[cfg(test)]
        GkrmError::BaselineCaptureTestSeamFailure => GkrmError::BaselineCaptureTestSeamFailure,
    }
}

fn note_production_blob_map_shape(blob_sizes: &BTreeMap<Sha256Digest, u64>) {
    // Production capture retains only digest→size metadata, never digest→bytes.
    let _ = blob_sizes;
    #[cfg(test)]
    {
        with_capture_test_state(|state| {
            state.production_blob_map_is_sizes_only = true;
        });
    }
}

fn record_zip_entry_open(index: usize) {
    #[cfg(test)]
    {
        with_capture_test_state(|state| {
            *state.zip_entry_open_counts.entry(index).or_insert(0) += 1;
        });
    }
    #[cfg(not(test))]
    {
        let _ = index;
    }
}

#[cfg(test)]
type CaptureHook = Box<dyn FnOnce() -> Result<()>>;
#[cfg(test)]
type DigestHook = Box<dyn FnOnce(&Sha256Digest, &cap_std::fs::Dir) -> Result<()>>;
#[cfg(test)]
type PackageHook = Box<dyn FnOnce(&Path)>;
#[cfg(test)]
type DigestResultHook = Box<dyn FnOnce(&Sha256Digest) -> Result<()>>;
#[cfg(test)]
type IndexResultHook = Box<dyn FnOnce(usize) -> Result<()>>;
#[cfg(test)]
type SpoolCleanupHook = Box<dyn FnOnce(&cap_std::fs::Dir, &str)>;
#[cfg(test)]
type SpoolChildHook = Box<dyn FnOnce(&cap_std::fs::Dir, &str)>;
#[cfg(test)]
type SpoolValidationHook = Box<dyn FnOnce(&cap_std::fs::Dir, &str) -> Result<()>>;

#[cfg(test)]
#[derive(Default)]
struct CaptureTestState {
    after_snapshot: Option<(std::path::PathBuf, PackageHook)>,
    after_ignored_spooled: Option<DigestHook>,
    before_provider_open: Option<DigestResultHook>,
    before_publish: Option<CaptureHook>,
    during_ignored_spool_write: Option<CaptureHook>,
    during_writer_copy: Option<CaptureHook>,
    during_existing_verify: Option<DigestHook>,
    ignored_entry_open: Option<IndexResultHook>,
    before_partial_spool_create: Option<CaptureHook>,
    before_spool_cleanup: Option<SpoolCleanupHook>,
    after_spool_child_created: Option<SpoolChildHook>,
    during_spool_validation: Option<SpoolValidationHook>,
    forced_spool_names: Vec<String>,
    force_spool_collisions_remaining: u64,
    force_spool_identity_mismatch: bool,
    spool_cleanup_attempts: u64,
    spool_create_attempts: u64,
    spool_name_attempts: u64,
    zip_entry_open_counts: BTreeMap<usize, u64>,
    production_blob_map_is_sizes_only: bool,
}

#[cfg(test)]
thread_local! {
    static CAPTURE_TEST_STATE: std::cell::RefCell<Option<CaptureTestState>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn with_capture_test_state(f: impl FnOnce(&mut CaptureTestState)) {
    CAPTURE_TEST_STATE.with(|cell| {
        if let Some(state) = cell.borrow_mut().as_mut() {
            f(state);
        }
    });
}

#[cfg(test)]
fn take_from_capture_test_state<T>(
    f: impl FnOnce(&mut CaptureTestState) -> Option<T>,
) -> Option<T> {
    CAPTURE_TEST_STATE.with(|cell| cell.borrow_mut().as_mut().and_then(f))
}

fn run_after_snapshot_created_for_capture(package: &Path) {
    #[cfg(test)]
    {
        let hook = take_from_capture_test_state(|state| {
            let (target, hook) = state.after_snapshot.take()?;
            if target == package {
                Some(hook)
            } else {
                state.after_snapshot = Some((target, hook));
                None
            }
        });
        if let Some(hook) = hook {
            hook(package);
        }
    }
    #[cfg(not(test))]
    {
        let _ = package;
    }
}

fn run_after_ignored_spooled_hook(
    digest: &Sha256Digest,
    spool_dir: &cap_std::fs::Dir,
) -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) = take_from_capture_test_state(|state| state.after_ignored_spooled.take())
        {
            return hook(digest, spool_dir);
        }
    }
    #[cfg(not(test))]
    {
        let _ = (digest, spool_dir);
    }
    Ok(())
}

fn run_before_provider_open_hook(digest: &Sha256Digest) -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) = take_from_capture_test_state(|state| state.before_provider_open.take())
        {
            return hook(digest);
        }
    }
    #[cfg(not(test))]
    {
        let _ = digest;
    }
    Ok(())
}

fn run_before_publish_hook() -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) = take_from_capture_test_state(|state| state.before_publish.take()) {
            return hook();
        }
    }
    Ok(())
}

fn run_during_ignored_spool_write_hook() -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) =
            take_from_capture_test_state(|state| state.during_ignored_spool_write.take())
        {
            return hook();
        }
    }
    Ok(())
}

fn run_before_partial_spool_create_hook() -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) =
            take_from_capture_test_state(|state| state.before_partial_spool_create.take())
        {
            return hook();
        }
    }
    Ok(())
}

fn run_during_existing_spool_verify_hook(
    digest: &Sha256Digest,
    spool_dir: &cap_std::fs::Dir,
) -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) =
            take_from_capture_test_state(|state| state.during_existing_verify.take())
        {
            return hook(digest, spool_dir);
        }
    }
    #[cfg(not(test))]
    {
        let _ = (digest, spool_dir);
    }
    Ok(())
}

fn run_ignored_entry_open_hook(index: usize) -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) = take_from_capture_test_state(|state| state.ignored_entry_open.take()) {
            return hook(index);
        }
    }
    #[cfg(not(test))]
    {
        let _ = index;
    }
    Ok(())
}

fn record_spool_cleanup_attempt() {
    #[cfg(test)]
    {
        with_capture_test_state(|state| {
            state.spool_cleanup_attempts = state.spool_cleanup_attempts.saturating_add(1);
        });
    }
}

fn run_before_spool_cleanup_hook(tmp_root: &cap_std::fs::Dir, spool_name: &str) {
    #[cfg(test)]
    {
        if let Some(hook) = take_from_capture_test_state(|state| state.before_spool_cleanup.take())
        {
            hook(tmp_root, spool_name);
        }
    }
    #[cfg(not(test))]
    {
        let _ = (tmp_root, spool_name);
    }
}

fn run_after_spool_child_created_hook(tmp_root: &cap_std::fs::Dir, spool_name: &str) {
    #[cfg(test)]
    {
        with_capture_test_state(|state| {
            state.spool_create_attempts = state.spool_create_attempts.saturating_add(1);
        });
        if let Some(hook) =
            take_from_capture_test_state(|state| state.after_spool_child_created.take())
        {
            hook(tmp_root, spool_name);
        }
    }
    #[cfg(not(test))]
    {
        let _ = (tmp_root, spool_name);
    }
}

fn run_during_spool_validation_hook(tmp_root: &cap_std::fs::Dir, spool_name: &str) -> Result<()> {
    #[cfg(test)]
    {
        if let Some(hook) =
            take_from_capture_test_state(|state| state.during_spool_validation.take())
        {
            return hook(tmp_root, spool_name);
        }
    }
    #[cfg(not(test))]
    {
        let _ = (tmp_root, spool_name);
    }
    Ok(())
}

fn take_forced_spool_name_for_tests() -> Option<String> {
    #[cfg(test)]
    {
        take_from_capture_test_state(|state| {
            if state.forced_spool_names.is_empty() {
                None
            } else {
                Some(state.forced_spool_names.remove(0))
            }
        })
    }
    #[cfg(not(test))]
    {
        None
    }
}

fn force_spool_create_collision_for_tests() -> bool {
    #[cfg(test)]
    {
        take_from_capture_test_state(|state| {
            if state.force_spool_collisions_remaining == 0 {
                None
            } else {
                state.force_spool_collisions_remaining -= 1;
                Some(())
            }
        })
        .is_some()
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn force_spool_identity_mismatch_for_tests() -> bool {
    #[cfg(test)]
    {
        take_from_capture_test_state(|state| {
            if state.force_spool_identity_mismatch {
                state.force_spool_identity_mismatch = false;
                Some(())
            } else {
                None
            }
        })
        .is_some()
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn record_spool_name_attempt() {
    #[cfg(test)]
    {
        with_capture_test_state(|state| {
            state.spool_name_attempts = state.spool_name_attempts.saturating_add(1);
        });
    }
}

#[cfg(test)]
pub(super) fn select_resource_for_tests<'a>(
    discovery: &'a ZipResourceDiscovery,
    selector: &IncomingResourceSelector,
    resource_key: &SafeResourceKey,
) -> Result<(&'a DiscoveredZipResource, Vec<BaselineCaptureWarning>)> {
    select_resource(discovery, selector, resource_key)
}

#[cfg(test)]
pub(crate) fn redact_capture_error_for_tests(error: GkrmError) -> GkrmError {
    redact_capture_error(error)
}

/// Mirror of selected-entry archive-index uniqueness used by inventory.
#[cfg(test)]
pub(super) fn reject_duplicate_selected_archive_indexes_for_tests(
    entries: &[ZipEntryInfo],
) -> Result<()> {
    let mut seen_indexes = BTreeSet::new();
    for entry in entries {
        if entry.kind != ZipEntryKind::File {
            continue;
        }
        if !seen_indexes.insert(entry.archive_index) {
            return Err(GkrmError::BaselineCaptureDuplicateArchiveEntry);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_seams {
    use super::*;
    use std::path::PathBuf;

    /// RAII ownership for capture test hooks/counters on the current thread.
    ///
    /// Nested guards restore the prior owned state on Drop (panic-safe), including
    /// the writer-copy hook stored in that state. Integration captures without a
    /// guard never observe or mutate owned state. The guard is `!Send` / `!Sync`.
    pub struct CaptureHookGuard {
        previous: Option<CaptureTestState>,
        _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    impl CaptureHookGuard {
        fn acquire() -> Self {
            let previous = CAPTURE_TEST_STATE.with(|cell| cell.borrow_mut().take());
            CAPTURE_TEST_STATE.with(|cell| {
                *cell.borrow_mut() = Some(CaptureTestState::default());
            });
            Self {
                previous,
                _not_send: std::marker::PhantomData,
            }
        }
    }

    impl Drop for CaptureHookGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            CAPTURE_TEST_STATE.with(|cell| {
                *cell.borrow_mut() = previous;
            });
        }
    }

    /// Arm thread-local capture instrumentation for the current test.
    pub fn hook_lock() -> CaptureHookGuard {
        CaptureHookGuard::acquire()
    }

    fn require_state<R>(f: impl FnOnce(&mut CaptureTestState) -> R) -> R {
        CAPTURE_TEST_STATE.with(|cell| {
            let mut borrow = cell.borrow_mut();
            let state = borrow
                .as_mut()
                .expect("capture test hooks require hook_lock() ownership");
            f(state)
        })
    }

    #[allow(dead_code)]
    pub fn clear_all_hooks() {
        require_state(|state| {
            *state = CaptureTestState::default();
        });
    }

    /// RAII ownership for the writer-copy hook inside the current capture test state.
    ///
    /// Nested guards restore the prior hook on Drop (panic-safe). Consumed hooks are
    /// not resurrected. The guard is `!Send` / `!Sync`.
    pub struct WriterCopyHookGuard {
        previous: Option<CaptureHook>,
        _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
    }

    impl Drop for WriterCopyHookGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            CAPTURE_TEST_STATE.with(|cell| {
                if let Some(state) = cell.borrow_mut().as_mut() {
                    state.during_writer_copy = previous;
                }
            });
        }
    }

    pub fn set_during_writer_copy_hook(
        hook: impl FnOnce() -> Result<()> + 'static,
    ) -> WriterCopyHookGuard {
        require_state(|state| {
            let previous = state.during_writer_copy.take();
            state.during_writer_copy = Some(Box::new(hook));
            WriterCopyHookGuard {
                previous,
                _not_send: std::marker::PhantomData,
            }
        })
    }

    pub fn writer_copy_hook_is_armed() -> bool {
        CAPTURE_TEST_STATE.with(|cell| {
            cell.borrow()
                .as_ref()
                .map(|state| state.during_writer_copy.is_some())
                .unwrap_or(false)
        })
    }

    pub(crate) fn run_during_writer_copy_hook() -> Result<()> {
        if let Some(hook) = take_from_capture_test_state(|state| state.during_writer_copy.take()) {
            return hook();
        }
        Ok(())
    }

    pub fn set_after_snapshot_created_hook(package: &Path, hook: impl FnOnce(&Path) + 'static) {
        require_state(|state| {
            state.after_snapshot = Some((package.to_path_buf(), Box::new(hook)));
        });
    }

    pub fn set_after_ignored_spooled_hook(
        hook: impl FnOnce(&Sha256Digest, &cap_std::fs::Dir) -> Result<()> + 'static,
    ) {
        require_state(|state| {
            state.after_ignored_spooled = Some(Box::new(hook));
        });
    }

    pub fn set_before_provider_open_hook(hook: impl FnOnce(&Sha256Digest) -> Result<()> + 'static) {
        require_state(|state| {
            state.before_provider_open = Some(Box::new(hook));
        });
    }

    pub fn set_before_publish_hook(hook: impl FnOnce() -> Result<()> + 'static) {
        require_state(|state| {
            state.before_publish = Some(Box::new(hook));
        });
    }

    pub fn set_during_ignored_spool_write_hook(hook: impl FnOnce() -> Result<()> + 'static) {
        require_state(|state| {
            state.during_ignored_spool_write = Some(Box::new(hook));
        });
    }

    pub fn set_before_partial_spool_create_hook(hook: impl FnOnce() -> Result<()> + 'static) {
        require_state(|state| {
            state.before_partial_spool_create = Some(Box::new(hook));
        });
    }

    pub fn set_before_spool_cleanup_hook(hook: impl FnOnce(&cap_std::fs::Dir, &str) + 'static) {
        require_state(|state| {
            state.before_spool_cleanup = Some(Box::new(hook));
        });
    }

    pub fn set_after_spool_child_created_hook(
        hook: impl FnOnce(&cap_std::fs::Dir, &str) + 'static,
    ) {
        require_state(|state| {
            state.after_spool_child_created = Some(Box::new(hook));
        });
    }

    pub fn set_during_spool_validation_hook(
        hook: impl FnOnce(&cap_std::fs::Dir, &str) -> Result<()> + 'static,
    ) {
        require_state(|state| {
            state.during_spool_validation = Some(Box::new(hook));
        });
    }

    pub fn push_forced_spool_names(names: impl IntoIterator<Item = impl Into<String>>) {
        require_state(|state| {
            state
                .forced_spool_names
                .extend(names.into_iter().map(Into::into));
        });
    }

    pub fn force_spool_create_collisions(count: u64) {
        require_state(|state| {
            state.force_spool_collisions_remaining = count;
        });
    }

    pub fn force_next_spool_identity_mismatch() {
        require_state(|state| {
            state.force_spool_identity_mismatch = true;
        });
    }

    pub fn spool_create_attempt_count() -> u64 {
        require_state(|state| state.spool_create_attempts)
    }

    pub fn spool_name_attempt_count() -> u64 {
        require_state(|state| state.spool_name_attempts)
    }

    /// Create a capture spool guard and drop it without `finish` (Drop safety net).
    pub fn abandon_capture_spool_guard(store: &Path) -> Result<()> {
        let store_root =
            open_or_create_store_root_for_write(store).map_err(redact_capture_error)?;
        let tmp_root = ensure_child_dir(&store_root.dir, ".tmp").map_err(redact_capture_error)?;
        let guard = CaptureSpoolGuard::create(&tmp_root)?;
        drop(guard);
        Ok(())
    }

    /// Finish a freshly created guard once; Drop must not perform a second cleanup.
    pub fn finish_capture_spool_guard_once(store: &Path) -> Result<()> {
        let store_root =
            open_or_create_store_root_for_write(store).map_err(redact_capture_error)?;
        let tmp_root = ensure_child_dir(&store_root.dir, ".tmp").map_err(redact_capture_error)?;
        let guard = CaptureSpoolGuard::create(&tmp_root)?;
        let before = spool_cleanup_attempt_count();
        let finished = guard.finish(Err(GkrmError::BaselineCaptureNoResources));
        assert!(finished.is_err());
        assert_eq!(spool_cleanup_attempt_count(), before + 1);
        Ok(())
    }

    pub fn spool_cleanup_attempt_count() -> u64 {
        require_state(|state| state.spool_cleanup_attempts)
    }

    pub fn set_during_existing_spool_verify_hook(
        hook: impl FnOnce(&Sha256Digest, &cap_std::fs::Dir) -> Result<()> + 'static,
    ) {
        require_state(|state| {
            state.during_existing_verify = Some(Box::new(hook));
        });
    }

    pub fn clear_zip_entry_open_counts() {
        require_state(|state| {
            state.zip_entry_open_counts.clear();
            state.production_blob_map_is_sizes_only = false;
        });
    }

    pub fn zip_entry_open_count(index: usize) -> u64 {
        require_state(|state| {
            state
                .zip_entry_open_counts
                .get(&index)
                .copied()
                .unwrap_or(0)
        })
    }

    pub fn production_blob_map_was_sizes_only() -> bool {
        require_state(|state| state.production_blob_map_is_sizes_only)
    }

    pub fn list_capture_spools(store: &Path) -> Vec<PathBuf> {
        let tmp = store.join(".tmp");
        if !tmp.exists() {
            return Vec::new();
        }
        let mut names = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&tmp) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("capture-") {
                    names.push(entry.path());
                }
            }
        }
        names
    }

    pub fn verify_existing_spool_blob_for_tests(
        spool_dir: &cap_std::fs::Dir,
        digest: &Sha256Digest,
        expected_size: u64,
    ) -> Result<()> {
        let mut buffer = [0_u8; HASH_BUFFER_SIZE];
        verify_existing_spool_blob(spool_dir, digest, expected_size, &mut buffer)
    }

    pub fn plant_spool_object(
        spool_dir: &cap_std::fs::Dir,
        digest: &Sha256Digest,
        bytes: &[u8],
    ) -> Result<()> {
        let name = digest.to_string();
        let mut file = create_new_file(spool_dir, &name)?;
        file.write_all(bytes)
            .map_err(|source| spool_io_failure(BaselineCaptureBlobSpoolStage::Write, source))?;
        Ok(())
    }

    pub fn temporary_spool_budget_for_tests(max_total: u64, max_blob: u64) -> Result<u64> {
        temporary_spool_budget(max_total, max_blob)
    }
}
