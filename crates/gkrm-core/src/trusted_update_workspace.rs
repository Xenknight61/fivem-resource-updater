use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use cap_fs_ext::{DirEntryExt, DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir as CapDir, File as CapFile, Metadata as CapMetadata, OpenOptions};
use uuid::Uuid;

use crate::baseline::fs_security::{
    create_new_file, dir_identity, ensure_child_dir, open_child_dir, open_existing_directory,
    open_file_nofollow, open_or_create_store_root_for_write, validate_single_component,
    verify_regular_file,
};
use crate::baseline::store::{fsync_file, sync_dir};
use crate::file_identity::{
    capture_stable_file_identity, is_windows_reparse_point_cap, StableFileIdentity,
};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::trusted_cli_update_artifact::rename_file_noreplace;
use crate::{GkrmError, Result, Sha256Digest};

const BASELINES_DIR: &str = "baselines";
const STAGING_DIR: &str = "staging";
const TRANSACTIONS_DIR: &str = "transactions";
const ARTIFACTS_DIR: &str = "artifacts";
const WORKSPACE_MARKER: &str = ".gkrm-trusted-update-workspace";
const WORKSPACE_MARKER_TEMP_PREFIX: &str = ".gkrm-trusted-update-workspace.tmp-";
const WORKSPACE_MARKER_MAGIC: &[u8] = b"gkrm-trusted-update-workspace\n";
/// The pre-release presence-only marker. It cannot establish which sibling roots were
/// legitimate, so it is refused — but it is refused as a recognized legacy layout rather
/// than as damaged evidence, because the two need different operator responses. The magic
/// above diverges from this prefix at the newline, so a valid version-2 marker never matches.
const WORKSPACE_LEGACY_V1_MARKER_PREFIX: &[u8] = b"gkrm-trusted-update-workspace-v1";
const WORKSPACE_MARKER_VERSION: u16 = 2;
const WORKSPACE_MARKER_MAX_BYTES: u64 = 2_048;
const WORKSPACE_COMPONENT_MAX_BYTES: usize = 255;
const WORKSPACE_PUBLICATION_LOCK: &str = ".publication.lock";
const WORKSPACE_PUBLICATION_LOCK_MAGIC: &[u8] = b"gkrm-workspace-publication-lock-v1\n";
const PLAN_ARTIFACT_PREFIX: &str = "plan-";
const PLAN_ARTIFACT_SUFFIX: &str = ".bin";
const MAX_WORKSPACE_TRAVERSAL_DEPTH: usize = 32;

#[derive(Clone)]
pub struct TrustedUpdateWorkspace {
    app_root: PathBuf,
    baseline_store: TrustedBaselineStore,
    staging_root: TrustedWorkspaceRoot,
    transaction_root: TrustedWorkspaceRoot,
    artifact_root: TrustedArtifactRoot,
    capabilities: Arc<TrustedWorkspaceCapabilities>,
}

struct TrustedWorkspaceCapabilities {
    app_root: CapDir,
    app_root_identity: StableFileIdentity,
    baseline_store: CapDir,
    baseline_store_identity: StableFileIdentity,
    staging_root: CapDir,
    staging_root_identity: StableFileIdentity,
    transaction_root: CapDir,
    transaction_root_identity: StableFileIdentity,
    artifact_root: CapDir,
    artifact_root_identity: StableFileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceIdentityRecord {
    baseline_component: String,
    staging_component: String,
    transaction_component: String,
    artifact_component: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedBaselineStore {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedWorkspaceRoot {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedArtifactRoot {
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedUpdateWorkspaceOptions {
    pub max_regular_file_bytes: u64,
    pub max_directory_entries: usize,
    pub max_plan_artifacts: usize,
    pub max_individual_artifact_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedUpdateWorkspaceUsage {
    regular_file_bytes: u64,
    directory_entries: usize,
    plan_artifacts: usize,
    largest_artifact_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedUpdateWorkspaceReservation {
    regular_file_bytes: u64,
    directory_entries: usize,
    plan_artifacts: usize,
    largest_artifact_bytes: u64,
}

pub struct TrustedWorkspacePublicationLock {
    _file: CapFile,
}

pub struct ExplicitTrustedUpdateWorkspaceRequest<'a> {
    pub baseline_store: &'a Path,
    pub staging_root: &'a Path,
    pub transaction_root: &'a Path,
    pub artifact_root: &'a Path,
    pub artifact_out: &'a Path,
    pub installed_root: &'a Path,
    pub package_file: &'a Path,
}

pub struct ExistingExplicitTrustedUpdateWorkspaceRequest<'a> {
    pub baseline_store: &'a Path,
    pub staging_root: &'a Path,
    pub transaction_root: &'a Path,
    pub artifact_root: &'a Path,
}

impl std::fmt::Debug for TrustedUpdateWorkspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedUpdateWorkspace")
            .field("app_root", &self.app_root)
            .field("baseline_store", &self.baseline_store)
            .field("staging_root", &self.staging_root)
            .field("transaction_root", &self.transaction_root)
            .field("artifact_root", &self.artifact_root)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TrustedUpdateWorkspace {
    fn eq(&self, other: &Self) -> bool {
        self.app_root == other.app_root
            && self.baseline_store == other.baseline_store
            && self.staging_root == other.staging_root
            && self.transaction_root == other.transaction_root
            && self.artifact_root == other.artifact_root
            && self.capabilities.app_root_identity == other.capabilities.app_root_identity
            && self.capabilities.baseline_store_identity
                == other.capabilities.baseline_store_identity
            && self.capabilities.staging_root_identity == other.capabilities.staging_root_identity
            && self.capabilities.transaction_root_identity
                == other.capabilities.transaction_root_identity
            && self.capabilities.artifact_root_identity == other.capabilities.artifact_root_identity
    }
}

impl Eq for TrustedUpdateWorkspace {}

impl Default for TrustedUpdateWorkspaceOptions {
    fn default() -> Self {
        Self {
            max_regular_file_bytes: 8 * 1024 * 1024 * 1024,
            max_directory_entries: 250_000,
            max_plan_artifacts: 1_000,
            max_individual_artifact_bytes: 64 * 1024 * 1024,
        }
    }
}

impl TrustedUpdateWorkspace {
    pub fn app_root(&self) -> &Path {
        &self.app_root
    }

    pub fn baseline_store(&self) -> &Path {
        &self.baseline_store.path
    }

    pub fn staging_root(&self) -> &Path {
        &self.staging_root.path
    }

    pub fn transaction_root(&self) -> &Path {
        &self.transaction_root.path
    }

    pub fn artifact_root(&self) -> &TrustedArtifactRoot {
        &self.artifact_root
    }

    pub(crate) fn revalidate_explicit_roots(
        &self,
        baseline_store: &Path,
        staging_root: &Path,
        transaction_root: &Path,
        artifact_root: &Path,
    ) -> Result<()> {
        revalidate_workspace_paths(self)?;
        if !path_matches_retained_root(
            baseline_store,
            &self.baseline_store.path,
            &self.capabilities.baseline_store_identity,
            "trusted-update-baselines",
        )? || !path_matches_retained_root(
            staging_root,
            &self.staging_root.path,
            &self.capabilities.staging_root_identity,
            "trusted-update-staging",
        )? || !path_matches_retained_root(
            transaction_root,
            &self.transaction_root.path,
            &self.capabilities.transaction_root_identity,
            "trusted-update-transactions",
        )? || !path_matches_retained_root(
            artifact_root,
            &self.artifact_root.path,
            &self.capabilities.artifact_root_identity,
            "trusted-update-artifacts",
        )? {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
        Ok(())
    }

    pub(crate) fn revalidate_transaction_root(&self, transaction_root: &Path) -> Result<()> {
        revalidate_workspace_paths(self)?;
        if !path_matches_retained_root(
            transaction_root,
            &self.transaction_root.path,
            &self.capabilities.transaction_root_identity,
            "trusted-update-transactions",
        )? {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
        Ok(())
    }

    pub(crate) fn try_clone_transaction_root_capability(
        &self,
    ) -> Result<(CapDir, StableFileIdentity)> {
        clone_retained_capability(
            &self.capabilities.transaction_root,
            &self.capabilities.transaction_root_identity,
            "trusted-update-transactions",
        )
    }

    pub(crate) fn try_clone_baseline_store_capability(
        &self,
    ) -> Result<(CapDir, StableFileIdentity)> {
        clone_retained_capability(
            &self.capabilities.baseline_store,
            &self.capabilities.baseline_store_identity,
            "trusted-update-baselines",
        )
    }

    pub(crate) fn try_clone_artifact_root_capability(
        &self,
    ) -> Result<(CapDir, StableFileIdentity)> {
        clone_retained_capability(
            &self.capabilities.artifact_root,
            &self.capabilities.artifact_root_identity,
            "trusted-update-artifacts",
        )
    }
}

impl TrustedArtifactRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn allocate_plan_artifact_path(&self) -> Result<PathBuf> {
        for _ in 0..32 {
            let candidate = self.path.join(format!(
                "{PLAN_ARTIFACT_PREFIX}{}{PLAN_ARTIFACT_SUFFIX}",
                Uuid::new_v4()
            ));
            if !candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(GkrmError::TrustedUpdateWorkspaceCapacityReached)
    }
}

impl TrustedUpdateWorkspaceUsage {
    pub fn regular_file_bytes(&self) -> u64 {
        self.regular_file_bytes
    }

    pub fn directory_entries(&self) -> usize {
        self.directory_entries
    }

    pub fn plan_artifacts(&self) -> usize {
        self.plan_artifacts
    }

    pub fn largest_artifact_bytes(&self) -> u64 {
        self.largest_artifact_bytes
    }
}

impl TrustedUpdateWorkspaceReservation {
    pub fn new(
        regular_file_bytes: u64,
        directory_entries: usize,
        plan_artifacts: usize,
        largest_artifact_bytes: u64,
    ) -> Result<Self> {
        if largest_artifact_bytes > regular_file_bytes {
            return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
        }
        Ok(Self {
            regular_file_bytes,
            directory_entries,
            plan_artifacts,
            largest_artifact_bytes,
        })
    }

    pub fn regular_file_bytes(&self) -> u64 {
        self.regular_file_bytes
    }

    pub fn directory_entries(&self) -> usize {
        self.directory_entries
    }

    pub fn plan_artifacts(&self) -> usize {
        self.plan_artifacts
    }

    pub fn largest_artifact_bytes(&self) -> u64 {
        self.largest_artifact_bytes
    }
}

pub fn resolve_trusted_update_workspace(app_data_root: &Path) -> Result<TrustedUpdateWorkspace> {
    if !app_data_root.is_absolute() {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let app_root_open = open_or_create_store_root_for_write(app_data_root)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let identity =
        WorkspaceIdentityRecord::new(BASELINES_DIR, STAGING_DIR, TRANSACTIONS_DIR, ARTIFACTS_DIR)?;
    let identity_exists =
        existing_workspace_identity_matches_or_absent(&app_root_open.dir, &identity)?;
    ensure_child_dir(&app_root_open.dir, BASELINES_DIR)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    ensure_child_dir(&app_root_open.dir, STAGING_DIR)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    ensure_child_dir(&app_root_open.dir, TRANSACTIONS_DIR)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    ensure_child_dir(&app_root_open.dir, ARTIFACTS_DIR)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if !identity_exists {
        publish_workspace_identity(&app_root_open.dir, &identity)?;
    }
    let app_root = canonical_directory(app_data_root)?;
    build_trusted_workspace_from_open_parent(app_root, app_root_open.dir, identity)
}

/// Open an already initialized trusted update workspace without creating or
/// repairing any filesystem object. A completely absent root is not an error;
/// callers performing read-only status inspection can safely treat it as empty.
pub fn open_existing_trusted_update_workspace(
    app_data_root: &Path,
) -> Result<Option<TrustedUpdateWorkspace>> {
    if !app_data_root.is_absolute() {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let app_root_open = match open_existing_directory(app_data_root, "trusted-update-workspace") {
        Ok(opened) => opened,
        Err(GkrmError::BaselineStoreIo { ref cause, .. })
            if cause.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(None)
        }
        Err(_) => return Err(GkrmError::TrustedUpdateWorkspaceInvalid),
    };
    let identity =
        load_durable_workspace_identity(&app_root_open.dir).map_err(collapse_workspace_error)?;
    let app_root = canonical_directory(app_data_root)?;
    build_trusted_workspace_from_open_parent(app_root, app_root_open.dir, identity).map(Some)
}

pub fn resolve_trusted_update_workspace_from_explicit_roots(
    request: ExplicitTrustedUpdateWorkspaceRequest<'_>,
) -> Result<TrustedUpdateWorkspace> {
    let baseline_store = request.baseline_store;
    let staging_root = request.staging_root;
    let transaction_root = request.transaction_root;
    let artifact_root = request.artifact_root;
    for path in [
        baseline_store,
        staging_root,
        transaction_root,
        artifact_root,
        request.installed_root,
        request.package_file,
    ] {
        if !path.is_absolute() {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    validate_existing_source_inputs(request.installed_root, request.package_file)?;
    let app_root = common_sibling_parent([
        baseline_store,
        staging_root,
        transaction_root,
        artifact_root,
    ])?;
    let app_root_open = open_or_create_store_root_for_write(&app_root)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let identity = WorkspaceIdentityRecord::from_explicit_roots(
        baseline_store,
        staging_root,
        transaction_root,
        artifact_root,
    )?;
    let identity_exists =
        existing_workspace_identity_matches_or_absent(&app_root_open.dir, &identity)?;
    ensure_child_dir(&app_root_open.dir, &identity.baseline_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    ensure_child_dir(&app_root_open.dir, &identity.staging_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    ensure_child_dir(&app_root_open.dir, &identity.transaction_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    ensure_child_dir(&app_root_open.dir, &identity.artifact_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if !identity_exists {
        publish_workspace_identity(&app_root_open.dir, &identity)?;
    }
    let app_root = canonical_directory(&app_root)?;
    let workspace =
        build_trusted_workspace_from_open_parent(app_root, app_root_open.dir, identity)?;
    ensure_workspace_disjoint_from_sources(
        [
            &workspace.baseline_store.path,
            &workspace.staging_root.path,
            &workspace.transaction_root.path,
            &workspace.artifact_root.path,
        ],
        request.installed_root,
        request.package_file,
        request.artifact_out,
        &workspace.artifact_root.path,
    )?;
    workspace.revalidate_explicit_roots(
        baseline_store,
        staging_root,
        transaction_root,
        artifact_root,
    )?;
    Ok(workspace)
}

/// Open an existing CLI workspace from all four explicit trusted roots.
///
/// Unlike the compatibility transaction-root-only path, this retains enough
/// authority to validate artifact-bound terminal-retirement evidence. Nothing
/// is created or repaired while opening the workspace.
pub fn open_existing_trusted_update_workspace_from_explicit_roots(
    request: ExistingExplicitTrustedUpdateWorkspaceRequest<'_>,
) -> Result<TrustedUpdateWorkspace> {
    let roots = [
        request.baseline_store,
        request.staging_root,
        request.transaction_root,
        request.artifact_root,
    ];
    if roots.iter().any(|path| !path.is_absolute()) {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }

    let app_root = common_sibling_parent(roots)?;
    let app_root_open = open_existing_directory(&app_root, "trusted-update-workspace")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let identity =
        load_durable_workspace_identity(&app_root_open.dir).map_err(collapse_workspace_error)?;
    let app_root = canonical_directory(&app_root)?;
    let workspace =
        build_trusted_workspace_from_open_parent(app_root, app_root_open.dir, identity)?;
    workspace.revalidate_explicit_roots(
        request.baseline_store,
        request.staging_root,
        request.transaction_root,
        request.artifact_root,
    )?;
    Ok(workspace)
}

fn canonical_existing_workspace_root(path: &Path) -> Result<PathBuf> {
    open_existing_directory(path, "trusted-update-workspace-root")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    canonical_directory(path)
}

impl WorkspaceIdentityRecord {
    fn new(
        baseline_component: &str,
        staging_component: &str,
        transaction_component: &str,
        artifact_component: &str,
    ) -> Result<Self> {
        for component in [
            baseline_component,
            staging_component,
            transaction_component,
            artifact_component,
        ] {
            validate_workspace_component(component)?;
        }
        let record = Self {
            baseline_component: baseline_component.to_owned(),
            staging_component: staging_component.to_owned(),
            transaction_component: transaction_component.to_owned(),
            artifact_component: artifact_component.to_owned(),
        };
        if BTreeSet::from([
            record.baseline_component.as_str(),
            record.staging_component.as_str(),
            record.transaction_component.as_str(),
            record.artifact_component.as_str(),
        ])
        .len()
            != 4
        {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
        Ok(record)
    }

    fn from_explicit_roots(
        baseline_store: &Path,
        staging_root: &Path,
        transaction_root: &Path,
        artifact_root: &Path,
    ) -> Result<Self> {
        Self::new(
            workspace_component_from_path(baseline_store)?,
            workspace_component_from_path(staging_root)?,
            workspace_component_from_path(transaction_root)?,
            workspace_component_from_path(artifact_root)?,
        )
    }
}

fn workspace_component_from_path(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|component| component.to_str())
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)
}

fn validate_workspace_component(component: &str) -> Result<()> {
    if component.len() > WORKSPACE_COMPONENT_MAX_BYTES {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    validate_single_component(component).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)
}

fn workspace_identity_record_id(record: &WorkspaceIdentityRecord) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-trusted-update-workspace-v2")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    encoder.u64(u64::from(WORKSPACE_MARKER_VERSION));
    encoder
        .string(&record.baseline_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    encoder
        .string(&record.staging_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    encoder
        .string(&record.transaction_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    encoder
        .string(&record.artifact_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    Ok(encoder.finish())
}

fn encode_workspace_identity(record: &WorkspaceIdentityRecord) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(WORKSPACE_MARKER_MAGIC);
    bytes.extend_from_slice(&WORKSPACE_MARKER_VERSION.to_le_bytes());
    for component in [
        &record.baseline_component,
        &record.staging_component,
        &record.transaction_component,
        &record.artifact_component,
    ] {
        let len =
            u16::try_from(component.len()).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(component.as_bytes());
    }
    bytes.extend_from_slice(workspace_identity_record_id(record)?.as_bytes());
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|len| len > WORKSPACE_MARKER_MAX_BYTES)
    {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(bytes)
}

fn parse_workspace_identity(bytes: &[u8]) -> Result<WorkspaceIdentityRecord> {
    if bytes.starts_with(WORKSPACE_LEGACY_V1_MARKER_PREFIX) {
        return Err(GkrmError::TrustedUpdateWorkspaceLegacyUnsupported);
    }
    if !bytes.starts_with(WORKSPACE_MARKER_MAGIC) {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let mut offset = WORKSPACE_MARKER_MAGIC.len();
    let version_bytes: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    offset += 2;
    if u16::from_le_bytes(version_bytes) != WORKSPACE_MARKER_VERSION {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let mut components = Vec::with_capacity(4);
    for _ in 0..4 {
        let len_bytes: [u8; 2] = bytes
            .get(offset..offset + 2)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
        offset += 2;
        let len = usize::from(u16::from_le_bytes(len_bytes));
        if len > WORKSPACE_COMPONENT_MAX_BYTES {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
        let component = std::str::from_utf8(
            bytes
                .get(offset..offset + len)
                .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?,
        )
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        offset += len;
        validate_workspace_component(component)?;
        components.push(component.to_owned());
    }
    let expected_id = bytes
        .get(offset..offset + 32)
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    offset += 32;
    if offset != bytes.len() {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let record = WorkspaceIdentityRecord::new(
        &components[0],
        &components[1],
        &components[2],
        &components[3],
    )?;
    if workspace_identity_record_id(&record)?.as_bytes() != expected_id {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(record)
}

fn build_trusted_workspace_from_open_parent(
    app_root: PathBuf,
    app_root_dir: CapDir,
    identity: WorkspaceIdentityRecord,
) -> Result<TrustedUpdateWorkspace> {
    let app_root_identity = dir_identity(&app_root_dir, "trusted-update-workspace")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let baseline_dir = open_child_dir(&app_root_dir, &identity.baseline_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let staging_dir = open_child_dir(&app_root_dir, &identity.staging_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let transaction_dir = open_child_dir(&app_root_dir, &identity.transaction_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let artifact_dir = open_child_dir(&app_root_dir, &identity.artifact_component)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let baseline_identity = dir_identity(&baseline_dir, "trusted-update-baselines")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let staging_identity = dir_identity(&staging_dir, "trusted-update-staging")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let transaction_identity = dir_identity(&transaction_dir, "trusted-update-transactions")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let artifact_identity = dir_identity(&artifact_dir, "trusted-update-artifacts")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let all_identities = [
        &app_root_identity,
        &baseline_identity,
        &staging_identity,
        &transaction_identity,
        &artifact_identity,
    ];
    for (index, identity) in all_identities.iter().enumerate() {
        if all_identities
            .iter()
            .skip(index + 1)
            .any(|other| *other == *identity)
        {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }

    let baseline_store = app_root.join(&identity.baseline_component);
    let staging_root = app_root.join(&identity.staging_component);
    let transaction_root = app_root.join(&identity.transaction_component);
    let artifact_root = app_root.join(&identity.artifact_component);
    ensure_children_under_app_root(
        &app_root,
        [
            &baseline_store,
            &staging_root,
            &transaction_root,
            &artifact_root,
        ],
    )?;
    ensure_pairwise_disjoint([
        &baseline_store,
        &staging_root,
        &transaction_root,
        &artifact_root,
    ])?;
    let workspace = TrustedUpdateWorkspace {
        app_root,
        baseline_store: TrustedBaselineStore {
            path: baseline_store,
        },
        staging_root: TrustedWorkspaceRoot { path: staging_root },
        transaction_root: TrustedWorkspaceRoot {
            path: transaction_root,
        },
        artifact_root: TrustedArtifactRoot {
            path: artifact_root,
        },
        capabilities: Arc::new(TrustedWorkspaceCapabilities {
            app_root: app_root_dir,
            app_root_identity,
            baseline_store: baseline_dir,
            baseline_store_identity: baseline_identity,
            staging_root: staging_dir,
            staging_root_identity: staging_identity,
            transaction_root: transaction_dir,
            transaction_root_identity: transaction_identity,
            artifact_root: artifact_dir,
            artifact_root_identity: artifact_identity,
        }),
    };
    revalidate_workspace_paths(&workspace)?;
    Ok(workspace)
}

pub fn enforce_trusted_update_workspace_capacity(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedUpdateWorkspaceOptions,
) -> Result<TrustedUpdateWorkspaceUsage> {
    if options.max_regular_file_bytes == 0
        || options.max_directory_entries == 0
        || options.max_plan_artifacts == 0
        || options.max_individual_artifact_bytes == 0
    {
        return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
    }
    let mut usage = TrustedUpdateWorkspaceUsage {
        regular_file_bytes: 0,
        directory_entries: 0,
        plan_artifacts: 0,
        largest_artifact_bytes: 0,
    };
    for (root, expected_identity, is_artifact_root) in [
        (
            &workspace.capabilities.baseline_store,
            &workspace.capabilities.baseline_store_identity,
            false,
        ),
        (
            &workspace.capabilities.staging_root,
            &workspace.capabilities.staging_root_identity,
            false,
        ),
        (
            &workspace.capabilities.transaction_root,
            &workspace.capabilities.transaction_root_identity,
            false,
        ),
        (
            &workspace.capabilities.artifact_root,
            &workspace.capabilities.artifact_root_identity,
            true,
        ),
    ] {
        let root_identity = dir_identity(root, "trusted-update-workspace-capacity-root")
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        if &root_identity != expected_identity {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
        inspect_usage_dir(root, root_identity, is_artifact_root, 0, &mut usage)?;
    }
    if usage.regular_file_bytes > options.max_regular_file_bytes
        || usage.directory_entries > options.max_directory_entries
        || usage.plan_artifacts > options.max_plan_artifacts
        || usage.largest_artifact_bytes > options.max_individual_artifact_bytes
    {
        return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
    }
    Ok(usage)
}

pub fn acquire_trusted_update_workspace_publication_lock(
    workspace: &TrustedUpdateWorkspace,
) -> Result<TrustedWorkspacePublicationLock> {
    let app_root = workspace
        .capabilities
        .app_root
        .try_clone()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let before = dir_identity(&app_root, "trusted-update-workspace-lock")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if before != workspace.capabilities.app_root_identity {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let file = open_or_create_workspace_lock_file(&app_root)?;
    let after = dir_identity(&app_root, "trusted-update-workspace-lock")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if before != after {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    revalidate_workspace_paths(workspace)?;
    Ok(TrustedWorkspacePublicationLock { _file: file })
}

pub fn enforce_trusted_update_workspace_capacity_for_new_plan_artifact(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedUpdateWorkspaceOptions,
    incoming_artifact_bytes: u64,
) -> Result<TrustedUpdateWorkspaceUsage> {
    let reservation = TrustedUpdateWorkspaceReservation::new(
        incoming_artifact_bytes,
        1,
        1,
        incoming_artifact_bytes,
    )?;
    enforce_trusted_update_workspace_capacity_for_reservation(workspace, options, reservation)
}

pub fn enforce_trusted_update_workspace_capacity_for_reservation(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedUpdateWorkspaceOptions,
    reservation: TrustedUpdateWorkspaceReservation,
) -> Result<TrustedUpdateWorkspaceUsage> {
    let mut usage = enforce_trusted_update_workspace_capacity(workspace, options)?;
    usage.regular_file_bytes = usage
        .regular_file_bytes
        .checked_add(reservation.regular_file_bytes)
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    usage.directory_entries = usage
        .directory_entries
        .checked_add(reservation.directory_entries)
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    usage.plan_artifacts = usage
        .plan_artifacts
        .checked_add(reservation.plan_artifacts)
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    usage.largest_artifact_bytes = usage
        .largest_artifact_bytes
        .max(reservation.largest_artifact_bytes);
    if usage.regular_file_bytes > options.max_regular_file_bytes
        || usage.directory_entries > options.max_directory_entries
        || usage.plan_artifacts > options.max_plan_artifacts
        || usage.largest_artifact_bytes > options.max_individual_artifact_bytes
    {
        return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
    }
    Ok(usage)
}

fn canonical_directory(path: &Path) -> Result<PathBuf> {
    let _opened = open_existing_directory(path, "trusted-update-workspace")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    path.canonicalize()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)
}

fn directory_identity_for_path(path: &Path, context: &'static str) -> Result<StableFileIdentity> {
    let opened = open_existing_directory(path, context)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    dir_identity(&opened.dir, context).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)
}

fn revalidate_workspace_paths(workspace: &TrustedUpdateWorkspace) -> Result<()> {
    let capabilities = &workspace.capabilities;
    for (dir, expected, context) in [
        (
            &capabilities.app_root,
            &capabilities.app_root_identity,
            "trusted-update-workspace",
        ),
        (
            &capabilities.baseline_store,
            &capabilities.baseline_store_identity,
            "trusted-update-baselines",
        ),
        (
            &capabilities.staging_root,
            &capabilities.staging_root_identity,
            "trusted-update-staging",
        ),
        (
            &capabilities.transaction_root,
            &capabilities.transaction_root_identity,
            "trusted-update-transactions",
        ),
        (
            &capabilities.artifact_root,
            &capabilities.artifact_root_identity,
            "trusted-update-artifacts",
        ),
    ] {
        if dir_identity(dir, context).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?
            != *expected
        {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    if !path_matches_retained_root(
        workspace.app_root(),
        workspace.app_root(),
        &capabilities.app_root_identity,
        "trusted-update-workspace",
    )? || !path_matches_retained_root(
        workspace.baseline_store(),
        workspace.baseline_store(),
        &capabilities.baseline_store_identity,
        "trusted-update-baselines",
    )? || !path_matches_retained_root(
        workspace.staging_root(),
        workspace.staging_root(),
        &capabilities.staging_root_identity,
        "trusted-update-staging",
    )? || !path_matches_retained_root(
        workspace.transaction_root(),
        workspace.transaction_root(),
        &capabilities.transaction_root_identity,
        "trusted-update-transactions",
    )? || !path_matches_retained_root(
        workspace.artifact_root().path(),
        workspace.artifact_root().path(),
        &capabilities.artifact_root_identity,
        "trusted-update-artifacts",
    )? {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let app_root = workspace.app_root().to_path_buf();
    let baseline_store = workspace.baseline_store().to_path_buf();
    let staging_root = workspace.staging_root().to_path_buf();
    let transaction_root = workspace.transaction_root().to_path_buf();
    let artifact_root = workspace.artifact_root().path().to_path_buf();
    ensure_children_under_app_root(
        &app_root,
        [
            &baseline_store,
            &staging_root,
            &transaction_root,
            &artifact_root,
        ],
    )?;
    ensure_pairwise_disjoint([
        &baseline_store,
        &staging_root,
        &transaction_root,
        &artifact_root,
    ])
}

fn path_matches_retained_root(
    supplied: &Path,
    retained_path: &Path,
    retained_identity: &StableFileIdentity,
    context: &'static str,
) -> Result<bool> {
    let supplied = canonical_existing_workspace_root(supplied)?;
    if supplied != retained_path {
        return Ok(false);
    }
    Ok(directory_identity_for_path(&supplied, context)? == *retained_identity)
}

fn clone_retained_capability(
    dir: &CapDir,
    retained_identity: &StableFileIdentity,
    context: &'static str,
) -> Result<(CapDir, StableFileIdentity)> {
    let before =
        dir_identity(dir, context).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if before != *retained_identity {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let cloned = dir
        .try_clone()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let after =
        dir_identity(&cloned, context).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if after != *retained_identity {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok((cloned, after))
}

fn load_workspace_identity(parent: &CapDir) -> Result<WorkspaceIdentityRecord> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(WORKSPACE_MARKER, &options)
        .map_err(|source| GkrmError::TrustedCliUpdateIo {
            kind: source.kind(),
        })?;
    verify_regular_file(&file, WORKSPACE_MARKER)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let before = capture_stable_file_identity(&file)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let len = file
        .metadata()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?
        .len();
    if len > WORKSPACE_MARKER_MAX_BYTES {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(WORKSPACE_MARKER_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let after = capture_stable_file_identity(&file)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if before != after || u64::try_from(bytes.len()).ok() != Some(len) {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    parse_workspace_identity(&bytes)
}

fn sync_workspace_identity_parent(parent: &CapDir) -> Result<()> {
    #[cfg(test)]
    if workspace_identity_parent_sync_fault_enabled() {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    sync_dir(parent, "trusted-update-workspace-marker")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)
}

fn load_durable_workspace_identity(parent: &CapDir) -> Result<WorkspaceIdentityRecord> {
    let before = load_workspace_identity(parent)?;
    sync_workspace_identity_parent(parent)?;
    let after = load_workspace_identity(parent)?;
    if before != after {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(after)
}

fn existing_workspace_identity_matches_or_absent(
    parent: &CapDir,
    expected: &WorkspaceIdentityRecord,
) -> Result<bool> {
    match load_durable_workspace_identity(parent) {
        Ok(actual) if &actual == expected => Ok(true),
        Ok(_) => Err(GkrmError::TrustedUpdateWorkspaceInvalid),
        Err(GkrmError::TrustedCliUpdateIo {
            kind: std::io::ErrorKind::NotFound,
        }) => Ok(false),
        Err(error) => Err(collapse_workspace_error(error)),
    }
}

/// Redact a workspace failure to the single opaque invalid category, except for the
/// recognized pre-release layout. That one case is kept distinct all the way to the
/// operator because "recreate the workspace deliberately" and "your durable evidence
/// failed validation" call for entirely different responses.
fn collapse_workspace_error(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedUpdateWorkspaceLegacyUnsupported => error,
        _ => GkrmError::TrustedUpdateWorkspaceInvalid,
    }
}

fn publish_workspace_identity(parent: &CapDir, identity: &WorkspaceIdentityRecord) -> Result<()> {
    let bytes = encode_workspace_identity(identity)?;
    let temp_name = format!("{WORKSPACE_MARKER_TEMP_PREFIX}{}", Uuid::new_v4());
    validate_single_component(&temp_name).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let mut file = create_new_file(parent, &temp_name)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let published = (|| -> Result<()> {
        file.write_all(&bytes)
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        fsync_file(&file, "trusted-update-workspace-marker")
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        drop(file);
        sync_dir(parent, "trusted-update-workspace-marker-temp")
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        match rename_file_noreplace(parent, &temp_name, WORKSPACE_MARKER) {
            Ok(()) => {
                sync_workspace_identity_parent(parent)?;
                let loaded = load_workspace_identity(parent)
                    .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
                if loaded != *identity {
                    return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let loaded = load_workspace_identity(parent)
                    .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
                if loaded != *identity {
                    return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
                }
                let _ = parent.remove_file(&temp_name);
                let durable = load_durable_workspace_identity(parent)?;
                if durable != *identity {
                    return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
                }
            }
            Err(_) => return Err(GkrmError::TrustedUpdateWorkspaceInvalid),
        }
        Ok(())
    })();
    let _ = parent.remove_file(&temp_name);
    published
}

fn common_sibling_parent<const N: usize>(paths: [&Path; N]) -> Result<PathBuf> {
    let Some(first_parent) = paths[0].parent() else {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    };
    for path in paths.iter().skip(1) {
        if path.parent() != Some(first_parent) {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    if first_parent == paths[0] {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(first_parent.to_path_buf())
}

fn validate_existing_source_inputs(installed_root: &Path, package_file: &Path) -> Result<()> {
    open_existing_directory(installed_root, "trusted-update-installed")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let parent = package_file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let name = package_file
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    validate_single_component(name).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let parent = open_existing_directory(parent, "trusted-update-package-parent")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let file = open_file_nofollow(&parent.dir, name)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    verify_regular_file(&file, name).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)
}

fn ensure_workspace_disjoint_from_sources<const N: usize>(
    workspace_roots: [&PathBuf; N],
    installed_root: &Path,
    package_file: &Path,
    artifact_out: &Path,
    artifact_root: &Path,
) -> Result<()> {
    let installed = canonical_directory(installed_root)?;
    let package = package_file
        .canonicalize()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let artifact_root = canonical_directory(artifact_root)?;
    let artifact_out_parent = artifact_out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let artifact_out_parent = canonical_directory(artifact_out_parent)?;
    if !artifact_out_parent.starts_with(&artifact_root) {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    let artifact_out_name = artifact_out
        .file_name()
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let artifact_out_canonical = artifact_out_parent.join(artifact_out_name);
    for root in workspace_roots {
        let root = canonical_directory(root)?;
        if paths_overlap_canonical(&root, &installed) || paths_overlap_canonical(&root, &package) {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
        if package.starts_with(&root) {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    if paths_overlap_canonical(&artifact_out_canonical, &installed)
        || paths_overlap_canonical(&artifact_out_canonical, &package)
    {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(())
}

fn paths_overlap_canonical(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn ensure_children_under_app_root<const N: usize>(
    app_root: &Path,
    children: [&PathBuf; N],
) -> Result<()> {
    for child in children {
        let canonical = canonical_directory(child)?;
        if !canonical.starts_with(app_root) || canonical == app_root {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    Ok(())
}

fn ensure_pairwise_disjoint<const N: usize>(paths: [&PathBuf; N]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for path in paths {
        let canonical = canonical_directory(path)?;
        if !seen.insert(canonical) {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    Ok(())
}

fn inspect_usage_dir(
    dir: &CapDir,
    expected_identity: StableFileIdentity,
    artifact_root: bool,
    depth: usize,
    usage: &mut TrustedUpdateWorkspaceUsage,
) -> Result<()> {
    if depth > MAX_WORKSPACE_TRAVERSAL_DEPTH {
        return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
    }
    let current = dir_identity(dir, "trusted-update-workspace-capacity-dir")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if current != expected_identity {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    usage.directory_entries = usage
        .directory_entries
        .checked_add(1)
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    let entries = dir
        .entries()
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    for entry in entries {
        let entry = entry.map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        validate_single_component(&name).map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        let metadata = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
        reject_workspace_entry_metadata(&metadata)?;
        if metadata.file_type().is_file() {
            usage.directory_entries = usage
                .directory_entries
                .checked_add(1)
                .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
            usage.regular_file_bytes = usage
                .regular_file_bytes
                .checked_add(metadata.len())
                .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
            if artifact_root && is_plan_artifact_name(&name) {
                usage.plan_artifacts = usage
                    .plan_artifacts
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
                usage.largest_artifact_bytes = usage.largest_artifact_bytes.max(metadata.len());
            }
        } else if metadata.file_type().is_dir() {
            #[cfg(test)]
            run_capacity_race_hook(&name);
            let child = dir
                .open_dir_nofollow(&name)
                .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
            let opened_metadata = child
                .dir_metadata()
                .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
            reject_workspace_entry_metadata(&opened_metadata)?;
            if !opened_metadata.file_type().is_dir()
                || metadata_identity(&metadata) != metadata_identity(&opened_metadata)
            {
                return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
            }
            inspect_usage_dir(
                &child,
                metadata_identity(&metadata),
                false,
                depth + 1,
                usage,
            )?;
        } else {
            return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
        }
    }
    let current_after = dir_identity(dir, "trusted-update-workspace-capacity-dir")
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    if current_after != expected_identity {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(())
}

fn reject_workspace_entry_metadata(metadata: &CapMetadata) -> Result<()> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point_cap(metadata) {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    if !metadata.file_type().is_dir() && !metadata.file_type().is_file() {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(())
}

fn metadata_identity(metadata: &CapMetadata) -> StableFileIdentity {
    #[cfg(unix)]
    {
        StableFileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    #[cfg(windows)]
    {
        StableFileIdentity::Windows {
            volume_serial: metadata.dev(),
            file_index: metadata.ino(),
        }
    }
}

fn open_or_create_workspace_lock_file(parent: &CapDir) -> Result<CapFile> {
    match try_open_workspace_lock(parent) {
        Ok(file) => return Ok(file),
        Err(GkrmError::TrustedCliUpdateIo {
            kind: std::io::ErrorKind::NotFound,
        }) => {}
        Err(GkrmError::BaselineStoreMissing { .. }) => {}
        Err(error) => return Err(error),
    }
    match create_new_file(parent, WORKSPACE_PUBLICATION_LOCK) {
        Ok(mut file) => {
            file.write_all(WORKSPACE_PUBLICATION_LOCK_MAGIC)
                .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
            fsync_file(&file, "trusted-update-workspace-lock").map_err(|_| {
                GkrmError::TrustedCliUpdateIo {
                    kind: std::io::ErrorKind::Other,
                }
            })?;
            drop(file);
            sync_dir(parent, "trusted-update-workspace-lock").map_err(|_| {
                GkrmError::TrustedCliUpdateIo {
                    kind: std::io::ErrorKind::Other,
                }
            })?;
            try_open_workspace_lock(parent)
        }
        Err(error) => {
            if matches!(
                error,
                GkrmError::BaselineStoreIo { ref cause, .. }
                    if cause.kind() == std::io::ErrorKind::AlreadyExists
            ) {
                try_open_workspace_lock(parent)
            } else {
                Err(GkrmError::TrustedUpdateWorkspaceInvalid)
            }
        }
    }
}

fn try_open_workspace_lock(parent: &CapDir) -> Result<CapFile> {
    let mut options = OpenOptions::new();
    options.read(true);
    options.write(true);
    options.follow(FollowSymlinks::No);
    let mut file = parent
        .open_with(WORKSPACE_PUBLICATION_LOCK, &options)
        .map_err(|source| GkrmError::TrustedCliUpdateIo {
            kind: source.kind(),
        })?;
    verify_regular_file(&file, WORKSPACE_PUBLICATION_LOCK)
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceInvalid)?;
    try_lock_workspace_file(&file)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    if bytes != WORKSPACE_PUBLICATION_LOCK_MAGIC {
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    Ok(file)
}

fn try_lock_workspace_file(file: &CapFile) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
        }
        return Err(GkrmError::TrustedUpdateWorkspaceInvalid);
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            h_event: *mut core::ffi::c_void,
        }
        extern "system" {
            fn LockFileEx(
                h_file: *mut core::ffi::c_void,
                dw_flags: u32,
                dw_reserved: u32,
                n_number_of_bytes_to_lock_low: u32,
                n_number_of_bytes_to_lock_high: u32,
                lp_overlapped: *mut Overlapped,
            ) -> i32;
            fn GetLastError() -> u32;
        }
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
        const ERROR_LOCK_VIOLATION: u32 = 33;
        const ERROR_IO_PENDING: u32 = 997;
        const ERROR_BUSY: u32 = 170;
        const ERROR_SHARING_VIOLATION: u32 = 32;
        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: core::ptr::null_mut(),
        };
        let ok = unsafe {
            LockFileEx(
                file.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if matches!(
            code,
            ERROR_LOCK_VIOLATION | ERROR_IO_PENDING | ERROR_BUSY | ERROR_SHARING_VIOLATION
        ) {
            return Err(GkrmError::TrustedUpdateWorkspaceCapacityReached);
        }
        Err(GkrmError::TrustedUpdateWorkspaceInvalid)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(GkrmError::TrustedUpdateWorkspaceInvalid)
    }
}

fn is_plan_artifact_name(name: &str) -> bool {
    name.starts_with(PLAN_ARTIFACT_PREFIX) && name.ends_with(PLAN_ARTIFACT_SUFFIX)
}

#[cfg(test)]
type CapacityRaceHook = std::cell::RefCell<Option<Box<dyn Fn(&str)>>>;

#[cfg(test)]
thread_local! {
    static WORKSPACE_IDENTITY_PARENT_SYNC_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn workspace_identity_parent_sync_fault_enabled() -> bool {
    WORKSPACE_IDENTITY_PARENT_SYNC_FAULT.get()
}

#[cfg(test)]
fn with_workspace_identity_parent_sync_fault<T>(f: impl FnOnce() -> T) -> T {
    struct Guard(bool);

    impl Drop for Guard {
        fn drop(&mut self) {
            WORKSPACE_IDENTITY_PARENT_SYNC_FAULT.set(self.0);
        }
    }

    let previous = WORKSPACE_IDENTITY_PARENT_SYNC_FAULT.replace(true);
    let _guard = Guard(previous);
    f()
}

#[cfg(test)]
thread_local! {
    static CAPACITY_RACE_HOOK: CapacityRaceHook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_capacity_race_hook(name: &str) {
    CAPACITY_RACE_HOOK.with(|hook| {
        if let Some(callback) = hook.borrow().as_ref() {
            callback(name);
        }
    });
}

#[cfg(test)]
fn with_capacity_race_hook<T>(hook: impl Fn(&str) + 'static, f: impl FnOnce() -> T) -> T {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            CAPACITY_RACE_HOOK.with(|hook| hook.borrow_mut().take());
        }
    }
    CAPACITY_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    let _guard = Guard;
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn workspace_derives_core_owned_roots() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        assert!(workspace.baseline_store().ends_with(BASELINES_DIR));
        assert!(workspace.staging_root().ends_with(STAGING_DIR));
        assert!(workspace.transaction_root().ends_with(TRANSACTIONS_DIR));
        assert!(workspace.artifact_root().path().ends_with(ARTIFACTS_DIR));
    }

    #[test]
    fn workspace_rejects_relative_app_data_root() {
        let err = resolve_trusted_update_workspace(Path::new("relative-app-data")).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn capacity_counts_published_artifacts() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let artifact = workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        fs::write(&artifact, b"artifact").unwrap();
        let usage = enforce_trusted_update_workspace_capacity(
            &workspace,
            TrustedUpdateWorkspaceOptions::default(),
        )
        .unwrap();
        assert_eq!(usage.plan_artifacts(), 1);
        assert!(usage.regular_file_bytes() >= 8);
    }

    #[test]
    fn capacity_rejects_without_cleanup() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let artifact = workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        fs::write(&artifact, b"artifact").unwrap();
        let err = enforce_trusted_update_workspace_capacity(
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
        assert!(artifact.exists());
    }

    #[test]
    fn capacity_traversal_rejects_directory_replaced_after_metadata() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let nested = workspace.artifact_root().path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("before.bin"), b"before").unwrap();
        let replacement = workspace.artifact_root().path().join("replacement");
        fs::create_dir(&replacement).unwrap();
        fs::write(replacement.join("after.bin"), b"after").unwrap();

        let nested_for_hook = nested.clone();
        let replacement_for_hook = replacement.clone();
        let err = with_capacity_race_hook(
            move |name| {
                if name == "nested" {
                    fs::remove_file(nested_for_hook.join("before.bin")).unwrap();
                    fs::remove_dir(&nested_for_hook).unwrap();
                    fs::rename(&replacement_for_hook, &nested_for_hook).unwrap();
                }
            },
            || {
                enforce_trusted_update_workspace_capacity(
                    &workspace,
                    TrustedUpdateWorkspaceOptions::default(),
                )
            },
        )
        .unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[cfg(unix)]
    #[test]
    fn capacity_traversal_rejects_directory_replaced_by_symlink_after_metadata() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let nested = workspace.artifact_root().path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("before.bin"), b"before").unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("after.bin"), b"after").unwrap();

        let nested_for_hook = nested.clone();
        let outside_for_hook = outside.clone();
        let err = with_capacity_race_hook(
            move |name| {
                if name == "nested" {
                    fs::remove_file(nested_for_hook.join("before.bin")).unwrap();
                    fs::remove_dir(&nested_for_hook).unwrap();
                    symlink(&outside_for_hook, &nested_for_hook).unwrap();
                }
            },
            || {
                enforce_trusted_update_workspace_capacity(
                    &workspace,
                    TrustedUpdateWorkspaceOptions::default(),
                )
            },
        )
        .unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[cfg(windows)]
    #[test]
    fn capacity_traversal_rejects_directory_replaced_by_junction_after_metadata() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let nested = workspace.artifact_root().path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("before.bin"), b"before").unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("after.bin"), b"after").unwrap();

        let nested_for_hook = nested.clone();
        let outside_for_hook = outside.clone();
        let err = with_capacity_race_hook(
            move |name| {
                if name == "nested" {
                    fs::remove_file(nested_for_hook.join("before.bin")).unwrap();
                    fs::remove_dir(&nested_for_hook).unwrap();
                    create_junction(&outside_for_hook, &nested_for_hook);
                }
            },
            || {
                enforce_trusted_update_workspace_capacity(
                    &workspace,
                    TrustedUpdateWorkspaceOptions::default(),
                )
            },
        )
        .unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
        assert_eq!(fs::read(outside.join("after.bin")).unwrap(), b"after");
    }

    #[test]
    fn incoming_artifact_capacity_is_checked_before_publication() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let err = enforce_trusted_update_workspace_capacity_for_new_plan_artifact(
            &workspace,
            TrustedUpdateWorkspaceOptions {
                max_regular_file_bytes: 4,
                max_individual_artifact_bytes: 4,
                ..TrustedUpdateWorkspaceOptions::default()
            },
            5,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
        ));
    }

    #[test]
    fn workspace_publication_lock_rejects_real_os_contention_until_drop() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let first = acquire_trusted_update_workspace_publication_lock(&workspace).unwrap();
        let err = match acquire_trusted_update_workspace_publication_lock(&workspace) {
            Ok(_) => panic!("second workspace publication lock must not be acquired"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
                | GkrmError::TrustedUpdateWorkspaceInvalid
        ));
        drop(first);
        acquire_trusted_update_workspace_publication_lock(&workspace).unwrap();
    }

    #[test]
    fn workspace_publication_lock_rejects_separate_process_contention() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};

        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("trusted_update_workspace::tests::workspace_publication_lock_child_process_holds_lock")
            .arg("--exact")
            .arg("--nocapture")
            .env("GKRM_WORKSPACE_LOCK_CHILD_ROOT", temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut observed = String::new();
        for _ in 0..16 {
            let mut line = String::new();
            let read = reader.read_line(&mut line).unwrap();
            assert!(read != 0, "child exited before acquiring workspace lock");
            observed.push_str(&line);
            if line.contains("gkrm-workspace-lock-child-ready") {
                break;
            }
        }
        assert!(
            observed.contains("gkrm-workspace-lock-child-ready"),
            "unexpected child output: {observed:?}"
        );
        let err = match acquire_trusted_update_workspace_publication_lock(&workspace) {
            Ok(_) => {
                drop(child.stdin.take());
                let _ = child.kill();
                panic!("parent must not acquire lock held by child process");
            }
            Err(err) => err,
        };
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
                | GkrmError::TrustedUpdateWorkspaceInvalid
        ));
        drop(child.stdin.take());
        let status = child.wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn workspace_publication_lock_child_process_holds_lock() {
        use std::io::{Read, Write};

        let Ok(root) = std::env::var("GKRM_WORKSPACE_LOCK_CHILD_ROOT") else {
            return;
        };
        let workspace = resolve_trusted_update_workspace(Path::new(&root)).unwrap();
        let _lock = acquire_trusted_update_workspace_publication_lock(&workspace).unwrap();
        println!("gkrm-workspace-lock-child-ready");
        std::io::stdout().flush().unwrap();
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer).unwrap();
    }

    #[test]
    fn explicit_cli_workspace_uses_shared_publication_lock() {
        let temp = tempdir().unwrap();
        let baseline = temp.path().join("store");
        let staging = temp.path().join("staging");
        let transactions = temp.path().join("txn");
        let artifacts = temp.path().join("out");
        let installed = temp.path().join("installed");
        fs::create_dir(&installed).unwrap();
        let package = temp.path().join("package.zip");
        fs::write(&package, b"zip").unwrap();
        let artifact_out = artifacts.join("plan.bin");
        let workspace = resolve_trusted_update_workspace_from_explicit_roots(
            ExplicitTrustedUpdateWorkspaceRequest {
                baseline_store: &baseline,
                staging_root: &staging,
                transaction_root: &transactions,
                artifact_root: &artifacts,
                artifact_out: &artifact_out,
                installed_root: &installed,
                package_file: &package,
            },
        )
        .unwrap();
        assert_eq!(workspace.baseline_store(), baseline.canonicalize().unwrap());
        assert_eq!(workspace.staging_root(), staging.canonicalize().unwrap());
        assert_eq!(
            workspace.transaction_root(),
            transactions.canonicalize().unwrap()
        );
        assert_eq!(
            workspace.artifact_root().path(),
            artifacts.canonicalize().unwrap()
        );
        let first = acquire_trusted_update_workspace_publication_lock(&workspace).unwrap();
        let err = match acquire_trusted_update_workspace_publication_lock(&workspace) {
            Ok(_) => panic!("second explicit workspace publication lock must not be acquired"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
                | GkrmError::TrustedUpdateWorkspaceInvalid
        ));
        drop(first);
    }

    struct ExplicitWorkspaceFixture {
        _temp: tempfile::TempDir,
        baseline: PathBuf,
        staging: PathBuf,
        transactions: PathBuf,
        artifacts: PathBuf,
        artifact_out: PathBuf,
        installed: PathBuf,
        package: PathBuf,
    }

    fn explicit_workspace_fixture() -> ExplicitWorkspaceFixture {
        let temp = tempdir().unwrap();
        let baseline = temp.path().join("store");
        let staging = temp.path().join("staging");
        let transactions = temp.path().join("txn");
        let artifacts = temp.path().join("out");
        let artifact_out = artifacts.join("plan.bin");
        let installed = temp.path().join("installed");
        let package = temp.path().join("package.zip");
        fs::create_dir(&installed).unwrap();
        fs::write(&package, b"zip").unwrap();
        ExplicitWorkspaceFixture {
            _temp: temp,
            baseline,
            staging,
            transactions,
            artifacts,
            artifact_out,
            installed,
            package,
        }
    }

    fn resolve_explicit_fixture(
        fixture: &ExplicitWorkspaceFixture,
    ) -> Result<TrustedUpdateWorkspace> {
        resolve_trusted_update_workspace_from_explicit_roots(
            ExplicitTrustedUpdateWorkspaceRequest {
                baseline_store: &fixture.baseline,
                staging_root: &fixture.staging,
                transaction_root: &fixture.transactions,
                artifact_root: &fixture.artifacts,
                artifact_out: &fixture.artifact_out,
                installed_root: &fixture.installed,
                package_file: &fixture.package,
            },
        )
    }

    fn open_explicit_roots(
        baseline: &Path,
        staging: &Path,
        transactions: &Path,
        artifacts: &Path,
    ) -> Result<TrustedUpdateWorkspace> {
        open_existing_trusted_update_workspace_from_explicit_roots(
            ExistingExplicitTrustedUpdateWorkspaceRequest {
                baseline_store: baseline,
                staging_root: staging,
                transaction_root: transactions,
                artifact_root: artifacts,
            },
        )
    }

    #[test]
    fn existing_explicit_cli_workspace_reopens_only_the_complete_marked_root_set() {
        let fixture = explicit_workspace_fixture();
        let resolved = resolve_explicit_fixture(&fixture).unwrap();
        let expected = (
            resolved.baseline_store().to_path_buf(),
            resolved.staging_root().to_path_buf(),
            resolved.transaction_root().to_path_buf(),
            resolved.artifact_root().path().to_path_buf(),
        );
        drop(resolved);
        let reopened = open_explicit_roots(
            &fixture.baseline,
            &fixture.staging,
            &fixture.transactions,
            &fixture.artifacts,
        )
        .unwrap();
        assert_eq!(reopened.baseline_store(), expected.0);
        assert_eq!(reopened.staging_root(), expected.1);
        assert_eq!(reopened.transaction_root(), expected.2);
        assert_eq!(reopened.artifact_root().path(), expected.3);

        let unrelated = tempdir().unwrap();
        for name in ["store", "staging", "txn", "out"] {
            fs::create_dir(unrelated.path().join(name)).unwrap();
        }
        let error = open_existing_trusted_update_workspace_from_explicit_roots(
            ExistingExplicitTrustedUpdateWorkspaceRequest {
                baseline_store: &unrelated.path().join("store"),
                staging_root: &unrelated.path().join("staging"),
                transaction_root: &unrelated.path().join("txn"),
                artifact_root: &unrelated.path().join("out"),
            },
        )
        .unwrap_err();
        assert!(matches!(error, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn marked_parent_rejects_all_alternate_roots_mixed_substitutions_and_role_swaps() {
        let fixture = explicit_workspace_fixture();
        let workspace = resolve_explicit_fixture(&fixture).unwrap();
        drop(workspace);
        let alternate = [
            fixture._temp.path().join("store-2"),
            fixture._temp.path().join("staging-2"),
            fixture._temp.path().join("txn-2"),
            fixture._temp.path().join("out-2"),
        ];
        for root in &alternate {
            fs::create_dir(root).unwrap();
        }

        for roots in [
            [&alternate[0], &alternate[1], &alternate[2], &alternate[3]],
            [
                &alternate[0],
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            ],
            [
                &fixture.baseline,
                &alternate[1],
                &fixture.transactions,
                &fixture.artifacts,
            ],
            [
                &fixture.baseline,
                &fixture.staging,
                &alternate[2],
                &fixture.artifacts,
            ],
            [
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &alternate[3],
            ],
            [
                &fixture.baseline,
                &fixture.staging,
                &fixture.artifacts,
                &fixture.transactions,
            ],
        ] {
            let error = open_explicit_roots(roots[0], roots[1], roots[2], roots[3]).unwrap_err();
            assert!(matches!(error, GkrmError::TrustedUpdateWorkspaceInvalid));
        }
        open_explicit_roots(
            &fixture.baseline,
            &fixture.staging,
            &fixture.transactions,
            &fixture.artifacts,
        )
        .unwrap();
    }

    #[test]
    fn strong_workspace_marker_tamper_and_unsupported_versions_fail_closed() {
        for mutation in 0..5 {
            let fixture = explicit_workspace_fixture();
            drop(resolve_explicit_fixture(&fixture).unwrap());
            let marker = fixture._temp.path().join(WORKSPACE_MARKER);
            let mut bytes = fs::read(&marker).unwrap();
            match mutation {
                0 => bytes.truncate(bytes.len() - 1),
                1 => bytes[WORKSPACE_MARKER_MAGIC.len()] = 3,
                2 => {
                    let first_component = WORKSPACE_MARKER_MAGIC.len() + 2 + 2;
                    bytes[first_component] ^= 1;
                }
                3 => {
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                }
                4 => bytes.extend_from_slice(b"trailing-garbage"),
                _ => unreachable!(),
            }
            fs::write(&marker, &bytes).unwrap();
            let error = open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            )
            .unwrap_err();
            assert!(matches!(error, GkrmError::TrustedUpdateWorkspaceInvalid));
        }
    }

    #[test]
    fn weak_workspace_marker_is_rejected_without_migration_or_rewrite() {
        let fixture = explicit_workspace_fixture();
        for root in [
            &fixture.baseline,
            &fixture.staging,
            &fixture.transactions,
            &fixture.artifacts,
        ] {
            fs::create_dir(root).unwrap();
        }
        let marker = fixture._temp.path().join(WORKSPACE_MARKER);
        let weak = b"gkrm-trusted-update-workspace-v1\n";
        fs::write(&marker, weak).unwrap();
        // Still refused, still never migrated or rewritten — but reported as the recognized
        // pre-release layout so the operator is told to recreate the workspace rather than
        // being told their durable evidence failed validation.
        assert!(matches!(
            open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            ),
            Err(GkrmError::TrustedUpdateWorkspaceLegacyUnsupported)
        ));
        assert!(matches!(
            resolve_explicit_fixture(&fixture),
            Err(GkrmError::TrustedUpdateWorkspaceLegacyUnsupported)
        ));
        assert!(matches!(
            open_existing_trusted_update_workspace(fixture._temp.path()),
            Err(GkrmError::TrustedUpdateWorkspaceLegacyUnsupported)
        ));
        assert_eq!(fs::read(marker).unwrap(), weak);
    }

    #[test]
    fn a_damaged_marker_stays_the_opaque_invalid_category() {
        let fixture = explicit_workspace_fixture();
        for root in [
            &fixture.baseline,
            &fixture.staging,
            &fixture.transactions,
            &fixture.artifacts,
        ] {
            fs::create_dir(root).unwrap();
        }
        let marker = fixture._temp.path().join(WORKSPACE_MARKER);
        for damaged in [
            b"gkrm-trusted-update-workspace-v9\n".to_vec(),
            b"not a workspace marker at all\n".to_vec(),
            Vec::new(),
        ] {
            fs::write(&marker, &damaged).unwrap();
            assert!(
                matches!(
                    open_existing_trusted_update_workspace(fixture._temp.path()),
                    Err(GkrmError::TrustedUpdateWorkspaceInvalid)
                ),
                "unexpected classification for {damaged:?}"
            );
        }
    }

    #[test]
    fn post_rename_sync_failure_cannot_grant_authority_and_exact_retry_is_durable() {
        let fixture = explicit_workspace_fixture();
        let publish_error = with_workspace_identity_parent_sync_fault(|| {
            let error = resolve_explicit_fixture(&fixture).unwrap_err();
            assert!(matches!(error, GkrmError::TrustedUpdateWorkspaceInvalid));
            assert!(fixture._temp.path().join(WORKSPACE_MARKER).is_file());

            let reopen_error = open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            )
            .unwrap_err();
            assert!(matches!(
                reopen_error,
                GkrmError::TrustedUpdateWorkspaceInvalid
            ));
            error
        });
        assert!(matches!(
            publish_error,
            GkrmError::TrustedUpdateWorkspaceInvalid
        ));

        let marker = fixture._temp.path().join(WORKSPACE_MARKER);
        let marker_before_retry = fs::read(&marker).unwrap();
        let workspace = resolve_explicit_fixture(&fixture).unwrap();
        assert_eq!(fs::read(&marker).unwrap(), marker_before_retry);
        drop(workspace);

        let alternate = [
            fixture._temp.path().join("store-uncertain-alt"),
            fixture._temp.path().join("staging-uncertain-alt"),
            fixture._temp.path().join("txn-uncertain-alt"),
            fixture._temp.path().join("out-uncertain-alt"),
        ];
        for root in &alternate {
            fs::create_dir(root).unwrap();
        }
        assert!(matches!(
            open_explicit_roots(&alternate[0], &alternate[1], &alternate[2], &alternate[3]),
            Err(GkrmError::TrustedUpdateWorkspaceInvalid)
        ));
        assert_eq!(fs::read(&marker).unwrap(), marker_before_retry);
        open_explicit_roots(
            &fixture.baseline,
            &fixture.staging,
            &fixture.transactions,
            &fixture.artifacts,
        )
        .unwrap();
        assert_eq!(fs::read(marker).unwrap(), marker_before_retry);
    }

    #[test]
    fn existing_workspace_opener_is_read_only_and_missing_bound_root_is_not_recreated() {
        let fixture = explicit_workspace_fixture();
        drop(resolve_explicit_fixture(&fixture).unwrap());
        let before = crate::trusted_staging::test_support::hash_tree(fixture._temp.path());
        drop(
            open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            )
            .unwrap(),
        );
        assert_eq!(
            crate::trusted_staging::test_support::hash_tree(fixture._temp.path()),
            before
        );

        fs::remove_dir(&fixture.transactions).unwrap();
        assert!(matches!(
            open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            ),
            Err(GkrmError::TrustedUpdateWorkspaceInvalid)
        ));
        assert!(!fixture.transactions.exists());
    }

    #[test]
    fn conflicting_workspace_rebinding_rejects_before_creating_alternate_roots() {
        let fixture = explicit_workspace_fixture();
        drop(resolve_explicit_fixture(&fixture).unwrap());
        let alternate = ExplicitWorkspaceFixture {
            baseline: fixture._temp.path().join("store-2"),
            staging: fixture._temp.path().join("staging-2"),
            transactions: fixture._temp.path().join("txn-2"),
            artifacts: fixture._temp.path().join("out-2"),
            artifact_out: fixture._temp.path().join("out-2").join("plan.bin"),
            installed: fixture.installed.clone(),
            package: fixture.package.clone(),
            _temp: fixture._temp,
        };
        assert!(matches!(
            resolve_explicit_fixture(&alternate),
            Err(GkrmError::TrustedUpdateWorkspaceInvalid)
        ));
        for root in [
            &alternate.baseline,
            &alternate.staging,
            &alternate.transactions,
            &alternate.artifacts,
        ] {
            assert!(!root.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_workspace_rejects_bound_root_replaced_by_symlink() {
        use std::os::unix::fs::symlink;

        let fixture = explicit_workspace_fixture();
        drop(resolve_explicit_fixture(&fixture).unwrap());
        let original = fixture._temp.path().join("store-original");
        fs::rename(&fixture.baseline, &original).unwrap();
        let outside = fixture._temp.path().join("outside-store");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &fixture.baseline).unwrap();
        assert!(matches!(
            open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            ),
            Err(GkrmError::TrustedUpdateWorkspaceInvalid)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn existing_workspace_rejects_bound_root_replaced_by_junction() {
        let fixture = explicit_workspace_fixture();
        drop(resolve_explicit_fixture(&fixture).unwrap());
        let original = fixture._temp.path().join("store-original");
        fs::rename(&fixture.baseline, &original).unwrap();
        let outside = fixture._temp.path().join("outside-store");
        fs::create_dir(&outside).unwrap();
        create_junction(&outside, &fixture.baseline);
        assert!(matches!(
            open_explicit_roots(
                &fixture.baseline,
                &fixture.staging,
                &fixture.transactions,
                &fixture.artifacts,
            ),
            Err(GkrmError::TrustedUpdateWorkspaceInvalid)
        ));
    }

    #[test]
    fn explicit_cli_workspace_rejects_installed_overlap_with_workspace_root() {
        let fixture = explicit_workspace_fixture();
        fs::create_dir_all(&fixture.staging).unwrap();
        let installed_inside_staging = fixture.staging.join("installed");
        fs::create_dir(&installed_inside_staging).unwrap();
        let fixture = ExplicitWorkspaceFixture {
            installed: installed_inside_staging,
            ..fixture
        };
        let err = resolve_explicit_fixture(&fixture).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn explicit_cli_workspace_rejects_workspace_root_inside_installed() {
        let fixture = explicit_workspace_fixture();
        let installed = fixture._temp.path().join("installed-parent");
        fs::create_dir(&installed).unwrap();
        let fixture = ExplicitWorkspaceFixture {
            baseline: installed.join("store"),
            staging: installed.join("staging"),
            transactions: installed.join("txn"),
            artifacts: installed.join("out"),
            artifact_out: installed.join("out").join("plan.bin"),
            installed,
            ..fixture
        };
        let err = resolve_explicit_fixture(&fixture).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn explicit_cli_workspace_rejects_package_inside_artifact_root() {
        let fixture = explicit_workspace_fixture();
        fs::create_dir_all(&fixture.artifacts).unwrap();
        let package = fixture.artifacts.join("package.zip");
        fs::write(&package, b"zip").unwrap();
        let fixture = ExplicitWorkspaceFixture { package, ..fixture };
        let err = resolve_explicit_fixture(&fixture).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn explicit_cli_workspace_rejects_artifact_output_overlapping_package() {
        let fixture = explicit_workspace_fixture();
        let artifact_out = fixture.artifacts.join("package.zip");
        fs::create_dir_all(&fixture.artifacts).unwrap();
        fs::write(&artifact_out, b"zip").unwrap();
        let fixture = ExplicitWorkspaceFixture {
            package: artifact_out.clone(),
            artifact_out,
            ..fixture
        };
        let err = resolve_explicit_fixture(&fixture).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn explicit_cli_workspace_rejects_artifact_output_outside_artifact_root() {
        let fixture = explicit_workspace_fixture();
        let artifact_out = fixture._temp.path().join("other").join("plan.bin");
        fs::create_dir_all(artifact_out.parent().unwrap()).unwrap();
        let fixture = ExplicitWorkspaceFixture {
            artifact_out,
            ..fixture
        };
        let err = resolve_explicit_fixture(&fixture).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[test]
    fn workspace_rejects_child_replaced_by_file() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join(BASELINES_DIR), b"not a directory").unwrap();
        let err = resolve_trusted_update_workspace(temp.path()).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_rejects_symlink_child() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let target = temp.path().join("outside");
        fs::create_dir(&target).unwrap();
        symlink(&target, temp.path().join(BASELINES_DIR)).unwrap();
        let err = resolve_trusted_update_workspace(temp.path()).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
    }

    #[cfg(windows)]
    fn create_junction(target: &Path, link: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .status()
            .expect("run mklink");
        assert!(status.success(), "directory junction creation must succeed");
    }

    #[cfg(windows)]
    #[test]
    fn workspace_rejects_baselines_junction_child() {
        let temp = tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("marker.txt"), b"untouched").unwrap();
        create_junction(&outside, &temp.path().join(BASELINES_DIR));

        let err = resolve_trusted_update_workspace(temp.path()).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
        assert_eq!(fs::read(outside.join("marker.txt")).unwrap(), b"untouched");
    }

    #[cfg(windows)]
    #[test]
    fn workspace_rejects_artifacts_junction_child() {
        let temp = tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("marker.txt"), b"untouched").unwrap();
        create_junction(&outside, &temp.path().join(ARTIFACTS_DIR));

        let err = resolve_trusted_update_workspace(temp.path()).unwrap_err();
        assert!(matches!(err, GkrmError::TrustedUpdateWorkspaceInvalid));
        assert_eq!(fs::read(outside.join("marker.txt")).unwrap(), b"untouched");
    }
}
