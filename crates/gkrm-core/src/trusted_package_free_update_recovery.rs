//! Restart-safe Task 31B recovery from Task 31A durable v2 authority.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};
use std::path::Path;

mod baselines;
mod history;
mod undo;
pub(crate) use baselines::validate_two_way_baseline_transition;
pub use baselines::{discard_unreferenced_trusted_baseline, referenced_trusted_baselines};
pub use history::{inspect_trusted_two_way_updates, TrustedTwoWayUpdateRecord};
pub(crate) use undo::trusted_two_way_causal_head;
pub use undo::{
    inspect_trusted_undo_receipts, TrustedUndoDisposition, TrustedUndoExecutionOutcome,
    TrustedUndoFileChange, TrustedUndoPlan, TrustedUndoPlanEntry, TrustedUndoReceipt,
    TrustedUndoSource,
};

#[cfg(test)]
use std::cell::{Cell, RefCell};

use cap_fs_ext::DirEntryExt;
use cap_std::fs::Dir as CapDir;

use crate::baseline::fs_security::{
    create_new_file, dir_identity, ensure_child_dir, open_child_dir, open_existing_directory,
    open_file_nofollow, try_open_child_dir, validate_single_component,
};
use crate::baseline::store::{allocate_temp_name, fsync_file, rename_noreplace_relative, sync_dir};
use crate::file_identity::{
    capture_stable_file_identity, is_windows_reparse_point_cap, StableFileIdentity,
};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::trusted_apply_planning::InstalledApplyPlanningSource;
use crate::trusted_cli_update_artifact::{
    descriptor_apply_graph, parse_cli_artifact, TrustedCliUpdateArtifact, TrustedCliUpdateOptions,
    ARTIFACT_V2_FORMAT_VERSION,
};
use crate::trusted_recovery_authority::{
    build_recovery_authority_body, dispatch_recovery_derivation, encode_publication_binding_id,
    reconstruct_recovery_derivation_from_snapshot, verify_installed_authority_commitment,
    verify_selected_resource_commitment, RecoveryAuthorityLimits,
    RecoveryDerivationFromSnapshotRequestV1, RecoveryDerivationRequestV1,
};
use crate::trusted_staging::{
    reopen_trusted_staging_bundle_from_artifact, TrustedStagingOptions, TrustedStagingRoot,
};
use crate::trusted_transactional_apply_execution::backup::revalidate_sealed_backup_for_recovery;
use crate::trusted_transactional_apply_execution::id::event_tag;
use crate::trusted_transactional_apply_execution::journal::load_and_validate_journal_chain;
use crate::trusted_transactional_apply_execution::recovery::binding::VerifiedPublishedTransaction;
use crate::trusted_transactional_apply_execution::recovery::{
    recover_with_verified, scan_trusted_transactions_for_overview,
    TrustedRecoveryExecutionAuthority, TrustedRecoveryOverviewCandidate,
};
use crate::trusted_transactional_apply_execution::{
    read_resource_lock_id_binding, read_snapshot_a_binding, verify_recovery_authority_envelope,
    TrustedTransactionRoot,
};
use crate::{
    enforce_trusted_update_workspace_capacity_for_reservation,
    open_existing_trusted_update_workspace, resolve_official_baseline,
    resolve_trusted_update_workspace, scan_installed_resources, BaselineResolutionOptions,
    BaselineResolutionRequest, GkrmError, InstalledResourceRoot, InstalledScanLimits,
    OfficialBaselineSelector, Result, SafeResourceKey, Sha256Digest, TransactionJournalEvent,
    TrustedApplyPlan, TrustedRecoveryCandidateId, TrustedRecoveryCandidateKind,
    TrustedRecoveryOptions, TrustedRecoveryResult, TrustedRecoveryScanOptions,
    TrustedStagingBundle, TrustedTransactionalApplyPlan, TrustedUpdateWorkspace,
    TrustedUpdateWorkspaceOptions, TrustedUpdateWorkspaceReservation,
};

const HARD_MAX_ARTIFACT_DIRECTORY_ENTRIES: usize = 250_000;
const HARD_MAX_CANDIDATE_ARTIFACTS: usize = 1_000;
const HARD_MAX_SINGLE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const HARD_MAX_TOTAL_ARTIFACT_BYTES_READ: u64 = 8 * 1024 * 1024 * 1024;
const TERMINAL_RETIREMENTS_DIR: &str = "terminal-retirements";
const TERMINAL_RETIREMENTS_TMP_DIR: &str = ".terminal-retirements-tmp";
const TERMINAL_RETIREMENT_RECORD_FILE: &str = "record.bin";
const TERMINAL_RETIREMENT_MAGIC: &[u8] = b"gkrm-terminal-evidence-retirement\n";
const TERMINAL_RETIREMENT_VERSION: u16 = 1;
const HARD_MAX_RETIREMENT_DIRECTORY_ENTRIES: usize = 20_000;
const HARD_MAX_RETIREMENT_RECORDS: usize = 10_000;
const HARD_MAX_SINGLE_RETIREMENT_BYTES: u64 = 1_024;
const HARD_MAX_TOTAL_RETIREMENT_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Clone, Copy)]
struct TerminalRetirementLimits {
    max_directory_entries: usize,
    max_records: usize,
    max_single_record_bytes: u64,
    max_total_record_bytes: u64,
}

const PRODUCTION_TERMINAL_RETIREMENT_LIMITS: TerminalRetirementLimits = TerminalRetirementLimits {
    max_directory_entries: HARD_MAX_RETIREMENT_DIRECTORY_ENTRIES,
    max_records: HARD_MAX_RETIREMENT_RECORDS,
    max_single_record_bytes: HARD_MAX_SINGLE_RETIREMENT_BYTES,
    max_total_record_bytes: HARD_MAX_TOTAL_RETIREMENT_BYTES,
};

#[cfg(test)]
thread_local! {
    static ARTIFACT_PARSE_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
    static OVERVIEW_ARTIFACT_CATALOG_LOADS: Cell<usize> = const { Cell::new(0) };
    static OVERVIEW_RETIREMENT_CATALOG_LOADS: Cell<usize> = const { Cell::new(0) };
    static VALIDATION_OBSERVATIONS: RefCell<Vec<ValidationObservation>> = const { RefCell::new(Vec::new()) };
    static RETIREMENT_LIMIT_OVERRIDE: RefCell<Option<TerminalRetirementLimits>> = const { RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct RetirementLimitGuard(Option<TerminalRetirementLimits>);

#[cfg(test)]
impl Drop for RetirementLimitGuard {
    fn drop(&mut self) {
        RETIREMENT_LIMIT_OVERRIDE.with(|limits| *limits.borrow_mut() = self.0);
    }
}

#[cfg(test)]
pub(crate) fn set_retirement_limits_for_test(
    max_directory_entries: usize,
    max_records: usize,
    max_single_record_bytes: u64,
    max_total_record_bytes: u64,
) -> RetirementLimitGuard {
    let replacement = TerminalRetirementLimits {
        max_directory_entries,
        max_records,
        max_single_record_bytes,
        max_total_record_bytes,
    };
    let previous = RETIREMENT_LIMIT_OVERRIDE.with(|limits| limits.replace(Some(replacement)));
    RetirementLimitGuard(previous)
}

fn terminal_retirement_limits() -> TerminalRetirementLimits {
    #[cfg(test)]
    if let Some(limits) = RETIREMENT_LIMIT_OVERRIDE.with(|limits| *limits.borrow()) {
        return limits;
    }
    PRODUCTION_TERMINAL_RETIREMENT_LIMITS
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidationObservation {
    AuthoritySelfIdVerified,
    SelectedResourceCommitmentVerified,
    InstalledAuthorityCommitmentVerified,
    ArtifactSelfIdVerified,
    ArtifactCrossBindingVerified,
    PublicationBindingVerified,
    FrozenDerivationDispatchStarted,
    FrozenDerivationReconstructionCompleted,
    UnsupportedDerivationRejected,
}

#[cfg(test)]
pub(crate) struct ValidationObservationGuard;

#[cfg(test)]
impl Drop for ValidationObservationGuard {
    fn drop(&mut self) {
        VALIDATION_OBSERVATIONS.with(|events| events.borrow_mut().clear());
    }
}

#[cfg(test)]
pub(crate) fn validation_observation_guard() -> ValidationObservationGuard {
    VALIDATION_OBSERVATIONS.with(|events| events.borrow_mut().clear());
    ValidationObservationGuard
}

#[cfg(test)]
pub(crate) fn validation_observations() -> Vec<ValidationObservation> {
    VALIDATION_OBSERVATIONS.with(|events| events.borrow().clone())
}

#[cfg(test)]
fn note_validation_observation(event: ValidationObservation) {
    VALIDATION_OBSERVATIONS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
pub(crate) fn reset_artifact_parse_attempts() {
    ARTIFACT_PARSE_ATTEMPTS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn artifact_parse_attempts() -> usize {
    ARTIFACT_PARSE_ATTEMPTS.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_overview_artifact_catalog_loads() {
    OVERVIEW_ARTIFACT_CATALOG_LOADS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn overview_artifact_catalog_loads() -> usize {
    OVERVIEW_ARTIFACT_CATALOG_LOADS.with(Cell::get)
}

#[cfg(test)]
pub(crate) fn reset_overview_retirement_catalog_loads() {
    OVERVIEW_RETIREMENT_CATALOG_LOADS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn overview_retirement_catalog_loads() -> usize {
    OVERVIEW_RETIREMENT_CATALOG_LOADS.with(Cell::get)
}

#[cfg(test)]
fn note_artifact_parse_attempt() {
    ARTIFACT_PARSE_ATTEMPTS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
fn note_overview_artifact_catalog_load() {
    OVERVIEW_ARTIFACT_CATALOG_LOADS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
fn note_overview_retirement_catalog_load() {
    OVERVIEW_RETIREMENT_CATALOG_LOADS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    type Hook = Box<dyn FnOnce() + Send + 'static>;

    #[derive(Default)]
    struct Hooks {
        target_workspace: Option<PathBuf>,
        after_pre_lock_reconstruction: Option<Hook>,
        after_mutating_locks_acquired: Option<Hook>,
    }

    static SERIAL: Mutex<()> = Mutex::new(());
    static HOOKS: Mutex<Hooks> = Mutex::new(Hooks {
        target_workspace: None,
        after_pre_lock_reconstruction: None,
        after_mutating_locks_acquired: None,
    });

    pub(crate) struct Guard {
        _serial: MutexGuard<'static, ()>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            *HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = Hooks::default();
        }
    }

    pub(crate) fn lock() -> Guard {
        let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        *HOOKS.lock().unwrap_or_else(|p| p.into_inner()) = Hooks::default();
        Guard { _serial: serial }
    }

    pub(crate) fn set_after_pre_lock_reconstruction(
        workspace: &Path,
        hook: impl FnOnce() + Send + 'static,
    ) {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        hooks.target_workspace = Some(workspace.to_path_buf());
        hooks.after_pre_lock_reconstruction = Some(Box::new(hook));
    }

    pub(crate) fn set_after_mutating_locks_acquired(
        workspace: &Path,
        hook: impl FnOnce() + Send + 'static,
    ) {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        hooks.target_workspace = Some(workspace.to_path_buf());
        hooks.after_mutating_locks_acquired = Some(Box::new(hook));
    }

    pub(crate) fn fire_after_pre_lock_reconstruction(workspace: &Path) {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        let hook = (hooks.target_workspace.as_deref() == Some(workspace))
            .then(|| hooks.after_pre_lock_reconstruction.take())
            .flatten();
        drop(hooks);
        if let Some(hook) = hook {
            hook();
        }
    }

    pub(crate) fn fire_after_mutating_locks_acquired(workspace: &Path) {
        let mut hooks = HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        let hook = (hooks.target_workspace.as_deref() == Some(workspace))
            .then(|| hooks.after_mutating_locks_acquired.take())
            .flatten();
        drop(hooks);
        if let Some(hook) = hook {
            hook();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedPackageFreeUpdateRecoveryOptions {
    pub max_artifact_directory_entries: usize,
    pub max_artifacts: usize,
    pub max_artifact_bytes: u64,
    pub max_total_artifact_bytes: u64,
    pub installed_scan_limits: InstalledScanLimits,
    pub scan: TrustedRecoveryScanOptions,
    pub recovery: TrustedRecoveryOptions,
    pub authority: RecoveryAuthorityLimits,
}

/// Opaque installed-resource catalog produced by the trusted installed scan boundary.
///
/// The catalog's fields are private and its selections can only name resources that
/// the scan actually discovered and re-opened through core's no-follow validation.
pub struct TrustedInstalledRecoveryScan {
    selections: BTreeMap<SafeResourceKey, InstalledApplyPlanningSource>,
}

impl std::fmt::Debug for TrustedInstalledRecoveryScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedInstalledRecoveryScan")
    }
}

/// Recovery-grade installed authority selected from an opaque trusted scan.
///
/// External callers cannot construct this authority from raw paths or loose
/// `InstalledResourceRoot` intent. They must obtain it from
/// [`scan_trusted_installed_recovery_resources`] and select a discovered
/// [`SafeResourceKey`].
///
/// ```compile_fail
/// use std::path::Path;
/// use gkrm_core::{InstalledResourceRoot, InstalledScanLimits, TrustedInstalledRecoverySelection};
///
/// let _selection = TrustedInstalledRecoverySelection::try_new(
///     Path::new("C:/arbitrary"),
///     InstalledResourceRoot::Root,
///     InstalledScanLimits::default(),
/// );
/// ```
///
/// A publicly path-minted planning source cannot be wrapped either because the
/// recovery selection's field is private:
///
/// ```compile_fail
/// use std::path::Path;
/// use gkrm_core::{InstalledApplyPlanningSource, InstalledResourceRoot, InstalledScanLimits,
///     TrustedInstalledRecoverySelection};
///
/// let source = InstalledApplyPlanningSource::try_new(
///     Path::new("C:/arbitrary"),
///     InstalledResourceRoot::Root,
///     InstalledScanLimits::default(),
/// )?;
/// let _selection = TrustedInstalledRecoverySelection { source };
/// # Ok::<(), gkrm_core::GkrmError>(())
/// ```
pub struct TrustedInstalledRecoverySelection {
    source: InstalledApplyPlanningSource,
}

impl std::fmt::Debug for TrustedInstalledRecoverySelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedInstalledRecoverySelection")
    }
}

/// Run the existing installed-resource scanner, then bind every discovered
/// resource to retained no-follow root/resource capabilities and stable identities.
pub fn scan_trusted_installed_recovery_resources(
    installed_root: &Path,
    limits: InstalledScanLimits,
) -> Result<TrustedInstalledRecoveryScan> {
    let scan = scan_installed_resources(installed_root, limits)?;
    let mut selections = BTreeMap::new();
    for resource in scan.resources {
        let key = SafeResourceKey::parse(&resource.name)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let source = InstalledApplyPlanningSource::try_new(installed_root, resource.root, limits)?;
        if selections.insert(key, source).is_some() {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
    }
    Ok(TrustedInstalledRecoveryScan { selections })
}

impl TrustedInstalledRecoveryScan {
    /// Consume the trusted catalog and select exactly one discovered resource key.
    pub fn select(
        mut self,
        resource_key: &SafeResourceKey,
    ) -> Result<TrustedInstalledRecoverySelection> {
        let source = self
            .selections
            .remove(resource_key)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        Ok(TrustedInstalledRecoverySelection { source })
    }
}

impl TrustedInstalledRecoverySelection {
    pub(crate) fn source(&self) -> &InstalledApplyPlanningSource {
        &self.source
    }
}

impl Default for TrustedPackageFreeUpdateRecoveryOptions {
    fn default() -> Self {
        Self {
            max_artifact_directory_entries: HARD_MAX_ARTIFACT_DIRECTORY_ENTRIES,
            max_artifacts: 1_000,
            max_artifact_bytes: 64 * 1024 * 1024,
            max_total_artifact_bytes: HARD_MAX_TOTAL_ARTIFACT_BYTES_READ,
            installed_scan_limits: InstalledScanLimits::default(),
            scan: TrustedRecoveryScanOptions::default(),
            recovery: TrustedRecoveryOptions::default(),
            authority: RecoveryAuthorityLimits::default(),
        }
    }
}

impl TrustedPackageFreeUpdateRecoveryOptions {
    fn validate(self) -> Result<Self> {
        if self.max_artifact_directory_entries == 0
            || self.max_artifact_directory_entries > HARD_MAX_ARTIFACT_DIRECTORY_ENTRIES
            || self.max_artifacts == 0
            || self.max_artifacts > HARD_MAX_CANDIDATE_ARTIFACTS
            || self.max_artifact_bytes == 0
            || self.max_artifact_bytes > HARD_MAX_SINGLE_ARTIFACT_BYTES
            || self.max_total_artifact_bytes == 0
            || self.max_total_artifact_bytes > HARD_MAX_TOTAL_ARTIFACT_BYTES_READ
            || self.max_artifact_bytes > self.max_total_artifact_bytes
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        self.installed_scan_limits
            .validate()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        self.scan.validate()?;
        self.recovery.validate()?;
        self.authority.validate()?;
        Ok(self)
    }
}

pub struct TrustedPackageFreeUpdateRecoveryRequest<'a> {
    workspace: &'a TrustedUpdateWorkspace,
    candidate: &'a TrustedRecoveryCandidateId,
    installed_selection: &'a TrustedInstalledRecoverySelection,
    options: TrustedPackageFreeUpdateRecoveryOptions,
}

/// Read-only classification of durable Task 31A/31B recovery evidence for one
/// freshly selected installed resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustedPublishedUpdateRecoveryState {
    Clear,
    Recoverable,
    Committed,
    RolledBack,
    SafeRestart,
    RecoveryRequired,
    ManualAttention,
    Unsupported,
    Ambiguous,
}

/// Opaque result of trusted durable recovery inspection. Candidate authority is
/// retained by backend adapters and must not be serialized across IPC.
pub struct TrustedPublishedUpdateRecoveryInspection {
    state: TrustedPublishedUpdateRecoveryState,
    candidate: Option<TrustedRecoveryCandidateId>,
}

/// Aggregate, identifier-free recovery truth for one managed desktop workspace.
///
/// This overview deliberately does not bind or expose a recovery candidate. It is
/// suitable only as a read-only, fail-closed startup prerequisite. Resource-bound
/// inspection and recovery continue to require [`TrustedInstalledRecoverySelection`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrustedRecoveryWorkspaceOverview {
    active_recovery: bool,
    terminal_evidence: bool,
    manual_attention: bool,
    unsupported_evidence: bool,
}

impl TrustedRecoveryWorkspaceOverview {
    pub fn is_clear(&self) -> bool {
        !self.active_recovery
            && !self.terminal_evidence
            && !self.manual_attention
            && !self.unsupported_evidence
    }

    pub fn has_active_recovery(&self) -> bool {
        self.active_recovery
    }

    pub fn has_terminal_evidence(&self) -> bool {
        self.terminal_evidence
    }

    pub fn has_manual_attention(&self) -> bool {
        self.manual_attention
    }

    pub fn has_unsupported_evidence(&self) -> bool {
        self.unsupported_evidence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkspaceEvidenceClass {
    Active,
    Terminal,
    Retired,
    ManualAttention,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidatedTerminalEvidence {
    plan_id: Sha256Digest,
    resource_lock_id: Sha256Digest,
    snapshot_a: Sha256Digest,
    terminal_event: TransactionJournalEvent,
    terminal_journal_id: Sha256Digest,
    publication_binding_id: Sha256Digest,
    artifact_id: Sha256Digest,
    recovery_authority_id: Sha256Digest,
    evidence_commitment: Sha256Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalRetirementRecord {
    evidence: ValidatedTerminalEvidence,
    record_id: Sha256Digest,
}

#[derive(Default)]
struct TerminalRetirementCatalog {
    records: BTreeMap<Sha256Digest, TerminalRetirementRecord>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrustedTerminalEvidenceRetirementOptions {
    pub acknowledged: bool,
    pub inspection: TrustedPackageFreeUpdateRecoveryOptions,
    pub workspace: TrustedUpdateWorkspaceOptions,
}

/// Aggregate result of one explicit retirement pass.
///
/// Evidence that still blocks a successor update is never reported here: every
/// blocking classification fails the pass with
/// [`GkrmError::TrustedTerminalEvidenceRetirementBlocked`] instead, so a
/// returned outcome always means no blocking terminal evidence remained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedTerminalEvidenceRetirementOutcome {
    retired: usize,
    already_retired: usize,
}

impl TrustedTerminalEvidenceRetirementOutcome {
    pub fn retired_count(&self) -> usize {
        self.retired
    }

    pub fn already_retired_count(&self) -> usize {
        self.already_retired
    }
}

#[derive(Clone, Copy)]
struct RecoveryOverviewArtifactSummary {
    recovery_authority_id: Option<Sha256Digest>,
    transactional_plan_id: Sha256Digest,
    snapshot_a: Sha256Digest,
    apply_plan_id: Sha256Digest,
    baseline_id_digest: Sha256Digest,
    staging_manifest_id: Sha256Digest,
    staging_bundle_id: Sha256Digest,
    selected_resource_commitment: Sha256Digest,
}

struct RecoveryOverviewArtifactCatalog {
    // `Some(summary)` is one exact validated artifact; `None` preserves a
    // duplicate validated identity as fail-closed ambiguity.
    entries: BTreeMap<Sha256Digest, Option<RecoveryOverviewArtifactSummary>>,
}

impl RecoveryOverviewArtifactCatalog {
    fn resolve_exact(
        &self,
        expected_id: &Sha256Digest,
    ) -> Result<&RecoveryOverviewArtifactSummary> {
        match self.entries.get(expected_id) {
            Some(Some(summary)) => Ok(summary),
            Some(None) => Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous),
            None => Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch),
        }
    }
}

/// Inspect aggregate transaction/recovery evidence without installed-resource
/// authority and without creating, repairing, rewriting, or deleting workspace
/// state. An absent workspace authority is recovery-clear.
pub fn inspect_trusted_recovery_workspace_overview(
    workspace: Option<&TrustedUpdateWorkspace>,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<TrustedRecoveryWorkspaceOverview> {
    let options = options.validate()?;
    let Some(workspace) = workspace else {
        return Ok(TrustedRecoveryWorkspaceOverview::default());
    };
    inspect_workspace_evidence(workspace, options).map(|inspection| inspection.overview)
}

struct WorkspaceEvidenceInspection {
    overview: TrustedRecoveryWorkspaceOverview,
    terminal: Vec<ValidatedTerminalEvidence>,
    already_retired: usize,
    retired_plan_ids: BTreeSet<Sha256Digest>,
    retired_undo_plan_ids: BTreeSet<Sha256Digest>,
}

fn inspect_workspace_evidence(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<WorkspaceEvidenceInspection> {
    let transaction_root =
        TrustedTransactionRoot::try_open_in_workspace(workspace).map_err(map_durable_error)?;
    let candidates = scan_trusted_transactions_for_overview(&transaction_root, options.scan)
        .map_err(map_durable_error)?;
    let retirement_catalog = load_terminal_retirement_catalog(&transaction_root);
    inspect_workspace_evidence_from_loaded_catalogs(
        workspace,
        options,
        &transaction_root,
        candidates,
        retirement_catalog,
    )
}

fn inspect_workspace_evidence_from_loaded_catalogs(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedPackageFreeUpdateRecoveryOptions,
    transaction_root: &TrustedTransactionRoot,
    candidates: Vec<TrustedRecoveryOverviewCandidate>,
    retirement_catalog: Result<TerminalRetirementCatalog>,
) -> Result<WorkspaceEvidenceInspection> {
    let mut overview = TrustedRecoveryWorkspaceOverview::default();
    let mut bound = Vec::new();
    for candidate in candidates {
        match candidate {
            TrustedRecoveryOverviewCandidate::Bound(plan_id) => bound.push(plan_id),
            TrustedRecoveryOverviewCandidate::Malformed => overview.manual_attention = true,
            TrustedRecoveryOverviewCandidate::Unsupported => overview.unsupported_evidence = true,
        }
    }

    let mut retirement_catalog = match retirement_catalog {
        Ok(catalog) => catalog,
        Err(GkrmError::TrustedTerminalEvidenceRetirementVersionUnsupported) => {
            overview.unsupported_evidence = true;
            return Ok(WorkspaceEvidenceInspection {
                overview,
                terminal: Vec::new(),
                already_retired: 0,
                retired_plan_ids: BTreeSet::new(),
                retired_undo_plan_ids: BTreeSet::new(),
            });
        }
        Err(_) => {
            overview.manual_attention = true;
            return Ok(WorkspaceEvidenceInspection {
                overview,
                terminal: Vec::new(),
                already_retired: 0,
                retired_plan_ids: BTreeSet::new(),
                retired_undo_plan_ids: BTreeSet::new(),
            });
        }
    };
    if bound.is_empty() {
        if !retirement_catalog.records.is_empty() {
            overview.manual_attention = true;
        }
        return Ok(WorkspaceEvidenceInspection {
            overview,
            terminal: Vec::new(),
            already_retired: 0,
            retired_plan_ids: BTreeSet::new(),
            retired_undo_plan_ids: BTreeSet::new(),
        });
    }

    let transactions = match open_child_dir(transaction_root.dir(), "transactions") {
        Ok(transactions) => transactions,
        Err(_) => {
            overview.manual_attention = true;
            return Ok(WorkspaceEvidenceInspection {
                overview,
                terminal: Vec::new(),
                already_retired: 0,
                retired_plan_ids: BTreeSet::new(),
                retired_undo_plan_ids: BTreeSet::new(),
            });
        }
    };
    let catalog = match load_recovery_overview_artifact_catalog(workspace, options) {
        Ok(catalog) => catalog,
        Err(_) => {
            overview.manual_attention = true;
            return Ok(WorkspaceEvidenceInspection {
                overview,
                terminal: Vec::new(),
                already_retired: 0,
                retired_plan_ids: BTreeSet::new(),
                retired_undo_plan_ids: BTreeSet::new(),
            });
        }
    };

    let mut terminal = Vec::new();
    let mut already_retired = 0usize;
    let mut retired_plan_ids = BTreeSet::new();
    let mut retired_undo_plan_ids = BTreeSet::new();
    for plan_id in bound {
        let (class, evidence) = classify_workspace_candidate(
            &transactions,
            &catalog,
            &mut retirement_catalog,
            &plan_id,
            options,
        );
        match class {
            WorkspaceEvidenceClass::Active => overview.active_recovery = true,
            WorkspaceEvidenceClass::Terminal => {
                overview.terminal_evidence = true;
                if let Some(evidence) = evidence {
                    terminal.push(evidence);
                }
            }
            WorkspaceEvidenceClass::Retired => {
                already_retired = already_retired.saturating_add(1);
                retired_plan_ids.insert(plan_id);
                if evidence
                    .is_some_and(|item| item.terminal_event == TransactionJournalEvent::Committed)
                {
                    retired_undo_plan_ids.insert(plan_id);
                }
            }
            WorkspaceEvidenceClass::ManualAttention => overview.manual_attention = true,
            WorkspaceEvidenceClass::Unsupported => overview.unsupported_evidence = true,
        }
    }
    if !retirement_catalog.records.is_empty() {
        overview.manual_attention = true;
    }
    Ok(WorkspaceEvidenceInspection {
        overview,
        terminal,
        already_retired,
        retired_plan_ids,
        retired_undo_plan_ids,
    })
}

pub(crate) fn validated_retired_terminal_plan_ids(
    transaction_root: &TrustedTransactionRoot,
    max_journal_records: usize,
) -> Result<BTreeSet<Sha256Digest>> {
    // Preserve the established recovery path and its error classification when
    // no retirement namespace exists. Only pay the bounded workspace-wide
    // retirement validation cost when a record could actually suppress a
    // terminal peer.
    transaction_root
        .revalidate_identity()
        .map_err(map_durable_error)?;
    let workspace = transaction_root
        .workspace()
        .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let retirement_catalog = load_terminal_retirement_catalog(transaction_root)?;
    if retirement_catalog.records.is_empty() {
        return Ok(BTreeSet::new());
    }
    let mut options = TrustedPackageFreeUpdateRecoveryOptions::default();
    options.scan.max_journal_records = max_journal_records;
    options.recovery.max_journal_records = max_journal_records;
    let options = options.validate()?;
    let candidates = scan_trusted_transactions_for_overview(transaction_root, options.scan)
        .map_err(map_durable_error)?;
    let inspection = inspect_workspace_evidence_from_loaded_catalogs(
        workspace,
        options,
        transaction_root,
        candidates,
        Ok(retirement_catalog),
    )?;
    if inspection.overview.has_manual_attention() || inspection.overview.has_unsupported_evidence()
    {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
    }
    Ok(inspection.retired_plan_ids)
}

fn classify_workspace_candidate(
    transactions: &CapDir,
    artifact_catalog: &RecoveryOverviewArtifactCatalog,
    retirement_catalog: &mut TerminalRetirementCatalog,
    plan_id: &Sha256Digest,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> (WorkspaceEvidenceClass, Option<ValidatedTerminalEvidence>) {
    let validated = || -> Result<(TransactionJournalEvent, Option<ValidatedTerminalEvidence>)> {
        let txn = open_child_dir(transactions, &plan_id.to_string()).map_err(map_durable_error)?;
        let snapshot = read_snapshot_a_binding(&txn).map_err(map_durable_error)?;
        let resource_lock = read_resource_lock_id_binding(&txn).map_err(map_durable_error)?;
        let journal = open_child_dir(&txn, "journal").map_err(map_durable_error)?;
        let cursor = load_and_validate_journal_chain(
            &journal,
            plan_id,
            &snapshot,
            options.recovery.max_journal_records,
        )
        .map_err(map_durable_error)?;
        let Some(publication) = cursor.publication_binding_id else {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
        };
        let envelope = verify_recovery_authority_envelope(&txn).map_err(map_durable_error)?;
        let body = envelope.body();
        if body.transactional_plan_id() != plan_id || body.snapshot_a_id() != &snapshot {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        dispatch_recovery_derivation(
            body.apply_derivation_version(),
            body.transaction_derivation_version(),
        )
        .map_err(map_durable_error)?;
        let expected_publication = encode_publication_binding_id(
            envelope.artifact_id(),
            envelope.authority_id(),
            plan_id,
            &snapshot,
            &resource_lock,
        )
        .map_err(map_durable_error)?;
        if expected_publication.digest() != &publication
            || &expected_publication != envelope.publication_binding_id()
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let artifact = artifact_catalog.resolve_exact(envelope.artifact_id())?;
        if artifact.recovery_authority_id != Some(*envelope.authority_id().digest())
            || artifact.transactional_plan_id != *plan_id
            || artifact.snapshot_a != snapshot
            || artifact.apply_plan_id != *body.apply_plan_id()
            || artifact.baseline_id_digest != *body.baseline_id()
            || artifact.staging_manifest_id != *body.staging_manifest_id()
            || artifact.staging_bundle_id != *body.staging_bundle_id()
            || artifact.selected_resource_commitment != *body.selected_resource_commitment()
        {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let event = cursor
            .last_event
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let terminal = if is_retirable_terminal_event(event) {
            let terminal_journal_id = cursor
                .previous_id
                .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
            Some(build_validated_terminal_evidence(
                *plan_id,
                resource_lock,
                snapshot,
                event,
                terminal_journal_id,
                publication,
                *envelope.artifact_id(),
                *envelope.authority_id().digest(),
            )?)
        } else {
            None
        };
        Ok((event, terminal))
    };

    match validated() {
        Ok((event, Some(evidence))) if is_retirable_terminal_event(event) => {
            match retirement_catalog.records.remove(plan_id) {
                Some(record) if record.evidence == evidence => {
                    (WorkspaceEvidenceClass::Retired, Some(evidence))
                }
                Some(_) => (WorkspaceEvidenceClass::ManualAttention, None),
                None => (WorkspaceEvidenceClass::Terminal, Some(evidence)),
            }
        }
        Ok(_) => {
            if retirement_catalog.records.remove(plan_id).is_some() {
                (WorkspaceEvidenceClass::ManualAttention, None)
            } else {
                (WorkspaceEvidenceClass::Active, None)
            }
        }
        Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported) => {
            (WorkspaceEvidenceClass::Unsupported, None)
        }
        Err(_) => (WorkspaceEvidenceClass::ManualAttention, None),
    }
}

fn is_retirable_terminal_event(event: TransactionJournalEvent) -> bool {
    matches!(
        event,
        TransactionJournalEvent::Committed
            | TransactionJournalEvent::RolledBack
            | TransactionJournalEvent::AbortedBeforeMutation
    )
}

#[allow(clippy::too_many_arguments)]
fn build_validated_terminal_evidence(
    plan_id: Sha256Digest,
    resource_lock_id: Sha256Digest,
    snapshot_a: Sha256Digest,
    terminal_event: TransactionJournalEvent,
    terminal_journal_id: Sha256Digest,
    publication_binding_id: Sha256Digest,
    artifact_id: Sha256Digest,
    recovery_authority_id: Sha256Digest,
) -> Result<ValidatedTerminalEvidence> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-terminal-evidence-v1")
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    encoder.digest(&plan_id);
    encoder.digest(&resource_lock_id);
    encoder.digest(&snapshot_a);
    encoder.u8(event_tag(terminal_event));
    encoder.digest(&terminal_journal_id);
    encoder.digest(&publication_binding_id);
    encoder.digest(&artifact_id);
    encoder.digest(&recovery_authority_id);
    let evidence_commitment = encoder.finish();
    Ok(ValidatedTerminalEvidence {
        plan_id,
        resource_lock_id,
        snapshot_a,
        terminal_event,
        terminal_journal_id,
        publication_binding_id,
        artifact_id,
        recovery_authority_id,
        evidence_commitment,
    })
}

fn encode_retirement_record(evidence: ValidatedTerminalEvidence) -> Result<Vec<u8>> {
    let record_id = retirement_record_id(&evidence)?;
    let mut bytes = Vec::with_capacity(TERMINAL_RETIREMENT_MAGIC.len() + 2 + 9 * 32 + 1);
    bytes.extend_from_slice(TERMINAL_RETIREMENT_MAGIC);
    bytes.extend_from_slice(&TERMINAL_RETIREMENT_VERSION.to_le_bytes());
    for digest in [
        evidence.plan_id,
        evidence.resource_lock_id,
        evidence.snapshot_a,
    ] {
        bytes.extend_from_slice(digest.as_bytes());
    }
    bytes.push(event_tag(evidence.terminal_event));
    for digest in [
        evidence.terminal_journal_id,
        evidence.publication_binding_id,
        evidence.artifact_id,
        evidence.recovery_authority_id,
        evidence.evidence_commitment,
        record_id,
    ] {
        bytes.extend_from_slice(digest.as_bytes());
    }
    Ok(bytes)
}

fn retirement_record_id(evidence: &ValidatedTerminalEvidence) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-terminal-retirement-record-v1")
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    encoder.digest(&evidence.plan_id);
    encoder.digest(&evidence.resource_lock_id);
    encoder.digest(&evidence.snapshot_a);
    encoder.u8(event_tag(evidence.terminal_event));
    encoder.digest(&evidence.terminal_journal_id);
    encoder.digest(&evidence.publication_binding_id);
    encoder.digest(&evidence.artifact_id);
    encoder.digest(&evidence.recovery_authority_id);
    encoder.digest(&evidence.evidence_commitment);
    Ok(encoder.finish())
}

fn retirement_directory_name(plan_id: &Sha256Digest) -> String {
    plan_id.to_string()
}

fn plan_id_from_retirement_directory_name(name: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_lowercase_hex(name)
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)
}

fn parse_terminal_event(tag: u8) -> Result<TransactionJournalEvent> {
    match tag {
        7 => Ok(TransactionJournalEvent::Committed),
        10 => Ok(TransactionJournalEvent::RolledBack),
        12 => Ok(TransactionJournalEvent::AbortedBeforeMutation),
        _ => Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid),
    }
}

fn take_digest(bytes: &[u8], offset: &mut usize) -> Result<Sha256Digest> {
    let end = offset
        .checked_add(32)
        .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let raw: [u8; 32] = bytes
        .get(*offset..end)
        .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
        .try_into()
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    *offset = end;
    Ok(Sha256Digest::new(raw))
}

fn parse_retirement_record(bytes: &[u8]) -> Result<TerminalRetirementRecord> {
    if !bytes.starts_with(TERMINAL_RETIREMENT_MAGIC) {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
    }
    let mut offset = TERMINAL_RETIREMENT_MAGIC.len();
    let version_end = offset
        .checked_add(2)
        .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let version = u16::from_le_bytes(
        bytes
            .get(offset..version_end)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
            .try_into()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?,
    );
    if version != TERMINAL_RETIREMENT_VERSION {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementVersionUnsupported);
    }
    offset = version_end;
    let plan_id = take_digest(bytes, &mut offset)?;
    let resource_lock_id = take_digest(bytes, &mut offset)?;
    let snapshot_a = take_digest(bytes, &mut offset)?;
    let terminal_event = parse_terminal_event(
        *bytes
            .get(offset)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?,
    )?;
    offset = offset
        .checked_add(1)
        .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let terminal_journal_id = take_digest(bytes, &mut offset)?;
    let publication_binding_id = take_digest(bytes, &mut offset)?;
    let artifact_id = take_digest(bytes, &mut offset)?;
    let recovery_authority_id = take_digest(bytes, &mut offset)?;
    let evidence_commitment = take_digest(bytes, &mut offset)?;
    let record_id = take_digest(bytes, &mut offset)?;
    if offset != bytes.len() {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
    }
    let evidence = build_validated_terminal_evidence(
        plan_id,
        resource_lock_id,
        snapshot_a,
        terminal_event,
        terminal_journal_id,
        publication_binding_id,
        artifact_id,
        recovery_authority_id,
    )?;
    if evidence.evidence_commitment != evidence_commitment
        || retirement_record_id(&evidence)? != record_id
    {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
    }
    Ok(TerminalRetirementRecord {
        evidence,
        record_id,
    })
}

fn load_terminal_retirement_catalog(
    transaction_root: &TrustedTransactionRoot,
) -> Result<TerminalRetirementCatalog> {
    #[cfg(test)]
    note_overview_retirement_catalog_load();
    let limits = terminal_retirement_limits();
    let Some(dir) = try_open_child_dir(transaction_root.dir(), TERMINAL_RETIREMENTS_DIR)
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
    else {
        return Ok(TerminalRetirementCatalog::default());
    };
    dir_identity(&dir, "terminal-retirements")
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let mut names = Vec::new();
    let mut directory_entries = 0usize;
    for entry in dir
        .entries()
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        directory_entries = directory_entries
            .checked_add(1)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if directory_entries > limits.max_directory_entries {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded {
                limit: "max_retirement_directory_entries",
            });
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        validate_single_component(&name)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let metadata = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if is_windows_reparse_point_cap(&metadata)
            || metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
        {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        names.push(name);
    }
    if names.len() > limits.max_records {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded {
            limit: "max_retirement_records",
        });
    }
    names.sort();
    let mut total_bytes = 0u64;
    let mut records = BTreeMap::new();
    for name in names {
        let name_plan_id = plan_id_from_retirement_directory_name(&name)?;
        let record_dir = open_child_dir(&dir, &name)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        dir_identity(&record_dir, "terminal-retirement")
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let mut nested = record_dir
            .entries()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let entry = nested
            .next()
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if nested.next().is_some()
            || entry.file_name().to_str() != Some(TERMINAL_RETIREMENT_RECORD_FILE)
        {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        directory_entries = directory_entries
            .checked_add(1)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if directory_entries > limits.max_directory_entries {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded {
                limit: "max_retirement_directory_entries",
            });
        }
        let mut file = open_file_nofollow(&record_dir, TERMINAL_RETIREMENT_RECORD_FILE)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let before = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let len = file
            .metadata()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
            .len();
        if len > limits.max_single_record_bytes {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded {
                limit: "max_retirement_record_bytes",
            });
        }
        total_bytes = total_bytes
            .checked_add(len)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if total_bytes > limits.max_total_record_bytes {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementLimitExceeded {
                limit: "max_total_retirement_bytes",
            });
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(limits.max_single_record_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let after = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if before != after || u64::try_from(bytes.len()).ok() != Some(len) {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        let record = parse_retirement_record(&bytes)?;
        if record.evidence.plan_id != name_plan_id
            || retirement_directory_name(&record.evidence.plan_id) != name
            || records.insert(record.evidence.plan_id, record).is_some()
        {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
    }
    Ok(TerminalRetirementCatalog { records })
}

/// What letting go of unaccounted staged copies amounted to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrustedStagingReleaseOutcome {
    /// Staged copies removed.
    pub released: u32,
    /// Staged copies left because an authority artifact still names them.
    pub kept: u32,
}

/// Let go of the staged copies of packages nothing accounts for any more.
///
/// Every apply stages the package it is about to write, verified, under a directory named by that
/// staging manifest's own identity — and it is what a recovery replays from, so a staged copy an
/// authority artifact still names is one somebody may yet need. Nothing has ever removed the rest.
/// A staged copy is the size of the package it came from, so an operator accumulates one per
/// update they run, indefinitely, for work that finished long ago.
///
/// Accounted for is read from the artifacts rather than from age or count: an artifact names the
/// staging manifest it was applied from, and a directory no artifact names is answering to nobody.
/// A workspace with recovery outstanding is refused outright, because what is outstanding there is
/// exactly what a staged copy would be needed for.
///
/// Callers must hold the application's own single-durable-operation permit: an apply running
/// beside this would be publishing a staged copy while this decides nothing accounts for it.
pub fn discard_unaccounted_trusted_staging_bundles(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedTerminalEvidenceRetirementOptions,
) -> Result<TrustedStagingReleaseOutcome> {
    let inspection_options = validate_staging_release_options(options)?;
    let _publication_lock = crate::acquire_trusted_update_workspace_publication_lock(workspace)?;
    let allowed = check_staging_release_allowed(workspace, inspection_options)?;
    let survey = survey_staging_bundles(workspace, &allowed)?;
    let Some(bundles) = open_staging_bundles(workspace)? else {
        return Ok(TrustedStagingReleaseOutcome::default());
    };

    let mut outcome = TrustedStagingReleaseOutcome {
        released: 0,
        kept: survey.kept,
    };
    for name in survey.unaccounted {
        bundles
            .remove_dir_all(&name)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        outcome.released = outcome.released.saturating_add(1);
    }
    Ok(outcome)
}

/// The staged copies nothing accounts for, by the name each is held under.
///
/// The same reading `discard_unaccounted_trusted_staging_bundles` acts on, without acting: a
/// caller that wants to say how much a release would free has to be told the same answer the
/// release will reach, or the number on the screen is one nobody computed.
pub fn unaccounted_trusted_staging_bundles(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedTerminalEvidenceRetirementOptions,
) -> Result<Vec<String>> {
    let inspection_options = validate_staging_release_options(options)?;
    let _publication_lock = crate::acquire_trusted_update_workspace_publication_lock(workspace)?;
    let allowed = check_staging_release_allowed(workspace, inspection_options)?;
    Ok(survey_staging_bundles(workspace, &allowed)?.unaccounted)
}

/// What a release is allowed to do, and what the workspace has already closed.
struct StagingReleaseAllowance {
    options: TrustedPackageFreeUpdateRecoveryOptions,
    /// Acknowledged transactions with no committed Undo source to retain.
    retired: BTreeSet<Sha256Digest>,
}

fn validate_staging_release_options(
    options: TrustedTerminalEvidenceRetirementOptions,
) -> Result<TrustedPackageFreeUpdateRecoveryOptions> {
    if !options.acknowledged {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementAcknowledgementRequired);
    }
    options.inspection.validate()
}

/// Refuse outright where a staged copy is exactly what somebody may still need.
/// Called only while the workspace publication lock is held.
fn check_staging_release_allowed(
    workspace: &TrustedUpdateWorkspace,
    inspection_options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<StagingReleaseAllowance> {
    let inspection = inspect_workspace_evidence(workspace, inspection_options)?;
    // Anything in flight, needing a person, or that this cannot read is the case a staged copy
    // exists for. Nothing is removed while one of them stands.
    if inspection.overview.has_active_recovery()
        || inspection.overview.has_manual_attention()
        || inspection.overview.has_unsupported_evidence()
    {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementBlocked);
    }
    Ok(StagingReleaseAllowance {
        options: inspection_options,
        retired: inspection
            .retired_plan_ids
            .difference(&inspection.retired_undo_plan_ids)
            .copied()
            .collect(),
    })
}

fn open_staging_bundles(workspace: &TrustedUpdateWorkspace) -> Result<Option<CapDir>> {
    let staging_root = TrustedStagingRoot::try_open(workspace.staging_root())?;
    try_open_child_dir(staging_root.dir(), "bundles")
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)
}

/// Which staged copies are named by an artifact and which are named by nothing.
struct StagingSurvey {
    unaccounted: Vec<String>,
    kept: u32,
}

fn survey_staging_bundles(
    workspace: &TrustedUpdateWorkspace,
    allowed: &StagingReleaseAllowance,
) -> Result<StagingSurvey> {
    let options = allowed.options;
    let accounted = staging_manifests_named_by_artifacts(workspace, options, &allowed.retired)?;
    let Some(bundles) = open_staging_bundles(workspace)? else {
        return Ok(StagingSurvey {
            unaccounted: Vec::new(),
            kept: 0,
        });
    };

    let mut unaccounted = Vec::new();
    let mut kept = 0u32;
    let mut inspected = 0usize;
    for entry in bundles
        .entries()
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        inspected = inspected
            .checked_add(1)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if inspected > options.max_artifact_directory_entries {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        validate_single_component(&name).map_err(map_durable_error)?;
        let metadata = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        // A link where a staged copy should be is not something to walk into and delete.
        if is_windows_reparse_point_cap(&metadata) || metadata.file_type().is_symlink() {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        if !metadata.file_type().is_dir() {
            continue;
        }
        if accounted.contains(&name) {
            kept = kept.saturating_add(1);
        } else {
            unaccounted.push(name);
        }
    }
    unaccounted.sort();
    Ok(StagingSurvey { unaccounted, kept })
}

/// The staging manifests the workspace's own authority artifacts name, by directory name.
///
/// An artifact that will not parse is deliberately not skipped here. Everywhere else an unreadable
/// artifact costs nothing; here it would silently turn "I cannot tell what this accounts for" into
/// "nothing accounts for it", and delete a staged copy a recovery needed.
///
/// Retirement acknowledges a terminal operation so a successor can start; it does not
/// revoke Undo. Committed parents retain their staged source even after retirement.
/// Only an acknowledged rollback has no committed update to undo. An authenticated
/// supersession receipt will be needed before committed source staging can be released.
fn staging_manifests_named_by_artifacts(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedPackageFreeUpdateRecoveryOptions,
    retired: &BTreeSet<Sha256Digest>,
) -> Result<BTreeSet<String>> {
    let (root, _identity) = workspace
        .try_clone_artifact_root_capability()
        .map_err(map_durable_error)?;
    let parse_options = TrustedCliUpdateOptions {
        max_artifact_bytes: usize::try_from(options.max_artifact_bytes)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?,
        ..TrustedCliUpdateOptions::default()
    };

    let mut names = Vec::new();
    let mut inspected = 0usize;
    for entry in root
        .entries()
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
    {
        let entry = entry.map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        inspected = inspected
            .checked_add(1)
            .ok_or(GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if inspected > options.max_artifact_directory_entries {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        validate_single_component(&name).map_err(map_durable_error)?;
        let metadata = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        if is_windows_reparse_point_cap(&metadata) || metadata.file_type().is_symlink() {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
        if metadata.file_type().is_file() && name.starts_with("plan-") && name.ends_with(".bin") {
            names.push(name);
            if names.len() > options.max_artifacts {
                return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
            }
        }
    }

    let mut accounted = BTreeSet::new();
    for name in names {
        let mut file = open_file_nofollow(&root, &name)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        let metadata = file
            .metadata()
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        if metadata.len() > options.max_artifact_bytes {
            return Err(GkrmError::TrustedCliUpdateArtifactInvalid);
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(options.max_artifact_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| GkrmError::TrustedCliUpdateArtifactInvalid)?;
        let artifact = parse_cli_artifact(&bytes, &parse_options)?;
        if retired.contains(&artifact.body().transactional_plan_id) {
            continue;
        }
        accounted.insert(artifact.body().staging_manifest_id.to_string());
    }
    Ok(accounted)
}

/// Explicitly publish immutable retirement evidence for every currently
/// validated, unretired terminal transaction in one trusted workspace.
pub fn retire_trusted_terminal_update_evidence(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedTerminalEvidenceRetirementOptions,
) -> Result<TrustedTerminalEvidenceRetirementOutcome> {
    retire_terminal_update_evidence(workspace, options, None)
}

fn retire_terminal_update_evidence(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedTerminalEvidenceRetirementOptions,
    selected: Option<&Sha256Digest>,
) -> Result<TrustedTerminalEvidenceRetirementOutcome> {
    if !options.acknowledged {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementAcknowledgementRequired);
    }
    let inspection_options = options.inspection.validate()?;
    let _publication_lock = crate::acquire_trusted_update_workspace_publication_lock(workspace)?;
    let mut inspection = inspect_workspace_evidence(workspace, inspection_options)?;
    if inspection.overview.has_active_recovery()
        || inspection.overview.has_manual_attention()
        || inspection.overview.has_unsupported_evidence()
    {
        return Err(GkrmError::TrustedTerminalEvidenceRetirementBlocked);
    }
    if let Some(selected) = selected {
        inspection
            .terminal
            .retain(|evidence| &evidence.plan_id == selected);
        if inspection.terminal.is_empty() && !inspection.retired_plan_ids.contains(selected) {
            return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
        }
    }
    if inspection.terminal.is_empty() {
        return Ok(TrustedTerminalEvidenceRetirementOutcome {
            retired: 0,
            already_retired: inspection.already_retired,
        });
    }

    let transaction_root = TrustedTransactionRoot::try_open_in_workspace(workspace)
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let encoded = inspection
        .terminal
        .into_iter()
        .map(|evidence| encode_retirement_record(evidence).map(|bytes| (evidence, bytes)))
        .collect::<Result<Vec<_>>>()?;
    let retirement_root_entry = usize::from(
        try_open_child_dir(transaction_root.dir(), TERMINAL_RETIREMENTS_DIR)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
            .is_none(),
    );
    let temporary_root_entry = usize::from(
        try_open_child_dir(transaction_root.dir(), TERMINAL_RETIREMENTS_TMP_DIR)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?
            .is_none(),
    );
    let record_entries = encoded
        .len()
        .checked_mul(2)
        .and_then(|entries| entries.checked_add(retirement_root_entry))
        .and_then(|entries| entries.checked_add(temporary_root_entry))
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    let record_bytes = encoded
        .iter()
        .try_fold(0u64, |total, (_, bytes)| {
            total.checked_add(u64::try_from(bytes.len()).ok()?)
        })
        .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    let reservation = TrustedUpdateWorkspaceReservation::new(record_bytes, record_entries, 0, 0)?;
    enforce_trusted_update_workspace_capacity_for_reservation(
        workspace,
        options.workspace,
        reservation,
    )?;
    let retirements = ensure_child_dir(transaction_root.dir(), TERMINAL_RETIREMENTS_DIR)
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    let tmp = ensure_child_dir(transaction_root.dir(), TERMINAL_RETIREMENTS_TMP_DIR)
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
    sync_dir(transaction_root.dir(), "terminal-retirement-root")
        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;

    let mut retired = 0usize;
    let mut already_retired = inspection.already_retired;
    for (evidence, bytes) in encoded {
        let destination_name = retirement_directory_name(&evidence.plan_id);
        let temp_name = allocate_temp_name(&tmp)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let temp_dir = crate::baseline::fs_security::create_new_child_dir(&tmp, &temp_name)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        let mut file = create_new_file(&temp_dir, TERMINAL_RETIREMENT_RECORD_FILE)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        std::io::Write::write_all(&mut file, &bytes)
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        fsync_file(&file, "terminal-retirement-record")
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        drop(file);
        sync_dir(&temp_dir, "terminal-retirement-temp-record")
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        drop(temp_dir);
        sync_dir(&tmp, "terminal-retirement-temp")
            .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
        match rename_noreplace_relative(&tmp, &temp_name, &retirements, &destination_name) {
            Ok(()) => {
                sync_dir(&retirements, "terminal-retirements")
                    .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
                retired = retired.saturating_add(1);
            }
            Err(_) => {
                let existing_dir = open_child_dir(&retirements, &destination_name)
                    .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
                let mut existing =
                    open_file_nofollow(&existing_dir, TERMINAL_RETIREMENT_RECORD_FILE)
                        .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
                let mut existing_bytes = Vec::new();
                existing
                    .by_ref()
                    .take(HARD_MAX_SINGLE_RETIREMENT_BYTES.saturating_add(1))
                    .read_to_end(&mut existing_bytes)
                    .map_err(|_| GkrmError::TrustedTerminalEvidenceRetirementInvalid)?;
                if parse_retirement_record(&existing_bytes)?.evidence != evidence {
                    return Err(GkrmError::TrustedTerminalEvidenceRetirementInvalid);
                }
                let _ = tmp.remove_dir_all(&temp_name);
                already_retired = already_retired.saturating_add(1);
            }
        }
    }
    Ok(TrustedTerminalEvidenceRetirementOutcome {
        retired,
        already_retired,
    })
}

impl std::fmt::Debug for TrustedPublishedUpdateRecoveryInspection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedPublishedUpdateRecoveryInspection")
            .field("state", &self.state)
            .field("has_candidate", &self.candidate.is_some())
            .finish()
    }
}

impl TrustedPublishedUpdateRecoveryInspection {
    pub fn state(&self) -> TrustedPublishedUpdateRecoveryState {
        self.state
    }

    pub fn candidate_id(&self) -> Option<&TrustedRecoveryCandidateId> {
        self.candidate.as_ref()
    }
}

impl std::fmt::Debug for TrustedPackageFreeUpdateRecoveryRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedPackageFreeUpdateRecoveryRequest")
    }
}

impl<'a> TrustedPackageFreeUpdateRecoveryRequest<'a> {
    pub fn try_new(
        workspace: &'a TrustedUpdateWorkspace,
        candidate: &'a TrustedRecoveryCandidateId,
        installed_selection: &'a TrustedInstalledRecoverySelection,
        options: TrustedPackageFreeUpdateRecoveryOptions,
    ) -> Result<Self> {
        let options = options.validate()?;
        Ok(Self {
            workspace,
            candidate,
            installed_selection,
            options,
        })
    }
}

struct ReconstructedV2Authority {
    bundle: TrustedStagingBundle,
    apply_plan: TrustedApplyPlan,
    tx_plan: TrustedTransactionalApplyPlan,
    journal_event: TransactionJournalEvent,
}

struct PreLockPublishedNamespaceBinding {
    transactions_parent_identity: StableFileIdentity,
    transaction_identity: StableFileIdentity,
    journal_identity: StableFileIdentity,
}

/// Inspect one installed resource's durable recovery evidence without acquiring
/// mutating locks, appending journal records, or deleting retained evidence.
pub fn inspect_trusted_published_update_v2(
    workspace: &TrustedUpdateWorkspace,
    installed_selection: &TrustedInstalledRecoverySelection,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<TrustedPublishedUpdateRecoveryInspection> {
    let options = options.validate()?;
    let Some(workspace) =
        open_existing_trusted_update_workspace(workspace.app_root()).map_err(map_durable_error)?
    else {
        return Ok(TrustedPublishedUpdateRecoveryInspection {
            state: TrustedPublishedUpdateRecoveryState::Clear,
            candidate: None,
        });
    };
    let transaction_root =
        TrustedTransactionRoot::try_open_in_workspace(&workspace).map_err(map_durable_error)?;
    let retired_plan_ids = match validated_retired_terminal_plan_ids(
        &transaction_root,
        options.recovery.max_journal_records,
    ) {
        Ok(ids) => ids,
        Err(_) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::ManualAttention,
                candidate: None,
            })
        }
    };
    let (installed_source, resource_key) = reopen_fresh_installed_selection(
        installed_selection.source(),
        options.installed_scan_limits,
    )?;
    installed_source
        .capture_tree_snapshot(&resource_key)
        .map_err(map_durable_error)?;

    let scan = match crate::scan_trusted_transactions(&transaction_root, options.scan) {
        Ok(scan) => scan,
        Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::Unsupported,
                candidate: None,
            })
        }
        Err(error) => return Err(error),
    };
    if scan
        .candidates()
        .iter()
        .any(|candidate| candidate.kind() == TrustedRecoveryCandidateKind::Malformed)
    {
        return Ok(TrustedPublishedUpdateRecoveryInspection {
            state: TrustedPublishedUpdateRecoveryState::Ambiguous,
            candidate: None,
        });
    }
    if scan.candidates().is_empty() {
        return Ok(TrustedPublishedUpdateRecoveryInspection {
            state: TrustedPublishedUpdateRecoveryState::Clear,
            candidate: None,
        });
    }

    let expected_lock =
        crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id(
            resource_key.as_str(),
        )
        .map_err(map_durable_error)?;
    let transactions =
        open_child_dir(transaction_root.dir(), "transactions").map_err(map_durable_error)?;
    let mut matching = Vec::new();
    for candidate in scan.candidates() {
        let Some(plan_id) = candidate.proven_plan_id else {
            continue;
        };
        if retired_plan_ids.contains(&plan_id) {
            continue;
        }
        let txn = match open_child_dir(&transactions, &plan_id.to_string()) {
            Ok(txn) => txn,
            Err(_) => {
                return Ok(TrustedPublishedUpdateRecoveryInspection {
                    state: TrustedPublishedUpdateRecoveryState::Ambiguous,
                    candidate: None,
                })
            }
        };
        let lock = match read_resource_lock_id_binding(&txn) {
            Ok(lock) => lock,
            Err(_) => {
                return Ok(TrustedPublishedUpdateRecoveryInspection {
                    state: TrustedPublishedUpdateRecoveryState::Ambiguous,
                    candidate: None,
                })
            }
        };
        if lock == expected_lock {
            matching.push((*candidate.candidate_id(), plan_id));
        }
    }

    let (candidate, plan_id) = match matching.as_slice() {
        [] => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::Clear,
                candidate: None,
            })
        }
        [only] => *only,
        _ => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::Ambiguous,
                candidate: None,
            })
        }
    };

    let (txn, _) = match open_candidate_transaction(&transaction_root, &plan_id) {
        Ok(opened) => opened,
        Err(_) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::ManualAttention,
                candidate: None,
            })
        }
    };
    let snapshot = match read_snapshot_a_binding(&txn) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::ManualAttention,
                candidate: None,
            })
        }
    };
    let journal = match open_child_dir(&txn, "journal") {
        Ok(journal) => journal,
        Err(_) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::ManualAttention,
                candidate: None,
            })
        }
    };
    let cursor = match load_and_validate_journal_chain(
        &journal,
        &plan_id,
        &snapshot,
        options.recovery.max_journal_records,
    ) {
        Ok(cursor) => cursor,
        Err(GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::Unsupported,
                candidate: None,
            })
        }
        Err(_) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::ManualAttention,
                candidate: None,
            })
        }
    };
    if cursor.publication_binding_id.is_none() {
        return Ok(TrustedPublishedUpdateRecoveryInspection {
            state: TrustedPublishedUpdateRecoveryState::ManualAttention,
            candidate: None,
        });
    }
    let reconstructed = match reconstruct_v2_authority(
        &workspace,
        &txn,
        &installed_source,
        &resource_key,
        installed_source.selected_resource_root(),
        &plan_id,
        options,
    ) {
        Ok(reconstructed) => reconstructed,
        Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::Unsupported,
                candidate: None,
            })
        }
        Err(_) => {
            return Ok(TrustedPublishedUpdateRecoveryInspection {
                state: TrustedPublishedUpdateRecoveryState::ManualAttention,
                candidate: None,
            })
        }
    };
    let state = match reconstructed.journal_event {
        TransactionJournalEvent::Committed => TrustedPublishedUpdateRecoveryState::Committed,
        TransactionJournalEvent::RolledBack => TrustedPublishedUpdateRecoveryState::RolledBack,
        TransactionJournalEvent::AbortedBeforeMutation => {
            TrustedPublishedUpdateRecoveryState::SafeRestart
        }
        TransactionJournalEvent::RecoveryRequired => {
            TrustedPublishedUpdateRecoveryState::RecoveryRequired
        }
        _ => TrustedPublishedUpdateRecoveryState::Recoverable,
    };
    Ok(TrustedPublishedUpdateRecoveryInspection {
        state,
        candidate: Some(candidate),
    })
}

/// Recover one exact Task 31A v2 candidate without any package or process-local plan authority.
pub fn recover_trusted_published_update_v2(
    request: TrustedPackageFreeUpdateRecoveryRequest<'_>,
) -> Result<TrustedRecoveryResult> {
    let options = request.options.validate()?;
    let pre_workspace = resolve_trusted_update_workspace(request.workspace.app_root())
        .map_err(map_durable_error)?;
    let transaction_root =
        TrustedTransactionRoot::try_open_in_workspace(&pre_workspace).map_err(map_durable_error)?;
    let (pre_source, pre_key) = reopen_fresh_installed_selection(
        request.installed_selection.source(),
        options.installed_scan_limits,
    )?;
    pre_source
        .capture_tree_snapshot(&pre_key)
        .map_err(map_durable_error)?;

    let scan = crate::scan_trusted_transactions(&transaction_root, options.scan)?;
    let matches: Vec<_> = scan
        .candidates()
        .iter()
        .filter(|candidate| candidate.candidate_id() == request.candidate)
        .collect();
    let candidate = match matches.as_slice() {
        [candidate] if candidate.kind() == TrustedRecoveryCandidateKind::Bound => *candidate,
        [] => return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound),
        _ => return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous),
    };
    let plan_id = candidate
        .proven_plan_id
        .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound)?;
    let retired = validated_retired_terminal_plan_ids(
        &transaction_root,
        options.recovery.max_journal_records,
    )?;
    if retired.contains(&plan_id) {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound);
    }
    require_unambiguous_same_resource(&transaction_root, &scan, &pre_key, &plan_id, &retired)?;

    // Pre-lock inspection rejects plainly invalid/legacy evidence. This complete
    // authority is deliberately dropped before either lock becomes authority.
    let (pre_txn, pre_namespace) = open_candidate_transaction(&transaction_root, &plan_id)?;
    let pre = reconstruct_v2_authority(
        &pre_workspace,
        &pre_txn,
        &pre_source,
        &pre_key,
        pre_source.selected_resource_root(),
        &plan_id,
        options,
    )?;
    drop(pre);
    drop(pre_txn);
    drop(pre_source);

    #[cfg(test)]
    test_hooks::fire_after_pre_lock_reconstruction(request.workspace.app_root());

    // Fixed lock order: resource lock, then transaction recovery lock. Acquire
    // returns only freshly rebound transaction/journal capabilities.
    let verified = VerifiedPublishedTransaction::acquire_with_expected_namespace(
        &transaction_root,
        pre_key.as_str(),
        &plan_id,
        &pre_namespace.transactions_parent_identity,
        &pre_namespace.transaction_identity,
        &pre_namespace.journal_identity,
    )?;
    #[cfg(test)]
    test_hooks::fire_after_mutating_locks_acquired(request.workspace.app_root());

    // Nothing reconstructed before the locks is reused below.
    let post_workspace = resolve_trusted_update_workspace(request.workspace.app_root())
        .map_err(map_durable_error)?;
    let (installed_source, resource_key) = reopen_fresh_installed_selection(
        request.installed_selection.source(),
        options.installed_scan_limits,
    )?;
    if resource_key != pre_key {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    verified.reassert(&transaction_root)?;
    let fresh_scan = crate::scan_trusted_transactions(&transaction_root, options.scan)?;
    let fresh_retired = validated_retired_terminal_plan_ids(
        &transaction_root,
        options.recovery.max_journal_records,
    )?;
    if fresh_retired.contains(&plan_id) {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound);
    }
    require_unambiguous_same_resource(
        &transaction_root,
        &fresh_scan,
        &resource_key,
        &plan_id,
        &fresh_retired,
    )?;
    let reconstructed = reconstruct_v2_authority(
        &post_workspace,
        &verified.txn_dir,
        &installed_source,
        &resource_key,
        installed_source.selected_resource_root(),
        &plan_id,
        options,
    )?;

    let authority = TrustedRecoveryExecutionAuthority::package_free(
        &reconstructed.tx_plan,
        &reconstructed.apply_plan,
        &reconstructed.bundle,
        &resource_key,
        &installed_source,
        &transaction_root,
        options.recovery,
    );
    recover_with_verified(&authority, verified)
}

fn reopen_fresh_installed_selection(
    trusted_selection: &InstalledApplyPlanningSource,
    limits: InstalledScanLimits,
) -> Result<(InstalledApplyPlanningSource, SafeResourceKey)> {
    let source = trusted_selection
        .reopen_for_package_free_recovery(limits)
        .map_err(map_durable_error)?;
    let key = source
        .resource_key_for_package_free_recovery()
        .map_err(map_durable_error)?;
    Ok((source, key))
}

fn open_candidate_transaction(
    root: &TrustedTransactionRoot,
    plan_id: &Sha256Digest,
) -> Result<(CapDir, PreLockPublishedNamespaceBinding)> {
    let transactions = open_child_dir(root.dir(), "transactions").map_err(map_durable_error)?;
    let transactions_parent_identity =
        dir_identity(&transactions, "transactions").map_err(map_durable_error)?;
    let transaction =
        open_child_dir(&transactions, &plan_id.to_string()).map_err(map_durable_error)?;
    let transaction_identity =
        dir_identity(&transaction, "transaction").map_err(map_durable_error)?;
    let journal = open_child_dir(&transaction, "journal").map_err(map_durable_error)?;
    let journal_identity = dir_identity(&journal, "journal").map_err(map_durable_error)?;
    Ok((
        transaction,
        PreLockPublishedNamespaceBinding {
            transactions_parent_identity,
            transaction_identity,
            journal_identity,
        },
    ))
}

fn require_unambiguous_same_resource(
    root: &TrustedTransactionRoot,
    scan: &crate::TrustedRecoveryScanResult,
    resource_key: &SafeResourceKey,
    selected_plan: &Sha256Digest,
    retired: &BTreeSet<Sha256Digest>,
) -> Result<()> {
    if scan
        .candidates()
        .iter()
        .any(|candidate| candidate.kind() == TrustedRecoveryCandidateKind::Malformed)
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
    }
    let expected = crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id(
        resource_key.as_str(),
    )
    .map_err(map_durable_error)?;
    let transactions = open_child_dir(root.dir(), "transactions").map_err(map_durable_error)?;
    let mut matching = Vec::new();
    for candidate in scan.candidates() {
        let Some(plan_id) = candidate.proven_plan_id else {
            continue;
        };
        if retired.contains(&plan_id) {
            continue;
        }
        let txn = open_child_dir(&transactions, &plan_id.to_string()).map_err(map_durable_error)?;
        let lock = read_resource_lock_id_binding(&txn).map_err(map_durable_error)?;
        if lock == expected {
            matching.push(plan_id);
        }
    }
    match matching.as_slice() {
        [only] if only == selected_plan => {}
        [] => return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch),
        _ => return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_v2_authority(
    workspace: &TrustedUpdateWorkspace,
    txn_dir: &CapDir,
    installed_source: &InstalledApplyPlanningSource,
    fresh_key: &SafeResourceKey,
    selected_root: &InstalledResourceRoot,
    plan_id: &Sha256Digest,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<ReconstructedV2Authority> {
    reconstruct_v2_authority_inner(
        workspace,
        txn_dir,
        installed_source,
        fresh_key,
        selected_root,
        plan_id,
        options,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_forward_v2_authority(
    workspace: &TrustedUpdateWorkspace,
    txn_dir: &CapDir,
    installed_source: &InstalledApplyPlanningSource,
    fresh_key: &SafeResourceKey,
    selected_root: &InstalledResourceRoot,
    plan_id: &Sha256Digest,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<ReconstructedV2Authority> {
    reconstruct_v2_authority_inner(
        workspace,
        txn_dir,
        installed_source,
        fresh_key,
        selected_root,
        plan_id,
        options,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_v2_authority_inner(
    workspace: &TrustedUpdateWorkspace,
    txn_dir: &CapDir,
    installed_source: &InstalledApplyPlanningSource,
    fresh_key: &SafeResourceKey,
    selected_root: &InstalledResourceRoot,
    plan_id: &Sha256Digest,
    options: TrustedPackageFreeUpdateRecoveryOptions,
    allow_undo: bool,
) -> Result<ReconstructedV2Authority> {
    let envelope = match verify_recovery_authority_envelope(txn_dir) {
        Ok(envelope) => envelope,
        Err(error) => {
            let snapshot = read_snapshot_a_binding(txn_dir).map_err(map_durable_error)?;
            let journal = open_child_dir(txn_dir, "journal").map_err(map_durable_error)?;
            if let Ok(cursor) = load_and_validate_journal_chain(
                &journal,
                plan_id,
                &snapshot,
                options.recovery.max_journal_records,
            ) {
                if cursor.publication_binding_id.is_none() {
                    return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
                }
            }
            return Err(map_durable_error(error));
        }
    };
    let body = envelope.body();
    #[cfg(test)]
    note_validation_observation(ValidationObservation::AuthoritySelfIdVerified);
    if body.transactional_plan_id() != plan_id {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    verify_selected_resource_commitment(fresh_key, body.selected_resource_commitment())
        .map_err(map_durable_error)?;
    #[cfg(test)]
    note_validation_observation(ValidationObservation::SelectedResourceCommitmentVerified);
    verify_installed_authority_commitment(
        installed_source,
        fresh_key,
        body.installed_authority_commitment(),
    )
    .map_err(map_durable_error)?;
    #[cfg(test)]
    note_validation_observation(ValidationObservation::InstalledAuthorityCommitmentVerified);

    let artifact = resolve_exact_artifact(
        workspace,
        envelope.artifact_id(),
        options.max_artifact_directory_entries,
        options.max_artifacts,
        options.max_artifact_bytes,
        options.max_total_artifact_bytes,
    )?;
    #[cfg(test)]
    note_validation_observation(ValidationObservation::ArtifactSelfIdVerified);
    if artifact.version() != ARTIFACT_V2_FORMAT_VERSION
        || artifact.artifact_id().digest() != envelope.artifact_id()
        || artifact.body().recovery_authority_id != Some(*envelope.authority_id().digest())
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
    }
    if artifact.undo_descriptor().is_some() {
        if !allow_undo {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
        }
        return reconstruct_undo_v2_authority(
            workspace,
            txn_dir,
            installed_source,
            fresh_key,
            selected_root,
            plan_id,
            options,
            &envelope,
            &artifact,
        );
    }
    if artifact.two_way_descriptor().is_some() {
        return reconstruct_two_way_v2_authority(
            workspace,
            txn_dir,
            installed_source,
            fresh_key,
            selected_root,
            plan_id,
            options,
            &envelope,
            &artifact,
        );
    }
    let descriptor = artifact
        .apply_descriptor()
        .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported)?;
    if descriptor.version()
        != crate::trusted_cli_update_artifact::TrustedCliApplyDescriptor::VERSION
        || &descriptor.resource_key().map_err(map_durable_error)? != fresh_key
        || &descriptor
            .selected_installed_root()
            .map_err(map_durable_error)?
            != selected_root
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let baseline_id = descriptor.baseline_id().map_err(map_durable_error)?;
    let baseline_digest =
        Sha256Digest::from_lowercase_hex(baseline_id.as_str()).map_err(map_durable_error)?;
    if &baseline_digest != body.baseline_id()
        || artifact.body().baseline_id_digest != baseline_digest
        || artifact.body().staging_manifest_id != *body.staging_manifest_id()
        || artifact.body().staging_bundle_id != *body.staging_bundle_id()
        || artifact.body().snapshot_a != *body.snapshot_a_id()
        || artifact.body().apply_plan_id != *body.apply_plan_id()
        || artifact.body().transactional_plan_id != *body.transactional_plan_id()
        || artifact.body().selected_resource_commitment != *body.selected_resource_commitment()
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    #[cfg(test)]
    note_validation_observation(ValidationObservation::ArtifactCrossBindingVerified);

    let baseline = resolve_official_baseline(BaselineResolutionRequest::try_new(
        workspace.baseline_store(),
        fresh_key,
        OfficialBaselineSelector::Exact(baseline_id.clone()),
        BaselineResolutionOptions::default(),
    )?)
    .map_err(map_durable_error)?;
    let staging_root =
        TrustedStagingRoot::try_open(workspace.staging_root()).map_err(map_durable_error)?;
    let staging_options = TrustedStagingOptions::default();
    let bundle = reopen_trusted_staging_bundle_from_artifact(
        &staging_root,
        artifact.body(),
        fresh_key,
        &baseline_id,
        &descriptor
            .installed_snapshot_fingerprint()
            .map_err(map_durable_error)?,
        &descriptor
            .incoming_package_fingerprint()
            .map_err(map_durable_error)?,
        &descriptor
            .incoming_resource_fingerprint()
            .map_err(map_durable_error)?,
        staging_options,
    )
    .map_err(map_durable_error)?;
    let (plan, review, merge_ids, merged_bytes) = descriptor_apply_graph(
        fresh_key,
        &baseline_id,
        descriptor,
        artifact.body(),
        &bundle,
        staging_options.max_file_bytes(),
    )
    .map_err(map_durable_error)?;

    let snapshot_binding = read_snapshot_a_binding(txn_dir).map_err(map_durable_error)?;
    let resource_lock = read_resource_lock_id_binding(txn_dir).map_err(map_durable_error)?;
    let expected_lock =
        crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id(
            fresh_key.as_str(),
        )
        .map_err(map_durable_error)?;
    if snapshot_binding != *body.snapshot_a_id() || resource_lock != expected_lock {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let publication = encode_publication_binding_id(
        envelope.artifact_id(),
        envelope.authority_id(),
        plan_id,
        &snapshot_binding,
        &resource_lock,
    )
    .map_err(map_durable_error)?;
    if &publication != envelope.publication_binding_id() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let journal_dir = open_child_dir(txn_dir, "journal").map_err(map_durable_error)?;
    let cursor = load_and_validate_journal_chain(
        &journal_dir,
        plan_id,
        &snapshot_binding,
        options.recovery.max_journal_records,
    )
    .map_err(map_durable_error)?;
    if cursor.publication_binding_id != Some(*publication.digest()) {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
    }
    #[cfg(test)]
    note_validation_observation(ValidationObservation::PublicationBindingVerified);

    let snapshot = body.to_installed_snapshot().map_err(map_durable_error)?;
    #[cfg(test)]
    note_validation_observation(ValidationObservation::FrozenDerivationDispatchStarted);
    let derivation_result = reconstruct_recovery_derivation_from_snapshot(
        body.apply_derivation_version(),
        body.transaction_derivation_version(),
        RecoveryDerivationFromSnapshotRequestV1 {
            request: RecoveryDerivationRequestV1 {
                bundle: &bundle,
                plan: &plan,
                review: &review,
                merge_ids,
                merged_bytes: merged_bytes.as_ref(),
                baseline: &baseline,
                installed_source,
            },
            snapshot: &snapshot,
        },
    );
    #[cfg(test)]
    if matches!(
        &derivation_result,
        Err(GkrmError::TrustedRecoveryAuthorityDerivationUnsupported)
    ) {
        note_validation_observation(ValidationObservation::UnsupportedDerivationRejected);
    }
    let derivation = derivation_result.map_err(map_durable_error)?;
    #[cfg(test)]
    note_validation_observation(ValidationObservation::FrozenDerivationReconstructionCompleted);
    if derivation.apply_plan.plan_id().digest() != body.apply_plan_id()
        || derivation.transactional_plan.plan_id().digest() != body.transactional_plan_id()
        || derivation.snapshot.fingerprint != *body.snapshot_a_id()
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let (recomputed_body, recomputed_id) = build_recovery_authority_body(
        installed_source,
        fresh_key,
        baseline_digest,
        *bundle.manifest().manifest_id().digest(),
        *bundle.bundle_id().digest(),
        *derivation.apply_plan.plan_id().digest(),
        *derivation.transactional_plan.plan_id().digest(),
        &snapshot,
        options.authority,
    )
    .map_err(map_durable_error)?;
    if &recomputed_body != body || &recomputed_id != envelope.authority_id() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }

    if let Some(seal) = cursor.backup_seal {
        revalidate_sealed_backup_for_recovery(
            txn_dir,
            plan_id,
            derivation.transactional_plan.backup().entries(),
            &seal,
        )
        .map_err(map_durable_error)?;
    }

    Ok(ReconstructedV2Authority {
        bundle,
        apply_plan: derivation.apply_plan,
        tx_plan: derivation.transactional_plan,
        journal_event: cursor
            .last_event
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_two_way_v2_authority(
    workspace: &TrustedUpdateWorkspace,
    txn_dir: &CapDir,
    installed_source: &InstalledApplyPlanningSource,
    fresh_key: &SafeResourceKey,
    selected_root: &InstalledResourceRoot,
    plan_id: &Sha256Digest,
    options: TrustedPackageFreeUpdateRecoveryOptions,
    envelope: &crate::trusted_recovery_authority::RecoveryAuthorityEnvelopeV1,
    artifact: &TrustedCliUpdateArtifact,
) -> Result<ReconstructedV2Authority> {
    let body = envelope.body();
    let descriptor = artifact
        .two_way_descriptor()
        .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported)?;
    let plan = descriptor.reconstruct().map_err(map_durable_error)?;
    if plan.resource_key() != fresh_key
        || &descriptor.selected_root().map_err(map_durable_error)? != selected_root
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let mut marker = CanonicalFingerprintEncoder::new("gkrm-two-way-absent-record-v1")
        .map_err(map_durable_error)?;
    marker.string("baseline").map_err(map_durable_error)?;
    let baseline_digest = marker.finish();
    if &baseline_digest != body.baseline_id()
        || artifact.body().baseline_id_digest != baseline_digest
        || artifact.body().staging_manifest_id != *body.staging_manifest_id()
        || artifact.body().staging_bundle_id != *body.staging_bundle_id()
        || artifact.body().snapshot_a != *body.snapshot_a_id()
        || artifact.body().apply_plan_id != *body.apply_plan_id()
        || artifact.body().transactional_plan_id != *body.transactional_plan_id()
        || artifact.body().selected_resource_commitment != *body.selected_resource_commitment()
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let staging_root =
        TrustedStagingRoot::try_open(workspace.staging_root()).map_err(map_durable_error)?;
    let bundle = crate::trusted_staging::reopen_trusted_two_way_staging_bundle(
        &staging_root,
        artifact.body(),
        &plan,
        TrustedStagingOptions::default(),
    )
    .map_err(map_durable_error)?;
    let snapshot_binding = read_snapshot_a_binding(txn_dir).map_err(map_durable_error)?;
    let resource_lock = read_resource_lock_id_binding(txn_dir).map_err(map_durable_error)?;
    let expected_lock =
        crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id(
            fresh_key.as_str(),
        )
        .map_err(map_durable_error)?;
    if snapshot_binding != *body.snapshot_a_id() || resource_lock != expected_lock {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let publication = encode_publication_binding_id(
        envelope.artifact_id(),
        envelope.authority_id(),
        plan_id,
        &snapshot_binding,
        &resource_lock,
    )
    .map_err(map_durable_error)?;
    if &publication != envelope.publication_binding_id() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let journal_dir = open_child_dir(txn_dir, "journal").map_err(map_durable_error)?;
    let cursor = load_and_validate_journal_chain(
        &journal_dir,
        plan_id,
        &snapshot_binding,
        options.recovery.max_journal_records,
    )
    .map_err(map_durable_error)?;
    if cursor.publication_binding_id != Some(*publication.digest()) {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
    }
    #[cfg(test)]
    note_validation_observation(ValidationObservation::PublicationBindingVerified);

    let snapshot = body.to_installed_snapshot().map_err(map_durable_error)?;
    dispatch_recovery_derivation(
        body.apply_derivation_version(),
        body.transaction_derivation_version(),
    )
    .map_err(map_durable_error)?;
    let review_id = *bundle.manifest().review_id_digest();
    let apply_plan = crate::trusted_apply_planning::plan_trusted_apply_v1_from_snapshot(
        crate::TrustedApplyPlanningRequest::try_new_two_way(
            &bundle,
            &plan,
            review_id,
            installed_source,
            crate::TrustedApplyPlanningOptions::default(),
        )?,
        &snapshot,
    )
    .map_err(map_durable_error)?;
    let tx_plan = crate::trusted_transactional_apply_planning::plan_trusted_transactional_apply_v1_from_snapshot(
        crate::TrustedTransactionalApplyPlanningRequest::try_new_two_way(&apply_plan, &bundle, &plan, review_id, installed_source, crate::TrustedTransactionalApplyPlanningOptions::default())?, &snapshot,
    ).map_err(map_durable_error)?;
    if apply_plan.plan_id().digest() != body.apply_plan_id()
        || tx_plan.plan_id().digest() != body.transactional_plan_id()
        || snapshot.fingerprint != *body.snapshot_a_id()
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let (recomputed_body, recomputed_id) = build_recovery_authority_body(
        installed_source,
        fresh_key,
        baseline_digest,
        *bundle.manifest().manifest_id().digest(),
        *bundle.bundle_id().digest(),
        *apply_plan.plan_id().digest(),
        *tx_plan.plan_id().digest(),
        &snapshot,
        options.authority,
    )
    .map_err(map_durable_error)?;
    if &recomputed_body != body || &recomputed_id != envelope.authority_id() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }

    if let Some(seal) = cursor.backup_seal {
        revalidate_sealed_backup_for_recovery(txn_dir, plan_id, tx_plan.backup().entries(), &seal)
            .map_err(map_durable_error)?;
    }

    Ok(ReconstructedV2Authority {
        bundle,
        apply_plan,
        tx_plan,
        journal_event: cursor
            .last_event
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_undo_v2_authority(
    workspace: &TrustedUpdateWorkspace,
    txn_dir: &CapDir,
    installed_source: &InstalledApplyPlanningSource,
    fresh_key: &SafeResourceKey,
    selected_root: &InstalledResourceRoot,
    plan_id: &Sha256Digest,
    options: TrustedPackageFreeUpdateRecoveryOptions,
    envelope: &crate::trusted_recovery_authority::RecoveryAuthorityEnvelopeV1,
    artifact: &TrustedCliUpdateArtifact,
) -> Result<ReconstructedV2Authority> {
    let body = envelope.body();
    let descriptor = artifact
        .undo_descriptor()
        .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported)?;
    if &descriptor.resource_key().map_err(map_durable_error)? != fresh_key
        || &descriptor.selected_root().map_err(map_durable_error)? != selected_root
        || descriptor
            .parent_transaction_id()
            .map_err(map_durable_error)?
            == *plan_id
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let baseline_digest =
        crate::trusted_staging::undo_record_marker("baseline").map_err(map_durable_error)?;
    if &baseline_digest != body.baseline_id()
        || artifact.body().baseline_id_digest != baseline_digest
        || artifact.body().staging_manifest_id != *body.staging_manifest_id()
        || artifact.body().staging_bundle_id != *body.staging_bundle_id()
        || artifact.body().snapshot_a != *body.snapshot_a_id()
        || artifact.body().apply_plan_id != *body.apply_plan_id()
        || artifact.body().transactional_plan_id != *body.transactional_plan_id()
        || artifact.body().selected_resource_commitment != *body.selected_resource_commitment()
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let snapshot = body.to_installed_snapshot().map_err(map_durable_error)?;
    let parent = TrustedUndoSource::reopen_committed_parent(
        workspace,
        installed_source,
        fresh_key,
        &descriptor
            .parent_transaction_id()
            .map_err(map_durable_error)?,
        options,
    )?;
    let staged = crate::trusted_staging::reopen_undo_candidate(
        workspace,
        &parent,
        &snapshot,
        installed_source,
        artifact.body(),
        descriptor,
    )
    .map_err(map_durable_error)?;
    let bundle = staged.bundle();
    let snapshot_binding = read_snapshot_a_binding(txn_dir).map_err(map_durable_error)?;
    let resource_lock = read_resource_lock_id_binding(txn_dir).map_err(map_durable_error)?;
    let expected_lock =
        crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id(
            fresh_key.as_str(),
        )
        .map_err(map_durable_error)?;
    if snapshot_binding != *body.snapshot_a_id() || resource_lock != expected_lock {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let publication = encode_publication_binding_id(
        envelope.artifact_id(),
        envelope.authority_id(),
        plan_id,
        &snapshot_binding,
        &resource_lock,
    )
    .map_err(map_durable_error)?;
    if &publication != envelope.publication_binding_id() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let journal_dir = open_child_dir(txn_dir, "journal").map_err(map_durable_error)?;
    let cursor = load_and_validate_journal_chain(
        &journal_dir,
        plan_id,
        &snapshot_binding,
        options.recovery.max_journal_records,
    )
    .map_err(map_durable_error)?;
    if cursor.publication_binding_id != Some(*publication.digest()) {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported);
    }
    #[cfg(test)]
    note_validation_observation(ValidationObservation::PublicationBindingVerified);

    dispatch_recovery_derivation(
        body.apply_derivation_version(),
        body.transaction_derivation_version(),
    )
    .map_err(map_durable_error)?;
    let apply_plan = crate::trusted_apply_planning::plan_trusted_apply_v1_from_snapshot(
        crate::TrustedApplyPlanningRequest::try_new_undo(
            &staged,
            installed_source,
            crate::TrustedApplyPlanningOptions::default(),
        )?,
        &snapshot,
    )
    .map_err(map_durable_error)?;
    let tx_plan = crate::trusted_transactional_apply_planning::plan_trusted_transactional_apply_v1_from_snapshot(
        crate::TrustedTransactionalApplyPlanningRequest::try_new_undo(&apply_plan, &staged, installed_source, crate::TrustedTransactionalApplyPlanningOptions::default())?, &snapshot,
    ).map_err(map_durable_error)?;
    if apply_plan.plan_id().digest() != body.apply_plan_id()
        || tx_plan.plan_id().digest() != body.transactional_plan_id()
        || snapshot.fingerprint != *body.snapshot_a_id()
    {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    let (recomputed_body, recomputed_id) = build_recovery_authority_body(
        installed_source,
        fresh_key,
        baseline_digest,
        *bundle.manifest().manifest_id().digest(),
        *bundle.bundle_id().digest(),
        *apply_plan.plan_id().digest(),
        *tx_plan.plan_id().digest(),
        &snapshot,
        options.authority,
    )
    .map_err(map_durable_error)?;
    if &recomputed_body != body || &recomputed_id != envelope.authority_id() {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }

    if let Some(seal) = cursor.backup_seal {
        revalidate_sealed_backup_for_recovery(txn_dir, plan_id, tx_plan.backup().entries(), &seal)
            .map_err(map_durable_error)?;
    }

    Ok(ReconstructedV2Authority {
        bundle: staged.into_bundle(),
        apply_plan,
        tx_plan,
        journal_event: cursor
            .last_event
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
    })
}

fn load_recovery_overview_artifact_catalog(
    workspace: &TrustedUpdateWorkspace,
    options: TrustedPackageFreeUpdateRecoveryOptions,
) -> Result<RecoveryOverviewArtifactCatalog> {
    #[cfg(test)]
    note_overview_artifact_catalog_load();

    let (root, root_identity) = workspace
        .try_clone_artifact_root_capability()
        .map_err(map_durable_error)?;
    let mut names = Vec::new();
    let mut inspected_entries = 0usize;
    for entry in root
        .entries()
        .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
    {
        let entry =
            entry.map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        inspected_entries = inspected_entries
            .checked_add(1)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if inspected_entries > options.max_artifact_directory_entries {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        validate_single_component(&name).map_err(map_durable_error)?;
        let metadata = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if is_windows_reparse_point_cap(&metadata) || metadata.file_type().is_symlink() {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        if metadata.file_type().is_file() && name.starts_with("plan-") && name.ends_with(".bin") {
            names.push(name);
            if names.len() > options.max_artifacts {
                return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
            }
        } else if !metadata.file_type().is_file() {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
    }
    names.sort();

    let parse_options = TrustedCliUpdateOptions {
        max_artifact_bytes: usize::try_from(options.max_artifact_bytes)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
        ..TrustedCliUpdateOptions::default()
    };
    let mut total_bytes_read = 0u64;
    let mut catalog = RecoveryOverviewArtifactCatalog {
        entries: BTreeMap::new(),
    };
    for name in names {
        let mut file = open_file_nofollow(&root, &name).map_err(map_durable_error)?;
        let before = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let length = file
            .metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
            .len();
        if length > options.max_artifact_bytes {
            continue;
        }
        let prospective_total = total_bytes_read
            .checked_add(length)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if prospective_total > options.max_total_artifact_bytes {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        file.rewind()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(options.max_artifact_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > options.max_artifact_bytes {
            continue;
        }
        let bytes_read = u64::try_from(bytes.len())
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        total_bytes_read = total_bytes_read
            .checked_add(bytes_read)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if total_bytes_read > options.max_total_artifact_bytes {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let length_after = file
            .metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
            .len();
        let after = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if before != after || length_after != length {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        #[cfg(test)]
        note_artifact_parse_attempt();
        let Ok(artifact) = parse_cli_artifact(&bytes, &parse_options) else {
            continue;
        };
        if artifact.version() != ARTIFACT_V2_FORMAT_VERSION {
            continue;
        }
        let body = artifact.body();
        let summary = RecoveryOverviewArtifactSummary {
            recovery_authority_id: body.recovery_authority_id,
            transactional_plan_id: body.transactional_plan_id,
            snapshot_a: body.snapshot_a,
            apply_plan_id: body.apply_plan_id,
            baseline_id_digest: body.baseline_id_digest,
            staging_manifest_id: body.staging_manifest_id,
            staging_bundle_id: body.staging_bundle_id,
            selected_resource_commitment: body.selected_resource_commitment,
        };
        let artifact_id = *artifact.artifact_id().digest();
        match catalog.entries.get_mut(&artifact_id) {
            Some(entry) => *entry = None,
            None => {
                catalog.entries.insert(artifact_id, Some(summary));
            }
        }
    }
    if dir_identity(&root, "artifact-root").map_err(map_durable_error)? != root_identity {
        return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
    }
    Ok(catalog)
}

fn resolve_exact_artifact(
    workspace: &TrustedUpdateWorkspace,
    expected_id: &Sha256Digest,
    max_directory_entries: usize,
    max_artifacts: usize,
    max_bytes: u64,
    max_total_bytes: u64,
) -> Result<TrustedCliUpdateArtifact> {
    let root = open_existing_directory(workspace.artifact_root().path(), "artifact-root")
        .map_err(map_durable_error)?;
    let mut names = Vec::new();
    let mut inspected_entries = 0usize;
    for entry in root
        .dir
        .entries()
        .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
    {
        let entry =
            entry.map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        inspected_entries = inspected_entries
            .checked_add(1)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if inspected_entries > max_directory_entries {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        validate_single_component(&name).map_err(map_durable_error)?;
        let metadata = entry
            .full_metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if is_windows_reparse_point_cap(&metadata) || metadata.file_type().is_symlink() {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        if metadata.file_type().is_file() && name.starts_with("plan-") && name.ends_with(".bin") {
            names.push(name);
            if names.len() > max_artifacts {
                return Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous);
            }
        } else if !metadata.file_type().is_file() {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
    }
    names.sort();
    let parse_options = TrustedCliUpdateOptions {
        max_artifact_bytes: usize::try_from(max_bytes)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
        ..TrustedCliUpdateOptions::default()
    };
    let mut matches = Vec::new();
    let mut total_bytes_read = 0u64;
    for name in names {
        let mut file = open_file_nofollow(&root.dir, &name).map_err(map_durable_error)?;
        let before = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let length = file
            .metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
            .len();
        if length > max_bytes {
            continue;
        }
        let prospective_total = total_bytes_read
            .checked_add(length)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if prospective_total > max_total_bytes {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        file.rewind()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            continue;
        }
        let bytes_read = u64::try_from(bytes.len())
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        total_bytes_read = total_bytes_read
            .checked_add(bytes_read)
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if total_bytes_read > max_total_bytes {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        let length_after = file
            .metadata()
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
            .len();
        let after = capture_stable_file_identity(&file)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        if before != after || length_after != length {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        #[cfg(test)]
        note_artifact_parse_attempt();
        let Ok(artifact) = parse_cli_artifact(&bytes, &parse_options) else {
            continue;
        };
        if artifact.version() == ARTIFACT_V2_FORMAT_VERSION
            && artifact.artifact_id().digest() == expected_id
        {
            matches.push(artifact);
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch),
        _ => Err(GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous),
    }
}

fn map_durable_error(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedRecoveryAuthorityDerivationUnsupported
        | GkrmError::TrustedRecoveryAuthorityVersionUnsupported
        | GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported => {
            GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
        }
        GkrmError::TrustedTransactionalApplyExecutionLockContention => error,
        GkrmError::TrustedPackageFreeUpdateRecoveryCandidateNotFound
        | GkrmError::TrustedPackageFreeUpdateRecoveryCandidateAmbiguous
        | GkrmError::TrustedPackageFreeUpdateRecoveryUnsupported
        | GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch => error,
        _ => GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch,
    }
}
