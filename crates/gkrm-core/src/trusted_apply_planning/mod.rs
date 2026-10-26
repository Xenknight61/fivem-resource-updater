//! Trusted read-only apply operation planner (Milestone 2 Task 21).

#![allow(clippy::too_many_arguments)]

mod binding;
mod id;
mod operations;
mod sources;
mod tree;

#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;

use crate::baseline::BaselineStoreLimits;
use crate::trusted_staging::{
    verify_published_bundle_readonly, TrustedStagingBundle, TrustedStagingBundleId,
    TrustedStagingManifestId, TrustedStagingStatus,
};
use crate::{
    GkrmError, InstalledScanLimits, ResolvedOfficialBaseline, ResourceRelativePath, Result,
    Sha256Digest, ThreeWayMergeAnalysisPlan, ThreeWayMergeSynthesisPlan, ThreeWayMergedBytesPlan,
    ThreeWayPlanReview, ThreeWayTextDiffPlan, ThreeWayUpdatePlan,
};

pub use crate::error::ApplyPlanningIoOperation;
pub use sources::InstalledApplyPlanningSource;

use binding::bind_before_io;
pub(crate) use id::{encode_backup_set_id, encode_operation_id, OperationIdInputs};
use id::{encode_plan_id, PlanIdInputs};
use operations::{build_desired_tree, build_operations, trees_equal};
#[cfg(test)]
pub(crate) use operations::{
    frozen_task21_v1_aggregate_ids_for_test, frozen_task21_v1_operations_fixture,
    frozen_task21_v1_operations_with_binding_mutation_for_test,
};
pub(crate) use tree::ApplyFileState;
pub(crate) use tree::InstalledApplyTreeSnapshot;
pub(crate) use tree::{encode_installed_apply_tree_snapshot, parents_of};

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
#[cfg(test)]
use std::thread::ThreadId;

#[cfg(test)]
thread_local! {
    static INSTALLED_READ_COUNT: Cell<usize> = const { Cell::new(0) };
    static STAGING_READ_COUNT: Cell<usize> = const { Cell::new(0) };
    static CONTENT_READ_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
type ApplyPlanningHook = Box<dyn FnMut() + Send + 'static>;

#[cfg(test)]
struct ApplyPlanningHooks {
    owner: ThreadId,
    after_scan_a: Option<ApplyPlanningHook>,
    after_first_staging_verify: Option<ApplyPlanningHook>,
    after_operations: Option<ApplyPlanningHook>,
    before_scan_b: Option<ApplyPlanningHook>,
    after_scan_b: Option<ApplyPlanningHook>,
}

#[cfg(test)]
static APPLY_PLANNING_HOOKS: Mutex<Option<ApplyPlanningHooks>> = Mutex::new(None);
#[cfg(test)]
static APPLY_PLANNING_HOOK_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) struct ApplyPlanningHookGuard {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
pub(crate) fn lock_apply_planning_hooks() -> ApplyPlanningHookGuard {
    let guard = APPLY_PLANNING_HOOK_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let mut hooks = APPLY_PLANNING_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    *hooks = Some(ApplyPlanningHooks {
        owner: std::thread::current().id(),
        after_scan_a: None,
        after_first_staging_verify: None,
        after_operations: None,
        before_scan_b: None,
        after_scan_b: None,
    });
    ApplyPlanningHookGuard { _guard: guard }
}

#[cfg(test)]
impl Drop for ApplyPlanningHookGuard {
    fn drop(&mut self) {
        let mut hooks = APPLY_PLANNING_HOOKS
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *hooks = None;
    }
}

#[cfg(test)]
macro_rules! set_apply_hook {
    ($field:ident, $hook:expr) => {{
        let mut hooks = APPLY_PLANNING_HOOKS
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(hooks) = hooks.as_mut() {
            if hooks.owner == std::thread::current().id() {
                hooks.$field = Some(Box::new($hook));
            }
        }
    }};
}

#[cfg(test)]
pub(crate) fn set_after_scan_a_hook(hook: impl FnMut() + Send + 'static) {
    set_apply_hook!(after_scan_a, hook);
}
#[cfg(test)]
pub(crate) fn set_after_first_staging_verify_hook(hook: impl FnMut() + Send + 'static) {
    set_apply_hook!(after_first_staging_verify, hook);
}
#[cfg(test)]
pub(crate) fn set_after_operations_hook(hook: impl FnMut() + Send + 'static) {
    set_apply_hook!(after_operations, hook);
}
#[cfg(test)]
pub(crate) fn set_before_scan_b_hook(hook: impl FnMut() + Send + 'static) {
    set_apply_hook!(before_scan_b, hook);
}
#[cfg(test)]
pub(crate) fn set_after_scan_b_hook(hook: impl FnMut() + Send + 'static) {
    set_apply_hook!(after_scan_b, hook);
}

#[cfg(test)]
enum ApplyHookPoint {
    AfterSnapshotA,
    AfterFirstStagingVerify,
    AfterOperations,
    BeforeSnapshotB,
    AfterSnapshotB,
}

#[cfg(test)]
fn run_apply_hook(point: ApplyHookPoint) {
    let mut hooks = APPLY_PLANNING_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            let hook = match point {
                ApplyHookPoint::AfterSnapshotA => hooks.after_scan_a.as_mut(),
                ApplyHookPoint::AfterFirstStagingVerify => {
                    hooks.after_first_staging_verify.as_mut()
                }
                ApplyHookPoint::AfterOperations => hooks.after_operations.as_mut(),
                ApplyHookPoint::BeforeSnapshotB => hooks.before_scan_b.as_mut(),
                ApplyHookPoint::AfterSnapshotB => hooks.after_scan_b.as_mut(),
            };
            if let Some(hook) = hook {
                hook();
            }
        }
    }
}

#[cfg(test)]
pub(super) fn note_installed_read() {
    INSTALLED_READ_COUNT.with(|c| c.set(c.get() + 1));
    CONTENT_READ_COUNT.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
pub(super) fn note_staging_read_count() {
    STAGING_READ_COUNT.with(|c| c.set(c.get() + 1));
    CONTENT_READ_COUNT.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
pub(crate) fn content_read_count() -> usize {
    CONTENT_READ_COUNT.with(|c| c.get())
}

#[cfg(test)]
pub(crate) fn installed_read_count() -> usize {
    INSTALLED_READ_COUNT.with(|c| c.get())
}

#[cfg(test)]
pub(crate) fn staging_read_count() -> usize {
    STAGING_READ_COUNT.with(|c| c.get())
}

#[cfg(test)]
pub(crate) fn reset_content_read_count() {
    CONTENT_READ_COUNT.with(|c| c.set(0));
    INSTALLED_READ_COUNT.with(|c| c.set(0));
    STAGING_READ_COUNT.with(|c| c.set(0));
}

#[derive(Clone, Copy)]
pub struct TrustedApplyPlanningOptions {
    pub max_entries: usize,
    pub max_operations: usize,
    pub max_directories: usize,
    pub max_total_expected_write_bytes: u64,
    pub max_total_backup_bytes: u64,
    pub max_path_depth: usize,
    pub max_path_component_bytes: usize,
    pub installed_scan_limits: InstalledScanLimits,
    pub baseline_store_limits: BaselineStoreLimits,
}

impl Default for TrustedApplyPlanningOptions {
    fn default() -> Self {
        Self {
            max_entries: 20_000,
            max_operations: 40_000,
            max_directories: 20_000,
            max_total_expected_write_bytes: 2 * 1024 * 1024 * 1024,
            max_total_backup_bytes: 2 * 1024 * 1024 * 1024,
            max_path_depth: 64,
            max_path_component_bytes: 255,
            installed_scan_limits: InstalledScanLimits::default(),
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl TrustedApplyPlanningOptions {
    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            ("max_entries", self.max_entries),
            ("max_operations", self.max_operations),
            ("max_directories", self.max_directories),
            ("max_path_depth", self.max_path_depth),
            ("max_path_component_bytes", self.max_path_component_bytes),
        ] {
            if value == 0 {
                return Err(GkrmError::TrustedApplyPlanningOptionsInvalid { limit: name });
            }
        }
        if self.max_total_expected_write_bytes == 0 || self.max_total_backup_bytes == 0 {
            return Err(GkrmError::TrustedApplyPlanningOptionsInvalid {
                limit: "byte_limits",
            });
        }
        self.installed_scan_limits.validate().map_err(|_| {
            GkrmError::TrustedApplyPlanningOptionsInvalid {
                limit: "installed_scan_limits",
            }
        })?;
        self.baseline_store_limits.validate().map_err(|_| {
            GkrmError::TrustedApplyPlanningOptionsInvalid {
                limit: "baseline_store_limits",
            }
        })?;
        Ok(())
    }

    fn options_tag(self) -> Result<Vec<u8>> {
        use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
        let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-apply-options-v1")
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_entries)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_operations)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_directories)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        enc.u64(self.max_total_expected_write_bytes);
        enc.u64(self.max_total_backup_bytes);
        enc.usize(self.max_path_depth)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_path_component_bytes)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
        Ok(enc.finish().as_bytes().to_vec())
    }
}

/// Where an apply plan's identity and staleness fingerprints come from.
///
/// Apply planning computes its operations from the staged bundle and the live tree; the plan is
/// only ever consulted for identity and for proving the installation has not moved since it was
/// planned. Both kinds of update can supply that, so the planner takes whichever produced the
/// bundle rather than assuming a three-way comparison happened.
#[derive(Clone, Copy)]
pub(crate) enum ApplyPlanningSource<'a> {
    ThreeWay {
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
    },
    TwoWay {
        plan: &'a crate::TwoWayUpdatePlan,
        review_id: Sha256Digest,
    },
    Undo {
        staged: &'a crate::TrustedUndoStagingBundle,
    },
}

/// Marker recorded where a three-way plan records its baseline identifier.
pub(crate) const TWO_WAY_BASELINE_MARKER: &str = "two-way:no-official-baseline";

impl<'a> ApplyPlanningSource<'a> {
    pub(crate) fn resource_key(&self) -> &crate::SafeResourceKey {
        match self {
            Self::ThreeWay { plan, .. } => plan.resource_key(),
            Self::TwoWay { plan, .. } => plan.resource_key(),
            Self::Undo { staged } => staged.resource_key(),
        }
    }

    pub(crate) fn plan_id_digest(&self) -> &Sha256Digest {
        match self {
            Self::ThreeWay { plan, .. } => plan.plan_id().digest(),
            Self::TwoWay { plan, .. } => plan.plan_id().digest(),
            Self::Undo { staged } => staged.bundle().manifest().plan_id_digest(),
        }
    }

    pub(crate) fn review_id_digest(&self) -> &Sha256Digest {
        match self {
            Self::ThreeWay { review, .. } => review.review_id().digest(),
            Self::TwoWay { review_id, .. } => review_id,
            Self::Undo { staged } => staged.bundle().manifest().review_id_digest(),
        }
    }

    pub(crate) fn baseline_id_str(&self) -> &str {
        match self {
            Self::ThreeWay { plan, .. } => plan.baseline_id().as_str(),
            Self::TwoWay { .. } => TWO_WAY_BASELINE_MARKER,
            Self::Undo { .. } => crate::trusted_staging::UNDO_BASELINE_MARKER,
        }
    }

    pub(crate) fn installed_fingerprint(&self) -> &Sha256Digest {
        match self {
            Self::ThreeWay { plan, .. } => plan.installed_snapshot_fingerprint(),
            Self::TwoWay { plan, .. } => plan.installed_fingerprint(),
            Self::Undo { staged } => staged.installed_fingerprint(),
        }
    }

    pub(crate) fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        match self {
            Self::ThreeWay { plan, .. } => plan.incoming_package_fingerprint(),
            Self::TwoWay { plan, .. } => plan.incoming_package_fingerprint(),
            Self::Undo { staged } => staged.original_artifact_id(),
        }
    }

    pub(crate) fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        match self {
            Self::ThreeWay { plan, .. } => plan.incoming_resource_fingerprint(),
            Self::TwoWay { plan, .. } => plan.incoming_resource_fingerprint(),
            Self::Undo { staged } => staged.original_authority_id(),
        }
    }

    pub(crate) fn three_way(&self) -> Option<(&'a ThreeWayUpdatePlan, &'a ThreeWayPlanReview)> {
        match self {
            Self::ThreeWay { plan, review } => Some((plan, review)),
            Self::TwoWay { .. } | Self::Undo { .. } => None,
        }
    }
}

pub struct TrustedApplyPlanningRequest<'a> {
    pub(crate) bundle: &'a TrustedStagingBundle,
    pub(crate) source: ApplyPlanningSource<'a>,
    pub(crate) analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
    pub(crate) text_diff: Option<&'a ThreeWayTextDiffPlan>,
    pub(crate) synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
    pub(crate) package_free_merge_ids: Option<PackageFreeMergeChainIds>,
    pub(crate) merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
    pub(crate) baseline: Option<&'a ResolvedOfficialBaseline>,
    pub(crate) installed_source: &'a InstalledApplyPlanningSource,
    pub(crate) options: TrustedApplyPlanningOptions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PackageFreeMergeChainIds {
    pub(crate) analysis_id: Sha256Digest,
    pub(crate) text_diff_id: Sha256Digest,
    pub(crate) synthesis_id: Sha256Digest,
    pub(crate) merged_bytes_id: Sha256Digest,
}

impl<'a> TrustedApplyPlanningRequest<'a> {
    pub(crate) fn try_new_undo(
        staged: &'a crate::TrustedUndoStagingBundle,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        staged.validate_installed_binding(installed_source)?;
        Ok(Self {
            bundle: staged.bundle(),
            source: ApplyPlanningSource::Undo { staged },
            analysis: None,
            text_diff: None,
            synthesis: None,
            package_free_merge_ids: None,
            merged_bytes: None,
            baseline: None,
            installed_source,
            options,
        })
    }

    pub fn try_new(
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
        text_diff: Option<&'a ThreeWayTextDiffPlan>,
        synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            bundle,
            source: ApplyPlanningSource::ThreeWay { plan, review },
            analysis,
            text_diff,
            synthesis,
            package_free_merge_ids: None,
            merged_bytes,
            baseline: Some(baseline),
            installed_source,
            options,
        })
    }

    /// Plan an apply for a bundle staged from an installation and a package alone.
    pub fn try_new_two_way(
        bundle: &'a TrustedStagingBundle,
        plan: &'a crate::TwoWayUpdatePlan,
        review_id: Sha256Digest,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            bundle,
            source: ApplyPlanningSource::TwoWay { plan, review_id },
            analysis: None,
            text_diff: None,
            synthesis: None,
            package_free_merge_ids: None,
            merged_bytes: None,
            baseline: None,
            installed_source,
            options,
        })
    }

    pub(crate) fn try_new_package_free(
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        merge_ids: Option<PackageFreeMergeChainIds>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            bundle,
            source: ApplyPlanningSource::ThreeWay { plan, review },
            analysis: None,
            text_diff: None,
            synthesis: None,
            package_free_merge_ids: merge_ids,
            merged_bytes,
            baseline: Some(baseline),
            installed_source,
            options,
        })
    }

    pub(crate) fn analysis_id_digest(&self) -> Option<&Sha256Digest> {
        self.package_free_merge_ids
            .as_ref()
            .map(|ids| &ids.analysis_id)
            .or_else(|| self.analysis.map(|a| a.analysis_id().digest()))
    }

    pub(crate) fn text_diff_id_digest(&self) -> Option<&Sha256Digest> {
        self.package_free_merge_ids
            .as_ref()
            .map(|ids| &ids.text_diff_id)
            .or_else(|| self.text_diff.map(|t| t.text_diff_plan_id().digest()))
    }

    pub(crate) fn synthesis_id_digest(&self) -> Option<&Sha256Digest> {
        self.package_free_merge_ids
            .as_ref()
            .map(|ids| &ids.synthesis_id)
            .or_else(|| self.synthesis.map(|s| s.synthesis_plan_id().digest()))
    }

    pub(crate) fn merged_bytes_id_digest(&self) -> Option<&Sha256Digest> {
        self.package_free_merge_ids
            .as_ref()
            .map(|ids| &ids.merged_bytes_id)
            .or_else(|| self.merged_bytes.map(|m| m.merged_bytes_plan_id().digest()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustedApplyOperationKind {
    CreateDirectory,
    InstallFile,
    ReplaceFile,
    DeleteFile,
    RemoveDirectory,
}

impl std::fmt::Debug for TrustedApplyOperationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CreateDirectory => "CreateDirectory",
            Self::InstallFile => "InstallFile",
            Self::ReplaceFile => "ReplaceFile",
            Self::DeleteFile => "DeleteFile",
            Self::RemoveDirectory => "RemoveDirectory",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustedApplyOperationPhase {
    RemoveBlockingFile,
    DeleteBlockingDescendant,
    RemoveBlockingDirectory,
    CreateDirectory,
    WriteFile,
    DeleteObsoleteFile,
    RemoveObsoleteDirectory,
}

impl std::fmt::Debug for TrustedApplyOperationPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RemoveBlockingFile => "RemoveBlockingFile",
            Self::DeleteBlockingDescendant => "DeleteBlockingDescendant",
            Self::RemoveBlockingDirectory => "RemoveBlockingDirectory",
            Self::CreateDirectory => "CreateDirectory",
            Self::WriteFile => "WriteFile",
            Self::DeleteObsoleteFile => "DeleteObsoleteFile",
            Self::RemoveObsoleteDirectory => "RemoveObsoleteDirectory",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ApplyBackupRequirement {
    None,
    PreserveInstalledFile,
    PreserveRemovedDirectoryMetadata,
}

impl std::fmt::Debug for ApplyBackupRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::PreserveInstalledFile => "PreserveInstalledFile",
            Self::PreserveRemovedDirectoryMetadata => "PreserveRemovedDirectoryMetadata",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustedApplyStatus {
    ReadyForTransactionalApply,
    NoFilesystemChanges,
}

impl std::fmt::Debug for TrustedApplyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadyForTransactionalApply => "ReadyForTransactionalApply",
            Self::NoFilesystemChanges => "NoFilesystemChanges",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedApplyOperationId(Sha256Digest);

impl TrustedApplyOperationId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl std::fmt::Debug for TrustedApplyOperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedApplyOperationId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedApplyBackupSetId(Sha256Digest);

impl TrustedApplyBackupSetId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl std::fmt::Debug for TrustedApplyBackupSetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedApplyBackupSetId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedApplyPlanId(Sha256Digest);

impl TrustedApplyPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    /// Lowercase hexadecimal encoding of the plan ID digest.
    pub fn to_hex(&self) -> String {
        self.0.to_string()
    }
}

impl std::fmt::Debug for TrustedApplyPlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedApplyPlanId")
    }
}

pub struct TrustedApplyOperation {
    destination: ResourceRelativePath,
    kind: TrustedApplyOperationKind,
    phase: TrustedApplyOperationPhase,
    pre_state: ApplyFileState,
    post_state: ApplyFileState,
    staged_binding_tag: u8,
    backup_requirement: ApplyBackupRequirement,
    operation_id: TrustedApplyOperationId,
}

impl TrustedApplyOperation {
    pub fn kind(&self) -> TrustedApplyOperationKind {
        self.kind
    }
    pub fn phase(&self) -> TrustedApplyOperationPhase {
        self.phase
    }
    pub fn backup_requirement(&self) -> ApplyBackupRequirement {
        self.backup_requirement
    }
    pub fn operation_id(&self) -> &TrustedApplyOperationId {
        &self.operation_id
    }

    pub(crate) fn destination(&self) -> &ResourceRelativePath {
        &self.destination
    }

    pub(crate) fn pre_state(&self) -> &ApplyFileState {
        &self.pre_state
    }

    pub(crate) fn post_state(&self) -> &ApplyFileState {
        &self.post_state
    }

    pub(crate) fn staged_binding_tag(&self) -> u8 {
        self.staged_binding_tag
    }

    #[cfg(test)]
    pub(crate) fn destination_for_test(&self) -> &ResourceRelativePath {
        &self.destination
    }
}

impl std::fmt::Debug for TrustedApplyOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedApplyOperation")
            .field("kind", &self.kind)
            .field("phase", &self.phase)
            .field("backup", &self.backup_requirement)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedApplySummary {
    pub(crate) operation_count: usize,
    pub(crate) create_directory_count: usize,
    pub(crate) install_file_count: usize,
    pub(crate) replace_file_count: usize,
    pub(crate) delete_file_count: usize,
    pub(crate) remove_directory_count: usize,
    pub(crate) total_expected_write_bytes: u64,
    pub(crate) total_backup_bytes: u64,
}

impl TrustedApplySummary {
    pub fn operation_count(&self) -> usize {
        self.operation_count
    }
    pub fn total_expected_write_bytes(&self) -> u64 {
        self.total_expected_write_bytes
    }
    pub fn total_backup_bytes(&self) -> u64 {
        self.total_backup_bytes
    }
}

impl std::fmt::Debug for TrustedApplySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedApplySummary")
            .field("operation_count", &self.operation_count)
            .finish_non_exhaustive()
    }
}

pub struct TrustedApplyPlan {
    operations: Vec<TrustedApplyOperation>,
    summary: TrustedApplySummary,
    status: TrustedApplyStatus,
    plan_id: TrustedApplyPlanId,
    backup_set_id: TrustedApplyBackupSetId,
    bundle_id: TrustedStagingBundleId,
    manifest_id: TrustedStagingManifestId,
}

impl TrustedApplyPlan {
    pub fn operations(&self) -> &[TrustedApplyOperation] {
        &self.operations
    }
    pub fn summary(&self) -> &TrustedApplySummary {
        &self.summary
    }
    pub fn status(&self) -> TrustedApplyStatus {
        self.status
    }
    pub fn plan_id(&self) -> &TrustedApplyPlanId {
        &self.plan_id
    }
    pub fn backup_set_id(&self) -> &TrustedApplyBackupSetId {
        &self.backup_set_id
    }
    pub fn bundle_id(&self) -> &TrustedStagingBundleId {
        &self.bundle_id
    }
    pub fn manifest_id(&self) -> &TrustedStagingManifestId {
        &self.manifest_id
    }
}

impl std::fmt::Debug for TrustedApplyPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedApplyPlan")
            .field("status", &self.status)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

/// Plan trusted apply operations without mutating installed or staging trees.
pub fn plan_trusted_apply(request: TrustedApplyPlanningRequest<'_>) -> Result<TrustedApplyPlan> {
    #[allow(unused_mut)] // mutation exists only in the cfg(test) live-semantics proof
    let mut plan = plan_trusted_apply_v1(request)?;
    #[cfg(test)]
    if LIVE_PLANNER_ALTERNATE_SEMANTICS.with(std::cell::Cell::get) {
        plan.operations.reverse();
    }
    Ok(plan)
}

#[cfg(test)]
thread_local! {
    static LIVE_PLANNER_ALTERNATE_SEMANTICS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) struct AlternateLiveApplyPlannerGuard {
    previous: bool,
}

#[cfg(test)]
impl Drop for AlternateLiveApplyPlannerGuard {
    fn drop(&mut self) {
        LIVE_PLANNER_ALTERNATE_SEMANTICS.with(|value| value.set(self.previous));
    }
}

#[cfg(test)]
pub(crate) fn use_alternate_live_apply_planner_for_test() -> AlternateLiveApplyPlannerGuard {
    let previous = LIVE_PLANNER_ALTERNATE_SEMANTICS.with(|value| {
        let previous = value.get();
        value.set(true);
        previous
    });
    AlternateLiveApplyPlannerGuard { previous }
}

/// Frozen Task 21-v1 derivation used by durable recovery authority.
///
/// Future live planning semantics must add a new implementation and change only
/// `plan_trusted_apply`; recovery derivation v1 continues to call this function.
pub(crate) fn plan_trusted_apply_v1(
    request: TrustedApplyPlanningRequest<'_>,
) -> Result<TrustedApplyPlan> {
    // 1. Pre-I/O binding
    bind_before_io(&request)?;

    let bundle = request.bundle;
    let manifest = bundle.manifest();

    // 2. Read-only staging verification first (quarantine/untrusted reject before installed reads)
    note_staging_read();
    bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedApplyPlanningStagingRevalidationFailed)?;
    verify_published_bundle_readonly(
        bundle.published_dir_for_apply_planning(),
        bundle.resource_dir_for_apply_planning(),
        manifest,
    )
    .map_err(map_staging_verify)?;
    if let ApplyPlanningSource::Undo { staged } = request.source {
        staged.verify_directories()?;
    }
    #[cfg(test)]
    run_apply_hook(ApplyHookPoint::AfterFirstStagingVerify);

    // 3. Installed tree snapshot A (files + directories + identities)
    let snapshot_a = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())?;
    let file_fp_a = snapshot_a.file_only_plan_fingerprint(request.source.resource_key())?;
    if &file_fp_a != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    #[cfg(test)]
    run_apply_hook(ApplyHookPoint::AfterSnapshotA);

    if snapshot_a.directories.len() > request.options.max_directories {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_directories",
        });
    }
    let plan = derive_trusted_apply_v1_from_snapshot(&request, &snapshot_a)?;

    // 4. Installed tree snapshot B (independent re-enumeration)
    #[cfg(test)]
    run_apply_hook(ApplyHookPoint::BeforeSnapshotB);
    let snapshot_b = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())?;
    if snapshot_b.fingerprint != snapshot_a.fingerprint {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    let file_fp_b = snapshot_b.file_only_plan_fingerprint(request.source.resource_key())?;
    if file_fp_b != file_fp_a || &file_fp_b != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    #[cfg(test)]
    run_apply_hook(ApplyHookPoint::AfterSnapshotB);

    // 5. Staging verify again
    note_staging_read();
    bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedApplyPlanningStagingRevalidationFailed)?;
    verify_published_bundle_readonly(
        bundle.published_dir_for_apply_planning(),
        bundle.resource_dir_for_apply_planning(),
        manifest,
    )
    .map_err(map_staging_verify)?;
    if let ApplyPlanningSource::Undo { staged } = request.source {
        staged.verify_directories()?;
    }

    Ok(plan)
}

/// Frozen Task 21-v1 derivation from a canonical durable snapshot A.
///
/// This is recovery-only authority: it never substitutes the current installed
/// tree for the persisted pre-mutation tree and it still performs both staging
/// validations and the complete Task 14–21 binding checks.
pub(crate) fn plan_trusted_apply_v1_from_snapshot(
    request: TrustedApplyPlanningRequest<'_>,
    snapshot_a: &InstalledApplyTreeSnapshot,
) -> Result<TrustedApplyPlan> {
    bind_before_io(&request)?;
    let bundle = request.bundle;
    let manifest = bundle.manifest();
    note_staging_read();
    bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedApplyPlanningStagingRevalidationFailed)?;
    verify_published_bundle_readonly(
        bundle.published_dir_for_apply_planning(),
        bundle.resource_dir_for_apply_planning(),
        manifest,
    )
    .map_err(map_staging_verify)?;
    if let ApplyPlanningSource::Undo { staged } = request.source {
        staged.verify_directories()?;
    }

    let file_fp = snapshot_a.file_only_plan_fingerprint(request.source.resource_key())?;
    if &file_fp != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    let plan = derive_trusted_apply_v1_from_snapshot(&request, snapshot_a)?;

    note_staging_read();
    bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedApplyPlanningStagingRevalidationFailed)?;
    verify_published_bundle_readonly(
        bundle.published_dir_for_apply_planning(),
        bundle.resource_dir_for_apply_planning(),
        manifest,
    )
    .map_err(map_staging_verify)?;
    if let ApplyPlanningSource::Undo { staged } = request.source {
        staged.verify_directories()?;
    }
    Ok(plan)
}

fn derive_trusted_apply_v1_from_snapshot(
    request: &TrustedApplyPlanningRequest<'_>,
    snapshot_a: &InstalledApplyTreeSnapshot,
) -> Result<TrustedApplyPlan> {
    if snapshot_a.directories.len() > request.options.max_directories {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_directories",
        });
    }
    let bundle = request.bundle;
    let manifest = bundle.manifest();
    let installed_tree = snapshot_a.as_tree_model();
    let mut desired = build_desired_tree(manifest)?;
    if let ApplyPlanningSource::Undo { staged } = request.source {
        staged.validate_installed_binding(request.installed_source)?;
        if &snapshot_a.fingerprint != staged.current_tree_fingerprint() {
            return Err(GkrmError::TrustedApplyPlanningInstalledStale);
        }
        staged.verify_directories()?;
        if !desired.directories.is_subset(staged.directories()) {
            return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
        }
        desired.directories = staged.directories().clone();
    }
    if desired.directories.len() > request.options.max_directories {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_directories",
        });
    }

    let planned = build_operations(
        &installed_tree,
        &desired,
        manifest,
        bundle.bundle_id(),
        manifest.manifest_id(),
        request.options.max_operations,
    )?;
    #[cfg(test)]
    run_apply_hook(ApplyHookPoint::AfterOperations);

    if planned.total_write_bytes > request.options.max_total_expected_write_bytes {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_total_expected_write_bytes",
        });
    }
    if planned.total_backup_bytes > request.options.max_total_backup_bytes {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_total_backup_bytes",
        });
    }

    let equal = trees_equal(&installed_tree, &desired);
    let status = if planned.operations.is_empty() {
        if !equal {
            return Err(GkrmError::TrustedApplyPlanningIncompleteCoverage);
        }
        TrustedApplyStatus::NoFilesystemChanges
    } else {
        TrustedApplyStatus::ReadyForTransactionalApply
    };

    let summary = summarize(
        &planned.operations,
        planned.total_write_bytes,
        planned.total_backup_bytes,
    )?;
    let backup_set_id = encode_backup_set_id(&planned.operations)?;
    let options_tag = request.options.options_tag()?;

    let plan_id = encode_plan_id(PlanIdInputs {
        plan_id: request.source.plan_id_digest(),
        review_id: request.source.review_id_digest(),
        analysis_id: request.analysis_id_digest(),
        text_diff_id: request.text_diff_id_digest(),
        synthesis_id: request.synthesis_id_digest(),
        merged_bytes_id: request.merged_bytes_id_digest(),
        bundle_id: bundle.bundle_id().digest(),
        manifest_id: manifest.manifest_id().digest(),
        resource_key: request.source.resource_key().as_str(),
        baseline_id: request.source.baseline_id_str(),
        installed_fp: request.source.installed_fingerprint(),
        incoming_package_fp: request.source.incoming_package_fingerprint(),
        incoming_resource_fp: request.source.incoming_resource_fingerprint(),
        options_tag: &options_tag,
        installed_tree_snapshot_fingerprint: &snapshot_a.fingerprint,
        operations: &planned.operations,
        backup_set: &backup_set_id,
        summary: &summary,
        status,
    })?;

    let _ = TrustedStagingStatus::ReadyForApplyPlanning;
    let _ = ApplyPlanningIoOperation::HashFile;

    Ok(TrustedApplyPlan {
        operations: planned.operations,
        summary,
        status,
        plan_id,
        backup_set_id,
        bundle_id: TrustedStagingBundleId::from_digest(*bundle.bundle_id().digest()),
        manifest_id: TrustedStagingManifestId::from_digest(*manifest.manifest_id().digest()),
    })
}

fn summarize(
    ops: &[TrustedApplyOperation],
    write_bytes: u64,
    backup_bytes: u64,
) -> Result<TrustedApplySummary> {
    let mut create_directory_count = 0usize;
    let mut install_file_count = 0usize;
    let mut replace_file_count = 0usize;
    let mut delete_file_count = 0usize;
    let mut remove_directory_count = 0usize;
    for op in ops {
        match op.kind {
            TrustedApplyOperationKind::CreateDirectory => {
                create_directory_count = create_directory_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::InstallFile => {
                install_file_count = install_file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::ReplaceFile => {
                replace_file_count = replace_file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::DeleteFile => {
                delete_file_count = delete_file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::RemoveDirectory => {
                remove_directory_count = remove_directory_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedApplyPlanningArithmeticOverflow)?;
            }
        }
    }
    Ok(TrustedApplySummary {
        operation_count: ops.len(),
        create_directory_count,
        install_file_count,
        replace_file_count,
        delete_file_count,
        remove_directory_count,
        total_expected_write_bytes: write_bytes,
        total_backup_bytes: backup_bytes,
    })
}

fn map_staging_verify(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedStagingUnsafeFilesystemObject
        | GkrmError::TrustedStagingManifestTreeMismatch
        | GkrmError::TrustedStagingDigestLengthMismatch
        | GkrmError::TrustedStagingRootReplaced
        | GkrmError::TrustedApplyPlanningStagingRevalidationFailed => {
            GkrmError::TrustedApplyPlanningStagingRevalidationFailed
        }
        GkrmError::TrustedStagingIo { operation: _, kind } => GkrmError::TrustedApplyPlanningIo {
            operation: ApplyPlanningIoOperation::ReadManifest,
            kind,
        },
        other => {
            let _ = other;
            GkrmError::TrustedApplyPlanningStagingRevalidationFailed
        }
    }
}

fn note_staging_read() {
    #[cfg(test)]
    note_staging_read_count();
}
