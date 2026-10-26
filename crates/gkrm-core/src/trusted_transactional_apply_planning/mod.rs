//! Trusted read-only transactional apply execution planner (Milestone 2 Task 22).

#![allow(clippy::too_many_arguments)]

pub(crate) mod backup;
mod binding;
pub(crate) mod id;
pub(crate) mod journal;
mod revalidation;
pub(crate) mod rollback;
pub(crate) mod steps;

#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;

use crate::baseline::BaselineStoreLimits;
use crate::trusted_apply_planning::PackageFreeMergeChainIds;
use crate::trusted_staging::{
    TrustedStagingBundle, TrustedStagingBundleId, TrustedStagingManifestId,
};
use crate::{
    ApplyBackupRequirement, GkrmError, InstalledApplyPlanningSource, InstalledScanLimits,
    ResolvedOfficialBaseline, ResourceRelativePath, Result, Sha256Digest,
    ThreeWayMergeAnalysisPlan, ThreeWayMergeSynthesisPlan, ThreeWayMergedBytesPlan,
    ThreeWayPlanReview, ThreeWayTextDiffPlan, ThreeWayUpdatePlan,
    TransactionalApplyPlanningIoOperation, TrustedApplyOperationId, TrustedApplyOperationKind,
    TrustedApplyPlan,
};

use backup::build_backup_plan;
use binding::bind_before_io;
use id::{encode_execution_plan_id, PlanIdInputs};
use journal::{build_journal_plan, build_recovery_table};
use revalidation::{
    capture_and_check_preconditions, capture_snapshot_b, staging_verify,
    validate_persisted_snapshot_preconditions,
};
use rollback::build_rollback_steps;
use steps::build_forward_steps;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static STAGING_READ_COUNT: Cell<usize> = const { Cell::new(0) };
    static CONTENT_READ_COUNT: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn note_staging_read_count() {
    STAGING_READ_COUNT.with(|c| c.set(c.get() + 1));
    CONTENT_READ_COUNT.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
pub(crate) fn content_read_count() -> usize {
    CONTENT_READ_COUNT.with(|c| c.get())
}

#[cfg(test)]
pub(crate) fn reset_content_read_count() {
    CONTENT_READ_COUNT.with(|c| c.set(0));
    STAGING_READ_COUNT.with(|c| c.set(0));
}

#[derive(Clone, Copy)]
pub struct TrustedTransactionalApplyPlanningOptions {
    pub max_operations: usize,
    pub max_backup_entries: usize,
    pub max_backup_bytes: u64,
    pub max_journal_records: usize,
    pub max_transaction_steps: usize,
    pub max_path_depth: usize,
    pub max_path_component_bytes: usize,
    pub installed_scan_limits: InstalledScanLimits,
    pub baseline_store_limits: BaselineStoreLimits,
}

impl Default for TrustedTransactionalApplyPlanningOptions {
    fn default() -> Self {
        Self {
            max_operations: 40_000,
            max_backup_entries: 40_000,
            max_backup_bytes: 2 * 1024 * 1024 * 1024,
            max_journal_records: 1_000,
            max_transaction_steps: 80_000,
            max_path_depth: 64,
            max_path_component_bytes: 255,
            installed_scan_limits: InstalledScanLimits::default(),
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl TrustedTransactionalApplyPlanningOptions {
    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            ("max_operations", self.max_operations),
            ("max_backup_entries", self.max_backup_entries),
            ("max_journal_records", self.max_journal_records),
            ("max_transaction_steps", self.max_transaction_steps),
            ("max_path_depth", self.max_path_depth),
            ("max_path_component_bytes", self.max_path_component_bytes),
        ] {
            if value == 0 {
                return Err(GkrmError::TrustedTransactionalApplyPlanningOptionsInvalid {
                    limit: name,
                });
            }
        }
        if self.max_backup_bytes == 0 {
            return Err(GkrmError::TrustedTransactionalApplyPlanningOptionsInvalid {
                limit: "max_backup_bytes",
            });
        }
        self.installed_scan_limits.validate().map_err(|_| {
            GkrmError::TrustedTransactionalApplyPlanningOptionsInvalid {
                limit: "installed_scan_limits",
            }
        })?;
        self.baseline_store_limits.validate().map_err(|_| {
            GkrmError::TrustedTransactionalApplyPlanningOptionsInvalid {
                limit: "baseline_store_limits",
            }
        })?;
        Ok(())
    }

    pub(crate) fn options_tag(self) -> Result<Vec<u8>> {
        use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
        let mut enc =
            CanonicalFingerprintEncoder::new("gkrm-trusted-transactional-apply-options-v1")
                .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_operations)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_backup_entries)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        enc.u64(self.max_backup_bytes);
        enc.usize(self.max_journal_records)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_transaction_steps)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_path_depth)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        enc.usize(self.max_path_component_bytes)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
        Ok(enc.finish().as_bytes().to_vec())
    }
}

pub struct TrustedTransactionalApplyPlanningRequest<'a> {
    pub(crate) apply_plan: &'a TrustedApplyPlan,
    pub(crate) bundle: &'a TrustedStagingBundle,
    pub(crate) source: crate::trusted_apply_planning::ApplyPlanningSource<'a>,
    pub(crate) analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
    pub(crate) text_diff: Option<&'a ThreeWayTextDiffPlan>,
    pub(crate) synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
    pub(crate) package_free_merge_ids: Option<PackageFreeMergeChainIds>,
    pub(crate) merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
    pub(crate) baseline: Option<&'a ResolvedOfficialBaseline>,
    pub(crate) installed_source: &'a InstalledApplyPlanningSource,
    pub(crate) options: TrustedTransactionalApplyPlanningOptions,
}

impl<'a> TrustedTransactionalApplyPlanningRequest<'a> {
    pub(crate) fn try_new_undo(
        apply_plan: &'a TrustedApplyPlan,
        staged: &'a crate::TrustedUndoStagingBundle,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedTransactionalApplyPlanningOptions,
    ) -> Result<Self> {
        staged.validate_installed_binding(installed_source)?;
        Self::try_new_from_source(
            apply_plan,
            staged.bundle(),
            crate::trusted_apply_planning::ApplyPlanningSource::Undo { staged },
            None,
            None,
            None,
            installed_source,
            options,
        )
    }

    pub fn try_new(
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
        text_diff: Option<&'a ThreeWayTextDiffPlan>,
        synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedTransactionalApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            apply_plan,
            bundle,
            source: crate::trusted_apply_planning::ApplyPlanningSource::ThreeWay { plan, review },
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

    /// Plan the transaction for an update planned from an installation and a package alone.
    pub fn try_new_two_way(
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a crate::TwoWayUpdatePlan,
        review_id: crate::Sha256Digest,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedTransactionalApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            apply_plan,
            bundle,
            source: crate::trusted_apply_planning::ApplyPlanningSource::TwoWay { plan, review_id },
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

    /// Recompute a transaction plan for whichever source produced the original request.
    pub(crate) fn try_new_from_source(
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        source: crate::trusted_apply_planning::ApplyPlanningSource<'a>,
        merge_ids: Option<PackageFreeMergeChainIds>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: Option<&'a ResolvedOfficialBaseline>,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedTransactionalApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            apply_plan,
            bundle,
            source,
            analysis: None,
            text_diff: None,
            synthesis: None,
            package_free_merge_ids: merge_ids,
            merged_bytes,
            baseline,
            installed_source,
            options,
        })
    }

    pub(crate) fn try_new_package_free(
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        merge_ids: Option<PackageFreeMergeChainIds>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        options: TrustedTransactionalApplyPlanningOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            apply_plan,
            bundle,
            source: crate::trusted_apply_planning::ApplyPlanningSource::ThreeWay { plan, review },
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustedTransactionalApplyStatus {
    ReadyForTransactionalExecution,
    NoFilesystemChanges,
}

impl std::fmt::Debug for TrustedTransactionalApplyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadyForTransactionalExecution => "ReadyForTransactionalExecution",
            Self::NoFilesystemChanges => "NoFilesystemChanges",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransactionStepPhase {
    Preflight,
    PersistPreparedJournal,
    CreateBackupBundle,
    PersistBackupCompleteJournal,
    PersistApplyingJournal,
    ApplyBlockingDeletes,
    ApplyBlockingDirectoryRemovals,
    CreateDirectories,
    InstallOrReplaceFiles,
    DeleteObsoleteFiles,
    RemoveObsoleteDirectories,
    PersistAppliedJournal,
    VerifyInstalledTree,
    PersistVerifiedJournal,
    PersistCommittedJournal,
    Finalize,
    Rollback,
}

impl std::fmt::Debug for TransactionStepPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Preflight => "Preflight",
            Self::PersistPreparedJournal => "PersistPreparedJournal",
            Self::CreateBackupBundle => "CreateBackupBundle",
            Self::PersistBackupCompleteJournal => "PersistBackupCompleteJournal",
            Self::PersistApplyingJournal => "PersistApplyingJournal",
            Self::ApplyBlockingDeletes => "ApplyBlockingDeletes",
            Self::ApplyBlockingDirectoryRemovals => "ApplyBlockingDirectoryRemovals",
            Self::CreateDirectories => "CreateDirectories",
            Self::InstallOrReplaceFiles => "InstallOrReplaceFiles",
            Self::DeleteObsoleteFiles => "DeleteObsoleteFiles",
            Self::RemoveObsoleteDirectories => "RemoveObsoleteDirectories",
            Self::PersistAppliedJournal => "PersistAppliedJournal",
            Self::VerifyInstalledTree => "VerifyInstalledTree",
            Self::PersistVerifiedJournal => "PersistVerifiedJournal",
            Self::PersistCommittedJournal => "PersistCommittedJournal",
            Self::Finalize => "Finalize",
            Self::Rollback => "Rollback",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum JournalState {
    Prepared,
    BackupComplete,
    Applying,
    Applied,
    Verified,
    Committed,
    RollingBack,
    RolledBack,
    RecoveryRequired,
}

impl std::fmt::Debug for JournalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Prepared => "Prepared",
            Self::BackupComplete => "BackupComplete",
            Self::Applying => "Applying",
            Self::Applied => "Applied",
            Self::Verified => "Verified",
            Self::Committed => "Committed",
            Self::RollingBack => "RollingBack",
            Self::RolledBack => "RolledBack",
            Self::RecoveryRequired => "RecoveryRequired",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RollbackAction {
    RemoveInstalledFile,
    RestoreInstalledFile,
    /// Recreate a removed directory, then restore approved metadata.
    ///
    /// Task 23 must: ensure parents exist (shallow→deep), create the directory,
    /// restore approved metadata, and only then restore descendant files.
    /// The resource root is never recreated or removed.
    RecreateDirectoryWithMetadata,
    RemoveCreatedDirectory,
    VerifyRollbackState,
}

impl std::fmt::Debug for RollbackAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::RemoveInstalledFile => "RemoveInstalledFile",
            Self::RestoreInstalledFile => "RestoreInstalledFile",
            Self::RecreateDirectoryWithMetadata => "RecreateDirectoryWithMetadata",
            Self::RemoveCreatedDirectory => "RemoveCreatedDirectory",
            Self::VerifyRollbackState => "VerifyRollbackState",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransactionCrashBoundary {
    BeforePrepared,
    PreparedIncompleteBackup,
    BackupCompleteBeforeMutation,
    Applying,
    Applied,
    Verified,
    RollingBack,
    RolledBack,
    Committed,
    InconsistentEvidence,
}

impl std::fmt::Debug for TransactionCrashBoundary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BeforePrepared => "BeforePrepared",
            Self::PreparedIncompleteBackup => "PreparedIncompleteBackup",
            Self::BackupCompleteBeforeMutation => "BackupCompleteBeforeMutation",
            Self::Applying => "Applying",
            Self::Applied => "Applied",
            Self::Verified => "Verified",
            Self::RollingBack => "RollingBack",
            Self::RolledBack => "RolledBack",
            Self::Committed => "Committed",
            Self::InconsistentEvidence => "InconsistentEvidence",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Restart,
    DiscardIncompleteBackupAndRestart,
    ContinueOrSafelyAbort,
    RollBackFromCompletedStep,
    VerifyThenCommitOrRollBack,
    ReverifyThenCommitOrRollBack,
    ResumeRollback,
    FinalizeRollbackCleanup,
    ForwardCompleteNeverRollBack,
    ManualRecoveryRequired,
}

impl std::fmt::Debug for RecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Restart => "Restart",
            Self::DiscardIncompleteBackupAndRestart => "DiscardIncompleteBackupAndRestart",
            Self::ContinueOrSafelyAbort => "ContinueOrSafelyAbort",
            Self::RollBackFromCompletedStep => "RollBackFromCompletedStep",
            Self::VerifyThenCommitOrRollBack => "VerifyThenCommitOrRollBack",
            Self::ReverifyThenCommitOrRollBack => "ReverifyThenCommitOrRollBack",
            Self::ResumeRollback => "ResumeRollback",
            Self::FinalizeRollbackCleanup => "FinalizeRollbackCleanup",
            Self::ForwardCompleteNeverRollBack => "ForwardCompleteNeverRollBack",
            Self::ManualRecoveryRequired => "ManualRecoveryRequired",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransactionJournalRecordKind {
    StateTransition,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedBackupEntryId(Sha256Digest);
impl TrustedBackupEntryId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}
impl std::fmt::Debug for TrustedBackupEntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedBackupEntryId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedBackupPlanId(Sha256Digest);
impl TrustedBackupPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}
impl std::fmt::Debug for TrustedBackupPlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedBackupPlanId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedTransactionStepId(Sha256Digest);
impl TrustedTransactionStepId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}
impl std::fmt::Debug for TrustedTransactionStepId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedTransactionStepId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedRollbackStepId(Sha256Digest);
impl TrustedRollbackStepId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}
impl std::fmt::Debug for TrustedRollbackStepId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedRollbackStepId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedJournalRecordId(Sha256Digest);
impl TrustedJournalRecordId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}
impl std::fmt::Debug for TrustedJournalRecordId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedJournalRecordId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedRecoveryTableId(Sha256Digest);
impl TrustedRecoveryTableId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}
impl std::fmt::Debug for TrustedRecoveryTableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedRecoveryTableId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedTransactionalApplyPlanId(Sha256Digest);
impl TrustedTransactionalApplyPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        self.0.to_string()
    }
}
impl std::fmt::Debug for TrustedTransactionalApplyPlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedTransactionalApplyPlanId")
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct TrustedBackupEntry {
    pub(crate) entry_id: TrustedBackupEntryId,
    pub(crate) operation_id: TrustedApplyOperationId,
    pub(crate) operation_kind: TrustedApplyOperationKind,
    pub(crate) kind: ApplyBackupRequirement,
    pub(crate) destination: ResourceRelativePath,
    pub(crate) state_tag: u8,
    pub(crate) digest: Option<Sha256Digest>,
    pub(crate) byte_length: Option<u64>,
    pub(crate) restore_order: u32,
}

pub struct TrustedBackupPlan {
    plan_id: TrustedBackupPlanId,
    pub(crate) entries: Vec<TrustedBackupEntry>,
    total_backup_bytes: u64,
    #[allow(dead_code)]
    task21_backup_set_commitment: Sha256Digest,
}

impl TrustedBackupPlan {
    pub fn plan_id(&self) -> &TrustedBackupPlanId {
        &self.plan_id
    }
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
    pub fn total_backup_bytes(&self) -> u64 {
        self.total_backup_bytes
    }
    pub fn entry_ids(&self) -> impl Iterator<Item = &TrustedBackupEntryId> {
        self.entries.iter().map(|e| &e.entry_id)
    }
    pub(crate) fn entries(&self) -> &[TrustedBackupEntry] {
        &self.entries
    }
}

impl std::fmt::Debug for TrustedBackupPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedBackupPlan")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct TrustedTransactionStep {
    pub(crate) step_id: TrustedTransactionStepId,
    pub(crate) phase: TransactionStepPhase,
    pub(crate) operation_id: Option<TrustedApplyOperationId>,
    #[allow(dead_code)]
    pub(crate) pre_tag: u8,
    #[allow(dead_code)]
    pub(crate) post_tag: u8,
    #[allow(dead_code)]
    pub(crate) staged_binding_tag: Option<u8>,
    #[allow(dead_code)]
    pub(crate) backup_entry_id: Option<TrustedBackupEntryId>,
    #[allow(dead_code)]
    pub(crate) journal_to: Option<JournalState>,
}

pub struct TrustedRollbackStep {
    step_id: TrustedRollbackStepId,
    action: RollbackAction,
    operation_id: Option<TrustedApplyOperationId>,
    forward_step_id: TrustedTransactionStepId,
    #[allow(dead_code)]
    backup_entry_id: Option<TrustedBackupEntryId>,
}

impl TrustedRollbackStep {
    pub fn step_id(&self) -> &TrustedRollbackStepId {
        &self.step_id
    }
    pub fn action(&self) -> RollbackAction {
        self.action
    }
    pub fn operation_id(&self) -> Option<&TrustedApplyOperationId> {
        self.operation_id.as_ref()
    }
    pub fn forward_step_id(&self) -> &TrustedTransactionStepId {
        &self.forward_step_id
    }
    pub(crate) fn backup_entry_id(&self) -> Option<&TrustedBackupEntryId> {
        self.backup_entry_id.as_ref()
    }
}

impl std::fmt::Debug for TrustedRollbackStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedRollbackStep")
            .field("action", &self.action)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
pub(crate) struct TransactionJournalRecord {
    pub(crate) record_id: TrustedJournalRecordId,
    pub(crate) kind: TransactionJournalRecordKind,
    pub(crate) from: Option<JournalState>,
    pub(crate) to: JournalState,
    pub(crate) sequence: u32,
}

pub struct TrustedJournalPlan {
    pub(crate) records: Vec<TransactionJournalRecord>,
}

impl TrustedJournalPlan {
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
    pub fn record_ids(&self) -> impl Iterator<Item = &TrustedJournalRecordId> {
        self.records.iter().map(|r| &r.record_id)
    }
}

impl std::fmt::Debug for TrustedJournalPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedJournalPlan")
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

pub struct TrustedRecoveryTable {
    table_id: TrustedRecoveryTableId,
    rows: Vec<(TransactionCrashBoundary, RecoveryAction)>,
}

impl TrustedRecoveryTable {
    pub fn table_id(&self) -> &TrustedRecoveryTableId {
        &self.table_id
    }
    pub fn rows(&self) -> &[(TransactionCrashBoundary, RecoveryAction)] {
        &self.rows
    }
}

impl std::fmt::Debug for TrustedRecoveryTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedRecoveryTable")
            .field("row_count", &self.rows.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedTransactionalApplySummary {
    pub(crate) forward_step_count: usize,
    pub(crate) rollback_step_count: usize,
    pub(crate) backup_entry_count: usize,
    pub(crate) journal_record_count: usize,
    pub(crate) total_expected_write_bytes: u64,
    pub(crate) total_backup_bytes: u64,
}

impl TrustedTransactionalApplySummary {
    pub fn forward_step_count(&self) -> usize {
        self.forward_step_count
    }
    pub fn rollback_step_count(&self) -> usize {
        self.rollback_step_count
    }
    pub fn backup_entry_count(&self) -> usize {
        self.backup_entry_count
    }
    pub fn journal_record_count(&self) -> usize {
        self.journal_record_count
    }
    pub fn total_expected_write_bytes(&self) -> u64 {
        self.total_expected_write_bytes
    }
    pub fn total_backup_bytes(&self) -> u64 {
        self.total_backup_bytes
    }
}

impl std::fmt::Debug for TrustedTransactionalApplySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedTransactionalApplySummary")
            .field("forward_step_count", &self.forward_step_count)
            .field("rollback_step_count", &self.rollback_step_count)
            .finish_non_exhaustive()
    }
}

pub struct TrustedTransactionalApplyPlan {
    backup: TrustedBackupPlan,
    forward_steps: Vec<TrustedTransactionStep>,
    rollback_steps: Vec<TrustedRollbackStep>,
    journal: TrustedJournalPlan,
    recovery: TrustedRecoveryTable,
    summary: TrustedTransactionalApplySummary,
    status: TrustedTransactionalApplyStatus,
    plan_id: TrustedTransactionalApplyPlanId,
    apply_plan_id: crate::TrustedApplyPlanId,
    bundle_id: TrustedStagingBundleId,
    manifest_id: TrustedStagingManifestId,
}

impl TrustedTransactionalApplyPlan {
    pub fn backup(&self) -> &TrustedBackupPlan {
        &self.backup
    }
    pub fn forward_step_count(&self) -> usize {
        self.forward_steps.len()
    }
    pub fn forward_step_ids(&self) -> impl Iterator<Item = &TrustedTransactionStepId> {
        self.forward_steps.iter().map(|s| &s.step_id)
    }
    pub fn forward_phases(&self) -> impl Iterator<Item = TransactionStepPhase> + '_ {
        self.forward_steps.iter().map(|s| s.phase)
    }
    pub(crate) fn forward_steps(&self) -> &[TrustedTransactionStep] {
        &self.forward_steps
    }
    pub fn rollback_steps(&self) -> &[TrustedRollbackStep] {
        &self.rollback_steps
    }
    pub fn journal(&self) -> &TrustedJournalPlan {
        &self.journal
    }
    pub fn recovery(&self) -> &TrustedRecoveryTable {
        &self.recovery
    }
    pub fn summary(&self) -> &TrustedTransactionalApplySummary {
        &self.summary
    }
    pub fn status(&self) -> TrustedTransactionalApplyStatus {
        self.status
    }
    pub fn plan_id(&self) -> &TrustedTransactionalApplyPlanId {
        &self.plan_id
    }
    pub fn apply_plan_id(&self) -> &crate::TrustedApplyPlanId {
        &self.apply_plan_id
    }
    pub fn bundle_id(&self) -> &TrustedStagingBundleId {
        &self.bundle_id
    }
    pub fn manifest_id(&self) -> &TrustedStagingManifestId {
        &self.manifest_id
    }
}

impl std::fmt::Debug for TrustedTransactionalApplyPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedTransactionalApplyPlan")
            .field("status", &self.status)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

/// Plan transactional apply execution without mutating installed or staging trees.
pub fn plan_trusted_transactional_apply(
    request: TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<TrustedTransactionalApplyPlan> {
    plan_trusted_transactional_apply_v1(request)
}

/// Frozen Task 22-v1 derivation used by durable recovery authority.
///
/// Future live planning semantics must add a new implementation and change only
/// `plan_trusted_transactional_apply`; recovery derivation v1 remains immutable.
pub(crate) fn plan_trusted_transactional_apply_v1(
    request: TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<TrustedTransactionalApplyPlan> {
    bind_before_io(&request)?;

    staging_verify(&request)?;
    let trees = capture_and_check_preconditions(&request)?;

    let backup = build_backup_plan(
        request.apply_plan.plan_id().digest(),
        request.apply_plan.backup_set_id().digest(),
        request.apply_plan.operations(),
        request.options.max_backup_entries,
        request.options.max_backup_bytes,
    )?;

    let (forward, status) = build_forward_steps(
        request.apply_plan.status(),
        request.apply_plan.operations(),
        &backup,
        request.options.max_transaction_steps,
    )?;

    let rollback = build_rollback_steps(
        request.apply_plan.operations(),
        &forward.steps,
        &backup,
        request.options.max_transaction_steps,
    )?;

    let journal = build_journal_plan(request.options.max_journal_records)?;
    let recovery = build_recovery_table()?;

    // Prepared must precede backup in the forward plan.
    let mut saw_prepared = false;
    let mut saw_backup = false;
    for step in &forward.steps {
        match step.phase {
            TransactionStepPhase::PersistPreparedJournal => saw_prepared = true,
            TransactionStepPhase::CreateBackupBundle => {
                if !saw_prepared {
                    return Err(GkrmError::TrustedTransactionalApplyPlanningJournalInvalid);
                }
                saw_backup = true;
            }
            TransactionStepPhase::PersistApplyingJournal
                if matches!(
                    status,
                    TrustedTransactionalApplyStatus::ReadyForTransactionalExecution
                ) && !saw_backup
                    && !backup.entries.is_empty() =>
            {
                return Err(GkrmError::TrustedTransactionalApplyPlanningJournalInvalid);
            }
            _ => {}
        }
    }

    capture_snapshot_b(&request, &trees)?;
    staging_verify(&request)?;

    let summary = TrustedTransactionalApplySummary {
        forward_step_count: forward.steps.len(),
        rollback_step_count: rollback.len(),
        backup_entry_count: backup.entries.len(),
        journal_record_count: journal.records.len(),
        total_expected_write_bytes: forward.total_write_bytes,
        total_backup_bytes: backup.total_backup_bytes,
    };

    let options_tag = request.options.options_tag()?;
    let forward_ids: Vec<_> = forward.steps.iter().map(|s| *s.step_id.digest()).collect();
    let rollback_ids: Vec<_> = rollback.iter().map(|s| *s.step_id.digest()).collect();
    let journal_ids: Vec<_> = journal
        .records
        .iter()
        .map(|r| *r.record_id.digest())
        .collect();

    let plan_id = encode_execution_plan_id(PlanIdInputs {
        apply_plan_id: request.apply_plan.plan_id().digest(),
        review_id: request.source.review_id_digest(),
        analysis_id: request.analysis_id_digest(),
        text_diff_id: request.text_diff_id_digest(),
        synthesis_id: request.synthesis_id_digest(),
        merged_bytes_id: request.merged_bytes_id_digest(),
        bundle_id: request.bundle.bundle_id().digest(),
        manifest_id: request.bundle.manifest().manifest_id().digest(),
        resource_key: request.source.resource_key().as_str(),
        baseline_id: request.source.baseline_id_str(),
        installed_fp: request.source.installed_fingerprint(),
        incoming_package_fp: request.source.incoming_package_fingerprint(),
        incoming_resource_fp: request.source.incoming_resource_fingerprint(),
        installed_tree_snapshot_fp: &trees.installed_tree_snapshot_fp,
        options_tag: &options_tag,
        backup_plan_id: backup.plan_id.digest(),
        forward_step_ids: &forward_ids,
        rollback_step_ids: &rollback_ids,
        journal_record_ids: &journal_ids,
        recovery_table_id: recovery.table_id.digest(),
        summary: &summary,
        status,
    })?;

    let _ = TransactionalApplyPlanningIoOperation::HashFile;

    Ok(TrustedTransactionalApplyPlan {
        backup,
        forward_steps: forward.steps,
        rollback_steps: rollback,
        journal,
        recovery,
        summary,
        status,
        plan_id,
        apply_plan_id: *request.apply_plan.plan_id(),
        bundle_id: TrustedStagingBundleId::from_digest(*request.bundle.bundle_id().digest()),
        manifest_id: TrustedStagingManifestId::from_digest(
            *request.bundle.manifest().manifest_id().digest(),
        ),
    })
}

/// Frozen Task 22-v1 derivation from the canonical durable pre-mutation tree.
pub(crate) fn plan_trusted_transactional_apply_v1_from_snapshot(
    request: TrustedTransactionalApplyPlanningRequest<'_>,
    snapshot_a: &crate::trusted_apply_planning::InstalledApplyTreeSnapshot,
) -> Result<TrustedTransactionalApplyPlan> {
    bind_before_io(&request)?;
    staging_verify(&request)?;
    let trees = validate_persisted_snapshot_preconditions(&request, snapshot_a)?;

    let backup = build_backup_plan(
        request.apply_plan.plan_id().digest(),
        request.apply_plan.backup_set_id().digest(),
        request.apply_plan.operations(),
        request.options.max_backup_entries,
        request.options.max_backup_bytes,
    )?;
    let (forward, status) = build_forward_steps(
        request.apply_plan.status(),
        request.apply_plan.operations(),
        &backup,
        request.options.max_transaction_steps,
    )?;
    let rollback = build_rollback_steps(
        request.apply_plan.operations(),
        &forward.steps,
        &backup,
        request.options.max_transaction_steps,
    )?;
    let journal = build_journal_plan(request.options.max_journal_records)?;
    let recovery = build_recovery_table()?;

    let mut saw_prepared = false;
    let mut saw_backup = false;
    for step in &forward.steps {
        match step.phase {
            TransactionStepPhase::PersistPreparedJournal => saw_prepared = true,
            TransactionStepPhase::CreateBackupBundle => {
                if !saw_prepared {
                    return Err(GkrmError::TrustedTransactionalApplyPlanningJournalInvalid);
                }
                saw_backup = true;
            }
            TransactionStepPhase::PersistApplyingJournal
                if matches!(
                    status,
                    TrustedTransactionalApplyStatus::ReadyForTransactionalExecution
                ) && !saw_backup
                    && !backup.entries.is_empty() =>
            {
                return Err(GkrmError::TrustedTransactionalApplyPlanningJournalInvalid);
            }
            _ => {}
        }
    }
    staging_verify(&request)?;

    let summary = TrustedTransactionalApplySummary {
        forward_step_count: forward.steps.len(),
        rollback_step_count: rollback.len(),
        backup_entry_count: backup.entries.len(),
        journal_record_count: journal.records.len(),
        total_expected_write_bytes: forward.total_write_bytes,
        total_backup_bytes: backup.total_backup_bytes(),
    };
    let options_tag = request.options.options_tag()?;
    let forward_ids: Vec<_> = forward.steps.iter().map(|s| *s.step_id.digest()).collect();
    let rollback_ids: Vec<_> = rollback.iter().map(|s| *s.step_id().digest()).collect();
    let journal_ids: Vec<_> = journal
        .records
        .iter()
        .map(|r| *r.record_id.digest())
        .collect();
    let plan_id = encode_execution_plan_id(PlanIdInputs {
        apply_plan_id: request.apply_plan.plan_id().digest(),
        review_id: request.source.review_id_digest(),
        analysis_id: request.analysis_id_digest(),
        text_diff_id: request.text_diff_id_digest(),
        synthesis_id: request.synthesis_id_digest(),
        merged_bytes_id: request.merged_bytes_id_digest(),
        bundle_id: request.bundle.bundle_id().digest(),
        manifest_id: request.bundle.manifest().manifest_id().digest(),
        resource_key: request.source.resource_key().as_str(),
        baseline_id: request.source.baseline_id_str(),
        installed_fp: request.source.installed_fingerprint(),
        incoming_package_fp: request.source.incoming_package_fingerprint(),
        incoming_resource_fp: request.source.incoming_resource_fingerprint(),
        installed_tree_snapshot_fp: &trees.installed_tree_snapshot_fp,
        options_tag: &options_tag,
        backup_plan_id: backup.plan_id.digest(),
        forward_step_ids: &forward_ids,
        rollback_step_ids: &rollback_ids,
        journal_record_ids: &journal_ids,
        recovery_table_id: recovery.table_id.digest(),
        summary: &summary,
        status,
    })?;

    Ok(TrustedTransactionalApplyPlan {
        backup,
        forward_steps: forward.steps,
        rollback_steps: rollback,
        journal,
        recovery,
        summary,
        status,
        plan_id,
        apply_plan_id: *request.apply_plan.plan_id(),
        bundle_id: TrustedStagingBundleId::from_digest(*request.bundle.bundle_id().digest()),
        manifest_id: TrustedStagingManifestId::from_digest(
            *request.bundle.manifest().manifest_id().digest(),
        ),
    })
}
