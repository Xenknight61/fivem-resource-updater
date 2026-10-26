//! Trusted transactional apply execution (Milestone 2 Task 23).

#![allow(clippy::too_many_arguments)]

pub(crate) mod backup;
#[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
pub(crate) mod hooks;
pub(crate) mod id;
pub(crate) mod journal;
pub(crate) mod locks;
mod paths;
mod publish;
pub mod recovery;
mod root;

#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::path::Path;

use cap_std::fs::Dir as CapDir;

use crate::baseline::ensure_baseline_store_disjoint_from_installed;
use crate::baseline::fs_security::{create_new_child_dir, dir_identity, try_open_child_dir};
use crate::baseline::store::{allocate_temp_name, rename_noreplace_relative, sync_dir};
use crate::file_identity::StableFileIdentity;
use crate::trusted_apply_planning::{
    encode_installed_apply_tree_snapshot, parents_of, ApplyFileState, InstalledApplyTreeSnapshot,
};
use crate::trusted_recovery_authority::{
    build_recovery_authority_body, dispatch_recovery_derivation, encode_publication_binding_id,
    parse_recovery_authority_envelope_reader, verify_selected_resource_commitment,
    write_recovery_authority_envelope as write_authority_envelope_stream,
    RecoveryAuthorityEnvelopeV1, RecoveryAuthorityLimits, RecoveryAuthorityPublication,
    MAX_ENVELOPE_BYTES,
};
use crate::trusted_staging::verify_published_bundle_readonly;
use crate::{
    GkrmError, InstalledApplyPlanningSource, ResolvedOfficialBaseline, Result, RollbackAction,
    Sha256Digest, ThreeWayMergeAnalysisPlan, ThreeWayMergeSynthesisPlan, ThreeWayMergedBytesPlan,
    ThreeWayPlanReview, ThreeWayTextDiffPlan, ThreeWayUpdatePlan, TransactionalApplyIoOperation,
    TrustedApplyOperation, TrustedApplyOperationKind, TrustedApplyPlan, TrustedApplyStatus,
    TrustedStagingBundle, TrustedTransactionalApplyPlan, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest, TrustedTransactionalApplyStatus,
};

use crate::trusted_apply_planning::PackageFreeMergeChainIds;
use crate::trusted_transactional_apply_planning::plan_trusted_transactional_apply;
use backup::create_and_seal_backup;
use journal::{
    append_record, append_terminal_record, ensure_journal_dir, load_and_validate_journal_chain,
    map_baseline_to_io, map_io, predict_record_id, AppendArgs, JournalCursor,
};
use paths::{
    create_directory, delete_file, install_or_replace_file, probe_destination,
    probe_file_pre_state, read_staging_file, remove_directory, verify_absent_file,
    verify_directory_present, verify_path_absent, verify_present_file, RollbackFileMatchProbe,
    RollbackProbe,
};
pub use recovery::{
    recover_trusted_transaction, scan_trusted_transactions, RecoveredCommittedTransaction,
    RecoveredRolledBackTransaction, RecoveryStillRequired, SafeRestartTransaction,
    TrustedRecoveryCandidate, TrustedRecoveryCandidateId, TrustedRecoveryCandidateKind,
    TrustedRecoveryOptions, TrustedRecoveryResult, TrustedRecoveryResultId,
    TrustedRecoveryScanOptions, TrustedRecoveryScanResult, TrustedRecoveryScanResultId,
    TrustedTransactionRecoveryRequest,
};
pub use root::TrustedTransactionRoot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionJournalEvent {
    Prepared,
    BackupEntryCompleted,
    BackupComplete,
    Applying,
    ForwardStepCompleted,
    Applied,
    Verified,
    Committed,
    RollingBack,
    RollbackStepCompleted,
    RolledBack,
    RecoveryRequired,
    /// Durable safe-abort before any installed mutation (Task 24).
    AbortedBeforeMutation,
}

#[derive(Clone, Copy)]
pub struct TrustedTransactionalApplyExecutionOptions {
    pub max_operations: usize,
    pub max_backup_entries: usize,
    pub max_backup_bytes: u64,
    pub max_write_bytes: u64,
    pub max_journal_bytes: u64,
    pub max_journal_records: usize,
    pub max_transaction_files: usize,
    pub max_path_depth: usize,
    pub max_path_component_bytes: usize,
}

impl Default for TrustedTransactionalApplyExecutionOptions {
    fn default() -> Self {
        Self {
            max_operations: 40_000,
            max_backup_entries: 40_000,
            max_backup_bytes: 2 * 1024 * 1024 * 1024,
            max_write_bytes: 2 * 1024 * 1024 * 1024,
            max_journal_bytes: 64 * 1024 * 1024,
            max_journal_records: 200_000,
            max_transaction_files: 200_000,
            max_path_depth: 64,
            max_path_component_bytes: 255,
        }
    }
}

impl TrustedTransactionalApplyExecutionOptions {
    pub fn validate(self) -> Result<()> {
        for (name, value) in [
            ("max_operations", self.max_operations),
            ("max_backup_entries", self.max_backup_entries),
            ("max_journal_records", self.max_journal_records),
            ("max_transaction_files", self.max_transaction_files),
            ("max_path_depth", self.max_path_depth),
            ("max_path_component_bytes", self.max_path_component_bytes),
        ] {
            if value == 0 {
                return Err(
                    GkrmError::TrustedTransactionalApplyExecutionOptionsInvalid { limit: name },
                );
            }
        }
        for (name, value) in [
            ("max_backup_bytes", self.max_backup_bytes),
            ("max_write_bytes", self.max_write_bytes),
            ("max_journal_bytes", self.max_journal_bytes),
        ] {
            if value == 0 {
                return Err(
                    GkrmError::TrustedTransactionalApplyExecutionOptionsInvalid { limit: name },
                );
            }
        }
        Ok(())
    }
}

pub struct TrustedTransactionalApplyExecutionRequest<'a> {
    pub(crate) tx_plan: &'a TrustedTransactionalApplyPlan,
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
    pub(crate) transaction_root: &'a TrustedTransactionRoot,
    pub(crate) package_path: Option<&'a Path>,
    pub(crate) options: TrustedTransactionalApplyExecutionOptions,
    pub(crate) recovery_authority: Option<&'a RecoveryAuthorityPublication>,
    pub(crate) artifact_revalidator: Option<&'a dyn Fn() -> Result<RecoveryAuthorityPublication>>,
}

impl<'a> TrustedTransactionalApplyExecutionRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_new_undo_with_recovery_authority(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        staged: &'a crate::TrustedUndoStagingBundle,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        recovery_authority: &'a RecoveryAuthorityPublication,
        artifact_revalidator: &'a dyn Fn() -> Result<RecoveryAuthorityPublication>,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        options.validate()?;
        staged.validate_installed_binding(installed_source)?;
        Ok(Self {
            tx_plan,
            apply_plan,
            bundle: staged.bundle(),
            source: crate::trusted_apply_planning::ApplyPlanningSource::Undo { staged },
            analysis: None,
            text_diff: None,
            synthesis: None,
            package_free_merge_ids: None,
            merged_bytes: None,
            baseline: None,
            installed_source,
            transaction_root,
            package_path: None,
            options,
            recovery_authority: Some(recovery_authority),
            artifact_revalidator: Some(artifact_revalidator),
        })
    }

    pub fn try_new(
        tx_plan: &'a TrustedTransactionalApplyPlan,
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
        transaction_root: &'a TrustedTransactionRoot,
        package_path: &'a Path,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            tx_plan,
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
            transaction_root,
            package_path: Some(package_path),
            options,
            recovery_authority: None,
            artifact_revalidator: None,
        })
    }

    pub(crate) fn try_new_package_free(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        merge_ids: Option<PackageFreeMergeChainIds>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            tx_plan,
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
            transaction_root,
            package_path: None,
            options,
            recovery_authority: None,
            artifact_revalidator: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    /// Execute the transaction for an update planned from an installation and a package alone.
    pub fn try_new_two_way(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a crate::TwoWayUpdatePlan,
        review_id: crate::Sha256Digest,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        Self::try_new_two_way_inner(
            tx_plan,
            apply_plan,
            bundle,
            plan,
            review_id,
            installed_source,
            transaction_root,
            None,
            options,
        )
    }

    /// A two-way apply that publishes recovery authority alongside its transaction.
    ///
    /// Without it the transaction is durable but unaccountable: the workspace can see that
    /// something finished and never learn what, so it blocks every later update on the same
    /// resource and no one can close it.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new_two_way_with_recovery_authority(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a crate::TwoWayUpdatePlan,
        review_id: crate::Sha256Digest,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        recovery_authority: &'a RecoveryAuthorityPublication,
        artifact_revalidator: &'a dyn Fn() -> Result<RecoveryAuthorityPublication>,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        let mut request = Self::try_new_two_way_inner(
            tx_plan,
            apply_plan,
            bundle,
            plan,
            review_id,
            installed_source,
            transaction_root,
            Some(recovery_authority),
            options,
        )?;
        request.artifact_revalidator = Some(artifact_revalidator);
        Ok(request)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_new_two_way_inner(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a crate::TwoWayUpdatePlan,
        review_id: crate::Sha256Digest,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        recovery_authority: Option<&'a RecoveryAuthorityPublication>,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            tx_plan,
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
            transaction_root,
            package_path: None,
            options,
            recovery_authority,
            artifact_revalidator: None,
        })
    }

    pub(crate) fn try_new_package_free_with_recovery_authority(
        tx_plan: &'a TrustedTransactionalApplyPlan,
        apply_plan: &'a TrustedApplyPlan,
        bundle: &'a TrustedStagingBundle,
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        merge_ids: Option<PackageFreeMergeChainIds>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledApplyPlanningSource,
        transaction_root: &'a TrustedTransactionRoot,
        recovery_authority: &'a RecoveryAuthorityPublication,
        artifact_revalidator: &'a dyn Fn() -> Result<RecoveryAuthorityPublication>,
        options: TrustedTransactionalApplyExecutionOptions,
    ) -> Result<Self> {
        let mut request = Self::try_new_package_free(
            tx_plan,
            apply_plan,
            bundle,
            plan,
            review,
            merge_ids,
            merged_bytes,
            baseline,
            installed_source,
            transaction_root,
            options,
        )?;
        request.recovery_authority = Some(recovery_authority);
        request.artifact_revalidator = Some(artifact_revalidator);
        Ok(request)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedTransactionResultId(Sha256Digest);
impl TrustedTransactionResultId {
    #[allow(dead_code)]
    pub(crate) fn digest(&self) -> &Sha256Digest {
        &self.0
    }
    #[allow(dead_code, clippy::wrong_self_convention)]
    pub(crate) fn to_hex(&self) -> String {
        self.0.to_string()
    }
}
impl std::fmt::Debug for TrustedTransactionResultId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedTransactionResultId")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedTransactionSummary {
    pub(crate) forward_completed: usize,
    pub(crate) rollback_completed: usize,
    pub(crate) journal_records: usize,
    pub(crate) backup_entries: usize,
}

impl TrustedTransactionSummary {
    pub fn forward_completed(&self) -> usize {
        self.forward_completed
    }
    pub fn rollback_completed(&self) -> usize {
        self.rollback_completed
    }
    pub fn journal_records(&self) -> usize {
        self.journal_records
    }
    pub fn backup_entries(&self) -> usize {
        self.backup_entries
    }
}
impl std::fmt::Debug for TrustedTransactionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedTransactionSummary")
            .field("forward_completed", &self.forward_completed)
            .field("rollback_completed", &self.rollback_completed)
            .finish_non_exhaustive()
    }
}

pub struct CommittedTransaction {
    result_id: TrustedTransactionResultId,
    summary: TrustedTransactionSummary,
}
impl CommittedTransaction {
    pub fn result_id(&self) -> &TrustedTransactionResultId {
        &self.result_id
    }
    pub fn summary(&self) -> &TrustedTransactionSummary {
        &self.summary
    }
}
impl std::fmt::Debug for CommittedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommittedTransaction")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

pub struct RolledBackTransaction {
    result_id: TrustedTransactionResultId,
    summary: TrustedTransactionSummary,
}
impl RolledBackTransaction {
    pub fn result_id(&self) -> &TrustedTransactionResultId {
        &self.result_id
    }
    pub fn summary(&self) -> &TrustedTransactionSummary {
        &self.summary
    }
}
impl std::fmt::Debug for RolledBackTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RolledBackTransaction")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

pub struct RecoveryRequiredTransaction {
    result_id: TrustedTransactionResultId,
    summary: TrustedTransactionSummary,
}
impl RecoveryRequiredTransaction {
    pub fn result_id(&self) -> &TrustedTransactionResultId {
        &self.result_id
    }
    pub fn summary(&self) -> &TrustedTransactionSummary {
        &self.summary
    }
}
impl std::fmt::Debug for RecoveryRequiredTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryRequiredTransaction")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

pub enum TrustedTransactionResult {
    Committed(CommittedTransaction),
    RolledBack(RolledBackTransaction),
    RecoveryRequired(RecoveryRequiredTransaction),
}
impl std::fmt::Debug for TrustedTransactionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Committed(v) => f.debug_tuple("Committed").field(v).finish(),
            Self::RolledBack(v) => f.debug_tuple("RolledBack").field(v).finish(),
            Self::RecoveryRequired(v) => f.debug_tuple("RecoveryRequired").field(v).finish(),
        }
    }
}

/// Execute a trusted transactional apply. Terminal outcomes are returned as `Ok`.
pub fn execute_trusted_transactional_apply(
    request: TrustedTransactionalApplyExecutionRequest<'_>,
) -> Result<TrustedTransactionResult> {
    request.options.validate()?;
    // Resource lock must precede existence check, publication, and all mutation.
    let resource_lock = locks::acquire_resource_lock(
        request.transaction_root.dir(),
        request.source.resource_key().as_str(),
    )?;
    #[cfg(test)]
    hooks::record_authority_verification_event(
        hooks::AuthorityVerificationEvent::ResourceLockAcquired,
    );
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::AfterResourceLock);
    if request.recovery_authority.is_some()
        && recovery::same_resource_recovery_blocks_new_work(
            request.transaction_root,
            request.source.resource_key(),
            request.options.max_journal_records,
        )?
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRecoveryRequired);
    }
    let prepared = pre_mutation_bind(&request)?;
    run_published_transaction(request, prepared, resource_lock)
}

struct PreparedState {
    snapshot_a_fp: Sha256Digest,
    plan_id: Sha256Digest,
    plan_id_hex: String,
    is_noop: bool,
}

fn pre_mutation_bind(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
) -> Result<PreparedState> {
    request.options.validate()?;
    if let Some(revalidate) = request.artifact_revalidator {
        let fresh = revalidate()
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
        let expected = request
            .recovery_authority
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
        if fresh.body() != expected.body()
            || fresh.authority_id() != expected.authority_id()
            || fresh.artifact_id() != expected.artifact_id()
        {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
        }
    }

    // Recompute Task 22 plan and require identical plan ID.
    let planning_request = if request.package_path.is_none() {
        TrustedTransactionalApplyPlanningRequest::try_new_from_source(
            request.apply_plan,
            request.bundle,
            request.source,
            request.package_free_merge_ids,
            request.merged_bytes,
            request.baseline,
            request.installed_source,
            TrustedTransactionalApplyPlanningOptions::default(),
        )
    } else {
        {
            // The packaged path always originates from a three-way plan; a two-way apply never
            // carries a package path, so this branch cannot be reached without one.
            let Some((plan, review)) = request.source.three_way() else {
                return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
            };
            let Some(baseline) = request.baseline else {
                return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
            };
            TrustedTransactionalApplyPlanningRequest::try_new(
                request.apply_plan,
                request.bundle,
                plan,
                review,
                request.analysis,
                request.text_diff,
                request.synthesis,
                request.merged_bytes,
                baseline,
                request.installed_source,
                TrustedTransactionalApplyPlanningOptions::default(),
            )
        }
    }
    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
    let recomputed = plan_trusted_transactional_apply(planning_request)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionPlanIntegrityMismatch)?;
    if recomputed.plan_id().digest() != request.tx_plan.plan_id().digest()
        || recomputed.status() != request.tx_plan.status()
        || recomputed.summary().forward_step_count()
            != request.tx_plan.summary().forward_step_count()
        || recomputed.backup().entry_count() != request.tx_plan.backup().entry_count()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionPlanIntegrityMismatch);
    }
    if request.tx_plan.apply_plan_id().digest() != request.apply_plan.plan_id().digest()
        || request.tx_plan.bundle_id().digest() != request.bundle.bundle_id().digest()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }

    let is_noop = matches!(
        request.tx_plan.status(),
        TrustedTransactionalApplyStatus::NoFilesystemChanges
    );
    match request.apply_plan.status() {
        TrustedApplyStatus::NoFilesystemChanges if !is_noop => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionStatusInvalid);
        }
        TrustedApplyStatus::ReadyForTransactionalApply if is_noop => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionStatusInvalid);
        }
        _ => {}
    }

    if request.apply_plan.operations().len() > request.options.max_operations
        || request.tx_plan.backup().entry_count() > request.options.max_backup_entries
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_operations",
        });
    }
    if request.tx_plan.backup().total_backup_bytes() > request.options.max_backup_bytes {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_backup_bytes",
        });
    }
    if request.tx_plan.summary().total_expected_write_bytes() > request.options.max_write_bytes {
        return Err(GkrmError::TrustedTransactionalApplyExecutionLimitExceeded {
            limit: "max_write_bytes",
        });
    }

    request
        .bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed)?;
    verify_published_bundle_readonly(
        request.bundle.published_dir_for_apply_planning(),
        request.bundle.resource_dir_for_apply_planning(),
        request.bundle.manifest(),
    )
    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed)?;

    let snapshot = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    let file_fp = snapshot
        .file_only_plan_fingerprint(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    if &file_fp != request.source.installed_fingerprint() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionInstalledStale);
    }
    for op in request.apply_plan.operations() {
        verify_op_precondition(op, &snapshot)?;
    }

    if let Some(publication) = request.recovery_authority {
        let body = publication.body();
        verify_selected_resource_commitment(
            request.source.resource_key(),
            &body.selected_resource_commitment,
        )
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
        let (recomputed_body, recomputed_id) = build_recovery_authority_body(
            request.installed_source,
            request.source.resource_key(),
            body.baseline_id,
            *request.bundle.manifest().manifest_id().digest(),
            *request.bundle.bundle_id().digest(),
            *request.apply_plan.plan_id().digest(),
            *request.tx_plan.plan_id().digest(),
            &snapshot,
            RecoveryAuthorityLimits::default(),
        )
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
        if &recomputed_body != body || &recomputed_id != publication.authority_id() {
            return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
        }
    }

    ensure_disjoint(request)?;
    request.transaction_root.revalidate_identity()?;

    let plan_id = *request.tx_plan.plan_id().digest();
    let plan_id_hex = plan_id.to_string();
    ensure_txn_absent(request.transaction_root, &plan_id_hex)?;

    Ok(PreparedState {
        snapshot_a_fp: snapshot.fingerprint,
        plan_id,
        plan_id_hex,
        is_noop,
    })
}

fn verify_op_precondition(
    op: &TrustedApplyOperation,
    snapshot: &crate::trusted_apply_planning::InstalledApplyTreeSnapshot,
) -> Result<()> {
    match op.kind() {
        TrustedApplyOperationKind::DeleteFile | TrustedApplyOperationKind::ReplaceFile => {
            match op.pre_state() {
                ApplyFileState::Present {
                    digest,
                    byte_length,
                } => match snapshot.files.get(op.destination()) {
                    Some(ApplyFileState::Present {
                        digest: got_d,
                        byte_length: got_l,
                    }) if got_d == digest && got_l == byte_length => Ok(()),
                    _ => Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch),
                },
                ApplyFileState::Absent => {
                    Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch)
                }
            }
        }
        TrustedApplyOperationKind::InstallFile => match op.pre_state() {
            ApplyFileState::Absent => {
                if snapshot.files.contains_key(op.destination()) {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch);
                }
                Ok(())
            }
            ApplyFileState::Present { .. } => {
                Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch)
            }
        },
        TrustedApplyOperationKind::CreateDirectory => Ok(()),
        TrustedApplyOperationKind::RemoveDirectory => {
            if snapshot.directories.contains(op.destination()) {
                Ok(())
            } else {
                Err(GkrmError::TrustedTransactionalApplyExecutionPreconditionMismatch)
            }
        }
    }
}

fn ensure_disjoint(request: &TrustedTransactionalApplyExecutionRequest<'_>) -> Result<()> {
    let txn = request.transaction_root.path_for_disjointness();
    let installed = request.installed_source.installed_root_path();
    let staging = request
        .bundle
        .staging_root_for_apply_planning()
        .path_for_disjointness();
    // A two-way apply has no baseline store, so there is nothing extra to keep disjoint from.
    let store = request
        .baseline
        .map(|baseline| baseline.stored_baseline().store_root());
    for other in [Some(installed), Some(staging), store]
        .into_iter()
        .flatten()
    {
        ensure_baseline_store_disjoint_from_installed(txn, other)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootOverlap)?;
    }
    if let Some(package) = request.package_path {
        if paths_equal_loose(txn, package)
            || path_is_within(package, txn)?
            || path_is_within(txn, package)?
        {
            return Err(GkrmError::TrustedTransactionalApplyExecutionRootOverlap);
        }
    }
    Ok(())
}

fn paths_equal_loose(left: &Path, right: &Path) -> bool {
    left == right
}

/// Fail closed: canonicalize failure is treated as overlap (not disjoint).
fn path_is_within(inner: &Path, outer: &Path) -> Result<bool> {
    let inner = inner
        .canonicalize()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootOverlap)?;
    let outer = outer
        .canonicalize()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRootOverlap)?;
    Ok(inner.starts_with(outer))
}

/// Whether one transaction is already on record in this root.
///
/// Asked before anything is written, so a caller that is about to open a transaction can find out
/// that it would collide without first publishing the evidence that accounts for it. A refused
/// apply that has already left an authority artifact behind leaves the workspace holding evidence
/// for a transaction that never ran.
pub fn trusted_transaction_is_on_record(
    root: &TrustedTransactionRoot,
    plan_id: &Sha256Digest,
) -> Result<bool> {
    match ensure_txn_absent(root, &plan_id.to_string()) {
        Ok(()) => Ok(false),
        Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists) => Ok(true),
        Err(other) => Err(other),
    }
}

fn ensure_txn_absent(root: &TrustedTransactionRoot, plan_id_hex: &str) -> Result<()> {
    let transactions = match try_open_child_dir(root.dir(), "transactions")
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenTransactionRoot, e))?
    {
        Some(dir) => dir,
        None => return Ok(()),
    };
    if try_open_child_dir(&transactions, plan_id_hex)
        .map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::OpenPublishedTransaction, e)
        })?
        .is_some()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists);
    }
    Ok(())
}

fn ensure_internal_layout(root: &TrustedTransactionRoot) -> Result<(CapDir, CapDir)> {
    root.revalidate_identity()?;
    let tmp = match try_open_child_dir(root.dir(), ".tmp").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
    })? {
        Some(d) => d,
        None => create_new_child_dir(root.dir(), ".tmp").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
        })?,
    };
    let transactions = match try_open_child_dir(root.dir(), "transactions").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
    })? {
        Some(d) => d,
        None => create_new_child_dir(root.dir(), "transactions").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
        })?,
    };
    Ok((tmp, transactions))
}

struct PublishedTxn {
    dir: CapDir,
    journal_dir: CapDir,
    dir_identity: StableFileIdentity,
    journal_dir_identity: StableFileIdentity,
}

/// The only transaction namespace authority permitted after both execution locks are held.
///
/// Construction consumes and drops the pre-lock capabilities, freshly reopens both namespace
/// entries from the trusted transaction root, proves their stable identities, and retains the
/// locks for the lifetime of every subsequent validation, mutation, and failure path.
struct LockedPublishedTxn {
    dir: CapDir,
    journal_dir: CapDir,
    _locks: locks::HeldTransactionLocks,
}

fn run_published_transaction(
    request: TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: PreparedState,
    resource_lock: cap_std::fs::File,
) -> Result<TrustedTransactionResult> {
    let (tmp_root, transactions_dir) = ensure_internal_layout(request.transaction_root)?;
    // Under the held resource lock, re-check absence immediately before publication.
    ensure_txn_absent(request.transaction_root, &prepared.plan_id_hex)?;
    let temp_name = allocate_temp_name(&tmp_root)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::CreateTempDirectory, e))?;
    let resource_lock_id = locks::encode_resource_lock_id(request.source.resource_key().as_str())?;
    let recovery_envelope = if let Some(publication) = request.recovery_authority {
        let binding = encode_publication_binding_id(
            publication.artifact_id(),
            publication.authority_id(),
            &prepared.plan_id,
            &prepared.snapshot_a_fp,
            &resource_lock_id,
        )?;
        Some(RecoveryAuthorityEnvelopeV1::create(
            publication.body().clone(),
            *publication.authority_id(),
            *publication.artifact_id(),
            binding,
            RecoveryAuthorityLimits::default(),
        )?)
    } else {
        None
    };
    let mut cursor = recovery_envelope
        .as_ref()
        .map_or_else(JournalCursor::new, |envelope| {
            JournalCursor::new_v2(*envelope.publication_binding_id().digest())
        });
    {
        let temp_dir = create_new_child_dir(&tmp_root, &temp_name).map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateTempDirectory, e)
        })?;
        let _ = create_new_child_dir(&temp_dir, "work").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
        })?;
        let journal_dir = ensure_journal_dir(&temp_dir)?;
        if let Some(envelope) = recovery_envelope.as_ref() {
            write_recovery_authority_envelope(&temp_dir, envelope)?;
        }
        write_snapshot_a_binding(&temp_dir, &prepared.snapshot_a_fp)?;
        #[cfg(test)]
        hooks::fire_publication_hook(hooks::PublicationPoint::AfterSnapshotFsync);
        write_resource_lock_id_binding(&temp_dir, &resource_lock_id)?;
        #[cfg(test)]
        hooks::fire_publication_hook(hooks::PublicationPoint::AfterResourceLockFsync);
        append_record(
            &journal_dir,
            &mut cursor,
            AppendArgs {
                plan_id: &prepared.plan_id,
                snapshot_a: &prepared.snapshot_a_fp,
                event: TransactionJournalEvent::Prepared,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: request.options.max_journal_bytes,
                max_journal_records: request.options.max_journal_records,
            },
        )?;
        #[cfg(test)]
        hooks::fire_publication_hook(hooks::PublicationPoint::AfterPreparedAppend);
        drop(journal_dir);
        #[cfg(test)]
        hooks::fire_publication_hook(hooks::PublicationPoint::BeforeTempDirectorySync);
        #[cfg(test)]
        if hooks::force_temp_directory_sync_failure() {
            return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
                operation: TransactionalApplyIoOperation::SyncInstalledDirectory,
                kind: std::io::ErrorKind::Other,
            });
        }
        sync_dir(&temp_dir, "temporary-transaction").map_err(|e| {
            map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
        })?;
        #[cfg(test)]
        hooks::fire_publication_hook(hooks::PublicationPoint::AfterTempDirectorySync);
        drop(temp_dir);
    }

    // Prepare all fallible post-rename capabilities before publication.
    let transactions_cleanup = transactions_dir
        .try_clone()
        .map_err(|e| map_io(TransactionalApplyIoOperation::CloneCleanupCapability, e))?;
    let root_sync = request
        .transaction_root
        .dir()
        .try_clone()
        .map_err(|e| map_io(TransactionalApplyIoOperation::CloneCleanupCapability, e))?;
    let published_name = prepared.plan_id_hex.clone();
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::BeforeRename);
    #[cfg(test)]
    if hooks::force_publish_failure() {
        let _ = tmp_root.remove_dir_all(&temp_name);
        return Err(GkrmError::TrustedTransactionalApplyExecutionIo {
            operation: TransactionalApplyIoOperation::RenamePublish,
            kind: std::io::ErrorKind::Other,
        });
    }
    rename_noreplace_relative(&tmp_root, &temp_name, &transactions_dir, &published_name)
        .map_err(|e| map_io(TransactionalApplyIoOperation::RenamePublish, e))?;
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::AfterRename);
    // Published transaction is now armed. No bare `?` outside recovery handlers.
    // Resource lock remains held; acquire transaction lock next.
    match open_armed_published_transaction(
        &request,
        &prepared,
        &transactions_cleanup,
        &root_sync,
        &published_name,
        &mut cursor,
    ) {
        Ok(txn) => {
            let transaction_lock =
                match locks::acquire_transaction_lock(&txn.dir, &prepared.plan_id) {
                    Ok(lock) => lock,
                    Err(lock_err) => {
                        drop(resource_lock);
                        return published_fail_closed(lock_err);
                    }
                };
            let held_locks = locks::HeldSplitLocks {
                resource: resource_lock,
                transaction: transaction_lock,
            }
            .into_held();
            #[cfg(test)]
            hooks::record_authority_verification_event(
                hooks::AuthorityVerificationEvent::RecoveryLockAcquired,
            );
            #[cfg(test)]
            hooks::fire_publication_hook(hooks::PublicationPoint::AfterRecoveryLock);
            let txn = match revalidate_complete_authority_after_lock(
                &request, &prepared, txn, held_locks,
            ) {
                Ok(fresh_txn) => fresh_txn,
                Err(primary) => return published_fail_closed(primary),
            };
            // After publication: never return raw pre-publication-classifiable errors.
            // Route every fallible post-lock check through published failure/recovery machinery.
            #[cfg(test)]
            if hooks::force_post_lock_root_replaced() {
                return handle_failure(
                    &request,
                    &prepared,
                    &txn,
                    &mut cursor,
                    GkrmError::TrustedTransactionalApplyExecutionRootReplaced,
                );
            }
            #[cfg(test)]
            if hooks::force_post_lock_installed_stale() {
                return handle_failure(
                    &request,
                    &prepared,
                    &txn,
                    &mut cursor,
                    GkrmError::TrustedTransactionalApplyExecutionInstalledStale,
                );
            }
            #[cfg(test)]
            if hooks::force_post_publish_setup_io() {
                return handle_failure(
                    &request,
                    &prepared,
                    &txn,
                    &mut cursor,
                    GkrmError::TrustedTransactionalApplyExecutionIo {
                        operation: TransactionalApplyIoOperation::SyncInstalledDirectory,
                        kind: std::io::ErrorKind::Other,
                    },
                );
            }
            if let Err(primary) = request.transaction_root.revalidate_identity() {
                return handle_failure(&request, &prepared, &txn, &mut cursor, primary);
            }
            if let Err(primary) = request
                .installed_source
                .validate_identities()
                .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)
            {
                return handle_failure(&request, &prepared, &txn, &mut cursor, primary);
            }
            match execute_after_publish(&request, &prepared, &txn, &mut cursor) {
                Ok(result) => Ok(result),
                Err(primary) => handle_failure(&request, &prepared, &txn, &mut cursor, primary),
            }
        }
        Err(setup_err) => {
            drop(resource_lock);
            published_fail_closed(setup_err)
        }
    }
}

fn published_fail_closed(primary: GkrmError) -> Result<TrustedTransactionResult> {
    Err(
        GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery {
            primary: Box::new(primary),
            recovery_journal: Box::new(
                GkrmError::TrustedTransactionalApplyExecutionRecoveryRequired,
            ),
        },
    )
}

fn open_armed_published_transaction(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    transactions_cleanup: &CapDir,
    root_sync: &CapDir,
    published_name: &str,
    cursor: &mut JournalCursor,
) -> Result<PublishedTxn> {
    // Durability of the directory entry itself lives in `transactions/`, not only the
    // transaction root that contains that subdirectory.
    sync_dir(transactions_cleanup, "transactions").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
    })?;
    sync_dir(root_sync, "transaction-root").map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::SyncInstalledDirectory, e)
    })?;
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::AfterParentSync);
    let published = open_child_dir_pub(transactions_cleanup, published_name)?;
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::AfterPublishedReopen);
    let journal_dir = ensure_journal_dir(&published)?;
    let validated = load_and_validate_journal_chain(
        &journal_dir,
        &prepared.plan_id,
        &prepared.snapshot_a_fp,
        request.options.max_journal_records,
    )?;
    if validated.last_event != Some(TransactionJournalEvent::Prepared)
        || validated.record_count != 1
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    if let Some(publication) = request.recovery_authority {
        let resource_lock_id =
            locks::encode_resource_lock_id(request.source.resource_key().as_str())?;
        let binding = encode_publication_binding_id(
            publication.artifact_id(),
            publication.authority_id(),
            &prepared.plan_id,
            &prepared.snapshot_a_fp,
            &resource_lock_id,
        )?;
        let expected = RecoveryAuthorityEnvelopeV1::create(
            publication.body().clone(),
            *publication.authority_id(),
            *publication.artifact_id(),
            binding,
            RecoveryAuthorityLimits::default(),
        )?;
        let reopened = verify_recovery_authority_envelope(&published)?;
        if reopened != expected {
            return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
        }
        if validated.publication_binding_id != Some(*expected.publication_binding_id().digest()) {
            return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
        }
    } else if validated.publication_binding_id.is_some() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    *cursor = validated;
    request.transaction_root.revalidate_identity()?;
    let published_identity = published_namespace_identity(&published)?;
    let journal_dir_identity = published_namespace_identity(&journal_dir)?;
    Ok(PublishedTxn {
        dir: published,
        journal_dir,
        dir_identity: published_identity,
        journal_dir_identity,
    })
}

fn revalidate_complete_authority_after_lock(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    bound_txn: PublishedTxn,
    held_locks: locks::HeldTransactionLocks,
) -> Result<LockedPublishedTxn> {
    // Retained transaction and journal handles are deliberately not authority at this
    // boundary. Reopen the published namespace from the trusted root after both locks,
    // then prove that both directory entries still name the nodes bound before locking.
    let PublishedTxn {
        dir: bound_dir,
        journal_dir: bound_journal_dir,
        dir_identity: bound_dir_identity,
        journal_dir_identity: bound_journal_dir_identity,
    } = bound_txn;
    drop(bound_journal_dir);
    drop(bound_dir);
    request.transaction_root.revalidate_identity()?;
    let transactions = open_child_dir_pub(request.transaction_root.dir(), "transactions")?;
    let fresh_dir = open_child_dir_pub(&transactions, &prepared.plan_id_hex)?;
    let fresh_dir_identity = published_namespace_identity(&fresh_dir)?;
    require_published_namespace_identity(&bound_dir_identity, &fresh_dir_identity)?;
    let fresh_journal_dir = open_child_dir_pub(&fresh_dir, "journal")?;
    let fresh_journal_dir_identity = published_namespace_identity(&fresh_journal_dir)?;
    require_published_namespace_identity(&bound_journal_dir_identity, &fresh_journal_dir_identity)?;
    let fresh_txn = LockedPublishedTxn {
        dir: fresh_dir,
        journal_dir: fresh_journal_dir,
        _locks: held_locks,
    };

    let Some(expected_publication) = request.recovery_authority else {
        return Ok(fresh_txn);
    };
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::DuringFinalRevalidation);

    let envelope = verify_recovery_authority_envelope(&fresh_txn.dir)?;
    let fresh_publication = request
        .artifact_revalidator
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?(
    )
    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
    verify_fresh_selected_resource_commitments(
        request.source.resource_key(),
        &fresh_publication,
        &envelope,
    )?;
    if fresh_publication.artifact_id() != envelope.artifact_id()
        || fresh_publication.authority_id() != envelope.authority_id()
        || fresh_publication.body() != envelope.body()
        || expected_publication.artifact_id() != envelope.artifact_id()
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }

    request
        .installed_source
        .validate_identities()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    let snapshot = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    verify_published_bundle_readonly(
        request.bundle.published_dir_for_apply_planning(),
        request.bundle.resource_dir_for_apply_planning(),
        request.bundle.manifest(),
    )
    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed)?;
    request
        .bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed)?;

    let body = envelope.body();
    let _derivation = dispatch_recovery_derivation(
        body.apply_derivation_version(),
        body.transaction_derivation_version(),
    )?;
    let (recomputed_body, recomputed_authority_id) = build_recovery_authority_body(
        request.installed_source,
        request.source.resource_key(),
        body.baseline_id,
        *request.bundle.manifest().manifest_id().digest(),
        *request.bundle.bundle_id().digest(),
        *request.apply_plan.plan_id().digest(),
        *request.tx_plan.plan_id().digest(),
        &snapshot,
        RecoveryAuthorityLimits::default(),
    )?;
    if &recomputed_body != body || &recomputed_authority_id != envelope.authority_id() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }

    let durable_snapshot = read_snapshot_a_binding(&fresh_txn.dir)?;
    if durable_snapshot != snapshot.fingerprint || durable_snapshot != prepared.snapshot_a_fp {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }
    let expected_resource_lock =
        locks::encode_resource_lock_id(request.source.resource_key().as_str())?;
    let durable_resource_lock = read_resource_lock_id_binding(&fresh_txn.dir)?;
    if durable_resource_lock != expected_resource_lock {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }
    let binding = encode_publication_binding_id(
        envelope.artifact_id(),
        envelope.authority_id(),
        &prepared.plan_id,
        &durable_snapshot,
        &durable_resource_lock,
    )?;
    if &binding != envelope.publication_binding_id() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }
    let journal = load_and_validate_journal_chain(
        &fresh_txn.journal_dir,
        &prepared.plan_id,
        &durable_snapshot,
        request.options.max_journal_records,
    )?;
    if journal.publication_binding_id != Some(*binding.digest())
        || journal.last_event != Some(TransactionJournalEvent::Prepared)
        || journal.record_count != 1
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    request.transaction_root.revalidate_identity()?;
    Ok(fresh_txn)
}

fn verify_fresh_selected_resource_commitments(
    resource_key: &crate::SafeResourceKey,
    fresh_publication: &RecoveryAuthorityPublication,
    envelope: &RecoveryAuthorityEnvelopeV1,
) -> Result<()> {
    #[cfg(not(test))]
    {
        verify_selected_resource_commitment(
            resource_key,
            &fresh_publication.body().selected_resource_commitment,
        )
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)?;
        verify_selected_resource_commitment(
            resource_key,
            &envelope.body().selected_resource_commitment,
        )
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)
    }

    #[cfg(test)]
    {
        let test_resource_key = hooks::resolve_post_lock_resource_key(resource_key);
        hooks::record_authority_verification_event(
            hooks::AuthorityVerificationEvent::FinalSelectedResourceCommitmentVerificationStarted,
        );
        if verify_selected_resource_commitment(
            &test_resource_key,
            &fresh_publication.body().selected_resource_commitment,
        )
        .is_err()
        {
            hooks::record_authority_verification_event(
                hooks::AuthorityVerificationEvent::FinalSelectedResourceCommitmentMismatch,
            );
            return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
        }
        if verify_selected_resource_commitment(
            &test_resource_key,
            &envelope.body().selected_resource_commitment,
        )
        .is_err()
        {
            hooks::record_authority_verification_event(
                hooks::AuthorityVerificationEvent::FinalSelectedResourceCommitmentMismatch,
            );
            return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
        }
        Ok(())
    }
}

fn published_namespace_identity(dir: &CapDir) -> Result<StableFileIdentity> {
    dir_identity(dir, "published-transaction-namespace").map_err(|error| {
        map_baseline_to_io(
            TransactionalApplyIoOperation::OpenPublishedTransaction,
            error,
        )
    })
}

fn require_published_namespace_identity(
    bound: &StableFileIdentity,
    freshly_reopened: &StableFileIdentity,
) -> Result<()> {
    if bound != freshly_reopened {
        return Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch);
    }
    Ok(())
}

fn open_child_dir_pub(parent: &CapDir, name: &str) -> Result<CapDir> {
    crate::baseline::fs_security::open_child_dir(parent, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::OpenPublishedTransaction, e))
}

fn execute_after_publish(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
) -> Result<TrustedTransactionResult> {
    #[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
    hooks::fire_publication_hook(hooks::PublicationPoint::BeforeBackup);
    let backup_seal = create_and_seal_backup(
        &txn.dir,
        &txn.journal_dir,
        cursor,
        request.installed_source,
        &prepared.plan_id,
        &prepared.snapshot_a_fp,
        request.tx_plan.backup().entries(),
        request.options.max_backup_bytes,
        request.options.max_journal_bytes,
        request.options.max_journal_records,
    )?;

    // Pre-apply race check.
    let snap_b = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    if snap_b.fingerprint != prepared.snapshot_a_fp {
        return Err(GkrmError::TrustedTransactionalApplyExecutionInstalledStale);
    }
    request
        .installed_source
        .validate_identities()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    verify_published_bundle_readonly(
        request.bundle.published_dir_for_apply_planning(),
        request.bundle.resource_dir_for_apply_planning(),
        request.bundle.manifest(),
    )
    .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionStagingRevalidationFailed)?;
    request.transaction_root.revalidate_identity()?;

    if prepared.is_noop {
        return commit_noop(request, prepared, txn, cursor, backup_seal);
    }

    append_record(
        &txn.journal_dir,
        cursor,
        AppendArgs {
            plan_id: &prepared.plan_id,
            snapshot_a: &prepared.snapshot_a_fp,
            event: TransactionJournalEvent::Applying,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: request.options.max_journal_bytes,
            max_journal_records: request.options.max_journal_records,
        },
    )?;

    let resource = request
        .installed_source
        .open_resource_dir()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    let staging_resource = request.bundle.resource_dir_for_apply_planning();

    for step in request.tx_plan.forward_steps() {
        let Some(op_id) = step.operation_id.as_ref() else {
            continue;
        };
        let op = request
            .apply_plan
            .operations()
            .iter()
            .find(|o| o.operation_id().digest() == op_id.digest())
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionForwardFailed)?;
        execute_forward_op(op, &resource, staging_resource)?;
        cursor.forward_completed.push(*step.step_id.digest());
        append_record(
            &txn.journal_dir,
            cursor,
            AppendArgs {
                plan_id: &prepared.plan_id,
                snapshot_a: &prepared.snapshot_a_fp,
                event: TransactionJournalEvent::ForwardStepCompleted,
                related_step_id: Some(step.step_id.digest()),
                related_entry_id: None,
                max_journal_bytes: request.options.max_journal_bytes,
                max_journal_records: request.options.max_journal_records,
            },
        )?;
    }

    append_record(
        &txn.journal_dir,
        cursor,
        AppendArgs {
            plan_id: &prepared.plan_id,
            snapshot_a: &prepared.snapshot_a_fp,
            event: TransactionJournalEvent::Applied,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: request.options.max_journal_bytes,
            max_journal_records: request.options.max_journal_records,
        },
    )?;

    finalize_commit(request, prepared, txn, cursor, backup_seal)
}

fn execute_forward_op(
    op: &TrustedApplyOperation,
    resource: &CapDir,
    staging: &CapDir,
) -> Result<()> {
    if op.destination().as_str().is_empty() {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    #[cfg(any(test, all(feature = "desktop-test-support", debug_assertions)))]
    if hooks::forward_op_fault_matches(op.kind()) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
    }
    match op.kind() {
        TrustedApplyOperationKind::DeleteFile => {
            verify_present_file(resource, op.destination(), op.pre_state())?;
            delete_file(resource, op.destination())?;
            verify_absent_file(resource, op.destination())?;
        }
        TrustedApplyOperationKind::RemoveDirectory => {
            verify_directory_present(resource, op.destination())?;
            remove_directory(resource, op.destination())?;
            verify_path_absent(resource, op.destination())?;
        }
        TrustedApplyOperationKind::CreateDirectory => {
            verify_path_absent(resource, op.destination())?;
            create_directory(resource, op.destination())?;
            verify_directory_present(resource, op.destination())?;
        }
        TrustedApplyOperationKind::InstallFile => {
            let (bytes, digest, len) = read_staging_file(staging, op.destination())?;
            let ApplyFileState::Present {
                digest: exp_d,
                byte_length: exp_l,
            } = op.post_state()
            else {
                return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
            };
            if &digest != exp_d || len != *exp_l {
                return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
            }
            install_or_replace_file(resource, op.destination(), &bytes, exp_d, *exp_l, false)?;
            verify_present_file(resource, op.destination(), op.post_state())?;
        }
        TrustedApplyOperationKind::ReplaceFile => {
            verify_present_file(resource, op.destination(), op.pre_state())?;
            let (bytes, digest, len) = read_staging_file(staging, op.destination())?;
            let ApplyFileState::Present {
                digest: exp_d,
                byte_length: exp_l,
            } = op.post_state()
            else {
                return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
            };
            if &digest != exp_d || len != *exp_l {
                return Err(GkrmError::TrustedTransactionalApplyExecutionForwardFailed);
            }
            install_or_replace_file(resource, op.destination(), &bytes, exp_d, *exp_l, true)?;
            verify_present_file(resource, op.destination(), op.post_state())?;
        }
    }
    Ok(())
}

fn commit_noop(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
    backup_seal: Sha256Digest,
) -> Result<TrustedTransactionResult> {
    let snap = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionInstalledStale)?;
    if snap.fingerprint != prepared.snapshot_a_fp {
        return Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed);
    }
    finalize_commit(request, prepared, txn, cursor, backup_seal)
}

fn finalize_commit(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
    backup_seal: Sha256Digest,
) -> Result<TrustedTransactionResult> {
    let installed = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)?;
    verify_installed_matches_staging(request.bundle, &installed)?;
    for op in request.apply_plan.operations() {
        verify_post_state(op, &installed)?;
    }

    let desired = desired_tree_from_staging(request)?;
    let verification_seal = id::encode_verification_seal(
        &prepared.plan_id,
        &prepared.snapshot_a_fp,
        &installed.fingerprint,
        &desired,
    )?;
    cursor.verification_seal = Some(verification_seal);
    let verified_id = append_record(
        &txn.journal_dir,
        cursor,
        AppendArgs {
            plan_id: &prepared.plan_id,
            snapshot_a: &prepared.snapshot_a_fp,
            event: TransactionJournalEvent::Verified,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: request.options.max_journal_bytes,
            max_journal_records: request.options.max_journal_records,
        },
    )?;

    let commit_seal = id::encode_commit_seal(
        &prepared.plan_id,
        &backup_seal,
        &verification_seal,
        &verified_id,
    )?;
    cursor.commit_seal = Some(commit_seal);

    let terminal_args = AppendArgs {
        plan_id: &prepared.plan_id,
        snapshot_a: &prepared.snapshot_a_fp,
        event: TransactionJournalEvent::Committed,
        related_step_id: None,
        related_entry_id: None,
        max_journal_bytes: request.options.max_journal_bytes,
        max_journal_records: request.options.max_journal_records,
    };
    let committed_id = predict_record_id(cursor, &terminal_args)?;
    let result_id = TrustedTransactionResultId(id::encode_result_id(
        &prepared.plan_id,
        TransactionJournalEvent::Committed,
        &committed_id,
        Some(&backup_seal),
        Some(&commit_seal),
        None,
    )?);
    let summary = summary_from_projected(cursor, request, 1);

    let got_id = append_terminal_record(&txn.journal_dir, Some(&txn.dir), cursor, terminal_args)?;
    debug_assert_eq!(got_id, committed_id);
    let _ = got_id;
    Ok(TrustedTransactionResult::Committed(CommittedTransaction {
        result_id,
        summary,
    }))
}

fn verify_post_state(
    op: &TrustedApplyOperation,
    installed: &InstalledApplyTreeSnapshot,
) -> Result<()> {
    match op.kind() {
        TrustedApplyOperationKind::DeleteFile => {
            if installed.files.contains_key(op.destination()) {
                return Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed);
            }
            Ok(())
        }
        TrustedApplyOperationKind::RemoveDirectory => {
            if installed.directories.contains(op.destination()) {
                return Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed);
            }
            Ok(())
        }
        TrustedApplyOperationKind::CreateDirectory => {
            if !installed.directories.contains(op.destination()) {
                return Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed);
            }
            Ok(())
        }
        TrustedApplyOperationKind::InstallFile | TrustedApplyOperationKind::ReplaceFile => {
            match (op.post_state(), installed.files.get(op.destination())) {
                (
                    ApplyFileState::Present {
                        digest,
                        byte_length,
                    },
                    Some(ApplyFileState::Present {
                        digest: got_d,
                        byte_length: got_l,
                    }),
                ) if got_d == digest && got_l == byte_length => Ok(()),
                _ => Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed),
            }
        }
    }
}

fn desired_tree_from_staging(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
) -> Result<Sha256Digest> {
    use crate::trusted_staging::StagingFinalState;
    use std::collections::{BTreeMap, BTreeSet};

    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    for entry in request.bundle.manifest().entries() {
        match entry.final_state() {
            StagingFinalState::Absent => {}
            StagingFinalState::Installed
            | StagingFinalState::Incoming
            | StagingFinalState::Merged => {
                let digest = *entry
                    .expected_digest()
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)?;
                let len = entry
                    .expected_byte_length()
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)?;
                files.insert(
                    entry.path().clone(),
                    ApplyFileState::Present {
                        digest,
                        byte_length: len,
                    },
                );
                for parent in parents_of(entry.path()) {
                    directories.insert(parent);
                }
            }
        }
    }
    encode_installed_apply_tree_snapshot(&files, &directories)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)
}

/// Tri-state probe: does the live installed tree satisfy the staging desired subset?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DesiredStateProbe {
    ProvenMatch,
    ProvenMismatch,
    Ambiguous,
}

/// Probe desired-state using Task 23 subset verification (never full-tree == staging).
pub(crate) fn probe_desired_state(
    bundle: &TrustedStagingBundle,
    installed_source: &InstalledApplyPlanningSource,
    resource_key: &crate::SafeResourceKey,
) -> DesiredStateProbe {
    match installed_source.capture_tree_snapshot(resource_key) {
        Ok(installed) => match verify_installed_matches_staging(bundle, &installed) {
            Ok(()) => DesiredStateProbe::ProvenMatch,
            Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)
            | Err(GkrmError::TrustedTransactionRecoveryRevalidationFailed) => {
                DesiredStateProbe::ProvenMismatch
            }
            Err(_) => DesiredStateProbe::Ambiguous,
        },
        Err(_) => DesiredStateProbe::Ambiguous,
    }
}

/// Subset verifier shared by Task 23 commit and Task 24 recovery.
///
/// Requires every staging-manifest path to match exactly. Additional installed
/// files/directories (customer-preserved) are allowed and do not cause mismatch.
pub(crate) fn verify_installed_matches_staging(
    bundle: &TrustedStagingBundle,
    installed: &InstalledApplyTreeSnapshot,
) -> Result<()> {
    use crate::trusted_staging::StagingFinalState;
    for entry in bundle.manifest().entries() {
        match entry.final_state() {
            StagingFinalState::Absent => {
                if installed.files.contains_key(entry.path()) {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed);
                }
            }
            StagingFinalState::Installed
            | StagingFinalState::Incoming
            | StagingFinalState::Merged => {
                let digest = entry
                    .expected_digest()
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)?;
                let len = entry
                    .expected_byte_length()
                    .ok_or(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)?;
                match installed.files.get(entry.path()) {
                    Some(ApplyFileState::Present {
                        digest: got_d,
                        byte_length: got_l,
                    }) if got_d == digest && *got_l == len => {}
                    _ => {
                        return Err(GkrmError::TrustedTransactionalApplyExecutionVerificationFailed)
                    }
                }
                for parent in parents_of(entry.path()) {
                    if !installed.directories.contains(&parent) {
                        return Err(
                            GkrmError::TrustedTransactionalApplyExecutionVerificationFailed,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn summary_from_projected(
    cursor: &JournalCursor,
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    extra_records: usize,
) -> TrustedTransactionSummary {
    TrustedTransactionSummary {
        forward_completed: cursor.forward_completed.len(),
        rollback_completed: cursor.rollback_completed.len(),
        journal_records: cursor.record_count.saturating_add(extra_records),
        backup_entries: request.tx_plan.backup().entry_count(),
    }
}

fn handle_failure(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
    primary: GkrmError,
) -> Result<TrustedTransactionResult> {
    let memory_forward = cursor.forward_completed.clone();
    let durable = load_and_validate_journal_chain(
        &txn.journal_dir,
        &prepared.plan_id,
        &prepared.snapshot_a_fp,
        request.options.max_journal_records,
    );
    if let Ok(ref validated) = durable {
        cursor.forward_completed = validated.forward_completed.clone();
        cursor.rollback_completed = validated.rollback_completed.clone();
        cursor.backup_seal = validated.backup_seal;
        cursor.verification_seal = validated.verification_seal;
        cursor.commit_seal = validated.commit_seal;
        cursor.rollback_seal = validated.rollback_seal;
        cursor.previous_id = validated.previous_id;
        cursor.sequence = validated.sequence;
        cursor.record_count = validated.record_count;
        cursor.last_event = validated.last_event;
        cursor.total_journal_bytes = validated.total_journal_bytes;
    }
    let mut completed_forward: std::collections::BTreeSet<Sha256Digest> =
        cursor.forward_completed.iter().copied().collect();
    for id in &memory_forward {
        completed_forward.insert(*id);
    }
    let durable_forward = completed_forward.len();
    let last_event = cursor
        .last_event
        .or_else(|| durable.as_ref().ok().and_then(|c| c.last_event));
    let applying_or_later = matches!(
        last_event,
        Some(
            TransactionJournalEvent::Applying
                | TransactionJournalEvent::ForwardStepCompleted
                | TransactionJournalEvent::Applied
                | TransactionJournalEvent::Verified
                | TransactionJournalEvent::RollingBack
                | TransactionJournalEvent::RollbackStepCompleted
        )
    );
    let installed_changed = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map(|snap| snap.fingerprint != prepared.snapshot_a_fp)
        .unwrap_or(true);
    let mutation_began = !memory_forward.is_empty()
        || durable_forward > 0
        || (applying_or_later && installed_changed);

    if !mutation_began {
        return seal_recovery_required(request, prepared, txn, cursor, primary);
    }

    match run_rollback(request, prepared, txn, cursor) {
        Ok(result) => Ok(result),
        Err(rollback_err) => seal_recovery_required_with_rollback(
            request,
            prepared,
            txn,
            cursor,
            primary,
            rollback_err,
        ),
    }
}

fn seal_recovery_required(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
    primary: GkrmError,
) -> Result<TrustedTransactionResult> {
    match prepare_and_append_recovery(request, prepared, &txn.journal_dir, cursor, Some(&txn.dir)) {
        Ok(result) => {
            let _ = primary;
            Ok(result)
        }
        Err(journal_err) => Err(
            GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery {
                primary: Box::new(primary),
                recovery_journal: Box::new(journal_err),
            },
        ),
    }
}

fn seal_recovery_required_with_rollback(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
    primary: GkrmError,
    rollback_err: GkrmError,
) -> Result<TrustedTransactionResult> {
    match prepare_and_append_recovery(request, prepared, &txn.journal_dir, cursor, Some(&txn.dir)) {
        Ok(result) => {
            let _ = (primary, rollback_err);
            Ok(result)
        }
        Err(journal_err) => Err(
            GkrmError::TrustedTransactionalApplyExecutionFailedCompound {
                primary: Box::new(primary),
                rollback: Box::new(rollback_err),
                journal: Box::new(journal_err),
                cleanup: Box::new(GkrmError::TrustedTransactionalApplyExecutionRecoveryRequired),
            },
        ),
    }
}

fn prepare_and_append_recovery(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    journal_dir: &CapDir,
    cursor: &mut JournalCursor,
    txn_dir: Option<&CapDir>,
) -> Result<TrustedTransactionResult> {
    let terminal_args = AppendArgs {
        plan_id: &prepared.plan_id,
        snapshot_a: &prepared.snapshot_a_fp,
        event: TransactionJournalEvent::RecoveryRequired,
        related_step_id: None,
        related_entry_id: None,
        max_journal_bytes: request.options.max_journal_bytes,
        max_journal_records: request.options.max_journal_records,
    };
    let recovery_id = predict_record_id(cursor, &terminal_args)?;
    let result_id = TrustedTransactionResultId(id::encode_result_id(
        &prepared.plan_id,
        TransactionJournalEvent::RecoveryRequired,
        &recovery_id,
        cursor.backup_seal.as_ref(),
        None,
        None,
    )?);
    let summary = summary_from_projected(cursor, request, 1);
    let got_id = append_terminal_record(journal_dir, txn_dir, cursor, terminal_args)?;
    debug_assert_eq!(got_id, recovery_id);
    let _ = got_id;
    Ok(TrustedTransactionResult::RecoveryRequired(
        RecoveryRequiredTransaction { result_id, summary },
    ))
}

fn run_rollback(
    request: &TrustedTransactionalApplyExecutionRequest<'_>,
    prepared: &PreparedState,
    txn: &LockedPublishedTxn,
    cursor: &mut JournalCursor,
) -> Result<TrustedTransactionResult> {
    append_record(
        &txn.journal_dir,
        cursor,
        AppendArgs {
            plan_id: &prepared.plan_id,
            snapshot_a: &prepared.snapshot_a_fp,
            event: TransactionJournalEvent::RollingBack,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: request.options.max_journal_bytes,
            max_journal_records: request.options.max_journal_records,
        },
    )?;

    let resource = request
        .installed_source
        .open_resource_dir()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
    let backup_files = open_child_dir_pub(&open_child_dir_pub(&txn.dir, "backup")?, "files")?;
    let backup_dirs = open_child_dir_pub(&open_child_dir_pub(&txn.dir, "backup")?, "directories")?;

    for step in request.tx_plan.rollback_steps() {
        if matches!(step.action(), RollbackAction::VerifyRollbackState) {
            continue;
        }
        let op_id = step
            .operation_id()
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
        let op = request
            .apply_plan
            .operations()
            .iter()
            .find(|o| o.operation_id().digest() == op_id.digest())
            .ok_or(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
        let needed = decide_rollback_action(step, op, &resource)?;
        match needed {
            RollbackLiveDecision::Skip => continue,
            RollbackLiveDecision::Execute => {}
        }
        execute_rollback_action(
            step.action(),
            op,
            &resource,
            &backup_files,
            &backup_dirs,
            step.backup_entry_id().map(|e| e.digest()),
        )?;
        cursor.rollback_completed.push(*step.step_id().digest());
        append_record(
            &txn.journal_dir,
            cursor,
            AppendArgs {
                plan_id: &prepared.plan_id,
                snapshot_a: &prepared.snapshot_a_fp,
                event: TransactionJournalEvent::RollbackStepCompleted,
                related_step_id: Some(step.step_id().digest()),
                related_entry_id: step.backup_entry_id().map(|e| e.digest()),
                max_journal_bytes: request.options.max_journal_bytes,
                max_journal_records: request.options.max_journal_records,
            },
        )?;
    }

    let restored = request
        .installed_source
        .capture_tree_snapshot(request.source.resource_key())
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
    if restored.fingerprint != prepared.snapshot_a_fp {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed);
    }
    let rollback_seal = id::encode_rollback_seal(
        &prepared.plan_id,
        &prepared.snapshot_a_fp,
        &restored.fingerprint,
    )?;
    cursor.rollback_seal = Some(rollback_seal);
    let terminal_args = AppendArgs {
        plan_id: &prepared.plan_id,
        snapshot_a: &prepared.snapshot_a_fp,
        event: TransactionJournalEvent::RolledBack,
        related_step_id: None,
        related_entry_id: None,
        max_journal_bytes: request.options.max_journal_bytes,
        max_journal_records: request.options.max_journal_records,
    };
    let rolled_id = predict_record_id(cursor, &terminal_args)?;
    let result_id = TrustedTransactionResultId(id::encode_result_id(
        &prepared.plan_id,
        TransactionJournalEvent::RolledBack,
        &rolled_id,
        cursor.backup_seal.as_ref(),
        None,
        Some(&rollback_seal),
    )?);
    let summary = summary_from_projected(cursor, request, 1);
    let got_id = append_terminal_record(&txn.journal_dir, Some(&txn.dir), cursor, terminal_args)?;
    debug_assert_eq!(got_id, rolled_id);
    let _ = got_id;
    Ok(TrustedTransactionResult::RolledBack(
        RolledBackTransaction { result_id, summary },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackLiveDecision {
    Skip,
    Execute,
}

fn decide_rollback_action(
    step: &crate::TrustedRollbackStep,
    op: &TrustedApplyOperation,
    resource: &CapDir,
) -> Result<RollbackLiveDecision> {
    match step.action() {
        RollbackAction::VerifyRollbackState => Ok(RollbackLiveDecision::Skip),
        RollbackAction::RemoveInstalledFile => {
            match probe_destination(resource, op.destination()) {
                RollbackProbe::ProvenAbsent => Ok(RollbackLiveDecision::Skip),
                RollbackProbe::ProvenRegularFile => Ok(RollbackLiveDecision::Execute),
                RollbackProbe::ProvenDirectory | RollbackProbe::Ambiguous => {
                    Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)
                }
            }
        }
        RollbackAction::RestoreInstalledFile => match op.pre_state() {
            ApplyFileState::Present { .. } => {
                match probe_file_pre_state(resource, op.destination(), op.pre_state()) {
                    RollbackFileMatchProbe::ProvenMatch => Ok(RollbackLiveDecision::Skip),
                    RollbackFileMatchProbe::ProvenAbsent
                    | RollbackFileMatchProbe::ProvenMismatch => Ok(RollbackLiveDecision::Execute),
                    RollbackFileMatchProbe::Ambiguous => {
                        Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)
                    }
                }
            }
            ApplyFileState::Absent => match probe_destination(resource, op.destination()) {
                RollbackProbe::ProvenAbsent => Ok(RollbackLiveDecision::Skip),
                RollbackProbe::ProvenRegularFile
                | RollbackProbe::ProvenDirectory
                | RollbackProbe::Ambiguous => {
                    Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)
                }
            },
        },
        RollbackAction::RemoveCreatedDirectory => {
            match probe_destination(resource, op.destination()) {
                RollbackProbe::ProvenAbsent => Ok(RollbackLiveDecision::Skip),
                RollbackProbe::ProvenDirectory => Ok(RollbackLiveDecision::Execute),
                RollbackProbe::ProvenRegularFile | RollbackProbe::Ambiguous => {
                    Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)
                }
            }
        }
        RollbackAction::RecreateDirectoryWithMetadata => {
            match probe_destination(resource, op.destination()) {
                RollbackProbe::ProvenDirectory => Ok(RollbackLiveDecision::Skip),
                RollbackProbe::ProvenAbsent => Ok(RollbackLiveDecision::Execute),
                RollbackProbe::ProvenRegularFile | RollbackProbe::Ambiguous => {
                    Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)
                }
            }
        }
    }
}

fn execute_rollback_action(
    action: RollbackAction,
    op: &TrustedApplyOperation,
    resource: &CapDir,
    backup_files: &CapDir,
    backup_dirs: &CapDir,
    backup_entry_id: Option<&Sha256Digest>,
) -> Result<()> {
    #[cfg(test)]
    if hooks::rollback_action_fault_matches(action) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed);
    }
    match action {
        RollbackAction::RemoveInstalledFile => {
            delete_file(resource, op.destination())?;
            verify_absent_file(resource, op.destination())?;
            Ok(())
        }
        RollbackAction::RestoreInstalledFile => {
            let entry_id = backup_entry_id
                .ok_or(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
            let name = entry_id.to_string();
            let ApplyFileState::Present {
                digest,
                byte_length,
            } = op.pre_state()
            else {
                return Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed);
            };
            let file = crate::baseline::fs_security::open_file_nofollow(backup_files, &name)
                .map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?;
            let (got_d, got_l) = paths::hash_file(&file)?;
            drop(file);
            let mut file = crate::baseline::fs_security::open_file_nofollow(backup_files, &name)
                .map_err(|e| {
                    map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e)
                })?;
            use std::io::Read;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|e| map_io(TransactionalApplyIoOperation::OpenBackupObject, e))?;
            if &got_d != digest || got_l != *byte_length {
                return Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed);
            }
            let replace = match probe_destination(resource, op.destination()) {
                RollbackProbe::ProvenAbsent => false,
                RollbackProbe::ProvenRegularFile => true,
                RollbackProbe::ProvenDirectory | RollbackProbe::Ambiguous => {
                    return Err(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed);
                }
            };
            install_or_replace_file(
                resource,
                op.destination(),
                &bytes,
                digest,
                *byte_length,
                replace,
            )?;
            verify_present_file(resource, op.destination(), op.pre_state())?;
            Ok(())
        }
        RollbackAction::RecreateDirectoryWithMetadata => {
            create_directory(resource, op.destination())?;
            verify_directory_present(resource, op.destination())?;
            if let Some(entry_id) = backup_entry_id {
                let meta_name = format!("{}.meta", entry_id);
                crate::baseline::fs_security::open_file_nofollow(backup_dirs, &meta_name).map_err(
                    |e| map_baseline_to_io(TransactionalApplyIoOperation::OpenBackupObject, e),
                )?;
            }
            Ok(())
        }
        RollbackAction::RemoveCreatedDirectory => {
            verify_directory_present(resource, op.destination())?;
            remove_directory(resource, op.destination())?;
            verify_path_absent(resource, op.destination())?;
            Ok(())
        }
        RollbackAction::VerifyRollbackState => Ok(()),
    }
}

const SNAPSHOT_A_MAGIC: &[u8] = b"gkrm-txn-snapshot-a-v1\n";
const RESOURCE_LOCK_ID_MAGIC: &[u8] = b"gkrm-txn-resource-lock-id-v1\n";

fn write_recovery_authority_envelope(
    txn_dir: &CapDir,
    envelope: &RecoveryAuthorityEnvelopeV1,
) -> Result<()> {
    let name = "recovery-authority.bin";
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::BeforeAuthorityWrite);
    let mut file = crate::baseline::fs_security::create_new_file(txn_dir, name).map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
    })?;
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::DuringAuthorityWrite);
    write_authority_envelope_stream(envelope, &mut file, RecoveryAuthorityLimits::default())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    crate::baseline::store::fsync_file(&file, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncJournalRecord, e))?;
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::AfterAuthorityFsync);
    drop(file);
    let parsed = verify_recovery_authority_envelope(txn_dir)?;
    if &parsed != envelope {
        return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
    }
    #[cfg(test)]
    hooks::fire_publication_hook(hooks::PublicationPoint::AfterAuthorityVerify);
    Ok(())
}

pub(crate) fn verify_recovery_authority_envelope(
    txn_dir: &CapDir,
) -> Result<RecoveryAuthorityEnvelopeV1> {
    use std::io::Read;
    let name = "recovery-authority.bin";
    let mut file = crate::baseline::fs_security::open_file_nofollow(txn_dir, name)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject)?;
    crate::baseline::fs_security::verify_regular_file(&file, name)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject)?;
    let metadata_len = file
        .metadata()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?
        .len();
    if metadata_len
        > u64::try_from(MAX_ENVELOPE_BYTES)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?
    {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        });
    }
    let max_plus_one = u64::try_from(MAX_ENVELOPE_BYTES)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    let mut bounded = file.by_ref().take(max_plus_one);
    parse_recovery_authority_envelope_reader(&mut bounded, RecoveryAuthorityLimits::default())
}

fn write_binding_file(
    txn_dir: &CapDir,
    name: &str,
    magic: &[u8],
    digest: &Sha256Digest,
) -> Result<()> {
    use std::io::Write;
    let mut file = crate::baseline::fs_security::create_new_file(txn_dir, name).map_err(|e| {
        map_baseline_to_io(TransactionalApplyIoOperation::CreateInternalDirectory, e)
    })?;
    file.write_all(magic)
        .map_err(|e| map_io(TransactionalApplyIoOperation::WriteJournalRecord, e))?;
    file.write_all(digest.as_bytes())
        .map_err(|e| map_io(TransactionalApplyIoOperation::WriteJournalRecord, e))?;
    crate::baseline::store::fsync_file(&file, name)
        .map_err(|e| map_baseline_to_io(TransactionalApplyIoOperation::SyncJournalRecord, e))?;
    Ok(())
}

fn write_snapshot_a_binding(txn_dir: &CapDir, snapshot_a: &Sha256Digest) -> Result<()> {
    write_binding_file(txn_dir, "snapshot-a.bin", SNAPSHOT_A_MAGIC, snapshot_a)
}

fn write_resource_lock_id_binding(txn_dir: &CapDir, resource_lock_id: &Sha256Digest) -> Result<()> {
    write_binding_file(
        txn_dir,
        "resource-lock-id.bin",
        RESOURCE_LOCK_ID_MAGIC,
        resource_lock_id,
    )
}

fn read_binding_file(txn_dir: &CapDir, name: &str, magic: &[u8]) -> Result<Sha256Digest> {
    use std::io::Read;
    let mut file = crate::baseline::fs_security::open_file_nofollow(txn_dir, name)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject)?;
    crate::baseline::fs_security::verify_regular_file(&file, name)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionUnsafeFilesystemObject)?;
    let expected_len = magic
        .len()
        .checked_add(32)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    let metadata_len = file
        .metadata()
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?
        .len();
    if metadata_len
        != u64::try_from(expected_len)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?
    {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    let capacity = expected_len
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionJournalInvalid)?;
    file.by_ref()
        .take(
            u64::try_from(capacity)
                .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionArithmeticOverflow)?,
        )
        .read_to_end(&mut bytes)
        .map_err(|e| map_io(TransactionalApplyIoOperation::OpenJournalRecord, e))?;
    if bytes.len() != expected_len || !bytes.starts_with(magic) {
        return Err(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid);
    }
    let mut dig = [0u8; 32];
    dig.copy_from_slice(&bytes[magic.len()..]);
    Ok(Sha256Digest::new(dig))
}

/// Read and validate `snapshot-a.bin` as untrusted filesystem content.
pub(crate) fn read_snapshot_a_binding(txn_dir: &CapDir) -> Result<Sha256Digest> {
    read_binding_file(txn_dir, "snapshot-a.bin", SNAPSHOT_A_MAGIC)
}

/// Read and validate `resource-lock-id.bin` as untrusted filesystem content.
pub(crate) fn read_resource_lock_id_binding(txn_dir: &CapDir) -> Result<Sha256Digest> {
    read_binding_file(txn_dir, "resource-lock-id.bin", RESOURCE_LOCK_ID_MAGIC)
}

/// Task 24 resume: run remaining rollback steps using Task 23 helpers.
pub(crate) fn recovery_run_rollback(
    request: &recovery::TrustedRecoveryExecutionAuthority<'_>,
    verified: &recovery::binding::VerifiedPublishedTransaction,
    mut cursor: JournalCursor,
    snapshot_a: &Sha256Digest,
) -> Result<recovery::TrustedRecoveryResult> {
    use recovery::{
        encode_recovery_result_id_pub, revalidate_peers_or_still_required,
        RecoveredRolledBackTransaction, RecoveryStillRequired, TrustedRecoveryResult,
        TrustedRecoveryResultId,
    };

    verified
        .reassert(request.transaction_root)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;

    let plan_id = *request.tx_plan.plan_id().digest();
    let expected_resource_lock = locks::encode_resource_lock_id(request.resource_key.as_str())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;

    #[cfg(test)]
    hooks::fire_peer_race_hook(hooks::PeerRacePoint::BeforeFirstRollbackMutation);
    if let Some(blocked) =
        revalidate_peers_or_still_required(request, verified, &plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }

    let txn_dir = &verified.txn_dir;
    let journal_dir = &verified.journal_dir;

    if !matches!(
        cursor.last_event,
        Some(TransactionJournalEvent::RollingBack | TransactionJournalEvent::RollbackStepCompleted)
    ) {
        verified
            .reassert(request.transaction_root)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
        append_record(
            journal_dir,
            &mut cursor,
            AppendArgs {
                plan_id: &plan_id,
                snapshot_a,
                event: TransactionJournalEvent::RollingBack,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: u64::MAX / 4,
                max_journal_records: request.options.max_journal_records,
            },
        )?;
    }

    let resource = request
        .installed_source
        .open_resource_dir()
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
    let backup_root = open_child_dir_pub(txn_dir, "backup")?;
    let backup_files = open_child_dir_pub(&backup_root, "files")?;
    let backup_dirs = open_child_dir_pub(&backup_root, "directories")?;

    let completed: BTreeSet<Sha256Digest> = cursor.rollback_completed.iter().copied().collect();
    let mut steps_done = 0_usize;
    for step in request.tx_plan.rollback_steps() {
        if steps_done >= request.options.max_recovery_steps {
            return Err(GkrmError::TrustedTransactionRecoveryLimitExceeded {
                limit: "max_recovery_steps",
            });
        }
        steps_done = steps_done.saturating_add(1);
        if completed.contains(step.step_id().digest()) {
            continue;
        }
        if matches!(step.action(), RollbackAction::VerifyRollbackState) {
            continue;
        }
        let op_id = match step.operation_id() {
            Some(id) => id,
            None => {
                return Ok(TrustedRecoveryResult::RecoveryStillRequired(
                    RecoveryStillRequired {
                        result_id: TrustedRecoveryResultId(encode_recovery_result_id_pub(
                            &plan_id,
                            b"rollback-missing-op",
                            None,
                        )?),
                    },
                ));
            }
        };
        let op = match request
            .apply_plan
            .operations()
            .iter()
            .find(|o| o.operation_id().digest() == op_id.digest())
        {
            Some(op) => op,
            None => {
                return Ok(TrustedRecoveryResult::RecoveryStillRequired(
                    RecoveryStillRequired {
                        result_id: TrustedRecoveryResultId(encode_recovery_result_id_pub(
                            &plan_id,
                            b"rollback-op-missing",
                            None,
                        )?),
                    },
                ));
            }
        };
        match decide_rollback_action(step, op, &resource) {
            Ok(RollbackLiveDecision::Skip) => continue,
            Ok(RollbackLiveDecision::Execute) => {}
            Err(_) => {
                return Ok(TrustedRecoveryResult::RecoveryStillRequired(
                    RecoveryStillRequired {
                        result_id: TrustedRecoveryResultId(encode_recovery_result_id_pub(
                            &plan_id,
                            b"rollback-probe",
                            None,
                        )?),
                    },
                ));
            }
        }
        verified
            .reassert(request.transaction_root)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
        #[cfg(test)]
        hooks::fire_peer_race_hook(hooks::PeerRacePoint::BeforeRollbackStepMutation);
        if let Some(blocked) = revalidate_peers_or_still_required(
            request,
            verified,
            &plan_id,
            &expected_resource_lock,
        )? {
            return Ok(blocked);
        }
        if execute_rollback_action(
            step.action(),
            op,
            &resource,
            &backup_files,
            &backup_dirs,
            step.backup_entry_id().map(|e| e.digest()),
        )
        .is_err()
        {
            return Ok(TrustedRecoveryResult::RecoveryStillRequired(
                RecoveryStillRequired {
                    result_id: TrustedRecoveryResultId(encode_recovery_result_id_pub(
                        &plan_id,
                        b"rollback-step-failed",
                        None,
                    )?),
                },
            ));
        }
        cursor.rollback_completed.push(*step.step_id().digest());
        verified
            .reassert(request.transaction_root)
            .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
        append_record(
            journal_dir,
            &mut cursor,
            AppendArgs {
                plan_id: &plan_id,
                snapshot_a,
                event: TransactionJournalEvent::RollbackStepCompleted,
                related_step_id: Some(step.step_id().digest()),
                related_entry_id: step.backup_entry_id().map(|e| e.digest()),
                max_journal_bytes: u64::MAX / 4,
                max_journal_records: request.options.max_journal_records,
            },
        )?;
    }

    let restored = request
        .installed_source
        .capture_tree_snapshot(request.resource_key)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
    if &restored.fingerprint != snapshot_a {
        return Ok(TrustedRecoveryResult::RecoveryStillRequired(
            RecoveryStillRequired {
                result_id: TrustedRecoveryResultId(encode_recovery_result_id_pub(
                    &plan_id,
                    b"rollback-tree-mismatch",
                    None,
                )?),
            },
        ));
    }
    let rollback_seal = id::encode_rollback_seal(&plan_id, snapshot_a, &restored.fingerprint)?;
    cursor.rollback_seal = Some(rollback_seal);
    let terminal_args = AppendArgs {
        plan_id: &plan_id,
        snapshot_a,
        event: TransactionJournalEvent::RolledBack,
        related_step_id: None,
        related_entry_id: None,
        max_journal_bytes: u64::MAX / 4,
        max_journal_records: request.options.max_journal_records,
    };
    let rolled_id = predict_record_id(&cursor, &terminal_args)?;
    let result_id = TrustedRecoveryResultId(encode_recovery_result_id_pub(
        &plan_id,
        b"recovered-rolled-back",
        Some(&rolled_id),
    )?);
    verified
        .reassert(request.transaction_root)
        .map_err(|_| GkrmError::TrustedTransactionalApplyExecutionRollbackFailed)?;
    #[cfg(test)]
    hooks::fire_peer_race_hook(hooks::PeerRacePoint::BeforeRolledBackTerminal);
    if let Some(blocked) =
        revalidate_peers_or_still_required(request, verified, &plan_id, &expected_resource_lock)?
    {
        return Ok(blocked);
    }
    let got = append_terminal_record(journal_dir, Some(txn_dir), &mut cursor, terminal_args)?;
    debug_assert_eq!(got, rolled_id);
    let _ = got;
    Ok(TrustedRecoveryResult::RecoveredRolledBack(
        RecoveredRolledBackTransaction { result_id },
    ))
}
