//! Deterministic ID encoding for Task 22 transactional apply planning.

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{
    ApplyBackupRequirement, GkrmError, ResourceRelativePath, Result, Sha256Digest,
    TrustedApplyOperationId, TrustedApplyOperationKind,
};

use super::{
    JournalState, RecoveryAction, RollbackAction, TransactionCrashBoundary,
    TransactionJournalRecordKind, TransactionStepPhase, TrustedBackupEntry, TrustedBackupEntryId,
    TrustedBackupPlanId, TrustedJournalRecordId, TrustedRecoveryTableId, TrustedRollbackStepId,
    TrustedTransactionStepId, TrustedTransactionalApplyPlanId, TrustedTransactionalApplyStatus,
    TrustedTransactionalApplySummary,
};

pub(super) fn encode_backup_entry_id(
    operation_id: &TrustedApplyOperationId,
    kind: ApplyBackupRequirement,
    op_kind: TrustedApplyOperationKind,
    destination: &ResourceRelativePath,
    state_tag: u8,
    digest: Option<&Sha256Digest>,
    length: Option<u64>,
    restore_order: u32,
) -> Result<TrustedBackupEntryId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-backup-entry-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.digest(operation_id.digest());
    enc.u8(backup_kind_tag(kind));
    enc.u8(op_kind_tag(op_kind));
    enc.path(destination)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.u8(state_tag);
    match (digest, length) {
        (Some(d), Some(len)) => {
            enc.u8(1);
            enc.digest(d);
            enc.u64(len);
        }
        (None, None) => enc.u8(0),
        _ => return Err(GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure),
    }
    enc.u64(u64::from(restore_order));
    Ok(TrustedBackupEntryId(enc.finish()))
}

/// Recompute Task 21 backup-set semantic commitment from Task 22 backup entries.
pub(super) fn recompute_task21_backup_set_commitment(
    entries: &[TrustedBackupEntry],
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-apply-backup-set-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.usize(entries.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    for entry in entries {
        enc.digest(entry.operation_id.digest());
        enc.u8(backup_kind_tag(entry.kind));
        enc.u8(op_kind_tag(entry.operation_kind));
        enc.path(&entry.destination)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    }
    Ok(enc.finish())
}

pub(super) fn encode_backup_plan_id(
    apply_plan_id: &Sha256Digest,
    backup_set_id: &Sha256Digest,
    entries: &[TrustedBackupEntry],
    total_backup_bytes: u64,
) -> Result<TrustedBackupPlanId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-backup-plan-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.digest(apply_plan_id);
    enc.digest(backup_set_id);
    enc.usize(entries.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    for entry in entries {
        enc.digest(entry.entry_id.digest());
        enc.u64(u64::from(entry.restore_order));
    }
    enc.u64(total_backup_bytes);
    Ok(TrustedBackupPlanId(enc.finish()))
}

pub(super) struct StepIdInputs<'a> {
    pub(super) role: u8,
    pub(super) phase: TransactionStepPhase,
    pub(super) operation_id: Option<&'a TrustedApplyOperationId>,
    pub(super) pre_tag: u8,
    pub(super) post_tag: u8,
    pub(super) backup_entry_id: Option<&'a Sha256Digest>,
    pub(super) journal_to: Option<JournalState>,
    pub(super) rollback_action: Option<RollbackAction>,
    pub(super) sequence: u32,
}

pub(super) fn encode_step_id(input: StepIdInputs<'_>) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-step-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.u8(input.role);
    enc.u8(phase_tag(input.phase));
    match input.operation_id {
        Some(id) => {
            enc.u8(1);
            enc.digest(id.digest());
        }
        None => enc.u8(0),
    }
    enc.u8(input.pre_tag);
    enc.u8(input.post_tag);
    match input.backup_entry_id {
        Some(id) => {
            enc.u8(1);
            enc.digest(id);
        }
        None => enc.u8(0),
    }
    match input.journal_to {
        Some(state) => {
            enc.u8(1);
            enc.u8(journal_state_tag(state));
        }
        None => enc.u8(0),
    }
    match input.rollback_action {
        Some(action) => {
            enc.u8(1);
            enc.u8(rollback_action_tag(action));
        }
        None => enc.u8(0),
    }
    enc.u64(u64::from(input.sequence));
    Ok(enc.finish())
}

pub(super) fn encode_forward_step_id(input: StepIdInputs<'_>) -> Result<TrustedTransactionStepId> {
    Ok(TrustedTransactionStepId(encode_step_id(input)?))
}

pub(super) fn encode_rollback_step_id(input: StepIdInputs<'_>) -> Result<TrustedRollbackStepId> {
    Ok(TrustedRollbackStepId(encode_step_id(input)?))
}

pub(super) fn encode_journal_record_id(
    from: Option<JournalState>,
    to: JournalState,
    sequence: u32,
    related_step: Option<&Sha256Digest>,
) -> Result<TrustedJournalRecordId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-journal-record-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.u8(journal_record_kind_tag(
        TransactionJournalRecordKind::StateTransition,
    ));
    match from {
        Some(s) => {
            enc.u8(1);
            enc.u8(journal_state_tag(s));
        }
        None => enc.u8(0),
    }
    enc.u8(journal_state_tag(to));
    enc.u64(u64::from(sequence));
    match related_step {
        Some(id) => {
            enc.u8(1);
            enc.digest(id);
        }
        None => enc.u8(0),
    }
    Ok(TrustedJournalRecordId(enc.finish()))
}

pub(super) fn encode_recovery_table_id(
    rows: &[(TransactionCrashBoundary, RecoveryAction)],
) -> Result<TrustedRecoveryTableId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-recovery-table-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.usize(rows.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    for (boundary, action) in rows {
        enc.u8(crash_boundary_tag(*boundary));
        enc.u8(recovery_action_tag(*action));
    }
    Ok(TrustedRecoveryTableId(enc.finish()))
}

pub(crate) struct PlanIdInputs<'a> {
    pub(crate) apply_plan_id: &'a Sha256Digest,
    pub(crate) review_id: &'a Sha256Digest,
    pub(crate) analysis_id: Option<&'a Sha256Digest>,
    pub(crate) text_diff_id: Option<&'a Sha256Digest>,
    pub(crate) synthesis_id: Option<&'a Sha256Digest>,
    pub(crate) merged_bytes_id: Option<&'a Sha256Digest>,
    pub(crate) bundle_id: &'a Sha256Digest,
    pub(crate) manifest_id: &'a Sha256Digest,
    pub(crate) resource_key: &'a str,
    pub(crate) baseline_id: &'a str,
    pub(crate) installed_fp: &'a Sha256Digest,
    pub(crate) incoming_package_fp: &'a Sha256Digest,
    pub(crate) incoming_resource_fp: &'a Sha256Digest,
    pub(crate) installed_tree_snapshot_fp: &'a Sha256Digest,
    pub(crate) options_tag: &'a [u8],
    pub(crate) backup_plan_id: &'a Sha256Digest,
    pub(crate) forward_step_ids: &'a [Sha256Digest],
    pub(crate) rollback_step_ids: &'a [Sha256Digest],
    pub(crate) journal_record_ids: &'a [Sha256Digest],
    pub(crate) recovery_table_id: &'a Sha256Digest,
    pub(crate) summary: &'a TrustedTransactionalApplySummary,
    pub(crate) status: TrustedTransactionalApplyStatus,
}

pub(crate) fn encode_execution_plan_id(
    input: PlanIdInputs<'_>,
) -> Result<TrustedTransactionalApplyPlanId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transactional-apply-plan-v1")
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.digest(input.apply_plan_id);
    enc.digest(input.review_id);
    optional_digest(&mut enc, input.analysis_id);
    optional_digest(&mut enc, input.text_diff_id);
    optional_digest(&mut enc, input.synthesis_id);
    optional_digest(&mut enc, input.merged_bytes_id);
    enc.digest(input.bundle_id);
    enc.digest(input.manifest_id);
    enc.string(input.resource_key)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.string(input.baseline_id)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.digest(input.installed_fp);
    enc.digest(input.incoming_package_fp);
    enc.digest(input.incoming_resource_fp);
    enc.digest(input.installed_tree_snapshot_fp);
    enc.octet_string(input.options_tag)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.digest(input.backup_plan_id);
    enc.usize(input.forward_step_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    for id in input.forward_step_ids {
        enc.digest(id);
    }
    enc.usize(input.rollback_step_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    for id in input.rollback_step_ids {
        enc.digest(id);
    }
    enc.usize(input.journal_record_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    for id in input.journal_record_ids {
        enc.digest(id);
    }
    enc.digest(input.recovery_table_id);
    enc.usize(input.summary.forward_step_count)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.rollback_step_count)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.backup_entry_count)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.journal_record_count)
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    enc.u64(input.summary.total_expected_write_bytes);
    enc.u64(input.summary.total_backup_bytes);
    enc.u8(status_tag(input.status));
    Ok(TrustedTransactionalApplyPlanId(enc.finish()))
}

fn optional_digest(enc: &mut CanonicalFingerprintEncoder, value: Option<&Sha256Digest>) {
    match value {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
}

fn backup_kind_tag(kind: ApplyBackupRequirement) -> u8 {
    match kind {
        ApplyBackupRequirement::None => 0,
        ApplyBackupRequirement::PreserveInstalledFile => 1,
        ApplyBackupRequirement::PreserveRemovedDirectoryMetadata => 2,
    }
}

fn op_kind_tag(kind: TrustedApplyOperationKind) -> u8 {
    match kind {
        TrustedApplyOperationKind::CreateDirectory => 0,
        TrustedApplyOperationKind::InstallFile => 1,
        TrustedApplyOperationKind::ReplaceFile => 2,
        TrustedApplyOperationKind::DeleteFile => 3,
        TrustedApplyOperationKind::RemoveDirectory => 4,
    }
}

fn phase_tag(phase: TransactionStepPhase) -> u8 {
    match phase {
        TransactionStepPhase::Preflight => 0,
        TransactionStepPhase::PersistPreparedJournal => 1,
        TransactionStepPhase::CreateBackupBundle => 2,
        TransactionStepPhase::PersistBackupCompleteJournal => 3,
        TransactionStepPhase::PersistApplyingJournal => 4,
        TransactionStepPhase::ApplyBlockingDeletes => 5,
        TransactionStepPhase::ApplyBlockingDirectoryRemovals => 6,
        TransactionStepPhase::CreateDirectories => 7,
        TransactionStepPhase::InstallOrReplaceFiles => 8,
        TransactionStepPhase::DeleteObsoleteFiles => 9,
        TransactionStepPhase::RemoveObsoleteDirectories => 10,
        TransactionStepPhase::PersistAppliedJournal => 11,
        TransactionStepPhase::VerifyInstalledTree => 12,
        TransactionStepPhase::PersistVerifiedJournal => 13,
        TransactionStepPhase::PersistCommittedJournal => 14,
        TransactionStepPhase::Finalize => 15,
        TransactionStepPhase::Rollback => 16,
    }
}

fn journal_state_tag(state: JournalState) -> u8 {
    match state {
        JournalState::Prepared => 0,
        JournalState::BackupComplete => 1,
        JournalState::Applying => 2,
        JournalState::Applied => 3,
        JournalState::Verified => 4,
        JournalState::Committed => 5,
        JournalState::RollingBack => 6,
        JournalState::RolledBack => 7,
        JournalState::RecoveryRequired => 8,
    }
}

fn journal_record_kind_tag(kind: TransactionJournalRecordKind) -> u8 {
    match kind {
        TransactionJournalRecordKind::StateTransition => 0,
    }
}

fn rollback_action_tag(action: RollbackAction) -> u8 {
    match action {
        RollbackAction::RemoveInstalledFile => 0,
        RollbackAction::RestoreInstalledFile => 1,
        RollbackAction::RecreateDirectoryWithMetadata => 2,
        RollbackAction::RemoveCreatedDirectory => 3,
        RollbackAction::VerifyRollbackState => 4,
    }
}

fn crash_boundary_tag(boundary: TransactionCrashBoundary) -> u8 {
    match boundary {
        TransactionCrashBoundary::BeforePrepared => 0,
        TransactionCrashBoundary::PreparedIncompleteBackup => 1,
        TransactionCrashBoundary::BackupCompleteBeforeMutation => 2,
        TransactionCrashBoundary::Applying => 3,
        TransactionCrashBoundary::Applied => 4,
        TransactionCrashBoundary::Verified => 5,
        TransactionCrashBoundary::RollingBack => 6,
        TransactionCrashBoundary::RolledBack => 7,
        TransactionCrashBoundary::Committed => 8,
        TransactionCrashBoundary::InconsistentEvidence => 9,
    }
}

fn recovery_action_tag(action: RecoveryAction) -> u8 {
    match action {
        RecoveryAction::Restart => 0,
        RecoveryAction::DiscardIncompleteBackupAndRestart => 1,
        RecoveryAction::ContinueOrSafelyAbort => 2,
        RecoveryAction::RollBackFromCompletedStep => 3,
        RecoveryAction::VerifyThenCommitOrRollBack => 4,
        RecoveryAction::ReverifyThenCommitOrRollBack => 5,
        RecoveryAction::ResumeRollback => 6,
        RecoveryAction::FinalizeRollbackCleanup => 7,
        RecoveryAction::ForwardCompleteNeverRollBack => 8,
        RecoveryAction::ManualRecoveryRequired => 9,
    }
}

fn status_tag(status: TrustedTransactionalApplyStatus) -> u8 {
    match status {
        TrustedTransactionalApplyStatus::ReadyForTransactionalExecution => 0,
        TrustedTransactionalApplyStatus::NoFilesystemChanges => 1,
    }
}
