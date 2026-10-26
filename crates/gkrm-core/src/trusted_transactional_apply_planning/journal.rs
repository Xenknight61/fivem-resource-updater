//! Journal plan and crash-recovery table for Task 22.

use crate::{GkrmError, Result};

use super::id::{encode_journal_record_id, encode_recovery_table_id};
use super::{
    JournalState, RecoveryAction, TransactionCrashBoundary, TransactionJournalRecord,
    TransactionJournalRecordKind, TrustedJournalPlan, TrustedRecoveryTable,
};

pub(super) fn validate_transition(from: JournalState, to: JournalState) -> Result<()> {
    let ok = matches!(
        (from, to),
        (JournalState::Prepared, JournalState::BackupComplete)
            | (JournalState::BackupComplete, JournalState::Applying)
            | (JournalState::Applying, JournalState::Applied)
            | (JournalState::Applied, JournalState::Verified)
            | (JournalState::Verified, JournalState::Committed)
            | (JournalState::Applying, JournalState::RollingBack)
            | (JournalState::Applied, JournalState::RollingBack)
            | (JournalState::Verified, JournalState::RollingBack)
            | (JournalState::RollingBack, JournalState::RolledBack)
    );
    if ok {
        Ok(())
    } else {
        Err(GkrmError::TrustedTransactionalApplyPlanningJournalInvalid)
    }
}

pub(crate) fn build_journal_plan(max_records: usize) -> Result<TrustedJournalPlan> {
    let forward = [
        (None, JournalState::Prepared),
        (Some(JournalState::Prepared), JournalState::BackupComplete),
        (Some(JournalState::BackupComplete), JournalState::Applying),
        (Some(JournalState::Applying), JournalState::Applied),
        (Some(JournalState::Applied), JournalState::Verified),
        (Some(JournalState::Verified), JournalState::Committed),
    ];

    let mut records = Vec::new();
    for (index, (from, to)) in forward.into_iter().enumerate() {
        if let Some(from_state) = from {
            validate_transition(from_state, to)?;
        }
        let sequence = u32::try_from(index)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
        let record_id = encode_journal_record_id(from, to, sequence, None)?;
        records.push(TransactionJournalRecord {
            record_id,
            kind: TransactionJournalRecordKind::StateTransition,
            from,
            to,
            sequence,
        });
    }

    // Planned rollback transitions (available edges; not executed by Task 22).
    let rollback_edges = [
        (JournalState::Applying, JournalState::RollingBack),
        (JournalState::Applied, JournalState::RollingBack),
        (JournalState::Verified, JournalState::RollingBack),
        (JournalState::RollingBack, JournalState::RolledBack),
    ];
    for (from, to) in rollback_edges {
        validate_transition(from, to)?;
        let sequence = u32::try_from(records.len())
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
        let record_id = encode_journal_record_id(Some(from), to, sequence, None)?;
        records.push(TransactionJournalRecord {
            record_id,
            kind: TransactionJournalRecordKind::StateTransition,
            from: Some(from),
            to,
            sequence,
        });
    }

    if records.len() > max_records {
        return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
            limit: "max_journal_records",
        });
    }

    Ok(TrustedJournalPlan { records })
}

pub(crate) fn build_recovery_table() -> Result<TrustedRecoveryTable> {
    let rows = [
        (
            TransactionCrashBoundary::BeforePrepared,
            RecoveryAction::Restart,
        ),
        (
            TransactionCrashBoundary::PreparedIncompleteBackup,
            RecoveryAction::DiscardIncompleteBackupAndRestart,
        ),
        (
            TransactionCrashBoundary::BackupCompleteBeforeMutation,
            RecoveryAction::ContinueOrSafelyAbort,
        ),
        (
            TransactionCrashBoundary::Applying,
            RecoveryAction::RollBackFromCompletedStep,
        ),
        (
            TransactionCrashBoundary::Applied,
            RecoveryAction::VerifyThenCommitOrRollBack,
        ),
        (
            TransactionCrashBoundary::Verified,
            RecoveryAction::ReverifyThenCommitOrRollBack,
        ),
        (
            TransactionCrashBoundary::RollingBack,
            RecoveryAction::ResumeRollback,
        ),
        (
            TransactionCrashBoundary::RolledBack,
            RecoveryAction::FinalizeRollbackCleanup,
        ),
        (
            TransactionCrashBoundary::Committed,
            RecoveryAction::ForwardCompleteNeverRollBack,
        ),
        (
            TransactionCrashBoundary::InconsistentEvidence,
            RecoveryAction::ManualRecoveryRequired,
        ),
    ];

    // Committed must never map to rollback.
    for (boundary, action) in &rows {
        if *boundary == TransactionCrashBoundary::Committed
            && matches!(
                action,
                RecoveryAction::RollBackFromCompletedStep
                    | RecoveryAction::ResumeRollback
                    | RecoveryAction::VerifyThenCommitOrRollBack
                    | RecoveryAction::ReverifyThenCommitOrRollBack
            )
        {
            return Err(GkrmError::TrustedTransactionalApplyPlanningRecoveryInvalid);
        }
    }

    let table_id = encode_recovery_table_id(&rows)?;
    Ok(TrustedRecoveryTable {
        table_id,
        rows: rows.to_vec(),
    })
}

#[cfg(test)]
pub(super) fn assert_illegal_committed_rollback() {
    assert!(validate_transition(JournalState::Committed, JournalState::RollingBack).is_err());
}
