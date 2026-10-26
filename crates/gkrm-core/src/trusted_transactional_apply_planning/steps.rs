//! Forward execution step construction for Task 22.

use crate::{
    ApplyBackupRequirement, GkrmError, Result, TrustedApplyOperation, TrustedApplyOperationKind,
    TrustedApplyOperationPhase, TrustedApplyStatus,
};

use super::id::{encode_forward_step_id, StepIdInputs};
use super::{
    JournalState, TransactionStepPhase, TrustedBackupEntry, TrustedBackupPlan,
    TrustedTransactionStep, TrustedTransactionalApplyStatus,
};

pub(crate) struct BuiltForwardSteps {
    pub(crate) steps: Vec<TrustedTransactionStep>,
    pub(crate) total_write_bytes: u64,
}

pub(crate) fn build_forward_steps(
    apply_status: TrustedApplyStatus,
    operations: &[TrustedApplyOperation],
    backup: &TrustedBackupPlan,
    max_steps: usize,
) -> Result<(BuiltForwardSteps, TrustedTransactionalApplyStatus)> {
    let mut steps = Vec::new();
    let mut seq = 0_u32;

    push_control(&mut steps, &mut seq, TransactionStepPhase::Preflight, None)?;
    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::PersistPreparedJournal,
        Some(JournalState::Prepared),
    )?;

    let status = match apply_status {
        TrustedApplyStatus::NoFilesystemChanges => {
            if !operations.is_empty() {
                return Err(GkrmError::TrustedTransactionalApplyPlanningStatusInvalid);
            }
            push_control(
                &mut steps,
                &mut seq,
                TransactionStepPhase::PersistBackupCompleteJournal,
                Some(JournalState::BackupComplete),
            )?;
            push_control(
                &mut steps,
                &mut seq,
                TransactionStepPhase::PersistApplyingJournal,
                Some(JournalState::Applying),
            )?;
            push_control(
                &mut steps,
                &mut seq,
                TransactionStepPhase::PersistAppliedJournal,
                Some(JournalState::Applied),
            )?;
            push_control(
                &mut steps,
                &mut seq,
                TransactionStepPhase::VerifyInstalledTree,
                None,
            )?;
            push_control(
                &mut steps,
                &mut seq,
                TransactionStepPhase::PersistVerifiedJournal,
                Some(JournalState::Verified),
            )?;
            push_control(
                &mut steps,
                &mut seq,
                TransactionStepPhase::PersistCommittedJournal,
                Some(JournalState::Committed),
            )?;
            push_control(&mut steps, &mut seq, TransactionStepPhase::Finalize, None)?;
            if steps.len() > max_steps {
                return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
                    limit: "max_transaction_steps",
                });
            }
            return Ok((
                BuiltForwardSteps {
                    steps,
                    total_write_bytes: 0,
                },
                TrustedTransactionalApplyStatus::NoFilesystemChanges,
            ));
        }
        TrustedApplyStatus::ReadyForTransactionalApply => {
            TrustedTransactionalApplyStatus::ReadyForTransactionalExecution
        }
    };

    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::CreateBackupBundle,
        None,
    )?;
    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::PersistBackupCompleteJournal,
        Some(JournalState::BackupComplete),
    )?;
    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::PersistApplyingJournal,
        Some(JournalState::Applying),
    )?;

    let backup_by_op: std::collections::BTreeMap<_, _> = backup
        .entries
        .iter()
        .map(|e| (e.operation_id.digest().to_string(), e))
        .collect();

    let mut total_write_bytes = 0_u64;
    for op in operations {
        let phase = map_apply_phase(op.phase());
        let backup_entry: Option<&TrustedBackupEntry> = if op.backup_requirement()
            == ApplyBackupRequirement::None
        {
            None
        } else {
            Some(
                backup_by_op
                    .get(&op.operation_id().digest().to_string())
                    .copied()
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete)?,
            )
        };

        if matches!(
            op.kind(),
            TrustedApplyOperationKind::InstallFile | TrustedApplyOperationKind::ReplaceFile
        ) {
            if let Some(len) = op.post_state().length_opt() {
                total_write_bytes = total_write_bytes
                    .checked_add(len)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
        }

        let pre_tag = op.pre_state().encode_tag();
        let post_tag = op.post_state().encode_tag();
        let binding = match op.staged_binding_tag() {
            255 => None,
            tag => Some(tag),
        };
        let backup_id = backup_entry.map(|e| *e.entry_id.digest());
        let step_id = encode_forward_step_id(StepIdInputs {
            role: 1,
            phase,
            operation_id: Some(op.operation_id()),
            pre_tag,
            post_tag,
            backup_entry_id: backup_id.as_ref(),
            journal_to: None,
            rollback_action: None,
            sequence: seq,
        })?;
        seq = seq
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
        steps.push(TrustedTransactionStep {
            step_id,
            phase,
            operation_id: Some(*op.operation_id()),
            pre_tag,
            post_tag,
            staged_binding_tag: binding,
            backup_entry_id: backup_entry.map(|e| e.entry_id),
            journal_to: None,
        });
    }

    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::PersistAppliedJournal,
        Some(JournalState::Applied),
    )?;
    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::VerifyInstalledTree,
        None,
    )?;
    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::PersistVerifiedJournal,
        Some(JournalState::Verified),
    )?;
    push_control(
        &mut steps,
        &mut seq,
        TransactionStepPhase::PersistCommittedJournal,
        Some(JournalState::Committed),
    )?;
    push_control(&mut steps, &mut seq, TransactionStepPhase::Finalize, None)?;

    if steps.len() > max_steps {
        return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
            limit: "max_transaction_steps",
        });
    }

    Ok((
        BuiltForwardSteps {
            steps,
            total_write_bytes,
        },
        status,
    ))
}

fn push_control(
    steps: &mut Vec<TrustedTransactionStep>,
    seq: &mut u32,
    phase: TransactionStepPhase,
    journal_to: Option<JournalState>,
) -> Result<()> {
    let step_id = encode_forward_step_id(StepIdInputs {
        role: 0,
        phase,
        operation_id: None,
        pre_tag: 0,
        post_tag: 0,
        backup_entry_id: None,
        journal_to,
        rollback_action: None,
        sequence: *seq,
    })?;
    *seq = seq
        .checked_add(1)
        .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
    steps.push(TrustedTransactionStep {
        step_id,
        phase,
        operation_id: None,
        pre_tag: 0,
        post_tag: 0,
        staged_binding_tag: None,
        backup_entry_id: None,
        journal_to,
    });
    Ok(())
}

fn map_apply_phase(phase: TrustedApplyOperationPhase) -> TransactionStepPhase {
    match phase {
        TrustedApplyOperationPhase::RemoveBlockingFile
        | TrustedApplyOperationPhase::DeleteBlockingDescendant => {
            TransactionStepPhase::ApplyBlockingDeletes
        }
        TrustedApplyOperationPhase::RemoveBlockingDirectory => {
            TransactionStepPhase::ApplyBlockingDirectoryRemovals
        }
        TrustedApplyOperationPhase::CreateDirectory => TransactionStepPhase::CreateDirectories,
        TrustedApplyOperationPhase::WriteFile => TransactionStepPhase::InstallOrReplaceFiles,
        TrustedApplyOperationPhase::DeleteObsoleteFile => TransactionStepPhase::DeleteObsoleteFiles,
        TrustedApplyOperationPhase::RemoveObsoleteDirectory => {
            TransactionStepPhase::RemoveObsoleteDirectories
        }
    }
}
