//! Explicit rollback step construction and dependency validation for Task 22.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    ApplyBackupRequirement, GkrmError, Result, TrustedApplyOperation, TrustedApplyOperationKind,
    TrustedApplyOperationPhase,
};

use super::id::{encode_rollback_step_id, StepIdInputs};
use super::{
    RollbackAction, TransactionStepPhase, TrustedBackupPlan, TrustedRollbackStep,
    TrustedTransactionStep,
};

pub(crate) fn build_rollback_steps(
    operations: &[TrustedApplyOperation],
    forward: &[TrustedTransactionStep],
    backup: &TrustedBackupPlan,
    max_steps: usize,
) -> Result<Vec<TrustedRollbackStep>> {
    let mut mutating: Vec<&TrustedApplyOperation> = Vec::new();
    for step in forward {
        let Some(op_id) = step.operation_id.as_ref() else {
            continue;
        };
        let op = operations
            .iter()
            .find(|o| o.operation_id().digest() == op_id.digest())
            .ok_or(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid)?;
        mutating.push(op);
    }

    if mutating.len() != forward.iter().filter(|s| s.operation_id.is_some()).count() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
    }

    let mut ordered: Vec<&TrustedApplyOperation> = Vec::new();

    // 1. Recreate removed directories shallow→deep (parents before children).
    let mut group = filter_phase(
        &mutating,
        TrustedApplyOperationPhase::RemoveObsoleteDirectory,
    );
    sort_shallow_first(&mut group);
    ordered.append(&mut group);

    // 2. Restore obsolete files (required parents already recreated).
    ordered.extend(filter_phase(
        &mutating,
        TrustedApplyOperationPhase::DeleteObsoleteFile,
    ));

    // 3. Undo installs/replaces deepest-first.
    let mut group = filter_phase(&mutating, TrustedApplyOperationPhase::WriteFile);
    sort_deep_first(&mut group);
    ordered.append(&mut group);

    // 4. Remove created directories deepest-first.
    let mut group = filter_phase(&mutating, TrustedApplyOperationPhase::CreateDirectory);
    sort_deep_first(&mut group);
    ordered.append(&mut group);

    // 5. Recreate blocking directories shallow→deep.
    let mut group = filter_phase(
        &mutating,
        TrustedApplyOperationPhase::RemoveBlockingDirectory,
    );
    sort_shallow_first(&mut group);
    ordered.append(&mut group);

    // 6. Restore blocking file deletes shallow→deep.
    let mut group = filter_phase(
        &mutating,
        TrustedApplyOperationPhase::DeleteBlockingDescendant,
    );
    group.extend(filter_phase(
        &mutating,
        TrustedApplyOperationPhase::RemoveBlockingFile,
    ));
    sort_shallow_first(&mut group);
    ordered.append(&mut group);

    if ordered.len() != mutating.len() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
    }

    let backup_by_op: BTreeMap<_, _> = backup
        .entries
        .iter()
        .map(|e| (e.operation_id.digest().to_string(), e))
        .collect();

    let mut steps = Vec::new();
    let mut seq = 0_u32;
    for op in &ordered {
        let action = map_rollback_action(op);
        let needs_backup = op.backup_requirement() != ApplyBackupRequirement::None;
        let backup_entry = backup_by_op.get(&op.operation_id().digest().to_string());
        if needs_backup && backup_entry.is_none() {
            return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
        }
        let backup_id = backup_entry.map(|e| *e.entry_id.digest());
        let forward_step_id = forward
            .iter()
            .find(|s| {
                s.operation_id
                    .as_ref()
                    .is_some_and(|id| id.digest() == op.operation_id().digest())
            })
            .map(|s| s.step_id)
            .ok_or(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid)?;
        let step_id = encode_rollback_step_id(StepIdInputs {
            role: 2,
            phase: TransactionStepPhase::Rollback,
            operation_id: Some(op.operation_id()),
            pre_tag: op.post_state().encode_tag(),
            post_tag: op.pre_state().encode_tag(),
            backup_entry_id: backup_id.as_ref(),
            journal_to: None,
            rollback_action: Some(action),
            sequence: seq,
        })?;
        seq = seq
            .checked_add(1)
            .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
        steps.push(TrustedRollbackStep {
            step_id,
            action,
            operation_id: Some(*op.operation_id()),
            forward_step_id,
            backup_entry_id: backup_entry.map(|e| e.entry_id),
        });
    }

    if !mutating.is_empty() {
        let step_id = encode_rollback_step_id(StepIdInputs {
            role: 3,
            phase: TransactionStepPhase::Rollback,
            operation_id: None,
            pre_tag: 0,
            post_tag: 0,
            backup_entry_id: None,
            journal_to: None,
            rollback_action: Some(RollbackAction::VerifyRollbackState),
            sequence: seq,
        })?;
        steps.push(TrustedRollbackStep {
            step_id,
            action: RollbackAction::VerifyRollbackState,
            operation_id: None,
            forward_step_id: forward[0].step_id,
            backup_entry_id: None,
        });
    }

    validate_rollback_dependencies(&ordered, &steps, backup)?;

    if steps.len() > max_steps {
        return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
            limit: "max_transaction_steps",
        });
    }
    Ok(steps)
}

fn validate_rollback_dependencies(
    ordered_ops: &[&TrustedApplyOperation],
    steps: &[TrustedRollbackStep],
    backup: &TrustedBackupPlan,
) -> Result<()> {
    let mutating_steps: Vec<&TrustedRollbackStep> = steps
        .iter()
        .filter(|s| s.action != RollbackAction::VerifyRollbackState)
        .collect();
    if mutating_steps.len() != ordered_ops.len() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
    }

    let mut seen_ops = BTreeSet::new();
    let mut seen_targets = BTreeSet::new();
    let mut recreated_dirs: BTreeSet<String> = BTreeSet::new();
    let step_index: BTreeMap<String, usize> = mutating_steps
        .iter()
        .enumerate()
        .filter_map(|(idx, step)| {
            step.operation_id
                .as_ref()
                .map(|id| (id.digest().to_string(), idx))
        })
        .collect();

    for (op, step) in ordered_ops.iter().zip(mutating_steps.iter()) {
        if op.destination().as_str().is_empty() {
            return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
        }
        let op_key = op.operation_id().digest().to_string();
        if !seen_ops.insert(op_key) {
            return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
        }
        let dest = op.destination().as_str().to_owned();
        if !seen_targets.insert(format!("{}:{dest}", kind_key(op.kind()))) {
            return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
        }

        if step.operation_id.as_ref().map(|id| id.digest()) != Some(op.operation_id().digest()) {
            return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
        }

        match (op.kind(), step.action) {
            (TrustedApplyOperationKind::InstallFile, RollbackAction::RemoveInstalledFile)
            | (TrustedApplyOperationKind::ReplaceFile, RollbackAction::RestoreInstalledFile)
            | (TrustedApplyOperationKind::DeleteFile, RollbackAction::RestoreInstalledFile)
            | (
                TrustedApplyOperationKind::CreateDirectory,
                RollbackAction::RemoveCreatedDirectory,
            )
            | (
                TrustedApplyOperationKind::RemoveDirectory,
                RollbackAction::RecreateDirectoryWithMetadata,
            ) => {}
            _ => return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid),
        }

        if op.backup_requirement() != ApplyBackupRequirement::None {
            let has = backup
                .entries
                .iter()
                .any(|e| e.operation_id.digest() == op.operation_id().digest());
            if !has || step.backup_entry_id.is_none() {
                return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
            }
        }

        match step.action {
            RollbackAction::RecreateDirectoryWithMetadata => {
                for parent in parents_of(&dest) {
                    let parent_also_removed = ordered_ops.iter().any(|other| {
                        other.kind() == TrustedApplyOperationKind::RemoveDirectory
                            && other.destination().as_str() == parent
                    });
                    if parent_also_removed && !recreated_dirs.contains(parent) {
                        return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
                    }
                }
                recreated_dirs.insert(dest.clone());
            }
            RollbackAction::RestoreInstalledFile => {
                for parent in parents_of(&dest) {
                    let parent_removed = ordered_ops.iter().any(|other| {
                        other.kind() == TrustedApplyOperationKind::RemoveDirectory
                            && other.destination().as_str() == parent
                    });
                    if parent_removed && !recreated_dirs.contains(parent) {
                        return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
                    }
                }
            }
            RollbackAction::RemoveCreatedDirectory => {
                let dir_idx = *step_index
                    .get(&op.operation_id().digest().to_string())
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid)?;
                for other in ordered_ops {
                    let child = other.destination().as_str();
                    let is_desc = child.starts_with(&(dest.clone() + "/"));
                    if !is_desc {
                        continue;
                    }
                    if other.kind() == TrustedApplyOperationKind::CreateDirectory
                        || matches!(
                            other.kind(),
                            TrustedApplyOperationKind::InstallFile
                                | TrustedApplyOperationKind::ReplaceFile
                        )
                    {
                        let child_idx = *step_index
                            .get(&other.operation_id().digest().to_string())
                            .ok_or(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid)?;
                        if child_idx >= dir_idx {
                            return Err(
                                GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid,
                            );
                        }
                    }
                }
            }
            RollbackAction::RemoveInstalledFile => {}
            RollbackAction::VerifyRollbackState => {
                return Err(GkrmError::TrustedTransactionalApplyPlanningRollbackInvalid);
            }
        }
    }

    Ok(())
}

fn kind_key(kind: TrustedApplyOperationKind) -> u8 {
    match kind {
        TrustedApplyOperationKind::CreateDirectory => 0,
        TrustedApplyOperationKind::InstallFile => 1,
        TrustedApplyOperationKind::ReplaceFile => 2,
        TrustedApplyOperationKind::DeleteFile => 3,
        TrustedApplyOperationKind::RemoveDirectory => 4,
    }
}

fn parents_of(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut idx = path.len();
    while let Some(slash) = path[..idx].rfind('/') {
        out.push(&path[..slash]);
        idx = slash;
    }
    out.reverse();
    out
}

fn filter_phase<'a>(
    mutating: &[&'a TrustedApplyOperation],
    phase: TrustedApplyOperationPhase,
) -> Vec<&'a TrustedApplyOperation> {
    mutating
        .iter()
        .copied()
        .filter(|op| op.phase() == phase)
        .collect()
}

fn sort_deep_first(ops: &mut [&TrustedApplyOperation]) {
    ops.sort_by(|a, b| {
        path_depth(b.destination().as_str())
            .cmp(&path_depth(a.destination().as_str()))
            .then(b.destination().as_str().cmp(a.destination().as_str()))
    });
}

fn sort_shallow_first(ops: &mut [&TrustedApplyOperation]) {
    ops.sort_by(|a, b| {
        path_depth(a.destination().as_str())
            .cmp(&path_depth(b.destination().as_str()))
            .then(a.destination().as_str().cmp(b.destination().as_str()))
    });
}

fn map_rollback_action(op: &TrustedApplyOperation) -> RollbackAction {
    match op.kind() {
        TrustedApplyOperationKind::InstallFile => RollbackAction::RemoveInstalledFile,
        TrustedApplyOperationKind::ReplaceFile | TrustedApplyOperationKind::DeleteFile => {
            RollbackAction::RestoreInstalledFile
        }
        TrustedApplyOperationKind::CreateDirectory => RollbackAction::RemoveCreatedDirectory,
        TrustedApplyOperationKind::RemoveDirectory => RollbackAction::RecreateDirectoryWithMetadata,
    }
}

fn path_depth(path: &str) -> usize {
    path.split('/').count()
}

#[cfg(test)]
mod dependency_tests {
    use super::parents_of;

    #[test]
    fn parents_of_orders_shallow_to_deep() {
        assert_eq!(parents_of("a/b/c"), vec!["a", "a/b"]);
        assert!(parents_of("leaf").is_empty());
    }
}
