//! Metadata-only backup planning for Task 22.

use crate::trusted_apply_planning::ApplyFileState;
use crate::{
    ApplyBackupRequirement, GkrmError, Result, TrustedApplyOperation, TrustedApplyOperationKind,
};

use super::id::{
    encode_backup_entry_id, encode_backup_plan_id, recompute_task21_backup_set_commitment,
};
use super::{TrustedBackupEntry, TrustedBackupPlan};

pub(crate) fn build_backup_plan(
    apply_plan_id: &crate::Sha256Digest,
    backup_set_id: &crate::Sha256Digest,
    operations: &[TrustedApplyOperation],
    max_backup_entries: usize,
    max_backup_bytes: u64,
) -> Result<TrustedBackupPlan> {
    let mut candidates: Vec<&TrustedApplyOperation> = operations
        .iter()
        .filter(|op| op.backup_requirement() != ApplyBackupRequirement::None)
        .collect();

    // Restore order: deepest paths first for file restores; directories after descendant files.
    candidates.sort_by(|a, b| {
        let da = path_depth(a.destination().as_str());
        let db = path_depth(b.destination().as_str());
        db.cmp(&da)
            .then(b.destination().as_str().cmp(a.destination().as_str()))
            .then(
                backup_kind_rank(a.backup_requirement())
                    .cmp(&backup_kind_rank(b.backup_requirement())),
            )
    });

    if candidates.len() > max_backup_entries {
        return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
            limit: "max_backup_entries",
        });
    }

    let mut entries = Vec::with_capacity(candidates.len());
    let mut total_backup_bytes = 0_u64;
    for (index, op) in candidates.into_iter().enumerate() {
        let restore_order = u32::try_from(index)
            .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
        let (state_tag, digest, length) = match op.backup_requirement() {
            ApplyBackupRequirement::PreserveInstalledFile => match op.pre_state() {
                ApplyFileState::Present {
                    digest,
                    byte_length,
                } => {
                    total_backup_bytes = total_backup_bytes
                        .checked_add(*byte_length)
                        .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
                    (1_u8, Some(digest), Some(*byte_length))
                }
                ApplyFileState::Absent => {
                    return Err(
                        GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete,
                    );
                }
            },
            ApplyBackupRequirement::PreserveRemovedDirectoryMetadata => {
                if !matches!(op.kind(), TrustedApplyOperationKind::RemoveDirectory) {
                    return Err(
                        GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete,
                    );
                }
                (2_u8, None, None)
            }
            ApplyBackupRequirement::None => unreachable!(),
        };

        let entry_id = encode_backup_entry_id(
            op.operation_id(),
            op.backup_requirement(),
            op.kind(),
            op.destination(),
            state_tag,
            digest,
            length,
            restore_order,
        )?;

        entries.push(TrustedBackupEntry {
            entry_id,
            operation_id: *op.operation_id(),
            operation_kind: op.kind(),
            kind: op.backup_requirement(),
            destination: op.destination().clone(),
            state_tag,
            digest: digest.copied(),
            byte_length: length,
            restore_order,
        });
    }

    if total_backup_bytes > max_backup_bytes {
        return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
            limit: "max_backup_bytes",
        });
    }

    // Task 21 backup-set commitment uses apply-plan operation order, not restore order.
    let in_apply_order: Vec<TrustedBackupEntry> = {
        let mut by_op = std::collections::BTreeMap::new();
        for entry in &entries {
            by_op.insert(entry.operation_id.digest().to_string(), entry.clone());
        }
        let mut ordered = Vec::new();
        for op in operations {
            if op.backup_requirement() == ApplyBackupRequirement::None {
                continue;
            }
            let key = op.operation_id().digest().to_string();
            let entry = by_op
                .remove(&key)
                .ok_or(GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete)?;
            ordered.push(entry);
        }
        if !by_op.is_empty() {
            return Err(GkrmError::TrustedTransactionalApplyPlanningBackupCoverageIncomplete);
        }
        ordered
    };

    let commitment = recompute_task21_backup_set_commitment(&in_apply_order)?;
    if &commitment != backup_set_id {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBackupSetMismatch);
    }

    let plan_id =
        encode_backup_plan_id(apply_plan_id, backup_set_id, &entries, total_backup_bytes)?;
    Ok(TrustedBackupPlan {
        plan_id,
        entries,
        total_backup_bytes,
        task21_backup_set_commitment: commitment,
    })
}

fn path_depth(path: &str) -> usize {
    path.split('/').count()
}

fn backup_kind_rank(kind: ApplyBackupRequirement) -> u8 {
    match kind {
        ApplyBackupRequirement::PreserveInstalledFile => 0,
        ApplyBackupRequirement::PreserveRemovedDirectoryMetadata => 1,
        ApplyBackupRequirement::None => 2,
    }
}
