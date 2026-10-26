//! Deterministic ID encoding for trusted apply planning.

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest};

use super::tree::ApplyFileState;
use super::{
    ApplyBackupRequirement, TrustedApplyBackupSetId, TrustedApplyOperation,
    TrustedApplyOperationId, TrustedApplyOperationKind, TrustedApplyOperationPhase,
    TrustedApplyPlanId, TrustedApplyStatus, TrustedApplySummary,
};

pub(crate) struct OperationIdInputs<'a> {
    pub(crate) bundle_id: &'a Sha256Digest,
    pub(crate) manifest_id: &'a Sha256Digest,
    pub(crate) phase: TrustedApplyOperationPhase,
    pub(crate) kind: TrustedApplyOperationKind,
    pub(crate) destination: &'a ResourceRelativePath,
    pub(crate) pre: &'a ApplyFileState,
    pub(crate) post: &'a ApplyFileState,
    pub(crate) binding_tag: u8,
    pub(crate) backup: ApplyBackupRequirement,
}

pub(crate) fn encode_operation_id(input: OperationIdInputs<'_>) -> Result<TrustedApplyOperationId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-apply-operation-v1")
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.digest(input.bundle_id);
    enc.digest(input.manifest_id);
    enc.u8(phase_tag(input.phase));
    enc.u8(kind_tag(input.kind));
    enc.path(input.destination)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    encode_state(&mut enc, input.pre)?;
    encode_state(&mut enc, input.post)?;
    enc.u8(input.binding_tag);
    enc.u8(backup_tag(input.backup));
    Ok(TrustedApplyOperationId(enc.finish()))
}

pub(crate) fn encode_backup_set_id(
    operations: &[TrustedApplyOperation],
) -> Result<TrustedApplyBackupSetId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-apply-backup-set-v1")
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    let relevant: Vec<_> = operations
        .iter()
        .filter(|o| o.backup_requirement != ApplyBackupRequirement::None)
        .collect();
    enc.usize(relevant.len())
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    for op in relevant {
        enc.digest(op.operation_id.digest());
        enc.u8(backup_tag(op.backup_requirement));
        enc.u8(kind_tag(op.kind));
        enc.path(&op.destination)
            .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    }
    Ok(TrustedApplyBackupSetId(enc.finish()))
}

pub(super) struct PlanIdInputs<'a> {
    pub(super) plan_id: &'a Sha256Digest,
    pub(super) review_id: &'a Sha256Digest,
    pub(super) analysis_id: Option<&'a Sha256Digest>,
    pub(super) text_diff_id: Option<&'a Sha256Digest>,
    pub(super) synthesis_id: Option<&'a Sha256Digest>,
    pub(super) merged_bytes_id: Option<&'a Sha256Digest>,
    pub(super) bundle_id: &'a Sha256Digest,
    pub(super) manifest_id: &'a Sha256Digest,
    pub(super) resource_key: &'a str,
    pub(super) baseline_id: &'a str,
    pub(super) installed_fp: &'a Sha256Digest,
    pub(super) incoming_package_fp: &'a Sha256Digest,
    pub(super) incoming_resource_fp: &'a Sha256Digest,
    pub(super) options_tag: &'a [u8],
    pub(super) installed_tree_snapshot_fingerprint: &'a Sha256Digest,
    pub(super) operations: &'a [TrustedApplyOperation],
    pub(super) backup_set: &'a TrustedApplyBackupSetId,
    pub(super) summary: &'a TrustedApplySummary,
    pub(super) status: TrustedApplyStatus,
}

pub(super) fn encode_plan_id(input: PlanIdInputs<'_>) -> Result<TrustedApplyPlanId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-trusted-apply-plan-v1")
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.digest(input.plan_id);
    enc.digest(input.review_id);
    optional_digest(&mut enc, input.analysis_id);
    optional_digest(&mut enc, input.text_diff_id);
    optional_digest(&mut enc, input.synthesis_id);
    optional_digest(&mut enc, input.merged_bytes_id);
    enc.digest(input.bundle_id);
    enc.digest(input.manifest_id);
    enc.string(input.resource_key)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.string(input.baseline_id)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.digest(input.installed_fp);
    enc.digest(input.incoming_package_fp);
    enc.digest(input.incoming_resource_fp);
    enc.octet_string(input.options_tag)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.digest(input.installed_tree_snapshot_fingerprint);
    enc.usize(input.operations.len())
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    for op in input.operations {
        enc.digest(op.operation_id.digest());
    }
    enc.digest(input.backup_set.digest());
    enc.usize(input.summary.operation_count)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.create_directory_count)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.install_file_count)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.replace_file_count)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.delete_file_count)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.usize(input.summary.remove_directory_count)
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    enc.u64(input.summary.total_expected_write_bytes);
    enc.u64(input.summary.total_backup_bytes);
    enc.u8(status_tag(input.status));
    Ok(TrustedApplyPlanId(enc.finish()))
}

fn encode_state(enc: &mut CanonicalFingerprintEncoder, state: &ApplyFileState) -> Result<()> {
    enc.u8(state.encode_tag());
    match state {
        ApplyFileState::Absent => {}
        ApplyFileState::Present {
            digest,
            byte_length,
        } => {
            enc.digest(digest);
            enc.u64(*byte_length);
        }
    }
    Ok(())
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

fn phase_tag(phase: TrustedApplyOperationPhase) -> u8 {
    match phase {
        TrustedApplyOperationPhase::RemoveBlockingFile => 0,
        TrustedApplyOperationPhase::DeleteBlockingDescendant => 1,
        TrustedApplyOperationPhase::RemoveBlockingDirectory => 2,
        TrustedApplyOperationPhase::CreateDirectory => 3,
        TrustedApplyOperationPhase::WriteFile => 4,
        TrustedApplyOperationPhase::DeleteObsoleteFile => 5,
        TrustedApplyOperationPhase::RemoveObsoleteDirectory => 6,
    }
}

fn kind_tag(kind: TrustedApplyOperationKind) -> u8 {
    match kind {
        TrustedApplyOperationKind::CreateDirectory => 0,
        TrustedApplyOperationKind::InstallFile => 1,
        TrustedApplyOperationKind::ReplaceFile => 2,
        TrustedApplyOperationKind::DeleteFile => 3,
        TrustedApplyOperationKind::RemoveDirectory => 4,
    }
}

fn backup_tag(backup: ApplyBackupRequirement) -> u8 {
    match backup {
        ApplyBackupRequirement::None => 0,
        ApplyBackupRequirement::PreserveInstalledFile => 1,
        ApplyBackupRequirement::PreserveRemovedDirectoryMetadata => 2,
    }
}

fn status_tag(status: TrustedApplyStatus) -> u8 {
    match status {
        TrustedApplyStatus::ReadyForTransactionalApply => 0,
        TrustedApplyStatus::NoFilesystemChanges => 1,
    }
}
