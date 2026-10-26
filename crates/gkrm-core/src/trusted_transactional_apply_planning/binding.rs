//! Pre-I/O Task 14–21 binding for transactional apply planning.

use crate::trusted_apply_planning::{
    encode_backup_set_id, encode_operation_id, ApplyFileState, OperationIdInputs,
};
use crate::trusted_staging::{encode_bundle_id, StagingFinalState, TrustedStagingStatus};
use crate::{
    ApplyBackupRequirement, GkrmError, MergedByteDisposition, Result, ThreeWayPlanReviewStatus,
    ThreeWayReviewedAction, TrustedApplyOperationKind, TrustedApplyOperationPhase,
    TrustedApplyStatus, TrustedApplySummary,
};

use super::TrustedTransactionalApplyPlanningRequest;

/// A two-way apply must carry no three-way artifact at all.
fn verify_two_way_absences(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    if request.analysis.is_some()
        || request.text_diff.is_some()
        || request.synthesis.is_some()
        || request.merged_bytes.is_some()
        || request.package_free_merge_ids.is_some()
        || request.baseline.is_some()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    Ok(())
}

pub(super) fn bind_before_io(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    request.options.validate()?;
    verify_status(request)?;
    // A two-way apply carries no review, merge chain, or baseline; requiring their absence is the
    // equivalent of the three-way binding checks, which each return early for this path.
    if request.source.three_way().is_none() {
        verify_two_way_absences(request)?;
    }
    verify_plan_review_binding(request)?;
    verify_merge_chain_presence(request)?;
    verify_merge_chain_bindings(request)?;
    verify_baseline_binding(request)?;
    verify_review_completeness(request)?;
    verify_bundle_binding(request)?;
    verify_apply_plan_binding(request)?;
    verify_apply_plan_integrity(request)?;
    enforce_structural_limits(request)?;
    Ok(())
}

fn verify_status(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    match request.apply_plan.status() {
        TrustedApplyStatus::ReadyForTransactionalApply
        | TrustedApplyStatus::NoFilesystemChanges => Ok(()),
    }
}

fn verify_plan_review_binding(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<()> {
    let Some((plan, review)) = request.source.three_way() else {
        return Ok(());
    };
    if review.plan_id() != plan.plan_id()
        || review.resource_key() != plan.resource_key()
        || review.baseline_id() != plan.baseline_id()
        || review.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || review.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || review.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
        }
    }
    Ok(())
}

fn merge_required(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> bool {
    let Some((_, review)) = request.source.three_way() else {
        return false;
    };
    review
        .entries()
        .iter()
        .any(|e| e.action() == ThreeWayReviewedAction::QueueMergeAnalysis)
}

fn verify_merge_chain_presence(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<()> {
    let required = merge_required(request);
    let legacy_present = request.analysis.is_some()
        && request.text_diff.is_some()
        && request.synthesis.is_some()
        && request.package_free_merge_ids.is_none()
        && request.merged_bytes.is_some();
    let package_free_present = request.analysis.is_none()
        && request.text_diff.is_none()
        && request.synthesis.is_none()
        && request.package_free_merge_ids.is_some()
        && request.merged_bytes.is_some();
    let absent = request.analysis.is_none()
        && request.text_diff.is_none()
        && request.synthesis.is_none()
        && request.package_free_merge_ids.is_none()
        && request.merged_bytes.is_none();
    if required && !(legacy_present || package_free_present) {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    if !required && !absent {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    Ok(())
}

fn verify_merge_chain_bindings(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<()> {
    if !merge_required(request) {
        return Ok(());
    }
    let Some((plan, review)) = request.source.three_way() else {
        return Ok(());
    };
    if let Some(ids) = request.package_free_merge_ids {
        let merged_bytes = request
            .merged_bytes
            .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;
        if merged_bytes.plan_id() != plan.plan_id()
            || merged_bytes.review_id() != review.review_id()
            || merged_bytes.analysis_id().digest() != &ids.analysis_id
            || merged_bytes.text_diff_plan_id().digest() != &ids.text_diff_id
            || merged_bytes.synthesis_plan_id().digest() != &ids.synthesis_id
            || merged_bytes.merged_bytes_plan_id().digest() != &ids.merged_bytes_id
        {
            return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
        }
        return Ok(());
    }
    let analysis = request
        .analysis
        .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;
    let text_diff = request
        .text_diff
        .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;
    let synthesis = request
        .synthesis
        .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;
    let merged_bytes = request
        .merged_bytes
        .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;

    if analysis.plan_id() != plan.plan_id()
        || analysis.resource_key() != plan.resource_key()
        || analysis.baseline_id() != plan.baseline_id()
        || analysis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
        || analysis.review_id() != review.review_id()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    if text_diff.plan_id() != plan.plan_id()
        || text_diff.review_id() != review.review_id()
        || text_diff.analysis_id() != analysis.analysis_id()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    if synthesis.plan_id() != plan.plan_id()
        || synthesis.review_id() != review.review_id()
        || synthesis.analysis_id() != analysis.analysis_id()
        || synthesis.text_diff_plan_id() != text_diff.text_diff_plan_id()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    if merged_bytes.plan_id() != plan.plan_id()
        || merged_bytes.review_id() != review.review_id()
        || merged_bytes.analysis_id() != analysis.analysis_id()
        || merged_bytes.text_diff_plan_id() != text_diff.text_diff_plan_id()
        || merged_bytes.synthesis_plan_id() != synthesis.synthesis_plan_id()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    Ok(())
}

fn verify_baseline_binding(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    // A two-way apply carries no baseline at all; `verify_two_way_absences` proved its absence.
    let Some((plan, _)) = request.source.three_way() else {
        return Ok(());
    };
    let Some(baseline) = request.baseline else {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    };
    if baseline.resource_key() != plan.resource_key()
        || baseline.baseline_id() != plan.baseline_id()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    Ok(())
}

fn verify_review_completeness(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<()> {
    let Some((_, review)) = request.source.three_way() else {
        return Ok(());
    };
    if review.status() == ThreeWayPlanReviewStatus::Incomplete {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    for entry in review.entries() {
        match entry.action() {
            ThreeWayReviewedAction::Pending | ThreeWayReviewedAction::ManualReview => {
                return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
            }
            ThreeWayReviewedAction::QueueMergeAnalysis => {
                let merged = request
                    .merged_bytes
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;
                let mb = merged
                    .entries()
                    .iter()
                    .find(|e| e.path() == entry.path())
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch)?;
                match mb.disposition() {
                    MergedByteDisposition::ReadyForStaging => {
                        if mb.artifact().is_none() || mb.artifact_id().is_none() {
                            return Err(
                                GkrmError::TrustedTransactionalApplyPlanningBindingMismatch,
                            );
                        }
                    }
                    MergedByteDisposition::ManualReviewOutputLimit => {
                        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
                    }
                }
            }
            ThreeWayReviewedAction::UseIncomingState
            | ThreeWayReviewedAction::PreserveInstalledState
            | ThreeWayReviewedAction::NotRequired => {}
        }
    }
    Ok(())
}

fn verify_bundle_binding(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    let bundle = request.bundle;
    if bundle.status() != TrustedStagingStatus::ReadyForApplyPlanning {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    let manifest = bundle.manifest();
    let summary = bundle.summary();

    if manifest.plan_id_digest() != request.source.plan_id_digest()
        || manifest.review_id_digest() != request.source.review_id_digest()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }

    let expected_analysis = request.analysis_id_digest().copied();
    let expected_text = request.text_diff_id_digest().copied();
    let expected_synth = request.synthesis_id_digest().copied();
    let expected_merged = request.merged_bytes_id_digest().copied();
    if manifest.analysis_id_digest().copied() != expected_analysis
        || manifest.text_diff_id_digest().copied() != expected_text
        || manifest.synthesis_id_digest().copied() != expected_synth
        || manifest.merged_bytes_id_digest().copied() != expected_merged
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }

    if summary.total_entries() != manifest.entries().len() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }

    let mut present = 0usize;
    let mut absent = 0usize;
    for entry in manifest.entries() {
        match entry.final_state() {
            StagingFinalState::Absent => {
                absent = absent.saturating_add(1);
                if entry.expected_digest().is_some() || entry.expected_byte_length().is_some() {
                    return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
                }
            }
            StagingFinalState::Installed
            | StagingFinalState::Incoming
            | StagingFinalState::Merged => {
                present = present.saturating_add(1);
                if entry.expected_digest().is_none() || entry.expected_byte_length().is_none() {
                    return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
                }
            }
        }
    }
    if summary.present_entries() != present || summary.absent_entries() != absent {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }

    let recomputed = encode_bundle_id(manifest, summary, bundle.status())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningIdEncodingFailure)?;
    if recomputed.digest() != bundle.bundle_id().digest() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    Ok(())
}

fn verify_apply_plan_binding(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    let apply = request.apply_plan;
    if apply.bundle_id().digest() != request.bundle.bundle_id().digest()
        || apply.manifest_id().digest() != request.bundle.manifest().manifest_id().digest()
    {
        return Err(GkrmError::TrustedTransactionalApplyPlanningBindingMismatch);
    }
    match apply.status() {
        TrustedApplyStatus::NoFilesystemChanges => {
            if !apply.operations().is_empty()
                || apply.summary().operation_count != 0
                || apply.summary().total_expected_write_bytes != 0
                || apply.summary().total_backup_bytes != 0
            {
                return Err(GkrmError::TrustedTransactionalApplyPlanningStatusInvalid);
            }
        }
        TrustedApplyStatus::ReadyForTransactionalApply if apply.operations().is_empty() => {
            return Err(GkrmError::TrustedTransactionalApplyPlanningStatusInvalid);
        }
        TrustedApplyStatus::ReadyForTransactionalApply => {}
    }
    Ok(())
}

fn verify_apply_plan_integrity(
    request: &TrustedTransactionalApplyPlanningRequest<'_>,
) -> Result<()> {
    let apply = request.apply_plan;
    let bundle_id = request.bundle.bundle_id();
    let manifest_id = request.bundle.manifest().manifest_id();

    let mut create_directory_count = 0usize;
    let mut install_file_count = 0usize;
    let mut replace_file_count = 0usize;
    let mut delete_file_count = 0usize;
    let mut remove_directory_count = 0usize;
    let mut total_write_bytes = 0_u64;
    let mut total_backup_bytes = 0_u64;

    let mut prev_phase_ord = 0_u8;
    for op in apply.operations() {
        let phase_ord = phase_ordinal(op.phase());
        if phase_ord < prev_phase_ord {
            return Err(GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch);
        }
        prev_phase_ord = phase_ord;

        let recomputed = encode_operation_id(OperationIdInputs {
            bundle_id: bundle_id.digest(),
            manifest_id: manifest_id.digest(),
            phase: op.phase(),
            kind: op.kind(),
            destination: op.destination(),
            pre: op.pre_state(),
            post: op.post_state(),
            binding_tag: op.staged_binding_tag(),
            backup: op.backup_requirement(),
        })
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch)?;
        if recomputed.digest() != op.operation_id().digest() {
            return Err(GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch);
        }

        match op.kind() {
            TrustedApplyOperationKind::CreateDirectory => {
                create_directory_count = create_directory_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::InstallFile => {
                install_file_count = install_file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::ReplaceFile => {
                replace_file_count = replace_file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::DeleteFile => {
                delete_file_count = delete_file_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
            TrustedApplyOperationKind::RemoveDirectory => {
                remove_directory_count = remove_directory_count
                    .checked_add(1)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
        }

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
        if op.backup_requirement() == ApplyBackupRequirement::PreserveInstalledFile {
            if let Some(len) = op.pre_state().length_opt() {
                total_backup_bytes = total_backup_bytes
                    .checked_add(len)
                    .ok_or(GkrmError::TrustedTransactionalApplyPlanningArithmeticOverflow)?;
            }
        }

        let _ = ApplyFileState::Absent;
    }

    let summary = apply.summary();
    if !summary_matches(
        summary,
        apply.operations().len(),
        create_directory_count,
        install_file_count,
        replace_file_count,
        delete_file_count,
        remove_directory_count,
        total_write_bytes,
        total_backup_bytes,
    ) {
        return Err(GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch);
    }

    let backup_set = encode_backup_set_id(apply.operations())
        .map_err(|_| GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch)?;
    if backup_set.digest() != apply.backup_set_id().digest() {
        return Err(GkrmError::TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch);
    }
    Ok(())
}

fn summary_matches(
    summary: &TrustedApplySummary,
    operation_count: usize,
    create_directory_count: usize,
    install_file_count: usize,
    replace_file_count: usize,
    delete_file_count: usize,
    remove_directory_count: usize,
    total_write_bytes: u64,
    total_backup_bytes: u64,
) -> bool {
    summary.operation_count == operation_count
        && summary.create_directory_count == create_directory_count
        && summary.install_file_count == install_file_count
        && summary.replace_file_count == replace_file_count
        && summary.delete_file_count == delete_file_count
        && summary.remove_directory_count == remove_directory_count
        && summary.total_expected_write_bytes == total_write_bytes
        && summary.total_backup_bytes == total_backup_bytes
}

fn phase_ordinal(phase: TrustedApplyOperationPhase) -> u8 {
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

fn enforce_structural_limits(request: &TrustedTransactionalApplyPlanningRequest<'_>) -> Result<()> {
    let opts = request.options;
    let ops = request.apply_plan.operations();
    if ops.len() > opts.max_operations {
        return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
            limit: "max_operations",
        });
    }
    for op in ops {
        let depth = op.destination().as_str().split('/').count();
        if depth > opts.max_path_depth {
            return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
                limit: "max_path_depth",
            });
        }
        for component in op.destination().as_str().split('/') {
            if component.len() > opts.max_path_component_bytes {
                return Err(GkrmError::TrustedTransactionalApplyPlanningLimitExceeded {
                    limit: "max_path_component_bytes",
                });
            }
        }
    }
    Ok(())
}
