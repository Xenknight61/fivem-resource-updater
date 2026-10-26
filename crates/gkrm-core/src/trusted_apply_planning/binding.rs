//! Pre-I/O Task 14–20 binding for apply planning.

use crate::{
    GkrmError, MergedByteDisposition, Result, ThreeWayPlanReviewStatus, ThreeWayReviewedAction,
};

use super::TrustedApplyPlanningRequest;

pub(super) fn bind_before_io(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    request.options.validate()?;
    // Only a three-way plan has a review, a merge chain, and a baseline to bind. A two-way plan
    // carries none of them, so requiring their absence is the equivalent check: a bundle that
    // arrived with merge-chain identifiers was not produced by this path.
    match request.source.three_way() {
        Some(_) => {
            verify_plan_review_binding(request)?;
            verify_merge_chain_presence(request)?;
            verify_merge_chain_bindings(request)?;
            verify_baseline_binding(request)?;
            verify_review_completeness(request)?;
        }
        None => verify_two_way_absences(request)?,
    }
    verify_bundle_binding(request)?;
    enforce_structural_limits(request)?;
    Ok(())
}

/// A two-way apply must carry no three-way artifact at all.
fn verify_two_way_absences(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    if request.analysis.is_some()
        || request.text_diff.is_some()
        || request.synthesis.is_some()
        || request.merged_bytes.is_some()
        || request.package_free_merge_ids.is_some()
        || request.baseline.is_some()
    {
        return Err(GkrmError::TrustedApplyPlanningPlanReviewBindingMismatch);
    }
    Ok(())
}

fn verify_plan_review_binding(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
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
        return Err(GkrmError::TrustedApplyPlanningPlanReviewBindingMismatch);
    }
    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::TrustedApplyPlanningPlanReviewBindingMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::TrustedApplyPlanningPlanReviewBindingMismatch);
        }
    }
    Ok(())
}

fn merge_required(request: &TrustedApplyPlanningRequest<'_>) -> bool {
    let Some((_, review)) = request.source.three_way() else {
        return false;
    };
    review
        .entries()
        .iter()
        .any(|e| e.action() == ThreeWayReviewedAction::QueueMergeAnalysis)
}

fn verify_merge_chain_presence(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
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
        return Err(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch);
    }
    if !required && !absent {
        return Err(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch);
    }
    Ok(())
}

fn verify_merge_chain_bindings(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    if !merge_required(request) {
        return Ok(());
    }
    let Some((plan, review)) = request.source.three_way() else {
        return Ok(());
    };
    if let Some(ids) = request.package_free_merge_ids {
        let merged_bytes = request
            .merged_bytes
            .ok_or(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch)?;
        if merged_bytes.plan_id() != plan.plan_id()
            || merged_bytes.review_id() != review.review_id()
            || merged_bytes.analysis_id().digest() != &ids.analysis_id
            || merged_bytes.text_diff_plan_id().digest() != &ids.text_diff_id
            || merged_bytes.synthesis_plan_id().digest() != &ids.synthesis_id
            || merged_bytes.merged_bytes_plan_id().digest() != &ids.merged_bytes_id
        {
            return Err(GkrmError::TrustedApplyPlanningMergeChainBindingMismatch);
        }
        return Ok(());
    }
    let analysis = request
        .analysis
        .ok_or(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch)?;
    let text_diff = request
        .text_diff
        .ok_or(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch)?;
    let synthesis = request
        .synthesis
        .ok_or(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch)?;
    let merged_bytes = request
        .merged_bytes
        .ok_or(GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch)?;

    if analysis.plan_id() != plan.plan_id()
        || analysis.resource_key() != plan.resource_key()
        || analysis.baseline_id() != plan.baseline_id()
        || analysis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
        || analysis.review_id() != review.review_id()
    {
        return Err(GkrmError::TrustedApplyPlanningMergeChainBindingMismatch);
    }
    if text_diff.plan_id() != plan.plan_id()
        || text_diff.review_id() != review.review_id()
        || text_diff.analysis_id() != analysis.analysis_id()
    {
        return Err(GkrmError::TrustedApplyPlanningMergeChainBindingMismatch);
    }
    if synthesis.plan_id() != plan.plan_id()
        || synthesis.review_id() != review.review_id()
        || synthesis.analysis_id() != analysis.analysis_id()
        || synthesis.text_diff_plan_id() != text_diff.text_diff_plan_id()
    {
        return Err(GkrmError::TrustedApplyPlanningMergeChainBindingMismatch);
    }
    if merged_bytes.plan_id() != plan.plan_id()
        || merged_bytes.review_id() != review.review_id()
        || merged_bytes.analysis_id() != analysis.analysis_id()
        || merged_bytes.text_diff_plan_id() != text_diff.text_diff_plan_id()
        || merged_bytes.synthesis_plan_id() != synthesis.synthesis_plan_id()
    {
        return Err(GkrmError::TrustedApplyPlanningMergeChainBindingMismatch);
    }
    Ok(())
}

fn verify_baseline_binding(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    let (Some((plan, _)), Some(baseline)) = (request.source.three_way(), request.baseline) else {
        return Err(GkrmError::TrustedApplyPlanningBaselineMismatch);
    };
    if baseline.resource_key() != plan.resource_key()
        || baseline.baseline_id() != plan.baseline_id()
    {
        return Err(GkrmError::TrustedApplyPlanningBaselineMismatch);
    }
    Ok(())
}

fn verify_review_completeness(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    let Some((_, review)) = request.source.three_way() else {
        return Ok(());
    };
    if review.status() == ThreeWayPlanReviewStatus::Incomplete {
        return Err(GkrmError::TrustedApplyPlanningReviewUnresolved);
    }
    for entry in review.entries() {
        match entry.action() {
            ThreeWayReviewedAction::Pending | ThreeWayReviewedAction::ManualReview => {
                return Err(GkrmError::TrustedApplyPlanningReviewUnresolved);
            }
            ThreeWayReviewedAction::QueueMergeAnalysis => {
                let merged = request
                    .merged_bytes
                    .ok_or(GkrmError::TrustedApplyPlanningMissingMergedArtifact)?;
                let mb = merged
                    .entries()
                    .iter()
                    .find(|e| e.path() == entry.path())
                    .ok_or(GkrmError::TrustedApplyPlanningMissingMergedArtifact)?;
                match mb.disposition() {
                    MergedByteDisposition::ReadyForStaging => {
                        if mb.artifact().is_none() || mb.artifact_id().is_none() {
                            return Err(GkrmError::TrustedApplyPlanningMissingMergedArtifact);
                        }
                    }
                    MergedByteDisposition::ManualReviewOutputLimit => {
                        return Err(GkrmError::TrustedApplyPlanningManualMergeResult);
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

fn verify_bundle_binding(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    use crate::trusted_staging::{encode_bundle_id, StagingFinalState, TrustedStagingStatus};

    let bundle = request.bundle;
    if bundle.status() != TrustedStagingStatus::ReadyForApplyPlanning {
        return Err(GkrmError::TrustedApplyPlanningBundleStatusInvalid);
    }
    let manifest = bundle.manifest();
    let summary = bundle.summary();

    if manifest.plan_id_digest() != request.source.plan_id_digest()
        || manifest.review_id_digest() != request.source.review_id_digest()
    {
        return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
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
        return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
    }

    if summary.total_entries() != manifest.entries().len() {
        return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
    }

    let mut present = 0usize;
    let mut absent = 0usize;
    for entry in manifest.entries() {
        match entry.final_state() {
            StagingFinalState::Absent => {
                absent = absent.saturating_add(1);
                if entry.expected_digest().is_some() || entry.expected_byte_length().is_some() {
                    return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
                }
            }
            StagingFinalState::Installed
            | StagingFinalState::Incoming
            | StagingFinalState::Merged => {
                present = present.saturating_add(1);
                if entry.expected_digest().is_none() || entry.expected_byte_length().is_none() {
                    return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
                }
            }
        }
    }
    if summary.present_entries() != present || summary.absent_entries() != absent {
        return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
    }

    let recomputed = encode_bundle_id(manifest, summary, bundle.status())
        .map_err(|_| GkrmError::TrustedApplyPlanningIdEncodingFailure)?;
    if recomputed.digest() != bundle.bundle_id().digest() {
        return Err(GkrmError::TrustedApplyPlanningBundleBindingMismatch);
    }
    Ok(())
}

fn enforce_structural_limits(request: &TrustedApplyPlanningRequest<'_>) -> Result<()> {
    let opts = request.options;
    let entries = request.bundle.manifest().entries();
    if entries.len() > opts.max_entries {
        return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
            limit: "max_entries",
        });
    }
    for entry in entries {
        let depth = entry.path().as_str().split('/').count();
        if depth > opts.max_path_depth {
            return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
                limit: "max_path_depth",
            });
        }
        for component in entry.path().as_str().split('/') {
            if component.len() > opts.max_path_component_bytes {
                return Err(GkrmError::TrustedApplyPlanningLimitExceeded {
                    limit: "max_path_component_bytes",
                });
            }
        }
    }
    Ok(())
}
