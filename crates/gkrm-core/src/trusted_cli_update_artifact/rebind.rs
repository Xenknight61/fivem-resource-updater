//! Shared live-authority rebuild and exact CLI artifact comparison for apply/recover.

use std::path::Path;

use crate::trusted_apply_planning::{
    plan_trusted_apply, InstalledApplyPlanningSource, TrustedApplyPlan,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest,
};
use crate::trusted_recovery_authority::{build_recovery_authority_body, RecoveryAuthorityLimits};
use crate::trusted_staging::{
    reopen_trusted_staging_bundle, IncomingStagingContentSource, InstalledStagingContentSource,
    TrustedStagingBundle, TrustedStagingOperatorMergeInput, TrustedStagingOptions,
    TrustedStagingRequest, TrustedStagingRoot,
};
use crate::trusted_transactional_apply_planning::{
    plan_trusted_transactional_apply, TrustedTransactionalApplyPlan,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
};
use crate::{
    analyze_queued_three_way_merges, create_three_way_update_plan, inspect_installation_update,
    plan_three_way_merge_synthesis, plan_three_way_text_diffs, resolve_official_baseline,
    review_three_way_update_plan, synthesize_three_way_merged_bytes, BaselineResolutionOptions,
    BaselineResolutionRequest, GkrmError, IncomingMergeContentSource,
    IncomingMergeContentSourceLimits, InspectionOptions, InstalledMergeContentSource,
    InstalledScanLimits, OfficialBaselineSelector, ResolvedOfficialBaseline, Result,
    SafeResourceKey, Sha256Digest, ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisPlan,
    ThreeWayMergeAnalysisRequest, ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisPlan,
    ThreeWayMergeSynthesisRequest, ThreeWayMergedBytesOptions, ThreeWayMergedBytesPlan,
    ThreeWayMergedBytesRequest, ThreeWayPlanReview, ThreeWayPlanReviewRequest,
    ThreeWayPlannerOptions, ThreeWayReviewedAction, ThreeWayTextDiffOptions, ThreeWayTextDiffPlan,
    ThreeWayTextDiffRequest, ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest,
};

use super::artifact::{encode_body, TrustedCliUpdateArtifact, TrustedCliUpdateArtifactBody};
use super::decisions::{
    build_decision_document, parse_decision_document, TrustedCliDecisionDocument,
};
use super::id::encode_operator_merge_set_id;
use super::limits::TrustedCliUpdateOptions;
use super::operator_merge::{
    build_operator_merge_set, validate_and_load_operator_merge_root, TrustedOperatorMergeSet,
};
use super::publish::read_regular_file_limited;
use super::resource::{
    resolve_selected_resource, snapshots_for_selection, SelectedPackageResource,
};

/// Live roots and inputs used to rebuild Task 14–22 authority for apply/recover.
pub(crate) struct TrustedCliUpdateRebindRequest<'a> {
    pub package: &'a Path,
    pub installed: &'a Path,
    pub baseline_store: &'a Path,
    pub baseline_selector: OfficialBaselineSelector,
    pub resource: Option<&'a SafeResourceKey>,
    pub staging_root: &'a Path,
    pub decisions_path: Option<&'a Path>,
    pub operator_merge_root: Option<&'a Path>,
    pub recovery_authority: bool,
    pub options: TrustedCliUpdateOptions,
}

/// Rebuilt live chain plus the exact commitment body compared to the CLI artifact.
pub(crate) struct RebuiltTrustedCliUpdateAuthority {
    pub commitments: TrustedCliUpdateArtifactBody,
    pub selected: SelectedPackageResource,
    pub baseline: ResolvedOfficialBaseline,
    pub plan: ThreeWayUpdatePlan,
    #[allow(dead_code)] // retained so decision bytes stay owned for the rebuild lifetime
    pub decisions: TrustedCliDecisionDocument,
    pub review: ThreeWayPlanReview,
    pub analysis: Option<ThreeWayMergeAnalysisPlan>,
    pub text_diff: Option<ThreeWayTextDiffPlan>,
    pub synthesis: Option<ThreeWayMergeSynthesisPlan>,
    pub merged_bytes: Option<ThreeWayMergedBytesPlan>,
    #[allow(dead_code)] // retained so operator merge bytes zeroize on drop after staging reopen
    pub operator_set: TrustedOperatorMergeSet,
    pub bundle: TrustedStagingBundle,
    pub apply_plan: TrustedApplyPlan,
    pub tx_plan: TrustedTransactionalApplyPlan,
    pub installed_apply: InstalledApplyPlanningSource,
}

/// Securely recompute Task 14–22 authority from live inputs without staging mutation.
pub(crate) fn rebuild_trusted_cli_update_authority(
    request: &TrustedCliUpdateRebindRequest<'_>,
) -> Result<RebuiltTrustedCliUpdateAuthority> {
    let options = request.options.validate()?;
    let report = inspect_installation_update(
        request.installed,
        request.package,
        InspectionOptions::default(),
    )?;
    let selected = resolve_selected_resource(&report, request.resource)?;
    let baseline = resolve_official_baseline(BaselineResolutionRequest::try_new(
        request.baseline_store,
        &selected.resource_key,
        request.baseline_selector.clone(),
        BaselineResolutionOptions::default(),
    )?)?;
    let baseline_digest = Sha256Digest::from_lowercase_hex(baseline.baseline_id().as_str())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;

    let (installed_snap, incoming_snap) = snapshots_for_selection(&report, &selected)?;
    let plan = create_three_way_update_plan(ThreeWayUpdatePlanRequest::try_new(
        &baseline,
        &installed_snap,
        &incoming_snap,
        ThreeWayPlannerOptions::default(),
    )?)?;

    let decisions = match request.decisions_path {
        Some(path) => {
            let dbytes = read_regular_file_limited(path, options.max_decision_document_bytes)?;
            parse_decision_document(&plan, &dbytes, &options)?
        }
        None => build_decision_document(&plan, Vec::new(), &options)?,
    };
    let review = review_three_way_update_plan(ThreeWayPlanReviewRequest::try_new(
        &plan,
        &decisions.to_decision_set()?,
    )?)?;

    let needs_merge = review
        .entries()
        .iter()
        .any(|e| e.action() == ThreeWayReviewedAction::QueueMergeAnalysis);
    let installed_merge = InstalledMergeContentSource::try_new(
        request.installed,
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_merge = IncomingMergeContentSource::try_new(
        request.package,
        selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;
    let (analysis, text_diff, synthesis, merged_bytes) = if needs_merge {
        let analysis = analyze_queued_three_way_merges(ThreeWayMergeAnalysisRequest::try_new(
            &plan,
            &review,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayMergeAnalysisOptions::default(),
        )?)?;
        let text_diff = plan_three_way_text_diffs(ThreeWayTextDiffRequest::try_new(
            &plan,
            &review,
            &analysis,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayTextDiffOptions::default(),
        )?)?;
        let synthesis = plan_three_way_merge_synthesis(ThreeWayMergeSynthesisRequest::try_new(
            &plan,
            &review,
            &analysis,
            &text_diff,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayMergeSynthesisOptions::default(),
        )?)?;
        let merged = synthesize_three_way_merged_bytes(ThreeWayMergedBytesRequest::try_new(
            &plan,
            &review,
            &analysis,
            &text_diff,
            &synthesis,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayMergedBytesOptions::default(),
        )?)?;
        (
            Some(analysis),
            Some(text_diff),
            Some(synthesis),
            Some(merged),
        )
    } else {
        (None, None, None, None)
    };

    let mut operator_relpaths = Vec::new();
    for entry in decisions.entries() {
        if let Some(rel) = &entry.operator_merge_relpath {
            operator_relpaths.push(rel.clone());
        }
    }
    let operator_set = if let Some(merge_root) = request.operator_merge_root {
        validate_and_load_operator_merge_root(
            merge_root,
            &operator_relpaths,
            plan.plan_id(),
            review.review_id(),
            &options,
        )?
    } else if operator_relpaths.is_empty() {
        build_operator_merge_set(Vec::new(), &options)?
    } else {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    };

    let expected_op_set_id = if operator_set.artifacts().is_empty() {
        encode_operator_merge_set_id(&[])?
    } else {
        *operator_set.set_id()
    };
    let op_inputs: Vec<TrustedStagingOperatorMergeInput<'_>> = operator_set
        .artifacts()
        .iter()
        .map(|a| TrustedStagingOperatorMergeInput {
            path: a.path(),
            artifact_id: *a.artifact_id().digest(),
            content_digest: *a.digest_for_staging(),
            bytes: a.bytes_for_staging(),
        })
        .collect();

    let staging_root = TrustedStagingRoot::try_open(request.staging_root)?;
    let installed_staging = InstalledStagingContentSource::try_new(
        request.installed,
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_staging = IncomingStagingContentSource::try_new(
        request.package,
        selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;
    let bundle = reopen_trusted_staging_bundle(
        TrustedStagingRequest::try_new(
            &plan,
            &review,
            analysis.as_ref(),
            text_diff.as_ref(),
            synthesis.as_ref(),
            merged_bytes.as_ref(),
            &baseline,
            &installed_staging,
            &incoming_staging,
            &staging_root,
            TrustedStagingOptions::default(),
        )?
        .with_operator_merges(&op_inputs),
    )?;

    let installed_apply = InstalledApplyPlanningSource::try_new(
        request.installed,
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let apply_plan = plan_trusted_apply(TrustedApplyPlanningRequest::try_new(
        &bundle,
        &plan,
        &review,
        analysis.as_ref(),
        text_diff.as_ref(),
        synthesis.as_ref(),
        merged_bytes.as_ref(),
        &baseline,
        &installed_apply,
        TrustedApplyPlanningOptions::default(),
    )?)?;
    let snapshot = installed_apply
        .capture_tree_snapshot(plan.resource_key())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let snapshot_a = snapshot.fingerprint;
    let tx_plan =
        plan_trusted_transactional_apply(TrustedTransactionalApplyPlanningRequest::try_new(
            &apply_plan,
            &bundle,
            &plan,
            &review,
            analysis.as_ref(),
            text_diff.as_ref(),
            synthesis.as_ref(),
            merged_bytes.as_ref(),
            &baseline,
            &installed_apply,
            TrustedTransactionalApplyPlanningOptions::default(),
        )?)?;

    let recovery_authority_id = if request.recovery_authority {
        let (authority_body, authority_id) = build_recovery_authority_body(
            &installed_apply,
            &selected.resource_key,
            baseline_digest,
            *bundle.manifest().manifest_id().digest(),
            *bundle.bundle_id().digest(),
            *apply_plan.plan_id().digest(),
            *tx_plan.plan_id().digest(),
            &snapshot,
            RecoveryAuthorityLimits::default(),
        )?;
        if authority_body.selected_resource_commitment != selected.resource_commitment {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        Some(*authority_id.digest())
    } else {
        None
    };

    let commitments = TrustedCliUpdateArtifactBody {
        package_fingerprint: *report.incoming_package_fingerprint(),
        selected_resource_commitment: selected.resource_commitment,
        baseline_id_digest: baseline_digest,
        plan_id: *plan.plan_id().digest(),
        review_id: *review.review_id().digest(),
        analysis_id: analysis.as_ref().map(|a| *a.analysis_id().digest()),
        text_diff_id: text_diff.as_ref().map(|t| *t.text_diff_plan_id().digest()),
        synthesis_id: synthesis.as_ref().map(|s| *s.synthesis_plan_id().digest()),
        merged_bytes_id: merged_bytes
            .as_ref()
            .map(|m| *m.merged_bytes_plan_id().digest()),
        operator_merge_set_id: expected_op_set_id,
        staging_manifest_id: *bundle.manifest().manifest_id().digest(),
        staging_bundle_id: *bundle.bundle_id().digest(),
        apply_plan_id: *apply_plan.plan_id().digest(),
        snapshot_a,
        transactional_plan_id: *tx_plan.plan_id().digest(),
        recovery_authority_id,
        decision_document_id: *decisions.document_id().digest(),
    };

    Ok(RebuiltTrustedCliUpdateAuthority {
        commitments,
        selected,
        baseline,
        plan,
        decisions,
        review,
        analysis,
        text_diff,
        synthesis,
        merged_bytes,
        operator_set,
        bundle,
        apply_plan,
        tx_plan,
        installed_apply,
    })
}

/// Exact comparison of every CLI artifact commitment against the live rebuild.
///
/// Optional Task 16–19 fields use exact presence matching (Some/None must agree).
pub(crate) fn require_cli_artifact_matches_live_authority(
    artifact: &TrustedCliUpdateArtifact,
    live: &RebuiltTrustedCliUpdateAuthority,
) -> Result<()> {
    // Aggregate body digest comparison fails closed when any committed field drifts,
    // including newly added body fields that participate in `encode_body`.
    let artifact_digest = encode_body(artifact.body())?;
    let live_digest = encode_body(&live.commitments)?;
    if artifact_digest != live_digest || artifact.body() != &live.commitments {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod completeness_tests {
    use super::*;
    use crate::Sha256Digest;

    fn sample_body() -> TrustedCliUpdateArtifactBody {
        TrustedCliUpdateArtifactBody {
            package_fingerprint: Sha256Digest::new([1; 32]),
            selected_resource_commitment: Sha256Digest::new([2; 32]),
            baseline_id_digest: Sha256Digest::new([3; 32]),
            plan_id: Sha256Digest::new([4; 32]),
            review_id: Sha256Digest::new([5; 32]),
            analysis_id: None,
            text_diff_id: None,
            synthesis_id: None,
            merged_bytes_id: None,
            operator_merge_set_id: Sha256Digest::new([6; 32]),
            staging_manifest_id: Sha256Digest::new([7; 32]),
            staging_bundle_id: Sha256Digest::new([8; 32]),
            apply_plan_id: Sha256Digest::new([9; 32]),
            snapshot_a: Sha256Digest::new([10; 32]),
            transactional_plan_id: Sha256Digest::new([11; 32]),
            recovery_authority_id: None,
            decision_document_id: Sha256Digest::new([12; 32]),
        }
    }

    #[test]
    fn encode_body_digest_changes_when_any_committed_field_changes() {
        let base = sample_body();
        let base_digest = encode_body(&base).unwrap();
        let mut changed = sample_body();
        changed.package_fingerprint = Sha256Digest::new([0xff; 32]);
        assert_ne!(encode_body(&changed).unwrap(), base_digest);
        changed = sample_body();
        changed.analysis_id = Some(Sha256Digest::new([0xab; 32]));
        assert_ne!(encode_body(&changed).unwrap(), base_digest);
        changed = sample_body();
        changed.text_diff_id = Some(Sha256Digest::new([0xac; 32]));
        assert_ne!(encode_body(&changed).unwrap(), base_digest);
        changed = sample_body();
        changed.synthesis_id = Some(Sha256Digest::new([0xad; 32]));
        assert_ne!(encode_body(&changed).unwrap(), base_digest);
        changed = sample_body();
        changed.merged_bytes_id = Some(Sha256Digest::new([0xae; 32]));
        assert_ne!(encode_body(&changed).unwrap(), base_digest);
        changed = sample_body();
        changed.decision_document_id = Sha256Digest::new([0xaf; 32]);
        assert_ne!(encode_body(&changed).unwrap(), base_digest);
        // Presence mismatch (artifact Some vs live None) must differ.
        let with = {
            let mut b = sample_body();
            b.analysis_id = Some(Sha256Digest::new([1; 32]));
            b
        };
        let without = sample_body();
        assert_ne!(encode_body(&with).unwrap(), encode_body(&without).unwrap());
    }
}
