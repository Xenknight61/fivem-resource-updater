//! Frozen Task21V1 + Task22V1 recovery derivation.

use crate::trusted_apply_planning::{
    plan_trusted_apply_v1, plan_trusted_apply_v1_from_snapshot, InstalledApplyTreeSnapshot,
    PackageFreeMergeChainIds,
};
use crate::trusted_transactional_apply_planning::{
    plan_trusted_transactional_apply_v1, plan_trusted_transactional_apply_v1_from_snapshot,
};
use crate::{
    GkrmError, InstalledApplyPlanningSource, ResolvedOfficialBaseline, Result,
    ThreeWayMergedBytesPlan, ThreeWayPlanReview, ThreeWayUpdatePlan, TrustedApplyPlan,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedStagingBundle,
    TrustedTransactionalApplyPlan, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest,
};

pub(crate) struct RecoveryDerivationRequestV1<'a> {
    pub(crate) bundle: &'a TrustedStagingBundle,
    pub(crate) plan: &'a ThreeWayUpdatePlan,
    pub(crate) review: &'a ThreeWayPlanReview,
    pub(crate) merge_ids: Option<PackageFreeMergeChainIds>,
    pub(crate) merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
    pub(crate) baseline: &'a ResolvedOfficialBaseline,
    pub(crate) installed_source: &'a InstalledApplyPlanningSource,
}

pub(crate) struct RecoveryDerivationResultV1 {
    pub(crate) apply_plan: TrustedApplyPlan,
    pub(crate) snapshot: InstalledApplyTreeSnapshot,
    pub(crate) transactional_plan: TrustedTransactionalApplyPlan,
}

pub(crate) struct RecoveryDerivationFromSnapshotRequestV1<'a> {
    pub(crate) request: RecoveryDerivationRequestV1<'a>,
    pub(crate) snapshot: &'a InstalledApplyTreeSnapshot,
}

pub(super) fn reconstruct(
    request: RecoveryDerivationRequestV1<'_>,
) -> Result<RecoveryDerivationResultV1> {
    let apply_plan = plan_trusted_apply_v1(TrustedApplyPlanningRequest::try_new_package_free(
        request.bundle,
        request.plan,
        request.review,
        request.merge_ids,
        request.merged_bytes,
        request.baseline,
        request.installed_source,
        TrustedApplyPlanningOptions::default(),
    )?)?;
    let snapshot = request
        .installed_source
        .capture_tree_snapshot(request.plan.resource_key())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let transactional_plan = plan_trusted_transactional_apply_v1(
        TrustedTransactionalApplyPlanningRequest::try_new_package_free(
            &apply_plan,
            request.bundle,
            request.plan,
            request.review,
            request.merge_ids,
            request.merged_bytes,
            request.baseline,
            request.installed_source,
            TrustedTransactionalApplyPlanningOptions::default(),
        )?,
    )?;
    Ok(RecoveryDerivationResultV1 {
        apply_plan,
        snapshot,
        transactional_plan,
    })
}

pub(super) fn reconstruct_from_snapshot(
    input: RecoveryDerivationFromSnapshotRequestV1<'_>,
) -> Result<RecoveryDerivationResultV1> {
    let request = input.request;
    let apply_plan = plan_trusted_apply_v1_from_snapshot(
        TrustedApplyPlanningRequest::try_new_package_free(
            request.bundle,
            request.plan,
            request.review,
            request.merge_ids,
            request.merged_bytes,
            request.baseline,
            request.installed_source,
            TrustedApplyPlanningOptions::default(),
        )?,
        input.snapshot,
    )?;
    let transactional_plan = plan_trusted_transactional_apply_v1_from_snapshot(
        TrustedTransactionalApplyPlanningRequest::try_new_package_free(
            &apply_plan,
            request.bundle,
            request.plan,
            request.review,
            request.merge_ids,
            request.merged_bytes,
            request.baseline,
            request.installed_source,
            TrustedTransactionalApplyPlanningOptions::default(),
        )?,
        input.snapshot,
    )?;
    Ok(RecoveryDerivationResultV1 {
        apply_plan,
        snapshot: input.snapshot.clone(),
        transactional_plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trusted_apply_planning::{
        plan_trusted_apply, use_alternate_live_apply_planner_for_test,
    };
    use crate::trusted_staging::test_support::{build_mini, installed_root, stage_ok};
    use crate::InstalledScanLimits;

    #[test]
    fn frozen_v1_reconstruction_pins_task21_and_task22_ids() {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        let installed_source = InstalledApplyPlanningSource::try_new(
            &fixture.installed_parent,
            installed_root("gksphone"),
            InstalledScanLimits::default(),
        )
        .unwrap();
        let merge_ids = PackageFreeMergeChainIds {
            analysis_id: *fixture.analysis.analysis_id().digest(),
            text_diff_id: *fixture.text_diff.text_diff_plan_id().digest(),
            synthesis_id: *fixture.synthesis.synthesis_plan_id().digest(),
            merged_bytes_id: *fixture.merged_bytes.merged_bytes_plan_id().digest(),
        };

        let _alternate_live_semantics = use_alternate_live_apply_planner_for_test();
        let live = plan_trusted_apply(
            TrustedApplyPlanningRequest::try_new_package_free(
                &bundle,
                &fixture.plan,
                &fixture.review,
                Some(merge_ids),
                Some(&fixture.merged_bytes),
                &fixture.baseline,
                &installed_source,
                TrustedApplyPlanningOptions::default(),
            )
            .unwrap(),
        )
        .unwrap();

        let result = reconstruct(RecoveryDerivationRequestV1 {
            bundle: &bundle,
            plan: &fixture.plan,
            review: &fixture.review,
            merge_ids: Some(merge_ids),
            merged_bytes: Some(&fixture.merged_bytes),
            baseline: &fixture.baseline,
            installed_source: &installed_source,
        })
        .unwrap();
        let live_ids: Vec<_> = live
            .operations()
            .iter()
            .map(|operation| *operation.operation_id().digest())
            .collect();
        let frozen_ids: Vec<_> = result
            .apply_plan
            .operations()
            .iter()
            .map(|operation| *operation.operation_id().digest())
            .collect();
        assert_eq!(
            live_ids,
            frozen_ids.iter().rev().copied().collect::<Vec<_>>()
        );
        assert_ne!(live_ids, frozen_ids);
        assert_eq!(
            result.apply_plan.plan_id().to_hex(),
            "96b92a0cd0671ee7be14566a6e69a4bfcf18bd5663fa1ea0ac423692a36d9dc6"
        );
        assert_eq!(
            result.transactional_plan.plan_id().to_hex(),
            "b3c0863b6db64874166d3e1857612f5a1f7c540ba508ec34628a44d365dbce2b"
        );
        assert_eq!(
            result.snapshot.fingerprint.to_string(),
            "097300511aeed45a0879ffc00eb41b5aaa9e8798e562faa72bc7929a1d280a7b"
        );
    }
}
