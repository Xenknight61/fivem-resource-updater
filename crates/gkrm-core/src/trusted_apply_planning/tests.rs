//! Unit tests for trusted apply planning.

use crate::trusted_staging::test_support::{
    build_mini, hash_tree, installed_root, stage_ok, MiniFixture,
};
use crate::{
    plan_trusted_apply, InstalledApplyPlanningSource, InstalledScanLimits,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedApplyStatus,
    TrustedStagingBundle,
};

use super::{content_read_count, reset_content_read_count};

fn plan_for(fixture: &MiniFixture, bundle: &TrustedStagingBundle) -> crate::TrustedApplyPlan {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    plan_trusted_apply(
        TrustedApplyPlanningRequest::try_new(
            bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            TrustedApplyPlanningOptions::default(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn binding_failure_before_content_reads() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    reset_content_read_count();
    let err = plan_trusted_apply(
        TrustedApplyPlanningRequest::try_new(
            &bundle,
            &fixture.plan,
            &fixture.review,
            None,
            None,
            None,
            None,
            &fixture.baseline,
            &installed,
            TrustedApplyPlanningOptions::default(),
        )
        .unwrap(),
    )
    .expect_err("merge chain required");
    assert!(matches!(
        err,
        crate::GkrmError::TrustedApplyPlanningMergeChainPresenceMismatch
    ));
    assert_eq!(content_read_count(), 0);
}

#[test]
fn successful_plan_leaves_trees_unchanged() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let plan = plan_for(&fixture, &bundle);
    assert!(matches!(
        plan.status(),
        TrustedApplyStatus::ReadyForTransactionalApply | TrustedApplyStatus::NoFilesystemChanges
    ));
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
}

#[test]
fn readonly_staging_verify_does_not_mutate() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before = format!("{:?}", hash_tree(&fixture.staging_root));
    crate::trusted_staging::verify_published_bundle_readonly(
        bundle.published_dir_for_apply_planning(),
        bundle.resource_dir_for_apply_planning(),
        bundle.manifest(),
    )
    .unwrap();
    assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before);
}

#[test]
fn plan_is_deterministic() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let a = plan_for(&fixture, &bundle);
    let b = plan_for(&fixture, &bundle);
    assert_eq!(a.plan_id().digest(), b.plan_id().digest());
    assert_eq!(a.backup_set_id().digest(), b.backup_set_id().digest());
    assert_eq!(a.operations().len(), b.operations().len());
    for (x, y) in a.operations().iter().zip(b.operations()) {
        assert_eq!(x.operation_id().digest(), y.operation_id().digest());
        assert_eq!(x.kind(), y.kind());
        assert_eq!(x.phase(), y.phase());
    }

    // Content-stable fixed vectors for the canonical MiniFixture (no production
    // encoder in the expected side of these assertions).
    const FIXED_TASK21_PLAN_ID: &str =
        "96b92a0cd0671ee7be14566a6e69a4bfcf18bd5663fa1ea0ac423692a36d9dc6";
    const FIXED_TASK21_INSTALLED_APPLY_TREE_SNAPSHOT_FINGERPRINT: &str =
        "097300511aeed45a0879ffc00eb41b5aaa9e8798e562faa72bc7929a1d280a7b";
    const FIXED_TASK21_BACKUP_SET_ID: &str =
        "9c31572877b838d0b1f0de316167320c765f02d58f1d5ecc69b88914e359dca2";
    const FIXED_TASK21_FIRST_OPERATION_ID: &str =
        "7a1fcbaa40dfafaa9a6b837a830e6e5ef7c136db552c85b03a53ac5a9de87955";
    assert_eq!(a.plan_id().to_hex(), FIXED_TASK21_PLAN_ID);
    assert_eq!(
        a.backup_set_id().digest().to_string(),
        FIXED_TASK21_BACKUP_SET_ID
    );
    assert_eq!(
        a.operations()[0].operation_id().digest().to_string(),
        FIXED_TASK21_FIRST_OPERATION_ID
    );
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let snap = installed
        .capture_tree_snapshot(fixture.plan.resource_key())
        .unwrap();
    assert_eq!(
        snap.fingerprint.to_string(),
        FIXED_TASK21_INSTALLED_APPLY_TREE_SNAPSHOT_FINGERPRINT
    );

    // Independent filesystem roots must yield the same content-stable IDs.
    let fixture2 = build_mini();
    let bundle2 = stage_ok(&fixture2);
    let c = plan_for(&fixture2, &bundle2);
    assert_eq!(c.plan_id().to_hex(), FIXED_TASK21_PLAN_ID);
    assert_eq!(
        c.backup_set_id().digest().to_string(),
        FIXED_TASK21_BACKUP_SET_ID
    );
    assert_eq!(
        c.operations()[0].operation_id().digest().to_string(),
        FIXED_TASK21_FIRST_OPERATION_ID
    );
}

#[test]
fn public_debug_redacts_paths() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let plan = plan_for(&fixture, &bundle);
    let text = format!("{plan:?}");
    assert!(!text.contains("fxmanifest.lua"));
    assert!(!text.contains("gksphone"));
    for op in plan.operations() {
        let op_dbg = format!("{op:?}");
        assert!(!op_dbg.contains("fxmanifest.lua"));
    }
}

#[test]
fn no_public_destination_path_accessor() {
    // Compile-time / API surface check: destination is only available via
    // cfg(test) crate-private destination_for_test, not a public method.
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let plan = plan_for(&fixture, &bundle);
    let op = &plan.operations()[0];
    let _ = op.destination_for_test();
    let debug = format!("{op:?}");
    assert!(!debug.contains("fxmanifest.lua"));
    assert!(!debug.contains("merge.lua"));
    assert!(!debug.contains("destination"));
}
