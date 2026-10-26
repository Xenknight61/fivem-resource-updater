//! Unit tests for Task 23 transactional apply execution.

use std::fs;

use crate::trusted_staging::test_support::{build_mini, stage_ok};
use crate::{
    execute_trusted_transactional_apply, plan_trusted_apply, plan_trusted_transactional_apply,
    InstallationRelativePath, InstalledApplyPlanningSource, InstalledResourceRoot,
    InstalledScanLimits, TrustedApplyPlanningOptions, TrustedApplyPlanningRequest,
    TrustedTransactionResult, TrustedTransactionRoot, TrustedTransactionalApplyExecutionOptions,
    TrustedTransactionalApplyExecutionRequest, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest,
};
use std::path::Path;

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

#[test]
fn successful_commit_on_mini_fixture() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let apply = plan_trusted_apply(
        TrustedApplyPlanningRequest::try_new(
            &bundle,
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
    .unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let tx_plan = plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            &apply,
            &bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            TrustedTransactionalApplyPlanningOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();

    let txn_root_path = fixture._temp.path().join("txn-root");
    fs::create_dir_all(&txn_root_path).unwrap();
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let result = execute_trusted_transactional_apply(
        TrustedTransactionalApplyExecutionRequest::try_new(
            &tx_plan,
            &apply,
            &bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            &txn_root,
            &fixture.package_v2,
            TrustedTransactionalApplyExecutionOptions::default(),
        )
        .unwrap(),
    )
    .expect("execute");
    match &result {
        TrustedTransactionResult::Committed(_) => {}
        other => panic!("expected Committed, got {other:?}"),
    }
    assert!(txn_root_path
        .join("transactions")
        .join(tx_plan.plan_id().to_hex())
        .join("journal")
        .exists());
}

#[test]
fn binding_failure_creates_no_transaction() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let apply = plan_trusted_apply(
        TrustedApplyPlanningRequest::try_new(
            &bundle,
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
    .unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let tx_plan = plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            &apply,
            &bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            TrustedTransactionalApplyPlanningOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();

    // Overlapping transaction root with installed.
    let txn_root = TrustedTransactionRoot::try_open(&fixture.installed_parent).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let err = execute_trusted_transactional_apply(
        TrustedTransactionalApplyExecutionRequest::try_new(
            &tx_plan,
            &apply,
            &bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            &txn_root,
            &fixture.package_v2,
            TrustedTransactionalApplyExecutionOptions::default(),
        )
        .unwrap(),
    )
    .expect_err("overlap");
    let _ = err;
    assert!(!fixture.installed_parent.join("transactions").exists());
}
