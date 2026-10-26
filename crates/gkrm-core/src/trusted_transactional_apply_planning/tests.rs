//! Unit tests for trusted transactional apply planning.

use crate::trusted_staging::test_support::{
    build_mini, hash_tree, installed_root, stage_ok, MiniFixture,
};
use crate::{
    plan_trusted_apply, plan_trusted_transactional_apply, InstalledApplyPlanningSource,
    InstalledScanLimits, JournalState, TransactionStepPhase, TrustedApplyPlanningOptions,
    TrustedApplyPlanningRequest, TrustedApplyStatus, TrustedStagingBundle,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
    TrustedTransactionalApplyStatus,
};

use super::{content_read_count, journal, reset_content_read_count};

fn apply_plan_for(fixture: &MiniFixture, bundle: &TrustedStagingBundle) -> crate::TrustedApplyPlan {
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

fn tx_plan_for(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply_plan: &crate::TrustedApplyPlan,
) -> crate::TrustedTransactionalApplyPlan {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            apply_plan,
            bundle,
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
    .unwrap()
}

#[test]
fn binding_failure_before_content_reads() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let apply_plan = apply_plan_for(&fixture, &bundle);
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    reset_content_read_count();
    let err = plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            &apply_plan,
            &bundle,
            &fixture.plan,
            &fixture.review,
            None,
            None,
            None,
            None,
            &fixture.baseline,
            &installed,
            TrustedTransactionalApplyPlanningOptions::default(),
        )
        .unwrap(),
    )
    .expect_err("merge chain required");
    assert!(matches!(
        err,
        crate::GkrmError::TrustedTransactionalApplyPlanningBindingMismatch
    ));
    assert_eq!(content_read_count(), 0);
}

#[test]
fn successful_plan_leaves_trees_unchanged_and_orders_journal() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let apply_plan = apply_plan_for(&fixture, &bundle);
    assert!(matches!(
        apply_plan.status(),
        TrustedApplyStatus::ReadyForTransactionalApply
    ));
    let plan = tx_plan_for(&fixture, &bundle, &apply_plan);
    assert!(matches!(
        plan.status(),
        TrustedTransactionalApplyStatus::ReadyForTransactionalExecution
    ));
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);

    let phases: Vec<_> = plan.forward_phases().collect();
    let prepared = phases
        .iter()
        .position(|p| *p == TransactionStepPhase::PersistPreparedJournal)
        .unwrap();
    let backup = phases
        .iter()
        .position(|p| *p == TransactionStepPhase::CreateBackupBundle)
        .unwrap();
    let applying = phases
        .iter()
        .position(|p| *p == TransactionStepPhase::PersistApplyingJournal)
        .unwrap();
    assert!(prepared < backup);
    assert!(backup < applying);

    assert_eq!(
        plan.backup().entry_count(),
        apply_plan
            .operations()
            .iter()
            .filter(|o| !matches!(o.backup_requirement(), crate::ApplyBackupRequirement::None))
            .count()
    );
    assert!(!plan.rollback_steps().is_empty());
    assert!(plan.journal().record_count() > 0);
    assert_eq!(plan.recovery().rows().len(), 10);
}

#[test]
fn journal_rejects_committed_rollback() {
    journal::assert_illegal_committed_rollback();
    assert!(
        journal::validate_transition(JournalState::Committed, JournalState::RollingBack).is_err()
    );
}

#[test]
fn plan_is_deterministic_across_roots() {
    let fixture_a = build_mini();
    let bundle_a = stage_ok(&fixture_a);
    let apply_a = apply_plan_for(&fixture_a, &bundle_a);
    let plan_a = tx_plan_for(&fixture_a, &bundle_a, &apply_a);

    let fixture_b = build_mini();
    let bundle_b = stage_ok(&fixture_b);
    let apply_b = apply_plan_for(&fixture_b, &bundle_b);
    let plan_b = tx_plan_for(&fixture_b, &bundle_b, &apply_b);

    assert_eq!(plan_a.plan_id().to_hex(), plan_b.plan_id().to_hex());
    assert_eq!(
        plan_a.backup().plan_id().digest().to_string(),
        plan_b.backup().plan_id().digest().to_string()
    );
}
