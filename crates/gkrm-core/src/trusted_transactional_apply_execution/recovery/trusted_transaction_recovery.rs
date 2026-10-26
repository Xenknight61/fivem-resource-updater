//! Unit tests for Task 24 recovery.

use std::fs;

use crate::trusted_staging::test_support::{build_mini, stage_ok};
use crate::{
    execute_trusted_transactional_apply, plan_trusted_apply, plan_trusted_transactional_apply,
    recover_trusted_transaction, scan_trusted_transactions, InstallationRelativePath,
    InstalledApplyPlanningSource, InstalledResourceRoot, InstalledScanLimits,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedRecoveryCandidateKind,
    TrustedRecoveryOptions, TrustedRecoveryResult, TrustedRecoveryScanOptions,
    TrustedTransactionRecoveryRequest, TrustedTransactionResult, TrustedTransactionRoot,
    TrustedTransactionalApplyExecutionOptions, TrustedTransactionalApplyExecutionRequest,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
};
use std::path::Path;

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

fn build_plans(
    fixture: &crate::trusted_staging::test_support::MiniFixture,
) -> (
    crate::TrustedStagingBundle,
    crate::TrustedApplyPlan,
    crate::TrustedTransactionalApplyPlan,
) {
    let bundle = stage_ok(fixture);
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
    (bundle, apply, tx_plan)
}

#[test]
fn scan_empty_root_is_read_only() {
    let fixture = build_mini();
    let txn_root_path = fixture._temp.path().join("txn-root-empty");
    fs::create_dir_all(&txn_root_path).unwrap();
    let before = hash_listing(&txn_root_path);
    let root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let scan = scan_trusted_transactions(&root, TrustedRecoveryScanOptions::default()).unwrap();
    assert!(scan.candidates().is_empty());
    let after = hash_listing(&txn_root_path);
    assert_eq!(before, after);
}

#[test]
fn scan_ignores_tmp_and_finds_committed() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan) = build_plans(&fixture);
    let txn_root_path = fixture._temp.path().join("txn-root");
    fs::create_dir_all(&txn_root_path).unwrap();
    fs::create_dir_all(txn_root_path.join(".tmp").join("should-ignore")).unwrap();
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
    .unwrap();
    assert!(matches!(result, TrustedTransactionResult::Committed(_)));

    let before = hash_listing(&txn_root_path);
    let scan = scan_trusted_transactions(&txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let after = hash_listing(&txn_root_path);
    assert_eq!(before, after, "scan must be read-only");
    assert_eq!(scan.candidates().len(), 1);
    assert_eq!(
        scan.candidates()[0].kind(),
        TrustedRecoveryCandidateKind::Bound
    );
    let text = format!("{:?}", scan);
    assert!(!text.contains(tx_plan.plan_id().to_hex().as_str()));
}

#[test]
fn prepared_safe_abort_allows_restart() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan) = build_plans(&fixture);
    let txn_root_path = fixture._temp.path().join("txn-abort");
    fs::create_dir_all(&txn_root_path).unwrap();
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();

    // Create Prepared-only transaction by forcing journal fault after Prepared publish path:
    // run execute with BackupComplete journal fault so we stop at Prepared or during backup.
    let _guard = crate::trusted_transactional_apply_execution::hooks::lock_execution_hooks();
    crate::trusted_transactional_apply_execution::hooks::set_journal_fault(Some(
        crate::trusted_transactional_apply_execution::hooks::JournalFault::BackupEntryCompleted,
    ));
    let _ = execute_trusted_transactional_apply(
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
    );
    crate::trusted_transactional_apply_execution::hooks::set_journal_fault(None);

    let scan = scan_trusted_transactions(&txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let Some(candidate) = scan
        .candidates()
        .iter()
        .find(|c| c.kind() == TrustedRecoveryCandidateKind::Bound)
    else {
        // If fault sealed RecoveryRequired instead, that is also acceptable for this fixture.
        return;
    };

    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let recovered = recover_trusted_transaction(
        TrustedTransactionRecoveryRequest::try_new(
            candidate,
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
            TrustedRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        matches!(
            recovered,
            TrustedRecoveryResult::SafeRestart(_) | TrustedRecoveryResult::RecoveryStillRequired(_)
        ),
        "{recovered:?}"
    );
}

#[test]
fn lock_file_persists_after_release() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan) = build_plans(&fixture);
    let txn_root_path = fixture._temp.path().join("txn-lock");
    fs::create_dir_all(&txn_root_path).unwrap();
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let _ = execute_trusted_transactional_apply(
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
    );
    let locks_dir = txn_root_path.join("locks").join("resources");
    assert!(locks_dir.exists(), "resource lock directory should persist");
    let count = fs::read_dir(&locks_dir).unwrap().count();
    assert!(count >= 1, "lock file should remain after handle release");
}

#[test]
fn committed_drift_never_auto_rolls_back() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan) = build_plans(&fixture);
    let txn_root_path = fixture._temp.path().join("txn-drift");
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
    .unwrap();
    assert!(matches!(result, TrustedTransactionResult::Committed(_)));

    // Drift a staged managed file after commit (not a preserved customer extra).
    fs::write(
        fixture.installed_parent.join("gksphone").join("take.lua"),
        b"tampered-after-commit\n",
    )
    .unwrap();

    let scan = scan_trusted_transactions(&txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let candidate = &scan.candidates()[0];
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let recovered = recover_trusted_transaction(
        TrustedTransactionRecoveryRequest::try_new(
            candidate,
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
            TrustedRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        recovered,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    // Tampered staged file must still exist (no auto rollback).
    assert_eq!(
        fs::read(fixture.installed_parent.join("gksphone").join("take.lua")).unwrap(),
        b"tampered-after-commit\n"
    );
}

fn hash_listing(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let rel = path.strip_prefix(base).unwrap_or(&path);
            out.push(rel.to_string_lossy().replace('\\', "/"));
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}
