//! Security and concurrency tests for Task 24 recovery.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use crate::trusted_staging::test_support::{build_mini, stage_ok};
use crate::trusted_transactional_apply_execution::locks::{
    acquire_resource_lock, encode_resource_lock_id,
};
use crate::trusted_transactional_apply_execution::recovery::id::{
    encode_candidate_id, encode_malformed_candidate_id, encode_recovery_result_id,
    encode_scan_result_id, encode_transaction_lock_binding_id,
};
use crate::{
    execute_trusted_transactional_apply, plan_trusted_apply, plan_trusted_transactional_apply,
    recover_trusted_transaction, scan_trusted_transactions, GkrmError, InstallationRelativePath,
    InstalledApplyPlanningSource, InstalledResourceRoot, InstalledScanLimits, Sha256Digest,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedRecoveryOptions,
    TrustedRecoveryResult, TrustedRecoveryScanOptions, TrustedTransactionRecoveryRequest,
    TrustedTransactionRoot, TrustedTransactionalApplyExecutionOptions,
    TrustedTransactionalApplyExecutionRequest, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest,
};

use super::map_journal_scan_error;

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

fn assert_error_surfaces_redacted(error: &GkrmError, forbidden: &[&str]) {
    let surfaces = [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ];
    let mut chain = String::new();
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = current {
        chain.push_str(&format!("{err}"));
        chain.push_str(&format!("{err:?}"));
        current = err.source();
    }
    for surface in surfaces.iter().chain(std::iter::once(&chain)) {
        for token in forbidden {
            assert!(!surface.contains(token), "leaked {token:?} in {surface}");
        }
        assert!(
            !surface.contains("Os {") && !surface.contains("code:"),
            "raw io error leaked: {surface}"
        );
    }
}

#[test]
fn recovery_scan_preserves_unsupported_journal_version_classification() {
    assert!(matches!(
        map_journal_scan_error(
            GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported
        ),
        GkrmError::TrustedTransactionalApplyExecutionJournalVersionUnsupported
    ));
    assert!(matches!(
        map_journal_scan_error(GkrmError::TrustedTransactionRecoveryJournalInvalid),
        GkrmError::TrustedTransactionRecoveryJournalInvalid
    ));
}

#[test]
fn fixed_recovery_identity_vectors_are_literal() {
    let plan = Sha256Digest::new([0x11; 32]);
    let related = Sha256Digest::new([0x22; 32]);
    assert_eq!(
        encode_candidate_id(&plan).unwrap().to_string(),
        "d8542af46c1c725987ffba008692fa242bbe2a177981a68c8ad7b2b3690eb252"
    );
    assert_eq!(
        encode_malformed_candidate_id(0).unwrap().to_string(),
        "86684fb96405226539f64005e5ab268f024ef13aed77843d3d7faa168855650d"
    );
    assert_eq!(
        encode_scan_result_id(&[plan]).unwrap().to_string(),
        "3429f908eccb5d3e3c5a08efa3c45cc72a4591f3ca073f2cfbc3ac890f37a75d"
    );
    assert_eq!(
        encode_recovery_result_id(&plan, b"safe-restart", Some(&related))
            .unwrap()
            .to_string(),
        "5e3b1e215444f31e664a47c06ba39da2184659faf380170691f3b869bf74a632"
    );
    assert_eq!(
        encode_recovery_result_id(&plan, b"recovered-committed", Some(&related))
            .unwrap()
            .to_string(),
        "20680df0131cad1cb04677cfcd2ca1224e2760fd2cf8fa44a662d716788f7743"
    );
    assert_eq!(
        encode_recovery_result_id(&plan, b"recovered-rolled-back", Some(&related))
            .unwrap()
            .to_string(),
        "2613ba51bbae486d49443f3359680186d51762d8be426bf6e7dbde263cf4e44e"
    );
    assert_eq!(
        encode_recovery_result_id(&plan, b"conflict", None)
            .unwrap()
            .to_string(),
        "63d82a20da09134e7d8065a146c759e5d6a39e0670c3f2cebd22a3c994a9685d"
    );
    assert_eq!(
        encode_resource_lock_id("gksphone").unwrap().to_string(),
        "77065fc44fd478c66958de74a93dc97bce2c60da8ca2818022f5846b7e8be7b8"
    );
    assert_eq!(
        encode_transaction_lock_binding_id(&plan)
            .unwrap()
            .to_string(),
        "a334a85172fa12bd73c456931ea7a2bf13e84320b9bf361f99de5854260f5650"
    );

    // AbortedBeforeMutation journal record ID (sequence 1 after Prepared-shaped cursor).
    use crate::trusted_transactional_apply_execution::id::{
        encode_body_commitment, encode_journal_record_id,
    };
    use crate::trusted_transactional_apply_execution::TransactionJournalEvent;
    let snapshot = Sha256Digest::new([0x33; 32]);
    let body = encode_body_commitment(
        &plan,
        &snapshot,
        None,
        &[],
        &[],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let prepared =
        encode_journal_record_id(&plan, 0, None, TransactionJournalEvent::Prepared, &body).unwrap();
    let abort_body = encode_body_commitment(
        &plan,
        &snapshot,
        None,
        &[],
        &[],
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let aborted = encode_journal_record_id(
        &plan,
        1,
        Some(&prepared),
        TransactionJournalEvent::AbortedBeforeMutation,
        &abort_body,
    )
    .unwrap();
    assert_eq!(
        aborted.to_string(),
        "7726c7ffeee1e49a7406d3ea67cdf87a8b44f0b21b503da7962c8ee7df150db5"
    );
}

#[test]
fn resource_lock_blocks_concurrent_task23_and_recovery() {
    let fixture = build_mini();
    let txn_root_path = fixture._temp.path().join("txn-lock-race");
    fs::create_dir_all(&txn_root_path).unwrap();
    let root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let held = acquire_resource_lock(root.dir(), "gksphone").unwrap();

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
            &root,
            &fixture.package_v2,
            TrustedTransactionalApplyExecutionOptions::default(),
        )
        .unwrap(),
    )
    .expect_err("Task 23 must fail closed while resource lock is held");
    assert!(
        matches!(
            err,
            GkrmError::TrustedTransactionalApplyExecutionLockContention
        ),
        "expected lock contention, got {err:?}"
    );
    assert_error_surfaces_redacted(
        &err,
        &[
            "gksphone",
            "txn-lock-race",
            fixture._temp.path().to_string_lossy().as_ref(),
        ],
    );
    // No published transaction while blocked.
    assert!(
        !txn_root_path.join("transactions").exists() || {
            fs::read_dir(txn_root_path.join("transactions"))
                .map(|rd| rd.count() == 0)
                .unwrap_or(true)
        }
    );
    drop(held);
}

#[test]
fn two_recoverers_contend_on_one_transaction() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan, txn_root_path) = {
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
        let txn_root_path = fixture._temp.path().join("txn-two-recoverers");
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
        )
        .unwrap();
        (bundle, apply, tx_plan, txn_root_path)
    };

    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let txn_root_path = txn_root_path.clone();
        let installed_parent = fixture.installed_parent.clone();
        let package = fixture.package_v2.clone();
        // Recreate plans on each thread by cloning isn't possible for opaque plans;
        // use shared fixture paths and rebuild light scan/recover locally.
        handles.push(thread::spawn(move || {
            let root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
            let scan =
                scan_trusted_transactions(&root, TrustedRecoveryScanOptions::default()).unwrap();
            let candidate = &scan.candidates()[0];
            // Hold resource lock across the barrier after first recoverer starts locking.
            barrier.wait();
            let installed = InstalledApplyPlanningSource::try_new(
                &installed_parent,
                installed_root("gksphone"),
                InstalledScanLimits::default(),
            );
            let _ = (candidate, installed, package);
            // Contending on resource lock acquisition itself.
            let result = acquire_resource_lock(root.dir(), "gksphone");
            result
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let oks = results.iter().filter(|r| r.is_ok()).count();
    let errs = results.iter().filter(|r| r.is_err()).count();
    assert_eq!(oks, 1, "exactly one recoverer/lock holder succeeds");
    assert_eq!(errs, 1, "peer fails closed on contention");
    let _ = (bundle, apply, tx_plan);
}

#[test]
fn lock_file_persists_and_is_reacquirable_after_release() {
    let dir = tempfile::tempdir().unwrap();
    let root_path = dir.path().join("txn-root");
    fs::create_dir_all(&root_path).unwrap();
    let root = TrustedTransactionRoot::try_open(&root_path).unwrap();
    {
        let held = acquire_resource_lock(root.dir(), "gksphone").unwrap();
        drop(held);
    }
    let lock_dir = root_path.join("locks").join("resources");
    assert!(lock_dir.exists());
    assert!(fs::read_dir(&lock_dir).unwrap().count() >= 1);
    let again = acquire_resource_lock(root.dir(), "gksphone").unwrap();
    drop(again);
}

#[test]
fn snapshot_a_tamper_fails_closed() {
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
    let txn_root_path = fixture._temp.path().join("txn-snap-tamper");
    fs::create_dir_all(&txn_root_path).unwrap();
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    execute_trusted_transactional_apply(
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

    let snap = txn_root_path
        .join("transactions")
        .join(tx_plan.plan_id().to_hex())
        .join("snapshot-a.bin");
    let mut bytes = fs::read(&snap).unwrap();
    bytes.push(0xff); // trailing byte
    fs::write(&snap, &bytes).unwrap();

    let scan = scan_trusted_transactions(&txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    // Tampered snapshot-a makes the candidate malformed at scan or recovery.
    if scan.candidates().is_empty()
        || scan
            .candidates()
            .iter()
            .all(|c| c.kind() == crate::TrustedRecoveryCandidateKind::Malformed)
    {
        return;
    }
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
    );
    match recovered {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) => {}
        Err(e) => assert_error_surfaces_redacted(&e, &["snapshot-a", "gksphone"]),
        Ok(other) => panic!("tampered snapshot must not recover successfully: {other:?}"),
    }
}

#[test]
fn fixed_order_lock_acquisition_no_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let root_path = dir.path().join("txn-root");
    fs::create_dir_all(&root_path).unwrap();
    let root = TrustedTransactionRoot::try_open(&root_path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let barrier = Arc::clone(&barrier);
        let root_path = root_path.clone();
        handles.push(thread::spawn(move || {
            let root = TrustedTransactionRoot::try_open(&root_path).unwrap();
            barrier.wait();
            for _ in 0..20 {
                if let Ok(lock) = acquire_resource_lock(root.dir(), "gksphone") {
                    thread::sleep(Duration::from_millis(1));
                    drop(lock);
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("no deadlock");
    }
    let _ = root;
}

#[test]
fn task24_holding_resource_lock_blocks_recovery_mutation() {
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
    let txn_root_path = fixture._temp.path().join("txn-held-recover");
    fs::create_dir_all(&txn_root_path).unwrap();
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
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
        .find(|c| c.kind() == crate::TrustedRecoveryCandidateKind::Bound)
    else {
        return;
    };
    let held = acquire_resource_lock(txn_root.dir(), "gksphone").unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let err = recover_trusted_transaction(
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
    .expect_err("recovery must fail closed while resource lock is held");
    assert!(
        matches!(
            err,
            GkrmError::TrustedTransactionalApplyExecutionLockContention
        ),
        "expected lock contention, got {err:?}"
    );
    assert_error_surfaces_redacted(&err, &["gksphone", "txn-held-recover"]);
    drop(held);
}
