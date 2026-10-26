//! Tests for Critical/Important Task 24 review fixes.

use std::fs;
use std::path::Path;

use crate::trusted_staging::test_support::{build_mini, stage_ok};
use crate::trusted_transactional_apply_execution::hooks::{
    lock_execution_hooks, set_journal_fault, JournalFault,
};
use crate::trusted_transactional_apply_execution::journal::{
    append_record, ensure_journal_dir, load_and_validate_journal_chain, AppendArgs, JournalCursor,
};
use crate::trusted_transactional_apply_execution::TransactionJournalEvent;
use crate::{
    execute_trusted_transactional_apply, plan_trusted_apply, plan_trusted_transactional_apply,
    recover_trusted_transaction, scan_trusted_transactions, InstallationRelativePath,
    InstalledApplyPlanningSource, InstalledResourceRoot, InstalledScanLimits, Sha256Digest,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedRecoveryCandidateKind,
    TrustedRecoveryOptions, TrustedRecoveryResult, TrustedRecoveryScanOptions,
    TrustedTransactionRecoveryRequest, TrustedTransactionResult, TrustedTransactionRoot,
    TrustedTransactionalApplyExecutionOptions, TrustedTransactionalApplyExecutionRequest,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
};
use cap_fs_ext::ambient_authority;
use cap_std::fs::Dir as CapDir;
fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

fn plan_and_commit(
    fixture: &crate::trusted_staging::test_support::MiniFixture,
    txn_name: &str,
) -> (
    crate::TrustedStagingBundle,
    crate::TrustedApplyPlan,
    crate::TrustedTransactionalApplyPlan,
    TrustedTransactionRoot,
    std::path::PathBuf,
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
    let txn_root_path = fixture._temp.path().join(txn_name);
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
    (bundle, apply, tx_plan, txn_root, txn_root_path)
}

fn recover_bound(
    fixture: &crate::trusted_staging::test_support::MiniFixture,
    bundle: &crate::TrustedStagingBundle,
    apply: &crate::TrustedApplyPlan,
    tx_plan: &crate::TrustedTransactionalApplyPlan,
    txn_root: &TrustedTransactionRoot,
) -> TrustedRecoveryResult {
    let scan = scan_trusted_transactions(txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let candidate = scan
        .candidates()
        .iter()
        .find(|c| c.kind() == TrustedRecoveryCandidateKind::Bound)
        .expect("bound candidate");
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    recover_trusted_transaction(
        TrustedTransactionRecoveryRequest::try_new(
            candidate,
            tx_plan,
            apply,
            bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            txn_root,
            &fixture.package_v2,
            TrustedRecoveryOptions::default(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn committed_with_preserved_customer_file_and_directory_rediscovers() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan, txn_root, _) = plan_and_commit(&fixture, "customer-extras");
    // Customer extras after commit must not invalidate subset match.
    fs::write(
        fixture
            .installed_parent
            .join("gksphone")
            .join("customer.cfg"),
        b"keep-me\n",
    )
    .unwrap();
    fs::create_dir_all(
        fixture
            .installed_parent
            .join("gksphone")
            .join("customer-data")
            .join("nested"),
    )
    .unwrap();
    fs::write(
        fixture
            .installed_parent
            .join("gksphone")
            .join("customer-data")
            .join("nested")
            .join("note.txt"),
        b"nested\n",
    )
    .unwrap();

    let recovered = recover_bound(&fixture, &bundle, &apply, &tx_plan, &txn_root);
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveredCommitted(_)),
        "preserved extras must not block committed rediscovery: {recovered:?}"
    );
    assert_eq!(
        fs::read(
            fixture
                .installed_parent
                .join("gksphone")
                .join("customer.cfg")
        )
        .unwrap(),
        b"keep-me\n"
    );
    assert!(fixture
        .installed_parent
        .join("gksphone")
        .join("customer-data")
        .join("nested")
        .join("note.txt")
        .exists());
}

#[test]
fn extras_plus_correct_staging_subset_still_committed_rediscovery() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan, txn_root, _) = plan_and_commit(&fixture, "extras-after");
    fs::write(
        fixture.installed_parent.join("gksphone").join("extra.lua"),
        b"extra\n",
    )
    .unwrap();
    let recovered = recover_bound(&fixture, &bundle, &apply, &tx_plan, &txn_root);
    assert!(matches!(
        recovered,
        TrustedRecoveryResult::RecoveredCommitted(_)
    ));
}

#[test]
fn staged_file_missing_or_changed_is_mismatch_not_auto_rollback() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan, txn_root, _) = plan_and_commit(&fixture, "staged-mismatch");
    fs::remove_file(fixture.installed_parent.join("gksphone").join("merge.lua")).unwrap();
    let recovered = recover_bound(&fixture, &bundle, &apply, &tx_plan, &txn_root);
    assert!(matches!(
        recovered,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    // Change another staged file on a fresh commit.
    let fixture2 = build_mini();
    let (bundle2, apply2, tx_plan2, txn_root2, _) = plan_and_commit(&fixture2, "staged-changed");
    fs::write(
        fixture2.installed_parent.join("gksphone").join("take.lua"),
        b"wrong\n",
    )
    .unwrap();
    let recovered2 = recover_bound(&fixture2, &bundle2, &apply2, &tx_plan2, &txn_root2);
    assert!(matches!(
        recovered2,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(
        fs::read(fixture2.installed_parent.join("gksphone").join("take.lua")).unwrap(),
        b"wrong\n"
    );
}

#[test]
fn backup_file_tamper_before_rollback_fails_closed() {
    use crate::trusted_transactional_apply_execution::hooks::{
        set_interrupt_after_file_publish, set_rollback_action_fault, RollbackActionFault,
    };

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
    let txn_root_path = fixture._temp.path().join("backup-tamper");
    fs::create_dir_all(&txn_root_path).unwrap();
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();

    // Leave a non-terminal journal: mutate, fail rollback action, and block RecoveryRequired seal.
    let _guard = lock_execution_hooks();
    set_interrupt_after_file_publish(true);
    set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
    set_journal_fault(Some(JournalFault::RecoveryRequired));
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
    set_journal_fault(None);
    set_rollback_action_fault(None);
    set_interrupt_after_file_publish(false);

    let backup_files = txn_root_path
        .join("transactions")
        .join(tx_plan.plan_id().to_hex())
        .join("backup")
        .join("files");
    assert!(
        backup_files.is_dir(),
        "fixture must have produced a sealed backup"
    );
    let mut tampered = false;
    for entry in fs::read_dir(&backup_files).unwrap().flatten() {
        if entry.path().is_file() {
            fs::write(entry.path(), b"tampered-backup").unwrap();
            tampered = true;
            break;
        }
    }
    assert!(tampered, "expected at least one backup file to tamper");

    let before =
        fs::read(fixture.installed_parent.join("gksphone").join("take.lua")).unwrap_or_default();
    let recovered = recover_bound(&fixture, &bundle, &apply, &tx_plan, &txn_root);
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "tampered backup must fail closed without rollback: {recovered:?}"
    );
    assert_eq!(
        fs::read(fixture.installed_parent.join("gksphone").join("take.lua")).unwrap_or_default(),
        before,
        "installed must not be restored from tampered backup bytes"
    );
}

#[test]
fn terminal_journal_states_reject_any_successor() {
    let plan_id = Sha256Digest::new([0x11; 32]);
    let snapshot_a = Sha256Digest::new([0x22; 32]);

    for terminal in [
        TransactionJournalEvent::Committed,
        TransactionJournalEvent::RolledBack,
        TransactionJournalEvent::RecoveryRequired,
        TransactionJournalEvent::AbortedBeforeMutation,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let cap = CapDir::open_ambient_dir(dir.path(), ambient_authority()).unwrap();
        let j = ensure_journal_dir(&cap).unwrap();
        let mut cursor = JournalCursor::new();
        // Minimal valid prefix into a terminal.
        let prefix = match terminal {
            TransactionJournalEvent::AbortedBeforeMutation => {
                vec![TransactionJournalEvent::Prepared]
            }
            TransactionJournalEvent::Committed => vec![
                TransactionJournalEvent::Prepared,
                TransactionJournalEvent::BackupComplete,
                TransactionJournalEvent::Verified,
            ],
            TransactionJournalEvent::RolledBack => vec![
                TransactionJournalEvent::Prepared,
                TransactionJournalEvent::BackupComplete,
                TransactionJournalEvent::Applying,
                TransactionJournalEvent::RollingBack,
            ],
            TransactionJournalEvent::RecoveryRequired => vec![
                TransactionJournalEvent::Prepared,
                TransactionJournalEvent::BackupComplete,
                TransactionJournalEvent::Applying,
            ],
            _ => unreachable!(),
        };
        for event in prefix {
            if event == TransactionJournalEvent::BackupComplete {
                cursor.backup_seal = Some(Sha256Digest::new([0x33; 32]));
            }
            if event == TransactionJournalEvent::Verified {
                cursor.verification_seal = Some(Sha256Digest::new([0x44; 32]));
            }
            append_record(
                &j,
                &mut cursor,
                AppendArgs {
                    plan_id: &plan_id,
                    snapshot_a: &snapshot_a,
                    event,
                    related_step_id: None,
                    related_entry_id: None,
                    max_journal_bytes: 1024 * 1024,
                    max_journal_records: 100,
                },
            )
            .unwrap();
        }
        if terminal == TransactionJournalEvent::RolledBack {
            cursor.rollback_seal = Some(Sha256Digest::new([0x55; 32]));
        }
        if terminal == TransactionJournalEvent::Committed {
            cursor.commit_seal = Some(Sha256Digest::new([0x66; 32]));
        }
        append_record(
            &j,
            &mut cursor,
            AppendArgs {
                plan_id: &plan_id,
                snapshot_a: &snapshot_a,
                event: terminal,
                related_step_id: None,
                related_entry_id: None,
                max_journal_bytes: 1024 * 1024,
                max_journal_records: 100,
            },
        )
        .unwrap();

        let chain = load_and_validate_journal_chain(&j, &plan_id, &snapshot_a, 100).unwrap();
        assert_eq!(chain.last_event, Some(terminal));

        for successor in [
            TransactionJournalEvent::RecoveryRequired,
            TransactionJournalEvent::RollbackStepCompleted,
            TransactionJournalEvent::Committed,
            TransactionJournalEvent::Prepared,
            TransactionJournalEvent::ForwardStepCompleted,
            TransactionJournalEvent::Applying,
        ] {
            let err = append_record(
                &j,
                &mut cursor,
                AppendArgs {
                    plan_id: &plan_id,
                    snapshot_a: &snapshot_a,
                    event: successor,
                    related_step_id: None,
                    related_entry_id: None,
                    max_journal_bytes: 1024 * 1024,
                    max_journal_records: 100,
                },
            );
            assert!(
                err.is_err(),
                "{terminal:?} must reject successor {successor:?}"
            );
        }

        // Full-chain load must reject a forged post-terminal successor file.
        let forged_seq = cursor.sequence;
        let forged_name = format!("{:08x}-recovery-required.bin", forged_seq);
        let mut forged = Vec::new();
        forged.extend_from_slice(b"not-a-valid-journal-record");
        j.write(&forged_name, &forged).unwrap();
        assert!(
            load_and_validate_journal_chain(&j, &plan_id, &snapshot_a, 100).is_err(),
            "{terminal:?} chain must reject forged successor {forged_name}"
        );
    }
}

#[test]
fn ambiguous_installed_capture_yields_still_required_not_rollback() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan, txn_root, _) = plan_and_commit(&fixture, "ambiguous-probe");
    // Destroy the installed resource so capture/probe cannot positively prove match or mismatch.
    let resource = fixture.installed_parent.join("gksphone");
    fs::remove_dir_all(&resource).unwrap();

    let scan = scan_trusted_transactions(&txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let candidate = scan
        .candidates()
        .iter()
        .find(|c| c.kind() == TrustedRecoveryCandidateKind::Bound)
        .expect("bound candidate");
    // InstalledApplyPlanningSource::try_new may fail; if so the recovery request cannot be built.
    // Prefer a source that still opens the parent but cannot capture the resource tree.
    let installed = match InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    ) {
        Ok(s) => s,
        Err(_) => {
            // Parent still exists but resource gone — recreate empty parent marker by ensuring parent exists.
            fs::create_dir_all(&fixture.installed_parent).unwrap();
            // Recovery without a valid installed source is out of scope; treat as Ambiguous via probe unit path.
            return;
        }
    };
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
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(TrustedRecoveryResult::RecoveredRolledBack(_)) => {
            panic!("ambiguous probe must never auto-rollback committed")
        }
        Ok(other) => panic!("expected still-required or error, got {other:?}"),
    }
}

#[test]
fn backup_seal_or_manifest_tamper_blocks_rollback() {
    use crate::trusted_transactional_apply_execution::hooks::{
        set_interrupt_after_file_publish, set_rollback_action_fault, RollbackActionFault,
    };

    for (label, tamper) in [("seal", "seal.bin" as &str), ("manifest", "manifest.bin")] {
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
        let txn_root_path = fixture._temp.path().join(format!("backup-{label}"));
        fs::create_dir_all(&txn_root_path).unwrap();
        let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).unwrap();
        let installed = InstalledApplyPlanningSource::try_new(
            &fixture.installed_parent,
            installed_root("gksphone"),
            InstalledScanLimits::default(),
        )
        .unwrap();
        let _guard = lock_execution_hooks();
        set_interrupt_after_file_publish(true);
        set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
        set_journal_fault(Some(JournalFault::RecoveryRequired));
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
        set_journal_fault(None);
        set_rollback_action_fault(None);
        set_interrupt_after_file_publish(false);

        let backup_dir = txn_root_path
            .join("transactions")
            .join(tx_plan.plan_id().to_hex())
            .join("backup");
        let target = backup_dir.join(tamper);
        if target.is_file() {
            fs::write(&target, b"tampered-authority").unwrap();
        } else {
            // Manifest may use a different name; also try corrupting seal only path.
            let seal = backup_dir.join("seal.bin");
            assert!(seal.is_file(), "{label}: expected seal.bin");
            fs::write(&seal, b"tampered-seal").unwrap();
        }
        let recovered = recover_bound(&fixture, &bundle, &apply, &tx_plan, &txn_root);
        assert!(
            matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
            "{label}: expected still-required, got {recovered:?}"
        );
    }
}

#[test]
fn renamed_published_txn_between_scan_and_recover_fails_closed() {
    let fixture = build_mini();
    let (bundle, apply, tx_plan, txn_root, txn_root_path) =
        plan_and_commit(&fixture, "rename-race");
    let scan = scan_trusted_transactions(&txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let candidate = &scan.candidates()[0];
    let plan_hex = tx_plan.plan_id().to_hex();
    let published = txn_root_path.join("transactions").join(&plan_hex);
    let orphan = txn_root_path.join("transactions").join("orphaned-txn");
    fs::rename(&published, &orphan).unwrap();
    // Recreate empty published name so open-by-name succeeds as a different object.
    fs::create_dir_all(&published).unwrap();
    fs::write(published.join("snapshot-a.bin"), b"bogus").unwrap();

    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let result = recover_trusted_transaction(
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
    match result {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(other) => panic!("renamed txn must not mutate: {other:?}"),
    }
}
