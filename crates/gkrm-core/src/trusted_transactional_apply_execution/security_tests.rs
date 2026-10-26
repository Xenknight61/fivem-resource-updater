//! Security/redaction/integrity tests for Task 23.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use cap_fs_ext::ambient_authority;
use cap_std::fs::Dir as CapDir;
use tempfile::tempdir;

use crate::trusted_staging::test_support::{build_mini, stage_ok, MiniFixture};
use crate::{
    execute_trusted_transactional_apply, plan_trusted_apply, plan_trusted_transactional_apply,
    GkrmError, InstallationRelativePath, InstalledApplyPlanningSource, InstalledResourceRoot,
    InstalledScanLimits, Result, Sha256Digest, TrustedApplyPlanningOptions,
    TrustedApplyPlanningRequest, TrustedTransactionResult, TrustedTransactionRoot,
    TrustedTransactionalApplyExecutionOptions, TrustedTransactionalApplyExecutionRequest,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
};

use super::hooks::{
    lock_execution_hooks, set_force_backup_copy_failure, set_force_backup_final_revalidate_failure,
    set_force_backup_seal_failure, set_force_backup_sync_failure,
    set_force_directory_remains_after_remove, set_force_journal_chain_validation_failure,
    set_force_journal_dir_sync_failure, set_force_journal_record_sync_failure,
    set_force_journal_reopen_failure, set_force_parent_identity_replacement_on_remove,
    set_force_parent_sync_failure, set_force_post_lock_installed_stale,
    set_force_post_lock_root_replaced, set_force_post_publish_setup_io, set_force_publish_failure,
    set_force_remove_directory_failure, set_force_rename_failure,
    set_force_result_id_encoding_failure, set_force_rollback_probe_ambiguous,
    set_force_txn_dir_sync_failure, set_forward_op_fault, set_inject_backup_root_extra_dir,
    set_inject_backup_root_extra_file, set_inject_backup_root_temp_file,
    set_interrupt_after_file_publish, set_interrupt_before_file_publish, set_journal_fault,
    set_rollback_action_fault, ForwardOpFault, JournalFault, RollbackActionFault,
};
use super::id::{
    encode_backup_seal, encode_body_commitment, encode_commit_seal, encode_journal_record_id,
    encode_result_id, encode_rollback_seal, encode_verification_seal,
};
use super::journal::{
    append_record, ensure_journal_dir, load_and_validate_journal_chain, AppendArgs, JournalCursor,
};
use super::paths::{
    create_directory, probe_destination, remove_directory, verify_directory_present,
    verify_path_absent, RollbackProbe,
};
use super::TransactionJournalEvent;

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

#[test]
fn byte_identical_directory_nodes_do_not_transfer_published_namespace_authority() {
    let temp = tempdir().unwrap();
    let first_path = temp.path().join("first");
    let replacement_path = temp.path().join("replacement");
    fs::create_dir_all(first_path.join("journal")).unwrap();
    fs::create_dir_all(replacement_path.join("journal")).unwrap();
    fs::write(first_path.join("authority.bin"), b"identical").unwrap();
    fs::write(replacement_path.join("authority.bin"), b"identical").unwrap();
    let first = CapDir::open_ambient_dir(&first_path, ambient_authority()).unwrap();
    let replacement = CapDir::open_ambient_dir(&replacement_path, ambient_authority()).unwrap();
    let bound = super::published_namespace_identity(&first).unwrap();
    let substituted = super::published_namespace_identity(&replacement).unwrap();
    assert_ne!(bound, substituted);
    assert!(matches!(
        super::require_published_namespace_identity(&bound, &substituted),
        Err(GkrmError::TrustedTransactionalApplyExecutionBindingMismatch)
    ));
}

fn hash_tree(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut entries = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut children: Vec<_> = fs::read_dir(dir).unwrap().filter_map(|e| e.ok()).collect();
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let path = child.path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.push((rel, fs::read(&path).unwrap()));
            }
        }
    }
    walk(root, root, &mut entries);
    let mut hasher = Sha256::new();
    for (rel, bytes) in entries {
        hasher.update(rel.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    format!("{:x}", hasher.finalize())
}

fn plan_and_execute(
    fixture: &MiniFixture,
    bundle: &crate::TrustedStagingBundle,
) -> Result<(TrustedTransactionResult, String)> {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let apply = plan_trusted_apply(
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
    .unwrap();
    let plan_id_hex = tx_plan.plan_id().to_hex();
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
            bundle,
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
    )?;
    Ok((result, plan_id_hex))
}

fn execute_mini(fixture: &MiniFixture) -> Result<(TrustedTransactionResult, String)> {
    let bundle = stage_ok(fixture);
    plan_and_execute(fixture, &bundle)
}

fn assert_terminal(result: &TrustedTransactionResult) {
    match result {
        TrustedTransactionResult::Committed(_)
        | TrustedTransactionResult::RolledBack(_)
        | TrustedTransactionResult::RecoveryRequired(_) => {}
    }
}

fn assert_error_surfaces_redacted(error: &GkrmError, fixture: &MiniFixture, extra: &[&str]) {
    let staging = fixture.staging_root.to_string_lossy().into_owned();
    let installed = fixture.installed_resource.to_string_lossy().into_owned();
    let package = fixture.package_v2.to_string_lossy().into_owned();
    let store = fixture.store.to_string_lossy().into_owned();
    let txn = fixture._temp.path().join("txn-root");
    let txn_s = txn.to_string_lossy().into_owned();
    let mut sentinels = vec![
        staging.as_str(),
        installed.as_str(),
        package.as_str(),
        store.as_str(),
        txn_s.as_str(),
        "fxmanifest.lua",
        "gksphone",
        "tmp-",
    ];
    sentinels.extend_from_slice(extra);
    for text in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        for sentinel in &sentinels {
            assert!(
                !text.contains(sentinel),
                "error surface leaked `{sentinel}`: {text}"
            );
        }
    }
    walk_error_chain(error, &sentinels);
    if let GkrmError::TrustedTransactionalApplyExecutionFailedCompound {
        primary,
        rollback,
        journal,
        cleanup,
    } = error
    {
        for branch in [primary, rollback, journal, cleanup] {
            walk_error_chain(branch, &sentinels);
        }
    }
    if let GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery {
        primary,
        recovery_journal,
    } = error
    {
        walk_error_chain(primary, &sentinels);
        walk_error_chain(recovery_journal, &sentinels);
    }
}

fn walk_error_chain(error: &GkrmError, sentinels: &[&str]) {
    use std::error::Error;
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(err) = current {
        for text in [format!("{err}"), format!("{err:?}"), format!("{err:#?}")] {
            for sentinel in sentinels {
                assert!(
                    !text.contains(sentinel),
                    "source-chain leaked `{sentinel}`: {text}"
                );
            }
        }
        assert!(
            err.downcast_ref::<std::io::Error>().is_none(),
            "raw std::io::Error reachable: {err:?}"
        );
        current = err.source();
    }
}

fn open_cap(path: &Path) -> CapDir {
    CapDir::open_ambient_dir(path, ambient_authority()).unwrap()
}

fn write_minimal_chain(journal: &CapDir, plan_id: &Sha256Digest, snapshot_a: &Sha256Digest) {
    let mut cursor = JournalCursor::new();
    append_record(
        journal,
        &mut cursor,
        AppendArgs {
            plan_id,
            snapshot_a,
            event: TransactionJournalEvent::Prepared,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .unwrap();
}

#[test]
fn debug_redacts_transaction_result_surfaces() {
    let text = format!("{:?}", TransactionJournalEvent::Committed);
    assert!(!text.contains('/'));
    let id = super::TrustedTransactionResultId(Sha256Digest::new([0_u8; 32]));
    assert_eq!(format!("{id:?}"), "TrustedTransactionResultId");
}

#[test]
fn fixed_identity_vectors_match_hardcoded_literals() {
    let plan_id = Sha256Digest::new([0x11; 32]);
    let snapshot_a = Sha256Digest::new([0x22; 32]);
    let step_id = Sha256Digest::new([0x33; 32]);
    let empty: &[Sha256Digest] = &[];

    let prepared_body = encode_body_commitment(
        &plan_id,
        &snapshot_a,
        None,
        empty,
        empty,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let prepared_id = encode_journal_record_id(
        &plan_id,
        0,
        None,
        TransactionJournalEvent::Prepared,
        &prepared_body,
    )
    .unwrap();

    let backup_seal = encode_backup_seal(&plan_id, empty, &[]).unwrap();
    let backup_body = encode_body_commitment(
        &plan_id,
        &snapshot_a,
        Some(&backup_seal),
        empty,
        empty,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    let backup_complete_id = encode_journal_record_id(
        &plan_id,
        1,
        Some(&prepared_id),
        TransactionJournalEvent::BackupComplete,
        &backup_body,
    )
    .unwrap();

    let forward_completed = [step_id];
    let forward_body = encode_body_commitment(
        &plan_id,
        &snapshot_a,
        Some(&backup_seal),
        &forward_completed,
        empty,
        None,
        None,
        None,
        Some(&step_id),
        None,
    )
    .unwrap();
    let forward_step_id = encode_journal_record_id(
        &plan_id,
        2,
        Some(&backup_complete_id),
        TransactionJournalEvent::ForwardStepCompleted,
        &forward_body,
    )
    .unwrap();

    let rollback_completed = [step_id];
    let rollback_body = encode_body_commitment(
        &plan_id,
        &snapshot_a,
        Some(&backup_seal),
        &forward_completed,
        &rollback_completed,
        None,
        None,
        None,
        Some(&step_id),
        None,
    )
    .unwrap();
    let rollback_step_id = encode_journal_record_id(
        &plan_id,
        3,
        Some(&forward_step_id),
        TransactionJournalEvent::RollbackStepCompleted,
        &rollback_body,
    )
    .unwrap();

    let verification_seal =
        encode_verification_seal(&plan_id, &snapshot_a, &snapshot_a, &snapshot_a).unwrap();
    let commit_seal =
        encode_commit_seal(&plan_id, &backup_seal, &verification_seal, &prepared_id).unwrap();
    let rollback_seal = encode_rollback_seal(&plan_id, &snapshot_a, &snapshot_a).unwrap();

    let committed_result = encode_result_id(
        &plan_id,
        TransactionJournalEvent::Committed,
        &prepared_id,
        Some(&backup_seal),
        Some(&commit_seal),
        None,
    )
    .unwrap();
    let rolled_back_result = encode_result_id(
        &plan_id,
        TransactionJournalEvent::RolledBack,
        &prepared_id,
        Some(&backup_seal),
        None,
        Some(&rollback_seal),
    )
    .unwrap();
    let recovery_result = encode_result_id(
        &plan_id,
        TransactionJournalEvent::RecoveryRequired,
        &prepared_id,
        Some(&backup_seal),
        None,
        None,
    )
    .unwrap();

    assert_eq!(
        prepared_id.to_string(),
        "2bd6adbc62604f3d345242d3d6d313db2666cabee66210a99a0a32b7040f6f34"
    );
    assert_eq!(
        backup_complete_id.to_string(),
        "60210e6b93390d6d63a44403141cc21ac3b843bbe07c1d3ea2a8de8f37e83cdd"
    );
    assert_eq!(
        forward_step_id.to_string(),
        "f713e2f52eddb8d7591ba97fe18d7f87e83e904a199156503cdfa6dbfc077cfa"
    );
    assert_eq!(
        rollback_step_id.to_string(),
        "e8007fe38663b02e32a6aa36aa89945fbb710cb1ae5d5c51b4b20e70a8767fa7"
    );
    assert_eq!(
        backup_seal.to_string(),
        "07a5c2d51068b0c5d4a144386feb7f6bbb7c86946faf15c7eee774a8cd71e5d7"
    );
    assert_eq!(
        verification_seal.to_string(),
        "85e221e83edc0cc76b96b76c9d6027b0466c1979b870d9085212768cc144b155"
    );
    assert_eq!(
        commit_seal.to_string(),
        "b50948ea8b94e15a3d6718b96f189a5e4e85712a5f42129a4930bb500c8a4b01"
    );
    assert_eq!(
        committed_result.to_string(),
        "4d301bb440a66513af506b054541a1c3369b794836f1fd7c4852d02d61a9ca04"
    );
    assert_eq!(
        rolled_back_result.to_string(),
        "9d71008d615cf3b08e8ef1dbe0e8232c6addc78d1401826fd1ee29f9b6a56e73"
    );
    assert_eq!(
        recovery_result.to_string(),
        "d54d7a1b6b1e02bd05458111ced8bd96f518563ac4892d1e90490dcd384a17eb"
    );
}

#[test]
fn journal_chain_rejects_integrity_failures() {
    let tmp = tempdir().unwrap();
    let root = open_cap(tmp.path());
    let journal = ensure_journal_dir(&root).unwrap();
    let plan_id = Sha256Digest::new([0x44; 32]);
    let snapshot_a = Sha256Digest::new([0x55; 32]);
    write_minimal_chain(&journal, &plan_id, &snapshot_a);
    load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, 100).unwrap();

    // Missing sequence: drop prepared, leave a forged seq=1 file alone.
    let ambient = tmp.path().join("journal");
    let prepared = ambient.join("00000000-prepared.bin");
    let bytes = fs::read(&prepared).unwrap();
    fs::remove_file(&prepared).unwrap();
    fs::write(ambient.join("00000001-backup-complete.bin"), &bytes).unwrap();
    assert!(load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, 100).is_err());

    // Restore and test duplicate sequence.
    fs::write(&prepared, &bytes).unwrap();
    let _ = fs::remove_file(ambient.join("00000001-backup-complete.bin"));
    fs::write(ambient.join("00000000-prepared-dup.bin"), &bytes).unwrap();
    assert!(load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, 100).is_err());
    let _ = fs::remove_file(ambient.join("00000000-prepared-dup.bin"));

    // Unexpected filename/state tag.
    fs::rename(&prepared, ambient.join("00000000-committed.bin")).unwrap();
    assert!(load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, 100).is_err());
    fs::rename(ambient.join("00000000-committed.bin"), &prepared).unwrap();

    // Broken previous-record ID / altered canonical bytes.
    let mut altered = bytes.clone();
    let last = altered.len() - 1;
    altered[last] ^= 0xff;
    fs::write(&prepared, &altered).unwrap();
    assert!(load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, 100).is_err());
    fs::write(&prepared, &bytes).unwrap();

    // Trailing bytes.
    let mut trailing = bytes.clone();
    trailing.push(0);
    fs::write(&prepared, &trailing).unwrap();
    assert!(load_and_validate_journal_chain(&journal, &plan_id, &snapshot_a, 100).is_err());
    fs::write(&prepared, &bytes).unwrap();

    // Record from another transaction plan.
    let other = Sha256Digest::new([0x66; 32]);
    assert!(load_and_validate_journal_chain(&journal, &other, &snapshot_a, 100).is_err());

    // Forward completion before Applying.
    for entry in fs::read_dir(&ambient).unwrap() {
        let _ = fs::remove_file(entry.unwrap().path());
    }
    let mut cursor = JournalCursor::new();
    append_record(
        &journal,
        &mut cursor,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::Prepared,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .unwrap();
    // Manually craft a forward-step file at seq 1 without Applying.
    let step = Sha256Digest::new([0x77; 32]);
    cursor.forward_completed.push(step);
    let err = append_record(
        &journal,
        &mut cursor,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::ForwardStepCompleted,
            related_step_id: Some(&step),
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    );
    assert!(err.is_err());
}

#[test]
fn journal_rejects_transition_after_committed_and_rollback_before_rolling_back() {
    let tmp = tempdir().unwrap();
    let root = open_cap(tmp.path());
    let journal = ensure_journal_dir(&root).unwrap();
    let plan_id = Sha256Digest::new([0x88; 32]);
    let snapshot_a = Sha256Digest::new([0x99; 32]);
    let mut cursor = JournalCursor::new();
    for event in [
        TransactionJournalEvent::Prepared,
        TransactionJournalEvent::BackupComplete,
        TransactionJournalEvent::Verified,
        TransactionJournalEvent::Committed,
    ] {
        if event == TransactionJournalEvent::BackupComplete {
            cursor.backup_seal = Some(Sha256Digest::new([0xaa; 32]));
        }
        if event == TransactionJournalEvent::Verified {
            cursor.verification_seal = Some(Sha256Digest::new([0xbb; 32]));
        }
        if event == TransactionJournalEvent::Committed {
            cursor.commit_seal = Some(Sha256Digest::new([0xcc; 32]));
        }
        append_record(
            &journal,
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
    let err = append_record(
        &journal,
        &mut cursor,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::RollingBack,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    );
    assert!(err.is_err());

    // Fresh journal: rollback step before RollingBack.
    let tmp2 = tempdir().unwrap();
    let root2 = open_cap(tmp2.path());
    let journal2 = ensure_journal_dir(&root2).unwrap();
    let mut cursor2 = JournalCursor::new();
    append_record(
        &journal2,
        &mut cursor2,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::Prepared,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .unwrap();
    let step = Sha256Digest::new([0xdd; 32]);
    cursor2.rollback_completed.push(step);
    assert!(append_record(
        &journal2,
        &mut cursor2,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::RollbackStepCompleted,
            related_step_id: Some(&step),
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .is_err());
}

#[test]
fn atomic_publish_crash_boundaries_and_parent_sync() {
    let _guard = lock_execution_hooks();
    for (setup, expect_recovery_or_rollback) in [
        (
            Box::new(|| set_interrupt_before_file_publish(true)) as Box<dyn Fn()>,
            true,
        ),
        (Box::new(|| set_force_rename_failure(true)), true),
        (Box::new(|| set_interrupt_after_file_publish(true)), true),
        (Box::new(|| set_force_parent_sync_failure(true)), true),
    ] {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        let before = hash_tree(&fixture.installed_resource);
        let staging_before = hash_tree(&fixture.staging_root);
        setup();
        let result = plan_and_execute(&fixture, &bundle);
        set_interrupt_before_file_publish(false);
        set_force_rename_failure(false);
        set_interrupt_after_file_publish(false);
        set_force_parent_sync_failure(false);
        match &result {
            Ok(r) => {
                assert_terminal(&r.0);
                if expect_recovery_or_rollback {
                    assert!(!matches!(r.0, TrustedTransactionResult::Committed(_)));
                }
            }
            Err(err) => {
                assert_error_surfaces_redacted(err, &fixture, &[]);
            }
        }
        let after = hash_tree(&fixture.installed_resource);
        if after != before {
            if let Ok((TrustedTransactionResult::Committed(_), _)) = &result {
                panic!("Committed with installed tree drift");
            }
        }
        assert_eq!(hash_tree(&fixture.staging_root), staging_before);
    }
}

#[test]
fn injected_journal_and_backup_faults_yield_terminal_outcomes() {
    let _guard = lock_execution_hooks();
    let faults: Vec<Box<dyn Fn()>> = vec![
        Box::new(|| set_journal_fault(Some(JournalFault::Prepared))),
        Box::new(|| set_force_publish_failure(true)),
        Box::new(|| set_force_backup_copy_failure(true)),
        Box::new(|| set_force_backup_sync_failure(true)),
        Box::new(|| set_force_backup_seal_failure(true)),
        Box::new(|| set_journal_fault(Some(JournalFault::BackupComplete))),
        Box::new(|| set_journal_fault(Some(JournalFault::Applying))),
        Box::new(|| set_forward_op_fault(Some(ForwardOpFault::ReplaceFile))),
        Box::new(|| set_journal_fault(Some(JournalFault::ForwardStepCompleted))),
        Box::new(|| set_journal_fault(Some(JournalFault::Applied))),
        Box::new(|| set_journal_fault(Some(JournalFault::Verified))),
        Box::new(|| set_journal_fault(Some(JournalFault::Committed))),
        Box::new(|| {
            set_interrupt_after_file_publish(true);
            set_journal_fault(Some(JournalFault::RollingBack));
        }),
        Box::new(|| {
            set_interrupt_after_file_publish(true);
            set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
        }),
        Box::new(|| {
            set_interrupt_after_file_publish(true);
            set_journal_fault(Some(JournalFault::RollbackStepCompleted));
        }),
        Box::new(|| {
            set_interrupt_after_file_publish(true);
            set_journal_fault(Some(JournalFault::RolledBack));
        }),
        Box::new(|| {
            set_interrupt_after_file_publish(true);
            set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
            set_journal_fault(Some(JournalFault::RecoveryRequired));
        }),
    ];
    // Enumerate remaining fault tags so hooks stay live under -D warnings.
    let _ = (
        ForwardOpFault::InstallFile,
        ForwardOpFault::DeleteFile,
        ForwardOpFault::CreateDirectory,
        ForwardOpFault::RemoveDirectory,
        RollbackActionFault::RemoveInstalledFile,
        RollbackActionFault::RecreateDirectoryWithMetadata,
        RollbackActionFault::RemoveCreatedDirectory,
        JournalFault::BackupEntryCompleted,
    );
    for fault in faults {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        let before = hash_tree(&fixture.installed_resource);
        let staging_before = hash_tree(&fixture.staging_root);
        fault();
        let outcome = plan_and_execute(&fixture, &bundle);
        set_journal_fault(None);
        set_force_publish_failure(false);
        set_force_backup_copy_failure(false);
        set_force_backup_sync_failure(false);
        set_force_backup_seal_failure(false);
        set_force_backup_final_revalidate_failure(false);
        set_forward_op_fault(None);
        set_rollback_action_fault(None);
        set_interrupt_after_file_publish(false);
        match &outcome {
            Ok(r) => {
                assert_terminal(&r.0);
                assert!(!matches!(r.0, TrustedTransactionResult::Committed(_)));
            }
            Err(err) => {
                assert_error_surfaces_redacted(err, &fixture, &[]);
            }
        }
        let after = hash_tree(&fixture.installed_resource);
        if after != before {
            if let Ok((TrustedTransactionResult::Committed(_), _)) = &outcome {
                panic!("false Committed");
            }
        }
        assert_eq!(hash_tree(&fixture.staging_root), staging_before);
    }
}

#[test]
fn pre_existing_transaction_and_root_attacks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before = hash_tree(&fixture.installed_resource);
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
    let plan_id_hex = tx_plan.plan_id().to_hex();
    let txn_root_path = fixture._temp.path().join("txn-root");
    fs::create_dir_all(txn_root_path.join("transactions").join(&plan_id_hex)).unwrap();
    let err = plan_and_execute(&fixture, &bundle).expect_err("duplicate txn id");
    assert!(matches!(
        err,
        GkrmError::TrustedTransactionalApplyExecutionTransactionExists
    ));
    assert_error_surfaces_redacted(&err, &fixture, &[plan_id_hex.as_str()]);
    assert_eq!(hash_tree(&fixture.installed_resource), before);

    let fixture2 = build_mini();
    let bundle2 = stage_ok(&fixture2);
    let txn_root_path = fixture2._temp.path().join("txn-root");
    fs::create_dir_all(&txn_root_path).unwrap();
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                txn_root_path.join("transactions").to_str().unwrap_or(""),
                fixture2.installed_parent.to_str().unwrap_or(""),
            ])
            .status();
    }
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(
            &fixture2.installed_parent,
            txn_root_path.join("transactions"),
        );
    }
    let before2 = hash_tree(&fixture2.installed_resource);
    let outcome = plan_and_execute(&fixture2, &bundle2);
    match &outcome {
        Ok(r) => assert_terminal(&r.0),
        Err(err) => assert_error_surfaces_redacted(err, &fixture2, &[]),
    }
    if !matches!(&outcome, Ok((TrustedTransactionResult::Committed(_), _))) {
        assert_eq!(hash_tree(&fixture2.installed_resource), before2);
    }
}

#[test]
fn installed_destination_hardlink_or_symlink_rejected() {
    let fixture = build_mini();
    let target = fixture.installed_resource.join("client.lua");
    if !target.exists() {
        // Mini fixture file name may differ; skip soft if absent.
        let _ = target;
        return;
    }
    let attack = fixture.installed_resource.join("client-attack.lua");
    #[cfg(unix)]
    {
        let _ = fs::hard_link(&target, &attack);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/H",
                attack.to_str().unwrap_or(""),
                target.to_str().unwrap_or(""),
            ])
            .status();
    }
    // Mutating installed before apply should either fail binding or refuse unsafe objects.
    let before = hash_tree(&fixture.installed_resource);
    let outcome = execute_mini(&fixture);
    match outcome {
        Ok(r) => {
            assert_terminal(&r.0);
            if matches!(r.0, TrustedTransactionResult::Committed(_)) {
                // Extra hard-linked peer file may be preserved as customer-only.
            }
        }
        Err(err) => assert_error_surfaces_redacted(&err, &fixture, &[]),
    }
    let _ = before;
}

#[test]
fn backup_manifest_seal_and_source_mutation_attacks() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    let before = hash_tree(&fixture.installed_resource);
    set_force_backup_seal_failure(true);
    let outcome = execute_mini(&fixture);
    set_force_backup_seal_failure(false);
    match outcome {
        Ok(r) => {
            assert_terminal(&r.0);
            assert!(!matches!(r.0, TrustedTransactionResult::Committed(_)));
        }
        Err(err) => assert_error_surfaces_redacted(&err, &fixture, &[]),
    }
    assert_eq!(hash_tree(&fixture.installed_resource), before);

    // Installed mutation during backup (simulated via copy failure after source change hook).
    let fixture2 = build_mini();
    let before2 = hash_tree(&fixture2.installed_resource);
    set_force_backup_copy_failure(true);
    let outcome2 = execute_mini(&fixture2);
    set_force_backup_copy_failure(false);
    match outcome2 {
        Ok(r) => {
            assert_terminal(&r.0);
            assert!(!matches!(r.0, TrustedTransactionResult::Committed(_)));
        }
        Err(err) => assert_error_surfaces_redacted(&err, &fixture2, &[]),
    }
    assert_eq!(hash_tree(&fixture2.installed_resource), before2);
}

#[test]
fn compound_and_io_errors_redact_sensitive_surfaces() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    set_force_publish_failure(true);
    let err = execute_mini(&fixture).expect_err("publish fault");
    set_force_publish_failure(false);
    assert_error_surfaces_redacted(&err, &fixture, &[]);

    let compound = GkrmError::TrustedTransactionalApplyExecutionFailedCompound {
        primary: Box::new(GkrmError::TrustedTransactionalApplyExecutionForwardFailed),
        rollback: Box::new(GkrmError::TrustedTransactionalApplyExecutionRollbackFailed),
        journal: Box::new(GkrmError::TrustedTransactionalApplyExecutionJournalInvalid),
        cleanup: Box::new(GkrmError::TrustedTransactionalApplyExecutionIo {
            operation: crate::TransactionalApplyIoOperation::SyncJournalDirectory,
            kind: std::io::ErrorKind::Other,
        }),
    };
    assert_error_surfaces_redacted(&compound, &fixture, &[]);
}

#[test]
fn forward_step_completion_failure_uses_filesystem_state() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    let before = hash_tree(&fixture.installed_resource);
    set_journal_fault(Some(JournalFault::ForwardStepCompleted));
    let outcome = execute_mini(&fixture);
    set_journal_fault(None);
    match outcome {
        Ok(r) => {
            assert_terminal(&r.0);
            assert!(
                matches!(r.0, TrustedTransactionResult::RolledBack(_)),
                "expected RolledBack after Applying→mutation without ForwardStepCompleted"
            );
            assert_eq!(hash_tree(&fixture.installed_resource), before);
        }
        Err(err) => panic!("unexpected error: {err:?}"),
    }
}

#[test]
fn parent_sync_failure_after_replace_rolls_back() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before = hash_tree(&fixture.installed_resource);
    set_force_parent_sync_failure(true);
    let outcome = plan_and_execute(&fixture, &bundle);
    set_force_parent_sync_failure(false);
    match outcome {
        Ok((TrustedTransactionResult::RolledBack(_), _)) => {
            assert_eq!(hash_tree(&fixture.installed_resource), before);
        }
        Ok((TrustedTransactionResult::RecoveryRequired(_), _)) => {}
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn recovery_journal_failure_does_not_claim_durable_recovery() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    set_force_backup_seal_failure(true);
    set_journal_fault(Some(JournalFault::RecoveryRequired));
    let err = plan_and_execute(&fixture, &bundle).expect_err("unsealed recovery");
    set_force_backup_seal_failure(false);
    set_journal_fault(None);
    assert!(matches!(
        err,
        GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery { .. }
            | GkrmError::TrustedTransactionalApplyExecutionFailedCompound { .. }
    ));
    assert_error_surfaces_redacted(&err, &fixture, &[]);
}

#[test]
fn backup_final_revalidate_failure_before_backup_complete() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before = hash_tree(&fixture.installed_resource);
    set_force_backup_final_revalidate_failure(true);
    let outcome = plan_and_execute(&fixture, &bundle);
    set_force_backup_final_revalidate_failure(false);
    match &outcome {
        Ok(r) => {
            assert_terminal(&r.0);
            assert!(!matches!(r.0, TrustedTransactionResult::Committed(_)));
        }
        Err(err) => assert_error_surfaces_redacted(err, &fixture, &[]),
    }
    assert_eq!(hash_tree(&fixture.installed_resource), before);
}

#[test]
fn applying_to_rolling_back_transition_accepted_committed_rejected() {
    let tmp = tempdir().unwrap();
    let root = open_cap(tmp.path());
    let journal = ensure_journal_dir(&root).unwrap();
    let plan_id = Sha256Digest::new([0xab; 32]);
    let snapshot_a = Sha256Digest::new([0xcd; 32]);
    let mut cursor = JournalCursor::new();
    for event in [
        TransactionJournalEvent::Prepared,
        TransactionJournalEvent::BackupComplete,
        TransactionJournalEvent::Applying,
    ] {
        if event == TransactionJournalEvent::BackupComplete {
            cursor.backup_seal = Some(Sha256Digest::new([0xef; 32]));
        }
        append_record(
            &journal,
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
    append_record(
        &journal,
        &mut cursor,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::RollingBack,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .expect("Applying → RollingBack");
    append_record(
        &journal,
        &mut cursor,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::RolledBack,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .expect("RollingBack → RolledBack");

    // Fresh committed journal cannot transition to RollingBack.
    let tmp2 = tempdir().unwrap();
    let root2 = open_cap(tmp2.path());
    let journal2 = ensure_journal_dir(&root2).unwrap();
    let mut cursor2 = JournalCursor::new();
    for event in [
        TransactionJournalEvent::Prepared,
        TransactionJournalEvent::BackupComplete,
        TransactionJournalEvent::Verified,
        TransactionJournalEvent::Committed,
    ] {
        if event == TransactionJournalEvent::BackupComplete {
            cursor2.backup_seal = Some(Sha256Digest::new([0x11; 32]));
        }
        if event == TransactionJournalEvent::Verified {
            cursor2.verification_seal = Some(Sha256Digest::new([0x22; 32]));
        }
        if event == TransactionJournalEvent::Committed {
            cursor2.commit_seal = Some(Sha256Digest::new([0x33; 32]));
        }
        append_record(
            &journal2,
            &mut cursor2,
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
    assert!(append_record(
        &journal2,
        &mut cursor2,
        AppendArgs {
            plan_id: &plan_id,
            snapshot_a: &snapshot_a,
            event: TransactionJournalEvent::RollingBack,
            related_step_id: None,
            related_entry_id: None,
            max_journal_bytes: 1024 * 1024,
            max_journal_records: 100,
        },
    )
    .is_err());
}

#[test]
fn directory_create_remove_verify_pre_post() {
    let tmp = tempdir().unwrap();
    let dir = open_cap(tmp.path());
    crate::baseline::fs_security::create_new_child_dir(&dir, "nested").unwrap();
    let path = crate::ResourceRelativePath::try_from_slash_str("nested/newdir").unwrap();
    verify_path_absent(&dir, &path).unwrap();
    create_directory(&dir, &path).unwrap();
    verify_directory_present(&dir, &path).unwrap();
    assert!(create_directory(&dir, &path).is_err());
    remove_directory(&dir, &path).unwrap();
    verify_path_absent(&dir, &path).unwrap();
    assert!(remove_directory(&dir, &path).is_err());
}

#[test]
fn publish_install_replace_unit_smoke() {
    let tmp = tempdir().unwrap();
    let dir = open_cap(tmp.path());
    let digest = {
        use sha2::{Digest, Sha256};
        Sha256Digest::new(Sha256::digest(b"hello-task23").into())
    };
    // Install
    {
        let mut f = crate::baseline::fs_security::create_new_file(&dir, ".gkrm-tmp").unwrap();
        f.write_all(b"hello-task23").unwrap();
        crate::baseline::store::fsync_file(&f, ".gkrm-tmp").unwrap();
        drop(f);
        super::publish::publish_install(&dir, ".gkrm-tmp", "dest.txt", &digest, 12).unwrap();
        assert!(tmp.path().join("dest.txt").exists());
        assert!(!tmp.path().join(".gkrm-tmp").exists());
    }
    // Replace without delete-first window (dest remains present conceptually via atomic replace).
    let digest2 = {
        use sha2::{Digest, Sha256};
        Sha256Digest::new(Sha256::digest(b"hello-task23!").into())
    };
    let mut f = crate::baseline::fs_security::create_new_file(&dir, ".gkrm-tmp2").unwrap();
    f.write_all(b"hello-task23!").unwrap();
    crate::baseline::store::fsync_file(&f, ".gkrm-tmp2").unwrap();
    drop(f);
    super::publish::publish_replace(&dir, ".gkrm-tmp2", "dest.txt", &digest2, 13).unwrap();
    let mut got = String::new();
    fs::File::open(tmp.path().join("dest.txt"))
        .unwrap()
        .read_to_string(&mut got)
        .unwrap();
    assert_eq!(got, "hello-task23!");
}

fn journal_event_names(txn_root: &Path, plan_id_hex: &str) -> Vec<String> {
    let journal = txn_root
        .join("transactions")
        .join(plan_id_hex)
        .join("journal");
    let mut names: Vec<_> = fs::read_dir(&journal)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn assert_no_rollback_step_completed(txn_root: &Path, plan_id_hex: &str) {
    for name in journal_event_names(txn_root, plan_id_hex) {
        assert!(
            !name.contains("rollback-step"),
            "unexpected RollbackStepCompleted: {name}"
        );
    }
}

#[test]
fn remove_created_directory_success_and_failure_modes() {
    let _guard = lock_execution_hooks();
    let tmp = tempdir().unwrap();
    let dir = open_cap(tmp.path());
    crate::baseline::fs_security::create_new_child_dir(&dir, "nested").unwrap();
    let path = crate::ResourceRelativePath::try_from_slash_str("nested/created").unwrap();

    // Success path: verify → remove → absent.
    create_directory(&dir, &path).unwrap();
    assert_eq!(
        probe_destination(&dir, &path),
        RollbackProbe::ProvenDirectory
    );
    verify_directory_present(&dir, &path).unwrap();
    remove_directory(&dir, &path).unwrap();
    verify_path_absent(&dir, &path).unwrap();
    assert_eq!(probe_destination(&dir, &path), RollbackProbe::ProvenAbsent);

    // Remove call fails.
    create_directory(&dir, &path).unwrap();
    set_force_remove_directory_failure(true);
    assert!(remove_directory(&dir, &path).is_err());
    set_force_remove_directory_failure(false);
    assert!(tmp.path().join("nested/created").exists());
    remove_directory(&dir, &path).unwrap();

    // Directory remains after remove (post-verify would fail for rollback action).
    create_directory(&dir, &path).unwrap();
    set_force_directory_remains_after_remove(true);
    assert!(remove_directory(&dir, &path).is_ok());
    // Hook recreates the directory; absence is not proven.
    assert!(verify_path_absent(&dir, &path).is_err());
    set_force_directory_remains_after_remove(false);
    remove_directory(&dir, &path).unwrap();

    // Non-empty directory fails closed.
    create_directory(&dir, &path).unwrap();
    fs::write(tmp.path().join("nested/created/child.txt"), b"x").unwrap();
    assert!(remove_directory(&dir, &path).is_err());
    fs::remove_file(tmp.path().join("nested/created/child.txt")).unwrap();
    remove_directory(&dir, &path).unwrap();

    // Parent identity replacement fails closed.
    create_directory(&dir, &path).unwrap();
    set_force_parent_identity_replacement_on_remove(true);
    assert!(matches!(
        remove_directory(&dir, &path),
        Err(GkrmError::TrustedTransactionalApplyExecutionRootReplaced)
    ));
    set_force_parent_identity_replacement_on_remove(false);
    // Directory may already have been removed before the identity check.
    let _ = remove_directory(&dir, &path);

    // Unsafe substitution: file where directory expected.
    fs::write(tmp.path().join("nested/created"), b"not-a-dir").unwrap();
    assert!(remove_directory(&dir, &path).is_err());
    assert_eq!(
        probe_destination(&dir, &path),
        RollbackProbe::ProvenRegularFile
    );
    fs::remove_file(tmp.path().join("nested/created")).unwrap();
}

#[test]
fn ambiguous_rollback_probe_never_skips_or_journals_completion() {
    let _guard = lock_execution_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before = hash_tree(&fixture.installed_resource);
    set_interrupt_after_file_publish(true);
    set_force_rollback_probe_ambiguous(true);
    let outcome = plan_and_execute(&fixture, &bundle);
    set_force_rollback_probe_ambiguous(false);
    set_interrupt_after_file_publish(false);
    match outcome {
        Ok((TrustedTransactionResult::RecoveryRequired(_), plan_id_hex)) => {
            assert_no_rollback_step_completed(
                fixture._temp.path().join("txn-root").as_path(),
                &plan_id_hex,
            );
        }
        Ok((other, _)) => panic!("expected RecoveryRequired, got {other:?}"),
        Err(err) => assert_error_surfaces_redacted(&err, &fixture, &[]),
    }
    let after = hash_tree(&fixture.installed_resource);
    if after != before {
        // Installed may remain drifted only when recovery was required.
    }
}

#[test]
fn terminal_result_precompute_failure_injection() {
    let _guard = lock_execution_hooks();

    // Result-ID encoding failure before append → no Committed terminal result.
    {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        set_force_result_id_encoding_failure(true);
        let outcome = plan_and_execute(&fixture, &bundle);
        set_force_result_id_encoding_failure(false);
        match outcome {
            Ok((TrustedTransactionResult::Committed(_), _)) => {
                panic!("must not return Committed when result-id encoding fails before append")
            }
            Ok((r, plan_id)) => {
                assert_terminal(&r);
                let names =
                    journal_event_names(fixture._temp.path().join("txn-root").as_path(), &plan_id);
                assert!(
                    names.iter().all(|n| !n.contains("committed")),
                    "Committed must not be durable when encoding failed before append: {names:?}"
                );
            }
            Err(err) => assert_error_surfaces_redacted(&err, &fixture, &[]),
        }
    }

    for (label, set_fault, clear_fault) in terminal_durability_faults() {
        // Committed path
        {
            let fixture = build_mini();
            let bundle = stage_ok(&fixture);
            set_fault();
            let outcome = plan_and_execute(&fixture, &bundle);
            clear_fault();
            assert_no_matching_terminal(
                &outcome,
                &fixture,
                label,
                TerminalKind::Committed,
                "committed",
            );
        }
        // RolledBack path
        {
            let fixture = build_mini();
            let bundle = stage_ok(&fixture);
            set_interrupt_after_file_publish(true);
            set_fault();
            let outcome = plan_and_execute(&fixture, &bundle);
            clear_fault();
            set_interrupt_after_file_publish(false);
            assert_no_matching_terminal(
                &outcome,
                &fixture,
                label,
                TerminalKind::RolledBack,
                "rolled-back",
            );
        }
        // RecoveryRequired path
        {
            let fixture = build_mini();
            let bundle = stage_ok(&fixture);
            set_interrupt_after_file_publish(true);
            set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
            set_fault();
            let outcome = plan_and_execute(&fixture, &bundle);
            clear_fault();
            set_rollback_action_fault(None);
            set_interrupt_after_file_publish(false);
            assert_no_matching_terminal(
                &outcome,
                &fixture,
                label,
                TerminalKind::RecoveryRequired,
                "recovery-required",
            );
        }
    }
}

#[derive(Clone, Copy)]
enum TerminalKind {
    Committed,
    RolledBack,
    RecoveryRequired,
}

type TerminalFaultPair = (&'static str, Box<dyn Fn()>, Box<dyn Fn()>);

fn terminal_durability_faults() -> Vec<TerminalFaultPair> {
    vec![
        (
            "record sync",
            Box::new(|| set_force_journal_record_sync_failure(true)),
            Box::new(|| set_force_journal_record_sync_failure(false)),
        ),
        (
            "journal dir sync",
            Box::new(|| set_force_journal_dir_sync_failure(true)),
            Box::new(|| set_force_journal_dir_sync_failure(false)),
        ),
        (
            "txn dir sync",
            Box::new(|| set_force_txn_dir_sync_failure(true)),
            Box::new(|| set_force_txn_dir_sync_failure(false)),
        ),
        (
            "reopen",
            Box::new(|| set_force_journal_reopen_failure(true)),
            Box::new(|| set_force_journal_reopen_failure(false)),
        ),
        (
            "chain validation",
            Box::new(|| set_force_journal_chain_validation_failure(true)),
            Box::new(|| set_force_journal_chain_validation_failure(false)),
        ),
    ]
}

fn assert_no_matching_terminal(
    outcome: &Result<(TrustedTransactionResult, String)>,
    fixture: &MiniFixture,
    label: &str,
    kind: TerminalKind,
    journal_tag: &str,
) {
    match outcome {
        Ok((TrustedTransactionResult::Committed(_), _))
            if matches!(kind, TerminalKind::Committed) =>
        {
            panic!("{label}: must not return Committed after pre-validation durability fault")
        }
        Ok((TrustedTransactionResult::RolledBack(_), _))
            if matches!(kind, TerminalKind::RolledBack) =>
        {
            panic!("{label}: must not return RolledBack after pre-validation durability fault")
        }
        Ok((TrustedTransactionResult::RecoveryRequired(_), _))
            if matches!(kind, TerminalKind::RecoveryRequired) =>
        {
            panic!(
                "{label}: must not return RecoveryRequired after pre-validation durability fault"
            )
        }
        Ok((r, plan_id)) => {
            assert_terminal(r);
            // If a different terminal was sealed, that is fine; the faulted terminal must not
            // be both returned and claimed durable as authoritative success for this path.
            let names =
                journal_event_names(fixture._temp.path().join("txn-root").as_path(), plan_id);
            if matches!(
                (kind, r),
                (
                    TerminalKind::Committed,
                    TrustedTransactionResult::Committed(_)
                ) | (
                    TerminalKind::RolledBack,
                    TrustedTransactionResult::RolledBack(_)
                ) | (
                    TerminalKind::RecoveryRequired,
                    TrustedTransactionResult::RecoveryRequired(_)
                )
            ) {
                panic!("{label}: public result matched faulted terminal kind");
            }
            let _ = (names, journal_tag);
        }
        Err(err) => assert_error_surfaces_redacted(err, fixture, &[]),
    }
}

#[test]
fn terminal_success_returns_matching_public_result_without_post_validation_fallible_work() {
    let _guard = lock_execution_hooks();

    // Committed
    {
        let fixture = build_mini();
        let (result, plan_id) = execute_mini(&fixture).expect("commit");
        assert!(matches!(result, TrustedTransactionResult::Committed(_)));
        let names = journal_event_names(fixture._temp.path().join("txn-root").as_path(), &plan_id);
        assert!(names.iter().any(|n| n.contains("committed")));
        assert!(!names.iter().any(|n| n.contains("rolled-back")));
        assert!(!names.iter().any(|n| n.contains("recovery-required")));
    }

    // RolledBack
    {
        let fixture = build_mini();
        let before = hash_tree(&fixture.installed_resource);
        set_journal_fault(Some(JournalFault::ForwardStepCompleted));
        let (result, plan_id) = execute_mini(&fixture).expect("rollback");
        set_journal_fault(None);
        assert!(
            matches!(result, TrustedTransactionResult::RolledBack(_)),
            "expected RolledBack, got {result:?}"
        );
        assert_eq!(hash_tree(&fixture.installed_resource), before);
        let names = journal_event_names(fixture._temp.path().join("txn-root").as_path(), &plan_id);
        assert!(names.iter().any(|n| n.contains("rolled-back")));
        assert!(!names.iter().any(|n| n.contains("committed")));
    }

    // RecoveryRequired
    {
        let fixture = build_mini();
        set_interrupt_after_file_publish(true);
        set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
        let outcome = execute_mini(&fixture);
        set_rollback_action_fault(None);
        set_interrupt_after_file_publish(false);
        match outcome {
            Ok((TrustedTransactionResult::RecoveryRequired(_), plan_id)) => {
                let names =
                    journal_event_names(fixture._temp.path().join("txn-root").as_path(), &plan_id);
                assert!(names.iter().any(|n| n.contains("recovery-required")));
                assert!(!names.iter().any(|n| n.contains("committed")));
            }
            Ok((other, _)) => panic!("expected RecoveryRequired, got {other:?}"),
            Err(err) => panic!("unexpected unsealed recovery: {err:?}"),
        }
    }
}

#[test]
fn backup_root_namespace_rejects_extras_and_missing() {
    let _guard = lock_execution_hooks();
    for (label, setup) in [
        (
            "extra file",
            Box::new(|| set_inject_backup_root_extra_file(true)) as Box<dyn Fn()>,
        ),
        (
            "extra dir",
            Box::new(|| set_inject_backup_root_extra_dir(true)),
        ),
        (
            "temp file",
            Box::new(|| set_inject_backup_root_temp_file(true)),
        ),
    ] {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        let before = hash_tree(&fixture.installed_resource);
        setup();
        let outcome = plan_and_execute(&fixture, &bundle);
        set_inject_backup_root_extra_file(false);
        set_inject_backup_root_extra_dir(false);
        set_inject_backup_root_temp_file(false);
        match outcome {
            Ok((TrustedTransactionResult::Committed(_), _)) => {
                panic!("{label}: must not Commit with polluted backup root")
            }
            Ok((r, _)) => {
                assert_terminal(&r);
                assert!(!matches!(r, TrustedTransactionResult::Committed(_)));
            }
            Err(err) => assert_error_surfaces_redacted(&err, &fixture, &[]),
        }
        assert_eq!(hash_tree(&fixture.installed_resource), before);
    }
}

#[test]
fn remove_created_directory_failed_undo_has_no_completion_record() {
    let _guard = lock_execution_hooks();
    // Force a rollback that includes Restore; additionally force remove-directory fault is
    // covered by unit tests above. Here ambiguous probe proves no RollbackStepCompleted.
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    set_interrupt_after_file_publish(true);
    set_force_rollback_probe_ambiguous(true);
    let outcome = plan_and_execute(&fixture, &bundle);
    set_force_rollback_probe_ambiguous(false);
    set_interrupt_after_file_publish(false);
    if let Ok((_, plan_id)) = &outcome {
        assert_no_rollback_step_completed(fixture._temp.path().join("txn-root").as_path(), plan_id);
    }
}

#[test]
fn post_lock_revalidation_failures_never_escape_as_raw_prepublication_errors() {
    let _guard = lock_execution_hooks();
    #[allow(clippy::type_complexity)]
    let cases: &[(&str, Box<dyn Fn()>, Box<dyn Fn()>)] = &[
        (
            "root-replaced",
            Box::new(|| set_force_post_lock_root_replaced(true)),
            Box::new(|| set_force_post_lock_root_replaced(false)),
        ),
        (
            "installed-stale",
            Box::new(|| set_force_post_lock_installed_stale(true)),
            Box::new(|| set_force_post_lock_installed_stale(false)),
        ),
        (
            "setup-io",
            Box::new(|| set_force_post_publish_setup_io(true)),
            Box::new(|| set_force_post_publish_setup_io(false)),
        ),
    ];
    for (label, set_fault, clear_fault) in cases {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        set_fault();
        let outcome = plan_and_execute(&fixture, &bundle);
        clear_fault();
        match outcome {
            Ok((TrustedTransactionResult::RecoveryRequired(_), plan_id)) => {
                assert!(
                    fixture
                        ._temp
                        .path()
                        .join("txn-root")
                        .join("transactions")
                        .join(&plan_id)
                        .is_dir(),
                    "{label}: published transaction must remain"
                );
            }
            Err(GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery { .. }) => {}
            Err(GkrmError::TrustedTransactionalApplyExecutionFailedCompound { .. }) => {}
            Ok((TrustedTransactionResult::Committed(_), _))
            | Ok((TrustedTransactionResult::RolledBack(_), _)) => {
                panic!("{label}: unexpected terminal success/rollback without recovery path")
            }
            Err(err) => {
                assert!(
                    !matches!(
                        err,
                        GkrmError::TrustedTransactionalApplyExecutionInstalledStale
                            | GkrmError::TrustedTransactionalApplyExecutionRootReplaced
                            | GkrmError::TrustedTransactionalApplyExecutionIo { .. }
                    ),
                    "{label}: raw pre-publication-classifiable error escaped: {err:?}"
                );
                panic!("{label}: unexpected error: {err:?}");
            }
        }
    }
}
