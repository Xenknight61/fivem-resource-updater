//! Same-resource peer safety and capability-rebind regressions for Task 24.

use std::fs;
use std::path::{Path, PathBuf};

use crate::trusted_staging::test_support::{build_mini, stage_ok, MiniFixture};
use crate::trusted_transactional_apply_execution::hooks::{
    lock_execution_hooks, set_interrupt_after_file_publish, set_journal_fault, set_journal_faults,
    set_peer_race_hook, set_rollback_action_fault, JournalFault, PeerRacePoint,
    RollbackActionFault,
};
use crate::trusted_transactional_apply_execution::locks::encode_resource_lock_id;
use crate::trusted_transactional_apply_execution::recovery::binding::VerifiedPublishedTransaction;
use crate::{
    execute_trusted_transactional_apply, plan_trusted_apply, plan_trusted_transactional_apply,
    recover_trusted_transaction, scan_trusted_transactions, InstallationRelativePath,
    InstalledApplyPlanningSource, InstalledResourceRoot, InstalledScanLimits, Sha256Digest,
    TrustedApplyPlan, TrustedApplyPlanningOptions, TrustedApplyPlanningRequest,
    TrustedRecoveryCandidateKind, TrustedRecoveryOptions, TrustedRecoveryResult,
    TrustedRecoveryScanOptions, TrustedStagingBundle, TrustedTransactionRecoveryRequest,
    TrustedTransactionResult, TrustedTransactionRoot, TrustedTransactionalApplyExecutionOptions,
    TrustedTransactionalApplyExecutionRequest, TrustedTransactionalApplyPlan,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
};

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), to).unwrap();
        }
    }
}

fn hash_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn write_resource_lock_file(txn_dir: &Path, lock_id: &Sha256Digest) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"gkrm-txn-resource-lock-id-v1\n");
    bytes.extend_from_slice(lock_id.as_bytes());
    fs::write(txn_dir.join("resource-lock-id.bin"), bytes).unwrap();
}

fn take_lua(fixture: &MiniFixture) -> PathBuf {
    fixture.installed_parent.join("gksphone").join("take.lua")
}

fn open_root(path: &Path) -> TrustedTransactionRoot {
    fs::create_dir_all(path).unwrap();
    TrustedTransactionRoot::try_open(path).unwrap()
}

fn plan_apply_tx(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
) -> (TrustedApplyPlan, TrustedTransactionalApplyPlan) {
    plan_apply_tx_with_apply_options(fixture, bundle, TrustedApplyPlanningOptions::default())
}

fn alt_apply_options() -> TrustedApplyPlanningOptions {
    let mut opts = TrustedApplyPlanningOptions::default();
    opts.max_entries = opts.max_entries.saturating_sub(1).max(16);
    opts
}

fn plan_apply_tx_with_apply_options(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply_options: TrustedApplyPlanningOptions,
) -> (TrustedApplyPlan, TrustedTransactionalApplyPlan) {
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
            apply_options,
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
    (apply, tx_plan)
}

fn execute_tx(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx_plan: &TrustedTransactionalApplyPlan,
    txn_root: &TrustedTransactionRoot,
) -> std::result::Result<TrustedTransactionResult, crate::GkrmError> {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    execute_trusted_transactional_apply(
        TrustedTransactionalApplyExecutionRequest::try_new(
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
            TrustedTransactionalApplyExecutionOptions::default(),
        )
        .unwrap(),
    )
}

fn leave_interrupted(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx_plan: &TrustedTransactionalApplyPlan,
    txn_root: &TrustedTransactionRoot,
) {
    let _guard = lock_execution_hooks();
    set_interrupt_after_file_publish(true);
    set_rollback_action_fault(Some(RollbackActionFault::RestoreInstalledFile));
    set_journal_fault(Some(JournalFault::RecoveryRequired));
    let _ = execute_tx(fixture, bundle, apply, tx_plan, txn_root);
    set_journal_fault(None);
    set_rollback_action_fault(None);
    set_interrupt_after_file_publish(false);
}

fn recover_plan(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx_plan: &TrustedTransactionalApplyPlan,
    txn_root: &TrustedTransactionRoot,
) -> std::result::Result<TrustedRecoveryResult, crate::GkrmError> {
    let plan_id = *tx_plan.plan_id().digest();
    let scan = scan_trusted_transactions(txn_root, TrustedRecoveryScanOptions::default()).unwrap();
    let candidate = scan
        .candidates()
        .iter()
        .find(|c| {
            c.kind() == TrustedRecoveryCandidateKind::Bound && c.proven_plan_id == Some(plan_id)
        })
        .ok_or(crate::GkrmError::TrustedTransactionRecoveryCandidateInvalid)?;
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
}

#[test]
fn older_interrupted_cannot_rollback_over_newer_committed() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed_snap = fixture._temp.path().join("installed-snap");
    copy_dir(&fixture.installed_parent.join("gksphone"), &installed_snap);
    let root_path = fixture._temp.path().join("peer-root");
    let txn_root = open_root(&root_path);

    let (apply1, tx1) = plan_apply_tx(&fixture, &bundle);
    let plan1 = *tx1.plan_id().digest();
    leave_interrupted(&fixture, &bundle, &apply1, &tx1, &txn_root);

    let live = fixture.installed_parent.join("gksphone");
    let _ = fs::remove_dir_all(&live);
    copy_dir(&installed_snap, &live);
    // Alternate optional-analysis binding yields a distinct plan id without InstalledStale.
    let (apply2, tx2) = plan_apply_tx_with_apply_options(&fixture, &bundle, alt_apply_options());
    let plan2 = *tx2.plan_id().digest();
    assert_ne!(plan1, plan2);
    assert!(matches!(
        execute_tx(&fixture, &bundle, &apply2, &tx2, &txn_root).unwrap(),
        TrustedTransactionResult::Committed(_)
    ));
    let committed_bytes = hash_file(&take_lua(&fixture));

    let recovered = recover_plan(&fixture, &bundle, &apply1, &tx1, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "older interrupted must not mutate under newer committed: {recovered:?}"
    );
    assert_eq!(hash_file(&take_lua(&fixture)), committed_bytes);
}

#[test]
fn committed_peer_blocks_interrupted_and_committed_rediscovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed_snap = fixture._temp.path().join("installed-snap-2");
    copy_dir(&fixture.installed_parent.join("gksphone"), &installed_snap);
    let root_path = fixture._temp.path().join("peer-root-2");
    let txn_root = open_root(&root_path);

    let (apply1, tx1) = plan_apply_tx(&fixture, &bundle);
    leave_interrupted(&fixture, &bundle, &apply1, &tx1, &txn_root);

    let live = fixture.installed_parent.join("gksphone");
    let _ = fs::remove_dir_all(&live);
    copy_dir(&installed_snap, &live);
    let (apply2, tx2) = plan_apply_tx_with_apply_options(&fixture, &bundle, alt_apply_options());
    execute_tx(&fixture, &bundle, &apply2, &tx2, &txn_root).unwrap();
    let after = hash_file(&take_lua(&fixture));

    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply1, &tx1, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply2, &tx2, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(hash_file(&take_lua(&fixture)), after);
}

#[test]
fn rolled_back_peer_blocks_later_interrupted_recovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("peer-rb");
    let txn_root = open_root(&root_path);
    let (apply1, tx1) = plan_apply_tx(&fixture, &bundle);
    {
        let _guard = lock_execution_hooks();
        set_interrupt_after_file_publish(true);
        let _ = execute_tx(&fixture, &bundle, &apply1, &tx1, &txn_root);
        set_interrupt_after_file_publish(false);
    }
    let _ = recover_plan(&fixture, &bundle, &apply1, &tx1, &txn_root);

    let (apply2, tx2) = plan_apply_tx_with_apply_options(&fixture, &bundle, alt_apply_options());
    leave_interrupted(&fixture, &bundle, &apply2, &tx2, &txn_root);
    let before = hash_file(&take_lua(&fixture));
    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply2, &tx2, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

#[test]
fn recovery_required_peer_blocks_interrupted_recovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed_snap = fixture._temp.path().join("snap-rr");
    copy_dir(&fixture.installed_parent.join("gksphone"), &installed_snap);
    let root_path = fixture._temp.path().join("peer-rr");
    let txn_root = open_root(&root_path);
    let (apply1, tx1) = plan_apply_tx(&fixture, &bundle);
    {
        let _guard = lock_execution_hooks();
        set_journal_fault(Some(JournalFault::ForwardStepCompleted));
        let _ = execute_tx(&fixture, &bundle, &apply1, &tx1, &txn_root);
        set_journal_fault(None);
    }

    let live = fixture.installed_parent.join("gksphone");
    let _ = fs::remove_dir_all(&live);
    copy_dir(&installed_snap, &live);
    let (apply2, tx2) = plan_apply_tx_with_apply_options(&fixture, &bundle, alt_apply_options());
    leave_interrupted(&fixture, &bundle, &apply2, &tx2, &txn_root);
    let before = hash_file(&take_lua(&fixture));
    match recover_plan(&fixture, &bundle, &apply2, &tx2, &txn_root) {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(other) => panic!("RecoveryRequired peer must block: {other:?}"),
    }
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

#[test]
fn aborted_before_mutation_peer_blocks_interrupted_recovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("peer-abort");
    let txn_root = open_root(&root_path);
    let (apply1, tx1) = plan_apply_tx(&fixture, &bundle);
    {
        let _guard = lock_execution_hooks();
        // Fail at Applying so a published BackupComplete journal remains.
        set_journal_fault(Some(JournalFault::Applying));
        let _ = execute_tx(&fixture, &bundle, &apply1, &tx1, &txn_root);
        set_journal_fault(None);
    }
    // Durable abort when safe; otherwise the published peer still remains.
    let _ = recover_plan(&fixture, &bundle, &apply1, &tx1, &txn_root);

    let (apply2, tx2) = plan_apply_tx_with_apply_options(&fixture, &bundle, alt_apply_options());
    leave_interrupted(&fixture, &bundle, &apply2, &tx2, &txn_root);
    let before = hash_file(&take_lua(&fixture));
    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply2, &tx2, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

#[test]
fn unrelated_resource_peer_does_not_block_recovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("peer-unrelated");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    assert!(matches!(
        execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap(),
        TrustedTransactionResult::Committed(_)
    ));
    let other = root_path
        .join("transactions")
        .join(Sha256Digest::new([0xab; 32]).to_string());
    fs::create_dir_all(&other).unwrap();
    write_resource_lock_file(&other, &Sha256Digest::new([0xcd; 32]));
    fs::create_dir_all(other.join("journal")).unwrap();
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveredCommitted(_)),
        "unrelated resource peer must not block: {recovered:?}"
    );
}

#[test]
fn single_same_resource_transaction_recovers_normally() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("peer-single");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    assert!(matches!(
        execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap(),
        TrustedTransactionResult::Committed(_)
    ));
    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveredCommitted(_)
    ));
}

#[test]
fn torn_same_resource_peer_journal_blocks_without_mutation() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("peer-torn");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let before = hash_file(&take_lua(&fixture));
    let peer = root_path
        .join("transactions")
        .join(Sha256Digest::new([0x11; 32]).to_string());
    fs::create_dir_all(peer.join("journal")).unwrap();
    write_resource_lock_file(&peer, &encode_resource_lock_id("gksphone").unwrap());
    fs::write(peer.join("journal").join("00000000-prepared.bin"), b"torn").unwrap();
    let mut snap_bytes = b"gkrm-txn-snapshot-a-v1\n".to_vec();
    snap_bytes.extend_from_slice(&[0u8; 32]);
    fs::write(peer.join("snapshot-a.bin"), snap_bytes).unwrap();

    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

#[test]
fn unreadable_snapshot_or_lock_peer_blocks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("peer-bad-snap");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let before = hash_file(&take_lua(&fixture));

    let peer = root_path
        .join("transactions")
        .join(Sha256Digest::new([0x22; 32]).to_string());
    fs::create_dir_all(peer.join("journal")).unwrap();
    write_resource_lock_file(&peer, &encode_resource_lock_id("gksphone").unwrap());
    fs::write(peer.join("snapshot-a.bin"), b"bad").unwrap();
    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(hash_file(&take_lua(&fixture)), before);

    let peer2 = root_path
        .join("transactions")
        .join(Sha256Digest::new([0x33; 32]).to_string());
    fs::create_dir_all(&peer2).unwrap();
    fs::write(peer2.join("resource-lock-id.bin"), b"not-a-lock").unwrap();
    assert!(matches!(
        recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap(),
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

#[test]
fn recover_fails_closed_after_journal_or_transactions_replacement() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("rebind-root");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let before = hash_file(&take_lua(&fixture));

    // Journal directory replacement before recover (no live locks held).
    let journal = root_path
        .join("transactions")
        .join(plan_id.to_string())
        .join("journal");
    let orphan_j = root_path.join("orphaned-journal");
    fs::rename(&journal, &orphan_j).unwrap();
    fs::create_dir_all(&journal).unwrap();
    match recover_plan(&fixture, &bundle, &apply, &tx, &txn_root) {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(other) => panic!("journal replacement must fail closed: {other:?}"),
    }
    assert_eq!(hash_file(&take_lua(&fixture)), before);

    // Restore journal and replace transactions parent.
    let _ = fs::remove_dir_all(&journal);
    fs::rename(&orphan_j, &journal).unwrap();
    let transactions = root_path.join("transactions");
    let orphan_p = root_path.join("orphaned-transactions");
    fs::rename(&transactions, &orphan_p).unwrap();
    fs::create_dir_all(transactions.join(plan_id.to_string())).unwrap();
    match recover_plan(&fixture, &bundle, &apply, &tx, &txn_root) {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(other) => panic!("transactions/ replacement must fail closed: {other:?}"),
    }
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

#[test]
fn reassert_succeeds_while_bindings_stable() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("reassert-ok");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let verified = VerifiedPublishedTransaction::acquire(&txn_root, "gksphone", &plan_id).unwrap();
    assert!(verified.reassert(&txn_root).is_ok());
    drop(verified);
}

#[test]
fn recover_after_txn_dir_replacement_does_not_mutate_installed() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("replace-txn");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    execute_tx(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let before = hash_file(&take_lua(&fixture));
    let published = root_path.join("transactions").join(plan_id.to_string());
    let orphan = root_path.join("transactions").join("orphaned-old");
    fs::rename(&published, &orphan).unwrap();
    fs::create_dir_all(&published).unwrap();
    fs::write(published.join("snapshot-a.bin"), b"bogus").unwrap();
    match recover_plan(&fixture, &bundle, &apply, &tx, &txn_root) {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(other) => panic!("replaced txn must not recover: {other:?}"),
    }
    assert_eq!(hash_file(&take_lua(&fixture)), before);
}

fn hash_tree(root: &Path) -> String {
    use sha2::{Digest, Sha256};
    if root.is_file() {
        let bytes = fs::read(root).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
        return format!("{:x}", hasher.finalize());
    }
    let mut entries = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(rd) = fs::read_dir(dir) else {
            return;
        };
        let mut children: Vec<_> = rd.filter_map(|e| e.ok()).collect();
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
            } else if let Ok(bytes) = fs::read(&path) {
                out.push((rel, bytes));
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

fn inject_same_resource_peer(transactions_dir: &Path, digest_byte: u8) -> PathBuf {
    let peer = transactions_dir.join(Sha256Digest::new([digest_byte; 32]).to_string());
    fs::create_dir_all(peer.join("journal")).unwrap();
    write_resource_lock_file(&peer, &encode_resource_lock_id("gksphone").unwrap());
    let mut snap = b"gkrm-txn-snapshot-a-v1\n".to_vec();
    snap.extend_from_slice(&[0u8; 32]);
    fs::write(peer.join("snapshot-a.bin"), snap).unwrap();
    fs::write(peer.join("journal").join("00000000-prepared.bin"), b"torn").unwrap();
    peer
}

fn inject_ambiguous_peer(transactions_dir: &Path, digest_byte: u8) -> PathBuf {
    let peer = transactions_dir.join(Sha256Digest::new([digest_byte; 32]).to_string());
    fs::create_dir_all(&peer).unwrap();
    // Incomplete: lock present enough to look same-resource but journal absent/invalid.
    write_resource_lock_file(&peer, &encode_resource_lock_id("gksphone").unwrap());
    peer
}

fn inject_unrelated_peer(transactions_dir: &Path, digest_byte: u8) -> PathBuf {
    let peer = transactions_dir.join(Sha256Digest::new([digest_byte; 32]).to_string());
    fs::create_dir_all(peer.join("journal")).unwrap();
    write_resource_lock_file(&peer, &Sha256Digest::new([0xcd; 32]));
    peer
}

fn snapshot_trees(
    fixture: &MiniFixture,
    root_path: &Path,
    plan_id: &Sha256Digest,
) -> (String, String, String, String, String) {
    let transaction = root_path.join("transactions").join(plan_id.to_string());
    let backup = root_path
        .join("transactions")
        .join(plan_id.to_string())
        .join("backup");
    let journal = transaction.join("journal");
    (
        hash_tree(&fixture.package_v2),
        hash_tree(&fixture.staging_root),
        hash_tree(&backup),
        hash_tree(&fixture.installed_parent.join("gksphone")),
        hash_tree(&journal),
    )
}

fn assert_trees_unchanged(
    fixture: &MiniFixture,
    root_path: &Path,
    plan_id: &Sha256Digest,
    before: &(String, String, String, String, String),
) {
    let after = snapshot_trees(fixture, root_path, plan_id);
    assert_eq!(after.0, before.0, "package changed");
    assert_eq!(after.1, before.1, "staging changed");
    assert_eq!(after.2, before.2, "backup changed");
    assert_eq!(after.3, before.3, "installed changed");
    assert_eq!(after.4, before.4, "journal changed");
}

fn leave_at_applied(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx_plan: &TrustedTransactionalApplyPlan,
    txn_root: &TrustedTransactionRoot,
) {
    let _guard = lock_execution_hooks();
    // Stop after Applied without starting rollback mutation or sealing RecoveryRequired.
    set_journal_faults(&[
        JournalFault::Verified,
        JournalFault::RollingBack,
        JournalFault::RecoveryRequired,
    ]);
    let _ = execute_tx(fixture, bundle, apply, tx_plan, txn_root);
    set_journal_faults(&[]);
    set_journal_fault(None);
}

#[test]
fn peer_race_same_resource_before_backup_revalidate_blocks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-backup");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    leave_interrupted(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let tx_dir = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeBackupRevalidate, move || {
        inject_same_resource_peer(&tx_dir, 0xa1);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "{recovered:?}"
    );
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn peer_race_same_resource_before_first_rollback_mutation_blocks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-first-rb");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    leave_interrupted(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let tx_dir = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeFirstRollbackMutation, move || {
        inject_same_resource_peer(&tx_dir, 0xa2);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "{recovered:?}"
    );
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn peer_race_ambiguous_before_rollback_blocks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-amb-rb");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    leave_interrupted(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let tx_dir = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeFirstRollbackMutation, move || {
        inject_ambiguous_peer(&tx_dir, 0xa3);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "{recovered:?}"
    );
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn peer_race_same_resource_before_applied_commit_blocks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-commit");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    leave_at_applied(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let tx_dir = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeCommitDesiredState, move || {
        inject_same_resource_peer(&tx_dir, 0xa4);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "{recovered:?}"
    );
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn peer_race_ambiguous_before_verified_commit_blocks() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-verified");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    leave_at_applied(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let tx_dir = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeVerifiedAppend, move || {
        inject_ambiguous_peer(&tx_dir, 0xa5);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveryStillRequired(_)),
        "{recovered:?}"
    );
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn peer_race_unrelated_resource_allows_commit_recovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-unrelated");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    leave_at_applied(&fixture, &bundle, &apply, &tx, &txn_root);
    let tx_dir = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeCommitDesiredState, move || {
        inject_unrelated_peer(&tx_dir, 0xb1);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveredCommitted(_)),
        "unrelated peer must not block: {recovered:?}"
    );
}

#[test]
fn peer_race_unrelated_before_rollback_allows_recovery() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-unrel-rb");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    leave_interrupted(&fixture, &bundle, &apply, &tx, &txn_root);
    let tx_dir = root_path.join("transactions");
    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeBackupRevalidate, move || {
        inject_unrelated_peer(&tx_dir, 0xb3);
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveredRolledBack(_)),
        "unrelated peer must allow rollback: {recovered:?}"
    );
}

#[test]
fn peer_enumeration_replacement_fails_closed() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-enum-replace");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    leave_at_applied(&fixture, &bundle, &apply, &tx, &txn_root);
    let tx_dir = root_path.join("transactions");
    let peer = inject_unrelated_peer(&tx_dir, 0xc1);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::DuringPeerEnumeration, move || {
        let orphan = tx_dir.join("orphan-enum");
        fs::rename(&peer, &orphan).expect("replace peer during enumeration");
        fs::create_dir_all(&peer).unwrap();
        write_resource_lock_file(&peer, &Sha256Digest::new([0xef; 32]));
    });
    match recover_plan(&fixture, &bundle, &apply, &tx, &txn_root) {
        Ok(TrustedRecoveryResult::RecoveryStillRequired(_)) | Err(_) => {}
        Ok(other) => panic!("enumeration replacement must fail closed: {other:?}"),
    }
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn cooperating_task23_blocked_by_held_resource_lock_after_final_peer_check() {
    use crate::trusted_transactional_apply_execution::locks;

    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("race-lock");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    leave_at_applied(&fixture, &bundle, &apply, &tx, &txn_root);

    let root_dir = txn_root.dir().try_clone().expect("clone root");
    let contention = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = contention.clone();

    let _guard = lock_execution_hooks();
    set_peer_race_hook(PeerRacePoint::BeforeCommitTerminalAppend, move || {
        match locks::acquire_resource_lock(&root_dir, "gksphone") {
            Err(crate::GkrmError::TrustedTransactionalApplyExecutionLockContention) => {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            other => panic!("expected lock contention, got {other:?}"),
        }
    });
    let recovered = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(
        matches!(recovered, TrustedRecoveryResult::RecoveredCommitted(_)),
        "{recovered:?}"
    );
    assert!(
        contention.load(std::sync::atomic::Ordering::SeqCst),
        "cooperating Task 23/24 must observe held resource lock"
    );
}

fn prepare_valid_same_resource_peer(target_root: &Path) -> (PathBuf, PathBuf) {
    let donor = build_mini();
    let donor_bundle = stage_ok(&donor);
    let donor_root_path = donor._temp.path().join("donor-root");
    let donor_root = open_root(&donor_root_path);
    let (donor_apply, donor_tx) =
        plan_apply_tx_with_apply_options(&donor, &donor_bundle, alt_apply_options());
    assert!(matches!(
        execute_tx(&donor, &donor_bundle, &donor_apply, &donor_tx, &donor_root).unwrap(),
        TrustedTransactionResult::Committed(_)
    ));
    let peer_name = donor_tx.plan_id().digest().to_string();
    let parked = target_root.join("parked-valid-peer");
    copy_dir(
        &donor_root_path.join("transactions").join(&peer_name),
        &parked,
    );
    let published = target_root.join("transactions").join(peer_name);
    (parked, published)
}

fn prepare_committed_terminal(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx: &TrustedTransactionalApplyPlan,
    root: &TrustedTransactionRoot,
) {
    assert!(matches!(
        execute_tx(fixture, bundle, apply, tx, root).unwrap(),
        TrustedTransactionResult::Committed(_)
    ));
}

fn prepare_rolled_back_terminal(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx: &TrustedTransactionalApplyPlan,
    root: &TrustedTransactionRoot,
) {
    leave_interrupted(fixture, bundle, apply, tx, root);
    assert!(matches!(
        recover_plan(fixture, bundle, apply, tx, root).unwrap(),
        TrustedRecoveryResult::RecoveredRolledBack(_)
    ));
}

fn prepare_aborted_terminal(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
    apply: &TrustedApplyPlan,
    tx: &TrustedTransactionalApplyPlan,
    root: &TrustedTransactionRoot,
) {
    {
        let _guard = lock_execution_hooks();
        set_journal_faults(&[
            JournalFault::BackupEntryCompleted,
            JournalFault::RecoveryRequired,
        ]);
        let _ = execute_tx(fixture, bundle, apply, tx, root);
        set_journal_faults(&[]);
    }
    assert!(matches!(
        recover_plan(fixture, bundle, apply, tx, root).unwrap(),
        TrustedRecoveryResult::SafeRestart(_)
    ));
}

#[test]
fn terminal_committed_final_peer_validation_blocks_same_resource() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("terminal-committed-same");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    prepare_committed_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
    let (parked, published) = prepare_valid_same_resource_peer(&root_path);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);

    let _guard = lock_execution_hooks();
    set_peer_race_hook(
        PeerRacePoint::BeforeReadonlyTerminalFinalization,
        move || {
            fs::rename(&parked, &published).unwrap();
        },
    );
    let result = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(matches!(
        result,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn terminal_committed_final_peer_validation_blocks_ambiguous() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("terminal-committed-ambiguous");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    prepare_committed_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let transactions = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(
        PeerRacePoint::BeforeReadonlyTerminalFinalization,
        move || {
            inject_ambiguous_peer(&transactions, 0xd1);
        },
    );
    let result = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(matches!(
        result,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn terminal_committed_final_unrelated_peer_preserves_result_id() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("terminal-committed-unrelated");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    prepare_committed_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
    let first = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let first_id = match first {
        TrustedRecoveryResult::RecoveredCommitted(value) => value.result_id().to_hex(),
        other => panic!("expected committed rediscovery, got {other:?}"),
    };
    let transactions = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(
        PeerRacePoint::BeforeReadonlyTerminalFinalization,
        move || {
            inject_unrelated_peer(&transactions, 0xd2);
        },
    );
    let second = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    let second_id = match second {
        TrustedRecoveryResult::RecoveredCommitted(value) => value.result_id().to_hex(),
        other => panic!("unrelated peer must allow committed rediscovery: {other:?}"),
    };
    assert_eq!(second_id, first_id);
}

#[test]
fn terminal_rolled_back_final_peer_validation_blocks_same_and_ambiguous() {
    for (label, ambiguous) in [("same", false), ("ambiguous", true)] {
        let fixture = build_mini();
        let bundle = stage_ok(&fixture);
        let root_path = fixture
            ._temp
            .path()
            .join(format!("terminal-rolledback-{label}"));
        let txn_root = open_root(&root_path);
        let (apply, tx) = plan_apply_tx(&fixture, &bundle);
        let plan_id = *tx.plan_id().digest();
        prepare_rolled_back_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
        let before = snapshot_trees(&fixture, &root_path, &plan_id);
        let transactions = root_path.join("transactions");
        let valid_peer = (!ambiguous).then(|| prepare_valid_same_resource_peer(&root_path));

        let _guard = lock_execution_hooks();
        set_peer_race_hook(
            PeerRacePoint::BeforeReadonlyTerminalFinalization,
            move || {
                if let Some((parked, published)) = &valid_peer {
                    fs::rename(parked, published).unwrap();
                } else {
                    inject_ambiguous_peer(&transactions, 0xd3);
                }
            },
        );
        let result = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
        assert!(matches!(
            result,
            TrustedRecoveryResult::RecoveryStillRequired(_)
        ));
        assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
    }
}

#[test]
fn terminal_safe_restart_final_peer_validation_blocks_same_resource() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("terminal-safe-restart-same");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    prepare_aborted_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
    let (parked, published) = prepare_valid_same_resource_peer(&root_path);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);

    let _guard = lock_execution_hooks();
    set_peer_race_hook(
        PeerRacePoint::BeforeReadonlyTerminalFinalization,
        move || {
            fs::rename(&parked, &published).unwrap();
        },
    );
    let result = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(matches!(
        result,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn terminal_final_peer_enumeration_replacement_fails_closed() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("terminal-enum-replace");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    let plan_id = *tx.plan_id().digest();
    prepare_committed_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
    let before = snapshot_trees(&fixture, &root_path, &plan_id);
    let transactions = root_path.join("transactions");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(
        PeerRacePoint::BeforeReadonlyTerminalFinalization,
        move || {
            let peer = inject_unrelated_peer(&transactions, 0xd4);
            let peer_replacement = peer.clone();
            let transactions_replacement = transactions.clone();
            set_peer_race_hook(PeerRacePoint::DuringPeerEnumeration, move || {
                let orphan = transactions_replacement.join("terminal-enum-orphan");
                fs::rename(&peer_replacement, &orphan).unwrap();
                fs::create_dir_all(&peer_replacement).unwrap();
                write_resource_lock_file(&peer_replacement, &Sha256Digest::new([0xee; 32]));
            });
        },
    );
    let result = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(matches!(
        result,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_trees_unchanged(&fixture, &root_path, &plan_id, &before);
}

#[test]
fn terminal_journal_change_before_final_return_fails_closed_without_recovery_append() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let root_path = fixture._temp.path().join("terminal-journal-change");
    let txn_root = open_root(&root_path);
    let (apply, tx) = plan_apply_tx(&fixture, &bundle);
    prepare_committed_terminal(&fixture, &bundle, &apply, &tx, &txn_root);
    let journal = root_path
        .join("transactions")
        .join(tx.plan_id().digest().to_string())
        .join("journal");
    let before_count = fs::read_dir(&journal).unwrap().count();
    let injected = journal.join("ffffffff-external.bin");

    let _guard = lock_execution_hooks();
    set_peer_race_hook(
        PeerRacePoint::BeforeReadonlyTerminalFinalization,
        move || {
            fs::write(&injected, b"external journal mutation").unwrap();
        },
    );
    let result = recover_plan(&fixture, &bundle, &apply, &tx, &txn_root).unwrap();
    assert!(matches!(
        result,
        TrustedRecoveryResult::RecoveryStillRequired(_)
    ));
    assert_eq!(
        fs::read_dir(&journal).unwrap().count(),
        before_count + 1,
        "recovery must not append after the external journal mutation"
    );
}
