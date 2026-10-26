//! Focused Task 22 security verification tests.

use crate::trusted_staging::test_support::{
    build_mini, hash_tree, installed_root, stage_ok, MiniFixture,
};
use crate::{
    plan_trusted_apply, plan_trusted_transactional_apply, GkrmError, InstalledApplyPlanningSource,
    InstalledScanLimits, RecoveryAction, RollbackAction, TransactionCrashBoundary,
    TransactionStepPhase, TrustedApplyPlanningOptions, TrustedApplyPlanningRequest,
    TrustedStagingBundle, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest,
};

fn apply_and_tx(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
) -> crate::TrustedTransactionalApplyPlan {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let apply_plan = plan_trusted_apply(
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
    plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            &apply_plan,
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
fn recovery_table_covers_boundaries_and_committed_never_rolls_back() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let plan = apply_and_tx(&fixture, &bundle);
    let rows = plan.recovery().rows();
    assert!(rows
        .iter()
        .any(|(b, _)| *b == TransactionCrashBoundary::BeforePrepared));
    assert!(rows
        .iter()
        .any(|(b, _)| *b == TransactionCrashBoundary::Committed));
    let committed = rows
        .iter()
        .find(|(b, _)| *b == TransactionCrashBoundary::Committed)
        .unwrap()
        .1;
    assert_eq!(committed, RecoveryAction::ForwardCompleteNeverRollBack);
}

#[test]
fn rollback_actions_cover_operation_kinds() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let plan = apply_and_tx(&fixture, &bundle);
    let actions: Vec<_> = plan.rollback_steps().iter().map(|s| s.action()).collect();
    assert!(actions.contains(&RollbackAction::VerifyRollbackState));
    assert!(actions.iter().any(|a| matches!(
        a,
        RollbackAction::RemoveInstalledFile
            | RollbackAction::RestoreInstalledFile
            | RollbackAction::RemoveCreatedDirectory
            | RollbackAction::RecreateDirectoryWithMetadata
    )));
}

#[test]
fn limit_failure_returns_no_plan() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let apply_plan = plan_trusted_apply(
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
    let options = TrustedTransactionalApplyPlanningOptions {
        max_transaction_steps: 1,
        ..TrustedTransactionalApplyPlanningOptions::default()
    };
    let err = plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            &apply_plan,
            &bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            options,
        )
        .unwrap(),
    )
    .expect_err("limit");
    assert!(matches!(
        err,
        GkrmError::TrustedTransactionalApplyPlanningLimitExceeded { .. }
    ));
}

#[test]
fn debug_redacts_sensitive_surfaces() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let plan = apply_and_tx(&fixture, &bundle);
    let text = format!("{plan:?}");
    assert!(!text.contains("fxmanifest.lua"));
    assert!(!text.contains("gksphone"));
    for phase in plan.forward_phases() {
        let _ = phase;
        assert!(matches!(
            phase,
            TransactionStepPhase::Preflight
                | TransactionStepPhase::PersistPreparedJournal
                | TransactionStepPhase::CreateBackupBundle
                | TransactionStepPhase::PersistBackupCompleteJournal
                | TransactionStepPhase::PersistApplyingJournal
                | TransactionStepPhase::ApplyBlockingDeletes
                | TransactionStepPhase::ApplyBlockingDirectoryRemovals
                | TransactionStepPhase::CreateDirectories
                | TransactionStepPhase::InstallOrReplaceFiles
                | TransactionStepPhase::DeleteObsoleteFiles
                | TransactionStepPhase::RemoveObsoleteDirectories
                | TransactionStepPhase::PersistAppliedJournal
                | TransactionStepPhase::VerifyInstalledTree
                | TransactionStepPhase::PersistVerifiedJournal
                | TransactionStepPhase::PersistCommittedJournal
                | TransactionStepPhase::Finalize
                | TransactionStepPhase::Rollback
        ));
    }
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
}

#[test]
fn fixed_vectors_hardcoded() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let plan = apply_and_tx(&fixture, &bundle);

    const FIXED_TASK22_PLAN_ID: &str =
        "b3c0863b6db64874166d3e1857612f5a1f7c540ba508ec34628a44d365dbce2b";
    const FIXED_TASK22_BACKUP_PLAN_ID: &str =
        "41b7d8996b34fd8a091c90da3c266700bb76fdb64cfcd66651fe4ca11531e8e5";
    const FIXED_TASK22_BACKUP_ENTRY0_ID: &str =
        "5bed7158a64fdd6a56d43c045fb4e8b43ea13b2aa24fb56147c47577e31cb675";
    const FIXED_TASK22_FORWARD_MUTATING_STEP0_ID: &str =
        "01f1d4b403e9aa562fb25f698b00b8edb223ecd1ea87f2bd1fc8167788e340d8";
    const FIXED_TASK22_ROLLBACK_STEP0_ID: &str =
        "136f175a301cd0282ff12892c3a9d96075967c67feabcf9f1f359ba787380629";
    const FIXED_TASK22_JOURNAL_RECORD0_ID: &str =
        "9528f9150b710c75a9e0fbfec56c9e63c0e81a090728a21ac04ef3f4484f261d";
    const FIXED_TASK22_RECOVERY_TABLE_ID: &str =
        "170759b216739a795569b0ebce28e208dda6cb9522c84e72f38c5c58c3811be2";

    let plan_id = plan.plan_id().to_hex();
    let backup_plan_id = plan.backup().plan_id().digest().to_string();
    let backup_entry0 = plan
        .backup()
        .entry_ids()
        .next()
        .expect("backup entry")
        .digest()
        .to_string();
    let fwd_ids: Vec<_> = plan
        .forward_step_ids()
        .map(|id| id.digest().to_string())
        .collect();
    let phases: Vec<_> = plan.forward_phases().collect();
    let first_mutating = phases
        .iter()
        .zip(fwd_ids.iter())
        .find(|(p, _)| {
            matches!(
                p,
                TransactionStepPhase::ApplyBlockingDeletes
                    | TransactionStepPhase::ApplyBlockingDirectoryRemovals
                    | TransactionStepPhase::CreateDirectories
                    | TransactionStepPhase::InstallOrReplaceFiles
                    | TransactionStepPhase::DeleteObsoleteFiles
                    | TransactionStepPhase::RemoveObsoleteDirectories
            )
        })
        .map(|(_, id)| id.clone())
        .expect("mutating step");
    let rollback0 = plan.rollback_steps()[0].step_id().digest().to_string();
    let journal0 = plan
        .journal()
        .record_ids()
        .next()
        .expect("journal record")
        .digest()
        .to_string();
    let recovery = plan.recovery().table_id().digest().to_string();

    assert_eq!(plan_id, FIXED_TASK22_PLAN_ID);
    assert_eq!(backup_plan_id, FIXED_TASK22_BACKUP_PLAN_ID);
    assert_eq!(backup_entry0, FIXED_TASK22_BACKUP_ENTRY0_ID);
    assert_eq!(first_mutating, FIXED_TASK22_FORWARD_MUTATING_STEP0_ID);
    assert_eq!(rollback0, FIXED_TASK22_ROLLBACK_STEP0_ID);
    assert_eq!(journal0, FIXED_TASK22_JOURNAL_RECORD0_ID);
    assert_eq!(recovery, FIXED_TASK22_RECOVERY_TABLE_ID);
}

#[test]
fn task22_v1_comprehensive_backup_forward_and_rollback_vectors() {
    // Literal Task 22 vectors below were regenerated and checked with an
    // independent Python struct.pack(<Q)/SHA-256 canonical encoder.
    let operations = crate::trusted_apply_planning::frozen_task21_v1_operations_fixture();
    let backup_set = crate::trusted_apply_planning::encode_backup_set_id(&operations).unwrap();
    let apply_plan_id = crate::Sha256Digest::from_lowercase_hex(
        "2c4f6dabe072570da4ddc7560a2de3137d2d5ea5723fc10ea144b72be701dd5d",
    )
    .unwrap();
    let backup = super::backup::build_backup_plan(
        &apply_plan_id,
        backup_set.digest(),
        &operations,
        100,
        1_000,
    )
    .unwrap();
    let (forward, status) = super::steps::build_forward_steps(
        crate::TrustedApplyStatus::ReadyForTransactionalApply,
        &operations,
        &backup,
        200,
    )
    .unwrap();
    let rollback =
        super::rollback::build_rollback_steps(&operations, &forward.steps, &backup, 200).unwrap();
    let backup_semantics: Vec<_> = backup
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{:?}|{:?}|{}|{}|{}|{}|{}",
                entry.destination.as_str(),
                entry.restore_order,
                entry.kind,
                entry.operation_kind,
                entry.state_tag,
                entry
                    .digest
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                entry
                    .byte_length
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                entry.operation_id.digest(),
                entry.entry_id.digest(),
            )
        })
        .collect();
    assert_eq!(
        backup_semantics,
        [
            "block/deep/old.lua|0|PreserveInstalledFile|DeleteFile|1|0101010101010101010101010101010101010101010101010101010101010101|1|3da586d8454150cf6d46ce9b86daeb569121df23dc630b314c07a2b05823424c|ec5d22f38f274855a52b112c8471b7062b14c7b406ca30a085d7924b745b4cec",
            "obsolete/deep|1|PreserveRemovedDirectoryMetadata|RemoveDirectory|2|none|none|c813dc99b58cb63eeac8410992f8c12ab7e51a41dff7d336e6e02ddbf735b222|07e5e4e9f478b0519f2f5e6252046644ab7f2dd180ddc15495d5a2b4a9aedca6",
            "block/deep|2|PreserveRemovedDirectoryMetadata|RemoveDirectory|2|none|none|af0890c36761188378ed1cbd4f661d1480779a6fefe4d58362c6a957bedbafef|822c0191a7c864e415de8606455f7b9236babbd918a5f23cb8c07a80f1285824",
            "replace.lua|3|PreserveInstalledFile|ReplaceFile|1|0404040404040404040404040404040404040404040404040404040404040404|4|bed0e69f92ff3447d289333495a1c912b98b67baae0a1069514cd38086cc1bb4|f95016f897bdb47db178e555b074c763416812a2f50d23cadf26e097a72db64e",
            "remove.lua|4|PreserveInstalledFile|DeleteFile|1|0303030303030303030303030303030303030303030303030303030303030303|3|5f83313d93fd3a8d955e375e799ec20e87db7445ef3a3e6a2635821f3c887b56|7ca87ce9921fa2c82fc8c732a4953b3068739c6b1854235f638551d09908ed65",
            "obsolete|5|PreserveRemovedDirectoryMetadata|RemoveDirectory|2|none|none|f92cbe61eb93055722aeac51ebb590de4e489996bbcf09e05e13b620125127f2|c04ab2137f8c39f4394c1595ac4aeb2a0b57bd76f1e91f34dbbba43dc31a6327",
            "file-to-dir|6|PreserveInstalledFile|DeleteFile|1|0202020202020202020202020202020202020202020202020202020202020202|2|7ebb803fc4dce74483b26c6432129fafb6fa5540624457688b8fddf0f8de4317|1556deeaec1423c62b910d5bec754f26693db4144f168a82205126c12a76e465",
            "block|7|PreserveRemovedDirectoryMetadata|RemoveDirectory|2|none|none|9dbc44bd24092eb7624f2c78d986fa3ce7194dee1f0f50f4552487dc14bf82d0|7e29a698c5b9b4b61a851b1107692d2b6e97ccc80e75e26dce1a5f020d3e2b18",
        ]
    );
    let backup_vectors: Vec<_> = backup
        .entries
        .iter()
        .map(|entry| {
            (
                entry.destination.as_str().to_owned(),
                entry.entry_id.digest().to_string(),
            )
        })
        .collect();
    let forward_vectors: Vec<_> = forward
        .steps
        .iter()
        .map(|step| {
            (
                format!("{:?}", step.phase),
                step.step_id.digest().to_string(),
            )
        })
        .collect();
    let rollback_vectors: Vec<_> = rollback
        .iter()
        .map(|step| {
            let destination = step.operation_id.as_ref().and_then(|id| {
                operations
                    .iter()
                    .find(|operation| operation.operation_id() == id)
                    .map(|operation| operation.destination_for_test().as_str().to_owned())
            });
            (
                format!("{:?}", step.action),
                destination,
                step.step_id.digest().to_string(),
            )
        })
        .collect();
    assert_eq!(
        backup_vectors,
        [
            (
                "block/deep/old.lua".into(),
                "ec5d22f38f274855a52b112c8471b7062b14c7b406ca30a085d7924b745b4cec".into()
            ),
            (
                "obsolete/deep".into(),
                "07e5e4e9f478b0519f2f5e6252046644ab7f2dd180ddc15495d5a2b4a9aedca6".into()
            ),
            (
                "block/deep".into(),
                "822c0191a7c864e415de8606455f7b9236babbd918a5f23cb8c07a80f1285824".into()
            ),
            (
                "replace.lua".into(),
                "f95016f897bdb47db178e555b074c763416812a2f50d23cadf26e097a72db64e".into()
            ),
            (
                "remove.lua".into(),
                "7ca87ce9921fa2c82fc8c732a4953b3068739c6b1854235f638551d09908ed65".into()
            ),
            (
                "obsolete".into(),
                "c04ab2137f8c39f4394c1595ac4aeb2a0b57bd76f1e91f34dbbba43dc31a6327".into()
            ),
            (
                "file-to-dir".into(),
                "1556deeaec1423c62b910d5bec754f26693db4144f168a82205126c12a76e465".into()
            ),
            (
                "block".into(),
                "7e29a698c5b9b4b61a851b1107692d2b6e97ccc80e75e26dce1a5f020d3e2b18".into()
            ),
        ]
    );
    assert_eq!(
        forward_vectors,
        [
            (
                "Preflight".into(),
                "02c2c99fb30833a47d9d25629c9d4d06d96c5282b2d4ff481be785709760bcb8".into()
            ),
            (
                "PersistPreparedJournal".into(),
                "987836cbadd386371f252785fb9a9b03e4d81b1d0baabd4709efb8621b64e6b2".into()
            ),
            (
                "CreateBackupBundle".into(),
                "fbbfccc12cba959e3da179ff07a452ee22e1efefec525dd65dc685d06ca1fc1d".into()
            ),
            (
                "PersistBackupCompleteJournal".into(),
                "51efb3ca89fefbb5a0b3374e6291f2fb039611b963825e871fb9e0f44ea24ddd".into()
            ),
            (
                "PersistApplyingJournal".into(),
                "4fd808babdd916fd46bcedc41564410b11cdc313d6d04d2b3dcd0c784113237b".into()
            ),
            (
                "ApplyBlockingDeletes".into(),
                "97a86525fafb38260edb0686a0625526949d3dd7e07132b531c3b64e15ea2ae3".into()
            ),
            (
                "ApplyBlockingDeletes".into(),
                "fc99553a9cf783e31ed3ba06fae2c42db32aa29288dedf44a5ce4fe889b5774c".into()
            ),
            (
                "ApplyBlockingDirectoryRemovals".into(),
                "b9e1a898180e1f305003dfa24f7f6a9e16d8e442b58fb1c48cb2d4d1ce0ad14d".into()
            ),
            (
                "ApplyBlockingDirectoryRemovals".into(),
                "0f822074aff2ed5bc1a53771561c43357cee1af5f1e5a47f4e15d0bb81eb41a0".into()
            ),
            (
                "CreateDirectories".into(),
                "9f9ed85506a54196985df89b7dc6cc3dd782e81c0b4c283a442b8470920665fc".into()
            ),
            (
                "CreateDirectories".into(),
                "36887c6711510508afbd262e6b3120c635fc1f292ec139d38153f8eb97108df1".into()
            ),
            (
                "CreateDirectories".into(),
                "c6747a54a0aa6355fbf09a1d47d743571adaf852edad441c480c07195e7735d8".into()
            ),
            (
                "CreateDirectories".into(),
                "262323caa96b47a80bd32f30dd59675b3821d1b079158a0177280b8e0901001f".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "8acf02b67778f2bfa8a503b4c5d3025d2a7bdf9dd62302131cc365149af300fd".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "892d76c65694e5fe1471543e28b8308cb9d66d7a59fa9d4ee000efbff1e5fd5f".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "9f6be7760a935543ff9ffdfe4f6be66a71e192cfbf2bdbb8f1a5b1c4616576e8".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "f51216fa66b5bbc54bd2c7655547d864e2a3f31c965fe6e2939a7a04fdce665b".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "511dd2de523b1598046df2a7f0601b27440da27d047293b9a8c66f57535f309b".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "32b9ab7837236d9621d74f99710133dbc55d58be02f0b15aa93769de0fd2ef50".into()
            ),
            (
                "InstallOrReplaceFiles".into(),
                "c70847ab61a3394c772acfe07f8a705a2c07b03fc47a48ba02015f1be603beb1".into()
            ),
            (
                "DeleteObsoleteFiles".into(),
                "7b144648ab36db1b83e71eb755a0754632f573811062c9147f8f0093d0ec0e30".into()
            ),
            (
                "RemoveObsoleteDirectories".into(),
                "402c0aa066641f235fb64242fcc952a05b1b7e7ee0f268645b6defe220ef0f38".into()
            ),
            (
                "RemoveObsoleteDirectories".into(),
                "4a0d3a6afbd03fedb1ff4d1982aef905f4684affcb7bb58dcc589707ebe23719".into()
            ),
            (
                "PersistAppliedJournal".into(),
                "028410c5fae5d1541bc55fc6375ca635c4c86e113b0a00919f75fbb9ddbca6ad".into()
            ),
            (
                "VerifyInstalledTree".into(),
                "6405001668275163f39fe1a6fc8ed75d086f378a147feac331268747a0b2b5a9".into()
            ),
            (
                "PersistVerifiedJournal".into(),
                "82f33679f4ded8f8480239ba64da6ea7d1596389386e5aba29e55947490742c0".into()
            ),
            (
                "PersistCommittedJournal".into(),
                "050025e05f943861c4c8bbbb40e866a2ce3f74eed2d17b1d57420bbed4f11dd9".into()
            ),
            (
                "Finalize".into(),
                "6664697bd750501643597101d134403d6e2868e9b89f5f03f80facfb6faa8a8c".into()
            ),
        ]
    );
    let forward_associations: Vec<_> = forward
        .steps
        .iter()
        .map(|step| {
            step.operation_id.as_ref().map_or_else(
                || "none".to_owned(),
                |operation_id| {
                    let operation = operations
                        .iter()
                        .find(|operation| operation.operation_id() == operation_id)
                        .unwrap();
                    format!(
                        "{}|{}",
                        operation.destination_for_test().as_str(),
                        operation_id.digest()
                    )
                },
            )
        })
        .collect();
    assert_eq!(
        forward_associations,
        [
            "none",
            "none",
            "none",
            "none",
            "none",
            "file-to-dir|7ebb803fc4dce74483b26c6432129fafb6fa5540624457688b8fddf0f8de4317",
            "block/deep/old.lua|3da586d8454150cf6d46ce9b86daeb569121df23dc630b314c07a2b05823424c",
            "block/deep|af0890c36761188378ed1cbd4f661d1480779a6fefe4d58362c6a957bedbafef",
            "block|9dbc44bd24092eb7624f2c78d986fa3ce7194dee1f0f50f4552487dc14bf82d0",
            "created-empty|053eded2c5e72441b7031f2f6e69ca3c238b9c8a97c1a9bf31a5e8ee3ccd4fec",
            "file-to-dir|8912ca28a368991b8d45a8d9e00d10470044cef216879e119cc2735d7b975a55",
            "siblings|9661b5d3748bf1c523f70a5ed77105f021d60b53891d2db75501450d796cca79",
            "file-to-dir/deep|981c5f473df94e2247c0aa2b52e7907b2f19add138b0893d643468b910d36a93",
            "block|d98f2ae4877bec645837db665b4b4ff92b779134ad2e663bd712766643bb51eb",
            "create.lua|7a75efee50a78b3e5a49778c6b065bc5fce372286166c8bd27ba2badd5595642",
            "file-to-dir/a.lua|addc9e87548617802e46fc332f91d32995f17e05a2765f4b21695b622838a66c",
            "file-to-dir/deep/z.lua|989a4268b33569c02925157ce57d8abf8743b33904e0be227fbf61956d0acad8",
            "replace.lua|bed0e69f92ff3447d289333495a1c912b98b67baae0a1069514cd38086cc1bb4",
            "siblings/a.lua|871a9c62447e7d1d298131586e8d09d95599a07cd1732581ed05bf4f9db11a0a",
            "siblings/b.lua|36579b23111e576b3f44ac0d41b9a1851f6a5a46941e00672ec8472bbd7ab8d2",
            "remove.lua|5f83313d93fd3a8d955e375e799ec20e87db7445ef3a3e6a2635821f3c887b56",
            "obsolete/deep|c813dc99b58cb63eeac8410992f8c12ab7e51a41dff7d336e6e02ddbf735b222",
            "obsolete|f92cbe61eb93055722aeac51ebb590de4e489996bbcf09e05e13b620125127f2",
            "none",
            "none",
            "none",
            "none",
            "none",
        ]
    );
    let forward_bindings: Vec<_> = forward
        .steps
        .iter()
        .map(|step| {
            format!(
                "{}|{}|{}|{}|{}",
                step.pre_tag,
                step.post_tag,
                step.staged_binding_tag
                    .map_or_else(|| "none".to_owned(), |v| v.to_string()),
                step.backup_entry_id
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |id| id.digest().to_string()),
                step.journal_to
                    .map_or_else(|| "none".to_owned(), |v| format!("{v:?}")),
            )
        })
        .collect();
    assert_eq!(
        forward_bindings,
        [
            "0|0|none|none|none",
            "0|0|none|none|Prepared",
            "0|0|none|none|none",
            "0|0|none|none|BackupComplete",
            "0|0|none|none|Applying",
            "1|0|none|1556deeaec1423c62b910d5bec754f26693db4144f168a82205126c12a76e465|none",
            "1|0|none|ec5d22f38f274855a52b112c8471b7062b14c7b406ca30a085d7924b745b4cec|none",
            "0|0|none|822c0191a7c864e415de8606455f7b9236babbd918a5f23cb8c07a80f1285824|none",
            "0|0|none|7e29a698c5b9b4b61a851b1107692d2b6e97ccc80e75e26dce1a5f020d3e2b18|none",
            "0|0|none|none|none",
            "0|0|none|none|none",
            "0|0|none|none|none",
            "0|0|none|none|none",
            "0|1|2|none|none",
            "0|1|2|none|none",
            "0|1|3|none|none",
            "0|1|4|none|none",
            "1|1|2|f95016f897bdb47db178e555b074c763416812a2f50d23cadf26e097a72db64e|none",
            "0|1|3|none|none",
            "0|1|4|none|none",
            "1|0|none|7ca87ce9921fa2c82fc8c732a4953b3068739c6b1854235f638551d09908ed65|none",
            "0|0|none|07e5e4e9f478b0519f2f5e6252046644ab7f2dd180ddc15495d5a2b4a9aedca6|none",
            "0|0|none|c04ab2137f8c39f4394c1595ac4aeb2a0b57bd76f1e91f34dbbba43dc31a6327|none",
            "0|0|none|none|Applied",
            "0|0|none|none|none",
            "0|0|none|none|Verified",
            "0|0|none|none|Committed",
            "0|0|none|none|none",
        ]
    );
    let expected_rollback = [
        (
            "RecreateDirectoryWithMetadata",
            Some("obsolete"),
            "5badc8d3c60aff4ecde90ce88e630cf8b7f186227549118da9ad1be2e4233fca",
        ),
        (
            "RecreateDirectoryWithMetadata",
            Some("obsolete/deep"),
            "84a12f63584ce64955a16924225f3728ce7276f039e7f5bfa6111dec29d35e4c",
        ),
        (
            "RestoreInstalledFile",
            Some("remove.lua"),
            "0e96a784583fc0d6485933de09512fe5ec5cadb91521598dfa24add6ae3cb488",
        ),
        (
            "RemoveInstalledFile",
            Some("file-to-dir/deep/z.lua"),
            "661a56243f9a0ce60255656945c4f79acc23948d99c6ff2492b6c2ad8aa2a130",
        ),
        (
            "RemoveInstalledFile",
            Some("siblings/b.lua"),
            "856d5019be7263901e457e695fee5bb48ad2cce217e953e821c850803bffa924",
        ),
        (
            "RemoveInstalledFile",
            Some("siblings/a.lua"),
            "62155ac938f8397968d1b1913540c4e5fda0ab343c5d45b2e693743f3b7362f5",
        ),
        (
            "RemoveInstalledFile",
            Some("file-to-dir/a.lua"),
            "e302e11e46a9da49b67ab2d4b86fbfb10cdae8788b981d631f1f3e814e0aba67",
        ),
        (
            "RestoreInstalledFile",
            Some("replace.lua"),
            "0a460fb6fd1e1461d59829186a306210ca858d1ba6ef19db391de65e658b7851",
        ),
        (
            "RemoveInstalledFile",
            Some("create.lua"),
            "00e6b9efe581e1ac558452bdd469c49e33952acd24eb528512346ffff08e0411",
        ),
        (
            "RemoveInstalledFile",
            Some("block"),
            "127964ba41e00c9691f1e2df5328044a8058a96db885e155085724c4af1f5665",
        ),
        (
            "RemoveCreatedDirectory",
            Some("file-to-dir/deep"),
            "c4196d5d04541f28f4a0ce7cd3f6efa3036452af158bf7901b077cc337c4c850",
        ),
        (
            "RemoveCreatedDirectory",
            Some("siblings"),
            "eb5502abad2a3af28800cc55a7fbcc3a9a1b0529e7a73911e51604c5ef5dc8e7",
        ),
        (
            "RemoveCreatedDirectory",
            Some("file-to-dir"),
            "27df490286b91797b292f1852d4dfa1e96f81cf83c9fd48b1cf0639cb928beff",
        ),
        (
            "RemoveCreatedDirectory",
            Some("created-empty"),
            "26c034b4a6e4e7758d7af4873969873c4a67594e8de155e0ef53ff863c759a34",
        ),
        (
            "RecreateDirectoryWithMetadata",
            Some("block"),
            "ef00f808a9aca994fa33030f188501c5815164ee7238621d27bb90424bf3181f",
        ),
        (
            "RecreateDirectoryWithMetadata",
            Some("block/deep"),
            "306ddc2709f843abbc34e1b2e1cd49b6b1f09ef17ec666ff974321a78fe6fa52",
        ),
        (
            "RestoreInstalledFile",
            Some("file-to-dir"),
            "1ebd214e36af8e30a0a010e46b81a726e6c031647c8ae93543a29c3c760920c7",
        ),
        (
            "RestoreInstalledFile",
            Some("block/deep/old.lua"),
            "fa2e7aa514b98325e281c5ec5bbf530c3019a01dc16069396301b35794b35414",
        ),
        (
            "VerifyRollbackState",
            None,
            "4b3c864b7c17bc78dbaac126495cdccf2f435f6046b3dbb7c67b5ff753e744fc",
        ),
    ];
    let expected_rollback: Vec<_> = expected_rollback
        .into_iter()
        .map(|(action, path, id)| (action.to_owned(), path.map(str::to_owned), id.to_owned()))
        .collect();
    assert_eq!(rollback_vectors, expected_rollback);
    let rollback_dependencies: Vec<_> = rollback
        .iter()
        .enumerate()
        .map(|(index, step)| {
            let group = match index {
                0..=1 => "recreate-obsolete-directories",
                2 => "restore-obsolete-files",
                3..=9 => "undo-file-writes",
                10..=13 => "remove-created-directories",
                14..=15 => "recreate-blocking-directories",
                16..=17 => "restore-blocking-files",
                _ => "verify-rollback",
            };
            format!(
                "{group}|{}|{}|{}",
                step.operation_id()
                    .map_or_else(|| "none".to_owned(), |id| id.digest().to_string()),
                step.forward_step_id().digest(),
                step.backup_entry_id()
                    .map_or_else(|| "none".to_owned(), |id| id.digest().to_string())
            )
        })
        .collect();
    assert_eq!(
        rollback_dependencies,
        [
            "recreate-obsolete-directories|f92cbe61eb93055722aeac51ebb590de4e489996bbcf09e05e13b620125127f2|4a0d3a6afbd03fedb1ff4d1982aef905f4684affcb7bb58dcc589707ebe23719|c04ab2137f8c39f4394c1595ac4aeb2a0b57bd76f1e91f34dbbba43dc31a6327",
            "recreate-obsolete-directories|c813dc99b58cb63eeac8410992f8c12ab7e51a41dff7d336e6e02ddbf735b222|402c0aa066641f235fb64242fcc952a05b1b7e7ee0f268645b6defe220ef0f38|07e5e4e9f478b0519f2f5e6252046644ab7f2dd180ddc15495d5a2b4a9aedca6",
            "restore-obsolete-files|5f83313d93fd3a8d955e375e799ec20e87db7445ef3a3e6a2635821f3c887b56|7b144648ab36db1b83e71eb755a0754632f573811062c9147f8f0093d0ec0e30|7ca87ce9921fa2c82fc8c732a4953b3068739c6b1854235f638551d09908ed65",
            "undo-file-writes|989a4268b33569c02925157ce57d8abf8743b33904e0be227fbf61956d0acad8|f51216fa66b5bbc54bd2c7655547d864e2a3f31c965fe6e2939a7a04fdce665b|none",
            "undo-file-writes|36579b23111e576b3f44ac0d41b9a1851f6a5a46941e00672ec8472bbd7ab8d2|c70847ab61a3394c772acfe07f8a705a2c07b03fc47a48ba02015f1be603beb1|none",
            "undo-file-writes|871a9c62447e7d1d298131586e8d09d95599a07cd1732581ed05bf4f9db11a0a|32b9ab7837236d9621d74f99710133dbc55d58be02f0b15aa93769de0fd2ef50|none",
            "undo-file-writes|addc9e87548617802e46fc332f91d32995f17e05a2765f4b21695b622838a66c|9f6be7760a935543ff9ffdfe4f6be66a71e192cfbf2bdbb8f1a5b1c4616576e8|none",
            "undo-file-writes|bed0e69f92ff3447d289333495a1c912b98b67baae0a1069514cd38086cc1bb4|511dd2de523b1598046df2a7f0601b27440da27d047293b9a8c66f57535f309b|f95016f897bdb47db178e555b074c763416812a2f50d23cadf26e097a72db64e",
            "undo-file-writes|7a75efee50a78b3e5a49778c6b065bc5fce372286166c8bd27ba2badd5595642|892d76c65694e5fe1471543e28b8308cb9d66d7a59fa9d4ee000efbff1e5fd5f|none",
            "undo-file-writes|d98f2ae4877bec645837db665b4b4ff92b779134ad2e663bd712766643bb51eb|8acf02b67778f2bfa8a503b4c5d3025d2a7bdf9dd62302131cc365149af300fd|none",
            "remove-created-directories|981c5f473df94e2247c0aa2b52e7907b2f19add138b0893d643468b910d36a93|262323caa96b47a80bd32f30dd59675b3821d1b079158a0177280b8e0901001f|none",
            "remove-created-directories|9661b5d3748bf1c523f70a5ed77105f021d60b53891d2db75501450d796cca79|c6747a54a0aa6355fbf09a1d47d743571adaf852edad441c480c07195e7735d8|none",
            "remove-created-directories|8912ca28a368991b8d45a8d9e00d10470044cef216879e119cc2735d7b975a55|36887c6711510508afbd262e6b3120c635fc1f292ec139d38153f8eb97108df1|none",
            "remove-created-directories|053eded2c5e72441b7031f2f6e69ca3c238b9c8a97c1a9bf31a5e8ee3ccd4fec|9f9ed85506a54196985df89b7dc6cc3dd782e81c0b4c283a442b8470920665fc|none",
            "recreate-blocking-directories|9dbc44bd24092eb7624f2c78d986fa3ce7194dee1f0f50f4552487dc14bf82d0|0f822074aff2ed5bc1a53771561c43357cee1af5f1e5a47f4e15d0bb81eb41a0|7e29a698c5b9b4b61a851b1107692d2b6e97ccc80e75e26dce1a5f020d3e2b18",
            "recreate-blocking-directories|af0890c36761188378ed1cbd4f661d1480779a6fefe4d58362c6a957bedbafef|b9e1a898180e1f305003dfa24f7f6a9e16d8e442b58fb1c48cb2d4d1ce0ad14d|822c0191a7c864e415de8606455f7b9236babbd918a5f23cb8c07a80f1285824",
            "restore-blocking-files|7ebb803fc4dce74483b26c6432129fafb6fa5540624457688b8fddf0f8de4317|97a86525fafb38260edb0686a0625526949d3dd7e07132b531c3b64e15ea2ae3|1556deeaec1423c62b910d5bec754f26693db4144f168a82205126c12a76e465",
            "restore-blocking-files|3da586d8454150cf6d46ce9b86daeb569121df23dc630b314c07a2b05823424c|fc99553a9cf783e31ed3ba06fae2c42db32aa29288dedf44a5ce4fe889b5774c|ec5d22f38f274855a52b112c8471b7062b14c7b406ca30a085d7924b745b4cec",
            "verify-rollback|none|02c2c99fb30833a47d9d25629c9d4d06d96c5282b2d4ff481be785709760bcb8|none",
        ]
    );

    let journal = super::journal::build_journal_plan(100).unwrap();
    let recovery = super::journal::build_recovery_table().unwrap();
    let summary = super::TrustedTransactionalApplySummary {
        forward_step_count: forward.steps.len(),
        rollback_step_count: rollback.len(),
        backup_entry_count: backup.entries.len(),
        journal_record_count: journal.records.len(),
        total_expected_write_bytes: forward.total_write_bytes,
        total_backup_bytes: backup.total_backup_bytes(),
    };
    let options_tag = super::TrustedTransactionalApplyPlanningOptions::default()
        .options_tag()
        .unwrap();
    let forward_ids: Vec<_> = forward
        .steps
        .iter()
        .map(|step| *step.step_id.digest())
        .collect();
    let rollback_ids: Vec<_> = rollback
        .iter()
        .map(|step| *step.step_id().digest())
        .collect();
    let journal_ids: Vec<_> = journal
        .records
        .iter()
        .map(|record| *record.record_id.digest())
        .collect();
    let snapshot = crate::Sha256Digest::from_lowercase_hex(
        "6dd3bce88d3f0dd6c0e514088c7d70731f64427f8d81341be4063933acafac3d",
    )
    .unwrap();
    let (_, bundle_id, manifest_id) =
        crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(false);
    let transaction_plan_id = super::id::encode_execution_plan_id(super::id::PlanIdInputs {
        apply_plan_id: &apply_plan_id,
        review_id: &crate::Sha256Digest::new([0x32; 32]),
        analysis_id: Some(&crate::Sha256Digest::new([0x33; 32])),
        text_diff_id: Some(&crate::Sha256Digest::new([0x34; 32])),
        synthesis_id: Some(&crate::Sha256Digest::new([0x35; 32])),
        merged_bytes_id: Some(&crate::Sha256Digest::new([0x36; 32])),
        bundle_id: bundle_id.digest(),
        manifest_id: manifest_id.digest(),
        resource_key: "gksphone",
        baseline_id: "3131313131313131313131313131313131313131313131313131313131313131",
        installed_fp: &crate::Sha256Digest::new([0x37; 32]),
        incoming_package_fp: &crate::Sha256Digest::new([0x38; 32]),
        incoming_resource_fp: &crate::Sha256Digest::new([0x39; 32]),
        installed_tree_snapshot_fp: &snapshot,
        options_tag: &options_tag,
        backup_plan_id: backup.plan_id().digest(),
        forward_step_ids: &forward_ids,
        rollback_step_ids: &rollback_ids,
        journal_record_ids: &journal_ids,
        recovery_table_id: recovery.table_id().digest(),
        summary: &summary,
        status: super::TrustedTransactionalApplyStatus::ReadyForTransactionalExecution,
    })
    .unwrap();
    assert_eq!(
        backup_set.digest().to_string(),
        "87bec313adf0b4fb7e5a80f6347d5348e1cb87be0ffa8bd493cd8d8caa20be73"
    );
    assert_eq!(
        backup.plan_id().digest().to_string(),
        "975c52cdd71206b91dd09361d06e1cbade3b42138adc30a9f379cf97a8ae3f0f"
    );
    assert_eq!(
        crate::Sha256Digest::new(options_tag.try_into().unwrap()).to_string(),
        "640908d5a596eab84e40e82f0b52f065b9eb8c2d225d588f47c7efadce9057cb"
    );
    assert_eq!(
        (
            summary.forward_step_count,
            summary.rollback_step_count,
            summary.backup_entry_count,
            summary.journal_record_count,
            summary.total_expected_write_bytes,
            summary.total_backup_bytes,
        ),
        (28, 19, 8, 10, 56, 10)
    );
    assert_eq!(
        status,
        super::TrustedTransactionalApplyStatus::ReadyForTransactionalExecution
    );
    let journal_vectors: Vec<_> = journal
        .records
        .iter()
        .map(|record| {
            format!(
                "{}|{:?}|{:?}|{}",
                record.sequence,
                record.from,
                record.to,
                record.record_id.digest()
            )
        })
        .collect();
    assert_eq!(
        journal_vectors,
        [
            "0|None|Prepared|9528f9150b710c75a9e0fbfec56c9e63c0e81a090728a21ac04ef3f4484f261d",
            "1|Some(Prepared)|BackupComplete|9d5685c9307d9c3322a937dd901110963cae0a3be2ef8ca3694f13930db8ab80",
            "2|Some(BackupComplete)|Applying|31eaf358c6cc9732e4283190d205a11599310c88c129e480c3a1ca855cae49c8",
            "3|Some(Applying)|Applied|b9da0dc70b4aa8af4a5088a18c88bef1667036729fbd1bb9102f9cb2bdc716db",
            "4|Some(Applied)|Verified|9a257a570edc77946720718b494bf5dc4248be25bd20dea2b49236d60d33d3d0",
            "5|Some(Verified)|Committed|5c878fed6b9f57137e76d3edb5292e3974a2a0d689d86d964cda5f480dfd6efe",
            "6|Some(Applying)|RollingBack|e0fbb7f267b25dc50e1385402ddd8197cbb898e3607b8c98394dac52b49c0930",
            "7|Some(Applied)|RollingBack|2fbb0c0bf345a3e81e01bbb8227b218c677de53e372cb7c11c4bd54c463f9d76",
            "8|Some(Verified)|RollingBack|c9782ddafd5bec36dbd2104f6627ccf86e2413e5e8208ecb15222dec278c0d88",
            "9|Some(RollingBack)|RolledBack|87c9e60589c3ebbf6bc602ce6b04dd7ff7737aed75a5759ca6f1efa4c4f3c35d",
        ]
    );
    let recovery_vectors: Vec<_> = recovery
        .rows()
        .iter()
        .map(|(boundary, action)| format!("{boundary:?}|{action:?}"))
        .collect();
    assert_eq!(
        recovery_vectors,
        [
            "BeforePrepared|Restart",
            "PreparedIncompleteBackup|DiscardIncompleteBackupAndRestart",
            "BackupCompleteBeforeMutation|ContinueOrSafelyAbort",
            "Applying|RollBackFromCompletedStep",
            "Applied|VerifyThenCommitOrRollBack",
            "Verified|ReverifyThenCommitOrRollBack",
            "RollingBack|ResumeRollback",
            "RolledBack|FinalizeRollbackCleanup",
            "Committed|ForwardCompleteNeverRollBack",
            "InconsistentEvidence|ManualRecoveryRequired",
        ]
    );
    assert_eq!(
        recovery.table_id().digest().to_string(),
        "170759b216739a795569b0ebce28e208dda6cb9522c84e72f38c5c58c3811be2"
    );
    assert_eq!(
        transaction_plan_id.digest().to_string(),
        "99df55f70de4727bd089c9b6c5d116d8a72d5f2e59012b47da51da37eac1db81"
    );
}

fn frozen_task22_transaction_id(
    operations: &[crate::TrustedApplyOperation],
    mutate_merged_binding: bool,
) -> (crate::Sha256Digest, crate::Sha256Digest) {
    let (snapshot, backup_set, apply_plan_id) =
        crate::trusted_apply_planning::frozen_task21_v1_aggregate_ids_for_test(
            operations,
            mutate_merged_binding,
        );
    let backup =
        super::backup::build_backup_plan(&apply_plan_id, &backup_set, operations, 100, 1_000)
            .unwrap();
    let (forward, _) = super::steps::build_forward_steps(
        crate::TrustedApplyStatus::ReadyForTransactionalApply,
        operations,
        &backup,
        200,
    )
    .unwrap();
    let rollback =
        super::rollback::build_rollback_steps(operations, &forward.steps, &backup, 200).unwrap();
    let journal = super::journal::build_journal_plan(100).unwrap();
    let recovery = super::journal::build_recovery_table().unwrap();
    let summary = super::TrustedTransactionalApplySummary {
        forward_step_count: forward.steps.len(),
        rollback_step_count: rollback.len(),
        backup_entry_count: backup.entries.len(),
        journal_record_count: journal.records.len(),
        total_expected_write_bytes: forward.total_write_bytes,
        total_backup_bytes: backup.total_backup_bytes(),
    };
    let options_tag = super::TrustedTransactionalApplyPlanningOptions::default()
        .options_tag()
        .unwrap();
    let forward_ids: Vec<_> = forward
        .steps
        .iter()
        .map(|step| *step.step_id.digest())
        .collect();
    let rollback_ids: Vec<_> = rollback
        .iter()
        .map(|step| *step.step_id().digest())
        .collect();
    let journal_ids: Vec<_> = journal
        .records
        .iter()
        .map(|record| *record.record_id.digest())
        .collect();
    let (_, bundle_id, manifest_id) =
        crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(mutate_merged_binding);
    let transaction_plan_id = super::id::encode_execution_plan_id(super::id::PlanIdInputs {
        apply_plan_id: &apply_plan_id,
        review_id: &crate::Sha256Digest::new([0x32; 32]),
        analysis_id: Some(&crate::Sha256Digest::new([0x33; 32])),
        text_diff_id: Some(&crate::Sha256Digest::new([0x34; 32])),
        synthesis_id: Some(&crate::Sha256Digest::new([0x35; 32])),
        merged_bytes_id: Some(&crate::Sha256Digest::new([0x36; 32])),
        bundle_id: bundle_id.digest(),
        manifest_id: manifest_id.digest(),
        resource_key: "gksphone",
        baseline_id: "3131313131313131313131313131313131313131313131313131313131313131",
        installed_fp: &crate::Sha256Digest::new([0x37; 32]),
        incoming_package_fp: &crate::Sha256Digest::new([0x38; 32]),
        incoming_resource_fp: &crate::Sha256Digest::new([0x39; 32]),
        installed_tree_snapshot_fp: &snapshot,
        options_tag: &options_tag,
        backup_plan_id: backup.plan_id().digest(),
        forward_step_ids: &forward_ids,
        rollback_step_ids: &rollback_ids,
        journal_record_ids: &journal_ids,
        recovery_table_id: recovery.table_id().digest(),
        summary: &summary,
        status: super::TrustedTransactionalApplyStatus::ReadyForTransactionalExecution,
    })
    .unwrap();
    (apply_plan_id, *transaction_plan_id.digest())
}

#[test]
fn staging_binding_only_change_propagates_operation_apply_and_transaction_ids() {
    let (original_bindings, original_bundle, original_manifest) =
        crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(false);
    let (mutated_bindings, mutated_bundle, mutated_manifest) =
        crate::trusted_staging::frozen_task21_v1_staging_fixture_for_test(true);
    let binding_path =
        crate::ResourceRelativePath::try_from_slash_str("file-to-dir/a.lua").unwrap();
    let mut original_other_bindings = original_bindings.clone();
    let mut mutated_other_bindings = mutated_bindings.clone();
    let original_binding = original_other_bindings.remove(&binding_path).unwrap();
    let mutated_binding = mutated_other_bindings.remove(&binding_path).unwrap();
    assert!(original_other_bindings == mutated_other_bindings);
    assert!(matches!(
        &original_binding,
        crate::trusted_staging::StagingSourceBinding::MergedArtifact(id)
            if id.digest().to_string()
                == "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"
    ));
    assert!(matches!(
        &mutated_binding,
        crate::trusted_staging::StagingSourceBinding::MergedArtifact(id)
            if id.digest().to_string()
                == "d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7"
    ));
    assert_eq!(
        original_bundle.digest().to_string(),
        "196a435bfce5d5745f24f9ab6836cc9b431b9510cccf892833013da801956da1"
    );
    assert_eq!(
        original_manifest.digest().to_string(),
        "96c120917d4774003607d8b72b44a9271f4e1c26fd9acba31a42de5c145986e7"
    );
    assert_eq!(
        mutated_bundle.digest().to_string(),
        "8178171bbd51b31c5415593af556a8aa2755f2c12e4d8543c2e512b9a4915e72"
    );
    assert_eq!(
        mutated_manifest.digest().to_string(),
        "4fd671d86a7cb897baa76be07928ec9c37a089ba888d5e6289d80857e3b76061"
    );
    let original = crate::trusted_apply_planning::frozen_task21_v1_operations_fixture();
    let mutated =
        crate::trusted_apply_planning::frozen_task21_v1_operations_with_binding_mutation_for_test();
    assert_eq!(original.len(), mutated.len());
    for (original, mutated) in original.iter().zip(&mutated) {
        assert_eq!(original.phase(), mutated.phase());
        assert_eq!(original.kind(), mutated.kind());
        assert_eq!(
            original.destination_for_test(),
            mutated.destination_for_test()
        );
        assert_eq!(original.backup_requirement(), mutated.backup_requirement());
        assert!(original.pre_state() == mutated.pre_state());
        assert!(original.post_state() == mutated.post_state());
        assert_eq!(original.staged_binding_tag(), mutated.staged_binding_tag());
    }
    let original_operation = original
        .iter()
        .find(|operation| operation.destination_for_test().as_str() == "file-to-dir/a.lua")
        .unwrap();
    let mutated_operation = mutated
        .iter()
        .find(|operation| operation.destination_for_test().as_str() == "file-to-dir/a.lua")
        .unwrap();

    assert_eq!(original_operation.phase(), mutated_operation.phase());
    assert_eq!(original_operation.kind(), mutated_operation.kind());
    assert_eq!(
        original_operation.backup_requirement(),
        mutated_operation.backup_requirement()
    );
    assert!(original_operation.pre_state() == mutated_operation.pre_state());
    assert!(original_operation.post_state() == mutated_operation.post_state());
    assert_eq!(original_operation.staged_binding_tag(), 3);
    assert_eq!(mutated_operation.staged_binding_tag(), 3);
    assert_eq!(
        original_operation.operation_id().digest().to_string(),
        "addc9e87548617802e46fc332f91d32995f17e05a2765f4b21695b622838a66c"
    );
    assert_eq!(
        mutated_operation.operation_id().digest().to_string(),
        "cf3d2072a4efd04f96df29aa713b272d244cfacfd7966caed961d63103aad5a5"
    );

    let (original_apply, original_transaction) = frozen_task22_transaction_id(&original, false);
    let (mutated_apply, mutated_transaction) = frozen_task22_transaction_id(&mutated, true);
    assert_eq!(
        original_apply.to_string(),
        "2c4f6dabe072570da4ddc7560a2de3137d2d5ea5723fc10ea144b72be701dd5d"
    );
    assert_eq!(
        mutated_apply.to_string(),
        "6cd0d7a46e3c0ff57465afb3d8a71a026ffe8350aacdbfa09ad71410ffd114d1"
    );
    assert_eq!(
        original_transaction.to_string(),
        "99df55f70de4727bd089c9b6c5d116d8a72d5f2e59012b47da51da37eac1db81"
    );
    assert_eq!(
        mutated_transaction.to_string(),
        "bda6e8362f92b88c0a2a7e135becc66e1a60ec3fff66deaa60edc6be1e476185"
    );
    assert_ne!(original_apply, mutated_apply);
    assert_ne!(original_transaction, mutated_transaction);
}
