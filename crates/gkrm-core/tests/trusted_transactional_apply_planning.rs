//! Integration tests for Task 22 transactional apply planning (Task 13→22).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, execute_trusted_transactional_apply, inspect_installation_update,
    plan_three_way_merge_synthesis, plan_three_way_text_diffs, plan_trusted_apply,
    plan_trusted_transactional_apply, resolve_official_baseline, review_three_way_update_plan,
    stage_trusted_resource, synthesize_three_way_merged_bytes, BaselineCaptureOptions,
    BaselineCaptureRequest, BaselineResolutionOptions, BaselineResolutionRequest,
    IncomingMergeContentSourceLimits, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
    IncomingStagingContentSource, InspectionOptions, InstallationRelativePath,
    InstalledApplyPlanningSource, InstalledResourceRoot, InstalledResourceSnapshot,
    InstalledScanLimits, InstalledStagingContentSource, MergedByteDisposition,
    OfficialBaselineSelector, PolicyTransitionAcknowledgement, ResolvedOfficialBaseline,
    RollbackAction, SafeResourceKey, ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisPlan,
    ThreeWayMergeAnalysisRequest, ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisPlan,
    ThreeWayMergeSynthesisRequest, ThreeWayMergedBytesOptions, ThreeWayMergedBytesPlan,
    ThreeWayMergedBytesRequest, ThreeWayPlanDecision, ThreeWayPlanDecisionChoice,
    ThreeWayPlanDecisionSet, ThreeWayPlanDisposition, ThreeWayPlanReview,
    ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayTextDiffOptions,
    ThreeWayTextDiffPlan, ThreeWayTextDiffRequest, ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest,
    TransactionCrashBoundary, TransactionStepPhase, TrustedApplyOperationKind,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedApplyStatus,
    TrustedStagingBundle, TrustedStagingOptions, TrustedStagingRequest, TrustedStagingRoot,
    TrustedTransactionResult, TrustedTransactionRoot, TrustedTransactionalApplyExecutionOptions,
    TrustedTransactionalApplyExecutionRequest, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest, TrustedTransactionalApplyStatus, ZipRelativePath,
    ZipResourceRoot,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'keep.lua',\n  'take.lua',\n  'merge.lua',\n  'gone.lua',\n  'fresh/app.lua',\n  'obsolete/item.lua',\n}\n";
const MERGE_BASE: &[u8] = b"L1\nL2\nL3\nL4\n";
const MERGE_INSTALLED: &[u8] = b"L1x\nL2\nL3\nL4\n";
const MERGE_INCOMING: &[u8] = b"L1\nL2\nL3\nL4y\n";
const KEEP_BASE: &[u8] = b"keep-base\n";
const KEEP_INSTALLED: &[u8] = b"keep-installed\n";
const KEEP_INCOMING: &[u8] = b"keep-incoming\n";
const TAKE_BASE: &[u8] = b"take-base\n";
const TAKE_INSTALLED: &[u8] = b"take-installed\n";
const TAKE_INCOMING: &[u8] = b"take-incoming\n";
const GONE_BASE: &[u8] = b"gone-base\n";
const GONE_INSTALLED: &[u8] = b"gone-installed\n";
const OBSOLETE_ITEM: &[u8] = b"obsolete-item\n";
const FRESH_APP: &[u8] = b"fresh-app\n";

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent");
    fs::write(path, contents).expect("write");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("zip");
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(*name, options).expect("start");
        writer.write_all(contents).expect("write");
    }
    writer.finish().expect("finish");
}

fn key(value: &str) -> SafeResourceKey {
    SafeResourceKey::parse(value).expect("key")
}

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

fn incoming_root(path: &str) -> ZipResourceRoot {
    ZipResourceRoot::Path(ZipRelativePath::parse_canonical(path).unwrap())
}

fn hash_tree(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    fn walk(dir: &Path, prefix: &str, out: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name().into_string().expect("utf8");
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = entry.path();
            let meta = entry.metadata().expect("meta");
            if meta.is_dir() {
                out.insert(format!("{rel}/"), "dir".to_owned());
                walk(&path, &rel, out);
            } else if meta.is_file() {
                let bytes = fs::read(&path).expect("read");
                out.insert(rel, format!("{:x}", Sha256::digest(&bytes)));
            }
        }
    }
    walk(root, "", &mut out);
    out
}

struct Fixture {
    _temp_dir: tempfile::TempDir,
    store: PathBuf,
    installed_parent: PathBuf,
    installed_resource: PathBuf,
    package_v2: PathBuf,
    staging_root: PathBuf,
    baseline: ResolvedOfficialBaseline,
    plan: ThreeWayUpdatePlan,
    review: ThreeWayPlanReview,
    analysis: Option<ThreeWayMergeAnalysisPlan>,
    text_diff: Option<ThreeWayTextDiffPlan>,
    synthesis: Option<ThreeWayMergeSynthesisPlan>,
    merged_bytes: Option<ThreeWayMergedBytesPlan>,
}

fn build_mutating_fixture() -> Fixture {
    let temp = tempdir().expect("temp");
    let installed_for_capture = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let staging_root = temp.path().join("staging");
    let package_v1 = temp.path().join("official-v1.zip");
    let package_v2 = temp.path().join("official-v2.zip");
    fs::create_dir_all(&installed_for_capture).expect("dir");
    fs::create_dir_all(&store).expect("store");
    fs::create_dir_all(&staging_root).expect("staging");

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/keep.lua", KEEP_BASE),
            ("gksphone/take.lua", TAKE_BASE),
            ("gksphone/merge.lua", MERGE_BASE),
            ("gksphone/gone.lua", GONE_BASE),
            ("gksphone/obsolete/item.lua", OBSOLETE_ITEM),
        ],
    );
    let capture = capture_official_baseline_in_standalone_store(
        &gkrm_core::resolve_standalone_baseline_store(&store).expect("standalone store"),
        BaselineCaptureRequest::try_new(
            &installed_for_capture,
            &store,
            &package_v1,
            key("gksphone"),
            IncomingResourceSelector::AutoSingle,
            BaselineCaptureOptions::default(),
        )
        .expect("capture req"),
    )
    .expect("capture");
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &key("gksphone"),
            OfficialBaselineSelector::Exact(capture.baseline_id().clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("resolve req"),
    )
    .expect("resolve");

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("keep.lua"), KEEP_INSTALLED);
    write_file(&installed_resource.join("take.lua"), TAKE_INSTALLED);
    write_file(&installed_resource.join("merge.lua"), MERGE_INSTALLED);
    write_file(&installed_resource.join("gone.lua"), GONE_INSTALLED);
    write_file(
        &installed_resource.join("obsolete").join("item.lua"),
        OBSOLETE_ITEM,
    );

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/keep.lua", KEEP_INCOMING),
            ("gksphone/take.lua", TAKE_INCOMING),
            ("gksphone/merge.lua", MERGE_INCOMING),
            ("gksphone/fresh/app.lua", FRESH_APP),
        ],
    );

    let report =
        inspect_installation_update(&installed_parent, &package_v2, InspectionOptions::default())
            .expect("inspect");
    let installed_snapshot = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .expect("installed snap");
    let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("incoming snap");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan req"),
    )
    .expect("plan");

    let decisions = plan
        .entries()
        .iter()
        .filter(|entry| {
            !matches!(
                entry.disposition(),
                ThreeWayPlanDisposition::NoChange
                    | ThreeWayPlanDisposition::Converged
                    | ThreeWayPlanDisposition::ConvergedAddition
                    | ThreeWayPlanDisposition::ConvergedDeletion
            )
        })
        .map(|entry| {
            let choice = match entry.path().as_str() {
                "merge.lua" => ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                "keep.lua" => ThreeWayPlanDecisionChoice::PreserveInstalledState,
                "take.lua" | "gone.lua" | "fresh/app.lua" | "obsolete/item.lua" => {
                    ThreeWayPlanDecisionChoice::UseIncomingState
                }
                other => panic!("unexpected decision entry: {other}"),
            };
            ThreeWayPlanDecision::try_new(
                entry.path().clone(),
                choice,
                PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("decision")
        })
        .collect::<Vec<_>>();
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(
            &plan,
            &ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).expect("set"),
        )
        .expect("review req"),
    )
    .expect("review");

    let installed_source = gkrm_core::InstalledMergeContentSource::try_new(
        &installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming_source = gkrm_core::IncomingMergeContentSource::try_new(
        &package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming");
    let analysis = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &plan,
            &review,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis req"),
    )
    .expect("analysis");
    let text_diff = plan_three_way_text_diffs(
        ThreeWayTextDiffRequest::try_new(
            &plan,
            &review,
            &analysis,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayTextDiffOptions::default(),
        )
        .expect("text req"),
    )
    .expect("text");
    let synthesis = plan_three_way_merge_synthesis(
        ThreeWayMergeSynthesisRequest::try_new(
            &plan,
            &review,
            &analysis,
            &text_diff,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeSynthesisOptions::default(),
        )
        .expect("synthesis req"),
    )
    .expect("synthesis");
    let merged_bytes = synthesize_three_way_merged_bytes(
        ThreeWayMergedBytesRequest::try_new(
            &plan,
            &review,
            &analysis,
            &text_diff,
            &synthesis,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergedBytesOptions::default(),
        )
        .expect("merged req"),
    )
    .expect("merged");
    assert!(merged_bytes
        .entries()
        .iter()
        .all(|e| e.disposition() == MergedByteDisposition::ReadyForStaging));

    Fixture {
        _temp_dir: temp,
        store,
        installed_parent,
        installed_resource,
        package_v2,
        staging_root,
        baseline,
        plan,
        review,
        analysis: Some(analysis),
        text_diff: Some(text_diff),
        synthesis: Some(synthesis),
        merged_bytes: Some(merged_bytes),
    }
}

fn build_noop_fixture() -> Fixture {
    let temp = tempdir().expect("temp");
    let installed_for_capture = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let staging_root = temp.path().join("staging");
    let package = temp.path().join("official.zip");
    fs::create_dir_all(&installed_for_capture).expect("dir");
    fs::create_dir_all(&store).expect("store");
    fs::create_dir_all(&staging_root).expect("staging");

    let identical = [
        ("gksphone/fxmanifest.lua", MANIFEST),
        ("gksphone/keep.lua", KEEP_BASE),
        ("gksphone/take.lua", TAKE_BASE),
    ];
    write_zip(&package, &identical);
    let capture = capture_official_baseline_in_standalone_store(
        &gkrm_core::resolve_standalone_baseline_store(&store).expect("standalone store"),
        BaselineCaptureRequest::try_new(
            &installed_for_capture,
            &store,
            &package,
            key("gksphone"),
            IncomingResourceSelector::AutoSingle,
            BaselineCaptureOptions::default(),
        )
        .expect("capture req"),
    )
    .expect("capture");
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &key("gksphone"),
            OfficialBaselineSelector::Exact(capture.baseline_id().clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("resolve req"),
    )
    .expect("resolve");

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("keep.lua"), KEEP_BASE);
    write_file(&installed_resource.join("take.lua"), TAKE_BASE);

    let report =
        inspect_installation_update(&installed_parent, &package, InspectionOptions::default())
            .expect("inspect");
    let installed_snapshot = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .expect("installed snap");
    let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("incoming snap");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan req"),
    )
    .expect("plan");
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(
            &plan,
            &ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), Vec::new()).expect("set"),
        )
        .expect("review req"),
    )
    .expect("review");

    Fixture {
        _temp_dir: temp,
        store,
        installed_parent,
        installed_resource,
        package_v2: package,
        staging_root,
        baseline,
        plan,
        review,
        analysis: None,
        text_diff: None,
        synthesis: None,
        merged_bytes: None,
    }
}

fn stage_bundle(fixture: &Fixture) -> TrustedStagingBundle {
    let root = TrustedStagingRoot::try_open(&fixture.staging_root).expect("root");
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed staging");
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming staging");
    stage_trusted_resource(
        TrustedStagingRequest::try_new(
            &fixture.plan,
            &fixture.review,
            fixture.analysis.as_ref(),
            fixture.text_diff.as_ref(),
            fixture.synthesis.as_ref(),
            fixture.merged_bytes.as_ref(),
            &fixture.baseline,
            &installed,
            &incoming,
            &root,
            TrustedStagingOptions::default(),
        )
        .expect("stage req"),
    )
    .expect("stage")
}

fn plan_apply(fixture: &Fixture, bundle: &TrustedStagingBundle) -> gkrm_core::TrustedApplyPlan {
    let apply_installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("apply installed");
    plan_trusted_apply(
        TrustedApplyPlanningRequest::try_new(
            bundle,
            &fixture.plan,
            &fixture.review,
            fixture.analysis.as_ref(),
            fixture.text_diff.as_ref(),
            fixture.synthesis.as_ref(),
            fixture.merged_bytes.as_ref(),
            &fixture.baseline,
            &apply_installed,
            TrustedApplyPlanningOptions::default(),
        )
        .expect("plan req"),
    )
    .expect("apply plan")
}

fn plan_tx(
    fixture: &Fixture,
    bundle: &TrustedStagingBundle,
    apply_plan: &gkrm_core::TrustedApplyPlan,
) -> gkrm_core::TrustedTransactionalApplyPlan {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("tx installed");
    plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new(
            apply_plan,
            bundle,
            &fixture.plan,
            &fixture.review,
            fixture.analysis.as_ref(),
            fixture.text_diff.as_ref(),
            fixture.synthesis.as_ref(),
            fixture.merged_bytes.as_ref(),
            &fixture.baseline,
            &installed,
            TrustedTransactionalApplyPlanningOptions::default(),
        )
        .expect("tx req"),
    )
    .expect("tx plan")
}

#[test]
fn task13_to_22_production_flow() {
    let fixture = build_mutating_fixture();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_store = format!("{:?}", hash_tree(&fixture.store));

    let bundle = stage_bundle(&fixture);
    let after_stage_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let apply = plan_apply(&fixture, &bundle);
    assert!(matches!(
        apply.status(),
        TrustedApplyStatus::ReadyForTransactionalApply
    ));
    let kinds: BTreeSet<_> = apply.operations().iter().map(|o| o.kind()).collect();
    assert!(kinds.contains(&TrustedApplyOperationKind::ReplaceFile)); // take/merge
    assert!(kinds.contains(&TrustedApplyOperationKind::DeleteFile)); // gone / obsolete
    assert!(kinds.contains(&TrustedApplyOperationKind::InstallFile)); // fresh
    assert!(kinds.contains(&TrustedApplyOperationKind::CreateDirectory)); // fresh/
    assert!(kinds.contains(&TrustedApplyOperationKind::RemoveDirectory)); // obsolete/
    assert!(apply.operations().iter().any(|o| !matches!(
        o.backup_requirement(),
        gkrm_core::ApplyBackupRequirement::None
    )));

    let tx = plan_tx(&fixture, &bundle, &apply);
    assert!(matches!(
        tx.status(),
        TrustedTransactionalApplyStatus::ReadyForTransactionalExecution
    ));

    let backup_needed = apply
        .operations()
        .iter()
        .filter(|o| {
            !matches!(
                o.backup_requirement(),
                gkrm_core::ApplyBackupRequirement::None
            )
        })
        .count();
    assert_eq!(tx.backup().entry_count(), backup_needed);

    let phases: Vec<_> = tx.forward_phases().collect();
    let prepared = phases
        .iter()
        .position(|p| *p == TransactionStepPhase::PersistPreparedJournal)
        .expect("prepared");
    let backup = phases
        .iter()
        .position(|p| *p == TransactionStepPhase::CreateBackupBundle)
        .expect("backup");
    let applying = phases
        .iter()
        .position(|p| *p == TransactionStepPhase::PersistApplyingJournal)
        .expect("applying");
    assert!(prepared < backup);
    assert!(backup < applying);

    let mutating_forward = phases
        .iter()
        .filter(|p| {
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
        .count();
    assert_eq!(mutating_forward, apply.operations().len());
    let mutating_rollback = tx
        .rollback_steps()
        .iter()
        .filter(|s| s.action() != RollbackAction::VerifyRollbackState)
        .count();
    assert_eq!(mutating_rollback, apply.operations().len());
    assert!(tx
        .rollback_steps()
        .iter()
        .any(|s| s.action() == RollbackAction::RecreateDirectoryWithMetadata));

    assert_eq!(tx.recovery().rows().len(), 10);
    assert!(tx
        .recovery()
        .rows()
        .iter()
        .any(|(b, _)| *b == TransactionCrashBoundary::Committed));

    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        after_stage_s
    );
    assert_eq!(format!("{:?}", hash_tree(&fixture.store)), before_store);
}

#[test]
fn task13_to_23_production_flow() {
    let fixture = build_mutating_fixture();
    let before_store = format!("{:?}", hash_tree(&fixture.store));
    let bundle = stage_bundle(&fixture);
    let after_stage_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let apply = plan_apply(&fixture, &bundle);
    let tx = plan_tx(&fixture, &bundle, &apply);

    let txn_root_path = fixture._temp_dir.path().join("txn-root");
    fs::create_dir_all(&txn_root_path).expect("txn root");
    let txn_root = TrustedTransactionRoot::try_open(&txn_root_path).expect("open txn");
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let result = execute_trusted_transactional_apply(
        TrustedTransactionalApplyExecutionRequest::try_new(
            &tx,
            &apply,
            &bundle,
            &fixture.plan,
            &fixture.review,
            fixture.analysis.as_ref(),
            fixture.text_diff.as_ref(),
            fixture.synthesis.as_ref(),
            fixture.merged_bytes.as_ref(),
            &fixture.baseline,
            &installed,
            &txn_root,
            &fixture.package_v2,
            TrustedTransactionalApplyExecutionOptions::default(),
        )
        .expect("exec req"),
    )
    .expect("execute");
    assert!(matches!(result, TrustedTransactionResult::Committed(_)));
    assert!(txn_root_path
        .join("transactions")
        .join(tx.plan_id().to_hex())
        .join("journal")
        .exists());
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        after_stage_s
    );
    assert_eq!(format!("{:?}", hash_tree(&fixture.store)), before_store);
}

#[test]
fn noop_filesystem_changes_execution_plan() {
    let fixture = build_noop_fixture();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));

    let bundle = stage_bundle(&fixture);
    let after_stage_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let apply = plan_apply(&fixture, &bundle);
    assert!(matches!(
        apply.status(),
        TrustedApplyStatus::NoFilesystemChanges
    ));
    assert!(apply.operations().is_empty());
    assert_eq!(apply.summary().operation_count(), 0);
    assert_eq!(apply.summary().total_expected_write_bytes(), 0);
    assert_eq!(apply.summary().total_backup_bytes(), 0);

    let tx = plan_tx(&fixture, &bundle, &apply);
    assert!(matches!(
        tx.status(),
        TrustedTransactionalApplyStatus::NoFilesystemChanges
    ));
    assert_eq!(tx.backup().entry_count(), 0);
    assert_eq!(tx.summary().total_expected_write_bytes(), 0);
    assert_eq!(tx.summary().total_backup_bytes(), 0);
    assert_eq!(tx.summary().backup_entry_count(), 0);
    assert!(tx.rollback_steps().is_empty());

    let phases: Vec<_> = tx.forward_phases().collect();
    assert!(phases.contains(&TransactionStepPhase::Preflight));
    assert!(phases.contains(&TransactionStepPhase::PersistPreparedJournal));
    assert!(phases.contains(&TransactionStepPhase::PersistCommittedJournal));
    assert!(phases.contains(&TransactionStepPhase::Finalize));
    assert!(!phases.contains(&TransactionStepPhase::CreateBackupBundle));
    assert!(!phases.iter().any(|p| matches!(
        p,
        TransactionStepPhase::ApplyBlockingDeletes
            | TransactionStepPhase::InstallOrReplaceFiles
            | TransactionStepPhase::DeleteObsoleteFiles
            | TransactionStepPhase::CreateDirectories
            | TransactionStepPhase::RemoveObsoleteDirectories
    )));

    const FIXED_TASK22_NOOP_PLAN_ID: &str =
        "3b1eb6b87ff7123b75c44681bde68aa5fc3afddfb015268a44589e30ad6ca594";
    assert_eq!(tx.plan_id().to_hex(), FIXED_TASK22_NOOP_PLAN_ID);

    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        after_stage_s
    );
}
