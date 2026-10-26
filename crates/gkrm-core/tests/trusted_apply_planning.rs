//! Integration tests for Task 21 trusted apply planning.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, plan_three_way_merge_synthesis,
    plan_three_way_text_diffs, plan_trusted_apply, resolve_official_baseline,
    review_three_way_update_plan, stage_trusted_resource, synthesize_three_way_merged_bytes,
    BaselineCaptureOptions, BaselineCaptureRequest, BaselineResolutionOptions,
    BaselineResolutionRequest, IncomingMergeContentSourceLimits, IncomingOfficialResourceSnapshot,
    IncomingResourceSelector, IncomingStagingContentSource, InspectionOptions,
    InstallationRelativePath, InstalledApplyPlanningSource, InstalledResourceRoot,
    InstalledResourceSnapshot, InstalledScanLimits, InstalledStagingContentSource,
    MergedByteDisposition, OfficialBaselineSelector, PolicyTransitionAcknowledgement,
    ResolvedOfficialBaseline, SafeResourceKey, ThreeWayMergeAnalysisOptions,
    ThreeWayMergeAnalysisPlan, ThreeWayMergeAnalysisRequest, ThreeWayMergeSynthesisOptions,
    ThreeWayMergeSynthesisPlan, ThreeWayMergeSynthesisRequest, ThreeWayMergedBytesOptions,
    ThreeWayMergedBytesPlan, ThreeWayMergedBytesRequest, ThreeWayPlanDecision,
    ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet, ThreeWayPlanDisposition,
    ThreeWayPlanReview, ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayTextDiffOptions,
    ThreeWayTextDiffPlan, ThreeWayTextDiffRequest, ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest,
    TrustedApplyOperationKind, TrustedApplyPlanningOptions, TrustedApplyPlanningRequest,
    TrustedApplyStatus, TrustedStagingOptions, TrustedStagingRequest, TrustedStagingRoot,
    ZipRelativePath, ZipResourceRoot,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'keep.lua',\n  'take.lua',\n  'merge.lua',\n  'gone.lua',\n}\n";
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
    analysis: ThreeWayMergeAnalysisPlan,
    text_diff: ThreeWayTextDiffPlan,
    synthesis: ThreeWayMergeSynthesisPlan,
    merged_bytes: ThreeWayMergedBytesPlan,
}

fn build_review_decisions(plan: &ThreeWayUpdatePlan) -> ThreeWayPlanDecisionSet {
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
                "take.lua" | "gone.lua" => ThreeWayPlanDecisionChoice::UseIncomingState,
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
    ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).expect("set")
}

fn build_fixture() -> Fixture {
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

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/keep.lua", KEEP_INCOMING),
            ("gksphone/take.lua", TAKE_INCOMING),
            ("gksphone/merge.lua", MERGE_INCOMING),
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
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &build_review_decisions(&plan))
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
        analysis,
        text_diff,
        synthesis,
        merged_bytes,
    }
}

fn stage_and_plan(fixture: &Fixture) -> gkrm_core::TrustedApplyPlan {
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
    let bundle = stage_trusted_resource(
        TrustedStagingRequest::try_new(
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &installed,
            &incoming,
            &root,
            TrustedStagingOptions::default(),
        )
        .expect("stage req"),
    )
    .expect("stage");

    let apply_installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("apply installed");
    plan_trusted_apply(
        TrustedApplyPlanningRequest::try_new(
            &bundle,
            &fixture.plan,
            &fixture.review,
            Some(&fixture.analysis),
            Some(&fixture.text_diff),
            Some(&fixture.synthesis),
            Some(&fixture.merged_bytes),
            &fixture.baseline,
            &apply_installed,
            TrustedApplyPlanningOptions::default(),
        )
        .expect("plan req"),
    )
    .expect("plan")
}

#[test]
fn task13_to_21_flow_is_read_only_and_deterministic() {
    let fixture = build_fixture();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).expect("pkg");
    let before_store = format!("{:?}", hash_tree(&fixture.store));

    let plan_a = stage_and_plan(&fixture);
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(fs::read(&fixture.package_v2).expect("pkg"), before_p);
    assert_eq!(format!("{:?}", hash_tree(&fixture.store)), before_store);

    assert!(matches!(
        plan_a.status(),
        TrustedApplyStatus::ReadyForTransactionalApply
    ));
    assert!(!plan_a.operations().is_empty());
    assert!(plan_a.operations().iter().any(|o| {
        matches!(
            o.kind(),
            TrustedApplyOperationKind::InstallFile
                | TrustedApplyOperationKind::ReplaceFile
                | TrustedApplyOperationKind::DeleteFile
        )
    }));

    // Second staging root for a second independent plan ID comparison.
    let staging_b = fixture._temp_dir.path().join("staging-b");
    fs::create_dir_all(&staging_b).expect("staging-b");
    let mut fixture_b = build_fixture();
    fixture_b.staging_root = staging_b;
    let plan_b = stage_and_plan(&fixture_b);
    // Plan, backup-set, and operation IDs are content-stable across independent roots.
    assert_eq!(plan_a.plan_id().to_hex(), plan_b.plan_id().to_hex());
    assert_eq!(
        plan_a.backup_set_id().digest().to_string(),
        plan_b.backup_set_id().digest().to_string()
    );
    assert_eq!(plan_a.operations().len(), plan_b.operations().len());
    for (a, b) in plan_a.operations().iter().zip(plan_b.operations()) {
        assert_eq!(a.operation_id().digest(), b.operation_id().digest());
        assert_eq!(a.kind(), b.kind());
        assert_eq!(a.phase(), b.phase());
    }
}
