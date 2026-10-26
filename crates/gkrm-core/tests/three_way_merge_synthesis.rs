use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, plan_three_way_merge_synthesis,
    plan_three_way_text_diffs, resolve_official_baseline, review_three_way_update_plan,
    BaselineCaptureOptions, BaselineCaptureRequest, BaselineResolutionOptions,
    BaselineResolutionRequest, BaselineStoreLimits, GkrmError, IncomingMergeContentSource,
    IncomingMergeContentSourceLimits, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
    InspectionOptions, InstallationRelativePath, InstalledMergeContentSource,
    InstalledResourceRoot, InstalledResourceSnapshot, InstalledScanLimits,
    MergeSynthesisDisposition, MergeSynthesisOperationKind, MergeSynthesisStatus,
    OfficialBaselineSelector, PolicyTransitionAcknowledgement, ResolvedOfficialBaseline,
    SafeResourceKey, SupportedTextNewlineStyle, TextTerminalNewline, ThreeWayMergeAnalysisOptions,
    ThreeWayMergeAnalysisPlan, ThreeWayMergeAnalysisRequest, ThreeWayMergeAnalysisStatus,
    ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisRequest, ThreeWayPlanDecision,
    ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet, ThreeWayPlanDisposition,
    ThreeWayPlanReview, ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayReviewedAction,
    ThreeWayTextDiffDisposition, ThreeWayTextDiffOptions, ThreeWayTextDiffPlan,
    ThreeWayTextDiffRequest, ThreeWayTextDiffStatus, ThreeWayTextOverlapClassification,
    ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest, ZipRelativePath, ZipResourceRoot,
};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'disjoint.lua',\n  'divergent_insert.lua',\n  'overlap_replace.lua',\n  'envelope.lua',\n  'equivalent.lua',\n}\n";

const CONFLICT_ONLY_MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'divergent_insert.lua',\n  'overlap_replace.lua',\n}\n";

const DISJOINT_BASE: &[u8] = b"L1\nL2\nL3\nL4\n";
const DISJOINT_INSTALLED: &[u8] = b"L1x\nL2\nL3\nL4\n";
const DISJOINT_INCOMING: &[u8] = b"L1\nL2\nL3\nL4y\n";

const DIVERGENT_BASE: &[u8] = b"L1\nL2\n";
const DIVERGENT_INSTALLED: &[u8] = b"L1\nINST\nL2\n";
const DIVERGENT_INCOMING: &[u8] = b"L1\nINCOMING\nL2\n";

const OVERLAP_BASE: &[u8] = b"L1\nL2\nL3\n";
const OVERLAP_INSTALLED: &[u8] = b"L1\nL2a\nL3\n";
const OVERLAP_INCOMING: &[u8] = b"L1\nL2b\nL3\n";

const ENVELOPE_BASE: &[u8] = b"hello\n";
const ENVELOPE_INSTALLED: &[u8] = b"hello\r\n";
const ENVELOPE_INCOMING: &[u8] = b"\xEF\xBB\xBFhello\n";

const EQUIVALENT_BASE: &[u8] = b"line 1\nshared old\nline 3\n";
const EQUIVALENT_INSTALLED: &[u8] = b"installed extra\nline 1\nshared new\nline 3\n";
const EQUIVALENT_INCOMING: &[u8] = b"line 1\nshared new\nline 3\nincoming extra\n";

/// Approved Task 18 plan-ID for the production fixture with default synthesis options.
/// Update after the first successful `cargo test` run locks the digest.
const FIXED_TASK18_PRODUCTION_PLAN_ID: &str =
    "86bbc01f41d7e93fb647ec31162c13cf79c9a7b3c471af47679e0551e98194c7";
const FIXED_DISJOINT_INSTALLED_OP_ID: &str =
    "560205a2e10f0b80817c639eeaed4916870fb8546a6c49cadc394d0b32f93dd0";
const FIXED_DISJOINT_COPY_BASE_OP_ID: &str =
    "c8f4778fa79abc49a9c9fe2ade3b9e266d7108e6b9b4c1cfca7286984f3a7d84";
const FIXED_DISJOINT_INCOMING_OP_ID: &str =
    "6635259b615deaa8ecd33c3754b77b0fdcaa100297958cc3efaa4e1394565915";

fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().expect("test path should have parent"))
        .expect("parent should be created");
    fs::write(path, contents).expect("file should be written");
}

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("zip should be created");
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer
            .start_file(*name, options)
            .expect("entry should start");
        writer.write_all(contents).expect("entry should be written");
    }
    writer.finish().expect("zip should finish");
}

fn key(value: &str) -> SafeResourceKey {
    SafeResourceKey::parse(value).expect("safe key")
}

fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

fn incoming_root(path: &str) -> ZipResourceRoot {
    ZipResourceRoot::Path(ZipRelativePath::parse_canonical(path).unwrap())
}

fn plan_disposition(plan: &ThreeWayUpdatePlan, path: &str) -> ThreeWayPlanDisposition {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing plan entry {path}"))
        .disposition()
}

fn text_disposition(plan: &ThreeWayTextDiffPlan, path: &str) -> ThreeWayTextDiffDisposition {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing text-diff entry {path}"))
        .disposition()
}

fn synthesis_disposition(
    plan: &gkrm_core::ThreeWayMergeSynthesisPlan,
    path: &str,
) -> MergeSynthesisDisposition {
    synthesis_entry(plan, path).disposition()
}

fn synthesis_entry<'a>(
    plan: &'a gkrm_core::ThreeWayMergeSynthesisPlan,
    path: &str,
) -> &'a gkrm_core::ThreeWayMergeSynthesisEntry {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing synthesis entry {path}"))
}

fn queue_all_merge_candidates(plan: &ThreeWayUpdatePlan) -> ThreeWayPlanDecisionSet {
    let decisions = plan
        .entries()
        .iter()
        .filter(|entry| entry.disposition() == ThreeWayPlanDisposition::MergeCandidate)
        .map(|entry| {
            ThreeWayPlanDecision::try_new(
                entry.path().clone(),
                ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("queue decision")
        })
        .collect::<Vec<_>>();
    ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).expect("decision set")
}

fn default_text_diff_options() -> ThreeWayTextDiffOptions {
    ThreeWayTextDiffOptions::default()
}

fn default_synthesis_options() -> ThreeWayMergeSynthesisOptions {
    ThreeWayMergeSynthesisOptions::default()
}

struct MergeSynthesisFixture {
    temp_dir: tempfile::TempDir,
    installed_parent: PathBuf,
    installed_resource: PathBuf,
    package_v2: PathBuf,
    baseline: ResolvedOfficialBaseline,
    plan: ThreeWayUpdatePlan,
    review: ThreeWayPlanReview,
    analysis: ThreeWayMergeAnalysisPlan,
    text_diff: ThreeWayTextDiffPlan,
}

fn plan_text_diff_for(
    installed_parent: &Path,
    package_v2: &Path,
    plan: &ThreeWayUpdatePlan,
    review: &ThreeWayPlanReview,
    analysis: &ThreeWayMergeAnalysisPlan,
    baseline: &ResolvedOfficialBaseline,
) -> ThreeWayTextDiffPlan {
    let installed_source = InstalledMergeContentSource::try_new(
        installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed source");
    let incoming_source = IncomingMergeContentSource::try_new(
        package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming source");
    plan_three_way_text_diffs(
        ThreeWayTextDiffRequest::try_new(
            plan,
            review,
            analysis,
            baseline,
            &installed_source,
            &incoming_source,
            default_text_diff_options(),
        )
        .expect("text-diff request"),
    )
    .expect("text-diff plan")
}

fn build_production_fixture() -> MergeSynthesisFixture {
    let temp = tempdir().expect("temp");
    let installed_for_capture = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let package_v1 = temp.path().join("official-v1.zip");
    let package_v2 = temp.path().join("official-v2.zip");
    fs::create_dir_all(&installed_for_capture).expect("capture installed");
    fs::create_dir_all(&store).expect("store");

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/disjoint.lua", DISJOINT_BASE),
            ("gksphone/divergent_insert.lua", DIVERGENT_BASE),
            ("gksphone/overlap_replace.lua", OVERLAP_BASE),
            ("gksphone/envelope.lua", ENVELOPE_BASE),
            ("gksphone/equivalent.lua", EQUIVALENT_BASE),
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
        .expect("capture request"),
    )
    .expect("capture");
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &key("gksphone"),
            OfficialBaselineSelector::Exact(capture.baseline_id().clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("resolution request"),
    )
    .expect("resolve");

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("disjoint.lua"), DISJOINT_INSTALLED);
    write_file(
        &installed_resource.join("divergent_insert.lua"),
        DIVERGENT_INSTALLED,
    );
    write_file(
        &installed_resource.join("overlap_replace.lua"),
        OVERLAP_INSTALLED,
    );
    write_file(&installed_resource.join("envelope.lua"), ENVELOPE_INSTALLED);
    write_file(
        &installed_resource.join("equivalent.lua"),
        EQUIVALENT_INSTALLED,
    );

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/disjoint.lua", DISJOINT_INCOMING),
            ("gksphone/divergent_insert.lua", DIVERGENT_INCOMING),
            ("gksphone/overlap_replace.lua", OVERLAP_INCOMING),
            ("gksphone/envelope.lua", ENVELOPE_INCOMING),
            ("gksphone/equivalent.lua", EQUIVALENT_INCOMING),
        ],
    );

    let report =
        inspect_installation_update(&installed_parent, &package_v2, InspectionOptions::default())
            .expect("inspection");
    let installed_snapshot = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .expect("installed snapshot");
    let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("incoming snapshot");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("plan");

    for path in [
        "disjoint.lua",
        "divergent_insert.lua",
        "overlap_replace.lua",
        "envelope.lua",
        "equivalent.lua",
    ] {
        assert_eq!(
            plan_disposition(&plan, path),
            ThreeWayPlanDisposition::MergeCandidate,
            "{path} should be a merge candidate"
        );
    }

    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &queue_all_merge_candidates(&plan))
            .expect("review request"),
    )
    .expect("review");
    assert!(review
        .entries()
        .iter()
        .any(|entry| entry.action() == ThreeWayReviewedAction::QueueMergeAnalysis));

    let installed_source = InstalledMergeContentSource::try_new(
        &installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed source");
    let incoming_source = IncomingMergeContentSource::try_new(
        &package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming source");
    let analysis = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &plan,
            &review,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis request"),
    )
    .expect("analysis");

    assert_eq!(analysis.summary().ready_for_text_merge_planning(), 5);
    assert_eq!(
        analysis.status(),
        ThreeWayMergeAnalysisStatus::ReadyForFurtherPlanning
    );

    let text_diff = plan_text_diff_for(
        &installed_parent,
        &package_v2,
        &plan,
        &review,
        &analysis,
        &baseline,
    );
    assert_eq!(text_diff.status(), ThreeWayTextDiffStatus::HasConflicts);
    assert_eq!(text_diff.summary().ready_for_merge_synthesis(), 3);
    assert_eq!(
        text_disposition(&text_diff, "disjoint.lua"),
        ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
    );
    assert_eq!(
        text_disposition(&text_diff, "equivalent.lua"),
        ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
    );

    MergeSynthesisFixture {
        temp_dir: temp,
        installed_parent,
        installed_resource,
        package_v2,
        baseline,
        plan,
        review,
        analysis,
        text_diff,
    }
}

fn build_conflict_only_fixture() -> MergeSynthesisFixture {
    let temp = tempdir().expect("temp");
    let installed_for_capture = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let package_v1 = temp.path().join("official-v1.zip");
    let package_v2 = temp.path().join("official-v2.zip");
    fs::create_dir_all(&installed_for_capture).expect("capture installed");
    fs::create_dir_all(&store).expect("store");

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", CONFLICT_ONLY_MANIFEST),
            ("gksphone/divergent_insert.lua", DIVERGENT_BASE),
            ("gksphone/overlap_replace.lua", OVERLAP_BASE),
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
        .expect("capture request"),
    )
    .expect("capture");
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &key("gksphone"),
            OfficialBaselineSelector::Exact(capture.baseline_id().clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("resolution request"),
    )
    .expect("resolve");

    write_file(
        &installed_resource.join("fxmanifest.lua"),
        CONFLICT_ONLY_MANIFEST,
    );
    write_file(
        &installed_resource.join("divergent_insert.lua"),
        DIVERGENT_INSTALLED,
    );
    write_file(
        &installed_resource.join("overlap_replace.lua"),
        OVERLAP_INSTALLED,
    );

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", CONFLICT_ONLY_MANIFEST),
            ("gksphone/divergent_insert.lua", DIVERGENT_INCOMING),
            ("gksphone/overlap_replace.lua", OVERLAP_INCOMING),
        ],
    );

    let report =
        inspect_installation_update(&installed_parent, &package_v2, InspectionOptions::default())
            .expect("inspection");
    let installed_snapshot = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .expect("installed snapshot");
    let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("incoming snapshot");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("plan");

    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &queue_all_merge_candidates(&plan))
            .expect("review request"),
    )
    .expect("review");

    let installed_source = InstalledMergeContentSource::try_new(
        &installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed source");
    let incoming_source = IncomingMergeContentSource::try_new(
        &package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming source");
    let analysis = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &plan,
            &review,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis request"),
    )
    .expect("analysis");

    let text_diff = plan_text_diff_for(
        &installed_parent,
        &package_v2,
        &plan,
        &review,
        &analysis,
        &baseline,
    );
    assert_eq!(text_diff.summary().ready_for_merge_synthesis(), 0);
    assert_eq!(text_diff.summary().conflict_text(), 2);

    MergeSynthesisFixture {
        temp_dir: temp,
        installed_parent,
        installed_resource,
        package_v2,
        baseline,
        plan,
        review,
        analysis,
        text_diff,
    }
}

fn plan_merge_synthesis(
    fixture: &MergeSynthesisFixture,
    options: ThreeWayMergeSynthesisOptions,
) -> Result<gkrm_core::ThreeWayMergeSynthesisPlan, GkrmError> {
    let installed_source = InstalledMergeContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed source");
    let incoming_source = IncomingMergeContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming source");
    plan_three_way_merge_synthesis(
        ThreeWayMergeSynthesisRequest::try_new(
            &fixture.plan,
            &fixture.review,
            &fixture.analysis,
            &fixture.text_diff,
            &fixture.baseline,
            &installed_source,
            &incoming_source,
            options,
        )
        .expect("synthesis request"),
    )
}

fn installed_file_hashes(fixture: &MergeSynthesisFixture) -> Vec<(PathBuf, Vec<u8>)> {
    [
        "disjoint.lua",
        "divergent_insert.lua",
        "overlap_replace.lua",
        "envelope.lua",
        "equivalent.lua",
    ]
    .into_iter()
    .filter_map(|name| {
        let path = fixture.installed_resource.join(name);
        if path.exists() {
            Some((path.clone(), fs::read(&path).expect("read installed")))
        } else {
            None
        }
    })
    .collect()
}

#[test]
fn production_merge_synthesis_through_tasks_13_to_18() {
    let fixture = build_production_fixture();

    let installed_before = installed_file_hashes(&fixture);
    let package_before = fs::read(&fixture.package_v2).expect("package before");

    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    let repeated = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("repeat");

    assert_eq!(synthesis.plan_id(), fixture.plan.plan_id());
    assert_eq!(synthesis.review_id(), fixture.review.review_id());
    assert_eq!(synthesis.analysis_id(), fixture.analysis.analysis_id());
    assert_eq!(
        synthesis.text_diff_plan_id(),
        fixture.text_diff.text_diff_plan_id()
    );
    assert_eq!(
        synthesis.status(),
        MergeSynthesisStatus::ReadyForByteSynthesis
    );
    assert_eq!(synthesis.summary().total_candidates(), 3);
    assert_eq!(synthesis.summary().ready_for_byte_synthesis(), 3);
    assert_eq!(synthesis.summary().manual_operation_limit(), 0);
    assert!(synthesis.summary().total_operations() > 0);

    assert_eq!(
        synthesis.synthesis_plan_id().digest().to_string(),
        repeated.synthesis_plan_id().digest().to_string()
    );
    assert_eq!(
        synthesis.synthesis_plan_id().digest().to_string(),
        FIXED_TASK18_PRODUCTION_PLAN_ID,
        "update FIXED_TASK18_PRODUCTION_PLAN_ID to {}",
        synthesis.synthesis_plan_id().digest()
    );

    let paths: Vec<_> = synthesis
        .entries()
        .iter()
        .map(|entry| entry.path().as_str())
        .collect();
    assert_eq!(paths, ["disjoint.lua", "envelope.lua", "equivalent.lua"]);
    assert!(!paths.contains(&"divergent_insert.lua"));
    assert!(!paths.contains(&"overlap_replace.lua"));

    for path in ["disjoint.lua", "equivalent.lua"] {
        assert_eq!(
            synthesis_disposition(&synthesis, path),
            MergeSynthesisDisposition::ReadyForByteSynthesis
        );
        assert!(synthesis_entry(&synthesis, path)
            .merged_line_sequence_commitment()
            .is_some());
        assert!(!synthesis_entry(&synthesis, path).operations().is_empty());
    }

    let envelope_entry = synthesis_entry(&synthesis, "envelope.lua");
    assert_eq!(
        envelope_entry.disposition(),
        MergeSynthesisDisposition::ReadyForByteSynthesis
    );
    assert!(envelope_entry.merged_line_sequence_commitment().is_some());

    let debug_plan = format!("{synthesis:?}");
    assert!(!debug_plan.contains("L1x"));
    assert!(!debug_plan.contains("shared new"));

    for (path, before) in installed_before {
        assert_eq!(fs::read(path).expect("installed after"), before);
    }
    assert_eq!(
        fs::read(&fixture.package_v2).expect("package after"),
        package_before
    );
}

#[test]
fn wrong_text_diff_binding_fails_before_io() {
    let left = build_production_fixture();
    let right = build_conflict_only_fixture();
    assert_ne!(
        left.text_diff.text_diff_plan_id(),
        right.text_diff.text_diff_plan_id()
    );

    let installed_source = InstalledMergeContentSource::try_new(
        &left.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed source");
    let incoming_source = IncomingMergeContentSource::try_new(
        &left.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming source");

    let before = fs::read(left.installed_resource.join("disjoint.lua")).expect("before");
    let error = plan_three_way_merge_synthesis(
        ThreeWayMergeSynthesisRequest::try_new(
            &left.plan,
            &left.review,
            &left.analysis,
            &right.text_diff,
            &left.baseline,
            &installed_source,
            &incoming_source,
            default_synthesis_options(),
        )
        .expect("request"),
    )
    .expect_err("cross-wired text-diff must fail");

    assert!(matches!(
        error,
        GkrmError::ThreeWayMergeSynthesisPlanTextDiffBindingMismatch
            | GkrmError::ThreeWayMergeSynthesisReviewTextDiffBindingMismatch
            | GkrmError::ThreeWayMergeSynthesisAnalysisTextDiffBindingMismatch
            | GkrmError::ThreeWayMergeSynthesisTextDiffStructuralMismatch
    ));
    assert_eq!(
        fs::read(left.installed_resource.join("disjoint.lua")).expect("after"),
        before
    );
}

#[test]
fn no_ready_merge_synthesis_candidates() {
    let fixture = build_conflict_only_fixture();
    let error = plan_merge_synthesis(&fixture, default_synthesis_options())
        .expect_err("conflict-only resource has no ready synthesis candidates");
    assert!(matches!(
        error,
        GkrmError::ThreeWayMergeSynthesisNoReadyCandidates
    ));
}

#[test]
fn stale_installed_source_fails() {
    let fixture = build_production_fixture();
    write_file(
        &fixture.installed_resource.join("disjoint.lua"),
        b"mutated-after-text-diff\n",
    );

    let error = plan_merge_synthesis(&fixture, default_synthesis_options())
        .expect_err("installed mutation must fail closed");
    assert!(matches!(
        error,
        GkrmError::ThreeWayMergeSynthesisInstalledPreFingerprintMismatch
            | GkrmError::ThreeWayMergeSynthesisInstalledCandidateInvalid
            | GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged
            | GkrmError::ThreeWayMergeSynthesisSourceIdentityChanged
            | GkrmError::ThreeWayMergeSynthesisTask16MetadataMismatch
            | GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch
    ));
}

#[test]
fn disjoint_installed_incoming_edits_schedule() {
    let fixture = build_production_fixture();
    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    let entry = synthesis_entry(&synthesis, "disjoint.lua");
    let kinds: Vec<_> = entry.operations().iter().map(|op| op.kind()).collect();
    assert_eq!(
        kinds,
        [
            MergeSynthesisOperationKind::UseInstalledReplacement,
            MergeSynthesisOperationKind::CopyBase,
            MergeSynthesisOperationKind::UseIncomingReplacement,
        ]
    );
    let ids: Vec<_> = entry
        .operations()
        .iter()
        .map(|op| op.id().digest().to_string())
        .collect();
    assert_eq!(
        ids,
        [
            FIXED_DISJOINT_INSTALLED_OP_ID,
            FIXED_DISJOINT_COPY_BASE_OP_ID,
            FIXED_DISJOINT_INCOMING_OP_ID,
        ],
        "update fixed disjoint operation IDs to {ids:?}"
    );
}

#[test]
fn equivalent_group_emitted_once() {
    let fixture = build_production_fixture();
    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    let entry = synthesis_entry(&synthesis, "equivalent.lua");
    let equivalent_ops: Vec<_> = entry
        .operations()
        .iter()
        .filter(|op| op.kind() == MergeSynthesisOperationKind::UseEquivalentReplacement)
        .collect();
    assert_eq!(equivalent_ops.len(), 1);
    assert!(equivalent_ops[0].equivalent_peer_hunk_id().is_some());

    let installed_inserts: Vec<_> = entry
        .operations()
        .iter()
        .filter(|op| op.kind() == MergeSynthesisOperationKind::UseInstalledReplacement)
        .collect();
    let incoming_inserts: Vec<_> = entry
        .operations()
        .iter()
        .filter(|op| op.kind() == MergeSynthesisOperationKind::UseIncomingReplacement)
        .collect();
    assert_eq!(installed_inserts.len(), 1);
    assert_eq!(incoming_inserts.len(), 1);
    assert_eq!(
        installed_inserts[0].base_range().start(),
        installed_inserts[0].base_range().end()
    );
    assert_eq!(
        incoming_inserts[0].base_range().start(),
        incoming_inserts[0].base_range().end()
    );
}

#[test]
fn insert_and_same_anchor_ordering() {
    let fixture = build_production_fixture();
    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    let entry = synthesis_entry(&synthesis, "equivalent.lua");
    let anchors: Vec<_> = entry
        .operations()
        .iter()
        .map(|op| (op.base_range().start(), op.kind()))
        .collect();
    assert_eq!(anchors[0].0, 0);
    assert_eq!(
        anchors[0].1,
        MergeSynthesisOperationKind::UseInstalledReplacement
    );
    let last = anchors.last().expect("incoming insert at end");
    assert_eq!(last.1, MergeSynthesisOperationKind::UseIncomingReplacement);
    assert!(last.0 >= anchors[0].0);
}

#[test]
fn complete_base_coverage_and_no_duplicate_hunks() {
    let fixture = build_production_fixture();
    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");

    for path in ["disjoint.lua", "equivalent.lua"] {
        let entry = synthesis_entry(&synthesis, path);
        let base_len = entry
            .operations()
            .iter()
            .filter(|op| op.base_range().start() != op.base_range().end())
            .map(|op| op.base_range().end())
            .max()
            .unwrap_or(0);
        let mut covered = vec![false; base_len];
        for op in entry.operations() {
            if op.base_range().start() == op.base_range().end() {
                continue;
            }
            let range = op.base_range();
            for item in &mut covered[range.start()..range.end()] {
                assert!(!*item, "{path}: overlapping base index");
                *item = true;
            }
        }
        for (index, seen) in covered.iter().enumerate() {
            assert!(seen, "{path}: base index {index} not covered");
        }

        let mut hunk_ids = BTreeSet::new();
        for op in entry.operations() {
            if let Some(hunk_id) = op.source_hunk_id() {
                assert!(
                    hunk_ids.insert(hunk_id.digest().to_string()),
                    "{path}: duplicate hunk id"
                );
            }
            if let Some(peer) = op.equivalent_peer_hunk_id() {
                assert!(
                    hunk_ids.insert(format!("peer:{}", peer.digest())),
                    "{path}: duplicate peer hunk id"
                );
            }
        }
    }
}

#[test]
fn replay_produces_merged_line_commitment() {
    let fixture = build_production_fixture();
    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    for path in ["disjoint.lua", "equivalent.lua"] {
        let entry = synthesis_entry(&synthesis, path);
        assert_eq!(
            entry.disposition(),
            MergeSynthesisDisposition::ReadyForByteSynthesis
        );
        assert!(entry.merged_line_sequence_commitment().is_some());
    }
}

#[test]
fn envelope_resolution_for_ready_entries() {
    let fixture = build_production_fixture();
    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    let envelope = synthesis_entry(&synthesis, "disjoint.lua").final_envelope();
    assert!(!envelope.bom());
    assert_eq!(envelope.newline_style(), SupportedTextNewlineStyle::Lf);
    assert_eq!(envelope.terminal_newline(), TextTerminalNewline::Present);
}

#[test]
fn source_byte_limit_is_top_level_error() {
    let fixture = build_production_fixture();
    let options = ThreeWayMergeSynthesisOptions::try_new(
        1_000,
        1,
        128 * 1024 * 1024,
        200_000,
        600_000,
        50_000,
        500_000,
        BaselineStoreLimits::default(),
    )
    .expect("tiny per-file limit");
    let error = plan_merge_synthesis(&fixture, options).expect_err("retain limit must fail");
    assert!(matches!(
        error,
        GkrmError::ThreeWayMergeSynthesisSourceByteLimitExceeded { .. }
            | GkrmError::ThreeWayMergeSynthesisTotalSourceByteLimitExceeded { .. }
    ));
}

#[test]
fn operation_limit_yields_manual_empty_ops() {
    let fixture = build_production_fixture();
    let options = ThreeWayMergeSynthesisOptions::try_new(
        1_000,
        4 * 1024 * 1024,
        128 * 1024 * 1024,
        200_000,
        600_000,
        1,
        500_000,
        BaselineStoreLimits::default(),
    )
    .expect("single-op limit");
    let synthesis = plan_merge_synthesis(&fixture, options).expect("partial manual plan");
    assert_eq!(
        synthesis.status(),
        MergeSynthesisStatus::HasManualReviewEntries
    );

    let disjoint = synthesis_entry(&synthesis, "disjoint.lua");
    assert_eq!(
        disjoint.disposition(),
        MergeSynthesisDisposition::ManualReviewOperationLimit
    );
    assert!(disjoint.operations().is_empty());
    assert!(disjoint.merged_line_sequence_commitment().is_none());

    let ready_ops: usize = synthesis
        .entries()
        .iter()
        .filter(|entry| entry.disposition() == MergeSynthesisDisposition::ReadyForByteSynthesis)
        .map(|entry| entry.operations().len())
        .sum();
    assert_eq!(synthesis.summary().total_operations(), ready_ops);
    assert_eq!(
        synthesis
            .entries()
            .iter()
            .filter(|entry| {
                entry.disposition() == MergeSynthesisDisposition::ManualReviewOperationLimit
            })
            .map(|entry| entry.operations().len())
            .sum::<usize>(),
        0
    );
}

#[test]
fn total_operation_limit_yields_manual_without_partial_ops() {
    let fixture = build_production_fixture();
    let options = ThreeWayMergeSynthesisOptions::try_new(
        1_000,
        4 * 1024 * 1024,
        128 * 1024 * 1024,
        200_000,
        600_000,
        2,
        2,
        BaselineStoreLimits::default(),
    )
    .expect("tiny total ops");
    let synthesis = plan_merge_synthesis(&fixture, options).expect("plan under total limit");
    assert_eq!(
        synthesis.status(),
        MergeSynthesisStatus::HasManualReviewEntries
    );
    let mut limited = 0usize;
    for entry in synthesis.entries() {
        if entry.disposition() == MergeSynthesisDisposition::ManualReviewOperationLimit {
            limited = limited.saturating_add(1);
            assert!(entry.operations().is_empty());
            assert!(entry.merged_line_sequence_commitment().is_none());
        }
    }
    assert!(limited >= 1);
    assert!(synthesis.summary().total_operations() <= 2);
}

#[test]
fn candidate_order_independent() {
    let fixture = build_production_fixture();
    let first = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("first");
    let second = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("second");
    assert_eq!(
        first.synthesis_plan_id().digest(),
        second.synthesis_plan_id().digest()
    );
    let paths: Vec<_> = first.entries().iter().map(|e| e.path().as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted, "entries must be path-sorted");
}

#[test]
fn binding_error_display_omits_paths() {
    let left = build_production_fixture();
    let right = build_conflict_only_fixture();
    let temp_prefix = left
        .temp_dir
        .path()
        .canonicalize()
        .unwrap_or_else(|_| left.temp_dir.path().to_path_buf());
    let temp_display = temp_prefix.to_string_lossy().into_owned();

    let installed_source = InstalledMergeContentSource::try_new(
        &left.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed source");
    let incoming_source = IncomingMergeContentSource::try_new(
        &left.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming source");

    let error = plan_three_way_merge_synthesis(
        ThreeWayMergeSynthesisRequest::try_new(
            &left.plan,
            &right.review,
            &left.analysis,
            &left.text_diff,
            &left.baseline,
            &installed_source,
            &incoming_source,
            default_synthesis_options(),
        )
        .expect("request"),
    )
    .expect_err("binding mismatch");

    let rendered = format!("{error}");
    assert!(
        !rendered.contains(&temp_display),
        "error display leaked temp path: {rendered}"
    );
    let raw_temp = left.temp_dir.path().to_string_lossy();
    assert!(
        !rendered.contains(raw_temp.as_ref()),
        "error display leaked raw temp path: {rendered}"
    );
}

#[test]
fn no_source_modification() {
    let fixture = build_production_fixture();
    let before = installed_file_hashes(&fixture);
    let package_before = fs::read(&fixture.package_v2).expect("package before");
    let _ = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    for (path, bytes) in before {
        assert_eq!(fs::read(path).expect("installed after"), bytes);
    }
    assert_eq!(
        fs::read(&fixture.package_v2).expect("package after"),
        package_before
    );
}

#[test]
fn multi_hunk_equivalent_requires_contiguous_sides() {
    // Single-hunk equivalent after Task 17 coalescence: L1a+L2a replace shared old once.
    let fixture = build_production_fixture();
    let text_entry = fixture
        .text_diff
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == "equivalent.lua")
        .expect("equivalent text-diff entry");
    let equiv_group = text_entry
        .overlap_groups()
        .iter()
        .find(|group| group.classification() == ThreeWayTextOverlapClassification::Equivalent)
        .expect("equivalent overlap group");
    assert_eq!(equiv_group.installed_hunk_ids().len(), 1);
    assert_eq!(equiv_group.incoming_hunk_ids().len(), 1);

    let synthesis = plan_merge_synthesis(&fixture, default_synthesis_options()).expect("synthesis");
    let entry = synthesis_entry(&synthesis, "equivalent.lua");
    assert_eq!(
        entry
            .operations()
            .iter()
            .filter(|op| op.kind() == MergeSynthesisOperationKind::UseEquivalentReplacement)
            .count(),
        1
    );
}
