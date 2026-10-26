use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, plan_three_way_text_diffs,
    resolve_official_baseline, review_three_way_update_plan, BaselineCaptureOptions,
    BaselineCaptureRequest, BaselineResolutionOptions, BaselineResolutionRequest,
    BaselineStoreLimits, GkrmError, IncomingMergeContentSource, IncomingMergeContentSourceLimits,
    IncomingOfficialResourceSnapshot, IncomingResourceSelector, InspectionOptions,
    InstallationRelativePath, InstalledMergeContentSource, InstalledResourceRoot,
    InstalledResourceSnapshot, InstalledScanLimits, OfficialBaselineSelector,
    PolicyTransitionAcknowledgement, ResolvedOfficialBaseline, SafeResourceKey,
    TextTerminalNewline, ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisPlan,
    ThreeWayMergeAnalysisRequest, ThreeWayMergeAnalysisStatus, ThreeWayPlanDecision,
    ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet, ThreeWayPlanDisposition,
    ThreeWayPlanReview, ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayReviewedAction,
    ThreeWayTextDiffDisposition, ThreeWayTextDiffOptions, ThreeWayTextDiffRequest,
    ThreeWayTextDiffStatus, ThreeWayTextEnvelopePlanState, ThreeWayTextOverlapClassification,
    ThreeWayTextScalarResolution, ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest, ZipRelativePath,
    ZipResourceRoot,
};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'disjoint.lua',\n  'divergent_insert.lua',\n  'overlap_replace.lua',\n  'envelope.lua',\n  'equivalent.lua',\n}\n";

const BINARY_ONLY_MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore { 'binary.lua' }\n";

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

// Identical shared replacement plus disjoint extras so L and N stay pairwise distinct.
const EQUIVALENT_BASE: &[u8] = b"line 1\nshared old\nline 3\n";
const EQUIVALENT_INSTALLED: &[u8] = b"installed extra\nline 1\nshared new\nline 3\n";
const EQUIVALENT_INCOMING: &[u8] = b"line 1\nshared new\nline 3\nincoming extra\n";

/// Approved Task 17 plan-ID for the production fixture with default text-diff options.
/// Literal lock for canonical encoding (Unknown terminal / envelope-plan-state tags).
const FIXED_TASK17_PRODUCTION_PLAN_ID: &str =
    "2ba6725e573b253d378674d3037d5f3579666c15102736010ce5512b0bb9587a";

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

fn text_disposition(
    plan: &gkrm_core::ThreeWayTextDiffPlan,
    path: &str,
) -> ThreeWayTextDiffDisposition {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing text-diff entry {path}"))
        .disposition()
}

fn text_entry<'a>(
    plan: &'a gkrm_core::ThreeWayTextDiffPlan,
    path: &str,
) -> &'a gkrm_core::ThreeWayTextDiffEntry {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing text-diff entry {path}"))
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

fn options_with(max_candidates: usize, max_source_bytes_per_file: u64) -> ThreeWayTextDiffOptions {
    ThreeWayTextDiffOptions::try_new(
        max_candidates,
        max_source_bytes_per_file,
        128 * 1024 * 1024,
        600_000,
        200_000,
        10_000,
        2_000_000,
        10_000,
        10_000,
        BaselineStoreLimits::default(),
    )
    .expect("options")
}

struct TextDiffFixture {
    temp_dir: tempfile::TempDir,
    installed_parent: PathBuf,
    installed_resource: PathBuf,
    package_v2: PathBuf,
    baseline: ResolvedOfficialBaseline,
    plan: ThreeWayUpdatePlan,
    review: ThreeWayPlanReview,
    analysis: ThreeWayMergeAnalysisPlan,
}

fn build_production_fixture() -> TextDiffFixture {
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

    TextDiffFixture {
        temp_dir: temp,
        installed_parent,
        installed_resource,
        package_v2,
        baseline,
        plan,
        review,
        analysis,
    }
}

fn build_binary_only_fixture() -> TextDiffFixture {
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
            ("gksphone/fxmanifest.lua", BINARY_ONLY_MANIFEST),
            ("gksphone/binary.lua", b"base"),
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
        BINARY_ONLY_MANIFEST,
    );
    write_file(&installed_resource.join("binary.lua"), b"local\0");

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", BINARY_ONLY_MANIFEST),
            ("gksphone/binary.lua", b"official\0"),
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
    assert_eq!(
        plan_disposition(&plan, "binary.lua"),
        ThreeWayPlanDisposition::MergeCandidate
    );

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
    assert_eq!(analysis.summary().ready_for_text_merge_planning(), 0);
    assert_eq!(analysis.summary().manual_binary(), 1);

    TextDiffFixture {
        temp_dir: temp,
        installed_parent,
        installed_resource,
        package_v2,
        baseline,
        plan,
        review,
        analysis,
    }
}

fn plan_text_diffs(
    fixture: &TextDiffFixture,
    options: ThreeWayTextDiffOptions,
) -> Result<gkrm_core::ThreeWayTextDiffPlan, GkrmError> {
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
    plan_three_way_text_diffs(
        ThreeWayTextDiffRequest::try_new(
            &fixture.plan,
            &fixture.review,
            &fixture.analysis,
            &fixture.baseline,
            &installed_source,
            &incoming_source,
            options,
        )
        .expect("text-diff request"),
    )
}

#[test]
fn production_text_diff_uses_real_plan_review_analysis_and_sources() {
    let fixture = build_production_fixture();

    let installed_before = [
        ("disjoint.lua", DISJOINT_INSTALLED),
        ("divergent_insert.lua", DIVERGENT_INSTALLED),
        ("overlap_replace.lua", OVERLAP_INSTALLED),
        ("envelope.lua", ENVELOPE_INSTALLED),
        ("equivalent.lua", EQUIVALENT_INSTALLED),
    ]
    .into_iter()
    .map(|(name, expected)| {
        let path = fixture.installed_resource.join(name);
        let bytes = fs::read(&path).expect("installed before");
        assert_eq!(bytes, expected);
        (path, bytes)
    })
    .collect::<Vec<_>>();
    let package_before = fs::read(&fixture.package_v2).expect("package before");

    let text_plan = plan_text_diffs(&fixture, default_text_diff_options()).expect("text-diff plan");
    let repeated = plan_text_diffs(&fixture, default_text_diff_options()).expect("repeat plan");

    assert_eq!(text_plan.plan_id(), fixture.plan.plan_id());
    assert_eq!(text_plan.review_id(), fixture.review.review_id());
    assert_eq!(text_plan.analysis_id(), fixture.analysis.analysis_id());
    assert_eq!(text_plan.status(), ThreeWayTextDiffStatus::HasConflicts);
    assert_eq!(text_plan.summary().total_candidates(), 5);
    assert_eq!(text_plan.summary().ready_for_merge_synthesis(), 3);
    assert_eq!(text_plan.summary().conflict_text(), 2);
    assert_eq!(
        text_plan.text_diff_plan_id().digest().to_string(),
        FIXED_TASK17_PRODUCTION_PLAN_ID
    );
    assert_eq!(
        text_plan.text_diff_plan_id().digest(),
        repeated.text_diff_plan_id().digest()
    );

    let option_changed = plan_text_diffs(
        &fixture,
        ThreeWayTextDiffOptions::try_new(
            1_000,
            4 * 1024 * 1024,
            128 * 1024 * 1024,
            600_000,
            200_000,
            10_000,
            2_000_000,
            9_999,
            10_000,
            BaselineStoreLimits::default(),
        )
        .expect("option variant"),
    )
    .expect("option-changed plan");
    assert_ne!(
        option_changed.text_diff_plan_id().digest().to_string(),
        FIXED_TASK17_PRODUCTION_PLAN_ID
    );

    assert_eq!(
        text_disposition(&text_plan, "disjoint.lua"),
        ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
    );
    assert_eq!(
        text_disposition(&text_plan, "divergent_insert.lua"),
        ThreeWayTextDiffDisposition::ConflictReviewTextEdits
    );
    assert_eq!(
        text_disposition(&text_plan, "overlap_replace.lua"),
        ThreeWayTextDiffDisposition::ConflictReviewTextEdits
    );
    assert_eq!(
        text_disposition(&text_plan, "envelope.lua"),
        ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
    );
    assert_eq!(
        text_disposition(&text_plan, "equivalent.lua"),
        ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
    );

    let envelope = text_entry(&text_plan, "envelope.lua");
    let envelope_plan = match envelope.envelope_plan() {
        ThreeWayTextEnvelopePlanState::Planned(plan) => plan,
        ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge => {
            panic!("envelope.lua should have a planned envelope")
        }
    };
    assert_eq!(
        envelope_plan.bom(),
        ThreeWayTextScalarResolution::UseIncoming
    );
    assert_eq!(
        envelope_plan.newline_style(),
        ThreeWayTextScalarResolution::UseInstalled
    );
    assert_eq!(
        envelope_plan.terminal_newline(),
        ThreeWayTextScalarResolution::KeepBase
    );
    assert!(envelope.installed_hunks().is_empty());
    assert!(envelope.incoming_hunks().is_empty());
    assert!(envelope.overlap_groups().is_empty());

    let disjoint = text_entry(&text_plan, "disjoint.lua");
    assert!(disjoint.overlap_groups().is_empty());
    assert!(!disjoint.installed_hunks().is_empty());
    assert!(!disjoint.incoming_hunks().is_empty());

    let equivalent = text_entry(&text_plan, "equivalent.lua");
    assert_eq!(
        equivalent.baseline_text_digest(),
        text_entry(&repeated, "equivalent.lua").baseline_text_digest()
    );
    assert_ne!(
        equivalent.baseline_text_digest(),
        equivalent.installed_text_digest()
    );
    assert_ne!(
        equivalent.baseline_text_digest(),
        equivalent.incoming_text_digest()
    );
    assert_ne!(
        equivalent.installed_text_digest(),
        equivalent.incoming_text_digest()
    );
    let equiv_group = equivalent
        .overlap_groups()
        .iter()
        .find(|group| group.classification() == ThreeWayTextOverlapClassification::Equivalent)
        .expect("equivalent overlap group");
    assert_eq!(equiv_group.installed_hunk_ids().len(), 1);
    assert_eq!(equiv_group.incoming_hunk_ids().len(), 1);
    assert_eq!(equiv_group.base_range().start(), 1);
    assert_eq!(equiv_group.base_range().end(), 2);
    assert!(!equivalent.overlap_groups().iter().any(|group| {
        matches!(
            group.classification(),
            ThreeWayTextOverlapClassification::DivergentInsertion
                | ThreeWayTextOverlapClassification::OverlappingEditConflict
        )
    }));
    let repeated_equiv = text_entry(&repeated, "equivalent.lua")
        .overlap_groups()
        .iter()
        .find(|group| group.classification() == ThreeWayTextOverlapClassification::Equivalent)
        .expect("repeated equivalent group");
    assert_eq!(equiv_group.id(), repeated_equiv.id());

    let divergent = text_entry(&text_plan, "divergent_insert.lua");
    assert!(divergent.overlap_groups().iter().any(|group| {
        group.classification() == ThreeWayTextOverlapClassification::DivergentInsertion
    }));

    let overlap = text_entry(&text_plan, "overlap_replace.lua");
    assert!(overlap.overlap_groups().iter().any(|group| {
        group.classification() == ThreeWayTextOverlapClassification::OverlappingEditConflict
    }));

    for (path, before) in installed_before {
        assert_eq!(fs::read(path).expect("installed after"), before);
    }
    assert_eq!(
        fs::read(&fixture.package_v2).expect("package after"),
        package_before
    );
}

#[test]
fn wrong_analysis_plan_id_fails_before_source_reads() {
    // Identical content yields identical digests; cross-wire against a divergent fixture.
    let left = build_production_fixture();
    let right = build_binary_only_fixture();
    assert_ne!(left.plan.plan_id(), right.plan.plan_id());
    assert_ne!(left.analysis.plan_id(), right.analysis.plan_id());

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
    let error = plan_three_way_text_diffs(
        ThreeWayTextDiffRequest::try_new(
            &left.plan,
            &left.review,
            &right.analysis,
            &left.baseline,
            &installed_source,
            &incoming_source,
            default_text_diff_options(),
        )
        .expect("request"),
    )
    .expect_err("cross-wired analysis must fail");

    assert!(matches!(
        error,
        GkrmError::ThreeWayTextDiffPlanAnalysisBindingMismatch
            | GkrmError::ThreeWayTextDiffReviewAnalysisBindingMismatch
    ));
    assert_eq!(
        fs::read(left.installed_resource.join("disjoint.lua")).expect("after"),
        before
    );
}

#[test]
fn wrong_review_binding_fails_before_source_reads() {
    let left = build_production_fixture();
    let right = build_binary_only_fixture();
    assert_ne!(left.review.review_id(), right.review.review_id());

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

    let error = plan_three_way_text_diffs(
        ThreeWayTextDiffRequest::try_new(
            &left.plan,
            &right.review,
            &left.analysis,
            &left.baseline,
            &installed_source,
            &incoming_source,
            default_text_diff_options(),
        )
        .expect("request"),
    )
    .expect_err("cross-wired review must fail");

    assert!(matches!(
        error,
        GkrmError::ThreeWayTextDiffPlanReviewBindingMismatch
    ));
}

#[test]
fn no_ready_candidates_returns_structured_error() {
    let fixture = build_binary_only_fixture();
    let error = plan_text_diffs(&fixture, default_text_diff_options())
        .expect_err("binary-only queue must have no ready candidates");
    assert!(matches!(
        error,
        GkrmError::ThreeWayTextDiffNoReadyCandidates
    ));
}

#[test]
fn mutated_installed_candidate_after_analysis_fails_revalidation() {
    let fixture = build_production_fixture();
    write_file(
        &fixture.installed_resource.join("disjoint.lua"),
        b"mutated-after-analysis\n",
    );

    let error = plan_text_diffs(&fixture, default_text_diff_options())
        .expect_err("installed mutation must fail closed");
    assert!(matches!(
        error,
        GkrmError::ThreeWayTextDiffInstalledPreFingerprintMismatch
            | GkrmError::ThreeWayTextDiffInstalledCandidateInvalid
            | GkrmError::ThreeWayTextDiffInstalledResourceChanged
            | GkrmError::ThreeWayTextDiffSourceIdentityChanged
            | GkrmError::ThreeWayTextDiffTask16MetadataMismatch
    ));
}

#[test]
fn zero_text_diff_options_are_rejected() {
    let error =
        ThreeWayTextDiffOptions::try_new(0, 1, 1, 1, 1, 1, 1, 1, 1, BaselineStoreLimits::default())
            .expect_err("zero max_candidates");
    assert!(matches!(
        error,
        GkrmError::ThreeWayTextDiffOptionsInvalid {
            limit: "max_candidates"
        }
    ));
}

#[test]
fn candidate_limit_exceeded_before_reads() {
    let fixture = build_production_fixture();
    let error = plan_text_diffs(&fixture, options_with(1, 4 * 1024 * 1024))
        .expect_err("five ready candidates exceed limit 1");
    assert!(matches!(
        error,
        GkrmError::ThreeWayTextDiffCandidateLimitExceeded {
            limit: 1,
            actual: 5
        }
    ));
}

#[test]
fn small_max_source_bytes_yields_manual_review_disposition() {
    let fixture = build_production_fixture();
    let text_plan = plan_text_diffs(&fixture, options_with(1_000, 1)).expect("plan succeeds");

    assert_eq!(
        text_plan.status(),
        ThreeWayTextDiffStatus::HasManualReviewEntries
    );
    assert_eq!(text_plan.summary().manual_source_too_large(), 5);
    assert_eq!(text_plan.summary().total_installed_hunks(), 0);
    assert_eq!(text_plan.summary().total_incoming_hunks(), 0);
    assert_eq!(text_plan.summary().total_overlap_groups(), 0);
    for path in [
        "disjoint.lua",
        "divergent_insert.lua",
        "overlap_replace.lua",
        "envelope.lua",
        "equivalent.lua",
    ] {
        let entry = text_entry(&text_plan, path);
        assert_eq!(
            entry.disposition(),
            ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge
        );
        assert!(entry.installed_hunks().is_empty());
        assert!(entry.incoming_hunks().is_empty());
        assert!(entry.overlap_groups().is_empty());
        assert_eq!(
            entry.envelope_plan(),
            &ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge
        );
        assert_eq!(
            entry.baseline_envelope().terminal_newline(),
            gkrm_core::TextTerminalNewline::Unknown
        );
        assert_eq!(
            entry.installed_envelope().terminal_newline(),
            gkrm_core::TextTerminalNewline::Unknown
        );
        assert_eq!(
            entry.incoming_envelope().terminal_newline(),
            gkrm_core::TextTerminalNewline::Unknown
        );
    }
}

#[test]
fn binding_error_display_omits_absolute_temp_paths() {
    let left = build_production_fixture();
    let right = build_binary_only_fixture();
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

    let error = plan_three_way_text_diffs(
        ThreeWayTextDiffRequest::try_new(
            &left.plan,
            &right.review,
            &left.analysis,
            &left.baseline,
            &installed_source,
            &incoming_source,
            default_text_diff_options(),
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
fn shared_reader_analysis_id_and_metadata_are_stable() {
    let fixture = build_production_fixture();
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

    let repeated = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &fixture.plan,
            &fixture.review,
            &fixture.baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis request"),
    )
    .expect("repeat analysis");

    assert_eq!(fixture.analysis.analysis_id(), repeated.analysis_id());
    assert_eq!(fixture.analysis.entries().len(), repeated.entries().len());
    for (left, right) in fixture.analysis.entries().iter().zip(repeated.entries()) {
        assert_eq!(left.path(), right.path());
        assert_eq!(left.disposition(), right.disposition());
        assert_eq!(left.baseline(), right.baseline());
        assert_eq!(left.installed(), right.installed());
        assert_eq!(left.incoming(), right.incoming());
    }

    let text_plan =
        plan_text_diffs(&fixture, default_text_diff_options()).expect("text-diff after repeat");
    assert_eq!(text_plan.analysis_id(), fixture.analysis.analysis_id());
}

const MIXED_MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore { 'mixed.lua' }\n";

/// Larger than MIXED_MAX_RETAIN so the source is streamed but not retained.
const MIXED_OVERSIZED: &[u8] = b"oversized-source-payload-0123456789\n";
const MIXED_RETAINED_ABSENT: &[u8] = b"keep-me";
const MIXED_RETAINED_LF: &[u8] = b"keep-me\n";
const MIXED_RETAINED_CRLF: &[u8] = b"keep-me\r\n";
const MIXED_RETAINED_BOM_LF: &[u8] = b"\xEF\xBB\xBFkeep\n";
const MIXED_RETAINED_OTHER_LF: &[u8] = b"other-n\n";
const MIXED_RETAINED_OTHER_ABSENT: &[u8] = b"other-n";
const MIXED_MAX_RETAIN: u64 = 16;

fn build_mixed_size_fixture(baseline: &[u8], installed: &[u8], incoming: &[u8]) -> TextDiffFixture {
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
            ("gksphone/fxmanifest.lua", MIXED_MANIFEST),
            ("gksphone/mixed.lua", baseline),
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
    let baseline_resolved = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &key("gksphone"),
            OfficialBaselineSelector::Exact(capture.baseline_id().clone()),
            BaselineResolutionOptions::default(),
        )
        .expect("resolution request"),
    )
    .expect("resolve");

    write_file(&installed_resource.join("fxmanifest.lua"), MIXED_MANIFEST);
    write_file(&installed_resource.join("mixed.lua"), installed);
    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MIXED_MANIFEST),
            ("gksphone/mixed.lua", incoming),
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
            &baseline_resolved,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("plan");
    assert_eq!(
        plan_disposition(&plan, "mixed.lua"),
        ThreeWayPlanDisposition::MergeCandidate
    );

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
            &baseline_resolved,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis request"),
    )
    .expect("analysis");
    assert_eq!(analysis.summary().ready_for_text_merge_planning(), 1);

    TextDiffFixture {
        temp_dir: temp,
        installed_parent,
        installed_resource,
        package_v2,
        baseline: baseline_resolved,
        plan,
        review,
        analysis,
    }
}

fn assert_oversized_manual_entry(
    entry: &gkrm_core::ThreeWayTextDiffEntry,
    baseline_terminal: TextTerminalNewline,
    installed_terminal: TextTerminalNewline,
    incoming_terminal: TextTerminalNewline,
) {
    assert_eq!(
        entry.disposition(),
        ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge
    );
    assert_eq!(
        entry.envelope_plan(),
        &ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge
    );
    assert!(entry.installed_hunks().is_empty());
    assert!(entry.incoming_hunks().is_empty());
    assert!(entry.overlap_groups().is_empty());
    assert_eq!(
        entry.baseline_envelope().terminal_newline(),
        baseline_terminal
    );
    assert_eq!(
        entry.installed_envelope().terminal_newline(),
        installed_terminal
    );
    assert_eq!(
        entry.incoming_envelope().terminal_newline(),
        incoming_terminal
    );
}

#[test]
fn mixed_size_baseline_oversized_preserves_retained_terminals() {
    let fixture =
        build_mixed_size_fixture(MIXED_OVERSIZED, MIXED_RETAINED_LF, MIXED_RETAINED_OTHER_LF);
    let plan = plan_text_diffs(&fixture, options_with(10, MIXED_MAX_RETAIN)).expect("plan");
    let entry = text_entry(&plan, "mixed.lua");
    assert_oversized_manual_entry(
        entry,
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Present,
        TextTerminalNewline::Present,
    );
    assert_eq!(plan.summary().manual_source_too_large(), 1);
    assert_eq!(plan.summary().total_installed_hunks(), 0);
}

#[test]
fn mixed_size_installed_oversized_only_marks_installed_unknown() {
    let fixture = build_mixed_size_fixture(
        MIXED_RETAINED_ABSENT,
        MIXED_OVERSIZED,
        MIXED_RETAINED_OTHER_ABSENT,
    );
    let plan = plan_text_diffs(&fixture, options_with(10, MIXED_MAX_RETAIN)).expect("plan");
    assert_oversized_manual_entry(
        text_entry(&plan, "mixed.lua"),
        TextTerminalNewline::Absent,
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Absent,
    );
}

#[test]
fn mixed_size_incoming_oversized_only_marks_incoming_unknown() {
    let fixture = build_mixed_size_fixture(MIXED_RETAINED_CRLF, MIXED_RETAINED_LF, MIXED_OVERSIZED);
    let plan = plan_text_diffs(&fixture, options_with(10, MIXED_MAX_RETAIN)).expect("plan");
    assert_oversized_manual_entry(
        text_entry(&plan, "mixed.lua"),
        TextTerminalNewline::Present,
        TextTerminalNewline::Present,
        TextTerminalNewline::Unknown,
    );
}

#[test]
fn mixed_size_multiple_oversized_sources_preserve_retained_sibling() {
    let fixture = build_mixed_size_fixture(
        MIXED_OVERSIZED,
        MIXED_RETAINED_BOM_LF,
        b"oversized-incoming-payload-0123456789\n",
    );
    let plan = plan_text_diffs(&fixture, options_with(10, MIXED_MAX_RETAIN)).expect("plan");
    assert_oversized_manual_entry(
        text_entry(&plan, "mixed.lua"),
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Present,
        TextTerminalNewline::Unknown,
    );
    assert!(text_entry(&plan, "mixed.lua").installed_envelope().bom());
}

#[test]
fn mixed_size_retained_empty_and_variants() {
    let empty = build_mixed_size_fixture(MIXED_OVERSIZED, b"", MIXED_RETAINED_OTHER_ABSENT);
    let plan = plan_text_diffs(&empty, options_with(10, MIXED_MAX_RETAIN)).expect("empty");
    assert_oversized_manual_entry(
        text_entry(&plan, "mixed.lua"),
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Absent,
        TextTerminalNewline::Absent,
    );

    let crlf = build_mixed_size_fixture(
        MIXED_OVERSIZED,
        MIXED_RETAINED_CRLF,
        MIXED_RETAINED_OTHER_LF,
    );
    let plan = plan_text_diffs(&crlf, options_with(10, MIXED_MAX_RETAIN)).expect("crlf");
    assert_oversized_manual_entry(
        text_entry(&plan, "mixed.lua"),
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Present,
        TextTerminalNewline::Present,
    );
}

#[test]
fn mixed_size_retained_terminal_change_changes_plan_id() {
    let absent = build_mixed_size_fixture(
        MIXED_OVERSIZED,
        MIXED_RETAINED_ABSENT,
        MIXED_RETAINED_OTHER_ABSENT,
    );
    let present =
        build_mixed_size_fixture(MIXED_OVERSIZED, MIXED_RETAINED_LF, MIXED_RETAINED_OTHER_LF);
    let absent_plan =
        plan_text_diffs(&absent, options_with(10, MIXED_MAX_RETAIN)).expect("absent plan");
    let present_plan =
        plan_text_diffs(&present, options_with(10, MIXED_MAX_RETAIN)).expect("present plan");

    let absent_entry = text_entry(&absent_plan, "mixed.lua");
    let present_entry = text_entry(&present_plan, "mixed.lua");
    assert_oversized_manual_entry(
        absent_entry,
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Absent,
        TextTerminalNewline::Absent,
    );
    assert_oversized_manual_entry(
        present_entry,
        TextTerminalNewline::Unknown,
        TextTerminalNewline::Present,
        TextTerminalNewline::Present,
    );
    assert_ne!(
        absent_plan.text_diff_plan_id().digest(),
        present_plan.text_diff_plan_id().digest()
    );
}

#[test]
fn production_candidate_order_sort_yields_stable_plan_id() {
    let fixture = build_production_fixture();
    let first = plan_text_diffs(&fixture, default_text_diff_options()).expect("first");
    let second = plan_text_diffs(&fixture, default_text_diff_options()).expect("second");
    assert_eq!(
        first.text_diff_plan_id().digest().to_string(),
        FIXED_TASK17_PRODUCTION_PLAN_ID
    );
    assert_eq!(
        first.text_diff_plan_id().digest(),
        second.text_diff_plan_id().digest()
    );
    let paths: Vec<_> = first.entries().iter().map(|e| e.path().as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort_unstable();
    assert_eq!(paths, sorted, "entries must be path-sorted");
}
