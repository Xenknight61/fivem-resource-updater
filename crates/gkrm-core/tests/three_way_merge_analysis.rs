use std::fs;
use std::io::Write;
use std::path::Path;

use gkrm_core::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, resolve_official_baseline,
    review_three_way_update_plan, BaselineCaptureOptions, BaselineCaptureRequest,
    BaselineResolutionOptions, BaselineResolutionRequest, IncomingMergeContentSource,
    IncomingMergeContentSourceLimits, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
    InspectionOptions, InstallationRelativePath, InstalledMergeContentSource,
    InstalledResourceRoot, InstalledResourceSnapshot, InstalledScanLimits,
    OfficialBaselineSelector, PolicyTransitionAcknowledgement, SafeResourceKey,
    ThreeWayMergeAnalysisDisposition, ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisRequest,
    ThreeWayMergeAnalysisStatus, ThreeWayPlanDecision, ThreeWayPlanDecisionChoice,
    ThreeWayPlanDecisionSet, ThreeWayPlanDisposition, ThreeWayPlanReview,
    ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayReviewedAction, ThreeWayUpdatePlan,
    ThreeWayUpdatePlanRequest, ZipRelativePath, ZipResourceRoot,
};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore { 'shared.lua', 'binary.lua' }\n";

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

fn plan_path(plan: &ThreeWayUpdatePlan, path: &str) -> gkrm_core::ResourceRelativePath {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing plan entry {path}"))
        .path()
        .clone()
}

fn disposition_for(plan: &ThreeWayUpdatePlan, path: &str) -> ThreeWayPlanDisposition {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing plan entry {path}"))
        .disposition()
}

struct AnalysisFixture {
    temp_dir: tempfile::TempDir,
    installed_parent: std::path::PathBuf,
    installed_resource: std::path::PathBuf,
    package_v2: std::path::PathBuf,
    baseline: gkrm_core::ResolvedOfficialBaseline,
    plan: ThreeWayUpdatePlan,
    review: ThreeWayPlanReview,
}

fn build_analysis_fixture() -> AnalysisFixture {
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
            ("gksphone/shared.lua", b"base\n"),
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

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("shared.lua"), b"local\n");
    write_file(&installed_resource.join("binary.lua"), b"local\0");

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/shared.lua", b"official\n"),
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
    let decision_set = ThreeWayPlanDecisionSet::try_new(
        *plan.plan_id(),
        vec![
            ThreeWayPlanDecision::try_new(
                plan_path(&plan, "binary.lua"),
                ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("binary decision"),
            ThreeWayPlanDecision::try_new(
                plan_path(&plan, "shared.lua"),
                ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("text decision"),
        ],
    )
    .expect("decision set");
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &decision_set).expect("review request"),
    )
    .expect("review");

    AnalysisFixture {
        temp_dir: temp,
        installed_parent,
        installed_resource,
        package_v2,
        baseline,
        plan,
        review,
    }
}

#[test]
fn production_merge_analysis_uses_real_plan_review_and_sources() {
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
            ("gksphone/shared.lua", b"base\n"),
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

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("shared.lua"), b"local\n");
    write_file(&installed_resource.join("binary.lua"), b"local\0");

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/shared.lua", b"official\n"),
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
        disposition_for(&plan, "shared.lua"),
        ThreeWayPlanDisposition::MergeCandidate
    );
    assert_eq!(
        disposition_for(&plan, "binary.lua"),
        ThreeWayPlanDisposition::MergeCandidate
    );

    let decision_set = ThreeWayPlanDecisionSet::try_new(
        *plan.plan_id(),
        vec![
            ThreeWayPlanDecision::try_new(
                plan_path(&plan, "binary.lua"),
                ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("binary decision"),
            ThreeWayPlanDecision::try_new(
                plan_path(&plan, "shared.lua"),
                ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("text decision"),
        ],
    )
    .expect("decision set");
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &decision_set).expect("review request"),
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
    let before = fs::read(installed_resource.join("shared.lua")).expect("before");
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
    let repeated = analyze_queued_three_way_merges(
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
    .expect("repeat analysis");

    assert_eq!(analysis.plan_id(), plan.plan_id());
    assert_eq!(analysis.review_id(), review.review_id());
    assert_eq!(
        analysis.status(),
        ThreeWayMergeAnalysisStatus::HasManualReviewEntries
    );
    assert_eq!(analysis.summary().total_candidates(), 2);
    assert_eq!(analysis.summary().ready_for_text_merge_planning(), 1);
    assert_eq!(analysis.summary().manual_binary(), 1);
    assert_eq!(analysis.analysis_id(), repeated.analysis_id());
    assert_eq!(
        analysis
            .entries()
            .iter()
            .find(|entry| entry.path().as_str() == "shared.lua")
            .expect("text entry")
            .disposition(),
        ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
    );
    assert_eq!(
        analysis
            .entries()
            .iter()
            .find(|entry| entry.path().as_str() == "binary.lua")
            .expect("binary entry")
            .disposition(),
        ThreeWayMergeAnalysisDisposition::ManualReviewBinary
    );
    assert_eq!(
        fs::read(installed_resource.join("shared.lua")).expect("after"),
        before
    );
}

#[test]
fn retained_selected_resource_capability_ignores_ambient_namespace_replacement() {
    let fixture = build_analysis_fixture();
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
    let retained_location = fixture.installed_parent.join("retained-gksphone");
    if fs::rename(&fixture.installed_resource, &retained_location).is_ok() {
        write_file(&fixture.installed_resource.join("fxmanifest.lua"), MANIFEST);
        write_file(
            &fixture.installed_resource.join("shared.lua"),
            b"replacement\n",
        );
        write_file(
            &fixture.installed_resource.join("binary.lua"),
            b"replacement\0",
        );
    } else {
        write_file(
            &fixture.installed_resource.join("shared.lua"),
            b"mutated-before-analysis\n",
        );
    }

    let result = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &fixture.plan,
            &fixture.review,
            &fixture.baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis request"),
    );

    if retained_location.exists() {
        let analysis = result.expect("retained capability should avoid replacement mixing");
        assert_eq!(analysis.summary().total_candidates(), 2);
        let shared = analysis
            .entries()
            .iter()
            .find(|entry| entry.path().as_str() == "shared.lua")
            .expect("shared analysis");
        assert_eq!(shared.installed().byte_length(), b"local\n".len() as u64);
        assert_ne!(
            shared.installed().byte_length(),
            b"replacement\n".len() as u64
        );
    } else {
        assert!(result.is_err(), "mutation must fail closed");
    }
}

#[test]
fn retained_installed_root_capability_ignores_ambient_namespace_replacement() {
    let fixture = build_analysis_fixture();
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
    let retained_root = fixture.temp_dir.path().join("retained-installed");
    if fs::rename(&fixture.installed_parent, &retained_root).is_ok() {
        write_file(&fixture.installed_resource.join("fxmanifest.lua"), MANIFEST);
        write_file(
            &fixture.installed_resource.join("shared.lua"),
            b"replacement\n",
        );
        write_file(
            &fixture.installed_resource.join("binary.lua"),
            b"replacement\0",
        );
    } else {
        write_file(
            &fixture.installed_resource.join("binary.lua"),
            b"mutated-before-analysis\0",
        );
    }

    let result = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &fixture.plan,
            &fixture.review,
            &fixture.baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .expect("analysis request"),
    );

    if retained_root.exists() {
        let analysis = result.expect("retained capability should avoid replacement mixing");
        assert_eq!(analysis.summary().total_candidates(), 2);
        let binary = analysis
            .entries()
            .iter()
            .find(|entry| entry.path().as_str() == "binary.lua")
            .expect("binary analysis");
        assert_eq!(binary.installed().byte_length(), b"local\0".len() as u64);
        assert_ne!(
            binary.installed().byte_length(),
            b"replacement\0".len() as u64
        );
    } else {
        assert!(result.is_err(), "mutation must fail closed");
    }
}

/// UTF-8 BOM + multi-byte UTF-8 + CRLF + blank line + terminal newline, no NUL.
const RICH_MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore { 'rich.lua' }\n";
const RICH_BASE: &[u8] = b"\xEF\xBB\xBFcaf\xc3\xa9\r\n\r\nline\r\n";
const RICH_INSTALLED: &[u8] = b"\xEF\xBB\xBFcaf\xc3\xa9\r\n\r\nlocal\r\n";
const RICH_INCOMING: &[u8] = b"\xEF\xBB\xBFcaf\xc3\xa9\r\n\r\nofficial\r\n";

/// Independent SHA-256 hex locks for the rich Task 16 sources (not derived from SUT).
const RICH_BASE_SHA256: &str = "d0fef1fb2340333ca0f335788560972514d809a44d78ede71a2178e3d8ed9894";
const RICH_INSTALLED_SHA256: &str =
    "70798b4675ed4eead80bdd5caa6d575bcee088b72e297ecafbfbecff58e30858";
const RICH_INCOMING_SHA256: &str =
    "8bbbaef333d8bcf4b6faf1e435eaa672f43a682ac12e98de500d060a908b2852";

/// Approved Task 16 analysis-ID for the rich shared-reader fixture with default options.
const FIXED_TASK16_RICH_ANALYSIS_ID: &str =
    "175bceecc14d7414278402c96d8661c5ec85cef08bb9cf5e1c48b0074988e3f5";

#[test]
fn fixed_task16_shared_reader_regression_vectors() {
    use gkrm_core::{
        MergeContentEncoding, MergeContentKind, MergeNewlineStyle, ThreeWayMergeAnalysisStatus,
    };

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
            ("gksphone/fxmanifest.lua", RICH_MANIFEST),
            ("gksphone/rich.lua", RICH_BASE),
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

    write_file(&installed_resource.join("fxmanifest.lua"), RICH_MANIFEST);
    write_file(&installed_resource.join("rich.lua"), RICH_INSTALLED);
    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", RICH_MANIFEST),
            ("gksphone/rich.lua", RICH_INCOMING),
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
        disposition_for(&plan, "rich.lua"),
        ThreeWayPlanDisposition::MergeCandidate
    );

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
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(
            &plan,
            &ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).expect("decision set"),
        )
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

    assert_eq!(
        analysis.analysis_id().digest().to_string(),
        FIXED_TASK16_RICH_ANALYSIS_ID
    );
    assert_eq!(
        analysis.status(),
        ThreeWayMergeAnalysisStatus::ReadyForFurtherPlanning
    );
    assert_eq!(analysis.summary().total_candidates(), 1);
    assert_eq!(analysis.summary().ready_for_text_merge_planning(), 1);

    let entry = analysis
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == "rich.lua")
        .expect("rich entry");
    assert_eq!(
        entry.disposition(),
        ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
    );

    let assert_rich =
        |label: &str, content: &gkrm_core::MergeContentAnalysis, sha: &str, byte_length: u64| {
            assert_eq!(content.sha256().to_string(), sha, "{label} sha256");
            assert_eq!(content.byte_length(), byte_length, "{label} length");
            assert_eq!(
                content.content_kind(),
                MergeContentKind::Text,
                "{label} kind"
            );
            assert_eq!(
                content.encoding(),
                MergeContentEncoding::Utf8WithBom,
                "{label} encoding"
            );
            assert_eq!(
                content.newline_style(),
                MergeNewlineStyle::CrLf,
                "{label} newline"
            );
            assert_eq!(content.line_count(), Some(3), "{label} line_count");
            assert_eq!(content.max_line_bytes(), Some(8), "{label} max_line");
            assert!(!content.is_empty(), "{label} empty");
        };

    assert_rich("baseline", entry.baseline(), RICH_BASE_SHA256, 18);
    assert_rich("installed", entry.installed(), RICH_INSTALLED_SHA256, 19);
    assert_rich("incoming", entry.incoming(), RICH_INCOMING_SHA256, 22);

    let repeated = analyze_queued_three_way_merges(
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
    .expect("repeat analysis");
    assert_eq!(analysis.analysis_id(), repeated.analysis_id());
}
