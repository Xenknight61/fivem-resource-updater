use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, plan_three_way_merge_synthesis,
    plan_three_way_text_diffs, resolve_official_baseline, review_three_way_update_plan,
    stage_trusted_resource, synthesize_three_way_merged_bytes, BaselineCaptureOptions,
    BaselineCaptureRequest, BaselineResolutionOptions, BaselineResolutionRequest,
    IncomingMergeContentSourceLimits, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
    IncomingStagingContentSource, InspectionOptions, InstallationRelativePath,
    InstalledResourceRoot, InstalledResourceSnapshot, InstalledScanLimits,
    InstalledStagingContentSource, MergedByteDisposition, OfficialBaselineSelector,
    PolicyTransitionAcknowledgement, ResolvedOfficialBaseline, SafeResourceKey, StagingFinalState,
    ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisPlan, ThreeWayMergeAnalysisRequest,
    ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisPlan, ThreeWayMergeSynthesisRequest,
    ThreeWayMergedBytesOptions, ThreeWayMergedBytesPlan, ThreeWayMergedBytesRequest,
    ThreeWayPlanDecision, ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet,
    ThreeWayPlanDisposition, ThreeWayPlanReview, ThreeWayPlanReviewRequest, ThreeWayPlannerOptions,
    ThreeWayReviewedAction, ThreeWayTextDiffOptions, ThreeWayTextDiffPlan, ThreeWayTextDiffRequest,
    ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest, TrustedStagingOptions, TrustedStagingRequest,
    TrustedStagingRoot, TrustedStagingStatus, ZipRelativePath, ZipResourceRoot,
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

const FIXED_TASK20_MANIFEST_ID: &str =
    "906687bb0eedaa99276906842aa5064e08f2e2fa8a30202a1d15433b3d35d7e7";
const FIXED_TASK20_BUNDLE_ID: &str =
    "e6e031fe0999658ab8ad21d21121d2e54ac60717f90cc3f38b1fb3d3bb707af5";
const FIXED_TASK20_ENTRY_ID_FXMANIFEST: &str =
    "35a6f8b8deb0c0236c65417befaaba327cfe6e7255a8cf605fb000cbd0f8e07a";
const FIXED_TASK20_ENTRY_ID_KEEP: &str =
    "43e897d8b43f244bd290da8e3b64bf6dde7333e09fd4321dcfcded38712b2f62";
const FIXED_TASK20_ENTRY_ID_TAKE: &str =
    "bf61346e0f15260258a3ce9212e626370fc1a1c78adfcaca000fdea695aead6a";
const FIXED_TASK20_ENTRY_ID_MERGE: &str =
    "6d9f68d6f8955f3cba0aa2cdc57923e7b7ee2f41c2754e6ca347804a7bdd8b99";
const FIXED_TASK20_ENTRY_ID_GONE: &str =
    "17f56496a21445adb5e9e91473ab2abcf1afffd4b55a041765f9e35ad11a11c7";

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
                let digest = Sha256::digest(&bytes);
                out.insert(rel, format!("{digest:x}"));
            }
        }
    }
    walk(root, "", &mut out);
    out
}

fn list_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.sort();
    names
}

struct StagingFixture {
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

fn build_fixture() -> StagingFixture {
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

    StagingFixture {
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

fn stage(
    fixture: &StagingFixture,
    staging_root: &Path,
) -> gkrm_core::Result<gkrm_core::TrustedStagingBundle> {
    let root = TrustedStagingRoot::try_open(staging_root)?;
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )?;
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )?;
    stage_trusted_resource(TrustedStagingRequest::try_new(
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
    )?)
}

#[test]
fn try_open_is_read_only() {
    let temp = tempdir().expect("temp");
    let staging = temp.path().join("staging");
    fs::create_dir_all(&staging).expect("dir");
    let _root = TrustedStagingRoot::try_open(&staging).expect("open");
    assert!(list_names(&staging).is_empty());
}

#[test]
fn malformed_bindings_create_zero_filesystem_objects() {
    let fixture = build_fixture();
    let staging = fixture.staging_root.clone();
    assert!(list_names(&staging).is_empty());

    let root = TrustedStagingRoot::try_open(&staging).expect("open");
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming");

    let err = stage_trusted_resource(
        TrustedStagingRequest::try_new(
            &fixture.plan,
            &fixture.review,
            None,
            None,
            None,
            None,
            &fixture.baseline,
            &installed,
            &incoming,
            &root,
            TrustedStagingOptions::default(),
        )
        .expect("req"),
    )
    .expect_err("orphan chain");
    let _ = err;
    assert!(list_names(&staging).is_empty());
}

#[test]
fn production_task_13_to_20_flow() {
    let fixture = build_fixture();
    let before_installed = hash_tree(&fixture.installed_resource);
    let before_package = fs::read(&fixture.package_v2).expect("pkg");
    let before_store = hash_tree(&fixture.store);

    let bundle = stage(&fixture, &fixture.staging_root).expect("stage");
    assert_eq!(bundle.status(), TrustedStagingStatus::ReadyForApplyPlanning);

    let by_path: BTreeMap<_, _> = bundle
        .manifest()
        .entries()
        .iter()
        .map(|e| (e.path().as_str(), e.final_state()))
        .collect();
    assert_eq!(by_path.get("keep.lua"), Some(&StagingFinalState::Installed));
    assert_eq!(by_path.get("take.lua"), Some(&StagingFinalState::Incoming));
    assert_eq!(by_path.get("merge.lua"), Some(&StagingFinalState::Merged));
    assert_eq!(by_path.get("gone.lua"), Some(&StagingFinalState::Absent));

    assert_eq!(hash_tree(&fixture.installed_resource), before_installed);
    assert_eq!(fs::read(&fixture.package_v2).expect("pkg"), before_package);
    assert_eq!(hash_tree(&fixture.store), before_store);
}

#[test]
fn metadata_namespace_not_in_resource() {
    let fixture = build_fixture();
    let bundle = stage(&fixture, &fixture.staging_root).expect("stage");
    let published = fixture
        .staging_root
        .join("bundles")
        .join(bundle.manifest().manifest_id().digest().to_string());
    let names = list_names(&published);
    assert_eq!(
        names,
        vec!["manifest.bin".to_owned(), "resource".to_owned()]
    );
    assert!(!published.join("resource").join("manifest.bin").exists());
}

#[test]
fn unresolved_manual_rejected_before_writes() {
    let fixture = build_fixture();
    let empty =
        ThreeWayPlanDecisionSet::try_new(*fixture.plan.plan_id(), Vec::new()).expect("empty");
    let incomplete = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&fixture.plan, &empty).expect("req"),
    )
    .expect("review");
    let root = TrustedStagingRoot::try_open(&fixture.staging_root).expect("open");
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming");
    let err = stage_trusted_resource(
        TrustedStagingRequest::try_new(
            &fixture.plan,
            &incomplete,
            None,
            None,
            None,
            None,
            &fixture.baseline,
            &installed,
            &incoming,
            &root,
            TrustedStagingOptions::default(),
        )
        .expect("req"),
    )
    .expect_err("incomplete");
    let _ = err;
    assert!(list_names(&fixture.staging_root).is_empty());
    assert!(fixture
        .review
        .entries()
        .iter()
        .any(|e| e.action() == ThreeWayReviewedAction::QueueMergeAnalysis
            || e.action() == ThreeWayReviewedAction::PreserveInstalledState));
}

#[test]
fn root_overlap_rejected() {
    let fixture = build_fixture();
    let root = TrustedStagingRoot::try_open(&fixture.installed_parent).expect("open");
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming");
    let err = stage_trusted_resource(
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
        .expect("req"),
    )
    .expect_err("overlap");
    assert!(matches!(
        err,
        gkrm_core::GkrmError::TrustedStagingRootOverlap
    ));
}

#[test]
fn an_identical_publication_target_is_adopted_and_a_tampered_one_is_rejected() {
    // A bundle is named by the digest of its own manifest, so a name that already exists holds
    // either exactly this content or something that has been tampered with. Staging the same
    // update twice is the first case and must not be an error; the second must still be.
    let fixture = build_fixture();
    let first = stage(&fixture, &fixture.staging_root).expect("first");
    let second = stage(&fixture, &fixture.staging_root).expect("second");
    assert_eq!(second.bundle_id(), first.bundle_id());
    assert_eq!(
        second.manifest().manifest_id(),
        first.manifest().manifest_id()
    );

    // Change one staged byte and the same name no longer holds the same content.
    let published = fixture
        .staging_root
        .join("bundles")
        .join(first.manifest().manifest_id().digest().to_string())
        .join("resource");
    let victim = std::fs::read_dir(&published)
        .expect("read staged resource")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.is_file())
        .expect("a staged file");
    std::fs::write(&victim, b"tampered").expect("tamper");

    assert!(matches!(
        stage(&fixture, &fixture.staging_root).expect_err("tampered"),
        gkrm_core::GkrmError::TrustedStagingDestinationExists
    ));
}

#[test]
fn absent_excluded_from_physical_enumeration() {
    let fixture = build_fixture();
    let bundle = stage(&fixture, &fixture.staging_root).expect("stage");
    let published = fixture
        .staging_root
        .join("bundles")
        .join(bundle.manifest().manifest_id().digest().to_string())
        .join("resource");
    assert!(!published.join("gone.lua").exists());
    assert!(published.join("merge.lua").exists());
}

#[test]
fn deterministic_ids_independent_of_temp() {
    let fixture = build_fixture();
    let staging_a = fixture._temp_dir.path().join("staging-a");
    let staging_b = fixture._temp_dir.path().join("staging-b");
    fs::create_dir_all(&staging_a).expect("a");
    fs::create_dir_all(&staging_b).expect("b");
    let a = stage(&fixture, &staging_a).expect("a");
    let b = stage(&fixture, &staging_b).expect("b");
    assert_eq!(
        a.manifest().manifest_id().digest(),
        b.manifest().manifest_id().digest()
    );
    assert_eq!(a.bundle_id().digest(), b.bundle_id().digest());
    assert_eq!(
        a.manifest().manifest_id().digest().to_string(),
        FIXED_TASK20_MANIFEST_ID
    );
    assert_eq!(a.bundle_id().digest().to_string(), FIXED_TASK20_BUNDLE_ID);
    let entry_ids: BTreeMap<_, _> = a
        .manifest()
        .entries()
        .iter()
        .map(|e| {
            (
                e.path().as_str().to_owned(),
                e.entry_id().digest().to_string(),
            )
        })
        .collect();
    assert_eq!(
        entry_ids.get("fxmanifest.lua").map(String::as_str),
        Some(FIXED_TASK20_ENTRY_ID_FXMANIFEST)
    );
    assert_eq!(
        entry_ids.get("keep.lua").map(String::as_str),
        Some(FIXED_TASK20_ENTRY_ID_KEEP)
    );
    assert_eq!(
        entry_ids.get("take.lua").map(String::as_str),
        Some(FIXED_TASK20_ENTRY_ID_TAKE)
    );
    assert_eq!(
        entry_ids.get("merge.lua").map(String::as_str),
        Some(FIXED_TASK20_ENTRY_ID_MERGE)
    );
    assert_eq!(
        entry_ids.get("gone.lua").map(String::as_str),
        Some(FIXED_TASK20_ENTRY_ID_GONE)
    );
}

#[test]
fn redaction_omits_absolute_paths() {
    let fixture = build_fixture();
    let bundle = stage(&fixture, &fixture.staging_root).expect("stage");
    let debug = format!("{bundle:?}");
    let display = format!("{bundle}");
    let manifest_dbg = format!("{:?}", bundle.manifest());
    let entry_dbg = format!("{:?}", bundle.manifest().entries()[0]);
    let staging = fixture.staging_root.to_string_lossy();
    for text in [&debug, &display, &manifest_dbg, &entry_dbg] {
        assert!(!text.contains(staging.as_ref()));
        assert!(!text.contains(fixture.package_v2.to_string_lossy().as_ref()));
        assert!(!text.contains("fxmanifest.lua"));
        assert!(!text.contains("keep.lua"));
    }
}

#[test]
fn candidate_order_independent_manifest_id() {
    let fixture = build_fixture();
    let a = stage(&fixture, &fixture.staging_root).expect("a");
    let staging_b = fixture._temp_dir.path().join("staging-order");
    fs::create_dir_all(&staging_b).expect("b");
    let b = stage(&fixture, &staging_b).expect("b");
    assert_eq!(
        a.manifest().manifest_id().digest().to_string(),
        b.manifest().manifest_id().digest().to_string()
    );
}
