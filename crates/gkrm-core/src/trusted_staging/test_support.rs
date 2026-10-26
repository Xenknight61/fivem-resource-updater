//! Shared fixture helpers for trusted staging unit tests.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

use crate::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, plan_three_way_merge_synthesis,
    plan_three_way_text_diffs, resolve_official_baseline, review_three_way_update_plan,
    synthesize_three_way_merged_bytes, BaselineCaptureOptions, BaselineCaptureRequest,
    BaselineResolutionOptions, BaselineResolutionRequest, IncomingMergeContentSource,
    IncomingMergeContentSourceLimits, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
    InstallationRelativePath, InstalledMergeContentSource, InstalledResourceRoot,
    InstalledResourceSnapshot, InstalledScanLimits, MergedByteDisposition,
    OfficialBaselineSelector, PolicyTransitionAcknowledgement, SafeResourceKey,
    ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisRequest, ThreeWayMergeSynthesisOptions,
    ThreeWayMergeSynthesisRequest, ThreeWayMergedBytesOptions, ThreeWayMergedBytesRequest,
    ThreeWayPlanDecision, ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet,
    ThreeWayPlanReviewRequest, ThreeWayPlannerOptions, ThreeWayTextDiffOptions,
    ThreeWayTextDiffRequest, ThreeWayUpdatePlanRequest, ZipRelativePath, ZipResourceRoot,
};

use super::{
    stage_trusted_resource, IncomingStagingContentSource, InstalledStagingContentSource,
    TrustedStagingBundle, TrustedStagingOptions, TrustedStagingRequest, TrustedStagingRoot,
};

pub(super) const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'merge.lua',\n  'take.lua',\n  'nested/child.lua',\n}\n";
pub(super) const MERGE_BASE: &[u8] = b"L1\nL2\nL3\nL4\n";
pub(super) const MERGE_INSTALLED: &[u8] = b"L1x\nL2\nL3\nL4\n";
pub(super) const MERGE_INCOMING: &[u8] = b"L1\nL2\nL3\nL4y\n";
pub(super) const TAKE_INSTALLED: &[u8] = b"take-installed\n";
pub(super) const TAKE_INCOMING: &[u8] = b"take-incoming\n";
pub(super) const TAKE_BASE: &[u8] = b"take-base\n";
pub(super) const NESTED_CHILD: &[u8] = b"nested-child\n";

pub(super) fn write_file(path: &Path, contents: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

pub(super) fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).unwrap();
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, contents) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(contents).unwrap();
    }
    writer.finish().unwrap();
}

pub(super) fn key(value: &str) -> SafeResourceKey {
    SafeResourceKey::parse(value).unwrap()
}

pub fn installed_root(path: &str) -> InstalledResourceRoot {
    InstalledResourceRoot::Path(InstallationRelativePath::from_path(Path::new(path)).unwrap())
}

pub(super) fn incoming_root(path: &str) -> ZipResourceRoot {
    ZipResourceRoot::Path(ZipRelativePath::parse_canonical(path).unwrap())
}

pub struct MiniFixture {
    pub _temp: tempfile::TempDir,
    pub store: PathBuf,
    pub installed_parent: PathBuf,
    pub installed_resource: PathBuf,
    pub package_v2: PathBuf,
    pub staging_root: PathBuf,
    pub baseline: crate::ResolvedOfficialBaseline,
    pub plan: crate::ThreeWayUpdatePlan,
    pub review: crate::ThreeWayPlanReview,
    pub analysis: crate::ThreeWayMergeAnalysisPlan,
    pub text_diff: crate::ThreeWayTextDiffPlan,
    pub synthesis: crate::ThreeWayMergeSynthesisPlan,
    pub merged_bytes: crate::ThreeWayMergedBytesPlan,
}

pub fn build_mini() -> MiniFixture {
    let temp = tempdir().unwrap();
    let capture_installed = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let staging_root = temp.path().join("staging");
    let package_v1 = temp.path().join("v1.zip");
    let package_v2 = temp.path().join("v2.zip");
    fs::create_dir_all(&capture_installed).unwrap();
    fs::create_dir_all(&store).unwrap();
    fs::create_dir_all(&staging_root).unwrap();

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/merge.lua", MERGE_BASE),
            ("gksphone/take.lua", TAKE_BASE),
            ("gksphone/nested/child.lua", NESTED_CHILD),
        ],
    );
    let capture = capture_official_baseline_in_standalone_store(
        &crate::resolve_standalone_baseline_store(&store).expect("standalone store"),
        BaselineCaptureRequest::try_new(
            &capture_installed,
            &store,
            &package_v1,
            key("gksphone"),
            IncomingResourceSelector::AutoSingle,
            BaselineCaptureOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    let baseline = resolve_official_baseline(
        BaselineResolutionRequest::try_new(
            &store,
            &key("gksphone"),
            OfficialBaselineSelector::Exact(capture.baseline_id().clone()),
            BaselineResolutionOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();

    write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
    write_file(&installed_resource.join("merge.lua"), MERGE_INSTALLED);
    write_file(&installed_resource.join("take.lua"), TAKE_INSTALLED);
    write_file(
        &installed_resource.join("nested").join("child.lua"),
        NESTED_CHILD,
    );
    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/merge.lua", MERGE_INCOMING),
            ("gksphone/take.lua", TAKE_INCOMING),
            ("gksphone/nested/child.lua", NESTED_CHILD),
        ],
    );

    let report = inspect_installation_update(
        &installed_parent,
        &package_v2,
        crate::InspectionOptions::default(),
    )
    .unwrap();
    let installed_snapshot = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .unwrap();
    let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .unwrap();
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
    let decisions = plan
        .entries()
        .iter()
        .filter_map(|entry| {
            let choice = match entry.path().as_str() {
                "merge.lua" => ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                "take.lua" => ThreeWayPlanDecisionChoice::UseIncomingState,
                _ => return None,
            };
            Some(
                ThreeWayPlanDecision::try_new(
                    entry.path().clone(),
                    choice,
                    PolicyTransitionAcknowledgement::NotProvided,
                )
                .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(
            &plan,
            &ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();

    let installed_source = InstalledMergeContentSource::try_new(
        &installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let incoming_source = IncomingMergeContentSource::try_new(
        &package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .unwrap();
    let analysis = analyze_queued_three_way_merges(
        ThreeWayMergeAnalysisRequest::try_new(
            &plan,
            &review,
            &baseline,
            &installed_source,
            &incoming_source,
            ThreeWayMergeAnalysisOptions::default(),
        )
        .unwrap(),
    )
    .unwrap();
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
        .unwrap(),
    )
    .unwrap();
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
        .unwrap(),
    )
    .unwrap();
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
        .unwrap(),
    )
    .unwrap();
    assert!(merged_bytes
        .entries()
        .iter()
        .all(|e| e.disposition() == MergedByteDisposition::ReadyForStaging));

    MiniFixture {
        _temp: temp,
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

pub fn stage_ok(fixture: &MiniFixture) -> TrustedStagingBundle {
    let root = TrustedStagingRoot::try_open(&fixture.staging_root).unwrap();
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .unwrap();
    stage_trusted_resource(
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
        .unwrap(),
    )
    .unwrap()
}

pub(super) fn stage_err(fixture: &MiniFixture) -> crate::GkrmError {
    stage_result(fixture).expect_err("expected staging failure")
}

pub(super) fn stage_result(
    fixture: &MiniFixture,
) -> std::result::Result<TrustedStagingBundle, crate::GkrmError> {
    let root = TrustedStagingRoot::try_open(&fixture.staging_root).unwrap();
    let installed = InstalledStagingContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let incoming = IncomingStagingContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .unwrap();
    stage_trusted_resource(
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
        .unwrap(),
    )
}

pub fn hash_tree(root: &Path) -> std::collections::BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    let mut out = std::collections::BTreeMap::new();
    fn walk(dir: &Path, prefix: &str, out: &mut std::collections::BTreeMap<String, String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let path = entry.path();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                walk(&path, &rel, out);
            } else if meta.is_file() {
                let bytes = fs::read(&path).unwrap();
                out.insert(rel, format!("{:x}", Sha256::digest(&bytes)));
            }
        }
    }
    walk(root, "", &mut out);
    out
}
