//! Focused Task 19 verification tests (manual binding, post-limit failure).

use super::*;
use crate::three_way_merge_synthesis::{
    plan_three_way_merge_synthesis, MergeSynthesisOperation, MergeSynthesisOperationId,
    MergeSynthesisOperationKind, ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisRequest,
};
use crate::three_way_text_diff::{
    plan_three_way_text_diffs, LineRange, TextLineSequenceCommitment, TextTerminalNewline,
    ThreeWayTextDiffOptions, ThreeWayTextDiffRequest,
};
use crate::{
    analyze_queued_three_way_merges, capture_official_baseline_in_standalone_store,
    create_three_way_update_plan, inspect_installation_update, resolve_official_baseline,
    review_three_way_update_plan, BaselineCaptureOptions, BaselineCaptureRequest,
    BaselineResolutionOptions, BaselineResolutionRequest, IncomingMergeContentSourceLimits,
    IncomingOfficialResourceSnapshot, IncomingResourceSelector, InspectionOptions,
    InstallationRelativePath, InstalledResourceRoot, InstalledResourceSnapshot,
    InstalledScanLimits, OfficialBaselineSelector, PolicyTransitionAcknowledgement,
    ThreeWayMergeAnalysisOptions, ThreeWayMergeAnalysisRequest, ThreeWayPlanDecision,
    ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet, ThreeWayPlanReviewRequest,
    ThreeWayPlannerOptions, ThreeWayUpdatePlanRequest, ZipRelativePath, ZipResourceRoot,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] =
    b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'a_first.lua',\n  'z_later.lua',\n}\n";
const A_BASE: &[u8] = b"A1\nA2\n";
const A_INSTALLED: &[u8] = b"A1x\nA2\n";
const A_INCOMING: &[u8] = b"A1\nA2y\n";
const Z_BASE: &[u8] = b"Z1\nZ2\n";
const Z_INSTALLED: &[u8] = b"Z1x\nZ2\n";
const Z_INCOMING: &[u8] = b"Z1\nZ2y\n";

struct VerifyFixture {
    _temp_dir: tempfile::TempDir,
    store: PathBuf,
    installed_parent: PathBuf,
    installed_resource: PathBuf,
    package_v2: PathBuf,
    baseline: ResolvedOfficialBaseline,
    plan: crate::ThreeWayUpdatePlan,
    review: ThreeWayPlanReview,
    analysis: ThreeWayMergeAnalysisPlan,
    text_diff: ThreeWayTextDiffPlan,
    synthesis: ThreeWayMergeSynthesisPlan,
}

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

fn queue_all(plan: &crate::ThreeWayUpdatePlan) -> ThreeWayPlanDecisionSet {
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
            .expect("decision")
        })
        .collect::<Vec<_>>();
    ThreeWayPlanDecisionSet::try_new(*plan.plan_id(), decisions).expect("set")
}

fn build_two_ready_fixture() -> VerifyFixture {
    let temp = tempdir().expect("temp");
    let installed_for_capture = temp.path().join("capture-installed");
    let installed_parent = temp.path().join("installed");
    let installed_resource = installed_parent.join("gksphone");
    let store = temp.path().join("store");
    let package_v1 = temp.path().join("official-v1.zip");
    let package_v2 = temp.path().join("official-v2.zip");
    fs::create_dir_all(&installed_for_capture).expect("dir");
    fs::create_dir_all(&store).expect("store");

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/a_first.lua", A_BASE),
            ("gksphone/z_later.lua", Z_BASE),
        ],
    );
    let capture = capture_official_baseline_in_standalone_store(
        &crate::resolve_standalone_baseline_store(&store).expect("standalone store"),
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
    write_file(&installed_resource.join("a_first.lua"), A_INSTALLED);
    write_file(&installed_resource.join("z_later.lua"), Z_INSTALLED);
    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/a_first.lua", A_INCOMING),
            ("gksphone/z_later.lua", Z_INCOMING),
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
    .expect("snap");
    let incoming_snapshot = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("incoming");
    let plan = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan"),
    )
    .expect("plan");
    let review = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &queue_all(&plan)).expect("review"),
    )
    .expect("review");
    let installed_source = InstalledMergeContentSource::try_new(
        &installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming_source = IncomingMergeContentSource::try_new(
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
        .expect("analysis"),
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
        .expect("text"),
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
        .expect("synthesis"),
    )
    .expect("synthesis");

    VerifyFixture {
        _temp_dir: temp,
        store,
        installed_parent,
        installed_resource,
        package_v2,
        baseline,
        plan,
        review,
        analysis,
        text_diff,
        synthesis,
    }
}

fn all_manual_synthesis(fixture: &VerifyFixture) -> ThreeWayMergeSynthesisPlan {
    let installed_source = InstalledMergeContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming_source = IncomingMergeContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming");
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
        .expect("req"),
    )
    .expect("all-manual synthesis")
}

fn default_merged_options() -> ThreeWayMergedBytesOptions {
    ThreeWayMergedBytesOptions::default()
}

fn synthesize_with(
    fixture: &VerifyFixture,
    synthesis: &ThreeWayMergeSynthesisPlan,
    options: ThreeWayMergedBytesOptions,
) -> Result<ThreeWayMergedBytesPlan> {
    let installed_source = InstalledMergeContentSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .expect("installed");
    let incoming_source = IncomingMergeContentSource::try_new(
        &fixture.package_v2,
        incoming_root("gksphone"),
        IncomingMergeContentSourceLimits::default(),
    )
    .expect("incoming");
    synthesize_three_way_merged_bytes(
        ThreeWayMergedBytesRequest::try_new(
            &fixture.plan,
            &fixture.review,
            &fixture.analysis,
            &fixture.text_diff,
            synthesis,
            &fixture.baseline,
            &installed_source,
            &incoming_source,
            options,
        )
        .expect("req"),
    )
}

fn first_manual_index(synthesis: &ThreeWayMergeSynthesisPlan) -> usize {
    synthesis
        .entries()
        .iter()
        .position(|e| e.disposition() == MergeSynthesisDisposition::ManualReviewOperationLimit)
        .expect("manual entry")
}

fn mutate_manual(
    synthesis: &ThreeWayMergeSynthesisPlan,
    mutate: impl FnOnce(&mut ThreeWayMergeSynthesisEntry),
) -> ThreeWayMergeSynthesisPlan {
    let mut entries = synthesis.entries().to_vec();
    let index = first_manual_index(synthesis);
    mutate(&mut entries[index]);
    synthesis.clone_with_entries_for_test(entries)
}

fn assert_rejects_before_io(err: GkrmError, counters: MergedBytesIoCounters) {
    assert_eq!(
        counters.total_source_io(),
        0,
        "expected zero source I/O, got {counters:?}; err={err:?}"
    );
    assert!(
        matches!(
            err,
            GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch
                | GkrmError::ThreeWayMergedBytesSynthesisStructuralMismatch
                | GkrmError::ThreeWayMergedBytesInvalidEnvelope
                | GkrmError::ThreeWayMergedBytesNoReadyCandidates
        ),
        "unexpected err={err:?}"
    );
}

#[test]
fn manual_task18_entry_mutations_reject_before_any_source_io() {
    let fixture = build_two_ready_fixture();
    let synthesis = all_manual_synthesis(&fixture);
    assert!(synthesis
        .entries()
        .iter()
        .all(|e| { e.disposition() == MergeSynthesisDisposition::ManualReviewOperationLimit }));

    let cases: Vec<(
        &str,
        Box<dyn Fn(&ThreeWayMergeSynthesisPlan) -> ThreeWayMergeSynthesisPlan>,
    )> = vec![
        (
            "path",
            Box::new(|s| {
                mutate_manual(s, |entry| {
                    entry.mutate_path_for_test(
                        ResourceRelativePath::try_from_slash_str("missing.lua").unwrap(),
                    );
                })
            }),
        ),
        (
            "disposition",
            Box::new(|s| {
                mutate_manual(s, |entry| {
                    entry.mutate_disposition_for_test(
                        MergeSynthesisDisposition::ReadyForByteSynthesis,
                    );
                })
            }),
        ),
        (
            "envelope",
            Box::new(|s| {
                mutate_manual(s, |entry| {
                    let env = entry.final_envelope();
                    entry.mutate_envelope_for_test(FinalTextEnvelope::from_parts(
                        env.bom(),
                        env.newline_style(),
                        TextTerminalNewline::Unknown,
                    ));
                })
            }),
        ),
        (
            "nonempty_ops",
            Box::new(|s| {
                mutate_manual(s, |entry| {
                    let dummy = MergeSynthesisOperation::from_parts_for_test(
                        MergeSynthesisOperationId::from_digest_for_test(Sha256Digest::new(
                            [0x11; 32],
                        )),
                        MergeSynthesisOperationKind::CopyBase,
                        LineRange::new(0, 1).unwrap(),
                        None,
                        None,
                        None,
                        TextLineSequenceCommitment::from_digest_for_test(Sha256Digest::new(
                            [0x22; 32],
                        )),
                    );
                    entry.mutate_operations_for_test(vec![dummy]);
                })
            }),
        ),
        (
            "merged_commitment_some",
            Box::new(|s| {
                mutate_manual(s, |entry| {
                    entry.mutate_merged_commitment_for_test(Some(
                        TextLineSequenceCommitment::from_digest_for_test(Sha256Digest::new(
                            [0x33; 32],
                        )),
                    ));
                })
            }),
        ),
        (
            "entry_reorder",
            Box::new(|s| {
                let mut entries = s.entries().to_vec();
                assert!(entries.len() >= 2);
                entries.swap(0, 1);
                s.clone_with_entries_for_test(entries)
            }),
        ),
        (
            "entry_count",
            Box::new(|s| {
                let mut entries = s.entries().to_vec();
                entries.pop();
                s.clone_with_entries_for_test(entries)
            }),
        ),
    ];

    for (label, mutator) in cases {
        let mutated = mutator(&synthesis);
        let _hooks = lock_merged_bytes_hooks();
        let err = synthesize_with(&fixture, &mutated, default_merged_options()).expect_err(label);
        let counters = snapshot_io_counters();
        assert_rejects_before_io(err, counters);
    }
}

fn corrupt_baseline_blob(fixture: &VerifyFixture, relative: &str) {
    let record = fixture
        .baseline
        .stored_baseline()
        .files()
        .iter()
        .find(|f| f.relative_path().as_str() == relative)
        .expect("record");
    let digest = record.blob_sha256().expect("blob digest");
    let blob_path = fixture
        .store
        .join("baselines")
        .join(fixture.baseline.resource_key().as_str())
        .join(fixture.baseline.baseline_id().as_str())
        .join("blobs")
        .join(digest.to_string());
    fs::write(&blob_path, b"corrupted-task19-baseline-blob").expect("corrupt");
}

#[test]
fn failure_after_output_limit_entry_is_top_level_err_without_retained_bytes() {
    let fixture = build_two_ready_fixture();
    assert!(fixture.synthesis.entries().len() >= 2);
    assert!(fixture
        .synthesis
        .entries()
        .iter()
        .all(|e| e.disposition() == MergeSynthesisDisposition::ReadyForByteSynthesis));
    assert!(
        fixture.synthesis.entries()[0].path().as_str()
            < fixture.synthesis.entries()[1].path().as_str()
    );

    corrupt_baseline_blob(&fixture, "z_later.lua");

    let options = ThreeWayMergedBytesOptions::try_new(
        1_000,
        4 * 1024 * 1024,
        128 * 1024 * 1024,
        1,
        1,
        200_000,
        600_000,
        BaselineStoreLimits::default(),
    )
    .expect("tiny output");

    let _hooks = lock_merged_bytes_hooks();
    let before_live = live_merged_byte_artifacts();
    let err = synthesize_with(&fixture, &fixture.synthesis, options).expect_err("must fail");
    assert!(
        matches!(
            err,
            GkrmError::ThreeWayMergedBytesBaselineBlobVerificationFailed { .. }
                | GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch
                | GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch
                | GkrmError::ThreeWayMergedBytesInstalledCandidateInvalid
        ),
        "unexpected err={err:?}"
    );
    assert_eq!(
        live_merged_byte_artifacts(),
        before_live,
        "no retained MergedByteArtifact bytes may survive a top-level Err"
    );
}

#[test]
fn failure_after_manual_output_limit_is_not_hidden_by_earlier_manual() {
    let fixture = build_two_ready_fixture();
    let options = ThreeWayMergedBytesOptions::try_new(
        1_000,
        4 * 1024 * 1024,
        128 * 1024 * 1024,
        1,
        1,
        200_000,
        600_000,
        BaselineStoreLimits::default(),
    )
    .expect("tiny output");

    let saw_first = Arc::new(Mutex::new(false));
    let saw_first_hook = Arc::clone(&saw_first);
    let installed_resource = fixture.installed_resource.clone();

    let _hooks = lock_merged_bytes_hooks();
    set_between_entries_hook(move |completed| {
        if completed == 1 {
            *saw_first_hook.lock().unwrap() = true;
            fs::write(
                installed_resource.join("z_later.lua"),
                b"stale-after-limit\n",
            )
            .expect("stale later");
        }
    });

    let before_live = live_merged_byte_artifacts();
    let err = synthesize_with(&fixture, &fixture.synthesis, options).expect_err("must fail");
    assert!(
        *saw_first.lock().unwrap(),
        "first path-sorted entry must complete before later failure"
    );
    assert!(
        matches!(
            err,
            GkrmError::ThreeWayMergedBytesInstalledCandidateInvalid
                | GkrmError::ThreeWayMergedBytesSourceIdentityChanged
                | GkrmError::ThreeWayMergedBytesInstalledResourceChanged
                | GkrmError::ThreeWayMergedBytesTask16MetadataMismatch
                | GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch
                | GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch
        ),
        "later failure must surface as top-level Err, not Ok; got {err:?}"
    );
    assert_eq!(live_merged_byte_artifacts(), before_live);
}
