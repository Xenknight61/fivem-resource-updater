use std::fs;
use std::io::Write;
use std::path::Path;

use gkrm_core::{
    capture_official_baseline_in_standalone_store, create_three_way_update_plan,
    inspect_installation_update, resolve_official_baseline, review_three_way_update_plan,
    BaselineCaptureOptions, BaselineCaptureRequest, BaselineResolutionOptions,
    BaselineResolutionRequest, GkrmError, IncomingOfficialResourceSnapshot,
    IncomingResourceSelector, InspectionOptions, InstallationRelativePath, InstalledResourceRoot,
    InstalledResourceSnapshot, OfficialBaselineSelector, PolicyTransitionAcknowledgement,
    ResourceRelativePath, SafeResourceKey, ThreeWayPlanDecision, ThreeWayPlanDecisionChoice,
    ThreeWayPlanDecisionSet, ThreeWayPlanDisposition, ThreeWayPlanReviewRequest,
    ThreeWayPlanReviewStatus, ThreeWayPlannerOptions, ThreeWayReviewedAction, ThreeWayUpdatePlan,
    ThreeWayUpdatePlanRequest, ZipRelativePath, ZipResourceRoot,
};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\n";

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

fn plan_path(plan: &ThreeWayUpdatePlan, path: &str) -> ResourceRelativePath {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing plan entry {path}"))
        .path()
        .clone()
}

fn decision(
    path: ResourceRelativePath,
    choice: ThreeWayPlanDecisionChoice,
) -> ThreeWayPlanDecision {
    ThreeWayPlanDecision::try_new(path, choice, PolicyTransitionAcknowledgement::NotProvided)
        .expect("decision")
}

fn disposition_for(plan: &ThreeWayUpdatePlan, path: &str) -> ThreeWayPlanDisposition {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing plan entry {path}"))
        .disposition()
}

#[test]
fn production_review_binds_to_real_plan_and_records_partial_and_complete_decisions() {
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
            ("gksphone/shared.lua", b"base"),
            ("gksphone/old.lua", b"old"),
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
    write_file(&installed_resource.join("shared.lua"), b"local");
    write_file(&installed_resource.join("old.lua"), b"old");
    write_file(&installed_resource.join("customer.lua"), b"customer");

    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/shared.lua", b"official-v2"),
            ("gksphone/new.lua", b"new"),
        ],
    );
    let report =
        inspect_installation_update(&installed_parent, &package_v2, InspectionOptions::default())
            .expect("inspection");
    fs::remove_file(&package_v2).expect("remove package before planning/review");

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
        disposition_for(&plan, "customer.lua"),
        ThreeWayPlanDisposition::PreserveInstalledAddition
    );
    assert_eq!(
        disposition_for(&plan, "new.lua"),
        ThreeWayPlanDisposition::AddIncoming
    );
    assert_eq!(
        disposition_for(&plan, "shared.lua"),
        ThreeWayPlanDisposition::ConflictReview
    );

    let partial_decision_set = ThreeWayPlanDecisionSet::try_new(
        *plan.plan_id(),
        vec![
            decision(
                plan_path(&plan, "customer.lua"),
                ThreeWayPlanDecisionChoice::AcceptRecommended,
            ),
            decision(
                plan_path(&plan, "new.lua"),
                ThreeWayPlanDecisionChoice::AcceptRecommended,
            ),
        ],
    )
    .expect("partial decision set");
    let partial = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &partial_decision_set).expect("review request"),
    )
    .expect("partial review");
    assert_eq!(partial.plan_id(), plan.plan_id());
    assert_eq!(partial.status(), ThreeWayPlanReviewStatus::Incomplete);
    assert!(partial.summary().pending() > 0);
    assert_eq!(
        action_for(&partial, "customer.lua"),
        ThreeWayReviewedAction::PreserveInstalledState
    );
    assert_eq!(
        action_for(&partial, "new.lua"),
        ThreeWayReviewedAction::UseIncomingState
    );

    let complete_decision_set = ThreeWayPlanDecisionSet::try_new(
        *plan.plan_id(),
        vec![
            decision(
                plan_path(&plan, "shared.lua"),
                ThreeWayPlanDecisionChoice::PreserveInstalledState,
            ),
            decision(
                plan_path(&plan, "old.lua"),
                ThreeWayPlanDecisionChoice::UseIncomingState,
            ),
            decision(
                plan_path(&plan, "new.lua"),
                ThreeWayPlanDecisionChoice::UseIncomingState,
            ),
            decision(
                plan_path(&plan, "customer.lua"),
                ThreeWayPlanDecisionChoice::PreserveInstalledState,
            ),
        ],
    )
    .expect("complete decision set");
    let complete = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &complete_decision_set).expect("review request"),
    )
    .expect("complete review");
    let repeated = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&plan, &complete_decision_set).expect("review request"),
    )
    .expect("repeat review");

    assert_eq!(
        complete.status(),
        ThreeWayPlanReviewStatus::DecisionComplete
    );
    assert_eq!(complete.review_id(), repeated.review_id());
    assert_eq!(complete.summary().pending(), 0);
    assert_eq!(complete.summary().decisions_required(), 4);
    assert_eq!(complete.summary().decisions_recorded(), 4);
    assert_eq!(
        action_for(&complete, "old.lua"),
        ThreeWayReviewedAction::UseIncomingState
    );
    assert_eq!(
        action_for(&complete, "shared.lua"),
        ThreeWayReviewedAction::PreserveInstalledState
    );

    assert!(!installed_resource.join("new.lua").exists());
    assert!(installed_resource.join("customer.lua").exists());
    assert!(!store.join("active.json").exists());
    assert!(!store.join("current.json").exists());
}

#[test]
fn production_review_rejects_decision_set_for_another_real_plan_before_path_validation() {
    let temp = tempdir().expect("temp");
    let installed_parent = temp.path().join("installed");
    let store = temp.path().join("store");
    let package_v1 = temp.path().join("official-v1.zip");
    let package_v2 = temp.path().join("official-v2.zip");
    fs::create_dir_all(temp.path().join("capture-installed")).expect("capture installed");
    fs::create_dir_all(&store).expect("store");

    write_zip(
        &package_v1,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/shared.lua", b"base"),
        ],
    );
    let capture = capture_official_baseline_in_standalone_store(
        &gkrm_core::resolve_standalone_baseline_store(&store).expect("standalone store"),
        BaselineCaptureRequest::try_new(
            &temp.path().join("capture-installed"),
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

    write_file(&installed_parent.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed_parent.join("gksphone/shared.lua"), b"base");
    write_zip(
        &package_v2,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/shared.lua", b"official-v2"),
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
    let first = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("plan request"),
    )
    .expect("first plan");

    write_file(&installed_parent.join("gksphone/shared.lua"), b"local");
    let changed_report =
        inspect_installation_update(&installed_parent, &package_v2, InspectionOptions::default())
            .expect("changed inspection");
    let changed_installed = InstalledResourceSnapshot::try_from_inspection(
        &changed_report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .expect("changed installed");
    let changed_incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        &changed_report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("changed incoming");
    let second = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &changed_installed,
            &changed_incoming,
            ThreeWayPlannerOptions::default(),
        )
        .expect("second request"),
    )
    .expect("second plan");
    assert_ne!(first.plan_id(), second.plan_id());

    let stale = ThreeWayPlanDecisionSet::try_new(
        *second.plan_id(),
        vec![decision(
            plan_path(&second, "shared.lua"),
            ThreeWayPlanDecisionChoice::UseIncomingState,
        )],
    )
    .expect("stale set");
    let err = review_three_way_update_plan(
        ThreeWayPlanReviewRequest::try_new(&first, &stale).expect("request"),
    )
    .expect_err("plan mismatch first");
    assert!(matches!(err, GkrmError::ThreeWayReviewPlanIdMismatch));
}

fn action_for(review: &gkrm_core::ThreeWayPlanReview, path: &str) -> ThreeWayReviewedAction {
    review
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing review entry {path}"))
        .action()
}
