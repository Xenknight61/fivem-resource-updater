use std::fs;
use std::io::Write;
use std::path::Path;

use gkrm_core::{
    capture_official_baseline_in_standalone_store, create_three_way_update_plan,
    inspect_installation_update, resolve_official_baseline, BaselineCaptureOptions,
    BaselineCaptureRequest, BaselineResolutionOptions, BaselineResolutionRequest,
    EscrowPolicyTransition, GkrmError, IncomingOfficialResourceSnapshot, IncomingResourceSelector,
    InspectionOptions, InstallationRelativePath, InstalledResourceRoot, InstalledResourceSnapshot,
    OfficialBaselineSelector, SafeResourceKey, Sha256Digest, ThreeWayPlanDisposition,
    ThreeWayPlannerOptions, ThreeWayUpdatePlanRequest, ZipRelativePath, ZipResourceRoot,
};
use sha2::{Digest, Sha256};
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

fn digest_file(path: &Path) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(fs::read(path).expect("read file")).into())
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

#[test]
fn production_end_to_end_plan_uses_resolved_baseline_and_complete_snapshots() {
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
    let package_v2_fingerprint = digest_file(&package_v2);
    let report =
        inspect_installation_update(&installed_parent, &package_v2, InspectionOptions::default())
            .expect("inspection");
    assert_eq!(
        report.incoming_package_fingerprint(),
        &package_v2_fingerprint
    );
    fs::remove_file(&package_v2).expect("remove package after inspection");

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
    assert_eq!(
        incoming_snapshot.package_fingerprint(),
        &package_v2_fingerprint
    );
    assert_ne!(
        incoming_snapshot.package_fingerprint(),
        &Sha256Digest::new([0; 32])
    );

    let request = ThreeWayUpdatePlanRequest::try_new(
        &baseline,
        &installed_snapshot,
        &incoming_snapshot,
        ThreeWayPlannerOptions::default(),
    )
    .expect("plan request");
    let plan = create_three_way_update_plan(request).expect("plan");
    let repeated = create_three_way_update_plan(
        ThreeWayUpdatePlanRequest::try_new(
            &baseline,
            &installed_snapshot,
            &incoming_snapshot,
            ThreeWayPlannerOptions::default(),
        )
        .expect("repeat request"),
    )
    .expect("repeat plan");

    assert_eq!(plan.resource_key(), &key("gksphone"));
    assert_eq!(plan.plan_id(), repeated.plan_id());
    assert_eq!(plan.entries(), repeated.entries());
    assert_eq!(plan.incoming_package_fingerprint(), &package_v2_fingerprint);
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
    assert_eq!(
        disposition_for(&plan, "old.lua"),
        ThreeWayPlanDisposition::RemoveForIncoming
    );
    assert_eq!(
        plan.entries()
            .iter()
            .find(|entry| entry.path().as_str() == "shared.lua")
            .expect("shared entry")
            .policy_transition(),
        EscrowPolicyTransition::None
    );
    assert!(!installed_resource.join("new.lua").exists());
    assert!(!store.join("active.json").exists());
    assert!(!store.join("current.json").exists());
}

#[test]
fn production_snapshot_selection_rejects_wrong_or_missing_roots() {
    let temp = tempdir().expect("temp");
    let installed_parent = temp.path().join("installed");
    let package = temp.path().join("official.zip");
    write_file(&installed_parent.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed_parent.join("other/fxmanifest.lua"), MANIFEST);
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", MANIFEST),
            ("gksphone/only.lua", b"phone"),
            ("other/fxmanifest.lua", MANIFEST),
            ("other/only.lua", b"other"),
        ],
    );
    let report =
        inspect_installation_update(&installed_parent, &package, InspectionOptions::default())
            .expect("inspection");

    let phone_installed = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("gksphone"),
        &key("gksphone"),
    )
    .expect("phone installed");
    let phone_incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("gksphone"),
        &key("gksphone"),
    )
    .expect("phone incoming");
    assert_eq!(phone_installed.file_count(), 1);
    assert_eq!(phone_incoming.file_count(), 2);

    let wrong_installed = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("other"),
        &key("gksphone"),
    )
    .expect_err("wrong installed key");
    assert!(matches!(
        wrong_installed,
        GkrmError::ThreeWayBaselineInstalledResourceMismatch
    ));

    let wrong_incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("other"),
        &key("gksphone"),
    )
    .expect_err("wrong incoming key");
    assert!(matches!(
        wrong_incoming,
        GkrmError::ThreeWayBaselineIncomingResourceMismatch
    ));

    let missing_installed = InstalledResourceSnapshot::try_from_inspection(
        &report,
        &installed_root("missing"),
        &key("missing"),
    )
    .expect_err("missing installed");
    assert!(matches!(
        missing_installed,
        GkrmError::ThreeWaySelectedInstalledResourceMissing
    ));

    let missing_incoming = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &incoming_root("missing"),
        &key("missing"),
    )
    .expect_err("missing incoming");
    assert!(matches!(
        missing_incoming,
        GkrmError::ThreeWaySelectedIncomingResourceMissing
    ));
}

#[test]
fn root_incoming_resource_without_trusted_identity_is_rejected() {
    let temp = tempdir().expect("temp");
    let installed_parent = temp.path().join("installed");
    let package = temp.path().join("root-resource.zip");
    write_file(&installed_parent.join("gksphone/fxmanifest.lua"), MANIFEST);
    write_file(&installed_parent.join("gksphone/client.lua"), b"local");
    write_zip(
        &package,
        &[("fxmanifest.lua", MANIFEST), ("client.lua", b"incoming")],
    );

    let report =
        inspect_installation_update(&installed_parent, &package, InspectionOptions::default())
            .expect("inspection");
    let err = IncomingOfficialResourceSnapshot::try_from_inspection(
        &report,
        &ZipResourceRoot::Root,
        &key("gksphone"),
    )
    .expect_err("root resource must not inherit expected key");

    assert!(matches!(
        err,
        GkrmError::ThreeWayIncomingRootIdentityUnavailable
    ));
    let display = err.to_string();
    assert!(!display.contains("gksphone"));
    assert!(!display.contains("root-resource.zip"));
}

fn disposition_for(plan: &gkrm_core::ThreeWayUpdatePlan, path: &str) -> ThreeWayPlanDisposition {
    plan.entries()
        .iter()
        .find(|entry| entry.path().as_str() == path)
        .unwrap_or_else(|| panic!("missing plan entry {path}"))
        .disposition()
}
