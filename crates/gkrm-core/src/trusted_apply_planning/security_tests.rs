//! Focused Task 21 security verification tests.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::trusted_staging::test_support::{
    build_mini, hash_tree, installed_root, stage_ok, MiniFixture,
};
use crate::{
    plan_trusted_apply, GkrmError, InstalledApplyPlanningSource, InstalledScanLimits,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedApplyStatus,
    TrustedStagingBundle,
};

use super::{
    installed_read_count, lock_apply_planning_hooks, reset_content_read_count,
    set_after_first_staging_verify_hook, set_after_operations_hook, set_after_scan_a_hook,
    set_after_scan_b_hook, set_before_scan_b_hook, staging_read_count,
};

const UNTRUSTED_MARKER: &str = ".gkrm-untrusted-v1";

fn plan_result(
    fixture: &MiniFixture,
    bundle: &TrustedStagingBundle,
) -> crate::Result<crate::TrustedApplyPlan> {
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )?;
    plan_trusted_apply(TrustedApplyPlanningRequest::try_new(
        bundle,
        &fixture.plan,
        &fixture.review,
        Some(&fixture.analysis),
        Some(&fixture.text_diff),
        Some(&fixture.synthesis),
        Some(&fixture.merged_bytes),
        &fixture.baseline,
        &installed,
        TrustedApplyPlanningOptions::default(),
    )?)
}

fn published_dir(fixture: &MiniFixture, bundle: &TrustedStagingBundle) -> PathBuf {
    fixture
        .staging_root
        .join("bundles")
        .join(bundle.manifest().manifest_id().digest().to_string())
}

fn write_untrusted_marker(published: &Path) {
    fs::write(published.join(UNTRUSTED_MARKER), b"untrusted").unwrap();
}

fn assert_error_chain_redacted(
    error: &GkrmError,
    fixture: &MiniFixture,
    published_name: Option<&str>,
) {
    let staging = fixture.staging_root.to_string_lossy().into_owned();
    let installed = fixture.installed_resource.to_string_lossy().into_owned();
    let installed_parent = fixture.installed_parent.to_string_lossy().into_owned();
    let package = fixture.package_v2.to_string_lossy().into_owned();
    let store = fixture.store.to_string_lossy().into_owned();
    let plan_digest = fixture.plan.plan_id().digest().to_string();
    let mut sentinels = vec![
        staging.as_str(),
        installed.as_str(),
        installed_parent.as_str(),
        package.as_str(),
        store.as_str(),
        "fxmanifest.lua",
        "gksphone",
        "merge.lua",
        UNTRUSTED_MARKER,
        "tmp-",
        plan_digest.as_str(),
    ];
    if let Some(name) = published_name {
        sentinels.push(name);
    }

    for text in [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        for sentinel in &sentinels {
            assert!(
                !text.contains(sentinel),
                "error surface leaked `{sentinel}`: {text}"
            );
        }
    }
    walk_error_chain(error, &sentinels);
}

fn walk_error_chain(error: &GkrmError, sentinels: &[&str]) {
    use std::error::Error;
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(err) = current {
        for text in [format!("{err}"), format!("{err:?}"), format!("{err:#?}")] {
            for sentinel in sentinels {
                assert!(
                    !text.contains(sentinel),
                    "source-chain leaked `{sentinel}`: {text}"
                );
            }
        }
        assert!(
            err.downcast_ref::<std::io::Error>().is_none(),
            "raw std::io::Error reachable in Task 21 chain: {err:?}"
        );
        current = err.source();
    }
}

fn assert_plan_debug_redacted(plan: &crate::TrustedApplyPlan, fixture: &MiniFixture) {
    let staging = fixture.staging_root.to_string_lossy().into_owned();
    let installed = fixture.installed_resource.to_string_lossy().into_owned();
    let plan_id = plan.plan_id().digest().to_string();
    let backup_id = plan.backup_set_id().digest().to_string();
    let op_id = plan.operations()[0].operation_id().digest().to_string();
    let sentinels = [
        staging.as_str(),
        installed.as_str(),
        "fxmanifest.lua",
        "gksphone",
        "merge.lua",
        plan_id.as_str(),
        backup_id.as_str(),
        op_id.as_str(),
    ];
    let text = format!("{plan:?}");
    for sentinel in sentinels {
        assert!(
            !text.contains(sentinel),
            "plan Debug leaked `{sentinel}`: {text}"
        );
    }
    for op in plan.operations() {
        let op_dbg = format!("{op:?}");
        assert!(!op_dbg.contains("fxmanifest.lua"));
        assert!(!op_dbg.contains(&op_id));
    }
}

#[test]
fn quarantine_marker_before_planning_rejects_before_installed_reads() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    let published_name = bundle.manifest().manifest_id().digest().to_string();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    write_untrusted_marker(&published);
    let staging_with_marker = format!("{:?}", hash_tree(&fixture.staging_root));

    reset_content_read_count();
    let err = plan_result(&fixture, &bundle).expect_err("quarantined");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
    ));
    assert_eq!(installed_read_count(), 0);
    assert!(staging_read_count() >= 1);
    assert!(published.join(UNTRUSTED_MARKER).is_file());
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        staging_with_marker
    );
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_error_chain_redacted(&err, &fixture, Some(&published_name));
}

#[test]
fn quarantine_marker_between_staging_verifies_leaves_marker() {
    let _hooks = lock_apply_planning_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    let published_name = bundle.manifest().manifest_id().digest().to_string();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));

    set_after_scan_b_hook({
        let published = published.clone();
        move || write_untrusted_marker(&published)
    });

    let err = plan_result(&fixture, &bundle).expect_err("mid-flight quarantine");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
    ));
    assert!(published.join(UNTRUSTED_MARKER).is_file());
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_error_chain_redacted(&err, &fixture, Some(&published_name));
}

#[test]
fn manifest_id_directory_without_trusted_layout_rejected() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    let published_name = bundle.manifest().manifest_id().digest().to_string();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    fs::remove_file(published.join("manifest.bin")).unwrap();

    let err = plan_result(&fixture, &bundle).expect_err("name-only trust");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
            | GkrmError::TrustedApplyPlanningIo { .. }
    ));
    assert!(!published.join(UNTRUSTED_MARKER).exists());
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_error_chain_redacted(&err, &fixture, Some(&published_name));
}

#[test]
fn reconstructed_resource_bytes_rejected_without_cleanup() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    let target = published.join("resource").join("fxmanifest.lua");
    fs::write(&target, b"reconstructed-not-trusted\n").unwrap();
    let staging_after_mutation = format!("{:?}", hash_tree(&fixture.staging_root));

    let err = plan_result(&fixture, &bundle).expect_err("reconstructed");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
    ));
    assert!(!published.join(UNTRUSTED_MARKER).exists());
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        staging_after_mutation
    );
    assert_eq!(fs::read(&target).unwrap(), b"reconstructed-not-trusted\n");
    assert_error_chain_redacted(&err, &fixture, None);
}

#[test]
fn emptied_resource_tree_rejected_without_quarantine() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    let resource = published.join("resource");
    for entry in fs::read_dir(&resource).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            fs::remove_dir_all(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    }
    let staging_after = format!("{:?}", hash_tree(&fixture.staging_root));
    let err = plan_result(&fixture, &bundle).expect_err("redirected");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
    ));
    assert!(!published.join(UNTRUSTED_MARKER).exists());
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        staging_after
    );
    assert_error_chain_redacted(&err, &fixture, None);
}

#[test]
fn post_publish_quarantined_bundle_rejects_before_installed_reads() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    write_untrusted_marker(&published);
    reset_content_read_count();
    let err = plan_result(&fixture, &bundle).expect_err("post-quarantine");
    assert_eq!(installed_read_count(), 0);
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
    ));
    assert!(published.join(UNTRUSTED_MARKER).is_file());
}

fn mutate_content(root: &Path) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(root.join("merge.lua"))
        .unwrap();
    file.write_all(b"race").unwrap();
}

fn mutate_add(root: &Path) {
    fs::write(root.join("race-added.lua"), b"added").unwrap();
}

fn mutate_delete(root: &Path) {
    fs::remove_file(root.join("take.lua")).unwrap();
}

fn mutate_file_to_dir(root: &Path) {
    let path = root.join("take.lua");
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("nested.lua"), b"x").unwrap();
}

fn run_installed_race(set_hook: impl FnOnce(Box<dyn FnMut() + Send + 'static>), mutate: fn(&Path)) {
    let _hooks = lock_apply_planning_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let resource = fixture.installed_resource.clone();
    set_hook(Box::new(move || mutate(&resource)));
    let err = plan_result(&fixture, &bundle).expect_err("installed race");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningInstalledStale
            | GkrmError::TrustedApplyPlanningStagingRevalidationFailed
            | GkrmError::TrustedApplyPlanningIo { .. }
            | GkrmError::TrustedApplyPlanningPathTypeConflict
    ));
    assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
    assert_error_chain_redacted(&err, &fixture, None);
}

#[test]
fn installed_races_after_snapshot_a() {
    run_installed_race(set_after_scan_a_hook, mutate_content);
    run_installed_race(set_after_scan_a_hook, mutate_add);
    run_installed_race(set_after_scan_a_hook, mutate_delete);
    run_installed_race(set_after_scan_a_hook, mutate_file_to_dir);
}

#[test]
fn installed_races_after_first_staging_verify() {
    run_installed_race(set_after_first_staging_verify_hook, mutate_content);
}

#[test]
fn installed_races_after_operations() {
    run_installed_race(set_after_operations_hook, mutate_delete);
}

#[test]
fn installed_races_before_snapshot_b() {
    run_installed_race(set_before_scan_b_hook, mutate_file_to_dir);
}

#[test]
fn empty_directory_races_fail_closed() {
    run_installed_race(set_after_scan_a_hook, mutate_add_empty_dir);
    run_installed_race(set_after_operations_hook, mutate_add_empty_dir);
    run_installed_race(set_before_scan_b_hook, mutate_add_empty_dir);
    run_installed_race(set_after_scan_a_hook, mutate_add_nested_empty_dir);
    run_installed_race(set_before_scan_b_hook, mutate_add_nested_empty_dir);
}

fn mutate_add_empty_dir(root: &Path) {
    fs::create_dir(root.join("empty-race-dir")).unwrap();
}

fn mutate_add_nested_empty_dir(root: &Path) {
    fs::create_dir_all(root.join("empty-parent").join("empty-child")).unwrap();
}

#[test]
fn empty_directory_seeded_remove_and_rename_races() {
    type HookSetter = fn(Box<dyn FnMut() + Send + 'static>);
    type Mutator = fn(&Path);
    let cases: &[(HookSetter, Mutator, &str)] = &[
        (
            set_after_scan_a_hook,
            mutate_remove_seeded_empty,
            "remove-after-a",
        ),
        (
            set_before_scan_b_hook,
            mutate_remove_seeded_empty,
            "remove-before-b",
        ),
        (
            set_after_operations_hook,
            mutate_rename_seeded_empty,
            "rename-after-ops",
        ),
        (
            set_after_scan_a_hook,
            mutate_remove_seeded_nested_empty,
            "nested-remove",
        ),
    ];
    for (set_hook, mutate, label) in cases {
        let _hooks = lock_apply_planning_hooks();
        let fixture = build_mini();
        fs::create_dir(fixture.installed_resource.join("seeded-empty")).unwrap();
        fs::create_dir_all(
            fixture
                .installed_resource
                .join("seeded-nested")
                .join("leaf-empty"),
        )
        .unwrap();
        let bundle = stage_ok(&fixture);
        let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
        let resource = fixture.installed_resource.clone();
        set_hook(Box::new(move || mutate(&resource)));
        let err = plan_result(&fixture, &bundle)
            .expect_err(&format!("expected Err for empty-dir race `{label}`"));
        assert!(
            matches!(err, crate::GkrmError::TrustedApplyPlanningInstalledStale),
            "label={label} err={err:?}"
        );
        assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
        assert_error_chain_redacted(&err, &fixture, None);
    }
}

fn mutate_remove_seeded_empty(root: &Path) {
    fs::remove_dir(root.join("seeded-empty")).unwrap();
}

fn mutate_rename_seeded_empty(root: &Path) {
    fs::rename(root.join("seeded-empty"), root.join("seeded-empty-renamed")).unwrap();
}

fn mutate_remove_seeded_nested_empty(root: &Path) {
    fs::remove_dir_all(root.join("seeded-nested")).unwrap();
}

#[test]
fn installed_races_after_snapshot_b_before_final_staging() {
    let _hooks = lock_apply_planning_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let published = published_dir(&fixture, &bundle);
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    set_after_scan_b_hook({
        let published = published.clone();
        move || write_untrusted_marker(&published)
    });
    let err = plan_result(&fixture, &bundle).expect_err("after snapshot B");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningStagingRevalidationFailed
    ));
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert!(published.join(UNTRUSTED_MARKER).is_file());
}

#[test]
fn resource_directory_identity_replacement_fails() {
    let _hooks = lock_apply_planning_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let parent = fixture.installed_parent.clone();
    let resource_name = "gksphone".to_owned();
    set_before_scan_b_hook(move || {
        let old = parent.join(&resource_name);
        let tmp = parent.join("gksphone-replaced");
        fs::rename(&old, &tmp).unwrap();
        fs::create_dir(&old).unwrap();
        for entry in fs::read_dir(&tmp).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let from = entry.path();
            let to = old.join(&name);
            if from.is_dir() {
                copy_dir_recursive(&from, &to);
            } else {
                fs::copy(&from, &to).unwrap();
            }
        }
        fs::remove_dir_all(tmp).unwrap();
    });
    let err = plan_result(&fixture, &bundle).expect_err("identity replace");
    assert!(matches!(
        err,
        GkrmError::TrustedApplyPlanningInstalledStale | GkrmError::TrustedApplyPlanningIo { .. }
    ));
    assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
    assert_error_chain_redacted(&err, &fixture, None);
}

fn copy_dir_recursive(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir_recursive(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
fn symlink_substitution_fails_closed_when_supported() {
    let _hooks = lock_apply_planning_hooks();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let resource = fixture.installed_resource.clone();
    set_before_scan_b_hook(move || {
        let target = resource.join("merge.lua");
        let backup = resource.join("merge.lua.bak");
        fs::rename(&target, &backup).unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_file;
            if symlink_file(&backup, &target).is_err() {
                fs::rename(&backup, &target).unwrap();
            }
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&backup, &target).unwrap();
        }
    });
    match plan_result(&fixture, &bundle) {
        Err(err) => {
            assert!(matches!(
                err,
                GkrmError::TrustedApplyPlanningInstalledStale
                    | GkrmError::TrustedApplyPlanningIo { .. }
            ));
            assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
            assert_error_chain_redacted(&err, &fixture, None);
        }
        Ok(_) => {
            assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
        }
    }
}

#[test]
fn successful_and_failure_paths_hash_trees_and_fixed_ids() {
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_s = format!("{:?}", hash_tree(&fixture.staging_root));
    let plan = plan_result(&fixture, &bundle).unwrap();
    assert!(matches!(
        plan.status(),
        TrustedApplyStatus::ReadyForTransactionalApply | TrustedApplyStatus::NoFilesystemChanges
    ));
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(format!("{:?}", hash_tree(&fixture.staging_root)), before_s);
    assert_plan_debug_redacted(&plan, &fixture);

    const FIXED_TASK21_PLAN_ID: &str =
        "96b92a0cd0671ee7be14566a6e69a4bfcf18bd5663fa1ea0ac423692a36d9dc6";
    const FIXED_TASK21_INSTALLED_APPLY_TREE_SNAPSHOT_FINGERPRINT: &str =
        "097300511aeed45a0879ffc00eb41b5aaa9e8798e562faa72bc7929a1d280a7b";
    const FIXED_TASK21_BACKUP_SET_ID: &str =
        "9c31572877b838d0b1f0de316167320c765f02d58f1d5ecc69b88914e359dca2";
    const FIXED_TASK21_FIRST_OPERATION_ID: &str =
        "7a1fcbaa40dfafaa9a6b837a830e6e5ef7c136db552c85b03a53ac5a9de87955";
    assert_eq!(plan.plan_id().to_hex(), FIXED_TASK21_PLAN_ID);
    assert_eq!(
        plan.backup_set_id().digest().to_string(),
        FIXED_TASK21_BACKUP_SET_ID
    );
    assert_eq!(
        plan.operations()[0].operation_id().digest().to_string(),
        FIXED_TASK21_FIRST_OPERATION_ID
    );
    let installed = InstalledApplyPlanningSource::try_new(
        &fixture.installed_parent,
        installed_root("gksphone"),
        InstalledScanLimits::default(),
    )
    .unwrap();
    let snap = installed
        .capture_tree_snapshot(fixture.plan.resource_key())
        .unwrap();
    assert_eq!(
        snap.fingerprint.to_string(),
        FIXED_TASK21_INSTALLED_APPLY_TREE_SNAPSHOT_FINGERPRINT
    );

    write_untrusted_marker(&published_dir(&fixture, &bundle));
    let staging_marked = format!("{:?}", hash_tree(&fixture.staging_root));
    let err = plan_result(&fixture, &bundle).expect_err("marked");
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.staging_root)),
        staging_marked
    );
    assert_error_chain_redacted(
        &err,
        &fixture,
        Some(
            bundle
                .manifest()
                .manifest_id()
                .digest()
                .to_string()
                .as_str(),
        ),
    );
}
