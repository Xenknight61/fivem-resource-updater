//! Capture spool guard create-before-ownership, allocation, and Drop (Task 12).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

use crate::baseline::capture::test_seams::{
    abandon_capture_spool_guard, finish_capture_spool_guard_once,
    force_next_spool_identity_mismatch, force_spool_create_collisions, hook_lock,
    list_capture_spools, push_forced_spool_names, set_after_spool_child_created_hook,
    set_during_spool_validation_hook, spool_cleanup_attempt_count, spool_create_attempt_count,
    spool_name_attempt_count,
};
use crate::baseline::capture::{
    capture_official_baseline_in_standalone_store, BaselineCaptureOptions, BaselineCaptureRequest,
    IncomingResourceSelector,
};
use crate::baseline::key::SafeResourceKey;
use crate::{BaselineCaptureBlobSpoolStage, GkrmError};

fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in entries {
        writer.start_file(*name, options).expect("start");
        writer.write_all(bytes).expect("write");
    }
    writer.finish().expect("finish");
}

fn ignored_package(package: &Path) {
    write_zip(
        package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'config.lua'\n}\n",
            ),
            ("res/config.lua", b"cfg-body"),
            ("res/client.lua", b"protected"),
        ],
    );
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    let store = temp.path().join("store");
    let package = temp.path().join("pkg.zip");
    fs::create_dir_all(&installed).unwrap();
    fs::create_dir_all(&store).unwrap();
    fs::write(installed.join("customer.lua"), b"preserve-me").unwrap();
    (temp, installed, store, package)
}

fn capture_default(
    installed: &Path,
    store: &Path,
    package: &Path,
) -> Result<crate::baseline::capture::BaselineCaptureResult, GkrmError> {
    let request = BaselineCaptureRequest::try_new(
        installed,
        store,
        package,
        SafeResourceKey::parse("res").unwrap(),
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )?;
    let store = crate::resolve_standalone_baseline_store(store)?;
    capture_official_baseline_in_standalone_store(&store, request)
}

fn assert_no_published_baseline(store: &Path) {
    let baselines = store.join("baselines");
    if !baselines.exists() {
        return;
    }
    for key_entry in fs::read_dir(&baselines).unwrap() {
        let key_path = key_entry.unwrap().path();
        if key_path.is_dir() {
            assert!(
                fs::read_dir(&key_path).unwrap().next().is_none(),
                "unexpected published baseline under {}",
                key_path.display()
            );
        }
    }
}

fn assert_installed_unchanged(installed: &Path) {
    assert_eq!(
        fs::read(installed.join("customer.lua")).unwrap(),
        b"preserve-me"
    );
}

fn assert_display_safe(err: &GkrmError, roots: &[&Path]) {
    let text = err.to_string();
    assert!(!text.contains(".p-"), "leaked .p-: {text}");
    assert!(!text.contains(".partial-"), "leaked .partial-: {text}");
    assert!(
        !text.contains("capture-"),
        "leaked capture- spool name: {text}"
    );
    assert!(!text.to_ascii_lowercase().contains("at index "));
    for root in roots {
        let display = root.display().to_string();
        if !display.is_empty() {
            assert!(!text.contains(&display), "leaked path {display}: {text}");
        }
        if let Ok(canonical) = root.canonicalize() {
            let canonical_display = canonical.display().to_string();
            assert!(
                !text.contains(&canonical_display),
                "leaked canonical {canonical_display}: {text}"
            );
        }
    }
}

fn is_spool_stage(err: &GkrmError, stage: BaselineCaptureBlobSpoolStage) -> bool {
    match err {
        GkrmError::BaselineCaptureBlobSpoolFailure { stage: got, .. } => *got == stage,
        GkrmError::BaselineCaptureFailedWithCleanupFailure { primary, .. } => {
            is_spool_stage(primary, stage)
        }
        _ => false,
    }
}

#[test]
fn first_generated_spool_name_succeeds_without_probes() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);

    capture_default(&installed, &store, &package).expect("capture");
    assert_eq!(spool_name_attempt_count(), 1);
    assert_eq!(spool_create_attempt_count(), 1);
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn already_exists_retries_with_new_name() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);

    let tmp = store.join(".tmp");
    fs::create_dir_all(&tmp).unwrap();
    fs::create_dir(tmp.join("capture-taken00000000")).unwrap();
    push_forced_spool_names(["capture-taken00000000", "capture-free000000001"]);

    capture_default(&installed, &store, &package).expect("capture after retry");
    assert!(spool_name_attempt_count() >= 2);
    assert_eq!(spool_create_attempt_count(), 1);
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(tmp.join("capture-taken00000000").is_dir());
    assert!(
        !tmp.join("capture-free000000001").exists(),
        "owned spool child must be cleaned; collision target must not be removed"
    );
}

#[test]
fn name_allocation_exhaustion_is_bounded_and_structured() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    force_spool_create_collisions(64);

    let err = capture_default(&installed, &store, &package).expect_err("exhausted");
    assert_eq!(spool_name_attempt_count(), 64);
    assert_eq!(spool_create_attempt_count(), 0);
    assert_eq!(spool_cleanup_attempt_count(), 0);
    assert!(is_spool_stage(
        &err,
        BaselineCaptureBlobSpoolStage::Allocate
    ));
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn create_then_open_failure_attempts_cleanup() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_after_spool_child_created_hook(|tmp_root, name| {
        tmp_root.remove_dir(name).expect("remove before open");
    });

    let err = capture_default(&installed, &store, &package).expect_err("open fail");
    assert_eq!(spool_create_attempt_count(), 1);
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(is_spool_stage(&err, BaselineCaptureBlobSpoolStage::Open));
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn create_then_validation_failure_attempts_cleanup() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_during_spool_validation_hook(|_tmp, _name| {
        Err(GkrmError::BaselineCaptureBlobSpoolFailure {
            stage: BaselineCaptureBlobSpoolStage::Validate,
            kind: std::io::ErrorKind::Other,
        })
    });

    let err = capture_default(&installed, &store, &package).expect_err("validate fail");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(is_spool_stage(
        &err,
        BaselineCaptureBlobSpoolStage::Validate
    ));
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn create_then_reparse_or_symlink_attempts_cleanup() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let outside = store.join("outside-target");
    fs::create_dir_all(&outside).unwrap();

    set_after_spool_child_created_hook({
        let store = store.clone();
        let outside = outside.clone();
        move |tmp_root, name| {
            tmp_root.remove_dir(name).expect("remove ordinary spool");
            let link = store.join(".tmp").join(name);
            if !try_symlink_dir(&outside, &link) {
                // Fall back to a non-directory so open validation still fails closed.
                fs::write(&link, b"not-a-dir").expect("file substitute");
            }
        }
    });

    let err = capture_default(&installed, &store, &package).expect_err("reparse/link");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(
        is_spool_stage(&err, BaselineCaptureBlobSpoolStage::Open)
            || matches!(
                err,
                GkrmError::BaselineCaptureFailedWithCleanupFailure { .. }
            ),
        "unexpected {err:?}"
    );
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn create_then_identity_mismatch_attempts_cleanup() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    force_next_spool_identity_mismatch();

    let err = capture_default(&installed, &store, &package).expect_err("identity");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(is_spool_stage(
        &err,
        BaselineCaptureBlobSpoolStage::Validate
    ));
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn create_then_open_failure_plus_cleanup_failure_preserves_both() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_after_spool_child_created_hook(|tmp_root, name| {
        tmp_root.remove_dir(name).expect("remove dir");
        let mut file = tmp_root.create(name).expect("plant file at spool name");
        file.write_all(b"blocker").unwrap();
    });

    let err = capture_default(&installed, &store, &package).expect_err("setup+cleanup");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    match err {
        GkrmError::BaselineCaptureFailedWithCleanupFailure { primary, cleanup } => {
            assert!(is_spool_stage(
                &primary,
                BaselineCaptureBlobSpoolStage::Open
            ));
            assert!(
                cleanup.capture_cleanup_error().is_some()
                    || cleanup.to_string().contains("cleanup")
            );
            assert_display_safe(&primary, &[&installed, &store, &package]);
            assert_display_safe(&cleanup, &[&installed, &store, &package]);
        }
        other => panic!("expected combined failure, got {other:?}"),
    }
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn explicit_finish_cleans_exactly_once() {
    let _guard = hook_lock();
    let (_temp, _installed, store, _package) = setup();
    finish_capture_spool_guard_once(&store).expect("finish once");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn abandoned_guard_drop_cleans_once() {
    let _guard = hook_lock();
    let (_temp, _installed, store, _package) = setup();
    abandon_capture_spool_guard(&store).expect("abandon");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn panic_during_capture_does_not_escape_tmp() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_during_spool_validation_hook(|_tmp, _name| panic!("injected capture unwind"));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = capture_default(&installed, &store, &package);
    }));
    assert!(result.is_err());
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
    assert_eq!(
        fs::read_dir(store.join(".tmp"))
            .map(|entries| entries.filter_map(Result::ok).count())
            .unwrap_or(0),
        0,
        "panic path must not leave capture children outside cleaned .tmp"
    );
}

fn try_symlink_dir(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    }
}
