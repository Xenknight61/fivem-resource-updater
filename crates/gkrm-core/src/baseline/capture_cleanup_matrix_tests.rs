//! Capture vs spool-cleanup result matrix (Task 12).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

use crate::baseline::capture::test_seams::{
    hook_lock, list_capture_spools, set_before_publish_hook, set_before_spool_cleanup_hook,
    spool_cleanup_attempt_count,
};
use crate::baseline::capture::{
    capture_official_baseline_in_standalone_store, BaselineCaptureOptions, BaselineCaptureRequest,
    IncomingResourceSelector,
};
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::BaselineStoreLimits;
use crate::baseline::store::load_baseline_bundle;
use crate::manifest::ManifestLimits;
use crate::package_limits::PackageLimits;
use crate::GkrmError;

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

fn poison_spool_with_nested_dir(tmp_root: &cap_std::fs::Dir, spool_name: &str) {
    let spool = tmp_root
        .open_dir(spool_name)
        .expect("open capture spool for poison");
    spool
        .create_dir("poison")
        .expect("nested dir blocks cleanup");
}

#[test]
fn capture_success_cleanup_success() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);

    let result = capture_default(&installed, &store, &package).expect("capture");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(list_capture_spools(&store).is_empty());
    assert_installed_unchanged(&installed);

    let loaded = load_baseline_bundle(
        &store,
        result.resource_key(),
        result.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load published baseline");
    assert_eq!(loaded.counts().files(), result.counts().files());
}

#[test]
fn capture_success_cleanup_failure_keeps_published_baseline() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_before_spool_cleanup_hook(poison_spool_with_nested_dir);

    let err = capture_default(&installed, &store, &package).expect_err("cleanup fail");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(
        matches!(err, GkrmError::BaselineCaptureSpoolCleanupFailed { .. }),
        "unexpected {err:?}"
    );
    assert!(err.capture_cleanup_error().is_some());
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert_installed_unchanged(&installed);
    assert!(
        !list_capture_spools(&store).is_empty(),
        "poisoned spool should remain under .tmp"
    );

    let baselines = store.join("baselines").join("res");
    let id_dir = fs::read_dir(&baselines)
        .expect("published baseline dir")
        .next()
        .expect("one baseline")
        .unwrap()
        .path();
    let baseline_id = crate::BaselineId::parse(
        id_dir
            .file_name()
            .unwrap()
            .to_str()
            .expect("utf8 baseline id"),
    )
    .expect("baseline id");
    let loaded = load_baseline_bundle(
        &store,
        &SafeResourceKey::parse("res").unwrap(),
        &baseline_id,
        BaselineStoreLimits::default(),
    )
    .expect("published baseline remains valid");
    assert!(loaded.counts().files() > 0);
}

#[test]
fn capture_failure_cleanup_success() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_before_publish_hook(|| Err(GkrmError::BaselineCaptureTestSeamFailure));

    let err = capture_default(&installed, &store, &package).expect_err("capture fail");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    assert!(matches!(err, GkrmError::BaselineCaptureTestSeamFailure));
    assert!(err.capture_primary_error().is_none());
    assert!(err.capture_cleanup_error().is_none());
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
}

#[test]
fn capture_failure_cleanup_failure_preserves_both_errors() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_before_publish_hook(|| Err(GkrmError::BaselineCaptureTestSeamFailure));
    set_before_spool_cleanup_hook(poison_spool_with_nested_dir);

    let err = capture_default(&installed, &store, &package).expect_err("both fail");
    assert_eq!(spool_cleanup_attempt_count(), 1);
    let GkrmError::BaselineCaptureFailedWithCleanupFailure { primary, cleanup } = &err else {
        panic!("expected combined error, got {err:?}");
    };
    assert!(matches!(
        **primary,
        GkrmError::BaselineCaptureTestSeamFailure
    ));
    assert!(matches!(
        **cleanup,
        GkrmError::BaselineCaptureSpoolCleanupFailed { .. }
    ));
    assert!(matches!(
        err.capture_primary_error(),
        Some(GkrmError::BaselineCaptureTestSeamFailure)
    ));
    assert!(err.capture_cleanup_error().is_some());
    assert_display_safe(&err, &[&installed, &store, &package]);
    assert_display_safe(primary, &[&installed, &store, &package]);
    assert_display_safe(cleanup, &[&installed, &store, &package]);
    assert_no_published_baseline(&store);
    assert_installed_unchanged(&installed);
    assert!(
        !list_capture_spools(&store).is_empty(),
        "cleanup failure should leave private spool under .tmp"
    );
}

#[test]
fn cleanup_matrix_options_surface_is_stable() {
    let _: fn(
        &crate::StandaloneBaselineStore,
        BaselineCaptureRequest<'_>,
    ) -> crate::Result<crate::baseline::capture::BaselineCaptureResult> =
        capture_official_baseline_in_standalone_store;
    let _ = PackageLimits::default();
    let _ = ManifestLimits::default();
}
