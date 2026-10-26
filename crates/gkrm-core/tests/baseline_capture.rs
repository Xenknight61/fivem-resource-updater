//! Integration tests for official baseline capture (Task 12).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use gkrm_core::{
    capture_official_baseline_in_standalone_store, load_baseline_bundle,
    resolve_standalone_baseline_store, BaselineCaptureOptions, BaselineCaptureRequest,
    BaselineCaptureWarning, BaselineEscrowClass, BaselineId, BaselineStoreLimits, GkrmError,
    IncomingResourceSelector, ManifestLimits, PackageLimits, SafeResourceKey, Sha256Digest,
    ZipRelativePath,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

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

fn digest_of(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}

fn package_fingerprint(path: &Path) -> Sha256Digest {
    let bytes = fs::read(path).expect("read zip");
    digest_of(&bytes)
}

fn capture(
    installed: &Path,
    store: &Path,
    package: &Path,
    key: &str,
    selector: IncomingResourceSelector,
) -> gkrm_core::BaselineCaptureResult {
    let store = resolve_standalone_baseline_store(store).expect("standalone store");
    let request = BaselineCaptureRequest::try_new(
        installed,
        store.root(),
        package,
        SafeResourceKey::parse(key).expect("key"),
        selector,
        BaselineCaptureOptions::default(),
    )
    .expect("request");
    capture_official_baseline_in_standalone_store(&store, request).expect("capture")
}

fn setup_roots(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let installed = temp.path().join("installed");
    let store = temp.path().join("store");
    let package = temp.path().join("pkg.zip");
    fs::create_dir_all(&installed).expect("installed");
    fs::create_dir_all(&store).expect("store");
    // Customer noise that must never affect capture.
    fs::write(installed.join("customer.lua"), b"do not read").expect("noise");
    (installed, store, package)
}

#[test]
fn auto_single_captures_nested_resource() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    let manifest = b"fx_version 'cerulean'\ngame 'gta5'\nversion '1.2.3'\nescrow_ignore {\n  'config.lua'\n}\n";
    write_zip(
        &package,
        &[
            ("gksphone/fxmanifest.lua", manifest),
            ("gksphone/client/main.lua", b"main"),
            ("gksphone/config.lua", b"cfg\n"),
            ("gksphone/stream/prop.ydr", b"propdata"),
            ("readme.txt", b"unassigned"),
        ],
    );

    let result = capture(
        &installed,
        &store,
        &package,
        "gksphone",
        IncomingResourceSelector::AutoSingle,
    );
    assert_eq!(result.resource_key().as_str(), "gksphone");
    assert_eq!(result.resource_label(), "gksphone");
    assert_eq!(result.resource_version(), Some("1.2.3"));
    assert_eq!(
        result.source_package_fingerprint(),
        &package_fingerprint(&package)
    );
    assert_eq!(result.counts().files(), 4);
    assert_eq!(result.counts().ignored_files(), 1);
    assert_eq!(result.unique_blob_count(), 1);
    assert!(result.warnings().is_empty());

    let loaded = load_baseline_bundle(
        &store,
        result.resource_key(),
        result.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    assert_eq!(loaded.files().len(), 4);
    let ignored = loaded
        .files()
        .iter()
        .find(|f| f.relative_path().as_str() == "config.lua")
        .expect("config");
    assert_eq!(ignored.escrow_class(), BaselineEscrowClass::Ignored);
    assert!(ignored.blob_sha256().is_some());
    let protected = loaded
        .files()
        .iter()
        .find(|f| f.relative_path().as_str() == "client/main.lua")
        .expect("main");
    assert_eq!(protected.escrow_class(), BaselineEscrowClass::Protected);
    assert!(protected.blob_sha256().is_none());
}

#[test]
fn multi_resource_requires_explicit_selection() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            ("a/fxmanifest.lua", b"fx_version 'cerulean'\ngame 'gta5'\n"),
            ("b/fxmanifest.lua", b"fx_version 'cerulean'\ngame 'gta5'\n"),
        ],
    );
    let request = BaselineCaptureRequest::try_new(
        &installed,
        &store,
        &package,
        SafeResourceKey::parse("a").unwrap(),
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )
    .unwrap();
    let store = resolve_standalone_baseline_store(&store).unwrap();
    let err =
        capture_official_baseline_in_standalone_store(&store, request).expect_err("ambiguous");
    assert!(matches!(err, GkrmError::BaselineCaptureAmbiguousResources));
}

#[test]
fn explicit_selection_ignores_malformed_sibling_manifest() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            (
                "good/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\nversion '2.0.0'\n",
            ),
            ("good/client.lua", b"print('ok')"),
            ("bad/fxmanifest.lua", b"this is not valid lua {{{"),
            ("bad/client.lua", b"x"),
        ],
    );
    let selector = IncomingResourceSelector::ManifestPackagePath(
        ZipRelativePath::parse_canonical("good/fxmanifest.lua").unwrap(),
    );
    let result = capture(&installed, &store, &package, "good", selector);
    assert_eq!(result.resource_version(), Some("2.0.0"));
    assert_eq!(result.counts().files(), 2);
}

#[test]
fn root_resource_selection_uses_key_label() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            ("fxmanifest.lua", b"fx_version 'cerulean'\ngame 'gta5'\n"),
            ("client.lua", b"main"),
        ],
    );
    let selector = IncomingResourceSelector::ManifestPackagePath(
        ZipRelativePath::parse_canonical("fxmanifest.lua").unwrap(),
    );
    let result = capture(&installed, &store, &package, "rootres", selector);
    assert_eq!(result.resource_label(), "rootres");
    assert_eq!(
        result.warnings(),
        &[
            BaselineCaptureWarning::RootResourceSelected,
            BaselineCaptureWarning::ManifestVersionUnavailable
        ]
    );
}

#[test]
fn live_zip_replacement_after_snapshot_does_not_change_baseline() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"one"),
        ],
    );
    let first_fp = package_fingerprint(&package);
    // Capture in a thread? Fingerprint is from snapshot at create time.
    // Replace after first capture and compare IDs from two captures of original vs replaced.
    let first = capture(
        &installed,
        &store,
        &package,
        "res",
        IncomingResourceSelector::AutoSingle,
    );
    assert_eq!(first.source_package_fingerprint(), &first_fp);

    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"two"),
        ],
    );
    let store2 = temp.path().join("store2");
    fs::create_dir_all(&store2).expect("store2");
    let second = capture(
        &installed,
        &store2,
        &package,
        "res",
        IncomingResourceSelector::AutoSingle,
    );
    assert_ne!(
        first.source_package_fingerprint(),
        second.source_package_fingerprint()
    );
    assert_ne!(first.baseline_id(), second.baseline_id());
}

#[test]
fn policy_a_unrelated_package_bytes_change_baseline_id() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"same"),
            (
                "other/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("other/x.lua", b"old"),
        ],
    );
    let selector = IncomingResourceSelector::ManifestPackagePath(
        ZipRelativePath::parse_canonical("res/fxmanifest.lua").unwrap(),
    );
    let first = capture(&installed, &store, &package, "res", selector.clone());

    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"same"),
            (
                "other/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("other/x.lua", b"new"),
        ],
    );
    let store2 = temp.path().join("store2");
    fs::create_dir_all(&store2).expect("store2");
    let second = capture(&installed, &store2, &package, "res", selector);
    assert_ne!(first.baseline_id(), second.baseline_id());
}

#[test]
fn installed_mutation_does_not_affect_baseline_id() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"body"),
        ],
    );
    let first = capture(
        &installed,
        &store,
        &package,
        "res",
        IncomingResourceSelector::AutoSingle,
    );
    fs::write(installed.join("customer.lua"), b"mutated heavily").expect("mutate");
    fs::write(installed.join("new.lua"), b"extra").expect("extra");
    let store2 = temp.path().join("store2");
    fs::create_dir_all(&store2).expect("store2");
    let second = capture(
        &installed,
        &store2,
        &package,
        "res",
        IncomingResourceSelector::AutoSingle,
    );
    assert_eq!(first.baseline_id(), second.baseline_id());
    assert_eq!(
        fs::read(installed.join("customer.lua")).unwrap(),
        b"mutated heavily"
    );
}

#[test]
fn repeated_capture_is_idempotent() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"body"),
        ],
    );
    let first = capture(
        &installed,
        &store,
        &package,
        "res",
        IncomingResourceSelector::AutoSingle,
    );
    let second = capture(
        &installed,
        &store,
        &package,
        "res",
        IncomingResourceSelector::AutoSingle,
    );
    assert_eq!(first.baseline_id(), second.baseline_id());
    assert_eq!(first.locator(), second.locator());
}

#[test]
fn store_install_overlap_rejected() {
    let temp = tempdir().expect("temp");
    let root = temp.path().join("shared");
    fs::create_dir_all(&root).unwrap();
    let package = temp.path().join("pkg.zip");
    write_zip(
        &package,
        &[(
            "res/fxmanifest.lua",
            b"fx_version 'cerulean'\ngame 'gta5'\n",
        )],
    );
    let request = BaselineCaptureRequest::try_new(
        &root,
        &root,
        &package,
        SafeResourceKey::parse("res").unwrap(),
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )
    .unwrap();
    let store = resolve_standalone_baseline_store(&root).unwrap();
    let err = capture_official_baseline_in_standalone_store(&store, request).expect_err("overlap");
    assert!(matches!(err, GkrmError::BaselineStoreInstallOverlap));
}

#[test]
fn failed_capture_publishes_nothing() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(&package, &[("readme.txt", b"no resource")]);
    let request = BaselineCaptureRequest::try_new(
        &installed,
        &store,
        &package,
        SafeResourceKey::parse("x").unwrap(),
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )
    .unwrap();
    let standalone = resolve_standalone_baseline_store(&store).unwrap();
    let err =
        capture_official_baseline_in_standalone_store(&standalone, request).expect_err("none");
    assert!(matches!(err, GkrmError::BaselineCaptureNoResources));
    assert!(
        !store.join("baselines").exists()
            || store.join("baselines").read_dir().unwrap().next().is_none()
    );
}

#[test]
fn selected_file_limit_enforced() {
    let temp = tempdir().expect("temp");
    let (installed, store, package) = setup_roots(&temp);
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\n",
            ),
            ("res/a.lua", b"a"),
            ("res/b.lua", b"b"),
        ],
    );
    let options = BaselineCaptureOptions::try_new(
        PackageLimits::default(),
        ManifestLimits::default(),
        BaselineStoreLimits::default(),
        1,
        1024 * 1024,
        1024 * 1024 * 1024,
    )
    .unwrap();
    let request = BaselineCaptureRequest::try_new(
        &installed,
        &store,
        &package,
        SafeResourceKey::parse("res").unwrap(),
        IncomingResourceSelector::AutoSingle,
        options,
    )
    .unwrap();
    let store = resolve_standalone_baseline_store(&store).unwrap();
    let err = capture_official_baseline_in_standalone_store(&store, request).expect_err("limit");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureSelectedFileLimit { .. }
    ));
}

#[test]
fn no_apply_or_merge_surface_from_capture_api() {
    let _: fn(
        &gkrm_core::StandaloneBaselineStore,
        BaselineCaptureRequest<'_>,
    ) -> gkrm_core::Result<gkrm_core::BaselineCaptureResult> =
        capture_official_baseline_in_standalone_store;
    let _: fn(
        &Path,
        &SafeResourceKey,
        &BaselineId,
        BaselineStoreLimits,
    ) -> gkrm_core::Result<gkrm_core::StoredBaseline> = load_baseline_bundle;
}
