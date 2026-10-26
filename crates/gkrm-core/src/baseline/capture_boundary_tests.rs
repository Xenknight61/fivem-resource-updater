//! Task 12 capture→spool→provider→writer boundary tests.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter};

use crate::baseline::capture::test_seams::{
    clear_zip_entry_open_counts, hook_lock, list_capture_spools, plant_spool_object,
    production_blob_map_was_sizes_only, set_after_ignored_spooled_hook,
    set_after_snapshot_created_hook, set_before_provider_open_hook, set_before_publish_hook,
    set_during_existing_spool_verify_hook, set_during_ignored_spool_write_hook,
    temporary_spool_budget_for_tests, verify_existing_spool_blob_for_tests, zip_entry_open_count,
};
use crate::baseline::capture::{
    capture_official_baseline_in_standalone_store,
    capture_official_baseline_in_workspace_with_expected_package_commitment,
    BaselineCaptureOptions, BaselineCaptureRequest, ExpectedPackageBaselineCaptureRequest,
    IncomingResourceSelector,
};
use crate::baseline::fs_security::{
    create_new_child_dir, ensure_child_dir, open_or_create_store_root_for_write,
};
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::BaselineStoreLimits;
use crate::baseline::store::load_baseline_bundle;
use crate::manifest::ManifestLimits;
use crate::package_limits::PackageLimits;
use crate::{
    inspect_package_resources, resolve_trusted_update_workspace, GkrmError,
    PackageResourceInspectionOptions, PackageSourceCommitment, Sha256Digest,
    TrustedUpdateWorkspaceOptions,
};

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

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    let store = temp.path().join("store");
    let package = temp.path().join("pkg.zip");
    fs::create_dir_all(&installed).unwrap();
    fs::create_dir_all(&store).unwrap();
    (temp, installed, store, package)
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

fn inspected_commitment(package: &Path) -> PackageSourceCommitment {
    inspect_package_resources(package, PackageResourceInspectionOptions::default())
        .expect("inspect package")
        .package_commitment()
}

fn capture_bound(
    workspace: &crate::TrustedUpdateWorkspace,
    installed: &Path,
    package: &Path,
    expected: PackageSourceCommitment,
) -> Result<crate::baseline::capture::BaselineCaptureResult, GkrmError> {
    let request = ExpectedPackageBaselineCaptureRequest::try_new(
        installed,
        package,
        expected,
        SafeResourceKey::parse("res").unwrap(),
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )?;
    capture_official_baseline_in_workspace_with_expected_package_commitment(
        workspace,
        request,
        TrustedUpdateWorkspaceOptions::default(),
    )
}

fn assert_no_published_baseline(store: &Path) {
    let baselines = store.join("baselines");
    if !baselines.exists() {
        return;
    }
    for key_entry in fs::read_dir(&baselines).unwrap() {
        let key_path = key_entry.unwrap().path();
        if key_path.is_dir() {
            let mut ids = fs::read_dir(&key_path).unwrap();
            assert!(
                ids.next().is_none(),
                "unexpected published baseline under {}",
                key_path.display()
            );
        }
    }
}

fn display_contains_any(err: &GkrmError, needles: &[&str]) -> bool {
    let text = err.to_string();
    needles.iter().any(|n| text.contains(n))
}

#[test]
fn live_zip_replacement_during_capture_uses_snapshot_only() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let original_fp = digest_of(&fs::read(&package).unwrap());

    set_after_snapshot_created_hook(&package, {
        let package = package.clone();
        move |_| {
            write_zip(
                &package,
                &[
                    (
                        "res/fxmanifest.lua",
                        b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'config.lua'\n}\n",
                    ),
                    ("res/config.lua", b"REPLACED"),
                    ("res/client.lua", b"changed-protected"),
                ],
            );
        }
    });

    let result = capture_default(&installed, &store, &package).expect("capture");
    assert_eq!(result.source_package_fingerprint(), &original_fp);

    let loaded = load_baseline_bundle(
        &store,
        result.resource_key(),
        result.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    let config = loaded
        .files()
        .iter()
        .find(|f| f.relative_path().as_str() == "config.lua")
        .expect("config");
    assert_eq!(config.sha256(), &digest_of(b"cfg-body"));
    assert_ne!(config.sha256(), &digest_of(b"REPLACED"));
}

#[test]
fn bound_capture_rejects_same_length_replacement_before_publication() {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    let package = temp.path().join("previous.zip");
    fs::create_dir(&installed).unwrap();
    ignored_package(&package);
    let original = fs::read(&package).unwrap();
    let expected = inspected_commitment(&package);

    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'config.lua'\n}\n",
            ),
            ("res/config.lua", b"NEW-body"),
            ("res/client.lua", b"intruder!"),
        ],
    );
    let replacement = fs::read(&package).unwrap();
    assert_eq!(original.len(), replacement.len());
    assert_ne!(original, replacement);

    let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
    let err = capture_bound(&workspace, &installed, &package, expected)
        .expect_err("changed package must fail");
    assert!(matches!(err, GkrmError::BaselineCapturePackageChanged));
    assert_no_published_baseline(workspace.baseline_store());
}

#[test]
fn bound_capture_accepts_matching_commitment_and_stores_it() {
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    let package = temp.path().join("previous.zip");
    fs::create_dir(&installed).unwrap();
    ignored_package(&package);
    let expected = inspected_commitment(&package);
    let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();

    let result = capture_bound(&workspace, &installed, &package, expected)
        .expect("matching capture must succeed");
    assert_eq!(result.source_package_fingerprint(), expected.fingerprint());
    let stored = load_baseline_bundle(
        workspace.baseline_store(),
        result.resource_key(),
        result.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load captured baseline");
    assert_eq!(
        stored.source_package_fingerprint(),
        Some(expected.fingerprint())
    );
}

#[test]
fn bound_capture_consumes_verified_snapshot_after_source_path_replacement() {
    let _guard = hook_lock();
    let temp = tempdir().expect("temp");
    let installed = temp.path().join("installed");
    let package = temp.path().join("previous.zip");
    fs::create_dir(&installed).unwrap();
    ignored_package(&package);
    let expected = inspected_commitment(&package);
    let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();

    set_after_snapshot_created_hook(&package, {
        let package = package.clone();
        move |_| {
            write_zip(
                &package,
                &[
                    (
                        "res/fxmanifest.lua",
                        b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'config.lua'\n}\n",
                    ),
                    ("res/config.lua", b"REPLACED"),
                    ("res/client.lua", b"changed-protected"),
                ],
            );
        }
    });

    let result = capture_bound(&workspace, &installed, &package, expected)
        .expect("verified snapshot remains authoritative");
    assert_eq!(result.source_package_fingerprint(), expected.fingerprint());
    let stored = load_baseline_bundle(
        workspace.baseline_store(),
        result.resource_key(),
        result.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load captured baseline");
    let config = stored
        .files()
        .iter()
        .find(|file| file.relative_path().as_str() == "config.lua")
        .expect("config file");
    assert_eq!(config.sha256(), &digest_of(b"cfg-body"));
    assert_ne!(config.sha256(), &digest_of(b"REPLACED"));
}

#[test]
fn post_spool_byte_mutation_rejects_before_publish() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let installed_before = fs::read_dir(&installed).unwrap().count();

    set_after_ignored_spooled_hook({
        let store = store.clone();
        move |digest, _spool_dir| {
            let name = digest.to_string();
            for spool in list_capture_spools(&store) {
                fs::write(spool.join(&name), b"mutated-spool-bytes").expect("mutate");
            }
            Ok(())
        }
    });

    let err = capture_default(&installed, &store, &package).expect_err("mutated spool");
    assert!(
        matches!(
            err,
            GkrmError::BaselineBlobDigestMismatch { .. }
                | GkrmError::BaselineCaptureBlobVerificationFailed
                | GkrmError::BaselineCaptureSpoolIdentityChanged
                | GkrmError::BaselineCaptureSpoolVerificationFailure
                | GkrmError::BaselineBlobSizeMismatch { .. }
                | GkrmError::BaselineStoreUnexpectedType { .. }
                | GkrmError::BaselineStoreIo { .. }
                | GkrmError::BaselineCaptureStoreFailure { .. }
        ),
        "unexpected {err:?}"
    );
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
    assert_eq!(fs::read_dir(&installed).unwrap().count(), installed_before);
}

#[test]
fn post_spool_replacement_rejects_before_publish() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);

    set_after_ignored_spooled_hook({
        let store = store.clone();
        move |digest, _spool_dir| {
            let name = digest.to_string();
            for spool in list_capture_spools(&store) {
                let target = spool.join(&name);
                let _ = fs::remove_file(&target);
                fs::write(&target, b"replacement-bytes!!").expect("replace");
            }
            Ok(())
        }
    });

    let err = capture_default(&installed, &store, &package).expect_err("replaced spool");
    assert!(list_capture_spools(&store).is_empty());
    let _ = err;
}

#[cfg(unix)]
#[test]
fn post_spool_symlink_substitution_rejects_before_publish() {
    let _guard = hook_lock();
    let (temp, installed, store, package) = setup();
    ignored_package(&package);
    let outside = temp.path().join("outside-blob");
    fs::write(&outside, b"outside-payload").unwrap();

    set_after_ignored_spooled_hook({
        let store = store.clone();
        let outside = outside.clone();
        move |digest, _spool_dir| {
            let name = digest.to_string();
            for spool in list_capture_spools(&store) {
                let target = spool.join(&name);
                let _ = fs::remove_file(&target);
                std::os::unix::fs::symlink(&outside, &target).expect("symlink");
            }
            Ok(())
        }
    });

    let err = capture_default(&installed, &store, &package).expect_err("symlink spool");
    assert!(matches!(
        err,
        GkrmError::BaselineStoreSymlink { .. }
            | GkrmError::BaselineCaptureIgnoredBlobMissing
            | GkrmError::BaselineStoreIo { .. }
            | GkrmError::BaselineStoreReparsePoint { .. }
    ));
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn concurrent_identical_captures_are_idempotent() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let installed = Arc::new(installed);
    let store = Arc::new(store);
    let package = Arc::new(package);

    let mut handles = Vec::new();
    for _ in 0..4 {
        let installed = Arc::clone(&installed);
        let store = Arc::clone(&store);
        let package = Arc::clone(&package);
        handles.push(std::thread::spawn(move || {
            capture_default(&installed, &store, &package)
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    let oks: Vec<_> = results.into_iter().filter_map(Result::ok).collect();
    assert!(!oks.is_empty());
    let first = &oks[0];
    for other in &oks {
        assert_eq!(other.baseline_id(), first.baseline_id());
    }
    let loaded = load_baseline_bundle(
        &store,
        first.resource_key(),
        first.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("single valid bundle");
    assert_eq!(loaded.files().len(), 3);
}

#[test]
fn concurrent_capture_against_corrupted_same_id_conflicts() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let first = capture_default(&installed, &store, &package).expect("first");
    let baseline_dir = store
        .join("baselines")
        .join(first.resource_key().as_str())
        .join(first.baseline_id().as_str());
    let manifest = baseline_dir.join("baseline.json");
    let mut bytes = fs::read(&manifest).unwrap();
    // Corrupt a non-identity JSON field while keeping the document parseable enough to conflict.
    if let Some(pos) = bytes.windows(7).position(|w| w == b"\"files\"") {
        bytes[pos + 1] = b'x';
    } else {
        bytes.push(b' ');
    }
    fs::write(&manifest, &bytes).unwrap();

    let err = capture_default(&installed, &store, &package).expect_err("conflict");
    assert!(
        matches!(
            err,
            GkrmError::BaselineExistingConflict { .. }
                | GkrmError::BaselineCaptureBaselineConflict
                | GkrmError::BaselineIncompleteBundle { .. }
                | GkrmError::BaselineIdMismatch { .. }
                | GkrmError::BaselineInvalidOrdering { .. }
                | GkrmError::BaselineInvalidHash { .. }
                | GkrmError::BaselineCaptureBundleConstruction { .. }
                | GkrmError::BaselineCaptureBlobVerificationFailed
        ),
        "unexpected {err:?}"
    );
}

#[test]
fn symlinked_package_is_rejected_by_capture_api() {
    let _guard = hook_lock();
    let (temp, installed, store, package) = setup();
    ignored_package(&package);
    let link = temp.path().join("pkg-link.zip");
    if !try_symlink_file(&package, &link) {
        return;
    }
    let err = capture_default(&installed, &store, &link).expect_err("symlink package");
    assert!(matches!(
        err,
        GkrmError::BaselineCapturePackageSymlink
            | GkrmError::BaselineCapturePackageOpen { .. }
            | GkrmError::BaselineCapturePackagePathInvalid
    ));
    assert!(!display_contains_any(
        &err,
        &[
            package.to_string_lossy().as_ref(),
            link.to_string_lossy().as_ref(),
            store.to_string_lossy().as_ref(),
            installed.to_string_lossy().as_ref(),
        ]
    ));
}

#[test]
fn symlinked_package_parent_is_rejected_by_capture_api() {
    let _guard = hook_lock();
    let (temp, installed, store, package) = setup();
    ignored_package(&package);
    let real_parent = temp.path().join("real-parent");
    let link_parent = temp.path().join("link-parent");
    fs::create_dir_all(&real_parent).unwrap();
    let real_pkg = real_parent.join("pkg.zip");
    fs::rename(&package, &real_pkg).unwrap();
    if !try_symlink_dir(&real_parent, &link_parent) {
        return;
    }
    let linked_pkg = link_parent.join("pkg.zip");
    let err = capture_default(&installed, &store, &linked_pkg).expect_err("symlink parent");
    assert!(matches!(
        err,
        GkrmError::BaselineCapturePackageSymlink
            | GkrmError::BaselineCapturePackageOpen { .. }
            | GkrmError::BaselineCapturePackagePathInvalid
            | GkrmError::BaselineCapturePackageReparsePoint
    ));
    assert!(!display_contains_any(
        &err,
        &[
            linked_pkg.to_string_lossy().as_ref(),
            store.to_string_lossy().as_ref(),
            installed.to_string_lossy().as_ref(),
        ]
    ));
}

#[cfg(windows)]
#[test]
fn junction_package_parent_is_rejected_where_supported() {
    let _guard = hook_lock();
    let (temp, installed, store, package) = setup();
    ignored_package(&package);
    let real_parent = temp.path().join("real-junc");
    let link_parent = temp.path().join("junc-parent");
    fs::create_dir_all(&real_parent).unwrap();
    let real_pkg = real_parent.join("pkg.zip");
    fs::rename(&package, &real_pkg).unwrap();
    if !try_junction(&real_parent, &link_parent) {
        return;
    }
    let linked_pkg = link_parent.join("pkg.zip");
    let err = capture_default(&installed, &store, &linked_pkg).expect_err("junction parent");
    assert!(matches!(
        err,
        GkrmError::BaselineCapturePackageReparsePoint
            | GkrmError::BaselineCapturePackageSymlink
            | GkrmError::BaselineCapturePackageOpen { .. }
            | GkrmError::BaselineCapturePackagePathInvalid
    ));
}

#[test]
fn unreadable_and_linklike_installed_children_do_not_block_capture() {
    let _guard = hook_lock();
    let (temp, installed, store, package) = setup();
    ignored_package(&package);
    let child = installed.join("nested");
    fs::create_dir_all(&child).unwrap();
    fs::write(child.join("secret.lua"), b"secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(child.join("secret.lua"), fs::Permissions::from_mode(0o000));
        let target = temp.path().join("outside.lua");
        fs::write(&target, b"x").unwrap();
        let _ = std::os::unix::fs::symlink(&target, installed.join("link.lua"));
    }
    #[cfg(windows)]
    {
        let target = temp.path().join("outside.lua");
        fs::write(&target, b"x").unwrap();
        let _ = std::os::windows::fs::symlink_file(&target, installed.join("link.lua"));
    }

    let result =
        capture_default(&installed, &store, &package).expect("capture ignores installed children");
    assert_eq!(result.counts().files(), 3);
    assert!(installed.join("secret.lua").exists() || cfg!(windows));
}

#[test]
fn failure_during_spool_write_cleans_capture_spool() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_during_ignored_spool_write_hook(|| Err(GkrmError::BaselineCaptureTestSeamFailure));
    let err = capture_default(&installed, &store, &package).expect_err("spool write fail");
    assert!(matches!(err, GkrmError::BaselineCaptureTestSeamFailure));
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
}

#[test]
fn failure_during_provider_open_cleans_capture_spool() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_before_provider_open_hook(|_| Err(GkrmError::BaselineCaptureTestSeamFailure));
    let err = capture_default(&installed, &store, &package).expect_err("provider open fail");
    assert!(matches!(err, GkrmError::BaselineCaptureTestSeamFailure));
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn failure_during_writer_copy_cleans_capture_spool() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let _writer_guard = crate::baseline::capture::test_seams::set_during_writer_copy_hook(|| {
        Err(GkrmError::BaselineCaptureTestSeamFailure)
    });
    let err = capture_default(&installed, &store, &package).expect_err("writer copy fail");
    assert!(matches!(err, GkrmError::BaselineCaptureTestSeamFailure));
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
}

#[test]
fn failure_before_publish_cleans_capture_spool() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    set_before_publish_hook(|| Err(GkrmError::BaselineCaptureTestSeamFailure));
    let err = capture_default(&installed, &store, &package).expect_err("publish fail");
    assert!(matches!(err, GkrmError::BaselineCaptureTestSeamFailure));
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn one_pass_ignored_entry_opened_once_and_sizes_only_map() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    clear_zip_entry_open_counts();
    ignored_package(&package);
    let _ = capture_default(&installed, &store, &package).expect("capture");
    let opens: Vec<u64> = (0..8)
        .map(zip_entry_open_count)
        .filter(|c| *c > 0)
        .collect();
    assert!(!opens.is_empty());
    assert!(opens.iter().all(|c| *c == 1), "opens={opens:?}");
    assert!(production_blob_map_was_sizes_only());
}

#[test]
fn total_blob_limit_first_unique_fails_and_cleans() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    ignored_package(&package);
    let limits = BaselineStoreLimits::new(1024 * 1024, 4, 4, 8).unwrap();
    let options = BaselineCaptureOptions::try_new(
        PackageLimits::default(),
        ManifestLimits::default(),
        limits,
        100,
        1024 * 1024,
        1024 * 1024,
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
    let standalone = crate::resolve_standalone_baseline_store(&store).unwrap();
    let err = capture_official_baseline_in_standalone_store(&standalone, request)
        .expect_err("total limit");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureTotalBlobLimitExceeded { .. }
            | GkrmError::BaselineCaptureBlobSizeLimitExceeded { .. }
            | GkrmError::BaselineTotalBlobLimitExceeded { .. }
            | GkrmError::BaselineCaptureBundleConstruction { .. }
    ));
    assert!(list_capture_spools(&store).is_empty());
}

#[test]
fn duplicate_digest_does_not_increase_unique_total() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'a.lua',\n  'b.lua'\n}\n",
            ),
            ("res/a.lua", b"same-bytes"),
            ("res/b.lua", b"same-bytes"),
        ],
    );
    // max_total allows only one unique blob of 10 bytes
    let limits = BaselineStoreLimits::new(1024 * 1024, 16, 10, 10).unwrap();
    let options = BaselineCaptureOptions::try_new(
        PackageLimits::default(),
        ManifestLimits::default(),
        limits,
        100,
        1024 * 1024,
        1024 * 1024,
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
    let standalone = crate::resolve_standalone_baseline_store(&store).unwrap();
    let result =
        capture_official_baseline_in_standalone_store(&standalone, request).expect("dup digests");
    assert_eq!(result.unique_blob_count(), 1);
    assert_eq!(result.total_unique_blob_bytes(), 10);
}

#[test]
fn capture_error_display_redacts_absolute_paths() {
    let _guard = hook_lock();
    let (temp, installed, store, package) = setup();
    ignored_package(&package);
    let missing = temp.path().join("missing-dir").join("nope.zip");
    let request = BaselineCaptureRequest::try_new(
        &installed,
        &store,
        &missing,
        SafeResourceKey::parse("res").unwrap(),
        IncomingResourceSelector::AutoSingle,
        BaselineCaptureOptions::default(),
    )
    .unwrap();
    let standalone = crate::resolve_standalone_baseline_store(&store).unwrap();
    let err =
        capture_official_baseline_in_standalone_store(&standalone, request).expect_err("missing");
    let text = err.to_string();
    assert!(
        !text.contains(missing.to_string_lossy().as_ref()),
        "leaked package path: {text}"
    );
    assert!(!text.contains(store.to_string_lossy().as_ref()));
    assert!(!text.contains(installed.to_string_lossy().as_ref()));
}

#[test]
fn existing_spool_wrong_bytes_fail_closed() {
    let _guard = hook_lock();
    let temp = tempdir().unwrap();
    let store = open_or_create_store_root_for_write(temp.path()).unwrap();
    let tmp = ensure_child_dir(&store.dir, ".tmp").unwrap();
    let spool = create_new_child_dir(&tmp, "capture-test").unwrap();
    let digest = digest_of(b"correct");
    plant_spool_object(&spool, &digest, b"wrong!!!").unwrap();
    let err = verify_existing_spool_blob_for_tests(&spool, &digest, 7).expect_err("wrong bytes");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureSpoolVerificationFailure
            | GkrmError::BaselineCaptureIgnoredBlobSizeMismatch { .. }
    ));
}

#[test]
fn existing_spool_wrong_size_fail_closed() {
    let _guard = hook_lock();
    let temp = tempdir().unwrap();
    let store = open_or_create_store_root_for_write(temp.path()).unwrap();
    let tmp = ensure_child_dir(&store.dir, ".tmp").unwrap();
    let spool = create_new_child_dir(&tmp, "capture-test2").unwrap();
    let digest = digest_of(b"abcdefg");
    plant_spool_object(&spool, &digest, b"abcdefg").unwrap();
    let err = verify_existing_spool_blob_for_tests(&spool, &digest, 3).expect_err("wrong size");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureIgnoredBlobSizeMismatch { .. }
    ));
}

#[test]
fn existing_spool_identical_reuses() {
    let _guard = hook_lock();
    let temp = tempdir().unwrap();
    let store = open_or_create_store_root_for_write(temp.path()).unwrap();
    let tmp = ensure_child_dir(&store.dir, ".tmp").unwrap();
    let spool = create_new_child_dir(&tmp, "capture-test3").unwrap();
    let bytes = b"identical-spool";
    let digest = digest_of(bytes);
    plant_spool_object(&spool, &digest, bytes).unwrap();
    verify_existing_spool_blob_for_tests(&spool, &digest, bytes.len() as u64).expect("ok");
}

#[test]
fn existing_spool_mutation_during_verify_fails() {
    let _guard = hook_lock();
    let temp = tempdir().unwrap();
    let store_path = temp.path().to_path_buf();
    let store = open_or_create_store_root_for_write(&store_path).unwrap();
    let tmp = ensure_child_dir(&store.dir, ".tmp").unwrap();
    let spool = create_new_child_dir(&tmp, "capture-test4").unwrap();
    let bytes = b"stable-content";
    let digest = digest_of(bytes);
    plant_spool_object(&spool, &digest, bytes).unwrap();
    set_during_existing_spool_verify_hook({
        let store_path = store_path.clone();
        move |digest, _| {
            let path = store_path
                .join(".tmp")
                .join("capture-test4")
                .join(digest.to_string());
            let _ = fs::write(path, b"mutated-during-verify!!!!");
            Ok(())
        }
    });
    let err = verify_existing_spool_blob_for_tests(&spool, &digest, bytes.len() as u64)
        .expect_err("mutated");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureSpoolIdentityChanged
            | GkrmError::BaselineCaptureSpoolVerificationFailure
            | GkrmError::BaselineCaptureIgnoredBlobSizeMismatch { .. }
    ));
}

#[test]
fn later_unique_blob_exceeds_remaining_total() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'a.lua',\n  'b.lua'\n}\n",
            ),
            ("res/a.lua", b"aaaaa"),
            ("res/b.lua", b"bbbbb"),
        ],
    );
    // First unique (5) fits; second unique would make 10 > 8.
    let limits = BaselineStoreLimits::new(1024 * 1024, 16, 5, 8).unwrap();
    let options = BaselineCaptureOptions::try_new(
        PackageLimits::default(),
        ManifestLimits::default(),
        limits,
        100,
        1024 * 1024,
        1024 * 1024,
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
    let standalone = crate::resolve_standalone_baseline_store(&store).unwrap();
    let err = capture_official_baseline_in_standalone_store(&standalone, request)
        .expect_err("second unique");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureTotalBlobLimitExceeded { .. }
            | GkrmError::BaselineCaptureBundleConstruction { .. }
    ));
    assert!(list_capture_spools(&store).is_empty());
    assert_no_published_baseline(&store);
}

#[test]
fn temporary_spool_budget_checked_add_overflow() {
    let _guard = hook_lock();
    let err = temporary_spool_budget_for_tests(u64::MAX, 1).expect_err("overflow");
    assert!(matches!(
        err,
        GkrmError::BaselineCaptureSpoolBudgetExceeded { .. }
    ));
}

#[test]
fn per_blob_limit_uses_resource_relative_path_not_digest_field() {
    let _guard = hook_lock();
    let (_temp, installed, store, package) = setup();
    write_zip(
        &package,
        &[
            (
                "res/fxmanifest.lua",
                b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore {\n  'big.lua'\n}\n",
            ),
            ("res/big.lua", b"0123456789abcdef"),
        ],
    );
    let limits = BaselineStoreLimits::new(1024 * 1024, 8, 8, 1024 * 1024).unwrap();
    let options = BaselineCaptureOptions::try_new(
        PackageLimits::default(),
        ManifestLimits::default(),
        limits,
        100,
        1024 * 1024,
        1024 * 1024,
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
    let store = crate::resolve_standalone_baseline_store(&store).unwrap();
    let err = capture_official_baseline_in_standalone_store(&store, request).expect_err("per-blob");
    match &err {
        GkrmError::BaselineCaptureBlobSizeLimitExceeded { limit, actual } => {
            assert!(*limit > 0);
            assert!(*actual > *limit);
        }
        other => panic!("unexpected {other:?}"),
    }
    let text = err.to_string();
    assert!(
        !text.contains("big.lua") && !text.contains("digest"),
        "per-blob limit must not expose path or digest wording: {text}"
    );
}

fn try_symlink_file(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
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

#[cfg(windows)]
fn try_junction(target: &Path, link: &Path) -> bool {
    std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.to_string_lossy(),
            &target.to_string_lossy(),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
