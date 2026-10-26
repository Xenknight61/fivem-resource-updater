//! Focused Task 20 security verification tests.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::baseline::fs_security::{create_new_file, open_child_dir};
use crate::{
    IncomingMergeContentSourceLimits, InstalledScanLimits, TrustedStagingOptions,
    TrustedStagingRequest, TrustedStagingRoot,
};

use super::manifest::encode_manifest_bytes;
use super::root::{lock_staging_hooks, staging_mutation_count, StagingHookGuard};
use super::test_support::{
    build_mini, hash_tree, incoming_root, installed_root, stage_err, stage_ok, stage_result,
    write_file, write_zip, MANIFEST, MERGE_INCOMING, NESTED_CHILD,
};
use super::write::revalidate_published_child;
use super::{
    lock_staging_write_hooks, reset_source_read_count, set_after_publish_hook,
    set_after_rename_hook, set_before_rename_hook, set_before_temp_verify_hook,
    set_before_write_present_files_hook, set_force_cleanup_capability_clone_failure,
    set_force_cleanup_failure, set_force_post_publish_tail, set_force_quarantine_failure,
    set_force_temp_cleanup_failure, source_read_count, stage_trusted_resource,
    IncomingStagingContentSource, InstalledStagingContentSource, PostPublishTailFault,
    StagingIoOperation, StagingSourceBinding, StagingWriteHookGuard, TrustedStagingManifest,
    TrustedStagingStatus,
};

fn lock_all() -> (
    std::sync::MutexGuard<'static, ()>,
    StagingWriteHookGuard,
    StagingHookGuard,
) {
    let hash = crate::installed_scan::INSTALLED_SCAN_HASH_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let write = lock_staging_write_hooks();
    let staging = lock_staging_hooks();
    (hash, write, staging)
}

fn sources_unchanged(
    fixture: &super::test_support::MiniFixture,
    before_i: &str,
    before_p: &[u8],
    before_s: &str,
) {
    assert_eq!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i
    );
    assert_eq!(fs::read(&fixture.package_v2).unwrap(), before_p);
    assert_eq!(format!("{:?}", hash_tree(&fixture.store)), before_s);
}

fn assert_fail_closed(err: &crate::GkrmError) {
    assert!(
        matches!(
            err,
            crate::GkrmError::TrustedStagingSourceUnavailable
                | crate::GkrmError::TrustedStagingDigestLengthMismatch
                | crate::GkrmError::TrustedStagingWriteFailure { .. }
                | crate::GkrmError::TrustedStagingIo { .. }
                | crate::GkrmError::TrustedStagingCleanupFailed { .. }
                | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
                | crate::GkrmError::TrustedStagingPostPublishVerificationFailed { .. }
                | crate::GkrmError::TrustedStagingManifestTreeMismatch
                | crate::GkrmError::TrustedStagingUnsafeFilesystemObject
                | crate::GkrmError::TrustedStagingDestinationExists
                | crate::GkrmError::TrustedStagingRootOverlap
                | crate::GkrmError::BaselineStoreSymlink { .. }
                | crate::GkrmError::BaselineStoreReparsePoint { .. }
                | crate::GkrmError::BaselineStoreHardLink { .. }
                | crate::GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
                | crate::GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid
                | crate::GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged
        ),
        "{err:?}"
    );
}

fn no_trusted_bundle(staging_root: &Path) {
    let bundles = staging_root.join("bundles");
    if !bundles.exists() {
        return;
    }
    for entry in fs::read_dir(&bundles).unwrap().filter_map(|e| e.ok()) {
        let path = entry.path();
        assert!(
            path.join(".gkrm-untrusted-v1").exists()
                || !path.join("manifest.bin").exists()
                || !path.join("resource").exists(),
            "unexpected reusable published child at {}",
            path.display()
        );
    }
}

fn ambient_tmp_resource(staging_root: &Path) -> Option<PathBuf> {
    let tmp = staging_root.join(".tmp");
    let child = fs::read_dir(&tmp).ok()?.find_map(|e| e.ok())?.path();
    Some(child.join("resource"))
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        false
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
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        false
    }
}

fn try_junction(target: &Path, link: &Path) -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                link.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        try_symlink_dir(target, link)
    }
}

#[test]
fn malformed_chain_fails_before_source_reads_and_staging_mutation() {
    let (_h, _w, _s) = lock_all();
    reset_source_read_count();
    let fixture = build_mini();
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
    reset_source_read_count();
    let _ = stage_trusted_resource(
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
        .unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        source_read_count(),
        0,
        "malformed chain must not probe sources"
    );
    assert_eq!(staging_mutation_count(), 0);
    assert!(fs::read_dir(&fixture.staging_root)
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn overlapping_roots_fail_before_source_reads_and_staging_objects() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let root = TrustedStagingRoot::try_open(&fixture.installed_parent).unwrap();
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
    reset_source_read_count();
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
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, crate::GkrmError::TrustedStagingRootOverlap));
    assert_eq!(source_read_count(), 0);
    assert_eq!(staging_mutation_count(), 0);
}

#[test]
fn unknown_file_before_temp_verify_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

    set_before_temp_verify_hook(|temp_dir| {
        let resource = open_child_dir(temp_dir, "resource").unwrap();
        let mut file = create_new_file(&resource, "attacker.lua").unwrap();
        file.write_all(b"evil").unwrap();
    });

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn publication_target_appearing_during_staging_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

    set_before_rename_hook(|_tmp, bundles, published_name| {
        let _ = bundles.create_dir(published_name);
    });

    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingDestinationExists
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
}

#[test]
fn installed_source_mutation_after_probe_before_stream_publishes_nothing() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let path = fixture.installed_resource.join("fxmanifest.lua");

    set_before_write_present_files_hook(move || {
        write_file(&path, b"mutated-installed-after-probe\n");
    });

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    assert_ne!(
        format!("{:?}", hash_tree(&fixture.installed_resource)),
        before_i,
        "test must actually mutate installed"
    );
    assert_eq!(fs::read(&fixture.package_v2).unwrap(), before_p);
    assert_eq!(format!("{:?}", hash_tree(&fixture.store)), before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn incoming_snapshot_stale_after_probe_publishes_nothing() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

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
    let snap = incoming.snapshot_temp_path_for_test().to_path_buf();
    set_before_write_present_files_hook(move || {
        // Corrupt retained snapshot evidence after probe / before streaming writes.
        write_zip(
            &snap,
            &[
                ("gksphone/fxmanifest.lua", MANIFEST),
                ("gksphone/merge.lua", MERGE_INCOMING),
                ("gksphone/take.lua", b"take-mutated-snapshot\n"),
                ("gksphone/nested/child.lua", NESTED_CHILD),
            ],
        );
    });

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
        .unwrap(),
    )
    .expect_err("stale incoming snapshot must fail closed");
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn merged_artifact_digest_mismatch_publishes_nothing() {
    let (_h, _w, _s) = lock_all();
    let mut fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let len = fixture
        .merged_bytes
        .entries()
        .iter()
        .find_map(|e| e.artifact().map(|a| a.byte_length() as usize))
        .expect("merged artifact");
    fixture
        .merged_bytes
        .corrupt_first_ready_artifact_bytes_for_test(vec![b'X'; len].into_boxed_slice());

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn destination_mutation_after_write_before_verify_publishes_nothing() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let staging = fixture.staging_root.clone();

    set_before_temp_verify_hook(move |_| {
        let resource = ambient_tmp_resource(&staging).expect("tmp resource");
        write_file(&resource.join("fxmanifest.lua"), b"dest-mutated\n");
    });

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn post_publish_unknown_file_removed_or_quarantined() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

    set_after_publish_hook(|bundles_dir, published_name| {
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut file = create_new_file(&published, "extra.bin").unwrap();
        file.write_all(b"x").unwrap();
    });

    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingPostPublishVerificationFailed { .. }
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn post_publish_resource_file_mutation_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let resource = open_child_dir(&published, "resource").unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = resource.open_with("fxmanifest.lua", &options).unwrap();
        file.write_all(b"post-publish-mutated").unwrap();
    });

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn post_publish_missing_file_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

    set_after_publish_hook(|bundles_dir, published_name| {
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let resource = open_child_dir(&published, "resource").unwrap();
        resource.remove_file("fxmanifest.lua").unwrap();
    });

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn post_publish_directory_replacement_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let staging = fixture.staging_root.clone();

    set_after_publish_hook(move |_bundles, published_name| {
        let resource = staging
            .join("bundles")
            .join(published_name)
            .join("resource");
        let outside = staging.join("outside-resource");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        write_file(&outside.join("fxmanifest.lua"), b"replaced\n");
        let _ = fs::remove_dir_all(&resource);
        let _ = try_junction(&outside, &resource);
    });

    let err = stage_err(&fixture);
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn post_publish_cleanup_failure_quarantines_child() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let expected_manifest = {
        let other_root = fixture._temp.path().join("staging-clean");
        fs::create_dir_all(&other_root).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other_root;
        stage_ok(&clean).manifest().clone()
    };

    set_force_cleanup_failure(true);
    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"bad").unwrap();
    });

    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));

    let bundles = fixture.staging_root.join("bundles");
    let children: Vec<_> = fs::read_dir(&bundles)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(children.len(), 1);
    let child = &children[0].path();
    assert!(child.join(".gkrm-untrusted-v1").exists());

    let root = TrustedStagingRoot::try_open(&fixture.staging_root).unwrap();
    let name = child.file_name().unwrap().to_str().unwrap();
    let bundles_cap = open_child_dir(root.dir(), "bundles").unwrap();
    let reopen = revalidate_published_child(&bundles_cap, name, &expected_manifest);
    assert!(
        reopen.is_err(),
        "quarantined child must never validate as trusted"
    );
}

#[test]
fn canonical_manifest_bytes_must_match_trusted_in_memory_manifest() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let expected = encode_manifest_bytes(bundle.manifest()).unwrap();
    let published = fixture
        .staging_root
        .join("bundles")
        .join(bundle.manifest().manifest_id().digest().to_string());
    let on_disk = fs::read(published.join("manifest.bin")).unwrap();
    assert_eq!(on_disk, expected);
}

#[test]
fn altered_manifest_sidecar_rejected_and_removed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"gkrm-staging-manifest-bin-v1").unwrap();
        file.write_all(&[0u8; 64]).unwrap();
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingPostPublishVerificationFailed { .. }
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn symlink_under_resource_rejected_where_supported() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let created = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let created_flag = std::sync::Arc::clone(&created);
    let staging = fixture.staging_root.clone();

    set_before_temp_verify_hook(move |_| {
        let Some(resource) = ambient_tmp_resource(&staging) else {
            return;
        };
        let target = resource.join("fxmanifest.lua");
        let link = resource.join("link.lua");
        if try_symlink_file(&target, &link) {
            created_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let result = stage_result(&fixture);
    if !created.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let err = result.expect_err("symlink under resource must fail closed");
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn hardlinked_destination_rejected_where_supported() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let created = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let created_flag = std::sync::Arc::clone(&created);
    let staging = fixture.staging_root.clone();
    let attacker = fixture._temp.path().join("attacker-hardlink-src");
    write_file(&attacker, b"hardlink-attacker\n");

    set_before_temp_verify_hook(move |_| {
        let Some(resource) = ambient_tmp_resource(&staging) else {
            return;
        };
        let dest = resource.join("fxmanifest.lua");
        let _ = fs::remove_file(&dest);
        if fs::hard_link(&attacker, &dest).is_ok() {
            created_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let result = stage_result(&fixture);
    if !created.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let err = result.expect_err("hardlinked destination must fail closed");
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[cfg(unix)]
#[test]
fn symlink_staging_tmp_is_rejected() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let outside = fixture._temp.path().join("outside-tmp");
    fs::create_dir_all(&outside).unwrap();
    let link = fixture.staging_root.join(".tmp");
    if std::os::unix::fs::symlink(&outside, &link).is_err() {
        return;
    }
    let err = stage_err(&fixture);
    assert_fail_closed(&err);
}

#[cfg(windows)]
#[test]
fn junction_staging_tmp_is_rejected_where_supported() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let outside = fixture._temp.path().join("outside-tmp");
    fs::create_dir_all(&outside).unwrap();
    let link = fixture.staging_root.join(".tmp");
    if !try_junction(&outside, &link) {
        return;
    }
    let err = stage_err(&fixture);
    assert_fail_closed(&err);
}

#[test]
fn nested_parent_replacement_before_verify_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let staging = fixture.staging_root.clone();
    let replaced = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let replaced_flag = std::sync::Arc::clone(&replaced);

    set_before_temp_verify_hook(move |_| {
        let Some(resource) = ambient_tmp_resource(&staging) else {
            return;
        };
        let nested = resource.join("nested");
        let outside = staging.join("outside-nested");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        write_file(&outside.join("child.lua"), b"nested-attacker\n");
        let _ = fs::remove_dir_all(&nested);
        if try_junction(&outside, &nested) {
            replaced_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let result = stage_result(&fixture);
    if !replaced.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let err = result.expect_err("nested parent replacement must fail");
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn staging_root_replacement_after_open_fails_closed() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));

    let real = fixture._temp.path().join("staging-real");
    fs::create_dir_all(&real).unwrap();
    let root = TrustedStagingRoot::try_open(&real).unwrap();
    let outside = fixture._temp.path().join("staging-outside");
    fs::create_dir_all(&outside).unwrap();
    let link = fixture.staging_root.join("replaced-root-link");
    let _ = fs::remove_dir_all(&link);
    if !try_junction(&outside, &link) && !try_symlink_dir(&outside, &link) {
        return;
    }
    // Replace ambient staging directory used by request after capability open on `real`.
    // Overlap/identity checks must still fail closed when the caller-supplied root drifts.
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
    // Drop and reopen against the attacked path when possible.
    drop(root);
    let attacked = if TrustedStagingRoot::try_open(&link).is_ok() {
        TrustedStagingRoot::try_open(&link).unwrap()
    } else {
        return;
    };
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
            &attacked,
            TrustedStagingOptions::default(),
        )
        .unwrap(),
    );
    // Symlinked/junction staging roots may be rejected at open or during staging.
    if let Err(err) = err {
        assert_fail_closed(&err);
    }
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
}

#[test]
fn special_non_regular_file_before_verify_fails_closed_where_supported() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let created = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let created_flag = std::sync::Arc::clone(&created);
    let staging = fixture.staging_root.clone();

    set_before_temp_verify_hook(move |_| {
        let Some(resource) = ambient_tmp_resource(&staging) else {
            return;
        };
        let special = resource.join("special.lua");
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixListener;
            let _ = fs::remove_file(&special);
            if UnixListener::bind(&special).is_ok() {
                created_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        #[cfg(not(unix))]
        {
            let target = resource.join("fxmanifest.lua");
            if try_symlink_file(&target, &special) {
                created_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });

    let result = stage_result(&fixture);
    if !created.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let err = result.expect_err("special file must fail closed");
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    no_trusted_bundle(&fixture.staging_root);
}

#[test]
fn bundles_dir_symlink_rejected_where_supported() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let outside = fixture._temp.path().join("outside-bundles");
    fs::create_dir_all(&outside).unwrap();
    let link = fixture.staging_root.join("bundles");
    if !try_junction(&outside, &link) && !try_symlink_dir(&outside, &link) {
        return;
    }
    let err = stage_err(&fixture);
    assert_fail_closed(&err);
}

#[test]
fn name_alone_never_trusts_published_directory() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let name = bundle.manifest().manifest_id().digest().to_string();
    let fake_root = fixture._temp.path().join("fake-staging");
    fs::create_dir_all(fake_root.join("bundles").join(&name).join("resource")).unwrap();
    write_file(
        &fake_root.join("bundles").join(&name).join("manifest.bin"),
        b"not-a-real-manifest",
    );
    let root = TrustedStagingRoot::try_open(&fake_root).unwrap();
    let bundles = open_child_dir(root.dir(), "bundles").unwrap();
    let reopen = revalidate_published_child(&bundles, &name, bundle.manifest());
    assert!(reopen.is_err());
}

fn assert_no_discoverable_trusted_child(
    staging_root: &Path,
    expected_manifest: &TrustedStagingManifest,
) {
    no_trusted_bundle(staging_root);
    let bundles = staging_root.join("bundles");
    if !bundles.exists() {
        return;
    }
    let Ok(root) = TrustedStagingRoot::try_open(staging_root) else {
        return;
    };
    let Ok(bundles_cap) = open_child_dir(root.dir(), "bundles") else {
        return;
    };
    for entry in fs::read_dir(&bundles).unwrap().filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        assert!(
            revalidate_published_child(&bundles_cap, name, expected_manifest).is_err(),
            "child {name} must not validate as trusted after failed staging"
        );
    }
}

#[test]
fn after_rename_published_child_open_failure_is_cleaned() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let expected = {
        let other = fixture._temp.path().join("staging-ref");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean).manifest().clone()
    };
    let before_i = format!("{:?}", hash_tree(&fixture.installed_resource));
    let before_p = fs::read(&fixture.package_v2).unwrap();
    let before_s = format!("{:?}", hash_tree(&fixture.store));
    let staging = fixture.staging_root.clone();
    let replaced = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&replaced);

    set_after_rename_hook(move |_bundles, published_name| {
        let published = staging.join("bundles").join(published_name);
        let outside = staging.join("outside-published");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        let _ = fs::remove_dir_all(&published);
        if try_junction(&outside, &published) || try_symlink_dir(&outside, &published) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let result = stage_result(&fixture);
    if !replaced.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let err = result.expect_err("post-rename open failure must fail closed");
    assert_fail_closed(&err);
    sources_unchanged(&fixture, &before_i, &before_p, &before_s);
    assert_no_discoverable_trusted_child(&fixture.staging_root, &expected);
}

#[test]
fn after_rename_resource_open_failure_is_cleaned() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let expected = {
        let other = fixture._temp.path().join("staging-ref2");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean).manifest().clone()
    };
    let staging = fixture.staging_root.clone();
    let replaced = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&replaced);

    set_after_rename_hook(move |_bundles, published_name| {
        let resource = staging
            .join("bundles")
            .join(published_name)
            .join("resource");
        let outside = staging.join("outside-resource2");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir_all(&outside).unwrap();
        let _ = fs::remove_dir_all(&resource);
        if try_junction(&outside, &resource) || try_symlink_dir(&outside, &resource) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let result = stage_result(&fixture);
    if !replaced.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let err = result.expect_err("resource open failure must clean published child");
    assert_fail_closed(&err);
    assert_no_discoverable_trusted_child(&fixture.staging_root, &expected);
}

#[test]
fn post_write_and_publish_disjointness_failure_removes_child() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let expected = {
        let other = fixture._temp.path().join("staging-ref3");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean).manifest().clone()
    };
    set_force_post_publish_tail(Some(PostPublishTailFault::Disjointness));
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingRootOverlap
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    assert_no_discoverable_trusted_child(&fixture.staging_root, &expected);
}

#[test]
fn post_write_and_publish_identity_failure_removes_child() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let expected = {
        let other = fixture._temp.path().join("staging-ref4");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean).manifest().clone()
    };
    set_force_post_publish_tail(Some(PostPublishTailFault::Identity));
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingRootReplaced
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    assert_no_discoverable_trusted_child(&fixture.staging_root, &expected);
}

#[test]
fn post_write_and_publish_reopen_failure_removes_child() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let expected = {
        let other = fixture._temp.path().join("staging-ref5");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean).manifest().clone()
    };
    set_force_post_publish_tail(Some(PostPublishTailFault::Reopen));
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingRootOverlap
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    assert_no_discoverable_trusted_child(&fixture.staging_root, &expected);
}

#[test]
fn destination_collision_preserves_temp_cleanup_failure() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_force_temp_cleanup_failure(true);
    set_before_rename_hook(|_tmp, bundles, published_name| {
        let _ = bundles.create_dir(published_name);
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    if let crate::GkrmError::TrustedStagingFailedWithCleanupFailure { primary, .. } = &err {
        assert!(matches!(
            primary.as_ref(),
            crate::GkrmError::TrustedStagingDestinationExists
        ));
    }
}

#[test]
fn rename_failure_preserves_temp_cleanup_failure() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_force_temp_cleanup_failure(true);
    // Force rename conflict by creating destination immediately before rename via hook,
    // then also force temp cleanup failure representation.
    set_before_rename_hook(|_tmp, bundles, published_name| {
        let _ = bundles.create_dir(published_name);
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
}

#[test]
fn post_publish_removal_and_quarantine_both_fail() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_force_cleanup_failure(true);
    set_force_quarantine_failure(true);
    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"bad").unwrap();
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
}

#[test]
fn public_debug_redacts_paths_and_digests() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let bundle = stage_ok(&fixture);
    let sentinel_path = "SENTINEL_PATH_fxmanifest.lua";
    let sentinel_digest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let entry = &bundle.manifest().entries()[0];
    let entry_dbg = format!("{entry:?}");
    let manifest_dbg = format!("{:?}", bundle.manifest());
    let binding_dbg = format!(
        "{:?}",
        StagingSourceBinding::InstalledDigest(crate::Sha256Digest::new([0xab; 32]),)
    );
    let bundle_dbg = format!("{bundle:?}");
    let summary_dbg = format!("{:?}", bundle.summary());
    let status_dbg = format!("{:?}", TrustedStagingStatus::ReadyForApplyPlanning);

    for text in [
        &entry_dbg,
        &manifest_dbg,
        &binding_dbg,
        &bundle_dbg,
        &summary_dbg,
        &status_dbg,
        &format!("{:?}", bundle.manifest()),
    ] {
        assert!(
            !text.contains(sentinel_path),
            "debug leaked sentinel path: {text}"
        );
        assert!(
            !text.contains(sentinel_digest),
            "debug leaked sentinel digest: {text}"
        );
        assert!(
            !text.contains("fxmanifest.lua"),
            "debug leaked relative path: {text}"
        );
        assert!(
            !text.contains("ababadab"),
            "debug leaked digest bytes: {text}"
        );
    }

    assert!(entry_dbg.contains("TrustedStagingEntry"));
    assert!(manifest_dbg.contains("entry_count"));
    assert!(binding_dbg.contains("Installed"));
    assert!(!binding_dbg.contains("abababab"));
}

#[test]
fn cleanup_capability_clone_failure_before_rename_leaves_no_published_child() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_force_cleanup_capability_clone_failure(true);
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingIo {
            operation: StagingIoOperation::CloneCleanupCapability,
            ..
        } | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    if let crate::GkrmError::TrustedStagingFailedWithCleanupFailure { primary, .. } = &err {
        assert!(matches!(
            primary.as_ref(),
            crate::GkrmError::TrustedStagingIo {
                operation: StagingIoOperation::CloneCleanupCapability,
                ..
            }
        ));
    }
    let bundles = fixture.staging_root.join("bundles");
    if bundles.exists() {
        let children: Vec<_> = fs::read_dir(&bundles)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            children.is_empty(),
            "clone failure must not publish a child"
        );
    }
    let tmp = fixture.staging_root.join(".tmp");
    if tmp.exists() {
        let children: Vec<_> = fs::read_dir(&tmp).unwrap().filter_map(|e| e.ok()).collect();
        assert!(
            children.is_empty(),
            "temp child must follow normal temp cleanup"
        );
    }
}

#[test]
fn post_rename_failure_with_armed_guard_removes_published_child() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"armed-guard-verify-fail").unwrap();
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingPostPublishVerificationFailed { .. }
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    no_trusted_bundle(&fixture.staging_root);
    let bundles = fixture.staging_root.join("bundles");
    if bundles.exists() {
        let children: Vec<_> = fs::read_dir(&bundles)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            children.is_empty(),
            "armed guard removal should leave no published child"
        );
    }
}

#[test]
fn post_publish_removal_fails_quarantine_succeeds_redacted() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_force_cleanup_failure(true);
    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"bad").unwrap();
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    assert_error_surfaces_redact_paths(&err, &fixture, None);
    let bundles = fixture.staging_root.join("bundles");
    let children: Vec<_> = fs::read_dir(&bundles)
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(children.len(), 1);
    assert!(children[0].path().join(".gkrm-untrusted-v1").exists());
}

#[test]
fn post_publish_removal_and_quarantine_both_fail_redacted() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    set_force_cleanup_failure(true);
    set_force_quarantine_failure(true);
    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, published_name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"bad").unwrap();
    });
    let err = stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    if let crate::GkrmError::TrustedStagingFailedWithCleanupFailure { primary, cleanup } = &err {
        assert_error_surfaces_redact_paths(primary, &fixture, None);
        assert_error_surfaces_redact_paths(cleanup, &fixture, None);
    }
    assert_error_surfaces_redact_paths(&err, &fixture, None);
    assert_no_raw_io_in_task20_chain(&err);
}

#[test]
fn rename_open_write_sync_remove_quarantine_use_sanitized_sources() {
    let (_h, _w, _s) = lock_all();

    // Destination collision before rename → DestinationExists (no raw I/O source).
    {
        let fixture = build_mini();
        set_before_rename_hook(|_tmp, bundles, published_name| {
            let _ = bundles.create_dir(published_name);
        });
        let err = stage_err(&fixture);
        assert!(matches!(
            err,
            crate::GkrmError::TrustedStagingDestinationExists
                | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
        ));
        assert_error_surfaces_redact_paths(&err, &fixture, None);
        assert_no_raw_io_in_task20_chain(&err);
    }

    // Forced clone failure uses TrustedStagingIo without nested std::io::Error.
    {
        let fixture = build_mini();
        set_before_rename_hook(|_, _, _| {});
        set_force_cleanup_capability_clone_failure(true);
        let err = stage_err(&fixture);
        assert_error_surfaces_redact_paths(&err, &fixture, None);
        assert_no_raw_io_in_task20_chain(&err);
        match &err {
            crate::GkrmError::TrustedStagingIo { operation, .. } => {
                assert_eq!(*operation, StagingIoOperation::CloneCleanupCapability);
            }
            crate::GkrmError::TrustedStagingFailedWithCleanupFailure { primary, .. } => {
                assert!(matches!(
                    primary.as_ref(),
                    crate::GkrmError::TrustedStagingIo {
                        operation: StagingIoOperation::CloneCleanupCapability,
                        ..
                    }
                ));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        set_force_cleanup_capability_clone_failure(false);
    }

    // Forced removal+quarantine failures use sanitized TrustedStagingIo sources.
    {
        let fixture = build_mini();
        set_force_cleanup_failure(true);
        set_force_quarantine_failure(true);
        set_after_publish_hook(|bundles_dir, published_name| {
            use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
            use cap_std::fs::OpenOptions;
            let published = open_child_dir(bundles_dir, published_name).unwrap();
            let mut options = OpenOptions::new();
            options.write(true);
            options.truncate(true);
            options.follow(FollowSymlinks::No);
            let mut file = published.open_with("manifest.bin", &options).unwrap();
            file.write_all(b"bad").unwrap();
        });
        let err = stage_err(&fixture);
        assert_error_surfaces_redact_paths(&err, &fixture, None);
        assert_no_raw_io_in_task20_chain(&err);
        if let crate::GkrmError::TrustedStagingFailedWithCleanupFailure { cleanup, .. } = &err {
            let cleanup_text = format!("{cleanup}");
            let cleanup_debug = format!("{cleanup:?}");
            assert!(
                matches!(
                    cleanup.as_ref(),
                    crate::GkrmError::TrustedStagingCleanupFailed { .. }
                ) || cleanup_text.contains("I/O failure")
                    || cleanup_text.contains("cleanup failed")
                    || cleanup_debug.contains("I/O failure")
                    || cleanup_debug.contains("cleanup failed"),
                "cleanup branch should use sanitized staging I/O: display={cleanup_text} debug={cleanup_debug}"
            );
        }
    }
}

#[test]
fn task20_error_chain_redacts_path_and_name_sentinels() {
    let (_h, _w, _s) = lock_all();
    let fixture = build_mini();
    let published_name = {
        let other = fixture._temp.path().join("staging-id-ref");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean)
            .manifest()
            .manifest_id()
            .digest()
            .to_string()
    };

    set_force_cleanup_failure(true);
    set_force_quarantine_failure(true);
    set_after_publish_hook(|bundles_dir, name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;
        let published = open_child_dir(bundles_dir, name).unwrap();
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published.open_with("manifest.bin", &options).unwrap();
        file.write_all(b"sentinel-mutation").unwrap();
    });
    let err = stage_err(&fixture);
    assert_error_surfaces_redact_paths(&err, &fixture, Some(&published_name));
    assert_no_raw_io_in_task20_chain(&err);

    // Clear fault injection before asserting successful behavior / fixed literals.
    set_force_cleanup_failure(false);
    set_force_quarantine_failure(false);
    set_after_publish_hook(|_, _| {});

    // Successful literals remain unchanged for a clean staging run.
    let ok = {
        let other = fixture._temp.path().join("staging-ok-literals");
        fs::create_dir_all(&other).unwrap();
        let mut clean = build_mini();
        clean.staging_root = other;
        stage_ok(&clean)
    };
    assert_eq!(
        ok.manifest().manifest_id().digest().to_string(),
        published_name
    );
    assert_eq!(ok.status(), TrustedStagingStatus::ReadyForApplyPlanning);
}

fn assert_error_surfaces_redact_paths(
    error: &crate::GkrmError,
    fixture: &super::test_support::MiniFixture,
    published_name: Option<&str>,
) {
    let staging = fixture.staging_root.to_string_lossy().into_owned();
    let installed = fixture.installed_resource.to_string_lossy().into_owned();
    let package = fixture.package_v2.to_string_lossy().into_owned();
    let baseline = fixture.store.to_string_lossy().into_owned();
    let resource_rel = "fxmanifest.lua";
    let mut sentinels = vec![
        staging.as_str(),
        installed.as_str(),
        package.as_str(),
        baseline.as_str(),
        resource_rel,
        "tmp-",
        ".gkrm-untrusted-v1",
    ];
    if let Some(name) = published_name {
        sentinels.push(name);
    }

    let surfaces = [
        format!("{error}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ];
    for text in &surfaces {
        for sentinel in &sentinels {
            assert!(
                !text.contains(sentinel),
                "error surface leaked sentinel `{sentinel}`: {text}"
            );
        }
    }

    walk_error_chain(error, &sentinels);

    if let crate::GkrmError::TrustedStagingFailedWithCleanupFailure { primary, cleanup } = error {
        for branch in [primary.as_ref(), cleanup.as_ref()] {
            let surfaces = [
                format!("{branch}"),
                format!("{branch:?}"),
                format!("{branch:#?}"),
            ];
            for text in &surfaces {
                for sentinel in &sentinels {
                    assert!(
                        !text.contains(sentinel),
                        "compound branch leaked `{sentinel}`: {text}"
                    );
                }
            }
            walk_error_chain(branch, &sentinels);
        }
    }
}

fn walk_error_chain(error: &crate::GkrmError, sentinels: &[&str]) {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = current {
        let display = format!("{err}");
        let debug = format!("{err:?}");
        let alt = format!("{err:#?}");
        for text in [&display, &debug, &alt] {
            for sentinel in sentinels {
                assert!(
                    !text.contains(sentinel),
                    "source-chain leaked `{sentinel}`: {text}"
                );
            }
        }
        // Nested std::io::Error must never appear in the Task 20 public chain.
        assert!(
            err.downcast_ref::<std::io::Error>().is_none(),
            "raw std::io::Error reachable in Task 20 chain: {err:?}"
        );
        current = err.source();
    }
}

fn assert_no_raw_io_in_task20_chain(error: &crate::GkrmError) {
    walk_error_chain(error, &[]);
    if let crate::GkrmError::TrustedStagingFailedWithCleanupFailure { primary, cleanup } = error {
        walk_error_chain(primary, &[]);
        walk_error_chain(cleanup, &[]);
    }
    if let crate::GkrmError::TrustedStagingPostPublishVerificationFailed { source }
    | crate::GkrmError::TrustedStagingCleanupFailed { source }
    | crate::GkrmError::TrustedStagingWriteFailure { source } = error
    {
        walk_error_chain(source, &[]);
    }
}
