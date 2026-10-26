//! Core trusted staging unit tests.

use std::fs;
use std::io::Write;

use crate::baseline::fs_security::open_child_dir;
use crate::{
    IncomingMergeContentSourceLimits, InstalledScanLimits, TrustedStagingOptions,
    TrustedStagingRequest, TrustedStagingRoot,
};

use super::root::{lock_staging_hooks, staging_mutation_count};
use super::test_support::{build_mini, incoming_root, installed_root};
use super::{
    lock_staging_write_hooks, set_after_publish_hook, stage_trusted_resource,
    IncomingStagingContentSource, InstalledStagingContentSource,
};

#[test]
fn binding_failure_before_staging_mutation() {
    let _hash_lock = crate::installed_scan::INSTALLED_SCAN_HASH_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _guard = lock_staging_hooks();
    let fixture = build_mini();
    let root = TrustedStagingRoot::try_open(&fixture.staging_root).unwrap();
    assert_eq!(staging_mutation_count(), 0);
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
    let err = stage_trusted_resource(
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
    let _ = err;
    assert_eq!(staging_mutation_count(), 0);
    assert!(fs::read_dir(&fixture.staging_root)
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn post_rename_verification_failure_removes_publication() {
    let _hash_lock = crate::installed_scan::INSTALLED_SCAN_HASH_TEST_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let _guard = lock_staging_hooks();
    let _write = lock_staging_write_hooks();
    let fixture = build_mini();

    set_after_publish_hook(|bundles_dir, published_name| {
        use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
        use cap_std::fs::OpenOptions;

        let published = open_child_dir(bundles_dir, published_name).expect("open published");
        let mut options = OpenOptions::new();
        options.write(true);
        options.truncate(true);
        options.follow(FollowSymlinks::No);
        let mut file = published
            .open_with("manifest.bin", &options)
            .expect("open manifest for write");
        file.write_all(b"corrupted-sidecar").expect("corrupt");
    });

    let err = super::test_support::stage_err(&fixture);
    assert!(matches!(
        err,
        crate::GkrmError::TrustedStagingPostPublishVerificationFailed { .. }
            | crate::GkrmError::TrustedStagingFailedWithCleanupFailure { .. }
    ));
    let bundles = fixture.staging_root.join("bundles");
    if bundles.exists() {
        let children: Vec<_> = fs::read_dir(&bundles)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            children.is_empty(),
            "failed publication must be removed; found {}",
            children.len()
        );
    }
}
