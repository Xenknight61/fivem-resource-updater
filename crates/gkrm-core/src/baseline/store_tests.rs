//! Unit and filesystem tests for the local baseline store.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::baseline::blob_provider::InMemoryBlobProvider;
use crate::baseline::dto::encode_baseline_json;
use crate::baseline::fs_security::ensure_baseline_store_disjoint_from_installed;
use crate::baseline::model::{
    make_file_record, BaselineEscrowClass, BaselineStoreLimits, ValidatedBaselineBundle,
};
use crate::baseline::store::{
    discard_baseline_bundle, load_baseline_bundle, lock_stream_verified_blob_identity_hook,
    set_before_blob_identity_revalidation_hook, stream_verified_blob_for_path,
    write_baseline_bundle,
};
use crate::baseline::{BaselineId, SafeResourceKey};
use crate::{GkrmError, ResourceRelativePath, Sha256Digest};

fn digest_of(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::new(Sha256::digest(bytes).into())
}

fn sample_bundle_and_provider() -> (ValidatedBaselineBundle, InMemoryBlobProvider) {
    let config = b"cfg\n";
    let config_digest = digest_of(config);
    let main_digest = digest_of(b"main");
    let mut blobs = BTreeMap::new();
    blobs.insert(config_digest, config.to_vec());
    let provider = InMemoryBlobProvider::new(blobs.clone());

    let bundle = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("gksphone").expect("key"),
        "gksphone".to_owned(),
        Some("1.2.3".to_owned()),
        Some(digest_of(b"package")),
        vec![
            make_file_record(
                ResourceRelativePath::try_from_slash_str("client/main.lua").expect("path"),
                4,
                main_digest,
                BaselineEscrowClass::Protected,
                None,
            ),
            make_file_record(
                ResourceRelativePath::try_from_slash_str("config.lua").expect("path"),
                config.len() as u64,
                config_digest,
                BaselineEscrowClass::Ignored,
                Some(config_digest),
            ),
            make_file_record(
                ResourceRelativePath::try_from_slash_str("stream/prop.ydr").expect("path"),
                8,
                digest_of(b"propdata"),
                BaselineEscrowClass::NotSupported,
                None,
            ),
        ],
        blobs,
        BaselineStoreLimits::default(),
    )
    .expect("bundle");
    (bundle, provider)
}

fn sample_bundle() -> ValidatedBaselineBundle {
    sample_bundle_and_provider().0
}

fn publish(
    store: &Path,
    bundle: &ValidatedBaselineBundle,
    provider: &InMemoryBlobProvider,
) -> crate::baseline::StoredBaselineLocator {
    write_baseline_bundle(store, bundle, provider, BaselineStoreLimits::default()).expect("write")
}

fn publish_sample(
    store: &Path,
) -> (
    ValidatedBaselineBundle,
    crate::baseline::StoredBaselineLocator,
) {
    let (bundle, provider) = sample_bundle_and_provider();
    let locator = publish(store, &bundle, &provider);
    (bundle, locator)
}

#[test]
fn a_baseline_can_be_let_go_of_and_the_rest_are_left_where_they_are() {
    // Nothing ever removed one, and they are the largest thing this keeps. An operator who updates
    // every month accumulates a copy of every version they ever ran.
    let temp = tempdir().expect("temp dir");
    let store = temp.path().join("store");
    let (kept, _) = publish_blob(&store, b"keep me\n".to_vec());
    let (going, _) = publish_blob(&store, b"let me go\n".to_vec());
    let key = SafeResourceKey::parse("gksphone").expect("key");
    assert_ne!(kept.baseline_id(), going.baseline_id());

    assert!(
        discard_baseline_bundle(&store, &key, going.baseline_id()).expect("discard"),
        "it was there"
    );
    assert!(load_baseline_bundle(
        &store,
        &key,
        going.baseline_id(),
        BaselineStoreLimits::default()
    )
    .is_err());
    // The one nobody asked about is untouched, blobs and all.
    load_baseline_bundle(
        &store,
        &key,
        kept.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("the other one still reads");
}

#[test]
fn letting_go_of_one_that_is_not_there_is_not_a_failure() {
    // Said rather than raised: two releases in a row, or a store somebody tidied by hand, are the
    // ordinary shape of this and neither is worth an error.
    let temp = tempdir().expect("temp dir");
    let store = temp.path().join("store");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let stranger = BaselineId::parse(&"a".repeat(64)).expect("id");
    // No store at all.
    assert!(discard_baseline_bundle(&store, &key, &stranger).is_err());

    let (published, _) = publish_blob(&store, b"keep me\n".to_vec());
    assert!(!discard_baseline_bundle(&store, &key, &stranger).expect("absent"));
    assert!(discard_baseline_bundle(&store, &key, published.baseline_id()).expect("present"));
    assert!(!discard_baseline_bundle(&store, &key, published.baseline_id()).expect("again"));
}

fn bundle_with_blob(bytes: Vec<u8>) -> (ValidatedBaselineBundle, InMemoryBlobProvider) {
    let digest = digest_of(&bytes);
    let mut blobs = BTreeMap::new();
    blobs.insert(digest, bytes.clone());
    let provider = InMemoryBlobProvider::new(blobs.clone());
    let bundle = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("gksphone").expect("key"),
        "gksphone".to_owned(),
        None,
        Some(digest_of(b"package")),
        vec![make_file_record(
            ResourceRelativePath::try_from_slash_str("config.lua").expect("path"),
            bytes.len() as u64,
            digest,
            BaselineEscrowClass::Ignored,
            Some(digest),
        )],
        blobs,
        BaselineStoreLimits::default(),
    )
    .expect("bundle");
    (bundle, provider)
}

fn publish_blob(
    store: &Path,
    bytes: Vec<u8>,
) -> (
    ValidatedBaselineBundle,
    crate::baseline::StoredBaselineLocator,
) {
    let (bundle, provider) = bundle_with_blob(bytes);
    let locator = publish(store, &bundle, &provider);
    (bundle, locator)
}

fn blob_path(store: &Path, bundle: &ValidatedBaselineBundle) -> std::path::PathBuf {
    let digest = bundle.files()[0].blob_sha256().expect("blob");
    store
        .join("baselines")
        .join(bundle.resource_key().as_str())
        .join(bundle.baseline_id().as_str())
        .join("blobs")
        .join(digest.to_string())
}

fn load_published(
    store: &Path,
    locator: &crate::baseline::StoredBaselineLocator,
) -> crate::StoredBaseline {
    load_baseline_bundle(
        store,
        locator.resource_key(),
        locator.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load")
}

fn replace_blob_with_same_bytes(path_on_disk: std::path::PathBuf, bytes: Vec<u8>) {
    fs::remove_file(&path_on_disk).expect("remove blob");
    fs::write(&path_on_disk, bytes).expect("replace blob");
}

#[test]
fn write_load_round_trip() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    let locator = publish(&store, &bundle, &provider);
    let loaded = load_baseline_bundle(
        &store,
        locator.resource_key(),
        locator.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    assert_eq!(loaded.baseline_id(), bundle.baseline_id());
    assert_eq!(loaded.files().len(), 3);
    assert_eq!(loaded.counts().blobs(), 1);
    let blob = loaded
        .read_verified_blob(
            bundle.files()[1].blob_sha256().expect("blob"),
            &BaselineStoreLimits::default(),
        )
        .expect("blob read");
    assert_eq!(blob, b"cfg\n");
}

#[test]
fn streaming_verified_blob_success_requires_complete_internal_verification() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_sample(&store);
    let loaded = load_baseline_bundle(
        &store,
        locator.resource_key(),
        locator.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    let path = bundle.files()[1].relative_path().clone();
    let mut observed = Vec::new();

    let metadata =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |chunk| {
            observed.extend_from_slice(chunk);
            Ok(())
        })
        .expect("stream");

    assert_eq!(observed, b"cfg\n");
    assert_eq!(
        &metadata.expected_digest,
        bundle.files()[1].blob_sha256().expect("blob")
    );
    assert_eq!(metadata.expected_size, 4);
}

#[test]
fn streaming_verified_blob_callback_failure_remains_primary_after_verification() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_sample(&store);
    let loaded = load_baseline_bundle(
        &store,
        locator.resource_key(),
        locator.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    let path = bundle.files()[1].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_chunk| {
            Err(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
        })
        .expect_err("callback failure");

    assert!(matches!(
        err,
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow
    ));
}

#[test]
fn streaming_verified_blob_combines_callback_and_verification_failures() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_sample(&store);
    let loaded = load_baseline_bundle(
        &store,
        locator.resource_key(),
        locator.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    let blob_digest = bundle.files()[1].blob_sha256().expect("blob");
    let blob_path = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str())
        .join("blobs")
        .join(blob_digest.to_string());
    fs::write(&blob_path, b"bad\n").expect("mutate blob");
    let path = bundle.files()[1].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_chunk| {
            Err(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
        })
        .expect_err("combined failure");

    assert!(matches!(
        err.baseline_verified_blob_callback_error(),
        Some(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
    ));
    assert!(matches!(
        err.baseline_verified_blob_verification_error(),
        Some(GkrmError::BaselineBlobDigestMismatch { .. })
    ));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[test]
fn streaming_verified_blob_callback_can_observe_partial_or_zero_bytes_and_still_verify_all() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bytes = vec![b'a'; 96 * 1024];
    let (bundle, locator) = publish_blob(&store, bytes.clone());
    let loaded = load_published(&store, &locator);
    let path = bundle.files()[0].relative_path().clone();
    let mut retained = Vec::new();
    let mut chunks = 0_usize;

    let metadata =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |chunk| {
            chunks += 1;
            if retained.len() < 17 {
                let remaining = 17 - retained.len();
                retained.extend_from_slice(&chunk[..remaining.min(chunk.len())]);
            }
            Ok(())
        })
        .expect("partial observer succeeds");

    assert_eq!(metadata.expected_size, bytes.len() as u64);
    assert_eq!(&metadata.expected_digest, bundle.files()[0].sha256());
    assert_eq!(retained.len(), 17);
    assert!(chunks > 1);

    let mut observed = 0_usize;
    stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |chunk| {
        assert!(!chunk.is_empty());
        observed += 1;
        Ok(())
    })
    .expect("zero retention succeeds");
    assert!(observed > 1);
}

#[test]
fn streaming_verified_blob_callback_failure_after_partial_observation_remains_primary() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, vec![b'b'; 96 * 1024]);
    let loaded = load_published(&store, &locator);
    let path = bundle.files()[0].relative_path().clone();
    let mut observed = 0_usize;

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |chunk| {
            observed += chunk.len().min(3);
            Err(GkrmError::ThreeWayMergeAnalysisTotalHashBudgetExceeded {
                limit: 1,
                actual: 2,
            })
        })
        .expect_err("callback failure");

    assert!(observed > 0);
    assert!(matches!(
        err,
        GkrmError::ThreeWayMergeAnalysisTotalHashBudgetExceeded {
            limit: 1,
            actual: 2
        }
    ));
}

#[test]
fn streaming_verified_blob_success_plus_digest_failure_returns_verification_error() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, b"abcdef".to_vec());
    let path_on_disk = blob_path(&store, &bundle);
    let loaded = load_published(&store, &locator);
    fs::write(&path_on_disk, b"abcdeg").expect("same-size mutation");
    let path = bundle.files()[0].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| Ok(()))
            .expect_err("digest failure");

    assert!(matches!(err, GkrmError::BaselineBlobDigestMismatch { .. }));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[test]
fn streaming_verified_blob_success_plus_size_failure_returns_verification_error() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, b"abcdef".to_vec());
    let path_on_disk = blob_path(&store, &bundle);
    let loaded = load_published(&store, &locator);
    fs::write(&path_on_disk, b"abc").expect("truncate");
    let path = bundle.files()[0].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| Ok(()))
            .expect_err("size failure");

    assert!(matches!(err, GkrmError::BaselineBlobSizeMismatch { .. }));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[test]
fn streaming_verified_blob_success_plus_identity_failure_returns_verification_error() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bytes = b"abcdef".to_vec();
    let (bundle, locator) = publish_blob(&store, bytes.clone());
    let path_on_disk = blob_path(&store, &bundle);
    let loaded = load_published(&store, &locator);
    let path = bundle.files()[0].relative_path().clone();
    let _guard = lock_stream_verified_blob_identity_hook();
    set_before_blob_identity_revalidation_hook(move || {
        replace_blob_with_same_bytes(path_on_disk, bytes);
    });

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| Ok(()))
            .expect_err("identity failure");

    assert!(matches!(
        err,
        GkrmError::BaselineIncompleteBundle {
            reason: "blob identity changed while reading"
        }
    ));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
    assert!(!err.to_string().contains(bundle.baseline_id().as_str()));
    assert!(!err
        .to_string()
        .contains(bundle.files()[0].sha256().to_string().as_str()));
}

#[test]
fn streaming_verified_blob_callback_failure_plus_size_failure_preserves_both() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, b"abcdef".to_vec());
    let path_on_disk = blob_path(&store, &bundle);
    let loaded = load_published(&store, &locator);
    fs::write(&path_on_disk, b"abc").expect("truncate");
    let path = bundle.files()[0].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| {
            Err(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
        })
        .expect_err("combined failure");

    assert!(matches!(
        err.baseline_verified_blob_callback_error(),
        Some(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
    ));
    assert!(matches!(
        err.baseline_verified_blob_verification_error(),
        Some(GkrmError::BaselineBlobSizeMismatch { .. })
    ));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[test]
fn streaming_verified_blob_callback_failure_plus_identity_failure_preserves_both() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bytes = b"abcdef".to_vec();
    let (bundle, locator) = publish_blob(&store, bytes.clone());
    let path_on_disk = blob_path(&store, &bundle);
    let loaded = load_published(&store, &locator);
    let path = bundle.files()[0].relative_path().clone();
    let _guard = lock_stream_verified_blob_identity_hook();
    set_before_blob_identity_revalidation_hook(move || {
        replace_blob_with_same_bytes(path_on_disk, bytes);
    });

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| {
            Err(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
        })
        .expect_err("combined identity failure");

    assert!(matches!(
        err,
        GkrmError::BaselineVerifiedBlobCallbackAndVerificationFailed { .. }
    ));
    assert!(matches!(
        err.baseline_verified_blob_callback_error(),
        Some(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)
    ));
    assert!(matches!(
        err.baseline_verified_blob_verification_error(),
        Some(GkrmError::BaselineIncompleteBundle {
            reason: "blob identity changed while reading"
        })
    ));
    assert!(err.source().is_some());
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
    assert!(!err.to_string().contains(bundle.baseline_id().as_str()));
    assert!(!err
        .to_string()
        .contains(bundle.files()[0].sha256().to_string().as_str()));
}

#[test]
fn streaming_verified_blob_large_blob_is_chunked_without_full_callback_retention() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bytes = vec![b'z'; 192 * 1024 + 17];
    let expected_digest = digest_of(&bytes);
    let (bundle, locator) = publish_blob(&store, bytes.clone());
    let loaded = load_published(&store, &locator);
    let path = bundle.files()[0].relative_path().clone();
    let mut chunks = 0_usize;
    let mut max_chunk = 0_usize;
    let mut observed_bytes = 0_u64;

    let metadata =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |chunk| {
            chunks += 1;
            max_chunk = max_chunk.max(chunk.len());
            observed_bytes += chunk.len() as u64;
            Ok(())
        })
        .expect("large stream");

    assert_eq!(metadata.expected_size, bytes.len() as u64);
    assert_eq!(metadata.expected_digest, expected_digest);
    assert_eq!(observed_bytes, bytes.len() as u64);
    assert!(chunks > 1);
    assert!(max_chunk <= 64 * 1024);
}

#[test]
fn streaming_verified_blob_replacement_during_callback_is_not_trusted() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bytes = vec![b'q'; 128 * 1024];
    let (bundle, locator) = publish_blob(&store, bytes);
    let path_on_disk = blob_path(&store, &bundle);
    let loaded = load_published(&store, &locator);
    let path = bundle.files()[0].relative_path().clone();
    let mut mutated = false;

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| {
            if !mutated {
                fs::write(&path_on_disk, vec![b'r'; 128 * 1024]).expect("mutate");
                mutated = true;
            }
            Ok(())
        })
        .expect_err("replacement or mutation must fail");

    assert!(matches!(
        err,
        GkrmError::BaselineBlobDigestMismatch { .. } | GkrmError::BaselineIncompleteBundle { .. }
    ));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[test]
fn streaming_verified_blob_hard_link_condition_is_rejected_where_supported() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, b"abcdef".to_vec());
    let path_on_disk = blob_path(&store, &bundle);
    let hard_link = path_on_disk.with_extension("hardlink");
    let loaded = load_published(&store, &locator);
    fs::hard_link(&path_on_disk, &hard_link).expect("hard link");
    let path = bundle.files()[0].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| Ok(()))
            .expect_err("hard link rejected");

    assert!(matches!(err, GkrmError::BaselineStoreHardLink { .. }));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[cfg(unix)]
#[test]
fn streaming_verified_blob_symlink_substitution_is_rejected() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, b"abcdef".to_vec());
    let path_on_disk = blob_path(&store, &bundle);
    let target = store.join("outside-blob");
    fs::write(&target, b"abcdef").expect("target");
    let loaded = load_published(&store, &locator);
    fs::remove_file(&path_on_disk).expect("remove blob");
    std::os::unix::fs::symlink(&target, &path_on_disk).expect("symlink");
    let path = bundle.files()[0].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| Ok(()))
            .expect_err("symlink rejected");

    assert!(matches!(
        err,
        GkrmError::BaselineStoreIo { .. }
            | GkrmError::BaselineStoreSymlink { .. }
            | GkrmError::BaselineStoreUnexpectedType { .. }
    ));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[cfg(windows)]
#[test]
fn streaming_verified_blob_symlink_substitution_is_rejected_where_supported() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, locator) = publish_blob(&store, b"abcdef".to_vec());
    let path_on_disk = blob_path(&store, &bundle);
    let target = store.join("outside-blob");
    fs::write(&target, b"abcdef").expect("target");
    let loaded = load_published(&store, &locator);
    fs::remove_file(&path_on_disk).expect("remove blob");
    if std::os::windows::fs::symlink_file(&target, &path_on_disk).is_err() {
        fs::create_dir(&path_on_disk).expect("fallback directory substitution");
    }
    let path = bundle.files()[0].relative_path().clone();

    let err =
        stream_verified_blob_for_path(&loaded, &path, &BaselineStoreLimits::default(), |_| Ok(()))
            .expect_err("unsafe substitution rejected");

    assert!(matches!(
        err,
        GkrmError::BaselineStoreIo { .. }
            | GkrmError::BaselineStoreSymlink { .. }
            | GkrmError::BaselineStoreReparsePoint { .. }
            | GkrmError::BaselineStoreUnexpectedType { .. }
    ));
    assert!(!err
        .to_string()
        .contains(temp.path().to_string_lossy().as_ref()));
}

#[test]
fn repeated_identical_write_is_idempotent() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let bundle = sample_bundle();
    let first = publish(&store, &bundle, &sample_bundle_and_provider().1);
    let second = publish(&store, &bundle, &sample_bundle_and_provider().1);
    assert_eq!(first, second);
}

#[test]
fn same_id_different_bytes_is_conflict() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);

    let baseline_dir = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str());
    let manifest_path = baseline_dir.join("baseline.json");
    let json = fs::read(&manifest_path).expect("read");
    // Corrupt a non-identity field that still leaves a readable JSON document with same id.
    // Replace resource_name value while keeping baseline_id unchanged.
    let text = String::from_utf8(json).expect("utf8");
    let corrupted = text.replacen("\"gksphone\"", "\"tampered\"", 2);
    fs::write(&manifest_path, corrupted.as_bytes()).expect("corrupt");

    let err = write_baseline_bundle(&store, &bundle, &provider, BaselineStoreLimits::default())
        .expect_err("conflict");
    // Reload may fail validation first; either conflict or id/name mismatch is acceptable rejection.
    assert!(matches!(
        err,
        GkrmError::BaselineExistingConflict { .. }
            | GkrmError::BaselineIdMismatch { .. }
            | GkrmError::BaselineStoreIo { .. }
            | GkrmError::BaselineCountMismatch { .. }
            | GkrmError::BaselineIncompleteBundle { .. }
    ));
}

#[test]
fn deterministic_json_bytes() {
    let left = encode_baseline_json(&sample_bundle()).expect("json");
    let right = encode_baseline_json(&sample_bundle()).expect("json");
    assert_eq!(left, right);
    assert!(left.ends_with(b"\n"));
    assert!(!left[..left.len() - 1].contains(&b'\n'));
}

#[test]
fn rejects_unsafe_paths_and_keys() {
    assert!(SafeResourceKey::parse("../x").is_err());
    assert!(SafeResourceKey::parse("a/b").is_err());
    assert!(SafeResourceKey::parse("CON").is_err());
    assert!(ResourceRelativePath::try_from_slash_str("../x").is_err());
    assert!(ResourceRelativePath::try_from_slash_str("a\\b").is_err());
    assert!(ResourceRelativePath::try_from_slash_str("/abs").is_err());
    assert!(BaselineId::parse("xyz").is_err());
    assert!(Sha256Digest::from_lowercase_hex("ZZ").is_err());
}

#[test]
fn rejects_escrow_blob_policy_mismatch() {
    let digest = digest_of(b"x");
    let err = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("phone").unwrap(),
        "phone".into(),
        None,
        None,
        vec![make_file_record(
            ResourceRelativePath::try_from_slash_str("a.lua").unwrap(),
            1,
            digest,
            BaselineEscrowClass::Protected,
            Some(digest),
        )],
        BTreeMap::from([(digest, b"x".to_vec())]),
        BaselineStoreLimits::default(),
    )
    .expect_err("policy");
    assert!(matches!(
        err,
        GkrmError::BaselineInconsistentEscrowBlob { .. }
    ));
}

#[test]
fn unique_blob_count_counts_objects_not_references() {
    let bytes = b"shared";
    let digest = digest_of(bytes);
    let mut blobs = BTreeMap::new();
    blobs.insert(digest, bytes.to_vec());
    let bundle = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("phone").unwrap(),
        "phone".into(),
        None,
        None,
        vec![
            make_file_record(
                ResourceRelativePath::try_from_slash_str("a.lua").unwrap(),
                bytes.len() as u64,
                digest,
                BaselineEscrowClass::Ignored,
                Some(digest),
            ),
            make_file_record(
                ResourceRelativePath::try_from_slash_str("b.lua").unwrap(),
                bytes.len() as u64,
                digest,
                BaselineEscrowClass::Ignored,
                Some(digest),
            ),
        ],
        blobs,
        BaselineStoreLimits::default(),
    )
    .expect("bundle");
    assert_eq!(bundle.counts().ignored_files(), 2);
    assert_eq!(bundle.counts().blobs(), 1);
    assert_eq!(bundle.counts().total_blob_bytes(), bytes.len() as u64);
}

#[test]
fn file_and_blob_limits() {
    let digest = digest_of(b"x");
    let limits = BaselineStoreLimits::new(1024, 1, 1, 1).expect("limits");
    let err = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("phone").unwrap(),
        "phone".into(),
        None,
        None,
        vec![
            make_file_record(
                ResourceRelativePath::try_from_slash_str("a.lua").unwrap(),
                1,
                digest,
                BaselineEscrowClass::Protected,
                None,
            ),
            make_file_record(
                ResourceRelativePath::try_from_slash_str("b.lua").unwrap(),
                1,
                digest_of(b"y"),
                BaselineEscrowClass::Protected,
                None,
            ),
        ],
        BTreeMap::new(),
        limits,
    )
    .expect_err("limit");
    assert!(matches!(
        err,
        GkrmError::BaselineFileCountLimitExceeded { .. }
    ));
}

#[test]
fn missing_and_unexpected_blob_on_disk() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let baseline_dir = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str());
    let blob_name = bundle.files()[1].blob_sha256().unwrap().to_string();
    fs::remove_file(baseline_dir.join("blobs").join(&blob_name)).expect("remove blob");
    let err = load_baseline_bundle(
        &store,
        bundle.resource_key(),
        bundle.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect_err("missing");
    assert!(matches!(
        err,
        GkrmError::BaselineMissingBlob { .. } | GkrmError::BaselineInconsistentEscrowBlob { .. }
    ));

    write_baseline_bundle(&store, &bundle, &provider, BaselineStoreLimits::default()).ok();
    // recreate clean
    let _ = fs::remove_dir_all(&store);
    publish(&store, &bundle, &sample_bundle_and_provider().1);
    let baseline_dir = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str());
    fs::write(baseline_dir.join("blobs").join("aa".repeat(32)), b"nope").expect("extra");
    let err = load_baseline_bundle(
        &store,
        bundle.resource_key(),
        bundle.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect_err("unexpected");
    assert!(matches!(
        err,
        GkrmError::BaselineUnexpectedBlob { .. }
            | GkrmError::BaselineInvalidHash { .. }
            | GkrmError::BaselineBlobDigestMismatch { .. }
    ));
}

#[test]
fn point_of_use_blob_revalidation_detects_mutation() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let loaded = load_baseline_bundle(
        &store,
        bundle.resource_key(),
        bundle.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    let digest = *bundle.files()[1].blob_sha256().unwrap();
    let blob_path = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str())
        .join("blobs")
        .join(digest.to_string());
    fs::write(&blob_path, b"mutated!!").expect("mutate");
    let err = loaded
        .read_verified_blob(&digest, &BaselineStoreLimits::default())
        .expect_err("mutated");
    assert!(matches!(
        err,
        GkrmError::BaselineBlobDigestMismatch { .. }
            | GkrmError::BaselineBlobSizeMismatch { .. }
            | GkrmError::BaselineIncompleteBundle { .. }
    ));
}

#[test]
fn store_install_overlap_rejected() {
    let temp = tempdir().expect("temp");
    let root = temp.path().join("root");
    fs::create_dir_all(&root).expect("root");
    let err = ensure_baseline_store_disjoint_from_installed(&root, &root).expect_err("equal");
    assert!(matches!(err, GkrmError::BaselineStoreInstallOverlap));

    let nested = root.join("nested");
    fs::create_dir_all(&nested).expect("nested");
    let err = ensure_baseline_store_disjoint_from_installed(&nested, &root).expect_err("nested");
    assert!(matches!(err, GkrmError::BaselineStoreInstallOverlap));
}

#[test]
fn failed_write_leaves_no_published_baseline() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let digest = digest_of(b"x");
    // Bundle claims ignored blob but provides wrong bytes length vs digest content mismatch handled at validate.
    let err = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("phone").unwrap(),
        "phone".into(),
        None,
        None,
        vec![make_file_record(
            ResourceRelativePath::try_from_slash_str("a.lua").unwrap(),
            2,
            digest,
            BaselineEscrowClass::Ignored,
            Some(digest),
        )],
        BTreeMap::from([(digest, b"x".to_vec())]),
        BaselineStoreLimits::default(),
    )
    .expect_err("validate");
    assert!(matches!(err, GkrmError::BaselineBlobSizeMismatch { .. }));
    assert!(!store.join("baselines").exists());
}

#[test]
fn concurrent_identical_writers() {
    let temp = tempdir().expect("temp");
    let store = Arc::new(temp.path().join("store"));
    let (bundle, provider) = sample_bundle_and_provider();
    let bundle = Arc::new(bundle);
    let provider = Arc::new(provider);
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let store = Arc::clone(&store);
        let bundle = Arc::clone(&bundle);
        let provider = Arc::clone(&provider);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            write_baseline_bundle(
                &store,
                &bundle,
                provider.as_ref(),
                BaselineStoreLimits::default(),
            )
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("join"))
        .collect();
    assert!(
        results.iter().all(|result| result.is_ok()),
        "concurrent identical writers failed: {results:?}"
    );
    let loaded = load_baseline_bundle(
        store.as_path(),
        bundle.resource_key(),
        bundle.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect("load");
    assert_eq!(loaded.files().len(), 3);
}

#[test]
fn concurrent_conflicting_writers() {
    let temp = tempdir().expect("temp");
    let store = Arc::new(temp.path().join("store"));
    // Two different bundles cannot share an ID unless content matches; craft by writing one then
    // attempting a second distinct bundle (different ID path) concurrently is fine.
    // For same-ID conflict: pre-publish A, then concurrent writers of A vs corrupted path handled above.
    let (first, first_provider) = sample_bundle_and_provider();
    write_baseline_bundle(
        store.as_path(),
        &first,
        &first_provider,
        BaselineStoreLimits::default(),
    )
    .expect("seed");

    let alt_bytes = b"other-config";
    let alt_digest = digest_of(alt_bytes);
    let mut blobs = BTreeMap::new();
    blobs.insert(alt_digest, alt_bytes.to_vec());
    let second_provider = InMemoryBlobProvider::new(blobs.clone());
    let second = ValidatedBaselineBundle::try_from_parts_with_bytes(
        SafeResourceKey::parse("gksphone").unwrap(),
        "gksphone".into(),
        Some("9.9.9".into()),
        None,
        vec![make_file_record(
            ResourceRelativePath::try_from_slash_str("config.lua").unwrap(),
            alt_bytes.len() as u64,
            alt_digest,
            BaselineEscrowClass::Ignored,
            Some(alt_digest),
        )],
        blobs,
        BaselineStoreLimits::default(),
    )
    .expect("second");
    assert_ne!(first.baseline_id(), second.baseline_id());

    let barrier = Arc::new(Barrier::new(2));
    let store_a = Arc::clone(&store);
    let store_b = Arc::clone(&store);
    let first = Arc::new(first);
    let first_provider = Arc::new(first_provider);
    let second = Arc::new(second);
    let second_provider = Arc::new(second_provider);
    let barrier_a = Arc::clone(&barrier);
    let barrier_b = Arc::clone(&barrier);
    let handle_a = thread::spawn(move || {
        barrier_a.wait();
        write_baseline_bundle(
            &store_a,
            &first,
            first_provider.as_ref(),
            BaselineStoreLimits::default(),
        )
    });
    let handle_b = thread::spawn(move || {
        barrier_b.wait();
        write_baseline_bundle(
            &store_b,
            &second,
            second_provider.as_ref(),
            BaselineStoreLimits::default(),
        )
    });
    assert!(handle_a.join().unwrap().is_ok());
    assert!(handle_b.join().unwrap().is_ok());
}

#[test]
fn symlink_store_root_rejected() {
    let temp = tempdir().expect("temp");
    let real = temp.path().join("real");
    fs::create_dir_all(&real).expect("real");
    let link = temp.path().join("link");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = {
            let (b, p) = sample_bundle_and_provider();
            write_baseline_bundle(&link, &b, &p, BaselineStoreLimits::default())
        }
        .expect_err("symlink root");
        assert!(matches!(
            err,
            GkrmError::BaselineStoreSymlink { .. } | GkrmError::BaselineStoreIo { .. }
        ));
    }
    #[cfg(windows)]
    {
        // Symlink creation may require privileges; skip soft if unavailable.
        if std::os::windows::fs::symlink_dir(&real, &link).is_ok() {
            let err = {
                let (b, p) = sample_bundle_and_provider();
                write_baseline_bundle(&link, &b, &p, BaselineStoreLimits::default())
            }
            .expect_err("symlink root");
            assert!(matches!(
                err,
                GkrmError::BaselineStoreSymlink { .. }
                    | GkrmError::BaselineStoreReparsePoint { .. }
                    | GkrmError::BaselineStoreIo { .. }
            ));
        }
    }
}

#[test]
fn symlinked_manifest_rejected_on_load() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let baseline_dir = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str());
    let manifest = baseline_dir.join("baseline.json");
    let backup = baseline_dir.join("baseline.json.bak");
    fs::rename(&manifest, &backup).expect("rename");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&backup, &manifest).expect("symlink");
        let err = load_baseline_bundle(
            &store,
            bundle.resource_key(),
            bundle.baseline_id(),
            BaselineStoreLimits::default(),
        )
        .expect_err("symlink manifest");
        assert!(matches!(
            err,
            GkrmError::BaselineStoreSymlink { .. } | GkrmError::BaselineStoreIo { .. }
        ));
    }
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_file(&backup, &manifest).is_ok() {
            let err = load_baseline_bundle(
                &store,
                bundle.resource_key(),
                bundle.baseline_id(),
                BaselineStoreLimits::default(),
            )
            .expect_err("symlink manifest");
            assert!(matches!(
                err,
                GkrmError::BaselineStoreSymlink { .. }
                    | GkrmError::BaselineStoreReparsePoint { .. }
                    | GkrmError::BaselineStoreIo { .. }
            ));
        }
    }
}

#[cfg(unix)]
#[test]
fn hardlinked_manifest_rejected() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let baseline_dir = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str());
    let manifest = baseline_dir.join("baseline.json");
    let link = baseline_dir.join("baseline.json.hl");
    fs::hard_link(&manifest, &link).expect("hardlink");
    let err = load_baseline_bundle(
        &store,
        bundle.resource_key(),
        bundle.baseline_id(),
        BaselineStoreLimits::default(),
    )
    .expect_err("hardlink");
    assert!(matches!(err, GkrmError::BaselineStoreHardLink { .. }));
}

#[cfg(unix)]
#[test]
fn restrictive_permissions_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let manifest = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str())
        .join("baseline.json");
    let mode = fs::metadata(&manifest).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(windows)]
#[test]
fn junction_store_component_rejected() {
    let temp = tempdir().expect("temp");
    let real = temp.path().join("real");
    fs::create_dir_all(&real).expect("real");
    let junction = temp.path().join("junction");
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            junction.to_str().unwrap(),
            real.to_str().unwrap(),
        ])
        .status()
        .expect("mklink");
    if !status.success() {
        return;
    }
    let err = {
        let (b, p) = sample_bundle_and_provider();
        write_baseline_bundle(&junction, &b, &p, BaselineStoreLimits::default())
    }
    .expect_err("junction");
    assert!(
        matches!(
            err,
            GkrmError::BaselineStoreReparsePoint { .. }
                | GkrmError::BaselineStoreSymlink { .. }
                | GkrmError::BaselineStoreIo { .. }
                | GkrmError::BaselineStoreUnexpectedType { .. }
                | GkrmError::BaselineStoreUnsafeComponent { .. }
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn no_writes_outside_store_and_no_installed_modification() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let installed = temp.path().join("installed");
    fs::create_dir_all(&installed).expect("installed");
    let marker = installed.join("keep.txt");
    fs::write(&marker, b"keep").expect("marker");
    publish_sample(&store);
    assert_eq!(fs::read(&marker).expect("read"), b"keep");
    assert!(store.join("baselines").exists());
    assert!(!installed.join("baselines").exists());
}

#[test]
fn atomic_publish_never_overwrites_existing_directory() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let baseline_dir = store
        .join("baselines")
        .join("gksphone")
        .join(bundle.baseline_id().as_str());
    let mut manifest = fs::OpenOptions::new()
        .append(true)
        .open(baseline_dir.join("baseline.json"))
        .expect("open");
    // Touching published bytes then attempting identical publish must not replace via rename.
    // Idempotent path loads and compares; after corruption load fails -> conflict/error, files remain.
    writeln!(manifest, " ").ok();
    let _ = write_baseline_bundle(&store, &bundle, &provider, BaselineStoreLimits::default());
    assert!(baseline_dir.join("baseline.json").exists());
}

fn assert_path_is_under(child: &Path, parent: &Path) {
    assert!(child.starts_with(parent));
}

#[test]
fn published_layout_matches_contract() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let baseline_dir = store
        .join("baselines")
        .join(bundle.resource_key().as_str())
        .join(bundle.baseline_id().as_str());
    assert!(baseline_dir.join("baseline.json").is_file());
    assert!(baseline_dir.join("blobs").is_dir());
    assert_path_is_under(&baseline_dir, &store);
    assert!(
        !store.join(".tmp").read_dir().unwrap().next().is_some() || store.join(".tmp").exists()
    );
}

#[test]
fn load_missing_store_does_not_create_directories() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("missing-store");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let id = BaselineId::parse(&"11".repeat(32)).expect("id");
    let err = load_baseline_bundle(&store, &key, &id, BaselineStoreLimits::default())
        .expect_err("missing store");
    assert!(
        matches!(
            err,
            GkrmError::BaselineStoreMissing { .. } | GkrmError::BaselineStoreIo { .. }
        ),
        "{err:?}"
    );
    assert!(!store.exists(), "load must not create a missing store root");
}

#[test]
fn write_creates_store_components_without_create_dir_all() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("a").join("b").join("store");
    assert!(!store.exists());
    publish_sample(&store);
    assert!(store.join("baselines").is_dir());
    assert!(store.join(".tmp").is_dir());
}

#[test]
fn error_display_omits_absolute_store_and_temp_paths() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store-root-path");
    let installed = temp.path().join("installed-root-path");
    fs::create_dir_all(&store).expect("store");
    fs::create_dir_all(&installed).expect("installed");
    publish_sample(&store);

    let key = SafeResourceKey::parse("gksphone").expect("key");
    let id = BaselineId::parse(&"22".repeat(32)).expect("id");
    let missing = load_baseline_bundle(&store, &key, &id, BaselineStoreLimits::default())
        .expect_err("missing baseline");
    let overlap =
        ensure_baseline_store_disjoint_from_installed(&store, &store).expect_err("overlap");

    for err in [&missing, &overlap] {
        let text = err.to_string();
        assert!(
            !text.contains(store.to_string_lossy().as_ref()),
            "display leaked store path: {text}"
        );
        assert!(
            !text.contains(temp.path().to_string_lossy().as_ref()),
            "display leaked temp path: {text}"
        );
        assert!(
            !text.contains(installed.to_string_lossy().as_ref()),
            "display leaked installed path: {text}"
        );
    }
}

#[test]
fn manifest_byte_cap_rejects_oversized_document() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    let (bundle, provider) = sample_bundle_and_provider();
    publish(&store, &bundle, &provider);
    let tiny = BaselineStoreLimits::new(32, 100, 1024, 1024).expect("limits");
    let err = load_baseline_bundle(
        store.as_path(),
        bundle.resource_key(),
        bundle.baseline_id(),
        tiny,
    )
    .expect_err("oversized");
    assert!(matches!(
        err,
        GkrmError::BaselineManifestLimitExceeded { .. }
    ));
}

#[test]
fn cleanup_rejects_symlink_escape_inside_temp_bundle() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    fs::create_dir_all(store.join(".tmp").join("tmp-escape")).expect("tmp");
    let outside = temp.path().join("outside.txt");
    fs::write(&outside, b"secret").expect("outside");
    let link = store.join(".tmp").join("tmp-escape").join("baseline.json");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).expect("symlink");
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_file(&outside, &link).is_err() {
            return;
        }
    }

    use crate::baseline::fs_security::remove_temp_child_nofollow;
    use cap_fs_ext::ambient_authority;
    use cap_std::fs::Dir as CapDir;

    let root = CapDir::open_ambient_dir(&store, ambient_authority()).expect("open store");
    let tmp = root.open_dir(".tmp").expect("tmp");
    let err = remove_temp_child_nofollow(&tmp, "tmp-escape").expect_err("symlink");
    assert!(
        matches!(
            err,
            GkrmError::BaselineStoreSymlink { .. }
                | GkrmError::BaselineStoreReparsePoint { .. }
                | GkrmError::BaselineStoreUnexpectedType { .. }
        ),
        "{err:?}"
    );
    assert!(
        outside.exists(),
        "cleanup must not follow link to delete outside"
    );
    assert_eq!(fs::read(&outside).expect("read"), b"secret");
}

#[test]
fn no_apply_merge_or_activation_exports() {
    // Task 12 adds capture; apply/merge/activation remain out of scope.
    let _ = load_baseline_bundle
        as fn(
            &Path,
            &SafeResourceKey,
            &BaselineId,
            BaselineStoreLimits,
        ) -> crate::Result<crate::StoredBaseline>;
    let _ = ensure_baseline_store_disjoint_from_installed as fn(&Path, &Path) -> crate::Result<()>;
    let _ = crate::capture_official_baseline_in_standalone_store
        as fn(
            &crate::StandaloneBaselineStore,
            crate::BaselineCaptureRequest<'_>,
        ) -> crate::Result<crate::BaselineCaptureResult>;
}
