//! Public-surface checks for the baseline store.
//!
//! Full write/load coverage lives in `gkrm-core` unit tests because
//! `write_baseline_bundle` is crate-private until Task 12 capture APIs land.

use gkrm_core::{
    ensure_baseline_store_disjoint_from_installed, load_baseline_bundle, BaselineId,
    BaselineStoreLimits, GkrmError, SafeResourceKey,
};
use tempfile::tempdir;

#[test]
fn public_types_parse_and_reject_unsafe_keys() {
    assert!(SafeResourceKey::parse("gksphone").is_ok());
    assert!(SafeResourceKey::parse("../x").is_err());
    assert!(BaselineId::parse(&"ab".repeat(32)).is_ok());
    assert!(BaselineId::parse("nope").is_err());
}

#[test]
fn load_missing_baseline_is_structured_error() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("store");
    // Pre-create only the empty store root; load must not create baselines/.tmp.
    std::fs::create_dir_all(&store).expect("store");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let id = BaselineId::parse(&"11".repeat(32)).expect("id");
    let err = load_baseline_bundle(&store, &key, &id, BaselineStoreLimits::default())
        .expect_err("missing");
    assert!(matches!(
        err,
        GkrmError::BaselineStoreMissing { .. } | GkrmError::BaselineStoreIo { .. }
    ));
    assert!(!store.join("baselines").exists());
    assert!(!store.join(".tmp").exists());
}

#[test]
fn load_nonexistent_store_root_does_not_create_it() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("does-not-exist");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let id = BaselineId::parse(&"11".repeat(32)).expect("id");
    let _ = load_baseline_bundle(&store, &key, &id, BaselineStoreLimits::default())
        .expect_err("missing");
    assert!(!store.exists());
}

#[test]
fn disjoint_helper_rejects_equal_roots() {
    let temp = tempdir().expect("temp");
    let root = temp.path().join("root");
    std::fs::create_dir_all(&root).expect("root");
    let err = ensure_baseline_store_disjoint_from_installed(&root, &root).expect_err("overlap");
    assert!(matches!(err, GkrmError::BaselineStoreInstallOverlap));
}
