//! Public-surface checks for official baseline catalog and resolution.

use gkrm_core::{
    catalog_official_baselines, resolve_official_baseline, BaselineCatalogIssueKind,
    BaselineCatalogRequest, BaselineCatalogValidationCategory, BaselineResolutionOptions,
    BaselineResolutionRequest, BaselineStoreLimits, GkrmError, OfficialBaselineSelector,
    SafeResourceKey,
};
use tempfile::tempdir;

#[test]
fn public_catalog_missing_store_is_empty_and_read_only() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("missing");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let request =
        BaselineCatalogRequest::try_new(&store, &key, BaselineResolutionOptions::default())
            .expect("request");

    let catalog = catalog_official_baselines(request).expect("catalog");

    assert_eq!(catalog.resource_key(), &key);
    assert!(catalog.entries().is_empty());
    assert!(catalog.issues().is_empty());
    assert!(!store.exists());
}

#[test]
fn public_resolution_options_reject_zero_catalog_limit() {
    let err =
        BaselineResolutionOptions::try_new(BaselineStoreLimits::default(), 0).expect_err("zero");

    assert!(matches!(
        err,
        GkrmError::BaselineResolutionOptionsInvalid {
            limit: "max_catalog_entries"
        }
    ));
}

#[test]
fn public_auto_single_missing_store_reports_no_baselines() {
    let temp = tempdir().expect("temp");
    let store = temp.path().join("missing");
    let key = SafeResourceKey::parse("gksphone").expect("key");
    let request = BaselineResolutionRequest::try_new(
        &store,
        &key,
        OfficialBaselineSelector::AutoSingle,
        BaselineResolutionOptions::default(),
    )
    .expect("request");

    let err = resolve_official_baseline(request).expect_err("missing");

    assert!(matches!(err, GkrmError::BaselineNoStoredBaselines));
    assert!(!store.exists());
}

#[test]
fn public_issue_and_validation_categories_are_stable_values() {
    assert_eq!(
        BaselineCatalogIssueKind::InvalidCandidateName,
        BaselineCatalogIssueKind::InvalidCandidateName
    );
    assert_eq!(
        BaselineCatalogValidationCategory::BlobDigest.to_string(),
        "blob-digest"
    );
}
