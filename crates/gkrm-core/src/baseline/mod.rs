//! Local portable baseline bundle format and secure filesystem store.
//!
//! Baselines represent official incoming resource releases only. They are never
//! derived from installed customer resource trees.

mod blob_provider;
mod canonical;
mod capture;
mod catalog;
mod dto;
pub(crate) mod fs_security;
mod id;
mod key;
mod model;
pub(crate) mod store;

#[cfg(test)]
mod store_tests;

#[cfg(test)]
mod capture_tests;

#[cfg(test)]
mod capture_boundary_tests;

#[cfg(test)]
mod capture_redaction_tests;

#[cfg(test)]
mod capture_cleanup_matrix_tests;

#[cfg(test)]
mod capture_spool_guard_tests;

#[cfg(test)]
mod capture_isolation_tests;

pub use crate::error::BaselineCatalogValidationCategory;
#[cfg(test)]
pub(crate) use blob_provider::InMemoryBlobProvider;
pub(crate) use capture::retain_stored_baseline_in_workspace;
pub use capture::{
    capture_official_baseline_from_package_in_trusted_update_workspace,
    capture_official_baseline_in_standalone_store, capture_official_baseline_in_workspace,
    capture_official_baseline_in_workspace_with_expected_package_commitment,
    resolve_standalone_baseline_store, BaselineCaptureOptions, BaselineCaptureRequest,
    BaselineCaptureResult, BaselineCaptureWarning, ExpectedPackageBaselineCaptureRequest,
    IncomingResourceSelector, StandaloneBaselineStore,
};
pub use catalog::{
    catalog_official_baselines, resolve_official_baseline, BaselineCatalog, BaselineCatalogEntry,
    BaselineCatalogIssue, BaselineCatalogIssueKind, BaselineCatalogRequest,
    BaselineResolutionOptions, BaselineResolutionRequest, OfficialBaselineSelector,
    ResolvedBaselineSelectionKind, ResolvedOfficialBaseline,
};
pub use fs_security::ensure_baseline_store_disjoint_from_installed;
pub use id::BaselineId;
pub use key::SafeResourceKey;
#[cfg(test)]
pub(crate) use model::make_file_record;
#[cfg(test)]
pub(crate) use model::ValidatedBaselineBundle;
pub use model::{
    BaselineCounts, BaselineEscrowClass, BaselineFileRecord, BaselineStoreLimits, StoredBaseline,
    StoredBaselineLocator,
};
pub use store::{discard_baseline_bundle, load_baseline_bundle};

#[cfg(test)]
mod public_surface_tests {
    use super::BaselineEscrowClass;

    #[test]
    fn trusted_escrow_class_exposes_stable_codes_without_serde_derives() {
        // Trusted domain enum must remain free of public Serialize/Deserialize derives.
        // JSON mapping happens only through private EscrowClassDto in dto.rs.
        assert_eq!(BaselineEscrowClass::Protected.as_str(), "protected");
        assert_eq!(BaselineEscrowClass::Ignored.as_str(), "ignored");
        assert_eq!(BaselineEscrowClass::NotSupported.as_str(), "not_supported");
        assert_eq!(BaselineEscrowClass::Protected.as_stable_code(), 1);
        assert_eq!(BaselineEscrowClass::Ignored.as_stable_code(), 2);
        assert_eq!(BaselineEscrowClass::NotSupported.as_stable_code(), 3);
    }
}
