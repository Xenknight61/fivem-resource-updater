//! Canonical durable recovery authority for Task 31A.

mod body;
mod canonical;
#[allow(dead_code)]
mod compatibility;
mod derivation;
mod envelope;
mod id;
mod installed;
mod limits;

pub use body::RecoveryAuthorityBodyV1;
pub use canonical::{encode_recovery_authority_body, parse_recovery_authority_body};
pub use envelope::{parse_recovery_authority_envelope, RecoveryAuthorityEnvelopeV1};
pub use id::{RecoveryAuthorityId, RecoveryPublicationBindingId};
pub use limits::{RecoveryAuthorityLimits, RecoveryAuthorityParserMemoryEstimate};

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::trusted_apply_planning::{InstalledApplyPlanningSource, InstalledApplyTreeSnapshot};
use crate::{Result, SafeResourceKey, Sha256Digest};

pub(crate) use derivation::{
    dispatch_recovery_derivation, reconstruct_recovery_derivation,
    reconstruct_recovery_derivation_from_snapshot, RecoveryDerivationFromSnapshotRequestV1,
    RecoveryDerivationRequestV1,
};
#[cfg(test)]
pub(crate) use envelope::encode_recovery_authority_envelope;
pub(crate) use envelope::{
    parse_recovery_authority_envelope_reader, write_recovery_authority_envelope, MAX_ENVELOPE_BYTES,
};
pub(crate) use id::encode_publication_binding_id;
#[cfg(test)]
pub(crate) use id::encode_recovery_authority_id_from_body as test_encode_recovery_authority_id;
#[cfg(all(feature = "desktop-test-support", debug_assertions))]
pub(crate) use id::encode_recovery_authority_id_from_body as desktop_test_encode_recovery_authority_id;
pub(crate) use installed::verify_installed_authority_commitment;

#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryAuthorityPublication {
    body: RecoveryAuthorityBodyV1,
    authority_id: RecoveryAuthorityId,
    artifact_id: Sha256Digest,
}

impl std::fmt::Debug for RecoveryAuthorityPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryAuthorityPublication")
    }
}

impl RecoveryAuthorityPublication {
    pub(crate) fn new(
        body: RecoveryAuthorityBodyV1,
        authority_id: RecoveryAuthorityId,
        artifact_id: Sha256Digest,
    ) -> Self {
        Self {
            body,
            authority_id,
            artifact_id,
        }
    }

    pub(crate) fn body(&self) -> &RecoveryAuthorityBodyV1 {
        &self.body
    }

    pub(crate) fn authority_id(&self) -> &RecoveryAuthorityId {
        &self.authority_id
    }

    pub(crate) fn artifact_id(&self) -> &Sha256Digest {
        &self.artifact_id
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_recovery_authority_body(
    installed_source: &InstalledApplyPlanningSource,
    resource_key: &SafeResourceKey,
    baseline_id: Sha256Digest,
    staging_manifest_id: Sha256Digest,
    staging_bundle_id: Sha256Digest,
    apply_plan_id: Sha256Digest,
    transactional_plan_id: Sha256Digest,
    snapshot: &InstalledApplyTreeSnapshot,
    limits: RecoveryAuthorityLimits,
) -> Result<(RecoveryAuthorityBodyV1, RecoveryAuthorityId)> {
    let _contract = dispatch_recovery_derivation(1, 1)?;
    let installed = installed::installed_authority_commitment(installed_source, resource_key)?;
    let selected_resource_commitment = selected_resource_commitment(resource_key)?;
    let body = RecoveryAuthorityBodyV1::from_snapshot(
        installed,
        selected_resource_commitment,
        baseline_id,
        staging_manifest_id,
        staging_bundle_id,
        snapshot.fingerprint,
        apply_plan_id,
        transactional_plan_id,
        snapshot,
    );
    let id = id::encode_recovery_authority_id_from_body(&body, limits)?;
    Ok((body, id))
}

/// Frozen Task 25 selected-resource commitment derived only from a validated key.
pub(crate) fn selected_resource_commitment(resource_key: &SafeResourceKey) -> Result<Sha256Digest> {
    selected_resource_commitment_from_str(resource_key.as_str())
}

pub(crate) fn selected_resource_commitment_from_str(resource_key: &str) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-selected-resource-v1")
        .map_err(|_| crate::GkrmError::TrustedRecoveryAuthorityInvalid)?;
    enc.string(resource_key)
        .map_err(|_| crate::GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    Ok(enc.finish())
}

pub(crate) fn verify_selected_resource_commitment(
    resource_key: &SafeResourceKey,
    stored: &Sha256Digest,
) -> Result<()> {
    if &selected_resource_commitment(resource_key)? != stored {
        return Err(crate::GkrmError::TrustedRecoveryAuthorityBindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
