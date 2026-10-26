//! Deterministic ID encoding for Task 25 CLI artifacts and decisions.

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result, Sha256Digest};

pub(crate) fn encode_decision_document_id(body: &Sha256Digest) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-decision-document-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.digest(body);
    Ok(enc.finish())
}

pub(crate) fn encode_operator_merge_artifact_id(
    plan_id: &Sha256Digest,
    review_id: &Sha256Digest,
    path: &str,
    byte_length: u64,
    content_digest: &Sha256Digest,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-operator-merge-artifact-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.digest(review_id);
    enc.string(path)
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.u64(byte_length);
    enc.digest(content_digest);
    Ok(enc.finish())
}

pub(crate) fn encode_operator_merge_set_id(ids: &[Sha256Digest]) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-operator-merge-set-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.usize(ids.len())
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    for id in ids {
        enc.digest(id);
    }
    Ok(enc.finish())
}

pub(crate) fn encode_resource_commitment(resource_key: &str) -> Result<Sha256Digest> {
    crate::trusted_recovery_authority::selected_resource_commitment_from_str(resource_key)
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)
}

pub(crate) fn encode_cli_artifact_id(body: &Sha256Digest) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-update-artifact-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.digest(body);
    Ok(enc.finish())
}

pub(crate) fn encode_cli_artifact_v2_id(prefix: &[u8]) -> Result<Sha256Digest> {
    use sha2::{Digest, Sha256};

    let prefix_sha256 = Sha256Digest::new(Sha256::digest(prefix).into());
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-update-artifact-v2")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.digest(&prefix_sha256);
    Ok(enc.finish())
}

pub(crate) fn encode_disposition_domain(
    plan_id: &Sha256Digest,
    paths_and_dispositions: &[(String, u8)],
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-cli-decision-disposition-domain-v1")
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.usize(paths_and_dispositions.len())
        .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
    for (path, disp) in paths_and_dispositions {
        enc.string(path)
            .map_err(|_| GkrmError::TrustedCliUpdateIdEncodingFailure)?;
        enc.u8(*disp);
    }
    Ok(enc.finish())
}
