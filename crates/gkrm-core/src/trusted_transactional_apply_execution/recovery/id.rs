//! Deterministic ID encoding for Task 24 recovery results.

use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result, Sha256Digest};

pub(crate) fn encode_candidate_id(plan_id: &Sha256Digest) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-recovery-candidate-v1")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    enc.digest(plan_id);
    Ok(enc.finish())
}

pub(crate) fn encode_malformed_candidate_id(index: u64) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-recovery-malformed-candidate-v1")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    enc.u64(index);
    Ok(enc.finish())
}

pub(crate) fn encode_scan_result_id(plan_ids: &[Sha256Digest]) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-recovery-scan-result-v1")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    enc.usize(plan_ids.len())
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    for id in plan_ids {
        enc.digest(id);
    }
    Ok(enc.finish())
}

pub(crate) fn encode_recovery_result_id(
    plan_id: &Sha256Digest,
    tag: &[u8],
    related: Option<&Sha256Digest>,
) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-recovery-result-v1")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    enc.digest(plan_id);
    enc.octet_string(tag)
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    match related {
        Some(d) => {
            enc.u8(1);
            enc.digest(d);
        }
        None => enc.u8(0),
    }
    Ok(enc.finish())
}

pub(crate) fn encode_recovery_result_id_pub(
    plan_id: &Sha256Digest,
    tag: &[u8],
    related: Option<&Sha256Digest>,
) -> Result<Sha256Digest> {
    encode_recovery_result_id(plan_id, tag, related)
}

#[allow(dead_code)] // Fixed-vector / lock-binding identity surface for Task 24.
pub(crate) fn encode_transaction_lock_binding_id(plan_id: &Sha256Digest) -> Result<Sha256Digest> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-transaction-lock-binding-v1")
        .map_err(|_| GkrmError::TrustedTransactionRecoveryIdEncodingFailure)?;
    enc.digest(plan_id);
    Ok(enc.finish())
}
