use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, Result, Sha256Digest};
use sha2::{Digest, Sha256};

use super::canonical::{encode_into, estimated_body_bytes};
use super::{RecoveryAuthorityBodyV1, RecoveryAuthorityLimits};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryAuthorityId(pub(crate) Sha256Digest);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecoveryPublicationBindingId(pub(crate) Sha256Digest);

macro_rules! opaque_id_impl {
    ($name:ident) => {
        impl $name {
            pub fn to_hex(&self) -> String {
                self.0.to_string()
            }

            pub(crate) fn digest(&self) -> &Sha256Digest {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

opaque_id_impl!(RecoveryAuthorityId);
opaque_id_impl!(RecoveryPublicationBindingId);

#[cfg(test)]
pub(crate) fn encode_recovery_authority_id(body: &[u8]) -> Result<RecoveryAuthorityId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-recovery-authority-id-v1")
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    enc.octet_string(body)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?;
    Ok(RecoveryAuthorityId(enc.finish()))
}

pub(crate) fn encode_recovery_authority_id_from_body(
    body: &RecoveryAuthorityBodyV1,
    limits: RecoveryAuthorityLimits,
) -> Result<RecoveryAuthorityId> {
    let body_len = estimated_body_bytes(body)?;
    let domain = b"gkrm-recovery-authority-id-v1";
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
            .to_le_bytes(),
    );
    hasher.update(domain);
    hasher.update(
        u64::try_from(body_len)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
            .to_le_bytes(),
    );
    encode_into(body, HashWriter(&mut hasher), limits)?;
    Ok(RecoveryAuthorityId(Sha256Digest::new(
        hasher.finalize().into(),
    )))
}

struct HashWriter<'a>(&'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn encode_publication_binding_id(
    artifact_id: &Sha256Digest,
    authority_id: &RecoveryAuthorityId,
    transactional_plan_id: &Sha256Digest,
    snapshot_a_id: &Sha256Digest,
    resource_lock_id: &Sha256Digest,
) -> Result<RecoveryPublicationBindingId> {
    let mut enc = CanonicalFingerprintEncoder::new("gkrm-recovery-publication-binding-v1")
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    enc.digest(artifact_id);
    enc.digest(authority_id.digest());
    enc.digest(transactional_plan_id);
    enc.digest(snapshot_a_id);
    enc.digest(resource_lock_id);
    Ok(RecoveryPublicationBindingId(enc.finish()))
}
