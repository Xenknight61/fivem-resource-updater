use std::io::{Read, Write};

use crate::{GkrmError, Result, Sha256Digest};

use super::canonical::{encode_into, estimated_body_bytes, parse_recovery_authority_body_reader};
use super::id::{
    encode_recovery_authority_id_from_body, RecoveryAuthorityId, RecoveryPublicationBindingId,
};
use super::{RecoveryAuthorityBodyV1, RecoveryAuthorityLimits};

const ENVELOPE_MAGIC: &[u8] = b"gkrm-recovery-authority-envelope-v1\n";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_IDS_BYTES: usize = 3 * 32;
pub(crate) const MAX_ENVELOPE_BYTES: usize =
    super::limits::MAX_RECOVERY_AUTHORITY_BODY_BYTES + 36 + 1 + 8 + ENVELOPE_IDS_BYTES;

#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryAuthorityEnvelopeV1 {
    body: RecoveryAuthorityBodyV1,
    authority_id: RecoveryAuthorityId,
    artifact_id: Sha256Digest,
    publication_binding_id: RecoveryPublicationBindingId,
}

impl std::fmt::Debug for RecoveryAuthorityEnvelopeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryAuthorityEnvelopeV1")
    }
}

impl RecoveryAuthorityEnvelopeV1 {
    pub(crate) fn create(
        body: RecoveryAuthorityBodyV1,
        expected_authority_id: RecoveryAuthorityId,
        artifact_id: Sha256Digest,
        publication_binding_id: RecoveryPublicationBindingId,
        limits: RecoveryAuthorityLimits,
    ) -> Result<Self> {
        let authority_id = encode_recovery_authority_id_from_body(&body, limits)?;
        if authority_id != expected_authority_id {
            return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
        }
        Ok(Self {
            body,
            authority_id,
            artifact_id,
            publication_binding_id,
        })
    }

    pub fn body(&self) -> &RecoveryAuthorityBodyV1 {
        &self.body
    }

    pub fn authority_id(&self) -> &RecoveryAuthorityId {
        &self.authority_id
    }

    pub fn artifact_id(&self) -> &Sha256Digest {
        &self.artifact_id
    }

    pub fn publication_binding_id(&self) -> &RecoveryPublicationBindingId {
        &self.publication_binding_id
    }
}

pub(crate) fn write_recovery_authority_envelope<W: Write>(
    envelope: &RecoveryAuthorityEnvelopeV1,
    writer: &mut W,
    limits: RecoveryAuthorityLimits,
) -> Result<()> {
    let body_len = estimated_body_bytes(&envelope.body)?;
    if body_len > limits.validate()?.max_body_bytes {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        });
    }
    writer
        .write_all(ENVELOPE_MAGIC)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    writer
        .write_all(&[ENVELOPE_VERSION])
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    writer
        .write_all(
            &u64::try_from(body_len)
                .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
                .to_le_bytes(),
        )
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    encode_into(&envelope.body, &mut *writer, limits)?;
    writer
        .write_all(envelope.authority_id.digest().as_bytes())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    writer
        .write_all(envelope.artifact_id.as_bytes())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    writer
        .write_all(envelope.publication_binding_id.digest().as_bytes())
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn encode_recovery_authority_envelope(
    envelope: &RecoveryAuthorityEnvelopeV1,
    limits: RecoveryAuthorityLimits,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            estimated_body_bytes(envelope.body())?
                .checked_add(ENVELOPE_MAGIC.len() + 1 + 8 + ENVELOPE_IDS_BYTES)
                .ok_or(GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?,
        )
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        })?;
    write_recovery_authority_envelope(envelope, &mut bytes, limits)?;
    Ok(bytes)
}

pub fn parse_recovery_authority_envelope(
    bytes: &[u8],
    limits: RecoveryAuthorityLimits,
) -> Result<RecoveryAuthorityEnvelopeV1> {
    parse_recovery_authority_envelope_reader(&mut std::io::Cursor::new(bytes), limits)
}

pub(crate) fn parse_recovery_authority_envelope_reader<R: Read>(
    reader: &mut R,
    limits: RecoveryAuthorityLimits,
) -> Result<RecoveryAuthorityEnvelopeV1> {
    let limits = limits.validate()?;
    let mut magic = [0_u8; 36];
    reader
        .read_exact(&mut magic)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    if magic != ENVELOPE_MAGIC {
        return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
    }
    let mut version = [0_u8; 1];
    reader
        .read_exact(&mut version)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    if version[0] != ENVELOPE_VERSION {
        return Err(GkrmError::TrustedRecoveryAuthorityVersionUnsupported);
    }
    let mut length = [0_u8; 8];
    reader
        .read_exact(&mut length)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    let body_len = u64::from_le_bytes(length);
    if body_len
        > u64::try_from(limits.max_body_bytes)
            .map_err(|_| GkrmError::TrustedRecoveryAuthorityArithmeticOverflow)?
    {
        return Err(GkrmError::TrustedRecoveryAuthorityLimitExceeded {
            limit: "max_body_bytes",
        });
    }
    let (body, authority_id) = parse_recovery_authority_body_reader(reader, body_len, limits)?;
    let stored_authority = read_digest(reader)?;
    if stored_authority != *authority_id.digest() {
        return Err(GkrmError::TrustedRecoveryAuthorityBindingMismatch);
    }
    let artifact_id = read_digest(reader)?;
    let publication_binding_id = RecoveryPublicationBindingId(read_digest(reader)?);
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?
        != 0
    {
        return Err(GkrmError::TrustedRecoveryAuthorityInvalid);
    }
    Ok(RecoveryAuthorityEnvelopeV1 {
        body,
        authority_id,
        artifact_id,
        publication_binding_id,
    })
}

fn read_digest<R: Read>(reader: &mut R) -> Result<Sha256Digest> {
    let mut bytes = [0_u8; 32];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| GkrmError::TrustedRecoveryAuthorityInvalid)?;
    Ok(Sha256Digest::new(bytes))
}
