use sha2::{Digest, Sha256};

use crate::{
    BaselineEscrowClass, GkrmError, ResourceRelativePath, Result, SafeResourceKey, Sha256Digest,
};

pub(crate) struct InstalledFingerprintFile<'a> {
    pub(crate) path: &'a ResourceRelativePath,
    pub(crate) sha256: &'a Sha256Digest,
}

pub(crate) struct InstalledSourceCommitmentFile<'a> {
    pub(crate) path: &'a ResourceRelativePath,
    pub(crate) size: u64,
    pub(crate) sha256: &'a Sha256Digest,
}

pub(crate) struct IncomingFingerprintFile<'a> {
    pub(crate) path: &'a ResourceRelativePath,
    pub(crate) sha256: &'a Sha256Digest,
    pub(crate) escrow_class: BaselineEscrowClass,
}

pub(crate) fn installed_resource_fingerprint(
    resource_key: &SafeResourceKey,
    files: &[InstalledFingerprintFile<'_>],
) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-installed-resource-snapshot-v1")?;
    encoder.string(resource_key.as_str())?;
    encoder.usize(files.len())?;
    for file in files {
        encoder.path(file.path)?;
        encoder.u8(1);
        encoder.digest(file.sha256);
    }
    Ok(encoder.finish())
}

pub(crate) fn installed_resource_source_commitment(
    resource_key: &SafeResourceKey,
    files: &[InstalledSourceCommitmentFile<'_>],
) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-installed-resource-source-v1")?;
    encoder.string(resource_key.as_str())?;
    encoder.usize(files.len())?;
    for file in files {
        encoder.path(file.path)?;
        encoder.u8(1);
        encoder.u64(file.size);
        encoder.digest(file.sha256);
    }
    Ok(encoder.finish())
}

pub(crate) fn incoming_resource_fingerprint(
    package_fingerprint: &Sha256Digest,
    resource_key: &SafeResourceKey,
    root_identity: &str,
    files: &[IncomingFingerprintFile<'_>],
) -> Result<Sha256Digest> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-incoming-resource-snapshot-v1")?;
    encoder.digest(package_fingerprint);
    encoder.string(resource_key.as_str())?;
    encoder.string(root_identity)?;
    encoder.usize(files.len())?;
    for file in files {
        encoder.path(file.path)?;
        encoder.u8(1);
        encoder.digest(file.sha256);
        encoder.escrow_class(Some(file.escrow_class));
    }
    Ok(encoder.finish())
}

pub(crate) struct CanonicalFingerprintEncoder {
    bytes: Vec<u8>,
}

impl CanonicalFingerprintEncoder {
    pub(crate) fn new(domain: &'static str) -> Result<Self> {
        let mut encoder = Self { bytes: Vec::new() };
        encoder.string(domain)?;
        Ok(encoder)
    }

    pub(crate) fn string(&mut self, value: &str) -> Result<()> {
        self.usize(value.len())?;
        self.bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }

    /// Length-prefixed opaque byte string (non-UTF-8-safe counterpart to [`Self::string`]).
    pub(crate) fn octet_string(&mut self, value: &[u8]) -> Result<()> {
        self.usize(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    pub(crate) fn path(&mut self, path: &ResourceRelativePath) -> Result<()> {
        self.string(path.as_str())
    }

    pub(crate) fn digest(&mut self, digest: &Sha256Digest) {
        self.bytes.extend_from_slice(digest.as_bytes());
    }

    pub(crate) fn usize(&mut self, value: usize) -> Result<()> {
        let value = u64::try_from(value).map_err(|_| GkrmError::ThreeWayArithmeticOverflow)?;
        self.bytes.extend_from_slice(&value.to_le_bytes());
        Ok(())
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn optional_usize(&mut self, value: Option<usize>) -> Result<()> {
        match value {
            Some(value) => {
                self.u8(1);
                self.usize(value)?;
            }
            None => self.u8(0),
        }
        Ok(())
    }

    pub(crate) fn escrow_class(&mut self, value: Option<BaselineEscrowClass>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u8(value.as_stable_code());
            }
            None => self.u8(0),
        }
    }

    pub(crate) fn finish(self) -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(self.bytes).into())
    }
}
