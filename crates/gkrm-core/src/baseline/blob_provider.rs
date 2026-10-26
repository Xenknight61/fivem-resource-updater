//! Crate-private verified blob sources for baseline publication.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};

use cap_std::fs::File as CapFile;
use sha2::{Digest, Sha256};

use crate::baseline::fs_security::capture_file_identity;
use crate::file_identity::StableFileIdentity;
use crate::{GkrmError, Result, Sha256Digest};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

enum VerifiedBlobSource {
    /// Production spool / store file with bound stable identity.
    CapFile {
        file: CapFile,
        identity: StableFileIdentity,
        component: String,
    },
    /// Test and load-path reconstruction only (no filesystem identity).
    Memory { cursor: Cursor<Vec<u8>> },
}

/// Reader returned by a verified blob provider (streamed, size-bounded).
pub(crate) struct VerifiedBlobReader {
    expected_size: u64,
    expected_digest: Sha256Digest,
    source: VerifiedBlobSource,
}

impl VerifiedBlobReader {
    pub(crate) fn from_cap_file(
        expected_digest: Sha256Digest,
        expected_size: u64,
        file: CapFile,
        identity: StableFileIdentity,
        component: impl Into<String>,
    ) -> Self {
        Self {
            expected_size,
            expected_digest,
            source: VerifiedBlobSource::CapFile {
                file,
                identity,
                component: component.into(),
            },
        }
    }

    pub(crate) fn from_memory(
        expected_digest: Sha256Digest,
        expected_size: u64,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            expected_size,
            expected_digest,
            source: VerifiedBlobSource::Memory {
                cursor: Cursor::new(bytes),
            },
        }
    }

    pub(crate) fn expected_size(&self) -> u64 {
        self.expected_size
    }

    pub(crate) fn expected_digest(&self) -> &Sha256Digest {
        &self.expected_digest
    }

    pub(crate) fn has_bound_source_identity(&self) -> bool {
        matches!(self.source, VerifiedBlobSource::CapFile { .. })
    }

    pub(crate) fn revalidate_source_identity(&self) -> Result<()> {
        match &self.source {
            VerifiedBlobSource::Memory { .. } => Ok(()),
            VerifiedBlobSource::CapFile {
                file,
                identity,
                component,
            } => {
                let actual = capture_file_identity(file, component)?;
                if actual != *identity {
                    return Err(GkrmError::BaselineCaptureSpoolIdentityChanged);
                }
                Ok(())
            }
        }
    }
}

impl Read for VerifiedBlobReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.source {
            VerifiedBlobSource::CapFile { file, .. } => file.read(buf),
            VerifiedBlobSource::Memory { cursor } => cursor.read(buf),
        }
    }
}

/// Opens verified blob sources by digest without requiring a full in-memory blob map.
pub(crate) trait VerifiedBaselineBlobProvider {
    fn open_verified_blob(&self, digest: &Sha256Digest) -> Result<VerifiedBlobReader>;
}

/// Bounded in-memory provider for unit tests and load-path reconstruction only.
#[derive(Debug, Clone, Default)]
pub(crate) struct InMemoryBlobProvider {
    blobs: BTreeMap<Sha256Digest, Vec<u8>>,
}

impl InMemoryBlobProvider {
    pub(crate) fn new(blobs: BTreeMap<Sha256Digest, Vec<u8>>) -> Self {
        Self { blobs }
    }

    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, digest: Sha256Digest, bytes: Vec<u8>) {
        self.blobs.insert(digest, bytes);
    }

    #[allow(dead_code)]
    pub(crate) fn get(&self, digest: &Sha256Digest) -> Option<&[u8]> {
        self.blobs.get(digest).map(Vec::as_slice)
    }
}

impl VerifiedBaselineBlobProvider for InMemoryBlobProvider {
    fn open_verified_blob(&self, digest: &Sha256Digest) -> Result<VerifiedBlobReader> {
        let bytes = self
            .blobs
            .get(digest)
            .ok_or_else(|| GkrmError::BaselineMissingBlob {
                digest: digest.to_string(),
            })?;
        Ok(VerifiedBlobReader::from_memory(
            *digest,
            bytes.len() as u64,
            bytes.clone(),
        ))
    }
}

/// Copy a verified blob reader into `writer`, enforcing identity (when bound), size, and digest.
///
/// Destination flush/fsync remains the caller's responsibility and must happen only after this
/// function returns successfully.
pub(crate) fn copy_verified_blob_to_writer<W: Write>(
    mut reader: VerifiedBlobReader,
    writer: &mut W,
    max_blob_bytes: u64,
) -> Result<()> {
    if reader.expected_size() > max_blob_bytes {
        return Err(GkrmError::BaselineBlobLimitExceeded {
            digest: reader.expected_digest().to_string(),
            limit: max_blob_bytes,
            actual: reader.expected_size(),
        });
    }

    reader.revalidate_source_identity()?;
    if reader.has_bound_source_identity() {
        run_during_writer_copy_hook()?;
    }

    let expected_size = reader.expected_size();
    let expected_digest = *reader.expected_digest();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_SIZE];
    let mut copied = 0_u64;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: format!("blobs/{}", expected_digest),
                cause: source,
            })?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(GkrmError::BaselineBlobSizeMismatch {
                digest: expected_digest.to_string(),
                expected: expected_size,
                actual: u64::MAX,
            })?;
        if copied > expected_size {
            return Err(GkrmError::BaselineBlobSizeMismatch {
                digest: expected_digest.to_string(),
                expected: expected_size,
                actual: copied,
            });
        }
        hasher.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|source| GkrmError::BaselineStoreIo {
                component: format!("blobs/{}", expected_digest),
                cause: source,
            })?;
    }

    if copied != expected_size {
        return Err(GkrmError::BaselineBlobSizeMismatch {
            digest: expected_digest.to_string(),
            expected: expected_size,
            actual: copied,
        });
    }

    let actual = Sha256Digest::new(hasher.finalize().into());
    if actual != expected_digest {
        return Err(GkrmError::BaselineBlobDigestMismatch {
            digest: expected_digest.to_string(),
        });
    }

    reader.revalidate_source_identity()?;
    Ok(())
}

fn run_during_writer_copy_hook() -> Result<()> {
    #[cfg(test)]
    {
        crate::baseline::capture::test_seams::run_during_writer_copy_hook()
    }
    #[cfg(not(test))]
    {
        Ok(())
    }
}
