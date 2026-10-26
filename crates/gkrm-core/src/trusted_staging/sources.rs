//! Retained installed/incoming content sources for Task 20 staging.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::file_identity::StableFileIdentity;
use crate::package_source::PackageSnapshot;
use crate::three_way_merge_analysis::{
    IncomingMergeContentSource, IncomingMergeContentSourceLimits, InstalledMergeContentSource,
};
use crate::{
    GkrmError, InstalledResourceRoot, InstalledScanLimits, ResourceRelativePath, Result,
    Sha256Digest, ZipResourceRoot,
};

/// Retained installed capability for staging any plan path.
pub struct InstalledStagingContentSource {
    installed_root: PathBuf,
    inner: InstalledMergeContentSource,
}

impl InstalledStagingContentSource {
    pub fn try_new(
        installed_root: &Path,
        selected_resource_root: InstalledResourceRoot,
        limits: InstalledScanLimits,
    ) -> Result<Self> {
        Ok(Self {
            installed_root: installed_root.to_path_buf(),
            inner: InstalledMergeContentSource::try_new(
                installed_root,
                selected_resource_root,
                limits,
            )?,
        })
    }

    pub(super) fn stream_verified(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        on_chunk: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        super::note_source_read();
        self.inner
            .stream_verified_file_bytes(path, expected_digest, on_chunk)
            .map_err(map_installed)
    }

    pub(super) fn installed_root_path(&self) -> &Path {
        &self.installed_root
    }

    pub(super) fn root_identity(&self) -> &StableFileIdentity {
        self.inner.installed_root_identity()
    }

    pub(super) fn resource_identity(&self) -> &StableFileIdentity {
        self.inner.selected_resource_identity()
    }
}

impl std::fmt::Debug for InstalledStagingContentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstalledStagingContentSource")
    }
}

/// Retained incoming package capability for staging any plan path.
pub struct IncomingStagingContentSource {
    inner: IncomingMergeContentSource,
}

impl IncomingStagingContentSource {
    pub fn try_new(
        package_path: &Path,
        selected_resource_root: ZipResourceRoot,
        limits: IncomingMergeContentSourceLimits,
    ) -> Result<Self> {
        Ok(Self {
            inner: IncomingMergeContentSource::try_new(
                package_path,
                selected_resource_root,
                limits,
            )?,
        })
    }

    pub(crate) fn from_package_snapshot(
        snapshot: Arc<PackageSnapshot>,
        selected_resource_root: ZipResourceRoot,
        limits: IncomingMergeContentSourceLimits,
    ) -> Result<Self> {
        Ok(Self {
            inner: IncomingMergeContentSource::from_package_snapshot(
                snapshot,
                selected_resource_root,
                limits,
            )?,
        })
    }

    pub(super) fn stream_verified(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        on_chunk: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        super::note_source_read();
        self.inner
            .stream_verified_entry_bytes(path, expected_digest, on_chunk)
            .map_err(map_incoming)
    }

    pub(super) fn package_fingerprint(&self) -> &Sha256Digest {
        self.inner.package_fingerprint()
    }

    pub(super) fn resource_fingerprint(&self) -> &Sha256Digest {
        self.inner.resource_fingerprint()
    }

    pub(super) fn package_path(&self) -> &Path {
        self.inner.source_package_path()
    }

    #[cfg(test)]
    pub(super) fn snapshot_temp_path_for_test(&self) -> &Path {
        self.inner.snapshot_temp_path_for_test()
    }
}

impl std::fmt::Debug for IncomingStagingContentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IncomingStagingContentSource")
    }
}

fn map_installed(error: GkrmError) -> GkrmError {
    map_source_boundary(error)
}

fn map_incoming(error: GkrmError) -> GkrmError {
    map_source_boundary(error)
}

fn map_source_boundary(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
        | GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid
        | GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged => {
            GkrmError::TrustedStagingSourceUnavailable
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::TrustedStagingArithmeticOverflow
        }
        GkrmError::BaselineStoreIo { cause: source, .. } => {
            let kind = source.kind();
            drop(source);
            GkrmError::TrustedStagingIo {
                operation: crate::StagingIoOperation::ReadSource,
                kind,
            }
        }
        GkrmError::BaselineAtomicPublishFailure { cause: source } => {
            let kind = source.kind();
            drop(source);
            GkrmError::TrustedStagingIo {
                operation: crate::StagingIoOperation::ReadSource,
                kind,
            }
        }
        GkrmError::TrustedStagingWriteFailure { source } => map_source_boundary(*source),
        // Preserve Task 20 errors from write callbacks / prior sanitization.
        GkrmError::TrustedStagingIo { .. }
        | GkrmError::TrustedStagingUnsafeFilesystemObject
        | GkrmError::TrustedStagingDigestLengthMismatch
        | GkrmError::TrustedStagingArithmeticOverflow
        | GkrmError::TrustedStagingSourceUnavailable
        | GkrmError::TrustedStagingFinalTreeRejected
        | GkrmError::TrustedStagingManifestTreeMismatch => error,
        other => {
            let _ = other;
            GkrmError::TrustedStagingSourceUnavailable
        }
    }
}
