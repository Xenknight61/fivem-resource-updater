use std::collections::BTreeMap;

use crate::baseline::canonical::{compute_baseline_id, CanonicalBaselineInput, CanonicalFileInput};
use crate::baseline::id::BaselineId;
use crate::baseline::key::SafeResourceKey;
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest};

/// Stable escrow class codes stored in baselines (no ignore-pattern lists).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BaselineEscrowClass {
    Protected,
    Ignored,
    NotSupported,
}

impl BaselineEscrowClass {
    pub fn as_stable_code(self) -> u8 {
        match self {
            Self::Protected => 1,
            Self::Ignored => 2,
            Self::NotSupported => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::Ignored => "ignored",
            Self::NotSupported => "not_supported",
        }
    }
}

/// One official incoming file recorded in a baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineFileRecord {
    relative_path: ResourceRelativePath,
    size: u64,
    sha256: Sha256Digest,
    escrow_class: BaselineEscrowClass,
    blob_sha256: Option<Sha256Digest>,
}

impl BaselineFileRecord {
    pub fn relative_path(&self) -> &ResourceRelativePath {
        &self.relative_path
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    pub fn escrow_class(&self) -> BaselineEscrowClass {
        self.escrow_class
    }

    pub fn blob_sha256(&self) -> Option<&Sha256Digest> {
        self.blob_sha256.as_ref()
    }
}

/// Derived aggregate counts for a baseline inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCounts {
    files: u64,
    protected_files: u64,
    ignored_files: u64,
    not_supported_files: u64,
    blobs: u64,
    total_blob_bytes: u64,
}

impl BaselineCounts {
    pub fn files(&self) -> u64 {
        self.files
    }

    pub fn protected_files(&self) -> u64 {
        self.protected_files
    }

    pub fn ignored_files(&self) -> u64 {
        self.ignored_files
    }

    pub fn not_supported_files(&self) -> u64 {
        self.not_supported_files
    }

    pub fn blobs(&self) -> u64 {
        self.blobs
    }

    pub fn total_blob_bytes(&self) -> u64 {
        self.total_blob_bytes
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        files: u64,
        protected_files: u64,
        ignored_files: u64,
        not_supported_files: u64,
        blobs: u64,
        total_blob_bytes: u64,
    ) -> Self {
        Self {
            files,
            protected_files,
            ignored_files,
            not_supported_files,
            blobs,
            total_blob_bytes,
        }
    }
}

/// Hard limits applied while writing or loading baseline bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineStoreLimits {
    max_manifest_bytes: u64,
    max_files: usize,
    max_blob_bytes: u64,
    max_total_blob_bytes: u64,
}

impl Default for BaselineStoreLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 1_048_576,
            max_files: 20_000,
            max_blob_bytes: 512 * 1024 * 1024,
            max_total_blob_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

impl BaselineStoreLimits {
    pub fn new(
        max_manifest_bytes: u64,
        max_files: usize,
        max_blob_bytes: u64,
        max_total_blob_bytes: u64,
    ) -> Result<Self> {
        let limits = Self {
            max_manifest_bytes,
            max_files,
            max_blob_bytes,
            max_total_blob_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn max_manifest_bytes(&self) -> u64 {
        self.max_manifest_bytes
    }

    pub fn max_files(&self) -> usize {
        self.max_files
    }

    pub fn max_blob_bytes(&self) -> u64 {
        self.max_blob_bytes
    }

    pub fn max_total_blob_bytes(&self) -> u64 {
        self.max_total_blob_bytes
    }

    pub(crate) fn validate(self) -> Result<()> {
        if self.max_manifest_bytes == 0 {
            return Err(GkrmError::BaselineStoreZeroLimit {
                limit: "max_manifest_bytes",
            });
        }
        if self.max_files == 0 {
            return Err(GkrmError::BaselineStoreZeroLimit { limit: "max_files" });
        }
        if self.max_blob_bytes == 0 {
            return Err(GkrmError::BaselineStoreZeroLimit {
                limit: "max_blob_bytes",
            });
        }
        if self.max_total_blob_bytes == 0 {
            return Err(GkrmError::BaselineStoreZeroLimit {
                limit: "max_total_blob_bytes",
            });
        }
        Ok(())
    }
}

/// Crate-private validated official baseline ready for atomic store publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedBaselineBundle {
    baseline_id: BaselineId,
    resource_key: SafeResourceKey,
    resource_name: String,
    resource_version: Option<String>,
    source_package_fingerprint: Option<Sha256Digest>,
    files: Vec<BaselineFileRecord>,
    counts: BaselineCounts,
    /// Unique blob digests mapped to expected byte sizes (no in-memory content).
    blob_sizes: BTreeMap<Sha256Digest, u64>,
}

impl ValidatedBaselineBundle {
    pub(crate) fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
    }

    pub(crate) fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub(crate) fn resource_name(&self) -> &str {
        &self.resource_name
    }

    pub(crate) fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    pub(crate) fn source_package_fingerprint(&self) -> Option<&Sha256Digest> {
        self.source_package_fingerprint.as_ref()
    }

    pub(crate) fn files(&self) -> &[BaselineFileRecord] {
        &self.files
    }

    pub(crate) fn counts(&self) -> &BaselineCounts {
        &self.counts
    }

    pub(crate) fn blob_sizes(&self) -> &BTreeMap<Sha256Digest, u64> {
        &self.blob_sizes
    }

    pub(crate) fn try_from_parts(
        resource_key: SafeResourceKey,
        resource_name: String,
        resource_version: Option<String>,
        source_package_fingerprint: Option<Sha256Digest>,
        mut files: Vec<BaselineFileRecord>,
        blob_sizes: BTreeMap<Sha256Digest, u64>,
        limits: BaselineStoreLimits,
    ) -> Result<Self> {
        limits.validate()?;
        validate_resource_name(&resource_name)?;
        if let Some(version) = resource_version.as_deref() {
            validate_optional_text(version, "resource_version")?;
        }

        if files.len() > limits.max_files {
            return Err(GkrmError::BaselineFileCountLimitExceeded {
                limit: limits.max_files,
                actual: files.len(),
            });
        }

        files.sort_by(|left, right| {
            left.relative_path
                .as_str()
                .cmp(right.relative_path.as_str())
        });
        validate_sorted_unique_files(&files)?;
        validate_escrow_blob_policy(&files, &blob_sizes)?;
        let counts = derive_counts(&files, &blob_sizes)?;
        validate_blob_limits(&blob_sizes, &counts, limits)?;

        let baseline_id = compute_baseline_id(&CanonicalBaselineInput {
            resource_key: resource_key.as_str(),
            resource_name: &resource_name,
            resource_version: resource_version.as_deref(),
            source_package_fingerprint: source_package_fingerprint.as_ref(),
            files: files
                .iter()
                .map(|file| CanonicalFileInput {
                    path: file.relative_path.as_str(),
                    size: file.size,
                    sha256: &file.sha256,
                    escrow_class: file.escrow_class,
                    blob_sha256: file.blob_sha256.as_ref(),
                })
                .collect(),
        });

        Ok(Self {
            baseline_id,
            resource_key,
            resource_name,
            resource_version,
            source_package_fingerprint,
            files,
            counts,
            blob_sizes,
        })
    }

    /// Validate in-memory blob bytes (tests / load path), then retain sizes only.
    pub(crate) fn try_from_parts_with_bytes(
        resource_key: SafeResourceKey,
        resource_name: String,
        resource_version: Option<String>,
        source_package_fingerprint: Option<Sha256Digest>,
        files: Vec<BaselineFileRecord>,
        blobs: BTreeMap<Sha256Digest, Vec<u8>>,
        limits: BaselineStoreLimits,
    ) -> Result<Self> {
        let mut blob_sizes = BTreeMap::new();
        for (digest, bytes) in &blobs {
            let actual = hash_bytes(bytes);
            if &actual != digest {
                return Err(GkrmError::BaselineBlobDigestMismatch {
                    digest: digest.to_string(),
                });
            }
            blob_sizes.insert(*digest, bytes.len() as u64);
        }
        // Policy checks that sizes match file records happen in try_from_parts.
        // Also verify ignored file sizes against byte lengths before dropping bytes.
        for file in &files {
            if let Some(blob_digest) = file.blob_sha256.as_ref() {
                let Some(bytes) = blobs.get(blob_digest) else {
                    return Err(GkrmError::BaselineMissingBlob {
                        digest: blob_digest.to_string(),
                    });
                };
                if bytes.len() as u64 != file.size {
                    return Err(GkrmError::BaselineBlobSizeMismatch {
                        digest: blob_digest.to_string(),
                        expected: file.size,
                        actual: bytes.len() as u64,
                    });
                }
            }
        }
        Self::try_from_parts(
            resource_key,
            resource_name,
            resource_version,
            source_package_fingerprint,
            files,
            blob_sizes,
            limits,
        )
    }
}

/// Locator for a published baseline under a store root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBaselineLocator {
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
}

impl StoredBaselineLocator {
    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
    }

    pub(crate) fn new(resource_key: SafeResourceKey, baseline_id: BaselineId) -> Self {
        Self {
            resource_key,
            baseline_id,
        }
    }
}

/// Opaque trusted baseline loaded and fully validated from the local store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBaseline {
    store_root: std::path::PathBuf,
    baseline_id: BaselineId,
    resource_key: SafeResourceKey,
    resource_name: String,
    resource_version: Option<String>,
    source_package_fingerprint: Option<Sha256Digest>,
    files: Vec<BaselineFileRecord>,
    counts: BaselineCounts,
}

impl StoredBaseline {
    pub fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn resource_name(&self) -> &str {
        &self.resource_name
    }

    pub fn resource_version(&self) -> Option<&str> {
        self.resource_version.as_deref()
    }

    pub fn source_package_fingerprint(&self) -> Option<&Sha256Digest> {
        self.source_package_fingerprint.as_ref()
    }

    pub fn files(&self) -> &[BaselineFileRecord] {
        &self.files
    }

    pub fn counts(&self) -> &BaselineCounts {
        &self.counts
    }

    pub(crate) fn store_root(&self) -> &std::path::Path {
        &self.store_root
    }

    pub(crate) fn from_validated(
        store_root: std::path::PathBuf,
        bundle: &ValidatedBaselineBundle,
    ) -> Self {
        Self {
            store_root,
            baseline_id: bundle.baseline_id.clone(),
            resource_key: bundle.resource_key.clone(),
            resource_name: bundle.resource_name.clone(),
            resource_version: bundle.resource_version.clone(),
            source_package_fingerprint: bundle.source_package_fingerprint,
            files: bundle.files.clone(),
            counts: bundle.counts.clone(),
        }
    }

    /// Reopen and revalidate a blob at point of use.
    pub fn read_verified_blob(
        &self,
        digest: &Sha256Digest,
        limits: &BaselineStoreLimits,
    ) -> Result<Vec<u8>> {
        crate::baseline::store::read_verified_blob(self, digest, limits)
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        baseline_id: BaselineId,
        resource_key: SafeResourceKey,
        resource_name: String,
        resource_version: Option<String>,
        source_package_fingerprint: Option<Sha256Digest>,
        files: Vec<BaselineFileRecord>,
        counts: BaselineCounts,
    ) -> Self {
        Self {
            store_root: std::path::PathBuf::new(),
            baseline_id,
            resource_key,
            resource_name,
            resource_version,
            source_package_fingerprint,
            files,
            counts,
        }
    }
}

pub(crate) fn make_file_record(
    relative_path: ResourceRelativePath,
    size: u64,
    sha256: Sha256Digest,
    escrow_class: BaselineEscrowClass,
    blob_sha256: Option<Sha256Digest>,
) -> BaselineFileRecord {
    BaselineFileRecord {
        relative_path,
        size,
        sha256,
        escrow_class,
        blob_sha256,
    }
}

fn validate_resource_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(GkrmError::BaselineUnsafeResourceKey {
            value: name.to_owned(),
        });
    }
    validate_optional_text(name, "resource_name")
}

fn validate_optional_text(value: &str, field: &str) -> Result<()> {
    if value.chars().any(|character| character.is_control()) {
        return Err(GkrmError::BaselineUnsafeRelativePath {
            path: field.to_string(),
        });
    }
    Ok(())
}

fn validate_sorted_unique_files(files: &[BaselineFileRecord]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for file in files {
        let path = file.relative_path.as_str();
        if let Some(previous_path) = previous {
            if path == previous_path {
                return Err(GkrmError::BaselineDuplicateFilePath {
                    path: path.to_owned(),
                });
            }
            if path < previous_path {
                return Err(GkrmError::BaselineInvalidOrdering {
                    path: path.to_owned(),
                });
            }
        }
        previous = Some(path);
    }
    Ok(())
}

fn validate_escrow_blob_policy(
    files: &[BaselineFileRecord],
    blob_sizes: &BTreeMap<Sha256Digest, u64>,
) -> Result<()> {
    let mut referenced = BTreeMap::<Sha256Digest, u64>::new();

    for file in files {
        // Escrow encrypts a resource's Lua, YFT, YDD, and YDR files, and a server owner can
        // neither read nor edit those, so a protected file's content is the vendor's alone and is
        // never retained. Every other file could have been edited by the operator, and what the
        // official package held of it is the only thing that can later tell their work from the
        // developer's. Files the developer declared editable always carry their content; the rest
        // carry it when the capture had room, and a later update that finds none is not wrong,
        // only less able to combine that one file.
        let blob_digest = match (file.escrow_class, file.blob_sha256.as_ref()) {
            (BaselineEscrowClass::Protected, None) => continue,
            (BaselineEscrowClass::Protected, Some(_)) => {
                return Err(GkrmError::BaselineInconsistentEscrowBlob {
                    path: file.relative_path.to_string(),
                    reason: format!("{} files must not retain blobs", file.escrow_class.as_str()),
                })
            }
            (BaselineEscrowClass::Ignored, None) => {
                return Err(GkrmError::BaselineInconsistentEscrowBlob {
                    path: file.relative_path.to_string(),
                    reason: "ignored files require a blob".to_owned(),
                })
            }
            (BaselineEscrowClass::NotSupported, None) => continue,
            (_, Some(blob_digest)) => blob_digest,
        };
        if blob_digest != &file.sha256 {
            return Err(GkrmError::BaselineInconsistentEscrowBlob {
                path: file.relative_path.to_string(),
                reason: "blob digest must equal file digest".to_owned(),
            });
        }
        let Some(size) = blob_sizes.get(blob_digest).copied() else {
            return Err(GkrmError::BaselineMissingBlob {
                digest: blob_digest.to_string(),
            });
        };
        if size != file.size {
            return Err(GkrmError::BaselineBlobSizeMismatch {
                digest: blob_digest.to_string(),
                expected: file.size,
                actual: size,
            });
        }
        referenced.insert(*blob_digest, file.size);
    }

    for digest in blob_sizes.keys() {
        if !referenced.contains_key(digest) {
            return Err(GkrmError::BaselineUnexpectedBlob {
                name: digest.to_string(),
            });
        }
    }

    Ok(())
}
fn derive_counts(
    files: &[BaselineFileRecord],
    blob_sizes: &BTreeMap<Sha256Digest, u64>,
) -> Result<BaselineCounts> {
    let mut protected_files = 0_u64;
    let mut ignored_files = 0_u64;
    let mut not_supported_files = 0_u64;

    for file in files {
        match file.escrow_class {
            BaselineEscrowClass::Protected => protected_files += 1,
            BaselineEscrowClass::Ignored => ignored_files += 1,
            BaselineEscrowClass::NotSupported => not_supported_files += 1,
        }
    }

    let total_blob_bytes = blob_sizes.values().try_fold(0_u64, |sum, size| {
        sum.checked_add(*size)
            .ok_or(GkrmError::BaselineTotalBlobLimitExceeded {
                limit: u64::MAX,
                actual: u64::MAX,
            })
    })?;

    Ok(BaselineCounts {
        files: files.len() as u64,
        protected_files,
        ignored_files,
        not_supported_files,
        blobs: blob_sizes.len() as u64,
        total_blob_bytes,
    })
}

fn validate_blob_limits(
    blob_sizes: &BTreeMap<Sha256Digest, u64>,
    counts: &BaselineCounts,
    limits: BaselineStoreLimits,
) -> Result<()> {
    for (digest, size) in blob_sizes {
        if *size > limits.max_blob_bytes {
            return Err(GkrmError::BaselineBlobLimitExceeded {
                digest: digest.to_string(),
                limit: limits.max_blob_bytes,
                actual: *size,
            });
        }
    }
    if counts.total_blob_bytes > limits.max_total_blob_bytes {
        return Err(GkrmError::BaselineTotalBlobLimitExceeded {
            limit: limits.max_total_blob_bytes,
            actual: counts.total_blob_bytes,
        });
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> Sha256Digest {
    use sha2::{Digest, Sha256};
    Sha256Digest::new(Sha256::digest(bytes).into())
}

pub(crate) fn verify_counts_match(
    expected: &BaselineCounts,
    actual: &BaselineCounts,
) -> Result<()> {
    for (field, expected_value, actual_value) in [
        ("files", expected.files, actual.files),
        (
            "protected_files",
            expected.protected_files,
            actual.protected_files,
        ),
        (
            "ignored_files",
            expected.ignored_files,
            actual.ignored_files,
        ),
        (
            "not_supported_files",
            expected.not_supported_files,
            actual.not_supported_files,
        ),
        ("blobs", expected.blobs, actual.blobs),
        (
            "total_blob_bytes",
            expected.total_blob_bytes,
            actual.total_blob_bytes,
        ),
    ] {
        if expected_value != actual_value {
            return Err(GkrmError::BaselineCountMismatch {
                field,
                expected: expected_value,
                actual: actual_value,
            });
        }
    }
    Ok(())
}

pub(crate) fn counts_from_dto(
    files: u64,
    protected_files: u64,
    ignored_files: u64,
    not_supported_files: u64,
    blobs: u64,
    total_blob_bytes: u64,
) -> BaselineCounts {
    BaselineCounts {
        files,
        protected_files,
        ignored_files,
        not_supported_files,
        blobs,
        total_blob_bytes,
    }
}
