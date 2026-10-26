use std::path::PathBuf;

use thiserror::Error;

use crate::baseline::BaselineId;
use crate::comparison::FileComparisonStatus;

pub type Result<T> = std::result::Result<T, GkrmError>;

/// Closed Task 21 filesystem operation tag for sanitized I/O errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyPlanningIoOperation {
    OpenInstalledRoot,
    OpenInstalledResource,
    ScanInstalled,
    EnumerateInstalled,
    OpenStagingPublished,
    OpenStagingResource,
    ReadManifest,
    HashFile,
    VerifyRegularFile,
    RevalidateIdentity,
}

impl std::fmt::Display for ApplyPlanningIoOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenInstalledRoot => "open-installed-root",
            Self::OpenInstalledResource => "open-installed-resource",
            Self::ScanInstalled => "scan-installed",
            Self::EnumerateInstalled => "enumerate-installed",
            Self::OpenStagingPublished => "open-staging-published",
            Self::OpenStagingResource => "open-staging-resource",
            Self::ReadManifest => "read-manifest",
            Self::HashFile => "hash-file",
            Self::VerifyRegularFile => "verify-regular-file",
            Self::RevalidateIdentity => "revalidate-identity",
        })
    }
}

/// Closed Task 22 filesystem operation tag for sanitized I/O errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionalApplyPlanningIoOperation {
    OpenInstalledRoot,
    OpenInstalledResource,
    ScanInstalled,
    EnumerateInstalled,
    OpenStagingPublished,
    OpenStagingResource,
    ReadManifest,
    HashFile,
    VerifyRegularFile,
    RevalidateIdentity,
}

impl std::fmt::Display for TransactionalApplyPlanningIoOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenInstalledRoot => "open-installed-root",
            Self::OpenInstalledResource => "open-installed-resource",
            Self::ScanInstalled => "scan-installed",
            Self::EnumerateInstalled => "enumerate-installed",
            Self::OpenStagingPublished => "open-staging-published",
            Self::OpenStagingResource => "open-staging-resource",
            Self::ReadManifest => "read-manifest",
            Self::HashFile => "hash-file",
            Self::VerifyRegularFile => "verify-regular-file",
            Self::RevalidateIdentity => "revalidate-identity",
        })
    }
}

/// Closed Task 23 filesystem operation tag for sanitized I/O errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionalApplyIoOperation {
    OpenTransactionRoot,
    CreateInternalDirectory,
    CreateTempDirectory,
    CreateTransactionDirectory,
    CreateJournalRecord,
    OpenJournalRecord,
    WriteJournalRecord,
    SyncJournalRecord,
    SyncJournalDirectory,
    EnumerateJournal,
    CreateBackupFile,
    CreateBackupDirectory,
    OpenBackupObject,
    WriteBackupObject,
    SyncBackupObject,
    WriteBackupManifest,
    WriteBackupSeal,
    RenamePublish,
    OpenPublishedTransaction,
    OpenInstalledRoot,
    OpenInstalledResource,
    OpenInstalledFile,
    CreateInstalledFile,
    CreateInstalledDirectory,
    RemoveInstalledFile,
    RemoveInstalledDirectory,
    RenameInstalled,
    SyncInstalledFile,
    SyncInstalledDirectory,
    OpenStagingResource,
    ReadStagingFile,
    HashFile,
    VerifyRegularFile,
    RevalidateIdentity,
    EnumerateInstalled,
    CloneCleanupCapability,
    AcquireResourceLock,
    AcquireTransactionLock,
    EnumerateTransactions,
}

impl std::fmt::Display for TransactionalApplyIoOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenTransactionRoot => "open-transaction-root",
            Self::CreateInternalDirectory => "create-internal-directory",
            Self::CreateTempDirectory => "create-temp-directory",
            Self::CreateTransactionDirectory => "create-transaction-directory",
            Self::CreateJournalRecord => "create-journal-record",
            Self::OpenJournalRecord => "open-journal-record",
            Self::WriteJournalRecord => "write-journal-record",
            Self::SyncJournalRecord => "sync-journal-record",
            Self::SyncJournalDirectory => "sync-journal-directory",
            Self::EnumerateJournal => "enumerate-journal",
            Self::CreateBackupFile => "create-backup-file",
            Self::CreateBackupDirectory => "create-backup-directory",
            Self::OpenBackupObject => "open-backup-object",
            Self::WriteBackupObject => "write-backup-object",
            Self::SyncBackupObject => "sync-backup-object",
            Self::WriteBackupManifest => "write-backup-manifest",
            Self::WriteBackupSeal => "write-backup-seal",
            Self::RenamePublish => "rename-publish",
            Self::OpenPublishedTransaction => "open-published-transaction",
            Self::OpenInstalledRoot => "open-installed-root",
            Self::OpenInstalledResource => "open-installed-resource",
            Self::OpenInstalledFile => "open-installed-file",
            Self::CreateInstalledFile => "create-installed-file",
            Self::CreateInstalledDirectory => "create-installed-directory",
            Self::RemoveInstalledFile => "remove-installed-file",
            Self::RemoveInstalledDirectory => "remove-installed-directory",
            Self::RenameInstalled => "rename-installed",
            Self::SyncInstalledFile => "sync-installed-file",
            Self::SyncInstalledDirectory => "sync-installed-directory",
            Self::OpenStagingResource => "open-staging-resource",
            Self::ReadStagingFile => "read-staging-file",
            Self::HashFile => "hash-file",
            Self::VerifyRegularFile => "verify-regular-file",
            Self::RevalidateIdentity => "revalidate-identity",
            Self::EnumerateInstalled => "enumerate-installed",
            Self::CloneCleanupCapability => "clone-cleanup-capability",
            Self::AcquireResourceLock => "acquire-resource-lock",
            Self::AcquireTransactionLock => "acquire-transaction-lock",
            Self::EnumerateTransactions => "enumerate-transactions",
        })
    }
}

/// Closed Task 20 filesystem operation tag for sanitized I/O errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingIoOperation {
    OpenRoot,
    CreateInternalDirectory,
    CreateTempDirectory,
    CreateResourceDirectory,
    CreateFile,
    OpenFile,
    ReadSource,
    WriteDestination,
    FlushFile,
    SyncFile,
    SyncDirectory,
    RenamePublish,
    OpenPublishedBundle,
    VerifyPublishedBundle,
    RemoveTemp,
    RemovePublished,
    QuarantinePublished,
    CloneCleanupCapability,
}

impl std::fmt::Display for StagingIoOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::OpenRoot => "open-root",
            Self::CreateInternalDirectory => "create-internal-directory",
            Self::CreateTempDirectory => "create-temp-directory",
            Self::CreateResourceDirectory => "create-resource-directory",
            Self::CreateFile => "create-file",
            Self::OpenFile => "open-file",
            Self::ReadSource => "read-source",
            Self::WriteDestination => "write-destination",
            Self::FlushFile => "flush-file",
            Self::SyncFile => "sync-file",
            Self::SyncDirectory => "sync-directory",
            Self::RenamePublish => "rename-publish",
            Self::OpenPublishedBundle => "open-published-bundle",
            Self::VerifyPublishedBundle => "verify-published-bundle",
            Self::RemoveTemp => "remove-temp",
            Self::RemovePublished => "remove-published",
            Self::QuarantinePublished => "quarantine-published",
            Self::CloneCleanupCapability => "clone-cleanup-capability",
        })
    }
}

#[derive(Error)]
pub enum GkrmError {
    #[error("failed to read installed path metadata")]
    InstalledPathMetadata {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed path does not exist")]
    InstalledPathMissing { path: PathBuf },

    #[error("installed path is not a directory")]
    InstalledPathNotDirectory { path: PathBuf },

    #[error("installed scan limit must be greater than zero: {limit}")]
    InstalledScanZeroLimit { limit: &'static str },

    #[error("failed to canonicalize installed root")]
    InstalledRootCanonicalize {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed root uses an unsupported path prefix")]
    InstalledRootUnsupportedPrefix { path: PathBuf },

    #[error("installed root must not be a symlink")]
    InstalledRootSymlink { path: PathBuf },

    #[error("installed root name is not valid UTF-8")]
    InstalledRootNameNonUtf8 { path: PathBuf },

    #[error("no FiveM resources found in installed path")]
    InstalledNoResourcesFound,

    #[error("failed to read installed directory")]
    InstalledDirectoryRead {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed to read entry from installed directory")]
    InstalledDirectoryEntryRead {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed directory disappeared during scan")]
    InstalledDirectoryDisappeared { path: String },

    #[error("installed file disappeared during scan")]
    InstalledFileDisappeared { path: String },

    #[error("failed to read installed entry metadata")]
    InstalledEntryMetadata {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed entry is a symlink")]
    InstalledEntrySymlink { path: String },

    #[error("installed fxmanifest.lua is a symlink")]
    InstalledFxManifestSymlink { path: String },

    #[error("installed entry is an unsupported reparse point")]
    InstalledEntryReparsePoint { path: String },

    #[error("installed entry has an unsupported filesystem type")]
    InstalledUnsupportedEntryType { path: String },

    #[error("installed path is empty")]
    InstalledPathEmpty { path: String },

    #[error("installed path is absolute")]
    InstalledPathAbsolute { path: String },

    #[error("installed path contains a non-UTF-8 component")]
    InstalledPathNonUtf8 { path: String },

    #[error("installed path contains a control character, U+{codepoint:04X}")]
    InstalledPathControlCharacter { path: String, codepoint: u32 },

    #[error("installed path contains an empty component")]
    InstalledPathEmptyComponent { path: String },

    #[error("installed path contains a current-directory component")]
    InstalledPathCurrentDirectory { path: String },

    #[error("installed path contains parent traversal")]
    InstalledPathParentTraversal { path: String },

    #[error("installed path contains a Windows-invalid character")]
    InstalledPathWindowsInvalidCharacter { path: String, character: char },

    #[error("installed path contains a component ending in dot or space, component")]
    InstalledPathWindowsTrailingDotOrSpace { path: String, component: String },

    #[error("installed path contains a Windows reserved device name")]
    InstalledPathWindowsReservedName { path: String, component: String },

    #[error("installed path is duplicated after normalization")]
    InstalledPathDuplicate { path: String },

    #[error("installed path collides case-insensitively after normalization")]
    InstalledPathCaseInsensitiveCollision { first: String, second: String },

    #[error("installed resource count exceeds limit: limit {limit}, actual {actual}")]
    InstalledResourceCountLimitExceeded { limit: usize, actual: usize },

    #[error("installed files per resource exceeds limit: limit {limit}, actual {actual}")]
    InstalledFilesPerResourceLimitExceeded {
        resource: String,
        limit: usize,
        actual: usize,
    },

    #[error("installed total file count exceeds limit: limit {limit}, actual {actual}")]
    InstalledTotalFilesLimitExceeded { limit: usize, actual: usize },

    #[error("installed total entry count exceeds limit: limit {limit}, actual {actual}")]
    InstalledTotalEntriesLimitExceeded { limit: usize, actual: usize },

    #[error("installed directory count exceeds limit: limit {limit}, actual {actual}")]
    InstalledDirectoryCountLimitExceeded { limit: usize, actual: usize },

    #[error("installed file exceeds size limit, limit {limit}, actual {actual}")]
    InstalledFileSizeLimitExceeded {
        path: String,
        limit: u64,
        actual: u64,
    },

    #[error("installed total scanned size exceeds limit: limit {limit}, actual {actual}")]
    InstalledTotalSizeLimitExceeded { limit: u64, actual: u64 },

    #[error("installed directory depth exceeds limit, limit {limit}, actual {actual}")]
    InstalledDirectoryDepthLimitExceeded {
        path: String,
        limit: usize,
        actual: usize,
    },

    #[error("installed file is outside every discovered resource")]
    InstalledFileOutsideResource { path: String },

    #[error("failed to derive installed resource-relative path: root, path")]
    InstalledResourceRelativePath { root: String, path: String },

    #[error("installed path escaped selected root during scan")]
    InstalledContainmentViolation { path: String },

    #[error("failed to open installed file")]
    InstalledFileOpen {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed to read opened installed file metadata")]
    InstalledFileMetadata {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed file modification timestamp is unavailable")]
    InstalledFileTimestampUnavailable {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed file stable identity is unavailable")]
    InstalledFileIdentityUnavailable {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("opened installed file is no longer a regular file")]
    InstalledOpenedFileNotRegular { path: String },

    #[error("installed file changed during scan")]
    InstalledFileChanged { path: String },

    #[error("installed file content changed during scan")]
    InstalledFileContentChanged { path: String },

    #[error("failed to hash installed file")]
    InstalledFileHashRead {
        path: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("installed file byte count changed during scan, expected {expected}, actual {actual}")]
    InstalledFileSizeMismatch {
        path: String,
        expected: u64,
        actual: u64,
    },

    #[error("failed to read package path metadata")]
    PackagePathMetadata {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("package path does not exist")]
    PackagePathMissing { path: PathBuf },

    #[error("package path is not a regular file")]
    PackagePathNotFile { path: PathBuf },

    #[error("package path must be a .zip file")]
    PackagePathNotZip { path: PathBuf },

    #[error("failed to open zip package")]
    ZipPackageOpen {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed to read zip archive")]
    ZipArchiveRead {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: zip::result::ZipError,
    },

    #[error("failed to read zip entry at index {index}")]
    ZipEntryRead {
        path: PathBuf,
        index: usize,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: zip::result::ZipError,
    },

    #[error("failed to stream zip entry")]
    ZipEntryStream {
        entry: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("zip entry name is not valid UTF-8 at index {index}")]
    ZipEntryNameInvalidUtf8 { index: usize },

    #[error("zip entry path is empty at index {index}")]
    ZipEntryPathEmpty { index: usize },

    #[error("zip entry path contains parent traversal at index {index}")]
    ZipEntryParentTraversal { index: usize, entry: String },

    #[error("zip entry path is Unix absolute at index {index}")]
    ZipEntryUnixAbsolutePath { index: usize, entry: String },

    #[error("zip entry path has a Windows drive prefix at index {index}")]
    ZipEntryWindowsDrivePath { index: usize, entry: String },

    #[error("zip entry path is a UNC path at index {index}")]
    ZipEntryUncPath { index: usize, entry: String },

    #[error("zip entry path begins with a Windows root separator at index {index}")]
    ZipEntryWindowsRootPath { index: usize, entry: String },

    #[error("zip entry path contains a control character at index {index}: U+{codepoint:04X}")]
    ZipEntryControlCharacter {
        index: usize,
        entry: String,
        codepoint: u32,
    },

    #[error("zip entry path contains an empty component at index {index}")]
    ZipEntryEmptyComponent { index: usize, entry: String },

    #[error("zip entry path contains a current-directory component at index {index}")]
    ZipEntryCurrentDirectory { index: usize, entry: String },

    #[error("zip entry path contains a Windows-invalid character at index {index}")]
    ZipEntryWindowsInvalidCharacter {
        index: usize,
        entry: String,
        character: char,
    },

    #[error("zip entry path contains a component ending in dot or space at index {index}")]
    ZipEntryWindowsTrailingDotOrSpace {
        index: usize,
        entry: String,
        component: String,
    },

    #[error("zip entry path contains a Windows reserved device name at index {index}")]
    ZipEntryWindowsReservedName {
        index: usize,
        entry: String,
        component: String,
    },

    #[error("zip entry is a symlink at index {index}")]
    ZipEntrySymlink { index: usize, entry: String },

    #[error("zip entry is encrypted at index {index}")]
    ZipEntryEncrypted { index: usize, entry: String },

    #[error("zip entry uses an unsupported compression method at index {index}")]
    ZipEntryUnsupportedCompression {
        index: usize,
        entry: String,
        method: String,
    },

    #[error("zip directory entry has non-zero size at index {index}")]
    ZipDirectoryEntryNonZeroSize {
        index: usize,
        entry: String,
        compressed_size: u64,
        uncompressed_size: u64,
    },

    #[error("zip entry path is duplicated after normalization")]
    ZipEntryDuplicatePath { entry: String },

    #[error("zip entry path collides case-insensitively after normalization")]
    ZipEntryCaseInsensitiveCollision { first: String, second: String },

    #[error("zip entry count exceeds limit: limit {limit}, actual {actual}")]
    ZipEntryCountLimitExceeded { limit: usize, actual: usize },

    #[error("zip entry exceeds uncompressed size limit: limit {limit}, actual {actual}")]
    ZipEntrySizeLimitExceeded {
        entry: String,
        limit: u64,
        actual: u64,
    },

    #[error("zip entry streamed size mismatch, expected {expected}, actual {actual}")]
    ZipEntryStreamSizeMismatch {
        entry: String,
        expected: u64,
        actual: u64,
    },

    #[error("zip total uncompressed size exceeds limit: limit {limit}, actual {actual}")]
    ZipTotalSizeLimitExceeded { limit: u64, actual: u64 },

    #[error("zip entry compression ratio exceeds limit: limit {limit}, uncompressed {uncompressed_size}")]
    ZipCompressionRatioLimitExceeded {
        entry: String,
        limit: u64,
        compressed_size: u64,
        uncompressed_size: u64,
    },

    #[error("zip resource root has duplicate manifests")]
    ZipResourceDuplicateManifest {
        root: String,
        first: String,
        second: String,
    },

    #[error("manifest entry is missing from inspection")]
    ManifestEntryMissing { entry: String },

    #[error("manifest entry is not a file")]
    ManifestEntryNotFile { entry: String },

    #[error("manifest exceeds size limit, limit {limit}, actual {actual}")]
    ManifestSizeLimitExceeded {
        entry: String,
        limit: u64,
        actual: u64,
    },

    #[error("failed to open manifest zip package")]
    ManifestZipOpen {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed to read manifest zip archive")]
    ManifestZipArchiveRead {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: zip::result::ZipError,
    },

    #[error("manifest zip entry changed since inspection")]
    ManifestZipEntryChanged { entry: String, reason: String },

    #[error("failed to read manifest zip entry")]
    ManifestZipEntryRead {
        entry: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: zip::result::ZipError,
    },

    #[error("failed to stream manifest zip entry")]
    ManifestRead {
        entry: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("manifest is not valid UTF-8")]
    ManifestInvalidUtf8 {
        entry: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::string::FromUtf8Error,
    },

    #[error("manifest string escape is invalid")]
    ManifestInvalidStringEscape { entry: String, message: String },

    #[error("manifest Lua syntax is invalid")]
    ManifestLuaSyntax { entry: String, errors: String },

    #[error("manifest token traversal exceeds limit, limit {limit}, actual {actual}")]
    ManifestTokenLimitExceeded {
        entry: String,
        limit: usize,
        actual: usize,
    },

    #[error("manifest parser panicked unexpectedly")]
    ManifestParserPanic { entry: String },

    #[error("parsed manifest is missing for discovered resource root")]
    EscrowManifestMissing { root: String },

    #[error("multiple parsed manifests exist for resource root")]
    EscrowManifestDuplicate { root: String },

    #[error("parsed manifest does not match a discovered resource root")]
    EscrowManifestRootMismatch { root: String },

    #[error("parsed manifest path does not match discovered resource")]
    EscrowManifestPathMismatch {
        root: String,
        expected: String,
        actual: String,
    },

    #[error("discovered resource entry does not match inspection")]
    EscrowDiscoveryEntryMismatch { entry: String, reason: String },

    #[error("escrow glob policy is unsafe")]
    EscrowGlobUnsafe { pattern: String, reason: String },

    #[error("escrow_ignore glob has a trailing slash")]
    EscrowGlobTrailingSlash { pattern: String },

    #[error("escrow_ignore glob is malformed")]
    EscrowGlobMalformed {
        pattern: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: globset::Error,
    },

    #[error("failed to derive resource-relative path: root, entry")]
    EscrowResourceRelativePath { root: String, entry: String },

    #[error("comparison limit must be greater than zero: {limit}")]
    ComparisonZeroLimit { limit: &'static str },

    #[error("duplicate installed resource root in comparison input")]
    ComparisonDuplicateInstalledRoot { root: String },

    #[error("duplicate installed resource name in comparison input")]
    ComparisonDuplicateInstalledName { name: String },

    #[error("duplicate incoming resource root in comparison input")]
    ComparisonDuplicateIncomingRoot { root: String },

    #[error("duplicate incoming resource name in comparison input")]
    ComparisonDuplicateIncomingName { name: String },

    #[error("duplicate installed file path in comparison input")]
    ComparisonDuplicateInstalledFile { resource: String, path: String },

    #[error("comparison input is inconsistent")]
    ComparisonInconsistentReport { message: String },

    #[error("installed resource name mismatch in comparison input")]
    ComparisonInstalledNameMismatch {
        root: String,
        expected: String,
        actual: String,
    },

    #[error("incoming resource name mismatch in comparison input")]
    ComparisonIncomingNameMismatch {
        root: String,
        expected: String,
        actual: String,
    },

    #[error("duplicate incoming package path in comparison input")]
    ComparisonDuplicateIncomingPackagePath { path: String },

    #[error("duplicate incoming archive index in comparison input: {index}")]
    ComparisonDuplicateIncomingArchiveIndex { index: usize },

    #[error("duplicate incoming resource-relative path in comparison input")]
    ComparisonDuplicateIncomingRelativePath { resource: String, path: String },

    #[error("incoming file count exceeds comparison limit: limit {limit}, actual {actual}")]
    ComparisonIncomingFileCountLimitExceeded { limit: usize, actual: usize },

    #[error("incoming file exceeds comparison size limit: limit {limit}, actual {actual}")]
    ComparisonIncomingFileSizeLimitExceeded {
        entry: String,
        limit: u64,
        actual: u64,
    },

    #[error(
        "incoming total uncompressed size exceeds comparison limit: limit {limit}, actual {actual}"
    )]
    ComparisonIncomingTotalSizeLimitExceeded { limit: u64, actual: u64 },

    #[error("incoming archive size exceeds comparison limit: limit {limit}, actual {actual}")]
    ComparisonArchiveSizeLimitExceeded {
        path: PathBuf,
        limit: u64,
        actual: u64,
    },

    #[error("failed to open incoming package securely")]
    ComparisonPackageOpen {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed to read incoming package metadata")]
    ComparisonPackageMetadata {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("incoming package is not a regular file")]
    ComparisonPackageNotFile { path: PathBuf },

    #[error("incoming package is a symlink")]
    ComparisonPackageSymlink { path: PathBuf },

    #[error("incoming package is an unsupported reparse point")]
    ComparisonPackageReparsePoint { path: PathBuf },

    #[error("incoming package modification timestamp is unavailable")]
    ComparisonPackageTimestampUnavailable {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("incoming package stable identity is unavailable")]
    ComparisonPackageIdentityUnavailable {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed to hash incoming package archive")]
    ComparisonPackageHashRead {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error(
        "incoming package archive size changed while hashing, expected {expected}, actual {actual}"
    )]
    ComparisonPackageArchiveSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("package contents changed during verification")]
    ComparisonPackageChanged { path: PathBuf, reason: String },

    #[error("failed to read incoming zip archive for comparison")]
    ComparisonZipArchiveRead {
        path: PathBuf,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: zip::result::ZipError,
    },

    #[error("package contents changed during verification")]
    ComparisonZipEntryChanged { entry: String, reason: String },

    #[error("failed to read incoming zip entry")]
    ComparisonZipEntryRead {
        entry: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: zip::result::ZipError,
    },

    #[error("failed to stream incoming zip entry")]
    ComparisonZipEntryStream {
        entry: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("incoming zip entry streamed size mismatch, expected {expected}, actual {actual}")]
    ComparisonZipEntryStreamSizeMismatch {
        entry: String,
        expected: u64,
        actual: u64,
    },

    #[error("invalid update-plan file side combination")]
    UpdatePlanInvalidFileSides {
        status: FileComparisonStatus,
        has_installed: bool,
        has_incoming: bool,
    },

    #[error("missing incoming escrow classification in update-plan input: resource, path")]
    UpdatePlanMissingIncomingClassification { resource: String, path: String },

    #[error("unexpected incoming escrow classification in update-plan input: resource, path")]
    UpdatePlanUnexpectedIncomingClassification { resource: String, path: String },

    #[error("duplicate file path in update-plan input: resource, path")]
    UpdatePlanDuplicateFilePath { resource: String, path: String },

    #[error("installed resource appears in multiple update-plan matches")]
    UpdatePlanDuplicateInstalledResourceMatch { resource: String },

    #[error("incoming resource appears in multiple update-plan matches")]
    UpdatePlanDuplicateIncomingResourceMatch { resource: String },

    #[error("update-plan count mismatch for {expected}: actual {actual}, counted {counted}")]
    UpdatePlanCountMismatch {
        expected: &'static str,
        actual: usize,
        counted: usize,
    },

    #[error("unsupported baseline schema version")]
    BaselineUnsupportedSchema { version: u32 },

    #[error("invalid baseline id")]
    BaselineInvalidId { value: String },

    #[error("baseline id mismatch")]
    BaselineIdMismatch { stored: String, computed: String },

    #[error("requested baseline id does not match stored baseline id")]
    BaselineRequestedIdMismatch { requested: String, stored: String },

    #[error("unsafe baseline resource key")]
    BaselineUnsafeResourceKey { value: String },

    #[error("requested resource key does not match stored baseline key")]
    BaselineResourceKeyMismatch { requested: String, stored: String },

    #[error("unsafe baseline relative path")]
    BaselineUnsafeRelativePath { path: String },

    #[error("duplicate baseline file path")]
    BaselineDuplicateFilePath { path: String },

    #[error("baseline file inventory is not in deterministic path order near")]
    BaselineInvalidOrdering { path: String },

    #[error("invalid baseline digest encoding")]
    BaselineInvalidHash { value: String },

    #[error("baseline escrow/blob policy mismatch")]
    BaselineInconsistentEscrowBlob { path: String, reason: String },

    #[error("baseline blob is missing")]
    BaselineMissingBlob { digest: String },

    #[error("unexpected baseline blob or bundle entry")]
    BaselineUnexpectedBlob { name: String },

    #[error("baseline blob size mismatch: expected {expected}, actual {actual}")]
    BaselineBlobSizeMismatch {
        digest: String,
        expected: u64,
        actual: u64,
    },

    #[error("baseline blob digest mismatch for")]
    BaselineBlobDigestMismatch { digest: String },

    #[error("baseline manifest exceeds size limit: limit {limit}, actual {actual}")]
    BaselineManifestLimitExceeded { limit: u64, actual: u64 },

    #[error("baseline file count exceeds limit: limit {limit}, actual {actual}")]
    BaselineFileCountLimitExceeded { limit: usize, actual: usize },

    #[error("baseline blob exceeds size limit: limit {limit}, actual {actual}")]
    BaselineBlobLimitExceeded {
        digest: String,
        limit: u64,
        actual: u64,
    },

    #[error("baseline total blob bytes exceed limit: limit {limit}, actual {actual}")]
    BaselineTotalBlobLimitExceeded { limit: u64, actual: u64 },

    #[error("baseline store limit must be greater than zero: {limit}")]
    BaselineStoreZeroLimit { limit: &'static str },

    #[error("baseline aggregate count mismatch for {field}: expected {expected}, actual {actual}")]
    BaselineCountMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },

    #[error("unsafe baseline store component")]
    BaselineStoreUnsafeComponent { component: String },

    #[error("baseline store entry is a symlink")]
    BaselineStoreSymlink { component: String },

    #[error("baseline store entry is an unsupported reparse point")]
    BaselineStoreReparsePoint { component: String },

    #[error("baseline store entry is an unsafe hard link")]
    BaselineStoreHardLink { component: String },

    #[error("baseline store entry has unexpected type")]
    BaselineStoreUnexpectedType { component: String },

    #[error("baseline store root overlaps an installed resource root")]
    BaselineStoreInstallOverlap,

    #[error("baseline conflict detected")]
    BaselineExistingConflict {
        resource_key: String,
        baseline_id: String,
    },

    #[error("incomplete temporary baseline bundle under store")]
    BaselineIncompleteTemporary,

    #[error("platform does not support no-replace baseline publish")]
    BaselineUnsupportedNoReplacePublish,

    #[error("failed to publish baseline atomically")]
    BaselineAtomicPublishFailure {
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("failed baseline store I/O for")]
    BaselineStoreIo {
        component: String,
        // Retained privately as `cause`; deliberately excluded from Error::source().
        cause: std::io::Error,
    },

    #[error("baseline store path is missing")]
    BaselineStoreMissing { component: String },

    #[error("baseline bundle is incomplete")]
    BaselineIncompleteBundle { reason: &'static str },

    #[error("baseline store parent identity changed before publish")]
    BaselineStoreIdentityChanged { component: &'static str },

    #[error("baseline verified blob callback and verification both failed")]
    BaselineVerifiedBlobCallbackAndVerificationFailed {
        #[source]
        primary: Box<GkrmError>,
        verification: Box<GkrmError>,
    },

    #[error("baseline resolution options are invalid: {limit}")]
    BaselineResolutionOptionsInvalid { limit: &'static str },

    #[error("baseline catalog entry limit exceeded: limit {limit}, actual {actual}")]
    BaselineCatalogEntryLimitExceeded { limit: usize, actual: usize },

    #[error("secured baseline catalog enumeration failed")]
    BaselineSecuredCatalogEnumerationFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("no stored official baselines are available")]
    BaselineNoStoredBaselines,

    #[error("selected baseline was not found")]
    BaselineSelectedBaselineNotFound { baseline_id: String },

    #[error("multiple valid official baselines require exact selection")]
    BaselineMultipleValidBaselinesRequireExactSelection { baseline_ids: Vec<BaselineId> },

    #[error("automatic single-baseline selection is blocked by catalog issues: {issue_count}")]
    BaselineAutoSingleBlockedByCatalogIssues { issue_count: usize },

    #[error("official baseline catalog changed during resolution")]
    BaselineCatalogChangedDuringResolution,

    #[error("selected official baseline failed validation: {category}")]
    BaselineSelectedBaselineValidationFailed {
        baseline_id: String,
        category: BaselineCatalogValidationCategory,
        #[source]
        source: Box<GkrmError>,
    },

    #[error("three-way planner options are invalid: {limit}")]
    ThreeWayPlannerOptionsInvalid { limit: &'static str },

    #[error("three-way baseline and installed resource keys do not match")]
    ThreeWayBaselineInstalledResourceMismatch,

    #[error("three-way baseline and incoming resource keys do not match")]
    ThreeWayBaselineIncomingResourceMismatch,

    #[error("three-way installed and incoming resource keys do not match")]
    ThreeWayInstalledIncomingResourceMismatch,

    #[error("incoming root resource has no trusted logical identity for three-way planning")]
    ThreeWayIncomingRootIdentityUnavailable,

    #[error("trusted incoming resource identity is inconsistent")]
    ThreeWayIncomingResourceIdentityInconsistent,

    #[error("selected installed resource was not found in trusted inspection")]
    ThreeWaySelectedInstalledResourceMissing,

    #[error("selected installed resource is ambiguous in trusted inspection")]
    ThreeWaySelectedInstalledResourceAmbiguous,

    #[error("selected incoming resource was not found in trusted inspection")]
    ThreeWaySelectedIncomingResourceMissing,

    #[error("selected incoming resource is ambiguous in trusted inspection")]
    ThreeWaySelectedIncomingResourceAmbiguous,

    #[error("trusted snapshot version is unsupported")]
    ThreeWayUnsupportedTrustedSnapshotVersion,

    #[error("trusted baseline contains a duplicate normalized path")]
    ThreeWayDuplicateBaselinePath,

    #[error("trusted installed snapshot contains a duplicate normalized path")]
    ThreeWayDuplicateInstalledPath,

    #[error("trusted incoming snapshot contains a duplicate normalized path")]
    ThreeWayDuplicateIncomingPath,

    #[error("three-way plan entry limit exceeded: limit {limit}, actual {actual}")]
    ThreeWayPlanEntryLimitExceeded { limit: usize, actual: usize },

    #[error("three-way planner arithmetic overflow")]
    ThreeWayArithmeticOverflow,

    #[error("trusted snapshot is missing a required digest")]
    ThreeWayMissingRequiredDigest,

    #[error("trusted incoming package fingerprint is unavailable")]
    ThreeWayIncomingPackageFingerprintUnavailable,

    #[error("trusted ignored baseline file is missing blob metadata")]
    ThreeWayInconsistentIgnoredBaselineBlobPolicy,

    #[error("trusted snapshot fingerprint failed")]
    ThreeWaySnapshotFingerprintFailure,

    #[error("three-way planner internal invariant failed")]
    ThreeWayInternalInvariant,

    #[error("three-way review decision set does not match the trusted plan")]
    ThreeWayReviewPlanIdMismatch,

    #[error("three-way review decision set contains a duplicate path")]
    ThreeWayReviewDuplicateDecisionPath,

    #[error("three-way review decision path is not in the trusted plan")]
    ThreeWayReviewDecisionPathNotInPlan,

    #[error("three-way review decision was submitted for an entry that requires no decision")]
    ThreeWayReviewDecisionForNoDecisionEntry,

    #[error("three-way review recommendation is unavailable for the selected entry")]
    ThreeWayReviewRecommendationUnavailable,

    #[error("three-way review merge analysis is not allowed for the selected entry")]
    ThreeWayReviewMergeAnalysisNotAllowed,

    #[error("three-way review choice is not allowed for the selected entry")]
    ThreeWayReviewChoiceNotAllowed,

    #[error("three-way review policy acknowledgement is required")]
    ThreeWayReviewPolicyAcknowledgementRequired,

    #[error("three-way review policy acknowledgement is unnecessary")]
    ThreeWayReviewPolicyAcknowledgementUnnecessary,

    #[error("three-way review decision count exceeds plan entry count")]
    ThreeWayReviewDecisionCountExceedsPlanEntryCount,

    #[error("three-way review arithmetic overflow")]
    ThreeWayReviewArithmeticOverflow,

    #[error("three-way review entry count does not match plan entry count")]
    ThreeWayReviewEntryCountMismatch,

    #[error("three-way review summary invariant failed")]
    ThreeWayReviewSummaryInvariant,

    #[error("three-way review status invariant failed")]
    ThreeWayReviewStatusInvariant,

    #[error("three-way review id encoding failed")]
    ThreeWayReviewIdEncodingFailure,

    #[error("three-way merge analysis options are invalid: {limit}")]
    ThreeWayMergeAnalysisOptionsInvalid { limit: &'static str },

    #[error("three-way merge analysis plan and review do not match")]
    ThreeWayMergeAnalysisPlanReviewBindingMismatch,

    #[error("three-way merge analysis review entries do not match the trusted plan")]
    ThreeWayMergeAnalysisReviewStructuralMismatch,

    #[error("three-way merge analysis resolved baseline does not match the trusted plan")]
    ThreeWayMergeAnalysisBaselineMismatch,

    #[error("three-way merge analysis has no queued merge candidates")]
    ThreeWayMergeAnalysisNoQueuedCandidates,

    #[error("three-way merge analysis candidate limit exceeded")]
    ThreeWayMergeAnalysisCandidateLimitExceeded { limit: usize, actual: usize },

    #[error("queued three-way entry is not a merge candidate")]
    ThreeWayMergeAnalysisQueuedEntryNotMergeCandidate,

    #[error("queued three-way entry has a policy transition")]
    ThreeWayMergeAnalysisQueuedPolicyTransition,

    #[error("queued three-way entry is missing required B/L/N state or digest")]
    ThreeWayMergeAnalysisMissingStateOrDigest,

    #[error("queued three-way entry does not have divergent B/L/N hashes")]
    ThreeWayMergeAnalysisNonDivergentHashes,

    #[error("queued three-way entry has an invalid escrow class")]
    ThreeWayMergeAnalysisInvalidEscrowClass,

    #[error("queued three-way baseline blob metadata is unavailable")]
    ThreeWayMergeAnalysisBaselineBlobUnavailable,

    #[error("queued three-way baseline blob metadata does not match the trusted plan")]
    ThreeWayMergeAnalysisBaselineBlobMetadataMismatch,

    #[error("queued three-way baseline blob verification failed")]
    ThreeWayMergeAnalysisBaselineBlobVerificationFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("installed source pre-analysis fingerprint does not match the trusted plan")]
    ThreeWayMergeAnalysisInstalledPreFingerprintMismatch,

    #[error("installed source post-analysis fingerprint does not match the trusted plan")]
    ThreeWayMergeAnalysisInstalledPostFingerprintMismatch,

    #[error("installed source changed during merge analysis")]
    ThreeWayMergeAnalysisInstalledResourceChanged,

    #[error("installed merge candidate is missing, changed, or unsafe")]
    ThreeWayMergeAnalysisInstalledCandidateInvalid,

    #[error("incoming package fingerprint does not match the trusted plan")]
    ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch,

    #[error("incoming resource fingerprint does not match the trusted plan")]
    ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch,

    #[error("incoming resource identity does not match the trusted plan")]
    ThreeWayMergeAnalysisIncomingResourceIdentityMismatch,

    #[error("incoming merge candidate is missing, duplicate, changed, or unsafe")]
    ThreeWayMergeAnalysisIncomingCandidateInvalid,

    #[error("merge analysis source identity changed during read")]
    ThreeWayMergeAnalysisSourceIdentityChanged,

    #[error("three-way merge analysis total hash budget exceeded")]
    ThreeWayMergeAnalysisTotalHashBudgetExceeded { limit: u64, actual: u64 },

    #[error("three-way merge analysis arithmetic overflow")]
    ThreeWayMergeAnalysisArithmeticOverflow,

    #[error("three-way merge analysis summary invariant failed")]
    ThreeWayMergeAnalysisSummaryInvariant,

    #[error("three-way merge analysis status invariant failed")]
    ThreeWayMergeAnalysisStatusInvariant,

    #[error("three-way merge analysis id encoding failed")]
    ThreeWayMergeAnalysisIdEncodingFailure,

    #[error("three-way text diff options are invalid: {limit}")]
    ThreeWayTextDiffOptionsInvalid { limit: &'static str },

    #[error("three-way text diff plan and review do not match")]
    ThreeWayTextDiffPlanReviewBindingMismatch,

    #[error("three-way text diff plan and analysis do not match")]
    ThreeWayTextDiffPlanAnalysisBindingMismatch,

    #[error("three-way text diff review and analysis do not match")]
    ThreeWayTextDiffReviewAnalysisBindingMismatch,

    #[error("three-way text diff review entries do not match the trusted plan")]
    ThreeWayTextDiffReviewStructuralMismatch,

    #[error("three-way text diff analysis entries do not match queued review entries")]
    ThreeWayTextDiffAnalysisStructuralMismatch,

    #[error("three-way text diff resolved baseline does not match the trusted plan")]
    ThreeWayTextDiffBaselineMismatch,

    #[error("three-way text diff has no ready UTF-8 line merge candidates")]
    ThreeWayTextDiffNoReadyCandidates,

    #[error("three-way text diff candidate limit exceeded")]
    ThreeWayTextDiffCandidateLimitExceeded { limit: usize, actual: usize },

    #[error("three-way text diff candidate invariants are invalid")]
    ThreeWayTextDiffInvalidCandidateInvariant,

    #[error("three-way text diff baseline blob verification failed")]
    ThreeWayTextDiffBaselineBlobVerificationFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("installed source pre-diff fingerprint does not match the trusted plan")]
    ThreeWayTextDiffInstalledPreFingerprintMismatch,

    #[error("installed source post-diff fingerprint does not match the trusted plan")]
    ThreeWayTextDiffInstalledPostFingerprintMismatch,

    #[error("installed source changed during three-way text diff planning")]
    ThreeWayTextDiffInstalledResourceChanged,

    #[error("installed text-diff candidate is missing, changed, or unsafe")]
    ThreeWayTextDiffInstalledCandidateInvalid,

    #[error("incoming package fingerprint does not match the trusted text-diff plan")]
    ThreeWayTextDiffIncomingPackageFingerprintMismatch,

    #[error("incoming resource fingerprint does not match the trusted text-diff plan")]
    ThreeWayTextDiffIncomingResourceFingerprintMismatch,

    #[error("incoming resource identity does not match the trusted text-diff plan")]
    ThreeWayTextDiffIncomingResourceIdentityMismatch,

    #[error("incoming text-diff candidate is missing, duplicate, changed, or unsafe")]
    ThreeWayTextDiffIncomingCandidateInvalid,

    #[error("text-diff source identity changed during read")]
    ThreeWayTextDiffSourceIdentityChanged,

    #[error("reread content metadata does not match the trusted Task 16 analysis")]
    ThreeWayTextDiffTask16MetadataMismatch,

    #[error("three-way text diff total source-byte limit exceeded")]
    ThreeWayTextDiffTotalSourceByteLimitExceeded { limit: u64, actual: u64 },

    #[error("three-way text diff total line limit exceeded")]
    ThreeWayTextDiffTotalLineLimitExceeded { limit: usize, actual: usize },

    #[error("three-way text diff logical text is malformed")]
    ThreeWayTextDiffMalformedLogicalText,

    #[error("three-way text diff primitive script is invalid")]
    ThreeWayTextDiffInvalidPrimitiveScript,

    #[error("three-way text diff hunk is invalid")]
    ThreeWayTextDiffInvalidHunk,

    #[error("three-way text diff same-side hunks overlap")]
    ThreeWayTextDiffSameSideHunkOverlap,

    #[error("three-way text diff overlap component is invalid")]
    ThreeWayTextDiffInvalidOverlapComponent,

    #[error("three-way text diff summary invariant failed")]
    ThreeWayTextDiffSummaryInvariant,

    #[error("three-way text diff status invariant failed")]
    ThreeWayTextDiffStatusInvariant,

    #[error("three-way text diff id encoding failed")]
    ThreeWayTextDiffIdEncodingFailure,

    #[error("three-way text diff arithmetic overflow")]
    ThreeWayTextDiffArithmeticOverflow,

    #[error("three-way merge synthesis options are invalid: {limit}")]
    ThreeWayMergeSynthesisOptionsInvalid { limit: &'static str },

    #[error("three-way merge synthesis plan and review do not match")]
    ThreeWayMergeSynthesisPlanReviewBindingMismatch,

    #[error("three-way merge synthesis plan and analysis do not match")]
    ThreeWayMergeSynthesisPlanAnalysisBindingMismatch,

    #[error("three-way merge synthesis plan and text-diff plan do not match")]
    ThreeWayMergeSynthesisPlanTextDiffBindingMismatch,

    #[error("three-way merge synthesis review and analysis do not match")]
    ThreeWayMergeSynthesisReviewAnalysisBindingMismatch,

    #[error("three-way merge synthesis review and text-diff plan do not match")]
    ThreeWayMergeSynthesisReviewTextDiffBindingMismatch,

    #[error("three-way merge synthesis analysis and text-diff plan do not match")]
    ThreeWayMergeSynthesisAnalysisTextDiffBindingMismatch,

    #[error("three-way merge synthesis review entries do not match the trusted plan")]
    ThreeWayMergeSynthesisReviewStructuralMismatch,

    #[error("three-way merge synthesis analysis entries do not match queued review entries")]
    ThreeWayMergeSynthesisAnalysisStructuralMismatch,

    #[error("three-way merge synthesis text-diff entries do not match ready analysis candidates")]
    ThreeWayMergeSynthesisTextDiffStructuralMismatch,

    #[error("three-way merge synthesis resolved baseline does not match the trusted plan")]
    ThreeWayMergeSynthesisBaselineMismatch,

    #[error("three-way merge synthesis has no ready merge-synthesis candidates")]
    ThreeWayMergeSynthesisNoReadyCandidates,

    #[error("three-way merge synthesis candidate limit exceeded")]
    ThreeWayMergeSynthesisCandidateLimitExceeded { limit: usize, actual: usize },

    #[error("three-way merge synthesis candidate invariants are invalid")]
    ThreeWayMergeSynthesisInvalidCandidateInvariant,

    #[error("three-way merge synthesis baseline blob verification failed")]
    ThreeWayMergeSynthesisBaselineBlobVerificationFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("installed source pre-synthesis fingerprint does not match the trusted plan")]
    ThreeWayMergeSynthesisInstalledPreFingerprintMismatch,

    #[error("installed source post-synthesis fingerprint does not match the trusted plan")]
    ThreeWayMergeSynthesisInstalledPostFingerprintMismatch,

    #[error("installed source changed during three-way merge synthesis planning")]
    ThreeWayMergeSynthesisInstalledResourceChanged,

    #[error("installed merge-synthesis candidate is missing, changed, or unsafe")]
    ThreeWayMergeSynthesisInstalledCandidateInvalid,

    #[error("incoming package fingerprint does not match the trusted merge-synthesis plan")]
    ThreeWayMergeSynthesisIncomingPackageFingerprintMismatch,

    #[error("incoming resource fingerprint does not match the trusted merge-synthesis plan")]
    ThreeWayMergeSynthesisIncomingResourceFingerprintMismatch,

    #[error("incoming resource identity does not match the trusted merge-synthesis plan")]
    ThreeWayMergeSynthesisIncomingResourceIdentityMismatch,

    #[error("incoming merge-synthesis candidate is missing, duplicate, changed, or unsafe")]
    ThreeWayMergeSynthesisIncomingCandidateInvalid,

    #[error("merge-synthesis source identity changed during read")]
    ThreeWayMergeSynthesisSourceIdentityChanged,

    #[error("reread content metadata does not match the trusted Task 16 analysis")]
    ThreeWayMergeSynthesisTask16MetadataMismatch,

    #[error("reread content does not match the trusted Task 17 text-diff evidence")]
    ThreeWayMergeSynthesisTask17EvidenceMismatch,

    #[error("three-way merge synthesis total source-byte limit exceeded")]
    ThreeWayMergeSynthesisTotalSourceByteLimitExceeded { limit: u64, actual: u64 },

    #[error("three-way merge synthesis per-file source-byte limit exceeded")]
    ThreeWayMergeSynthesisSourceByteLimitExceeded { limit: u64, actual: u64 },

    #[error("three-way merge synthesis total line limit exceeded")]
    ThreeWayMergeSynthesisTotalLineLimitExceeded { limit: usize, actual: usize },

    #[error("three-way merge synthesis per-source line limit exceeded")]
    ThreeWayMergeSynthesisSourceLineLimitExceeded { limit: usize, actual: usize },

    #[error("three-way merge synthesis logical text is malformed")]
    ThreeWayMergeSynthesisMalformedLogicalText,

    #[error("three-way merge synthesis schedule invariant failed")]
    ThreeWayMergeSynthesisScheduleInvariant,

    #[error("three-way merge synthesis equivalent group is invalid")]
    ThreeWayMergeSynthesisInvalidEquivalentGroup,

    #[error("three-way merge synthesis envelope plan is invalid for a ready entry")]
    ThreeWayMergeSynthesisInvalidEnvelopePlan,

    #[error("three-way merge synthesis replay invariant failed")]
    ThreeWayMergeSynthesisReplayInvariant,

    #[error("three-way merge synthesis summary invariant failed")]
    ThreeWayMergeSynthesisSummaryInvariant,

    #[error("three-way merge synthesis status invariant failed")]
    ThreeWayMergeSynthesisStatusInvariant,

    #[error("three-way merge synthesis id encoding failed")]
    ThreeWayMergeSynthesisIdEncodingFailure,

    #[error("three-way merge synthesis arithmetic overflow")]
    ThreeWayMergeSynthesisArithmeticOverflow,

    #[error("three-way merged-bytes options are invalid: {limit}")]
    ThreeWayMergedBytesOptionsInvalid { limit: &'static str },

    #[error("three-way merged-bytes plan and review do not match")]
    ThreeWayMergedBytesPlanReviewBindingMismatch,

    #[error("three-way merged-bytes plan and analysis do not match")]
    ThreeWayMergedBytesPlanAnalysisBindingMismatch,

    #[error("three-way merged-bytes plan and text-diff plan do not match")]
    ThreeWayMergedBytesPlanTextDiffBindingMismatch,

    #[error("three-way merged-bytes plan and synthesis plan do not match")]
    ThreeWayMergedBytesPlanSynthesisBindingMismatch,

    #[error("three-way merged-bytes review and analysis do not match")]
    ThreeWayMergedBytesReviewAnalysisBindingMismatch,

    #[error("three-way merged-bytes review and text-diff plan do not match")]
    ThreeWayMergedBytesReviewTextDiffBindingMismatch,

    #[error("three-way merged-bytes review and synthesis plan do not match")]
    ThreeWayMergedBytesReviewSynthesisBindingMismatch,

    #[error("three-way merged-bytes analysis and text-diff plan do not match")]
    ThreeWayMergedBytesAnalysisTextDiffBindingMismatch,

    #[error("three-way merged-bytes analysis and synthesis plan do not match")]
    ThreeWayMergedBytesAnalysisSynthesisBindingMismatch,

    #[error("three-way merged-bytes text-diff and synthesis plan do not match")]
    ThreeWayMergedBytesTextDiffSynthesisBindingMismatch,

    #[error("three-way merged-bytes review entries do not match the trusted plan")]
    ThreeWayMergedBytesReviewStructuralMismatch,

    #[error("three-way merged-bytes analysis entries do not match queued review entries")]
    ThreeWayMergedBytesAnalysisStructuralMismatch,

    #[error("three-way merged-bytes text-diff entries do not match ready analysis candidates")]
    ThreeWayMergedBytesTextDiffStructuralMismatch,

    #[error("three-way merged-bytes synthesis entries do not match trusted text-diff evidence")]
    ThreeWayMergedBytesSynthesisStructuralMismatch,

    #[error("three-way merged-bytes resolved baseline does not match the trusted plan")]
    ThreeWayMergedBytesBaselineMismatch,

    #[error("three-way merged-bytes has no ready-for-staging candidates")]
    ThreeWayMergedBytesNoReadyCandidates,

    #[error("three-way merged-bytes candidate limit exceeded")]
    ThreeWayMergedBytesCandidateLimitExceeded { limit: usize, actual: usize },

    #[error("three-way merged-bytes candidate invariants are invalid")]
    ThreeWayMergedBytesInvalidCandidateInvariant,

    #[error("three-way merged-bytes baseline blob verification failed")]
    ThreeWayMergedBytesBaselineBlobVerificationFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("installed source pre-synthesis fingerprint does not match the trusted plan")]
    ThreeWayMergedBytesInstalledPreFingerprintMismatch,

    #[error("installed source post-synthesis fingerprint does not match the trusted plan")]
    ThreeWayMergedBytesInstalledPostFingerprintMismatch,

    #[error("installed source changed during three-way merged-bytes synthesis")]
    ThreeWayMergedBytesInstalledResourceChanged,

    #[error("installed merged-bytes candidate is missing, changed, or unsafe")]
    ThreeWayMergedBytesInstalledCandidateInvalid,

    #[error("incoming package fingerprint does not match the trusted merged-bytes plan")]
    ThreeWayMergedBytesIncomingPackageFingerprintMismatch,

    #[error("incoming resource fingerprint does not match the trusted merged-bytes plan")]
    ThreeWayMergedBytesIncomingResourceFingerprintMismatch,

    #[error("incoming resource identity does not match the trusted merged-bytes plan")]
    ThreeWayMergedBytesIncomingResourceIdentityMismatch,

    #[error("incoming merged-bytes candidate is missing, duplicate, changed, or unsafe")]
    ThreeWayMergedBytesIncomingCandidateInvalid,

    #[error("merged-bytes source identity changed during read")]
    ThreeWayMergedBytesSourceIdentityChanged,

    #[error("reread content metadata does not match the trusted Task 16 analysis")]
    ThreeWayMergedBytesTask16MetadataMismatch,

    #[error("reread content does not match the trusted Task 17 text-diff evidence")]
    ThreeWayMergedBytesTask17EvidenceMismatch,

    #[error("reread content does not match the trusted Task 18 synthesis evidence")]
    ThreeWayMergedBytesTask18EvidenceMismatch,

    #[error("three-way merged-bytes total source-byte limit exceeded")]
    ThreeWayMergedBytesTotalSourceByteLimitExceeded { limit: u64, actual: u64 },

    #[error("three-way merged-bytes per-file source-byte limit exceeded")]
    ThreeWayMergedBytesSourceByteLimitExceeded { limit: u64, actual: u64 },

    #[error("three-way merged-bytes total line limit exceeded")]
    ThreeWayMergedBytesTotalLineLimitExceeded { limit: usize, actual: usize },

    #[error("three-way merged-bytes per-source line limit exceeded")]
    ThreeWayMergedBytesSourceLineLimitExceeded { limit: usize, actual: usize },

    #[error("three-way merged-bytes logical text is malformed")]
    ThreeWayMergedBytesMalformedLogicalText,

    #[error("three-way merged-bytes schedule invariant failed")]
    ThreeWayMergedBytesScheduleInvariant,

    #[error("three-way merged-bytes equivalent group is invalid")]
    ThreeWayMergedBytesInvalidEquivalentGroup,

    #[error("three-way merged-bytes envelope is invalid for encoding")]
    ThreeWayMergedBytesInvalidEnvelope,

    #[error("three-way merged-bytes replay invariant failed")]
    ThreeWayMergedBytesReplayInvariant,

    #[error("three-way merged-bytes encode invariant failed")]
    ThreeWayMergedBytesEncodeInvariant,

    #[error("three-way merged-bytes summary invariant failed")]
    ThreeWayMergedBytesSummaryInvariant,

    #[error("three-way merged-bytes status invariant failed")]
    ThreeWayMergedBytesStatusInvariant,

    #[error("three-way merged-bytes id encoding failed")]
    ThreeWayMergedBytesIdEncodingFailure,

    #[error("three-way merged-bytes arithmetic overflow")]
    ThreeWayMergedBytesArithmeticOverflow,

    #[error("trusted staging options invalid: {limit}")]
    TrustedStagingOptionsInvalid { limit: &'static str },

    #[error("trusted staging plan/review binding mismatch")]
    TrustedStagingPlanReviewBindingMismatch,

    #[error("trusted staging merge-chain binding mismatch")]
    TrustedStagingMergeChainBindingMismatch,

    #[error("trusted staging merge-chain required or forbidden")]
    TrustedStagingMergeChainPresenceMismatch,

    #[error("trusted staging baseline binding mismatch")]
    TrustedStagingBaselineMismatch,

    #[error("trusted staging review is incomplete or unresolved")]
    TrustedStagingReviewUnresolved,

    #[error("trusted staging final-tree mapping rejected")]
    TrustedStagingFinalTreeRejected,

    #[error("trusted staging missing merged artifact")]
    TrustedStagingMissingMergedArtifact,

    #[error("trusted staging required manual merge result")]
    TrustedStagingManualMergeResult,

    #[error("trusted staging source content unavailable")]
    TrustedStagingSourceUnavailable,

    #[error("trusted staging root overlap or unsafe")]
    TrustedStagingRootOverlap,

    #[error("trusted staging root was replaced")]
    TrustedStagingRootReplaced,

    #[error("trusted staging destination already exists")]
    TrustedStagingDestinationExists,

    #[error("trusted staging unsafe filesystem object")]
    TrustedStagingUnsafeFilesystemObject,

    #[error("trusted staging write failure")]
    TrustedStagingWriteFailure {
        #[source]
        source: Box<GkrmError>,
    },

    /// Task 20 filesystem I/O failure with no path-bearing OS message or nested raw I/O.
    #[error("trusted staging I/O failure during {operation}")]
    TrustedStagingIo {
        operation: StagingIoOperation,
        kind: std::io::ErrorKind,
    },

    #[error("trusted staging digest or length mismatch")]
    TrustedStagingDigestLengthMismatch,

    #[error("trusted staging manifest or tree mismatch")]
    TrustedStagingManifestTreeMismatch,

    #[error("trusted staging limit exceeded")]
    TrustedStagingLimitExceeded { limit: &'static str },

    #[error("trusted staging arithmetic overflow")]
    TrustedStagingArithmeticOverflow,

    #[error("trusted staging id encoding failed")]
    TrustedStagingIdEncodingFailure,

    #[error("trusted staging cleanup failed")]
    TrustedStagingCleanupFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("trusted staging failed and cleanup also failed")]
    TrustedStagingFailedWithCleanupFailure {
        primary: Box<GkrmError>,
        cleanup: Box<GkrmError>,
    },

    #[error("trusted staging post-publish verification failed")]
    TrustedStagingPostPublishVerificationFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("trusted apply planning options invalid: {limit}")]
    TrustedApplyPlanningOptionsInvalid { limit: &'static str },

    #[error("trusted apply planning plan/review binding mismatch")]
    TrustedApplyPlanningPlanReviewBindingMismatch,

    #[error("trusted apply planning merge-chain binding mismatch")]
    TrustedApplyPlanningMergeChainBindingMismatch,

    #[error("trusted apply planning merge-chain presence mismatch")]
    TrustedApplyPlanningMergeChainPresenceMismatch,

    #[error("trusted apply planning baseline binding mismatch")]
    TrustedApplyPlanningBaselineMismatch,

    #[error("trusted apply planning review unresolved")]
    TrustedApplyPlanningReviewUnresolved,

    #[error("trusted apply planning manual merge result")]
    TrustedApplyPlanningManualMergeResult,

    #[error("trusted apply planning missing merged artifact")]
    TrustedApplyPlanningMissingMergedArtifact,

    #[error("trusted apply planning bundle status invalid")]
    TrustedApplyPlanningBundleStatusInvalid,

    #[error("trusted apply planning bundle binding mismatch")]
    TrustedApplyPlanningBundleBindingMismatch,

    #[error("trusted apply planning staging revalidation failed")]
    TrustedApplyPlanningStagingRevalidationFailed,

    #[error("trusted apply planning installed tree stale or unsafe")]
    TrustedApplyPlanningInstalledStale,

    #[error("trusted apply planning unexpected or missing entry")]
    TrustedApplyPlanningUnexpectedOrMissingEntry,

    #[error("trusted apply planning path type conflict")]
    TrustedApplyPlanningPathTypeConflict,

    #[error("trusted apply planning duplicate operation")]
    TrustedApplyPlanningDuplicateOperation,

    #[error("trusted apply planning incomplete final-state coverage")]
    TrustedApplyPlanningIncompleteCoverage,

    #[error("trusted apply planning limit exceeded: {limit}")]
    TrustedApplyPlanningLimitExceeded { limit: &'static str },

    #[error("trusted apply planning arithmetic overflow")]
    TrustedApplyPlanningArithmeticOverflow,

    #[error("trusted apply planning id encoding failed")]
    TrustedApplyPlanningIdEncodingFailure,

    #[error("trusted apply planning summary or status invariant failed")]
    TrustedApplyPlanningSummaryInvariant,

    #[error("trusted apply planning I/O failure during {operation}")]
    TrustedApplyPlanningIo {
        operation: ApplyPlanningIoOperation,
        kind: std::io::ErrorKind,
    },

    #[error("trusted transactional apply planning options invalid: {limit}")]
    TrustedTransactionalApplyPlanningOptionsInvalid { limit: &'static str },

    #[error("trusted transactional apply planning Task 14-21 binding mismatch")]
    TrustedTransactionalApplyPlanningBindingMismatch,

    #[error("trusted transactional apply planning apply-plan status invalid")]
    TrustedTransactionalApplyPlanningStatusInvalid,

    #[error("trusted transactional apply planning apply-plan integrity mismatch")]
    TrustedTransactionalApplyPlanningApplyPlanIntegrityMismatch,

    #[error("trusted transactional apply planning staging revalidation failed")]
    TrustedTransactionalApplyPlanningStagingRevalidationFailed,

    #[error("trusted transactional apply planning installed tree stale")]
    TrustedTransactionalApplyPlanningInstalledStale,

    #[error("trusted transactional apply planning operation precondition mismatch")]
    TrustedTransactionalApplyPlanningPreconditionMismatch,

    #[error("trusted transactional apply planning backup coverage incomplete")]
    TrustedTransactionalApplyPlanningBackupCoverageIncomplete,

    #[error("trusted transactional apply planning backup-set commitment mismatch")]
    TrustedTransactionalApplyPlanningBackupSetMismatch,

    #[error("trusted transactional apply planning journal transition invalid")]
    TrustedTransactionalApplyPlanningJournalInvalid,

    #[error("trusted transactional apply planning rollback mapping invalid")]
    TrustedTransactionalApplyPlanningRollbackInvalid,

    #[error("trusted transactional apply planning recovery table invalid")]
    TrustedTransactionalApplyPlanningRecoveryInvalid,

    #[error("trusted transactional apply planning limit exceeded: {limit}")]
    TrustedTransactionalApplyPlanningLimitExceeded { limit: &'static str },

    #[error("trusted transactional apply planning arithmetic overflow")]
    TrustedTransactionalApplyPlanningArithmeticOverflow,

    #[error("trusted transactional apply planning ID encoding failure")]
    TrustedTransactionalApplyPlanningIdEncodingFailure,

    #[error("trusted transactional apply planning summary or status invariant failed")]
    TrustedTransactionalApplyPlanningSummaryInvariant,

    #[error("trusted transactional apply planning I/O failure during {operation}")]
    TrustedTransactionalApplyPlanningIo {
        operation: TransactionalApplyPlanningIoOperation,
        kind: std::io::ErrorKind,
    },

    #[error("trusted transactional apply execution options invalid: {limit}")]
    TrustedTransactionalApplyExecutionOptionsInvalid { limit: &'static str },

    #[error("trusted transactional apply execution Task 14-22 binding mismatch")]
    TrustedTransactionalApplyExecutionBindingMismatch,

    #[error("trusted transactional apply execution status invalid")]
    TrustedTransactionalApplyExecutionStatusInvalid,

    #[error("trusted transactional apply execution plan integrity mismatch")]
    TrustedTransactionalApplyExecutionPlanIntegrityMismatch,

    #[error("trusted transactional apply execution staging revalidation failed")]
    TrustedTransactionalApplyExecutionStagingRevalidationFailed,

    #[error("trusted transactional apply execution installed tree stale")]
    TrustedTransactionalApplyExecutionInstalledStale,

    #[error("trusted transactional apply execution operation precondition mismatch")]
    TrustedTransactionalApplyExecutionPreconditionMismatch,

    #[error("trusted transactional apply execution transaction root overlap")]
    TrustedTransactionalApplyExecutionRootOverlap,

    #[error("trusted transactional apply execution transaction root replaced")]
    TrustedTransactionalApplyExecutionRootReplaced,

    #[error("trusted transactional apply execution transaction already exists")]
    TrustedTransactionalApplyExecutionTransactionExists,

    #[error("trusted transactional apply execution backup incomplete")]
    TrustedTransactionalApplyExecutionBackupIncomplete,

    #[error("trusted transactional apply execution backup seal mismatch")]
    TrustedTransactionalApplyExecutionBackupSealMismatch,

    #[error("trusted transactional apply execution journal invalid")]
    TrustedTransactionalApplyExecutionJournalInvalid,

    #[error("trusted transactional apply execution journal version unsupported")]
    TrustedTransactionalApplyExecutionJournalVersionUnsupported,

    #[error("trusted transactional apply execution forward step failed")]
    TrustedTransactionalApplyExecutionForwardFailed,

    #[error("trusted transactional apply execution verification failed")]
    TrustedTransactionalApplyExecutionVerificationFailed,

    #[error("trusted transactional apply execution rollback failed")]
    TrustedTransactionalApplyExecutionRollbackFailed,

    #[error("trusted transactional apply execution recovery required")]
    TrustedTransactionalApplyExecutionRecoveryRequired,

    #[error("trusted transactional apply execution limit exceeded: {limit}")]
    TrustedTransactionalApplyExecutionLimitExceeded { limit: &'static str },

    #[error("trusted transactional apply execution arithmetic overflow")]
    TrustedTransactionalApplyExecutionArithmeticOverflow,

    #[error("trusted transactional apply execution ID encoding failure")]
    TrustedTransactionalApplyExecutionIdEncodingFailure,

    #[error("trusted transactional apply execution unsafe filesystem object")]
    TrustedTransactionalApplyExecutionUnsafeFilesystemObject,

    #[error("trusted transactional apply execution I/O failure during {operation}")]
    TrustedTransactionalApplyExecutionIo {
        operation: TransactionalApplyIoOperation,
        kind: std::io::ErrorKind,
    },

    #[error(
        "trusted transactional apply execution failed with compound outcomes (primary/rollback/journal/cleanup)"
    )]
    TrustedTransactionalApplyExecutionFailedCompound {
        primary: Box<GkrmError>,
        rollback: Box<GkrmError>,
        journal: Box<GkrmError>,
        cleanup: Box<GkrmError>,
    },

    /// Published transaction exists, but a durable RecoveryRequired journal record could not be sealed.
    #[error(
        "trusted transactional apply execution published transaction needs recovery; recovery journal unsealed"
    )]
    TrustedTransactionalApplyExecutionPublishedNeedsRecovery {
        primary: Box<GkrmError>,
        recovery_journal: Box<GkrmError>,
    },

    #[error("trusted transactional apply execution lock contention")]
    TrustedTransactionalApplyExecutionLockContention,

    #[error("trusted transactional apply execution lock binding mismatch")]
    TrustedTransactionalApplyExecutionLockBindingMismatch,

    #[error("trusted transactional apply execution reliable locking unsupported")]
    TrustedTransactionalApplyExecutionLockUnsupported,

    #[error("trusted transaction recovery options invalid: {limit}")]
    TrustedTransactionRecoveryOptionsInvalid { limit: &'static str },

    #[error("trusted transaction recovery Task 14-23 binding mismatch")]
    TrustedTransactionRecoveryBindingMismatch,

    #[error("trusted transaction recovery candidate invalid")]
    TrustedTransactionRecoveryCandidateInvalid,

    #[error("trusted transaction recovery scan unsafe")]
    TrustedTransactionRecoveryScanUnsafe,

    #[error("trusted transaction recovery limit exceeded: {limit}")]
    TrustedTransactionRecoveryLimitExceeded { limit: &'static str },

    #[error("trusted transaction recovery ID encoding failure")]
    TrustedTransactionRecoveryIdEncodingFailure,

    #[error("trusted transaction recovery journal invalid")]
    TrustedTransactionRecoveryJournalInvalid,

    #[error("trusted transaction recovery revalidation failed")]
    TrustedTransactionRecoveryRevalidationFailed,

    #[error("trusted transaction recovery conflict")]
    TrustedTransactionRecoveryConflict,

    #[error("trusted transaction recovery I/O failure during {operation}")]
    TrustedTransactionRecoveryIo {
        operation: TransactionalApplyIoOperation,
        kind: std::io::ErrorKind,
    },

    #[error("trusted CLI update options invalid: {limit}")]
    TrustedCliUpdateOptionsInvalid { limit: &'static str },

    #[error("trusted CLI update resource selection required")]
    TrustedCliUpdateResourceSelectionRequired,

    #[error("trusted CLI update resource not found")]
    TrustedCliUpdateResourceNotFound,

    #[error("trusted CLI update resource ambiguous")]
    TrustedCliUpdateResourceAmbiguous,

    #[error("trusted CLI update recovery required before continue")]
    TrustedCliUpdateRecoveryRequired,

    #[error("trusted CLI update decisions invalid")]
    TrustedCliUpdateDecisionsInvalid,

    #[error("trusted CLI update decisions plan ID mismatch")]
    TrustedCliUpdateDecisionsPlanMismatch,

    #[error("trusted CLI update artifact invalid")]
    TrustedCliUpdateArtifactInvalid,

    #[error("trusted CLI update artifact version unsupported")]
    TrustedCliUpdateArtifactVersionUnsupported,

    #[error("trusted CLI update binding mismatch")]
    TrustedCliUpdateBindingMismatch,

    #[error("trusted update source changed")]
    TrustedUpdateSourceChanged,

    #[error("trusted CLI update destination exists")]
    TrustedCliUpdateDestinationExists,

    #[error("trusted CLI update path overlap")]
    TrustedCliUpdatePathOverlap,

    #[error("trusted CLI update operator merge invalid")]
    TrustedCliUpdateOperatorMergeInvalid,

    #[error("trusted CLI update operator merge not required for path")]
    TrustedCliUpdateOperatorMergeNotRequired,

    #[error("trusted CLI update candidate not found")]
    TrustedCliUpdateCandidateNotFound,

    #[error("trusted CLI update candidate ambiguous")]
    TrustedCliUpdateCandidateAmbiguous,

    #[error("trusted CLI update transaction already published")]
    TrustedCliUpdateTransactionAlreadyPublished,

    #[error("trusted CLI update ID encoding failure")]
    TrustedCliUpdateIdEncodingFailure,

    #[error("trusted CLI update limit exceeded: {limit}")]
    TrustedCliUpdateLimitExceeded { limit: &'static str },

    #[error("trusted recovery authority is invalid")]
    TrustedRecoveryAuthorityInvalid,

    #[error("trusted recovery authority version is unsupported")]
    TrustedRecoveryAuthorityVersionUnsupported,

    #[error("trusted recovery authority derivation is unsupported")]
    TrustedRecoveryAuthorityDerivationUnsupported,

    #[error("trusted recovery authority binding mismatch")]
    TrustedRecoveryAuthorityBindingMismatch,

    #[error("trusted recovery authority limit exceeded: {limit}")]
    TrustedRecoveryAuthorityLimitExceeded { limit: &'static str },

    #[error("trusted recovery authority arithmetic overflow")]
    TrustedRecoveryAuthorityArithmeticOverflow,

    #[error("trusted package-free update recovery candidate not found")]
    TrustedPackageFreeUpdateRecoveryCandidateNotFound,

    #[error("trusted package-free update recovery candidate ambiguous")]
    TrustedPackageFreeUpdateRecoveryCandidateAmbiguous,

    #[error("trusted package-free update recovery evidence unsupported")]
    TrustedPackageFreeUpdateRecoveryUnsupported,

    #[error("trusted package-free update recovery binding mismatch")]
    TrustedPackageFreeUpdateRecoveryBindingMismatch,

    #[error("trusted terminal-evidence retirement requires explicit acknowledgement")]
    TrustedTerminalEvidenceRetirementAcknowledgementRequired,

    #[error("trusted terminal-evidence retirement is blocked by unresolved evidence")]
    TrustedTerminalEvidenceRetirementBlocked,

    #[error("trusted terminal-evidence retirement evidence is invalid")]
    TrustedTerminalEvidenceRetirementInvalid,

    #[error("trusted terminal-evidence retirement version is unsupported")]
    TrustedTerminalEvidenceRetirementVersionUnsupported,

    #[error("trusted terminal-evidence retirement limit exceeded: {limit}")]
    TrustedTerminalEvidenceRetirementLimitExceeded { limit: &'static str },

    #[error("trusted CLI update I/O failure")]
    TrustedCliUpdateIo { kind: std::io::ErrorKind },

    #[error("trusted CLI update security rejection")]
    TrustedCliUpdateSecurityRejection,

    #[error("two-way plan snapshots are not bound to each other")]
    TwoWayPlanSnapshotMismatch,

    #[error("two-way plan encountered a duplicate path")]
    TwoWayPlanDuplicatePath,

    #[error("two-way plan invariant violated")]
    TwoWayPlanInvariant,

    #[error("two-way plan identity encoding failed")]
    TwoWayPlanIdEncodingFailure,

    #[error("the package installed from does not carry the resource being updated")]
    TwoWayBaselineResourceMismatch,

    #[error("a merged JSON document did not read back as JSON")]
    JsonMergeResultInvalid,

    #[error(
        "the installation or the package changed since the preview the decisions were made on"
    )]
    TwoWayPlanChangedSincePreview,

    #[error("two decisions name the same file")]
    TwoWayDuplicateFileChoice,

    #[error("two-way merge decisions do not match the file's change blocks")]
    TwoWayMergeChoiceCountMismatch,

    #[error("trusted update workspace is invalid")]
    TrustedUpdateWorkspaceInvalid,

    /// A pre-release presence-only workspace marker was found where a version-2
    /// binding is required. The evidence beneath it is not known to be damaged;
    /// the marker simply cannot prove which sibling roots were legitimate, so the
    /// workspace is refused without migration or cleanup.
    #[error("trusted update workspace uses an unsupported pre-release layout")]
    TrustedUpdateWorkspaceLegacyUnsupported,

    #[error("trusted update workspace capacity reached")]
    TrustedUpdateWorkspaceCapacityReached,

    #[error("baseline capture found no incoming resources")]
    BaselineCaptureNoResources,

    #[error("baseline capture resource selection is ambiguous")]
    BaselineCaptureAmbiguousResources,

    #[error("baseline capture selector did not match any discovered resource")]
    BaselineCaptureResourceNotFound,

    #[error("baseline capture selector matched multiple discovered resources")]
    BaselineCaptureResourceAmbiguous,

    #[error("baseline capture resource identity is unsafe")]
    BaselineCaptureUnsafeResourceIdentity,

    #[error("baseline capture selected an empty resource")]
    BaselineCaptureEmptyResource,

    #[error("baseline capture duplicate file path")]
    BaselineCaptureDuplicateFilePath,

    #[error("baseline capture duplicate archive entry association")]
    BaselineCaptureDuplicateArchiveEntry,

    #[error("baseline capture missing escrow classification")]
    BaselineCaptureMissingEscrowClassification,

    #[error("baseline capture inconsistent escrow classification")]
    BaselineCaptureInconsistentEscrowClassification,

    #[error("baseline capture selected file count exceeds limit: limit {limit}, actual {actual}")]
    BaselineCaptureSelectedFileLimit { limit: usize, actual: usize },

    #[error("baseline capture selected bytes exceed limit: limit {limit}, actual {actual}")]
    BaselineCaptureSelectedByteLimit { limit: u64, actual: u64 },

    #[error("baseline capture entry metadata mismatch")]
    BaselineCaptureEntrySizeMismatch { expected: u64, actual: u64 },

    #[error("baseline capture failed reading entry")]
    BaselineCaptureEntryReadFailure {
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },

    #[error("baseline capture ignored blob verification failed")]
    BaselineCaptureIgnoredBlobMissing,

    #[error("baseline capture ignored blob verification failed")]
    BaselineCaptureIgnoredBlobSizeMismatch { expected: u64, actual: u64 },

    #[error("baseline capture ignored blob verification failed")]
    BaselineCaptureIgnoredBlobDigestMismatch,

    #[error("baseline capture blob spool failure ({stage})")]
    BaselineCaptureBlobSpoolFailure {
        stage: BaselineCaptureBlobSpoolStage,
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },

    #[error("baseline capture spool cleanup failed")]
    BaselineCaptureSpoolCleanupFailed {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("baseline capture failed and spool cleanup also failed")]
    BaselineCaptureFailedWithCleanupFailure {
        #[source]
        primary: Box<GkrmError>,
        cleanup: Box<GkrmError>,
    },

    #[error("baseline capture options are invalid: {limit}")]
    BaselineCaptureOptionsInvalid { limit: &'static str },

    #[error("baseline capture bundle construction failed")]
    BaselineCaptureBundleConstruction {
        #[source]
        source: Box<GkrmError>,
    },

    #[error("baseline capture failed to open package")]
    BaselineCapturePackageOpen {
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },

    #[error("baseline capture failed to read package")]
    BaselineCapturePackageRead {
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },

    #[error("baseline capture package archive is invalid")]
    BaselineCaptureArchiveInvalid,

    #[error("baseline capture rejected a package symlink")]
    BaselineCapturePackageSymlink,

    #[error("baseline capture rejected a package reparse point")]
    BaselineCapturePackageReparsePoint,

    #[error("baseline capture rejected unsafe package path")]
    BaselineCapturePackagePathInvalid,

    #[error("baseline capture package changed during snapshot")]
    BaselineCapturePackageChanged,

    #[error("baseline capture package exceeds archive size limit: limit {limit}, actual {actual}")]
    BaselineCaptureArchiveSizeLimit { limit: u64, actual: u64 },

    #[error("baseline capture ignored blob verification failed")]
    BaselineCaptureBlobSizeLimitExceeded { limit: u64, actual: u64 },

    #[error("baseline capture unique blob bytes exceed limit: limit {limit}, actual {actual}")]
    BaselineCaptureTotalBlobLimitExceeded { limit: u64, actual: u64 },

    #[error("baseline capture temporary spool budget exceeded: limit {limit}, actual {actual}")]
    BaselineCaptureSpoolBudgetExceeded { limit: u64, actual: u64 },

    #[error("baseline capture spool object failed verification")]
    BaselineCaptureSpoolVerificationFailure,

    #[error("baseline capture spool source identity changed")]
    BaselineCaptureSpoolIdentityChanged,

    /// Test-only failure injection; absent from release builds.
    #[cfg(test)]
    #[error("baseline capture test seam failure")]
    BaselineCaptureTestSeamFailure,

    #[error("baseline capture rejected unsafe zip entry ({kind})")]
    BaselineCaptureUnsafeZipEntry {
        kind: BaselineCaptureUnsafeEntryKind,
    },

    #[error("baseline capture archive limit exceeded ({kind}): limit {limit}, actual {actual}")]
    BaselineCaptureArchiveLimitExceeded {
        kind: BaselineCaptureArchiveLimitKind,
        limit: u64,
        actual: u64,
    },

    #[error("baseline capture archive limit exceeded ({kind}): limit {limit}, actual {actual}")]
    BaselineCaptureArchiveEntryLimitExceeded {
        kind: BaselineCaptureArchiveLimitKind,
        limit: u64,
        actual: u64,
    },

    #[error("baseline capture archive entry read failed")]
    BaselineCaptureArchiveEntryRead,

    #[error("baseline capture archive entry stream failed")]
    BaselineCaptureArchiveEntryStream {
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },

    #[error("baseline capture archive entry is inconsistent")]
    BaselineCaptureArchiveEntryInconsistent,

    #[error("baseline capture archive entry metadata mismatch")]
    BaselineCaptureArchiveEntrySizeMismatch { expected: u64, actual: u64 },

    #[error("baseline capture manifest is invalid")]
    BaselineCaptureManifestInvalid,

    #[error("baseline capture escrow glob policy is unsafe")]
    BaselineCaptureEscrowGlobInvalid,

    #[error("baseline capture escrow manifest is invalid")]
    BaselineCaptureEscrowManifestInvalid,

    #[error("baseline capture escrow resource path is invalid")]
    BaselineCaptureEscrowResourcePathInvalid,

    #[error("baseline capture baseline conflict detected")]
    BaselineCaptureBaselineConflict,

    #[error("baseline capture blob verification failed")]
    BaselineCaptureBlobVerificationFailed,

    #[error("baseline capture bundle path is invalid")]
    BaselineCaptureBundlePathInvalid,

    #[error("baseline capture bundle ordering is invalid")]
    BaselineCaptureBundleOrderingInvalid,

    #[error("baseline capture bundle blob is invalid")]
    BaselineCaptureBundleBlobInvalid,

    #[error("baseline capture bundle identity mismatch")]
    BaselineCaptureBundleIdentityMismatch,

    #[error("baseline capture publication failed")]
    BaselineCapturePublicationFailed {
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },

    #[error("baseline capture rejected a non-capture domain failure")]
    BaselineCaptureForeignFailure,

    #[error("baseline capture store failure")]
    BaselineCaptureStoreFailure {
        /// Sanitized OS error category only; no raw dependency object is retained.
        kind: std::io::ErrorKind,
    },
}

/// Safe public category for baseline catalog and resolution validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BaselineCatalogValidationCategory {
    UnsupportedSchema,
    ResourceKeyMismatch,
    StoredRequestedIdMismatch,
    CanonicalIdMismatch,
    Ordering,
    Counts,
    BlobReference,
    BlobSize,
    BlobDigest,
    EscrowBlobPolicy,
    UnsafeFilesystem,
    UnexpectedBundleStructure,
    Limits,
    Io,
}

impl std::fmt::Display for BaselineCatalogValidationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedSchema => "unsupported-schema",
            Self::ResourceKeyMismatch => "resource-key-mismatch",
            Self::StoredRequestedIdMismatch => "stored-requested-id-mismatch",
            Self::CanonicalIdMismatch => "canonical-id-mismatch",
            Self::Ordering => "ordering",
            Self::Counts => "counts",
            Self::BlobReference => "blob-reference",
            Self::BlobSize => "blob-size",
            Self::BlobDigest => "blob-digest",
            Self::EscrowBlobPolicy => "escrow-blob-policy",
            Self::UnsafeFilesystem => "unsafe-filesystem",
            Self::UnexpectedBundleStructure => "unexpected-bundle-structure",
            Self::Limits => "limits",
            Self::Io => "io",
        })
    }
}

/// Safe public category for rejected ZIP entries during official baseline capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCaptureUnsafeEntryKind {
    Symlink,
    Encrypted,
    UnsupportedCompression,
    ParentTraversal,
    AbsoluteOrDrivePath,
    InvalidPath,
    DuplicatePath,
    CaseInsensitiveCollision,
    DirectoryNonZeroSize,
    EmptyOrInvalidName,
}

impl std::fmt::Display for BaselineCaptureUnsafeEntryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Symlink => "symlink",
            Self::Encrypted => "encrypted",
            Self::UnsupportedCompression => "unsupported-compression",
            Self::ParentTraversal => "parent-traversal",
            Self::AbsoluteOrDrivePath => "absolute-or-drive-path",
            Self::InvalidPath => "invalid-path",
            Self::DuplicatePath => "duplicate-path",
            Self::CaseInsensitiveCollision => "case-insensitive-collision",
            Self::DirectoryNonZeroSize => "directory-nonzero-size",
            Self::EmptyOrInvalidName => "empty-or-invalid-name",
        })
    }
}

/// Safe public category for archive limit failures during official baseline capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCaptureArchiveLimitKind {
    EntryCount,
    EntryUncompressedSize,
    TotalUncompressedSize,
    CompressionRatio,
    ArchiveFileSize,
}

impl std::fmt::Display for BaselineCaptureArchiveLimitKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EntryCount => "entry-count",
            Self::EntryUncompressedSize => "entry-uncompressed-size",
            Self::TotalUncompressedSize => "total-uncompressed-size",
            Self::CompressionRatio => "compression-ratio",
            Self::ArchiveFileSize => "archive-file-size",
        })
    }
}

/// Safe public stage label for private capture spool failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCaptureBlobSpoolStage {
    Allocate,
    Create,
    Open,
    Validate,
    Write,
    Flush,
    Rename,
    Cleanup,
}

impl std::fmt::Display for BaselineCaptureBlobSpoolStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Allocate => "spool allocation",
            Self::Create => "spool creation",
            Self::Open => "spool open",
            Self::Validate => "spool validation",
            Self::Write => "temporary blob write",
            Self::Flush => "temporary blob flush",
            Self::Rename => "temporary blob publish",
            Self::Cleanup => "spool cleanup",
        })
    }
}

impl GkrmError {
    /// Primary capture failure when both capture and spool cleanup failed.
    pub fn capture_primary_error(&self) -> Option<&GkrmError> {
        match self {
            Self::BaselineCaptureFailedWithCleanupFailure { primary, .. } => Some(primary),
            _ => None,
        }
    }

    /// Cleanup-stage failure when spool cleanup failed (alone or with a primary failure).
    pub fn capture_cleanup_error(&self) -> Option<&GkrmError> {
        match self {
            Self::BaselineCaptureSpoolCleanupFailed { source } => Some(source),
            Self::BaselineCaptureFailedWithCleanupFailure { cleanup, .. } => Some(cleanup),
            _ => None,
        }
    }

    pub fn baseline_verified_blob_callback_error(&self) -> Option<&GkrmError> {
        match self {
            Self::BaselineVerifiedBlobCallbackAndVerificationFailed { primary, .. } => {
                Some(primary)
            }
            _ => None,
        }
    }

    pub fn baseline_verified_blob_verification_error(&self) -> Option<&GkrmError> {
        match self {
            Self::BaselineVerifiedBlobCallbackAndVerificationFailed { verification, .. } => {
                Some(verification)
            }
            _ => None,
        }
    }
}

impl std::fmt::Debug for GkrmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Public Debug must not dump PathBuf/io::Error fields that retain filesystem identity.
        // Alternate Debug (`{:#?}`) uses the same sanitized Display contract.
        write!(f, "{self}")
    }
}
