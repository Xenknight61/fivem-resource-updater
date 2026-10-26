use std::cmp::Ordering;
use std::path::Path;

use cap_fs_ext::DirEntryExt;

use crate::baseline::fs_security::{
    dir_identity, open_baseline_catalog_resource, open_child_dir, reject_link_like_metadata,
    validate_single_component,
};
use crate::baseline::id::BaselineId;
use crate::baseline::key::SafeResourceKey;
use crate::baseline::model::{BaselineCounts, BaselineStoreLimits, StoredBaseline};
use crate::baseline::store::load_baseline_bundle;
use crate::file_identity::StableFileIdentity;
use crate::{BaselineCatalogValidationCategory, GkrmError, Result, Sha256Digest};

const DEFAULT_MAX_CATALOG_ENTRIES: usize = 256;

/// How to select a previously captured official baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfficialBaselineSelector {
    Exact(BaselineId),
    AutoSingle,
}

/// Validated options for official baseline cataloging and resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselineResolutionOptions {
    baseline_store_limits: BaselineStoreLimits,
    max_catalog_entries: usize,
}

impl Default for BaselineResolutionOptions {
    fn default() -> Self {
        Self {
            baseline_store_limits: BaselineStoreLimits::default(),
            max_catalog_entries: DEFAULT_MAX_CATALOG_ENTRIES,
        }
    }
}

impl BaselineResolutionOptions {
    pub fn try_new(
        baseline_store_limits: BaselineStoreLimits,
        max_catalog_entries: usize,
    ) -> Result<Self> {
        let options = Self {
            baseline_store_limits,
            max_catalog_entries,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn baseline_store_limits(&self) -> BaselineStoreLimits {
        self.baseline_store_limits
    }

    pub fn max_catalog_entries(&self) -> usize {
        self.max_catalog_entries
    }

    fn validate(self) -> Result<()> {
        self.baseline_store_limits.validate()?;
        if self.max_catalog_entries == 0 {
            return Err(GkrmError::BaselineResolutionOptionsInvalid {
                limit: "max_catalog_entries",
            });
        }
        Ok(())
    }
}

/// Opaque read-only catalog request.
#[derive(Debug)]
pub struct BaselineCatalogRequest<'a> {
    store_root: &'a Path,
    resource_key: &'a SafeResourceKey,
    options: BaselineResolutionOptions,
}

impl<'a> BaselineCatalogRequest<'a> {
    pub fn try_new(
        store_root: &'a Path,
        resource_key: &'a SafeResourceKey,
        options: BaselineResolutionOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            store_root,
            resource_key,
            options,
        })
    }
}

/// Opaque read-only resolution request.
#[derive(Debug)]
pub struct BaselineResolutionRequest<'a> {
    store_root: &'a Path,
    resource_key: &'a SafeResourceKey,
    selector: OfficialBaselineSelector,
    options: BaselineResolutionOptions,
}

impl<'a> BaselineResolutionRequest<'a> {
    pub fn try_new(
        store_root: &'a Path,
        resource_key: &'a SafeResourceKey,
        selector: OfficialBaselineSelector,
        options: BaselineResolutionOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            store_root,
            resource_key,
            selector,
            options,
        })
    }
}

/// Read-only informational catalog of trusted official baseline summaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCatalog {
    resource_key: SafeResourceKey,
    entries: Vec<BaselineCatalogEntry>,
    issues: Vec<BaselineCatalogIssue>,
}

impl BaselineCatalog {
    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }

    pub fn entries(&self) -> &[BaselineCatalogEntry] {
        &self.entries
    }

    pub fn issues(&self) -> &[BaselineCatalogIssue] {
        &self.issues
    }
}

/// Fully validated official baseline summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCatalogEntry {
    baseline_id: BaselineId,
    resource_name: String,
    resource_version: Option<String>,
    source_package_fingerprint: Option<Sha256Digest>,
    counts: BaselineCounts,
}

impl BaselineCatalogEntry {
    pub fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
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

    pub fn counts(&self) -> &BaselineCounts {
        &self.counts
    }
}

/// Safe public category for catalog issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BaselineCatalogIssueKind {
    InvalidCandidateName,
    UnexpectedEntryType,
    UnsafeCandidateEntry,
    BaselineValidationFailed,
}

/// Safe catalog issue. It never exposes raw entry names or paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineCatalogIssue {
    kind: BaselineCatalogIssueKind,
    baseline_id: Option<BaselineId>,
    validation_category: Option<BaselineCatalogValidationCategory>,
}

impl BaselineCatalogIssue {
    pub fn kind(&self) -> BaselineCatalogIssueKind {
        self.kind
    }

    pub fn baseline_id(&self) -> Option<&BaselineId> {
        self.baseline_id.as_ref()
    }

    pub fn validation_category(&self) -> Option<BaselineCatalogValidationCategory> {
        self.validation_category
    }

    fn invalid_candidate_name() -> Self {
        Self {
            kind: BaselineCatalogIssueKind::InvalidCandidateName,
            baseline_id: None,
            validation_category: None,
        }
    }

    fn unexpected_entry_type() -> Self {
        Self {
            kind: BaselineCatalogIssueKind::UnexpectedEntryType,
            baseline_id: None,
            validation_category: None,
        }
    }

    fn unsafe_candidate_entry() -> Self {
        Self {
            kind: BaselineCatalogIssueKind::UnsafeCandidateEntry,
            baseline_id: None,
            validation_category: None,
        }
    }

    fn validation_failed(
        baseline_id: BaselineId,
        category: BaselineCatalogValidationCategory,
    ) -> Self {
        Self {
            kind: BaselineCatalogIssueKind::BaselineValidationFailed,
            baseline_id: Some(baseline_id),
            validation_category: Some(category),
        }
    }

    fn stable_cmp(&self, other: &Self) -> Ordering {
        (
            self.kind,
            self.baseline_id.as_ref().map(BaselineId::as_str),
            self.validation_category,
        )
            .cmp(&(
                other.kind,
                other.baseline_id.as_ref().map(BaselineId::as_str),
                other.validation_category,
            ))
    }
}

/// Trusted resolved baseline for future planning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOfficialBaseline {
    stored_baseline: StoredBaseline,
    selection: ResolvedBaselineSelectionKind,
}

impl ResolvedOfficialBaseline {
    pub fn baseline_id(&self) -> &BaselineId {
        self.stored_baseline.baseline_id()
    }

    pub fn resource_key(&self) -> &SafeResourceKey {
        self.stored_baseline.resource_key()
    }

    pub fn resource_name(&self) -> &str {
        self.stored_baseline.resource_name()
    }

    pub fn resource_version(&self) -> Option<&str> {
        self.stored_baseline.resource_version()
    }

    pub fn source_package_fingerprint(&self) -> Option<&Sha256Digest> {
        self.stored_baseline.source_package_fingerprint()
    }

    pub fn counts(&self) -> &BaselineCounts {
        self.stored_baseline.counts()
    }

    pub fn selection(&self) -> ResolvedBaselineSelectionKind {
        self.selection
    }

    pub fn stored_baseline(&self) -> &StoredBaseline {
        &self.stored_baseline
    }

    #[cfg(test)]
    pub(crate) fn from_stored_baseline_for_test(stored_baseline: StoredBaseline) -> Self {
        Self {
            stored_baseline,
            selection: ResolvedBaselineSelectionKind::Exact,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolvedBaselineSelectionKind {
    Exact,
    AutoSingle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BaselineCatalogSnapshot {
    catalog: BaselineCatalog,
    resource_key_identity: Option<StableFileIdentity>,
    raw_entry_count: usize,
    candidate_identities: Vec<(BaselineId, StableFileIdentity)>,
}

/// Catalog fully validated official baselines for one resource key.
pub fn catalog_official_baselines(request: BaselineCatalogRequest<'_>) -> Result<BaselineCatalog> {
    request.options.validate()?;
    Ok(build_catalog_snapshot(request.store_root, request.resource_key, request.options)?.catalog)
}

/// Resolve a selected official baseline into a freshly loaded trusted baseline.
pub fn resolve_official_baseline(
    request: BaselineResolutionRequest<'_>,
) -> Result<ResolvedOfficialBaseline> {
    request.options.validate()?;
    match request.selector {
        OfficialBaselineSelector::Exact(ref baseline_id) => resolve_exact(
            request.store_root,
            request.resource_key,
            baseline_id,
            request.options,
        ),
        OfficialBaselineSelector::AutoSingle => {
            resolve_auto_single(request.store_root, request.resource_key, request.options)
        }
    }
}

fn resolve_exact(
    store_root: &Path,
    resource_key: &SafeResourceKey,
    baseline_id: &BaselineId,
    options: BaselineResolutionOptions,
) -> Result<ResolvedOfficialBaseline> {
    match load_baseline_bundle(
        store_root,
        resource_key,
        baseline_id,
        options.baseline_store_limits,
    ) {
        Ok(stored_baseline) => Ok(ResolvedOfficialBaseline {
            stored_baseline,
            selection: ResolvedBaselineSelectionKind::Exact,
        }),
        Err(error) if is_selected_baseline_not_found(&error, baseline_id, resource_key) => {
            Err(GkrmError::BaselineSelectedBaselineNotFound {
                baseline_id: baseline_id.to_string(),
            })
        }
        Err(error) => Err(GkrmError::BaselineSelectedBaselineValidationFailed {
            baseline_id: baseline_id.to_string(),
            category: validation_category(&error),
            source: Box::new(error),
        }),
    }
}

fn resolve_auto_single(
    store_root: &Path,
    resource_key: &SafeResourceKey,
    options: BaselineResolutionOptions,
) -> Result<ResolvedOfficialBaseline> {
    let before = build_catalog_snapshot(store_root, resource_key, options)?;

    if !before.catalog.issues.is_empty() {
        return Err(GkrmError::BaselineAutoSingleBlockedByCatalogIssues {
            issue_count: before.catalog.issues.len(),
        });
    }
    if before.catalog.entries.is_empty() {
        return Err(GkrmError::BaselineNoStoredBaselines);
    }
    if before.catalog.entries.len() > 1 {
        return Err(
            GkrmError::BaselineMultipleValidBaselinesRequireExactSelection {
                baseline_ids: before
                    .catalog
                    .entries
                    .iter()
                    .map(|entry| entry.baseline_id.clone())
                    .collect(),
            },
        );
    }

    run_after_auto_single_snapshot_a_hook()?;

    let baseline_id = before.catalog.entries[0].baseline_id.clone();
    let stored_baseline = load_baseline_bundle(
        store_root,
        resource_key,
        &baseline_id,
        options.baseline_store_limits,
    )
    .map_err(|error| {
        if is_selected_baseline_not_found(&error, &baseline_id, resource_key) {
            GkrmError::BaselineCatalogChangedDuringResolution
        } else {
            GkrmError::BaselineSelectedBaselineValidationFailed {
                baseline_id: baseline_id.to_string(),
                category: validation_category(&error),
                source: Box::new(error),
            }
        }
    })?;

    run_after_auto_single_selected_load_hook()?;

    let after = build_catalog_snapshot(store_root, resource_key, options)?;
    if !catalog_snapshots_equivalent_for_auto_single(&before, &after, &baseline_id) {
        return Err(GkrmError::BaselineCatalogChangedDuringResolution);
    }

    Ok(ResolvedOfficialBaseline {
        stored_baseline,
        selection: ResolvedBaselineSelectionKind::AutoSingle,
    })
}

fn build_catalog_snapshot(
    store_root: &Path,
    resource_key: &SafeResourceKey,
    options: BaselineResolutionOptions,
) -> Result<BaselineCatalogSnapshot> {
    record_catalog_enumeration_for_test();
    let Some(opened) =
        open_baseline_catalog_resource(store_root, resource_key).map_err(|source| {
            GkrmError::BaselineSecuredCatalogEnumerationFailed {
                source: Box::new(source),
            }
        })?
    else {
        return Ok(BaselineCatalogSnapshot {
            catalog: BaselineCatalog {
                resource_key: resource_key.clone(),
                entries: Vec::new(),
                issues: Vec::new(),
            },
            resource_key_identity: None,
            raw_entry_count: 0,
            candidate_identities: Vec::new(),
        });
    };

    let mut raw_entry_count = 0_usize;
    let mut candidates = Vec::<(BaselineId, StableFileIdentity)>::new();
    let mut issues = Vec::<BaselineCatalogIssue>::new();
    let entries = opened.key_dir.entries().map_err(|source| {
        GkrmError::BaselineSecuredCatalogEnumerationFailed {
            source: Box::new(GkrmError::BaselineStoreIo {
                component: "baseline-catalog".to_owned(),
                cause: source,
            }),
        }
    })?;

    for entry in entries {
        raw_entry_count =
            checked_increment_catalog_entries(raw_entry_count, options.max_catalog_entries)?;
        let entry = entry.map_err(
            |source| GkrmError::BaselineSecuredCatalogEnumerationFailed {
                source: Box::new(GkrmError::BaselineStoreIo {
                    component: "baseline-catalog-entry".to_owned(),
                    cause: source,
                }),
            },
        )?;
        match classify_catalog_child(&opened.key_dir, entry) {
            CatalogChild::Candidate {
                baseline_id,
                identity,
            } => candidates.push((baseline_id, identity)),
            CatalogChild::Issue(issue) => issues.push(issue),
        }
    }

    candidates.sort_by(|left, right| left.0.as_str().cmp(right.0.as_str()));

    let mut candidate_identities = Vec::with_capacity(candidates.len());
    let mut catalog_entries = Vec::new();
    for (baseline_id, identity) in candidates {
        record_catalog_candidate_validation_for_test();
        match load_baseline_bundle(
            store_root,
            resource_key,
            &baseline_id,
            options.baseline_store_limits,
        ) {
            Ok(stored) => {
                candidate_identities.push((baseline_id.clone(), identity));
                catalog_entries.push(BaselineCatalogEntry {
                    baseline_id: stored.baseline_id().clone(),
                    resource_name: stored.resource_name().to_owned(),
                    resource_version: stored.resource_version().map(ToOwned::to_owned),
                    source_package_fingerprint: stored.source_package_fingerprint().copied(),
                    counts: stored.counts().clone(),
                });
            }
            Err(error) => {
                issues.push(BaselineCatalogIssue::validation_failed(
                    baseline_id,
                    validation_category(&error),
                ));
            }
        }
    }

    catalog_entries
        .sort_by(|left, right| left.baseline_id.as_str().cmp(right.baseline_id.as_str()));
    issues.sort_by(BaselineCatalogIssue::stable_cmp);

    Ok(BaselineCatalogSnapshot {
        catalog: BaselineCatalog {
            resource_key: resource_key.clone(),
            entries: catalog_entries,
            issues,
        },
        resource_key_identity: Some(opened.key_identity),
        raw_entry_count,
        candidate_identities,
    })
}

enum CatalogChild {
    Candidate {
        baseline_id: BaselineId,
        identity: StableFileIdentity,
    },
    Issue(BaselineCatalogIssue),
}

fn classify_catalog_child(parent: &cap_std::fs::Dir, entry: cap_std::fs::DirEntry) -> CatalogChild {
    record_catalog_child_classification_for_test();
    let Ok(name) = entry.file_name().into_string() else {
        return CatalogChild::Issue(BaselineCatalogIssue::unsafe_candidate_entry());
    };
    if validate_single_component(&name).is_err() {
        return CatalogChild::Issue(BaselineCatalogIssue::unsafe_candidate_entry());
    }
    let Ok(metadata) = entry.full_metadata() else {
        return CatalogChild::Issue(BaselineCatalogIssue::unsafe_candidate_entry());
    };
    if reject_link_like_metadata(&metadata, "baseline-candidate").is_err() {
        return CatalogChild::Issue(BaselineCatalogIssue::unsafe_candidate_entry());
    }

    if metadata.file_type().is_file() {
        return CatalogChild::Issue(BaselineCatalogIssue::unexpected_entry_type());
    }
    if !metadata.file_type().is_dir() {
        return CatalogChild::Issue(BaselineCatalogIssue::unexpected_entry_type());
    }

    let Ok(candidate_dir) = open_child_dir(parent, &name) else {
        return CatalogChild::Issue(BaselineCatalogIssue::unsafe_candidate_entry());
    };
    let Ok(identity) = dir_identity(&candidate_dir, "baseline-candidate") else {
        return CatalogChild::Issue(BaselineCatalogIssue::unsafe_candidate_entry());
    };
    match BaselineId::parse(&name) {
        Ok(baseline_id) => CatalogChild::Candidate {
            baseline_id,
            identity,
        },
        Err(_) => CatalogChild::Issue(BaselineCatalogIssue::invalid_candidate_name()),
    }
}

fn checked_increment_catalog_entries(current: usize, limit: usize) -> Result<usize> {
    let actual = current
        .checked_add(1)
        .ok_or(GkrmError::BaselineCatalogEntryLimitExceeded {
            limit,
            actual: usize::MAX,
        })?;
    if actual > limit {
        return Err(GkrmError::BaselineCatalogEntryLimitExceeded { limit, actual });
    }
    Ok(actual)
}

fn catalog_snapshots_equivalent_for_auto_single(
    before: &BaselineCatalogSnapshot,
    after: &BaselineCatalogSnapshot,
    baseline_id: &BaselineId,
) -> bool {
    before.resource_key_identity == after.resource_key_identity
        && before.raw_entry_count == after.raw_entry_count
        && before.candidate_identities == after.candidate_identities
        && before.catalog.issues == after.catalog.issues
        && after.catalog.issues.is_empty()
        && after.catalog.entries.len() == 1
        && after.catalog.entries[0].baseline_id == *baseline_id
}

fn is_selected_baseline_not_found(
    error: &GkrmError,
    baseline_id: &BaselineId,
    resource_key: &SafeResourceKey,
) -> bool {
    match error {
        GkrmError::BaselineStoreMissing { component } => {
            component == "baselines"
                || component == resource_key.as_str()
                || component == baseline_id.as_str()
        }
        GkrmError::BaselineStoreIo {
            component,
            cause: source,
        } => component == "store-root" && source.kind() == std::io::ErrorKind::NotFound,
        _ => false,
    }
}

fn validation_category(error: &GkrmError) -> BaselineCatalogValidationCategory {
    match error {
        GkrmError::BaselineUnsupportedSchema { .. } => {
            BaselineCatalogValidationCategory::UnsupportedSchema
        }
        GkrmError::BaselineResourceKeyMismatch { .. } => {
            BaselineCatalogValidationCategory::ResourceKeyMismatch
        }
        GkrmError::BaselineRequestedIdMismatch { .. } => {
            BaselineCatalogValidationCategory::StoredRequestedIdMismatch
        }
        GkrmError::BaselineIdMismatch { .. } => {
            BaselineCatalogValidationCategory::CanonicalIdMismatch
        }
        GkrmError::BaselineDuplicateFilePath { .. } | GkrmError::BaselineInvalidOrdering { .. } => {
            BaselineCatalogValidationCategory::Ordering
        }
        GkrmError::BaselineCountMismatch { .. } => BaselineCatalogValidationCategory::Counts,
        GkrmError::BaselineMissingBlob { .. }
        | GkrmError::BaselineUnexpectedBlob { .. }
        | GkrmError::BaselineInvalidHash { .. } => BaselineCatalogValidationCategory::BlobReference,
        GkrmError::BaselineBlobSizeMismatch { .. } => BaselineCatalogValidationCategory::BlobSize,
        GkrmError::BaselineBlobDigestMismatch { .. } => {
            BaselineCatalogValidationCategory::BlobDigest
        }
        GkrmError::BaselineInconsistentEscrowBlob { .. } => {
            BaselineCatalogValidationCategory::EscrowBlobPolicy
        }
        GkrmError::BaselineStoreUnsafeComponent { .. }
        | GkrmError::BaselineStoreSymlink { .. }
        | GkrmError::BaselineStoreReparsePoint { .. }
        | GkrmError::BaselineStoreHardLink { .. } => {
            BaselineCatalogValidationCategory::UnsafeFilesystem
        }
        GkrmError::BaselineStoreUnexpectedType { .. }
        | GkrmError::BaselineStoreMissing { .. }
        | GkrmError::BaselineIncompleteBundle { .. } => {
            BaselineCatalogValidationCategory::UnexpectedBundleStructure
        }
        GkrmError::BaselineManifestLimitExceeded { .. }
        | GkrmError::BaselineFileCountLimitExceeded { .. }
        | GkrmError::BaselineBlobLimitExceeded { .. }
        | GkrmError::BaselineTotalBlobLimitExceeded { .. }
        | GkrmError::BaselineStoreZeroLimit { .. } => BaselineCatalogValidationCategory::Limits,
        GkrmError::BaselineUnsafeResourceKey { .. }
        | GkrmError::BaselineUnsafeRelativePath { .. } => {
            BaselineCatalogValidationCategory::UnexpectedBundleStructure
        }
        GkrmError::BaselineStoreIo { .. } => BaselineCatalogValidationCategory::Io,
        _ => BaselineCatalogValidationCategory::Io,
    }
}

fn run_after_auto_single_snapshot_a_hook() -> Result<()> {
    #[cfg(test)]
    {
        let hook = take_auto_single_hook_for_current_thread(&AFTER_AUTO_SINGLE_SNAPSHOT_A_HOOK);
        if let Some(hook) = hook {
            hook()?;
        }
    }
    Ok(())
}

fn run_after_auto_single_selected_load_hook() -> Result<()> {
    #[cfg(test)]
    {
        let hook = take_auto_single_hook_for_current_thread(&AFTER_AUTO_SINGLE_SELECTED_LOAD_HOOK);
        if let Some(hook) = hook {
            hook()?;
        }
    }
    Ok(())
}

#[cfg(test)]
fn record_catalog_enumeration_for_test() {
    if catalog_instrumentation_is_current_thread() {
        CATALOG_ENUMERATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(not(test))]
fn record_catalog_enumeration_for_test() {}

#[cfg(test)]
fn record_catalog_child_classification_for_test() {
    if catalog_instrumentation_is_current_thread() {
        CATALOG_CHILD_CLASSIFICATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(not(test))]
fn record_catalog_child_classification_for_test() {}

#[cfg(test)]
fn record_catalog_candidate_validation_for_test() {
    if catalog_instrumentation_is_current_thread() {
        CATALOG_CANDIDATE_VALIDATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(not(test))]
fn record_catalog_candidate_validation_for_test() {}

#[cfg(test)]
fn catalog_instrumentation_is_current_thread() -> bool {
    *CATALOG_INSTRUMENTATION_OWNER
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        == Some(std::thread::current().id())
}

#[cfg(test)]
fn take_auto_single_hook_for_current_thread(
    cell: &std::sync::OnceLock<std::sync::Mutex<Option<AutoSingleHookSlot>>>,
) -> Option<AutoSingleHook> {
    let mut slot = cell
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if slot
        .as_ref()
        .is_some_and(|hook| hook.owner == std::thread::current().id())
    {
        slot.take().map(|hook| hook.hook)
    } else {
        None
    }
}

#[cfg(test)]
fn clear_auto_single_hooks_for_test() {
    *AFTER_AUTO_SINGLE_SNAPSHOT_A_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    *AFTER_AUTO_SINGLE_SELECTED_LOAD_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

#[cfg(test)]
type AutoSingleHook = Box<dyn FnOnce() -> Result<()> + Send>;

#[cfg(test)]
struct AutoSingleHookSlot {
    owner: std::thread::ThreadId,
    hook: AutoSingleHook,
}

#[cfg(test)]
static BASELINE_CATALOG_TEST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
static CATALOG_INSTRUMENTATION_OWNER: std::sync::OnceLock<
    std::sync::Mutex<Option<std::thread::ThreadId>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static CATALOG_ENUMERATION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static CATALOG_CHILD_CLASSIFICATION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static CATALOG_CANDIDATE_VALIDATION_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static AFTER_AUTO_SINGLE_SNAPSHOT_A_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<AutoSingleHookSlot>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
static AFTER_AUTO_SINGLE_SELECTED_LOAD_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<AutoSingleHookSlot>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) mod test_hooks {
    use super::{
        clear_auto_single_hooks_for_test, AutoSingleHook, AutoSingleHookSlot,
        AFTER_AUTO_SINGLE_SELECTED_LOAD_HOOK, AFTER_AUTO_SINGLE_SNAPSHOT_A_HOOK,
        BASELINE_CATALOG_TEST_LOCK, CATALOG_CANDIDATE_VALIDATION_COUNT,
        CATALOG_CHILD_CLASSIFICATION_COUNT, CATALOG_ENUMERATION_COUNT,
        CATALOG_INSTRUMENTATION_OWNER,
    };
    use crate::Result;

    pub(crate) struct AutoSingleHookGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl AutoSingleHookGuard {
        fn acquire() -> Self {
            let lock = BASELINE_CATALOG_TEST_LOCK
                .get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            clear_auto_single_hooks_for_test();
            Self { _lock: lock }
        }
    }

    impl Drop for AutoSingleHookGuard {
        fn drop(&mut self) {
            clear_auto_single_hooks_for_test();
        }
    }

    pub(crate) fn with_auto_single_hooks_guard<T>(test: impl FnOnce() -> T) -> T {
        let _guard = AutoSingleHookGuard::acquire();
        test()
    }

    pub(crate) fn set_after_auto_single_snapshot_a_hook(
        hook: impl FnOnce() -> Result<()> + Send + 'static,
    ) {
        *AFTER_AUTO_SINGLE_SNAPSHOT_A_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(AutoSingleHookSlot {
            owner: std::thread::current().id(),
            hook: Box::new(hook) as AutoSingleHook,
        });
    }

    pub(crate) fn set_after_auto_single_selected_load_hook(
        hook: impl FnOnce() -> Result<()> + Send + 'static,
    ) {
        *AFTER_AUTO_SINGLE_SELECTED_LOAD_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(AutoSingleHookSlot {
            owner: std::thread::current().id(),
            hook: Box::new(hook) as AutoSingleHook,
        });
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct CatalogInstrumentationSnapshot {
        pub(crate) enumerations: usize,
        pub(crate) child_classifications: usize,
        pub(crate) candidate_validations: usize,
    }

    struct CatalogInstrumentationGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CatalogInstrumentationGuard {
        fn acquire() -> Self {
            let lock = BASELINE_CATALOG_TEST_LOCK
                .get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            clear_auto_single_hooks_for_test();
            CATALOG_ENUMERATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
            CATALOG_CHILD_CLASSIFICATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
            CATALOG_CANDIDATE_VALIDATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
            *CATALOG_INSTRUMENTATION_OWNER
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(std::thread::current().id());
            Self { _lock: lock }
        }

        fn snapshot(&self) -> CatalogInstrumentationSnapshot {
            CatalogInstrumentationSnapshot {
                enumerations: CATALOG_ENUMERATION_COUNT.load(std::sync::atomic::Ordering::SeqCst),
                child_classifications: CATALOG_CHILD_CLASSIFICATION_COUNT
                    .load(std::sync::atomic::Ordering::SeqCst),
                candidate_validations: CATALOG_CANDIDATE_VALIDATION_COUNT
                    .load(std::sync::atomic::Ordering::SeqCst),
            }
        }
    }

    impl Drop for CatalogInstrumentationGuard {
        fn drop(&mut self) {
            *CATALOG_INSTRUMENTATION_OWNER
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            CATALOG_ENUMERATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
            CATALOG_CHILD_CLASSIFICATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
            CATALOG_CANDIDATE_VALIDATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
            clear_auto_single_hooks_for_test();
        }
    }

    pub(crate) fn with_catalog_instrumentation_guard<T>(
        test: impl FnOnce() -> T,
    ) -> (T, CatalogInstrumentationSnapshot) {
        let guard = CatalogInstrumentationGuard::acquire();
        let output = test();
        let snapshot = guard.snapshot();
        (output, snapshot)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};

    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::test_hooks::{
        set_after_auto_single_selected_load_hook, set_after_auto_single_snapshot_a_hook,
        with_auto_single_hooks_guard, with_catalog_instrumentation_guard,
    };
    use super::*;
    use crate::baseline::blob_provider::InMemoryBlobProvider;
    use crate::baseline::model::{make_file_record, BaselineEscrowClass, ValidatedBaselineBundle};
    use crate::baseline::store::write_baseline_bundle;
    use crate::ResourceRelativePath;

    fn digest_of(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::new(Sha256::digest(bytes).into())
    }

    fn sample_bundle_and_provider(
        key: &str,
        resource_name: &str,
        version: Option<&str>,
        seed: &[u8],
    ) -> (ValidatedBaselineBundle, InMemoryBlobProvider) {
        let ignored_bytes = [b"cfg-", seed].concat();
        let protected_bytes = [b"main-", seed].concat();
        let ignored_digest = digest_of(&ignored_bytes);
        let protected_digest = digest_of(&protected_bytes);
        let mut blobs = BTreeMap::new();
        blobs.insert(ignored_digest, ignored_bytes.clone());
        let bundle = ValidatedBaselineBundle::try_from_parts_with_bytes(
            SafeResourceKey::parse(key).expect("key"),
            resource_name.to_owned(),
            version.map(ToOwned::to_owned),
            Some(digest_of(seed)),
            vec![
                make_file_record(
                    ResourceRelativePath::try_from_slash_str("config.lua").expect("path"),
                    ignored_bytes.len() as u64,
                    ignored_digest,
                    BaselineEscrowClass::Ignored,
                    Some(ignored_digest),
                ),
                make_file_record(
                    ResourceRelativePath::try_from_slash_str("client/main.lua").expect("path"),
                    protected_bytes.len() as u64,
                    protected_digest,
                    BaselineEscrowClass::Protected,
                    None,
                ),
            ],
            blobs.clone(),
            BaselineStoreLimits::default(),
        )
        .expect("bundle");
        (bundle, InMemoryBlobProvider::new(blobs))
    }

    fn publish_sample(
        store: &Path,
        key: &str,
        resource_name: &str,
        version: Option<&str>,
        seed: &[u8],
    ) -> BaselineId {
        let (bundle, provider) = sample_bundle_and_provider(key, resource_name, version, seed);
        let id = bundle.baseline_id().clone();
        write_baseline_bundle(store, &bundle, &provider, BaselineStoreLimits::default())
            .expect("publish");
        id
    }

    fn catalog_request<'a>(
        store: &'a Path,
        key: &'a SafeResourceKey,
    ) -> BaselineCatalogRequest<'a> {
        BaselineCatalogRequest::try_new(store, key, BaselineResolutionOptions::default())
            .expect("request")
    }

    fn resolution_request<'a>(
        store: &'a Path,
        key: &'a SafeResourceKey,
        selector: OfficialBaselineSelector,
    ) -> BaselineResolutionRequest<'a> {
        BaselineResolutionRequest::try_new(
            store,
            key,
            selector,
            BaselineResolutionOptions::default(),
        )
        .expect("request")
    }

    fn catalog_request_with_options<'a>(
        store: &'a Path,
        key: &'a SafeResourceKey,
        options: BaselineResolutionOptions,
    ) -> BaselineCatalogRequest<'a> {
        BaselineCatalogRequest::try_new(store, key, options).expect("request")
    }

    fn resolution_request_with_options<'a>(
        store: &'a Path,
        key: &'a SafeResourceKey,
        selector: OfficialBaselineSelector,
        options: BaselineResolutionOptions,
    ) -> BaselineResolutionRequest<'a> {
        BaselineResolutionRequest::try_new(store, key, selector, options).expect("request")
    }

    fn baseline_dir(store: &Path, key: &SafeResourceKey, id: &BaselineId) -> PathBuf {
        store.join("baselines").join(key.as_str()).join(id.as_str())
    }

    fn manifest_path(store: &Path, key: &SafeResourceKey, id: &BaselineId) -> PathBuf {
        baseline_dir(store, key, id).join("baseline.json")
    }

    fn blobs_dir(store: &Path, key: &SafeResourceKey, id: &BaselineId) -> PathBuf {
        baseline_dir(store, key, id).join("blobs")
    }

    fn read_manifest_json(
        store: &Path,
        key: &SafeResourceKey,
        id: &BaselineId,
    ) -> serde_json::Value {
        let bytes = fs::read(manifest_path(store, key, id)).expect("manifest");
        serde_json::from_slice(&bytes).expect("manifest json")
    }

    fn write_manifest_json(
        store: &Path,
        key: &SafeResourceKey,
        id: &BaselineId,
        value: &serde_json::Value,
    ) {
        let bytes = serde_json::to_vec(value).expect("encode json");
        fs::write(manifest_path(store, key, id), bytes).expect("write manifest");
    }

    fn first_blob_path(store: &Path, key: &SafeResourceKey, id: &BaselineId) -> PathBuf {
        fs::read_dir(blobs_dir(store, key, id))
            .expect("blobs")
            .next()
            .expect("blob")
            .expect("blob entry")
            .path()
    }

    fn write_extra_blob(store: &Path, key: &SafeResourceKey, id: &BaselineId, bytes: &[u8]) {
        let digest = digest_of(bytes);
        fs::write(blobs_dir(store, key, id).join(digest.to_string()), bytes).expect("extra blob");
    }

    fn copy_dir_recursive(source: &Path, dest: &Path) {
        fs::create_dir(dest).expect("create dest dir");
        for entry in fs::read_dir(source).expect("read source dir") {
            let entry = entry.expect("entry");
            let source_path = entry.path();
            let dest_path = dest.join(entry.file_name());
            if source_path.is_dir() {
                copy_dir_recursive(&source_path, &dest_path);
            } else {
                fs::copy(&source_path, &dest_path).expect("copy file");
            }
        }
    }

    fn replace_dir_with_copy(source: &Path, dest: &Path) {
        let backup = dest.with_extension("old");
        fs::rename(dest, &backup).expect("rename old");
        copy_dir_recursive(source, dest);
        fs::remove_dir_all(backup).expect("remove old");
    }

    fn store_tree_snapshot(root: &Path) -> Vec<String> {
        fn walk(root: &Path, current: &Path, out: &mut Vec<String>) {
            let mut entries = fs::read_dir(current)
                .expect("read tree")
                .map(|entry| entry.expect("entry"))
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let rel = path
                    .strip_prefix(root)
                    .expect("relative")
                    .to_string_lossy()
                    .replace('\\', "/");
                let meta = fs::symlink_metadata(&path).expect("metadata");
                out.push(format!("{rel}:{}:{}", meta.is_dir(), meta.len()));
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    walk(root, &path, out);
                }
            }
        }

        if !root.exists() {
            return Vec::new();
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out
    }

    fn assert_task13_display_redacted(error: &GkrmError, forbidden: &[String]) {
        let display = error.to_string();
        for value in forbidden {
            if !value.is_empty() {
                assert!(
                    !display.contains(value),
                    "public Display leaked {value:?}: {display}"
                );
            }
        }
        assert!(!display.contains("\\\\?\\"));
        assert!(!display.contains("FileIndex"));
    }

    fn assert_single_validation_issue(
        store: &Path,
        key: &SafeResourceKey,
        expected_id: &BaselineId,
        expected_category: BaselineCatalogValidationCategory,
        options: BaselineResolutionOptions,
    ) {
        let before = store_tree_snapshot(store);
        let catalog = catalog_official_baselines(catalog_request_with_options(store, key, options))
            .expect("catalog");
        assert_eq!(store_tree_snapshot(store), before);
        assert!(catalog.entries().is_empty());
        assert_eq!(catalog.issues().len(), 1);
        let issue = &catalog.issues()[0];
        assert_eq!(
            issue.kind(),
            BaselineCatalogIssueKind::BaselineValidationFailed
        );
        assert_eq!(issue.baseline_id(), Some(expected_id));
        assert_eq!(issue.validation_category(), Some(expected_category));

        let blocked = resolve_official_baseline(resolution_request_with_options(
            store,
            key,
            OfficialBaselineSelector::AutoSingle,
            options,
        ))
        .expect_err("blocked");
        assert!(matches!(
            blocked,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { issue_count: 1 }
        ));
        assert_task13_display_redacted(
            &blocked,
            &[
                store.to_string_lossy().to_string(),
                "unsafe-raw-name".to_owned(),
            ],
        );
    }

    fn run_catalog_validation_case(
        expected_category: BaselineCatalogValidationCategory,
        mutate: impl FnOnce(&Path, &SafeResourceKey, &BaselineId) -> BaselineId,
    ) {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"validation");
        let expected_id = mutate(&store, &key, &id);
        assert_single_validation_issue(
            &store,
            &key,
            &expected_id,
            expected_category,
            BaselineResolutionOptions::default(),
        );
    }

    fn run_catalog_validation_case_with_options(
        expected_category: BaselineCatalogValidationCategory,
        options: BaselineResolutionOptions,
        mutate: impl FnOnce(&Path, &SafeResourceKey, &BaselineId) -> BaselineId,
    ) {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"validation-limits");
        let expected_id = mutate(&store, &key, &id);
        assert_single_validation_issue(&store, &key, &expected_id, expected_category, options);
    }

    #[test]
    fn missing_store_returns_empty_catalog_without_creating_directories() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("missing");
        let key = SafeResourceKey::parse("gksphone").expect("key");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert!(catalog.entries().is_empty());
        assert!(catalog.issues().is_empty());
        assert!(!store.exists());
    }

    #[test]
    fn catalogs_one_valid_baseline_summary() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1.2.3"), b"one");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert!(catalog.issues().is_empty());
        assert_eq!(catalog.entries().len(), 1);
        let entry = &catalog.entries()[0];
        assert_eq!(entry.baseline_id(), &id);
        assert_eq!(entry.resource_name(), "GKSPHONE");
        assert_eq!(entry.resource_version(), Some("1.2.3"));
        assert!(entry.source_package_fingerprint().is_some());
        assert_eq!(entry.counts().files(), 2);
    }

    #[test]
    fn catalog_orders_multiple_valid_ids_deterministically() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let first = publish_sample(&store, key.as_str(), "GKSPHONE", Some("2"), b"b");
        let second = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"a");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");
        let ids = catalog
            .entries()
            .iter()
            .map(|entry| entry.baseline_id().as_str().to_owned())
            .collect::<Vec<_>>();
        let mut expected = vec![first.to_string(), second.to_string()];
        expected.sort();

        assert_eq!(ids, expected);
    }

    #[test]
    fn invalid_candidate_name_is_safe_issue_without_raw_name_leakage() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        fs::create_dir_all(
            store
                .join("baselines")
                .join(key.as_str())
                .join("not-a-baseline"),
        )
        .expect("invalid dir");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert!(catalog.entries().is_empty());
        assert_eq!(catalog.issues().len(), 1);
        assert_eq!(
            catalog.issues()[0].kind(),
            BaselineCatalogIssueKind::InvalidCandidateName
        );
        assert_eq!(catalog.issues()[0].baseline_id(), None);
        assert!(!format!("{:?}", catalog.issues()).contains("not-a-baseline"));
    }

    #[test]
    fn unexpected_regular_file_is_safe_issue() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let key_dir = store.join("baselines").join(key.as_str());
        fs::create_dir_all(&key_dir).expect("key dir");
        fs::write(key_dir.join("file.txt"), b"x").expect("file");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert_eq!(catalog.issues().len(), 1);
        assert_eq!(
            catalog.issues()[0].kind(),
            BaselineCatalogIssueKind::UnexpectedEntryType
        );
    }

    #[test]
    fn corrupted_baseline_becomes_validation_issue() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"bad-json");
        fs::write(
            store
                .join("baselines")
                .join(key.as_str())
                .join(id.as_str())
                .join("baseline.json"),
            b"not json\n",
        )
        .expect("corrupt");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert!(catalog.entries().is_empty());
        assert_eq!(catalog.issues().len(), 1);
        assert_eq!(
            catalog.issues()[0].kind(),
            BaselineCatalogIssueKind::BaselineValidationFailed
        );
        assert_eq!(catalog.issues()[0].baseline_id(), Some(&id));
    }

    #[test]
    fn catalog_validation_failures_are_safe_deterministic_categories() {
        run_catalog_validation_case(
            BaselineCatalogValidationCategory::UnsupportedSchema,
            |store, key, id| {
                let mut json = read_manifest_json(store, key, id);
                json["schema_version"] = serde_json::json!(2);
                write_manifest_json(store, key, id, &json);
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::CanonicalIdMismatch,
            |store, key, id| {
                let mut json = read_manifest_json(store, key, id);
                json["resource_name"] = serde_json::json!("ChangedName");
                write_manifest_json(store, key, id, &json);
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::Ordering,
            |store, key, id| {
                let mut json = read_manifest_json(store, key, id);
                json["files"].as_array_mut().expect("files").reverse();
                write_manifest_json(store, key, id, &json);
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::Counts,
            |store, key, id| {
                let mut json = read_manifest_json(store, key, id);
                json["counts"]["files"] = serde_json::json!(99);
                write_manifest_json(store, key, id, &json);
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::BlobReference,
            |store, key, id| {
                fs::remove_file(first_blob_path(store, key, id)).expect("remove blob");
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::BlobSize,
            |store, key, id| {
                let mut json = read_manifest_json(store, key, id);
                let ignored = json["files"]
                    .as_array_mut()
                    .expect("files")
                    .iter_mut()
                    .find(|file| !file["blob_sha256"].is_null())
                    .expect("ignored file");
                ignored["size"] = serde_json::json!(ignored["size"].as_u64().expect("size") + 1);
                write_manifest_json(store, key, id, &json);
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::BlobDigest,
            |store, key, id| {
                fs::write(first_blob_path(store, key, id), b"changed").expect("corrupt blob");
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::BlobReference,
            |store, key, id| {
                write_extra_blob(store, key, id, b"unreferenced");
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::EscrowBlobPolicy,
            |store, key, id| {
                let mut json = read_manifest_json(store, key, id);
                let protected = json["files"]
                    .as_array_mut()
                    .expect("files")
                    .iter_mut()
                    .find(|file| file["escrow_class"] == "protected")
                    .expect("protected file");
                let digest = protected["sha256"].as_str().expect("sha").to_owned();
                protected["blob_sha256"] = serde_json::json!(digest);
                fs::write(blobs_dir(store, key, id).join(&digest), b"main-validation")
                    .expect("protected blob");
                write_manifest_json(store, key, id, &json);
                id.clone()
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::StoredRequestedIdMismatch,
            |store, key, id| {
                let requested = BaselineId::parse(&"12".repeat(32)).expect("requested");
                fs::rename(
                    baseline_dir(store, key, id),
                    baseline_dir(store, key, &requested),
                )
                .expect("rename baseline");
                requested
            },
        );

        run_catalog_validation_case(
            BaselineCatalogValidationCategory::ResourceKeyMismatch,
            |store, key, id| {
                fs::remove_dir_all(baseline_dir(store, key, id)).expect("remove original");
                let foreign_key = SafeResourceKey::parse("gksphoneother").expect("foreign");
                let foreign_id =
                    publish_sample(store, foreign_key.as_str(), "GKSPHONE", None, b"foreign");
                let source = baseline_dir(store, &foreign_key, &foreign_id);
                let dest = baseline_dir(store, key, &foreign_id);
                fs::rename(source, dest).expect("move foreign");
                foreign_id
            },
        );

        let manifest_limits =
            BaselineStoreLimits::new(8, 20_000, 512 * 1024 * 1024, 2 * 1024 * 1024 * 1024)
                .expect("limits");
        let options =
            BaselineResolutionOptions::try_new(manifest_limits, DEFAULT_MAX_CATALOG_ENTRIES)
                .expect("options");
        run_catalog_validation_case_with_options(
            BaselineCatalogValidationCategory::Limits,
            options,
            |_store, _key, id| id.clone(),
        );

        let blob_limits =
            BaselineStoreLimits::new(1_048_576, 20_000, 1, 2 * 1024 * 1024 * 1024).expect("limits");
        let options = BaselineResolutionOptions::try_new(blob_limits, DEFAULT_MAX_CATALOG_ENTRIES)
            .expect("options");
        run_catalog_validation_case_with_options(
            BaselineCatalogValidationCategory::Limits,
            options,
            |_store, _key, id| id.clone(),
        );
    }

    #[cfg(unix)]
    #[test]
    fn catalog_candidate_with_unsafe_manifest_filesystem_is_validation_issue() {
        run_catalog_validation_case(
            BaselineCatalogValidationCategory::UnsafeFilesystem,
            |store, key, id| {
                let manifest = manifest_path(store, key, id);
                let target = manifest.with_extension("target");
                fs::rename(&manifest, &target).expect("rename manifest");
                std::os::unix::fs::symlink(&target, &manifest).expect("manifest symlink");
                id.clone()
            },
        );
    }

    #[test]
    fn catalog_entry_limit_is_enforced_during_enumeration() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let key_dir = store.join("baselines").join(key.as_str());
        fs::create_dir_all(&key_dir).expect("key dir");
        fs::create_dir(key_dir.join("a")).expect("a");
        fs::create_dir(key_dir.join("b")).expect("b");
        let options =
            BaselineResolutionOptions::try_new(BaselineStoreLimits::default(), 1).expect("options");
        let request = BaselineCatalogRequest::try_new(&store, &key, options).expect("request");

        let err = catalog_official_baselines(request).expect_err("limit");

        assert!(matches!(
            err,
            GkrmError::BaselineCatalogEntryLimitExceeded {
                limit: 1,
                actual: 2
            }
        ));
    }

    #[test]
    fn catalog_entry_limit_counts_raw_children_before_validation() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let valid = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"limit-valid");
        let key_dir = store.join("baselines").join(key.as_str());
        fs::create_dir(key_dir.join("invalid-raw-name")).expect("invalid");
        fs::write(key_dir.join("regular-file"), b"x").expect("file");
        fs::create_dir(key_dir.join("ab".repeat(32))).expect("incomplete candidate");
        #[cfg(unix)]
        {
            let target = temp.path().join("target");
            fs::create_dir(&target).expect("target");
            std::os::unix::fs::symlink(&target, key_dir.join("cd".repeat(32))).expect("symlink");
        }
        let expected_actual = if cfg!(unix) { 5 } else { 4 };
        let options =
            BaselineResolutionOptions::try_new(BaselineStoreLimits::default(), expected_actual - 1)
                .expect("options");
        let before = store_tree_snapshot(&store);

        let (err, counters) = with_catalog_instrumentation_guard(|| {
            catalog_official_baselines(catalog_request_with_options(&store, &key, options))
                .expect_err("limit")
        });

        assert!(matches!(
            err,
            GkrmError::BaselineCatalogEntryLimitExceeded { actual, .. } if actual == expected_actual
        ));
        assert_eq!(store_tree_snapshot(&store), before);
        assert_eq!(counters.enumerations, 1);
        assert_eq!(counters.candidate_validations, 0);
        assert!(baseline_dir(&store, &key, &valid).exists());
        assert_task13_display_redacted(
            &err,
            &[
                store.to_string_lossy().to_string(),
                "invalid-raw-name".to_owned(),
                "regular-file".to_owned(),
            ],
        );
    }

    #[test]
    fn exact_resolution_loads_valid_selected_baseline() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"exact");

        let resolved = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(id.clone()),
        ))
        .expect("resolve");

        assert_eq!(resolved.baseline_id(), &id);
        assert_eq!(resolved.selection(), ResolvedBaselineSelectionKind::Exact);
        assert_eq!(resolved.stored_baseline().baseline_id(), &id);
    }

    #[test]
    fn exact_missing_selection_is_not_found() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = BaselineId::parse(&"11".repeat(32)).expect("id");

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(id),
        ))
        .expect_err("missing");

        assert!(matches!(
            err,
            GkrmError::BaselineSelectedBaselineNotFound { .. }
        ));
    }

    #[test]
    fn task13_public_errors_do_not_leak_paths_or_raw_candidate_names() {
        let raw_name = "unsafe-raw-name".to_owned();

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        fs::create_dir(&store).expect("store");
        fs::write(store.join("baselines"), b"not a dir").expect("baselines file");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let enumeration =
            catalog_official_baselines(catalog_request(&store, &key)).expect_err("enumeration");
        assert!(matches!(
            enumeration,
            GkrmError::BaselineSecuredCatalogEnumerationFailed { .. }
        ));
        assert_task13_display_redacted(
            &enumeration,
            &[store.to_string_lossy().to_string(), raw_name.clone()],
        );

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let missing_id = BaselineId::parse(&"34".repeat(32)).expect("id");
        let not_found = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(missing_id),
        ))
        .expect_err("missing");
        assert_task13_display_redacted(
            &not_found,
            &[store.to_string_lossy().to_string(), raw_name.clone()],
        );

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let selected = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"selected-bad");
        fs::write(manifest_path(&store, &key, &selected), b"not json").expect("corrupt");
        let selected_failure = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(selected),
        ))
        .expect_err("selected validation");
        assert_task13_display_redacted(
            &selected_failure,
            &[
                store.to_string_lossy().to_string(),
                "baseline.json".to_owned(),
            ],
        );

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        fs::create_dir_all(store.join("baselines").join(key.as_str())).expect("key dir");
        fs::create_dir(store.join("baselines").join(key.as_str()).join(&raw_name)).expect("raw");
        fs::create_dir(store.join("baselines").join(key.as_str()).join("other")).expect("other");
        let options =
            BaselineResolutionOptions::try_new(BaselineStoreLimits::default(), 1).expect("limit");
        let limit = catalog_official_baselines(catalog_request_with_options(&store, &key, options))
            .expect_err("limit");
        assert_task13_display_redacted(
            &limit,
            &[store.to_string_lossy().to_string(), raw_name.clone()],
        );

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"one");
        publish_sample(&store, key.as_str(), "GKSPHONE", Some("2"), b"two");
        let multiple = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("multiple");
        assert_task13_display_redacted(
            &multiple,
            &[store.to_string_lossy().to_string(), raw_name.clone()],
        );

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        fs::create_dir_all(store.join("baselines").join(key.as_str()).join(&raw_name))
            .expect("issue");
        let blocked = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("blocked");
        assert_task13_display_redacted(
            &blocked,
            &[store.to_string_lossy().to_string(), raw_name.clone()],
        );

        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            publish_sample(&store, key.as_str(), "GKSPHONE", None, b"changed");
            let key_dir = store.join("baselines").join(key.as_str());
            set_after_auto_single_snapshot_a_hook(move || {
                fs::create_dir(key_dir.join("new-invalid")).expect("change");
                Ok(())
            });
            let changed = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert_task13_display_redacted(
                &changed,
                &[
                    store.to_string_lossy().to_string(),
                    "new-invalid".to_owned(),
                ],
            );
        });
    }

    #[test]
    fn exact_ignores_corrupt_sibling() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let good = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"good");
        let bad = publish_sample(&store, key.as_str(), "GKSPHONE", Some("2"), b"bad");
        fs::write(
            store
                .join("baselines")
                .join(key.as_str())
                .join(bad.as_str())
                .join("baseline.json"),
            b"not json\n",
        )
        .expect("corrupt");

        let resolved = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(good.clone()),
        ))
        .expect("resolve");

        assert_eq!(resolved.baseline_id(), &good);
    }

    #[test]
    fn exact_resolution_does_not_enumerate_or_inspect_siblings() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let selected = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"selected");

        let corrupt_json = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"bad-json");
        fs::write(manifest_path(&store, &key, &corrupt_json), b"not json").expect("corrupt json");

        let missing_blob = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"missing");
        fs::remove_file(first_blob_path(&store, &key, &missing_blob)).expect("remove blob");

        let corrupt_blob = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"corrupt");
        fs::write(first_blob_path(&store, &key, &corrupt_blob), b"corrupted").expect("blob");

        let unexpected_blob = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"extra");
        write_extra_blob(&store, &key, &unexpected_blob, b"unreferenced");

        let key_dir = store.join("baselines").join(key.as_str());
        fs::create_dir(key_dir.join("unsafe-raw-name")).expect("invalid sibling");
        fs::write(key_dir.join("regular-file"), b"x").expect("regular file");
        fs::create_dir(key_dir.join("ff".repeat(32))).expect("incomplete sibling");

        #[cfg(unix)]
        {
            let target = temp.path().join("link-target");
            fs::create_dir(&target).expect("link target");
            std::os::unix::fs::symlink(&target, key_dir.join("ee".repeat(32)))
                .expect("symlink sibling");
        }
        #[cfg(windows)]
        {
            let target = temp.path().join("link-target");
            fs::create_dir(&target).expect("link target");
            let _ = std::os::windows::fs::symlink_dir(&target, key_dir.join("ee".repeat(32)));
        }

        let (resolved, counters) = with_catalog_instrumentation_guard(|| {
            set_after_auto_single_snapshot_a_hook(|| panic!("exact must not run AutoSingle hook"));
            set_after_auto_single_selected_load_hook(|| {
                panic!("exact must not run AutoSingle hook")
            });
            resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::Exact(selected.clone()),
            ))
            .expect("exact")
        });

        assert_eq!(resolved.baseline_id(), &selected);
        assert_eq!(resolved.selection(), ResolvedBaselineSelectionKind::Exact);
        assert_eq!(counters.enumerations, 0);
        assert_eq!(counters.child_classifications, 0);
        assert_eq!(counters.candidate_validations, 0);
    }

    #[test]
    fn exact_incomplete_selected_bundle_is_validation_failure() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"incomplete");
        fs::remove_file(
            store
                .join("baselines")
                .join(key.as_str())
                .join(id.as_str())
                .join("baseline.json"),
        )
        .expect("remove manifest");

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(id),
        ))
        .expect_err("validation");

        assert!(matches!(
            err,
            GkrmError::BaselineSelectedBaselineValidationFailed { .. }
        ));
    }

    #[test]
    fn auto_single_succeeds_for_one_valid_and_zero_issues() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let id = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"auto");

        let resolved = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect("auto");

        assert_eq!(resolved.baseline_id(), &id);
        assert_eq!(
            resolved.selection(),
            ResolvedBaselineSelectionKind::AutoSingle
        );
    }

    #[test]
    fn auto_single_reports_issues_before_no_baselines() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        fs::create_dir_all(
            store
                .join("baselines")
                .join(key.as_str())
                .join("invalid-baseline"),
        )
        .expect("invalid");

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("blocked");

        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { issue_count: 1 }
        ));
    }

    #[test]
    fn auto_single_requires_exact_when_multiple_valid() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let first = publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"one");
        let second = publish_sample(&store, key.as_str(), "GKSPHONE", Some("2"), b"two");

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("multiple");

        let GkrmError::BaselineMultipleValidBaselinesRequireExactSelection { baseline_ids } = err
        else {
            panic!("unexpected error");
        };
        let ids = baseline_ids
            .iter()
            .map(BaselineId::as_str)
            .collect::<Vec<_>>();
        let mut expected = vec![first.as_str(), second.as_str()];
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn auto_single_condition_order_prefers_issues_over_zero_or_multiple_valid() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        fs::create_dir_all(
            store
                .join("baselines")
                .join(key.as_str())
                .join("only-corrupt"),
        )
        .expect("corrupt only");

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("issues");
        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { .. }
        ));

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let corrupt = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"corrupt-only");
        fs::write(manifest_path(&store, &key, &corrupt), b"not json").expect("corrupt");
        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("corrupt before zero");
        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { issue_count: 1 }
        ));

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        fs::create_dir_all(store.join("baselines").join(key.as_str())).expect("empty");
        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("none");
        assert!(matches!(err, GkrmError::BaselineNoStoredBaselines));

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"one");
        publish_sample(&store, key.as_str(), "GKSPHONE", Some("2"), b"two");
        fs::create_dir(store.join("baselines").join(key.as_str()).join("issue")).expect("issue");
        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("issues before multiple");
        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { .. }
        ));

        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        publish_sample(&store, key.as_str(), "GKSPHONE", Some("1"), b"one-valid");
        fs::create_dir(store.join("baselines").join(key.as_str()).join("issue")).expect("issue");
        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("issue before single");
        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { .. }
        ));
    }

    #[test]
    fn auto_single_detects_valid_sibling_added_between_snapshots() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            publish_sample(&store, key.as_str(), "GKSPHONE", None, b"stable");
            let hook_store = store.clone();
            set_after_auto_single_snapshot_a_hook(move || {
                publish_sample(&hook_store, "gksphone", "GKSPHONE", Some("2"), b"new-valid");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[test]
    fn auto_single_detects_corrupt_candidate_added_between_snapshots() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            publish_sample(&store, key.as_str(), "GKSPHONE", None, b"stable");
            let hook_store = store.clone();
            set_after_auto_single_snapshot_a_hook(move || {
                let corrupt = publish_sample(&hook_store, "gksphone", "GKSPHONE", None, b"bad");
                fs::write(
                    hook_store
                        .join("baselines")
                        .join("gksphone")
                        .join(corrupt.as_str())
                        .join("baseline.json"),
                    b"not json",
                )
                .expect("corrupt");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[test]
    fn auto_single_detects_selected_candidate_removed_or_replaced() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            let selected = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"remove");
            let selected_dir = baseline_dir(&store, &key, &selected);
            set_after_auto_single_snapshot_a_hook(move || {
                fs::remove_dir_all(&selected_dir).expect("remove selected");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });

        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            let selected = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"replace");
            let selected_dir = baseline_dir(&store, &key, &selected);
            let source = temp.path().join("source-copy");
            copy_dir_recursive(&selected_dir, &source);
            set_after_auto_single_snapshot_a_hook(move || {
                replace_dir_with_copy(&source, &selected_dir);
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[test]
    fn auto_single_detects_resource_key_directory_identity_change() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            let selected = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"key-dir");
            let key_dir = store.join("baselines").join(key.as_str());
            let replacement = temp.path().join("replacement-key-dir");
            copy_dir_recursive(&key_dir, &replacement);
            let moved = temp.path().join("old-key-dir");
            set_after_auto_single_selected_load_hook(move || {
                fs::rename(&key_dir, &moved).expect("move key dir");
                copy_dir_recursive(&replacement, &key_dir);
                assert!(key_dir.join(selected.as_str()).exists());
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[test]
    fn auto_single_selected_manifest_or_blob_corruption_fails_closed() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            let selected = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"manifest");
            let manifest = manifest_path(&store, &key, &selected);
            set_after_auto_single_snapshot_a_hook(move || {
                fs::write(&manifest, b"not json").expect("corrupt manifest");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("validation");
            assert!(matches!(
                err,
                GkrmError::BaselineSelectedBaselineValidationFailed { .. }
            ));
        });

        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            let selected = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"blob-before");
            let blob = first_blob_path(&store, &key, &selected);
            set_after_auto_single_snapshot_a_hook(move || {
                fs::write(&blob, b"changed").expect("corrupt blob");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("validation");
            assert!(matches!(
                err,
                GkrmError::BaselineSelectedBaselineValidationFailed { .. }
            ));
        });
    }

    #[test]
    fn auto_single_detects_new_invalid_entry_between_snapshots() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            publish_sample(&store, key.as_str(), "GKSPHONE", None, b"stable");
            let key_dir = store.join("baselines").join(key.as_str());
            set_after_auto_single_snapshot_a_hook(move || {
                fs::create_dir(key_dir.join("new-invalid")).expect("new invalid");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");

            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[test]
    fn auto_single_detects_blob_change_after_selected_load() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            let id = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"blob-change");
            let blobs_dir = store
                .join("baselines")
                .join(key.as_str())
                .join(id.as_str())
                .join("blobs");
            set_after_auto_single_selected_load_hook(move || {
                let blob = fs::read_dir(&blobs_dir)
                    .expect("read blobs")
                    .next()
                    .expect("blob")
                    .expect("entry")
                    .path();
                fs::write(blob, b"changed").expect("change blob");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");

            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[cfg(unix)]
    #[test]
    fn symlink_candidate_is_unsafe_issue() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let valid = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"valid-link");
        let key_dir = store.join("baselines").join(key.as_str());
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("target");
        std::os::unix::fs::symlink(&target, key_dir.join("aa".repeat(32))).expect("symlink");

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(catalog.issues().len(), 1);
        assert_eq!(
            catalog.issues()[0].kind(),
            BaselineCatalogIssueKind::UnsafeCandidateEntry
        );
        assert_eq!(catalog.issues()[0].baseline_id(), None);
        assert!(!format!("{:?}", catalog.issues()).contains(&"aa".repeat(32)));

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("blocked");
        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { issue_count: 1 }
        ));

        let resolved = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(valid.clone()),
        ))
        .expect("exact");
        assert_eq!(resolved.baseline_id(), &valid);
    }

    #[cfg(unix)]
    #[test]
    fn auto_single_detects_unsafe_link_added_between_snapshots() {
        with_auto_single_hooks_guard(|| {
            let temp = tempdir().expect("temp");
            let store = temp.path().join("store");
            let key = SafeResourceKey::parse("gksphone").expect("key");
            publish_sample(&store, key.as_str(), "GKSPHONE", None, b"stable-link");
            let key_dir = store.join("baselines").join(key.as_str());
            let target = temp.path().join("target");
            fs::create_dir(&target).expect("target");
            set_after_auto_single_snapshot_a_hook(move || {
                std::os::unix::fs::symlink(&target, key_dir.join("ab".repeat(32)))
                    .expect("symlink");
                Ok(())
            });

            let err = resolve_official_baseline(resolution_request(
                &store,
                &key,
                OfficialBaselineSelector::AutoSingle,
            ))
            .expect_err("changed");
            assert!(matches!(
                err,
                GkrmError::BaselineCatalogChangedDuringResolution
            ));
        });
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_candidate_is_unsafe_issue() {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let key = SafeResourceKey::parse("gksphone").expect("key");
        let valid = publish_sample(&store, key.as_str(), "GKSPHONE", None, b"valid-reparse");
        let key_dir = store.join("baselines").join(key.as_str());
        let target = temp.path().join("target");
        fs::create_dir(&target).expect("target");
        let link = key_dir.join("aa".repeat(32));
        let junction = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .status()
            .ok()
            .is_some_and(|status| status.success());
        if !junction {
            std::os::windows::fs::symlink_dir(&target, &link)
                .expect("create Windows reparse candidate");
        }

        let catalog = catalog_official_baselines(catalog_request(&store, &key)).expect("catalog");

        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(catalog.issues().len(), 1);
        assert_eq!(
            catalog.issues()[0].kind(),
            BaselineCatalogIssueKind::UnsafeCandidateEntry
        );
        assert_eq!(catalog.issues()[0].baseline_id(), None);
        assert!(!format!("{:?}", catalog.issues()).contains(&"aa".repeat(32)));

        let err = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::AutoSingle,
        ))
        .expect_err("blocked");
        assert!(matches!(
            err,
            GkrmError::BaselineAutoSingleBlockedByCatalogIssues { issue_count: 1 }
        ));

        let resolved = resolve_official_baseline(resolution_request(
            &store,
            &key,
            OfficialBaselineSelector::Exact(valid.clone()),
        ))
        .expect("exact");
        assert_eq!(resolved.baseline_id(), &valid);
    }
}
