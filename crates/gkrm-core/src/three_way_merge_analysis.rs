use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};
use std::path::Path;
use std::sync::Arc;

use cap_std::fs::Dir as CapDir;
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::baseline::fs_security::{
    capture_file_identity, dir_identity, open_child_dir, open_existing_directory,
    open_file_nofollow,
};
use crate::baseline::store::stream_verified_blob_for_path;
use crate::baseline::BaselineStoreLimits;
use crate::file_identity::StableFileIdentity;
use crate::manifest::parse_zip_resource_manifests_from_snapshot;
use crate::merge_content::{
    StreamingByteBudget, VerifiedMergeText, VerifiedMergeTextBuilder, STREAM_BUFFER_SIZE,
};
use crate::package_source::PackageSnapshot;
use crate::three_way_fingerprint::{
    self, CanonicalFingerprintEncoder, IncomingFingerprintFile, InstalledFingerprintFile,
};
use crate::zip_package::inspect_zip_snapshot;
use crate::{
    classify_zip_resource_escrow, discover_zip_resources, BaselineEscrowClass, BaselineId,
    EscrowFileClassification, EscrowPolicyTransition, GkrmError, InstalledResourceRoot,
    InstalledScanLimits, PackageLimits, ResolvedOfficialBaseline, ResourceRelativePath, Result,
    SafeResourceKey, Sha256Digest, ThreeWayFileState, ThreeWayMergeAnalysisDisposition::*,
    ThreeWayPlanDisposition, ThreeWayPlanId, ThreeWayPlanReview, ThreeWayPlanReviewId,
    ThreeWayReviewedAction, ThreeWayUpdatePlan, ZipEntryInfo, ZipEntryKind, ZipRelativePath,
    ZipResourceDiscovery, ZipResourceName, ZipResourceRoot,
};

#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
#[cfg(test)]
use std::thread::ThreadId;

const DEFAULT_MAX_CANDIDATES: usize = 1_000;
const DEFAULT_MAX_BUFFERED_FILE_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_HASHED_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_MAX_TEXT_LINES: usize = 200_000;
const DEFAULT_MAX_LINE_BYTES: usize = 1024 * 1024;

#[cfg(test)]
type PathHook = Box<dyn FnOnce(&ResourceRelativePath) + Send>;
#[cfg(test)]
type ReadHook = Box<dyn FnMut(&ResourceRelativePath, u64) + Send>;
#[cfg(test)]
type VoidHook = Box<dyn FnOnce() + Send>;

#[cfg(test)]
struct ThreeWayMergeAnalysisTestHooks {
    owner: ThreadId,
    after_installed_scan_a: Option<VoidHook>,
    before_candidate_open: Option<PathHook>,
    during_candidate_read: Option<ReadHook>,
    after_candidate_reads: Option<VoidHook>,
    before_installed_scan_b: Option<VoidHook>,
}

#[cfg(test)]
impl ThreeWayMergeAnalysisTestHooks {
    fn new() -> Self {
        Self {
            owner: std::thread::current().id(),
            after_installed_scan_a: None,
            before_candidate_open: None,
            during_candidate_read: None,
            after_candidate_reads: None,
            before_installed_scan_b: None,
        }
    }
}

#[cfg(test)]
static THREE_WAY_MERGE_ANALYSIS_HOOK_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static THREE_WAY_MERGE_ANALYSIS_HOOKS: Mutex<Option<ThreeWayMergeAnalysisTestHooks>> =
    Mutex::new(None);

#[cfg(test)]
fn lock_hook_state() -> MutexGuard<'static, Option<ThreeWayMergeAnalysisTestHooks>> {
    THREE_WAY_MERGE_ANALYSIS_HOOKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
struct ThreeWayMergeAnalysisHookGuard {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for ThreeWayMergeAnalysisHookGuard {
    fn drop(&mut self) {
        clear_three_way_merge_analysis_hooks();
    }
}

#[cfg(test)]
fn lock_three_way_merge_analysis_hooks() -> ThreeWayMergeAnalysisHookGuard {
    let guard = THREE_WAY_MERGE_ANALYSIS_HOOK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    clear_three_way_merge_analysis_hooks();
    *lock_hook_state() = Some(ThreeWayMergeAnalysisTestHooks::new());
    ThreeWayMergeAnalysisHookGuard { _guard: guard }
}

#[cfg(test)]
fn clear_three_way_merge_analysis_hooks() {
    *lock_hook_state() = None;
}

#[cfg(test)]
fn with_hooks_mut(update: impl FnOnce(&mut ThreeWayMergeAnalysisTestHooks)) {
    let mut hooks = lock_hook_state();
    let Some(hooks) = hooks.as_mut() else {
        return;
    };
    if hooks.owner == std::thread::current().id() {
        update(hooks);
    }
}

#[cfg(test)]
fn set_after_installed_scan_a_hook(hook: impl FnOnce() + Send + 'static) {
    with_hooks_mut(|hooks| hooks.after_installed_scan_a = Some(Box::new(hook)));
}

#[cfg(test)]
fn set_before_candidate_open_hook(hook: impl FnOnce(&ResourceRelativePath) + Send + 'static) {
    with_hooks_mut(|hooks| hooks.before_candidate_open = Some(Box::new(hook)));
}

#[cfg(test)]
fn set_during_candidate_read_hook(hook: impl FnMut(&ResourceRelativePath, u64) + Send + 'static) {
    with_hooks_mut(|hooks| hooks.during_candidate_read = Some(Box::new(hook)));
}

#[cfg(test)]
fn set_after_candidate_reads_hook(hook: impl FnOnce() + Send + 'static) {
    with_hooks_mut(|hooks| hooks.after_candidate_reads = Some(Box::new(hook)));
}

#[cfg(test)]
fn set_before_installed_scan_b_hook(hook: impl FnOnce() + Send + 'static) {
    with_hooks_mut(|hooks| hooks.before_installed_scan_b = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_after_installed_scan_a_hook() {
    let hook = lock_hook_state()
        .as_mut()
        .filter(|hooks| hooks.owner == std::thread::current().id())
        .and_then(|hooks| hooks.after_installed_scan_a.take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_after_installed_scan_a_hook() {}

#[cfg(test)]
fn run_before_candidate_open_hook(path: &ResourceRelativePath) {
    let hook = lock_hook_state()
        .as_mut()
        .filter(|hooks| hooks.owner == std::thread::current().id())
        .and_then(|hooks| hooks.before_candidate_open.take());
    if let Some(hook) = hook {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_before_candidate_open_hook(_path: &ResourceRelativePath) {}

#[cfg(test)]
fn run_during_candidate_read_hook(path: &ResourceRelativePath, bytes_read: u64) {
    let mut hooks = lock_hook_state();
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.during_candidate_read.as_mut() {
                hook(path, bytes_read);
            }
        }
    }
}

#[cfg(not(test))]
fn run_during_candidate_read_hook(_path: &ResourceRelativePath, _bytes_read: u64) {}

#[cfg(test)]
fn run_after_candidate_reads_hook() {
    let hook = lock_hook_state()
        .as_mut()
        .filter(|hooks| hooks.owner == std::thread::current().id())
        .and_then(|hooks| hooks.after_candidate_reads.take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_after_candidate_reads_hook() {}

#[cfg(test)]
fn run_before_installed_scan_b_hook() {
    let hook = lock_hook_state()
        .as_mut()
        .filter(|hooks| hooks.owner == std::thread::current().id())
        .and_then(|hooks| hooks.before_installed_scan_b.take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
fn run_before_installed_scan_b_hook() {}

#[derive(Debug)]
pub struct ThreeWayMergeAnalysisRequest<'a> {
    plan: &'a ThreeWayUpdatePlan,
    review: &'a ThreeWayPlanReview,
    baseline: &'a ResolvedOfficialBaseline,
    installed_source: &'a InstalledMergeContentSource,
    incoming_source: &'a IncomingMergeContentSource,
    options: ThreeWayMergeAnalysisOptions,
}

impl<'a> ThreeWayMergeAnalysisRequest<'a> {
    pub fn try_new(
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledMergeContentSource,
        incoming_source: &'a IncomingMergeContentSource,
        options: ThreeWayMergeAnalysisOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            plan,
            review,
            baseline,
            installed_source,
            incoming_source,
            options,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreeWayMergeAnalysisOptions {
    max_candidates: usize,
    max_buffered_file_bytes: u64,
    max_total_hashed_bytes: u64,
    max_text_lines: usize,
    max_line_bytes: usize,
    baseline_store_limits: BaselineStoreLimits,
}

impl Default for ThreeWayMergeAnalysisOptions {
    fn default() -> Self {
        Self {
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_buffered_file_bytes: DEFAULT_MAX_BUFFERED_FILE_BYTES,
            max_total_hashed_bytes: DEFAULT_MAX_TOTAL_HASHED_BYTES,
            max_text_lines: DEFAULT_MAX_TEXT_LINES,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl ThreeWayMergeAnalysisOptions {
    pub fn try_new(
        max_candidates: usize,
        max_buffered_file_bytes: u64,
        max_total_hashed_bytes: u64,
        max_text_lines: usize,
        max_line_bytes: usize,
        baseline_store_limits: BaselineStoreLimits,
    ) -> Result<Self> {
        let options = Self {
            max_candidates,
            max_buffered_file_bytes,
            max_total_hashed_bytes,
            max_text_lines,
            max_line_bytes,
            baseline_store_limits,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn max_candidates(&self) -> usize {
        self.max_candidates
    }

    pub fn max_buffered_file_bytes(&self) -> u64 {
        self.max_buffered_file_bytes
    }

    pub fn max_total_hashed_bytes(&self) -> u64 {
        self.max_total_hashed_bytes
    }

    pub fn max_text_lines(&self) -> usize {
        self.max_text_lines
    }

    pub fn max_line_bytes(&self) -> usize {
        self.max_line_bytes
    }

    pub fn baseline_store_limits(&self) -> &BaselineStoreLimits {
        &self.baseline_store_limits
    }

    fn validate(self) -> Result<()> {
        if self.max_candidates == 0 {
            return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
                limit: "max_candidates",
            });
        }
        if self.max_buffered_file_bytes == 0 {
            return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
                limit: "max_buffered_file_bytes",
            });
        }
        if self.max_total_hashed_bytes == 0 {
            return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
                limit: "max_total_hashed_bytes",
            });
        }
        if self.max_text_lines == 0 {
            return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
                limit: "max_text_lines",
            });
        }
        if self.max_line_bytes == 0 {
            return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
                limit: "max_line_bytes",
            });
        }
        self.baseline_store_limits.validate()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct InstalledMergeContentSource {
    installed_root_dir: CapDir,
    selected_resource_dir: CapDir,
    selected_resource_root: InstalledResourceRoot,
    resource_name: String,
    limits: InstalledScanLimits,
    installed_root_identity: StableFileIdentity,
    selected_resource_identity: StableFileIdentity,
}

impl InstalledMergeContentSource {
    pub fn try_new(
        installed_root: &Path,
        selected_resource_root: InstalledResourceRoot,
        limits: InstalledScanLimits,
    ) -> Result<Self> {
        validate_installed_limits(limits)?;
        let root = open_existing_directory(installed_root, "installed-root")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let installed_root_identity = dir_identity(&root.dir, "installed-root")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let selected_resource_dir = open_selected_resource_dir(&root.dir, &selected_resource_root)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let selected_resource_identity = dir_identity(&selected_resource_dir, "installed-resource")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let resource_name = installed_resource_name(installed_root, &selected_resource_root)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        Ok(Self {
            installed_root_dir: root.dir,
            selected_resource_dir,
            selected_resource_root,
            resource_name,
            limits,
            installed_root_identity,
            selected_resource_identity,
        })
    }
}

fn validate_installed_limits(limits: InstalledScanLimits) -> Result<()> {
    if limits.max_resources == 0
        || limits.max_files_per_resource == 0
        || limits.max_total_files == 0
        || limits.max_total_entries == 0
        || limits.max_directories == 0
        || limits.max_file_size == 0
        || limits.max_total_size == 0
        || limits.max_directory_depth == 0
    {
        return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
            limit: "installed_scan_limits",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncomingMergeContentSourceLimits {
    pub max_archive_size: u64,
    pub package_limits: PackageLimits,
    pub manifest_limits: crate::ManifestLimits,
}

impl Default for IncomingMergeContentSourceLimits {
    fn default() -> Self {
        Self {
            max_archive_size: 2 * 1024 * 1024 * 1024,
            package_limits: PackageLimits::default(),
            manifest_limits: crate::ManifestLimits::default(),
        }
    }
}

#[derive(Debug)]
pub struct IncomingMergeContentSource {
    snapshot: Arc<PackageSnapshot>,
    selected_resource_root: ZipResourceRoot,
    resource_key: SafeResourceKey,
    resource_fingerprint: Sha256Digest,
    inventory: BTreeMap<ResourceRelativePath, IncomingSourceFile>,
}

#[derive(Debug, Clone)]
struct IncomingSourceFile {
    entry: ZipEntryInfo,
    sha256: Sha256Digest,
    escrow_class: BaselineEscrowClass,
}

impl IncomingMergeContentSource {
    pub fn try_new(
        package_path: &Path,
        selected_resource_root: ZipResourceRoot,
        limits: IncomingMergeContentSourceLimits,
    ) -> Result<Self> {
        validate_incoming_source_limits(limits)?;
        let snapshot = Arc::new(
            PackageSnapshot::create(package_path, limits.max_archive_size)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?,
        );
        Self::from_package_snapshot(snapshot, selected_resource_root, limits)
    }

    pub(crate) fn from_package_snapshot(
        snapshot: Arc<PackageSnapshot>,
        selected_resource_root: ZipResourceRoot,
        limits: IncomingMergeContentSourceLimits,
    ) -> Result<Self> {
        validate_incoming_source_limits(limits)?;
        if limits.max_archive_size == 0
            || limits.package_limits.max_entries == 0
            || limits.package_limits.max_entry_uncompressed_size == 0
            || limits.package_limits.max_total_uncompressed_size == 0
            || limits.package_limits.max_compression_ratio == 0
            || limits.manifest_limits.max_manifest_size == 0
            || limits.manifest_limits.max_tokens == 0
        {
            return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
                limit: "incoming_source_limits",
            });
        }
        if matches!(selected_resource_root, ZipResourceRoot::Root) {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch);
        }
        let inspection = inspect_zip_snapshot(&snapshot, limits.package_limits)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let discovery = discover_zip_resources(&inspection)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let manifests = parse_zip_resource_manifests_from_snapshot(
            &snapshot,
            &inspection,
            &discovery,
            limits.manifest_limits,
        )
        .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let escrow = classify_zip_resource_escrow(&inspection, &discovery, &manifests)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let resource = exactly_one_zip_resource(&discovery, &selected_resource_root)?;
        let resource_key = trusted_zip_resource_key(resource)?;
        let escrow_resource = escrow
            .resources
            .iter()
            .find(|classified| classified.resource_root == selected_resource_root)
            .ok_or(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;

        let class_by_path = escrow_resource
            .files
            .iter()
            .map(|file| {
                let path = ResourceRelativePath::try_from_slash_str(&file.resource_relative_path)?;
                Ok((path, escrow_class_to_baseline(&file.classification)))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut inventory = BTreeMap::new();
        let mut archive = snapshot
            .open_zip_archive()
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let mut buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        for entry in &resource.entries {
            if entry.kind != ZipEntryKind::File {
                continue;
            }
            let path = zip_resource_relative_path(&selected_resource_root, &entry.path)?;
            let escrow_class = *class_by_path
                .get(&path)
                .ok_or(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
            let sha256 = hash_zip_entry_streaming(&mut archive, entry, &mut buffer, |_| Ok(()))?;
            if inventory
                .insert(
                    path,
                    IncomingSourceFile {
                        entry: entry.clone(),
                        sha256,
                        escrow_class,
                    },
                )
                .is_some()
            {
                return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
            }
        }
        let fingerprint = incoming_fingerprint_from_inventory(
            snapshot.fingerprint(),
            &resource_key,
            &selected_resource_root,
            &inventory,
        )?;
        Ok(Self {
            snapshot,
            selected_resource_root,
            resource_key,
            resource_fingerprint: fingerprint,
            inventory,
        })
    }
}

fn validate_incoming_source_limits(limits: IncomingMergeContentSourceLimits) -> Result<()> {
    if limits.max_archive_size == 0
        || limits.package_limits.max_entries == 0
        || limits.package_limits.max_entry_uncompressed_size == 0
        || limits.package_limits.max_total_uncompressed_size == 0
        || limits.package_limits.max_compression_ratio == 0
        || limits.manifest_limits.max_manifest_size == 0
        || limits.manifest_limits.max_tokens == 0
    {
        return Err(GkrmError::ThreeWayMergeAnalysisOptionsInvalid {
            limit: "incoming_source_limits",
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeNewlineStyle {
    None,
    Lf,
    CrLf,
    Cr,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeContentKind {
    Text,
    Binary,
    UnsupportedEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeContentEncoding {
    Utf8,
    Utf8WithBom,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayMergeAlgorithm {
    Utf8LineThreeWayV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeContentAnalysis {
    sha256: Sha256Digest,
    byte_length: u64,
    content_kind: MergeContentKind,
    encoding: MergeContentEncoding,
    newline_style: MergeNewlineStyle,
    line_count: Option<usize>,
    max_line_bytes: Option<usize>,
    is_empty: bool,
}

impl MergeContentAnalysis {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        sha256: Sha256Digest,
        byte_length: u64,
        content_kind: MergeContentKind,
        encoding: MergeContentEncoding,
        newline_style: MergeNewlineStyle,
        line_count: Option<usize>,
        max_line_bytes: Option<usize>,
        is_empty: bool,
    ) -> Self {
        Self {
            sha256,
            byte_length,
            content_kind,
            encoding,
            newline_style,
            line_count,
            max_line_bytes,
            is_empty,
        }
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
    pub fn content_kind(&self) -> MergeContentKind {
        self.content_kind
    }
    pub fn encoding(&self) -> MergeContentEncoding {
        self.encoding
    }
    pub fn newline_style(&self) -> MergeNewlineStyle {
        self.newline_style
    }
    pub fn line_count(&self) -> Option<usize> {
        self.line_count
    }
    pub fn max_line_bytes(&self) -> Option<usize> {
        self.max_line_bytes
    }
    pub fn is_empty(&self) -> bool {
        self.is_empty
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayMergeAnalysisDisposition {
    ReadyForUtf8LineMergePlanning,
    ManualReviewBinary,
    ManualReviewUnsupportedEncoding,
    ManualReviewFileTooLarge,
    ManualReviewTooManyLines,
    ManualReviewLineTooLong,
    ManualReviewUnsupportedNewlines,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayMergeAnalysisEntry {
    path: ResourceRelativePath,
    baseline: MergeContentAnalysis,
    installed: MergeContentAnalysis,
    incoming: MergeContentAnalysis,
    algorithm: Option<ThreeWayMergeAlgorithm>,
    disposition: ThreeWayMergeAnalysisDisposition,
}

impl ThreeWayMergeAnalysisEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }
    pub fn baseline(&self) -> &MergeContentAnalysis {
        &self.baseline
    }
    pub fn installed(&self) -> &MergeContentAnalysis {
        &self.installed
    }
    pub fn incoming(&self) -> &MergeContentAnalysis {
        &self.incoming
    }
    pub fn algorithm(&self) -> Option<ThreeWayMergeAlgorithm> {
        self.algorithm
    }
    pub fn disposition(&self) -> ThreeWayMergeAnalysisDisposition {
        self.disposition
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayMergeAnalysisSummary {
    total_candidates: usize,
    ready_for_text_merge_planning: usize,
    manual_binary: usize,
    manual_unsupported_encoding: usize,
    manual_too_large: usize,
    manual_too_many_lines: usize,
    manual_line_too_long: usize,
    manual_unsupported_newlines: usize,
}

impl ThreeWayMergeAnalysisSummary {
    pub fn total_candidates(&self) -> usize {
        self.total_candidates
    }
    pub fn ready_for_text_merge_planning(&self) -> usize {
        self.ready_for_text_merge_planning
    }
    pub fn manual_binary(&self) -> usize {
        self.manual_binary
    }
    pub fn manual_unsupported_encoding(&self) -> usize {
        self.manual_unsupported_encoding
    }
    pub fn manual_too_large(&self) -> usize {
        self.manual_too_large
    }
    pub fn manual_too_many_lines(&self) -> usize {
        self.manual_too_many_lines
    }
    pub fn manual_line_too_long(&self) -> usize {
        self.manual_line_too_long
    }
    pub fn manual_unsupported_newlines(&self) -> usize {
        self.manual_unsupported_newlines
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayMergeAnalysisStatus {
    ReadyForFurtherPlanning,
    HasManualReviewEntries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayMergeAnalysisId(Sha256Digest);

impl ThreeWayMergeAnalysisId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayMergeAnalysisPlan {
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
    plan_id: ThreeWayPlanId,
    review_id: ThreeWayPlanReviewId,
    installed_snapshot_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<ThreeWayMergeAnalysisEntry>,
    summary: ThreeWayMergeAnalysisSummary,
    status: ThreeWayMergeAnalysisStatus,
    analysis_id: ThreeWayMergeAnalysisId,
}

impl ThreeWayMergeAnalysisPlan {
    pub fn resource_key(&self) -> &SafeResourceKey {
        &self.resource_key
    }
    pub fn baseline_id(&self) -> &BaselineId {
        &self.baseline_id
    }
    pub fn plan_id(&self) -> &ThreeWayPlanId {
        &self.plan_id
    }
    pub fn review_id(&self) -> &ThreeWayPlanReviewId {
        &self.review_id
    }
    pub fn installed_snapshot_fingerprint(&self) -> &Sha256Digest {
        &self.installed_snapshot_fingerprint
    }
    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }
    pub fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_resource_fingerprint
    }
    pub fn entries(&self) -> &[ThreeWayMergeAnalysisEntry] {
        &self.entries
    }
    pub fn summary(&self) -> &ThreeWayMergeAnalysisSummary {
        &self.summary
    }
    pub fn status(&self) -> ThreeWayMergeAnalysisStatus {
        self.status
    }
    pub fn analysis_id(&self) -> &ThreeWayMergeAnalysisId {
        &self.analysis_id
    }
}

struct QueuedCandidate<'a> {
    path: &'a ResourceRelativePath,
    baseline_sha256: Sha256Digest,
    installed_sha256: Sha256Digest,
    incoming_sha256: Sha256Digest,
}

pub fn analyze_queued_three_way_merges(
    request: ThreeWayMergeAnalysisRequest<'_>,
) -> Result<ThreeWayMergeAnalysisPlan> {
    request.options.validate()?;
    verify_plan_review_binding(request.plan, request.review)?;
    verify_review_structure(request.plan, request.review)?;
    if request.baseline.baseline_id() != request.plan.baseline_id()
        || request.baseline.resource_key() != request.plan.resource_key()
    {
        return Err(GkrmError::ThreeWayMergeAnalysisBaselineMismatch);
    }

    let candidates = collect_queued_candidates(request.plan, request.review)?;
    if candidates.is_empty() {
        return Err(GkrmError::ThreeWayMergeAnalysisNoQueuedCandidates);
    }
    if candidates.len() > request.options.max_candidates {
        return Err(GkrmError::ThreeWayMergeAnalysisCandidateLimitExceeded {
            limit: request.options.max_candidates,
            actual: candidates.len(),
        });
    }
    for candidate in &candidates {
        verify_candidate_invariants(request.plan, candidate)?;
    }

    let installed_before = request
        .installed_source
        .scan_and_fingerprint(request.plan.resource_key())
        .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch)?;
    if &installed_before.fingerprint != request.plan.installed_snapshot_fingerprint() {
        return Err(GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch);
    }
    run_after_installed_scan_a_hook();
    request
        .incoming_source
        .validate_against_plan(request.plan)
        .map_err(|error| match error {
            GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch
            | GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch
            | GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch => error,
            _ => GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid,
        })?;
    validate_baseline_records(request.baseline, &candidates)?;

    let mut total_budget = StreamingByteBudget::new(request.options.max_total_hashed_bytes);
    let mut entries = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let baseline = analyze_baseline_candidate(&request, candidate, &mut total_budget)?;
        let installed = request.installed_source.analyze_candidate(
            candidate.path,
            candidate.installed_sha256,
            request.options,
            &mut total_budget,
        )?;
        let incoming = request.incoming_source.analyze_candidate(
            candidate.path,
            candidate.incoming_sha256,
            request.options,
            &mut total_budget,
        )?;
        let disposition = aggregate_disposition(
            [&baseline, &installed, &incoming],
            request.options.max_buffered_file_bytes,
            request.options.max_text_lines,
            request.options.max_line_bytes,
        );
        let algorithm = if disposition == ReadyForUtf8LineMergePlanning {
            Some(ThreeWayMergeAlgorithm::Utf8LineThreeWayV1)
        } else {
            None
        };
        entries.push(ThreeWayMergeAnalysisEntry {
            path: candidate.path.clone(),
            baseline,
            installed,
            incoming,
            algorithm,
            disposition,
        });
    }

    run_after_candidate_reads_hook();
    run_before_installed_scan_b_hook();
    let installed_after = request
        .installed_source
        .scan_and_fingerprint(request.plan.resource_key())
        .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledPostFingerprintMismatch)?;
    if installed_after.installed_root_identity != installed_before.installed_root_identity
        || installed_after.selected_resource_identity != installed_before.selected_resource_identity
        || installed_after.fingerprint != installed_before.fingerprint
        || &installed_after.fingerprint != request.plan.installed_snapshot_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged);
    }

    let summary = summarize(&entries)?;
    let status = status_from_summary(&summary)?;
    let analysis_id = analysis_id(&request, &entries, &summary, status)?;

    Ok(ThreeWayMergeAnalysisPlan {
        resource_key: request.plan.resource_key().clone(),
        baseline_id: request.plan.baseline_id().clone(),
        plan_id: *request.plan.plan_id(),
        review_id: *request.review.review_id(),
        installed_snapshot_fingerprint: *request.plan.installed_snapshot_fingerprint(),
        incoming_package_fingerprint: *request.plan.incoming_package_fingerprint(),
        incoming_resource_fingerprint: *request.plan.incoming_resource_fingerprint(),
        entries,
        summary,
        status,
        analysis_id,
    })
}

fn verify_plan_review_binding(
    plan: &ThreeWayUpdatePlan,
    review: &ThreeWayPlanReview,
) -> Result<()> {
    if review.plan_id() != plan.plan_id()
        || review.resource_key() != plan.resource_key()
        || review.baseline_id() != plan.baseline_id()
        || review.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || review.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || review.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergeAnalysisPlanReviewBindingMismatch);
    }
    Ok(())
}

fn verify_review_structure(plan: &ThreeWayUpdatePlan, review: &ThreeWayPlanReview) -> Result<()> {
    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::ThreeWayMergeAnalysisReviewStructuralMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::ThreeWayMergeAnalysisReviewStructuralMismatch);
        }
    }
    Ok(())
}

fn collect_queued_candidates<'a>(
    plan: &'a ThreeWayUpdatePlan,
    review: &'a ThreeWayPlanReview,
) -> Result<Vec<QueuedCandidate<'a>>> {
    let mut candidates = Vec::new();
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if review_entry.action() != ThreeWayReviewedAction::QueueMergeAnalysis {
            continue;
        }
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::ThreeWayMergeAnalysisReviewStructuralMismatch);
        }
        let (baseline_sha256, installed_sha256, incoming_sha256) = candidate_hashes(
            plan_entry.baseline_state(),
            plan_entry.installed_state(),
            plan_entry.incoming_state(),
        )?;
        candidates.push(QueuedCandidate {
            path: plan_entry.path(),
            baseline_sha256,
            installed_sha256,
            incoming_sha256,
        });
    }
    Ok(candidates)
}

fn verify_candidate_invariants(
    plan: &ThreeWayUpdatePlan,
    candidate: &QueuedCandidate<'_>,
) -> Result<()> {
    let entry = plan
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path)
        .ok_or(GkrmError::ThreeWayMergeAnalysisReviewStructuralMismatch)?;
    if entry.disposition() != ThreeWayPlanDisposition::MergeCandidate {
        return Err(GkrmError::ThreeWayMergeAnalysisQueuedEntryNotMergeCandidate);
    }
    if entry.policy_transition() != EscrowPolicyTransition::None {
        return Err(GkrmError::ThreeWayMergeAnalysisQueuedPolicyTransition);
    }
    let ThreeWayFileState::Present {
        escrow_class: Some(BaselineEscrowClass::Ignored),
        trusted_baseline_blob_available: true,
        ..
    } = entry.baseline_state()
    else {
        return Err(GkrmError::ThreeWayMergeAnalysisBaselineBlobUnavailable);
    };
    let ThreeWayFileState::Present {
        escrow_class: Some(BaselineEscrowClass::Ignored),
        ..
    } = entry.incoming_state()
    else {
        return Err(GkrmError::ThreeWayMergeAnalysisInvalidEscrowClass);
    };
    if candidate.baseline_sha256 == candidate.installed_sha256
        || candidate.baseline_sha256 == candidate.incoming_sha256
        || candidate.installed_sha256 == candidate.incoming_sha256
    {
        return Err(GkrmError::ThreeWayMergeAnalysisNonDivergentHashes);
    }
    Ok(())
}

fn candidate_hashes(
    baseline: &ThreeWayFileState,
    installed: &ThreeWayFileState,
    incoming: &ThreeWayFileState,
) -> Result<(Sha256Digest, Sha256Digest, Sha256Digest)> {
    match (baseline, installed, incoming) {
        (
            ThreeWayFileState::Present { sha256: b, .. },
            ThreeWayFileState::Present { sha256: l, .. },
            ThreeWayFileState::Present { sha256: n, .. },
        ) => Ok((*b, *l, *n)),
        _ => Err(GkrmError::ThreeWayMergeAnalysisMissingStateOrDigest),
    }
}

fn validate_baseline_records(
    baseline: &ResolvedOfficialBaseline,
    candidates: &[QueuedCandidate<'_>],
) -> Result<()> {
    for candidate in candidates {
        let record = baseline
            .stored_baseline()
            .files()
            .iter()
            .find(|file| file.relative_path() == candidate.path)
            .ok_or(GkrmError::ThreeWayMergeAnalysisBaselineBlobMetadataMismatch)?;
        if record.sha256() != &candidate.baseline_sha256
            || record.escrow_class() != BaselineEscrowClass::Ignored
            || record.blob_sha256().is_none()
        {
            return Err(GkrmError::ThreeWayMergeAnalysisBaselineBlobMetadataMismatch);
        }
    }
    Ok(())
}

fn analyze_baseline_candidate(
    request: &ThreeWayMergeAnalysisRequest<'_>,
    candidate: &QueuedCandidate<'_>,
    total_budget: &mut StreamingByteBudget,
) -> Result<MergeContentAnalysis> {
    let mut builder = VerifiedMergeTextBuilder::metadata_only();
    stream_verified_blob_for_path(
        request.baseline.stored_baseline(),
        candidate.path,
        request.options.baseline_store_limits(),
        |chunk| {
            total_budget.add_task16(chunk.len() as u64)?;
            builder.push(chunk)
        },
    )
    .map_err(task16_baseline_blob_verification_failed)?;
    let analysis = builder.finish_metadata()?;
    if analysis.sha256() != &candidate.baseline_sha256 {
        return Err(task16_baseline_blob_verification_failed(
            GkrmError::BaselineIncompleteBundle {
                reason: "verified baseline blob digest mismatch",
            },
        ));
    }
    Ok(analysis)
}

fn task16_baseline_blob_verification_failed(source: GkrmError) -> GkrmError {
    GkrmError::ThreeWayMergeAnalysisBaselineBlobVerificationFailed {
        source: Box::new(source),
    }
}

struct InstalledFingerprintSnapshot {
    fingerprint: Sha256Digest,
    installed_root_identity: StableFileIdentity,
    selected_resource_identity: StableFileIdentity,
}

impl InstalledMergeContentSource {
    fn validate_identities(&self) -> Result<()> {
        let installed_root_identity = dir_identity(&self.installed_root_dir, "installed-root")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let selected_resource_identity =
            dir_identity(&self.selected_resource_dir, "installed-resource")
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        if installed_root_identity != self.installed_root_identity
            || selected_resource_identity != self.selected_resource_identity
        {
            return Err(GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged);
        }
        Ok(())
    }

    fn scan_and_fingerprint(
        &self,
        expected_key: &SafeResourceKey,
    ) -> Result<InstalledFingerprintSnapshot> {
        self.validate_identities()?;
        let resource = crate::installed_scan::scan_installed_resource_from_capability(
            &self.selected_resource_dir,
            &self.resource_name,
            self.selected_resource_root.clone(),
            self.limits,
        )?;
        let resource_key = SafeResourceKey::parse(&resource.name)
            .map_err(|_| GkrmError::ThreeWayBaselineInstalledResourceMismatch)?;
        if &resource_key != expected_key {
            return Err(GkrmError::ThreeWayBaselineInstalledResourceMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut files = Vec::with_capacity(resource.files.len());
        for file in resource.files {
            if !seen.insert(file.relative_path.clone()) {
                return Err(GkrmError::ThreeWayDuplicateInstalledPath);
            }
            files.push((file.relative_path, file.sha256));
        }
        files.sort_by(|left, right| left.0.cmp(&right.0));
        let fingerprint_files = files
            .iter()
            .map(|(path, sha256)| InstalledFingerprintFile { path, sha256 })
            .collect::<Vec<_>>();
        let fingerprint = three_way_fingerprint::installed_resource_fingerprint(
            &resource_key,
            &fingerprint_files,
        )?;
        self.validate_identities()?;
        Ok(InstalledFingerprintSnapshot {
            fingerprint,
            installed_root_identity: self.installed_root_identity.clone(),
            selected_resource_identity: self.selected_resource_identity.clone(),
        })
    }

    fn analyze_candidate(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        options: ThreeWayMergeAnalysisOptions,
        total_budget: &mut StreamingByteBudget,
    ) -> Result<MergeContentAnalysis> {
        let _ = options;
        let verified = self
            .read_verified_merge_text(path, expected_digest, 0, |n| total_budget.add_task16(n))?;
        Ok(verified.into_parts().0)
    }

    /// Crate-private verified installed read for Task 16/17. `max_retain_bytes == 0` retains nothing.
    pub(crate) fn read_verified_merge_text(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        max_retain_bytes: u64,
        mut on_bytes: impl FnMut(u64) -> Result<()>,
    ) -> Result<VerifiedMergeText> {
        self.validate_identities()?;
        let mut dir = self
            .selected_resource_dir
            .try_clone()
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let components = path.as_str().split('/').collect::<Vec<_>>();
        let (file_name, parents) = components
            .split_last()
            .ok_or(GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        for parent in parents {
            dir = open_child_dir(&dir, parent)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        }
        run_before_candidate_open_hook(path);
        let mut file = open_file_nofollow(&dir, file_name)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let before = capture_file_identity(&file, "installed-candidate")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let mut builder = VerifiedMergeTextBuilder::new(max_retain_bytes);
        let mut buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut bytes_read = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
            if read == 0 {
                break;
            }
            bytes_read = bytes_read
                .checked_add(read as u64)
                .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
            on_bytes(read as u64)?;
            builder.push(&buffer[..read])?;
            run_during_candidate_read_hook(path, bytes_read);
        }
        let after_file = open_file_nofollow(&dir, file_name)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let after = capture_file_identity(&after_file, "installed-candidate")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        if before != after {
            return Err(GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged);
        }
        let verified = builder.finish()?;
        if verified.metadata().sha256() != &expected_digest {
            return Err(GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid);
        }
        self.validate_identities()?;
        Ok(verified)
    }

    /// Stream installed file bytes for Task 20 staging while verifying digest.
    pub(crate) fn stream_verified_file_bytes(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        self.validate_identities()?;
        let mut dir = self
            .selected_resource_dir
            .try_clone()
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let components = path.as_str().split('/').collect::<Vec<_>>();
        let (file_name, parents) = components
            .split_last()
            .ok_or(GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        for parent in parents {
            dir = open_child_dir(&dir, parent)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        }
        let mut file = open_file_nofollow(&dir, file_name)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let before = capture_file_identity(&file, "installed-candidate")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut total = 0_u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
            hasher.update(&buffer[..read]);
            on_chunk(&buffer[..read])?;
        }
        let after_file = open_file_nofollow(&dir, file_name)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        let after = capture_file_identity(&after_file, "installed-candidate")
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid)?;
        if before != after {
            return Err(GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged);
        }
        let digest = Sha256Digest::new(hasher.finalize().into());
        if digest != expected_digest {
            return Err(GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid);
        }
        self.validate_identities()?;
        Ok(total)
    }

    pub(crate) fn installed_root_identity(&self) -> &StableFileIdentity {
        &self.installed_root_identity
    }

    pub(crate) fn selected_resource_identity(&self) -> &StableFileIdentity {
        &self.selected_resource_identity
    }

    pub(crate) fn scan_fingerprint_for_plan(
        &self,
        expected_key: &SafeResourceKey,
    ) -> Result<(Sha256Digest, StableFileIdentity, StableFileIdentity)> {
        let snapshot = self.scan_and_fingerprint(expected_key)?;
        Ok((
            snapshot.fingerprint,
            snapshot.installed_root_identity,
            snapshot.selected_resource_identity,
        ))
    }
}

impl IncomingMergeContentSource {
    pub(crate) fn validate_against_plan(&self, plan: &ThreeWayUpdatePlan) -> Result<()> {
        let recomputed = incoming_fingerprint_from_inventory(
            self.snapshot.fingerprint(),
            &self.resource_key,
            &self.selected_resource_root,
            &self.inventory,
        )?;
        if recomputed != self.resource_fingerprint {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch);
        }
        if self.snapshot.fingerprint() != plan.incoming_package_fingerprint() {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch);
        }
        if &self.resource_key != plan.resource_key() {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch);
        }
        if &self.resource_fingerprint != plan.incoming_resource_fingerprint() {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch);
        }
        Ok(())
    }

    fn analyze_candidate(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        _options: ThreeWayMergeAnalysisOptions,
        total_budget: &mut StreamingByteBudget,
    ) -> Result<MergeContentAnalysis> {
        Ok(self
            .read_verified_merge_text(path, expected_digest, 0, |n| total_budget.add_task16(n))?
            .into_parts()
            .0)
    }

    pub(crate) fn read_verified_merge_text(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        max_retain_bytes: u64,
        mut on_bytes: impl FnMut(u64) -> Result<()>,
    ) -> Result<VerifiedMergeText> {
        let source = self
            .inventory
            .get(path)
            .ok_or(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        // Escrow-protected content is never read as text: it is encrypted, the operator cannot
        // have edited it, and retaining it here would be retaining what escrow exists to withhold.
        // Everything escrow left open — declared `escrow_ignore`, or of a kind escrow cannot
        // encrypt at all, like JSON or markup — is plain in the package and plain on the
        // operator's disk, and combining it is the whole point.
        if source.sha256 != expected_digest || source.escrow_class == BaselineEscrowClass::Protected
        {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
        let mut archive = self
            .snapshot
            .open_zip_archive()
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let mut builder = VerifiedMergeTextBuilder::new(max_retain_bytes);
        let mut buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let digest = hash_zip_entry_streaming(&mut archive, &source.entry, &mut buffer, |chunk| {
            on_bytes(chunk.len() as u64)?;
            builder.push(chunk)
        })?;
        if digest != expected_digest {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
        let verified = builder.finish()?;
        if verified.metadata().sha256() != &expected_digest {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
        Ok(verified)
    }

    /// Stream any inventory entry (including escrow-protected) for Task 20 staging.
    pub(crate) fn stream_verified_entry_bytes(
        &self,
        path: &ResourceRelativePath,
        expected_digest: Sha256Digest,
        mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        let source = self
            .inventory
            .get(path)
            .ok_or(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        if source.sha256 != expected_digest {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
        let mut archive = self
            .snapshot
            .open_zip_archive()
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let mut buffer = vec![0_u8; STREAM_BUFFER_SIZE];
        let mut total = 0_u64;
        let digest = hash_zip_entry_streaming(&mut archive, &source.entry, &mut buffer, |chunk| {
            total = total
                .checked_add(chunk.len() as u64)
                .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
            on_chunk(chunk)
        })?;
        if digest != expected_digest {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
        Ok(total)
    }

    pub(crate) fn package_fingerprint(&self) -> &Sha256Digest {
        self.snapshot.fingerprint()
    }

    pub(crate) fn resource_fingerprint(&self) -> &Sha256Digest {
        &self.resource_fingerprint
    }

    pub(crate) fn source_package_path(&self) -> &Path {
        self.snapshot.source_path()
    }

    #[cfg(test)]
    pub(crate) fn snapshot_temp_path_for_test(&self) -> &Path {
        self.snapshot.temp_path()
    }
}

fn open_selected_resource_dir(
    root: &CapDir,
    selected_root: &InstalledResourceRoot,
) -> Result<CapDir> {
    match selected_root {
        InstalledResourceRoot::Root => {
            root.try_clone()
                .map_err(|source| GkrmError::BaselineStoreIo {
                    component: "installed-root".to_owned(),
                    cause: source,
                })
        }
        InstalledResourceRoot::Path(path) => {
            let mut dir = root
                .try_clone()
                .map_err(|source| GkrmError::BaselineStoreIo {
                    component: "installed-root".to_owned(),
                    cause: source,
                })?;
            for component in path.as_str().split('/') {
                dir = open_child_dir(&dir, component)?;
            }
            Ok(dir)
        }
    }
}

fn installed_resource_name(
    installed_root: &Path,
    selected_root: &InstalledResourceRoot,
) -> Result<String> {
    match selected_root {
        InstalledResourceRoot::Root => installed_root
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .ok_or(GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid),
        InstalledResourceRoot::Path(path) => Ok(path.file_name().to_owned()),
    }
}

fn incoming_fingerprint_from_inventory(
    package_fingerprint: &Sha256Digest,
    resource_key: &SafeResourceKey,
    root: &ZipResourceRoot,
    inventory: &BTreeMap<ResourceRelativePath, IncomingSourceFile>,
) -> Result<Sha256Digest> {
    let files = inventory
        .iter()
        .map(|(path, file)| IncomingFingerprintFile {
            path,
            sha256: &file.sha256,
            escrow_class: file.escrow_class,
        })
        .collect::<Vec<_>>();
    three_way_fingerprint::incoming_resource_fingerprint(
        package_fingerprint,
        resource_key,
        zip_root_stable_identity(root),
        &files,
    )
}

fn hash_zip_entry_streaming<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    expected: &ZipEntryInfo,
    buffer: &mut [u8],
    mut on_chunk: impl FnMut(&[u8]) -> Result<()>,
) -> Result<Sha256Digest> {
    {
        let entry = archive
            .by_index_raw(expected.archive_index)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let actual_path = ZipRelativePath::new(expected.archive_index, entry.name_raw())
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        let actual_kind = if entry.is_dir() {
            ZipEntryKind::Directory
        } else {
            ZipEntryKind::File
        };
        if actual_path != expected.path
            || actual_kind != expected.kind
            || entry.size() != expected.uncompressed_size
            || entry.compressed_size() != expected.compressed_size
            || entry.crc32() != expected.crc32
            || entry.compression() != expected.compression_method
            || entry.encrypted() != expected.encrypted
            || entry.unix_mode() != expected.unix_mode
        {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
    }

    let mut entry = archive
        .by_index(expected.archive_index)
        .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    loop {
        let read = entry
            .read(buffer)
            .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
        if bytes_read > expected.uncompressed_size {
            return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
        }
        hasher.update(&buffer[..read]);
        on_chunk(&buffer[..read])?;
    }
    if bytes_read != expected.uncompressed_size {
        return Err(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid);
    }
    Ok(Sha256Digest::new(hasher.finalize().into()))
}

fn aggregate_disposition(
    analyses: [&MergeContentAnalysis; 3],
    max_buffered_file_bytes: u64,
    max_text_lines: usize,
    max_line_bytes: usize,
) -> ThreeWayMergeAnalysisDisposition {
    if analyses
        .iter()
        .any(|analysis| analysis.content_kind == MergeContentKind::Binary)
    {
        return ManualReviewBinary;
    }
    if analyses
        .iter()
        .any(|analysis| analysis.content_kind == MergeContentKind::UnsupportedEncoding)
    {
        return ManualReviewUnsupportedEncoding;
    }
    if analyses
        .iter()
        .any(|analysis| analysis.byte_length > max_buffered_file_bytes)
    {
        return ManualReviewFileTooLarge;
    }
    if analyses.iter().any(|analysis| {
        analysis
            .line_count
            .is_some_and(|line_count| line_count > max_text_lines)
    }) {
        return ManualReviewTooManyLines;
    }
    if analyses.iter().any(|analysis| {
        analysis
            .max_line_bytes
            .is_some_and(|line_bytes| line_bytes > max_line_bytes)
    }) {
        return ManualReviewLineTooLong;
    }
    if analyses.iter().any(|analysis| {
        matches!(
            analysis.newline_style,
            MergeNewlineStyle::Cr | MergeNewlineStyle::Mixed
        )
    }) {
        return ManualReviewUnsupportedNewlines;
    }
    ReadyForUtf8LineMergePlanning
}

fn summarize(entries: &[ThreeWayMergeAnalysisEntry]) -> Result<ThreeWayMergeAnalysisSummary> {
    let mut summary = ThreeWayMergeAnalysisSummary {
        total_candidates: entries.len(),
        ready_for_text_merge_planning: 0,
        manual_binary: 0,
        manual_unsupported_encoding: 0,
        manual_too_large: 0,
        manual_too_many_lines: 0,
        manual_line_too_long: 0,
        manual_unsupported_newlines: 0,
    };
    for entry in entries {
        match entry.disposition {
            ReadyForUtf8LineMergePlanning => inc(&mut summary.ready_for_text_merge_planning)?,
            ManualReviewBinary => inc(&mut summary.manual_binary)?,
            ManualReviewUnsupportedEncoding => inc(&mut summary.manual_unsupported_encoding)?,
            ManualReviewFileTooLarge => inc(&mut summary.manual_too_large)?,
            ManualReviewTooManyLines => inc(&mut summary.manual_too_many_lines)?,
            ManualReviewLineTooLong => inc(&mut summary.manual_line_too_long)?,
            ManualReviewUnsupportedNewlines => inc(&mut summary.manual_unsupported_newlines)?,
        }
    }
    let total = summary
        .ready_for_text_merge_planning
        .checked_add(summary.manual_binary)
        .and_then(|value| value.checked_add(summary.manual_unsupported_encoding))
        .and_then(|value| value.checked_add(summary.manual_too_large))
        .and_then(|value| value.checked_add(summary.manual_too_many_lines))
        .and_then(|value| value.checked_add(summary.manual_line_too_long))
        .and_then(|value| value.checked_add(summary.manual_unsupported_newlines))
        .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
    if total != summary.total_candidates {
        return Err(GkrmError::ThreeWayMergeAnalysisSummaryInvariant);
    }
    Ok(summary)
}

fn inc(value: &mut usize) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or(GkrmError::ThreeWayMergeAnalysisArithmeticOverflow)?;
    Ok(())
}

fn status_from_summary(
    summary: &ThreeWayMergeAnalysisSummary,
) -> Result<ThreeWayMergeAnalysisStatus> {
    if summary.total_candidates == summary.ready_for_text_merge_planning {
        Ok(ThreeWayMergeAnalysisStatus::ReadyForFurtherPlanning)
    } else if summary.ready_for_text_merge_planning <= summary.total_candidates {
        Ok(ThreeWayMergeAnalysisStatus::HasManualReviewEntries)
    } else {
        Err(GkrmError::ThreeWayMergeAnalysisStatusInvariant)
    }
}

fn analysis_id(
    request: &ThreeWayMergeAnalysisRequest<'_>,
    entries: &[ThreeWayMergeAnalysisEntry],
    summary: &ThreeWayMergeAnalysisSummary,
    status: ThreeWayMergeAnalysisStatus,
) -> Result<ThreeWayMergeAnalysisId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-three-way-merge-analysis-v1")
        .map_err(|_| GkrmError::ThreeWayMergeAnalysisIdEncodingFailure)?;
    encoder.digest(request.plan.plan_id().digest());
    encoder.digest(request.review.review_id().digest());
    encoder.string(request.plan.resource_key().as_str())?;
    encoder.string(request.plan.baseline_id().as_str())?;
    encoder.digest(request.plan.installed_snapshot_fingerprint());
    encoder.digest(request.plan.incoming_package_fingerprint());
    encoder.digest(request.plan.incoming_resource_fingerprint());
    encode_options(&mut encoder, request.options)?;
    encoder.usize(entries.len())?;
    for entry in entries {
        encoder.path(&entry.path)?;
        encode_content_analysis(&mut encoder, &entry.baseline)?;
        encode_content_analysis(&mut encoder, &entry.installed)?;
        encode_content_analysis(&mut encoder, &entry.incoming)?;
        encode_algorithm(&mut encoder, entry.algorithm);
        encoder.u8(analysis_disposition_code(entry.disposition));
    }
    encode_summary(&mut encoder, summary)?;
    encoder.u8(analysis_status_code(status));
    Ok(ThreeWayMergeAnalysisId(encoder.finish()))
}

fn encode_options(
    encoder: &mut CanonicalFingerprintEncoder,
    options: ThreeWayMergeAnalysisOptions,
) -> Result<()> {
    encoder.usize(options.max_candidates)?;
    encoder.u64(options.max_buffered_file_bytes);
    encoder.u64(options.max_total_hashed_bytes);
    encoder.usize(options.max_text_lines)?;
    encoder.usize(options.max_line_bytes)?;
    encoder.u64(options.baseline_store_limits.max_manifest_bytes());
    encoder.usize(options.baseline_store_limits.max_files())?;
    encoder.u64(options.baseline_store_limits.max_blob_bytes());
    encoder.u64(options.baseline_store_limits.max_total_blob_bytes());
    Ok(())
}

fn encode_content_analysis(
    encoder: &mut CanonicalFingerprintEncoder,
    analysis: &MergeContentAnalysis,
) -> Result<()> {
    encoder.digest(&analysis.sha256);
    encoder.u64(analysis.byte_length);
    encoder.u8(content_kind_code(analysis.content_kind));
    encoder.u8(content_encoding_code(analysis.encoding));
    encoder.u8(newline_style_code(analysis.newline_style));
    encoder.optional_usize(analysis.line_count)?;
    encoder.optional_usize(analysis.max_line_bytes)?;
    encoder.bool(analysis.is_empty);
    Ok(())
}

fn encode_algorithm(
    encoder: &mut CanonicalFingerprintEncoder,
    algorithm: Option<ThreeWayMergeAlgorithm>,
) {
    match algorithm {
        Some(ThreeWayMergeAlgorithm::Utf8LineThreeWayV1) => {
            encoder.u8(1);
            encoder.u8(0);
        }
        None => encoder.u8(0),
    }
}

fn encode_summary(
    encoder: &mut CanonicalFingerprintEncoder,
    summary: &ThreeWayMergeAnalysisSummary,
) -> Result<()> {
    encoder.usize(summary.total_candidates)?;
    encoder.usize(summary.ready_for_text_merge_planning)?;
    encoder.usize(summary.manual_binary)?;
    encoder.usize(summary.manual_unsupported_encoding)?;
    encoder.usize(summary.manual_too_large)?;
    encoder.usize(summary.manual_too_many_lines)?;
    encoder.usize(summary.manual_line_too_long)?;
    encoder.usize(summary.manual_unsupported_newlines)?;
    Ok(())
}

fn content_kind_code(value: MergeContentKind) -> u8 {
    match value {
        MergeContentKind::Text => 0,
        MergeContentKind::Binary => 1,
        MergeContentKind::UnsupportedEncoding => 2,
    }
}

fn content_encoding_code(value: MergeContentEncoding) -> u8 {
    match value {
        MergeContentEncoding::Utf8 => 0,
        MergeContentEncoding::Utf8WithBom => 1,
        MergeContentEncoding::Unsupported => 2,
    }
}

fn newline_style_code(value: MergeNewlineStyle) -> u8 {
    match value {
        MergeNewlineStyle::None => 0,
        MergeNewlineStyle::Lf => 1,
        MergeNewlineStyle::CrLf => 2,
        MergeNewlineStyle::Cr => 3,
        MergeNewlineStyle::Mixed => 4,
    }
}

fn analysis_disposition_code(value: ThreeWayMergeAnalysisDisposition) -> u8 {
    match value {
        ReadyForUtf8LineMergePlanning => 0,
        ManualReviewBinary => 1,
        ManualReviewUnsupportedEncoding => 2,
        ManualReviewFileTooLarge => 3,
        ManualReviewTooManyLines => 4,
        ManualReviewLineTooLong => 5,
        ManualReviewUnsupportedNewlines => 6,
    }
}

fn analysis_status_code(value: ThreeWayMergeAnalysisStatus) -> u8 {
    match value {
        ThreeWayMergeAnalysisStatus::ReadyForFurtherPlanning => 0,
        ThreeWayMergeAnalysisStatus::HasManualReviewEntries => 1,
    }
}

fn exactly_one_zip_resource<'a>(
    discovery: &'a ZipResourceDiscovery,
    root: &ZipResourceRoot,
) -> Result<&'a crate::DiscoveredZipResource> {
    let resources = discovery
        .resources
        .iter()
        .filter(|resource| &resource.root == root)
        .collect::<Vec<_>>();
    match resources.as_slice() {
        [resource] => Ok(*resource),
        [] => Err(GkrmError::ThreeWaySelectedIncomingResourceMissing),
        _ => Err(GkrmError::ThreeWaySelectedIncomingResourceAmbiguous),
    }
}

fn trusted_zip_resource_key(resource: &crate::DiscoveredZipResource) -> Result<SafeResourceKey> {
    match (&resource.root, &resource.name) {
        (ZipResourceRoot::Path(path), ZipResourceName::Directory(discovered_name)) => {
            let final_component = path
                .as_str()
                .rsplit_once('/')
                .map_or(path.as_str(), |(_, name)| name);
            if discovered_name != final_component {
                return Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch);
            }
            SafeResourceKey::parse(final_component)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch)
        }
        _ => Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch),
    }
}

fn zip_resource_relative_path(
    root: &ZipResourceRoot,
    path: &ZipRelativePath,
) -> Result<ResourceRelativePath> {
    match root {
        ZipResourceRoot::Root => {
            Err(GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch)
        }
        ZipResourceRoot::Path(root) => {
            let suffix = path
                .as_str()
                .strip_prefix(root.as_str())
                .and_then(|suffix| suffix.strip_prefix('/'))
                .ok_or(GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)?;
            ResourceRelativePath::try_from_slash_str(suffix)
                .map_err(|_| GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid)
        }
    }
}

fn zip_root_stable_identity(root: &ZipResourceRoot) -> &str {
    match root {
        ZipResourceRoot::Root => ".",
        ZipResourceRoot::Path(path) => path.as_str(),
    }
}

fn escrow_class_to_baseline(classification: &EscrowFileClassification) -> BaselineEscrowClass {
    match classification {
        EscrowFileClassification::Protected => BaselineEscrowClass::Protected,
        EscrowFileClassification::Ignored { .. } => BaselineEscrowClass::Ignored,
        EscrowFileClassification::NotSupported { .. } => BaselineEscrowClass::NotSupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fs;
    use std::io::Write;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::{Path, PathBuf};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter};

    fn analyze_chunks(chunks: &[&[u8]]) -> MergeContentAnalysis {
        let mut builder = VerifiedMergeTextBuilder::metadata_only();
        for chunk in chunks {
            builder.push(chunk).unwrap();
        }
        builder.finish_metadata().unwrap()
    }

    #[test]
    fn utf8_split_across_chunks_is_text() {
        let analysis = analyze_chunks(&[&[0xE2], &[0x82], &[0xAC, b'\n']]);
        assert_eq!(analysis.content_kind(), MergeContentKind::Text);
        assert_eq!(analysis.encoding(), MergeContentEncoding::Utf8);
        assert_eq!(analysis.newline_style(), MergeNewlineStyle::Lf);
        assert_eq!(analysis.line_count(), Some(1));
    }

    #[test]
    fn incomplete_utf8_at_eof_is_unsupported() {
        let analysis = analyze_chunks(&[&[0xE2, 0x82]]);
        assert_eq!(
            analysis.content_kind(),
            MergeContentKind::UnsupportedEncoding
        );
    }

    #[test]
    fn nul_marks_binary() {
        let analysis = analyze_chunks(&[b"abc", &[0], b"def"]);
        assert_eq!(analysis.content_kind(), MergeContentKind::Binary);
    }

    #[test]
    fn crlf_split_across_chunks_is_crlf() {
        let analysis = analyze_chunks(&[b"one\r", b"\ntwo\r", b"\n"]);
        assert_eq!(analysis.newline_style(), MergeNewlineStyle::CrLf);
        assert_eq!(analysis.line_count(), Some(2));
        assert_eq!(analysis.max_line_bytes(), Some(3));
    }

    #[test]
    fn mixed_newlines_are_detected() {
        let analysis = analyze_chunks(&[b"one\n", b"two\r\n", b"three\r"]);
        assert_eq!(analysis.newline_style(), MergeNewlineStyle::Mixed);
    }

    #[test]
    fn disposition_precedence_is_stable() {
        let binary = analyze_chunks(&[b"a\0"]);
        let huge = MergeContentAnalysis {
            byte_length: 10,
            ..analyze_chunks(&[b"text\n"])
        };
        assert_eq!(
            aggregate_disposition([&binary, &huge, &huge], 1, 1, 1),
            ManualReviewBinary
        );
    }

    const MANIFEST: &[u8] = b"fx_version 'cerulean'\ngame 'gta5'\nescrow_ignore { 'shared.lua' }\n";

    struct AnalysisFixture {
        _temp: tempfile::TempDir,
        installed_parent: PathBuf,
        installed_resource: PathBuf,
        package_v2: PathBuf,
        baseline: ResolvedOfficialBaseline,
        plan: ThreeWayUpdatePlan,
        review: ThreeWayPlanReview,
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().expect("test path should have parent")).expect("mkdir");
        fs::write(path, bytes).expect("write file");
    }

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("zip create");
        let mut writer = ZipWriter::new(file);
        let options =
            zip::write::SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(*name, options).expect("entry start");
            writer.write_all(bytes).expect("entry write");
        }
        writer.finish().expect("zip finish");
    }

    fn key() -> SafeResourceKey {
        SafeResourceKey::parse("gksphone").expect("key")
    }

    fn installed_root() -> InstalledResourceRoot {
        InstalledResourceRoot::Path(
            crate::InstallationRelativePath::from_path(Path::new("gksphone")).expect("root"),
        )
    }

    fn incoming_root() -> ZipResourceRoot {
        ZipResourceRoot::Path(ZipRelativePath::parse_canonical("gksphone").expect("root"))
    }

    fn plan_path(plan: &ThreeWayUpdatePlan, path: &str) -> ResourceRelativePath {
        plan.entries()
            .iter()
            .find(|entry| entry.path().as_str() == path)
            .expect("plan entry")
            .path()
            .clone()
    }

    fn build_fixture(shared_len: usize) -> AnalysisFixture {
        let temp = tempdir().expect("temp");
        let store = temp.path().join("store");
        let installed_parent = temp.path().join("installed");
        let installed_resource = installed_parent.join("gksphone");
        let package_v2 = temp.path().join("official-v2.zip");
        fs::create_dir_all(&store).expect("store");

        let base = vec![b'b'; shared_len];
        let local = vec![b'l'; shared_len];
        let official = vec![b'o'; shared_len];
        let base_digest = Sha256Digest::new(Sha256::digest(&base).into());
        let mut blobs = BTreeMap::new();
        blobs.insert(base_digest, base.clone());
        let bundle = crate::baseline::ValidatedBaselineBundle::try_from_parts_with_bytes(
            key(),
            "gksphone".to_owned(),
            None,
            Some(Sha256Digest::new(Sha256::digest(b"package").into())),
            vec![crate::baseline::make_file_record(
                ResourceRelativePath::try_from_slash_str("shared.lua").expect("path"),
                base.len() as u64,
                base_digest,
                BaselineEscrowClass::Ignored,
                Some(base_digest),
            )],
            blobs.clone(),
            BaselineStoreLimits::default(),
        )
        .expect("bundle");
        let provider = crate::baseline::InMemoryBlobProvider::new(blobs);
        let locator = crate::baseline::store::write_baseline_bundle(
            &store,
            &bundle,
            &provider,
            BaselineStoreLimits::default(),
        )
        .expect("write baseline");
        let baseline = crate::resolve_official_baseline(
            crate::BaselineResolutionRequest::try_new(
                &store,
                &key(),
                crate::OfficialBaselineSelector::Exact(locator.baseline_id().clone()),
                crate::BaselineResolutionOptions::default(),
            )
            .expect("resolve request"),
        )
        .expect("resolve");

        write_file(&installed_resource.join("fxmanifest.lua"), MANIFEST);
        write_file(&installed_resource.join("shared.lua"), &local);
        write_file(&installed_resource.join("local-only.lua"), b"local-only\n");
        write_zip(
            &package_v2,
            &[
                ("gksphone/fxmanifest.lua", MANIFEST),
                ("gksphone/shared.lua", &official),
            ],
        );
        let report = crate::inspect_installation_update(
            &installed_parent,
            &package_v2,
            crate::InspectionOptions::default(),
        )
        .expect("inspection");
        let installed = crate::InstalledResourceSnapshot::try_from_inspection(
            &report,
            &installed_root(),
            &key(),
        )
        .expect("installed snapshot");
        let incoming = crate::IncomingOfficialResourceSnapshot::try_from_inspection(
            &report,
            &incoming_root(),
            &key(),
        )
        .expect("incoming snapshot");
        let plan = crate::create_three_way_update_plan(
            crate::ThreeWayUpdatePlanRequest::try_new(
                &baseline,
                &installed,
                &incoming,
                crate::ThreeWayPlannerOptions::default(),
            )
            .expect("plan request"),
        )
        .expect("plan");
        assert_eq!(
            plan.entries()
                .iter()
                .find(|entry| entry.path().as_str() == "shared.lua")
                .expect("shared")
                .disposition(),
            ThreeWayPlanDisposition::MergeCandidate
        );
        let decision_set = crate::ThreeWayPlanDecisionSet::try_new(
            *plan.plan_id(),
            vec![crate::ThreeWayPlanDecision::try_new(
                plan_path(&plan, "shared.lua"),
                crate::ThreeWayPlanDecisionChoice::QueueMergeAnalysis,
                crate::PolicyTransitionAcknowledgement::NotProvided,
            )
            .expect("decision")],
        )
        .expect("decision set");
        let review = crate::review_three_way_update_plan(
            crate::ThreeWayPlanReviewRequest::try_new(&plan, &decision_set)
                .expect("review request"),
        )
        .expect("review");

        AnalysisFixture {
            _temp: temp,
            installed_parent,
            installed_resource,
            package_v2,
            baseline,
            plan,
            review,
        }
    }

    fn analyze_fixture(fixture: &AnalysisFixture) -> Result<ThreeWayMergeAnalysisPlan> {
        analyze_fixture_with_options(fixture, ThreeWayMergeAnalysisOptions::default())
    }

    fn analyze_fixture_with_options(
        fixture: &AnalysisFixture,
        options: ThreeWayMergeAnalysisOptions,
    ) -> Result<ThreeWayMergeAnalysisPlan> {
        let installed_source = InstalledMergeContentSource::try_new(
            &fixture.installed_parent,
            installed_root(),
            InstalledScanLimits::default(),
        )
        .expect("installed source");
        let incoming_source = IncomingMergeContentSource::try_new(
            &fixture.package_v2,
            incoming_root(),
            IncomingMergeContentSourceLimits::default(),
        )
        .expect("incoming source");
        analyze_queued_three_way_merges(
            ThreeWayMergeAnalysisRequest::try_new(
                &fixture.plan,
                &fixture.review,
                &fixture.baseline,
                &installed_source,
                &incoming_source,
                options,
            )
            .expect("analysis request"),
        )
    }

    fn baseline_blob_path(fixture: &AnalysisFixture) -> PathBuf {
        let record = fixture
            .baseline
            .stored_baseline()
            .files()
            .iter()
            .find(|file| file.relative_path().as_str() == "shared.lua")
            .expect("baseline record");
        fixture
            .baseline
            .stored_baseline()
            .store_root()
            .join("baselines")
            .join(fixture.baseline.resource_key().as_str())
            .join(fixture.baseline.baseline_id().as_str())
            .join("blobs")
            .join(record.blob_sha256().expect("blob").to_string())
    }

    fn assert_redacted(error: &GkrmError, fixture: &AnalysisFixture) {
        let display = error.to_string();
        assert!(!display.contains(fixture._temp.path().to_string_lossy().as_ref()));
        assert!(!display.contains("local-only"));
        assert!(!display.contains("shared.lua"));
        assert!(!display.contains("gksphone"));
        assert!(!display.contains("mutated"));
    }

    fn assert_task16_baseline_verification_boundary(
        error: &GkrmError,
        fixture: &AnalysisFixture,
        source_matches: impl FnOnce(&GkrmError) -> bool,
    ) {
        assert_redacted(error, fixture);
        let source = match error {
            GkrmError::ThreeWayMergeAnalysisBaselineBlobVerificationFailed { source } => {
                source.as_ref()
            }
            other => panic!("expected Task 16 baseline verification failure, got {other:?}"),
        };
        assert!(source_matches(source), "unexpected source: {source:?}");
        assert!(error.source().is_some());
        let display = error.to_string();
        let record = fixture
            .baseline
            .stored_baseline()
            .files()
            .iter()
            .find(|file| file.relative_path().as_str() == "shared.lua")
            .expect("baseline record");
        assert!(!display.contains(record.sha256().to_string().as_str()));
        assert!(!display.contains(record.blob_sha256().expect("blob").to_string().as_str()));
    }

    #[test]
    fn task16_non_candidate_modification_between_scans_fails_closed() {
        let fixture = build_fixture(128);
        let _hooks = lock_three_way_merge_analysis_hooks();
        let local_only = fixture.installed_resource.join("local-only.lua");
        set_after_installed_scan_a_hook(move || {
            fs::write(&local_only, b"mutated non candidate\n").expect("mutate");
        });

        let err = analyze_fixture(&fixture).expect_err("mutation must fail");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged
        ));
        assert_redacted(&err, &fixture);
    }

    #[test]
    fn task16_wraps_missing_baseline_blob_errors_at_boundary() {
        let fixture = build_fixture(128);
        fs::remove_file(baseline_blob_path(&fixture)).expect("remove baseline blob");

        let err = analyze_fixture(&fixture).expect_err("missing blob must fail");

        assert_task16_baseline_verification_boundary(&err, &fixture, |source| {
            matches!(
                source,
                GkrmError::BaselineStoreMissing { .. } | GkrmError::BaselineStoreIo { .. }
            )
        });
    }

    #[test]
    fn task16_wraps_baseline_blob_size_errors_at_boundary() {
        let fixture = build_fixture(128);
        fs::write(baseline_blob_path(&fixture), b"short").expect("truncate baseline blob");

        let err = analyze_fixture(&fixture).expect_err("size mismatch must fail");

        assert_task16_baseline_verification_boundary(&err, &fixture, |source| {
            matches!(source, GkrmError::BaselineBlobSizeMismatch { .. })
        });
    }

    #[test]
    fn task16_wraps_baseline_blob_digest_errors_at_boundary() {
        let fixture = build_fixture(128);
        fs::write(baseline_blob_path(&fixture), vec![b'x'; 128]).expect("mutate baseline blob");

        let err = analyze_fixture(&fixture).expect_err("digest mismatch must fail");

        assert_task16_baseline_verification_boundary(&err, &fixture, |source| {
            matches!(source, GkrmError::BaselineBlobDigestMismatch { .. })
        });
    }

    #[test]
    fn task16_wraps_baseline_blob_identity_errors_at_boundary() {
        let fixture = build_fixture(128);
        let blob = baseline_blob_path(&fixture);
        let _guard = crate::baseline::store::lock_stream_verified_blob_identity_hook();
        crate::baseline::store::set_before_blob_identity_revalidation_hook(move || {
            fs::remove_file(&blob).expect("remove blob");
            fs::write(&blob, vec![b'b'; 128]).expect("replace blob");
        });

        let err = analyze_fixture(&fixture).expect_err("identity mismatch must fail");

        assert_task16_baseline_verification_boundary(&err, &fixture, |source| {
            matches!(
                source,
                GkrmError::BaselineIncompleteBundle {
                    reason: "blob identity changed while reading"
                }
            )
        });
    }

    #[test]
    fn task16_wraps_baseline_blob_unsafe_type_errors_at_boundary() {
        let fixture = build_fixture(128);
        let blob = baseline_blob_path(&fixture);
        fs::remove_file(&blob).expect("remove blob");
        fs::create_dir(&blob).expect("directory substitution");

        let err = analyze_fixture(&fixture).expect_err("unsafe type must fail");

        assert_task16_baseline_verification_boundary(&err, &fixture, |source| {
            matches!(
                source,
                GkrmError::BaselineStoreUnexpectedType { .. }
                    | GkrmError::BaselineStoreIo { .. }
                    | GkrmError::BaselineStoreSymlink { .. }
                    | GkrmError::BaselineStoreReparsePoint { .. }
            )
        });
    }

    #[test]
    fn task16_wraps_combined_callback_and_baseline_verification_errors() {
        let fixture = build_fixture(128);
        fs::write(baseline_blob_path(&fixture), vec![b'x'; 128]).expect("mutate baseline blob");
        let options = ThreeWayMergeAnalysisOptions {
            max_total_hashed_bytes: 1,
            ..ThreeWayMergeAnalysisOptions::default()
        };

        let err =
            analyze_fixture_with_options(&fixture, options).expect_err("combined failure expected");

        assert_task16_baseline_verification_boundary(&err, &fixture, |source| {
            matches!(
                source,
                GkrmError::BaselineVerifiedBlobCallbackAndVerificationFailed { .. }
            ) && matches!(
                source.baseline_verified_blob_callback_error(),
                Some(GkrmError::ThreeWayMergeAnalysisTotalHashBudgetExceeded { .. })
            ) && matches!(
                source.baseline_verified_blob_verification_error(),
                Some(GkrmError::BaselineBlobDigestMismatch { .. })
            )
        });
    }

    #[test]
    fn task16_candidate_modification_before_read_fails_closed() {
        let fixture = build_fixture(128);
        let _hooks = lock_three_way_merge_analysis_hooks();
        let candidate = fixture.installed_resource.join("shared.lua");
        set_before_candidate_open_hook(move |_| {
            fs::write(&candidate, b"mutated-before-read\n").expect("mutate");
        });

        let err = analyze_fixture(&fixture).expect_err("mutation must fail");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
                | GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged
        ));
        assert_redacted(&err, &fixture);
    }

    #[test]
    fn task16_candidate_mutation_during_read_fails_closed() {
        let fixture = build_fixture(STREAM_BUFFER_SIZE * 3);
        let _hooks = lock_three_way_merge_analysis_hooks();
        let candidate = fixture.installed_resource.join("shared.lua");
        let mut mutated = false;
        set_during_candidate_read_hook(move |path, bytes_read| {
            if !mutated && path.as_str() == "shared.lua" && bytes_read >= STREAM_BUFFER_SIZE as u64
            {
                fs::write(&candidate, vec![b'x'; STREAM_BUFFER_SIZE * 3]).expect("mutate");
                mutated = true;
            }
        });

        let err = analyze_fixture(&fixture).expect_err("mutation must fail");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid
                | GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged
        ));
        assert_redacted(&err, &fixture);
    }

    #[test]
    fn task16_file_addition_between_scans_fails_closed() {
        let fixture = build_fixture(128);
        let _hooks = lock_three_way_merge_analysis_hooks();
        let added = fixture.installed_resource.join("added.lua");
        set_after_candidate_reads_hook(move || {
            fs::write(&added, b"added\n").expect("add");
        });

        let err = analyze_fixture(&fixture).expect_err("addition must fail");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged
        ));
        assert_redacted(&err, &fixture);
    }

    #[test]
    fn task16_file_removal_between_scans_fails_closed() {
        let fixture = build_fixture(128);
        let _hooks = lock_three_way_merge_analysis_hooks();
        let removed = fixture.installed_resource.join("local-only.lua");
        set_before_installed_scan_b_hook(move || {
            fs::remove_file(&removed).expect("remove");
        });

        let err = analyze_fixture(&fixture).expect_err("removal must fail");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged
                | GkrmError::ThreeWayMergeAnalysisInstalledPostFingerprintMismatch
        ));
        assert_redacted(&err, &fixture);
    }

    #[test]
    fn task16_unsafe_entry_insertion_between_scans_fails_closed() {
        let fixture = build_fixture(128);
        let _hooks = lock_three_way_merge_analysis_hooks();
        let link = fixture.installed_resource.join("unsafe-link.lua");
        let target = fixture.installed_resource.join("shared.lua");
        set_before_installed_scan_b_hook(move || {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &link).expect("symlink");
            #[cfg(windows)]
            if std::os::windows::fs::symlink_file(&target, &link).is_err() {
                fs::write(&link, b"fallback unsafe-entry coverage\n").expect("fallback entry");
            }
        });

        let err = analyze_fixture(&fixture).expect_err("unsafe entry must fail");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged
                | GkrmError::ThreeWayMergeAnalysisInstalledPostFingerprintMismatch
        ));
        assert_redacted(&err, &fixture);
    }

    #[test]
    fn task16_hook_poison_recovery_clears_stale_hook_slots() {
        let panic_invocations = Arc::new(AtomicUsize::new(0));
        let stale_invocations = Arc::new(AtomicUsize::new(0));
        let panic_counter = Arc::clone(&panic_invocations);
        let stale_counter = Arc::clone(&stale_invocations);

        let result = catch_unwind(AssertUnwindSafe(move || {
            let fixture = build_fixture(128);
            let _hooks = lock_three_way_merge_analysis_hooks();
            set_after_installed_scan_a_hook(move || {
                panic_counter.fetch_add(1, Ordering::SeqCst);
                panic!("deliberate Task 16 hook panic");
            });
            set_before_candidate_open_hook(move |_| {
                stale_counter.fetch_add(1, Ordering::SeqCst);
            });
            let _ = analyze_fixture(&fixture);
        }));

        assert!(result.is_err());
        assert_eq!(panic_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(stale_invocations.load(Ordering::SeqCst), 0);

        let fixture = build_fixture(128);
        {
            let _hooks = lock_three_way_merge_analysis_hooks();
            analyze_fixture(&fixture).expect("second analysis should not consume stale hooks");
        }

        assert_eq!(panic_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(stale_invocations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn task16_baseline_stream_budget_counts_all_helper_streamed_bytes_once() {
        let size = (STREAM_BUFFER_SIZE * 2 + 31) as u64;
        let fixture = build_fixture(size as usize);
        let path = plan_path(&fixture.plan, "shared.lua");
        let mut exact_budget = StreamingByteBudget::new(size);
        let mut retained = 0_usize;

        stream_verified_blob_for_path(
            fixture.baseline.stored_baseline(),
            &path,
            &BaselineStoreLimits::default(),
            |chunk| {
                exact_budget.add_task16(chunk.len() as u64)?;
                if retained < 5 {
                    retained += chunk.len().min(5 - retained);
                }
                Ok(())
            },
        )
        .expect("exact budget succeeds");
        assert_eq!(exact_budget.actual(), size);
        assert_eq!(retained, 5);

        let mut low_budget = StreamingByteBudget::new(size - 1);
        let err = stream_verified_blob_for_path(
            fixture.baseline.stored_baseline(),
            &path,
            &BaselineStoreLimits::default(),
            |chunk| low_budget.add_task16(chunk.len() as u64),
        )
        .expect_err("one byte below total fails");

        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeAnalysisTotalHashBudgetExceeded { .. }
        ));
        assert_eq!(low_budget.actual(), size);
        assert_redacted(&err, &fixture);
    }
}
