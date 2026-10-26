//! Trusted transactional resource staging (Milestone 2 Task 20).

#![allow(clippy::too_many_arguments)]

mod id;
mod manifest;
mod root;
mod sources;
mod two_way;
mod write;

mod undo;
mod undo_descriptor;
pub(crate) use undo::stage_undo_candidate;
pub use undo::TrustedUndoStagingBundle;
pub(crate) use undo::UNDO_BASELINE_MARKER;
pub(crate) use undo::{reopen_undo_candidate, undo_record_marker};
pub use undo_descriptor::TrustedUndoExecutionDescriptor;

use std::collections::BTreeSet;
use std::path::Path;

use crate::baseline::ensure_baseline_store_disjoint_from_installed;
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::three_way_merged_bytes::MergedByteArtifactId;
use crate::{
    BaselineStoreLimits, GkrmError, MergedByteDisposition, ResolvedOfficialBaseline,
    ResourceRelativePath, Result, Sha256Digest, ThreeWayMergeAnalysisPlan,
    ThreeWayMergeSynthesisPlan, ThreeWayMergedBytesPlan, ThreeWayPlanReview,
    ThreeWayPlanReviewStatus, ThreeWayReviewedAction, ThreeWayTextDiffPlan, ThreeWayUpdatePlan,
};

use crate::baseline::fs_security::try_open_child_dir;

use self::id::encode_status;
use self::manifest::{
    assign_entry_ids, encode_entry_id, encode_manifest_bytes, encode_manifest_id, map_final_tree,
    parse_manifest_bytes,
};
use self::write::{
    ensure_internal_layout, read_published_manifest_bytes, revalidate_published_child,
    write_and_publish,
};

pub use self::root::TrustedStagingRoot;
pub use self::sources::{IncomingStagingContentSource, InstalledStagingContentSource};
pub use self::two_way::{stage_trusted_resource_two_way, TwoWayStagingRequest, TwoWayUpdateMode};
pub use crate::error::StagingIoOperation;

pub(crate) use self::write::verify_published_bundle_readonly;

#[cfg(test)]
mod security_tests;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
#[cfg(test)]
use std::thread::ThreadId;

#[cfg(test)]
use cap_std::fs::Dir as CapDir;

#[cfg(test)]
struct StagingWriteHooks {
    owner: ThreadId,
    #[allow(clippy::type_complexity)]
    after_publish: Option<Box<dyn FnMut(&CapDir, &str) + Send>>,
    #[allow(clippy::type_complexity)]
    after_rename: Option<Box<dyn FnMut(&CapDir, &str) + Send>>,
    #[allow(clippy::type_complexity)]
    before_temp_verify: Option<Box<dyn FnMut(&CapDir) + Send>>,
    #[allow(clippy::type_complexity)]
    before_rename: Option<Box<dyn FnMut(&CapDir, &CapDir, &str) + Send>>,
    #[allow(clippy::type_complexity)]
    before_write_present_files: Option<Box<dyn FnMut() + Send>>,
    force_cleanup_failure: bool,
    force_temp_cleanup_failure: bool,
    force_quarantine_failure: bool,
    force_cleanup_capability_clone_failure: bool,
    force_post_publish_tail: Option<PostPublishTailFault>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) enum PostPublishTailFault {
    Disjointness,
    Identity,
    Reopen,
}

#[cfg(test)]
static STAGING_WRITE_HOOK_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static STAGING_WRITE_HOOKS: Mutex<Option<StagingWriteHooks>> = Mutex::new(None);
#[cfg(test)]
static SOURCE_READ_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(super) struct StagingWriteHookGuard {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for StagingWriteHookGuard {
    fn drop(&mut self) {
        *STAGING_WRITE_HOOKS
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = None;
        SOURCE_READ_COUNT.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(super) fn lock_staging_write_hooks() -> StagingWriteHookGuard {
    let guard = STAGING_WRITE_HOOK_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    *STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(StagingWriteHooks {
        owner: std::thread::current().id(),
        after_publish: None,
        after_rename: None,
        before_temp_verify: None,
        before_rename: None,
        before_write_present_files: None,
        force_cleanup_failure: false,
        force_temp_cleanup_failure: false,
        force_quarantine_failure: false,
        force_cleanup_capability_clone_failure: false,
        force_post_publish_tail: None,
    });
    SOURCE_READ_COUNT.store(0, Ordering::SeqCst);
    StagingWriteHookGuard { _guard: guard }
}

#[cfg(test)]
pub(super) fn set_after_publish_hook(hook: impl FnMut(&CapDir, &str) + Send + 'static) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.after_publish = Some(Box::new(hook));
        }
    }
}

#[cfg(test)]
pub(super) fn set_after_rename_hook(hook: impl FnMut(&CapDir, &str) + Send + 'static) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.after_rename = Some(Box::new(hook));
        }
    }
}

#[cfg(test)]
pub(super) fn set_before_temp_verify_hook(hook: impl FnMut(&CapDir) + Send + 'static) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.before_temp_verify = Some(Box::new(hook));
        }
    }
}

#[cfg(test)]
pub(super) fn set_before_rename_hook(hook: impl FnMut(&CapDir, &CapDir, &str) + Send + 'static) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.before_rename = Some(Box::new(hook));
        }
    }
}

#[cfg(test)]
pub(super) fn set_before_write_present_files_hook(hook: impl FnMut() + Send + 'static) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.before_write_present_files = Some(Box::new(hook));
        }
    }
}

#[cfg(test)]
pub(super) fn set_force_cleanup_failure(value: bool) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.force_cleanup_failure = value;
        }
    }
}

#[cfg(test)]
pub(super) fn set_force_temp_cleanup_failure(value: bool) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.force_temp_cleanup_failure = value;
        }
    }
}

#[cfg(test)]
pub(super) fn set_force_quarantine_failure(value: bool) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.force_quarantine_failure = value;
        }
    }
}

#[cfg(test)]
pub(super) fn set_force_cleanup_capability_clone_failure(value: bool) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.force_cleanup_capability_clone_failure = value;
        }
    }
}

#[cfg(test)]
pub(super) fn set_force_post_publish_tail(fault: Option<PostPublishTailFault>) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.force_post_publish_tail = fault;
        }
    }
}

#[cfg(test)]
pub(crate) fn run_after_publish_hook(bundles_dir: &CapDir, published_name: &str) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.after_publish.as_mut() {
                hook(bundles_dir, published_name);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn run_after_rename_hook(bundles_dir: &CapDir, published_name: &str) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.after_rename.as_mut() {
                hook(bundles_dir, published_name);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn run_before_temp_verify_hook(temp_dir: &CapDir) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.before_temp_verify.as_mut() {
                hook(temp_dir);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn run_before_rename_hook(
    tmp_root: &CapDir,
    bundles_dir: &CapDir,
    published_name: &str,
) {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.before_rename.as_mut() {
                hook(tmp_root, bundles_dir, published_name);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn run_before_write_present_files_hook() {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.before_write_present_files.as_mut() {
                hook();
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn force_cleanup_failure_enabled() -> bool {
    let hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    hooks
        .as_ref()
        .is_some_and(|h| h.owner == std::thread::current().id() && h.force_cleanup_failure)
}

#[cfg(test)]
pub(crate) fn force_temp_cleanup_failure_enabled() -> bool {
    let hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    hooks
        .as_ref()
        .is_some_and(|h| h.owner == std::thread::current().id() && h.force_temp_cleanup_failure)
}

#[cfg(test)]
pub(crate) fn force_quarantine_failure_enabled() -> bool {
    let hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    hooks
        .as_ref()
        .is_some_and(|h| h.owner == std::thread::current().id() && h.force_quarantine_failure)
}

#[cfg(test)]
pub(crate) fn force_cleanup_capability_clone_failure_enabled() -> bool {
    let hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    hooks.as_ref().is_some_and(|h| {
        h.owner == std::thread::current().id() && h.force_cleanup_capability_clone_failure
    })
}

#[cfg(test)]
fn take_post_publish_tail_fault() -> Option<PostPublishTailFault> {
    let mut hooks = STAGING_WRITE_HOOKS
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    hooks.as_mut().and_then(|h| {
        if h.owner == std::thread::current().id() {
            h.force_post_publish_tail.take()
        } else {
            None
        }
    })
}

#[cfg(test)]
pub(crate) fn source_read_count() -> usize {
    SOURCE_READ_COUNT.load(Ordering::SeqCst)
}

#[cfg(test)]
pub(crate) fn reset_source_read_count() {
    SOURCE_READ_COUNT.store(0, Ordering::SeqCst);
}

pub(super) fn note_source_read() {
    #[cfg(test)]
    {
        let write_owned = STAGING_WRITE_HOOKS
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|h| h.owner == std::thread::current().id());
        if write_owned || root::staging_hooks_owned() {
            SOURCE_READ_COUNT.fetch_add(1, Ordering::SeqCst);
        }
    }
}

const PUBLICATION_LAYOUT_TAG: &str = "gkrm-staging-publication-v1";
const FINAL_VERIFICATION_TAG: &str = "gkrm-staging-final-verify-v1";

const DEFAULT_MAX_ENTRIES: usize = 20_000;
const DEFAULT_MAX_DIRECTORIES: usize = 20_000;
const DEFAULT_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DEFAULT_MAX_PATH_DEPTH: usize = 64;
const DEFAULT_MAX_PATH_COMPONENT_BYTES: usize = 255;

/// Opaque validated Task 20 options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedStagingOptions {
    max_entries: usize,
    max_directories: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_path_depth: usize,
    max_path_component_bytes: usize,
    baseline_store_limits: BaselineStoreLimits,
}

impl Default for TrustedStagingOptions {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_directories: DEFAULT_MAX_DIRECTORIES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_path_depth: DEFAULT_MAX_PATH_DEPTH,
            max_path_component_bytes: DEFAULT_MAX_PATH_COMPONENT_BYTES,
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl TrustedStagingOptions {
    pub fn try_new(
        max_entries: usize,
        max_directories: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
        max_path_depth: usize,
        max_path_component_bytes: usize,
        baseline_store_limits: BaselineStoreLimits,
    ) -> Result<Self> {
        let options = Self {
            max_entries,
            max_directories,
            max_file_bytes,
            max_total_bytes,
            max_path_depth,
            max_path_component_bytes,
            baseline_store_limits,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }
    pub fn max_directories(&self) -> usize {
        self.max_directories
    }
    pub fn max_file_bytes(&self) -> u64 {
        self.max_file_bytes
    }
    pub fn max_total_bytes(&self) -> u64 {
        self.max_total_bytes
    }
    pub fn max_path_depth(&self) -> usize {
        self.max_path_depth
    }
    pub fn max_path_component_bytes(&self) -> usize {
        self.max_path_component_bytes
    }
    pub fn baseline_store_limits(&self) -> BaselineStoreLimits {
        self.baseline_store_limits
    }

    pub(crate) fn validate(self) -> Result<()> {
        if self.max_entries == 0 {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_entries",
            });
        }
        if self.max_directories == 0 {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_directories",
            });
        }
        if self.max_file_bytes == 0 {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_file_bytes",
            });
        }
        if self.max_total_bytes == 0 {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_total_bytes",
            });
        }
        if self.max_file_bytes > self.max_total_bytes {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_file_bytes",
            });
        }
        if self.max_path_depth == 0 {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_path_depth",
            });
        }
        if self.max_path_component_bytes == 0 {
            return Err(GkrmError::TrustedStagingOptionsInvalid {
                limit: "max_path_component_bytes",
            });
        }
        self.baseline_store_limits.validate().map_err(|_| {
            GkrmError::TrustedStagingOptionsInvalid {
                limit: "baseline_store_limits",
            }
        })?;
        Ok(())
    }

    fn options_tag(self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.max_entries as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.max_directories as u64).to_le_bytes());
        bytes.extend_from_slice(&self.max_file_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.max_total_bytes.to_le_bytes());
        bytes.extend_from_slice(&(self.max_path_depth as u64).to_le_bytes());
        bytes.extend_from_slice(&(self.max_path_component_bytes as u64).to_le_bytes());
        bytes.extend_from_slice(
            &self
                .baseline_store_limits
                .max_manifest_bytes()
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&(self.baseline_store_limits.max_files() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.baseline_store_limits.max_blob_bytes().to_le_bytes());
        bytes.extend_from_slice(
            &self
                .baseline_store_limits
                .max_total_blob_bytes()
                .to_le_bytes(),
        );
        Ok(bytes)
    }
}

/// Bound Task 14–19 inputs for trusted staging.
pub struct TrustedStagingRequest<'a> {
    plan: &'a ThreeWayUpdatePlan,
    review: &'a ThreeWayPlanReview,
    analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
    text_diff: Option<&'a ThreeWayTextDiffPlan>,
    synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
    merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
    baseline: &'a ResolvedOfficialBaseline,
    installed_source: &'a InstalledStagingContentSource,
    incoming_source: &'a IncomingStagingContentSource,
    staging_root: &'a TrustedStagingRoot,
    options: TrustedStagingOptions,
    operator_merges: &'a [TrustedStagingOperatorMergeInput<'a>],
}

/// Minimal Task 25 operator-merge input accepted by staging (bytes already verified).
#[derive(Clone, Copy)]
pub struct TrustedStagingOperatorMergeInput<'a> {
    pub path: &'a ResourceRelativePath,
    pub artifact_id: Sha256Digest,
    pub content_digest: Sha256Digest,
    pub bytes: &'a [u8],
}

impl<'a> TrustedStagingRequest<'a> {
    pub fn try_new(
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: Option<&'a ThreeWayMergeAnalysisPlan>,
        text_diff: Option<&'a ThreeWayTextDiffPlan>,
        synthesis: Option<&'a ThreeWayMergeSynthesisPlan>,
        merged_bytes: Option<&'a ThreeWayMergedBytesPlan>,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledStagingContentSource,
        incoming_source: &'a IncomingStagingContentSource,
        staging_root: &'a TrustedStagingRoot,
        options: TrustedStagingOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            plan,
            review,
            analysis,
            text_diff,
            synthesis,
            merged_bytes,
            baseline,
            installed_source,
            incoming_source,
            staging_root,
            options,
            operator_merges: &[],
        })
    }

    /// Attach verified Task 25 operator-merge inputs (does not weaken Task 19 semantics).
    pub fn with_operator_merges(
        mut self,
        operator_merges: &'a [TrustedStagingOperatorMergeInput<'a>],
    ) -> Self {
        self.operator_merges = operator_merges;
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StagingFinalState {
    Installed,
    Incoming,
    Merged,
    Absent,
}

impl std::fmt::Debug for StagingFinalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Installed => "Installed",
            Self::Incoming => "Incoming",
            Self::Merged => "Merged",
            Self::Absent => "Absent",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StagingContentOrigin {
    Installed,
    Incoming,
    Merged,
    Absent,
}

impl std::fmt::Debug for StagingContentOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Installed => "Installed",
            Self::Incoming => "Incoming",
            Self::Merged => "Merged",
            Self::Absent => "Absent",
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum StagingSourceBinding {
    InstalledDigest(Sha256Digest),
    IncomingDigest(Sha256Digest),
    MergedArtifact(MergedByteArtifactId),
    /// Task 25 trusted operator-merge artifact ID digest.
    OperatorMerge(Sha256Digest),
    Absent,
}

impl std::fmt::Debug for StagingSourceBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstalledDigest(_) => f.write_str("StagingSourceBinding::Installed(..)"),
            Self::IncomingDigest(_) => f.write_str("StagingSourceBinding::Incoming(..)"),
            Self::MergedArtifact(_) => f.write_str("StagingSourceBinding::Merged(..)"),
            Self::OperatorMerge(_) => f.write_str("StagingSourceBinding::OperatorMerge(..)"),
            Self::Absent => f.write_str("StagingSourceBinding::Absent"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedStagingEntryId(pub(super) Sha256Digest);

impl TrustedStagingEntryId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl std::fmt::Debug for TrustedStagingEntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedStagingEntryId")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TrustedStagingEntry {
    pub(super) path: ResourceRelativePath,
    pub(super) final_state: StagingFinalState,
    pub(super) origin: StagingContentOrigin,
    pub(super) expected_digest: Option<Sha256Digest>,
    pub(super) expected_byte_length: Option<u64>,
    pub(super) source_binding: StagingSourceBinding,
    pub(super) entry_id: TrustedStagingEntryId,
}

impl std::fmt::Debug for TrustedStagingEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedStagingEntry")
            .field("state", &self.final_state)
            .finish_non_exhaustive()
    }
}

impl TrustedStagingEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }
    pub fn final_state(&self) -> StagingFinalState {
        self.final_state
    }
    pub fn origin(&self) -> StagingContentOrigin {
        self.origin
    }
    pub fn entry_id(&self) -> &TrustedStagingEntryId {
        &self.entry_id
    }

    pub(crate) fn expected_digest(&self) -> Option<&Sha256Digest> {
        self.expected_digest.as_ref()
    }

    pub(crate) fn expected_byte_length(&self) -> Option<u64> {
        self.expected_byte_length
    }

    pub(crate) fn source_binding(&self) -> &StagingSourceBinding {
        &self.source_binding
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedStagingManifestId(pub(super) Sha256Digest);

impl TrustedStagingManifestId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

impl std::fmt::Debug for TrustedStagingManifestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedStagingManifestId")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TrustedStagingManifest {
    pub(super) entries: Vec<TrustedStagingEntry>,
    pub(super) manifest_id: TrustedStagingManifestId,
    pub(super) plan_id: Sha256Digest,
    pub(super) review_id: Sha256Digest,
    pub(super) analysis_id: Option<Sha256Digest>,
    pub(super) text_diff_id: Option<Sha256Digest>,
    pub(super) synthesis_id: Option<Sha256Digest>,
    pub(super) merged_bytes_id: Option<Sha256Digest>,
}

impl std::fmt::Debug for TrustedStagingManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedStagingManifest")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl TrustedStagingManifest {
    pub fn entries(&self) -> &[TrustedStagingEntry] {
        &self.entries
    }
    pub fn manifest_id(&self) -> &TrustedStagingManifestId {
        &self.manifest_id
    }

    pub(crate) fn plan_id_digest(&self) -> &Sha256Digest {
        &self.plan_id
    }

    pub(crate) fn review_id_digest(&self) -> &Sha256Digest {
        &self.review_id
    }

    pub(crate) fn analysis_id_digest(&self) -> Option<&Sha256Digest> {
        self.analysis_id.as_ref()
    }

    pub(crate) fn text_diff_id_digest(&self) -> Option<&Sha256Digest> {
        self.text_diff_id.as_ref()
    }

    pub(crate) fn synthesis_id_digest(&self) -> Option<&Sha256Digest> {
        self.synthesis_id.as_ref()
    }

    pub(crate) fn merged_bytes_id_digest(&self) -> Option<&Sha256Digest> {
        self.merged_bytes_id.as_ref()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrustedStagingStatus {
    ReadyForApplyPlanning,
}

impl std::fmt::Debug for TrustedStagingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadyForApplyPlanning")
    }
}

impl std::fmt::Display for TrustedStagingStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadyForApplyPlanning")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TrustedStagingSummary {
    total_entries: usize,
    present_entries: usize,
    absent_entries: usize,
    installed_entries: usize,
    incoming_entries: usize,
    merged_entries: usize,
    total_bytes: u64,
}

impl std::fmt::Debug for TrustedStagingSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedStagingSummary")
            .field("total_entries", &self.total_entries)
            .field("present_entries", &self.present_entries)
            .field("absent_entries", &self.absent_entries)
            .finish_non_exhaustive()
    }
}

impl TrustedStagingSummary {
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }
    pub fn present_entries(&self) -> usize {
        self.present_entries
    }
    pub fn absent_entries(&self) -> usize {
        self.absent_entries
    }
    pub fn installed_entries(&self) -> usize {
        self.installed_entries
    }
    pub fn incoming_entries(&self) -> usize {
        self.incoming_entries
    }
    pub fn merged_entries(&self) -> usize {
        self.merged_entries
    }
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedStagingBundleId(Sha256Digest);

impl TrustedStagingBundleId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

impl std::fmt::Debug for TrustedStagingBundleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedStagingBundleId")
    }
}

/// Opaque published staging bundle retained for Task 21 rebinding.
pub struct TrustedStagingBundle {
    staging_root: TrustedStagingRoot,
    published_dir: cap_std::fs::Dir,
    resource_dir: cap_std::fs::Dir,
    manifest: TrustedStagingManifest,
    summary: TrustedStagingSummary,
    status: TrustedStagingStatus,
    bundle_id: TrustedStagingBundleId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedStagingPublicationEstimate {
    regular_file_bytes: u64,
    directory_entries: usize,
}

impl TrustedStagingPublicationEstimate {
    pub fn regular_file_bytes(&self) -> u64 {
        self.regular_file_bytes
    }

    pub fn directory_entries(&self) -> usize {
        self.directory_entries
    }
}

impl TrustedStagingBundle {
    pub fn manifest(&self) -> &TrustedStagingManifest {
        &self.manifest
    }
    pub fn summary(&self) -> &TrustedStagingSummary {
        &self.summary
    }
    pub fn status(&self) -> TrustedStagingStatus {
        self.status
    }
    pub fn bundle_id(&self) -> &TrustedStagingBundleId {
        &self.bundle_id
    }

    /// Crate-private published child capability for Task 21 apply planning.
    pub(crate) fn published_dir_for_apply_planning(&self) -> &cap_std::fs::Dir {
        &self.published_dir
    }

    pub(crate) fn resource_dir_for_apply_planning(&self) -> &cap_std::fs::Dir {
        &self.resource_dir
    }

    pub(crate) fn staging_root_for_apply_planning(&self) -> &TrustedStagingRoot {
        &self.staging_root
    }
}

impl std::fmt::Debug for TrustedStagingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedStagingBundle")
            .field("status", &self.status)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for TrustedStagingBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("trusted-staging-bundle")
    }
}

fn prepare_staging_manifest(
    request: &TrustedStagingRequest<'_>,
) -> Result<(TrustedStagingManifest, TrustedStagingSummary)> {
    request.options.validate()?;
    verify_plan_review_binding(request)?;
    verify_merge_chain_presence(request)?;
    verify_merge_chain_bindings(request)?;
    verify_baseline_binding(request)?;
    verify_review_completeness(request)?;
    verify_incoming_fingerprints(request)?;

    let mut entries = map_final_tree(
        request.plan.entries(),
        request.review.entries(),
        request.synthesis,
        request.merged_bytes,
        request.operator_merges,
    )?;
    enforce_structural_limits(&entries, request.options)?;
    ensure_staging_disjointness(request)?;
    request.staging_root.revalidate_identity()?;
    probe_present_lengths(&mut entries, request)?;
    assign_entry_ids(&mut entries, request.plan.plan_id().digest())?;

    let options_tag = request.options.options_tag()?;
    let analysis_id = request.analysis.map(|a| *a.analysis_id().digest());
    let text_diff_id = request.text_diff.map(|t| *t.text_diff_plan_id().digest());
    let synthesis_id = request.synthesis.map(|s| *s.synthesis_plan_id().digest());
    let merged_bytes_id = request
        .merged_bytes
        .map(|m| *m.merged_bytes_plan_id().digest());

    let manifest_id = encode_manifest_id(
        request.plan.plan_id().digest(),
        request.review.review_id().digest(),
        analysis_id.as_ref(),
        text_diff_id.as_ref(),
        synthesis_id.as_ref(),
        merged_bytes_id.as_ref(),
        request.plan.resource_key().as_str(),
        request.plan.baseline_id().as_str(),
        request.plan.installed_snapshot_fingerprint(),
        request.plan.incoming_package_fingerprint(),
        request.plan.incoming_resource_fingerprint(),
        &options_tag,
        &entries,
    )?;

    let summary = summarize(&entries)?;
    enforce_byte_limits(&entries, &summary, request.options)?;

    Ok((
        TrustedStagingManifest {
            entries,
            manifest_id,
            plan_id: *request.plan.plan_id().digest(),
            review_id: *request.review.review_id().digest(),
            analysis_id,
            text_diff_id,
            synthesis_id,
            merged_bytes_id,
        },
        summary,
    ))
}

/// Stage a complete trusted resource tree under an isolated staging root.
pub fn stage_trusted_resource(request: TrustedStagingRequest<'_>) -> Result<TrustedStagingBundle> {
    let (manifest, summary) = prepare_staging_manifest(&request)?;

    let (tmp_root, bundles_dir) = ensure_internal_layout(request.staging_root)?;
    let (published, guard) = write_and_publish(
        request.staging_root,
        &tmp_root,
        &bundles_dir,
        &manifest,
        request.installed_source,
        write::AuxiliaryContentSource::Package(request.incoming_source),
        request.merged_bytes,
        request.operator_merges,
    )?;

    let finished = (|| -> Result<TrustedStagingBundle> {
        #[cfg(test)]
        match take_post_publish_tail_fault() {
            Some(PostPublishTailFault::Disjointness) => {
                return Err(GkrmError::TrustedStagingRootOverlap);
            }
            Some(PostPublishTailFault::Identity) => {
                return Err(GkrmError::TrustedStagingRootReplaced);
            }
            Some(PostPublishTailFault::Reopen) => {
                return Err(GkrmError::TrustedStagingRootOverlap);
            }
            None => {}
        }

        ensure_staging_disjointness(&request)?;
        request.staging_root.revalidate_identity()?;

        let status = TrustedStagingStatus::ReadyForApplyPlanning;
        let bundle_id = encode_bundle_id(&manifest, &summary, status)?;
        let staging_root =
            TrustedStagingRoot::try_open(request.staging_root.path_for_disjointness())?;

        Ok(TrustedStagingBundle {
            staging_root,
            published_dir: published.published_dir,
            resource_dir: published.resource_dir,
            manifest,
            summary,
            status,
            bundle_id,
        })
    })();

    match finished {
        Ok(bundle) => {
            guard.disarm();
            Ok(bundle)
        }
        Err(primary) => Err(guard.fail_with_cleanup(primary)),
    }
}

pub(crate) fn reopen_trusted_staging_bundle_from_artifact(
    staging_root: &TrustedStagingRoot,
    body: &crate::TrustedCliUpdateArtifactBody,
    resource_key: &crate::SafeResourceKey,
    baseline_id: &crate::BaselineId,
    installed_fp: &Sha256Digest,
    incoming_pkg_fp: &Sha256Digest,
    incoming_res_fp: &Sha256Digest,
    options: TrustedStagingOptions,
) -> Result<TrustedStagingBundle> {
    reopen_staging_artifact_with_marker(
        staging_root,
        body,
        resource_key,
        baseline_id.as_str(),
        installed_fp,
        incoming_pkg_fp,
        incoming_res_fp,
        options,
    )
}

pub(crate) fn reopen_trusted_two_way_staging_bundle(
    staging_root: &TrustedStagingRoot,
    body: &crate::TrustedCliUpdateArtifactBody,
    plan: &crate::TwoWayUpdatePlan,
    options: TrustedStagingOptions,
) -> Result<TrustedStagingBundle> {
    if body.analysis_id.is_some()
        || body.text_diff_id.is_some()
        || body.synthesis_id.is_some()
        || body.merged_bytes_id.is_some()
        || &body.plan_id != plan.plan_id().digest()
    {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    reopen_staging_artifact_with_marker(
        staging_root,
        body,
        plan.resource_key(),
        two_way::TWO_WAY_BASELINE_MARKER,
        plan.installed_fingerprint(),
        plan.incoming_package_fingerprint(),
        plan.incoming_resource_fingerprint(),
        options,
    )
}

fn reopen_staging_artifact_with_marker(
    staging_root: &TrustedStagingRoot,
    body: &crate::TrustedCliUpdateArtifactBody,
    resource_key: &crate::SafeResourceKey,
    baseline_marker: &str,
    installed_fp: &Sha256Digest,
    incoming_pkg_fp: &Sha256Digest,
    incoming_res_fp: &Sha256Digest,
    options: TrustedStagingOptions,
) -> Result<TrustedStagingBundle> {
    options.validate()?;
    staging_root.revalidate_identity()?;
    let bundles_dir = try_open_child_dir(staging_root.dir(), "bundles")
        .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?
        .ok_or(GkrmError::TrustedStagingManifestTreeMismatch)?;
    let published_name = body.staging_manifest_id.to_string();
    crate::baseline::fs_security::validate_single_component(&published_name)
        .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?;
    let published_probe =
        crate::baseline::fs_security::open_child_dir(&bundles_dir, &published_name)
            .map_err(|_| GkrmError::TrustedStagingManifestTreeMismatch)?;
    let manifest_bytes = read_published_manifest_bytes(
        &published_probe,
        options.baseline_store_limits().max_manifest_bytes(),
    )?;
    let manifest = parse_manifest_bytes(
        &manifest_bytes,
        body.plan_id,
        body.review_id,
        body.analysis_id,
        body.text_diff_id,
        body.synthesis_id,
        body.merged_bytes_id,
        options.max_entries,
    )?;
    if manifest.manifest_id().digest() != &body.staging_manifest_id {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    for entry in manifest.entries() {
        let recomputed = encode_entry_id(&body.plan_id, entry)?;
        if recomputed.digest() != entry.entry_id().digest() {
            return Err(GkrmError::TrustedStagingManifestTreeMismatch);
        }
    }
    let options_tag = options.options_tag()?;
    let recomputed_manifest_id = encode_manifest_id(
        &body.plan_id,
        &body.review_id,
        body.analysis_id.as_ref(),
        body.text_diff_id.as_ref(),
        body.synthesis_id.as_ref(),
        body.merged_bytes_id.as_ref(),
        resource_key.as_str(),
        baseline_marker,
        installed_fp,
        incoming_pkg_fp,
        incoming_res_fp,
        &options_tag,
        manifest.entries(),
    )?;
    if recomputed_manifest_id.digest() != manifest.manifest_id().digest()
        || recomputed_manifest_id.digest() != &body.staging_manifest_id
    {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let summary = summarize(manifest.entries())?;
    enforce_byte_limits(&manifest.entries, &summary, options)?;
    let status = TrustedStagingStatus::ReadyForApplyPlanning;
    let bundle_id = encode_bundle_id(&manifest, &summary, status)?;
    if bundle_id.digest() != &body.staging_bundle_id {
        return Err(GkrmError::TrustedStagingManifestTreeMismatch);
    }
    let (published_dir, resource_dir) =
        revalidate_published_child(&bundles_dir, &published_name, &manifest)?;
    let staging_root = TrustedStagingRoot::try_open(staging_root.path_for_disjointness())?;
    Ok(TrustedStagingBundle {
        staging_root,
        published_dir,
        resource_dir,
        manifest,
        summary,
        status,
        bundle_id,
    })
}

pub fn estimate_trusted_staging_publication(
    request: &TrustedStagingRequest<'_>,
) -> Result<TrustedStagingPublicationEstimate> {
    let (manifest, summary) = prepare_staging_manifest(request)?;
    let manifest_len = u64::try_from(encode_manifest_bytes(&manifest)?.len())
        .map_err(|_| GkrmError::TrustedStagingArithmeticOverflow)?;
    let regular_file_bytes = summary
        .total_bytes()
        .checked_add(manifest_len)
        .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
    let mut directories = BTreeSet::new();
    // The publication path may create the staging internals and one immutable bundle.
    directories.insert(".tmp".to_owned());
    directories.insert("bundles".to_owned());
    directories.insert("bundles/<published>".to_owned());
    directories.insert("bundles/<published>/resource".to_owned());
    for entry in manifest.entries() {
        if entry.final_state() == StagingFinalState::Absent {
            continue;
        }
        let components: Vec<_> = entry.path().as_str().split('/').collect();
        let mut prefix = String::from("bundles/<published>/resource");
        for component in &components[..components.len().saturating_sub(1)] {
            prefix.push('/');
            prefix.push_str(component);
            directories.insert(prefix.clone());
        }
    }
    let file_entries = summary
        .present_entries()
        .checked_add(1)
        .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
    let directory_entries = directories
        .len()
        .checked_add(file_entries)
        .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
    Ok(TrustedStagingPublicationEstimate {
        regular_file_bytes,
        directory_entries,
    })
}

/// Reopen and verify a previously published staging bundle (read-only tree check).
///
/// Used by Task 25 apply/recover after `update plan` published the bundle. Does not
/// write, rename, or delete staging objects.
pub fn reopen_trusted_staging_bundle(
    request: TrustedStagingRequest<'_>,
) -> Result<TrustedStagingBundle> {
    let (manifest, summary) = prepare_staging_manifest(&request)?;
    request.staging_root.revalidate_identity()?;
    let bundles_dir = try_open_child_dir(request.staging_root.dir(), "bundles")
        .map_err(|_| GkrmError::TrustedStagingUnsafeFilesystemObject)?
        .ok_or(GkrmError::TrustedStagingSourceUnavailable)?;
    let published_name = manifest.manifest_id.digest().to_string();
    let (published_dir, resource_dir) =
        revalidate_published_child(&bundles_dir, &published_name, &manifest)?;
    ensure_staging_disjointness(&request)?;
    request.staging_root.revalidate_identity()?;

    let status = TrustedStagingStatus::ReadyForApplyPlanning;
    let bundle_id = encode_bundle_id(&manifest, &summary, status)?;
    let staging_root = TrustedStagingRoot::try_open(request.staging_root.path_for_disjointness())?;
    Ok(TrustedStagingBundle {
        staging_root,
        published_dir,
        resource_dir,
        manifest,
        summary,
        status,
        bundle_id,
    })
}

fn verify_plan_review_binding(request: &TrustedStagingRequest<'_>) -> Result<()> {
    let plan = request.plan;
    let review = request.review;
    if review.plan_id() != plan.plan_id()
        || review.resource_key() != plan.resource_key()
        || review.baseline_id() != plan.baseline_id()
        || review.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || review.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || review.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::TrustedStagingPlanReviewBindingMismatch);
    }
    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::TrustedStagingPlanReviewBindingMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::TrustedStagingPlanReviewBindingMismatch);
        }
    }
    Ok(())
}

fn merge_required(request: &TrustedStagingRequest<'_>) -> bool {
    request
        .review
        .entries()
        .iter()
        .any(|entry| entry.action() == ThreeWayReviewedAction::QueueMergeAnalysis)
}

fn verify_merge_chain_presence(request: &TrustedStagingRequest<'_>) -> Result<()> {
    let required = merge_required(request);
    let present = request.analysis.is_some()
        && request.text_diff.is_some()
        && request.synthesis.is_some()
        && request.merged_bytes.is_some();
    let absent = request.analysis.is_none()
        && request.text_diff.is_none()
        && request.synthesis.is_none()
        && request.merged_bytes.is_none();
    if required && !present {
        return Err(GkrmError::TrustedStagingMergeChainPresenceMismatch);
    }
    if !required && !absent {
        return Err(GkrmError::TrustedStagingMergeChainPresenceMismatch);
    }
    Ok(())
}

fn verify_merge_chain_bindings(request: &TrustedStagingRequest<'_>) -> Result<()> {
    if !merge_required(request) {
        return Ok(());
    }
    let plan = request.plan;
    let review = request.review;
    let analysis = request
        .analysis
        .ok_or(GkrmError::TrustedStagingMergeChainPresenceMismatch)?;
    let text_diff = request
        .text_diff
        .ok_or(GkrmError::TrustedStagingMergeChainPresenceMismatch)?;
    let synthesis = request
        .synthesis
        .ok_or(GkrmError::TrustedStagingMergeChainPresenceMismatch)?;
    let merged_bytes = request
        .merged_bytes
        .ok_or(GkrmError::TrustedStagingMergeChainPresenceMismatch)?;

    if analysis.plan_id() != plan.plan_id()
        || analysis.resource_key() != plan.resource_key()
        || analysis.baseline_id() != plan.baseline_id()
        || analysis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
        || analysis.review_id() != review.review_id()
    {
        return Err(GkrmError::TrustedStagingMergeChainBindingMismatch);
    }
    if text_diff.plan_id() != plan.plan_id()
        || text_diff.resource_key() != plan.resource_key()
        || text_diff.baseline_id() != plan.baseline_id()
        || text_diff.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || text_diff.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || text_diff.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
        || text_diff.review_id() != review.review_id()
        || text_diff.analysis_id() != analysis.analysis_id()
    {
        return Err(GkrmError::TrustedStagingMergeChainBindingMismatch);
    }
    if synthesis.plan_id() != plan.plan_id()
        || synthesis.resource_key() != plan.resource_key()
        || synthesis.baseline_id() != plan.baseline_id()
        || synthesis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || synthesis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || synthesis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
        || synthesis.review_id() != review.review_id()
        || synthesis.analysis_id() != analysis.analysis_id()
        || synthesis.text_diff_plan_id() != text_diff.text_diff_plan_id()
    {
        return Err(GkrmError::TrustedStagingMergeChainBindingMismatch);
    }
    if merged_bytes.plan_id() != plan.plan_id()
        || merged_bytes.resource_key() != plan.resource_key()
        || merged_bytes.baseline_id() != plan.baseline_id()
        || merged_bytes.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || merged_bytes.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || merged_bytes.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
        || merged_bytes.review_id() != review.review_id()
        || merged_bytes.analysis_id() != analysis.analysis_id()
        || merged_bytes.text_diff_plan_id() != text_diff.text_diff_plan_id()
        || merged_bytes.synthesis_plan_id() != synthesis.synthesis_plan_id()
    {
        return Err(GkrmError::TrustedStagingMergeChainBindingMismatch);
    }
    Ok(())
}

fn verify_baseline_binding(request: &TrustedStagingRequest<'_>) -> Result<()> {
    if request.baseline.resource_key() != request.plan.resource_key()
        || request.baseline.baseline_id() != request.plan.baseline_id()
    {
        return Err(GkrmError::TrustedStagingBaselineMismatch);
    }
    Ok(())
}

fn verify_review_completeness(request: &TrustedStagingRequest<'_>) -> Result<()> {
    if request.review.status() == ThreeWayPlanReviewStatus::Incomplete {
        return Err(GkrmError::TrustedStagingReviewUnresolved);
    }
    for entry in request.review.entries() {
        match entry.action() {
            ThreeWayReviewedAction::Pending => {
                return Err(GkrmError::TrustedStagingReviewUnresolved);
            }
            ThreeWayReviewedAction::ManualReview => {
                if !request
                    .operator_merges
                    .iter()
                    .any(|m| m.path == entry.path())
                {
                    return Err(GkrmError::TrustedStagingReviewUnresolved);
                }
            }
            ThreeWayReviewedAction::QueueMergeAnalysis => {
                let merged = request
                    .merged_bytes
                    .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                let mb = merged
                    .entries()
                    .iter()
                    .find(|e| e.path() == entry.path())
                    .ok_or(GkrmError::TrustedStagingMissingMergedArtifact)?;
                match mb.disposition() {
                    MergedByteDisposition::ReadyForStaging => {
                        if mb.artifact().is_none() || mb.artifact_id().is_none() {
                            return Err(GkrmError::TrustedStagingMissingMergedArtifact);
                        }
                    }
                    MergedByteDisposition::ManualReviewOutputLimit => {
                        if !request
                            .operator_merges
                            .iter()
                            .any(|m| m.path == entry.path())
                        {
                            return Err(GkrmError::TrustedStagingManualMergeResult);
                        }
                    }
                }
            }
            ThreeWayReviewedAction::UseIncomingState
            | ThreeWayReviewedAction::PreserveInstalledState
            | ThreeWayReviewedAction::NotRequired => {}
        }
    }
    Ok(())
}

fn verify_incoming_fingerprints(request: &TrustedStagingRequest<'_>) -> Result<()> {
    if request.incoming_source.package_fingerprint() != request.plan.incoming_package_fingerprint()
        || request.incoming_source.resource_fingerprint()
            != request.plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::TrustedStagingSourceUnavailable);
    }
    Ok(())
}

fn probe_present_lengths(
    entries: &mut [TrustedStagingEntry],
    request: &TrustedStagingRequest<'_>,
) -> Result<()> {
    probe_present_lengths_from_sources(entries, request.installed_source, request.incoming_source)
}

/// Fill in every present entry's byte length by streaming it from the side it will come from.
///
/// Shared with the two-way path, which has the same content sources but no three-way request.
fn probe_present_lengths_from_sources(
    entries: &mut [TrustedStagingEntry],
    installed_source: &InstalledStagingContentSource,
    incoming_source: &IncomingStagingContentSource,
) -> Result<()> {
    for entry in entries.iter_mut() {
        if entry.final_state == StagingFinalState::Absent {
            continue;
        }
        if entry.expected_byte_length.is_some() {
            continue;
        }
        let digest = entry
            .expected_digest
            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
        let len = match entry.final_state {
            StagingFinalState::Installed => {
                installed_source.stream_verified(entry.path(), digest, |_| Ok(()))?
            }
            StagingFinalState::Incoming => {
                incoming_source.stream_verified(entry.path(), digest, |_| Ok(()))?
            }
            StagingFinalState::Merged | StagingFinalState::Absent => {
                return Err(GkrmError::TrustedStagingFinalTreeRejected);
            }
        };
        entry.expected_byte_length = Some(len);
    }
    Ok(())
}

fn summarize(entries: &[TrustedStagingEntry]) -> Result<TrustedStagingSummary> {
    let mut present = 0usize;
    let mut absent = 0usize;
    let mut installed = 0usize;
    let mut incoming = 0usize;
    let mut merged = 0usize;
    let mut total_bytes = 0u64;
    for entry in entries {
        match entry.final_state {
            StagingFinalState::Absent => absent = absent.saturating_add(1),
            StagingFinalState::Installed => {
                present = present.saturating_add(1);
                installed = installed.saturating_add(1);
                total_bytes = total_bytes
                    .checked_add(
                        entry
                            .expected_byte_length
                            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?,
                    )
                    .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
            }
            StagingFinalState::Incoming => {
                present = present.saturating_add(1);
                incoming = incoming.saturating_add(1);
                total_bytes = total_bytes
                    .checked_add(
                        entry
                            .expected_byte_length
                            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?,
                    )
                    .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
            }
            StagingFinalState::Merged => {
                present = present.saturating_add(1);
                merged = merged.saturating_add(1);
                total_bytes = total_bytes
                    .checked_add(
                        entry
                            .expected_byte_length
                            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?,
                    )
                    .ok_or(GkrmError::TrustedStagingArithmeticOverflow)?;
            }
        }
    }
    Ok(TrustedStagingSummary {
        total_entries: entries.len(),
        present_entries: present,
        absent_entries: absent,
        installed_entries: installed,
        incoming_entries: incoming,
        merged_entries: merged,
        total_bytes,
    })
}

#[cfg(test)]
pub(crate) fn frozen_task21_v1_staging_fixture_for_test(
    mutate_merged_binding: bool,
) -> (
    std::collections::BTreeMap<ResourceRelativePath, StagingSourceBinding>,
    TrustedStagingBundleId,
    TrustedStagingManifestId,
) {
    let digest = |byte| Sha256Digest::new([byte; 32]);
    let path = |value: &str| ResourceRelativePath::try_from_slash_str(value).unwrap();
    let present = |value: &str,
                   state: StagingFinalState,
                   origin: StagingContentOrigin,
                   byte: u8,
                   binding: StagingSourceBinding,
                   byte_length: u64| TrustedStagingEntry {
        path: path(value),
        final_state: state,
        origin,
        expected_digest: Some(digest(byte)),
        expected_byte_length: Some(byte_length),
        source_binding: binding,
        entry_id: TrustedStagingEntryId(digest(0)),
    };
    // Production-shaped Task 20 entries: block/create/replace come from incoming
    // digests; the two `*/a.lua` files come from merged-byte artifacts; the two
    // remaining nested/sibling writes come from operator-merge artifacts; and
    // remove.lua is the canonical absent entry. The mutation changes only the
    // merged artifact authority for file-to-dir/a.lua while retaining its final
    // digest and byte length.
    let mut entries = vec![
        present(
            "block",
            StagingFinalState::Incoming,
            StagingContentOrigin::Incoming,
            5,
            StagingSourceBinding::IncomingDigest(digest(5)),
            5,
        ),
        present(
            "create.lua",
            StagingFinalState::Incoming,
            StagingContentOrigin::Incoming,
            6,
            StagingSourceBinding::IncomingDigest(digest(6)),
            6,
        ),
        present(
            "file-to-dir/a.lua",
            StagingFinalState::Merged,
            StagingContentOrigin::Merged,
            7,
            StagingSourceBinding::MergedArtifact(MergedByteArtifactId::from_digest(digest(
                if mutate_merged_binding { 0xd7 } else { 0xa7 },
            ))),
            7,
        ),
        present(
            "file-to-dir/deep/z.lua",
            StagingFinalState::Merged,
            StagingContentOrigin::Merged,
            8,
            StagingSourceBinding::OperatorMerge(digest(0xa8)),
            8,
        ),
        TrustedStagingEntry {
            path: path("remove.lua"),
            final_state: StagingFinalState::Absent,
            origin: StagingContentOrigin::Absent,
            expected_digest: None,
            expected_byte_length: None,
            source_binding: StagingSourceBinding::Absent,
            entry_id: TrustedStagingEntryId(digest(0)),
        },
        present(
            "replace.lua",
            StagingFinalState::Incoming,
            StagingContentOrigin::Incoming,
            9,
            StagingSourceBinding::IncomingDigest(digest(9)),
            9,
        ),
        present(
            "siblings/a.lua",
            StagingFinalState::Merged,
            StagingContentOrigin::Merged,
            10,
            StagingSourceBinding::MergedArtifact(MergedByteArtifactId::from_digest(digest(0xaa))),
            10,
        ),
        present(
            "siblings/b.lua",
            StagingFinalState::Merged,
            StagingContentOrigin::Merged,
            11,
            StagingSourceBinding::OperatorMerge(digest(0xab)),
            11,
        ),
    ];
    entries.sort_by(|left, right| left.path.cmp(&right.path));

    let plan_id = digest(0x31);
    let review_id = digest(0x32);
    let analysis_id = digest(0x33);
    let text_diff_id = digest(0x34);
    let synthesis_id = digest(0x35);
    let merged_bytes_id = digest(0x36);
    assign_entry_ids(&mut entries, &plan_id).unwrap();
    let options_tag = TrustedStagingOptions::default().options_tag().unwrap();
    let manifest_id = encode_manifest_id(
        &plan_id,
        &review_id,
        Some(&analysis_id),
        Some(&text_diff_id),
        Some(&synthesis_id),
        Some(&merged_bytes_id),
        "gksphone",
        "3131313131313131313131313131313131313131313131313131313131313131",
        &digest(0x37),
        &digest(0x38),
        &digest(0x39),
        &options_tag,
        &entries,
    )
    .unwrap();
    let manifest = TrustedStagingManifest {
        entries,
        manifest_id,
        plan_id,
        review_id,
        analysis_id: Some(analysis_id),
        text_diff_id: Some(text_diff_id),
        synthesis_id: Some(synthesis_id),
        merged_bytes_id: Some(merged_bytes_id),
    };
    let summary = summarize(manifest.entries()).unwrap();
    let bundle_id = encode_bundle_id(
        &manifest,
        &summary,
        TrustedStagingStatus::ReadyForApplyPlanning,
    )
    .unwrap();
    let bindings = manifest
        .entries()
        .iter()
        .filter(|entry| entry.final_state() != StagingFinalState::Absent)
        .map(|entry| (entry.path().clone(), entry.source_binding().clone()))
        .collect();
    (bindings, bundle_id, manifest_id)
}

fn enforce_structural_limits(
    entries: &[TrustedStagingEntry],
    options: TrustedStagingOptions,
) -> Result<()> {
    if entries.len() > options.max_entries {
        return Err(GkrmError::TrustedStagingLimitExceeded {
            limit: "max_entries",
        });
    }
    let mut directories = BTreeSet::new();
    for entry in entries {
        let components: Vec<_> = entry.path().as_str().split('/').collect();
        if components.len() > options.max_path_depth {
            return Err(GkrmError::TrustedStagingLimitExceeded {
                limit: "max_path_depth",
            });
        }
        for component in &components {
            if component.len() > options.max_path_component_bytes {
                return Err(GkrmError::TrustedStagingLimitExceeded {
                    limit: "max_path_component_bytes",
                });
            }
        }
        if components.len() > 1 {
            let mut prefix = String::new();
            for component in &components[..components.len() - 1] {
                if prefix.is_empty() {
                    prefix.push_str(component);
                } else {
                    prefix.push('/');
                    prefix.push_str(component);
                }
                directories.insert(prefix.clone());
            }
        }
        // Known lengths (merged artifacts) are enforced before probe.
        if let Some(len) = entry.expected_byte_length {
            if len > options.max_file_bytes {
                return Err(GkrmError::TrustedStagingLimitExceeded {
                    limit: "max_file_bytes",
                });
            }
        }
    }
    if directories.len() > options.max_directories {
        return Err(GkrmError::TrustedStagingLimitExceeded {
            limit: "max_directories",
        });
    }
    Ok(())
}

fn enforce_byte_limits(
    entries: &[TrustedStagingEntry],
    summary: &TrustedStagingSummary,
    options: TrustedStagingOptions,
) -> Result<()> {
    if summary.total_bytes > options.max_total_bytes {
        return Err(GkrmError::TrustedStagingLimitExceeded {
            limit: "max_total_bytes",
        });
    }
    for entry in entries {
        if entry.final_state == StagingFinalState::Absent {
            continue;
        }
        let len = entry
            .expected_byte_length
            .ok_or(GkrmError::TrustedStagingFinalTreeRejected)?;
        if len > options.max_file_bytes {
            return Err(GkrmError::TrustedStagingLimitExceeded {
                limit: "max_file_bytes",
            });
        }
    }
    Ok(())
}

fn ensure_staging_disjointness(request: &TrustedStagingRequest<'_>) -> Result<()> {
    let staging = request.staging_root.path_for_disjointness();
    let installed = request.installed_source.installed_root_path();
    let store = request.baseline.stored_baseline().store_root();
    let package = request.incoming_source.package_path();

    ensure_baseline_store_disjoint_from_installed(staging, installed)
        .map_err(|_| GkrmError::TrustedStagingRootOverlap)?;
    ensure_baseline_store_disjoint_from_installed(staging, store)
        .map_err(|_| GkrmError::TrustedStagingRootOverlap)?;

    if request.staging_root.identity() == request.installed_source.root_identity()
        || request.staging_root.identity() == request.installed_source.resource_identity()
    {
        return Err(GkrmError::TrustedStagingRootOverlap);
    }
    if paths_equal_loose(staging, package) || path_is_within(package, staging)? {
        return Err(GkrmError::TrustedStagingRootOverlap);
    }
    Ok(())
}

fn paths_equal_loose(left: &Path, right: &Path) -> bool {
    left == right
}

/// Fail closed: canonicalize failure is treated as overlap (not disjoint).
fn path_is_within(inner: &Path, outer: &Path) -> Result<bool> {
    let inner = inner
        .canonicalize()
        .map_err(|_| GkrmError::TrustedStagingRootOverlap)?;
    let outer = outer
        .canonicalize()
        .map_err(|_| GkrmError::TrustedStagingRootOverlap)?;
    Ok(inner.starts_with(outer))
}

pub(crate) fn encode_bundle_id(
    manifest: &TrustedStagingManifest,
    summary: &TrustedStagingSummary,
    status: TrustedStagingStatus,
) -> Result<TrustedStagingBundleId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-trusted-staging-bundle-v1")
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(manifest.manifest_id.digest());
    encoder
        .string(PUBLICATION_LAYOUT_TAG)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.digest(&manifest.plan_id);
    encoder.digest(&manifest.review_id);
    match &manifest.analysis_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    match &manifest.text_diff_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    match &manifest.synthesis_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    match &manifest.merged_bytes_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id);
        }
        None => encoder.u8(0),
    }
    encoder.u8(encode_status(status));
    encoder
        .usize(summary.total_entries)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .usize(summary.present_entries)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .usize(summary.absent_entries)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .usize(summary.installed_entries)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .usize(summary.incoming_entries)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder
        .usize(summary.merged_entries)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    encoder.u64(summary.total_bytes);
    encoder
        .string(FINAL_VERIFICATION_TAG)
        .map_err(|_| GkrmError::TrustedStagingIdEncodingFailure)?;
    Ok(TrustedStagingBundleId(encoder.finish()))
}
