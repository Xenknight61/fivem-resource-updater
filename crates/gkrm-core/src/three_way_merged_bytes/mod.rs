//! Trusted, deterministic, in-memory merged-byte synthesis (Milestone 2 Task 19).

#![allow(clippy::type_complexity, clippy::too_many_arguments)]

mod encode;
mod id;
mod replay;

#[cfg(test)]
mod verification_tests;

use crate::baseline::store::stream_verified_blob_for_path;
use crate::baseline::BaselineStoreLimits;
use crate::merge_content::{StreamingByteBudget, VerifiedMergeText, VerifiedMergeTextBuilder};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::three_way_merge_synthesis::{
    encode_operation_id, FinalTextEnvelope, MergeSynthesisDisposition, MergeSynthesisOperation,
    MergeSynthesisOperationKind, ThreeWayMergeSynthesisEntry, ThreeWayMergeSynthesisPlan,
    ThreeWayMergeSynthesisPlanId,
};
use crate::three_way_text_diff::{
    commitment_for_range, split_logical_lines, SupportedTextNewlineStyle, TextDiffHunk,
    TextTerminalNewline, ThreeWayTextDiffDisposition, ThreeWayTextDiffEntry, ThreeWayTextDiffPlan,
    ThreeWayTextDiffPlanId, ThreeWayTextEnvelopePlanState, ThreeWayTextOverlapClassification,
};
use crate::{
    BaselineEscrowClass, BaselineId, EscrowPolicyTransition, GkrmError, IncomingMergeContentSource,
    InstalledMergeContentSource, MergeContentAnalysis, MergeNewlineStyle, ResolvedOfficialBaseline,
    ResourceRelativePath, Result, SafeResourceKey, Sha256Digest, ThreeWayFileState,
    ThreeWayMergeAlgorithm, ThreeWayMergeAnalysisDisposition, ThreeWayMergeAnalysisEntry,
    ThreeWayMergeAnalysisId, ThreeWayMergeAnalysisPlan, ThreeWayPlanDisposition, ThreeWayPlanId,
    ThreeWayPlanReview, ThreeWayPlanReviewId, ThreeWayReviewedAction, ThreeWayUpdatePlan,
};
use sha2::Digest;
use std::collections::BTreeSet;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
#[cfg(test)]
use std::thread::ThreadId;

#[cfg(test)]
struct MergedBytesTestHooks {
    owner: ThreadId,
    baseline_reads: AtomicUsize,
    installed_scans: AtomicUsize,
    installed_reads: AtomicUsize,
    incoming_validates: AtomicUsize,
    incoming_reads: AtomicUsize,
    between_entries: Option<Box<dyn FnMut(usize) + Send>>,
}

#[cfg(test)]
impl MergedBytesTestHooks {
    fn new() -> Self {
        Self {
            owner: std::thread::current().id(),
            baseline_reads: AtomicUsize::new(0),
            installed_scans: AtomicUsize::new(0),
            installed_reads: AtomicUsize::new(0),
            incoming_validates: AtomicUsize::new(0),
            incoming_reads: AtomicUsize::new(0),
            between_entries: None,
        }
    }
}

#[cfg(test)]
static MERGED_BYTES_HOOK_LOCK: Mutex<()> = Mutex::new(());
#[cfg(test)]
static MERGED_BYTES_HOOKS: Mutex<Option<MergedBytesTestHooks>> = Mutex::new(None);
#[cfg(test)]
static MERGED_BYTE_ARTIFACT_LIVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
fn lock_hook_state() -> MutexGuard<'static, Option<MergedBytesTestHooks>> {
    MERGED_BYTES_HOOKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
struct MergedBytesHookGuard {
    _guard: MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for MergedBytesHookGuard {
    fn drop(&mut self) {
        *lock_hook_state() = None;
    }
}

#[cfg(test)]
fn lock_merged_bytes_hooks() -> MergedBytesHookGuard {
    let guard = MERGED_BYTES_HOOK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *lock_hook_state() = Some(MergedBytesTestHooks::new());
    MergedBytesHookGuard { _guard: guard }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct MergedBytesIoCounters {
    baseline_reads: usize,
    installed_scans: usize,
    installed_reads: usize,
    incoming_validates: usize,
    incoming_reads: usize,
}

#[cfg(test)]
impl MergedBytesIoCounters {
    fn total_source_io(&self) -> usize {
        self.baseline_reads
            + self.installed_scans
            + self.installed_reads
            + self.incoming_validates
            + self.incoming_reads
    }
}

#[cfg(test)]
fn snapshot_io_counters() -> MergedBytesIoCounters {
    let hooks = lock_hook_state();
    let Some(hooks) = hooks.as_ref() else {
        return MergedBytesIoCounters::default();
    };
    if hooks.owner != std::thread::current().id() {
        return MergedBytesIoCounters::default();
    }
    MergedBytesIoCounters {
        baseline_reads: hooks.baseline_reads.load(Ordering::SeqCst),
        installed_scans: hooks.installed_scans.load(Ordering::SeqCst),
        installed_reads: hooks.installed_reads.load(Ordering::SeqCst),
        incoming_validates: hooks.incoming_validates.load(Ordering::SeqCst),
        incoming_reads: hooks.incoming_reads.load(Ordering::SeqCst),
    }
}

#[cfg(test)]
fn set_between_entries_hook(hook: impl FnMut(usize) + Send + 'static) {
    let mut hooks = lock_hook_state();
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            hooks.between_entries = Some(Box::new(hook));
        }
    }
}

#[cfg(test)]
fn note_baseline_read() {
    if let Some(hooks) = lock_hook_state().as_ref() {
        if hooks.owner == std::thread::current().id() {
            hooks.baseline_reads.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
fn note_installed_scan() {
    if let Some(hooks) = lock_hook_state().as_ref() {
        if hooks.owner == std::thread::current().id() {
            hooks.installed_scans.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
fn note_installed_read() {
    if let Some(hooks) = lock_hook_state().as_ref() {
        if hooks.owner == std::thread::current().id() {
            hooks.installed_reads.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
fn note_incoming_validate() {
    if let Some(hooks) = lock_hook_state().as_ref() {
        if hooks.owner == std::thread::current().id() {
            hooks.incoming_validates.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
fn note_incoming_read() {
    if let Some(hooks) = lock_hook_state().as_ref() {
        if hooks.owner == std::thread::current().id() {
            hooks.incoming_reads.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
fn run_between_entries_hook(completed: usize) {
    let mut hooks = lock_hook_state();
    if let Some(hooks) = hooks.as_mut() {
        if hooks.owner == std::thread::current().id() {
            if let Some(hook) = hooks.between_entries.as_mut() {
                hook(completed);
            }
        }
    }
}

#[cfg(not(test))]
fn note_baseline_read() {}
#[cfg(not(test))]
fn note_installed_scan() {}
#[cfg(not(test))]
fn note_installed_read() {}
#[cfg(not(test))]
fn note_incoming_validate() {}
#[cfg(not(test))]
fn note_incoming_read() {}
#[cfg(not(test))]
fn run_between_entries_hook(_completed: usize) {}

#[cfg(test)]
fn live_merged_byte_artifacts() -> usize {
    MERGED_BYTE_ARTIFACT_LIVE.load(Ordering::SeqCst)
}

use self::encode::{synthesize_output_artifact, EncodeOutcome};
use self::id::{encode_disposition, encode_newline, encode_status, encode_terminal_newline};
use self::replay::replay_synthesis_operations;

const DEFAULT_MAX_CANDIDATES: usize = 1_000;
const DEFAULT_MAX_SOURCE_BYTES_PER_FILE: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_BYTES_PER_FILE: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_MAX_LINES_PER_SOURCE: usize = 200_000;
const DEFAULT_MAX_TOTAL_LINES: usize = 600_000;

/// Opaque validated Task 19 options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreeWayMergedBytesOptions {
    max_candidates: usize,
    max_source_bytes_per_file: u64,
    max_total_source_bytes: u64,
    max_output_bytes_per_file: u64,
    max_total_output_bytes: u64,
    max_lines_per_source: usize,
    max_total_lines: usize,
    baseline_store_limits: BaselineStoreLimits,
}

/// Which side a surviving merged line came from.
///
/// Presentation only. The merge is decided by verified Task 18 operations; this records what
/// those operations did so an operator can be shown why their file looks the way it will.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergedLineOrigin {
    /// Unchanged since the official baseline.
    Baseline,
    /// The operator's own line survived.
    Installed,
    /// The incoming official line was taken.
    Incoming,
    /// Both sides made the same change.
    Converged,
}

/// A bounded, line-level view of one merged file, for operator display.
///
/// Only produced for paths the caller explicitly allow-listed through
/// [`ThreeWayMergedBytesOptions::with_line_view_paths`]. Escrow-protected vendor content must
/// never reach this type: the baseline store does not even retain it, and the caller is
/// responsible for allow-listing escrow-ignored paths only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedLineView {
    lines: Vec<MergedLine>,
    truncated: bool,
}

impl MergedLineView {
    pub fn lines(&self) -> &[MergedLine] {
        &self.lines
    }

    /// True when the file had more lines than the view limit and the tail was dropped.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One line of a [`MergedLineView`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedLine {
    origin: MergedLineOrigin,
    text: String,
    truncated: bool,
}

impl MergedLine {
    pub fn origin(&self) -> MergedLineOrigin {
        self.origin
    }

    /// Sanitized line text: valid UTF-8, control characters removed, bounded length.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// True when the individual line exceeded the per-line limit and was cut.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Hard ceiling on lines exposed per file, independent of the merge limits.
pub const MERGED_LINE_VIEW_MAX_LINES: usize = 400;
/// Hard ceiling on characters exposed per line.
pub const MERGED_LINE_VIEW_MAX_LINE_CHARS: usize = 240;

/// Build a bounded, sanitized view from replayed lines and their origins.
///
/// Non-UTF-8 input is refused rather than lossily converted: a lossy rendering would show the
/// operator text that is not in their file. Control characters other than tab are dropped so a
/// crafted line cannot rewrite the surrounding display.
fn build_line_view(lines: &[Vec<u8>], origins: &[MergedLineOrigin]) -> Result<MergedLineView> {
    if lines.len() != origins.len() {
        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
    }
    let truncated = lines.len() > MERGED_LINE_VIEW_MAX_LINES;
    let mut view_lines = Vec::with_capacity(lines.len().min(MERGED_LINE_VIEW_MAX_LINES));
    for (bytes, origin) in lines.iter().zip(origins).take(MERGED_LINE_VIEW_MAX_LINES) {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| GkrmError::ThreeWayMergedBytesReplayInvariant)?;
        let sanitized: String = text
            .chars()
            .filter(|character| *character == '\t' || !character.is_control())
            .collect();
        let mut cut = sanitized.chars().count() > MERGED_LINE_VIEW_MAX_LINE_CHARS;
        let mut clipped: String = sanitized
            .chars()
            .take(MERGED_LINE_VIEW_MAX_LINE_CHARS)
            .collect();
        if clipped.len() != sanitized.len() {
            cut = true;
        }
        clipped.shrink_to_fit();
        view_lines.push(MergedLine {
            origin: *origin,
            text: clipped,
            truncated: cut,
        });
    }
    Ok(MergedLineView {
        lines: view_lines,
        truncated,
    })
}

impl Default for ThreeWayMergedBytesOptions {
    fn default() -> Self {
        Self {
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_source_bytes_per_file: DEFAULT_MAX_SOURCE_BYTES_PER_FILE,
            max_total_source_bytes: DEFAULT_MAX_TOTAL_SOURCE_BYTES,
            max_output_bytes_per_file: DEFAULT_MAX_OUTPUT_BYTES_PER_FILE,
            max_total_output_bytes: DEFAULT_MAX_TOTAL_OUTPUT_BYTES,
            max_lines_per_source: DEFAULT_MAX_LINES_PER_SOURCE,
            max_total_lines: DEFAULT_MAX_TOTAL_LINES,
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl ThreeWayMergedBytesOptions {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        max_candidates: usize,
        max_source_bytes_per_file: u64,
        max_total_source_bytes: u64,
        max_output_bytes_per_file: u64,
        max_total_output_bytes: u64,
        max_lines_per_source: usize,
        max_total_lines: usize,
        baseline_store_limits: BaselineStoreLimits,
    ) -> Result<Self> {
        let options = Self {
            max_candidates,
            max_source_bytes_per_file,
            max_total_source_bytes,
            max_output_bytes_per_file,
            max_total_output_bytes,
            max_lines_per_source,
            max_total_lines,
            baseline_store_limits,
        };
        options.validate()?;
        Ok(options)
    }

    pub fn max_candidates(&self) -> usize {
        self.max_candidates
    }
    pub fn max_source_bytes_per_file(&self) -> u64 {
        self.max_source_bytes_per_file
    }
    pub fn max_total_source_bytes(&self) -> u64 {
        self.max_total_source_bytes
    }
    pub fn max_output_bytes_per_file(&self) -> u64 {
        self.max_output_bytes_per_file
    }
    pub fn max_total_output_bytes(&self) -> u64 {
        self.max_total_output_bytes
    }
    pub fn max_lines_per_source(&self) -> usize {
        self.max_lines_per_source
    }
    pub fn max_total_lines(&self) -> usize {
        self.max_total_lines
    }
    pub fn baseline_store_limits(&self) -> &BaselineStoreLimits {
        &self.baseline_store_limits
    }

    fn validate(self) -> Result<()> {
        for (value, name) in [
            (self.max_candidates, "max_candidates"),
            (self.max_lines_per_source, "max_lines_per_source"),
            (self.max_total_lines, "max_total_lines"),
        ] {
            if value == 0 {
                return Err(GkrmError::ThreeWayMergedBytesOptionsInvalid { limit: name });
            }
        }
        for (value, name) in [
            (self.max_source_bytes_per_file, "max_source_bytes_per_file"),
            (self.max_total_source_bytes, "max_total_source_bytes"),
            (self.max_output_bytes_per_file, "max_output_bytes_per_file"),
            (self.max_total_output_bytes, "max_total_output_bytes"),
        ] {
            if value == 0 {
                return Err(GkrmError::ThreeWayMergedBytesOptionsInvalid { limit: name });
            }
        }
        if self.max_source_bytes_per_file > self.max_total_source_bytes {
            return Err(GkrmError::ThreeWayMergedBytesOptionsInvalid {
                limit: "max_source_bytes_per_file",
            });
        }
        if self.max_output_bytes_per_file > self.max_total_output_bytes {
            return Err(GkrmError::ThreeWayMergedBytesOptionsInvalid {
                limit: "max_output_bytes_per_file",
            });
        }
        if self.max_lines_per_source > self.max_total_lines {
            return Err(GkrmError::ThreeWayMergedBytesOptionsInvalid {
                limit: "max_lines_per_source",
            });
        }
        Ok(())
    }
}

/// Opaque Task 19 request.
pub struct ThreeWayMergedBytesRequest<'a> {
    plan: &'a ThreeWayUpdatePlan,
    review: &'a ThreeWayPlanReview,
    analysis: &'a ThreeWayMergeAnalysisPlan,
    text_diff: &'a ThreeWayTextDiffPlan,
    synthesis: &'a ThreeWayMergeSynthesisPlan,
    baseline: &'a ResolvedOfficialBaseline,
    installed_source: &'a InstalledMergeContentSource,
    incoming_source: &'a IncomingMergeContentSource,
    options: ThreeWayMergedBytesOptions,
    /// Paths allowed to produce an operator-facing line view.
    ///
    /// This is the entire boundary for exposing merged file content. It is empty unless a
    /// caller opts in through [`ThreeWayMergedBytesRequest::with_line_view_paths`], so a caller
    /// that does nothing never receives any line text. Callers must allow-list escrow-ignored
    /// paths only; escrow-protected vendor content is not retained and must never be surfaced.
    line_view_paths: BTreeSet<ResourceRelativePath>,
}

impl<'a> ThreeWayMergedBytesRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: &'a ThreeWayMergeAnalysisPlan,
        text_diff: &'a ThreeWayTextDiffPlan,
        synthesis: &'a ThreeWayMergeSynthesisPlan,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledMergeContentSource,
        incoming_source: &'a IncomingMergeContentSource,
        options: ThreeWayMergedBytesOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            plan,
            review,
            analysis,
            text_diff,
            synthesis,
            baseline,
            installed_source,
            incoming_source,
            options,
            line_view_paths: BTreeSet::new(),
        })
    }

    /// Allow bounded line views for exactly these paths. See `line_view_paths`.
    pub fn with_line_view_paths(
        mut self,
        paths: impl IntoIterator<Item = ResourceRelativePath>,
    ) -> Self {
        self.line_view_paths = paths.into_iter().collect();
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MergedByteDisposition {
    ReadyForStaging,
    ManualReviewOutputLimit,
}

impl std::fmt::Debug for MergedByteDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadyForStaging => f.write_str("ReadyForStaging"),
            Self::ManualReviewOutputLimit => f.write_str("ManualReviewOutputLimit"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MergedByteStatus {
    ReadyForStaging,
    HasManualReviewEntries,
}

impl std::fmt::Debug for MergedByteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadyForStaging => f.write_str("ReadyForStaging"),
            Self::HasManualReviewEntries => f.write_str("HasManualReviewEntries"),
        }
    }
}

/// Opaque artifact identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MergedByteArtifactId(Sha256Digest);

impl MergedByteArtifactId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

impl std::fmt::Debug for MergedByteArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MergedByteArtifactId")
    }
}

/// Bounded in-memory merged bytes (crate-private accessors only).
pub struct MergedByteArtifact {
    bytes: Box<[u8]>,
    sha256: Sha256Digest,
    byte_length: u64,
    #[cfg(test)]
    live_tracked: bool,
}

impl MergedByteArtifact {
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    #[allow(dead_code)]
    pub(crate) fn bytes_for_staging(&self) -> &[u8] {
        &self.bytes
    }

    #[allow(dead_code)]
    pub(crate) fn digest_for_staging(&self) -> &Sha256Digest {
        &self.sha256
    }

    pub(crate) fn from_verified_parts(bytes: Box<[u8]>, sha256: Sha256Digest) -> Self {
        let byte_length = bytes.len() as u64;
        #[cfg(test)]
        let live_tracked = {
            let hooks = lock_hook_state();
            let track = hooks
                .as_ref()
                .is_some_and(|hooks| hooks.owner == std::thread::current().id());
            if track {
                MERGED_BYTE_ARTIFACT_LIVE.fetch_add(1, Ordering::SeqCst);
            }
            track
        };
        Self {
            bytes,
            sha256,
            byte_length,
            #[cfg(test)]
            live_tracked,
        }
    }

    /// Test-only: keep declared digest/length while replacing payload bytes.
    #[cfg(test)]
    pub(crate) fn corrupt_bytes_keep_declared_digest_for_test(&mut self, bytes: Box<[u8]>) {
        assert_eq!(
            bytes.len() as u64,
            self.byte_length,
            "corruption helper requires same declared length"
        );
        self.bytes = bytes;
    }
}

#[cfg(test)]
impl Drop for MergedByteArtifact {
    fn drop(&mut self) {
        if self.live_tracked {
            MERGED_BYTE_ARTIFACT_LIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl std::fmt::Debug for MergedByteArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MergedByteArtifact")
            .field("byte_length", &self.byte_length)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for MergedByteArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("merged-byte-artifact")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayMergedBytesPlanId(Sha256Digest);

impl ThreeWayMergedBytesPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

impl std::fmt::Debug for ThreeWayMergedBytesPlanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ThreeWayMergedBytesPlanId")
    }
}

pub struct ThreeWayMergedBytesEntry {
    path: ResourceRelativePath,
    final_envelope: FinalTextEnvelope,
    disposition: MergedByteDisposition,
    artifact: Option<MergedByteArtifact>,
    artifact_id: Option<MergedByteArtifactId>,
    line_view: Option<MergedLineView>,
}

impl ThreeWayMergedBytesEntry {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }
    pub fn final_envelope(&self) -> FinalTextEnvelope {
        self.final_envelope
    }
    pub fn disposition(&self) -> MergedByteDisposition {
        self.disposition
    }
    pub fn artifact(&self) -> Option<&MergedByteArtifact> {
        self.artifact.as_ref()
    }
    pub fn artifact_id(&self) -> Option<&MergedByteArtifactId> {
        self.artifact_id.as_ref()
    }

    /// Bounded operator-facing line view, present only for allow-listed paths.
    pub fn line_view(&self) -> Option<&MergedLineView> {
        self.line_view.as_ref()
    }
}

impl std::fmt::Debug for ThreeWayMergedBytesEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreeWayMergedBytesEntry")
            .field("disposition", &self.disposition)
            .field("has_artifact", &self.artifact.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedByteSummary {
    total_candidates: usize,
    ready_for_staging: usize,
    manual_output_limit: usize,
    total_output_bytes: u64,
}

impl MergedByteSummary {
    pub fn total_candidates(&self) -> usize {
        self.total_candidates
    }
    pub fn ready_for_staging(&self) -> usize {
        self.ready_for_staging
    }
    pub fn manual_output_limit(&self) -> usize {
        self.manual_output_limit
    }
    pub fn total_output_bytes(&self) -> u64 {
        self.total_output_bytes
    }
}

pub struct ThreeWayMergedBytesPlan {
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
    plan_id: ThreeWayPlanId,
    review_id: ThreeWayPlanReviewId,
    analysis_id: ThreeWayMergeAnalysisId,
    text_diff_plan_id: ThreeWayTextDiffPlanId,
    synthesis_plan_id: ThreeWayMergeSynthesisPlanId,
    installed_snapshot_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<ThreeWayMergedBytesEntry>,
    summary: MergedByteSummary,
    status: MergedByteStatus,
    merged_bytes_plan_id: ThreeWayMergedBytesPlanId,
}

impl ThreeWayMergedBytesPlan {
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
    pub fn analysis_id(&self) -> &ThreeWayMergeAnalysisId {
        &self.analysis_id
    }
    pub fn text_diff_plan_id(&self) -> &ThreeWayTextDiffPlanId {
        &self.text_diff_plan_id
    }
    pub fn synthesis_plan_id(&self) -> &ThreeWayMergeSynthesisPlanId {
        &self.synthesis_plan_id
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
    pub fn entries(&self) -> &[ThreeWayMergedBytesEntry] {
        &self.entries
    }

    pub(crate) fn from_desktop_apply_descriptor(
        plan: &ThreeWayUpdatePlan,
        review: &ThreeWayPlanReview,
        analysis_id: Sha256Digest,
        text_diff_plan_id: Sha256Digest,
        synthesis_plan_id: Sha256Digest,
        merged_bytes_plan_id: Sha256Digest,
        entries: Vec<(ResourceRelativePath, Sha256Digest, Sha256Digest, Box<[u8]>)>,
    ) -> Result<Self> {
        let entries = entries
            .into_iter()
            .map(|(path, artifact_id, digest, bytes)| {
                let computed = Sha256Digest::new(sha2::Sha256::digest(&bytes).into());
                if computed != digest {
                    return Err(GkrmError::TrustedCliUpdateBindingMismatch);
                }
                Ok(ThreeWayMergedBytesEntry {
                    path,
                    final_envelope: FinalTextEnvelope::from_parts(
                        false,
                        SupportedTextNewlineStyle::Lf,
                        TextTerminalNewline::Unknown,
                    ),
                    disposition: MergedByteDisposition::ReadyForStaging,
                    line_view: None,
                    artifact: Some(MergedByteArtifact::from_verified_parts(bytes, digest)),
                    artifact_id: Some(MergedByteArtifactId::from_digest(artifact_id)),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            resource_key: plan.resource_key().clone(),
            baseline_id: plan.baseline_id().clone(),
            plan_id: *plan.plan_id(),
            review_id: *review.review_id(),
            analysis_id: ThreeWayMergeAnalysisId::from_digest(analysis_id),
            text_diff_plan_id: ThreeWayTextDiffPlanId::new(text_diff_plan_id),
            synthesis_plan_id: ThreeWayMergeSynthesisPlanId::from_digest(synthesis_plan_id),
            installed_snapshot_fingerprint: *plan.installed_snapshot_fingerprint(),
            incoming_package_fingerprint: *plan.incoming_package_fingerprint(),
            incoming_resource_fingerprint: *plan.incoming_resource_fingerprint(),
            summary: MergedByteSummary {
                total_candidates: entries.len(),
                ready_for_staging: entries.len(),
                manual_output_limit: 0,
                total_output_bytes: entries
                    .iter()
                    .map(|entry| {
                        entry
                            .artifact
                            .as_ref()
                            .map_or(0, |artifact| artifact.byte_length())
                    })
                    .sum(),
            },
            entries,
            status: MergedByteStatus::ReadyForStaging,
            merged_bytes_plan_id: ThreeWayMergedBytesPlanId::from_digest(merged_bytes_plan_id),
        })
    }

    /// Test-only: corrupt the first ready artifact payload without updating its digest.
    #[cfg(test)]
    pub(crate) fn corrupt_first_ready_artifact_bytes_for_test(&mut self, bytes: Box<[u8]>) {
        for entry in &mut self.entries {
            if let Some(artifact) = entry.artifact.as_mut() {
                artifact.corrupt_bytes_keep_declared_digest_for_test(bytes);
                return;
            }
        }
        panic!("no merged artifact to corrupt");
    }

    pub fn summary(&self) -> &MergedByteSummary {
        &self.summary
    }
    pub fn status(&self) -> MergedByteStatus {
        self.status
    }
    pub fn merged_bytes_plan_id(&self) -> &ThreeWayMergedBytesPlanId {
        &self.merged_bytes_plan_id
    }
}

impl std::fmt::Debug for ThreeWayMergedBytesPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreeWayMergedBytesPlan")
            .field("status", &self.status)
            .field("summary", &self.summary)
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Synthesize bounded in-memory merged bytes for ready Task 18 entries.
pub fn synthesize_three_way_merged_bytes(
    request: ThreeWayMergedBytesRequest<'_>,
) -> Result<ThreeWayMergedBytesPlan> {
    request.options.validate()?;
    verify_bindings(&request)?;
    verify_structures(&request)?;
    if request.baseline.baseline_id() != request.plan.baseline_id()
        || request.baseline.resource_key() != request.plan.resource_key()
    {
        return Err(GkrmError::ThreeWayMergedBytesBaselineMismatch);
    }

    bind_all_synthesis_entries(&request)?;

    let mut candidates: Vec<&ThreeWayMergeSynthesisEntry> = request
        .synthesis
        .entries()
        .iter()
        .filter(|entry| entry.disposition() == MergeSynthesisDisposition::ReadyForByteSynthesis)
        .collect();
    if candidates.is_empty() {
        return Err(GkrmError::ThreeWayMergedBytesNoReadyCandidates);
    }
    if candidates.len() > request.options.max_candidates {
        return Err(GkrmError::ThreeWayMergedBytesCandidateLimitExceeded {
            limit: request.options.max_candidates,
            actual: candidates.len(),
        });
    }
    candidates.sort_by(|left, right| left.path().cmp(right.path()));
    for candidate in &candidates {
        verify_ready_candidate_invariants(&request, candidate)?;
    }

    let (fingerprint_a, root_identity_a, resource_identity_a) = {
        note_installed_scan();
        request
            .installed_source
            .scan_fingerprint_for_plan(request.plan.resource_key())
            .map_err(map_installed_scan_a)?
    };
    if &fingerprint_a != request.plan.installed_snapshot_fingerprint() {
        return Err(GkrmError::ThreeWayMergedBytesInstalledPreFingerprintMismatch);
    }
    {
        note_incoming_validate();
        request
            .incoming_source
            .validate_against_plan(request.plan)
            .map_err(map_incoming_validate)?;
    }

    let mut total_budget = StreamingByteBudget::new(request.options.max_total_source_bytes);
    let mut total_lines = 0usize;
    let mut remaining_output = request.options.max_total_output_bytes;
    let mut entries = Vec::with_capacity(candidates.len());

    for (index, candidate) in candidates.iter().enumerate() {
        let analysis_entry = request
            .analysis
            .entries()
            .iter()
            .find(|entry| entry.path() == candidate.path())
            .ok_or(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant)?;
        let text_entry = request
            .text_diff
            .entries()
            .iter()
            .find(|entry| entry.path() == candidate.path())
            .ok_or(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant)?;
        let entry = synthesize_candidate_entry(
            &request,
            candidate,
            analysis_entry,
            text_entry,
            &mut total_budget,
            &mut total_lines,
            &mut remaining_output,
        )?;
        entries.push(entry);
        run_between_entries_hook(index + 1);
    }

    let (fingerprint_b, root_identity_b, resource_identity_b) = {
        note_installed_scan();
        request
            .installed_source
            .scan_fingerprint_for_plan(request.plan.resource_key())
            .map_err(map_installed_scan_b)?
    };
    if root_identity_b != root_identity_a
        || resource_identity_b != resource_identity_a
        || fingerprint_b != fingerprint_a
        || &fingerprint_b != request.plan.installed_snapshot_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergedBytesInstalledResourceChanged);
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let summary = summarize(&entries)?;
    let status = status_from_summary(&summary)?;
    let merged_bytes_plan_id = encode_plan_id(&request, &entries, &summary, status)?;

    Ok(ThreeWayMergedBytesPlan {
        resource_key: request.plan.resource_key().clone(),
        baseline_id: request.plan.baseline_id().clone(),
        plan_id: *request.plan.plan_id(),
        review_id: *request.review.review_id(),
        analysis_id: *request.analysis.analysis_id(),
        text_diff_plan_id: *request.text_diff.text_diff_plan_id(),
        synthesis_plan_id: *request.synthesis.synthesis_plan_id(),
        installed_snapshot_fingerprint: *request.plan.installed_snapshot_fingerprint(),
        incoming_package_fingerprint: *request.plan.incoming_package_fingerprint(),
        incoming_resource_fingerprint: *request.plan.incoming_resource_fingerprint(),
        entries,
        summary,
        status,
        merged_bytes_plan_id,
    })
}

fn verify_bindings(request: &ThreeWayMergedBytesRequest<'_>) -> Result<()> {
    let plan = request.plan;
    let review = request.review;
    let analysis = request.analysis;
    let text_diff = request.text_diff;
    let synthesis = request.synthesis;

    if review.plan_id() != plan.plan_id()
        || review.resource_key() != plan.resource_key()
        || review.baseline_id() != plan.baseline_id()
        || review.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || review.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || review.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergedBytesPlanReviewBindingMismatch);
    }
    if analysis.plan_id() != plan.plan_id()
        || analysis.resource_key() != plan.resource_key()
        || analysis.baseline_id() != plan.baseline_id()
        || analysis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergedBytesPlanAnalysisBindingMismatch);
    }
    if text_diff.plan_id() != plan.plan_id()
        || text_diff.resource_key() != plan.resource_key()
        || text_diff.baseline_id() != plan.baseline_id()
        || text_diff.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || text_diff.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || text_diff.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergedBytesPlanTextDiffBindingMismatch);
    }
    if synthesis.plan_id() != plan.plan_id()
        || synthesis.resource_key() != plan.resource_key()
        || synthesis.baseline_id() != plan.baseline_id()
        || synthesis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || synthesis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || synthesis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergedBytesPlanSynthesisBindingMismatch);
    }
    if analysis.review_id() != review.review_id() {
        return Err(GkrmError::ThreeWayMergedBytesReviewAnalysisBindingMismatch);
    }
    if text_diff.review_id() != review.review_id() {
        return Err(GkrmError::ThreeWayMergedBytesReviewTextDiffBindingMismatch);
    }
    if synthesis.review_id() != review.review_id() {
        return Err(GkrmError::ThreeWayMergedBytesReviewSynthesisBindingMismatch);
    }
    if text_diff.analysis_id() != analysis.analysis_id() {
        return Err(GkrmError::ThreeWayMergedBytesAnalysisTextDiffBindingMismatch);
    }
    if synthesis.analysis_id() != analysis.analysis_id() {
        return Err(GkrmError::ThreeWayMergedBytesAnalysisSynthesisBindingMismatch);
    }
    if synthesis.text_diff_plan_id() != text_diff.text_diff_plan_id() {
        return Err(GkrmError::ThreeWayMergedBytesTextDiffSynthesisBindingMismatch);
    }
    Ok(())
}

fn verify_structures(request: &ThreeWayMergedBytesRequest<'_>) -> Result<()> {
    let plan = request.plan;
    let review = request.review;
    let analysis = request.analysis;
    let text_diff = request.text_diff;
    let synthesis = request.synthesis;

    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::ThreeWayMergedBytesReviewStructuralMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::ThreeWayMergedBytesReviewStructuralMismatch);
        }
    }

    let queued = plan
        .entries()
        .iter()
        .zip(review.entries())
        .filter(|(_, review_entry)| {
            review_entry.action() == ThreeWayReviewedAction::QueueMergeAnalysis
        })
        .map(|(plan_entry, _)| plan_entry.path())
        .collect::<Vec<_>>();
    if analysis.entries().len() != queued.len() {
        return Err(GkrmError::ThreeWayMergedBytesAnalysisStructuralMismatch);
    }
    for (analysis_entry, queued_path) in analysis.entries().iter().zip(queued) {
        if analysis_entry.path() != queued_path {
            return Err(GkrmError::ThreeWayMergedBytesAnalysisStructuralMismatch);
        }
    }

    let ready_analysis: Vec<_> = analysis
        .entries()
        .iter()
        .filter(|entry| {
            entry.disposition() == ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
        })
        .map(ThreeWayMergeAnalysisEntry::path)
        .collect();
    if text_diff.entries().len() != ready_analysis.len() {
        return Err(GkrmError::ThreeWayMergedBytesTextDiffStructuralMismatch);
    }
    let mut text_paths: Vec<_> = text_diff.entries().iter().map(|e| e.path()).collect();
    let mut analysis_paths = ready_analysis;
    text_paths.sort();
    analysis_paths.sort();
    if text_paths != analysis_paths {
        return Err(GkrmError::ThreeWayMergedBytesTextDiffStructuralMismatch);
    }

    let mut ready_text_paths: Vec<_> = text_diff
        .entries()
        .iter()
        .filter(|entry| entry.disposition() == ThreeWayTextDiffDisposition::ReadyForMergeSynthesis)
        .map(ThreeWayTextDiffEntry::path)
        .collect();
    // Task 18 emits entries in path-sorted order; Task 19 requires that exact
    // order and count (not a sorted multiset equality that would hide swaps).
    ready_text_paths.sort();
    let synthesis_paths: Vec<_> = synthesis.entries().iter().map(|e| e.path()).collect();
    if synthesis_paths != ready_text_paths {
        return Err(GkrmError::ThreeWayMergedBytesSynthesisStructuralMismatch);
    }
    Ok(())
}

fn bind_all_synthesis_entries(request: &ThreeWayMergedBytesRequest<'_>) -> Result<()> {
    for (index, entry) in request.synthesis.entries().iter().enumerate() {
        let text_entry = request
            .text_diff
            .entries()
            .iter()
            .find(|candidate| candidate.path() == entry.path())
            .ok_or(GkrmError::ThreeWayMergedBytesSynthesisStructuralMismatch)?;
        if entry.baseline_text_digest() != text_entry.baseline_text_digest()
            || entry.installed_text_digest() != text_entry.installed_text_digest()
            || entry.incoming_text_digest() != text_entry.incoming_text_digest()
        {
            return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
        }
        // Preserve original synthesis order relative to sorted text paths is not required;
        // index is retained only to ensure we walk the complete vector.
        let _ = index;
        match entry.disposition() {
            MergeSynthesisDisposition::ManualReviewOperationLimit => {
                if !entry.operations().is_empty()
                    || entry.merged_line_sequence_commitment().is_some()
                {
                    return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
                }
                validate_envelope_known(entry.final_envelope())?;
            }
            MergeSynthesisDisposition::ReadyForByteSynthesis => {
                if entry.operations().is_empty()
                    || entry.merged_line_sequence_commitment().is_none()
                {
                    return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
                }
                validate_envelope_known(entry.final_envelope())?;
                for op in entry.operations() {
                    bind_operation(request, entry, text_entry, op)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_envelope_known(envelope: FinalTextEnvelope) -> Result<()> {
    if envelope.terminal_newline() == TextTerminalNewline::Unknown {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEnvelope);
    }
    Ok(())
}

fn bind_operation(
    request: &ThreeWayMergedBytesRequest<'_>,
    entry: &ThreeWayMergeSynthesisEntry,
    _text_entry: &ThreeWayTextDiffEntry,
    op: &MergeSynthesisOperation,
) -> Result<()> {
    match op.kind() {
        MergeSynthesisOperationKind::CopyBase => {
            if op.source_range().is_some()
                || op.source_hunk_id().is_some()
                || op.equivalent_peer_hunk_id().is_some()
                || op.base_range().is_empty()
            {
                return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
            }
        }
        MergeSynthesisOperationKind::UseInstalledReplacement
        | MergeSynthesisOperationKind::UseIncomingReplacement => {
            if op.source_hunk_id().is_none()
                || op.equivalent_peer_hunk_id().is_some()
                || op.source_range().is_none()
            {
                return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
            }
        }
        MergeSynthesisOperationKind::UseEquivalentReplacement => {
            if op.source_hunk_id().is_none()
                || op.equivalent_peer_hunk_id().is_none()
                || op.source_range().is_none()
            {
                return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
            }
        }
    }
    let recomputed = encode_operation_id(
        request.text_diff.text_diff_plan_id(),
        entry.path(),
        op.kind(),
        op.base_range(),
        op.source_range(),
        op.source_hunk_id(),
        op.equivalent_peer_hunk_id(),
        op.output_commitment(),
    )
    .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
    if recomputed.digest() != op.id().digest() {
        return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
    }
    Ok(())
}

fn verify_ready_candidate_invariants(
    request: &ThreeWayMergedBytesRequest<'_>,
    candidate: &ThreeWayMergeSynthesisEntry,
) -> Result<()> {
    let plan_entry = request
        .plan
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant)?;
    let review_entry = request
        .review
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant)?;
    let analysis_entry = request
        .analysis
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant)?;
    let text_entry = request
        .text_diff
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant)?;

    if plan_entry.disposition() != ThreeWayPlanDisposition::MergeCandidate
        || review_entry.action() != ThreeWayReviewedAction::QueueMergeAnalysis
        || plan_entry.policy_transition() != EscrowPolicyTransition::None
        || analysis_entry.disposition()
            != ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
        || analysis_entry.algorithm() != Some(ThreeWayMergeAlgorithm::Utf8LineThreeWayV1)
        || text_entry.disposition() != ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
        || candidate.disposition() != MergeSynthesisDisposition::ReadyForByteSynthesis
    {
        return Err(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant);
    }
    if !matches!(
        text_entry.envelope_plan(),
        ThreeWayTextEnvelopePlanState::Planned(_)
    ) {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEnvelope);
    }
    let ThreeWayFileState::Present {
        escrow_class: Some(BaselineEscrowClass::Ignored),
        trusted_baseline_blob_available: true,
        ..
    } = plan_entry.baseline_state()
    else {
        return Err(GkrmError::ThreeWayMergedBytesInvalidCandidateInvariant);
    };
    Ok(())
}

fn synthesize_candidate_entry(
    request: &ThreeWayMergedBytesRequest<'_>,
    candidate: &ThreeWayMergeSynthesisEntry,
    analysis_entry: &ThreeWayMergeAnalysisEntry,
    text_entry: &ThreeWayTextDiffEntry,
    total_budget: &mut StreamingByteBudget,
    total_lines: &mut usize,
    remaining_output: &mut u64,
) -> Result<ThreeWayMergedBytesEntry> {
    let max_retain = request.options.max_source_bytes_per_file;
    note_baseline_read();
    let baseline_verified = read_baseline_verified(
        request.baseline,
        candidate.path(),
        *candidate.baseline_text_digest(),
        max_retain,
        request.options.baseline_store_limits(),
        |n| total_budget.add_task19(n),
    )?;
    note_installed_read();
    let installed_verified = request
        .installed_source
        .read_verified_merge_text(
            candidate.path(),
            *candidate.installed_text_digest(),
            max_retain,
            |n| total_budget.add_task19(n),
        )
        .map_err(map_installed_read)?;
    note_incoming_read();
    let incoming_verified = request
        .incoming_source
        .read_verified_merge_text(
            candidate.path(),
            *candidate.incoming_text_digest(),
            max_retain,
            |n| total_budget.add_task19(n),
        )
        .map_err(map_incoming_read)?;

    let (baseline_meta, baseline_bytes) = baseline_verified.into_parts();
    let (installed_meta, installed_bytes) = installed_verified.into_parts();
    let (incoming_meta, incoming_bytes) = incoming_verified.into_parts();

    ensure_metadata_matches(analysis_entry.baseline(), &baseline_meta)?;
    ensure_metadata_matches(analysis_entry.installed(), &installed_meta)?;
    ensure_metadata_matches(analysis_entry.incoming(), &incoming_meta)?;

    if baseline_meta.sha256() != candidate.baseline_text_digest()
        || installed_meta.sha256() != candidate.installed_text_digest()
        || incoming_meta.sha256() != candidate.incoming_text_digest()
        || baseline_meta.sha256() != text_entry.baseline_text_digest()
        || installed_meta.sha256() != text_entry.installed_text_digest()
        || incoming_meta.sha256() != text_entry.incoming_text_digest()
    {
        return Err(GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch);
    }

    let baseline_bytes =
        baseline_bytes.ok_or(GkrmError::ThreeWayMergedBytesSourceByteLimitExceeded {
            limit: max_retain,
            actual: baseline_meta.byte_length(),
        })?;
    let installed_bytes =
        installed_bytes.ok_or(GkrmError::ThreeWayMergedBytesSourceByteLimitExceeded {
            limit: max_retain,
            actual: installed_meta.byte_length(),
        })?;
    let incoming_bytes =
        incoming_bytes.ok_or(GkrmError::ThreeWayMergedBytesSourceByteLimitExceeded {
            limit: max_retain,
            actual: incoming_meta.byte_length(),
        })?;

    let (baseline_lines, baseline_bom, baseline_terminal) = split_logical_lines(
        &baseline_bytes,
        baseline_meta.encoding(),
        baseline_meta.newline_style(),
    )
    .map_err(map_logical)?;
    drop(baseline_bytes);
    account_lines(
        total_lines,
        baseline_lines.len(),
        request.options.max_lines_per_source,
        request.options.max_total_lines,
    )?;

    let (installed_lines, installed_bom, installed_terminal) = split_logical_lines(
        &installed_bytes,
        installed_meta.encoding(),
        installed_meta.newline_style(),
    )
    .map_err(map_logical)?;
    drop(installed_bytes);
    account_lines(
        total_lines,
        installed_lines.len(),
        request.options.max_lines_per_source,
        request.options.max_total_lines,
    )?;

    let (incoming_lines, incoming_bom, incoming_terminal) = split_logical_lines(
        &incoming_bytes,
        incoming_meta.encoding(),
        incoming_meta.newline_style(),
    )
    .map_err(map_logical)?;
    drop(incoming_bytes);
    account_lines(
        total_lines,
        incoming_lines.len(),
        request.options.max_lines_per_source,
        request.options.max_total_lines,
    )?;

    verify_source_envelopes(
        text_entry,
        baseline_bom,
        baseline_terminal,
        baseline_meta.newline_style(),
        installed_bom,
        installed_terminal,
        installed_meta.newline_style(),
        incoming_bom,
        incoming_terminal,
        incoming_meta.newline_style(),
    )?;
    verify_hunk_commitments(
        text_entry,
        &baseline_lines,
        &installed_lines,
        &incoming_lines,
    )?;

    let replayed = replay_synthesis_operations(
        candidate,
        text_entry,
        &baseline_lines,
        &installed_lines,
        &incoming_lines,
    )?;
    drop(baseline_lines);
    drop(installed_lines);
    drop(incoming_lines);

    let line_view = if request.line_view_paths.contains(candidate.path()) {
        Some(build_line_view(
            &replayed.merged_lines,
            &replayed.line_origins,
        )?)
    } else {
        None
    };

    let envelope = candidate.final_envelope();
    let (outcome, disposition) = synthesize_output_artifact(
        &replayed.merged_lines,
        envelope,
        request.options.max_output_bytes_per_file,
        *remaining_output,
    )?;
    drop(replayed);

    match (outcome, disposition) {
        (EncodeOutcome::ManualLimit, MergedByteDisposition::ManualReviewOutputLimit) => {
            Ok(ThreeWayMergedBytesEntry {
                path: candidate.path().clone(),
                final_envelope: envelope,
                disposition: MergedByteDisposition::ManualReviewOutputLimit,
                artifact: None,
                artifact_id: None,
                line_view,
            })
        }
        (EncodeOutcome::Ready(artifact), MergedByteDisposition::ReadyForStaging) => {
            *remaining_output = remaining_output
                .checked_sub(artifact.byte_length)
                .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
            let artifact_id = encode_artifact_id(
                request.synthesis.synthesis_plan_id(),
                candidate.path(),
                envelope,
                &artifact,
                MergedByteDisposition::ReadyForStaging,
            )?;
            Ok(ThreeWayMergedBytesEntry {
                path: candidate.path().clone(),
                final_envelope: envelope,
                disposition: MergedByteDisposition::ReadyForStaging,
                artifact: Some(artifact),
                artifact_id: Some(artifact_id),
                line_view,
            })
        }
        _ => Err(GkrmError::ThreeWayMergedBytesEncodeInvariant),
    }
}

fn summarize(entries: &[ThreeWayMergedBytesEntry]) -> Result<MergedByteSummary> {
    let mut ready = 0usize;
    let mut manual = 0usize;
    let mut total_output_bytes = 0u64;
    for entry in entries {
        match entry.disposition() {
            MergedByteDisposition::ReadyForStaging => {
                ready = ready
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
                let artifact = entry
                    .artifact
                    .as_ref()
                    .ok_or(GkrmError::ThreeWayMergedBytesSummaryInvariant)?;
                if entry.artifact_id.is_none() {
                    return Err(GkrmError::ThreeWayMergedBytesSummaryInvariant);
                }
                total_output_bytes = total_output_bytes
                    .checked_add(artifact.byte_length)
                    .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
            }
            MergedByteDisposition::ManualReviewOutputLimit => {
                manual = manual
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
                if entry.artifact.is_some() || entry.artifact_id.is_some() {
                    return Err(GkrmError::ThreeWayMergedBytesSummaryInvariant);
                }
            }
        }
    }
    let total_candidates = ready
        .checked_add(manual)
        .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
    if total_candidates != entries.len() {
        return Err(GkrmError::ThreeWayMergedBytesSummaryInvariant);
    }
    Ok(MergedByteSummary {
        total_candidates,
        ready_for_staging: ready,
        manual_output_limit: manual,
        total_output_bytes,
    })
}

fn status_from_summary(summary: &MergedByteSummary) -> Result<MergedByteStatus> {
    if summary.total_candidates == 0 {
        return Err(GkrmError::ThreeWayMergedBytesStatusInvariant);
    }
    Ok(if summary.manual_output_limit > 0 {
        MergedByteStatus::HasManualReviewEntries
    } else {
        MergedByteStatus::ReadyForStaging
    })
}

fn encode_artifact_id(
    synthesis_plan_id: &ThreeWayMergeSynthesisPlanId,
    path: &ResourceRelativePath,
    envelope: FinalTextEnvelope,
    artifact: &MergedByteArtifact,
    disposition: MergedByteDisposition,
) -> Result<MergedByteArtifactId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-merged-byte-artifact-v1")
        .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
    encoder.digest(synthesis_plan_id.digest());
    id_encode(encoder.path(path))?;
    encoder.bool(envelope.bom());
    encoder.u8(encode_newline(envelope.newline_style()));
    encoder.u8(encode_terminal_newline(envelope.terminal_newline()));
    encoder.digest(&artifact.sha256);
    encoder.u64(artifact.byte_length);
    encoder.u8(encode_disposition(disposition));
    Ok(MergedByteArtifactId(encoder.finish()))
}

fn encode_plan_id(
    request: &ThreeWayMergedBytesRequest<'_>,
    entries: &[ThreeWayMergedBytesEntry],
    summary: &MergedByteSummary,
    status: MergedByteStatus,
) -> Result<ThreeWayMergedBytesPlanId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-three-way-merged-bytes-plan-v1")
        .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
    encoder.digest(request.plan.plan_id().digest());
    encoder.digest(request.review.review_id().digest());
    encoder.digest(request.analysis.analysis_id().digest());
    encoder.digest(request.text_diff.text_diff_plan_id().digest());
    encoder.digest(request.synthesis.synthesis_plan_id().digest());
    id_encode(encoder.string(request.plan.resource_key().as_str()))?;
    id_encode(encoder.string(request.plan.baseline_id().as_str()))?;
    encoder.digest(request.plan.installed_snapshot_fingerprint());
    encoder.digest(request.plan.incoming_package_fingerprint());
    encoder.digest(request.plan.incoming_resource_fingerprint());
    encode_options(&mut encoder, request.options)?;
    id_encode(encoder.usize(entries.len()))?;
    for entry in entries {
        encode_entry(&mut encoder, entry)?;
    }
    encode_summary(&mut encoder, summary)?;
    encoder.u8(encode_status(status));
    Ok(ThreeWayMergedBytesPlanId(encoder.finish()))
}

fn encode_options(
    encoder: &mut CanonicalFingerprintEncoder,
    options: ThreeWayMergedBytesOptions,
) -> Result<()> {
    id_encode(encoder.usize(options.max_candidates))?;
    encoder.u64(options.max_source_bytes_per_file);
    encoder.u64(options.max_total_source_bytes);
    encoder.u64(options.max_output_bytes_per_file);
    encoder.u64(options.max_total_output_bytes);
    id_encode(encoder.usize(options.max_lines_per_source))?;
    id_encode(encoder.usize(options.max_total_lines))?;
    encoder.u64(options.baseline_store_limits.max_manifest_bytes());
    id_encode(encoder.usize(options.baseline_store_limits.max_files()))?;
    encoder.u64(options.baseline_store_limits.max_blob_bytes());
    encoder.u64(options.baseline_store_limits.max_total_blob_bytes());
    Ok(())
}

fn encode_entry(
    encoder: &mut CanonicalFingerprintEncoder,
    entry: &ThreeWayMergedBytesEntry,
) -> Result<()> {
    id_encode(encoder.path(&entry.path))?;
    encoder.bool(entry.final_envelope.bom());
    encoder.u8(encode_newline(entry.final_envelope.newline_style()));
    encoder.u8(encode_terminal_newline(
        entry.final_envelope.terminal_newline(),
    ));
    encoder.u8(encode_disposition(entry.disposition));
    match (&entry.artifact, &entry.artifact_id) {
        (Some(artifact), Some(id)) => {
            encoder.u8(1);
            encoder.digest(id.digest());
            encoder.digest(&artifact.sha256);
            encoder.u64(artifact.byte_length);
        }
        (None, None) => encoder.u8(0),
        _ => return Err(GkrmError::ThreeWayMergedBytesSummaryInvariant),
    }
    Ok(())
}

fn encode_summary(
    encoder: &mut CanonicalFingerprintEncoder,
    summary: &MergedByteSummary,
) -> Result<()> {
    id_encode(encoder.usize(summary.total_candidates))?;
    id_encode(encoder.usize(summary.ready_for_staging))?;
    id_encode(encoder.usize(summary.manual_output_limit))?;
    encoder.u64(summary.total_output_bytes);
    Ok(())
}

fn id_encode(result: std::result::Result<(), GkrmError>) -> Result<()> {
    result.map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)
}

fn ensure_metadata_matches(
    expected: &MergeContentAnalysis,
    actual: &MergeContentAnalysis,
) -> Result<()> {
    if expected != actual {
        return Err(GkrmError::ThreeWayMergedBytesTask16MetadataMismatch);
    }
    Ok(())
}

fn account_lines(
    total_lines: &mut usize,
    source_lines: usize,
    max_lines_per_source: usize,
    max_total_lines: usize,
) -> Result<()> {
    if source_lines > max_lines_per_source {
        return Err(GkrmError::ThreeWayMergedBytesSourceLineLimitExceeded {
            limit: max_lines_per_source,
            actual: source_lines,
        });
    }
    *total_lines = total_lines
        .checked_add(source_lines)
        .ok_or(GkrmError::ThreeWayMergedBytesArithmeticOverflow)?;
    if *total_lines > max_total_lines {
        return Err(GkrmError::ThreeWayMergedBytesTotalLineLimitExceeded {
            limit: max_total_lines,
            actual: *total_lines,
        });
    }
    Ok(())
}

fn verify_source_envelopes(
    candidate: &ThreeWayTextDiffEntry,
    baseline_bom: bool,
    baseline_terminal: bool,
    baseline_newline: MergeNewlineStyle,
    installed_bom: bool,
    installed_terminal: bool,
    installed_newline: MergeNewlineStyle,
    incoming_bom: bool,
    incoming_terminal: bool,
    incoming_newline: MergeNewlineStyle,
) -> Result<()> {
    let expected = [
        (
            candidate.baseline_envelope(),
            baseline_bom,
            baseline_terminal,
            baseline_newline,
        ),
        (
            candidate.installed_envelope(),
            installed_bom,
            installed_terminal,
            installed_newline,
        ),
        (
            candidate.incoming_envelope(),
            incoming_bom,
            incoming_terminal,
            incoming_newline,
        ),
    ];
    for (envelope, bom, terminal, newline) in expected {
        let mapped = map_newline(newline)?;
        let terminal = if terminal {
            TextTerminalNewline::Present
        } else {
            TextTerminalNewline::Absent
        };
        if envelope.bom() != bom
            || envelope.newline_style() != mapped
            || envelope.terminal_newline() != terminal
        {
            return Err(GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch);
        }
    }
    Ok(())
}

fn map_newline(style: MergeNewlineStyle) -> Result<SupportedTextNewlineStyle> {
    match style {
        MergeNewlineStyle::None => Ok(SupportedTextNewlineStyle::None),
        MergeNewlineStyle::Lf => Ok(SupportedTextNewlineStyle::Lf),
        MergeNewlineStyle::CrLf => Ok(SupportedTextNewlineStyle::CrLf),
        MergeNewlineStyle::Cr | MergeNewlineStyle::Mixed => {
            Err(GkrmError::ThreeWayMergedBytesMalformedLogicalText)
        }
    }
}

fn verify_hunk_commitments(
    candidate: &ThreeWayTextDiffEntry,
    baseline_lines: &[Vec<u8>],
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
) -> Result<()> {
    for hunk in candidate.installed_hunks() {
        verify_one_hunk(hunk, baseline_lines, installed_lines)?;
    }
    for hunk in candidate.incoming_hunks() {
        verify_one_hunk(hunk, baseline_lines, incoming_lines)?;
    }
    for group in candidate.overlap_groups() {
        if group.classification() != ThreeWayTextOverlapClassification::Equivalent {
            return Err(GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch);
        }
    }
    Ok(())
}

fn verify_one_hunk(
    hunk: &TextDiffHunk,
    baseline_lines: &[Vec<u8>],
    side_lines: &[Vec<u8>],
) -> Result<()> {
    let base = commitment_for_range(baseline_lines, hunk.base_range())
        .map_err(|_| GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch)?;
    let replacement = commitment_for_range(side_lines, hunk.side_range())
        .map_err(|_| GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch)?;
    if base.digest() != hunk.base_commitment().digest()
        || replacement.digest() != hunk.replacement_commitment().digest()
    {
        return Err(GkrmError::ThreeWayMergedBytesTask17EvidenceMismatch);
    }
    let _ = hunk.kind();
    Ok(())
}

fn read_baseline_verified(
    baseline: &ResolvedOfficialBaseline,
    path: &ResourceRelativePath,
    expected_digest: Sha256Digest,
    max_retain: u64,
    limits: &BaselineStoreLimits,
    mut on_bytes: impl FnMut(u64) -> Result<()>,
) -> Result<VerifiedMergeText> {
    let mut builder = VerifiedMergeTextBuilder::new(max_retain);
    stream_verified_blob_for_path(baseline.stored_baseline(), path, limits, |chunk| {
        on_bytes(chunk.len() as u64)?;
        builder.push(chunk).map_err(map_builder_err)
    })
    .map_err(task19_baseline_blob_verification_failed)?;
    let verified = builder.finish().map_err(map_builder_err)?;
    if verified.metadata().sha256() != &expected_digest {
        return Err(task19_baseline_blob_verification_failed(
            GkrmError::BaselineIncompleteBundle {
                reason: "verified baseline blob digest mismatch",
            },
        ));
    }
    Ok(verified)
}

fn task19_baseline_blob_verification_failed(source: GkrmError) -> GkrmError {
    GkrmError::ThreeWayMergedBytesBaselineBlobVerificationFailed {
        source: Box::new(source),
    }
}

fn map_builder_err(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergedBytesArithmeticOverflow
        }
        other => other,
    }
}

fn map_logical(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayTextDiffMalformedLogicalText
        | GkrmError::ThreeWayTextDiffArithmeticOverflow => {
            GkrmError::ThreeWayMergedBytesMalformedLogicalText
        }
        other => other,
    }
}

fn map_installed_scan_a(error: GkrmError) -> GkrmError {
    map_installed_common(error)
}

fn map_installed_scan_b(error: GkrmError) -> GkrmError {
    map_installed_common(error)
}

fn map_installed_read(error: GkrmError) -> GkrmError {
    map_installed_common(error)
}

fn map_installed_common(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayMergedBytesInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergedBytesInstalledCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged => {
            GkrmError::ThreeWayMergedBytesSourceIdentityChanged
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergedBytesArithmeticOverflow
        }
        other => other,
    }
}

fn map_incoming_validate(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayMergedBytesIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayMergedBytesIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayMergedBytesIncomingResourceIdentityMismatch
        }
        other => map_incoming_read(other),
    }
}

fn map_incoming_read(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid => {
            GkrmError::ThreeWayMergedBytesIncomingCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged => {
            GkrmError::ThreeWayMergedBytesSourceIdentityChanged
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergedBytesArithmeticOverflow
        }
        other => other,
    }
}

#[cfg(test)]
mod line_view_tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    }

    #[test]
    fn keeps_one_origin_per_surviving_line() {
        let view = build_line_view(
            &lines(&["a", "b", "c"]),
            &[
                MergedLineOrigin::Baseline,
                MergedLineOrigin::Installed,
                MergedLineOrigin::Incoming,
            ],
        )
        .expect("view");
        assert_eq!(view.lines().len(), 3);
        assert_eq!(view.lines()[0].origin(), MergedLineOrigin::Baseline);
        assert_eq!(view.lines()[1].origin(), MergedLineOrigin::Installed);
        assert_eq!(view.lines()[2].origin(), MergedLineOrigin::Incoming);
        assert_eq!(view.lines()[1].text(), "b");
        assert!(!view.truncated());
    }

    #[test]
    fn refuses_a_line_and_origin_count_mismatch() {
        assert!(build_line_view(&lines(&["a", "b"]), &[MergedLineOrigin::Baseline]).is_err());
    }

    #[test]
    fn refuses_non_utf8_rather_than_showing_text_that_is_not_in_the_file() {
        // A lossy conversion would put replacement characters on screen and claim they are the
        // operator's content. Refusing keeps the pane honest.
        let invalid = vec![vec![0xff, 0xfe]];
        assert!(build_line_view(&invalid, &[MergedLineOrigin::Baseline]).is_err());
    }

    #[test]
    fn drops_control_characters_but_keeps_tabs() {
        let view = build_line_view(
            &[b"a\tb\x07c\x1b[31m".to_vec()],
            &[MergedLineOrigin::Installed],
        )
        .expect("view");
        assert_eq!(view.lines()[0].text(), "a\tbc[31m");
    }

    #[test]
    fn bounds_the_file_and_each_line() {
        let long = "x".repeat(MERGED_LINE_VIEW_MAX_LINE_CHARS + 40);
        let many = vec![long.as_bytes().to_vec(); MERGED_LINE_VIEW_MAX_LINES + 10];
        let origins = vec![MergedLineOrigin::Baseline; many.len()];
        let view = build_line_view(&many, &origins).expect("view");
        assert_eq!(view.lines().len(), MERGED_LINE_VIEW_MAX_LINES);
        assert!(view.truncated());
        assert!(view.lines()[0].truncated());
        assert_eq!(
            view.lines()[0].text().chars().count(),
            MERGED_LINE_VIEW_MAX_LINE_CHARS
        );
    }
}
