//! Trusted, deterministic, bounded three-way text-diff planner (Milestone 2 Task 17).

mod envelope;
mod hunks;
mod id;
mod lines;
mod myers;
mod overlap;

pub use envelope::{
    SupportedTextNewlineStyle, TextEnvelope, TextTerminalNewline, ThreeWayTextEnvelopePlan,
    ThreeWayTextEnvelopePlanState, ThreeWayTextScalarResolution,
};
pub use hunks::{
    LineRange, TextDiffHunk, TextDiffHunkId, TextDiffHunkKind, TextDiffSide,
    TextLineSequenceCommitment,
};
pub use overlap::{
    ThreeWayTextOverlapClassification, ThreeWayTextOverlapGroup, ThreeWayTextOverlapGroupId,
};

#[cfg(test)]
pub(crate) use hunks::{coalesce_hunks_with_digest, replace_hunk_for_test};
pub(crate) use hunks::{commit_line_sequence, commitment_for_range};
pub(crate) use lines::split_logical_lines;
#[cfg(test)]
pub(crate) use overlap::test_support;

use crate::baseline::store::stream_verified_blob_for_path;
use crate::baseline::BaselineStoreLimits;
use crate::merge_content::{StreamingByteBudget, VerifiedMergeText, VerifiedMergeTextBuilder};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{
    BaselineEscrowClass, BaselineId, EscrowPolicyTransition, GkrmError, IncomingMergeContentSource,
    InstalledMergeContentSource, MergeContentAnalysis, MergeContentEncoding, MergeContentKind,
    MergeNewlineStyle, ResolvedOfficialBaseline, ResourceRelativePath, Result, SafeResourceKey,
    Sha256Digest, ThreeWayFileState, ThreeWayMergeAlgorithm, ThreeWayMergeAnalysisDisposition,
    ThreeWayMergeAnalysisEntry, ThreeWayMergeAnalysisId, ThreeWayMergeAnalysisPlan,
    ThreeWayPlanDisposition, ThreeWayPlanId, ThreeWayPlanReview, ThreeWayPlanReviewId,
    ThreeWayReviewedAction, ThreeWayUpdatePlan,
};

use self::envelope::{map_newline, plan_envelope};
use self::hunks::coalesce_hunks;
use self::id::{
    encode_envelope_plan_state, encode_kind, encode_line_range, encode_newline,
    encode_overlap_class, encode_resolution, encode_side, encode_terminal_newline,
};
pub(crate) use self::myers::{bounded_myers_diff, PrimitiveLineEdit, SideDiffLimit};
use self::overlap::{classify_overlap_groups, HunkEditView};

const DEFAULT_MAX_CANDIDATES: usize = 1_000;
const DEFAULT_MAX_SOURCE_BYTES_PER_FILE: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_LINES: usize = 600_000;
const DEFAULT_MAX_LINES_PER_SOURCE: usize = 200_000;
const DEFAULT_MAX_EDIT_DISTANCE_PER_SIDE: usize = 10_000;
const DEFAULT_MAX_TRACE_CELLS_PER_SIDE: usize = 2_000_000;
const DEFAULT_MAX_HUNKS_PER_SIDE: usize = 10_000;
const DEFAULT_MAX_OVERLAP_GROUPS_PER_ENTRY: usize = 10_000;

/// Opaque validated Task 17 planning options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreeWayTextDiffOptions {
    max_candidates: usize,
    max_source_bytes_per_file: u64,
    max_total_source_bytes: u64,
    max_total_lines: usize,
    max_lines_per_source: usize,
    max_edit_distance_per_side: usize,
    max_trace_cells_per_side: usize,
    max_hunks_per_side: usize,
    max_overlap_groups_per_entry: usize,
    baseline_store_limits: BaselineStoreLimits,
}

impl Default for ThreeWayTextDiffOptions {
    fn default() -> Self {
        Self {
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_source_bytes_per_file: DEFAULT_MAX_SOURCE_BYTES_PER_FILE,
            max_total_source_bytes: DEFAULT_MAX_TOTAL_SOURCE_BYTES,
            max_total_lines: DEFAULT_MAX_TOTAL_LINES,
            max_lines_per_source: DEFAULT_MAX_LINES_PER_SOURCE,
            max_edit_distance_per_side: DEFAULT_MAX_EDIT_DISTANCE_PER_SIDE,
            max_trace_cells_per_side: DEFAULT_MAX_TRACE_CELLS_PER_SIDE,
            max_hunks_per_side: DEFAULT_MAX_HUNKS_PER_SIDE,
            max_overlap_groups_per_entry: DEFAULT_MAX_OVERLAP_GROUPS_PER_ENTRY,
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl ThreeWayTextDiffOptions {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        max_candidates: usize,
        max_source_bytes_per_file: u64,
        max_total_source_bytes: u64,
        max_total_lines: usize,
        max_lines_per_source: usize,
        max_edit_distance_per_side: usize,
        max_trace_cells_per_side: usize,
        max_hunks_per_side: usize,
        max_overlap_groups_per_entry: usize,
        baseline_store_limits: BaselineStoreLimits,
    ) -> Result<Self> {
        let options = Self {
            max_candidates,
            max_source_bytes_per_file,
            max_total_source_bytes,
            max_total_lines,
            max_lines_per_source,
            max_edit_distance_per_side,
            max_trace_cells_per_side,
            max_hunks_per_side,
            max_overlap_groups_per_entry,
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

    pub fn max_total_lines(&self) -> usize {
        self.max_total_lines
    }

    pub fn max_lines_per_source(&self) -> usize {
        self.max_lines_per_source
    }

    pub fn max_edit_distance_per_side(&self) -> usize {
        self.max_edit_distance_per_side
    }

    pub fn max_trace_cells_per_side(&self) -> usize {
        self.max_trace_cells_per_side
    }

    pub fn max_hunks_per_side(&self) -> usize {
        self.max_hunks_per_side
    }

    pub fn max_overlap_groups_per_entry(&self) -> usize {
        self.max_overlap_groups_per_entry
    }

    pub fn baseline_store_limits(&self) -> &BaselineStoreLimits {
        &self.baseline_store_limits
    }

    fn validate(self) -> Result<()> {
        if self.max_candidates == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_candidates",
            });
        }
        if self.max_source_bytes_per_file == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_source_bytes_per_file",
            });
        }
        if self.max_total_source_bytes == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_total_source_bytes",
            });
        }
        if self.max_total_lines == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_total_lines",
            });
        }
        if self.max_lines_per_source == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_lines_per_source",
            });
        }
        if self.max_edit_distance_per_side == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_edit_distance_per_side",
            });
        }
        if self.max_trace_cells_per_side == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_trace_cells_per_side",
            });
        }
        if self.max_hunks_per_side == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_hunks_per_side",
            });
        }
        if self.max_overlap_groups_per_entry == 0 {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_overlap_groups_per_entry",
            });
        }
        if self.max_source_bytes_per_file > self.max_total_source_bytes {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_source_bytes_per_file",
            });
        }
        if self.max_lines_per_source > self.max_total_lines {
            return Err(GkrmError::ThreeWayTextDiffOptionsInvalid {
                limit: "max_lines_per_source",
            });
        }
        self.baseline_store_limits.validate()?;
        Ok(())
    }
}

/// Opaque Task 17 request binding Task 14/15/16 evidence and verified sources.
#[derive(Debug)]
pub struct ThreeWayTextDiffRequest<'a> {
    plan: &'a ThreeWayUpdatePlan,
    review: &'a ThreeWayPlanReview,
    analysis: &'a ThreeWayMergeAnalysisPlan,
    baseline: &'a ResolvedOfficialBaseline,
    installed_source: &'a InstalledMergeContentSource,
    incoming_source: &'a IncomingMergeContentSource,
    options: ThreeWayTextDiffOptions,
}

impl<'a> ThreeWayTextDiffRequest<'a> {
    pub fn try_new(
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: &'a ThreeWayMergeAnalysisPlan,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledMergeContentSource,
        incoming_source: &'a IncomingMergeContentSource,
        options: ThreeWayTextDiffOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            plan,
            review,
            analysis,
            baseline,
            installed_source,
            incoming_source,
            options,
        })
    }
}

/// Per-entry Task 17 disposition (no write authorization).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayTextDiffDisposition {
    ReadyForMergeSynthesis,
    ConflictReviewTextEdits,
    ConflictReviewEnvelope,
    ConflictReviewTextAndEnvelope,
    ManualReviewSourceTooLarge,
    ManualReviewEditDistanceLimit,
    ManualReviewDiffWorkLimit,
    ManualReviewHunkLimit,
    ManualReviewOverlapGroupLimit,
}

/// Plan-level Task 17 status (no write authorization).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayTextDiffStatus {
    ReadyForMergeSynthesis,
    HasConflicts,
    HasManualReviewEntries,
    HasConflictsAndManualReviewEntries,
}

/// Opaque deterministic Task 17 plan identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayTextDiffPlanId(Sha256Digest);

impl ThreeWayTextDiffPlanId {
    pub(crate) fn new(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Immutable per-path text-diff entry (no source text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayTextDiffEntry {
    path: ResourceRelativePath,
    baseline_text_digest: Sha256Digest,
    installed_text_digest: Sha256Digest,
    incoming_text_digest: Sha256Digest,
    baseline_envelope: TextEnvelope,
    installed_envelope: TextEnvelope,
    incoming_envelope: TextEnvelope,
    envelope_plan: ThreeWayTextEnvelopePlanState,
    installed_hunks: Vec<TextDiffHunk>,
    incoming_hunks: Vec<TextDiffHunk>,
    overlap_groups: Vec<ThreeWayTextOverlapGroup>,
    disposition: ThreeWayTextDiffDisposition,
}

impl ThreeWayTextDiffEntry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        path: ResourceRelativePath,
        baseline_text_digest: Sha256Digest,
        installed_text_digest: Sha256Digest,
        incoming_text_digest: Sha256Digest,
        baseline_envelope: TextEnvelope,
        installed_envelope: TextEnvelope,
        incoming_envelope: TextEnvelope,
        envelope_plan: ThreeWayTextEnvelopePlanState,
        installed_hunks: Vec<TextDiffHunk>,
        incoming_hunks: Vec<TextDiffHunk>,
        overlap_groups: Vec<ThreeWayTextOverlapGroup>,
        disposition: ThreeWayTextDiffDisposition,
    ) -> Self {
        Self {
            path,
            baseline_text_digest,
            installed_text_digest,
            incoming_text_digest,
            baseline_envelope,
            installed_envelope,
            incoming_envelope,
            envelope_plan,
            installed_hunks,
            incoming_hunks,
            overlap_groups,
            disposition,
        }
    }

    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    pub fn baseline_text_digest(&self) -> &Sha256Digest {
        &self.baseline_text_digest
    }

    pub fn installed_text_digest(&self) -> &Sha256Digest {
        &self.installed_text_digest
    }

    pub fn incoming_text_digest(&self) -> &Sha256Digest {
        &self.incoming_text_digest
    }

    pub fn baseline_envelope(&self) -> &TextEnvelope {
        &self.baseline_envelope
    }

    pub fn installed_envelope(&self) -> &TextEnvelope {
        &self.installed_envelope
    }

    pub fn incoming_envelope(&self) -> &TextEnvelope {
        &self.incoming_envelope
    }

    pub fn envelope_plan(&self) -> &ThreeWayTextEnvelopePlanState {
        &self.envelope_plan
    }

    pub fn installed_hunks(&self) -> &[TextDiffHunk] {
        &self.installed_hunks
    }

    pub fn incoming_hunks(&self) -> &[TextDiffHunk] {
        &self.incoming_hunks
    }

    pub fn overlap_groups(&self) -> &[ThreeWayTextOverlapGroup] {
        &self.overlap_groups
    }

    pub fn disposition(&self) -> ThreeWayTextDiffDisposition {
        self.disposition
    }
}

/// Checked Task 17 summary counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayTextDiffSummary {
    total_candidates: usize,
    ready_for_merge_synthesis: usize,
    conflict_text: usize,
    conflict_envelope: usize,
    conflict_text_and_envelope: usize,
    manual_source_too_large: usize,
    manual_edit_distance_limit: usize,
    manual_diff_work_limit: usize,
    manual_hunk_limit: usize,
    manual_overlap_group_limit: usize,
    total_installed_hunks: usize,
    total_incoming_hunks: usize,
    total_overlap_groups: usize,
}

impl ThreeWayTextDiffSummary {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        total_candidates: usize,
        ready_for_merge_synthesis: usize,
        conflict_text: usize,
        conflict_envelope: usize,
        conflict_text_and_envelope: usize,
        manual_source_too_large: usize,
        manual_edit_distance_limit: usize,
        manual_diff_work_limit: usize,
        manual_hunk_limit: usize,
        manual_overlap_group_limit: usize,
        total_installed_hunks: usize,
        total_incoming_hunks: usize,
        total_overlap_groups: usize,
    ) -> Self {
        Self {
            total_candidates,
            ready_for_merge_synthesis,
            conflict_text,
            conflict_envelope,
            conflict_text_and_envelope,
            manual_source_too_large,
            manual_edit_distance_limit,
            manual_diff_work_limit,
            manual_hunk_limit,
            manual_overlap_group_limit,
            total_installed_hunks,
            total_incoming_hunks,
            total_overlap_groups,
        }
    }

    pub fn total_candidates(&self) -> usize {
        self.total_candidates
    }

    pub fn ready_for_merge_synthesis(&self) -> usize {
        self.ready_for_merge_synthesis
    }

    pub fn conflict_text(&self) -> usize {
        self.conflict_text
    }

    pub fn conflict_envelope(&self) -> usize {
        self.conflict_envelope
    }

    pub fn conflict_text_and_envelope(&self) -> usize {
        self.conflict_text_and_envelope
    }

    pub fn manual_source_too_large(&self) -> usize {
        self.manual_source_too_large
    }

    pub fn manual_edit_distance_limit(&self) -> usize {
        self.manual_edit_distance_limit
    }

    pub fn manual_diff_work_limit(&self) -> usize {
        self.manual_diff_work_limit
    }

    pub fn manual_hunk_limit(&self) -> usize {
        self.manual_hunk_limit
    }

    pub fn manual_overlap_group_limit(&self) -> usize {
        self.manual_overlap_group_limit
    }

    pub fn total_installed_hunks(&self) -> usize {
        self.total_installed_hunks
    }

    pub fn total_incoming_hunks(&self) -> usize {
        self.total_incoming_hunks
    }

    pub fn total_overlap_groups(&self) -> usize {
        self.total_overlap_groups
    }
}

/// Immutable Task 17 text-diff plan (no source text, no write authorization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayTextDiffPlan {
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
    plan_id: ThreeWayPlanId,
    review_id: ThreeWayPlanReviewId,
    analysis_id: ThreeWayMergeAnalysisId,
    installed_snapshot_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<ThreeWayTextDiffEntry>,
    summary: ThreeWayTextDiffSummary,
    status: ThreeWayTextDiffStatus,
    text_diff_plan_id: ThreeWayTextDiffPlanId,
}

impl ThreeWayTextDiffPlan {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        resource_key: SafeResourceKey,
        baseline_id: BaselineId,
        plan_id: ThreeWayPlanId,
        review_id: ThreeWayPlanReviewId,
        analysis_id: ThreeWayMergeAnalysisId,
        installed_snapshot_fingerprint: Sha256Digest,
        incoming_package_fingerprint: Sha256Digest,
        incoming_resource_fingerprint: Sha256Digest,
        entries: Vec<ThreeWayTextDiffEntry>,
        summary: ThreeWayTextDiffSummary,
        status: ThreeWayTextDiffStatus,
        text_diff_plan_id: ThreeWayTextDiffPlanId,
    ) -> Self {
        Self {
            resource_key,
            baseline_id,
            plan_id,
            review_id,
            analysis_id,
            installed_snapshot_fingerprint,
            incoming_package_fingerprint,
            incoming_resource_fingerprint,
            entries,
            summary,
            status,
            text_diff_plan_id,
        }
    }

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

    pub fn installed_snapshot_fingerprint(&self) -> &Sha256Digest {
        &self.installed_snapshot_fingerprint
    }

    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }

    pub fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_resource_fingerprint
    }

    pub fn entries(&self) -> &[ThreeWayTextDiffEntry] {
        &self.entries
    }

    pub fn summary(&self) -> &ThreeWayTextDiffSummary {
        &self.summary
    }

    pub fn status(&self) -> ThreeWayTextDiffStatus {
        self.status
    }

    pub fn text_diff_plan_id(&self) -> &ThreeWayTextDiffPlanId {
        &self.text_diff_plan_id
    }
}

enum SideOutcome {
    Ok { hunks: Vec<TextDiffHunk> },
    EditDistance,
    TraceCells,
    HunkLimit,
}

/// Plan bounded three-way text diffs for ready Task 16 UTF-8 line-merge candidates.
pub fn plan_three_way_text_diffs(
    request: ThreeWayTextDiffRequest<'_>,
) -> Result<ThreeWayTextDiffPlan> {
    request.options.validate()?;
    verify_plan_review_binding(request.plan, request.review)?;
    verify_plan_analysis_binding(request.plan, request.analysis)?;
    verify_review_analysis_binding(request.review, request.analysis)?;
    verify_review_structure(request.plan, request.review)?;
    verify_analysis_structure(request.plan, request.review, request.analysis)?;
    if request.baseline.baseline_id() != request.plan.baseline_id()
        || request.baseline.resource_key() != request.plan.resource_key()
    {
        return Err(GkrmError::ThreeWayTextDiffBaselineMismatch);
    }

    let mut candidates = collect_ready_candidates(request.analysis)?;
    if candidates.is_empty() {
        return Err(GkrmError::ThreeWayTextDiffNoReadyCandidates);
    }
    if candidates.len() > request.options.max_candidates {
        return Err(GkrmError::ThreeWayTextDiffCandidateLimitExceeded {
            limit: request.options.max_candidates,
            actual: candidates.len(),
        });
    }
    // Structural Task 14/15/16 order was already verified above. Sort only the
    // selected ready subset for deterministic processing and plan-ID encoding.
    sort_ready_candidates(&mut candidates);
    for candidate in &candidates {
        verify_ready_candidate_invariants(request.plan, request.review, candidate)?;
    }

    let (fingerprint_a, root_identity_a, resource_identity_a) = request
        .installed_source
        .scan_fingerprint_for_plan(request.plan.resource_key())
        .map_err(map_installed_scan_a)?;
    if &fingerprint_a != request.plan.installed_snapshot_fingerprint() {
        return Err(GkrmError::ThreeWayTextDiffInstalledPreFingerprintMismatch);
    }

    request
        .incoming_source
        .validate_against_plan(request.plan)
        .map_err(map_incoming_validate)?;
    validate_baseline_records(request.baseline, request.plan, &candidates)?;

    let mut total_budget = StreamingByteBudget::new(request.options.max_total_source_bytes);
    let mut total_lines = 0usize;
    let mut entries = Vec::with_capacity(candidates.len());
    let analysis_id = request.analysis.analysis_id();

    for candidate in &candidates {
        let entry = plan_candidate_entry(
            &request,
            analysis_id,
            candidate,
            &mut total_budget,
            &mut total_lines,
        )?;
        entries.push(entry);
    }

    let (fingerprint_b, root_identity_b, resource_identity_b) = request
        .installed_source
        .scan_fingerprint_for_plan(request.plan.resource_key())
        .map_err(map_installed_scan_b)?;
    if root_identity_b != root_identity_a
        || resource_identity_b != resource_identity_a
        || fingerprint_b != fingerprint_a
        || &fingerprint_b != request.plan.installed_snapshot_fingerprint()
    {
        return Err(GkrmError::ThreeWayTextDiffInstalledResourceChanged);
    }

    let (entries, summary, status, text_diff_plan_id) =
        finalize_sorted_text_diff_plan(&request, entries)?;

    Ok(ThreeWayTextDiffPlan::new(
        request.plan.resource_key().clone(),
        request.plan.baseline_id().clone(),
        *request.plan.plan_id(),
        *request.review.review_id(),
        *request.analysis.analysis_id(),
        *request.plan.installed_snapshot_fingerprint(),
        *request.plan.incoming_package_fingerprint(),
        *request.plan.incoming_resource_fingerprint(),
        entries,
        summary,
        status,
        text_diff_plan_id,
    ))
}

fn plan_candidate_entry(
    request: &ThreeWayTextDiffRequest<'_>,
    analysis_id: &ThreeWayMergeAnalysisId,
    candidate: &ThreeWayMergeAnalysisEntry,
    total_budget: &mut StreamingByteBudget,
    total_lines: &mut usize,
) -> Result<ThreeWayTextDiffEntry> {
    let max_retain = request.options.max_source_bytes_per_file;
    let baseline_verified = read_baseline_verified(
        request.baseline,
        candidate.path(),
        *candidate.baseline().sha256(),
        max_retain,
        request.options.baseline_store_limits(),
        |n| total_budget.add_task17(n),
    )?;
    let installed_verified = request
        .installed_source
        .read_verified_merge_text(
            candidate.path(),
            *candidate.installed().sha256(),
            max_retain,
            |n| total_budget.add_task17(n),
        )
        .map_err(map_installed_read)?;
    let incoming_verified = request
        .incoming_source
        .read_verified_merge_text(
            candidate.path(),
            *candidate.incoming().sha256(),
            max_retain,
            |n| total_budget.add_task17(n),
        )
        .map_err(map_incoming_read)?;

    let (baseline_meta, baseline_bytes) = baseline_verified.into_parts();
    let (installed_meta, installed_bytes) = installed_verified.into_parts();
    let (incoming_meta, incoming_bytes) = incoming_verified.into_parts();

    ensure_metadata_matches(candidate.baseline(), &baseline_meta)?;
    ensure_metadata_matches(candidate.installed(), &installed_meta)?;
    ensure_metadata_matches(candidate.incoming(), &incoming_meta)?;

    let baseline_digest = *baseline_meta.sha256();
    let installed_digest = *installed_meta.sha256();
    let incoming_digest = *incoming_meta.sha256();

    let too_large =
        baseline_bytes.is_none() || installed_bytes.is_none() || incoming_bytes.is_none();
    if too_large {
        let baseline_envelope =
            envelope_from_verified_source(&baseline_meta, baseline_bytes.as_deref())?;
        let installed_envelope =
            envelope_from_verified_source(&installed_meta, installed_bytes.as_deref())?;
        let incoming_envelope =
            envelope_from_verified_source(&incoming_meta, incoming_bytes.as_deref())?;
        drop(baseline_bytes);
        drop(installed_bytes);
        drop(incoming_bytes);
        return Ok(ThreeWayTextDiffEntry::new(
            candidate.path().clone(),
            baseline_digest,
            installed_digest,
            incoming_digest,
            baseline_envelope,
            installed_envelope,
            incoming_envelope,
            ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge,
        ));
    }

    let baseline_bytes = baseline_bytes.expect("checked");
    let installed_bytes = installed_bytes.expect("checked");
    let incoming_bytes = incoming_bytes.expect("checked");

    let (baseline_lines, baseline_bom, baseline_terminal) = split_logical_lines(
        &baseline_bytes,
        baseline_meta.encoding(),
        baseline_meta.newline_style(),
    )?;
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
    )?;
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
    )?;
    drop(incoming_bytes);
    account_lines(
        total_lines,
        incoming_lines.len(),
        request.options.max_lines_per_source,
        request.options.max_total_lines,
    )?;

    let baseline_envelope = TextEnvelope::new(
        baseline_bom,
        map_newline(baseline_meta.newline_style())?,
        if baseline_terminal {
            TextTerminalNewline::Present
        } else {
            TextTerminalNewline::Absent
        },
    );
    let installed_envelope = TextEnvelope::new(
        installed_bom,
        map_newline(installed_meta.newline_style())?,
        if installed_terminal {
            TextTerminalNewline::Present
        } else {
            TextTerminalNewline::Absent
        },
    );
    let incoming_envelope = TextEnvelope::new(
        incoming_bom,
        map_newline(incoming_meta.newline_style())?,
        if incoming_terminal {
            TextTerminalNewline::Present
        } else {
            TextTerminalNewline::Absent
        },
    );
    let envelope_plan = ThreeWayTextEnvelopePlanState::Planned(plan_envelope(
        &baseline_envelope,
        &installed_envelope,
        &incoming_envelope,
    )?);

    let installed_outcome = diff_one_side(
        analysis_id,
        candidate.path(),
        TextDiffSide::Installed,
        &baseline_lines,
        &installed_lines,
        request.options,
    )?;
    let incoming_outcome = diff_one_side(
        analysis_id,
        candidate.path(),
        TextDiffSide::Incoming,
        &baseline_lines,
        &incoming_lines,
        request.options,
    )?;

    if let Some(disposition) =
        aggregate_side_limit_disposition(&installed_outcome, &incoming_outcome)
    {
        drop(baseline_lines);
        drop(installed_lines);
        drop(incoming_lines);
        return Ok(ThreeWayTextDiffEntry::new(
            candidate.path().clone(),
            baseline_digest,
            installed_digest,
            incoming_digest,
            baseline_envelope,
            installed_envelope,
            incoming_envelope,
            envelope_plan,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            disposition,
        ));
    }

    let SideOutcome::Ok {
        hunks: installed_hunks,
    } = installed_outcome
    else {
        return Err(GkrmError::ThreeWayTextDiffArithmeticOverflow);
    };
    let SideOutcome::Ok {
        hunks: incoming_hunks,
    } = incoming_outcome
    else {
        return Err(GkrmError::ThreeWayTextDiffArithmeticOverflow);
    };

    let installed_views = installed_hunks
        .iter()
        .map(|hunk| hunk_edit_view(hunk, &installed_lines))
        .collect::<Result<Vec<_>>>()?;
    let incoming_views = incoming_hunks
        .iter()
        .map(|hunk| hunk_edit_view(hunk, &incoming_lines))
        .collect::<Result<Vec<_>>>()?;

    let overlap_result = classify_overlap_groups(
        analysis_id,
        candidate.path(),
        &installed_views,
        &incoming_views,
        request.options.max_overlap_groups_per_entry,
    )?;
    drop(installed_views);
    drop(incoming_views);
    drop(baseline_lines);
    drop(installed_lines);
    drop(incoming_lines);

    let overlap_groups = match overlap_result {
        Ok(groups) => groups,
        Err(()) => {
            return Ok(ThreeWayTextDiffEntry::new(
                candidate.path().clone(),
                baseline_digest,
                installed_digest,
                incoming_digest,
                baseline_envelope,
                installed_envelope,
                incoming_envelope,
                envelope_plan,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                ThreeWayTextDiffDisposition::ManualReviewOverlapGroupLimit,
            ));
        }
    };

    let text_conflict = has_text_conflict(&overlap_groups);
    let envelope_conflict = has_envelope_conflict(&envelope_plan);
    let disposition = disposition_from_conflicts(text_conflict, envelope_conflict);

    Ok(ThreeWayTextDiffEntry::new(
        candidate.path().clone(),
        baseline_digest,
        installed_digest,
        incoming_digest,
        baseline_envelope,
        installed_envelope,
        incoming_envelope,
        envelope_plan,
        installed_hunks,
        incoming_hunks,
        overlap_groups,
        disposition,
    ))
}

fn diff_one_side(
    analysis_id: &ThreeWayMergeAnalysisId,
    path: &ResourceRelativePath,
    side: TextDiffSide,
    base_lines: &[Vec<u8>],
    side_lines: &[Vec<u8>],
    options: ThreeWayTextDiffOptions,
) -> Result<SideOutcome> {
    match bounded_myers_diff(
        base_lines,
        side_lines,
        options.max_edit_distance_per_side,
        options.max_trace_cells_per_side,
    )? {
        Err(SideDiffLimit::EditDistance) => Ok(SideOutcome::EditDistance),
        Err(SideDiffLimit::TraceCells) => Ok(SideOutcome::TraceCells),
        Ok(script) => {
            let hunks = coalesce_hunks(analysis_id, path, side, base_lines, side_lines, &script)?;
            if hunks.len() > options.max_hunks_per_side {
                Ok(SideOutcome::HunkLimit)
            } else {
                Ok(SideOutcome::Ok { hunks })
            }
        }
    }
}

fn aggregate_side_limit_disposition(
    installed: &SideOutcome,
    incoming: &SideOutcome,
) -> Option<ThreeWayTextDiffDisposition> {
    let edit_distance = matches!(installed, SideOutcome::EditDistance)
        || matches!(incoming, SideOutcome::EditDistance);
    let trace_cells =
        matches!(installed, SideOutcome::TraceCells) || matches!(incoming, SideOutcome::TraceCells);
    let hunk_limit =
        matches!(installed, SideOutcome::HunkLimit) || matches!(incoming, SideOutcome::HunkLimit);
    if edit_distance {
        Some(ThreeWayTextDiffDisposition::ManualReviewEditDistanceLimit)
    } else if trace_cells {
        Some(ThreeWayTextDiffDisposition::ManualReviewDiffWorkLimit)
    } else if hunk_limit {
        Some(ThreeWayTextDiffDisposition::ManualReviewHunkLimit)
    } else {
        None
    }
}

fn hunk_edit_view<'a>(
    hunk: &'a TextDiffHunk,
    side_lines: &'a [Vec<u8>],
) -> Result<HunkEditView<'a>> {
    let range = hunk.side_range();
    if range.end() > side_lines.len() {
        return Err(GkrmError::ThreeWayTextDiffInvalidHunk);
    }
    Ok(HunkEditView {
        hunk,
        replacement_lines: &side_lines[range.start()..range.end()],
    })
}

fn has_text_conflict(groups: &[ThreeWayTextOverlapGroup]) -> bool {
    groups.iter().any(|group| {
        !matches!(
            group.classification(),
            ThreeWayTextOverlapClassification::Equivalent
        )
    })
}

fn has_envelope_conflict(plan: &ThreeWayTextEnvelopePlanState) -> bool {
    let Some(plan) = plan.planned() else {
        return false;
    };
    matches!(plan.bom(), ThreeWayTextScalarResolution::Conflict)
        || matches!(plan.newline_style(), ThreeWayTextScalarResolution::Conflict)
        || matches!(
            plan.terminal_newline(),
            ThreeWayTextScalarResolution::Conflict
        )
}

fn disposition_from_conflicts(
    text_conflict: bool,
    envelope_conflict: bool,
) -> ThreeWayTextDiffDisposition {
    match (text_conflict, envelope_conflict) {
        (true, true) => ThreeWayTextDiffDisposition::ConflictReviewTextAndEnvelope,
        (true, false) => ThreeWayTextDiffDisposition::ConflictReviewTextEdits,
        (false, true) => ThreeWayTextDiffDisposition::ConflictReviewEnvelope,
        (false, false) => ThreeWayTextDiffDisposition::ReadyForMergeSynthesis,
    }
}

fn account_lines(
    total_lines: &mut usize,
    source_lines: usize,
    max_lines_per_source: usize,
    max_total_lines: usize,
) -> Result<()> {
    if source_lines > max_lines_per_source {
        return Err(GkrmError::ThreeWayTextDiffTotalLineLimitExceeded {
            limit: max_lines_per_source,
            actual: source_lines,
        });
    }
    *total_lines = total_lines
        .checked_add(source_lines)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    if *total_lines > max_total_lines {
        return Err(GkrmError::ThreeWayTextDiffTotalLineLimitExceeded {
            limit: max_total_lines,
            actual: *total_lines,
        });
    }
    Ok(())
}

fn envelope_from_verified_source(
    metadata: &MergeContentAnalysis,
    retained_bytes: Option<&[u8]>,
) -> Result<TextEnvelope> {
    let bom = metadata.encoding() == MergeContentEncoding::Utf8WithBom;
    let newline_style = map_newline(metadata.newline_style())?;
    let terminal_newline = match retained_bytes {
        None => TextTerminalNewline::Unknown,
        Some(bytes) => {
            let (_lines, derived_bom, terminal) =
                split_logical_lines(bytes, metadata.encoding(), metadata.newline_style())?;
            if derived_bom != bom {
                return Err(GkrmError::ThreeWayTextDiffMalformedLogicalText);
            }
            if terminal {
                TextTerminalNewline::Present
            } else {
                TextTerminalNewline::Absent
            }
        }
    };
    Ok(TextEnvelope::new(bom, newline_style, terminal_newline))
}

fn ensure_metadata_matches(
    expected: &MergeContentAnalysis,
    actual: &MergeContentAnalysis,
) -> Result<()> {
    if expected.sha256() != actual.sha256()
        || expected.byte_length() != actual.byte_length()
        || expected.content_kind() != actual.content_kind()
        || expected.encoding() != actual.encoding()
        || expected.newline_style() != actual.newline_style()
        || expected.line_count() != actual.line_count()
        || expected.max_line_bytes() != actual.max_line_bytes()
        || expected.is_empty() != actual.is_empty()
    {
        return Err(GkrmError::ThreeWayTextDiffTask16MetadataMismatch);
    }
    Ok(())
}

fn read_baseline_verified(
    baseline: &ResolvedOfficialBaseline,
    path: &ResourceRelativePath,
    expected_digest: Sha256Digest,
    max_retain_bytes: u64,
    limits: &BaselineStoreLimits,
    mut on_bytes: impl FnMut(u64) -> Result<()>,
) -> Result<VerifiedMergeText> {
    let mut builder = VerifiedMergeTextBuilder::new(max_retain_bytes);
    stream_verified_blob_for_path(baseline.stored_baseline(), path, limits, |chunk| {
        on_bytes(chunk.len() as u64)?;
        builder.push(chunk).map_err(map_builder_err)
    })
    .map_err(task17_baseline_blob_verification_failed)?;
    let verified = builder.finish().map_err(map_builder_err)?;
    if verified.metadata().sha256() != &expected_digest {
        return Err(task17_baseline_blob_verification_failed(
            GkrmError::BaselineIncompleteBundle {
                reason: "verified baseline blob digest mismatch",
            },
        ));
    }
    Ok(verified)
}

fn task17_baseline_blob_verification_failed(source: GkrmError) -> GkrmError {
    GkrmError::ThreeWayTextDiffBaselineBlobVerificationFailed {
        source: Box::new(source),
    }
}

fn map_builder_err(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayTextDiffArithmeticOverflow
        }
        other => other,
    }
}

fn map_installed_scan_a(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayTextDiffInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayTextDiffInstalledCandidateInvalid
        }
        _ => GkrmError::ThreeWayTextDiffInstalledPreFingerprintMismatch,
    }
}

fn map_installed_scan_b(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayTextDiffInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayTextDiffInstalledCandidateInvalid
        }
        _ => GkrmError::ThreeWayTextDiffInstalledPostFingerprintMismatch,
    }
}

fn map_installed_read(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayTextDiffInstalledCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged => {
            GkrmError::ThreeWayTextDiffSourceIdentityChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayTextDiffInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayTextDiffArithmeticOverflow
        }
        other => other,
    }
}

fn map_incoming_validate(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayTextDiffIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayTextDiffIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayTextDiffIncomingResourceIdentityMismatch
        }
        _ => GkrmError::ThreeWayTextDiffIncomingCandidateInvalid,
    }
}

fn map_incoming_read(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid => {
            GkrmError::ThreeWayTextDiffIncomingCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayTextDiffArithmeticOverflow
        }
        other => map_incoming_validate(other),
    }
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
        return Err(GkrmError::ThreeWayTextDiffPlanReviewBindingMismatch);
    }
    Ok(())
}

fn verify_plan_analysis_binding(
    plan: &ThreeWayUpdatePlan,
    analysis: &ThreeWayMergeAnalysisPlan,
) -> Result<()> {
    if analysis.plan_id() != plan.plan_id()
        || analysis.resource_key() != plan.resource_key()
        || analysis.baseline_id() != plan.baseline_id()
        || analysis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayTextDiffPlanAnalysisBindingMismatch);
    }
    Ok(())
}

fn verify_review_analysis_binding(
    review: &ThreeWayPlanReview,
    analysis: &ThreeWayMergeAnalysisPlan,
) -> Result<()> {
    if analysis.review_id() != review.review_id()
        || analysis.plan_id() != review.plan_id()
        || analysis.resource_key() != review.resource_key()
        || analysis.baseline_id() != review.baseline_id()
        || analysis.installed_snapshot_fingerprint() != review.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != review.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != review.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayTextDiffReviewAnalysisBindingMismatch);
    }
    Ok(())
}

fn verify_review_structure(plan: &ThreeWayUpdatePlan, review: &ThreeWayPlanReview) -> Result<()> {
    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::ThreeWayTextDiffReviewStructuralMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::ThreeWayTextDiffReviewStructuralMismatch);
        }
    }
    Ok(())
}

fn verify_analysis_structure(
    plan: &ThreeWayUpdatePlan,
    review: &ThreeWayPlanReview,
    analysis: &ThreeWayMergeAnalysisPlan,
) -> Result<()> {
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
        return Err(GkrmError::ThreeWayTextDiffAnalysisStructuralMismatch);
    }
    for (analysis_entry, queued_path) in analysis.entries().iter().zip(queued) {
        if analysis_entry.path() != queued_path {
            return Err(GkrmError::ThreeWayTextDiffAnalysisStructuralMismatch);
        }
        let plan_entry = plan
            .entries()
            .iter()
            .find(|entry| entry.path() == analysis_entry.path())
            .ok_or(GkrmError::ThreeWayTextDiffAnalysisStructuralMismatch)?;
        if plan_entry.disposition() != ThreeWayPlanDisposition::MergeCandidate {
            return Err(GkrmError::ThreeWayTextDiffAnalysisStructuralMismatch);
        }
    }
    Ok(())
}

fn collect_ready_candidates(
    analysis: &ThreeWayMergeAnalysisPlan,
) -> Result<Vec<&ThreeWayMergeAnalysisEntry>> {
    Ok(analysis
        .entries()
        .iter()
        .filter(|entry| {
            entry.disposition() == ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
        })
        .collect())
}

/// Defensive path-sort of the selected ready subset after structural binding checks.
fn sort_ready_candidates(candidates: &mut [&ThreeWayMergeAnalysisEntry]) {
    candidates.sort_by(|left, right| left.path().cmp(right.path()));
}

/// Defensive path-sort of planned entries before summary and plan-ID encoding.
fn sort_text_diff_entries(entries: &mut [ThreeWayTextDiffEntry]) {
    entries.sort_by(|left, right| left.path().cmp(right.path()));
}

fn finalize_sorted_text_diff_plan(
    request: &ThreeWayTextDiffRequest<'_>,
    mut entries: Vec<ThreeWayTextDiffEntry>,
) -> Result<(
    Vec<ThreeWayTextDiffEntry>,
    ThreeWayTextDiffSummary,
    ThreeWayTextDiffStatus,
    ThreeWayTextDiffPlanId,
)> {
    sort_text_diff_entries(&mut entries);
    let summary = summarize(&entries)?;
    let status = status_from_summary(&summary)?;
    let text_diff_plan_id = encode_text_diff_plan_id(request, &entries, &summary, status)?;
    Ok((entries, summary, status, text_diff_plan_id))
}

fn verify_ready_candidate_invariants(
    plan: &ThreeWayUpdatePlan,
    review: &ThreeWayPlanReview,
    candidate: &ThreeWayMergeAnalysisEntry,
) -> Result<()> {
    let plan_entry = plan
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant)?;
    let review_entry = review
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant)?;

    if plan_entry.disposition() != ThreeWayPlanDisposition::MergeCandidate
        || review_entry.action() != ThreeWayReviewedAction::QueueMergeAnalysis
        || plan_entry.policy_transition() != EscrowPolicyTransition::None
        || candidate.disposition()
            != ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
        || candidate.algorithm() != Some(ThreeWayMergeAlgorithm::Utf8LineThreeWayV1)
    {
        return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
    }

    let (baseline_sha, installed_sha, incoming_sha) = candidate_hashes(
        plan_entry.baseline_state(),
        plan_entry.installed_state(),
        plan_entry.incoming_state(),
    )?;
    if candidate.baseline().sha256() != &baseline_sha
        || candidate.installed().sha256() != &installed_sha
        || candidate.incoming().sha256() != &incoming_sha
        || baseline_sha == installed_sha
        || baseline_sha == incoming_sha
        || installed_sha == incoming_sha
    {
        return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
    }

    let ThreeWayFileState::Present {
        escrow_class: Some(BaselineEscrowClass::Ignored),
        trusted_baseline_blob_available: true,
        ..
    } = plan_entry.baseline_state()
    else {
        return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
    };
    let ThreeWayFileState::Present {
        escrow_class: Some(BaselineEscrowClass::Ignored),
        ..
    } = plan_entry.incoming_state()
    else {
        return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
    };
    if !matches!(
        plan_entry.installed_state(),
        ThreeWayFileState::Present { .. }
    ) {
        return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
    }

    for side in [
        candidate.baseline(),
        candidate.installed(),
        candidate.incoming(),
    ] {
        if side.content_kind() != MergeContentKind::Text {
            return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
        }
        if !matches!(
            side.encoding(),
            MergeContentEncoding::Utf8 | MergeContentEncoding::Utf8WithBom
        ) {
            return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
        }
        if !matches!(
            side.newline_style(),
            MergeNewlineStyle::None | MergeNewlineStyle::Lf | MergeNewlineStyle::CrLf
        ) {
            return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant);
        }
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
        _ => Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant),
    }
}

fn validate_baseline_records(
    baseline: &ResolvedOfficialBaseline,
    plan: &ThreeWayUpdatePlan,
    candidates: &[&ThreeWayMergeAnalysisEntry],
) -> Result<()> {
    for candidate in candidates {
        let plan_entry = plan
            .entries()
            .iter()
            .find(|entry| entry.path() == candidate.path())
            .ok_or(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant)?;
        let expected = match plan_entry.baseline_state() {
            ThreeWayFileState::Present { sha256, .. } => *sha256,
            _ => return Err(GkrmError::ThreeWayTextDiffInvalidCandidateInvariant),
        };
        let record = baseline
            .stored_baseline()
            .files()
            .iter()
            .find(|file| file.relative_path() == candidate.path())
            .ok_or(GkrmError::ThreeWayTextDiffBaselineMismatch)?;
        if record.sha256() != &expected
            || record.escrow_class() != BaselineEscrowClass::Ignored
            || record.blob_sha256().is_none()
        {
            return Err(GkrmError::ThreeWayTextDiffBaselineMismatch);
        }
    }
    Ok(())
}

fn summarize(entries: &[ThreeWayTextDiffEntry]) -> Result<ThreeWayTextDiffSummary> {
    let mut summary =
        ThreeWayTextDiffSummary::new(entries.len(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    for entry in entries {
        match entry.disposition() {
            ThreeWayTextDiffDisposition::ReadyForMergeSynthesis => {
                inc(&mut summary.ready_for_merge_synthesis)?;
            }
            ThreeWayTextDiffDisposition::ConflictReviewTextEdits => {
                inc(&mut summary.conflict_text)?;
            }
            ThreeWayTextDiffDisposition::ConflictReviewEnvelope => {
                inc(&mut summary.conflict_envelope)?;
            }
            ThreeWayTextDiffDisposition::ConflictReviewTextAndEnvelope => {
                inc(&mut summary.conflict_text_and_envelope)?;
            }
            ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge => {
                inc(&mut summary.manual_source_too_large)?;
            }
            ThreeWayTextDiffDisposition::ManualReviewEditDistanceLimit => {
                inc(&mut summary.manual_edit_distance_limit)?;
            }
            ThreeWayTextDiffDisposition::ManualReviewDiffWorkLimit => {
                inc(&mut summary.manual_diff_work_limit)?;
            }
            ThreeWayTextDiffDisposition::ManualReviewHunkLimit => {
                inc(&mut summary.manual_hunk_limit)?;
            }
            ThreeWayTextDiffDisposition::ManualReviewOverlapGroupLimit => {
                inc(&mut summary.manual_overlap_group_limit)?;
            }
        }
        if !is_manual_disposition(entry.disposition()) {
            summary.total_installed_hunks = summary
                .total_installed_hunks
                .checked_add(entry.installed_hunks().len())
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            summary.total_incoming_hunks = summary
                .total_incoming_hunks
                .checked_add(entry.incoming_hunks().len())
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            summary.total_overlap_groups = summary
                .total_overlap_groups
                .checked_add(entry.overlap_groups().len())
                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
        }
    }

    let disposition_total = summary
        .ready_for_merge_synthesis
        .checked_add(summary.conflict_text)
        .and_then(|v| v.checked_add(summary.conflict_envelope))
        .and_then(|v| v.checked_add(summary.conflict_text_and_envelope))
        .and_then(|v| v.checked_add(summary.manual_source_too_large))
        .and_then(|v| v.checked_add(summary.manual_edit_distance_limit))
        .and_then(|v| v.checked_add(summary.manual_diff_work_limit))
        .and_then(|v| v.checked_add(summary.manual_hunk_limit))
        .and_then(|v| v.checked_add(summary.manual_overlap_group_limit))
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    if disposition_total != summary.total_candidates {
        return Err(GkrmError::ThreeWayTextDiffSummaryInvariant);
    }
    Ok(summary)
}

fn inc(value: &mut usize) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    Ok(())
}

fn is_manual_disposition(disposition: ThreeWayTextDiffDisposition) -> bool {
    matches!(
        disposition,
        ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge
            | ThreeWayTextDiffDisposition::ManualReviewEditDistanceLimit
            | ThreeWayTextDiffDisposition::ManualReviewDiffWorkLimit
            | ThreeWayTextDiffDisposition::ManualReviewHunkLimit
            | ThreeWayTextDiffDisposition::ManualReviewOverlapGroupLimit
    )
}

fn status_from_summary(summary: &ThreeWayTextDiffSummary) -> Result<ThreeWayTextDiffStatus> {
    let conflicts = summary
        .conflict_text
        .checked_add(summary.conflict_envelope)
        .and_then(|v| v.checked_add(summary.conflict_text_and_envelope))
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    let manuals = summary
        .manual_source_too_large
        .checked_add(summary.manual_edit_distance_limit)
        .and_then(|v| v.checked_add(summary.manual_diff_work_limit))
        .and_then(|v| v.checked_add(summary.manual_hunk_limit))
        .and_then(|v| v.checked_add(summary.manual_overlap_group_limit))
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;

    Ok(match (conflicts > 0, manuals > 0) {
        (false, false) => {
            if summary.ready_for_merge_synthesis == summary.total_candidates {
                ThreeWayTextDiffStatus::ReadyForMergeSynthesis
            } else {
                return Err(GkrmError::ThreeWayTextDiffStatusInvariant);
            }
        }
        (true, false) => ThreeWayTextDiffStatus::HasConflicts,
        (false, true) => ThreeWayTextDiffStatus::HasManualReviewEntries,
        (true, true) => ThreeWayTextDiffStatus::HasConflictsAndManualReviewEntries,
    })
}

fn encode_text_diff_plan_id(
    request: &ThreeWayTextDiffRequest<'_>,
    entries: &[ThreeWayTextDiffEntry],
    summary: &ThreeWayTextDiffSummary,
    status: ThreeWayTextDiffStatus,
) -> Result<ThreeWayTextDiffPlanId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-three-way-text-diff-plan-v1")
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encoder.digest(request.plan.plan_id().digest());
    encoder.digest(request.review.review_id().digest());
    encoder.digest(request.analysis.analysis_id().digest());
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
    encoder.u8(status_code(status));
    Ok(ThreeWayTextDiffPlanId::new(encoder.finish()))
}

fn id_encode(result: std::result::Result<(), GkrmError>) -> Result<()> {
    result.map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)
}

fn encode_options(
    encoder: &mut CanonicalFingerprintEncoder,
    options: ThreeWayTextDiffOptions,
) -> Result<()> {
    id_encode(encoder.usize(options.max_candidates))?;
    encoder.u64(options.max_source_bytes_per_file);
    encoder.u64(options.max_total_source_bytes);
    id_encode(encoder.usize(options.max_total_lines))?;
    id_encode(encoder.usize(options.max_lines_per_source))?;
    id_encode(encoder.usize(options.max_edit_distance_per_side))?;
    id_encode(encoder.usize(options.max_trace_cells_per_side))?;
    id_encode(encoder.usize(options.max_hunks_per_side))?;
    id_encode(encoder.usize(options.max_overlap_groups_per_entry))?;
    encoder.u64(options.baseline_store_limits.max_manifest_bytes());
    id_encode(encoder.usize(options.baseline_store_limits.max_files()))?;
    encoder.u64(options.baseline_store_limits.max_blob_bytes());
    encoder.u64(options.baseline_store_limits.max_total_blob_bytes());
    Ok(())
}

fn encode_entry(
    encoder: &mut CanonicalFingerprintEncoder,
    entry: &ThreeWayTextDiffEntry,
) -> Result<()> {
    id_encode(encoder.path(entry.path()))?;
    encoder.digest(entry.baseline_text_digest());
    encoder.digest(entry.installed_text_digest());
    encoder.digest(entry.incoming_text_digest());
    encode_envelope(encoder, entry.baseline_envelope())?;
    encode_envelope(encoder, entry.installed_envelope())?;
    encode_envelope(encoder, entry.incoming_envelope())?;
    encode_envelope_plan(encoder, entry.envelope_plan());
    id_encode(encoder.usize(entry.installed_hunks().len()))?;
    for hunk in entry.installed_hunks() {
        encode_hunk(encoder, hunk)?;
    }
    id_encode(encoder.usize(entry.incoming_hunks().len()))?;
    for hunk in entry.incoming_hunks() {
        encode_hunk(encoder, hunk)?;
    }
    id_encode(encoder.usize(entry.overlap_groups().len()))?;
    for group in entry.overlap_groups() {
        encode_overlap_group(encoder, group)?;
    }
    encoder.u8(disposition_code(entry.disposition()));
    Ok(())
}

fn encode_envelope(
    encoder: &mut CanonicalFingerprintEncoder,
    envelope: &TextEnvelope,
) -> Result<()> {
    encoder.bool(envelope.bom());
    encoder.u8(encode_newline(envelope.newline_style()));
    encoder.u8(encode_terminal_newline(envelope.terminal_newline()));
    Ok(())
}

fn encode_envelope_plan(
    encoder: &mut CanonicalFingerprintEncoder,
    plan: &ThreeWayTextEnvelopePlanState,
) {
    encoder.u8(encode_envelope_plan_state(plan));
    match plan {
        ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge => {}
        ThreeWayTextEnvelopePlanState::Planned(plan) => {
            encoder.u8(encode_resolution(plan.bom()));
            encoder.u8(encode_resolution(plan.newline_style()));
            encoder.u8(encode_resolution(plan.terminal_newline()));
        }
    }
}

fn encode_hunk(encoder: &mut CanonicalFingerprintEncoder, hunk: &TextDiffHunk) -> Result<()> {
    encoder.digest(hunk.id().digest());
    encoder.u8(encode_side(hunk.side()));
    encoder.u8(encode_kind(hunk.kind()));
    encode_line_range(encoder, &hunk.base_range())?;
    encode_line_range(encoder, &hunk.side_range())?;
    encoder.digest(hunk.base_commitment().digest());
    encoder.digest(hunk.replacement_commitment().digest());
    Ok(())
}

fn encode_overlap_group(
    encoder: &mut CanonicalFingerprintEncoder,
    group: &ThreeWayTextOverlapGroup,
) -> Result<()> {
    encoder.digest(group.id().digest());
    encode_line_range(encoder, &group.base_range())?;
    id_encode(encoder.usize(group.installed_hunk_ids().len()))?;
    for hunk_id in group.installed_hunk_ids() {
        encoder.digest(hunk_id.digest());
    }
    id_encode(encoder.usize(group.incoming_hunk_ids().len()))?;
    for hunk_id in group.incoming_hunk_ids() {
        encoder.digest(hunk_id.digest());
    }
    encoder.u8(encode_overlap_class(group.classification()));
    Ok(())
}

fn encode_summary(
    encoder: &mut CanonicalFingerprintEncoder,
    summary: &ThreeWayTextDiffSummary,
) -> Result<()> {
    id_encode(encoder.usize(summary.total_candidates))?;
    id_encode(encoder.usize(summary.ready_for_merge_synthesis))?;
    id_encode(encoder.usize(summary.conflict_text))?;
    id_encode(encoder.usize(summary.conflict_envelope))?;
    id_encode(encoder.usize(summary.conflict_text_and_envelope))?;
    id_encode(encoder.usize(summary.manual_source_too_large))?;
    id_encode(encoder.usize(summary.manual_edit_distance_limit))?;
    id_encode(encoder.usize(summary.manual_diff_work_limit))?;
    id_encode(encoder.usize(summary.manual_hunk_limit))?;
    id_encode(encoder.usize(summary.manual_overlap_group_limit))?;
    id_encode(encoder.usize(summary.total_installed_hunks))?;
    id_encode(encoder.usize(summary.total_incoming_hunks))?;
    id_encode(encoder.usize(summary.total_overlap_groups))?;
    Ok(())
}

fn disposition_code(disposition: ThreeWayTextDiffDisposition) -> u8 {
    match disposition {
        ThreeWayTextDiffDisposition::ReadyForMergeSynthesis => 0,
        ThreeWayTextDiffDisposition::ConflictReviewTextEdits => 1,
        ThreeWayTextDiffDisposition::ConflictReviewEnvelope => 2,
        ThreeWayTextDiffDisposition::ConflictReviewTextAndEnvelope => 3,
        ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge => 4,
        ThreeWayTextDiffDisposition::ManualReviewEditDistanceLimit => 5,
        ThreeWayTextDiffDisposition::ManualReviewDiffWorkLimit => 6,
        ThreeWayTextDiffDisposition::ManualReviewHunkLimit => 7,
        ThreeWayTextDiffDisposition::ManualReviewOverlapGroupLimit => 8,
    }
}

fn status_code(status: ThreeWayTextDiffStatus) -> u8 {
    match status {
        ThreeWayTextDiffStatus::ReadyForMergeSynthesis => 0,
        ThreeWayTextDiffStatus::HasConflicts => 1,
        ThreeWayTextDiffStatus::HasManualReviewEntries => 2,
        ThreeWayTextDiffStatus::HasConflictsAndManualReviewEntries => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::envelope::plan_envelope;
    use super::lines::split_logical_lines;
    use super::*;
    use crate::merge_content::VerifiedMergeTextBuilder;
    use crate::MergeNewlineStyle;

    fn analyze_retained(bytes: &[u8]) -> VerifiedMergeText {
        let mut builder = VerifiedMergeTextBuilder::new(bytes.len() as u64);
        builder.push(bytes).expect("push");
        builder.finish().expect("finish")
    }

    fn analyze_meta(bytes: &[u8]) -> MergeContentAnalysis {
        let mut builder = VerifiedMergeTextBuilder::metadata_only();
        builder.push(bytes).expect("push");
        builder.finish_metadata().expect("meta")
    }

    #[test]
    fn bom_only_raw_metadata_versus_empty_logical_lines() {
        let bytes = [0xEF, 0xBB, 0xBF];
        let verified = analyze_retained(&bytes);
        let expected = analyze_meta(&bytes);
        ensure_metadata_matches(&expected, verified.metadata()).expect("task16 match");
        assert_eq!(
            verified.metadata().encoding(),
            MergeContentEncoding::Utf8WithBom
        );
        assert_eq!(verified.metadata().line_count(), Some(1));
        assert_eq!(verified.metadata().max_line_bytes(), Some(3));
        assert!(!verified.metadata().is_empty());

        let (lines, bom, terminal) = split_logical_lines(
            verified.retained_bytes().expect("retained"),
            verified.metadata().encoding(),
            verified.metadata().newline_style(),
        )
        .expect("logical");
        assert!(bom);
        assert!(lines.is_empty());
        assert!(!terminal);
        assert_ne!(
            verified.metadata().line_count().unwrap_or(0),
            lines.len(),
            "raw Task 16 line_count must not be compared to logical_lines.len()"
        );
    }

    #[test]
    fn bom_plus_one_line_strips_bom_from_logical_content() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello");
        let verified = analyze_retained(&bytes);
        let expected = analyze_meta(&bytes);
        ensure_metadata_matches(&expected, verified.metadata()).expect("task16 match");

        let (lines, bom, terminal) = split_logical_lines(
            verified.retained_bytes().expect("retained"),
            verified.metadata().encoding(),
            verified.metadata().newline_style(),
        )
        .expect("logical");
        assert!(bom);
        assert_eq!(lines, vec![b"hello".to_vec()]);
        assert!(!terminal);
        assert!(!lines[0].starts_with(&[0xEF, 0xBB, 0xBF]));
    }

    #[test]
    fn bom_plus_terminal_lf_uses_raw_metrics_and_logical_lines() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello\n");
        let verified = analyze_retained(&bytes);
        let expected = analyze_meta(&bytes);
        ensure_metadata_matches(&expected, verified.metadata()).expect("task16 match");
        assert_eq!(verified.metadata().newline_style(), MergeNewlineStyle::Lf);
        assert_eq!(verified.metadata().line_count(), Some(1));

        let (lines, bom, terminal) = split_logical_lines(
            verified.retained_bytes().expect("retained"),
            verified.metadata().encoding(),
            verified.metadata().newline_style(),
        )
        .expect("logical");
        assert!(bom);
        assert_eq!(lines, vec![b"hello".to_vec()]);
        assert!(terminal);
        assert!(TextEnvelope::new(
            bom,
            SupportedTextNewlineStyle::Lf,
            TextTerminalNewline::Present,
        )
        .bom());
    }

    #[test]
    fn bom_plus_terminal_crlf_uses_raw_metrics_and_logical_lines() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello\r\n");
        let verified = analyze_retained(&bytes);
        let expected = analyze_meta(&bytes);
        ensure_metadata_matches(&expected, verified.metadata()).expect("task16 match");
        assert_eq!(verified.metadata().newline_style(), MergeNewlineStyle::CrLf);

        let (lines, bom, terminal) = split_logical_lines(
            verified.retained_bytes().expect("retained"),
            verified.metadata().encoding(),
            verified.metadata().newline_style(),
        )
        .expect("logical");
        assert!(bom);
        assert_eq!(lines, vec![b"hello".to_vec()]);
        assert!(terminal);
        let envelope = TextEnvelope::new(
            bom,
            SupportedTextNewlineStyle::CrLf,
            TextTerminalNewline::Present,
        );
        assert!(envelope.bom());
        assert_eq!(envelope.newline_style(), SupportedTextNewlineStyle::CrLf);
    }

    #[test]
    fn envelope_from_verified_source_derives_terminal_only_when_retained() {
        let cases: &[(&[u8], TextTerminalNewline, &str)] = &[
            (b"", TextTerminalNewline::Absent, "empty"),
            (b"abc", TextTerminalNewline::Absent, "no terminal newline"),
            (b"abc\n", TextTerminalNewline::Present, "terminal LF"),
            (b"abc\r\n", TextTerminalNewline::Present, "terminal CRLF"),
            (
                b"\xEF\xBB\xBFx\n",
                TextTerminalNewline::Present,
                "BOM plus terminal",
            ),
        ];
        for (bytes, expected_terminal, label) in cases {
            let meta = analyze_meta(bytes);
            let known = envelope_from_verified_source(&meta, Some(bytes)).expect(label);
            assert_eq!(known.terminal_newline(), *expected_terminal, "{label}");
            assert_eq!(
                known.bom(),
                meta.encoding() == MergeContentEncoding::Utf8WithBom,
                "{label}"
            );

            let unknown = envelope_from_verified_source(&meta, None).expect(label);
            assert_eq!(
                unknown.terminal_newline(),
                TextTerminalNewline::Unknown,
                "{label}"
            );
            assert_eq!(unknown.bom(), known.bom(), "{label}");
            assert_eq!(unknown.newline_style(), known.newline_style(), "{label}");
            assert!(
                plan_envelope(&unknown, &unknown, &unknown).is_err(),
                "{label}: unknown terminal must not resolve"
            );
        }
    }

    #[test]
    fn mixed_retention_preserves_known_sibling_terminals() {
        let retained = b"hello\n";
        let oversized_meta = analyze_meta(b"this-source-is-too-large-for-retain\n");
        let retained_meta = analyze_meta(retained);

        let baseline =
            envelope_from_verified_source(&oversized_meta, None).expect("oversized baseline");
        let installed =
            envelope_from_verified_source(&retained_meta, Some(retained)).expect("retained L");
        let incoming =
            envelope_from_verified_source(&retained_meta, Some(retained)).expect("retained N");

        assert_eq!(baseline.terminal_newline(), TextTerminalNewline::Unknown);
        assert_eq!(installed.terminal_newline(), TextTerminalNewline::Present);
        assert_eq!(incoming.terminal_newline(), TextTerminalNewline::Present);
        assert!(plan_envelope(&baseline, &installed, &incoming).is_err());
    }

    fn synthetic_entry(path: &str, terminal: TextTerminalNewline) -> ThreeWayTextDiffEntry {
        let digest = Sha256Digest::new([path.as_bytes().first().copied().unwrap_or(0); 32]);
        let envelope = TextEnvelope::new(false, SupportedTextNewlineStyle::Lf, terminal);
        ThreeWayTextDiffEntry::new(
            ResourceRelativePath::try_from_slash_str(path).expect("path"),
            digest,
            Sha256Digest::new([1; 32]),
            Sha256Digest::new([2; 32]),
            envelope,
            envelope,
            envelope,
            ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge,
        )
    }

    #[test]
    fn sort_text_diff_entries_is_independent_of_input_order() {
        let orders = [
            vec!["zebra.lua", "alpha.lua", "middle.lua"],
            vec!["middle.lua", "zebra.lua", "alpha.lua"],
            vec!["alpha.lua", "middle.lua", "zebra.lua"],
            vec!["zebra.lua", "middle.lua", "alpha.lua"],
        ];
        let expected = ["alpha.lua", "middle.lua", "zebra.lua"];
        let mut digests = Vec::new();
        let mut summaries = Vec::new();
        let mut statuses = Vec::new();

        for order in orders {
            let mut entries = order
                .iter()
                .map(|path| synthetic_entry(path, TextTerminalNewline::Absent))
                .collect::<Vec<_>>();
            sort_text_diff_entries(&mut entries);
            assert_eq!(
                entries
                    .iter()
                    .map(|entry| entry.path().as_str())
                    .collect::<Vec<_>>(),
                expected
            );
            let summary = summarize(&entries).expect("summary");
            let status = status_from_summary(&summary).expect("status");
            let mut encoder = crate::three_way_fingerprint::CanonicalFingerprintEncoder::new(
                "gkrm-three-way-text-diff-plan-v1",
            )
            .expect("encoder");
            // Binding prefix is fixed so only entry/summary/status ordering is measured.
            encoder.digest(&Sha256Digest::new([0x11; 32]));
            encoder.digest(&Sha256Digest::new([0x22; 32]));
            encoder.digest(&Sha256Digest::new([0x33; 32]));
            encoder.string("gksphone").unwrap();
            encoder.string(&"aa".repeat(32)).unwrap();
            encoder.digest(&Sha256Digest::new([0x44; 32]));
            encoder.digest(&Sha256Digest::new([0x55; 32]));
            encoder.digest(&Sha256Digest::new([0x66; 32]));
            encode_options(&mut encoder, ThreeWayTextDiffOptions::default()).unwrap();
            id_encode(encoder.usize(entries.len())).unwrap();
            for entry in &entries {
                encode_entry(&mut encoder, entry).unwrap();
            }
            encode_summary(&mut encoder, &summary).unwrap();
            encoder.u8(status_code(status));
            digests.push(encoder.finish());
            summaries.push(summary);
            statuses.push(status);
        }

        assert!(digests.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(summaries.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(statuses.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn retained_sibling_terminal_change_affects_entry_encoding() {
        let mut without = vec![
            synthetic_entry("big.lua", TextTerminalNewline::Unknown),
            synthetic_entry("small.lua", TextTerminalNewline::Absent),
        ];
        let mut with_nl = vec![
            synthetic_entry("big.lua", TextTerminalNewline::Unknown),
            synthetic_entry("small.lua", TextTerminalNewline::Present),
        ];
        sort_text_diff_entries(&mut without);
        sort_text_diff_entries(&mut with_nl);

        let mut left =
            crate::three_way_fingerprint::CanonicalFingerprintEncoder::new("gkrm-test-entry-v1")
                .unwrap();
        encode_entry(&mut left, &without[1]).unwrap();
        let mut right =
            crate::three_way_fingerprint::CanonicalFingerprintEncoder::new("gkrm-test-entry-v1")
                .unwrap();
        encode_entry(&mut right, &with_nl[1]).unwrap();
        assert_ne!(left.finish(), right.finish());
        assert_eq!(
            without[1].disposition(),
            ThreeWayTextDiffDisposition::ManualReviewSourceTooLarge
        );
        assert_eq!(
            with_nl[1].envelope_plan(),
            &ThreeWayTextEnvelopePlanState::UnavailableSourceTooLarge
        );
    }
}
