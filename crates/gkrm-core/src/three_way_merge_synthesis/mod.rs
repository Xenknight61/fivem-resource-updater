//! Trusted, deterministic, read-only merge-synthesis operation planner (Milestone 2 Task 18).

#![allow(clippy::type_complexity, clippy::too_many_arguments)]

mod id;
mod schedule;

use crate::baseline::store::stream_verified_blob_for_path;
use crate::baseline::BaselineStoreLimits;
use crate::merge_content::{StreamingByteBudget, VerifiedMergeText, VerifiedMergeTextBuilder};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::three_way_text_diff::{
    commitment_for_range, split_logical_lines, LineRange, SupportedTextNewlineStyle, TextDiffHunk,
    TextDiffHunkId, TextDiffHunkKind, TextLineSequenceCommitment, TextTerminalNewline,
    ThreeWayTextDiffDisposition, ThreeWayTextDiffEntry, ThreeWayTextDiffPlan,
    ThreeWayTextDiffPlanId, ThreeWayTextEnvelopePlanState, ThreeWayTextOverlapClassification,
    ThreeWayTextScalarResolution,
};
use crate::{
    BaselineEscrowClass, BaselineId, EscrowPolicyTransition, GkrmError, IncomingMergeContentSource,
    InstalledMergeContentSource, MergeContentAnalysis, MergeNewlineStyle, ResolvedOfficialBaseline,
    ResourceRelativePath, Result, SafeResourceKey, Sha256Digest, ThreeWayFileState,
    ThreeWayMergeAlgorithm, ThreeWayMergeAnalysisDisposition, ThreeWayMergeAnalysisEntry,
    ThreeWayMergeAnalysisId, ThreeWayMergeAnalysisPlan, ThreeWayPlanDisposition, ThreeWayPlanId,
    ThreeWayPlanReview, ThreeWayPlanReviewId, ThreeWayReviewedAction, ThreeWayUpdatePlan,
};

use self::id::{
    encode_disposition, encode_kind, encode_newline, encode_status, encode_terminal_newline,
};
use self::schedule::synthesize_operations;
pub(crate) use self::schedule::verify_equivalent_operation_fidelity;

const DEFAULT_MAX_CANDIDATES: usize = 1_000;
const DEFAULT_MAX_SOURCE_BYTES_PER_FILE: u64 = 4 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const DEFAULT_MAX_LINES_PER_SOURCE: usize = 200_000;
const DEFAULT_MAX_TOTAL_LINES: usize = 600_000;
const DEFAULT_MAX_OPERATIONS_PER_ENTRY: usize = 50_000;
const DEFAULT_MAX_TOTAL_OPERATIONS: usize = 500_000;

/// Opaque validated Task 18 options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreeWayMergeSynthesisOptions {
    max_candidates: usize,
    max_source_bytes_per_file: u64,
    max_total_source_bytes: u64,
    max_lines_per_source: usize,
    max_total_lines: usize,
    max_operations_per_entry: usize,
    max_total_operations: usize,
    baseline_store_limits: BaselineStoreLimits,
}

impl Default for ThreeWayMergeSynthesisOptions {
    fn default() -> Self {
        Self {
            max_candidates: DEFAULT_MAX_CANDIDATES,
            max_source_bytes_per_file: DEFAULT_MAX_SOURCE_BYTES_PER_FILE,
            max_total_source_bytes: DEFAULT_MAX_TOTAL_SOURCE_BYTES,
            max_lines_per_source: DEFAULT_MAX_LINES_PER_SOURCE,
            max_total_lines: DEFAULT_MAX_TOTAL_LINES,
            max_operations_per_entry: DEFAULT_MAX_OPERATIONS_PER_ENTRY,
            max_total_operations: DEFAULT_MAX_TOTAL_OPERATIONS,
            baseline_store_limits: BaselineStoreLimits::default(),
        }
    }
}

impl ThreeWayMergeSynthesisOptions {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        max_candidates: usize,
        max_source_bytes_per_file: u64,
        max_total_source_bytes: u64,
        max_lines_per_source: usize,
        max_total_lines: usize,
        max_operations_per_entry: usize,
        max_total_operations: usize,
        baseline_store_limits: BaselineStoreLimits,
    ) -> Result<Self> {
        let options = Self {
            max_candidates,
            max_source_bytes_per_file,
            max_total_source_bytes,
            max_lines_per_source,
            max_total_lines,
            max_operations_per_entry,
            max_total_operations,
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
    pub fn max_lines_per_source(&self) -> usize {
        self.max_lines_per_source
    }
    pub fn max_total_lines(&self) -> usize {
        self.max_total_lines
    }
    pub fn max_operations_per_entry(&self) -> usize {
        self.max_operations_per_entry
    }
    pub fn max_total_operations(&self) -> usize {
        self.max_total_operations
    }
    pub fn baseline_store_limits(&self) -> &BaselineStoreLimits {
        &self.baseline_store_limits
    }

    fn validate(self) -> Result<()> {
        for (value, name) in [
            (self.max_candidates, "max_candidates"),
            (self.max_lines_per_source, "max_lines_per_source"),
            (self.max_total_lines, "max_total_lines"),
            (self.max_operations_per_entry, "max_operations_per_entry"),
            (self.max_total_operations, "max_total_operations"),
        ] {
            if value == 0 {
                return Err(GkrmError::ThreeWayMergeSynthesisOptionsInvalid { limit: name });
            }
        }
        if self.max_source_bytes_per_file == 0 {
            return Err(GkrmError::ThreeWayMergeSynthesisOptionsInvalid {
                limit: "max_source_bytes_per_file",
            });
        }
        if self.max_total_source_bytes == 0 {
            return Err(GkrmError::ThreeWayMergeSynthesisOptionsInvalid {
                limit: "max_total_source_bytes",
            });
        }
        if self.max_source_bytes_per_file > self.max_total_source_bytes {
            return Err(GkrmError::ThreeWayMergeSynthesisOptionsInvalid {
                limit: "max_source_bytes_per_file",
            });
        }
        if self.max_lines_per_source > self.max_total_lines {
            return Err(GkrmError::ThreeWayMergeSynthesisOptionsInvalid {
                limit: "max_lines_per_source",
            });
        }
        if self.max_operations_per_entry > self.max_total_operations {
            return Err(GkrmError::ThreeWayMergeSynthesisOptionsInvalid {
                limit: "max_operations_per_entry",
            });
        }
        Ok(())
    }
}

/// Opaque Task 18 request.
pub struct ThreeWayMergeSynthesisRequest<'a> {
    plan: &'a ThreeWayUpdatePlan,
    review: &'a ThreeWayPlanReview,
    analysis: &'a ThreeWayMergeAnalysisPlan,
    text_diff: &'a ThreeWayTextDiffPlan,
    baseline: &'a ResolvedOfficialBaseline,
    installed_source: &'a InstalledMergeContentSource,
    incoming_source: &'a IncomingMergeContentSource,
    options: ThreeWayMergeSynthesisOptions,
}

impl<'a> ThreeWayMergeSynthesisRequest<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        plan: &'a ThreeWayUpdatePlan,
        review: &'a ThreeWayPlanReview,
        analysis: &'a ThreeWayMergeAnalysisPlan,
        text_diff: &'a ThreeWayTextDiffPlan,
        baseline: &'a ResolvedOfficialBaseline,
        installed_source: &'a InstalledMergeContentSource,
        incoming_source: &'a IncomingMergeContentSource,
        options: ThreeWayMergeSynthesisOptions,
    ) -> Result<Self> {
        options.validate()?;
        Ok(Self {
            plan,
            review,
            analysis,
            text_diff,
            baseline,
            installed_source,
            incoming_source,
            options,
        })
    }
}

/// Closed operation kind for metadata-only synthesis planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeSynthesisOperationKind {
    CopyBase,
    UseInstalledReplacement,
    UseIncomingReplacement,
    UseEquivalentReplacement,
}

/// Opaque operation identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MergeSynthesisOperationId(Sha256Digest);

impl MergeSynthesisOperationId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_digest_for_test(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

/// Immutable synthesis operation (no plaintext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSynthesisOperation {
    id: MergeSynthesisOperationId,
    kind: MergeSynthesisOperationKind,
    base_range: LineRange,
    source_range: Option<LineRange>,
    source_hunk_id: Option<TextDiffHunkId>,
    equivalent_peer_hunk_id: Option<TextDiffHunkId>,
    output_commitment: TextLineSequenceCommitment,
}

impl MergeSynthesisOperation {
    pub fn id(&self) -> &MergeSynthesisOperationId {
        &self.id
    }
    pub fn kind(&self) -> MergeSynthesisOperationKind {
        self.kind
    }
    pub fn base_range(&self) -> LineRange {
        self.base_range
    }
    pub fn source_range(&self) -> Option<LineRange> {
        self.source_range
    }
    pub fn source_hunk_id(&self) -> Option<&TextDiffHunkId> {
        self.source_hunk_id.as_ref()
    }
    pub fn equivalent_peer_hunk_id(&self) -> Option<&TextDiffHunkId> {
        self.equivalent_peer_hunk_id.as_ref()
    }
    pub fn output_commitment(&self) -> &TextLineSequenceCommitment {
        &self.output_commitment
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts_for_test(
        id: MergeSynthesisOperationId,
        kind: MergeSynthesisOperationKind,
        base_range: LineRange,
        source_range: Option<LineRange>,
        source_hunk_id: Option<TextDiffHunkId>,
        equivalent_peer_hunk_id: Option<TextDiffHunkId>,
        output_commitment: TextLineSequenceCommitment,
    ) -> Self {
        Self {
            id,
            kind,
            base_range,
            source_range,
            source_hunk_id,
            equivalent_peer_hunk_id,
            output_commitment,
        }
    }
}

/// Final envelope metadata choice (no encoded bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalTextEnvelope {
    bom: bool,
    newline_style: SupportedTextNewlineStyle,
    terminal_newline: TextTerminalNewline,
}

impl FinalTextEnvelope {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn from_parts(
        bom: bool,
        newline_style: SupportedTextNewlineStyle,
        terminal_newline: TextTerminalNewline,
    ) -> Self {
        Self {
            bom,
            newline_style,
            terminal_newline,
        }
    }

    pub fn bom(&self) -> bool {
        self.bom
    }
    pub fn newline_style(&self) -> SupportedTextNewlineStyle {
        self.newline_style
    }
    pub fn terminal_newline(&self) -> TextTerminalNewline {
        self.terminal_newline
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeSynthesisDisposition {
    ReadyForByteSynthesis,
    ManualReviewOperationLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeSynthesisStatus {
    ReadyForByteSynthesis,
    HasManualReviewEntries,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayMergeSynthesisPlanId(Sha256Digest);

impl ThreeWayMergeSynthesisPlanId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    pub(crate) fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayMergeSynthesisEntry {
    path: ResourceRelativePath,
    baseline_text_digest: Sha256Digest,
    installed_text_digest: Sha256Digest,
    incoming_text_digest: Sha256Digest,
    final_envelope: FinalTextEnvelope,
    operations: Vec<MergeSynthesisOperation>,
    merged_line_sequence_commitment: Option<TextLineSequenceCommitment>,
    disposition: MergeSynthesisDisposition,
}

impl ThreeWayMergeSynthesisEntry {
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
    pub fn final_envelope(&self) -> FinalTextEnvelope {
        self.final_envelope
    }
    pub fn operations(&self) -> &[MergeSynthesisOperation] {
        &self.operations
    }
    pub fn merged_line_sequence_commitment(&self) -> Option<&TextLineSequenceCommitment> {
        self.merged_line_sequence_commitment.as_ref()
    }
    pub fn disposition(&self) -> MergeSynthesisDisposition {
        self.disposition
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSynthesisSummary {
    total_candidates: usize,
    ready_for_byte_synthesis: usize,
    manual_operation_limit: usize,
    total_operations: usize,
}

impl MergeSynthesisSummary {
    pub fn total_candidates(&self) -> usize {
        self.total_candidates
    }
    pub fn ready_for_byte_synthesis(&self) -> usize {
        self.ready_for_byte_synthesis
    }
    pub fn manual_operation_limit(&self) -> usize {
        self.manual_operation_limit
    }
    pub fn total_operations(&self) -> usize {
        self.total_operations
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayMergeSynthesisPlan {
    resource_key: SafeResourceKey,
    baseline_id: BaselineId,
    plan_id: ThreeWayPlanId,
    review_id: ThreeWayPlanReviewId,
    analysis_id: ThreeWayMergeAnalysisId,
    text_diff_plan_id: ThreeWayTextDiffPlanId,
    installed_snapshot_fingerprint: Sha256Digest,
    incoming_package_fingerprint: Sha256Digest,
    incoming_resource_fingerprint: Sha256Digest,
    entries: Vec<ThreeWayMergeSynthesisEntry>,
    summary: MergeSynthesisSummary,
    status: MergeSynthesisStatus,
    synthesis_plan_id: ThreeWayMergeSynthesisPlanId,
}

impl ThreeWayMergeSynthesisPlan {
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
    pub fn installed_snapshot_fingerprint(&self) -> &Sha256Digest {
        &self.installed_snapshot_fingerprint
    }
    pub fn incoming_package_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_package_fingerprint
    }
    pub fn incoming_resource_fingerprint(&self) -> &Sha256Digest {
        &self.incoming_resource_fingerprint
    }
    pub fn entries(&self) -> &[ThreeWayMergeSynthesisEntry] {
        &self.entries
    }
    pub fn summary(&self) -> &MergeSynthesisSummary {
        &self.summary
    }
    pub fn status(&self) -> MergeSynthesisStatus {
        self.status
    }
    pub fn synthesis_plan_id(&self) -> &ThreeWayMergeSynthesisPlanId {
        &self.synthesis_plan_id
    }

    #[cfg(test)]
    pub(crate) fn clone_with_entries_for_test(
        &self,
        entries: Vec<ThreeWayMergeSynthesisEntry>,
    ) -> Self {
        let mut cloned = self.clone();
        cloned.entries = entries;
        cloned
    }
}

impl ThreeWayMergeSynthesisEntry {
    #[cfg(test)]
    pub(crate) fn mutate_path_for_test(&mut self, path: ResourceRelativePath) {
        self.path = path;
    }

    #[cfg(test)]
    pub(crate) fn mutate_disposition_for_test(&mut self, disposition: MergeSynthesisDisposition) {
        self.disposition = disposition;
    }

    #[cfg(test)]
    pub(crate) fn mutate_envelope_for_test(&mut self, envelope: FinalTextEnvelope) {
        self.final_envelope = envelope;
    }

    #[cfg(test)]
    pub(crate) fn mutate_operations_for_test(&mut self, operations: Vec<MergeSynthesisOperation>) {
        self.operations = operations;
    }

    #[cfg(test)]
    pub(crate) fn mutate_merged_commitment_for_test(
        &mut self,
        commitment: Option<TextLineSequenceCommitment>,
    ) {
        self.merged_line_sequence_commitment = commitment;
    }
}

/// Plan metadata-only merge-synthesis operations for ready Task 17 entries.
pub fn plan_three_way_merge_synthesis(
    request: ThreeWayMergeSynthesisRequest<'_>,
) -> Result<ThreeWayMergeSynthesisPlan> {
    request.options.validate()?;
    verify_bindings(&request)?;
    verify_structures(&request)?;
    if request.baseline.baseline_id() != request.plan.baseline_id()
        || request.baseline.resource_key() != request.plan.resource_key()
    {
        return Err(GkrmError::ThreeWayMergeSynthesisBaselineMismatch);
    }

    let mut candidates = collect_ready_candidates(request.text_diff);
    if candidates.is_empty() {
        return Err(GkrmError::ThreeWayMergeSynthesisNoReadyCandidates);
    }
    if candidates.len() > request.options.max_candidates {
        return Err(GkrmError::ThreeWayMergeSynthesisCandidateLimitExceeded {
            limit: request.options.max_candidates,
            actual: candidates.len(),
        });
    }
    sort_ready_candidates(&mut candidates);
    for candidate in &candidates {
        verify_ready_candidate_invariants(&request, candidate)?;
    }

    let (fingerprint_a, root_identity_a, resource_identity_a) = request
        .installed_source
        .scan_fingerprint_for_plan(request.plan.resource_key())
        .map_err(map_installed_scan_a)?;
    if &fingerprint_a != request.plan.installed_snapshot_fingerprint() {
        return Err(GkrmError::ThreeWayMergeSynthesisInstalledPreFingerprintMismatch);
    }
    request
        .incoming_source
        .validate_against_plan(request.plan)
        .map_err(map_incoming_validate)?;

    let mut total_budget = StreamingByteBudget::new(request.options.max_total_source_bytes);
    let mut total_lines = 0usize;
    let mut total_operations = 0usize;
    let mut entries = Vec::with_capacity(candidates.len());

    for candidate in &candidates {
        let analysis_entry = request
            .analysis
            .entries()
            .iter()
            .find(|entry| entry.path() == candidate.path())
            .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant)?;
        let entry = plan_candidate_entry(
            &request,
            candidate,
            analysis_entry,
            &mut total_budget,
            &mut total_lines,
            &mut total_operations,
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
        return Err(GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged);
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let summary = summarize(&entries)?;
    let status = status_from_summary(&summary)?;
    let synthesis_plan_id = encode_plan_id(&request, &entries, &summary, status)?;

    Ok(ThreeWayMergeSynthesisPlan {
        resource_key: request.plan.resource_key().clone(),
        baseline_id: request.plan.baseline_id().clone(),
        plan_id: *request.plan.plan_id(),
        review_id: *request.review.review_id(),
        analysis_id: *request.analysis.analysis_id(),
        text_diff_plan_id: *request.text_diff.text_diff_plan_id(),
        installed_snapshot_fingerprint: *request.plan.installed_snapshot_fingerprint(),
        incoming_package_fingerprint: *request.plan.incoming_package_fingerprint(),
        incoming_resource_fingerprint: *request.plan.incoming_resource_fingerprint(),
        entries,
        summary,
        status,
        synthesis_plan_id,
    })
}

fn collect_ready_candidates(text_diff: &ThreeWayTextDiffPlan) -> Vec<&ThreeWayTextDiffEntry> {
    text_diff
        .entries()
        .iter()
        .filter(|entry| entry.disposition() == ThreeWayTextDiffDisposition::ReadyForMergeSynthesis)
        .collect()
}

fn sort_ready_candidates(candidates: &mut [&ThreeWayTextDiffEntry]) {
    candidates.sort_by(|left, right| left.path().cmp(right.path()));
}

fn verify_bindings(request: &ThreeWayMergeSynthesisRequest<'_>) -> Result<()> {
    let plan = request.plan;
    let review = request.review;
    let analysis = request.analysis;
    let text_diff = request.text_diff;

    if review.plan_id() != plan.plan_id()
        || review.resource_key() != plan.resource_key()
        || review.baseline_id() != plan.baseline_id()
        || review.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || review.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || review.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergeSynthesisPlanReviewBindingMismatch);
    }
    if analysis.plan_id() != plan.plan_id()
        || analysis.resource_key() != plan.resource_key()
        || analysis.baseline_id() != plan.baseline_id()
        || analysis.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || analysis.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || analysis.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergeSynthesisPlanAnalysisBindingMismatch);
    }
    if text_diff.plan_id() != plan.plan_id()
        || text_diff.resource_key() != plan.resource_key()
        || text_diff.baseline_id() != plan.baseline_id()
        || text_diff.installed_snapshot_fingerprint() != plan.installed_snapshot_fingerprint()
        || text_diff.incoming_package_fingerprint() != plan.incoming_package_fingerprint()
        || text_diff.incoming_resource_fingerprint() != plan.incoming_resource_fingerprint()
    {
        return Err(GkrmError::ThreeWayMergeSynthesisPlanTextDiffBindingMismatch);
    }
    if analysis.review_id() != review.review_id() {
        return Err(GkrmError::ThreeWayMergeSynthesisReviewAnalysisBindingMismatch);
    }
    if text_diff.review_id() != review.review_id() {
        return Err(GkrmError::ThreeWayMergeSynthesisReviewTextDiffBindingMismatch);
    }
    if text_diff.analysis_id() != analysis.analysis_id() {
        return Err(GkrmError::ThreeWayMergeSynthesisAnalysisTextDiffBindingMismatch);
    }
    Ok(())
}

fn verify_structures(request: &ThreeWayMergeSynthesisRequest<'_>) -> Result<()> {
    let plan = request.plan;
    let review = request.review;
    let analysis = request.analysis;
    let text_diff = request.text_diff;

    if plan.entries().len() != review.entries().len() {
        return Err(GkrmError::ThreeWayMergeSynthesisReviewStructuralMismatch);
    }
    for (plan_entry, review_entry) in plan.entries().iter().zip(review.entries()) {
        if plan_entry.path() != review_entry.path() {
            return Err(GkrmError::ThreeWayMergeSynthesisReviewStructuralMismatch);
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
        return Err(GkrmError::ThreeWayMergeSynthesisAnalysisStructuralMismatch);
    }
    for (analysis_entry, queued_path) in analysis.entries().iter().zip(queued) {
        if analysis_entry.path() != queued_path {
            return Err(GkrmError::ThreeWayMergeSynthesisAnalysisStructuralMismatch);
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
        return Err(GkrmError::ThreeWayMergeSynthesisTextDiffStructuralMismatch);
    }
    // Task 17 stores entries in path-sorted order; compare as sorted sets via zip after sort.
    let mut text_paths: Vec<_> = text_diff.entries().iter().map(|e| e.path()).collect();
    let mut analysis_paths = ready_analysis;
    text_paths.sort();
    analysis_paths.sort();
    if text_paths != analysis_paths {
        return Err(GkrmError::ThreeWayMergeSynthesisTextDiffStructuralMismatch);
    }
    Ok(())
}

fn verify_ready_candidate_invariants(
    request: &ThreeWayMergeSynthesisRequest<'_>,
    candidate: &ThreeWayTextDiffEntry,
) -> Result<()> {
    let plan_entry = request
        .plan
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant)?;
    let review_entry = request
        .review
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant)?;
    let analysis_entry = request
        .analysis
        .entries()
        .iter()
        .find(|entry| entry.path() == candidate.path())
        .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant)?;

    if plan_entry.disposition() != ThreeWayPlanDisposition::MergeCandidate
        || review_entry.action() != ThreeWayReviewedAction::QueueMergeAnalysis
        || plan_entry.policy_transition() != EscrowPolicyTransition::None
        || analysis_entry.disposition()
            != ThreeWayMergeAnalysisDisposition::ReadyForUtf8LineMergePlanning
        || analysis_entry.algorithm() != Some(ThreeWayMergeAlgorithm::Utf8LineThreeWayV1)
        || candidate.disposition() != ThreeWayTextDiffDisposition::ReadyForMergeSynthesis
    {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant);
    }
    if !matches!(
        candidate.envelope_plan(),
        ThreeWayTextEnvelopePlanState::Planned(_)
    ) {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
    }
    for envelope in [
        candidate.baseline_envelope(),
        candidate.installed_envelope(),
        candidate.incoming_envelope(),
    ] {
        if envelope.terminal_newline() == TextTerminalNewline::Unknown {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
        }
    }
    let ThreeWayFileState::Present {
        escrow_class: Some(BaselineEscrowClass::Ignored),
        trusted_baseline_blob_available: true,
        ..
    } = plan_entry.baseline_state()
    else {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidCandidateInvariant);
    };
    Ok(())
}

fn plan_candidate_entry(
    request: &ThreeWayMergeSynthesisRequest<'_>,
    candidate: &ThreeWayTextDiffEntry,
    analysis_entry: &ThreeWayMergeAnalysisEntry,
    total_budget: &mut StreamingByteBudget,
    total_lines: &mut usize,
    total_operations: &mut usize,
) -> Result<ThreeWayMergeSynthesisEntry> {
    let max_retain = request.options.max_source_bytes_per_file;
    let baseline_verified = read_baseline_verified(
        request.baseline,
        candidate.path(),
        *candidate.baseline_text_digest(),
        max_retain,
        request.options.baseline_store_limits(),
        |n| total_budget.add_task18(n),
    )?;
    let installed_verified = request
        .installed_source
        .read_verified_merge_text(
            candidate.path(),
            *candidate.installed_text_digest(),
            max_retain,
            |n| total_budget.add_task18(n),
        )
        .map_err(map_installed_read)?;
    let incoming_verified = request
        .incoming_source
        .read_verified_merge_text(
            candidate.path(),
            *candidate.incoming_text_digest(),
            max_retain,
            |n| total_budget.add_task18(n),
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
    {
        return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
    }

    let baseline_bytes =
        baseline_bytes.ok_or(GkrmError::ThreeWayMergeSynthesisSourceByteLimitExceeded {
            limit: max_retain,
            actual: baseline_meta.byte_length(),
        })?;
    let installed_bytes =
        installed_bytes.ok_or(GkrmError::ThreeWayMergeSynthesisSourceByteLimitExceeded {
            limit: max_retain,
            actual: installed_meta.byte_length(),
        })?;
    let incoming_bytes =
        incoming_bytes.ok_or(GkrmError::ThreeWayMergeSynthesisSourceByteLimitExceeded {
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
        candidate,
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
        candidate,
        &baseline_lines,
        &installed_lines,
        &incoming_lines,
    )?;

    let final_envelope = resolve_final_envelope(candidate)?;
    let synthesized = synthesize_operations(
        request.text_diff.text_diff_plan_id(),
        candidate,
        &baseline_lines,
        &installed_lines,
        &incoming_lines,
        request.options.max_operations_per_entry,
        request.options.max_total_operations,
        *total_operations,
    )?;

    if synthesized.limit_hit {
        drop(baseline_lines);
        drop(installed_lines);
        drop(incoming_lines);
        return Ok(ThreeWayMergeSynthesisEntry {
            path: candidate.path().clone(),
            baseline_text_digest: *candidate.baseline_text_digest(),
            installed_text_digest: *candidate.installed_text_digest(),
            incoming_text_digest: *candidate.incoming_text_digest(),
            final_envelope,
            operations: Vec::new(),
            merged_line_sequence_commitment: None,
            disposition: MergeSynthesisDisposition::ManualReviewOperationLimit,
        });
    }

    *total_operations = total_operations
        .checked_add(synthesized.operations.len())
        .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
    drop(baseline_lines);
    drop(installed_lines);
    drop(incoming_lines);

    Ok(ThreeWayMergeSynthesisEntry {
        path: candidate.path().clone(),
        baseline_text_digest: *candidate.baseline_text_digest(),
        installed_text_digest: *candidate.installed_text_digest(),
        incoming_text_digest: *candidate.incoming_text_digest(),
        final_envelope,
        operations: synthesized.operations,
        merged_line_sequence_commitment: Some(synthesized.merged_commitment),
        disposition: MergeSynthesisDisposition::ReadyForByteSynthesis,
    })
}

fn resolve_final_envelope(candidate: &ThreeWayTextDiffEntry) -> Result<FinalTextEnvelope> {
    let ThreeWayTextEnvelopePlanState::Planned(plan) = candidate.envelope_plan() else {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
    };
    let bom = resolve_bool_scalar(
        plan.bom(),
        candidate.baseline_envelope().bom(),
        candidate.installed_envelope().bom(),
        candidate.incoming_envelope().bom(),
    )?;
    let newline_style = resolve_newline_scalar(
        plan.newline_style(),
        candidate.baseline_envelope().newline_style(),
        candidate.installed_envelope().newline_style(),
        candidate.incoming_envelope().newline_style(),
    )?;
    let terminal_newline = resolve_terminal_scalar(
        plan.terminal_newline(),
        candidate.baseline_envelope().terminal_newline(),
        candidate.installed_envelope().terminal_newline(),
        candidate.incoming_envelope().terminal_newline(),
    )?;
    Ok(FinalTextEnvelope {
        bom,
        newline_style,
        terminal_newline,
    })
}

fn resolve_bool_scalar(
    resolution: ThreeWayTextScalarResolution,
    base: bool,
    installed: bool,
    incoming: bool,
) -> Result<bool> {
    match resolution {
        ThreeWayTextScalarResolution::KeepBase => Ok(base),
        ThreeWayTextScalarResolution::UseInstalled => Ok(installed),
        ThreeWayTextScalarResolution::UseIncoming => Ok(incoming),
        ThreeWayTextScalarResolution::Converged => {
            if installed != incoming {
                return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
            }
            Ok(installed)
        }
        ThreeWayTextScalarResolution::Conflict => {
            Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan)
        }
    }
}

fn resolve_newline_scalar(
    resolution: ThreeWayTextScalarResolution,
    base: SupportedTextNewlineStyle,
    installed: SupportedTextNewlineStyle,
    incoming: SupportedTextNewlineStyle,
) -> Result<SupportedTextNewlineStyle> {
    match resolution {
        ThreeWayTextScalarResolution::KeepBase => Ok(base),
        ThreeWayTextScalarResolution::UseInstalled => Ok(installed),
        ThreeWayTextScalarResolution::UseIncoming => Ok(incoming),
        ThreeWayTextScalarResolution::Converged => {
            if installed != incoming {
                return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
            }
            Ok(installed)
        }
        ThreeWayTextScalarResolution::Conflict => {
            Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan)
        }
    }
}

fn resolve_terminal_scalar(
    resolution: ThreeWayTextScalarResolution,
    base: TextTerminalNewline,
    installed: TextTerminalNewline,
    incoming: TextTerminalNewline,
) -> Result<TextTerminalNewline> {
    for value in [base, installed, incoming] {
        if value == TextTerminalNewline::Unknown {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
        }
    }
    match resolution {
        ThreeWayTextScalarResolution::KeepBase => Ok(base),
        ThreeWayTextScalarResolution::UseInstalled => Ok(installed),
        ThreeWayTextScalarResolution::UseIncoming => Ok(incoming),
        ThreeWayTextScalarResolution::Converged => {
            if installed != incoming {
                return Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan);
            }
            Ok(installed)
        }
        ThreeWayTextScalarResolution::Conflict => {
            Err(GkrmError::ThreeWayMergeSynthesisInvalidEnvelopePlan)
        }
    }
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
            return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
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
            Err(GkrmError::ThreeWayMergeSynthesisMalformedLogicalText)
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
            return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
        }
        for id in group.installed_hunk_ids() {
            if !candidate
                .installed_hunks()
                .iter()
                .any(|hunk| hunk.id() == id)
            {
                return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
            }
        }
        for id in group.incoming_hunk_ids() {
            if !candidate
                .incoming_hunks()
                .iter()
                .any(|hunk| hunk.id() == id)
            {
                return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
            }
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
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch)?;
    let replacement = commitment_for_range(side_lines, hunk.side_range())
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch)?;
    if base.digest() != hunk.base_commitment().digest()
        || replacement.digest() != hunk.replacement_commitment().digest()
    {
        return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
    }
    let expected_kind = match (hunk.base_range().is_empty(), hunk.side_range().is_empty()) {
        (true, false) => TextDiffHunkKind::Insert,
        (false, true) => TextDiffHunkKind::Delete,
        (false, false) => TextDiffHunkKind::Replace,
        (true, true) => return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch),
    };
    if hunk.kind() != expected_kind {
        return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
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
        return Err(GkrmError::ThreeWayMergeSynthesisSourceLineLimitExceeded {
            limit: max_lines_per_source,
            actual: source_lines,
        });
    }
    *total_lines = total_lines
        .checked_add(source_lines)
        .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
    if *total_lines > max_total_lines {
        return Err(GkrmError::ThreeWayMergeSynthesisTotalLineLimitExceeded {
            limit: max_total_lines,
            actual: *total_lines,
        });
    }
    Ok(())
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
        return Err(GkrmError::ThreeWayMergeSynthesisTask16MetadataMismatch);
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
    .map_err(task18_baseline_blob_verification_failed)?;
    let verified = builder.finish().map_err(map_builder_err)?;
    if verified.metadata().sha256() != &expected_digest {
        return Err(task18_baseline_blob_verification_failed(
            GkrmError::BaselineIncompleteBundle {
                reason: "verified baseline blob digest mismatch",
            },
        ));
    }
    Ok(verified)
}

fn task18_baseline_blob_verification_failed(source: GkrmError) -> GkrmError {
    GkrmError::ThreeWayMergeSynthesisBaselineBlobVerificationFailed {
        source: Box::new(source),
    }
}

fn map_builder_err(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergeSynthesisArithmeticOverflow
        }
        other => other,
    }
}

fn map_logical(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayTextDiffMalformedLogicalText => {
            GkrmError::ThreeWayMergeSynthesisMalformedLogicalText
        }
        GkrmError::ThreeWayTextDiffIdEncodingFailure => {
            GkrmError::ThreeWayMergeSynthesisIdEncodingFailure
        }
        other => other,
    }
}

fn map_installed_scan_a(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergeSynthesisInstalledCandidateInvalid
        }
        _ => GkrmError::ThreeWayMergeSynthesisInstalledPreFingerprintMismatch,
    }
}

fn map_installed_scan_b(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergeSynthesisInstalledCandidateInvalid
        }
        _ => GkrmError::ThreeWayMergeSynthesisInstalledPostFingerprintMismatch,
    }
}

fn map_installed_read(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisInstalledCandidateInvalid => {
            GkrmError::ThreeWayMergeSynthesisInstalledCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged => {
            GkrmError::ThreeWayMergeSynthesisSourceIdentityChanged
        }
        GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged => {
            GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergeSynthesisArithmeticOverflow
        }
        other => other,
    }
}

fn map_incoming_validate(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch => {
            GkrmError::ThreeWayMergeSynthesisIncomingPackageFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch => {
            GkrmError::ThreeWayMergeSynthesisIncomingResourceFingerprintMismatch
        }
        GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch => {
            GkrmError::ThreeWayMergeSynthesisIncomingResourceIdentityMismatch
        }
        _ => GkrmError::ThreeWayMergeSynthesisIncomingCandidateInvalid,
    }
}

fn map_incoming_read(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::ThreeWayMergeAnalysisIncomingCandidateInvalid => {
            GkrmError::ThreeWayMergeSynthesisIncomingCandidateInvalid
        }
        GkrmError::ThreeWayMergeAnalysisArithmeticOverflow => {
            GkrmError::ThreeWayMergeSynthesisArithmeticOverflow
        }
        other => map_incoming_validate(other),
    }
}

fn summarize(entries: &[ThreeWayMergeSynthesisEntry]) -> Result<MergeSynthesisSummary> {
    let mut ready = 0usize;
    let mut manual = 0usize;
    let mut total_operations = 0usize;
    for entry in entries {
        match entry.disposition() {
            MergeSynthesisDisposition::ReadyForByteSynthesis => {
                ready = ready
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
                total_operations = total_operations
                    .checked_add(entry.operations().len())
                    .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
                if entry.operations().is_empty()
                    || entry.merged_line_sequence_commitment().is_none()
                {
                    return Err(GkrmError::ThreeWayMergeSynthesisSummaryInvariant);
                }
            }
            MergeSynthesisDisposition::ManualReviewOperationLimit => {
                manual = manual
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
                if !entry.operations().is_empty()
                    || entry.merged_line_sequence_commitment().is_some()
                {
                    return Err(GkrmError::ThreeWayMergeSynthesisSummaryInvariant);
                }
            }
        }
    }
    let total_candidates = ready
        .checked_add(manual)
        .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
    if total_candidates != entries.len() {
        return Err(GkrmError::ThreeWayMergeSynthesisSummaryInvariant);
    }
    Ok(MergeSynthesisSummary {
        total_candidates,
        ready_for_byte_synthesis: ready,
        manual_operation_limit: manual,
        total_operations,
    })
}

fn status_from_summary(summary: &MergeSynthesisSummary) -> Result<MergeSynthesisStatus> {
    if summary.total_candidates == 0 {
        return Err(GkrmError::ThreeWayMergeSynthesisStatusInvariant);
    }
    Ok(if summary.manual_operation_limit > 0 {
        MergeSynthesisStatus::HasManualReviewEntries
    } else {
        MergeSynthesisStatus::ReadyForByteSynthesis
    })
}

pub(crate) fn encode_operation_id(
    text_diff_plan_id: &ThreeWayTextDiffPlanId,
    path: &ResourceRelativePath,
    kind: MergeSynthesisOperationKind,
    base_range: LineRange,
    source_range: Option<LineRange>,
    source_hunk_id: Option<&TextDiffHunkId>,
    equivalent_peer_hunk_id: Option<&TextDiffHunkId>,
    output_commitment: &TextLineSequenceCommitment,
) -> Result<MergeSynthesisOperationId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-merge-synthesis-operation-v1")
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
    encoder.digest(text_diff_plan_id.digest());
    id_encode(encoder.path(path))?;
    encoder.u8(encode_kind(kind));
    encode_line_range(&mut encoder, base_range)?;
    match source_range {
        Some(range) => {
            encoder.u8(1);
            encode_line_range(&mut encoder, range)?;
        }
        None => encoder.u8(0),
    }
    match source_hunk_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id.digest());
        }
        None => encoder.u8(0),
    }
    match equivalent_peer_hunk_id {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id.digest());
        }
        None => encoder.u8(0),
    }
    encoder.digest(output_commitment.digest());
    Ok(MergeSynthesisOperationId(encoder.finish()))
}

fn encode_line_range(encoder: &mut CanonicalFingerprintEncoder, range: LineRange) -> Result<()> {
    id_encode(encoder.usize(range.start()))?;
    id_encode(encoder.usize(range.end()))?;
    Ok(())
}

fn encode_plan_id(
    request: &ThreeWayMergeSynthesisRequest<'_>,
    entries: &[ThreeWayMergeSynthesisEntry],
    summary: &MergeSynthesisSummary,
    status: MergeSynthesisStatus,
) -> Result<ThreeWayMergeSynthesisPlanId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-three-way-merge-synthesis-plan-v1")
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
    encoder.digest(request.plan.plan_id().digest());
    encoder.digest(request.review.review_id().digest());
    encoder.digest(request.analysis.analysis_id().digest());
    encoder.digest(request.text_diff.text_diff_plan_id().digest());
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
    Ok(ThreeWayMergeSynthesisPlanId(encoder.finish()))
}

fn encode_options(
    encoder: &mut CanonicalFingerprintEncoder,
    options: ThreeWayMergeSynthesisOptions,
) -> Result<()> {
    id_encode(encoder.usize(options.max_candidates))?;
    encoder.u64(options.max_source_bytes_per_file);
    encoder.u64(options.max_total_source_bytes);
    id_encode(encoder.usize(options.max_lines_per_source))?;
    id_encode(encoder.usize(options.max_total_lines))?;
    id_encode(encoder.usize(options.max_operations_per_entry))?;
    id_encode(encoder.usize(options.max_total_operations))?;
    encoder.u64(options.baseline_store_limits.max_manifest_bytes());
    id_encode(encoder.usize(options.baseline_store_limits.max_files()))?;
    encoder.u64(options.baseline_store_limits.max_blob_bytes());
    encoder.u64(options.baseline_store_limits.max_total_blob_bytes());
    Ok(())
}

fn encode_entry(
    encoder: &mut CanonicalFingerprintEncoder,
    entry: &ThreeWayMergeSynthesisEntry,
) -> Result<()> {
    id_encode(encoder.path(entry.path()))?;
    encoder.digest(entry.baseline_text_digest());
    encoder.digest(entry.installed_text_digest());
    encoder.digest(entry.incoming_text_digest());
    encoder.bool(entry.final_envelope().bom());
    encoder.u8(encode_newline(entry.final_envelope().newline_style()));
    encoder.u8(encode_terminal_newline(
        entry.final_envelope().terminal_newline(),
    ));
    encoder.u8(encode_disposition(entry.disposition()));
    match entry.merged_line_sequence_commitment() {
        Some(commitment) => {
            encoder.u8(1);
            encoder.digest(commitment.digest());
        }
        None => encoder.u8(0),
    }
    id_encode(encoder.usize(entry.operations().len()))?;
    for op in entry.operations() {
        encode_operation(encoder, op)?;
    }
    Ok(())
}

fn encode_operation(
    encoder: &mut CanonicalFingerprintEncoder,
    op: &MergeSynthesisOperation,
) -> Result<()> {
    encoder.digest(op.id().digest());
    encoder.u8(encode_kind(op.kind()));
    encode_line_range(encoder, op.base_range())?;
    match op.source_range() {
        Some(range) => {
            encoder.u8(1);
            encode_line_range(encoder, range)?;
        }
        None => encoder.u8(0),
    }
    match op.source_hunk_id() {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id.digest());
        }
        None => encoder.u8(0),
    }
    match op.equivalent_peer_hunk_id() {
        Some(id) => {
            encoder.u8(1);
            encoder.digest(id.digest());
        }
        None => encoder.u8(0),
    }
    encoder.digest(op.output_commitment().digest());
    Ok(())
}

fn encode_summary(
    encoder: &mut CanonicalFingerprintEncoder,
    summary: &MergeSynthesisSummary,
) -> Result<()> {
    id_encode(encoder.usize(summary.total_candidates))?;
    id_encode(encoder.usize(summary.ready_for_byte_synthesis))?;
    id_encode(encoder.usize(summary.manual_operation_limit))?;
    id_encode(encoder.usize(summary.total_operations))?;
    Ok(())
}

fn id_encode(result: std::result::Result<(), GkrmError>) -> Result<()> {
    result.map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)
}
