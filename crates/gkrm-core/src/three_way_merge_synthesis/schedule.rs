//! Streaming bounded merge-synthesis scheduling and equivalent-fidelity checks.

use super::{encode_operation_id, MergeSynthesisOperation, MergeSynthesisOperationKind};
use crate::three_way_text_diff::{
    commit_line_sequence, LineRange, TextDiffHunk, TextDiffHunkId, TextDiffSide,
    TextLineSequenceCommitment, ThreeWayTextDiffEntry, ThreeWayTextDiffPlanId,
    ThreeWayTextOverlapClassification, ThreeWayTextOverlapGroup,
};
use crate::{GkrmError, ResourceRelativePath, Result};

#[derive(Debug)]
pub(super) struct SynthesizedOperations {
    pub(super) operations: Vec<MergeSynthesisOperation>,
    pub(super) merged_commitment: TextLineSequenceCommitment,
    pub(super) limit_hit: bool,
}

/// Streaming bounded emitter: retains ops only under limits; always validates emit+replay.
struct BoundedStreamingEmitter {
    max_per_entry: usize,
    max_total: usize,
    total_before: usize,
    planned: usize,
    retained: Vec<MergeSynthesisOperation>,
    limit_hit: bool,
    base_cursor: usize,
    base_len: usize,
    merged_lines: Vec<Vec<u8>>,
}

impl BoundedStreamingEmitter {
    fn new(max_per_entry: usize, max_total: usize, total_before: usize, base_len: usize) -> Self {
        Self {
            max_per_entry,
            max_total,
            total_before,
            planned: 0,
            retained: Vec::new(),
            limit_hit: false,
            base_cursor: 0,
            base_len,
            merged_lines: Vec::new(),
        }
    }

    fn emit(
        &mut self,
        op: MergeSynthesisOperation,
        replacement: Vec<Vec<u8>>,
        baseline_lines: &[Vec<u8>],
    ) -> Result<()> {
        self.apply_replay_step(&op, &replacement, baseline_lines)?;
        self.planned = self
            .planned
            .checked_add(1)
            .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
        let total_after = self
            .total_before
            .checked_add(self.planned)
            .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
        if self.planned > self.max_per_entry || total_after > self.max_total {
            self.limit_hit = true;
            self.retained.clear();
        } else if !self.limit_hit {
            self.retained.push(op);
        }
        drop(replacement);
        Ok(())
    }

    fn apply_replay_step(
        &mut self,
        op: &MergeSynthesisOperation,
        replacement: &[Vec<u8>],
        baseline_lines: &[Vec<u8>],
    ) -> Result<()> {
        let range = op.base_range();
        if range.start() != self.base_cursor || range.end() > self.base_len {
            return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
        }
        match op.kind() {
            MergeSynthesisOperationKind::CopyBase => {
                if range.is_empty()
                    || op.source_range().is_some()
                    || op.source_hunk_id().is_some()
                    || op.equivalent_peer_hunk_id().is_some()
                {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                let slice = &baseline_lines[range.start()..range.end()];
                if slice != replacement {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                let commitment = commit_line_sequence(slice)
                    .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
                if commitment.digest() != op.output_commitment().digest() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                self.merged_lines.extend(slice.iter().cloned());
                self.base_cursor = range.end();
            }
            MergeSynthesisOperationKind::UseInstalledReplacement
            | MergeSynthesisOperationKind::UseIncomingReplacement => {
                if op.source_hunk_id().is_none() || op.equivalent_peer_hunk_id().is_some() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                if op.source_range().is_none() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                let commitment = commit_line_sequence(replacement)
                    .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
                if commitment.digest() != op.output_commitment().digest() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                self.merged_lines.extend(replacement.iter().cloned());
                self.base_cursor = range.end();
            }
            MergeSynthesisOperationKind::UseEquivalentReplacement => {
                if op.source_hunk_id().is_none() || op.equivalent_peer_hunk_id().is_none() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                if op.source_range().is_none() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                let commitment = commit_line_sequence(replacement)
                    .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
                if commitment.digest() != op.output_commitment().digest() {
                    return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
                }
                self.merged_lines.extend(replacement.iter().cloned());
                self.base_cursor = range.end();
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<SynthesizedOperations> {
        if self.base_cursor != self.base_len {
            return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
        }
        let merged_commitment = commit_line_sequence(&self.merged_lines)
            .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
        drop(self.merged_lines);
        if self.limit_hit {
            Ok(SynthesizedOperations {
                operations: Vec::new(),
                merged_commitment,
                limit_hit: true,
            })
        } else {
            Ok(SynthesizedOperations {
                operations: self.retained,
                merged_commitment,
                limit_hit: false,
            })
        }
    }
}

#[derive(Clone)]
enum EditUnit {
    Equivalent {
        base_range: LineRange,
        source_range: LineRange,
        installed_hunk_ids: Vec<TextDiffHunkId>,
        incoming_hunk_ids: Vec<TextDiffHunkId>,
        output_commitment: TextLineSequenceCommitment,
    },
    Hunk {
        hunk: TextDiffHunk,
    },
}

pub(super) fn synthesize_operations(
    text_diff_plan_id: &ThreeWayTextDiffPlanId,
    candidate: &ThreeWayTextDiffEntry,
    baseline_lines: &[Vec<u8>],
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
    max_operations_per_entry: usize,
    max_total_operations: usize,
    total_operations_before: usize,
) -> Result<SynthesizedOperations> {
    let units = collect_edit_units(candidate, installed_lines, incoming_lines)?;
    stream_schedule_units(
        text_diff_plan_id,
        candidate,
        baseline_lines,
        installed_lines,
        incoming_lines,
        units,
        max_operations_per_entry,
        max_total_operations,
        total_operations_before,
    )
}

fn collect_edit_units(
    candidate: &ThreeWayTextDiffEntry,
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
) -> Result<Vec<EditUnit>> {
    let mut consumed_installed = std::collections::BTreeSet::new();
    let mut consumed_incoming = std::collections::BTreeSet::new();
    let mut units = Vec::new();

    for group in candidate.overlap_groups() {
        if group.classification() != ThreeWayTextOverlapClassification::Equivalent {
            return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
        }
        let unit = equivalent_unit(
            candidate,
            group,
            installed_lines,
            incoming_lines,
            &mut consumed_installed,
            &mut consumed_incoming,
        )?;
        units.push(unit);
    }

    for hunk in candidate.installed_hunks() {
        if consumed_installed.contains(hunk.id()) {
            continue;
        }
        if !consumed_installed.insert(*hunk.id()) {
            return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
        }
        units.push(EditUnit::Hunk { hunk: hunk.clone() });
    }
    for hunk in candidate.incoming_hunks() {
        if consumed_incoming.contains(hunk.id()) {
            continue;
        }
        if !consumed_incoming.insert(*hunk.id()) {
            return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
        }
        units.push(EditUnit::Hunk { hunk: hunk.clone() });
    }

    if consumed_installed.len() != candidate.installed_hunks().len()
        || consumed_incoming.len() != candidate.incoming_hunks().len()
    {
        return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
    }
    Ok(units)
}

fn equivalent_unit(
    candidate: &ThreeWayTextDiffEntry,
    group: &ThreeWayTextOverlapGroup,
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
    consumed_installed: &mut std::collections::BTreeSet<TextDiffHunkId>,
    consumed_incoming: &mut std::collections::BTreeSet<TextDiffHunkId>,
) -> Result<EditUnit> {
    let mut installed =
        collect_group_hunks(candidate.installed_hunks(), group.installed_hunk_ids())?;
    let mut incoming = collect_group_hunks(candidate.incoming_hunks(), group.incoming_hunk_ids())?;
    installed.sort_by_key(|hunk| (hunk.base_range().start(), *hunk.id().digest().as_bytes()));
    incoming.sort_by_key(|hunk| (hunk.base_range().start(), *hunk.id().digest().as_bytes()));

    if installed.is_empty() || incoming.is_empty() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }

    let base_range = group.base_range();
    ensure_contiguous_base_span(&installed, base_range)?;
    ensure_contiguous_base_span(&incoming, base_range)?;
    ensure_contiguous_side_span(&installed)?;
    ensure_contiguous_side_span(&incoming)?;

    let kind = installed[0].kind();
    if !installed
        .iter()
        .chain(incoming.iter())
        .all(|hunk| hunk.kind() == kind)
    {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }

    let installed_repl = composite_replacement(&installed, installed_lines)?;
    let incoming_repl = composite_replacement(&incoming, incoming_lines)?;
    if installed_repl != incoming_repl {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }

    let source_range = contiguous_installed_source_range(&installed)?;
    if source_range.end() > installed_lines.len() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    if &installed_lines[source_range.start()..source_range.end()] != installed_repl.as_slice() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }

    let output_commitment = commit_line_sequence(&installed_repl)
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;

    let mut installed_hunk_ids = Vec::with_capacity(installed.len());
    for hunk in &installed {
        if !consumed_installed.insert(*hunk.id()) {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
        }
        installed_hunk_ids.push(*hunk.id());
    }
    let mut incoming_hunk_ids = Vec::with_capacity(incoming.len());
    for hunk in &incoming {
        if !consumed_incoming.insert(*hunk.id()) {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
        }
        incoming_hunk_ids.push(*hunk.id());
    }

    Ok(EditUnit::Equivalent {
        base_range,
        source_range,
        installed_hunk_ids,
        incoming_hunk_ids,
        output_commitment,
    })
}

fn contiguous_installed_source_range(installed: &[&TextDiffHunk]) -> Result<LineRange> {
    if installed.is_empty() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    if installed.iter().all(|hunk| hunk.side_range().is_empty()) {
        let anchor = installed[0].side_range().start();
        if installed
            .iter()
            .any(|hunk| hunk.side_range().start() != anchor)
        {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
        }
        return LineRange::new(anchor, anchor)
            .map_err(|_| GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    let start = installed[0].side_range().start();
    let end = installed
        .last()
        .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup)?
        .side_range()
        .end();
    LineRange::new(start, end).map_err(|_| GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup)
}

fn collect_group_hunks<'a>(
    hunks: &'a [TextDiffHunk],
    ids: &[TextDiffHunkId],
) -> Result<Vec<&'a TextDiffHunk>> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let hunk = hunks
            .iter()
            .find(|hunk| hunk.id() == id)
            .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup)?;
        out.push(hunk);
    }
    if out.len() != ids.len() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    Ok(out)
}

fn ensure_contiguous_base_span(hunks: &[&TextDiffHunk], expected: LineRange) -> Result<()> {
    if hunks.is_empty() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    let mut cursor = expected.start();
    for hunk in hunks {
        if hunk.base_range().start() != cursor {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
        }
        cursor = hunk.base_range().end();
    }
    if cursor != expected.end() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    Ok(())
}

fn ensure_contiguous_side_span(hunks: &[&TextDiffHunk]) -> Result<()> {
    if hunks.is_empty() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    if hunks.iter().all(|hunk| hunk.side_range().is_empty()) {
        let anchor = hunks[0].side_range().start();
        if hunks.iter().any(|hunk| hunk.side_range().start() != anchor) {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
        }
        return Ok(());
    }
    if hunks.iter().any(|hunk| hunk.side_range().is_empty()) {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    let mut cursor = hunks[0].side_range().start();
    for hunk in hunks {
        if hunk.side_range().start() != cursor {
            return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
        }
        cursor = hunk.side_range().end();
    }
    Ok(())
}

fn composite_replacement(hunks: &[&TextDiffHunk], side_lines: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for hunk in hunks {
        let range = hunk.side_range();
        if range.end() > side_lines.len() {
            return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
        }
        out.extend(side_lines[range.start()..range.end()].iter().cloned());
    }
    Ok(out)
}

fn stream_schedule_units(
    text_diff_plan_id: &ThreeWayTextDiffPlanId,
    candidate: &ThreeWayTextDiffEntry,
    baseline_lines: &[Vec<u8>],
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
    units: Vec<EditUnit>,
    max_operations_per_entry: usize,
    max_total_operations: usize,
    total_operations_before: usize,
) -> Result<SynthesizedOperations> {
    #[derive(Clone)]
    struct SchedItem {
        anchor: usize,
        is_insert: bool,
        side_rank: u8,
        hunk_id_key: [u8; 32],
        unit: EditUnit,
    }

    let mut items = Vec::new();
    for unit in units {
        match &unit {
            EditUnit::Equivalent {
                base_range,
                installed_hunk_ids,
                ..
            } => {
                let is_insert = base_range.is_empty();
                let first = installed_hunk_ids
                    .first()
                    .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup)?;
                items.push(SchedItem {
                    anchor: base_range.start(),
                    is_insert,
                    side_rank: 0,
                    hunk_id_key: *first.digest().as_bytes(),
                    unit,
                });
            }
            EditUnit::Hunk { hunk } => {
                let is_insert = hunk.base_range().is_empty();
                let side_rank = match hunk.side() {
                    TextDiffSide::Installed => 0,
                    TextDiffSide::Incoming => 1,
                };
                items.push(SchedItem {
                    anchor: hunk.base_range().start(),
                    is_insert,
                    side_rank,
                    hunk_id_key: *hunk.id().digest().as_bytes(),
                    unit,
                });
            }
        }
    }

    items.sort_by(|left, right| {
        left.anchor
            .cmp(&right.anchor)
            .then_with(|| right.is_insert.cmp(&left.is_insert))
            .then_with(|| left.side_rank.cmp(&right.side_rank))
            .then_with(|| left.hunk_id_key.cmp(&right.hunk_id_key))
    });

    let mut emitter = BoundedStreamingEmitter::new(
        max_operations_per_entry,
        max_total_operations,
        total_operations_before,
        baseline_lines.len(),
    );
    let path = candidate.path();
    let base_len = baseline_lines.len();

    for item in items {
        let (base_start, base_end) = match &item.unit {
            EditUnit::Equivalent { base_range, .. } => (base_range.start(), base_range.end()),
            EditUnit::Hunk { hunk } => (hunk.base_range().start(), hunk.base_range().end()),
        };
        if base_start < emitter.base_cursor
            || base_start > base_len
            || base_end > base_len
            || base_start > base_end
        {
            return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
        }
        if base_start > emitter.base_cursor {
            let (op, lines) = make_copy_base(
                text_diff_plan_id,
                path,
                baseline_lines,
                emitter.base_cursor,
                base_start,
            )?;
            emitter.emit(op, lines, baseline_lines)?;
        }
        let (op, lines) = make_edit_op(
            text_diff_plan_id,
            path,
            &item.unit,
            candidate,
            installed_lines,
            incoming_lines,
        )?;
        emitter.emit(op, lines, baseline_lines)?;
    }
    if emitter.base_cursor < base_len {
        let (op, lines) = make_copy_base(
            text_diff_plan_id,
            path,
            baseline_lines,
            emitter.base_cursor,
            base_len,
        )?;
        emitter.emit(op, lines, baseline_lines)?;
    } else if emitter.base_cursor > base_len {
        return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
    }
    emitter.finish()
}

fn make_copy_base(
    text_diff_plan_id: &ThreeWayTextDiffPlanId,
    path: &ResourceRelativePath,
    baseline_lines: &[Vec<u8>],
    start: usize,
    end: usize,
) -> Result<(MergeSynthesisOperation, Vec<Vec<u8>>)> {
    if start >= end {
        return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
    }
    let base_range = LineRange::new(start, end)
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisScheduleInvariant)?;
    let lines = baseline_lines[start..end].to_vec();
    let output_commitment = commit_line_sequence(&lines)
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
    let id = encode_operation_id(
        text_diff_plan_id,
        path,
        MergeSynthesisOperationKind::CopyBase,
        base_range,
        None,
        None,
        None,
        &output_commitment,
    )?;
    Ok((
        MergeSynthesisOperation {
            id,
            kind: MergeSynthesisOperationKind::CopyBase,
            base_range,
            source_range: None,
            source_hunk_id: None,
            equivalent_peer_hunk_id: None,
            output_commitment,
        },
        lines,
    ))
}

fn make_edit_op(
    text_diff_plan_id: &ThreeWayTextDiffPlanId,
    path: &ResourceRelativePath,
    unit: &EditUnit,
    candidate: &ThreeWayTextDiffEntry,
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
) -> Result<(MergeSynthesisOperation, Vec<Vec<u8>>)> {
    match unit {
        EditUnit::Equivalent {
            base_range,
            source_range,
            installed_hunk_ids,
            incoming_hunk_ids,
            output_commitment,
        } => {
            let replacement = verify_equivalent_operation_fidelity(
                *base_range,
                *source_range,
                installed_hunk_ids,
                incoming_hunk_ids,
                candidate.installed_hunks(),
                candidate.incoming_hunks(),
                installed_lines,
                incoming_lines,
                output_commitment,
            )?;
            let installed_hunk_id = *installed_hunk_ids
                .first()
                .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup)?;
            let incoming_hunk_id = *incoming_hunk_ids
                .first()
                .ok_or(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup)?;
            let id = encode_operation_id(
                text_diff_plan_id,
                path,
                MergeSynthesisOperationKind::UseEquivalentReplacement,
                *base_range,
                Some(*source_range),
                Some(&installed_hunk_id),
                Some(&incoming_hunk_id),
                output_commitment,
            )?;
            Ok((
                MergeSynthesisOperation {
                    id,
                    kind: MergeSynthesisOperationKind::UseEquivalentReplacement,
                    base_range: *base_range,
                    source_range: Some(*source_range),
                    source_hunk_id: Some(installed_hunk_id),
                    equivalent_peer_hunk_id: Some(incoming_hunk_id),
                    output_commitment: *output_commitment,
                },
                replacement,
            ))
        }
        EditUnit::Hunk { hunk } => {
            let kind = match hunk.side() {
                TextDiffSide::Installed => MergeSynthesisOperationKind::UseInstalledReplacement,
                TextDiffSide::Incoming => MergeSynthesisOperationKind::UseIncomingReplacement,
            };
            let side_lines = match hunk.side() {
                TextDiffSide::Installed => installed_lines,
                TextDiffSide::Incoming => incoming_lines,
            };
            if hunk.side_range().end() > side_lines.len() {
                return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
            }
            let lines = side_lines[hunk.side_range().start()..hunk.side_range().end()].to_vec();
            let output_commitment = commit_line_sequence(&lines)
                .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
            if output_commitment.digest() != hunk.replacement_commitment().digest() {
                return Err(GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch);
            }
            let id = encode_operation_id(
                text_diff_plan_id,
                path,
                kind,
                hunk.base_range(),
                Some(hunk.side_range()),
                Some(hunk.id()),
                None,
                &output_commitment,
            )?;
            Ok((
                MergeSynthesisOperation {
                    id,
                    kind,
                    base_range: hunk.base_range(),
                    source_range: Some(hunk.side_range()),
                    source_hunk_id: Some(*hunk.id()),
                    equivalent_peer_hunk_id: None,
                    output_commitment,
                },
                lines,
            ))
        }
    }
}

/// Validate equivalent-group fidelity; returns the verified replacement lines.
pub(crate) fn verify_equivalent_operation_fidelity(
    base_range: LineRange,
    source_range: LineRange,
    installed_hunk_ids: &[TextDiffHunkId],
    incoming_hunk_ids: &[TextDiffHunkId],
    installed_hunks: &[TextDiffHunk],
    incoming_hunks: &[TextDiffHunk],
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
    output_commitment: &TextLineSequenceCommitment,
) -> Result<Vec<Vec<u8>>> {
    if installed_hunk_ids.is_empty() || incoming_hunk_ids.is_empty() {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    let installed = collect_group_hunks(installed_hunks, installed_hunk_ids)?;
    let incoming = collect_group_hunks(incoming_hunks, incoming_hunk_ids)?;
    ensure_contiguous_base_span(&installed, base_range)?;
    ensure_contiguous_base_span(&incoming, base_range)?;
    ensure_contiguous_side_span(&installed)?;
    ensure_contiguous_side_span(&incoming)?;

    let installed_composite = composite_replacement(&installed, installed_lines)?;
    let incoming_composite = composite_replacement(&incoming, incoming_lines)?;
    if incoming_composite != installed_composite {
        return Err(GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup);
    }
    if source_range.end() > installed_lines.len() {
        return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
    }
    let installed_slice = &installed_lines[source_range.start()..source_range.end()];
    if installed_slice != installed_composite.as_slice() {
        return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
    }
    let commitment = commit_line_sequence(&installed_composite)
        .map_err(|_| GkrmError::ThreeWayMergeSynthesisIdEncodingFailure)?;
    if commitment.digest() != output_commitment.digest() {
        return Err(GkrmError::ThreeWayMergeSynthesisReplayInvariant);
    }
    Ok(installed_composite)
}

/// Test helper: stream one-line CopyBase ops through the bounded emitter.
#[cfg(test)]
pub(super) fn synthesize_copy_span_ops_for_test(
    text_diff_plan_id: &ThreeWayTextDiffPlanId,
    path: &ResourceRelativePath,
    baseline_lines: &[Vec<u8>],
    max_operations_per_entry: usize,
    max_total_operations: usize,
    total_operations_before: usize,
    force_schedule_error_after_ops: Option<usize>,
) -> Result<SynthesizedOperations> {
    let mut emitter = BoundedStreamingEmitter::new(
        max_operations_per_entry,
        max_total_operations,
        total_operations_before,
        baseline_lines.len(),
    );
    let mut emitted = 0usize;
    let mut cursor = 0usize;
    while cursor < baseline_lines.len() {
        if force_schedule_error_after_ops == Some(emitted) {
            return Err(GkrmError::ThreeWayMergeSynthesisScheduleInvariant);
        }
        let end = cursor
            .checked_add(1)
            .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
        let (op, lines) = make_copy_base(text_diff_plan_id, path, baseline_lines, cursor, end)?;
        emitter.emit(op, lines, baseline_lines)?;
        emitted = emitted
            .checked_add(1)
            .ok_or(GkrmError::ThreeWayMergeSynthesisArithmeticOverflow)?;
        cursor = end;
    }
    emitter.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::three_way_text_diff::{
        coalesce_hunks_with_digest, replace_hunk_for_test, LineRange, PrimitiveLineEdit,
        TextDiffSide, ThreeWayTextDiffPlanId,
    };
    use crate::{ResourceRelativePath, Sha256Digest};

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn plan_id() -> ThreeWayTextDiffPlanId {
        ThreeWayTextDiffPlanId::new(digest(9))
    }

    fn path() -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str("x.lua").unwrap()
    }

    fn single_replace_hunks() -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<TextDiffHunk>) {
        let base = vec![b"x".to_vec(), b"y".to_vec(), b"c".to_vec()];
        let side = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let script = vec![
            PrimitiveLineEdit::DeleteBase { base_index: 0 },
            PrimitiveLineEdit::DeleteBase { base_index: 1 },
            PrimitiveLineEdit::InsertSide {
                side_index: 0,
                at_base_index: 2,
            },
            PrimitiveLineEdit::InsertSide {
                side_index: 1,
                at_base_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 2,
            },
        ];
        let hunks = coalesce_hunks_with_digest(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            &script,
        )
        .unwrap();
        (base, side, hunks)
    }

    #[test]
    fn valid_single_hunk_equivalent_fidelity() {
        let (_base, side, hunks) = single_replace_hunks();
        let hunk = &hunks[0];
        let ids = vec![*hunk.id()];
        let out = verify_equivalent_operation_fidelity(
            hunk.base_range(),
            hunk.side_range(),
            &ids,
            &ids,
            &hunks,
            &hunks,
            &side,
            &side,
            hunk.replacement_commitment(),
        )
        .unwrap();
        assert_eq!(
            out,
            side[hunk.side_range().start()..hunk.side_range().end()]
        );
    }

    #[test]
    fn incorrect_installed_source_range_fails() {
        let (_base, side, hunks) = single_replace_hunks();
        let hunk = &hunks[0];
        let ids = vec![*hunk.id()];
        let err = verify_equivalent_operation_fidelity(
            hunk.base_range(),
            LineRange::new(1, 3).unwrap(),
            &ids,
            &ids,
            &hunks,
            &hunks,
            &side,
            &side,
            hunk.replacement_commitment(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisReplayInvariant
        ));
    }

    #[test]
    fn same_length_wrong_lines_fail() {
        let (_base, side, hunks) = single_replace_hunks();
        let hunk = &hunks[0];
        let ids = vec![*hunk.id()];
        // side[0..2] is a,b — wrong window of same length uses [1,3)=b,c
        let err = verify_equivalent_operation_fidelity(
            hunk.base_range(),
            LineRange::new(1, 3).unwrap(),
            &ids,
            &ids,
            &hunks,
            &hunks,
            &side,
            &side,
            hunk.replacement_commitment(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisReplayInvariant
        ));
    }

    #[test]
    fn missing_peer_hunk_id_fails() {
        let (_base, side, hunks) = single_replace_hunks();
        let hunk = &hunks[0];
        let ids = vec![*hunk.id()];
        let err = verify_equivalent_operation_fidelity(
            hunk.base_range(),
            hunk.side_range(),
            &ids,
            &[],
            &hunks,
            &hunks,
            &side,
            &side,
            hunk.replacement_commitment(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup
        ));
    }

    #[test]
    fn incorrect_incoming_composite_fails() {
        let (_base, side, hunks) = single_replace_hunks();
        let hunk = &hunks[0];
        let ids = vec![*hunk.id()];
        let mut incoming_lines = side.clone();
        incoming_lines[0] = b"Z".to_vec();
        let err = verify_equivalent_operation_fidelity(
            hunk.base_range(),
            hunk.side_range(),
            &ids,
            &ids,
            &hunks,
            &hunks,
            &side,
            &incoming_lines,
            hunk.replacement_commitment(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup
        ));
    }

    #[test]
    fn output_commitment_mismatch_fails() {
        let (_base, side, hunks) = single_replace_hunks();
        let hunk = &hunks[0];
        let ids = vec![*hunk.id()];
        let wrong = commit_line_sequence(&[b"nope".to_vec()]).unwrap();
        let err = verify_equivalent_operation_fidelity(
            hunk.base_range(),
            hunk.side_range(),
            &ids,
            &ids,
            &hunks,
            &hunks,
            &side,
            &side,
            &wrong,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisReplayInvariant
        ));
    }

    #[test]
    fn unrepresentable_non_contiguous_side_span_fails() {
        // Two independent single-line replaces whose side ranges are not contiguous.
        let base_a = vec![b"a".to_vec(), b"b".to_vec()];
        let side_a = vec![b"a".to_vec(), b"X".to_vec()];
        let hunks_a = coalesce_hunks_with_digest(
            &digest(2),
            &path(),
            TextDiffSide::Installed,
            &base_a,
            &side_a,
            &[
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0,
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 2,
                },
            ],
        )
        .unwrap();
        let base_b = vec![b"c".to_vec(), b"d".to_vec()];
        let side_b = vec![b"c".to_vec(), b"Y".to_vec()];
        let hunks_b = coalesce_hunks_with_digest(
            &digest(3),
            &path(),
            TextDiffSide::Installed,
            &base_b,
            &side_b,
            &[
                PrimitiveLineEdit::Equal {
                    base_index: 0,
                    side_index: 0,
                },
                PrimitiveLineEdit::DeleteBase { base_index: 1 },
                PrimitiveLineEdit::InsertSide {
                    side_index: 1,
                    at_base_index: 2,
                },
            ],
        )
        .unwrap();
        assert_eq!(hunks_a.len(), 1);
        assert_eq!(hunks_b.len(), 1);
        // Both side ranges start at 1 — not a single contiguous composite span.
        let refs = [hunks_a[0].clone(), hunks_b[0].clone()];
        let ref_refs: Vec<&TextDiffHunk> = refs.iter().collect();
        let err = ensure_contiguous_side_span(&ref_refs).unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup
        ));
    }

    #[test]
    fn valid_contiguous_multi_hunk_equivalent_fidelity() {
        let base = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let side = vec![b"a".to_vec(), b"X".to_vec(), b"Y".to_vec(), b"d".to_vec()];
        let h1 = replace_hunk_for_test(
            &digest(3),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let h2 = replace_hunk_for_test(
            &digest(3),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        let hunks = vec![h1, h2];
        let ids: Vec<_> = hunks.iter().map(|h| *h.id()).collect();
        let base_span = LineRange::new(1, 3).unwrap();
        let source_span = LineRange::new(1, 3).unwrap();
        let commitment = commit_line_sequence(&side[1..3]).unwrap();
        let out = verify_equivalent_operation_fidelity(
            base_span,
            source_span,
            &ids,
            &ids,
            &hunks,
            &hunks,
            &side,
            &side,
            &commitment,
        )
        .unwrap();
        assert_eq!(out, vec![b"X".to_vec(), b"Y".to_vec()]);
    }

    #[test]
    fn bounded_emitter_clears_retained_on_limit() {
        let baseline: Vec<Vec<u8>> = (0..8).map(|i| vec![i]).collect();
        let result =
            synthesize_copy_span_ops_for_test(&plan_id(), &path(), &baseline, 3, 100, 0, None)
                .unwrap();
        assert!(result.limit_hit);
        assert!(result.operations.is_empty());
    }

    #[test]
    fn structural_error_after_limit_still_fails_closed() {
        let baseline: Vec<Vec<u8>> = (0..8).map(|i| vec![i]).collect();
        let err =
            synthesize_copy_span_ops_for_test(&plan_id(), &path(), &baseline, 2, 100, 0, Some(3))
                .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergeSynthesisScheduleInvariant
        ));
    }

    #[test]
    fn per_entry_limit_exceeded_by_one() {
        let baseline: Vec<Vec<u8>> = (0..4).map(|i| vec![i]).collect();
        let result =
            synthesize_copy_span_ops_for_test(&plan_id(), &path(), &baseline, 3, 100, 0, None)
                .unwrap();
        assert!(result.limit_hit);
        assert!(result.operations.is_empty());
    }

    #[test]
    fn total_plan_limit_respected() {
        let baseline: Vec<Vec<u8>> = (0..4).map(|i| vec![i]).collect();
        let result =
            synthesize_copy_span_ops_for_test(&plan_id(), &path(), &baseline, 100, 5, 3, None)
                .unwrap();
        assert!(result.limit_hit);
        assert!(result.operations.is_empty());
    }

    #[test]
    fn large_op_count_does_not_retain_full_vector() {
        let baseline: Vec<Vec<u8>> = (0..200).map(|i| vec![i as u8]).collect();
        let result =
            synthesize_copy_span_ops_for_test(&plan_id(), &path(), &baseline, 5, 5, 0, None)
                .unwrap();
        assert!(result.limit_hit);
        assert_eq!(result.operations.len(), 0);
    }
}
