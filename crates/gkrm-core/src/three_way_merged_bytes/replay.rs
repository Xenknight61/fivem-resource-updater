//! Independent Task 18 operation replay for Task 19.

use super::MergedLineOrigin;
use crate::three_way_merge_synthesis::{
    verify_equivalent_operation_fidelity, MergeSynthesisOperationKind, ThreeWayMergeSynthesisEntry,
};
use crate::three_way_text_diff::{
    commit_line_sequence, LineRange, TextDiffHunk, TextDiffHunkId, TextDiffSide,
    TextLineSequenceCommitment, ThreeWayTextDiffEntry, ThreeWayTextOverlapClassification,
    ThreeWayTextOverlapGroup,
};
use crate::{GkrmError, Result};
use std::collections::BTreeSet;

pub(super) struct ReplayResult {
    pub(super) merged_lines: Vec<Vec<u8>>,
    /// One origin per merged line, parallel to `merged_lines`.
    ///
    /// This records which side each surviving line came from so an operator can be shown what
    /// the merge decided. It is derived from the already-verified Task 18 operation kinds and
    /// never influences the merge: the output commitment is still checked against Task 18.
    pub(super) line_origins: Vec<MergedLineOrigin>,
}

/// Replay Task 18 operations against reread sources; verify commitment equals Task 18.
pub(super) fn replay_synthesis_operations(
    synthesis_entry: &ThreeWayMergeSynthesisEntry,
    text_entry: &ThreeWayTextDiffEntry,
    baseline_lines: &[Vec<u8>],
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
) -> Result<ReplayResult> {
    let expected = synthesis_entry
        .merged_line_sequence_commitment()
        .ok_or(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch)?;
    let ops = synthesis_entry.operations();
    if ops.is_empty() {
        return Err(GkrmError::ThreeWayMergedBytesTask18EvidenceMismatch);
    }

    let mut merged_lines = Vec::new();
    let mut line_origins = Vec::new();
    let mut base_cursor = 0usize;
    let base_len = baseline_lines.len();
    let mut consumed_installed = BTreeSet::new();
    let mut consumed_incoming = BTreeSet::new();

    for op in ops {
        let range = op.base_range();
        if range.start() != base_cursor || range.end() > base_len {
            return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
        }
        match op.kind() {
            MergeSynthesisOperationKind::CopyBase => {
                if range.is_empty()
                    || op.source_range().is_some()
                    || op.source_hunk_id().is_some()
                    || op.equivalent_peer_hunk_id().is_some()
                {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                let slice = &baseline_lines[range.start()..range.end()];
                let commitment = commit_line_sequence(slice)
                    .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
                if commitment.digest() != op.output_commitment().digest() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                merged_lines.extend(slice.iter().cloned());
                line_origins.extend(std::iter::repeat_n(MergedLineOrigin::Baseline, slice.len()));
                base_cursor = range.end();
            }
            MergeSynthesisOperationKind::UseInstalledReplacement => {
                let hunk_id = op
                    .source_hunk_id()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                if op.equivalent_peer_hunk_id().is_some() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                let source_range = op
                    .source_range()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                let hunk = text_entry
                    .installed_hunks()
                    .iter()
                    .find(|h| h.id() == hunk_id)
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                if hunk.side() != TextDiffSide::Installed
                    || hunk.base_range() != range
                    || hunk.side_range() != source_range
                {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                if !consumed_installed.insert(*hunk_id) {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                if source_range.end() > installed_lines.len() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                let slice = &installed_lines[source_range.start()..source_range.end()];
                let commitment = commit_line_sequence(slice)
                    .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
                if commitment.digest() != op.output_commitment().digest() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                merged_lines.extend(slice.iter().cloned());
                line_origins.extend(std::iter::repeat_n(
                    MergedLineOrigin::Installed,
                    slice.len(),
                ));
                base_cursor = range.end();
            }
            MergeSynthesisOperationKind::UseIncomingReplacement => {
                let hunk_id = op
                    .source_hunk_id()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                if op.equivalent_peer_hunk_id().is_some() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                let source_range = op
                    .source_range()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                let hunk = text_entry
                    .incoming_hunks()
                    .iter()
                    .find(|h| h.id() == hunk_id)
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                if hunk.side() != TextDiffSide::Incoming
                    || hunk.base_range() != range
                    || hunk.side_range() != source_range
                {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                if !consumed_incoming.insert(*hunk_id) {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                if source_range.end() > incoming_lines.len() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                let slice = &incoming_lines[source_range.start()..source_range.end()];
                let commitment = commit_line_sequence(slice)
                    .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
                if commitment.digest() != op.output_commitment().digest() {
                    return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                }
                merged_lines.extend(slice.iter().cloned());
                line_origins.extend(std::iter::repeat_n(MergedLineOrigin::Incoming, slice.len()));
                base_cursor = range.end();
            }
            MergeSynthesisOperationKind::UseEquivalentReplacement => {
                let installed_id = op
                    .source_hunk_id()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                let incoming_id = op
                    .equivalent_peer_hunk_id()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                let source_range = op
                    .source_range()
                    .ok_or(GkrmError::ThreeWayMergedBytesReplayInvariant)?;
                let replacement = resolve_and_verify_equivalent_group(
                    text_entry,
                    range,
                    source_range,
                    installed_id,
                    incoming_id,
                    installed_lines,
                    incoming_lines,
                    op.output_commitment(),
                )?;
                for id in &replacement.installed_ids {
                    if !consumed_installed.insert(*id) {
                        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                    }
                }
                for id in &replacement.incoming_ids {
                    if !consumed_incoming.insert(*id) {
                        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
                    }
                }
                line_origins.extend(std::iter::repeat_n(
                    MergedLineOrigin::Converged,
                    replacement.lines.len(),
                ));
                merged_lines.extend(replacement.lines);
                base_cursor = range.end();
            }
        }
    }

    if base_cursor != base_len {
        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
    }
    if consumed_installed.len() != text_entry.installed_hunks().len()
        || consumed_incoming.len() != text_entry.incoming_hunks().len()
    {
        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
    }
    for hunk in text_entry.installed_hunks() {
        if !consumed_installed.contains(hunk.id()) {
            return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
        }
    }
    for hunk in text_entry.incoming_hunks() {
        if !consumed_incoming.contains(hunk.id()) {
            return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
        }
    }

    let commitment = commit_line_sequence(&merged_lines)
        .map_err(|_| GkrmError::ThreeWayMergedBytesIdEncodingFailure)?;
    if commitment.digest() != expected.digest() {
        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
    }

    if line_origins.len() != merged_lines.len() {
        return Err(GkrmError::ThreeWayMergedBytesReplayInvariant);
    }

    Ok(ReplayResult {
        merged_lines,
        line_origins,
    })
}

struct EquivalentResolution {
    installed_ids: Vec<TextDiffHunkId>,
    incoming_ids: Vec<TextDiffHunkId>,
    lines: Vec<Vec<u8>>,
}

/// Resolve an equivalent overlap group by full canonical membership — never by first-ID alone.
fn resolve_and_verify_equivalent_group(
    text_entry: &ThreeWayTextDiffEntry,
    op_base_range: LineRange,
    op_source_range: LineRange,
    installed_ref: &TextDiffHunkId,
    incoming_ref: &TextDiffHunkId,
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
    output_commitment: &TextLineSequenceCommitment,
) -> Result<EquivalentResolution> {
    let mut matches = Vec::new();
    for group in text_entry.overlap_groups() {
        if group.classification() != ThreeWayTextOverlapClassification::Equivalent {
            continue;
        }
        if group.base_range() != op_base_range {
            continue;
        }
        let Ok(canon) = canonicalize_equivalent_group(text_entry, group) else {
            continue;
        };
        // Task 18 stores the sorted-first member on each side as the public refs.
        if canon.installed_ids.first() != Some(installed_ref)
            || canon.incoming_ids.first() != Some(incoming_ref)
        {
            continue;
        }
        // Full membership: both refs must belong to the complete member sets.
        if !canon.installed_ids.contains(installed_ref)
            || !canon.incoming_ids.contains(incoming_ref)
        {
            continue;
        }
        matches.push(canon);
    }
    if matches.len() != 1 {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup);
    }
    let canon = matches.remove(0);

    let lines = verify_equivalent_operation_fidelity(
        op_base_range,
        op_source_range,
        &canon.installed_ids,
        &canon.incoming_ids,
        text_entry.installed_hunks(),
        text_entry.incoming_hunks(),
        installed_lines,
        incoming_lines,
        output_commitment,
    )
    .map_err(map_equivalent_err)?;

    Ok(EquivalentResolution {
        installed_ids: canon.installed_ids,
        incoming_ids: canon.incoming_ids,
        lines,
    })
}

struct CanonicalEquivalentGroup {
    installed_ids: Vec<TextDiffHunkId>,
    incoming_ids: Vec<TextDiffHunkId>,
}

fn canonicalize_equivalent_group(
    text_entry: &ThreeWayTextDiffEntry,
    group: &ThreeWayTextOverlapGroup,
) -> Result<CanonicalEquivalentGroup> {
    let installed = resolve_member_hunks(text_entry.installed_hunks(), group.installed_hunk_ids())?;
    let incoming = resolve_member_hunks(text_entry.incoming_hunks(), group.incoming_hunk_ids())?;
    if installed.is_empty() || incoming.is_empty() {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup);
    }

    // Exact set: every listed ID resolves once; no duplicates in the group listing.
    let mut seen_installed = BTreeSet::new();
    for id in group.installed_hunk_ids() {
        if !seen_installed.insert(*id) {
            return Err(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup);
        }
    }
    let mut seen_incoming = BTreeSet::new();
    for id in group.incoming_hunk_ids() {
        if !seen_incoming.insert(*id) {
            return Err(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup);
        }
    }
    if seen_installed.len() != installed.len() || seen_incoming.len() != incoming.len() {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup);
    }

    let mut installed = installed;
    let mut incoming = incoming;
    installed.sort_by_key(|hunk| (hunk.base_range().start(), *hunk.id().digest().as_bytes()));
    incoming.sort_by_key(|hunk| (hunk.base_range().start(), *hunk.id().digest().as_bytes()));

    Ok(CanonicalEquivalentGroup {
        installed_ids: installed.iter().map(|h| *h.id()).collect(),
        incoming_ids: incoming.iter().map(|h| *h.id()).collect(),
    })
}

fn resolve_member_hunks<'a>(
    hunks: &'a [TextDiffHunk],
    ids: &[TextDiffHunkId],
) -> Result<Vec<&'a TextDiffHunk>> {
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let hunk = hunks
            .iter()
            .find(|hunk| hunk.id() == id)
            .ok_or(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup)?;
        out.push(hunk);
    }
    if out.len() != ids.len() {
        return Err(GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup);
    }
    Ok(out)
}

fn map_equivalent_err(err: GkrmError) -> GkrmError {
    match err {
        GkrmError::ThreeWayMergeSynthesisInvalidEquivalentGroup
        | GkrmError::ThreeWayMergeSynthesisReplayInvariant
        | GkrmError::ThreeWayMergeSynthesisTask17EvidenceMismatch => {
            GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup
        }
        GkrmError::ThreeWayMergeSynthesisIdEncodingFailure => {
            GkrmError::ThreeWayMergedBytesIdEncodingFailure
        }
        other => other,
    }
}

/// Test-only entry to exercise equivalent group resolution without full replay.
#[cfg(test)]
pub(super) fn resolve_equivalent_for_test(
    text_entry: &ThreeWayTextDiffEntry,
    op_base_range: LineRange,
    op_source_range: LineRange,
    installed_ref: &TextDiffHunkId,
    incoming_ref: &TextDiffHunkId,
    installed_lines: &[Vec<u8>],
    incoming_lines: &[Vec<u8>],
    output_commitment: &TextLineSequenceCommitment,
) -> Result<(Vec<TextDiffHunkId>, Vec<TextDiffHunkId>, Vec<Vec<u8>>)> {
    let resolved = resolve_and_verify_equivalent_group(
        text_entry,
        op_base_range,
        op_source_range,
        installed_ref,
        incoming_ref,
        installed_lines,
        incoming_lines,
        output_commitment,
    )?;
    Ok((
        resolved.installed_ids,
        resolved.incoming_ids,
        resolved.lines,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::three_way_text_diff::{
        commit_line_sequence, replace_hunk_for_test, test_support, LineRange, TextDiffSide,
    };
    use crate::{ResourceRelativePath, Sha256Digest};

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    fn path() -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str("x.lua").unwrap()
    }

    // Minimal overlap group construction for tests.

    #[test]
    fn correct_contiguous_multi_hunk_group_resolves() {
        let base = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let side = vec![b"a".to_vec(), b"X".to_vec(), b"Y".to_vec(), b"d".to_vec()];
        let h1 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let h2 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        let i1 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let i2 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        let installed = vec![h1, h2];
        let incoming = vec![i1, i2];
        let group = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 3).unwrap(),
            &[*installed[0].id(), *installed[1].id()],
            &[*incoming[0].id(), *incoming[1].id()],
        );
        let entry =
            test_support::text_diff_entry_for_test(&path(), installed, incoming, vec![group]);
        let commitment = commit_line_sequence(&side[1..3]).unwrap();
        let (inst_ids, inc_ids, lines) = resolve_equivalent_for_test(
            &entry,
            LineRange::new(1, 3).unwrap(),
            LineRange::new(1, 3).unwrap(),
            entry.installed_hunks()[0].id(),
            entry.incoming_hunks()[0].id(),
            &side,
            &side,
            &commitment,
        )
        .unwrap();
        assert_eq!(inst_ids.len(), 2);
        assert_eq!(inc_ids.len(), 2);
        assert_eq!(lines, vec![b"X".to_vec(), b"Y".to_vec()]);
    }

    #[test]
    fn missing_member_fails() {
        let base = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let side = vec![b"a".to_vec(), b"X".to_vec(), b"c".to_vec()];
        let h1 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let i1 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let ghost = digest(0xEE);
        let ghost_id = crate::three_way_text_diff::TextDiffHunkId::from_digest_for_test(ghost);
        let group = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 2).unwrap(),
            &[*h1.id(), ghost_id],
            &[*i1.id()],
        );
        let entry = test_support::text_diff_entry_for_test(
            &path(),
            vec![h1.clone()],
            vec![i1.clone()],
            vec![group],
        );
        let commitment = commit_line_sequence(&side[1..2]).unwrap();
        let err = resolve_equivalent_for_test(
            &entry,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
            h1.id(),
            i1.id(),
            &side,
            &side,
            &commitment,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup
        ));
    }

    #[test]
    fn wrong_group_despite_matching_first_id_fails_on_base_range() {
        let base = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"d".to_vec(),
            b"e".to_vec(),
        ];
        let side = vec![
            b"a".to_vec(),
            b"X".to_vec(),
            b"c".to_vec(),
            b"Y".to_vec(),
            b"e".to_vec(),
        ];
        // Two independent replaces; craft two groups. First members share sort-start order
        // characteristics but different base spans.
        let h1 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let h2 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(3, 4).unwrap(),
            LineRange::new(3, 4).unwrap(),
        )
        .unwrap();
        let i1 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let i2 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(3, 4).unwrap(),
            LineRange::new(3, 4).unwrap(),
        )
        .unwrap();
        let g1 = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 2).unwrap(),
            &[*h1.id()],
            &[*i1.id()],
        );
        let g2 = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(3, 4).unwrap(),
            &[*h2.id()],
            &[*i2.id()],
        );
        let entry = test_support::text_diff_entry_for_test(
            &path(),
            vec![h1.clone(), h2.clone()],
            vec![i1.clone(), i2.clone()],
            vec![g1, g2],
        );
        let commitment = commit_line_sequence(&side[1..2]).unwrap();
        // Op claims group1 refs but group2's base range — must fail closed.
        let err = resolve_equivalent_for_test(
            &entry,
            LineRange::new(3, 4).unwrap(),
            LineRange::new(1, 2).unwrap(),
            h1.id(),
            i1.id(),
            &side,
            &side,
            &commitment,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup
        ));
    }

    #[test]
    fn reordered_member_list_still_canonicalizes() {
        let base = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let side = vec![b"a".to_vec(), b"X".to_vec(), b"Y".to_vec(), b"d".to_vec()];
        let h1 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let h2 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        let i1 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let i2 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        // Deliberately reverse ID listing order in the group.
        let group = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 3).unwrap(),
            &[*h2.id(), *h1.id()],
            &[*i2.id(), *i1.id()],
        );
        let entry = test_support::text_diff_entry_for_test(
            &path(),
            vec![h1.clone(), h2.clone()],
            vec![i1.clone(), i2.clone()],
            vec![group],
        );
        let commitment = commit_line_sequence(&side[1..3]).unwrap();
        let (inst_ids, _, lines) = resolve_equivalent_for_test(
            &entry,
            LineRange::new(1, 3).unwrap(),
            LineRange::new(1, 3).unwrap(),
            h1.id(),
            i1.id(),
            &side,
            &side,
            &commitment,
        )
        .unwrap();
        assert_eq!(inst_ids[0], *h1.id());
        assert_eq!(inst_ids[1], *h2.id());
        assert_eq!(lines, vec![b"X".to_vec(), b"Y".to_vec()]);
    }

    #[test]
    fn extra_member_id_not_in_hunk_table_fails() {
        let base = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let side = vec![b"a".to_vec(), b"X".to_vec(), b"c".to_vec()];
        let h1 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let i1 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let extra = replace_hunk_for_test(
            &digest(3),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(0, 1).unwrap(),
            LineRange::new(0, 1).unwrap(),
        )
        .unwrap();
        // Group lists h1 + extra, but entry hunk table only has h1 (extra absent from table).
        let group = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 2).unwrap(),
            &[*h1.id(), *extra.id()],
            &[*i1.id()],
        );
        let entry = test_support::text_diff_entry_for_test(
            &path(),
            vec![h1.clone()],
            vec![i1.clone()],
            vec![group],
        );
        let commitment = commit_line_sequence(&side[1..2]).unwrap();
        let err = resolve_equivalent_for_test(
            &entry,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
            h1.id(),
            i1.id(),
            &side,
            &side,
            &commitment,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup
        ));
    }

    #[test]
    fn two_groups_sharing_first_sortable_id_fail_closed() {
        let base = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let side = vec![b"a".to_vec(), b"X".to_vec(), b"Y".to_vec(), b"d".to_vec()];
        let side_alt = vec![b"a".to_vec(), b"X".to_vec(), b"Z".to_vec(), b"d".to_vec()];
        let h1 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let h2 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        let h3 = replace_hunk_for_test(
            &digest(1),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side_alt,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        let i1 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(1, 2).unwrap(),
            LineRange::new(1, 2).unwrap(),
        )
        .unwrap();
        let i2 = replace_hunk_for_test(
            &digest(2),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            LineRange::new(2, 3).unwrap(),
            LineRange::new(2, 3).unwrap(),
        )
        .unwrap();
        // Ambiguous: same base range and same sorted-first IDs; membership differs by second hunk.
        let g1 = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 3).unwrap(),
            &[*h1.id(), *h2.id()],
            &[*i1.id(), *i2.id()],
        );
        let g2 = test_support::equivalent_group_for_test(
            &digest(9),
            &path(),
            LineRange::new(1, 3).unwrap(),
            &[*h1.id(), *h3.id()],
            &[*i1.id(), *i2.id()],
        );
        let entry = test_support::text_diff_entry_for_test(
            &path(),
            vec![h1.clone(), h2.clone(), h3.clone()],
            vec![i1.clone(), i2.clone()],
            vec![g1, g2],
        );
        let commitment = commit_line_sequence(&side[1..3]).unwrap();
        let err = resolve_equivalent_for_test(
            &entry,
            LineRange::new(1, 3).unwrap(),
            LineRange::new(1, 3).unwrap(),
            h1.id(),
            i1.id(),
            &side,
            &side,
            &commitment,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::ThreeWayMergedBytesInvalidEquivalentGroup
        ));
    }
}
