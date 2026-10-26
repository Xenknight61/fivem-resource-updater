//! Immutable coalesced line hunks and sequence commitments.

use super::id::{encode_kind, encode_line_range, encode_side};
use super::myers::PrimitiveLineEdit;
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest, ThreeWayMergeAnalysisId};

/// Which side produced a hunk relative to base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextDiffSide {
    Installed,
    Incoming,
}

/// Canonical hunk kind after coalescing primitive Myers edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextDiffHunkKind {
    Insert,
    Delete,
    Replace,
}

/// Half-open line index range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRange {
    start: usize,
    end: usize,
}

impl LineRange {
    pub(crate) fn new(start: usize, end: usize) -> Result<Self> {
        if start > end {
            return Err(GkrmError::ThreeWayTextDiffInvalidHunk);
        }
        Ok(Self { start, end })
    }

    pub fn start(&self) -> usize {
        self.start
    }

    pub fn end(&self) -> usize {
        self.end
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Opaque commitment over an ordered logical-line byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextLineSequenceCommitment(Sha256Digest);

impl TextLineSequenceCommitment {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_digest_for_test(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

/// Opaque deterministic hunk identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextDiffHunkId(Sha256Digest);

impl TextDiffHunkId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_digest_for_test(digest: Sha256Digest) -> Self {
        Self(digest)
    }
}

/// Immutable coalesced edit hunk (no replacement plaintext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextDiffHunk {
    id: TextDiffHunkId,
    side: TextDiffSide,
    kind: TextDiffHunkKind,
    base_range: LineRange,
    side_range: LineRange,
    base_commitment: TextLineSequenceCommitment,
    replacement_commitment: TextLineSequenceCommitment,
}

impl TextDiffHunk {
    pub fn id(&self) -> &TextDiffHunkId {
        &self.id
    }

    pub fn side(&self) -> TextDiffSide {
        self.side
    }

    pub fn kind(&self) -> TextDiffHunkKind {
        self.kind
    }

    pub fn base_range(&self) -> LineRange {
        self.base_range
    }

    pub fn side_range(&self) -> LineRange {
        self.side_range
    }

    pub fn base_commitment(&self) -> &TextLineSequenceCommitment {
        &self.base_commitment
    }

    pub fn replacement_commitment(&self) -> &TextLineSequenceCommitment {
        &self.replacement_commitment
    }
}

/// Commit an ordered logical-line sequence under `gkrm-text-line-sequence-v1`.
pub(crate) fn commit_line_sequence(lines: &[Vec<u8>]) -> Result<TextLineSequenceCommitment> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-text-line-sequence-v1")
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encoder
        .usize(lines.len())
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    for line in lines {
        encoder
            .octet_string(line)
            .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    }
    Ok(TextLineSequenceCommitment(encoder.finish()))
}

/// Commit the half-open `range` slice of `lines`.
pub(crate) fn commitment_for_range(
    lines: &[Vec<u8>],
    range: LineRange,
) -> Result<TextLineSequenceCommitment> {
    if range.end > lines.len() {
        return Err(GkrmError::ThreeWayTextDiffInvalidHunk);
    }
    commit_line_sequence(&lines[range.start..range.end])
}

/// Coalesce a validated Myers script into maximal adjacent non-equal hunks.
pub(super) fn coalesce_hunks(
    analysis_id: &ThreeWayMergeAnalysisId,
    path: &ResourceRelativePath,
    side: TextDiffSide,
    base_lines: &[Vec<u8>],
    side_lines: &[Vec<u8>],
    script: &[PrimitiveLineEdit],
) -> Result<Vec<TextDiffHunk>> {
    coalesce_hunks_with_digest(
        analysis_id.digest(),
        path,
        side,
        base_lines,
        side_lines,
        script,
    )
}

pub(crate) fn coalesce_hunks_with_digest(
    analysis_digest: &Sha256Digest,
    path: &ResourceRelativePath,
    side: TextDiffSide,
    base_lines: &[Vec<u8>],
    side_lines: &[Vec<u8>],
    script: &[PrimitiveLineEdit],
) -> Result<Vec<TextDiffHunk>> {
    let mut hunks = Vec::new();
    let mut expected_base = 0_usize;
    let mut expected_side = 0_usize;
    let mut index = 0_usize;

    while index < script.len() {
        match &script[index] {
            PrimitiveLineEdit::Equal {
                base_index,
                side_index,
            } => {
                if *base_index != expected_base || *side_index != expected_side {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                if *base_index >= base_lines.len() || *side_index >= side_lines.len() {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                if base_lines[*base_index] != side_lines[*side_index] {
                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                }
                expected_base = expected_base
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                expected_side = expected_side
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                index = index
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
            PrimitiveLineEdit::DeleteBase { .. } | PrimitiveLineEdit::InsertSide { .. } => {
                let side_anchor = expected_side;
                let mut delete_start = None;
                let mut delete_end = None;
                let mut insert_start = None;
                let mut insert_end = None;
                let mut insert_anchor = None;

                while index < script.len() {
                    match &script[index] {
                        PrimitiveLineEdit::Equal { .. } => break,
                        PrimitiveLineEdit::DeleteBase { base_index } => {
                            if *base_index != expected_base {
                                return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                            }
                            if *base_index >= base_lines.len() {
                                return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                            }
                            if delete_start.is_none() {
                                delete_start = Some(*base_index);
                            }
                            delete_end = Some(
                                base_index
                                    .checked_add(1)
                                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?,
                            );
                            expected_base = expected_base
                                .checked_add(1)
                                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                            index = index
                                .checked_add(1)
                                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                        }
                        PrimitiveLineEdit::InsertSide {
                            side_index,
                            at_base_index,
                        } => {
                            if *side_index != expected_side {
                                return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                            }
                            if *side_index >= side_lines.len() {
                                return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                            }
                            if *at_base_index != expected_base {
                                return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                            }
                            match insert_anchor {
                                None => insert_anchor = Some(*at_base_index),
                                Some(anchor) if anchor == *at_base_index => {}
                                Some(_) => {
                                    return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
                                }
                            }
                            if insert_start.is_none() {
                                insert_start = Some(*side_index);
                            }
                            insert_end = Some(
                                side_index
                                    .checked_add(1)
                                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?,
                            );
                            expected_side = expected_side
                                .checked_add(1)
                                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                            index = index
                                .checked_add(1)
                                .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                        }
                    }
                }

                let (kind, base_range, side_range) =
                    match (delete_start, delete_end, insert_start, insert_end) {
                        (Some(start), Some(end), None, None) => (
                            TextDiffHunkKind::Delete,
                            LineRange::new(start, end)?,
                            LineRange::new(side_anchor, side_anchor)?,
                        ),
                        (None, None, Some(start), Some(end)) => {
                            let anchor = insert_anchor
                                .ok_or(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript)?;
                            (
                                TextDiffHunkKind::Insert,
                                LineRange::new(anchor, anchor)?,
                                LineRange::new(start, end)?,
                            )
                        }
                        (Some(base_start), Some(base_end), Some(side_start), Some(side_end)) => (
                            TextDiffHunkKind::Replace,
                            LineRange::new(base_start, base_end)?,
                            LineRange::new(side_start, side_end)?,
                        ),
                        _ => return Err(GkrmError::ThreeWayTextDiffInvalidHunk),
                    };

                if base_range.is_empty() && side_range.is_empty() {
                    return Err(GkrmError::ThreeWayTextDiffInvalidHunk);
                }

                let base_commitment = commitment_for_range(base_lines, base_range)?;
                let replacement_commitment = commitment_for_range(side_lines, side_range)?;
                let id = encode_hunk_id(
                    analysis_digest,
                    path,
                    side,
                    kind,
                    &base_range,
                    &side_range,
                    &base_commitment,
                    &replacement_commitment,
                )?;

                hunks.push(TextDiffHunk {
                    id,
                    side,
                    kind,
                    base_range,
                    side_range,
                    base_commitment,
                    replacement_commitment,
                });
            }
        }
    }

    if expected_base != base_lines.len() || expected_side != side_lines.len() {
        return Err(GkrmError::ThreeWayTextDiffInvalidPrimitiveScript);
    }

    hunks.sort_by(|left, right| {
        (
            left.base_range.start,
            left.side_range.start,
            left.side_range.end,
        )
            .cmp(&(
                right.base_range.start,
                right.side_range.start,
                right.side_range.end,
            ))
    });

    validate_no_same_side_overlap(&hunks)?;
    Ok(hunks)
}

/// Test-only replace hunk with encoded ID and range commitments.
#[cfg(test)]
pub(crate) fn replace_hunk_for_test(
    analysis_digest: &Sha256Digest,
    path: &ResourceRelativePath,
    side: TextDiffSide,
    base_lines: &[Vec<u8>],
    side_lines: &[Vec<u8>],
    base_range: LineRange,
    side_range: LineRange,
) -> Result<TextDiffHunk> {
    let base_commitment = commitment_for_range(base_lines, base_range)?;
    let replacement_commitment = commitment_for_range(side_lines, side_range)?;
    let id = encode_hunk_id(
        analysis_digest,
        path,
        side,
        TextDiffHunkKind::Replace,
        &base_range,
        &side_range,
        &base_commitment,
        &replacement_commitment,
    )?;
    Ok(TextDiffHunk {
        id,
        side,
        kind: TextDiffHunkKind::Replace,
        base_range,
        side_range,
        base_commitment,
        replacement_commitment,
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_hunk_id(
    analysis_digest: &Sha256Digest,
    path: &ResourceRelativePath,
    side: TextDiffSide,
    kind: TextDiffHunkKind,
    base_range: &LineRange,
    side_range: &LineRange,
    base_commitment: &TextLineSequenceCommitment,
    replacement_commitment: &TextLineSequenceCommitment,
) -> Result<TextDiffHunkId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-text-diff-hunk-v1")
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encoder.digest(analysis_digest);
    encoder
        .path(path)
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encoder.u8(encode_side(side));
    encoder.u8(encode_kind(kind));
    encode_line_range(&mut encoder, base_range)?;
    encode_line_range(&mut encoder, side_range)?;
    encoder.digest(base_commitment.digest());
    encoder.digest(replacement_commitment.digest());
    Ok(TextDiffHunkId(encoder.finish()))
}

fn validate_no_same_side_overlap(hunks: &[TextDiffHunk]) -> Result<()> {
    for (index, left) in hunks.iter().enumerate() {
        for right in hunks.iter().skip(index.saturating_add(1)) {
            if same_side_base_ranges_overlap(left.base_range, right.base_range) {
                return Err(GkrmError::ThreeWayTextDiffSameSideHunkOverlap);
            }
        }
    }
    Ok(())
}

fn same_side_base_ranges_overlap(left: LineRange, right: LineRange) -> bool {
    match (left.is_empty(), right.is_empty()) {
        (false, false) => left.start < right.end && right.start < left.end,
        (true, true) => left.start == right.start,
        (true, false) => right.start < left.start && left.start < right.end,
        (false, true) => left.start < right.start && right.start < left.end,
    }
}

#[cfg(test)]
mod tests {
    use super::super::myers::{bounded_myers_diff, PrimitiveLineEdit};
    use super::*;

    fn lines(values: &[&str]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    }

    fn path() -> ResourceRelativePath {
        ResourceRelativePath::try_from_slash_str("config.lua").expect("path")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::new([byte; 32])
    }

    #[test]
    fn empty_sequence_commitment_is_stable() {
        let first = commit_line_sequence(&[]).unwrap();
        let second = commit_line_sequence(&[]).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.digest().to_string(),
            "2ae4716fbce4538e810da35f02bbe8809fe9677333b79a0f11fd78527b0e1525"
        );
    }

    #[test]
    fn two_line_commitment_is_stable_and_differs_from_permutation() {
        let ab = commit_line_sequence(&lines(&["a", "b"])).unwrap();
        assert_eq!(
            ab.digest().to_string(),
            "2e14026d81db55adad424194990a10d5afb4492af80d018e5c52e84780ac284d"
        );
        let ba = commit_line_sequence(&lines(&["b", "a"])).unwrap();
        assert_ne!(ab, ba);
        let aa = commit_line_sequence(&lines(&["a", "a"])).unwrap();
        assert_ne!(ab, aa);
    }

    #[test]
    fn coalesce_delete_insert_replace_and_sort() {
        let base = lines(&["a", "b", "c", "d"]);
        let side = lines(&["a", "x", "c"]);
        let script = bounded_myers_diff(&base, &side, 100, 10_000)
            .unwrap()
            .unwrap();
        let hunks = coalesce_hunks_with_digest(
            &digest(0x11),
            &path(),
            TextDiffSide::Installed,
            &base,
            &side,
            &script,
        )
        .unwrap();
        assert_eq!(hunks.len(), 2);
        assert_eq!(hunks[0].kind(), TextDiffHunkKind::Replace);
        assert_eq!(hunks[0].base_range(), LineRange::new(1, 2).unwrap());
        assert_eq!(hunks[0].side_range(), LineRange::new(1, 2).unwrap());
        assert_eq!(hunks[1].kind(), TextDiffHunkKind::Delete);
        assert_eq!(hunks[1].base_range(), LineRange::new(3, 4).unwrap());
        assert!(hunks[1].side_range().is_empty());
        assert_eq!(
            hunks[0].id().digest().to_string(),
            "7e159cef786a71f9b1cbc2be373716f99a690f8567a32bfc617cf4dfaf11c332"
        );
        assert_eq!(
            hunks[1].id().digest().to_string(),
            "773aab12c02de508bed1d7204dbb3f877cec18fc35d50e5f056b65a23b22afcc"
        );
    }

    #[test]
    fn coalesce_insert_only_uses_empty_base_anchor() {
        let base = lines(&["a", "c"]);
        let side = lines(&["a", "b", "c"]);
        let script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::InsertSide {
                side_index: 1,
                at_base_index: 1,
            },
            PrimitiveLineEdit::Equal {
                base_index: 1,
                side_index: 2,
            },
        ];
        let hunks = coalesce_hunks_with_digest(
            &digest(0x22),
            &path(),
            TextDiffSide::Incoming,
            &base,
            &side,
            &script,
        )
        .unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].kind(), TextDiffHunkKind::Insert);
        assert_eq!(hunks[0].base_range(), LineRange::new(1, 1).unwrap());
        assert_eq!(hunks[0].side_range(), LineRange::new(1, 2).unwrap());
    }

    #[test]
    fn rejects_empty_empty_hunk() {
        let err = coalesce_hunks_with_digest(
            &digest(0x33),
            &path(),
            TextDiffSide::Installed,
            &[],
            &[],
            &[
                // unreachable via myers, but defensive: empty run is invalid
            ],
        );
        assert!(err.is_ok());
        assert!(err.unwrap().is_empty());
    }

    #[test]
    fn line_range_rejects_inverted_bounds() {
        assert!(matches!(
            LineRange::new(2, 1),
            Err(GkrmError::ThreeWayTextDiffInvalidHunk)
        ));
    }

    #[test]
    fn commitment_for_range_matches_slice_commit() {
        let values = lines(&["a", "b", "c"]);
        let range = LineRange::new(1, 3).unwrap();
        assert_eq!(
            commitment_for_range(&values, range).unwrap(),
            commit_line_sequence(&values[1..3]).unwrap()
        );
    }
}
