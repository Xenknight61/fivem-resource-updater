//! Cross-side overlap grouping for installed and incoming hunks.

use super::hunks::{LineRange, TextDiffHunk, TextDiffHunkId, TextDiffHunkKind};
use super::id::{encode_line_range, encode_overlap_class};
use crate::three_way_fingerprint::CanonicalFingerprintEncoder;
use crate::{GkrmError, ResourceRelativePath, Result, Sha256Digest, ThreeWayMergeAnalysisId};

/// How a connected overlap component should be reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreeWayTextOverlapClassification {
    Equivalent,
    DivergentInsertion,
    OverlappingEditConflict,
}

/// Opaque deterministic overlap-group identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreeWayTextOverlapGroupId(Sha256Digest);

impl ThreeWayTextOverlapGroupId {
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

/// Immutable overlap group metadata (no replacement plaintext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreeWayTextOverlapGroup {
    id: ThreeWayTextOverlapGroupId,
    base_range: LineRange,
    installed_hunk_ids: Vec<TextDiffHunkId>,
    incoming_hunk_ids: Vec<TextDiffHunkId>,
    classification: ThreeWayTextOverlapClassification,
}

impl ThreeWayTextOverlapGroup {
    pub fn id(&self) -> &ThreeWayTextOverlapGroupId {
        &self.id
    }

    pub fn base_range(&self) -> LineRange {
        self.base_range
    }

    pub fn installed_hunk_ids(&self) -> &[TextDiffHunkId] {
        &self.installed_hunk_ids
    }

    pub fn incoming_hunk_ids(&self) -> &[TextDiffHunkId] {
        &self.incoming_hunk_ids
    }

    pub fn classification(&self) -> ThreeWayTextOverlapClassification {
        self.classification
    }
}

/// Hunk plus the side replacement lines covered by `side_range` (for byte equality).
pub(super) struct HunkEditView<'a> {
    pub hunk: &'a TextDiffHunk,
    pub replacement_lines: &'a [Vec<u8>],
}

/// Build deterministic overlap groups.
///
/// Returns `Ok(Err(()))` when `max_groups` would be exceeded (caller maps to disposition).
pub(super) fn classify_overlap_groups(
    analysis_id: &ThreeWayMergeAnalysisId,
    path: &ResourceRelativePath,
    installed: &[HunkEditView<'_>],
    incoming: &[HunkEditView<'_>],
    max_groups: usize,
) -> Result<std::result::Result<Vec<ThreeWayTextOverlapGroup>, ()>> {
    classify_overlap_groups_with_digest(analysis_id.digest(), path, installed, incoming, max_groups)
}

fn classify_overlap_groups_with_digest(
    analysis_digest: &Sha256Digest,
    path: &ResourceRelativePath,
    installed: &[HunkEditView<'_>],
    incoming: &[HunkEditView<'_>],
    max_groups: usize,
) -> Result<std::result::Result<Vec<ThreeWayTextOverlapGroup>, ()>> {
    let installed_len = installed.len();
    let total = installed_len
        .checked_add(incoming.len())
        .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
    if total == 0 {
        return Ok(Ok(Vec::new()));
    }

    let mut union_find = UnionFind::new(total);
    for (installed_index, installed_view) in installed.iter().enumerate() {
        for (incoming_index, incoming_view) in incoming.iter().enumerate() {
            if hunks_interact(installed_view, incoming_view) {
                let right = installed_len
                    .checked_add(incoming_index)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
                union_find.union(installed_index, right)?;
            }
        }
    }

    // Deterministic component collection (BTreeMap by root, members sorted).
    let mut components: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for index in 0..total {
        let root = union_find.find(index)?;
        components.entry(root).or_default().push(index);
    }

    let mut groups = Vec::new();
    for members in components.values() {
        let mut installed_members = Vec::new();
        let mut incoming_members = Vec::new();
        for &index in members {
            if index < installed_len {
                installed_members.push(index);
            } else {
                let incoming_index = index
                    .checked_sub(installed_len)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
                incoming_members.push(incoming_index);
            }
        }

        // Disjoint non-interacting hunks stay out of groups (singletons / one-sided).
        if installed_members.is_empty() || incoming_members.is_empty() {
            continue;
        }

        installed_members.sort_unstable();
        incoming_members.sort_unstable();

        let installed_views: Vec<&HunkEditView<'_>> = installed_members
            .iter()
            .map(|&index| &installed[index])
            .collect();
        let incoming_views: Vec<&HunkEditView<'_>> = incoming_members
            .iter()
            .map(|&index| &incoming[index])
            .collect();

        let classification = classify_component(&installed_views, &incoming_views)?;
        let base_range = covering_base_range(&installed_views, &incoming_views)?;
        let installed_hunk_ids: Vec<TextDiffHunkId> =
            installed_views.iter().map(|view| *view.hunk.id()).collect();
        let incoming_hunk_ids: Vec<TextDiffHunkId> =
            incoming_views.iter().map(|view| *view.hunk.id()).collect();

        let id = encode_group_id(
            analysis_digest,
            path,
            &base_range,
            &installed_hunk_ids,
            &incoming_hunk_ids,
            classification,
        )?;

        groups.push(ThreeWayTextOverlapGroup {
            id,
            base_range,
            installed_hunk_ids,
            incoming_hunk_ids,
            classification,
        });

        if groups.len() > max_groups {
            return Ok(Err(()));
        }
    }

    groups.sort_by(|left, right| {
        (
            left.base_range.start(),
            left.base_range.end(),
            encode_overlap_class(left.classification),
            left.installed_hunk_ids.clone(),
            left.incoming_hunk_ids.clone(),
        )
            .cmp(&(
                right.base_range.start(),
                right.base_range.end(),
                encode_overlap_class(right.classification),
                right.installed_hunk_ids.clone(),
                right.incoming_hunk_ids.clone(),
            ))
    });

    Ok(Ok(groups))
}

fn hunks_interact(left: &HunkEditView<'_>, right: &HunkEditView<'_>) -> bool {
    let left_range = left.hunk.base_range();
    let right_range = right.hunk.base_range();
    match (left_range.is_empty(), right_range.is_empty()) {
        (false, false) => {
            left_range.start() < right_range.end() && right_range.start() < left_range.end()
        }
        (true, true) => left_range.start() == right_range.start(),
        (true, false) => {
            right_range.start() < left_range.start() && left_range.start() < right_range.end()
        }
        (false, true) => {
            left_range.start() < right_range.start() && right_range.start() < left_range.end()
        }
    }
}

fn classify_component(
    installed: &[&HunkEditView<'_>],
    incoming: &[&HunkEditView<'_>],
) -> Result<ThreeWayTextOverlapClassification> {
    if installed.is_empty() || incoming.is_empty() {
        return Err(GkrmError::ThreeWayTextDiffInvalidOverlapComponent);
    }

    let all_insertions = installed
        .iter()
        .chain(incoming.iter())
        .all(|view| view.hunk.base_range().is_empty());

    if all_insertions {
        let first = installed[0].replacement_lines;
        let bytes_match = installed
            .iter()
            .chain(incoming.iter())
            .all(|view| view.replacement_lines == first);
        return Ok(if bytes_match {
            ThreeWayTextOverlapClassification::Equivalent
        } else {
            ThreeWayTextOverlapClassification::DivergentInsertion
        });
    }

    if component_is_equivalent(installed, incoming) {
        Ok(ThreeWayTextOverlapClassification::Equivalent)
    } else {
        Ok(ThreeWayTextOverlapClassification::OverlappingEditConflict)
    }
}

fn component_is_equivalent(
    installed: &[&HunkEditView<'_>],
    incoming: &[&HunkEditView<'_>],
) -> bool {
    let Some(first) = installed.first() else {
        return false;
    };
    let base_range = first.hunk.base_range();
    let replacement = first.replacement_lines;
    let kind = first.hunk.kind();

    installed.iter().chain(incoming.iter()).all(|view| {
        view.hunk.base_range() == base_range
            && view.replacement_lines == replacement
            && kinds_compatible(kind, view.hunk.kind())
    })
}

fn kinds_compatible(left: TextDiffHunkKind, right: TextDiffHunkKind) -> bool {
    left == right
}

fn covering_base_range(
    installed: &[&HunkEditView<'_>],
    incoming: &[&HunkEditView<'_>],
) -> Result<LineRange> {
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    for view in installed.iter().chain(incoming.iter()) {
        let range = view.hunk.base_range();
        start = Some(match start {
            None => range.start(),
            Some(current) => current.min(range.start()),
        });
        end = Some(match end {
            None => range.end(),
            Some(current) => current.max(range.end()),
        });
    }
    let start = start.ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
    let end = end.ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
    LineRange::new(start, end)
}

fn encode_group_id(
    analysis_digest: &Sha256Digest,
    path: &ResourceRelativePath,
    base_range: &LineRange,
    installed_hunk_ids: &[TextDiffHunkId],
    incoming_hunk_ids: &[TextDiffHunkId],
    classification: ThreeWayTextOverlapClassification,
) -> Result<ThreeWayTextOverlapGroupId> {
    let mut encoder = CanonicalFingerprintEncoder::new("gkrm-text-overlap-group-v1")
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encoder.digest(analysis_digest);
    encoder
        .path(path)
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    encode_line_range(&mut encoder, base_range)?;
    encoder
        .usize(installed_hunk_ids.len())
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    for id in installed_hunk_ids {
        encoder.digest(id.digest());
    }
    encoder
        .usize(incoming_hunk_ids.len())
        .map_err(|_| GkrmError::ThreeWayTextDiffIdEncodingFailure)?;
    for id in incoming_hunk_ids {
        encoder.digest(id.digest());
    }
    encoder.u8(encode_overlap_class(classification));
    Ok(ThreeWayTextOverlapGroupId(encoder.finish()))
}

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            rank: vec![0; len],
        }
    }

    fn find(&mut self, mut index: usize) -> Result<usize> {
        let mut root = index;
        loop {
            let parent = *self
                .parent
                .get(root)
                .ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
            if parent == root {
                break;
            }
            root = parent;
        }
        while index != root {
            let parent = *self
                .parent
                .get(index)
                .ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
            self.parent[index] = root;
            index = parent;
        }
        Ok(root)
    }

    fn union(&mut self, left: usize, right: usize) -> Result<()> {
        let left_root = self.find(left)?;
        let right_root = self.find(right)?;
        if left_root == right_root {
            return Ok(());
        }
        let left_rank = *self
            .rank
            .get(left_root)
            .ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
        let right_rank = *self
            .rank
            .get(right_root)
            .ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
        match left_rank.cmp(&right_rank) {
            std::cmp::Ordering::Less => self.parent[left_root] = right_root,
            std::cmp::Ordering::Greater => self.parent[right_root] = left_root,
            std::cmp::Ordering::Equal => {
                self.parent[right_root] = left_root;
                let rank = self
                    .rank
                    .get_mut(left_root)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidOverlapComponent)?;
                *rank = rank
                    .checked_add(1)
                    .ok_or(GkrmError::ThreeWayTextDiffArithmeticOverflow)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::hunks::{coalesce_hunks_with_digest, TextDiffSide};
    use super::super::myers::PrimitiveLineEdit;
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

    fn hunk_from_script(
        side: TextDiffSide,
        base: &[Vec<u8>],
        side_lines: &[Vec<u8>],
        script: &[PrimitiveLineEdit],
        analysis: u8,
    ) -> TextDiffHunk {
        let mut hunks =
            coalesce_hunks_with_digest(&digest(analysis), &path(), side, base, side_lines, script)
                .unwrap();
        assert_eq!(hunks.len(), 1);
        hunks.pop().unwrap()
    }

    #[test]
    fn equivalent_replaces_form_one_group() {
        let base = lines(&["a", "b", "c"]);
        let installed_lines = lines(&["a", "x", "c"]);
        let incoming_lines = lines(&["a", "x", "c"]);
        let script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::DeleteBase { base_index: 1 },
            PrimitiveLineEdit::InsertSide {
                side_index: 1,
                at_base_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 2,
            },
        ];
        let installed_hunk = hunk_from_script(
            TextDiffSide::Installed,
            &base,
            &installed_lines,
            &script,
            0x41,
        );
        let incoming_hunk = hunk_from_script(
            TextDiffSide::Incoming,
            &base,
            &incoming_lines,
            &script,
            0x41,
        );
        let installed_repl = &installed_lines
            [installed_hunk.side_range().start()..installed_hunk.side_range().end()];
        let incoming_repl =
            &incoming_lines[incoming_hunk.side_range().start()..incoming_hunk.side_range().end()];
        let groups = classify_overlap_groups_with_digest(
            &digest(0x41),
            &path(),
            &[HunkEditView {
                hunk: &installed_hunk,
                replacement_lines: installed_repl,
            }],
            &[HunkEditView {
                hunk: &incoming_hunk,
                replacement_lines: incoming_repl,
            }],
            10,
        )
        .unwrap()
        .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].classification(),
            ThreeWayTextOverlapClassification::Equivalent
        );
        assert_eq!(groups[0].base_range(), LineRange::new(1, 2).unwrap());
        assert_eq!(
            groups[0].id().digest().to_string(),
            "4d5458891c23ba68f4b5e9e35d3f08b22e65f038a301ac5d08d1d33dabf7f378"
        );
    }

    #[test]
    fn divergent_insertions_at_same_anchor() {
        let base = lines(&["a", "c"]);
        let installed_lines = lines(&["a", "x", "c"]);
        let incoming_lines = lines(&["a", "y", "c"]);
        let script_installed = vec![
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
        let script_incoming = script_installed.clone();
        let installed_hunk = hunk_from_script(
            TextDiffSide::Installed,
            &base,
            &installed_lines,
            &script_installed,
            0x42,
        );
        let incoming_hunk = hunk_from_script(
            TextDiffSide::Incoming,
            &base,
            &incoming_lines,
            &script_incoming,
            0x42,
        );
        let groups = classify_overlap_groups_with_digest(
            &digest(0x42),
            &path(),
            &[HunkEditView {
                hunk: &installed_hunk,
                replacement_lines: &installed_lines[1..2],
            }],
            &[HunkEditView {
                hunk: &incoming_hunk,
                replacement_lines: &incoming_lines[1..2],
            }],
            10,
        )
        .unwrap()
        .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].classification(),
            ThreeWayTextOverlapClassification::DivergentInsertion
        );
        assert!(groups[0].base_range().is_empty());
        assert_eq!(groups[0].base_range().start(), 1);
    }

    #[test]
    fn insert_at_boundary_of_delete_does_not_group() {
        let base = lines(&["a", "b", "c"]);
        // installed deletes b -> base range [1,2)
        let installed_lines = lines(&["a", "c"]);
        let installed_script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::DeleteBase { base_index: 1 },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 1,
            },
        ];
        // incoming inserts at end of delete (anchor 2) — ordered after, not conflict
        let incoming_lines = lines(&["a", "b", "x", "c"]);
        let incoming_script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::Equal {
                base_index: 1,
                side_index: 1,
            },
            PrimitiveLineEdit::InsertSide {
                side_index: 2,
                at_base_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 3,
            },
        ];
        let installed_hunk = hunk_from_script(
            TextDiffSide::Installed,
            &base,
            &installed_lines,
            &installed_script,
            0x43,
        );
        let incoming_hunk = hunk_from_script(
            TextDiffSide::Incoming,
            &base,
            &incoming_lines,
            &incoming_script,
            0x43,
        );
        let groups = classify_overlap_groups_with_digest(
            &digest(0x43),
            &path(),
            &[HunkEditView {
                hunk: &installed_hunk,
                replacement_lines: &[],
            }],
            &[HunkEditView {
                hunk: &incoming_hunk,
                replacement_lines: &incoming_lines[2..3],
            }],
            10,
        )
        .unwrap()
        .unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn overlapping_divergent_replaces_conflict() {
        let base = lines(&["a", "b", "c"]);
        let installed_lines = lines(&["a", "x", "c"]);
        let incoming_lines = lines(&["a", "y", "c"]);
        let script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::DeleteBase { base_index: 1 },
            PrimitiveLineEdit::InsertSide {
                side_index: 1,
                at_base_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 2,
            },
        ];
        let installed_hunk = hunk_from_script(
            TextDiffSide::Installed,
            &base,
            &installed_lines,
            &script,
            0x44,
        );
        let incoming_hunk = hunk_from_script(
            TextDiffSide::Incoming,
            &base,
            &incoming_lines,
            &script,
            0x44,
        );
        let groups = classify_overlap_groups_with_digest(
            &digest(0x44),
            &path(),
            &[HunkEditView {
                hunk: &installed_hunk,
                replacement_lines: &installed_lines[1..2],
            }],
            &[HunkEditView {
                hunk: &incoming_hunk,
                replacement_lines: &incoming_lines[1..2],
            }],
            10,
        )
        .unwrap()
        .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].classification(),
            ThreeWayTextOverlapClassification::OverlappingEditConflict
        );
    }

    #[test]
    fn disjoint_hunks_are_not_grouped() {
        let base = lines(&["a", "b", "c", "d"]);
        let installed_lines = lines(&["a", "x", "c", "d"]);
        let incoming_lines = lines(&["a", "b", "c", "y"]);
        let installed_script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::DeleteBase { base_index: 1 },
            PrimitiveLineEdit::InsertSide {
                side_index: 1,
                at_base_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 3,
                side_index: 3,
            },
        ];
        let incoming_script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::Equal {
                base_index: 1,
                side_index: 1,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 2,
            },
            PrimitiveLineEdit::DeleteBase { base_index: 3 },
            PrimitiveLineEdit::InsertSide {
                side_index: 3,
                at_base_index: 4,
            },
        ];
        let installed_hunk = hunk_from_script(
            TextDiffSide::Installed,
            &base,
            &installed_lines,
            &installed_script,
            0x45,
        );
        let incoming_hunk = hunk_from_script(
            TextDiffSide::Incoming,
            &base,
            &incoming_lines,
            &incoming_script,
            0x45,
        );
        let groups = classify_overlap_groups_with_digest(
            &digest(0x45),
            &path(),
            &[HunkEditView {
                hunk: &installed_hunk,
                replacement_lines: &installed_lines[1..2],
            }],
            &[HunkEditView {
                hunk: &incoming_hunk,
                replacement_lines: &incoming_lines[3..4],
            }],
            10,
        )
        .unwrap()
        .unwrap();
        assert!(groups.is_empty());
    }

    #[test]
    fn overlap_group_limit_returns_unit_err() {
        let base = lines(&["a", "b", "c"]);
        let installed_lines = lines(&["a", "x", "c"]);
        let incoming_lines = lines(&["a", "y", "c"]);
        let script = vec![
            PrimitiveLineEdit::Equal {
                base_index: 0,
                side_index: 0,
            },
            PrimitiveLineEdit::DeleteBase { base_index: 1 },
            PrimitiveLineEdit::InsertSide {
                side_index: 1,
                at_base_index: 2,
            },
            PrimitiveLineEdit::Equal {
                base_index: 2,
                side_index: 2,
            },
        ];
        let installed_hunk = hunk_from_script(
            TextDiffSide::Installed,
            &base,
            &installed_lines,
            &script,
            0x46,
        );
        let incoming_hunk = hunk_from_script(
            TextDiffSide::Incoming,
            &base,
            &incoming_lines,
            &script,
            0x46,
        );
        let result = classify_overlap_groups_with_digest(
            &digest(0x46),
            &path(),
            &[HunkEditView {
                hunk: &installed_hunk,
                replacement_lines: &installed_lines[1..2],
            }],
            &[HunkEditView {
                hunk: &incoming_hunk,
                replacement_lines: &incoming_lines[1..2],
            }],
            0,
        )
        .unwrap();
        assert!(result.is_err());
    }
}

/// Test-only constructors for Task 19 equivalent-resolution fixtures.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::three_way_text_diff::envelope::{
        SupportedTextNewlineStyle, TextEnvelope, TextTerminalNewline, ThreeWayTextEnvelopePlan,
        ThreeWayTextEnvelopePlanState, ThreeWayTextScalarResolution,
    };
    use crate::three_way_text_diff::{ThreeWayTextDiffDisposition, ThreeWayTextDiffEntry};

    pub(crate) fn equivalent_group_for_test(
        analysis_digest: &Sha256Digest,
        path: &ResourceRelativePath,
        base_range: LineRange,
        installed_hunk_ids: &[TextDiffHunkId],
        incoming_hunk_ids: &[TextDiffHunkId],
    ) -> ThreeWayTextOverlapGroup {
        let id = encode_group_id(
            analysis_digest,
            path,
            &base_range,
            installed_hunk_ids,
            incoming_hunk_ids,
            ThreeWayTextOverlapClassification::Equivalent,
        )
        .expect("group id");
        ThreeWayTextOverlapGroup {
            id,
            base_range,
            installed_hunk_ids: installed_hunk_ids.to_vec(),
            incoming_hunk_ids: incoming_hunk_ids.to_vec(),
            classification: ThreeWayTextOverlapClassification::Equivalent,
        }
    }

    pub(crate) fn text_diff_entry_for_test(
        path: &ResourceRelativePath,
        installed_hunks: Vec<TextDiffHunk>,
        incoming_hunks: Vec<TextDiffHunk>,
        overlap_groups: Vec<ThreeWayTextOverlapGroup>,
    ) -> ThreeWayTextDiffEntry {
        let envelope = TextEnvelope::new(
            false,
            SupportedTextNewlineStyle::Lf,
            TextTerminalNewline::Present,
        );
        let plan = ThreeWayTextEnvelopePlan::new(
            ThreeWayTextScalarResolution::KeepBase,
            ThreeWayTextScalarResolution::KeepBase,
            ThreeWayTextScalarResolution::KeepBase,
        );
        ThreeWayTextDiffEntry::new(
            path.clone(),
            Sha256Digest::new([0x11; 32]),
            Sha256Digest::new([0x22; 32]),
            Sha256Digest::new([0x33; 32]),
            envelope,
            envelope,
            envelope,
            ThreeWayTextEnvelopePlanState::Planned(plan),
            installed_hunks,
            incoming_hunks,
            overlap_groups,
            ThreeWayTextDiffDisposition::ReadyForMergeSynthesis,
        )
    }
}
