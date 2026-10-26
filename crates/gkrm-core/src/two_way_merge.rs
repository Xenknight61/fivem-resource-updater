//! Two-way merge of an installed file against an incoming official file.
//!
//! The three-way pipeline answers "who changed this line" by comparing both sides against the
//! official version the customer originally installed. That answer is only available when the
//! customer still has that original package, and for escrowed FiveM assets they usually do not:
//! re-uploading a new version replaces the old one in the buyer's account.
//!
//! This module answers a different, weaker, but sufficient question using only what the customer
//! actually has — their installation and the new package. It does not deduce authorship; it
//! applies a stated rule, and the operator reviews the result before anything is written:
//!
//! * a line the update adds where the operator has nothing is taken from the update;
//! * a line the operator has where the update has something different keeps the operator's
//!   content, because that is the content they deliberately edited;
//! * a line the operator has that the update no longer contains is kept for the same reason.
//!
//! Deletions and replacements are deliberately conflated: without the original there is no way to
//! tell "the vendor removed this" from "the operator added this", and keeping the operator's line
//! is the outcome that cannot silently destroy their work.
//!
//! That rule is only a starting position. The file is first split into runs the two sides agree on
//! and change blocks they do not, and each block is decided on its own. The two modes are the two
//! presets over those decisions, so nothing here is a guess the operator cannot see and overturn
//! before anything is written, or reverse after it.
//!
//! A run of differences is not one decision, and it is not one decision per line either. A
//! line-based diff reports "your last line went, theirs arrived" the same way whether the vendor
//! changed a setting or the two files simply end with unrelated lines, so pairing a run whole
//! would force a choice between things that were never alternatives. Splitting it per line is the
//! opposite mistake: a three-line function the operator added is one edit, and asking about each
//! of its lines separately invites an answer that leaves half a function behind.
//!
//! So a run is lined up against itself before it is split. A line that names what it sets can only
//! be the same decision as a line setting the same name — two values for one setting. Lines that
//! name nothing cannot be told apart that way, so a whole stretch of them is one thing, and one
//! stretch lines up with another: answering the two halves apart would write both into the file,
//! which is not a state either side ever had. Whatever is left over on one side alone is its own
//! decision, and a setting the update adds where the operator has none can never cost them a line.
//!
//! Lining the run up rather than sorting it is what keeps the file readable. Both sides come out
//! in the order they were written, so every answer produces a file whose lines are still in the
//! order the side they came from had them.

use crate::three_way_text_diff::{bounded_myers_diff, PrimitiveLineEdit, SideDiffLimit};
use crate::{GkrmError, Result};

/// Which side a surviving line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoWayLineOrigin {
    /// Both sides already agree on this line.
    Unchanged,
    /// The operator's own line survived a difference.
    Installed,
    /// The update contributed this line.
    Incoming,
}

/// What the operator chose to do with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoWayMergeMode {
    /// Keep the operator's content wherever the two sides disagree, and take what the update adds.
    PreserveLocalEdits,
    /// Take the incoming file wholesale, discarding local edits.
    ReplaceWithIncoming,
}

/// One line of a two-way merge result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayMergedLine {
    origin: TwoWayLineOrigin,
    bytes: Vec<u8>,
}

impl TwoWayMergedLine {
    pub fn origin(&self) -> TwoWayLineOrigin {
        self.origin
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One decision the operator has to make.
///
/// `installed` is what they have and `incoming` is what the update has in its place. Either may be
/// empty: an empty `installed` is a line the update adds, an empty `incoming` is a line the update
/// no longer carries. Both sides are present when they are two versions of the same thing — two
/// values for one setting, or two ways of writing the same stretch of the file — which is exactly
/// where taking both would leave the file holding a state neither side ever had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayChangeBlock {
    installed: Vec<Vec<u8>>,
    incoming: Vec<Vec<u8>>,
}

impl TwoWayChangeBlock {
    /// The operator's lines. Empty when the update is adding something new here.
    pub fn installed(&self) -> &[Vec<u8>] {
        &self.installed
    }

    /// The update's lines. Empty when the update no longer carries this content.
    pub fn incoming(&self) -> &[Vec<u8>] {
        &self.incoming
    }
}

/// What a line assigns, if it reads as an assignment.
///
/// A configuration line names the thing it sets before the sign. Comparison operators are not
/// assignments, and a line with nothing before the sign names nothing.
fn assignment_key(line: &[u8]) -> Option<&[u8]> {
    let mut index = 0usize;
    while index < line.len() {
        if line[index] == b'=' {
            let previous = index.checked_sub(1).map(|before| line[before]);
            let next = line.get(index + 1).copied();
            let comparison =
                matches!(previous, Some(b'=' | b'<' | b'>' | b'~' | b'!')) || next == Some(b'=');
            if !comparison {
                let key = trim_ascii(&line[..index]);
                return (!key.is_empty()).then_some(key);
            }
        }
        index += 1;
    }
    None
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    &bytes[start..end]
}

/// One thing inside a run that can be lined up against the other side.
///
/// A line that names what it sets stands for itself, because only the same name is an alternative
/// to it. Lines that name nothing cannot be told apart that way, so a whole stretch of them counts
/// as one thing — otherwise a three-line block would be lined up a line at a time and could come
/// back with one line from each side.
enum RunItem {
    /// A line that assigns `key`, together with the lines its value runs on to.
    Named {
        key: Vec<u8>,
        start: usize,
        end: usize,
    },
    /// A stretch of adjacent lines that assign nothing, as a half-open line range.
    Stretch { start: usize, end: usize },
}

impl RunItem {
    /// The lines this item stands for.
    fn range(&self) -> std::ops::Range<usize> {
        match self {
            RunItem::Named { start, end, .. } | RunItem::Stretch { start, end } => *start..*end,
        }
    }

    /// What decides whether this lines up with an item on the other side.
    ///
    /// The leading byte keeps the two kinds apart, so a setting is never an alternative to a
    /// stretch however the stretch happens to read.
    fn token(&self) -> Vec<u8> {
        match self {
            RunItem::Named { key, .. } => {
                let mut token = Vec::with_capacity(key.len().saturating_add(1));
                token.push(1u8);
                token.extend_from_slice(key);
                token
            }
            RunItem::Stretch { .. } => vec![0u8],
        }
    }
}

/// How the brackets on `line` leave a value that was `depth` brackets deep before it.
///
/// Text inside quotes and everything after a comment marker is not structure, so neither counts.
/// The depth never goes below zero: a stray closing bracket ends the value it appeared to close
/// rather than making the next one absorb the rest of the file.
fn bracket_depth(line: &[u8], depth: usize) -> usize {
    let mut depth = depth;
    let mut index = 0usize;
    let mut quote: Option<u8> = None;
    while index < line.len() {
        let byte = line[index];
        match quote {
            Some(open) => match byte {
                b'\\' => index = index.saturating_add(1),
                _ if byte == open => quote = None,
                _ => {}
            },
            None => match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'-' if line.get(index.saturating_add(1)) == Some(&b'-') => return depth,
                b'{' | b'[' | b'(' => depth = depth.saturating_add(1),
                b'}' | b']' | b')' => depth = depth.saturating_sub(1),
                _ => {}
            },
        }
        index = index.saturating_add(1);
    }
    depth
}

/// Read one side of a run as the things it can be lined up by.
///
/// A setting whose value opens a table does not finish on its own line, and the lines that finish
/// it are not a separate decision. Keeping the operator's `Config.Operators = {}` while taking the
/// rows the update wrote into its table leaves the rows outside any table at all.
fn run_items(lines: &[Vec<u8>]) -> Vec<RunItem> {
    let mut items: Vec<RunItem> = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let Some(key) = assignment_key(&lines[index]) else {
            match items.last_mut() {
                Some(RunItem::Stretch { end, .. }) if *end == index => {
                    *end = index.saturating_add(1);
                }
                _ => items.push(RunItem::Stretch {
                    start: index,
                    end: index.saturating_add(1),
                }),
            }
            index = index.saturating_add(1);
            continue;
        };

        let key = key.to_vec();
        let start = index;
        let mut depth = bracket_depth(&lines[index], 0);
        index = index.saturating_add(1);
        while depth > 0 && index < lines.len() {
            depth = bracket_depth(&lines[index], depth);
            index = index.saturating_add(1);
        }
        items.push(RunItem::Named {
            key,
            start,
            end: index,
        });
    }
    items
}

/// Close what the two sides have piled up since the last thing they lined up on.
///
/// Two stretches that name nothing are two versions of the same piece of the file, so they are one
/// decision: `SetFuel(car, 100.0)` and `SetFuel(car, 95.0)` answered apart wrote both calls into
/// the file. Anything that names something is its own decision instead, because pairing a setting
/// the operator wrote with an unrelated setting the update added would make them choose between
/// two things that were never alternatives.
fn close_pending(
    blocks: &mut Vec<TwoWayChangeBlock>,
    installed: &mut Vec<Vec<u8>>,
    incoming: &mut Vec<Vec<u8>>,
) {
    if installed.is_empty() && incoming.is_empty() {
        return;
    }

    let two_versions_of_one_stretch = !installed.is_empty()
        && !incoming.is_empty()
        && installed
            .iter()
            .chain(incoming.iter())
            .all(|line| assignment_key(line).is_none());
    if two_versions_of_one_stretch {
        blocks.push(TwoWayChangeBlock {
            installed: std::mem::take(installed),
            incoming: std::mem::take(incoming),
        });
        return;
    }

    if !installed.is_empty() {
        blocks.push(TwoWayChangeBlock {
            installed: std::mem::take(installed),
            incoming: Vec::new(),
        });
    }
    if !incoming.is_empty() {
        blocks.push(TwoWayChangeBlock {
            installed: Vec::new(),
            incoming: std::mem::take(incoming),
        });
    }
}

/// Split one run of differences into the decisions it actually contains.
///
/// The two sides are lined up by what their lines name before anything is split, so both come out
/// in the order they were written. Sorting them instead — every setting first, everything else
/// after — is what turned a section the update simply added into its punctuation followed by its
/// settings, hundreds of lines away from the braces they belonged to.
fn decisions_in_run(
    removed: Vec<Vec<u8>>,
    added: Vec<Vec<u8>>,
    options: TwoWayMergeOptions,
) -> Result<Vec<TwoWayChangeBlock>> {
    // Only one side has anything here, so there is nothing to line up: the run is what that side
    // has, whole and in the order it has it.
    if removed.is_empty() || added.is_empty() {
        return Ok(vec![TwoWayChangeBlock {
            installed: removed,
            incoming: added,
        }]);
    }

    let removed_items = run_items(&removed);
    let added_items = run_items(&added);
    let removed_tokens: Vec<Vec<u8>> = removed_items.iter().map(RunItem::token).collect();
    let added_tokens: Vec<Vec<u8>> = added_items.iter().map(RunItem::token).collect();

    let edits = match bounded_myers_diff(
        &removed_tokens,
        &added_tokens,
        options.max_edit_distance,
        options.max_trace_cells,
    )? {
        Ok(edits) => edits,
        // Too far apart to line up within the bounds. One decision over the whole run keeps both
        // sides in their own order, which is the answer that cannot invent a file.
        Err(SideDiffLimit::EditDistance) | Err(SideDiffLimit::TraceCells) => {
            return Ok(vec![TwoWayChangeBlock {
                installed: removed,
                incoming: added,
            }]);
        }
    };

    let mut blocks = Vec::new();
    let mut installed_pending: Vec<Vec<u8>> = Vec::new();
    let mut incoming_pending: Vec<Vec<u8>> = Vec::new();
    for edit in &edits {
        match edit {
            PrimitiveLineEdit::Equal {
                base_index,
                side_index,
            } => {
                close_pending(&mut blocks, &mut installed_pending, &mut incoming_pending);
                let ours = removed_items
                    .get(*base_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?;
                let theirs = added_items
                    .get(*side_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?;
                blocks.push(TwoWayChangeBlock {
                    installed: removed[ours.range()].to_vec(),
                    incoming: added[theirs.range()].to_vec(),
                });
            }
            PrimitiveLineEdit::DeleteBase { base_index } => {
                let ours = removed_items
                    .get(*base_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?;
                installed_pending.extend_from_slice(&removed[ours.range()]);
            }
            PrimitiveLineEdit::InsertSide { side_index, .. } => {
                let theirs = added_items
                    .get(*side_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?;
                incoming_pending.extend_from_slice(&added[theirs.range()]);
            }
        }
    }
    close_pending(&mut blocks, &mut installed_pending, &mut incoming_pending);

    Ok(blocks)
}

/// A file as an ordered sequence of agreement and disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoWaySegment {
    /// Lines both sides already have, verbatim.
    Unchanged(Vec<Vec<u8>>),
    /// A run the operator has to decide.
    Change(TwoWayChangeBlock),
}

/// Bounds on the underlying edit-script search, so a hostile pair of files cannot make the merge
/// run unbounded work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TwoWayMergeOptions {
    max_edit_distance: usize,
    max_trace_cells: usize,
    max_lines_per_side: usize,
}

impl Default for TwoWayMergeOptions {
    fn default() -> Self {
        Self {
            max_edit_distance: 4_096,
            max_trace_cells: 4_194_304,
            max_lines_per_side: 20_000,
        }
    }
}

impl TwoWayMergeOptions {
    pub fn max_lines_per_side(&self) -> usize {
        self.max_lines_per_side
    }
}

/// Split `installed` against `incoming` into agreement and change blocks.
///
/// Returns `Ok(None)` when the two files are too far apart to diff within the configured bounds.
/// A caller must then fall back to an explicit whole-file choice rather than guessing.
pub fn split_two_way(
    installed: &[Vec<u8>],
    incoming: &[Vec<u8>],
    options: TwoWayMergeOptions,
) -> Result<Option<Vec<TwoWaySegment>>> {
    if installed.len() > options.max_lines_per_side || incoming.len() > options.max_lines_per_side {
        return Ok(None);
    }

    let edits = match bounded_myers_diff(
        installed,
        incoming,
        options.max_edit_distance,
        options.max_trace_cells,
    )? {
        Ok(edits) => edits,
        Err(SideDiffLimit::EditDistance) | Err(SideDiffLimit::TraceCells) => return Ok(None),
    };

    let mut segments: Vec<TwoWaySegment> = Vec::new();
    let mut index = 0usize;
    while index < edits.len() {
        match &edits[index] {
            PrimitiveLineEdit::Equal { base_index, .. } => {
                let line = installed
                    .get(*base_index)
                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?
                    .clone();
                match segments.last_mut() {
                    Some(TwoWaySegment::Unchanged(lines)) => lines.push(line),
                    _ => segments.push(TwoWaySegment::Unchanged(vec![line])),
                }
                index += 1;
            }
            _ => {
                // One contiguous run of differences, collected whole. A changed line arrives as a
                // delete and an insert in the same run, so the run is the smallest thing that can
                // be decided without producing a file that has both sides of the same setting.
                let mut removed: Vec<Vec<u8>> = Vec::new();
                let mut added: Vec<Vec<u8>> = Vec::new();
                while index < edits.len() {
                    match &edits[index] {
                        PrimitiveLineEdit::Equal { .. } => break,
                        PrimitiveLineEdit::DeleteBase { base_index } => {
                            removed.push(
                                installed
                                    .get(*base_index)
                                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?
                                    .clone(),
                            );
                            index += 1;
                        }
                        PrimitiveLineEdit::InsertSide { side_index, .. } => {
                            added.push(
                                incoming
                                    .get(*side_index)
                                    .ok_or(GkrmError::ThreeWayTextDiffInvalidHunk)?
                                    .clone(),
                            );
                            index += 1;
                        }
                    }
                }
                for block in decisions_in_run(removed, added, options)? {
                    segments.push(TwoWaySegment::Change(block));
                }
            }
        }
    }

    Ok(Some(segments))
}

/// The change blocks of `segments`, in the order their decisions are given.
pub fn change_blocks(segments: &[TwoWaySegment]) -> impl Iterator<Item = &TwoWayChangeBlock> {
    segments.iter().filter_map(|segment| match segment {
        TwoWaySegment::Change(block) => Some(block),
        TwoWaySegment::Unchanged(_) => None,
    })
}

/// Where a mode starts each block before the operator touches it.
///
/// Preserving local edits takes the update's lines only where the operator has none of their own;
/// replacing takes them everywhere. Both are ordinary decisions, so an operator who wants one
/// block resolved the other way is not fighting a special case.
pub fn default_choices(segments: &[TwoWaySegment], mode: TwoWayMergeMode) -> Vec<bool> {
    default_choices_with_untouched(segments, mode, &[])
}

/// Where a mode starts each block, given what is known about who wrote the operator's side.
///
/// `untouched` carries one flag per change block, in order: true where the operator's side of that
/// block is exactly what they installed, so the developer is the only one who has changed anything
/// there. Such a block is not a decision — preserving local edits has no local edit to preserve —
/// and defaulting it to the operator's side keeps the version they installed over the one the
/// developer replaced it with. An operator who appended one function to a file lost every fix the
/// developer had made to the rest of it, silently, because the file counted as theirs.
///
/// An empty `untouched` means nothing is known, which is what two sides alone can say, and every
/// block is then treated as the operator's.
pub fn default_choices_with_untouched(
    segments: &[TwoWaySegment],
    mode: TwoWayMergeMode,
    untouched: &[bool],
) -> Vec<bool> {
    change_blocks(segments)
        .enumerate()
        .map(|(index, block)| match mode {
            TwoWayMergeMode::ReplaceWithIncoming => true,
            TwoWayMergeMode::PreserveLocalEdits => {
                block.installed.is_empty() || untouched.get(index).copied().unwrap_or(false)
            }
        })
        .collect()
}

/// Which change blocks hold nothing the operator wrote, judged against what they installed.
///
/// A block is theirs where any line on their side of it is one they added or changed since they
/// installed the file. Everything else in the file is the developer's on both sides, and the
/// update's version of it is simply the newer one.
///
/// Returns `Ok(None)` when the two cannot be lined up within the configured bounds, which is the
/// same answer as knowing nothing: every block is then the operator's.
pub fn untouched_blocks(
    baseline: &[Vec<u8>],
    installed: &[Vec<u8>],
    segments: &[TwoWaySegment],
    options: TwoWayMergeOptions,
) -> Result<Option<Vec<bool>>> {
    if baseline.len() > options.max_lines_per_side || installed.len() > options.max_lines_per_side {
        return Ok(None);
    }
    let edits = match bounded_myers_diff(
        baseline,
        installed,
        options.max_edit_distance,
        options.max_trace_cells,
    )? {
        Ok(edits) => edits,
        Err(SideDiffLimit::EditDistance) | Err(SideDiffLimit::TraceCells) => return Ok(None),
    };

    // The lines of the installed file the operator put there themselves.
    let mut theirs = vec![false; installed.len()];
    for edit in &edits {
        match edit {
            PrimitiveLineEdit::InsertSide { side_index, .. } => {
                if let Some(slot) = theirs.get_mut(*side_index) {
                    *slot = true;
                }
            }
            PrimitiveLineEdit::Equal { .. } | PrimitiveLineEdit::DeleteBase { .. } => {}
        }
    }
    // A line the operator deleted leaves no line to mark, so the two lines that survive around it
    // are marked instead: the block holding either of them is one they edited.
    for edit in &edits {
        if let PrimitiveLineEdit::DeleteBase { base_index } = edit {
            let after = edits
                .iter()
                .filter_map(|edit| match edit {
                    PrimitiveLineEdit::Equal {
                        base_index: base,
                        side_index,
                    } if base > base_index => Some(*side_index),
                    _ => None,
                })
                .min();
            for index in [after.map(|index| index.saturating_sub(1)), after]
                .into_iter()
                .flatten()
            {
                if let Some(slot) = theirs.get_mut(index) {
                    *slot = true;
                }
            }
        }
    }

    let mut untouched = Vec::new();
    let mut at = 0usize;
    for segment in segments {
        match segment {
            TwoWaySegment::Unchanged(lines) => at = at.saturating_add(lines.len()),
            TwoWaySegment::Change(block) => {
                let end = at.saturating_add(block.installed.len());
                untouched.push(
                    !theirs
                        .get(at..end)
                        .is_some_and(|range| range.contains(&true)),
                );
                at = end;
            }
        }
    }
    Ok(Some(untouched))
}

/// Resolve `segments` into the file that would be written.
///
/// `take_from_update` carries one decision per change block, in order: `true` takes the update's
/// lines there, `false` keeps the operator's. A count that does not match the blocks is refused
/// rather than padded, because a decision list that has drifted out of step with the file would
/// silently apply the operator's decisions to the wrong lines.
pub fn resolve_two_way(
    segments: &[TwoWaySegment],
    take_from_update: &[bool],
) -> Result<Vec<TwoWayMergedLine>> {
    if change_blocks(segments).count() != take_from_update.len() {
        return Err(GkrmError::TwoWayMergeChoiceCountMismatch);
    }

    let mut merged = Vec::new();
    let mut choices = take_from_update.iter();
    for segment in segments {
        match segment {
            TwoWaySegment::Unchanged(lines) => {
                for line in lines {
                    merged.push(TwoWayMergedLine {
                        origin: TwoWayLineOrigin::Unchanged,
                        bytes: line.clone(),
                    });
                }
            }
            TwoWaySegment::Change(block) => {
                let take = *choices
                    .next()
                    .ok_or(GkrmError::TwoWayMergeChoiceCountMismatch)?;
                let (lines, origin) = if take {
                    (&block.incoming, TwoWayLineOrigin::Incoming)
                } else {
                    (&block.installed, TwoWayLineOrigin::Installed)
                };
                for line in lines {
                    merged.push(TwoWayMergedLine {
                        origin,
                        bytes: line.clone(),
                    });
                }
            }
        }
    }

    Ok(merged)
}

/// Merge `installed` against `incoming` under `mode`, with no per-block overrides.
///
/// Returns `Ok(None)` when the two files are too far apart to diff within the configured bounds.
/// A caller must then fall back to an explicit whole-file choice rather than guessing.
pub fn merge_two_way(
    installed: &[Vec<u8>],
    incoming: &[Vec<u8>],
    mode: TwoWayMergeMode,
    options: TwoWayMergeOptions,
) -> Result<Option<Vec<TwoWayMergedLine>>> {
    let Some(segments) = split_two_way(installed, incoming, options)? else {
        return Ok(None);
    };
    let choices = default_choices(&segments, mode);
    Ok(Some(resolve_two_way(&segments, &choices)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(values: &[&str]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    }

    fn merged_text(result: &[TwoWayMergedLine]) -> Vec<String> {
        result
            .iter()
            .map(|line| String::from_utf8(line.bytes().to_vec()).unwrap())
            .collect()
    }

    fn preserve(installed: &[&str], incoming: &[&str]) -> Vec<TwoWayMergedLine> {
        merge_two_way(
            &lines(installed),
            &lines(incoming),
            TwoWayMergeMode::PreserveLocalEdits,
            TwoWayMergeOptions::default(),
        )
        .unwrap()
        .unwrap()
    }

    fn split(installed: &[&str], incoming: &[&str]) -> Vec<TwoWaySegment> {
        split_two_way(
            &lines(installed),
            &lines(incoming),
            TwoWayMergeOptions::default(),
        )
        .unwrap()
        .unwrap()
    }

    fn block_text(block: &TwoWayChangeBlock) -> (Vec<String>, Vec<String>) {
        let render = |side: &[Vec<u8>]| {
            side.iter()
                .map(|line| String::from_utf8(line.clone()).unwrap())
                .collect()
        };
        (render(block.installed()), render(block.incoming()))
    }

    #[test]
    fn keeps_operator_values_and_takes_new_official_settings() {
        // The case the product exists for: the customer edited two values, the update adds a new
        // one, and both facts have to survive the same merge.
        let result = preserve(
            &[
                "Config = {}",
                "",
                "Config.Locale = 'tr'",
                "Config.Currency = 'USD'",
                "Config.MaxContacts = 250",
                "Config.EnableDebug = false",
            ],
            &[
                "Config = {}",
                "",
                "Config.Locale = 'en'",
                "Config.Currency = 'USD'",
                "Config.MaxContacts = 100",
                "Config.EnableDebug = false",
                "Config.EnableVoiceMail = true",
            ],
        );

        assert_eq!(
            merged_text(&result),
            vec![
                "Config = {}",
                "",
                "Config.Locale = 'tr'",
                "Config.Currency = 'USD'",
                "Config.MaxContacts = 250",
                "Config.EnableDebug = false",
                "Config.EnableVoiceMail = true",
            ]
        );
        assert_eq!(result[2].origin(), TwoWayLineOrigin::Installed);
        assert_eq!(result[4].origin(), TwoWayLineOrigin::Installed);
        assert_eq!(result[6].origin(), TwoWayLineOrigin::Incoming);
        assert_eq!(result[3].origin(), TwoWayLineOrigin::Unchanged);
    }

    #[test]
    fn never_emits_both_sides_of_a_changed_line() {
        // Emitting the operator's line and the update's line would duplicate a config key rather
        // than merge it, which is worse than either choice alone.
        let result = preserve(&["Config.Locale = 'tr'"], &["Config.Locale = 'en'"]);
        assert_eq!(merged_text(&result), vec!["Config.Locale = 'tr'"]);
    }

    #[test]
    fn keeps_lines_the_update_no_longer_contains() {
        let result = preserve(&["a", "mine", "b"], &["a", "b"]);
        assert_eq!(merged_text(&result), vec!["a", "mine", "b"]);
        assert_eq!(result[1].origin(), TwoWayLineOrigin::Installed);
    }

    #[test]
    fn takes_pure_additions_anywhere_in_the_file() {
        let result = preserve(&["b"], &["a", "b", "c"]);
        assert_eq!(merged_text(&result), vec!["a", "b", "c"]);
        assert_eq!(result[0].origin(), TwoWayLineOrigin::Incoming);
        assert_eq!(result[2].origin(), TwoWayLineOrigin::Incoming);
    }

    #[test]
    fn identical_files_merge_to_themselves_with_no_attributed_change() {
        let result = preserve(&["a", "b"], &["a", "b"]);
        assert_eq!(merged_text(&result), vec!["a", "b"]);
        assert!(result
            .iter()
            .all(|line| line.origin() == TwoWayLineOrigin::Unchanged));
    }

    #[test]
    fn replace_mode_reproduces_the_incoming_file_exactly() {
        let installed = lines(&["Config.Locale = 'tr'", "mine", "shared"]);
        let incoming = lines(&["Config.Locale = 'en'", "shared", "new"]);
        let result = merge_two_way(
            &installed,
            &incoming,
            TwoWayMergeMode::ReplaceWithIncoming,
            TwoWayMergeOptions::default(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            merged_text(&result),
            vec!["Config.Locale = 'en'", "shared", "new"]
        );
    }

    #[test]
    fn empty_sides_are_handled_without_inventing_lines() {
        assert!(preserve(&[], &[]).is_empty());
        assert_eq!(merged_text(&preserve(&[], &["a"])), vec!["a"]);
        assert_eq!(merged_text(&preserve(&["a"], &[])), vec!["a"]);
    }

    #[test]
    fn refuses_rather_than_guesses_when_a_side_is_too_large() {
        let huge = vec![b"x".to_vec(); 32];
        let options = TwoWayMergeOptions {
            max_lines_per_side: 8,
            ..TwoWayMergeOptions::default()
        };
        assert!(
            merge_two_way(&huge, &[], TwoWayMergeMode::PreserveLocalEdits, options)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_change_block_carries_both_sides_of_the_disagreement() {
        // The operator cannot choose between two things they can only see one of.
        let segments = split(
            &["shared", "Config.Locale = 'tr'", "tail"],
            &["shared", "Config.Locale = 'en'", "tail"],
        );
        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            block_text(blocks[0]),
            (
                vec!["Config.Locale = 'tr'".to_string()],
                vec!["Config.Locale = 'en'".to_string()]
            )
        );
    }

    #[test]
    fn a_pure_addition_and_a_pure_removal_are_one_sided_blocks() {
        let added = split(&["a"], &["a", "new"]);
        let block: Vec<&TwoWayChangeBlock> = change_blocks(&added).collect();
        assert_eq!(block_text(block[0]), (vec![], vec!["new".to_string()]));

        let removed = split(&["a", "mine"], &["a"]);
        let block: Vec<&TwoWayChangeBlock> = change_blocks(&removed).collect();
        assert_eq!(block_text(block[0]), (vec!["mine".to_string()], vec![]));
    }

    #[test]
    fn each_block_is_decided_on_its_own() {
        // The whole point of the tick: keep one edit and accept the other, in one file.
        let segments = split(
            &["Config.Locale = 'tr'", "keep", "Config.MaxContacts = 250"],
            &["Config.Locale = 'en'", "keep", "Config.MaxContacts = 100"],
        );
        let merged = resolve_two_way(&segments, &[false, true]).unwrap();
        assert_eq!(
            merged_text(&merged),
            vec!["Config.Locale = 'tr'", "keep", "Config.MaxContacts = 100"]
        );
        assert_eq!(merged[0].origin(), TwoWayLineOrigin::Installed);
        assert_eq!(merged[2].origin(), TwoWayLineOrigin::Incoming);
    }

    #[test]
    fn rejecting_a_pure_addition_leaves_it_out() {
        let segments = split(&["a"], &["a", "new"]);
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &[false]).unwrap()),
            vec!["a"]
        );
    }

    #[test]
    fn accepting_a_removal_removes_the_line() {
        let segments = split(&["a", "mine"], &["a"]);
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &[true]).unwrap()),
            vec!["a"]
        );
    }

    #[test]
    fn the_two_modes_are_the_two_presets_over_the_same_blocks() {
        let installed = lines(&["Config.Locale = 'tr'", "shared"]);
        let incoming = lines(&["Config.Locale = 'en'", "shared", "new"]);
        let segments = split_two_way(&installed, &incoming, TwoWayMergeOptions::default())
            .unwrap()
            .unwrap();

        for mode in [
            TwoWayMergeMode::PreserveLocalEdits,
            TwoWayMergeMode::ReplaceWithIncoming,
        ] {
            let choices = default_choices(&segments, mode);
            assert_eq!(
                resolve_two_way(&segments, &choices).unwrap(),
                merge_two_way(&installed, &incoming, mode, TwoWayMergeOptions::default())
                    .unwrap()
                    .unwrap()
            );
        }
    }

    #[test]
    fn a_decision_list_out_of_step_with_the_file_is_refused() {
        // Padding or truncating would apply the operator's decisions to lines they never saw.
        let segments = split(&["a", "x = 1"], &["a", "x = 2"]);
        assert_eq!(change_blocks(&segments).count(), 1);
        for choices in [&[][..], &[false, false][..]] {
            assert!(matches!(
                resolve_two_way(&segments, choices),
                Err(GkrmError::TwoWayMergeChoiceCountMismatch)
            ));
        }
    }

    #[test]
    fn an_unrelated_removal_and_addition_are_two_decisions_and_both_can_survive() {
        // The case this rule exists for: the operator added a setting of their own at the end of
        // the file and the update added one of its own. A line diff reports that as "your last
        // line went, theirs arrived", and pairing them would make the operator choose between two
        // settings that were never alternatives — losing one of them either way.
        let segments = split(
            &["shared", "Config.MyOwnSetting = 'kept'"],
            &["shared", "Config.EnableVoiceMail = true"],
        );
        assert_eq!(change_blocks(&segments).count(), 2);

        let choices = default_choices(&segments, TwoWayMergeMode::PreserveLocalEdits);
        assert_eq!(choices, vec![false, true]);
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &choices).unwrap()),
            vec![
                "shared",
                "Config.MyOwnSetting = 'kept'",
                "Config.EnableVoiceMail = true",
            ]
        );
    }

    #[test]
    fn a_stretch_of_lines_is_one_decision_about_that_stretch() {
        // The operator added a three-line function. Asking about each of its lines separately
        // invites an answer that leaves half a function behind.
        let segments = split(
            &[
                "-- header",
                "CustomHook = function()",
                "    print('hi')",
                "end",
            ],
            &["-- header", "-- CustomHook = function() end"],
        );
        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            block_text(blocks[0]),
            (
                vec![
                    "CustomHook = function()".to_string(),
                    "    print('hi')".to_string(),
                    "end".to_string(),
                ],
                vec![]
            )
        );
        assert_eq!(
            block_text(blocks[1]),
            (vec![], vec!["-- CustomHook = function() end".to_string()])
        );
    }

    #[test]
    fn a_setting_between_two_others_keeps_its_place() {
        // Deciding the settings first and the rest afterwards would move the operator's own line
        // to the end of the run, rewriting their file to suit the merge.
        let segments = split(&["a = 1", "mine", "b = 1"], &["a = 2", "b = 2"]);
        let merged = resolve_two_way(&segments, &[false, false, false]).unwrap();
        assert_eq!(merged_text(&merged), vec!["a = 1", "mine", "b = 1"]);
    }

    #[test]
    fn two_values_for_the_same_setting_stay_one_decision() {
        // Splitting these would let the file end up holding both values for one setting.
        let segments = split(&["Config.MaxContacts = 275"], &["Config.MaxContacts = 100"]);
        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            block_text(blocks[0]),
            (
                vec!["Config.MaxContacts = 275".to_string()],
                vec!["Config.MaxContacts = 100".to_string()]
            )
        );
    }

    #[test]
    fn the_operators_own_lines_start_untouched_and_only_new_lines_start_taken() {
        // Four decisions, and only the one the operator has no line of their own for begins
        // ticked. Anything else would start by proposing to overwrite work they did on purpose.
        let segments = split(
            &[
                "Config = {}",
                "",
                "Config.Locale = 'tr'",
                "Config.Currency = 'USD'",
                "Config.MaxContacts = 275",
                "Config.EnableDebug = false",
                "Config.MyOwnSetting = 'kept'",
            ],
            &[
                "Config = {}",
                "",
                "Config.Locale = 'en'",
                "Config.Currency = 'USD'",
                "Config.MaxContacts = 100",
                "Config.EnableDebug = false",
                "Config.EnableVoiceMail = true",
            ],
        );
        assert_eq!(
            default_choices(&segments, TwoWayMergeMode::PreserveLocalEdits),
            vec![false, false, false, true]
        );
    }

    #[test]
    fn a_comparison_is_not_an_assignment() {
        // `if a == b then` names nothing, so it is never paired with another line by "key". It is
        // still one decision with the line that took its place: two versions of one stretch.
        assert_eq!(assignment_key(b"if a == b then"), None);
        let segments = split(&["if a == b then"], &["while c ~= d do"]);
        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            block_text(blocks[0]),
            (
                vec!["if a == b then".to_string()],
                vec!["while c ~= d do".to_string()]
            )
        );
    }

    #[test]
    fn a_call_the_update_rewrote_is_one_decision_not_two() {
        // Reported from a live update: the operator's `SetFuel(car, 100.0)` and the update's
        // `SetFuel(car, 95.0)` were answered apart, and the file came back holding both calls —
        // a state neither side ever had. A line that names nothing cannot be told apart from the
        // line that replaced it, so the two are one decision.
        let segments = split(
            &[
                "local car = get()",
                "  SetFuel(car, 100.0)",
                "local ped = me()",
            ],
            &[
                "local car = get()",
                "  SetFuel(car, 95.0)",
                "local ped = me()",
            ],
        );
        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            block_text(blocks[0]),
            (
                vec!["  SetFuel(car, 100.0)".to_string()],
                vec!["  SetFuel(car, 95.0)".to_string()]
            )
        );

        // Keeping settings keeps theirs, and taking the update's version replaces it. Neither
        // answer can produce both.
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &[false]).unwrap()),
            vec![
                "local car = get()",
                "  SetFuel(car, 100.0)",
                "local ped = me()"
            ]
        );
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &[true]).unwrap()),
            vec![
                "local car = get()",
                "  SetFuel(car, 95.0)",
                "local ped = me()"
            ]
        );
    }

    #[test]
    fn a_section_the_update_adds_arrives_in_one_piece() {
        // Reported from a live update: 2.7.1 added three configuration sections gksphone 2.4.0 did
        // not have, and the merge sorted each one into its comments and braces first and its
        // settings afterwards. The file came back with closing braces hundreds of lines above the
        // table they closed. An addition the operator has nothing against is one block, in order.
        let section = [
            "-- ### BIOMETRIC UNLOCK ### --",
            "Config.Biometric = {",
            "    Enabled = true,",
            "    FaceId = {",
            "        MaskComponent = 1,",
            "    },",
            "}",
        ];
        let mut incoming = vec!["Config.Debug = false"];
        incoming.extend_from_slice(&section);
        incoming.push("return Config");
        let segments = split(&["Config.Debug = false", "return Config"], &incoming);

        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 1);
        let section_text: Vec<String> = section.iter().map(|line| line.to_string()).collect();
        assert_eq!(block_text(blocks[0]), (vec![], section_text.clone()));

        let choices = default_choices(&segments, TwoWayMergeMode::PreserveLocalEdits);
        let merged = merged_text(&resolve_two_way(&segments, &choices).unwrap());
        assert_eq!(merged[1..merged.len() - 1], section_text[..]);
    }

    #[test]
    fn a_setting_whose_value_runs_on_is_answered_whole() {
        // Reported from the same live update: the operator had `Config.Operators = {}` and 2.7.1
        // filled that table over fourteen lines. Answering the first line apart from the rest kept
        // the empty table and wrote the update's rows after it, outside any table at all.
        let segments = split(
            &["Config.Operators = {}", "return Config"],
            &[
                "Config.Operators = {",
                "    [\"GKS\"] = { label = \"GKS\" },",
                "}",
                "return Config",
            ],
        );
        let blocks: Vec<&TwoWayChangeBlock> = change_blocks(&segments).collect();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            block_text(blocks[0]),
            (
                vec!["Config.Operators = {}".to_string()],
                vec![
                    "Config.Operators = {".to_string(),
                    "    [\"GKS\"] = { label = \"GKS\" },".to_string(),
                    "}".to_string(),
                ]
            )
        );

        // Either answer is a table that closes; neither is half of each.
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &[false]).unwrap()),
            vec!["Config.Operators = {}", "return Config"]
        );
        assert_eq!(
            merged_text(&resolve_two_way(&segments, &[true]).unwrap()),
            vec![
                "Config.Operators = {",
                "    [\"GKS\"] = { label = \"GKS\" },",
                "}",
                "return Config",
            ]
        );
    }

    #[test]
    fn a_bracket_in_a_string_or_a_comment_is_not_structure() {
        // Counting those would make a setting swallow the rest of the file, turning every decision
        // after it into part of one that has nothing to do with them.
        assert_eq!(bracket_depth(b"Config.Prefix = \"{\"", 0), 0);
        assert_eq!(bracket_depth(b"Config.Jobs = {} -- e.g. { police }", 0), 0);
        assert_eq!(bracket_depth(b"Config.Jobs = { -- add your own", 0), 1);
        assert_eq!(bracket_depth(b"}", 1), 0);
        // A stray closer ends the value it looked like it closed, and no more.
        assert_eq!(bracket_depth(b"}}}}", 1), 0);
    }

    #[test]
    fn every_answer_leaves_both_sides_in_the_order_they_were_written() {
        // Whatever is decided, a line that came from a side must still be after the lines that
        // were before it on that side. A merge that reorders one side produces a file neither
        // side ever had, which is how a working config.lua came back unparseable.
        let installed = lines(&[
            "Config.Framework = 'qb'",
            "-- my own note",
            "Config.Locale = 'tr'",
            "CustomHook()",
            "return Config",
        ]);
        let incoming = lines(&[
            "-- ### FRAMEWORK ### --",
            "Config.Framework = 'auto'",
            "Config.Locale = 'en'",
            "Config.NewSetting = 1,",
            "OfficialHook()",
            "return Config",
        ]);
        let segments = split_two_way(&installed, &incoming, TwoWayMergeOptions::default())
            .unwrap()
            .unwrap();
        let count = change_blocks(&segments).count();

        // Every way of answering, not a chosen one: order is a property of the merge, not of a
        // lucky set of ticks.
        for mask in 0u32..(1u32 << count) {
            let choices: Vec<bool> = (0..count).map(|bit| mask & (1 << bit) != 0).collect();
            let merged = resolve_two_way(&segments, &choices).unwrap();
            for (side, origin) in [
                (&installed, TwoWayLineOrigin::Installed),
                (&incoming, TwoWayLineOrigin::Incoming),
            ] {
                let taken: Vec<&Vec<u8>> = merged
                    .iter()
                    .filter(|line| line.origin() == origin)
                    .map(|line| &line.bytes)
                    .collect();
                let mut walk = side.iter();
                assert!(
                    taken
                        .iter()
                        .all(|line| walk.any(|candidate| candidate == *line)),
                    "choices {choices:?} reordered the {origin:?} side"
                );
            }
        }
    }
}
