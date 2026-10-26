//! The two-way update: an installed folder, a package, and a decision per change.
//!
//! This is the flow the product exists for. The operator points at the resource they installed and
//! at the new package they downloaded, sees both sides of every disagreement, and ticks the ones
//! they want the developer's version of. There is no baseline, no second package, and no decision
//! document — the comparison is the two sides they actually have.
//!
//! The security boundary is the one the three-way path already draws. Trusted absolute paths stay
//! here; the frontend addresses a preview by an opaque handle and a file by its resource-relative
//! path. Line content crosses only for files the incoming manifest declares escrow-ignored, which
//! are the only files a server owner could have edited in the first place.

use std::collections::BTreeMap;
use std::path::PathBuf;

use gkrm_core::{
    apply_two_way_update, default_choices, preview_two_way_update,
    resolve_trusted_update_workspace, ResourceRelativePath, TrustedCliUpdateOptions,
    TwoWayApplyRequest, TwoWayBaselineSource, TwoWayFileAction, TwoWayFileChoice, TwoWayMergeMode,
    TwoWaySegment, TwoWayUpdateMode, TwoWayUpdatePlan, TwoWayUpdateRequest,
    MERGED_LINE_VIEW_MAX_LINES, MERGED_LINE_VIEW_MAX_LINE_CHARS,
};
use uuid::Uuid;

use crate::dto::{
    SelectionKind, TwoWayApplyResponse, TwoWayDiffRow, TwoWayFile, TwoWayFileChoiceDto,
    TwoWayFileDisposition, TwoWayGetDiffResponse, TwoWayPreviewResponse, TwoWayReleaseResponse,
    TwoWayRowKind, TwoWaySummary,
};
use crate::error::{DesktopFailure, DesktopResult};
use crate::operation::{map_apply_core_error, map_core_error, MAX_LINE_VIEW_BYTES};
use crate::selection::resolve_selection_for_future_use;
use crate::state::DesktopAppState;

/// The most files one preview will describe on screen.
///
/// A resource with more paths than this is not refused — the update still applies in full — but the
/// listing is capped so one pathological package cannot grow the retained preview without bound.
pub const MAX_TWO_WAY_FILES: usize = 4096;

/// The most separately decidable changes one file will offer.
///
/// Every block is a checkbox the operator has to look at, and the decision list crosses the
/// boundary on every apply, so it is bounded like every other list here.
pub const MAX_TWO_WAY_BLOCKS: usize = 2048;

/// A preview held for the frontend to page through.
struct TwoWayRecord {
    /// The identity of the plan this preview showed.
    ///
    /// The apply re-plans from the live sources, so this is what says the file about to be written
    /// is the file the operator answered. Without it, a decision made against one version of a
    /// file lands on another whenever the block count happens to survive the change.
    plan_id: gkrm_core::Sha256Digest,
    installed: PathBuf,
    package: PathBuf,
    /// The package the operator installed from, when the preview was given one.
    ///
    /// The apply re-plans from the sources itself, so it must be handed the same baseline the
    /// preview was: without it the apply would ask about files the operator was never shown and
    /// refuse their decisions for not matching.
    baseline: Option<PathBuf>,
    /// What this installation was last updated from, when the preview reached for it itself.
    ///
    /// The apply re-plans from the sources, so it must be handed the same baseline the preview
    /// was, or it would ask a different set of questions than the operator answered.
    remembered_baseline: Option<gkrm_core::BaselineId>,
    installed_selection: String,
    package_selection: String,
    baseline_selection: Option<String>,
    app_data_root: PathBuf,
    /// The listed files, so a diff can only be asked for by a path this preview actually named.
    files: Vec<TwoWayFile>,
    /// Paths a decision may name, in their trusted form, so a decision names a path the core
    /// already knows. Every reviewed file is here, including the ones with no line view: those
    /// hold no per-line decisions, but they are still the operator's to answer whole.
    reviewed: BTreeMap<String, ResourceRelativePath>,
    /// Rendered diffs, by resource-relative path. Only escrow-ignored files appear here.
    diffs: BTreeMap<String, DiffState>,
    /// Reviewed files with no line view: why, and both sides where they were small enough to keep.
    whole_files: BTreeMap<String, gkrm_core::TwoWayWholeFile>,
}

enum DiffState {
    Available {
        rows: Vec<TwoWayDiffRow>,
        block_count: u32,
        default_choices: Vec<bool>,
        truncated: bool,
    },
    /// A view existed but was dropped to keep the retained preview bounded. The count of
    /// decisions survives it, so a file too large to draw can still be answered as a whole.
    Omitted { block_count: u32 },
}

#[derive(Default)]
pub struct TwoWayRegistry {
    records: BTreeMap<String, TwoWayRecord>,
}

impl TwoWayRegistry {
    fn insert(&mut self, record: TwoWayRecord) -> String {
        let handle = Uuid::new_v4().to_string();
        self.records.insert(handle.clone(), record);
        handle
    }

    fn get(&self, handle: &str) -> DesktopResult<&TwoWayRecord> {
        self.records.get(handle).ok_or(DesktopFailure::PlanNotFound)
    }

    fn release(&mut self, handle: &str) -> DesktopResult<()> {
        self.records
            .remove(handle)
            .map(|_| ())
            .ok_or(DesktopFailure::PlanNotFound)
    }
}

fn disposition(action: TwoWayFileAction) -> TwoWayFileDisposition {
    match action {
        TwoWayFileAction::Unchanged => TwoWayFileDisposition::Unchanged,
        TwoWayFileAction::TakeFromUpdate => TwoWayFileDisposition::TakeFromUpdate,
        TwoWayFileAction::Review => TwoWayFileDisposition::Review,
        TwoWayFileAction::KeepLocalOnly => TwoWayFileDisposition::KeepLocalOnly,
    }
}

fn summarize(plan: &TwoWayUpdatePlan) -> TwoWaySummary {
    let summary = plan.summary();
    TwoWaySummary {
        unchanged: summary.unchanged() as u32,
        take_from_update: summary.take_from_update() as u32,
        review: summary.review() as u32,
        keep_local_only: summary.keep_local_only() as u32,
        total: summary.total() as u32,
    }
}

/// How many identical lines are kept either side of a decision, for the operator to read it by.
const CONTEXT_LINES: usize = 3;
/// A run shorter than this is shown whole; folding it would cost a line to save one.
const MIN_FOLDED_LINES: usize = 2;

/// A stand-in for lines both sides already agree on.
fn gap(skipped: usize) -> TwoWayDiffRow {
    TwoWayDiffRow {
        kind: TwoWayRowKind::Gap,
        block: None,
        text: String::new(),
        truncated: false,
        skipped: Some(u32::try_from(skipped).unwrap_or(u32::MAX)),
        installed_line: None,
        incoming_line: None,
    }
}

fn line_number(counter: usize) -> Option<u32> {
    u32::try_from(counter).ok()
}

/// One display line, cut at the per-line character limit.
fn row(kind: TwoWayRowKind, block: Option<u32>, bytes: &[u8]) -> TwoWayDiffRow {
    let text = String::from_utf8_lossy(bytes);
    let mut shortened: String = text.chars().take(MERGED_LINE_VIEW_MAX_LINE_CHARS).collect();
    let cut = shortened.chars().count() < text.chars().count();
    if cut {
        shortened.push('…');
    }
    TwoWayDiffRow {
        kind,
        block,
        text: shortened,
        truncated: cut,
        skipped: None,
        installed_line: None,
        incoming_line: None,
    }
}

/// Render one file's segments as the rows the operator ticks.
///
/// Both sides of every disagreement are shown, in the order a diff reads them: what you have, then
/// what the update has in its place. A block with only one side is a pure addition or a pure
/// removal, and is still one decision.
///
/// Long lines are cut at a character boundary and long files at a row count, and both facts are
/// reported rather than hidden: a silently shortened diff would understate what is about to change.
fn render_diff(segments: &[TwoWaySegment], budget: &mut usize) -> DiffState {
    let default_choices = default_choices(segments, TwoWayMergeMode::PreserveLocalEdits);
    let block_count = default_choices.len() as u32;
    if default_choices.len() > MAX_TWO_WAY_BLOCKS {
        return DiffState::Omitted { block_count };
    }

    let mut rows: Vec<TwoWayDiffRow> = Vec::new();
    let mut used = 0usize;
    let mut block_index = 0u32;
    let mut truncated = false;
    // Where the next line of each side sits in its own file, so the operator can find a change
    // rather than only read it.
    let mut installed_at = 1usize;
    let mut incoming_at = 1usize;

    let push = |rows: &mut Vec<TwoWayDiffRow>, used: &mut usize, next: TwoWayDiffRow| -> bool {
        if rows.len() >= MERGED_LINE_VIEW_MAX_LINES {
            return false;
        }
        *used = used.saturating_add(next.text.len()).saturating_add(24);
        rows.push(next);
        true
    };

    for (position, segment) in segments.iter().enumerate() {
        match segment {
            TwoWaySegment::Unchanged(lines) => {
                // A five-hundred-line config is mostly lines nobody is touching. Keep enough of
                // them either side of a decision to read it by, and say how many stand between.
                let follows_decision = segments[..position]
                    .iter()
                    .any(|earlier| matches!(earlier, TwoWaySegment::Change(_)));
                let precedes_decision = segments[position + 1..]
                    .iter()
                    .any(|later| matches!(later, TwoWaySegment::Change(_)));
                let head = if follows_decision {
                    CONTEXT_LINES.min(lines.len())
                } else {
                    0
                };
                let tail = if precedes_decision {
                    CONTEXT_LINES.min(lines.len() - head)
                } else {
                    0
                };
                let hidden = lines.len() - head - tail;
                let folded = hidden >= MIN_FOLDED_LINES;
                let mut stop = false;
                for (index, line) in lines.iter().enumerate() {
                    if folded {
                        if index == head && !push(&mut rows, &mut used, gap(hidden)) {
                            stop = true;
                            break;
                        }
                        if index >= head && index < lines.len() - tail {
                            continue;
                        }
                    }
                    let mut next = row(TwoWayRowKind::Context, None, line);
                    next.installed_line = line_number(installed_at + index);
                    next.incoming_line = line_number(incoming_at + index);
                    if !push(&mut rows, &mut used, next) {
                        stop = true;
                        break;
                    }
                }
                if stop {
                    truncated = true;
                }
                installed_at += lines.len();
                incoming_at += lines.len();
            }
            TwoWaySegment::Change(block) => {
                for (index, line) in block.installed().iter().enumerate() {
                    let mut next = row(TwoWayRowKind::Yours, Some(block_index), line);
                    next.installed_line = line_number(installed_at + index);
                    if !push(&mut rows, &mut used, next) {
                        truncated = true;
                        break;
                    }
                }
                for (index, line) in block.incoming().iter().enumerate() {
                    let mut next = row(TwoWayRowKind::Theirs, Some(block_index), line);
                    next.incoming_line = line_number(incoming_at + index);
                    if !push(&mut rows, &mut used, next) {
                        truncated = true;
                        break;
                    }
                }
                installed_at += block.installed().len();
                incoming_at += block.incoming().len();
                block_index = block_index.saturating_add(1);
            }
        }
        if used > *budget {
            return DiffState::Omitted { block_count };
        }
    }

    *budget = budget.saturating_sub(used);
    DiffState::Available {
        rows,
        block_count,
        default_choices,
        truncated,
    }
}

/// Compare the installed resource against the package and hold the result for the frontend.
pub fn two_way_preview(
    state: &DesktopAppState,
    installed_handle: &str,
    package_handle: &str,
    baseline_handle: Option<&str>,
    app_data_root: PathBuf,
) -> DesktopResult<TwoWayPreviewResponse> {
    let installed = resolve_selection_for_future_use(state, installed_handle)?;
    let package = resolve_selection_for_future_use(state, package_handle)?;
    if installed.kind != SelectionKind::InstalledRoot || package.kind != SelectionKind::PackageFile
    {
        return Err(DesktopFailure::InvalidRequest);
    }
    // The package the operator installed from, if they still have it. It decides which files are
    // worth asking about and nothing else, so it is a package like the other one and held to the
    // same checks.
    let baseline = match baseline_handle {
        Some(handle) => {
            let selection = resolve_selection_for_future_use(state, handle)?;
            if selection.kind != SelectionKind::PackageFile {
                return Err(DesktopFailure::InvalidRequest);
            }
            Some(selection)
        }
        None => None,
    };

    let workspace = resolve_trusted_update_workspace(&app_data_root).map_err(map_core_error)?;
    // What this installation was last updated from, when nobody pointed at a package. After the
    // first update this is the ordinary case: the operator should not have to keep a ZIP to be
    // told which of their own files they edited.
    let remembered = match &baseline {
        Some(_) => None,
        None => crate::installed_baseline::lookup(&app_data_root, &installed.path),
    };
    let remembered_id = remembered
        .as_ref()
        .and_then(|entry| gkrm_core::BaselineId::parse(&entry.baseline_id).ok());
    let baseline_source = match (&baseline, &remembered_id) {
        (Some(selection), _) => Some(TwoWayBaselineSource::Package(selection.path.as_path())),
        (None, Some(baseline_id)) => Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id,
        }),
        (None, None) => None,
    };
    let preview = preview_two_way_update(TwoWayUpdateRequest {
        package: &package.path,
        installed: &installed.path,
        baseline: baseline_source,
        resource: None,
        transaction_root: workspace.transaction_root(),
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .map_err(map_core_error)?;

    let plan = preview.plan();
    let summary = summarize(plan);
    let listed = plan.entries().len().min(MAX_TWO_WAY_FILES);

    // Files the operator can look at line by line: every escrow-ignored file that differs.
    // Everything else is either unchanged, encrypted, or theirs alone.
    let mut budget = MAX_LINE_VIEW_BYTES;
    let mut diffs = BTreeMap::new();
    let mut reviewed = BTreeMap::new();
    // How many decisions each reviewed file holds, taken from the split rather than from the view
    // that was drawn of it. A file whose lines did not fit still holds its decisions, and the
    // operator answers it as a whole from the file list without ever opening it.
    let mut block_counts: BTreeMap<String, u32> = BTreeMap::new();
    // The reviewed files with no line view, with why and both sides as they were read. This is
    // what the screen shows in place of a diff: the reason in words, and for an image, the image.
    let mut whole_files: BTreeMap<String, gkrm_core::TwoWayWholeFile> = BTreeMap::new();
    for file in preview.reviewed() {
        let key = file.path().as_str().to_string();
        block_counts.insert(key.clone(), file.blocks().count() as u32);
        reviewed.insert(key.clone(), file.path().clone());
        diffs.insert(key, render_diff(file.segments(), &mut budget));
    }
    // Reviewed files with no line view. They hold no decisions to count, so they carry none — and
    // an answer for one is the whole file, which is a decision the operator can still make.
    for (path, whole) in preview.unmergeable() {
        let key = path.as_str().to_string();
        reviewed.insert(key.clone(), path.clone());
        whole_files.insert(key, whole.clone());
    }

    let files: Vec<TwoWayFile> = plan
        .entries()
        .iter()
        .take(MAX_TWO_WAY_FILES)
        .map(|entry| TwoWayFile {
            path: entry.path().as_str().to_string(),
            disposition: disposition(entry.action()),
            editable: entry.editable(),
            untouched: entry.untouched_since_install(),
            merged_by_key: whole_files
                .get(entry.path().as_str())
                .is_some_and(|whole| whole.merged().is_some()),
            block_count: block_counts
                .get(entry.path().as_str())
                .copied()
                .unwrap_or_default(),
        })
        .collect();

    let unmergeable: Vec<String> = whole_files.keys().cloned().collect();

    let resource = plan.resource_key().as_str().to_string();
    let mut registry = state.two_way.lock().map_err(|_| DesktopFailure::Internal)?;
    let handle = registry.insert(TwoWayRecord {
        plan_id: *plan.plan_id().digest(),
        installed: installed.path.clone(),
        package: package.path.clone(),
        baseline: baseline.as_ref().map(|selection| selection.path.clone()),
        remembered_baseline: remembered_id.clone(),
        installed_selection: installed_handle.to_string(),
        package_selection: package_handle.to_string(),
        baseline_selection: baseline_handle.map(str::to_string),
        app_data_root,
        files: files.clone(),
        reviewed,
        diffs,
        whole_files,
    });

    Ok(TwoWayPreviewResponse {
        handle,
        resource,
        installed_version: preview.installed_version().map(str::to_owned),
        incoming_version: preview.incoming_version().map(str::to_owned),
        summary,
        files,
        omitted_file_count: plan.entries().len().saturating_sub(listed) as u32,
        unmergeable,
        remembered_baseline_version: remembered.as_ref().and_then(|entry| entry.version.clone()),
        used_remembered_baseline: remembered_id.is_some(),
    })
}

/// One file's diff, with both sides of every change and where its ticks start.
pub fn two_way_get_diff(
    state: &DesktopAppState,
    handle: &str,
    path: &str,
) -> DesktopResult<TwoWayGetDiffResponse> {
    let registry = state.two_way.lock().map_err(|_| DesktopFailure::Internal)?;
    let record = registry.get(handle)?;
    if !record.files.iter().any(|file| file.path == path) {
        return Err(DesktopFailure::PlanChangeNotFound);
    }
    let empty = TwoWayGetDiffResponse {
        available: false,
        rows: Vec::new(),
        block_count: 0,
        default_choices: Vec::new(),
        truncated: false,
        omitted: false,
        merged_by_key: false,
        kept_keys: Vec::new(),
        kept_key_count: 0,
        whole_file_reason: None,
        installed_image: None,
        incoming_image: None,
        image_media_type: None,
    };
    match record.diffs.get(path) {
        Some(DiffState::Available {
            rows,
            block_count,
            default_choices,
            truncated,
        }) => Ok(TwoWayGetDiffResponse {
            available: true,
            rows: rows.clone(),
            block_count: *block_count,
            default_choices: default_choices.clone(),
            truncated: *truncated,
            omitted: false,
            ..empty
        }),
        // The view reports what it drew, which is nothing. What there is to decide is reported by
        // the file list, so a dropped view never has to carry ticks it has no rows for.
        Some(DiffState::Omitted { .. }) => Ok(TwoWayGetDiffResponse {
            omitted: true,
            ..empty
        }),
        // Encrypted content is never retained and never shown, and an unchanged file has nothing
        // to show. Both are the absence of a view rather than an error.
        None => match record.whole_files.get(path) {
            // No lines to draw, so the screen says why — and where the file is a picture, shows
            // the two of them rather than describing them.
            Some(whole) => {
                let media_type = image_media_type(path);
                let (installed_image, incoming_image) = match media_type {
                    Some(_) => (whole.installed().map(base64), whole.incoming().map(base64)),
                    None => (None, None),
                };
                // Enough of them to see what happened, and a count for the rest: a locale file can
                // keep more keys than any list is worth reading.
                const MAX_KEPT_KEYS_SHOWN: usize = 40;
                Ok(TwoWayGetDiffResponse {
                    merged_by_key: whole.merged().is_some(),
                    kept_keys: whole
                        .kept_keys()
                        .iter()
                        .take(MAX_KEPT_KEYS_SHOWN)
                        .cloned()
                        .collect(),
                    kept_key_count: u32::try_from(whole.kept_keys().len()).unwrap_or(u32::MAX),
                    whole_file_reason: Some(unmergeable_reason(whole.reason())),
                    image_media_type: media_type
                        .filter(|_| installed_image.is_some() || incoming_image.is_some()),
                    installed_image,
                    incoming_image,
                    ..empty
                })
            }
            None => Ok(empty),
        },
    }
}

fn unmergeable_reason(reason: gkrm_core::TwoWayUnmergeableReason) -> &'static str {
    match reason {
        gkrm_core::TwoWayUnmergeableReason::NotText => "not_text",
        gkrm_core::TwoWayUnmergeableReason::TooFarApart => "too_far_apart",
        gkrm_core::TwoWayUnmergeableReason::TooLarge => "too_large",
    }
}

/// The media type this path's name claims, for the kinds worth drawing.
///
/// A name is not proof of content, which is why the page is handed a data URL and nothing else:
/// the picture is drawn by the viewer or it is not drawn, and either way nothing is executed.
/// SVG is deliberately absent — it is markup a browser will run.
fn image_media_type(path: &str) -> Option<&'static str> {
    let extension = path
        .rsplit('/')
        .next()?
        .rsplit_once('.')?
        .1
        .to_ascii_lowercase();
    match extension.as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "bmp" => Some("image/bmp"),
        "ico" => Some("image/x-icon"),
        _ => None,
    }
}

/// Standard base64, no line breaks. Small enough to keep rather than to depend on.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Apply the update.
///
/// `keep_settings` is the preset for every reviewed file the operator did not decide by hand;
/// `choices` carries the ones they did, block by block.
pub fn two_way_apply(
    state: &DesktopAppState,
    handle: &str,
    keep_settings: bool,
    choices: &[TwoWayFileChoiceDto],
) -> DesktopResult<TwoWayApplyResponse> {
    // Take what the apply needs and drop the lock: the apply is long, and holding the registry
    // across it would block every other read of it.
    #[allow(clippy::type_complexity)]
    let (
        plan_id,
        installed,
        package,
        baseline,
        remembered_baseline,
        app_data_root,
        installed_selection,
        package_selection,
        baseline_selection,
        decisions,
    ) = {
        let registry = state.two_way.lock().map_err(|_| DesktopFailure::Internal)?;
        let record = registry.get(handle)?;

        // Every decision must name a file this preview offered for review, and carry exactly one
        // tick per change block it showed. Anything else is a decision made against a different
        // file than the one about to be written.
        let mut decisions: Vec<(ResourceRelativePath, Vec<bool>)> = Vec::new();
        for choice in choices {
            let path = record
                .reviewed
                .get(&choice.path)
                .ok_or(DesktopFailure::PlanChangeNotFound)?;
            let expected = match record.diffs.get(&choice.path) {
                Some(DiffState::Available { block_count, .. })
                | Some(DiffState::Omitted { block_count }) => *block_count as usize,
                // A reviewed file with no line view holds no per-line decisions. The empty list
                // is not a missing answer, it is the answer: take this file whole.
                None => 0,
            };
            if choice.take_from_update.len() != expected {
                return Err(DesktopFailure::InvalidRequest);
            }
            decisions.push((path.clone(), choice.take_from_update.clone()));
        }

        (
            record.plan_id,
            record.installed.clone(),
            record.package.clone(),
            record.baseline.clone(),
            record.remembered_baseline.clone(),
            record.app_data_root.clone(),
            record.installed_selection.clone(),
            record.package_selection.clone(),
            record.baseline_selection.clone(),
            decisions,
        )
    };

    // Both selections must still be the ones that were previewed. The apply re-seals and re-plans
    // from the sources itself, so this is about the operator's intent, not the merge's safety.
    let live_installed = resolve_selection_for_future_use(state, &installed_selection)?;
    let live_package = resolve_selection_for_future_use(state, &package_selection)?;
    if live_installed.path != installed || live_package.path != package {
        return Err(DesktopFailure::SelectionStale);
    }
    // The baseline decided which questions the operator was asked, so it is as much a part of what
    // they answered as the other two sides.
    if let Some(selection) = &baseline_selection {
        let live_baseline = resolve_selection_for_future_use(state, selection)?;
        if Some(&live_baseline.path) != baseline.as_ref() {
            return Err(DesktopFailure::SelectionStale);
        }
    }

    let core_choices: Vec<TwoWayFileChoice<'_>> = decisions
        .iter()
        .map(|(path, take_from_update)| TwoWayFileChoice {
            path,
            take_from_update,
        })
        .collect();

    let workspace = resolve_trusted_update_workspace(&app_data_root).map_err(map_core_error)?;
    let baseline_source = match (&baseline, &remembered_baseline) {
        (Some(path), _) => Some(TwoWayBaselineSource::Package(path.as_path())),
        (None, Some(baseline_id)) => Some(TwoWayBaselineSource::Stored {
            store_root: workspace.baseline_store(),
            baseline_id,
        }),
        (None, None) => None,
    };
    let outcome = apply_two_way_update(TwoWayApplyRequest {
        expected_plan_id: Some(&plan_id),
        package: &package,
        installed: &installed,
        baseline: baseline_source,
        resource: None,
        staging_root: workspace.staging_root(),
        transaction_root: workspace.transaction_root(),
        mode: if keep_settings {
            TwoWayUpdateMode::PreserveLocalEdits
        } else {
            TwoWayUpdateMode::ReplaceWithIncoming
        },
        choices: &core_choices,
        workspace: Some(&workspace),
        options: TrustedCliUpdateOptions::default(),
    })
    .map_err(map_apply_core_error)?;

    // Remember it, so the history screen can show what was done without asking the operator to
    // point at the folder again. An update that changed nothing is not one of them: a list of
    // non-events is a list nobody reads. A failure to write it is not a failure of the update
    // either — the update is already committed, and its durable evidence is the workspace's.
    let summary = summarize(outcome.plan());
    if outcome.outcome() != "already_up_to_date" {
        let id = Uuid::new_v4().to_string();
        // What it would take to put this back, filed under the same id. The transaction already
        // holds the content; this is the only record of which file each backed-up object came
        // from, and without it a finished update cannot be undone at all.
        if outcome.outcome() == "committed" {
            let _ = crate::undo::write(&app_data_root, &undo_record(&id, &installed, &outcome));
            // What this installation is now installed from, so the next update reaches for it
            // itself. It is a note about the package the workspace already kept; losing it costs
            // the next update its evidence and nothing else.
            if let Some(baseline_id) = outcome.baseline_id() {
                crate::installed_baseline::record(
                    &app_data_root,
                    crate::installed_baseline::InstalledBaseline {
                        installed_root: installed.to_string_lossy().into_owned(),
                        resource: outcome.plan().resource_key().as_str().to_string(),
                        baseline_id: baseline_id.as_str().to_string(),
                        version: outcome.incoming_version().map(str::to_owned),
                    },
                );
            }
        }
        let _ = crate::history::record(
            &app_data_root,
            crate::history::RecordedUpdate {
                id: &id,
                resource: outcome.plan().resource_key().as_str(),
                outcome: outcome.outcome(),
                reviewed: summary.review,
                replaced: summary.take_from_update,
                total: summary.total,
                from_version: outcome.installed_version().map(str::to_owned),
                to_version: outcome.incoming_version().map(str::to_owned),
            },
        );
    }

    Ok(TwoWayApplyResponse {
        outcome: outcome.outcome().to_string(),
        summary,
    })
}

/// What it would take to put this update back, read off the plan it just applied.
///
/// A file the update replaced is named with the digest of what was there before it; a file the
/// update created is named with the digest of what it wrote, so undoing removes only the file the
/// update actually put there. Files it left alone are not mentioned: an undo has nothing to say
/// about them.
fn undo_record(
    id: &str,
    installed: &std::path::Path,
    outcome: &gkrm_core::TwoWayApplyOutcome,
) -> crate::undo::UndoRecord {
    let plan = outcome.plan();
    let resource_path = outcome.installed_resource_path();
    let transaction_id = outcome.transaction_id();
    let previous_baseline = outcome.previous_baseline_id();
    let previous_version = outcome.installed_version();
    let mut restore = Vec::new();
    let mut remove = Vec::new();
    for entry in outcome.written_files() {
        let path = entry.path().as_str().to_string();
        match entry.before() {
            Some(before) => restore.push(crate::undo::UndoFile {
                path,
                sha256: before.to_string(),
                written_sha256: Some(entry.after().to_string()),
            }),
            None => remove.push(crate::undo::UndoFile {
                path,
                sha256: entry.after().to_string(),
                written_sha256: None,
            }),
        }
    }
    crate::undo::UndoRecord {
        id: id.to_string(),
        resource: plan.resource_key().as_str().to_string(),
        installed_root: installed.to_string_lossy().into_owned(),
        // Empty is the root itself. Always recorded, so putting the update back never has to
        // guess which of the two the operator pointed at.
        resource_path: Some(resource_path.unwrap_or_default().to_string()),
        // What the update is on record as. Putting it back takes the record with it, or the same
        // update could never be applied again.
        transaction_id: transaction_id.map(ToString::to_string),
        // What the installation was installed from before. Undoing puts the installation back to
        // what it was, and this is part of what it was; the version is carried only to say which
        // package it is when the operator is told about it.
        previous_baseline_id: previous_baseline.map(|id| id.as_str().to_string()),
        previous_baseline_version: previous_baseline.and(previous_version).map(str::to_owned),
        restore,
        remove,
    }
}

pub fn two_way_release(
    state: &DesktopAppState,
    handle: &str,
) -> DesktopResult<TwoWayReleaseResponse> {
    let mut registry = state.two_way.lock().map_err(|_| DesktopFailure::Internal)?;
    registry.release(handle)?;
    Ok(TwoWayReleaseResponse { released: true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gkrm_core::split_two_way;

    fn lines(values: &[&str]) -> Vec<Vec<u8>> {
        values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect()
    }

    fn rendered(installed: &[&str], incoming: &[&str]) -> Vec<TwoWayDiffRow> {
        let segments = split_two_way(
            &lines(installed),
            &lines(incoming),
            gkrm_core::TwoWayMergeOptions::default(),
        )
        .expect("split")
        .expect("mergeable");
        let mut budget = MAX_LINE_VIEW_BYTES;
        match render_diff(&segments, &mut budget) {
            DiffState::Available { rows, .. } => rows,
            DiffState::Omitted { .. } => panic!("omitted"),
        }
    }

    /// A file with one change in the middle of a long stretch nobody is touching.
    fn long_config(changed: &str) -> Vec<String> {
        let mut file: Vec<String> = (0..60)
            .map(|index| format!("Config.Filler{index} = {index}"))
            .collect();
        file.insert(30, changed.to_owned());
        file
    }

    #[test]
    fn lines_nobody_is_changing_are_stood_in_for_rather_than_scrolled_past() {
        // The case this exists for: a long config with a single edit in the middle. Showing all
        // sixty-one lines buries the one decision the operator has to make.
        let installed: Vec<String> = long_config("Config.Locale = 'tr'");
        let incoming: Vec<String> = long_config("Config.Locale = 'en'");
        let installed: Vec<&str> = installed.iter().map(String::as_str).collect();
        let incoming: Vec<&str> = incoming.iter().map(String::as_str).collect();

        let rows = rendered(&installed, &incoming);
        let context = rows
            .iter()
            .filter(|row| row.kind == TwoWayRowKind::Context)
            .count();
        let gaps: Vec<u32> = rows
            .iter()
            .filter_map(|row| (row.kind == TwoWayRowKind::Gap).then_some(row.skipped.unwrap_or(0)))
            .collect();

        // Three lines either side of the decision, and the rest accounted for by two gaps.
        assert_eq!(context, 6);
        assert_eq!(gaps, vec![27, 27]);
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind == TwoWayRowKind::Yours)
                .count(),
            1
        );
        // Every line is either shown or counted; none is silently dropped.
        let counted: u32 = gaps.iter().sum();
        assert_eq!(counted as usize + context, 60);
    }

    #[test]
    fn every_line_says_where_it_sits_in_its_own_file() {
        // A change is only findable in a five-hundred-line config if it says which line it is on.
        let rows = rendered(&["a = 1", "b = 1", "c = 1"], &["a = 1", "b = 2", "c = 1"]);
        let context: Vec<(Option<u32>, Option<u32>)> = rows
            .iter()
            .filter(|row| row.kind == TwoWayRowKind::Context)
            .map(|row| (row.installed_line, row.incoming_line))
            .collect();
        assert_eq!(context, vec![(Some(1), Some(1)), (Some(3), Some(3))]);

        let yours = rows
            .iter()
            .find(|row| row.kind == TwoWayRowKind::Yours)
            .expect("yours");
        assert_eq!((yours.installed_line, yours.incoming_line), (Some(2), None));
        let theirs = rows
            .iter()
            .find(|row| row.kind == TwoWayRowKind::Theirs)
            .expect("theirs");
        assert_eq!(
            (theirs.installed_line, theirs.incoming_line),
            (None, Some(2))
        );
    }

    #[test]
    fn a_short_stretch_is_shown_whole_rather_than_folded() {
        // Folding two lines to save one is noise, not brevity.
        let rows = rendered(&["a = 1", "b", "c = 1"], &["a = 2", "b", "c = 2"]);
        assert!(rows.iter().all(|row| row.kind != TwoWayRowKind::Gap));
    }

    /// What a file's decisions come to, however much of it was drawn.
    fn counted(installed: &[&str], incoming: &[&str], budget: usize) -> u32 {
        let segments = split_two_way(
            &lines(installed),
            &lines(incoming),
            gkrm_core::TwoWayMergeOptions::default(),
        )
        .expect("split")
        .expect("mergeable");
        let mut budget = budget;
        match render_diff(&segments, &mut budget) {
            DiffState::Available { block_count, .. } | DiffState::Omitted { block_count } => {
                block_count
            }
        }
    }

    #[test]
    fn a_file_too_large_to_draw_still_says_how_many_decisions_it_holds() {
        // The count is what lets the operator answer a file from the list without opening it. A
        // view that was dropped to stay within bounds must not take the count down with it, or
        // the one file they cannot read is also the one file they cannot answer.
        let installed: Vec<String> = (0..40).map(|index| format!("a{index} = 1")).collect();
        let incoming: Vec<String> = (0..40).map(|index| format!("a{index} = 2")).collect();
        let installed: Vec<&str> = installed.iter().map(String::as_str).collect();
        let incoming: Vec<&str> = incoming.iter().map(String::as_str).collect();

        let drawn = counted(&installed, &incoming, MAX_LINE_VIEW_BYTES);
        let dropped = counted(&installed, &incoming, 0);
        assert_eq!(drawn, 40);
        assert_eq!(dropped, drawn);
    }

    #[test]
    fn base64_matches_the_standard_including_its_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        // Every byte value, so the high bits and the alphabet's tail are exercised.
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(base64(&all).len(), 344);
        assert!(base64(&all).ends_with("/P3+/w=="));
    }

    #[test]
    fn only_pictures_a_viewer_draws_are_offered_as_pictures() {
        assert_eq!(image_media_type("html/img/bank.png"), Some("image/png"));
        assert_eq!(image_media_type("html/img/BANK.PNG"), Some("image/png"));
        assert_eq!(image_media_type("wall.jpeg"), Some("image/jpeg"));
        assert_eq!(image_media_type("config/config.json"), None);
        // Markup a browser would run is not a picture, whatever it is called.
        assert_eq!(image_media_type("html/img/logo.svg"), None);
        assert_eq!(image_media_type("noextension"), None);
    }

    #[test]
    fn a_gap_carries_a_count_and_a_line_never_does() {
        let installed: Vec<String> = long_config("Config.Locale = 'tr'");
        let incoming: Vec<String> = long_config("Config.Locale = 'en'");
        let installed: Vec<&str> = installed.iter().map(String::as_str).collect();
        let incoming: Vec<&str> = incoming.iter().map(String::as_str).collect();

        for row in rendered(&installed, &incoming) {
            assert_eq!(row.skipped.is_some(), row.kind == TwoWayRowKind::Gap);
        }
    }
}
