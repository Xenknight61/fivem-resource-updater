//! Preview an update from an installation and a package alone.
//!
//! The source sealing, resource selection, and recovery-first ordering are exactly the ones the
//! three-way path performs. Only the comparison differs: there is no baseline to resolve, so the
//! plan comes from the two snapshots directly and the editable files that differ are merged
//! two-way for the operator to look at before anything is written.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::artifact::encode_cli_artifact_v2_with_two_way_descriptor;
use super::id::encode_operator_merge_set_id;
use super::publish::publish_bytes_no_replace;
use super::{
    inspect_installation_update_from_package_snapshot, prepare_bound_trusted_update_sources,
    resolve_selected_resource, same_resource_recovery_blocks_new_work, snapshots_for_selection,
    source_commitments_from_report, verify_sealed_installed_snapshot_commitment,
    TrustedCliUpdateArtifactBody,
};
use crate::three_way_text_diff::split_logical_lines;
use crate::trusted_apply_planning::{
    plan_trusted_apply, InstalledApplyPlanningSource, TrustedApplyPlanningOptions,
    TrustedApplyPlanningRequest, TrustedApplyStatus,
};
use crate::trusted_recovery_authority::{
    build_recovery_authority_body, RecoveryAuthorityLimits, RecoveryAuthorityPublication,
};
use crate::trusted_staging::{
    stage_trusted_resource_two_way, IncomingStagingContentSource, InstalledStagingContentSource,
    TrustedStagingOperatorMergeInput, TrustedStagingOptions, TrustedStagingRoot,
    TwoWayStagingRequest, TwoWayUpdateMode,
};
use crate::trusted_transactional_apply_execution::{
    execute_trusted_transactional_apply, TrustedTransactionResult,
    TrustedTransactionalApplyExecutionOptions, TrustedTransactionalApplyExecutionRequest,
};
use crate::trusted_transactional_apply_planning::{
    plan_trusted_transactional_apply, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest,
};
use crate::{
    change_blocks, create_two_way_update_plan, default_choices_with_untouched,
    inspect_installation_update, resolve_two_way, split_two_way, untouched_blocks, BaselineId,
    BaselineResolutionOptions, BaselineResolutionRequest, BaselineStoreLimits, GkrmError,
    IncomingMergeContentSource, IncomingMergeContentSourceLimits, InspectionOptions,
    InstalledMergeContentSource, InstalledResourceRoot, InstalledScanLimits, MergeContentEncoding,
    MergeNewlineStyle, OfficialBaselineSelector, ResourceRelativePath, Result, SafeResourceKey,
    Sha256Digest, ThreeWayMergedBytesOptions, TrustedCliUpdateOptions, TrustedTransactionRoot,
    TrustedUpdateWorkspace, TwoWayBaseline, TwoWayChangeBlock, TwoWayFileAction, TwoWayMergeMode,
    TwoWayMergeOptions, TwoWayMergedLine, TwoWaySegment, TwoWayUpdatePlan, ZipRelativePath,
    ZipResourceRoot,
};

/// Where the version the operator installed comes from.
///
/// A package they still have, or one this kept for them the last time it updated this
/// installation. The second is the ordinary case after the first update: an operator should not
/// have to keep a ZIP to be told which of their own files they edited.
#[derive(Debug, Clone, Copy)]
pub enum TwoWayBaselineSource<'a> {
    /// A package on disk, as the operator points at it.
    Package(&'a Path),
    /// One this kept, by the identity it was kept under.
    Stored {
        store_root: &'a Path,
        baseline_id: &'a BaselineId,
    },
}

/// Inputs for a two-way preview.
pub struct TwoWayUpdateRequest<'a> {
    pub package: &'a Path,
    pub installed: &'a Path,
    /// What the operator installed from, when that is known.
    ///
    /// Read for evidence and for the versions of the files it holds, never as content to write: it
    /// says which editable files the operator has actually edited, so the ones only the developer
    /// touched stop being asked about, and it is what a merge compares against to tell one side's
    /// lines from the other's. No byte of it is written anywhere.
    pub baseline: Option<TwoWayBaselineSource<'a>>,
    pub resource: Option<&'a SafeResourceKey>,
    pub transaction_root: &'a Path,
    pub workspace: Option<&'a TrustedUpdateWorkspace>,
    pub options: TrustedCliUpdateOptions,
}

/// One editable file that differs, with both sides of every disagreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayReviewFile {
    path: ResourceRelativePath,
    segments: Vec<TwoWaySegment>,
    merged: Vec<TwoWayMergedLine>,
}

impl TwoWayReviewFile {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }

    /// The file as agreement and change blocks, in order. Each block is one decision.
    pub fn segments(&self) -> &[TwoWaySegment] {
        &self.segments
    }

    /// The change blocks alone, in the order their decisions are given.
    pub fn blocks(&self) -> impl Iterator<Item = &TwoWayChangeBlock> {
        change_blocks(&self.segments)
    }

    /// The file as it would be written under "keep my settings", one entry per surviving line.
    pub fn merged(&self) -> &[TwoWayMergedLine] {
        &self.merged
    }
}

/// What the operator decided for one file, block by block.
#[derive(Debug, Clone, Copy)]
pub struct TwoWayFileChoice<'a> {
    pub path: &'a ResourceRelativePath,
    /// One decision per change block, in order. `true` takes the update's lines there.
    pub take_from_update: &'a [bool],
}

/// A preview of the whole update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayUpdatePreview {
    plan: TwoWayUpdatePlan,
    reviewed: Vec<TwoWayReviewFile>,
    unmergeable: Vec<(ResourceRelativePath, TwoWayWholeFile)>,
    installed_version: Option<String>,
    incoming_version: Option<String>,
}

impl TwoWayUpdatePreview {
    pub fn plan(&self) -> &TwoWayUpdatePlan {
        &self.plan
    }

    pub fn reviewed(&self) -> &[TwoWayReviewFile] {
        &self.reviewed
    }

    /// Editable files that differ but cannot be merged line by line, each with the reason and the
    /// two sides as they were read. The operator still answers these; they just answer the whole
    /// file rather than the lines in it.
    pub fn unmergeable(&self) -> impl Iterator<Item = (&ResourceRelativePath, &TwoWayWholeFile)> {
        self.unmergeable.iter().map(|(path, whole)| (path, whole))
    }

    /// How many of them there are, without walking the sides.
    pub fn unmergeable_count(&self) -> usize {
        self.unmergeable.len()
    }

    /// The version the installation declares, if its manifest declares exactly one.
    pub fn installed_version(&self) -> Option<&str> {
        self.installed_version.as_deref()
    }

    /// The version the incoming package declares, on the same terms.
    pub fn incoming_version(&self) -> Option<&str> {
        self.incoming_version.as_deref()
    }
}

/// What a two-way apply reports back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayApplyOutcome {
    outcome: &'static str,
    plan: TwoWayUpdatePlan,
    installed_version: Option<String>,
    incoming_version: Option<String>,
    installed_resource_path: Option<String>,
    transaction_id: Option<Sha256Digest>,
    baseline_id: Option<BaselineId>,
    previous_baseline_id: Option<BaselineId>,
    written_files: Vec<TwoWayWrittenFile>,
}

/// Exact file states from the executed apply plan, including synthesized merge output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayWrittenFile {
    path: ResourceRelativePath,
    before: Option<Sha256Digest>,
    after: Sha256Digest,
}

impl TwoWayWrittenFile {
    pub fn path(&self) -> &ResourceRelativePath {
        &self.path
    }
    pub fn before(&self) -> Option<&Sha256Digest> {
        self.before.as_ref()
    }
    pub fn after(&self) -> &Sha256Digest {
        &self.after
    }
}

impl TwoWayApplyOutcome {
    /// Files actually installed or replaced; empty unless the transaction committed.
    pub fn written_files(&self) -> &[TwoWayWrittenFile] {
        &self.written_files
    }
    /// `already_up_to_date`, `committed`, `rolled_back`, or a recovery outcome.
    pub fn outcome(&self) -> &'static str {
        self.outcome
    }

    pub fn plan(&self) -> &TwoWayUpdatePlan {
        &self.plan
    }

    /// Official incoming baseline retained by a committed managed-workspace update.
    ///
    /// After an update the package that was applied is what the installation corresponds to, and
    /// keeping it is what lets the next update tell the operator's edits from the developer's
    /// without asking them to have held on to a ZIP. `None` for a no-op, unsuccessful
    /// transaction, or execution without a managed workspace. Capture failure in a
    /// managed workspace aborts before authority publication or live mutation.
    pub fn baseline_id(&self) -> Option<&BaselineId> {
        self.baseline_id.as_ref()
    }

    /// What the installation was installed from *before* this update.
    ///
    /// Undoing puts the installation back to what it was, and what it was installed from is part
    /// of what it was. This update was told that answer — as a package the operator named, or as
    /// one already in the store — so a caller that puts the update back can put the answer back
    /// with it instead of leaving the next update to ask for a ZIP again. `None` where this was
    /// never told, for an unsuccessful/no-op transaction, or without a workspace.
    pub fn previous_baseline_id(&self) -> Option<&BaselineId> {
        self.previous_baseline_id.as_ref()
    }

    /// What this apply is on record as, when it wrote anything.
    ///
    /// A transaction on record is evidence that an apply is in effect, and that is what makes the
    /// same apply from the same starting state a repeat rather than new work. A caller who puts
    /// the update back needs this to say which record went with it.
    pub fn transaction_id(&self) -> Option<&Sha256Digest> {
        self.transaction_id.as_ref()
    }

    /// Where the resource sits inside the installation the caller named, or `None` when the
    /// installation root is itself the resource.
    ///
    /// Both are ordinary: an operator points at a resources folder, or at the one resource in it.
    /// A caller that has to find these files again — to put the update back, say — cannot tell
    /// the two apart from the resource's name, because a resource is not obliged to be in a
    /// directory called after it.
    pub fn installed_resource_path(&self) -> Option<&str> {
        self.installed_resource_path.as_deref()
    }

    /// The version the installation declared before this update.
    pub fn installed_version(&self) -> Option<&str> {
        self.installed_version.as_deref()
    }

    /// The version the package declared.
    pub fn incoming_version(&self) -> Option<&str> {
        self.incoming_version.as_deref()
    }
}

/// Re-encode merged lines using the operator's own file conventions.
///
/// The result replaces their file, so it keeps their newline style, byte-order mark, and trailing
/// newline rather than adopting the package's. A file whose line endings are mixed or unsupported
/// is refused: rewriting it would silently normalise bytes the operator never asked to change.
fn encode_merged_file(
    lines: &[TwoWayMergedLine],
    encoding: MergeContentEncoding,
    newline: MergeNewlineStyle,
    terminal_newline: bool,
) -> Result<Vec<u8>> {
    // Byte values rather than escapes so the separator cannot be mangled by the source file
    // encoding: 10 is LF, 13 is CR.
    let separator: &[u8] = match newline {
        MergeNewlineStyle::Lf => &[10u8][..],
        MergeNewlineStyle::CrLf => &[13u8, 10u8][..],
        MergeNewlineStyle::Cr => &[13u8][..],
        MergeNewlineStyle::None => &[][..],
        MergeNewlineStyle::Mixed => return Err(GkrmError::TwoWayPlanInvariant),
    };
    let mut out = Vec::new();
    if encoding == MergeContentEncoding::Utf8WithBom {
        out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    } else if encoding != MergeContentEncoding::Utf8 {
        return Err(GkrmError::TwoWayPlanInvariant);
    }
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(separator);
        }
        out.extend_from_slice(line.bytes());
    }
    if terminal_newline && !lines.is_empty() {
        out.extend_from_slice(separator);
    }
    Ok(out)
}

/// The `version` each side's manifest declares, for the operator to see what they are moving to.
///
/// The manifest is read, never executed. A version that cannot be read — no manifest entry, a
/// manifest that does not parse, or one declaring several versions — is reported as absent rather
/// than guessed: a wrong version label is worse than none.
fn declared_installed_version(
    plan: &TwoWayUpdatePlan,
    installed: &InstalledMergeContentSource,
) -> Option<String> {
    let entry = plan
        .entries()
        .iter()
        .find(|entry| entry.path().as_str() == "fxmanifest.lua")?;
    let digest = entry.installed_digest()?;
    let max_retain = ThreeWayMergedBytesOptions::default().max_source_bytes_per_file();
    let bytes = installed
        .read_verified_merge_text(entry.path(), *digest, max_retain, |_| Ok(()))
        .ok()?
        .into_parts()
        .1?;
    let source = String::from_utf8(bytes).ok()?;
    let (manifest, _) = crate::parse_resource_manifest_source(
        "fxmanifest.lua",
        source,
        crate::ManifestLimits::default(),
    )
    .ok()?;
    crate::declared_manifest_version(&manifest).map(str::to_owned)
}

/// The version the incoming package declares, taken from the manifest parsed during inspection.
///
/// The package's own manifest is escrow-protected content, so it is never retained for reading
/// the way an editable file is. Inspection already parsed it to learn which paths the developer
/// left outside escrow, and that same parse carries the version.
fn declared_incoming_version(
    report: &crate::FullInspectionReport,
    incoming_root: &crate::ZipResourceRoot,
) -> Option<String> {
    report
        .manifests()
        .resources
        .iter()
        .find(|parsed| &parsed.resource_root == incoming_root)
        .and_then(|parsed| crate::declared_manifest_version(&parsed.manifest))
        .map(str::to_owned)
}

/// What the installation was installed from before this update, as an apply can still keep it.
///
/// An update that finishes is undoable, and undoing means putting back what was there — including
/// what this knew the installation corresponded to. That answer is in hand at plan time and gone
/// by the time anyone asks for it again, so it is carried through to the apply.
#[derive(Debug, Clone)]
enum PriorBaseline {
    /// A package the operator pointed at. Not in the store yet, so keeping it means capturing it.
    Package {
        path: std::path::PathBuf,
        /// Where the resource sits inside that package, which is not obliged to match the one in
        /// the update's own package.
        root: ZipResourceRoot,
        fingerprint: Sha256Digest,
    },
    /// One already in the store, which needs nothing kept.
    Stored(Box<crate::baseline::StoredBaseline>),
}

/// Everything both the preview and the apply need before they diverge.
struct PreparedTwoWay {
    bound_sources: super::BoundTrustedUpdateSources,
    selected: super::resource::SelectedPackageResource,
    plan: TwoWayUpdatePlan,
    /// The baseline's own JSON, by path, for documents a line merge cannot combine.
    baseline_documents: BTreeMap<ResourceRelativePath, Vec<u8>>,
    txn_root: TrustedTransactionRoot,
    /// Read from the sealed package's manifest during inspection, before anything is written.
    incoming_version: Option<String>,
    /// What the installation was installed from before this, for an undo to put back.
    prior_baseline: Option<PriorBaseline>,
}

/// Seal the sources, select the resource, refuse to proceed past unresolved recovery, and plan.
///
/// This is the three-way preamble verbatim minus the baseline resolution: sources are sealed and
/// re-inspected from the sealed copy, the sealed installed snapshot is checked against the
/// commitment that was accepted, and durable evidence for the resource still blocks new work.
fn prepare_two_way(
    package: &Path,
    installed: &Path,
    baseline: Option<TwoWayBaselineSource<'_>>,
    resource: Option<&SafeResourceKey>,
    transaction_root: &Path,
    workspace: Option<&TrustedUpdateWorkspace>,
    raw_options: TrustedCliUpdateOptions,
) -> Result<PreparedTwoWay> {
    let options = raw_options.validate()?;
    let initial_report =
        inspect_installation_update(installed, package, InspectionOptions::default())?;
    let initial_selected = resolve_selected_resource(&initial_report, resource)?;
    let accepted = source_commitments_from_report(&initial_report, &initial_selected)?;
    let bound_sources = prepare_bound_trusted_update_sources(
        installed,
        package,
        &initial_selected,
        &accepted,
        raw_options,
    )?;
    let report = inspect_installation_update_from_package_snapshot(
        bound_sources.installed_root(),
        bound_sources.incoming_package.as_ref(),
        InspectionOptions::default(),
    )?;
    let selected = resolve_selected_resource(&report, resource)?;
    verify_sealed_installed_snapshot_commitment(
        bound_sources.installed_root(),
        &selected,
        &accepted,
    )?;

    let txn_root = match workspace {
        Some(workspace) => TrustedTransactionRoot::try_open_in_workspace(workspace)?,
        None => TrustedTransactionRoot::try_open(transaction_root)?,
    };
    if same_resource_recovery_blocks_new_work(
        &txn_root,
        &selected.resource_key,
        options.max_journal_records,
    )? {
        return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
    }

    let (installed_snap, incoming_snap) = snapshots_for_selection(&report, &selected)?;
    let baseline = match baseline {
        Some(source) => Some(read_two_way_baseline(
            installed,
            source,
            &selected.resource_key,
        )?),
        None => None,
    };
    let plan = create_two_way_update_plan(
        &installed_snap,
        &incoming_snap,
        baseline.as_ref().map(|(baseline, _, _)| baseline),
    )?;
    let context = match workspace {
        Some(workspace) => {
            let source = InstalledApplyPlanningSource::try_new(
                installed,
                selected.installed_root.clone(),
                crate::InstalledScanLimits::default(),
            )?;
            crate::trusted_package_free_update_recovery::trusted_two_way_causal_head(
                workspace,
                &source,
                &selected.resource_key,
            )?
        }
        None => None,
    };
    let plan = plan.with_causal_context(context)?;
    // Now that the plan says which files are questions, read what the baseline held of those and
    // of nothing else. The package is already open.
    let baseline_documents = match &baseline {
        Some((_, source, _)) => {
            let wanted: BTreeSet<ResourceRelativePath> = plan
                .entries()
                .iter()
                .filter(|entry| entry.action() == TwoWayFileAction::Review)
                .map(|entry| entry.path().clone())
                .collect();
            source.documents(&wanted)
        }
        None => BTreeMap::new(),
    };
    let incoming_version = declared_incoming_version(&report, &selected.incoming_root);
    let prior_baseline = baseline.map(|(_, _, prior)| prior);

    Ok(PreparedTwoWay {
        bound_sources,
        selected,
        plan,
        baseline_documents,
        txn_root,
        incoming_version,
        prior_baseline,
    })
}

/// What the operator installed from: the digests it holds, and a reader for its own bytes.
///
/// The package is opened once. Sealing a fifty-megabyte zip and walking the installation against
/// it is the expensive part of an update, and doing it twice — once for the digests the plan needs
/// and again for the documents the merge needs — is doing the whole of it for nothing. The reader
/// keeps the sealed copy, so the second pass is a read rather than an inspection.
///
/// A package that does not carry the resource being updated is refused rather than quietly
/// ignored: a baseline for the wrong resource would answer "the operator has not touched this" for
/// every file in the update.
enum BaselineSource {
    /// A package the operator pointed at, sealed and open for reading.
    Package {
        source: IncomingMergeContentSource,
        digests: Vec<(ResourceRelativePath, Sha256Digest)>,
    },
    /// One this kept, loaded and validated from the store.
    Stored(Box<crate::StoredBaseline>),
}

impl BaselineSource {
    /// The baseline's own bytes for the files a plan asks the operator about.
    ///
    /// Read after the plan rather than before it, so the ceiling is spent on the handful of files
    /// that can use it instead of on every file in the package. Every read is checked against the
    /// digest the inspection recorded, so nothing here is taken on trust twice.
    fn documents(
        &self,
        wanted: &BTreeSet<ResourceRelativePath>,
    ) -> BTreeMap<ResourceRelativePath, Vec<u8>> {
        // What the baseline keeps of one file, and of all of them together. It lives as long as
        // the preview does.
        const MAX_BASELINE_DOCUMENT_BYTES: u64 = 1024 * 1024;
        const MAX_BASELINE_DOCUMENT_TOTAL: usize = 16 * 1024 * 1024;

        let mut documents = BTreeMap::new();
        let mut budget = MAX_BASELINE_DOCUMENT_TOTAL;
        match self {
            Self::Package { source, digests } => {
                for (path, digest) in digests {
                    if !wanted.contains(path) {
                        continue;
                    }
                    let Ok(text) = source.read_verified_merge_text(
                        path,
                        *digest,
                        MAX_BASELINE_DOCUMENT_BYTES,
                        |_| Ok(()),
                    ) else {
                        // Escrow-protected, or past the ceiling. Neither is a failure of the
                        // update: the file is then combined as it was before any of this existed.
                        continue;
                    };
                    let (_, bytes) = text.into_parts();
                    let Some(bytes) = bytes else { continue };
                    if bytes.len() > budget {
                        // Past the ceiling for this one. The next may still fit, and stopping here
                        // would decide which files can be combined by where their names fall.
                        continue;
                    }
                    budget = budget.saturating_sub(bytes.len());
                    documents.insert(path.clone(), bytes);
                }
            }
            Self::Stored(stored) => {
                for path in wanted {
                    let mut bytes = Vec::new();
                    let read = crate::baseline::store::stream_verified_blob_for_path(
                        stored,
                        path,
                        &BaselineStoreLimits::default(),
                        |chunk| {
                            if bytes.len().saturating_add(chunk.len())
                                > MAX_BASELINE_DOCUMENT_BYTES as usize
                            {
                                return Err(GkrmError::BaselineMissingBlob {
                                    digest: "larger than this will hold to compare".to_owned(),
                                });
                            }
                            bytes.extend_from_slice(chunk);
                            Ok(())
                        },
                    );
                    // Escrow-protected content has no blob, and a file past the ceiling is not one
                    // to hold. Neither is a failure of the update.
                    if read.is_err() || bytes.len() > budget {
                        continue;
                    }
                    budget = budget.saturating_sub(bytes.len());
                    documents.insert(path.clone(), bytes);
                }
            }
        }
        documents
    }
}

fn read_two_way_baseline(
    installed: &Path,
    source: TwoWayBaselineSource<'_>,
    resource_key: &SafeResourceKey,
) -> Result<(TwoWayBaseline, BaselineSource, PriorBaseline)> {
    let baseline_package = match source {
        TwoWayBaselineSource::Package(path) => path,
        TwoWayBaselineSource::Stored {
            store_root,
            baseline_id,
        } => {
            let (baseline, source) =
                read_stored_two_way_baseline(store_root, baseline_id, resource_key)?;
            let BaselineSource::Stored(stored) = &source else {
                return Err(GkrmError::TrustedCliUpdateBindingMismatch);
            };
            let prior = PriorBaseline::Stored(stored.clone());
            return Ok((baseline, source, prior));
        }
    };
    let snapshot = std::sync::Arc::new(crate::package_source::PackageSnapshot::create(
        baseline_package,
        IncomingMergeContentSourceLimits::default().max_archive_size,
    )?);
    let report = inspect_installation_update_from_package_snapshot(
        installed,
        snapshot.as_ref(),
        InspectionOptions::default(),
    )?;
    let selected = resolve_selected_resource(&report, Some(resource_key))?;
    if &selected.resource_key != resource_key {
        return Err(GkrmError::TwoWayBaselineResourceMismatch);
    }
    let (_, baseline_snap) = snapshots_for_selection(&report, &selected)?;
    let digests: Vec<(ResourceRelativePath, Sha256Digest)> = baseline_snap
        .incoming_file_states()
        .map(|(path, digest, _)| (path.clone(), *digest))
        .collect();
    let fingerprint = *snapshot.fingerprint();
    let source = IncomingMergeContentSource::from_package_snapshot(
        snapshot,
        selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;
    Ok((
        TwoWayBaseline::new(digests.clone()),
        BaselineSource::Package { source, digests },
        PriorBaseline::Package {
            path: baseline_package.to_path_buf(),
            root: selected.incoming_root.clone(),
            fingerprint,
        },
    ))
}

/// Keep a package in the store as a baseline, by the identity the store gives it.
///
/// Two packages are worth keeping when an update commits: the one it applied, which is what the
/// installation now corresponds to, and the one it was told the installation came from, which is
/// what it will correspond to again if the update is put back.
///
/// Capture before authority publication or live mutation, against the exact
/// package commitment used for planning. A changed path never supplies metadata.
fn keep_package_as_baseline(
    installed: &Path,
    package: &Path,
    resource_key: &SafeResourceKey,
    package_root: &ZipResourceRoot,
    workspace: &TrustedUpdateWorkspace,
    fingerprint: Sha256Digest,
) -> Result<BaselineId> {
    // The one resource this update was about, named the way the store names one. A package that
    // ships several — a phone, a tablet, a sound pack — cannot be captured by "the single one".
    let manifest = match package_root {
        ZipResourceRoot::Root => "fxmanifest.lua".to_owned(),
        ZipResourceRoot::Path(path) => format!("{}/fxmanifest.lua", path.as_str()),
    };
    let selector = crate::baseline::IncomingResourceSelector::ManifestPackagePath(
        ZipRelativePath::parse_canonical(&manifest)?,
    );
    let request = crate::baseline::ExpectedPackageBaselineCaptureRequest::try_new(
        installed,
        package,
        crate::PackageSourceCommitment::from_package_fingerprint(fingerprint),
        resource_key.clone(),
        selector,
        crate::baseline::BaselineCaptureOptions::default(),
    )?;
    crate::baseline::capture_official_baseline_in_workspace_with_expected_package_commitment(
        workspace,
        request,
        crate::TrustedUpdateWorkspaceOptions::default(),
    )
    .map(|result| result.baseline_id().clone())
}

/// The same, from a baseline this kept the last time it updated this installation.
///
/// The store holds what the package held, verified against the digests recorded when it was
/// captured, so an operator who has since deleted the ZIP is no worse off than one who kept it.
fn read_stored_two_way_baseline(
    store_root: &Path,
    baseline_id: &BaselineId,
    resource_key: &SafeResourceKey,
) -> Result<(TwoWayBaseline, BaselineSource)> {
    let resolved = crate::baseline::resolve_official_baseline(BaselineResolutionRequest::try_new(
        store_root,
        resource_key,
        OfficialBaselineSelector::Exact(baseline_id.clone()),
        BaselineResolutionOptions::default(),
    )?)?;
    let stored = resolved.stored_baseline().clone();
    if stored.resource_key() != resource_key {
        return Err(GkrmError::TwoWayBaselineResourceMismatch);
    }
    let digests: Vec<(ResourceRelativePath, Sha256Digest)> = stored
        .files()
        .iter()
        .map(|file| (file.relative_path().clone(), *file.sha256()))
        .collect();
    Ok((
        TwoWayBaseline::new(digests),
        BaselineSource::Stored(Box::new(stored)),
    ))
}

/// Whether this path names a JSON document, by the only thing available to say so.
fn has_json_name(path: &ResourceRelativePath) -> bool {
    path.as_str()
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("json"))
}

/// One merged file plus the conventions it must be written back with.
struct SplitFile {
    segments: Vec<TwoWaySegment>,
    encoding: MergeContentEncoding,
    newline: MergeNewlineStyle,
    terminal_newline: bool,
    /// One flag per change block: true where the operator's side of it is exactly what they
    /// installed, so nothing there is theirs to preserve. Empty where there was no baseline to
    /// judge by, which is the same as knowing nothing.
    untouched: Vec<bool>,
}

/// Split one reviewed file into change blocks, or report that it cannot be combined line by line.
/// Why one reviewed file has no line view, and the two sides as they were read.
///
/// The reason is not decoration: "this is an image" and "these two are too far apart to line up"
/// are different facts about a file, and telling an operator the first about the second is telling
/// them something untrue about their own JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwoWayWholeFile {
    reason: TwoWayUnmergeableReason,
    installed: Option<Vec<u8>>,
    incoming: Option<Vec<u8>>,
    merged: Option<Vec<u8>>,
    kept: Vec<String>,
    takes_update: bool,
}

impl TwoWayWholeFile {
    pub fn reason(&self) -> TwoWayUnmergeableReason {
        self.reason
    }

    /// The operator's copy, when it was small enough to keep.
    pub fn installed(&self) -> Option<&[u8]> {
        self.installed.as_deref()
    }

    /// The update's copy, on the same terms.
    pub fn incoming(&self) -> Option<&[u8]> {
        self.incoming.as_deref()
    }

    /// The two combined by key rather than by line, when they are documents and that worked.
    ///
    /// This is the update's own file with the values the operator changed put back into it. Where
    /// it is present the file is not really answered whole: leaving it alone takes this, and
    /// handing it over takes the update's version untouched.
    pub fn merged(&self) -> Option<&[u8]> {
        self.merged.as_deref()
    }

    /// The keys whose values came from the operator's file.
    ///
    /// A merge nobody can see is a merge nobody agreed to, and these two documents have no diff to
    /// show: every line of one differs from every line of the other, which is why they were
    /// combined by key in the first place. This is what actually happened to the file, in the
    /// terms it happened in.
    pub fn kept_keys(&self) -> &[String] {
        &self.kept
    }

    /// True when this document holds nothing of the operator's, so the update's is simply theirs.
    ///
    /// It reads as a file that could not be combined and is in fact one that did not need to be.
    /// Keeping it because the lines would not line up would cost them every string the update
    /// added, to protect an edit they never made.
    pub fn takes_update(&self) -> bool {
        self.takes_update
    }
}

/// Why a reviewed file cannot be combined line by line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoWayUnmergeableReason {
    /// Not text this can read: an image, an archive, an encoding it will not rewrite.
    NotText,
    /// Text on both sides, but too far apart to line up within the bounds this works to.
    TooFarApart,
    /// One side or the other is larger than this will hold in memory to compare.
    TooLarge,
}

enum ReviewedFile {
    Split(Box<SplitFile>),
    WholeFile(Box<TwoWayWholeFile>),
}

fn split_reviewed_file(
    entry: &crate::TwoWayPlanEntry,
    installed_merge: &InstalledMergeContentSource,
    incoming_merge: &IncomingMergeContentSource,
    baseline_document: Option<&[u8]>,
) -> Result<ReviewedFile> {
    let (Some(installed_digest), Some(incoming_digest)) =
        (entry.installed_digest(), entry.incoming_digest())
    else {
        return Err(GkrmError::TwoWayPlanInvariant);
    };
    // A two-way merge reads the same two files a three-way merge would, so it is bounded by the
    // same per-file source ceiling.
    let max_retain = ThreeWayMergedBytesOptions::default().max_source_bytes_per_file();

    let installed_text = installed_merge.read_verified_merge_text(
        entry.path(),
        *installed_digest,
        max_retain,
        |_| Ok(()),
    )?;
    let incoming_text = incoming_merge.read_verified_merge_text(
        entry.path(),
        *incoming_digest,
        max_retain,
        |_| Ok(()),
    )?;
    let (installed_meta, installed_bytes) = installed_text.into_parts();
    let (incoming_meta, incoming_bytes) = incoming_text.into_parts();

    // Where a line merge cannot combine two documents, their keys still can. It needs the version
    // the operator installed to tell their value from the developer's, which is the one thing two
    // sides never say.
    let whole = |reason, installed: Option<Vec<u8>>, incoming: Option<Vec<u8>>| {
        let combined = match (baseline_document, installed.as_deref(), incoming.as_deref()) {
            (Some(baseline), Some(mine), Some(theirs)) if has_json_name(entry.path()) => {
                crate::json_merge::merge_json_documents(baseline, mine, theirs)?
            }
            _ => None,
        };
        // A merge that kept nothing of theirs IS the update's document, and saying so is the
        // answer: they changed nothing in this file, so there is nothing of theirs to weigh
        // against five hundred new strings.
        let (merged, kept, takes_update) = match combined {
            Some(combined) if combined.kept.is_empty() => (None, Vec::new(), true),
            Some(combined) => (Some(combined.bytes), combined.kept, false),
            None => (None, Vec::new(), false),
        };
        Ok(ReviewedFile::WholeFile(Box::new(TwoWayWholeFile {
            reason,
            installed,
            incoming,
            merged,
            kept,
            takes_update,
        })))
    };

    let (Some(installed_bytes), Some(incoming_bytes)) = (installed_bytes, incoming_bytes) else {
        // Bytes are retained up to a ceiling. Past it there is nothing here to compare or to show.
        return whole(TwoWayUnmergeableReason::TooLarge, None, None);
    };
    let (Ok((installed_lines, _, installed_terminal)), Ok((incoming_lines, _, _))) = (
        split_logical_lines(
            &installed_bytes,
            installed_meta.encoding(),
            installed_meta.newline_style(),
        ),
        split_logical_lines(
            &incoming_bytes,
            incoming_meta.encoding(),
            incoming_meta.newline_style(),
        ),
    ) else {
        return whole(
            TwoWayUnmergeableReason::NotText,
            Some(installed_bytes),
            Some(incoming_bytes),
        );
    };

    match split_two_way(
        &installed_lines,
        &incoming_lines,
        TwoWayMergeOptions::default(),
    )? {
        Some(segments) => {
            // Which of those blocks hold anything the operator wrote. Without this, a file they
            // edited counts as theirs whole, and every fix the developer made to the rest of it
            // is dropped on their behalf.
            let untouched = match baseline_document.and_then(|baseline| {
                split_logical_lines(
                    baseline,
                    installed_meta.encoding(),
                    installed_meta.newline_style(),
                )
                .ok()
                .or_else(|| {
                    // The baseline may be laid out differently from what they have now; read it
                    // on its own terms before giving up on it.
                    let newline = if baseline.windows(2).any(|pair| pair == b"\r\n") {
                        MergeNewlineStyle::CrLf
                    } else if baseline.contains(&b'\n') {
                        MergeNewlineStyle::Lf
                    } else {
                        MergeNewlineStyle::None
                    };
                    split_logical_lines(baseline, MergeContentEncoding::Utf8, newline).ok()
                })
            }) {
                Some((baseline_lines, _, _)) => untouched_blocks(
                    &baseline_lines,
                    &installed_lines,
                    &segments,
                    TwoWayMergeOptions::default(),
                )?
                .unwrap_or_default(),
                None => Vec::new(),
            };
            Ok(ReviewedFile::Split(Box::new(SplitFile {
                segments,
                encoding: installed_meta.encoding(),
                newline: installed_meta.newline_style(),
                terminal_newline: installed_terminal,
                untouched,
            })))
        }
        None => whole(
            TwoWayUnmergeableReason::TooFarApart,
            Some(installed_bytes),
            Some(incoming_bytes),
        ),
    }
}

fn merge_mode(mode: TwoWayUpdateMode) -> TwoWayMergeMode {
    match mode {
        TwoWayUpdateMode::PreserveLocalEdits => TwoWayMergeMode::PreserveLocalEdits,
        TwoWayUpdateMode::ReplaceWithIncoming => TwoWayMergeMode::ReplaceWithIncoming,
    }
}

fn transaction_outcome(result: &TrustedTransactionResult) -> &'static str {
    match result {
        TrustedTransactionResult::Committed(_) => "committed",
        TrustedTransactionResult::RolledBack(_) => "rolled_back",
        TrustedTransactionResult::RecoveryRequired(_) => "recovery_required",
    }
}

/// Plan and merge an update using only the installation and the incoming package.
pub fn preview_two_way_update(request: TwoWayUpdateRequest<'_>) -> Result<TwoWayUpdatePreview> {
    let prepared = prepare_two_way(
        request.package,
        request.installed,
        request.baseline,
        request.resource,
        request.transaction_root,
        request.workspace,
        request.options,
    )?;
    let installed_merge = InstalledMergeContentSource::try_new(
        prepared.bound_sources.installed_root(),
        prepared.selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_merge = IncomingMergeContentSource::from_package_snapshot(
        prepared.bound_sources.incoming_package(),
        prepared.selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;

    // What the preview keeps of a file it cannot combine, so the screen has something to show in
    // place of a diff. A side larger than this is not shown, and once the whole preview has kept
    // this much it keeps no more: a preview is held for as long as the operator is looking at it,
    // and a resource full of wallpapers must not be held in memory whole.
    const MAX_WHOLE_FILE_SIDE_BYTES: usize = 1024 * 1024;
    const MAX_WHOLE_FILE_TOTAL_BYTES: usize = 24 * 1024 * 1024;
    let mut whole_file_budget = MAX_WHOLE_FILE_TOTAL_BYTES;
    // The same ceiling over the files that DO have a line view. Each of them holds both sides in
    // its segments and the merge beside them, and a package is allowed twenty thousand files: a
    // per-file limit alone lets a legal resource of large documents run to gigabytes. Past this,
    // a file is answered whole rather than line by line — a smaller answer, not a wrong one.
    const MAX_REVIEWED_TOTAL_BYTES: usize = 64 * 1024 * 1024;
    let mut reviewed_budget = MAX_REVIEWED_TOTAL_BYTES;

    let mut reviewed = Vec::new();
    let mut unmergeable = Vec::new();
    for entry in prepared.plan.entries() {
        if entry.action() != TwoWayFileAction::Review {
            continue;
        }
        match split_reviewed_file(
            entry,
            &installed_merge,
            &incoming_merge,
            prepared
                .baseline_documents
                .get(entry.path())
                .map(Vec::as_slice),
        )? {
            ReviewedFile::Split(file) => {
                let held: usize = file
                    .segments
                    .iter()
                    .map(|segment| match segment {
                        TwoWaySegment::Unchanged(lines) => {
                            lines.iter().map(Vec::len).sum::<usize>()
                        }
                        TwoWaySegment::Change(block) => block
                            .installed()
                            .iter()
                            .chain(block.incoming().iter())
                            .map(Vec::len)
                            .sum::<usize>(),
                    })
                    .sum();
                if held > reviewed_budget {
                    unmergeable.push((
                        entry.path().clone(),
                        TwoWayWholeFile {
                            reason: TwoWayUnmergeableReason::TooLarge,
                            installed: None,
                            incoming: None,
                            merged: None,
                            kept: Vec::new(),
                            takes_update: false,
                        },
                    ));
                    continue;
                }
                reviewed_budget = reviewed_budget.saturating_sub(held);
                let choices = default_choices_with_untouched(
                    &file.segments,
                    TwoWayMergeMode::PreserveLocalEdits,
                    &file.untouched,
                );
                reviewed.push(TwoWayReviewFile {
                    merged: resolve_two_way(&file.segments, &choices)?,
                    segments: file.segments,
                    path: entry.path().clone(),
                });
            }
            ReviewedFile::WholeFile(whole) => {
                let mut whole = *whole;
                let sides = || {
                    [
                        whole.installed.as_ref(),
                        whole.incoming.as_ref(),
                        whole.merged.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                };
                let held = sides().map(Vec::len).sum::<usize>();
                let too_large = sides().any(|side| side.len() > MAX_WHOLE_FILE_SIDE_BYTES);
                if too_large || held > whole_file_budget {
                    whole.installed = None;
                    whole.incoming = None;
                    // The merge itself is dropped too. What was kept is still named, so the screen
                    // says what happened even where it cannot hold the document it happened to.
                    whole.merged = None;
                } else {
                    whole_file_budget = whole_file_budget.saturating_sub(held);
                }
                unmergeable.push((entry.path().clone(), whole));
            }
        }
    }

    let installed_version = declared_installed_version(&prepared.plan, &installed_merge);
    let incoming_version = prepared.incoming_version.clone();

    Ok(TwoWayUpdatePreview {
        plan: prepared.plan,
        reviewed,
        unmergeable,
        installed_version,
        incoming_version,
    })
}

/// Marker digests standing in for records a two-way update genuinely does not have.
///
/// The artifact body has a field for each of these because a three-way update always has one. A
/// two-way update has no official baseline, no per-file review, and no decision document, and a
/// fabricated digest would put a claim in a durable record that nothing ever produced. Each marker
/// is instead a canonical, well-known value that says exactly which record is absent.
fn absent_record_marker(what: &str) -> Result<Sha256Digest> {
    let mut encoder = crate::three_way_fingerprint::CanonicalFingerprintEncoder::new(
        "gkrm-two-way-absent-record-v1",
    )
    .map_err(|_| GkrmError::TwoWayPlanIdEncodingFailure)?;
    encoder
        .string(what)
        .map_err(|_| GkrmError::TwoWayPlanIdEncodingFailure)?;
    Ok(encoder.finish())
}

/// Inputs for a two-way apply.
pub struct TwoWayApplyRequest<'a> {
    pub package: &'a Path,
    pub installed: &'a Path,
    /// What the operator installed from, as in [`TwoWayUpdateRequest`].
    ///
    /// The apply re-plans from the sources itself, so it must be given the same baseline the
    /// preview was, or it would ask a different set of questions than the operator answered.
    pub baseline: Option<TwoWayBaselineSource<'a>>,
    pub resource: Option<&'a SafeResourceKey>,
    pub staging_root: &'a Path,
    pub transaction_root: &'a Path,
    /// The preset for every reviewed file the operator did not decide individually.
    pub mode: TwoWayUpdateMode,
    /// Per-file, per-block decisions. A file listed here overrides the preset entirely.
    pub choices: &'a [TwoWayFileChoice<'a>],
    /// The identity of the plan the operator answered, when there was a preview.
    ///
    /// The apply re-plans from the live sources, which is what makes it safe; it also means the
    /// file the operator answered may not be the file about to be written. Matching by path and
    /// counting the blocks only catches a change that moves the count: revert one line and edit
    /// another and the count is the same while every decision has slid onto a different change.
    /// The plan's identity covers both sides byte for byte, so it catches all of it.
    pub expected_plan_id: Option<&'a Sha256Digest>,
    pub workspace: Option<&'a TrustedUpdateWorkspace>,
    pub options: TrustedCliUpdateOptions,
}

/// Apply an update planned from the installation and the package alone.
///
/// Every write, backup, journal record, and rollback is the transactional machinery the
/// three-way path uses. This only decides the candidate tree and hands it over.
pub fn apply_two_way_update(request: TwoWayApplyRequest<'_>) -> Result<TwoWayApplyOutcome> {
    let options = request.options.validate()?;
    let prepared = prepare_two_way(
        request.package,
        request.installed,
        request.baseline,
        request.resource,
        request.transaction_root,
        request.workspace,
        request.options,
    )?;

    // Merge every reviewed file up front, so nothing is written if any of them cannot be
    // produced. A partially mergeable update is refused rather than half applied.
    let installed_merge = InstalledMergeContentSource::try_new(
        prepared.bound_sources.installed_root(),
        prepared.selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_merge = IncomingMergeContentSource::from_package_snapshot(
        prepared.bound_sources.incoming_package(),
        prepared.selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;

    // The installation and the package must still be what the operator was shown. A plan is
    // identified by both sides and by what it would do to every file in them, so a difference of
    // any kind lands here rather than on their files.
    if let Some(expected) = request.expected_plan_id {
        if prepared.plan.plan_id().digest() != expected {
            return Err(GkrmError::TwoWayPlanChangedSincePreview);
        }
    }

    // Two decisions for one file cannot both be applied, and quietly taking the first would apply
    // one the operator may never have made.
    for (index, choice) in request.choices.iter().enumerate() {
        if request.choices[..index]
            .iter()
            .any(|earlier| earlier.path == choice.path)
        {
            return Err(GkrmError::TwoWayDuplicateFileChoice);
        }
    }

    // Every decision must name a file this update actually offers for review. Ignoring one would
    // silently drop a choice the operator made and believes they applied.
    for choice in request.choices {
        let reviewed =
            prepared.plan.entries().iter().any(|entry| {
                entry.action() == TwoWayFileAction::Review && entry.path() == choice.path
            });
        if !reviewed {
            return Err(GkrmError::TwoWayMergeChoiceCountMismatch);
        }
    }

    // Replacing wholesale with nothing decided by hand is served from the package's own bytes, so
    // the operator gets exactly what the developer shipped rather than a merge that happens to
    // take every line and then re-encodes it in their newline style.
    let merge_every_file =
        request.mode == TwoWayUpdateMode::PreserveLocalEdits || !request.choices.is_empty();

    let installed_version = declared_installed_version(&prepared.plan, &installed_merge);
    // Where these files are is not the resource's name: an operator can point at the resource
    // itself as readily as at the folder holding it, and only the selection knows which.
    let installed_resource_path = match &prepared.selected.installed_root {
        InstalledResourceRoot::Root => None,
        InstalledResourceRoot::Path(path) => Some(path.as_str().to_string()),
    };
    let incoming_version = prepared.incoming_version.clone();

    let mut merged_files = Vec::new();
    // Reviewed files that cannot be compared line by line: binary content, an encoding this
    // cannot rewrite, or two sides too far apart to diff within bounds. There is no per-line
    // decision to make for them, so the whole-file answer the operator gave is the decision, and
    // naming them keeps staging from having to guess which one that was.
    let mut keep_installed: Vec<ResourceRelativePath> = Vec::new();
    // The same files, answered the other way. A file with no lines to decide is decided whole, and
    // an empty decision list is how the operator says so.
    let mut take_incoming_whole: Vec<ResourceRelativePath> = Vec::new();
    if merge_every_file {
        for entry in prepared.plan.entries() {
            if entry.action() != TwoWayFileAction::Review {
                continue;
            }
            let reviewed = split_reviewed_file(
                entry,
                &installed_merge,
                &incoming_merge,
                prepared
                    .baseline_documents
                    .get(entry.path())
                    .map(Vec::as_slice),
            )?;
            let ReviewedFile::Split(split) = reviewed else {
                let ReviewedFile::WholeFile(whole) = reviewed else {
                    unreachable!("a reviewed file is one of the two")
                };
                match request
                    .choices
                    .iter()
                    .find(|choice| choice.path == entry.path())
                {
                    // This file has no lines to answer, so the answer is the whole of it.
                    Some(choice) if choice.take_from_update.is_empty() => {
                        take_incoming_whole.push(entry.path().clone());
                    }
                    // A decision made against lines this file does not offer is refused rather
                    // than quietly ignored.
                    Some(_) => return Err(GkrmError::TwoWayMergeChoiceCountMismatch),
                    None => match request.mode {
                        // Two documents a line merge could not combine, combined by key instead.
                        // The operator left it alone, and leaving it alone is what takes this.
                        TwoWayUpdateMode::PreserveLocalEdits => match whole.merged {
                            Some(bytes) => {
                                if bytes.is_empty() {
                                    return Err(GkrmError::JsonMergeResultInvalid);
                                }
                                let content_digest = Sha256Digest::new(
                                    <sha2::Sha256 as sha2::Digest>::digest(&bytes).into(),
                                );
                                merged_files.push((entry.path().clone(), content_digest, bytes));
                            }
                            // Combined, and nothing in it was theirs. The update's document is
                            // the answer rather than the file they have.
                            None if whole.takes_update => {
                                take_incoming_whole.push(entry.path().clone());
                            }
                            None => keep_installed.push(entry.path().clone()),
                        },
                        // Replacing wholesale already reaches this file through the mode itself.
                        TwoWayUpdateMode::ReplaceWithIncoming => {}
                    },
                }
                continue;
            };
            // A decision list that no longer matches the file is refused inside `resolve_two_way`,
            // so choices made against a preview of a file that has since changed cannot be applied
            // to lines the operator never saw.
            let choices = match request
                .choices
                .iter()
                .find(|choice| choice.path == entry.path())
            {
                Some(choice) => choice.take_from_update.to_vec(),
                // Replacing wholesale is served from the package's own bytes, and a file nobody
                // decided by hand must stay on that path: merging it here would take every line
                // and then write them back in the operator's newline style and encoding, which is
                // not what the developer shipped.
                None if request.mode == TwoWayUpdateMode::ReplaceWithIncoming => continue,
                None => default_choices_with_untouched(
                    &split.segments,
                    merge_mode(request.mode),
                    &split.untouched,
                ),
            };
            let merged = resolve_two_way(&split.segments, &choices)?;
            let bytes = encode_merged_file(
                &merged,
                split.encoding,
                split.newline,
                split.terminal_newline,
            )?;
            let content_digest =
                Sha256Digest::new(<sha2::Sha256 as sha2::Digest>::digest(&bytes).into());
            merged_files.push((entry.path().clone(), content_digest, bytes));
        }
    }
    let merges: Vec<TrustedStagingOperatorMergeInput<'_>> = merged_files
        .iter()
        .map(|(path, digest, bytes)| TrustedStagingOperatorMergeInput {
            path,
            // The merge is produced here, so its content digest is its identity.
            artifact_id: *digest,
            content_digest: *digest,
            bytes,
        })
        .collect();

    let installed_staging = InstalledStagingContentSource::try_new(
        prepared.bound_sources.installed_root(),
        prepared.selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_staging = IncomingStagingContentSource::from_package_snapshot(
        prepared.bound_sources.incoming_package(),
        prepared.selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;
    let staging_root = TrustedStagingRoot::try_open(request.staging_root)?;
    let bundle = stage_trusted_resource_two_way(TwoWayStagingRequest::try_new(
        &prepared.plan,
        request.mode,
        &installed_staging,
        &incoming_staging,
        &staging_root,
        &merges,
        &keep_installed,
        &take_incoming_whole,
        TrustedStagingOptions::default(),
    )?)?;

    let review_id = *bundle.manifest().review_id_digest();
    // Planning and applying target the live installation, not the sealed copy the plan was read
    // from: the sealed copy is a temporary directory that is deleted when this call returns.
    let installed_apply = InstalledApplyPlanningSource::try_new(
        request.installed,
        prepared.selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let apply_plan = plan_trusted_apply(TrustedApplyPlanningRequest::try_new_two_way(
        &bundle,
        &prepared.plan,
        review_id,
        &installed_apply,
        TrustedApplyPlanningOptions::default(),
    )?)?;
    // An installation that already matches the package has nothing to write. Opening a
    // transaction to record that would leave durable evidence of an event that did not happen —
    // and, repeated, evidence indistinguishable from the last time nothing happened, which is a
    // collision rather than a history.
    if apply_plan.status() == TrustedApplyStatus::NoFilesystemChanges {
        return Ok(TwoWayApplyOutcome {
            outcome: "already_up_to_date",
            plan: prepared.plan,
            installed_version,
            incoming_version,
            installed_resource_path,
            transaction_id: None,
            baseline_id: None,
            previous_baseline_id: None,
            written_files: Vec::new(),
        });
    }

    let tx_plan = plan_trusted_transactional_apply(
        TrustedTransactionalApplyPlanningRequest::try_new_two_way(
            &apply_plan,
            &bundle,
            &prepared.plan,
            review_id,
            &installed_apply,
            TrustedTransactionalApplyPlanningOptions::default(),
        )?,
    )?;

    let transaction_id = *tx_plan.plan_id().digest();

    // Asked before anything is written. A transaction is identified by the work it does and the
    // state it does it from, so this is the operator asking for something that has already
    // happened — and publishing the evidence that accounts for a transaction before finding out
    // it cannot be opened leaves the workspace holding evidence for a transaction that never ran,
    // which nothing can then resolve.
    if crate::trusted_transaction_is_on_record(&prepared.txn_root, &transaction_id)? {
        return Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists);
    }

    // Retain both official inputs before publishing authority. Capture reopens
    // paths only against the exact immutable package commitments used above.
    let baseline_transition = match request.workspace {
        Some(workspace) => {
            let after = keep_package_as_baseline(
                request.installed,
                request.package,
                &prepared.selected.resource_key,
                &prepared.selected.incoming_root,
                workspace,
                *prepared.plan.incoming_package_fingerprint(),
            )?;
            let before = match &prepared.prior_baseline {
                Some(PriorBaseline::Stored(stored)) => {
                    Some(crate::baseline::retain_stored_baseline_in_workspace(
                        workspace,
                        request.installed,
                        stored,
                    )?)
                }
                Some(PriorBaseline::Package {
                    path,
                    root,
                    fingerprint,
                }) => Some(keep_package_as_baseline(
                    request.installed,
                    path,
                    &prepared.selected.resource_key,
                    root,
                    workspace,
                    *fingerprint,
                )?),
                None => None,
            };
            Some(
                crate::two_way_plan::execution_descriptor::ManagedBaselineTransition::new(
                    before.as_ref(),
                    &after,
                ),
            )
        }
        None => None,
    };

    // Publish recovery authority for this transaction, so the workspace can account for it after
    // the fact. A transaction nobody can account for blocks every later update on the same
    // resource, and no one can close it.
    let authority = match request.workspace {
        Some(workspace) => Some(publish_two_way_recovery_authority(
            workspace,
            &prepared,
            &bundle,
            &apply_plan,
            &tx_plan,
            &installed_apply,
            baseline_transition
                .as_ref()
                .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?,
            options.max_artifact_bytes,
        )?),
        None => None,
    };

    // Re-read the published artifact from disk immediately before the transaction is armed, and
    // prove it still says what it said. A file that changed underneath is not authority for
    // anything, whoever changed it.
    let revalidate_artifact = || {
        let (publication, path) = authority
            .as_ref()
            .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
        let bytes = super::publish::read_regular_file_limited(path, options.max_artifact_bytes)?;
        let current = super::parse_cli_artifact(&bytes, &options)?;
        if current.version() != super::artifact::ARTIFACT_V2_FORMAT_VERSION
            || current.artifact_id().digest() != publication.artifact_id()
            || current.body().recovery_authority_id != Some(*publication.authority_id().digest())
            || current.apply_descriptor().is_some()
        {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        if let Some(workspace) = request.workspace {
            crate::trusted_package_free_update_recovery::validate_two_way_baseline_transition(
                workspace,
                current
                    .two_way_descriptor()
                    .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?,
            )?;
            let head = crate::trusted_package_free_update_recovery::trusted_two_way_causal_head(
                workspace,
                &installed_apply,
                prepared.plan.resource_key(),
            )?;
            if head.as_ref() != prepared.plan.causal_context() {
                return Err(GkrmError::TrustedCliUpdateBindingMismatch);
            }
        }
        Ok(RecoveryAuthorityPublication::new(
            publication.body().clone(),
            *publication.authority_id(),
            *publication.artifact_id(),
        ))
    };

    let execution = match authority.as_ref() {
        Some((publication, _)) => {
            TrustedTransactionalApplyExecutionRequest::try_new_two_way_with_recovery_authority(
                &tx_plan,
                &apply_plan,
                &bundle,
                &prepared.plan,
                review_id,
                &installed_apply,
                &prepared.txn_root,
                publication,
                &revalidate_artifact,
                TrustedTransactionalApplyExecutionOptions::default(),
            )?
        }
        None => TrustedTransactionalApplyExecutionRequest::try_new_two_way(
            &tx_plan,
            &apply_plan,
            &bundle,
            &prepared.plan,
            review_id,
            &installed_apply,
            &prepared.txn_root,
            TrustedTransactionalApplyExecutionOptions::default(),
        )?,
    };
    let result = execute_trusted_transactional_apply(execution)?;
    let written_files = if matches!(result, TrustedTransactionResult::Committed(_)) {
        apply_plan
            .operations()
            .iter()
            .filter_map(|operation| {
                use crate::TrustedApplyOperationKind;
                if !matches!(
                    operation.kind(),
                    TrustedApplyOperationKind::InstallFile | TrustedApplyOperationKind::ReplaceFile
                ) {
                    return None;
                }
                Some(TwoWayWrittenFile {
                    path: operation.destination().clone(),
                    before: operation.pre_state().digest_opt().copied(),
                    after: *operation.post_state().digest_opt()?,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let (baseline_id, previous_baseline_id) =
        if matches!(result, TrustedTransactionResult::Committed(_)) {
            match &baseline_transition {
                Some(transition) => (Some(transition.after()?), transition.before()?),
                None => (None, None),
            }
        } else {
            (None, None)
        };

    Ok(TwoWayApplyOutcome {
        outcome: transaction_outcome(&result),
        plan: prepared.plan,
        installed_version,
        incoming_version,
        installed_resource_path,
        transaction_id: Some(transaction_id),
        baseline_id,
        previous_baseline_id,
        written_files,
    })
}

/// Build and publish the recovery authority and artifact that account for a two-way transaction.
///
/// The artifact carries a distinct two-way descriptor family, including the exact plan and
/// staging review commitment. It never fabricates a three-way plan or baseline.
fn publish_two_way_recovery_authority(
    workspace: &TrustedUpdateWorkspace,
    prepared: &PreparedTwoWay,
    bundle: &crate::trusted_staging::TrustedStagingBundle,
    apply_plan: &crate::trusted_apply_planning::TrustedApplyPlan,
    tx_plan: &crate::trusted_transactional_apply_planning::TrustedTransactionalApplyPlan,
    installed_apply: &InstalledApplyPlanningSource,
    baseline_transition: &crate::two_way_plan::execution_descriptor::ManagedBaselineTransition,
    max_artifact_bytes: usize,
) -> Result<(RecoveryAuthorityPublication, std::path::PathBuf)> {
    let snapshot = installed_apply
        .capture_tree_snapshot(prepared.plan.resource_key())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let baseline_id = absent_record_marker("baseline")?;
    let (body, authority_id) = build_recovery_authority_body(
        installed_apply,
        prepared.plan.resource_key(),
        baseline_id,
        *bundle.manifest().manifest_id().digest(),
        *bundle.bundle_id().digest(),
        *apply_plan.plan_id().digest(),
        *tx_plan.plan_id().digest(),
        &snapshot,
        RecoveryAuthorityLimits::default(),
    )?;

    let artifact_body = TrustedCliUpdateArtifactBody {
        package_fingerprint: *prepared.plan.incoming_package_fingerprint(),
        selected_resource_commitment: body.selected_resource_commitment,
        baseline_id_digest: baseline_id,
        plan_id: *prepared.plan.plan_id().digest(),
        review_id: *bundle.manifest().review_id_digest(),
        analysis_id: None,
        text_diff_id: None,
        synthesis_id: None,
        merged_bytes_id: None,
        operator_merge_set_id: encode_operator_merge_set_id(&[])?,
        staging_manifest_id: *bundle.manifest().manifest_id().digest(),
        staging_bundle_id: *bundle.bundle_id().digest(),
        apply_plan_id: *apply_plan.plan_id().digest(),
        snapshot_a: snapshot.fingerprint,
        transactional_plan_id: *tx_plan.plan_id().digest(),
        recovery_authority_id: Some(*authority_id.digest()),
        decision_document_id: absent_record_marker("decision-document")?,
    };
    let descriptor =
        crate::two_way_plan::execution_descriptor::TwoWayExecutionDescriptor::from_plan(
            &prepared.plan,
            installed_apply.selected_resource_root(),
        )?
        .with_baseline_transition(baseline_transition.clone());
    let artifact = encode_cli_artifact_v2_with_two_way_descriptor(&artifact_body, &descriptor)?;
    let bytes = artifact.canonical_bytes();
    if bytes.len() > max_artifact_bytes {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        });
    }
    let _publication_lock = crate::acquire_trusted_update_workspace_publication_lock(workspace)?;
    crate::trusted_package_free_update_recovery::validate_two_way_baseline_transition(
        workspace,
        &descriptor,
    )?;
    let path = workspace.artifact_root().allocate_plan_artifact_path()?;
    publish_bytes_no_replace(&path, bytes)?;

    Ok((
        RecoveryAuthorityPublication::new(body, authority_id, *artifact.artifact_id().digest()),
        path,
    ))
}
