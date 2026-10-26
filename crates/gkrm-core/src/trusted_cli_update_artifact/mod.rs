//! Trusted CLI update orchestration (Milestone 2 Task 25).
//!
//! Security-sensitive sequencing lives here. `apps/gkrm-cli` is a thin adapter.

#![allow(clippy::too_many_arguments)]

mod artifact;
mod decisions;
mod id;
mod limits;
mod operator_merge;
mod publication_state;
mod publish;
pub(crate) use publish::rename_file_noreplace;
mod rebind;
mod resource;

#[cfg(test)]
mod hardening_tests;
#[cfg(test)]
mod workflow_tests;

mod two_way;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
pub use two_way::{
    apply_two_way_update, preview_two_way_update, TwoWayApplyOutcome, TwoWayApplyRequest,
    TwoWayBaselineSource, TwoWayFileChoice, TwoWayReviewFile, TwoWayUnmergeableReason,
    TwoWayUpdatePreview, TwoWayUpdateRequest, TwoWayWholeFile, TwoWayWrittenFile,
};

use cap_fs_ext::{DirEntryExt, MetadataExt};
use cap_std::fs::{Dir as CapDir, Metadata as CapMetadata};
use sha2::{Digest, Sha256};

use artifact::encode_cli_artifact_v2_with_apply_descriptor;
pub(crate) use artifact::ARTIFACT_V2_FORMAT_VERSION;
pub use artifact::{
    encode_cli_artifact, encode_cli_artifact_v2_with_undo_descriptor,
    encode_cli_artifact_with_apply_descriptor, parse_cli_artifact, TrustedCliApplyDescriptor,
    TrustedCliUpdateArtifact, TrustedCliUpdateArtifactBody, TrustedCliUpdateArtifactId,
};
pub use decisions::{
    build_decision_document, parse_decision_document, TrustedCliDecisionDocument,
    TrustedCliDecisionDocumentId, TrustedCliDecisionEntry,
};
pub use limits::TrustedCliUpdateOptions;
pub use operator_merge::{
    build_operator_merge_set, load_operator_merge_artifact, validate_and_load_operator_merge_root,
    TrustedOperatorMergeArtifact, TrustedOperatorMergeArtifactId, TrustedOperatorMergeSet,
};
pub use resource::{resolve_selected_resource, snapshots_for_selection, SelectedPackageResource};

use crate::package_source::PackageSnapshot;
use crate::trusted_apply_planning::{
    plan_trusted_apply, InstalledApplyPlanningSource, PackageFreeMergeChainIds,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest,
};
use crate::trusted_recovery_authority::{
    build_recovery_authority_body, reconstruct_recovery_derivation,
    verify_selected_resource_commitment, RecoveryAuthorityLimits, RecoveryAuthorityPublication,
    RecoveryDerivationRequestV1,
};
use crate::trusted_staging::{
    estimate_trusted_staging_publication, reopen_trusted_staging_bundle_from_artifact,
    stage_trusted_resource, verify_published_bundle_readonly, IncomingStagingContentSource,
    InstalledStagingContentSource, StagingSourceBinding, TrustedStagingOperatorMergeInput,
    TrustedStagingOptions, TrustedStagingRequest, TrustedStagingRoot,
};
use crate::trusted_transactional_apply_execution::recovery::same_resource_recovery_blocks_new_work;
use crate::trusted_transactional_apply_planning::{
    plan_trusted_transactional_apply, TrustedTransactionalApplyPlanningOptions,
    TrustedTransactionalApplyPlanningRequest,
};
use crate::{
    acquire_trusted_update_workspace_publication_lock,
    enforce_trusted_update_workspace_capacity_for_reservation, TrustedUpdateWorkspace,
    TrustedUpdateWorkspaceOptions, TrustedUpdateWorkspaceReservation,
};
use crate::{
    analyze_queued_three_way_merges, create_three_way_update_plan,
    execute_trusted_transactional_apply, inspect_installation_update,
    inspection::inspect_installation_update_from_package_snapshot, plan_three_way_merge_synthesis,
    plan_three_way_text_diffs, recover_trusted_transaction, resolve_official_baseline,
    review_three_way_update_plan, scan_installed_resources, scan_trusted_transactions,
    synthesize_three_way_merged_bytes, BaselineResolutionOptions, BaselineResolutionRequest,
    GkrmError, IncomingMergeContentSource, IncomingMergeContentSourceLimits, InspectionOptions,
    InstalledMergeContentSource, InstalledResourceRoot, InstalledScanLimits,
    OfficialBaselineSelector, Result, SafeResourceKey, Sha256Digest, ThreeWayMergeAnalysisOptions,
    ThreeWayMergeAnalysisRequest, ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisRequest,
    ThreeWayMergedBytesOptions, ThreeWayMergedBytesRequest, ThreeWayPlanReviewRequest,
    ThreeWayPlanReviewStatus, ThreeWayPlannerOptions, ThreeWayReviewedAction,
    ThreeWayTextDiffOptions, ThreeWayTextDiffRequest, ThreeWayUpdatePlanRequest,
    TrustedRecoveryCandidateId, TrustedRecoveryCandidateKind, TrustedRecoveryOptions,
    TrustedRecoveryResult, TrustedRecoveryScanOptions, TrustedTransactionRecoveryRequest,
    TrustedTransactionResult, TrustedTransactionRoot, TrustedTransactionalApplyExecutionOptions,
    TrustedTransactionalApplyExecutionRequest,
};

use self::id::encode_operator_merge_set_id;
use self::publish::ensure_output_disjoint;
pub(crate) use self::publish::{publish_bytes_no_replace, read_regular_file_limited};
use crate::baseline::fs_security::{
    capture_file_identity, create_new_child_dir, create_new_file, dir_identity, open_child_dir,
    open_existing_directory, open_file_nofollow, reject_link_like_metadata,
    validate_single_component, verify_regular_file,
};
use crate::file_identity::StableFileIdentity;

#[cfg(all(feature = "desktop-test-support", debug_assertions))]
pub(crate) fn make_unsupported_derivation_for_desktop_test(
    workspace: &TrustedUpdateWorkspace,
) -> Result<()> {
    fn only_path(root: &Path, directory: bool) -> Result<PathBuf> {
        let mut matches = std::fs::read_dir(root)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                if directory {
                    path.is_dir()
                } else {
                    path.is_file()
                }
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch);
        }
        Ok(matches.remove(0))
    }

    fn durable_digest(path: &Path) -> Result<Sha256Digest> {
        let bytes = std::fs::read(path)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        let digest = bytes
            .get(bytes.len().saturating_sub(32)..)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
        Ok(Sha256Digest::new(digest))
    }

    let transaction = only_path(&workspace.transaction_root().join("transactions"), true)?;
    let artifact_path = only_path(workspace.artifact_root().path(), false)?;
    let artifact = parse_cli_artifact(
        &std::fs::read(&artifact_path)
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
        &TrustedCliUpdateOptions::default(),
    )?;
    let descriptor = artifact
        .apply_descriptor()
        .ok_or(GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?
        .clone();
    let mut artifact_body = artifact.body().clone();
    let limits = RecoveryAuthorityLimits::default();
    let envelope = crate::parse_recovery_authority_envelope(
        &std::fs::read(transaction.join("recovery-authority.bin"))
            .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?,
        limits,
    )?;
    let mut authority_body = envelope.body().clone();
    authority_body.apply_derivation_version = 2;
    authority_body.transaction_derivation_version = 1;
    let authority_id =
        crate::trusted_recovery_authority::desktop_test_encode_recovery_authority_id(
            &authority_body,
            limits,
        )?;
    artifact_body.recovery_authority_id = Some(*authority_id.digest());
    let artifact =
        artifact::encode_cli_artifact_v2_with_apply_descriptor(&artifact_body, &descriptor)?;
    std::fs::write(&artifact_path, artifact.canonical_bytes())
        .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;

    let snapshot_a = durable_digest(&transaction.join("snapshot-a.bin"))?;
    let resource_lock = durable_digest(&transaction.join("resource-lock-id.bin"))?;
    let plan_id = *authority_body.transactional_plan_id();
    let publication = crate::trusted_recovery_authority::encode_publication_binding_id(
        artifact.artifact_id().digest(),
        &authority_id,
        &plan_id,
        &snapshot_a,
        &resource_lock,
    )?;
    let envelope = crate::RecoveryAuthorityEnvelopeV1::create(
        authority_body,
        authority_id,
        *artifact.artifact_id().digest(),
        publication,
        limits,
    )?;
    let mut envelope_bytes = Vec::new();
    crate::trusted_recovery_authority::write_recovery_authority_envelope(
        &envelope,
        &mut envelope_bytes,
        limits,
    )?;
    std::fs::write(transaction.join("recovery-authority.bin"), envelope_bytes)
        .map_err(|_| GkrmError::TrustedPackageFreeUpdateRecoveryBindingMismatch)?;
    crate::trusted_transactional_apply_execution::journal::reseal_v2_publication_binding_for_test(
        &transaction.join("journal"),
        &plan_id,
        &snapshot_a,
        *publication.digest(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedCliPlanOutcomeKind {
    PendingDecisions,
    ManualMergeRequired,
    ReadyToApply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedCliApplyOutcomeKind {
    Committed,
    RolledBack,
    RecoveryRequired,
    PublishedRecoveryUnsealed,
    PublishedRecoveryFailed,
    SafeFailureBeforePublication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedCliRecoverOutcomeKind {
    RecoveredCommitted,
    RecoveredRolledBack,
    SafeRestart,
    RecoveryStillRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCliReport {
    pub outcome: &'static str,
    pub pending_paths: Vec<String>,
    pub artifact_id_hex: Option<String>,
    pub candidate_selectors: Vec<String>,
    pub bound_candidates: usize,
    pub malformed_candidates: usize,
}

pub struct TrustedCliPlanRequest<'a> {
    pub package: &'a Path,
    pub installed: &'a Path,
    pub baseline_store: &'a Path,
    pub baseline_selector: OfficialBaselineSelector,
    pub resource: Option<&'a SafeResourceKey>,
    pub staging_root: &'a Path,
    pub transaction_root: &'a Path,
    pub decisions_path: Option<&'a Path>,
    pub decisions_out: Option<&'a Path>,
    pub operator_merge_root: Option<&'a Path>,
    pub artifact_out: &'a Path,
    pub workspace: Option<&'a TrustedUpdateWorkspace>,
    pub workspace_options: TrustedUpdateWorkspaceOptions,
    pub options: TrustedCliUpdateOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCliExpectedSourceCommitments {
    pub installed_resource: crate::InstalledResourceSourceCommitment,
    pub package: crate::PackageSourceCommitment,
}

pub struct TrustedCliApplyRequest<'a> {
    pub artifact: &'a Path,
    pub package: &'a Path,
    pub installed: &'a Path,
    pub baseline_store: &'a Path,
    pub baseline_selector: OfficialBaselineSelector,
    pub resource: Option<&'a SafeResourceKey>,
    pub staging_root: &'a Path,
    pub transaction_root: &'a Path,
    pub decisions_path: Option<&'a Path>,
    pub operator_merge_root: Option<&'a Path>,
    pub options: TrustedCliUpdateOptions,
}

pub struct TrustedCliStatusRequest<'a> {
    pub transaction_root: &'a Path,
    pub options: TrustedCliUpdateOptions,
}

pub struct TrustedCliRecoverRequest<'a> {
    pub candidate: &'a str,
    pub artifact: &'a Path,
    pub package: &'a Path,
    pub installed: &'a Path,
    pub baseline_store: &'a Path,
    pub baseline_selector: OfficialBaselineSelector,
    pub resource: Option<&'a SafeResourceKey>,
    pub staging_root: &'a Path,
    pub transaction_root: &'a Path,
    pub decisions_path: Option<&'a Path>,
    pub operator_merge_root: Option<&'a Path>,
    pub options: TrustedCliUpdateOptions,
}

#[derive(Debug)]
pub struct TrustedCliPlanReviewReport {
    pub report: TrustedCliReport,
    pub plan: crate::ThreeWayUpdatePlan,
    pub review: crate::ThreeWayPlanReview,
    pub desktop_apply_authority: Option<TrustedDesktopApplyAuthority>,
    /// Bounded operator-facing merged line views, for escrow-ignored paths only.
    ///
    /// Empty unless the merge pipeline ran and produced a view for an allow-listed path. No
    /// escrow-protected content ever appears here: protected baseline blobs are not retained,
    /// and the allowlist requires every present side of a path to be escrow-ignored.
    pub merged_line_views: Vec<(crate::ResourceRelativePath, crate::MergedLineView)>,
}

pub struct TrustedDesktopApplyAuthority {
    workspace: Option<TrustedUpdateWorkspace>,
    artifact: PathBuf,
    installed: PathBuf,
    baseline_store: PathBuf,
    staging_root: PathBuf,
    transaction_root: PathBuf,
    expected_artifact_id: TrustedCliUpdateArtifactId,
    installed_root_identity: StableFileIdentity,
    selected_resource_identity: StableFileIdentity,
    resource_key: SafeResourceKey,
    selected_installed_root: InstalledResourceRoot,
}

impl std::fmt::Debug for TrustedDesktopApplyAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TrustedDesktopApplyAuthority")
    }
}

pub struct TrustedDesktopApplyRequest<'a> {
    pub authority: &'a TrustedDesktopApplyAuthority,
    pub options: TrustedCliUpdateOptions,
}

#[derive(Debug)]
struct BoundTrustedUpdateSources {
    _installed_temp: tempfile::TempDir,
    installed_root: PathBuf,
    incoming_package: Arc<PackageSnapshot>,
}

impl BoundTrustedUpdateSources {
    fn installed_root(&self) -> &Path {
        &self.installed_root
    }

    fn incoming_package(&self) -> Arc<PackageSnapshot> {
        Arc::clone(&self.incoming_package)
    }
}

#[cfg(test)]
mod test_hooks {
    use std::cell::RefCell;
    use std::path::Path;
    use std::sync::Arc;

    type PlanTestHook = Arc<dyn Fn() + Send + Sync>;
    type PlanPathTestHook = Arc<dyn Fn(&Path) + Send + Sync>;

    #[derive(Clone, Default)]
    pub(super) struct TrustedCliPlanTestHooks {
        pub(super) after_commitment_comparison_before_sealing: Option<PlanTestHook>,
        pub(super) after_source_sealing: Option<PlanTestHook>,
        pub(super) before_source_child_reopen: Option<PlanPathTestHook>,
        pub(super) after_source_file_opened_before_copy: Option<PlanPathTestHook>,
        pub(super) after_sealed_snapshot_verified_before_staging: Option<PlanPathTestHook>,
        pub(super) after_published_bundle_verified_before_descriptor_graph: Option<PlanTestHook>,
    }

    thread_local! {
        static HOOKS: RefCell<Option<TrustedCliPlanTestHooks>> = const { RefCell::new(None) };
    }

    struct HooksGuard {
        previous: Option<TrustedCliPlanTestHooks>,
    }

    impl Drop for HooksGuard {
        fn drop(&mut self) {
            HOOKS.with(|slot| {
                *slot.borrow_mut() = self.previous.take();
            });
        }
    }

    pub(super) fn with_hooks<T>(hooks: TrustedCliPlanTestHooks, f: impl FnOnce() -> T) -> T {
        let previous = HOOKS.with(|slot| {
            let mut slot = slot.borrow_mut();
            let previous = slot.take();
            *slot = Some(hooks);
            previous
        });
        let _guard = HooksGuard { previous };
        f()
    }

    fn current() -> TrustedCliPlanTestHooks {
        HOOKS.with(|slot| slot.borrow().clone().unwrap_or_default())
    }

    pub(super) fn after_commitment_comparison_before_sealing() {
        if let Some(hook) = current().after_commitment_comparison_before_sealing {
            hook();
        }
    }

    pub(super) fn after_source_sealing() {
        if let Some(hook) = current().after_source_sealing {
            hook();
        }
    }

    pub(super) fn before_source_child_reopen(relative: &Path) {
        if let Some(hook) = current().before_source_child_reopen {
            hook(relative);
        }
    }

    pub(super) fn after_source_file_opened_before_copy(relative: &Path) {
        if let Some(hook) = current().after_source_file_opened_before_copy {
            hook(relative);
        }
    }

    pub(super) fn after_sealed_snapshot_verified_before_staging(snapshot_root: &Path) {
        if let Some(hook) = current().after_sealed_snapshot_verified_before_staging {
            hook(snapshot_root);
        }
    }

    pub(super) fn after_published_bundle_verified_before_descriptor_graph() {
        HOOKS.with(|slot| {
            let hook = slot.borrow_mut().as_mut().and_then(|hooks| {
                hooks
                    .after_published_bundle_verified_before_descriptor_graph
                    .take()
            });
            if let Some(hook) = hook {
                hook();
            }
        });
    }
}

pub fn plan_trusted_cli_update(request: TrustedCliPlanRequest<'_>) -> Result<TrustedCliReport> {
    plan_trusted_cli_update_for_review(request).map(|report| report.report)
}

pub fn plan_trusted_cli_update_in_workspace(
    request: TrustedCliPlanRequest<'_>,
) -> Result<TrustedCliReport> {
    let workspace = request
        .workspace
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    let artifact_root = request
        .artifact_out
        .parent()
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    workspace.revalidate_explicit_roots(
        request.baseline_store,
        request.staging_root,
        request.transaction_root,
        artifact_root,
    )?;
    plan_trusted_cli_update_for_review_inner(request, None, true).map(|report| report.report)
}

pub fn plan_trusted_cli_update_for_review(
    request: TrustedCliPlanRequest<'_>,
) -> Result<TrustedCliPlanReviewReport> {
    plan_trusted_cli_update_for_review_inner(request, None, false)
}

pub fn plan_trusted_cli_update_for_review_with_expected_source_commitments(
    request: TrustedCliPlanRequest<'_>,
    expected: &TrustedCliExpectedSourceCommitments,
) -> Result<TrustedCliPlanReviewReport> {
    plan_trusted_cli_update_for_review_inner(request, Some(expected), true)
}

#[cfg(test)]
fn plan_trusted_cli_update_for_review_with_test_hooks(
    request: TrustedCliPlanRequest<'_>,
    hooks: test_hooks::TrustedCliPlanTestHooks,
) -> Result<TrustedCliPlanReviewReport> {
    test_hooks::with_hooks(hooks, || {
        plan_trusted_cli_update_for_review_inner(request, None, false)
    })
}

fn plan_trusted_cli_update_for_review_inner(
    request: TrustedCliPlanRequest<'_>,
    expected_source_commitments: Option<&TrustedCliExpectedSourceCommitments>,
    recovery_authority_required: bool,
) -> Result<TrustedCliPlanReviewReport> {
    let options = request.options.validate()?;
    ensure_output_disjoint(
        request.artifact_out,
        &[
            request.package,
            request.installed,
            request.baseline_store,
            request.staging_root,
            request.transaction_root,
        ],
    )?;

    let initial_report = inspect_installation_update(
        request.installed,
        request.package,
        InspectionOptions::default(),
    )?;
    let initial_selected = resolve_selected_resource(&initial_report, request.resource)?;
    let accepted_source_commitments =
        source_commitments_from_report(&initial_report, &initial_selected)?;
    verify_expected_source_commitments(&accepted_source_commitments, expected_source_commitments)?;
    #[cfg(test)]
    test_hooks::after_commitment_comparison_before_sealing();
    let bound_sources = prepare_bound_trusted_update_sources(
        request.installed,
        request.package,
        &initial_selected,
        &accepted_source_commitments,
        request.options,
    )?;
    #[cfg(test)]
    test_hooks::after_source_sealing();
    let report = inspect_installation_update_from_package_snapshot(
        bound_sources.installed_root(),
        bound_sources.incoming_package.as_ref(),
        InspectionOptions::default(),
    )?;
    let selected = resolve_selected_resource(&report, request.resource)?;
    let sealed_source_commitments = source_commitments_from_report(&report, &selected)?;
    verify_expected_source_commitments(
        &sealed_source_commitments,
        Some(&accepted_source_commitments),
    )?;
    verify_sealed_installed_snapshot_commitment(
        bound_sources.installed_root(),
        &selected,
        &accepted_source_commitments,
    )?;
    #[cfg(test)]
    test_hooks::after_sealed_snapshot_verified_before_staging(bound_sources.installed_root());
    #[cfg(all(feature = "desktop-test-support", debug_assertions))]
    crate::desktop_test_support::sealed_snapshot_verified_before_staging(
        bound_sources.installed_root(),
        request.transaction_root,
        request.artifact_out,
    );
    let txn_root = match request.workspace {
        Some(workspace) => TrustedTransactionRoot::try_open_in_workspace(workspace)?,
        None => TrustedTransactionRoot::try_open(request.transaction_root)?,
    };
    if same_resource_recovery_blocks_new_work(
        &txn_root,
        &selected.resource_key,
        options.max_journal_records,
    )? {
        return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
    }

    let baseline = resolve_official_baseline(BaselineResolutionRequest::try_new(
        request.baseline_store,
        &selected.resource_key,
        request.baseline_selector.clone(),
        BaselineResolutionOptions::default(),
    )?)?;
    let (installed_snap, incoming_snap) = snapshots_for_selection(&report, &selected)?;
    let plan = create_three_way_update_plan(ThreeWayUpdatePlanRequest::try_new(
        &baseline,
        &installed_snap,
        &incoming_snap,
        ThreeWayPlannerOptions::default(),
    )?)?;

    let decisions = match request.decisions_path {
        Some(path) => {
            let bytes = read_regular_file_limited(path, options.max_decision_document_bytes)?;
            parse_decision_document(&plan, &bytes, &options)?
        }
        None => build_decision_document(&plan, Vec::new(), &options)?,
    };
    if let Some(out) = request.decisions_out {
        ensure_output_disjoint(
            out,
            &[
                request.package,
                request.installed,
                request.baseline_store,
                request.staging_root,
                request.transaction_root,
            ],
        )?;
        publish_bytes_no_replace(out, decisions.canonical_bytes())?;
    }

    let review = review_three_way_update_plan(ThreeWayPlanReviewRequest::try_new(
        &plan,
        &decisions.to_decision_set()?,
    )?)?;

    let pending: Vec<String> = review
        .entries()
        .iter()
        .filter(|e| e.action() == ThreeWayReviewedAction::Pending)
        .map(|e| e.path().as_str().to_owned())
        .collect();
    if !pending.is_empty() || review.status() == ThreeWayPlanReviewStatus::Incomplete {
        return Ok(TrustedCliPlanReviewReport {
            report: TrustedCliReport {
                outcome: "pending_decisions",
                pending_paths: pending,
                artifact_id_hex: None,
                candidate_selectors: Vec::new(),
                bound_candidates: 0,
                malformed_candidates: 0,
            },
            plan,
            review,
            desktop_apply_authority: None,
            merged_line_views: Vec::new(),
        });
    }

    let needs_merge = review
        .entries()
        .iter()
        .any(|e| e.action() == ThreeWayReviewedAction::QueueMergeAnalysis);
    let manual_without_op = review.entries().iter().any(|e| {
        e.action() == ThreeWayReviewedAction::ManualReview
            && !decisions
                .entries()
                .iter()
                .any(|d| d.path.as_str() == e.path().as_str() && d.operator_merge_relpath.is_some())
    });
    if manual_without_op && request.operator_merge_root.is_none() {
        let paths = review
            .entries()
            .iter()
            .filter(|e| e.action() == ThreeWayReviewedAction::ManualReview)
            .map(|e| e.path().as_str().to_owned())
            .collect();
        return Ok(TrustedCliPlanReviewReport {
            report: TrustedCliReport {
                outcome: "manual_merge_required",
                pending_paths: paths,
                artifact_id_hex: None,
                candidate_selectors: Vec::new(),
                bound_candidates: 0,
                malformed_candidates: 0,
            },
            plan,
            review,
            desktop_apply_authority: None,
            merged_line_views: Vec::new(),
        });
    }

    let installed_merge = InstalledMergeContentSource::try_new(
        bound_sources.installed_root(),
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_merge = IncomingMergeContentSource::from_package_snapshot(
        bound_sources.incoming_package(),
        selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;

    let (analysis, text_diff, synthesis, merged_bytes) = if needs_merge {
        let analysis = analyze_queued_three_way_merges(ThreeWayMergeAnalysisRequest::try_new(
            &plan,
            &review,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayMergeAnalysisOptions::default(),
        )?)?;
        let text_diff = plan_three_way_text_diffs(ThreeWayTextDiffRequest::try_new(
            &plan,
            &review,
            &analysis,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayTextDiffOptions::default(),
        )?)?;
        let synthesis = plan_three_way_merge_synthesis(ThreeWayMergeSynthesisRequest::try_new(
            &plan,
            &review,
            &analysis,
            &text_diff,
            &baseline,
            &installed_merge,
            &incoming_merge,
            ThreeWayMergeSynthesisOptions::default(),
        )?)?;
        let merged = synthesize_three_way_merged_bytes(
            ThreeWayMergedBytesRequest::try_new(
                &plan,
                &review,
                &analysis,
                &text_diff,
                &synthesis,
                &baseline,
                &installed_merge,
                &incoming_merge,
                ThreeWayMergedBytesOptions::default(),
            )?
            .with_line_view_paths(escrow_ignored_line_view_paths(&plan)),
        )?;
        (
            Some(analysis),
            Some(text_diff),
            Some(synthesis),
            Some(merged),
        )
    } else {
        (None, None, None, None)
    };

    let merged_line_views: Vec<(LineViewPath, crate::MergedLineView)> = merged_bytes
        .as_ref()
        .map(|plan| {
            plan.entries()
                .iter()
                .filter_map(|entry| {
                    entry
                        .line_view()
                        .map(|view| (entry.path().clone(), view.clone()))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut operator_relpaths = Vec::new();
    for entry in decisions.entries() {
        if let Some(rel) = &entry.operator_merge_relpath {
            operator_relpaths.push(rel.clone());
        }
    }
    for entry in review.entries() {
        if entry.action() == ThreeWayReviewedAction::ManualReview
            && !operator_relpaths.iter().any(|r| r == entry.path())
        {
            let paths = review
                .entries()
                .iter()
                .filter(|e| e.action() == ThreeWayReviewedAction::ManualReview)
                .map(|e| e.path().as_str().to_owned())
                .collect();
            return Ok(TrustedCliPlanReviewReport {
                report: TrustedCliReport {
                    outcome: "manual_merge_required",
                    pending_paths: paths,
                    artifact_id_hex: None,
                    candidate_selectors: Vec::new(),
                    bound_candidates: 0,
                    malformed_candidates: 0,
                },
                plan,
                review,
                desktop_apply_authority: None,
                merged_line_views,
            });
        }
    }
    let operator_set = if let Some(merge_root) = request.operator_merge_root {
        validate_and_load_operator_merge_root(
            merge_root,
            &operator_relpaths,
            plan.plan_id(),
            review.review_id(),
            &options,
        )?
    } else if operator_relpaths.is_empty() {
        build_operator_merge_set(Vec::new(), &options)?
    } else {
        let paths = review
            .entries()
            .iter()
            .filter(|e| e.action() == ThreeWayReviewedAction::ManualReview)
            .map(|e| e.path().as_str().to_owned())
            .collect();
        return Ok(TrustedCliPlanReviewReport {
            report: TrustedCliReport {
                outcome: "manual_merge_required",
                pending_paths: paths,
                artifact_id_hex: None,
                candidate_selectors: Vec::new(),
                bound_candidates: 0,
                malformed_candidates: 0,
            },
            plan,
            review,
            desktop_apply_authority: None,
            merged_line_views,
        });
    };
    let op_inputs: Vec<TrustedStagingOperatorMergeInput<'_>> = operator_set
        .artifacts()
        .iter()
        .map(|a| TrustedStagingOperatorMergeInput {
            path: a.path(),
            artifact_id: *a.artifact_id().digest(),
            content_digest: *a.digest_for_staging(),
            bytes: a.bytes_for_staging(),
        })
        .collect();

    let workspace_publication_lock = request
        .workspace
        .map(acquire_trusted_update_workspace_publication_lock)
        .transpose()?;

    let staging_root = TrustedStagingRoot::try_open(request.staging_root)?;
    let installed_staging = InstalledStagingContentSource::try_new(
        bound_sources.installed_root(),
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let incoming_staging = IncomingStagingContentSource::from_package_snapshot(
        bound_sources.incoming_package(),
        selected.incoming_root.clone(),
        IncomingMergeContentSourceLimits::default(),
    )?;
    let staging_req = TrustedStagingRequest::try_new(
        &plan,
        &review,
        analysis.as_ref(),
        text_diff.as_ref(),
        synthesis.as_ref(),
        merged_bytes.as_ref(),
        &baseline,
        &installed_staging,
        &incoming_staging,
        &staging_root,
        TrustedStagingOptions::default(),
    )?
    .with_operator_merges(&op_inputs);
    if let Some(workspace) = request.workspace {
        let staging_estimate = estimate_trusted_staging_publication(&staging_req)?;
        let max_artifact_bytes = u64::try_from(options.max_artifact_bytes)
            .map_err(|_| GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
        let regular_file_bytes = staging_estimate
            .regular_file_bytes()
            .checked_add(max_artifact_bytes)
            .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
        let directory_entries = staging_estimate
            .directory_entries()
            .checked_add(1)
            .ok_or(GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
        let reservation = TrustedUpdateWorkspaceReservation::new(
            regular_file_bytes,
            directory_entries,
            1,
            max_artifact_bytes,
        )?;
        enforce_trusted_update_workspace_capacity_for_reservation(
            workspace,
            request.workspace_options,
            reservation,
        )?;
    }
    let bundle = match stage_trusted_resource(staging_req) {
        Ok(b) => b,
        Err(
            GkrmError::TrustedStagingManualMergeResult | GkrmError::TrustedStagingReviewUnresolved,
        ) => {
            return Ok(TrustedCliPlanReviewReport {
                report: TrustedCliReport {
                    outcome: "manual_merge_required",
                    pending_paths: Vec::new(),
                    artifact_id_hex: None,
                    candidate_selectors: Vec::new(),
                    bound_candidates: 0,
                    malformed_candidates: 0,
                },
                plan,
                review,
                desktop_apply_authority: None,
                merged_line_views,
            });
        }
        Err(e) => return Err(e),
    };

    let installed_apply = InstalledApplyPlanningSource::try_new(
        bound_sources.installed_root(),
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let apply_plan = plan_trusted_apply(TrustedApplyPlanningRequest::try_new(
        &bundle,
        &plan,
        &review,
        analysis.as_ref(),
        text_diff.as_ref(),
        synthesis.as_ref(),
        merged_bytes.as_ref(),
        &baseline,
        &installed_apply,
        TrustedApplyPlanningOptions::default(),
    )?)?;
    let tx_plan =
        plan_trusted_transactional_apply(TrustedTransactionalApplyPlanningRequest::try_new(
            &apply_plan,
            &bundle,
            &plan,
            &review,
            analysis.as_ref(),
            text_diff.as_ref(),
            synthesis.as_ref(),
            merged_bytes.as_ref(),
            &baseline,
            &installed_apply,
            TrustedTransactionalApplyPlanningOptions::default(),
        )?)?;

    let baseline_digest = Sha256Digest::from_lowercase_hex(baseline.baseline_id().as_str())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let empty_set = encode_operator_merge_set_id(&[])?;
    let desktop_installed_authority = InstalledApplyPlanningSource::try_new(
        request.installed,
        selected.installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    let authority_source = if recovery_authority_required {
        &desktop_installed_authority
    } else {
        &installed_apply
    };
    let authority_snapshot = authority_source
        .capture_tree_snapshot(plan.resource_key())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let recovery_authority = if recovery_authority_required {
        let (recovery_body, recovery_id) = build_recovery_authority_body(
            authority_source,
            plan.resource_key(),
            baseline_digest,
            *bundle.manifest().manifest_id().digest(),
            *bundle.bundle_id().digest(),
            *apply_plan.plan_id().digest(),
            *tx_plan.plan_id().digest(),
            &authority_snapshot,
            RecoveryAuthorityLimits::default(),
        )?;
        if recovery_body.selected_resource_commitment != selected.resource_commitment {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        Some((recovery_body, recovery_id))
    } else {
        None
    };
    let body = TrustedCliUpdateArtifactBody {
        package_fingerprint: *report.incoming_package_fingerprint(),
        selected_resource_commitment: selected.resource_commitment,
        baseline_id_digest: baseline_digest,
        plan_id: *plan.plan_id().digest(),
        review_id: *review.review_id().digest(),
        analysis_id: analysis.as_ref().map(|a| *a.analysis_id().digest()),
        text_diff_id: text_diff.as_ref().map(|t| *t.text_diff_plan_id().digest()),
        synthesis_id: synthesis.as_ref().map(|s| *s.synthesis_plan_id().digest()),
        merged_bytes_id: merged_bytes
            .as_ref()
            .map(|m| *m.merged_bytes_plan_id().digest()),
        operator_merge_set_id: if operator_set.artifacts().is_empty() {
            empty_set
        } else {
            *operator_set.set_id()
        },
        staging_manifest_id: *bundle.manifest().manifest_id().digest(),
        staging_bundle_id: *bundle.bundle_id().digest(),
        apply_plan_id: *apply_plan.plan_id().digest(),
        snapshot_a: authority_snapshot.fingerprint,
        transactional_plan_id: *tx_plan.plan_id().digest(),
        recovery_authority_id: recovery_authority.as_ref().map(|(_, id)| *id.digest()),
        decision_document_id: *decisions.document_id().digest(),
    };
    let descriptor = TrustedCliApplyDescriptor::try_new(
        plan.resource_key(),
        plan.baseline_id(),
        &selected.installed_root,
        plan.installed_snapshot_fingerprint(),
        plan.incoming_package_fingerprint(),
        plan.incoming_resource_fingerprint(),
        &plan,
        &review,
    )?;
    let artifact = if recovery_authority.is_some() {
        encode_cli_artifact_v2_with_apply_descriptor(&body, &descriptor)?
    } else {
        encode_cli_artifact_with_apply_descriptor(&body, &descriptor)?
    };
    let artifact_bytes = artifact.canonical_bytes();
    let artifact_len_u64 = u64::try_from(artifact_bytes.len()).map_err(|_| {
        GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        }
    })?;
    let max_artifact_bytes_u64 = u64::try_from(options.max_artifact_bytes).map_err(|_| {
        GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        }
    })?;
    if artifact_len_u64 > max_artifact_bytes_u64 {
        return Err(GkrmError::TrustedCliUpdateLimitExceeded {
            limit: "max_artifact_bytes",
        });
    }
    let _workspace_publication_lock = workspace_publication_lock;
    publish_bytes_no_replace(request.artifact_out, artifact_bytes)?;

    let desktop_apply_authority = TrustedDesktopApplyAuthority {
        workspace: request.workspace.cloned(),
        artifact: request.artifact_out.to_path_buf(),
        installed: request.installed.to_path_buf(),
        baseline_store: request.baseline_store.to_path_buf(),
        staging_root: request.staging_root.to_path_buf(),
        transaction_root: request.transaction_root.to_path_buf(),
        expected_artifact_id: *artifact.artifact_id(),
        installed_root_identity: desktop_installed_authority
            .installed_root_identity()
            .clone(),
        selected_resource_identity: desktop_installed_authority
            .selected_resource_identity()
            .clone(),
        resource_key: plan.resource_key().clone(),
        selected_installed_root: selected.installed_root.clone(),
    };

    Ok(TrustedCliPlanReviewReport {
        report: TrustedCliReport {
            outcome: "ready_to_apply",
            pending_paths: Vec::new(),
            artifact_id_hex: Some(artifact.artifact_id().to_hex()),
            candidate_selectors: Vec::new(),
            bound_candidates: 0,
            malformed_candidates: 0,
        },
        plan,
        review,
        desktop_apply_authority: Some(desktop_apply_authority),
        merged_line_views,
    })
}

fn source_commitments_from_report(
    report: &crate::FullInspectionReport,
    selected: &SelectedPackageResource,
) -> Result<TrustedCliExpectedSourceCommitments> {
    let installed = report
        .installed()
        .resources
        .iter()
        .find(|resource| resource.root == selected.installed_root)
        .ok_or(GkrmError::TrustedUpdateSourceChanged)?;
    let installed_resource =
        crate::installed_resource_source_commitment(installed, &selected.resource_key)
            .map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    let package = crate::PackageSourceCommitment::from_package_fingerprint(
        *report.incoming_package_fingerprint(),
    );
    Ok(TrustedCliExpectedSourceCommitments {
        installed_resource,
        package,
    })
}

fn verify_expected_source_commitments(
    actual: &TrustedCliExpectedSourceCommitments,
    expected: Option<&TrustedCliExpectedSourceCommitments>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if actual != expected {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }
    Ok(())
}

fn prepare_bound_trusted_update_sources(
    installed_root: &Path,
    package_path: &Path,
    selected: &SelectedPackageResource,
    accepted: &TrustedCliExpectedSourceCommitments,
    options: TrustedCliUpdateOptions,
) -> Result<BoundTrustedUpdateSources> {
    let installed_temp =
        tempfile::tempdir().map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    // A resource that *is* the chosen folder has no directory above it inside the seal, so the
    // copy would inherit the temporary directory's random name and stop matching the resource it
    // came from. Give it a directory of its own, named for the resource, and seal into that.
    let sealed_installed_root = match selected.installed_root {
        InstalledResourceRoot::Root => {
            let named = installed_temp.path().join(selected.resource_key.as_str());
            std::fs::create_dir(&named)
                .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
            named
        }
        InstalledResourceRoot::Path(_) => installed_temp.path().to_path_buf(),
    };
    copy_selected_installed_resource_to_temp(
        installed_root,
        &selected.installed_root,
        &sealed_installed_root,
        options,
    )
    .map_err(map_original_source_binding_error)?;
    let sealed_installed_scan =
        scan_installed_resources(&sealed_installed_root, InstalledScanLimits::default())
            .map_err(map_original_source_binding_error)?;
    let sealed_installed = sealed_installed_scan
        .resources
        .iter()
        .find(|resource| resource.root == selected.installed_root)
        .ok_or(GkrmError::TrustedUpdateSourceChanged)?;
    let sealed_installed_commitment =
        crate::installed_resource_source_commitment(sealed_installed, &selected.resource_key)
            .map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    if sealed_installed_commitment != accepted.installed_resource {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }

    let package_snapshot = Arc::new(
        PackageSnapshot::create(package_path, options.max_package_bytes)
            .map_err(map_trusted_source_error)?,
    );
    let sealed_package_commitment =
        crate::PackageSourceCommitment::from_package_fingerprint(*package_snapshot.fingerprint());
    if sealed_package_commitment != accepted.package {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }

    Ok(BoundTrustedUpdateSources {
        _installed_temp: installed_temp,
        installed_root: sealed_installed_root,
        incoming_package: package_snapshot,
    })
}

fn copy_selected_installed_resource_to_temp(
    installed_root: &Path,
    selected_root: &InstalledResourceRoot,
    sealed_root: &Path,
    options: TrustedCliUpdateOptions,
) -> Result<()> {
    let source = open_selected_source_dir(installed_root, selected_root)?;
    let destination = create_selected_snapshot_destination(sealed_root, selected_root)?;
    let mut budget = SnapshotCopyBudget::new(options.max_staging_files, options.max_staging_bytes);
    copy_directory_contents_cap(&source, &destination, Path::new(""), &mut budget)
}

fn open_selected_source_dir(
    installed_root: &Path,
    selected_root: &InstalledResourceRoot,
) -> Result<CapDir> {
    let root = open_existing_directory(installed_root, "installed-root")
        .map_err(map_original_source_binding_error)?;
    match selected_root {
        InstalledResourceRoot::Root => root
            .dir
            .try_clone()
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() }),
        InstalledResourceRoot::Path(path) => {
            let mut dir = root.dir;
            for component in path.as_str().split('/') {
                dir = open_child_dir(&dir, component).map_err(map_original_source_binding_error)?;
            }
            Ok(dir)
        }
    }
}

fn create_selected_snapshot_destination(
    temp_root: &Path,
    selected_root: &InstalledResourceRoot,
) -> Result<CapDir> {
    let root = open_existing_directory(temp_root, "trusted-installed-snapshot")
        .map_err(map_private_snapshot_error)?;
    match selected_root {
        InstalledResourceRoot::Root => root
            .dir
            .try_clone()
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() }),
        InstalledResourceRoot::Path(path) => {
            let mut dir = root.dir;
            for component in path.as_str().split('/') {
                dir = create_new_child_dir(&dir, component).map_err(map_private_snapshot_error)?;
            }
            Ok(dir)
        }
    }
}

fn copy_directory_contents_cap(
    source: &CapDir,
    destination: &CapDir,
    relative: &Path,
    budget: &mut SnapshotCopyBudget,
) -> Result<()> {
    let source_identity =
        dir_identity(source, "installed-source-dir").map_err(map_original_source_binding_error)?;
    let entries = source
        .entries()
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    let mut entries = entries
        .into_iter()
        .map(|entry| {
            let name = entry_name_to_string(entry.file_name().as_os_str())?;
            validate_single_component(&name).map_err(map_original_source_binding_error)?;
            let metadata = entry
                .full_metadata()
                .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
            reject_link_like_metadata(&metadata, &name)
                .map_err(map_original_source_binding_error)?;
            Ok((name, metadata))
        })
        .collect::<Result<Vec<_>>>()?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    for (name, metadata) in entries {
        let child_relative = relative.join(&name);
        let file_type = metadata.file_type();
        let enumerated_identity = metadata_identity(&metadata);
        #[cfg(test)]
        test_hooks::before_source_child_reopen(&child_relative);
        if file_type.is_dir() {
            let child =
                open_child_dir(source, &name).map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
            let opened_identity = dir_identity(&child, "installed-source-dir")
                .map_err(map_original_source_binding_error)?;
            if opened_identity != enumerated_identity {
                return Err(GkrmError::TrustedUpdateSourceChanged);
            }
            let child_destination =
                create_new_child_dir(destination, &name).map_err(map_private_snapshot_error)?;
            copy_directory_contents_cap(&child, &child_destination, &child_relative, budget)?;
            let after_identity = dir_identity(&child, "installed-source-dir")
                .map_err(map_original_source_binding_error)?;
            if after_identity != opened_identity {
                return Err(GkrmError::TrustedUpdateSourceChanged);
            }
        } else if file_type.is_file() {
            budget.note_file(metadata.len())?;
            copy_regular_file_cap(source, destination, &name, &child_relative, &metadata)?;
        } else {
            return Err(GkrmError::TrustedUpdateSourceChanged);
        }
    }

    let source_after =
        dir_identity(source, "installed-source-dir").map_err(map_original_source_binding_error)?;
    if source_after != source_identity {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }
    Ok(())
}

fn copy_regular_file_cap(
    source_parent: &CapDir,
    destination_parent: &CapDir,
    name: &str,
    _relative: &Path,
    enumerated_metadata: &CapMetadata,
) -> Result<()> {
    let mut input = open_file_nofollow(source_parent, name)
        .map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    verify_regular_file(&input, name).map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    let opened_identity =
        capture_file_identity(&input, name).map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    if opened_identity != metadata_identity(enumerated_metadata) {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }
    let opened_metadata = input
        .metadata()
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    reject_link_like_metadata(&opened_metadata, name)
        .map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    if !opened_metadata.file_type().is_file() || opened_metadata.len() != enumerated_metadata.len()
    {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }

    #[cfg(test)]
    test_hooks::after_source_file_opened_before_copy(_relative);

    let mut output =
        create_new_file(destination_parent, name).map_err(map_private_snapshot_error)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
        if copied > opened_metadata.len() {
            return Err(GkrmError::TrustedUpdateSourceChanged);
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    }
    if copied != opened_metadata.len() {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }
    output
        .flush()
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    output
        .sync_all()
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    drop(output);

    let after_identity =
        capture_file_identity(&input, name).map_err(|_| GkrmError::TrustedUpdateSourceChanged)?;
    if after_identity != opened_identity {
        return Err(GkrmError::TrustedUpdateSourceChanged);
    }

    let source_digest = Sha256Digest::new(hasher.finalize().into());
    verify_copied_snapshot_file(destination_parent, name, copied, source_digest)
}

fn verify_copied_snapshot_file(
    destination_parent: &CapDir,
    name: &str,
    expected_len: u64,
    expected_digest: Sha256Digest,
) -> Result<()> {
    let mut file =
        open_file_nofollow(destination_parent, name).map_err(map_private_snapshot_error)?;
    let before = capture_file_identity(&file, name).map_err(map_private_snapshot_error)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(read as u64)
            .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
        if copied > expected_len {
            return Err(GkrmError::TrustedCliUpdateSecurityRejection);
        }
        hasher.update(&buffer[..read]);
    }
    let after = capture_file_identity(&file, name).map_err(map_private_snapshot_error)?;
    if before != after
        || copied != expected_len
        || Sha256Digest::new(hasher.finalize().into()) != expected_digest
    {
        return Err(GkrmError::TrustedCliUpdateSecurityRejection);
    }
    Ok(())
}

struct SnapshotCopyBudget {
    files: usize,
    bytes: u64,
    max_files: usize,
    max_bytes: u64,
}

impl SnapshotCopyBudget {
    fn new(max_files: usize, max_bytes: u64) -> Self {
        Self {
            files: 0,
            bytes: 0,
            max_files,
            max_bytes,
        }
    }

    fn note_file(&mut self, len: u64) -> Result<()> {
        self.files = self
            .files
            .checked_add(1)
            .ok_or(GkrmError::TrustedCliUpdateLimitExceeded {
                limit: "max_staging_files",
            })?;
        if self.files > self.max_files {
            return Err(GkrmError::TrustedCliUpdateLimitExceeded {
                limit: "max_staging_files",
            });
        }
        self.bytes =
            self.bytes
                .checked_add(len)
                .ok_or(GkrmError::TrustedCliUpdateLimitExceeded {
                    limit: "max_staging_bytes",
                })?;
        if self.bytes > self.max_bytes {
            return Err(GkrmError::TrustedCliUpdateLimitExceeded {
                limit: "max_staging_bytes",
            });
        }
        Ok(())
    }
}

fn entry_name_to_string(name: &OsStr) -> Result<String> {
    name.to_str()
        .map(str::to_owned)
        .ok_or(GkrmError::TrustedUpdateSourceChanged)
}

fn metadata_identity(metadata: &CapMetadata) -> StableFileIdentity {
    #[cfg(unix)]
    {
        StableFileIdentity::Unix {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    #[cfg(windows)]
    {
        StableFileIdentity::Windows {
            volume_serial: metadata.dev(),
            file_index: metadata.ino(),
        }
    }
}

fn verify_sealed_installed_snapshot_commitment(
    sealed_installed_root: &Path,
    selected: &SelectedPackageResource,
    accepted: &TrustedCliExpectedSourceCommitments,
) -> Result<()> {
    let sealed_installed_scan =
        scan_installed_resources(sealed_installed_root, InstalledScanLimits::default())
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    let sealed_installed = sealed_installed_scan
        .resources
        .iter()
        .find(|resource| resource.root == selected.installed_root)
        .ok_or(GkrmError::TrustedCliUpdateSecurityRejection)?;
    let sealed_installed_commitment =
        crate::installed_resource_source_commitment(sealed_installed, &selected.resource_key)
            .map_err(|_| GkrmError::TrustedCliUpdateSecurityRejection)?;
    if sealed_installed_commitment != accepted.installed_resource {
        return Err(GkrmError::TrustedCliUpdateSecurityRejection);
    }
    Ok(())
}

fn map_original_source_binding_error(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::BaselineStoreMissing { .. }
        | GkrmError::BaselineStoreUnsafeComponent { .. }
        | GkrmError::BaselineStoreHardLink { .. }
        | GkrmError::BaselineStoreUnexpectedType { .. } => GkrmError::TrustedUpdateSourceChanged,
        GkrmError::BaselineStoreIo { cause: source, .. } => {
            if source.kind() == std::io::ErrorKind::NotFound {
                GkrmError::TrustedUpdateSourceChanged
            } else {
                GkrmError::TrustedCliUpdateIo {
                    kind: source.kind(),
                }
            }
        }
        other => map_trusted_source_error(other),
    }
}

fn map_private_snapshot_error(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::BaselineStoreIo { cause: source, .. } => GkrmError::TrustedCliUpdateIo {
            kind: source.kind(),
        },
        GkrmError::BaselineStoreMissing { .. }
        | GkrmError::BaselineStoreUnsafeComponent { .. }
        | GkrmError::BaselineStoreHardLink { .. }
        | GkrmError::BaselineStoreUnexpectedType { .. } => {
            GkrmError::TrustedCliUpdateSecurityRejection
        }
        other => other,
    }
}

fn map_trusted_source_error(error: GkrmError) -> GkrmError {
    match error {
        GkrmError::TrustedUpdateSourceChanged
        | GkrmError::TrustedCliUpdateBindingMismatch
        | GkrmError::InstalledDirectoryDisappeared { .. }
        | GkrmError::InstalledFileDisappeared { .. }
        | GkrmError::InstalledFileChanged { .. }
        | GkrmError::InstalledFileContentChanged { .. }
        | GkrmError::InstalledFileSizeMismatch { .. }
        | GkrmError::ComparisonPackageArchiveSizeMismatch { .. }
        | GkrmError::ComparisonPackageChanged { .. }
        | GkrmError::ThreeWayMergeAnalysisInstalledPreFingerprintMismatch
        | GkrmError::ThreeWayMergeAnalysisInstalledPostFingerprintMismatch
        | GkrmError::ThreeWayMergeAnalysisInstalledResourceChanged
        | GkrmError::ThreeWayMergeAnalysisIncomingPackageFingerprintMismatch
        | GkrmError::ThreeWayMergeAnalysisIncomingResourceFingerprintMismatch
        | GkrmError::ThreeWayMergeAnalysisIncomingResourceIdentityMismatch
        | GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged
        | GkrmError::ThreeWayTextDiffInstalledPreFingerprintMismatch
        | GkrmError::ThreeWayTextDiffInstalledPostFingerprintMismatch
        | GkrmError::ThreeWayTextDiffInstalledResourceChanged
        | GkrmError::ThreeWayTextDiffIncomingPackageFingerprintMismatch
        | GkrmError::ThreeWayTextDiffIncomingResourceFingerprintMismatch
        | GkrmError::ThreeWayTextDiffIncomingResourceIdentityMismatch
        | GkrmError::ThreeWayTextDiffSourceIdentityChanged
        | GkrmError::ThreeWayMergeSynthesisInstalledPreFingerprintMismatch
        | GkrmError::ThreeWayMergeSynthesisInstalledPostFingerprintMismatch
        | GkrmError::ThreeWayMergeSynthesisInstalledResourceChanged
        | GkrmError::ThreeWayMergeSynthesisIncomingPackageFingerprintMismatch
        | GkrmError::ThreeWayMergeSynthesisIncomingResourceFingerprintMismatch
        | GkrmError::ThreeWayMergeSynthesisIncomingResourceIdentityMismatch
        | GkrmError::ThreeWayMergeSynthesisSourceIdentityChanged
        | GkrmError::ThreeWayMergedBytesInstalledPreFingerprintMismatch
        | GkrmError::ThreeWayMergedBytesInstalledPostFingerprintMismatch
        | GkrmError::ThreeWayMergedBytesInstalledResourceChanged
        | GkrmError::ThreeWayMergedBytesIncomingPackageFingerprintMismatch
        | GkrmError::ThreeWayMergedBytesIncomingResourceFingerprintMismatch
        | GkrmError::ThreeWayMergedBytesIncomingResourceIdentityMismatch
        | GkrmError::ThreeWayMergedBytesSourceIdentityChanged => {
            GkrmError::TrustedUpdateSourceChanged
        }
        other => other,
    }
}

#[cfg(test)]
mod source_error_normalization_tests {
    use super::*;

    #[test]
    fn proven_source_drift_errors_normalize_to_trusted_update_source_changed() {
        for error in [
            GkrmError::TrustedCliUpdateBindingMismatch,
            GkrmError::InstalledFileChanged {
                path: "client.lua".to_owned(),
            },
            GkrmError::ComparisonPackageChanged {
                path: PathBuf::from("package.zip"),
                reason: "changed".to_owned(),
            },
            GkrmError::ThreeWayMergeAnalysisSourceIdentityChanged,
        ] {
            assert!(matches!(
                map_trusted_source_error(error),
                GkrmError::TrustedUpdateSourceChanged
            ));
        }
    }

    #[test]
    fn sealed_snapshot_and_staging_errors_keep_their_category() {
        assert!(matches!(
            map_trusted_source_error(GkrmError::TrustedStagingSourceUnavailable),
            GkrmError::TrustedStagingSourceUnavailable
        ));
        assert!(matches!(
            map_trusted_source_error(GkrmError::TrustedStagingDigestLengthMismatch),
            GkrmError::TrustedStagingDigestLengthMismatch
        ));
        assert!(matches!(
            map_trusted_source_error(GkrmError::TrustedApplyPlanningInstalledStale),
            GkrmError::TrustedApplyPlanningInstalledStale
        ));
        assert!(matches!(
            map_trusted_source_error(GkrmError::TrustedTransactionalApplyPlanningInstalledStale),
            GkrmError::TrustedTransactionalApplyPlanningInstalledStale
        ));
        assert!(matches!(
            map_trusted_source_error(GkrmError::TrustedCliUpdateDestinationExists),
            GkrmError::TrustedCliUpdateDestinationExists
        ));
        assert!(matches!(
            map_trusted_source_error(GkrmError::TrustedUpdateWorkspaceCapacityReached),
            GkrmError::TrustedUpdateWorkspaceCapacityReached
        ));
    }

    #[test]
    fn public_planning_api_does_not_expose_test_hooks() {
        // Normalised, because the checkout's line endings are not what this test is about. On a
        // CRLF checkout the positive assertion below fails, and worse, every negative one passes
        // for free: a forbidden pattern written with a newline can never match.
        let module_source = include_str!("mod.rs").replace("\r\n", "\n");
        let lib_source = include_str!("../lib.rs").replace("\r\n", "\n");

        for forbidden in [
            ["pub ", "test_hooks"].concat(),
            ["pub struct ", "TrustedCliPlan", "TestHooks"].concat(),
            ["pub type ", "Plan", "TestHook"].concat(),
            ["pub type ", "Plan", "PathTestHook"].concat(),
            ["request", ".", "test_hooks"].concat(),
            ["cfg(not(test))", "\nstruct ", "TrustedCliPlan", "TestHooks"].concat(),
            ["fn ", "default_plan_", "test_hooks"].concat(),
            [",\n    ", "test_hooks", ": &"].concat(),
            ["pub use ", "desktop_test_support"].concat(),
        ] {
            assert!(!module_source.contains(&forbidden));
            assert!(!lib_source.contains(&forbidden));
        }
        assert!(lib_source.contains(
            "#[cfg(all(feature = \"desktop-test-support\", debug_assertions))]\npub mod desktop_test_support;"
        ));
        assert!(!lib_source.contains(&["TrustedCliPlan", "TestHooks"].concat()));
    }
}

#[cfg(test)]
fn publish_plan_artifact_with_optional_workspace_capacity(
    workspace: Option<&TrustedUpdateWorkspace>,
    workspace_options: TrustedUpdateWorkspaceOptions,
    artifact_out: &Path,
    artifact_bytes: &[u8],
) -> Result<()> {
    let Some(workspace) = workspace else {
        return publish_bytes_no_replace(artifact_out, artifact_bytes);
    };
    let artifact_len = u64::try_from(artifact_bytes.len())
        .map_err(|_| GkrmError::TrustedUpdateWorkspaceCapacityReached)?;
    let _lock = acquire_trusted_update_workspace_publication_lock(workspace)?;
    #[cfg(test)]
    publication_test_hook_after_production_lock_acquired();
    crate::enforce_trusted_update_workspace_capacity_for_new_plan_artifact(
        workspace,
        workspace_options,
        artifact_len,
    )?;
    publish_bytes_no_replace(artifact_out, artifact_bytes)
}

#[cfg(test)]
static PAUSE_AFTER_PRODUCTION_PUBLICATION_LOCK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn publication_test_hook_after_production_lock_acquired() {
    if !PAUSE_AFTER_PRODUCTION_PUBLICATION_LOCK.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    println!("A_LOCKED_IN_PRODUCTION");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    let mut command = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut command).unwrap();
    assert_eq!(command.trim(), "A_CONTINUE");
}

pub fn apply_trusted_cli_update(request: TrustedCliApplyRequest<'_>) -> Result<TrustedCliReport> {
    apply_trusted_cli_update_inner(request, None)
}

pub fn apply_trusted_cli_update_in_workspace(
    request: TrustedCliApplyRequest<'_>,
    workspace: &TrustedUpdateWorkspace,
) -> Result<TrustedCliReport> {
    let artifact_root = request
        .artifact
        .parent()
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    workspace.revalidate_explicit_roots(
        request.baseline_store,
        request.staging_root,
        request.transaction_root,
        artifact_root,
    )?;
    apply_trusted_cli_update_inner(request, Some(workspace))
}

fn apply_trusted_cli_update_inner(
    request: TrustedCliApplyRequest<'_>,
    workspace: Option<&TrustedUpdateWorkspace>,
) -> Result<TrustedCliReport> {
    let options = request.options.validate()?;
    let bytes = read_regular_file_limited(request.artifact, options.max_artifact_bytes)?;
    let artifact = parse_cli_artifact(&bytes, &options)?;

    let live =
        rebind::rebuild_trusted_cli_update_authority(&rebind::TrustedCliUpdateRebindRequest {
            package: request.package,
            installed: request.installed,
            baseline_store: request.baseline_store,
            baseline_selector: request.baseline_selector.clone(),
            resource: request.resource,
            staging_root: request.staging_root,
            decisions_path: request.decisions_path,
            operator_merge_root: request.operator_merge_root,
            recovery_authority: artifact.version() == artifact::ARTIFACT_V2_FORMAT_VERSION,
            options,
        })?;
    rebind::require_cli_artifact_matches_live_authority(&artifact, &live)?;

    let txn_root = match workspace {
        Some(workspace) => TrustedTransactionRoot::try_open_in_workspace(workspace)?,
        None => TrustedTransactionRoot::try_open(request.transaction_root)?,
    };
    if same_resource_recovery_blocks_new_work(
        &txn_root,
        &live.selected.resource_key,
        options.max_journal_records,
    )? {
        return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
    }

    if let Some(workspace) =
        workspace.filter(|_| artifact.version() == artifact::ARTIFACT_V2_FORMAT_VERSION)
    {
        let authority = TrustedDesktopApplyAuthority {
            workspace: Some(workspace.clone()),
            artifact: request.artifact.to_path_buf(),
            installed: request.installed.to_path_buf(),
            baseline_store: request.baseline_store.to_path_buf(),
            staging_root: request.staging_root.to_path_buf(),
            transaction_root: request.transaction_root.to_path_buf(),
            expected_artifact_id: *artifact.artifact_id(),
            installed_root_identity: live.installed_apply.installed_root_identity().clone(),
            selected_resource_identity: live.installed_apply.selected_resource_identity().clone(),
            resource_key: live.selected.resource_key.clone(),
            selected_installed_root: live.selected.installed_root.clone(),
        };
        return apply_trusted_desktop_update(TrustedDesktopApplyRequest {
            authority: &authority,
            options,
        });
    }

    // Point-of-use: reopen artifact and re-verify staged contents immediately before Task 23.
    {
        let again = read_regular_file_limited(request.artifact, options.max_artifact_bytes)?;
        let again_art = parse_cli_artifact(&again, &options)?;
        if again_art.artifact_id().digest() != artifact.artifact_id().digest() {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        verify_published_bundle_readonly(
            live.bundle.published_dir_for_apply_planning(),
            live.bundle.resource_dir_for_apply_planning(),
            live.bundle.manifest(),
        )?;
        live.bundle
            .staging_root_for_apply_planning()
            .revalidate_identity()?;
        if same_resource_recovery_blocks_new_work(
            &txn_root,
            &live.selected.resource_key,
            options.max_journal_records,
        )? {
            return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
        }
    }

    let exec = match execute_trusted_transactional_apply(
        TrustedTransactionalApplyExecutionRequest::try_new(
            &live.tx_plan,
            &live.apply_plan,
            &live.bundle,
            &live.plan,
            &live.review,
            live.analysis.as_ref(),
            live.text_diff.as_ref(),
            live.synthesis.as_ref(),
            live.merged_bytes.as_ref(),
            &live.baseline,
            &live.installed_apply,
            &txn_root,
            request.package,
            TrustedTransactionalApplyExecutionOptions::default(),
        )?,
    ) {
        Ok(r) => r,
        Err(GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery { .. }) => {
            return Ok(apply_report(
                "published_recovery_unsealed",
                artifact.artifact_id().to_hex(),
            ));
        }
        Err(GkrmError::TrustedTransactionalApplyExecutionFailedCompound { .. }) => {
            return Ok(apply_report(
                "published_recovery_failed",
                artifact.artifact_id().to_hex(),
            ));
        }
        Err(GkrmError::TrustedTransactionalApplyExecutionLockContention) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLockContention);
        }
        Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists) => {
            return Err(GkrmError::TrustedCliUpdateTransactionAlreadyPublished);
        }
        // Any other Task 23 error: classify publication state positively before mapping.
        // Never map to safe-before-publication without ProvenNotPublished.
        Err(_other) => {
            let publication = publication_state::classify_apply_failure_publication_state(
                request.transaction_root,
                live.tx_plan.plan_id().digest(),
                &options,
            );
            let outcome = publication_state::outcome_for_classified_apply_failure(publication);
            return Ok(apply_report(outcome, artifact.artifact_id().to_hex()));
        }
    };

    let outcome = match exec {
        TrustedTransactionResult::Committed(_) => "committed",
        TrustedTransactionResult::RolledBack(_) => "rolled_back",
        TrustedTransactionResult::RecoveryRequired(_) => "recovery_required",
    };
    Ok(apply_report(outcome, artifact.artifact_id().to_hex()))
}

fn apply_report(outcome: &'static str, artifact_id_hex: String) -> TrustedCliReport {
    TrustedCliReport {
        outcome,
        pending_paths: Vec::new(),
        artifact_id_hex: Some(artifact_id_hex),
        candidate_selectors: Vec::new(),
        bound_candidates: 0,
        malformed_candidates: 0,
    }
}

pub fn apply_trusted_desktop_update(
    request: TrustedDesktopApplyRequest<'_>,
) -> Result<TrustedCliReport> {
    let options = request.options.validate()?;
    let authority = request.authority;
    let txn_root = match authority.workspace.as_ref() {
        Some(workspace) => TrustedTransactionRoot::try_open_in_workspace(workspace)?,
        None => TrustedTransactionRoot::try_open(&authority.transaction_root)?,
    };
    let recovery_identity = InstalledApplyPlanningSource::try_new(
        &authority.installed,
        authority.selected_installed_root.clone(),
        InstalledScanLimits::default(),
    )?;
    if recovery_identity.installed_root_identity() != &authority.installed_root_identity
        || recovery_identity.selected_resource_identity() != &authority.selected_resource_identity
    {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    if same_resource_recovery_blocks_new_work(
        &txn_root,
        &authority.resource_key,
        options.max_journal_records,
    )? {
        return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
    }
    drop(recovery_identity);
    let bytes = read_regular_file_limited(&authority.artifact, options.max_artifact_bytes)?;
    let artifact = parse_cli_artifact(&bytes, &options)?;
    if artifact.artifact_id().digest() != authority.expected_artifact_id.digest() {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    let mut prepared = prepare_desktop_apply_inputs(authority, &artifact)?;

    if same_resource_recovery_blocks_new_work(
        &txn_root,
        prepared.plan.resource_key(),
        options.max_journal_records,
    )? {
        return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
    }

    let again = read_regular_file_limited(&authority.artifact, options.max_artifact_bytes)?;
    let again_art = parse_cli_artifact(&again, &options)?;
    if again_art.artifact_id().digest() != artifact.artifact_id().digest() {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    prepared = prepare_desktop_apply_inputs(authority, &again_art)?;
    if same_resource_recovery_blocks_new_work(
        &txn_root,
        prepared.plan.resource_key(),
        options.max_journal_records,
    )? {
        return Err(GkrmError::TrustedCliUpdateRecoveryRequired);
    }
    #[cfg(test)]
    crate::trusted_transactional_apply_execution::hooks::record_authority_verification_event(
        crate::trusted_transactional_apply_execution::hooks::AuthorityVerificationEvent::InitialDesktopAuthorityValidationPassed,
    );
    #[cfg(test)]
    crate::trusted_transactional_apply_execution::hooks::record_authority_verification_event(
        crate::trusted_transactional_apply_execution::hooks::AuthorityVerificationEvent::EarlySelectedResourceCommitmentVerified,
    );

    let expected_artifact_id = *again_art.artifact_id().digest();
    let expected_recovery_authority_id = again_art.body().recovery_authority_id;
    let revalidate_artifact = || {
        let current = read_regular_file_limited(&authority.artifact, options.max_artifact_bytes)?;
        let current = parse_cli_artifact(&current, &options)?;
        if current.version() != artifact::ARTIFACT_V2_FORMAT_VERSION
            || current.artifact_id().digest() != &expected_artifact_id
            || current.body().recovery_authority_id != expected_recovery_authority_id
        {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        let fresh = prepare_desktop_apply_inputs(authority, &current)?;
        let publication = fresh
            .recovery_publication
            .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
        if publication.artifact_id() != &expected_artifact_id
            || publication.authority_id().digest()
                != expected_recovery_authority_id
                    .as_ref()
                    .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?
        {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        #[cfg(test)]
        crate::trusted_transactional_apply_execution::hooks::record_artifact_revalidation_passed();
        Ok(publication)
    };

    let execution_request = if let Some(recovery_authority) = prepared.recovery_publication.as_ref()
    {
        TrustedTransactionalApplyExecutionRequest::try_new_package_free_with_recovery_authority(
            &prepared.live_tx_plan,
            &prepared.live_apply_plan,
            &prepared.bundle,
            &prepared.plan,
            &prepared.review,
            prepared.merge_ids,
            prepared.merged_bytes.as_ref(),
            &prepared.baseline,
            &prepared.installed_apply,
            &txn_root,
            recovery_authority,
            &revalidate_artifact,
            TrustedTransactionalApplyExecutionOptions::default(),
        )?
    } else {
        TrustedTransactionalApplyExecutionRequest::try_new_package_free(
            &prepared.live_tx_plan,
            &prepared.live_apply_plan,
            &prepared.bundle,
            &prepared.plan,
            &prepared.review,
            prepared.merge_ids,
            prepared.merged_bytes.as_ref(),
            &prepared.baseline,
            &prepared.installed_apply,
            &txn_root,
            TrustedTransactionalApplyExecutionOptions::default(),
        )?
    };
    let exec = match execute_trusted_transactional_apply(execution_request) {
        Ok(r) => r,
        Err(GkrmError::TrustedTransactionalApplyExecutionPublishedNeedsRecovery { .. }) => {
            return Ok(apply_report(
                "published_recovery_unsealed",
                artifact.artifact_id().to_hex(),
            ));
        }
        Err(GkrmError::TrustedTransactionalApplyExecutionFailedCompound { .. }) => {
            return Ok(apply_report(
                "published_recovery_failed",
                artifact.artifact_id().to_hex(),
            ));
        }
        Err(GkrmError::TrustedTransactionalApplyExecutionLockContention) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLockContention);
        }
        Err(GkrmError::TrustedTransactionalApplyExecutionTransactionExists) => {
            return Err(GkrmError::TrustedCliUpdateTransactionAlreadyPublished);
        }
        Err(_other) => {
            let publication = publication_state::classify_apply_failure_publication_state(
                &authority.transaction_root,
                prepared.live_tx_plan.plan_id().digest(),
                &options,
            );
            let outcome = publication_state::outcome_for_classified_apply_failure(publication);
            return Ok(apply_report(outcome, artifact.artifact_id().to_hex()));
        }
    };

    let outcome = match exec {
        TrustedTransactionResult::Committed(_) => "committed",
        TrustedTransactionResult::RolledBack(_) => "rolled_back",
        TrustedTransactionResult::RecoveryRequired(_) => "recovery_required",
    };
    Ok(apply_report(outcome, artifact.artifact_id().to_hex()))
}

#[cfg(test)]
fn apply_trusted_desktop_update_with_test_hooks(
    request: TrustedDesktopApplyRequest<'_>,
    hooks: test_hooks::TrustedCliPlanTestHooks,
) -> Result<TrustedCliReport> {
    test_hooks::with_hooks(hooks, || apply_trusted_desktop_update(request))
}

struct PreparedDesktopApplyInputs {
    baseline: crate::ResolvedOfficialBaseline,
    bundle: crate::TrustedStagingBundle,
    plan: crate::ThreeWayUpdatePlan,
    review: crate::ThreeWayPlanReview,
    merge_ids: Option<PackageFreeMergeChainIds>,
    merged_bytes: Option<crate::ThreeWayMergedBytesPlan>,
    installed_apply: InstalledApplyPlanningSource,
    live_apply_plan: crate::TrustedApplyPlan,
    live_tx_plan: crate::TrustedTransactionalApplyPlan,
    recovery_publication: Option<RecoveryAuthorityPublication>,
}

fn prepare_desktop_apply_inputs(
    authority: &TrustedDesktopApplyAuthority,
    artifact: &TrustedCliUpdateArtifact,
) -> Result<PreparedDesktopApplyInputs> {
    let descriptor = artifact
        .apply_descriptor()
        .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
    if descriptor.version() != TrustedCliApplyDescriptor::VERSION {
        return Err(GkrmError::TrustedCliUpdateArtifactVersionUnsupported);
    }
    let resource_key = descriptor.resource_key()?;
    let baseline_id = descriptor.baseline_id()?;
    let selected_installed_root = descriptor.selected_installed_root()?;
    if resource_key != authority.resource_key
        || selected_installed_root != authority.selected_installed_root
    {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    verify_selected_resource_commitment(
        &authority.resource_key,
        &artifact.body().selected_resource_commitment,
    )
    .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    if descriptor.incoming_package_fingerprint()? != artifact.body().package_fingerprint {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    let body_baseline_digest = Sha256Digest::from_lowercase_hex(baseline_id.as_str())
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    if body_baseline_digest != artifact.body().baseline_id_digest {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }

    let baseline = resolve_official_baseline(BaselineResolutionRequest::try_new(
        &authority.baseline_store,
        &resource_key,
        OfficialBaselineSelector::Exact(baseline_id.clone()),
        BaselineResolutionOptions::default(),
    )?)?;
    if baseline.resource_key() != &resource_key || baseline.baseline_id() != &baseline_id {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    verify_selected_resource_commitment(
        &resource_key,
        &artifact.body().selected_resource_commitment,
    )
    .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;

    let staging_options = TrustedStagingOptions::default();
    let staging_root = TrustedStagingRoot::try_open(&authority.staging_root)?;
    let bundle = reopen_trusted_staging_bundle_from_artifact(
        &staging_root,
        artifact.body(),
        &resource_key,
        &baseline_id,
        &descriptor.installed_snapshot_fingerprint()?,
        &descriptor.incoming_package_fingerprint()?,
        &descriptor.incoming_resource_fingerprint()?,
        staging_options,
    )?;
    verify_published_bundle_readonly(
        bundle.published_dir_for_apply_planning(),
        bundle.resource_dir_for_apply_planning(),
        bundle.manifest(),
    )?;
    bundle
        .staging_root_for_apply_planning()
        .revalidate_identity()?;
    #[cfg(test)]
    test_hooks::after_published_bundle_verified_before_descriptor_graph();

    let installed_apply = InstalledApplyPlanningSource::try_new(
        &authority.installed,
        selected_installed_root,
        InstalledScanLimits::default(),
    )?;
    if installed_apply.installed_root_identity() != &authority.installed_root_identity
        || installed_apply.selected_resource_identity() != &authority.selected_resource_identity
    {
        return Err(GkrmError::TrustedApplyPlanningInstalledStale);
    }
    let (plan, review, merge_ids, merged_bytes) = descriptor_apply_graph(
        &resource_key,
        &baseline_id,
        descriptor,
        artifact.body(),
        &bundle,
        staging_options.max_file_bytes(),
    )?;
    let derivation = reconstruct_recovery_derivation(
        1,
        1,
        RecoveryDerivationRequestV1 {
            bundle: &bundle,
            plan: &plan,
            review: &review,
            merge_ids,
            merged_bytes: merged_bytes.as_ref(),
            baseline: &baseline,
            installed_source: &installed_apply,
        },
    )?;
    let live_apply_plan = derivation.apply_plan;
    let live_snapshot = derivation.snapshot;
    let live_tx_plan = derivation.transactional_plan;
    let snapshot_a = live_snapshot.fingerprint;

    let live_body = TrustedCliUpdateArtifactBody {
        apply_plan_id: *live_apply_plan.plan_id().digest(),
        snapshot_a,
        transactional_plan_id: *live_tx_plan.plan_id().digest(),
        ..artifact.body().clone()
    };
    if artifact.body() != &live_body {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    let recovery_publication = if artifact.version() == artifact::ARTIFACT_V2_FORMAT_VERSION {
        let expected = artifact
            .body()
            .recovery_authority_id
            .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
        let (authority_body, authority_id) = build_recovery_authority_body(
            &installed_apply,
            &resource_key,
            artifact.body().baseline_id_digest,
            artifact.body().staging_manifest_id,
            artifact.body().staging_bundle_id,
            *live_apply_plan.plan_id().digest(),
            *live_tx_plan.plan_id().digest(),
            &live_snapshot,
            RecoveryAuthorityLimits::default(),
        )?;
        if authority_body.selected_resource_commitment
            != artifact.body().selected_resource_commitment
            || authority_id.digest() != &expected
        {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        Some(RecoveryAuthorityPublication::new(
            authority_body,
            authority_id,
            *artifact.artifact_id().digest(),
        ))
    } else {
        if artifact.body().recovery_authority_id.is_some() {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        None
    };

    Ok(PreparedDesktopApplyInputs {
        baseline,
        bundle,
        plan,
        review,
        merge_ids,
        merged_bytes,
        installed_apply,
        live_apply_plan,
        live_tx_plan,
        recovery_publication,
    })
}

pub(crate) type DescriptorApplyGraph = (
    crate::ThreeWayUpdatePlan,
    crate::ThreeWayPlanReview,
    Option<PackageFreeMergeChainIds>,
    Option<crate::ThreeWayMergedBytesPlan>,
);

pub(crate) fn descriptor_apply_graph(
    resource_key: &SafeResourceKey,
    baseline_id: &crate::BaselineId,
    descriptor: &TrustedCliApplyDescriptor,
    body: &TrustedCliUpdateArtifactBody,
    bundle: &crate::TrustedStagingBundle,
    max_staged_file_bytes: u64,
) -> Result<DescriptorApplyGraph> {
    let plan_entries = descriptor.plan_entries()?;
    let review_entries = descriptor.review_entries()?;
    if plan_entries.len() != bundle.manifest().entries().len() {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    for (plan_entry, bundle_entry) in plan_entries.iter().zip(bundle.manifest().entries()) {
        if plan_entry.path() != bundle_entry.path() {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
    }
    let plan = crate::ThreeWayUpdatePlan::from_desktop_apply_descriptor(
        resource_key.clone(),
        baseline_id.clone(),
        body.plan_id,
        descriptor.installed_snapshot_fingerprint()?,
        descriptor.incoming_package_fingerprint()?,
        descriptor.incoming_resource_fingerprint()?,
        plan_entries,
    );
    let review = crate::ThreeWayPlanReview::from_desktop_apply_descriptor(
        &plan,
        body.review_id,
        review_entries,
    );
    let merge_ids = (
        bundle.manifest().analysis_id_digest().copied(),
        bundle.manifest().text_diff_id_digest().copied(),
        bundle.manifest().synthesis_id_digest().copied(),
        bundle.manifest().merged_bytes_id_digest().copied(),
    );
    let (merge_ids, merged_bytes) = match merge_ids {
        (None, None, None, None) => (None, None),
        (Some(analysis_id), Some(text_diff_id), Some(synthesis_id), Some(merged_bytes_id)) => {
            let mut merged_entries = Vec::new();
            for review_entry in review.entries() {
                if review_entry.action() != ThreeWayReviewedAction::QueueMergeAnalysis {
                    continue;
                }
                let bundle_entry = bundle
                    .manifest()
                    .entries()
                    .iter()
                    .find(|entry| entry.path() == review_entry.path())
                    .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
                let artifact_id = match bundle_entry.source_binding() {
                    StagingSourceBinding::MergedArtifact(id) => *id.digest(),
                    StagingSourceBinding::OperatorMerge(id) => *id,
                    _ => return Err(GkrmError::TrustedCliUpdateBindingMismatch),
                };
                let digest = bundle_entry
                    .expected_digest()
                    .copied()
                    .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
                let len = bundle_entry
                    .expected_byte_length()
                    .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
                let bytes = read_staged_resource_file(
                    bundle,
                    review_entry.path(),
                    digest,
                    len,
                    max_staged_file_bytes,
                )?;
                merged_entries.push((review_entry.path().clone(), artifact_id, digest, bytes));
            }
            let merged_bytes = crate::ThreeWayMergedBytesPlan::from_desktop_apply_descriptor(
                &plan,
                &review,
                analysis_id,
                text_diff_id,
                synthesis_id,
                merged_bytes_id,
                merged_entries,
            )?;
            (
                Some(PackageFreeMergeChainIds {
                    analysis_id,
                    text_diff_id,
                    synthesis_id,
                    merged_bytes_id,
                }),
                Some(merged_bytes),
            )
        }
        _ => return Err(GkrmError::TrustedCliUpdateBindingMismatch),
    };
    Ok((plan, review, merge_ids, merged_bytes))
}

fn read_staged_resource_file(
    bundle: &crate::TrustedStagingBundle,
    path: &crate::ResourceRelativePath,
    expected_digest: Sha256Digest,
    expected_len: u64,
    max_staged_file_bytes: u64,
) -> Result<Box<[u8]>> {
    if expected_len == 0 || expected_len > max_staged_file_bytes {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    let read_limit = expected_len
        .checked_add(1)
        .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
    let expected_capacity =
        usize::try_from(expected_len).map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let components: Vec<_> = path.as_str().split('/').collect();
    let (file_name, parent_components) = components
        .split_last()
        .ok_or(GkrmError::TrustedCliUpdateBindingMismatch)?;
    let mut parent = bundle
        .resource_dir_for_apply_planning()
        .try_clone()
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    for component in parent_components {
        parent = open_child_dir(&parent, component)
            .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    }
    let file = open_file_nofollow(&parent, file_name)
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    verify_regular_file(&file, file_name)
        .map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    let mut bytes = Vec::with_capacity(expected_capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|e| GkrmError::TrustedCliUpdateIo { kind: e.kind() })?;
    let actual_len =
        u64::try_from(bytes.len()).map_err(|_| GkrmError::TrustedCliUpdateBindingMismatch)?;
    if actual_len != expected_len {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    let actual_digest = Sha256Digest::new(Sha256::digest(&bytes).into());
    if actual_digest != expected_digest {
        return Err(GkrmError::TrustedCliUpdateBindingMismatch);
    }
    Ok(bytes.into_boxed_slice())
}

pub fn status_trusted_cli_update(request: TrustedCliStatusRequest<'_>) -> Result<TrustedCliReport> {
    status_trusted_cli_update_inner(request, None)
}

use crate::{
    BaselineEscrowClass as EscrowClassForLineViews, ResourceRelativePath as LineViewPath,
    ThreeWayFileState as LineViewFileState, ThreeWayUpdatePlan as LineViewPlan,
};

/// Whether a path may ever carry an operator-facing merged line view.
///
/// Escrow class is a manifest property, so only the baseline and incoming sides can declare
/// one; the installed tree never does. A file that exists only in the customer's installation
/// therefore declares nothing, and calling that "protected" would be a false claim about
/// content the customer owns outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineViewEligibility {
    /// Every declared side is escrow-ignored. A line view may be produced.
    Ignored,
    /// Some declared side is escrow-protected or unsupported. Content is never retained or shown.
    Protected,
    /// No side declares a class, so there is nothing to protect and nothing to merge.
    Undeclared,
}

/// Classify every planned path for line-view purposes.
pub fn line_view_eligibility(plan: &LineViewPlan) -> Vec<(LineViewPath, LineViewEligibility)> {
    fn declared_class(state: &LineViewFileState) -> Option<EscrowClassForLineViews> {
        match state {
            LineViewFileState::Absent => None,
            LineViewFileState::Present { escrow_class, .. } => *escrow_class,
        }
    }

    plan.entries()
        .iter()
        .map(|entry| {
            let declared: Vec<_> = [
                declared_class(entry.baseline_state()),
                declared_class(entry.incoming_state()),
            ]
            .into_iter()
            .flatten()
            .collect();
            let eligibility = if declared.is_empty() {
                LineViewEligibility::Undeclared
            } else if declared
                .iter()
                .all(|class| *class == EscrowClassForLineViews::Ignored)
            {
                LineViewEligibility::Ignored
            } else {
                LineViewEligibility::Protected
            };
            (entry.path().clone(), eligibility)
        })
        .collect()
}

/// The allowlist for merged line views: paths whose every declared side is escrow-ignored.
pub fn escrow_ignored_line_view_paths(plan: &LineViewPlan) -> Vec<LineViewPath> {
    line_view_eligibility(plan)
        .into_iter()
        .filter(|(_, eligibility)| *eligibility == LineViewEligibility::Ignored)
        .map(|(path, _)| path)
        .collect()
}

pub fn status_trusted_cli_update_in_workspace(
    request: TrustedCliStatusRequest<'_>,
    workspace: &TrustedUpdateWorkspace,
) -> Result<TrustedCliReport> {
    workspace.revalidate_transaction_root(request.transaction_root)?;
    status_trusted_cli_update_inner(request, Some(workspace))
}

fn status_trusted_cli_update_inner(
    request: TrustedCliStatusRequest<'_>,
    workspace: Option<&TrustedUpdateWorkspace>,
) -> Result<TrustedCliReport> {
    let options = request.options.validate()?;
    let root = match workspace {
        Some(workspace) => TrustedTransactionRoot::try_open_in_workspace(workspace)?,
        None => TrustedTransactionRoot::try_open(request.transaction_root)?,
    };
    let retired_plan_ids = match workspace {
        Some(_) => {
            crate::trusted_package_free_update_recovery::validated_retired_terminal_plan_ids(
                &root,
                options.max_journal_records,
            )?
        }
        None => std::collections::BTreeSet::new(),
    };
    let scan = scan_trusted_transactions(
        &root,
        TrustedRecoveryScanOptions {
            max_transactions: options.max_transactions,
            max_journal_records: options.max_journal_records,
            ..TrustedRecoveryScanOptions::default()
        },
    )?;
    let mut selectors = Vec::new();
    let mut bound = 0usize;
    let mut malformed = 0usize;
    let mut candidates: Vec<_> = scan.candidates().iter().collect();
    candidates.sort_by_key(|c| c.candidate_id().to_selector_hex());
    for c in candidates {
        if c.proven_plan_id
            .is_some_and(|plan_id| retired_plan_ids.contains(&plan_id))
        {
            continue;
        }
        selectors.push(c.candidate_id().to_selector_hex());
        match c.kind() {
            TrustedRecoveryCandidateKind::Bound => bound += 1,
            TrustedRecoveryCandidateKind::Malformed => malformed += 1,
        }
    }
    Ok(TrustedCliReport {
        outcome: "status",
        pending_paths: Vec::new(),
        artifact_id_hex: None,
        candidate_selectors: selectors,
        bound_candidates: bound,
        malformed_candidates: malformed,
    })
}

pub fn recover_trusted_cli_update(
    request: TrustedCliRecoverRequest<'_>,
) -> Result<TrustedCliReport> {
    recover_trusted_cli_update_inner(request, None)
}

pub fn recover_trusted_cli_update_in_workspace(
    request: TrustedCliRecoverRequest<'_>,
    workspace: &TrustedUpdateWorkspace,
) -> Result<TrustedCliReport> {
    let artifact_root = request
        .artifact
        .parent()
        .ok_or(GkrmError::TrustedUpdateWorkspaceInvalid)?;
    workspace.revalidate_explicit_roots(
        request.baseline_store,
        request.staging_root,
        request.transaction_root,
        artifact_root,
    )?;
    recover_trusted_cli_update_inner(request, Some(workspace))
}

fn recover_trusted_cli_update_inner(
    request: TrustedCliRecoverRequest<'_>,
    workspace: Option<&TrustedUpdateWorkspace>,
) -> Result<TrustedCliReport> {
    let options = request.options.validate()?;
    let wanted = TrustedRecoveryCandidateId::from_selector_hex(request.candidate)?;
    let bytes = read_regular_file_limited(request.artifact, options.max_artifact_bytes)?;
    let artifact = parse_cli_artifact(&bytes, &options)?;

    let live =
        rebind::rebuild_trusted_cli_update_authority(&rebind::TrustedCliUpdateRebindRequest {
            package: request.package,
            installed: request.installed,
            baseline_store: request.baseline_store,
            baseline_selector: request.baseline_selector.clone(),
            resource: request.resource,
            staging_root: request.staging_root,
            decisions_path: request.decisions_path,
            operator_merge_root: request.operator_merge_root,
            recovery_authority: artifact.version() == artifact::ARTIFACT_V2_FORMAT_VERSION,
            options,
        })?;
    rebind::require_cli_artifact_matches_live_authority(&artifact, &live)?;

    // Point-of-use staging verify and artifact reopen before Task 24 recovery.
    {
        let again = read_regular_file_limited(request.artifact, options.max_artifact_bytes)?;
        let again_art = parse_cli_artifact(&again, &options)?;
        if again_art.artifact_id().digest() != artifact.artifact_id().digest() {
            return Err(GkrmError::TrustedCliUpdateBindingMismatch);
        }
        verify_published_bundle_readonly(
            live.bundle.published_dir_for_apply_planning(),
            live.bundle.resource_dir_for_apply_planning(),
            live.bundle.manifest(),
        )?;
        live.bundle
            .staging_root_for_apply_planning()
            .revalidate_identity()?;
    }

    let root = match workspace {
        Some(workspace) => TrustedTransactionRoot::try_open_in_workspace(workspace)?,
        None => TrustedTransactionRoot::try_open(request.transaction_root)?,
    };
    let scan = scan_trusted_transactions(
        &root,
        TrustedRecoveryScanOptions {
            max_transactions: options.max_transactions,
            max_journal_records: options.max_journal_records,
            ..TrustedRecoveryScanOptions::default()
        },
    )?;
    let matches: Vec<_> = scan
        .candidates()
        .iter()
        .filter(|c| c.candidate_id() == &wanted)
        .collect();
    let candidate = match matches.as_slice() {
        [one] if one.kind() == TrustedRecoveryCandidateKind::Bound => *one,
        [] => return Err(GkrmError::TrustedCliUpdateCandidateNotFound),
        _ => return Err(GkrmError::TrustedCliUpdateCandidateAmbiguous),
    };
    if let (Some(_), Some(plan_id)) = (workspace, candidate.proven_plan_id) {
        if crate::trusted_package_free_update_recovery::validated_retired_terminal_plan_ids(
            &root,
            options.max_journal_records,
        )?
        .contains(&plan_id)
        {
            return Err(GkrmError::TrustedCliUpdateCandidateNotFound);
        }
    }

    let recovered = match recover_trusted_transaction(TrustedTransactionRecoveryRequest::try_new(
        candidate,
        &live.tx_plan,
        &live.apply_plan,
        &live.bundle,
        &live.plan,
        &live.review,
        live.analysis.as_ref(),
        live.text_diff.as_ref(),
        live.synthesis.as_ref(),
        live.merged_bytes.as_ref(),
        &live.baseline,
        &live.installed_apply,
        &root,
        request.package,
        TrustedRecoveryOptions::default(),
    )?) {
        Ok(r) => r,
        Err(GkrmError::TrustedTransactionalApplyExecutionLockContention) => {
            return Err(GkrmError::TrustedTransactionalApplyExecutionLockContention);
        }
        Err(e) => return Err(e),
    };

    let outcome = match recovered {
        TrustedRecoveryResult::RecoveredCommitted(_) => "recovered_committed",
        TrustedRecoveryResult::RecoveredRolledBack(_) => "recovered_rolled_back",
        TrustedRecoveryResult::SafeRestart(_) => "safe_restart",
        TrustedRecoveryResult::RecoveryStillRequired(_) => "recovery_still_required",
    };
    Ok(TrustedCliReport {
        outcome,
        pending_paths: Vec::new(),
        artifact_id_hex: Some(artifact.artifact_id().to_hex()),
        candidate_selectors: vec![wanted.to_selector_hex()],
        bound_candidates: 1,
        malformed_candidates: 0,
    })
}

#[cfg(test)]
mod task29_workspace_publication_tests {
    use super::*;
    use crate::{resolve_trusted_update_workspace, TrustedUpdateWorkspaceOptions};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use tempfile::tempdir;

    #[test]
    fn locked_publication_rechecks_capacity_after_competing_writer() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let options = TrustedUpdateWorkspaceOptions {
            max_plan_artifacts: 1,
            ..TrustedUpdateWorkspaceOptions::default()
        };
        crate::enforce_trusted_update_workspace_capacity_for_new_plan_artifact(
            &workspace, options, 4,
        )
        .unwrap();
        crate::enforce_trusted_update_workspace_capacity_for_new_plan_artifact(
            &workspace, options, 4,
        )
        .unwrap();

        let first = workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        let second = workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        publish_plan_artifact_with_optional_workspace_capacity(
            Some(&workspace),
            options,
            &first,
            b"aaaa",
        )
        .unwrap();
        let err = publish_plan_artifact_with_optional_workspace_capacity(
            Some(&workspace),
            options,
            &second,
            b"bbbb",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
        ));
        assert!(first.exists());
        assert!(!second.exists());
        let usage = crate::enforce_trusted_update_workspace_capacity(
            &workspace,
            TrustedUpdateWorkspaceOptions::default(),
        )
        .unwrap();
        assert_eq!(usage.plan_artifacts(), 1);
    }

    #[test]
    fn locked_publication_exact_boundary_succeeds_and_one_byte_over_fails() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let exact = workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        let options = TrustedUpdateWorkspaceOptions {
            max_regular_file_bytes: 4,
            max_individual_artifact_bytes: 4,
            max_plan_artifacts: 1,
            ..TrustedUpdateWorkspaceOptions::default()
        };
        publish_plan_artifact_with_optional_workspace_capacity(
            Some(&workspace),
            options,
            &exact,
            b"1234",
        )
        .unwrap();

        let other_temp = tempdir().unwrap();
        let other_workspace = resolve_trusted_update_workspace(other_temp.path()).unwrap();
        let over = other_workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        let err = publish_plan_artifact_with_optional_workspace_capacity(
            Some(&other_workspace),
            options,
            &over,
            b"12345",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            GkrmError::TrustedUpdateWorkspaceCapacityReached
        ));
        assert!(!over.exists());
    }

    #[test]
    fn locked_publication_rejects_existing_destination_without_overwrite() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let artifact = workspace
            .artifact_root()
            .allocate_plan_artifact_path()
            .unwrap();
        std::fs::write(&artifact, b"old").unwrap();
        let err = publish_plan_artifact_with_optional_workspace_capacity(
            Some(&workspace),
            TrustedUpdateWorkspaceOptions::default(),
            &artifact,
            b"new",
        )
        .unwrap_err();
        assert!(matches!(err, GkrmError::TrustedCliUpdateDestinationExists));
        assert_eq!(std::fs::read(&artifact).unwrap(), b"old");
    }

    fn run_publication_child(root: &std::path::Path, name: &str, bytes: &str) -> String {
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("trusted_cli_update_artifact::task29_workspace_publication_tests::publication_race_child_process")
            .arg("--exact")
            .arg("--nocapture")
            .env("GKRM_PUBLICATION_CHILD_ROOT", root)
            .env("GKRM_PUBLICATION_CHILD_NAME", name)
            .env("GKRM_PUBLICATION_CHILD_BYTES", bytes)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[derive(Clone, Copy)]
    struct RaceLimits {
        max_regular_file_bytes: u64,
        max_directory_entries: usize,
        max_plan_artifacts: usize,
        max_individual_artifact_bytes: u64,
    }

    impl RaceLimits {
        fn from_env() -> Self {
            Self {
                max_regular_file_bytes: std::env::var("GKRM_PUBLICATION_MAX_BYTES")
                    .unwrap()
                    .parse()
                    .unwrap(),
                max_directory_entries: std::env::var("GKRM_PUBLICATION_MAX_ENTRIES")
                    .unwrap()
                    .parse()
                    .unwrap(),
                max_plan_artifacts: std::env::var("GKRM_PUBLICATION_MAX_ARTIFACTS")
                    .unwrap()
                    .parse()
                    .unwrap(),
                max_individual_artifact_bytes: std::env::var("GKRM_PUBLICATION_MAX_INDIVIDUAL")
                    .unwrap()
                    .parse()
                    .unwrap(),
            }
        }

        fn options(self) -> TrustedUpdateWorkspaceOptions {
            TrustedUpdateWorkspaceOptions {
                max_regular_file_bytes: self.max_regular_file_bytes,
                max_directory_entries: self.max_directory_entries,
                max_plan_artifacts: self.max_plan_artifacts,
                max_individual_artifact_bytes: self.max_individual_artifact_bytes,
            }
        }
    }

    struct RaceChild {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
    }

    impl RaceChild {
        fn spawn(
            role: &str,
            root: &std::path::Path,
            name: &str,
            bytes: &str,
            limits: RaceLimits,
        ) -> Self {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("trusted_cli_update_artifact::task29_workspace_publication_tests::publication_ab_race_child_process")
                .arg("--exact")
                .arg("--nocapture")
                .env("GKRM_PUBLICATION_AB_ROLE", role)
                .env("GKRM_PUBLICATION_CHILD_ROOT", root)
                .env("GKRM_PUBLICATION_CHILD_NAME", name)
                .env("GKRM_PUBLICATION_CHILD_BYTES", bytes)
                .env("GKRM_PUBLICATION_MAX_BYTES", limits.max_regular_file_bytes.to_string())
                .env("GKRM_PUBLICATION_MAX_ENTRIES", limits.max_directory_entries.to_string())
                .env("GKRM_PUBLICATION_MAX_ARTIFACTS", limits.max_plan_artifacts.to_string())
                .env("GKRM_PUBLICATION_MAX_INDIVIDUAL", limits.max_individual_artifact_bytes.to_string())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            let stdout = BufReader::new(child.stdout.take().unwrap());
            Self {
                child,
                stdin,
                stdout,
            }
        }

        fn read_line(&mut self) -> String {
            loop {
                let mut line = String::new();
                self.stdout.read_line(&mut line).unwrap();
                assert!(!line.is_empty(), "child closed stdout before protocol line");
                let trimmed = line.trim();
                if trimmed.starts_with("A_") || trimmed.starts_with("B_") {
                    return trimmed.to_owned();
                }
            }
        }

        fn send(&mut self, line: &str) {
            writeln!(self.stdin, "{line}").unwrap();
            self.stdin.flush().unwrap();
        }

        fn wait_ok(self) {
            drop(self.stdin);
            let output = self.child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "child failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    fn current_usage(root: &std::path::Path) -> crate::TrustedUpdateWorkspaceUsage {
        let workspace = resolve_trusted_update_workspace(root).unwrap();
        crate::enforce_trusted_update_workspace_capacity(
            &workspace,
            TrustedUpdateWorkspaceOptions::default(),
        )
        .unwrap()
    }

    fn run_ab_retry_protocol(
        limit_builder: impl FnOnce(&std::path::Path) -> RaceLimits,
        a_name: &str,
        a_bytes: &str,
        b_name: &str,
        b_bytes: &str,
        expected_b_retry: &str,
        expect_a_artifact: bool,
    ) {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let limits = limit_builder(temp.path());
        let mut a = RaceChild::spawn("A", temp.path(), a_name, a_bytes, limits);
        assert_eq!(a.read_line(), "A_LOCKED_IN_PRODUCTION");
        let mut b = RaceChild::spawn("B", temp.path(), b_name, b_bytes, limits);
        assert_eq!(b.read_line(), "B_BLOCKED");
        assert!(!workspace.artifact_root().path().join(b_name).exists());
        a.send("A_CONTINUE");
        assert_eq!(a.read_line(), "A_PUBLISHED_AND_RELEASED");
        b.send("B_RETRY");
        assert_eq!(b.read_line(), expected_b_retry);
        a.wait_ok();
        b.wait_ok();
        assert_eq!(
            workspace.artifact_root().path().join(a_name).exists(),
            expect_a_artifact
        );
        if expected_b_retry != "B_RETRY_OK" && a_name != b_name {
            assert!(!workspace.artifact_root().path().join(b_name).exists());
        }
        let usage =
            crate::enforce_trusted_update_workspace_capacity(&workspace, limits.options()).unwrap();
        assert!(usage.regular_file_bytes() <= limits.max_regular_file_bytes);
        assert!(usage.directory_entries() <= limits.max_directory_entries);
        assert!(usage.plan_artifacts() <= limits.max_plan_artifacts);
        assert!(workspace.app_root().join(".publication.lock").exists());
    }

    #[test]
    fn separate_process_publication_rescans_after_first_artifact_consumes_capacity() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let first = run_publication_child(temp.path(), "plan-a.bin", "1234");
        assert!(first.contains("gkrm-publication-child-ok"));
        let second = run_publication_child(temp.path(), "plan-b.bin", "1234");
        assert!(second.contains("gkrm-publication-child-capacity"));
        assert!(workspace.artifact_root().path().join("plan-a.bin").exists());
        assert!(!workspace.artifact_root().path().join("plan-b.bin").exists());
        let usage = crate::enforce_trusted_update_workspace_capacity(
            &workspace,
            TrustedUpdateWorkspaceOptions {
                max_regular_file_bytes: 4,
                max_directory_entries: 8,
                max_plan_artifacts: 1,
                max_individual_artifact_bytes: 4,
            },
        )
        .unwrap();
        assert_eq!(usage.plan_artifacts(), 1);
        assert_eq!(usage.largest_artifact_bytes(), 4);
    }

    #[test]
    fn separate_process_publication_releases_lock_after_destination_collision() {
        let temp = tempdir().unwrap();
        let workspace = resolve_trusted_update_workspace(temp.path()).unwrap();
        let collision = workspace.artifact_root().path().join("same.bin");
        std::fs::write(&collision, b"o").unwrap();
        let first = run_publication_child(temp.path(), "same.bin", "n");
        assert!(first.contains("gkrm-publication-child-destination"));
        let second = run_publication_child(temp.path(), "other.bin", "n");
        assert!(second.contains("gkrm-publication-child-ok"));
        assert_eq!(std::fs::read(&collision).unwrap(), b"o");
        assert!(workspace.artifact_root().path().join("other.bin").exists());
    }

    #[test]
    fn ab_race_regular_file_byte_capacity_retries_and_rescans() {
        run_ab_retry_protocol(
            |root| {
                let usage = current_usage(root);
                RaceLimits {
                    max_regular_file_bytes: usage.regular_file_bytes() + 4,
                    max_directory_entries: usage.directory_entries() + 8,
                    max_plan_artifacts: usage.plan_artifacts() + 8,
                    max_individual_artifact_bytes: 4,
                }
            },
            "plan-a-bytes.bin",
            "1234",
            "plan-b-bytes.bin",
            "1",
            "B_RETRY_CAPACITY",
            true,
        );
    }

    #[test]
    fn ab_race_directory_entry_capacity_retries_and_rescans() {
        run_ab_retry_protocol(
            |root| {
                let usage = current_usage(root);
                RaceLimits {
                    max_regular_file_bytes: usage.regular_file_bytes() + 100,
                    max_directory_entries: usage.directory_entries() + 1,
                    max_plan_artifacts: usage.plan_artifacts() + 8,
                    max_individual_artifact_bytes: 100,
                }
            },
            "plan-a-entry.bin",
            "a",
            "plan-b-entry.bin",
            "b",
            "B_RETRY_CAPACITY",
            true,
        );
    }

    #[test]
    fn ab_race_artifact_count_capacity_retries_and_rescans() {
        run_ab_retry_protocol(
            |root| {
                let usage = current_usage(root);
                RaceLimits {
                    max_regular_file_bytes: usage.regular_file_bytes() + 100,
                    max_directory_entries: usage.directory_entries() + 8,
                    max_plan_artifacts: usage.plan_artifacts() + 1,
                    max_individual_artifact_bytes: 100,
                }
            },
            "plan-a-count.bin",
            "a",
            "plan-b-count.bin",
            "b",
            "B_RETRY_CAPACITY",
            true,
        );
    }

    #[test]
    fn ab_race_exact_boundary_publication_then_retry_rejects() {
        run_ab_retry_protocol(
            |root| {
                let usage = current_usage(root);
                RaceLimits {
                    max_regular_file_bytes: usage.regular_file_bytes() + 4,
                    max_directory_entries: usage.directory_entries() + 1,
                    max_plan_artifacts: usage.plan_artifacts() + 1,
                    max_individual_artifact_bytes: 4,
                }
            },
            "plan-a-exact.bin",
            "1234",
            "plan-b-exact.bin",
            "1",
            "B_RETRY_CAPACITY",
            true,
        );
    }

    #[test]
    fn ab_race_a_publication_failure_releases_lock_for_b_success() {
        run_ab_retry_protocol(
            |root| {
                let usage = current_usage(root);
                RaceLimits {
                    max_regular_file_bytes: usage.regular_file_bytes() + 16,
                    max_directory_entries: usage.directory_entries() + 8,
                    max_plan_artifacts: usage.plan_artifacts() + 8,
                    max_individual_artifact_bytes: 16,
                }
            },
            "invalid/name.bin",
            "a",
            "plan-b-after-failure.bin",
            "b",
            "B_RETRY_OK",
            false,
        );
    }

    #[test]
    fn ab_race_no_replace_destination_collision_after_retry() {
        run_ab_retry_protocol(
            |root| {
                let usage = current_usage(root);
                RaceLimits {
                    max_regular_file_bytes: usage.regular_file_bytes() + 16,
                    max_directory_entries: usage.directory_entries() + 8,
                    max_plan_artifacts: usage.plan_artifacts() + 8,
                    max_individual_artifact_bytes: 16,
                }
            },
            "plan-collision.bin",
            "a",
            "plan-collision.bin",
            "new",
            "B_RETRY_DESTINATION",
            true,
        );
    }

    #[test]
    fn publication_race_child_process() {
        let Ok(root) = std::env::var("GKRM_PUBLICATION_CHILD_ROOT") else {
            return;
        };
        let name = std::env::var("GKRM_PUBLICATION_CHILD_NAME").unwrap();
        let bytes = std::env::var("GKRM_PUBLICATION_CHILD_BYTES").unwrap();
        let workspace = resolve_trusted_update_workspace(std::path::Path::new(&root)).unwrap();
        let artifact = workspace.artifact_root().path().join(name);
        let result = publish_plan_artifact_with_optional_workspace_capacity(
            Some(&workspace),
            TrustedUpdateWorkspaceOptions {
                max_regular_file_bytes: 4,
                max_directory_entries: 8,
                max_plan_artifacts: 1,
                max_individual_artifact_bytes: 4,
            },
            &artifact,
            bytes.as_bytes(),
        );
        match result {
            Ok(()) => println!("gkrm-publication-child-ok"),
            Err(GkrmError::TrustedUpdateWorkspaceCapacityReached) => {
                println!("gkrm-publication-child-capacity")
            }
            Err(GkrmError::TrustedCliUpdateDestinationExists) => {
                println!("gkrm-publication-child-destination")
            }
            Err(error) => panic!("unexpected child error: {error:?}"),
        }
    }

    #[test]
    fn publication_ab_race_child_process() {
        let Ok(role) = std::env::var("GKRM_PUBLICATION_AB_ROLE") else {
            return;
        };
        let root = std::env::var("GKRM_PUBLICATION_CHILD_ROOT").unwrap();
        let name = std::env::var("GKRM_PUBLICATION_CHILD_NAME").unwrap();
        let bytes = std::env::var("GKRM_PUBLICATION_CHILD_BYTES").unwrap();
        let limits = RaceLimits::from_env();
        let workspace = resolve_trusted_update_workspace(std::path::Path::new(&root)).unwrap();
        let artifact = workspace.artifact_root().path().join(name);
        match role.as_str() {
            "A" => {
                PAUSE_AFTER_PRODUCTION_PUBLICATION_LOCK
                    .store(true, std::sync::atomic::Ordering::Release);
                let result = publish_plan_artifact_with_optional_workspace_capacity(
                    Some(&workspace),
                    limits.options(),
                    &artifact,
                    bytes.as_bytes(),
                );
                match result {
                    Ok(()) => assert!(artifact.exists()),
                    Err(_) => assert!(!artifact.exists()),
                }
                println!("A_PUBLISHED_AND_RELEASED");
            }
            "B" => {
                let first = publish_plan_artifact_with_optional_workspace_capacity(
                    Some(&workspace),
                    limits.options(),
                    &artifact,
                    bytes.as_bytes(),
                );
                assert!(matches!(
                    first,
                    Err(GkrmError::TrustedUpdateWorkspaceCapacityReached)
                ));
                assert!(!artifact.exists());
                println!("B_BLOCKED");
                std::io::stdout().flush().unwrap();
                let mut command = String::new();
                std::io::stdin().read_line(&mut command).unwrap();
                assert_eq!(command.trim(), "B_RETRY");
                let second = publish_plan_artifact_with_optional_workspace_capacity(
                    Some(&workspace),
                    limits.options(),
                    &artifact,
                    bytes.as_bytes(),
                );
                match second {
                    Ok(()) => println!("B_RETRY_OK"),
                    Err(GkrmError::TrustedUpdateWorkspaceCapacityReached) => {
                        assert!(!artifact.exists());
                        println!("B_RETRY_CAPACITY");
                    }
                    Err(GkrmError::TrustedCliUpdateDestinationExists) => {
                        println!("B_RETRY_DESTINATION");
                    }
                    Err(error) => panic!("unexpected B error: {error:?}"),
                }
            }
            other => panic!("unexpected role {other}"),
        }
    }
}
