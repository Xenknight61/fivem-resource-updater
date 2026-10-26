pub mod baseline;
pub mod baseline_free_plan;
pub mod comparison;
#[cfg(all(feature = "desktop-test-support", debug_assertions))]
pub mod desktop_test_support;
pub mod error;
pub mod escrow_classification;
mod file_identity;
pub mod inspection;
pub mod installed_path;
pub mod installed_scan;
mod json_merge;
pub mod manifest;
mod merge_content;
pub mod package_limits;
mod package_source;
pub mod resource_discovery;
mod three_way_fingerprint;
pub mod three_way_merge_analysis;
pub mod three_way_merge_synthesis;
pub mod three_way_merged_bytes;
pub mod three_way_plan;
pub mod three_way_review;
pub mod three_way_text_diff;
pub mod trusted_apply_planning;
pub mod trusted_cli_update_artifact;
mod trusted_package_free_update_recovery;
pub mod trusted_recovery_authority;
pub mod trusted_staging;
pub mod trusted_transactional_apply_execution;
pub mod trusted_transactional_apply_planning;
pub mod trusted_update_workspace;
pub mod two_way_merge;
pub mod two_way_plan;
pub mod validation;
pub mod zip_package;
pub mod zip_path;

pub use baseline::{
    capture_official_baseline_from_package_in_trusted_update_workspace,
    capture_official_baseline_in_standalone_store, capture_official_baseline_in_workspace,
    capture_official_baseline_in_workspace_with_expected_package_commitment,
    catalog_official_baselines, discard_baseline_bundle,
    ensure_baseline_store_disjoint_from_installed, load_baseline_bundle, resolve_official_baseline,
    resolve_standalone_baseline_store, BaselineCaptureOptions, BaselineCaptureRequest,
    BaselineCaptureResult, BaselineCaptureWarning, BaselineCatalog, BaselineCatalogEntry,
    BaselineCatalogIssue, BaselineCatalogIssueKind, BaselineCatalogRequest, BaselineCounts,
    BaselineEscrowClass, BaselineFileRecord, BaselineId, BaselineResolutionOptions,
    BaselineResolutionRequest, BaselineStoreLimits, ExpectedPackageBaselineCaptureRequest,
    IncomingResourceSelector, OfficialBaselineSelector, ResolvedBaselineSelectionKind,
    ResolvedOfficialBaseline, SafeResourceKey, StandaloneBaselineStore, StoredBaseline,
    StoredBaselineLocator,
};
pub use baseline_free_plan::{
    create_baseline_free_update_plan, BaselineFreeDisposition, BaselineFreeUpdatePlan,
    ExpectedFileState, PlannedFile, ResourceUpdatePlan, UpdatePlanCounts, UpdatePlanReason,
    UpdatePlanWarning,
};
pub use comparison::{
    compare_installation_to_zip, ComparedFile, ComparedFileSide, ComparedIncomingFile,
    ComparisonLimits, ComparisonWarning, FileComparisonStatus, InstallationComparisonReport,
    ResourceComparison, ResourceMatch, ResourceMatchKind,
};
pub use error::{
    ApplyPlanningIoOperation, BaselineCaptureArchiveLimitKind, BaselineCaptureBlobSpoolStage,
    BaselineCaptureUnsafeEntryKind, BaselineCatalogValidationCategory, GkrmError, Result,
    StagingIoOperation, TransactionalApplyIoOperation, TransactionalApplyPlanningIoOperation,
};
pub use escrow_classification::{
    classify_zip_resource_escrow, ClassifiedResourceFile, ClassifiedZipResource,
    EscrowClassificationReport, EscrowClassificationWarning, EscrowFileClassification,
};
pub use inspection::{
    inspect_installation_update, inspect_package_resources, installed_resource_source_commitment,
    FullInspectionReport, InspectionOptions, InstalledResourceSourceCommitment,
    PackageResourceEscrowSummary, PackageResourceInspectionOptions,
    PackageResourceInspectionReport, PackageResourceInspectionResource,
    PackageResourceManifestSummary, PackageSourceCommitment,
    PACKAGE_RESOURCE_INSPECTION_MAX_PACKAGE_BYTES,
};
pub use installed_path::{InstallationRelativePath, ResourceRelativePath, Sha256Digest};
pub use installed_scan::{
    scan_installed_resources, InstalledFileIdentity, InstalledFileInfo, InstalledInstallationScan,
    InstalledResourceRoot, InstalledResourceScan, InstalledScanLimits, InstalledScanWarning,
};
pub use manifest::{
    declared_manifest_version, parse_resource_manifest_source, parse_zip_resource_manifests,
    FxManifest, FxManifestWarning, ManifestDeclarationKind, ManifestLimits, ManifestString,
    ParsedZipResourceManifest, ZipManifestParseReport,
};
pub use package_limits::PackageLimits;
pub use resource_discovery::{
    discover_zip_resources, DiscoveredZipResource, ZipResourceDiscovery, ZipResourceName,
    ZipResourceRoot, ZipResourceWarning,
};
pub use three_way_merge_analysis::{
    analyze_queued_three_way_merges, IncomingMergeContentSource, IncomingMergeContentSourceLimits,
    InstalledMergeContentSource, MergeContentAnalysis, MergeContentEncoding, MergeContentKind,
    MergeNewlineStyle, ThreeWayMergeAlgorithm, ThreeWayMergeAnalysisDisposition,
    ThreeWayMergeAnalysisEntry, ThreeWayMergeAnalysisId, ThreeWayMergeAnalysisOptions,
    ThreeWayMergeAnalysisPlan, ThreeWayMergeAnalysisRequest, ThreeWayMergeAnalysisStatus,
    ThreeWayMergeAnalysisSummary,
};
pub use three_way_merge_synthesis::{
    plan_three_way_merge_synthesis, FinalTextEnvelope, MergeSynthesisDisposition,
    MergeSynthesisOperation, MergeSynthesisOperationId, MergeSynthesisOperationKind,
    MergeSynthesisStatus, MergeSynthesisSummary, ThreeWayMergeSynthesisEntry,
    ThreeWayMergeSynthesisOptions, ThreeWayMergeSynthesisPlan, ThreeWayMergeSynthesisPlanId,
    ThreeWayMergeSynthesisRequest,
};
pub use three_way_merged_bytes::{
    synthesize_three_way_merged_bytes, MergedByteArtifact, MergedByteArtifactId,
    MergedByteDisposition, MergedByteStatus, MergedByteSummary, MergedLine, MergedLineOrigin,
    MergedLineView, ThreeWayMergedBytesEntry, ThreeWayMergedBytesOptions, ThreeWayMergedBytesPlan,
    ThreeWayMergedBytesPlanId, ThreeWayMergedBytesRequest, MERGED_LINE_VIEW_MAX_LINES,
    MERGED_LINE_VIEW_MAX_LINE_CHARS,
};
pub use three_way_plan::{
    create_three_way_update_plan, EscrowPolicyTransition, IncomingOfficialResourceSnapshot,
    InstalledResourceSnapshot, ThreeWayDelta, ThreeWayFileState, ThreeWayPlanDisposition,
    ThreeWayPlanEntry, ThreeWayPlanId, ThreeWayPlanReadiness, ThreeWayPlanSummary,
    ThreeWayPlannerOptions, ThreeWayUpdatePlan, ThreeWayUpdatePlanRequest,
};
pub use three_way_review::{
    review_three_way_update_plan, PolicyTransitionAcknowledgement, ThreeWayPlanDecision,
    ThreeWayPlanDecisionChoice, ThreeWayPlanDecisionSet, ThreeWayPlanReview,
    ThreeWayPlanReviewEntry, ThreeWayPlanReviewId, ThreeWayPlanReviewRequest,
    ThreeWayPlanReviewRequirement, ThreeWayPlanReviewStatus, ThreeWayPlanReviewSummary,
    ThreeWayReviewedAction,
};
pub use three_way_text_diff::{
    plan_three_way_text_diffs, LineRange, SupportedTextNewlineStyle, TextDiffHunk, TextDiffHunkId,
    TextDiffHunkKind, TextDiffSide, TextEnvelope, TextLineSequenceCommitment, TextTerminalNewline,
    ThreeWayTextDiffDisposition, ThreeWayTextDiffEntry, ThreeWayTextDiffOptions,
    ThreeWayTextDiffPlan, ThreeWayTextDiffPlanId, ThreeWayTextDiffRequest, ThreeWayTextDiffStatus,
    ThreeWayTextDiffSummary, ThreeWayTextEnvelopePlan, ThreeWayTextEnvelopePlanState,
    ThreeWayTextOverlapClassification, ThreeWayTextOverlapGroup, ThreeWayTextOverlapGroupId,
    ThreeWayTextScalarResolution,
};
pub use trusted_apply_planning::{
    plan_trusted_apply, ApplyBackupRequirement, InstalledApplyPlanningSource,
    TrustedApplyBackupSetId, TrustedApplyOperation, TrustedApplyOperationId,
    TrustedApplyOperationKind, TrustedApplyOperationPhase, TrustedApplyPlan, TrustedApplyPlanId,
    TrustedApplyPlanningOptions, TrustedApplyPlanningRequest, TrustedApplyStatus,
    TrustedApplySummary,
};
pub use trusted_cli_update_artifact::{
    apply_trusted_cli_update, apply_trusted_cli_update_in_workspace, apply_trusted_desktop_update,
    apply_two_way_update, build_decision_document, encode_cli_artifact,
    escrow_ignored_line_view_paths, line_view_eligibility, parse_cli_artifact,
    parse_decision_document, plan_trusted_cli_update, plan_trusted_cli_update_for_review,
    plan_trusted_cli_update_for_review_with_expected_source_commitments,
    plan_trusted_cli_update_in_workspace, preview_two_way_update, recover_trusted_cli_update,
    recover_trusted_cli_update_in_workspace, status_trusted_cli_update,
    status_trusted_cli_update_in_workspace, LineViewEligibility, TrustedCliApplyRequest,
    TrustedCliDecisionDocument, TrustedCliDecisionDocumentId, TrustedCliDecisionEntry,
    TrustedCliExpectedSourceCommitments, TrustedCliPlanRequest, TrustedCliPlanReviewReport,
    TrustedCliRecoverRequest, TrustedCliReport, TrustedCliStatusRequest, TrustedCliUpdateArtifact,
    TrustedCliUpdateArtifactBody, TrustedCliUpdateArtifactId, TrustedCliUpdateOptions,
    TrustedDesktopApplyAuthority, TrustedDesktopApplyRequest, TrustedOperatorMergeArtifact,
    TrustedOperatorMergeArtifactId, TrustedOperatorMergeSet, TwoWayApplyOutcome,
    TwoWayApplyRequest, TwoWayBaselineSource, TwoWayFileChoice, TwoWayReviewFile,
    TwoWayUnmergeableReason, TwoWayUpdatePreview, TwoWayUpdateRequest, TwoWayWholeFile,
    TwoWayWrittenFile,
};
pub use trusted_package_free_update_recovery::{
    discard_unaccounted_trusted_staging_bundles, discard_unreferenced_trusted_baseline,
    inspect_trusted_published_update_v2, inspect_trusted_recovery_workspace_overview,
    inspect_trusted_two_way_updates, inspect_trusted_undo_receipts,
    recover_trusted_published_update_v2, referenced_trusted_baselines,
    retire_trusted_terminal_update_evidence, scan_trusted_installed_recovery_resources,
    unaccounted_trusted_staging_bundles, TrustedInstalledRecoveryScan,
    TrustedInstalledRecoverySelection, TrustedPackageFreeUpdateRecoveryOptions,
    TrustedPackageFreeUpdateRecoveryRequest, TrustedPublishedUpdateRecoveryInspection,
    TrustedPublishedUpdateRecoveryState, TrustedRecoveryWorkspaceOverview,
    TrustedStagingReleaseOutcome, TrustedTerminalEvidenceRetirementOptions,
    TrustedTerminalEvidenceRetirementOutcome, TrustedTwoWayUpdateRecord, TrustedUndoDisposition,
    TrustedUndoExecutionOutcome, TrustedUndoFileChange, TrustedUndoPlan, TrustedUndoPlanEntry,
    TrustedUndoReceipt, TrustedUndoSource,
};
pub use trusted_recovery_authority::{
    parse_recovery_authority_body, parse_recovery_authority_envelope, RecoveryAuthorityBodyV1,
    RecoveryAuthorityEnvelopeV1, RecoveryAuthorityId, RecoveryAuthorityLimits,
    RecoveryAuthorityParserMemoryEstimate, RecoveryAuthorityPublication,
    RecoveryPublicationBindingId,
};
pub use trusted_staging::{
    estimate_trusted_staging_publication, reopen_trusted_staging_bundle, stage_trusted_resource,
    stage_trusted_resource_two_way, IncomingStagingContentSource, InstalledStagingContentSource,
    StagingContentOrigin, StagingFinalState, StagingSourceBinding, TrustedStagingBundle,
    TrustedStagingBundleId, TrustedStagingEntry, TrustedStagingEntryId, TrustedStagingManifest,
    TrustedStagingManifestId, TrustedStagingOperatorMergeInput, TrustedStagingOptions,
    TrustedStagingPublicationEstimate, TrustedStagingRequest, TrustedStagingRoot,
    TrustedStagingStatus, TrustedStagingSummary, TrustedUndoExecutionDescriptor,
    TrustedUndoStagingBundle, TwoWayStagingRequest, TwoWayUpdateMode,
};
pub use trusted_transactional_apply_execution::{
    execute_trusted_transactional_apply, recover_trusted_transaction, scan_trusted_transactions,
    trusted_transaction_is_on_record, CommittedTransaction, RecoveredCommittedTransaction,
    RecoveredRolledBackTransaction, RecoveryRequiredTransaction, RecoveryStillRequired,
    RolledBackTransaction, SafeRestartTransaction, TransactionJournalEvent,
    TrustedRecoveryCandidate, TrustedRecoveryCandidateId, TrustedRecoveryCandidateKind,
    TrustedRecoveryOptions, TrustedRecoveryResult, TrustedRecoveryResultId,
    TrustedRecoveryScanOptions, TrustedRecoveryScanResult, TrustedRecoveryScanResultId,
    TrustedTransactionRecoveryRequest, TrustedTransactionResult, TrustedTransactionResultId,
    TrustedTransactionRoot, TrustedTransactionSummary, TrustedTransactionalApplyExecutionOptions,
    TrustedTransactionalApplyExecutionRequest,
};
pub use trusted_transactional_apply_planning::{
    plan_trusted_transactional_apply, JournalState, RecoveryAction, RollbackAction,
    TransactionCrashBoundary, TransactionStepPhase, TrustedBackupEntryId, TrustedBackupPlan,
    TrustedBackupPlanId, TrustedJournalPlan, TrustedJournalRecordId, TrustedRecoveryTable,
    TrustedRecoveryTableId, TrustedRollbackStep, TrustedRollbackStepId, TrustedTransactionStepId,
    TrustedTransactionalApplyPlan, TrustedTransactionalApplyPlanId,
    TrustedTransactionalApplyPlanningOptions, TrustedTransactionalApplyPlanningRequest,
    TrustedTransactionalApplyStatus, TrustedTransactionalApplySummary,
};
pub use trusted_update_workspace::{
    acquire_trusted_update_workspace_publication_lock, enforce_trusted_update_workspace_capacity,
    enforce_trusted_update_workspace_capacity_for_new_plan_artifact,
    enforce_trusted_update_workspace_capacity_for_reservation,
    open_existing_trusted_update_workspace,
    open_existing_trusted_update_workspace_from_explicit_roots, resolve_trusted_update_workspace,
    resolve_trusted_update_workspace_from_explicit_roots,
    ExistingExplicitTrustedUpdateWorkspaceRequest, ExplicitTrustedUpdateWorkspaceRequest,
    TrustedArtifactRoot, TrustedBaselineStore, TrustedUpdateWorkspace,
    TrustedUpdateWorkspaceOptions, TrustedUpdateWorkspaceReservation, TrustedUpdateWorkspaceUsage,
    TrustedWorkspaceRoot,
};
pub use two_way_merge::{
    change_blocks, default_choices, default_choices_with_untouched, merge_two_way, resolve_two_way,
    split_two_way, untouched_blocks, TwoWayChangeBlock, TwoWayLineOrigin, TwoWayMergeMode,
    TwoWayMergeOptions, TwoWayMergedLine, TwoWaySegment,
};
pub use two_way_plan::{
    create_two_way_update_plan, TwoWayBaseline, TwoWayFileAction, TwoWayPlanEntry, TwoWayPlanId,
    TwoWayPlanSummary, TwoWayUpdatePlan,
};
pub use validation::{
    validate_cli_installed_argument, validate_cli_package_argument, validate_installed_path,
    validate_package_path, InspectRequest,
};
pub use zip_package::{inspect_zip_package, ZipEntryInfo, ZipEntryKind, ZipInspection};
pub use zip_path::ZipRelativePath;
