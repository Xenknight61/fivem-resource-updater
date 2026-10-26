export type SelectionKind = 'installedRoot' | 'packageFile'

export interface AppInfo {
  schemaVersion: 1
  appVersion: string
  coreVersion: string
  platform: 'windows' | 'linux' | 'macos' | 'unknown'
  buildProfile: 'debug' | 'release'
}

export interface SelectionSummary {
  handle: string
  kind: SelectionKind
  displayLabel: string
}

export interface SelectionDialogResult {
  cancelled: boolean
  selection?: SelectionSummary
}

export interface ListSelectionsRequest {
  kind?: SelectionKind
}

export interface ListSelectionsResponse {
  selections: SelectionSummary[]
}

export interface ReleaseSelectionRequest {
  handle: string
}

export interface ReleaseSelectionResponse {
  released: true
}

export type DesktopErrorCode =
  | 'invalid_request'
  | 'dialog_failed'
  | 'invalid_installed_root'
  | 'invalid_package_file'
  | 'selection_limit_reached'
  | 'selection_not_found'
  | 'selection_stale'
  | 'security_rejection'
  | 'busy'
  | 'scan_busy'
  | 'scan_limit_reached'
  | 'scan_not_found'
  | 'scan_failed'
  | 'invalid_scan_source'
  | 'resource_not_found'
  | 'inspection_rejected'
  | 'selection_busy'
  | 'planning_busy'
  | 'plan_limit_reached'
  | 'plan_not_found'
  | 'plan_not_ready'
  | 'plan_busy'
  | 'plan_already_applied'
  | 'plan_change_not_found'
  | 'plan_decision_invalid'
  | 'plan_decision_incomplete'
  | 'plan_policy_acknowledgement_required'
  | 'plan_creation_failed'
  | 'update_already_applied'
  | 'update_apply_failed'
  | 'undo_unavailable'
  | 'undo_installation_missing'
  | 'undo_failed'
  | 'resource_selection_stale'
  | 'source_changed'
  | 'baseline_not_found'
  | 'baseline_ambiguous'
  | 'baseline_session_limit_reached'
  | 'baseline_session_stale'
  | 'baseline_candidate_stale'
  | 'baseline_catalog_blocked'
  | 'baseline_capture_rejected'
  | 'baseline_package_changed'
  | 'baseline_busy'
  | 'workspace_capacity_reached'
  | 'plan_review_too_large'
  | 'recovery_required'
  | 'artifact_publication_failed'
  | 'plan_session_publication_failed'
  | 'recovery_session_limit_reached'
  | 'recovery_session_stale'
  | 'recovery_candidate_stale'
  | 'recovery_busy'
  | 'recovery_manual_attention'
  | 'recovery_ambiguous'
  | 'recovery_evidence_invalid'
  | 'recovery_unsupported'
  | 'workspace_legacy_unsupported'
  | 'internal'

export type DesktopErrorCategory =
  | 'input'
  | 'selection'
  | 'filesystem'
  | 'security'
  | 'busy'
  | 'internal'

export interface DesktopError {
  code: DesktopErrorCode
  category: DesktopErrorCategory
  message: string
  recoverable: boolean
}

export type ScanSourceKind = 'installedRoot' | 'packageFile'
export type ResourceStatus = 'available' | 'warnings'
export type ManifestKind = 'fxmanifest' | 'resourceManifest' | 'none'
export type EscrowState = 'notAvailable' | 'none' | 'partial' | 'protected'
export type FindingCode =
  | 'scanWarningsPresent'
  | 'manifestWarningsPresent'
  | 'escrowWarningsPresent'
  | 'packageEntriesUnassigned'
export type FindingSeverity = 'info' | 'warning'

export interface ScanSummary {
  sourceKind: ScanSourceKind
  sourceLabel: string
  resourceCount: number
  warningCount: number
  totalFileCount: number
  totalBytes: number
}

export interface ResourceSummary {
  resourceHandle: string
  sourceKind: ScanSourceKind
  displayName: string
  status: ResourceStatus
  fileCount: number
  totalBytes: number
  warningCount: number
}

export interface ManifestSummary {
  kind: ManifestKind
  clientScriptCount: number
  serverScriptCount: number
  sharedScriptCount: number
  dataFileCount: number
  hasUiPage: boolean
}

export interface EscrowSummary {
  state: EscrowState
  protectedFileCount: number
  ignoredFileCount: number
  unsupportedFileCount: number
}

export interface ResourceStatistics {
  fileCount: number
  totalBytes: number
}

export interface FindingSummary {
  code: FindingCode
  severity: FindingSeverity
  message: string
}

export interface ResourceDetail {
  resourceHandle: string
  sourceKind: ScanSourceKind
  displayName: string
  status: ResourceStatus
  manifest: ManifestSummary
  escrow: EscrowSummary
  statistics: ResourceStatistics
  findings: FindingSummary[]
  omittedFindingCount: number
}

export interface ScanInstalledRootRequest {
  selectionHandle: string
}

export interface InspectPackageRequest {
  selectionHandle: string
}

export interface StartScanResponse {
  scanHandle: string
  sourceKind: ScanSourceKind
  summary: ScanSummary
}

export interface ScanGetSummaryRequest {
  scanHandle: string
}

export interface ScanGetSummaryResponse {
  summary: ScanSummary
}

export interface ScanListResourcesRequest {
  scanHandle: string
  query?: string
  status?: ResourceStatus
  offset: number
  limit: number
}

export interface ScanListResourcesResponse {
  total: number
  offset: number
  limit: number
  resources: ResourceSummary[]
}

export interface ScanGetResourceDetailRequest {
  scanHandle: string
  resourceHandle: string
}

export interface ScanGetResourceDetailResponse {
  resource: ResourceDetail
}

export interface ScanReleaseRequest {
  scanHandle: string
}

export interface ScanReleaseResponse {
  released: true
}

export type SourceMatchStatus = 'matched' | 'mismatch'

export interface UpdateSourceMatchRequest {
  installedSelectionHandle: string
  installedScanHandle: string
  installedResourceHandle: string
  packageSelectionHandle: string
  packageScanHandle: string
  packageResourceHandle: string
}

export interface UpdateSourceMatchResponse {
  status: SourceMatchStatus
}

export type UpdateBaselineStatusRequest = UpdateSourceMatchRequest
export type BaselineStatus = 'missing' | 'ready' | 'multiple' | 'ambiguous' | 'blocked'

export type BaselineVersionPresentation =
  | { state: 'notDeclared' }
  | { state: 'declaredEmpty' }
  | { state: 'declared'; value: string }

export interface BaselineCandidatePresentation {
  resourceLabel: string
  version: BaselineVersionPresentation
  fileCount: number
  protectedFileCount: number
  editableFileCount: number
  retainedBlobCount: number
  retainedBlobBytes: number
}

export interface BaselineCandidateSummary {
  candidateHandle: string
  presentation: BaselineCandidatePresentation
}

export interface UpdateBaselineStatusResponse {
  baselineSessionHandle: string
  status: BaselineStatus
  candidates: BaselineCandidateSummary[]
  catalogNeedsAttention: boolean
}

export interface UpdateBaselineCaptureRequest {
  baselineSessionHandle: string
  previewSelectionHandle: string
  previewScanHandle: string
  previewResourceHandle: string
}

export interface UpdateBaselineCaptureResponse {
  baseline: UpdateBaselineStatusResponse
  selectedCandidateHandle: string
}

export interface UpdateBaselineReleaseRequest {
  baselineSessionHandle: string
}

export interface UpdateBaselineReleaseResponse {
  released: true
}

export type UpdatePlanStatus = 'pendingDecisions' | 'manualMergeRequired' | 'readyToApply'

export type PlanDisposition =
  | 'noChange'
  | 'useIncoming'
  | 'removeForIncoming'
  | 'preserveInstalled'
  | 'preserveInstalledDeletion'
  | 'addIncoming'
  | 'preserveInstalledAddition'
  | 'converged'
  | 'convergedAddition'
  | 'convergedDeletion'
  | 'mergeCandidate'
  | 'conflictReview'
  | 'deleteVsModifyConflict'
  | 'modifyVsDeleteConflict'
  | 'addVsAddConflict'
  | 'policyReview'
  | 'policyConflictReview'

export type PlanDelta = 'unchanged' | 'added' | 'modified' | 'deleted'
export type PlanReviewRequirement = 'noDecisionRequired' | 'decisionRequired'
export type PlanReviewedAction =
  | 'notRequired'
  | 'pending'
  | 'useIncomingState'
  | 'preserveInstalledState'
  | 'queueMergeAnalysis'
  | 'manualReview'
export type PlanDecisionChoice =
  | 'acceptRecommended'
  | 'useIncomingState'
  | 'preserveInstalledState'
  | 'queueMergeAnalysis'
  | 'manualReview'
export interface AllowedPlanDecision {
  choice: PlanDecisionChoice
  requiresPolicyAcknowledgement: boolean
}
export type PolicyTransitionKind = 'none' | 'changed'
export type FilePresenceState = 'absent' | 'present'
export type PlanFindingCode =
  | 'decisionRequired'
  | 'manualReviewRequired'
  | 'mergeAnalysisQueued'
  | 'conflictReviewRequired'
  | 'policyReviewRequired'
export type PlanFindingSeverity = 'info' | 'warning'

export interface CreateUpdatePlanRequest {
  installedSelectionHandle: string
  installedScanHandle: string
  installedResourceHandle: string
  packageSelectionHandle: string
  packageScanHandle: string
  packageResourceHandle: string
  baselineSessionHandle: string
  baselineCandidateHandle: string
}

export interface UpdatePlanSummary {
  planHandle: string
  status: UpdatePlanStatus
  installedResourceLabel: string
  incomingResourceLabel: string
  totalChangeCount: number
  noChangeCount: number
  incomingActionCount: number
  preservedLocalCount: number
  convergedCount: number
  mergeCandidateCount: number
  conflictCount: number
  policyReviewCount: number
  decisionsRequiredCount: number
  pendingDecisionCount: number
  manualReviewCount: number
}

export interface CreateUpdatePlanResponse {
  planHandle: string
  summary: UpdatePlanSummary
}

export interface UpdatePlanGetSummaryRequest {
  planHandle: string
}

export interface UpdatePlanGetSummaryResponse {
  summary: UpdatePlanSummary
}

export interface UpdatePlanListChangesRequest {
  planHandle: string
  query?: string
  disposition?: PlanDisposition
  reviewRequirement?: PlanReviewRequirement
  offset: number
  limit: number
}

export interface PlanChangeSummary {
  changeHandle: string
  displayPath: string
  disposition: PlanDisposition
  reviewRequirement: PlanReviewRequirement
  reviewedAction: PlanReviewedAction
  localDelta: PlanDelta
  incomingDelta: PlanDelta
  policyTransition: PolicyTransitionKind
  blocksAutomaticApply: boolean
  recommendedAction?: PlanReviewedAction
  allowedDecisions: AllowedPlanDecision[]
  findingCount: number
}

export interface UpdatePlanListChangesResponse {
  total: number
  offset: number
  limit: number
  changes: PlanChangeSummary[]
}

export interface PlanFinding {
  code: PlanFindingCode
  severity: PlanFindingSeverity
  message: string
}

export interface PlanChangeDetail {
  changeHandle: string
  displayPath: string
  disposition: PlanDisposition
  reviewRequirement: PlanReviewRequirement
  reviewedAction: PlanReviewedAction
  localDelta: PlanDelta
  incomingDelta: PlanDelta
  policyTransition: PolicyTransitionKind
  blocksAutomaticApply: boolean
  baselineState: FilePresenceState
  installedState: FilePresenceState
  incomingState: FilePresenceState
  recommendedAction?: PlanReviewedAction
  allowedDecisions: AllowedPlanDecision[]
  findings: PlanFinding[]
  omittedFindingCount: number
}

export interface UpdatePlanGetChangeDetailRequest {
  planHandle: string
  changeHandle: string
}

export type PlanDiffAvailability = 'available' | 'protected_content' | 'not_merged'
export type PlanDiffLineOrigin = 'baseline' | 'installed' | 'incoming' | 'converged'

export interface PlanDiffLine {
  origin: PlanDiffLineOrigin
  /** Sanitized line text: valid UTF-8, control characters removed, bounded length. */
  text: string
  /** True when this individual line was longer than the display limit and was cut. */
  truncated: boolean
}

export interface UpdatePlanGetChangeDiffRequest {
  planHandle: string
  changeHandle: string
}

export interface UpdatePlanGetChangeDiffResponse {
  availability: PlanDiffAvailability
  lines: PlanDiffLine[]
  /** True when the file had more lines than the display limit and the tail was dropped. */
  truncated: boolean
}

export interface UpdatePlanGetChangeDetailResponse {
  change: PlanChangeDetail
}

export interface UpdatePlanReleaseRequest {
  planHandle: string
}

export interface UpdatePlanReleaseResponse {
  released: true
}

export interface PlanDecisionSubmission {
  changeHandle: string
  choice: PlanDecisionChoice
  policyAcknowledged: boolean
}

export interface UpdatePlanSubmitDecisionsRequest {
  planHandle: string
  decisions: PlanDecisionSubmission[]
}

export interface UpdatePlanSubmitDecisionsResponse {
  planHandle: string
  summary: UpdatePlanSummary
}

export type ApplyOutcome =
  | 'committed'
  | 'rolled_back'
  | 'recovery_required'
  | 'published_recovery_unsealed'
  | 'published_recovery_failed'
  | 'safe_failure_before_publication'

export interface UpdatePlanApplyRequest {
  planHandle: string
}

export interface UpdatePlanApplyResponse {
  outcome: ApplyOutcome
}

export type RecoveryOverviewDisposition = 'clear' | 'attention_required'

export interface UpdateRecoveryOverviewResponse {
  disposition: RecoveryOverviewDisposition
  activeRecovery: boolean
  terminalEvidence: boolean
  manualAttention: boolean
  unsupportedEvidence: boolean
}

export interface UpdateRecoveryRetireTerminalRequest {
  acknowledged: boolean
}

export interface UpdateRecoveryRetireTerminalResponse {
  retiredCount: number
  alreadyRetiredCount: number
}

export interface UpdateRecoveryStatusRequest {
  installedSelectionHandle: string
  installedScanHandle: string
  installedResourceHandle: string
}

export type RecoveryStatus =
  | 'clear'
  | 'recovery_available'
  | 'committed'
  | 'rolled_back'
  | 'safe_restart'
  | 'recovery_required'
  | 'manual_attention'
  | 'ambiguous'
  | 'unsupported'

export interface UpdateRecoveryStatusResponse {
  recoveryHandle: string
  resourceLabel: string
  status: RecoveryStatus
  candidateCount: number
}

export interface UpdateRecoveryListCandidatesRequest {
  recoveryHandle: string
}

export type RecoveryCandidateState =
  | 'recoverable'
  | 'committed'
  | 'rolled_back'
  | 'safe_restart'
  | 'recovery_required'

export type RecoveryActionHint = 'recover' | 'none'

export interface RecoveryCandidateSummary {
  candidateHandle: string
  resourceLabel: string
  state: RecoveryCandidateState
  recoverable: boolean
  actionHint: RecoveryActionHint
}

export interface UpdateRecoveryListCandidatesResponse {
  candidates: RecoveryCandidateSummary[]
}

export interface UpdateRecoveryExecuteRequest {
  recoveryHandle: string
  candidateHandle: string
}

export type RecoveryOutcome =
  | 'recovered_committed'
  | 'recovered_rolled_back'
  | 'safe_restart'
  | 'recovery_still_required'

export interface UpdateRecoveryExecuteResponse {
  outcome: RecoveryOutcome
}

export interface UpdateRecoveryReleaseRequest {
  recoveryHandle: string
}

export interface UpdateRecoveryReleaseResponse {
  released: true
}

// --- The two-way update: a folder, a package, and a list to answer ----------------------------

export interface TwoWayPreviewRequest {
  installedSelectionHandle: string
  packageSelectionHandle: string
  /** The package the operator installed from, when they still have it. */
  baselineSelectionHandle?: string
}

/** What the update would do to one file. */
export type TwoWayFileDisposition =
  | 'unchanged'
  | 'take_from_update'
  | 'review'
  | 'keep_local_only'

export interface TwoWayFile {
  /** Resource-relative, never a filesystem path. */
  path: string
  disposition: TwoWayFileDisposition
  /** True when the incoming manifest declares this path escrow-ignored. */
  editable: boolean
  /**
   * True when the package the operator installed from holds exactly what they still have.
   *
   * The reason a file they could have edited is not being asked about. Always false when no
   * package was given to compare against.
   */
  untouched: boolean
  /**
   * True when this file was combined by key rather than by line.
   *
   * It holds no per-line decisions, and yet leaving it alone is a merge rather than a file kept
   * exactly as it is.
   */
  mergedByKey: boolean
  /**
   * How many decisions this file holds, or zero when it holds none.
   *
   * It comes from the split rather than from the view drawn of it, so a file whose lines were too
   * many to draw can still be answered from the list without ever being opened.
   */
  blockCount: number
}

export interface TwoWaySummary {
  unchanged: number
  takeFromUpdate: number
  review: number
  keepLocalOnly: number
  total: number
}

export interface TwoWayPreviewResponse {
  handle: string
  resource: string
  /** The version each side's manifest declares, when it declares exactly one. */
  installedVersion?: string
  incomingVersion?: string
  summary: TwoWaySummary
  files: TwoWayFile[]
  omittedFileCount: number
  unmergeable: string[]
  /**
   * The version this comparison reached for by itself, when nobody pointed at a package.
   *
   * It is what the last update to this installation applied, kept so the operator is not asked to
   * have held on to a ZIP.
   */
  rememberedBaselineVersion?: string
  /** True when the comparison used one it had kept rather than one it was given. */
  usedRememberedBaseline: boolean
}

export interface TwoWayGetDiffRequest {
  handle: string
  path: string
}

/** What one row of a diff is. */
export type TwoWayRowKind = 'context' | 'yours' | 'theirs' | 'gap'

export interface TwoWayDiffRow {
  kind: TwoWayRowKind
  /** Which change block this row belongs to, or undefined for context and gaps. */
  block?: number
  text: string
  truncated: boolean
  /** How many identical lines a gap stands in for. */
  skipped?: number
  /** Where the line sits in the file as installed, and as the update has it. */
  installedLine?: number
  incomingLine?: number
}

export interface TwoWayGetDiffResponse {
  available: boolean
  rows: TwoWayDiffRow[]
  /** How many separate decisions this file offers. */
  blockCount: number
  /** Where each decision starts before the operator touches it. */
  defaultChoices: boolean[]
  truncated: boolean
  omitted: boolean
  /** True when the two were combined by key instead of by line. */
  mergedByKey?: boolean
  /** The keys whose values were kept from the operator's file, and how many there were. */
  keptKeys?: string[]
  keptKeyCount?: number
  /** Why this file has no line view, when it has none. */
  wholeFileReason?: TwoWayWholeFileReason
  /** The operator's copy and the update's, as data URLs, when this is a picture worth showing. */
  installedImage?: string
  incomingImage?: string
}

/** Why a file cannot be combined line by line. */
export type TwoWayWholeFileReason = 'not_text' | 'too_far_apart' | 'too_large'

/** One file the operator decided by hand, block by block. */
export interface TwoWayFileChoice {
  path: string
  /** One decision per change block, in order. `true` takes the update's lines there. */
  takeFromUpdate: boolean[]
}

export interface TwoWayApplyRequest {
  handle: string
  /** The preset for every reviewed file the operator did not decide by hand. */
  keepSettings: boolean
  choices: TwoWayFileChoice[]
}

export interface TwoWayApplyResponse {
  outcome: string
  summary: TwoWaySummary
}

export interface TwoWayReleaseRequest {
  handle: string
}

export interface TwoWayReleaseResponse {
  released: boolean
}

/**
 * One copy of an official package the workspace is holding.
 *
 * Kept so a later update can tell the operator's own work from the developer's without asking them
 * to have held on to a ZIP. `neededFor` says what still reaches for it; absent means nothing does.
 */
export interface HeldBaseline {
  resource: string
  /** The version that package declared, when it declared one. */
  version?: string
  bytes: number
  /** `installation` compares against it next time; `undo` would put an installation back onto it. */
  neededFor?: 'installation' | 'undo'
}

export interface StorageReportResponse {
  baselines: HeldBaseline[]
  heldBytes: number
  /** What is held for nothing among the kept packages. */
  releasableBytes: number
  /**
   * The copies an apply staged to write from, counted and sized.
   *
   * Whether any of them can go is the workspace's to say rather than this application's — a staged
   * copy is what a recovery replays, and only an authority artifact says which is still needed. So
   * they are reported here and decided at the moment of release.
   */
  stagedCount: number
  stagedBytes: number
  /** What a release would free of the staged copies. Zero while the workspace has work outstanding. */
  stagedReleasableBytes: number
}

export interface StorageReleaseResponse {
  released: number
  bytes: number
}

/** One update this operator ran, as remembered for the history screen. */
export interface UpdateHistoryEntry {
  /** Names this update. Updates remembered before undo existed have none. */
  id: string
  resource: string
  outcome: string
  appliedAtMs: number
  reviewed: number
  replaced: number
  total: number
  fromVersion?: string
  toVersion?: string
  /** True while what this update replaced is still on record and can be put back. */
  undoable: boolean
}

export interface UpdateHistoryListResponse {
  entries: UpdateHistoryEntry[]
}

/** What putting an update back actually amounted to, file by file. */
export interface UpdateHistoryUndoResponse {
  restored: number
  removed: number
  unchanged: number
  skipped: number
  missing: number
}
