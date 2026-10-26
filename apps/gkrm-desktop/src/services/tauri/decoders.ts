import type {
  AppInfo,
  AllowedPlanDecision,
  ApplyOutcome,
  DesktopError,
  DesktopErrorCategory,
  DesktopErrorCode,
  ListSelectionsResponse,
  ResourceDetail,
  ResourceStatus,
  ResourceSummary,
  ReleaseSelectionResponse,
  CreateUpdatePlanResponse,
  FilePresenceState,
  PlanChangeDetail,
  PlanChangeSummary,
  PlanDecisionChoice,
  PlanDelta,
  PlanDisposition,
  PlanFindingCode,
  PlanReviewRequirement,
  PlanReviewedAction,
  PolicyTransitionKind,
  ScanGetResourceDetailResponse,
  ScanGetSummaryResponse,
  ScanListResourcesResponse,
  ScanReleaseResponse,
  ScanSourceKind,
  ScanSummary,
  StartScanResponse,
  SelectionDialogResult,
  SelectionKind,
  SelectionSummary,
  UpdatePlanGetChangeDetailResponse,
  PlanDiffAvailability,
  PlanDiffLine,
  PlanDiffLineOrigin,
  UpdatePlanGetChangeDiffResponse,
  UpdatePlanGetSummaryResponse,
  UpdatePlanApplyResponse,
  UpdatePlanListChangesResponse,
  UpdatePlanReleaseResponse,
  UpdatePlanSubmitDecisionsResponse,
  UpdatePlanStatus,
  RecoveryActionHint,
  RecoveryCandidateState,
  RecoveryCandidateSummary,
  RecoveryOutcome,
  RecoveryOverviewDisposition,
  RecoveryStatus,
  UpdateRecoveryExecuteResponse,
  UpdateRecoveryListCandidatesResponse,
  UpdateRecoveryReleaseResponse,
  UpdateRecoveryOverviewResponse,
  UpdateRecoveryRetireTerminalResponse,
  UpdateRecoveryStatusResponse,
  UpdateSourceMatchResponse,
  BaselineCandidateSummary,
  BaselineStatus,
  BaselineVersionPresentation,
  UpdateBaselineStatusResponse,
  UpdateBaselineCaptureResponse,
  UpdateBaselineReleaseResponse,
  TwoWayApplyResponse,
  TwoWayDiffRow,
  TwoWayRowKind,
  TwoWayFile,
  TwoWayFileDisposition,
  TwoWayWholeFileReason,
  TwoWayGetDiffResponse,
  TwoWayPreviewResponse,
  TwoWayReleaseResponse,
  TwoWaySummary,
  HeldBaseline,
  StorageReleaseResponse,
  StorageReportResponse,
  UpdateHistoryEntry,
  UpdateHistoryUndoResponse,
  UpdateHistoryListResponse,
} from '@/types/commands'

const selectionKinds = new Set<SelectionKind>(['installedRoot', 'packageFile'])
const errorCodes = new Set<DesktopErrorCode>([
  'invalid_request',
  'dialog_failed',
  'invalid_installed_root',
  'invalid_package_file',
  'selection_limit_reached',
  'selection_not_found',
  'selection_stale',
  'security_rejection',
  'busy',
  'scan_busy',
  'scan_limit_reached',
  'scan_not_found',
  'scan_failed',
  'invalid_scan_source',
  'resource_not_found',
  'inspection_rejected',
  'selection_busy',
  'planning_busy',
  'plan_limit_reached',
  'plan_not_found',
  'plan_not_ready',
  'plan_busy',
  'plan_already_applied',
  'plan_change_not_found',
  'plan_decision_invalid',
  'plan_decision_incomplete',
  'plan_policy_acknowledgement_required',
  'plan_creation_failed',
  'update_already_applied',
  'update_apply_failed',
  'undo_unavailable',
  'undo_installation_missing',
  'undo_failed',
  'resource_selection_stale',
  'source_changed',
  'baseline_not_found',
  'baseline_ambiguous',
  'baseline_session_limit_reached',
  'baseline_session_stale',
  'baseline_candidate_stale',
  'baseline_catalog_blocked',
  'baseline_capture_rejected',
  'baseline_package_changed',
  'baseline_busy',
  'workspace_capacity_reached',
  'plan_review_too_large',
  'recovery_required',
  'artifact_publication_failed',
  'plan_session_publication_failed',
  'recovery_session_limit_reached',
  'recovery_session_stale',
  'recovery_candidate_stale',
  'recovery_busy',
  'recovery_manual_attention',
  'recovery_ambiguous',
  'recovery_evidence_invalid',
  'recovery_unsupported',
  'workspace_legacy_unsupported',
  'internal',
])
const errorCategories = new Set<DesktopErrorCategory>([
  'input',
  'selection',
  'filesystem',
  'security',
  'busy',
  'internal',
])

const canonicalUuidV4Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

export const genericDesktopError: DesktopError = {
  code: 'internal',
  category: 'internal',
  message: 'The desktop adapter failed.',
  recoverable: false,
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasExactOwnKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isRecord(value) || Object.getPrototypeOf(value) !== Object.prototype) return false
  const own = Object.keys(value)
  return own.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
}

function exactOwnDataProperty(value: unknown, key: string): PropertyDescriptor | undefined {
  if (!hasExactOwnKeys(value, [key])) return undefined
  const descriptor = Object.getOwnPropertyDescriptor(value, key)
  if (
    descriptor === undefined ||
    !descriptor.enumerable ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
    Object.prototype.hasOwnProperty.call(descriptor, 'get') ||
    Object.prototype.hasOwnProperty.call(descriptor, 'set')
  ) {
    return undefined
  }
  return descriptor
}

function isString(value: unknown, max = 256): value is string {
  return typeof value === 'string' && value.length <= max
}

function isPlanDisplayPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Array.from(value).length <= 160 &&
    new TextEncoder().encode(value).byteLength <= 320
  )
}

function isSafeInteger(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max
}

export function isCanonicalUuidV4Handle(value: unknown): value is string {
  return typeof value === 'string' && canonicalUuidV4Pattern.test(value)
}

export function decodeDesktopError(value: unknown): DesktopError {
  if (!isRecord(value)) return genericDesktopError
  const { code, category, message, recoverable } = value
  if (
    isString(code, 64) &&
    errorCodes.has(code as DesktopErrorCode) &&
    isString(category, 32) &&
    errorCategories.has(category as DesktopErrorCategory) &&
    isString(message, 160) &&
    typeof recoverable === 'boolean'
  ) {
    return {
      code: code as DesktopErrorCode,
      category: category as DesktopErrorCategory,
      message,
      recoverable,
    }
  }
  return genericDesktopError
}

function decodeSelectionSummary(value: unknown): SelectionSummary {
  if (!isRecord(value)) throw new Error('malformed selection summary')
  const { handle, kind, displayLabel } = value
  if (
    !isCanonicalUuidV4Handle(handle) ||
    !isString(kind, 32) ||
    !selectionKinds.has(kind as SelectionKind) ||
    !isString(displayLabel, 80)
  ) {
    throw new Error('malformed selection summary')
  }
  return { handle, kind: kind as SelectionKind, displayLabel }
}

export function decodeAppInfo(value: unknown): AppInfo {
  if (!isRecord(value)) throw new Error('malformed app info')
  const { schemaVersion, appVersion, coreVersion, platform, buildProfile } = value
  if (
    schemaVersion !== 1 ||
    !isString(appVersion, 40) ||
    !isString(coreVersion, 40) ||
    !['windows', 'linux', 'macos', 'unknown'].includes(String(platform)) ||
    !['debug', 'release'].includes(String(buildProfile))
  ) {
    throw new Error('malformed app info')
  }
  return {
    schemaVersion,
    appVersion,
    coreVersion,
    platform: platform as AppInfo['platform'],
    buildProfile: buildProfile as AppInfo['buildProfile'],
  }
}

export function decodeSelectionDialogResult(value: unknown): SelectionDialogResult {
  if (!isRecord(value) || typeof value.cancelled !== 'boolean') {
    throw new Error('malformed selection dialog result')
  }
  if (value.cancelled) {
    if ('selection' in value && value.selection !== undefined && value.selection !== null) {
      throw new Error('invalid selection dialog result')
    }
    return { cancelled: true }
  }
  if (!('selection' in value) || value.selection === undefined || value.selection === null) {
    throw new Error('invalid selection dialog result')
  }
  return { cancelled: false, selection: decodeSelectionSummary(value.selection) }
}

export function decodeListSelectionsResponse(value: unknown): ListSelectionsResponse {
  if (!isRecord(value) || !Array.isArray(value.selections) || value.selections.length > 16) {
    throw new Error('malformed selections response')
  }
  return { selections: value.selections.map(decodeSelectionSummary) }
}

export function decodeReleaseSelectionResponse(value: unknown): ReleaseSelectionResponse {
  if (!isRecord(value) || value.released !== true) {
    throw new Error('malformed release response')
  }
  return { released: true }
}

function decodeScanSourceKind(value: unknown): ScanSourceKind {
  if (value === 'installedRoot' || value === 'packageFile') return value
  throw new Error('malformed scan source kind')
}

function decodeResourceStatus(value: unknown): ResourceStatus {
  if (value === 'available' || value === 'warnings') return value
  throw new Error('malformed resource status')
}

export function decodeScanSummary(value: unknown): ScanSummary {
  if (!isRecord(value)) throw new Error('malformed scan summary')
  const { sourceKind, sourceLabel, resourceCount, warningCount, totalFileCount, totalBytes } = value
  if (
    !isString(sourceLabel, 80) ||
    !isSafeInteger(resourceCount, 100000) ||
    !isSafeInteger(warningCount, 100000) ||
    !isSafeInteger(totalFileCount, 1000000) ||
    !isSafeInteger(totalBytes)
  ) {
    throw new Error('malformed scan summary')
  }
  return {
    sourceKind: decodeScanSourceKind(sourceKind),
    sourceLabel,
    resourceCount,
    warningCount,
    totalFileCount,
    totalBytes,
  }
}

function decodeResourceSummary(value: unknown): ResourceSummary {
  if (!isRecord(value)) throw new Error('malformed resource summary')
  const { resourceHandle, sourceKind, displayName, status, fileCount, totalBytes, warningCount } = value
  if (
    !isCanonicalUuidV4Handle(resourceHandle) ||
    !isString(displayName, 80) ||
    !isSafeInteger(fileCount, 1000000) ||
    !isSafeInteger(totalBytes) ||
    !isSafeInteger(warningCount, 100000)
  ) {
    throw new Error('malformed resource summary')
  }
  return {
    resourceHandle,
    sourceKind: decodeScanSourceKind(sourceKind),
    displayName,
    status: decodeResourceStatus(status),
    fileCount,
    totalBytes,
    warningCount,
  }
}

function decodeResourceDetail(value: unknown): ResourceDetail {
  if (!isRecord(value)) throw new Error('malformed resource detail')
  const { resourceHandle, sourceKind, displayName, status, manifest, escrow, statistics, findings, omittedFindingCount } =
    value
  if (
    !isCanonicalUuidV4Handle(resourceHandle) ||
    !isString(displayName, 80) ||
    !isRecord(manifest) ||
    !isRecord(escrow) ||
    !isRecord(statistics) ||
    !Array.isArray(findings) ||
    findings.length > 50 ||
    !isSafeInteger(omittedFindingCount, 100000)
  ) {
    throw new Error('malformed resource detail')
  }
  if (
    !['fxmanifest', 'resourceManifest', 'none'].includes(String(manifest.kind)) ||
    !isSafeInteger(manifest.clientScriptCount, 100000) ||
    !isSafeInteger(manifest.serverScriptCount, 100000) ||
    !isSafeInteger(manifest.sharedScriptCount, 100000) ||
    !isSafeInteger(manifest.dataFileCount, 100000) ||
    typeof manifest.hasUiPage !== 'boolean' ||
    !['notAvailable', 'none', 'partial', 'protected'].includes(String(escrow.state)) ||
    !isSafeInteger(escrow.protectedFileCount, 1000000) ||
    !isSafeInteger(escrow.ignoredFileCount, 1000000) ||
    !isSafeInteger(escrow.unsupportedFileCount, 1000000) ||
    !isSafeInteger(statistics.fileCount, 1000000) ||
    !isSafeInteger(statistics.totalBytes)
  ) {
    throw new Error('malformed resource detail')
  }
  const decodedFindings = findings.map((finding) => {
    if (!isRecord(finding)) throw new Error('malformed finding')
    if (
      !['scanWarningsPresent', 'manifestWarningsPresent', 'escrowWarningsPresent', 'packageEntriesUnassigned'].includes(
        String(finding.code),
      ) ||
      !['info', 'warning'].includes(String(finding.severity)) ||
      !isString(finding.message, 160)
    ) {
      throw new Error('malformed finding')
    }
    return {
      code: finding.code as ResourceDetail['findings'][number]['code'],
      severity: finding.severity as ResourceDetail['findings'][number]['severity'],
      message: finding.message,
    }
  })
  return {
    resourceHandle,
    sourceKind: decodeScanSourceKind(sourceKind),
    displayName,
    status: decodeResourceStatus(status),
    manifest: {
      kind: manifest.kind as ResourceDetail['manifest']['kind'],
      clientScriptCount: manifest.clientScriptCount,
      serverScriptCount: manifest.serverScriptCount,
      sharedScriptCount: manifest.sharedScriptCount,
      dataFileCount: manifest.dataFileCount,
      hasUiPage: manifest.hasUiPage,
    },
    escrow: {
      state: escrow.state as ResourceDetail['escrow']['state'],
      protectedFileCount: escrow.protectedFileCount,
      ignoredFileCount: escrow.ignoredFileCount,
      unsupportedFileCount: escrow.unsupportedFileCount,
    },
    statistics: {
      fileCount: statistics.fileCount,
      totalBytes: statistics.totalBytes,
    },
    findings: decodedFindings,
    omittedFindingCount,
  }
}

export function decodeStartScanResponse(value: unknown): StartScanResponse {
  if (!isRecord(value) || !isCanonicalUuidV4Handle(value.scanHandle)) {
    throw new Error('malformed start scan response')
  }
  return {
    scanHandle: value.scanHandle,
    sourceKind: decodeScanSourceKind(value.sourceKind),
    summary: decodeScanSummary(value.summary),
  }
}

export function decodeScanGetSummaryResponse(value: unknown): ScanGetSummaryResponse {
  if (!isRecord(value)) throw new Error('malformed scan summary response')
  return { summary: decodeScanSummary(value.summary) }
}

export function decodeScanListResourcesResponse(value: unknown): ScanListResourcesResponse {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.total, 1000000) ||
    !isSafeInteger(value.offset, 1000000) ||
    !isSafeInteger(value.limit, 50) ||
    !Array.isArray(value.resources) ||
    value.resources.length > 50
  ) {
    throw new Error('malformed scan list response')
  }
  return {
    total: value.total,
    offset: value.offset,
    limit: value.limit,
    resources: value.resources.map(decodeResourceSummary),
  }
}

export function decodeScanGetResourceDetailResponse(value: unknown): ScanGetResourceDetailResponse {
  if (!isRecord(value)) throw new Error('malformed resource detail response')
  return { resource: decodeResourceDetail(value.resource) }
}

export function decodeScanReleaseResponse(value: unknown): ScanReleaseResponse {
  if (!isRecord(value) || value.released !== true) {
    throw new Error('malformed scan release response')
  }
  return { released: true }
}

export function decodeUpdateSourceMatchResponse(value: unknown): UpdateSourceMatchResponse {
  if (!hasExactOwnKeys(value, ['status'])) throw new Error('malformed source match response')
  if (value.status !== 'matched' && value.status !== 'mismatch') {
    throw new Error('malformed source match response')
  }
  return { status: value.status }
}

const baselineStatuses = new Set<BaselineStatus>(['missing', 'ready', 'multiple', 'ambiguous', 'blocked'])

function isCanonicalPresentationText(value: unknown): value is string {
  return isString(value, 160) && value.length > 0 && value.trim() === value &&
    !value.includes('  ') && !/[^\S ]/u.test(value) && !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
}

function decodeBaselineCandidate(value: unknown): BaselineCandidateSummary {
  if (!hasExactOwnKeys(value, ['candidateHandle', 'presentation']) ||
      !isCanonicalUuidV4Handle(value.candidateHandle)) {
    throw new Error('malformed baseline candidate')
  }
  const presentation = value.presentation
  if (!hasExactOwnKeys(presentation, [
    'resourceLabel', 'version', 'fileCount',
    'protectedFileCount', 'editableFileCount', 'retainedBlobCount', 'retainedBlobBytes',
  ]) || !isCanonicalPresentationText(presentation.resourceLabel)) {
    throw new Error('malformed baseline candidate')
  }
  const version = presentation.version
  let decodedVersion: BaselineVersionPresentation
  if (hasExactOwnKeys(version, ['state']) && version.state === 'notDeclared') {
    decodedVersion = { state: 'notDeclared' }
  } else if (hasExactOwnKeys(version, ['state']) && version.state === 'declaredEmpty') {
    decodedVersion = { state: 'declaredEmpty' }
  } else if (hasExactOwnKeys(version, ['state', 'value']) && version.state === 'declared' &&
      isCanonicalPresentationText(version.value)) {
    decodedVersion = { state: 'declared', value: version.value }
  } else {
    throw new Error('malformed baseline candidate')
  }
  for (const count of [presentation.fileCount, presentation.protectedFileCount,
    presentation.editableFileCount, presentation.retainedBlobCount, presentation.retainedBlobBytes]) {
    if (!isSafeInteger(count)) throw new Error('malformed baseline candidate')
  }
  return {
    candidateHandle: value.candidateHandle,
    presentation: {
      resourceLabel: presentation.resourceLabel,
      version: decodedVersion,
      fileCount: presentation.fileCount as number,
      protectedFileCount: presentation.protectedFileCount as number,
      editableFileCount: presentation.editableFileCount as number,
      retainedBlobCount: presentation.retainedBlobCount as number,
      retainedBlobBytes: presentation.retainedBlobBytes as number,
    },
  }
}

export function decodeUpdateBaselineStatusResponse(value: unknown): UpdateBaselineStatusResponse {
  if (!hasExactOwnKeys(value, ['baselineSessionHandle', 'status', 'candidates', 'catalogNeedsAttention'])) {
    throw new Error('malformed baseline status response')
  }
  if (!isCanonicalUuidV4Handle(value.baselineSessionHandle) ||
      typeof value.status !== 'string' || !baselineStatuses.has(value.status as BaselineStatus) ||
      !Array.isArray(value.candidates) || value.candidates.length > 256 ||
      typeof value.catalogNeedsAttention !== 'boolean') {
    throw new Error('malformed baseline status response')
  }
  return {
    baselineSessionHandle: value.baselineSessionHandle,
    status: value.status as BaselineStatus,
    candidates: value.candidates.map(decodeBaselineCandidate),
    catalogNeedsAttention: value.catalogNeedsAttention,
  }
}

export function decodeUpdateBaselineCaptureResponse(value: unknown): UpdateBaselineCaptureResponse {
  if (!hasExactOwnKeys(value, ['baseline', 'selectedCandidateHandle']) ||
      !isCanonicalUuidV4Handle(value.selectedCandidateHandle)) {
    throw new Error('malformed baseline capture response')
  }
  return {
    baseline: decodeUpdateBaselineStatusResponse(value.baseline),
    selectedCandidateHandle: value.selectedCandidateHandle,
  }
}

export function decodeUpdateBaselineReleaseResponse(value: unknown): UpdateBaselineReleaseResponse {
  if (!hasExactOwnKeys(value, ['released']) || value.released !== true) {
    throw new Error('malformed baseline release response')
  }
  return { released: true }
}

const planStatuses = new Set<UpdatePlanStatus>(['pendingDecisions', 'manualMergeRequired', 'readyToApply'])
const applyOutcomes = new Set<ApplyOutcome>([
  'committed',
  'rolled_back',
  'recovery_required',
  'published_recovery_unsealed',
  'published_recovery_failed',
  'safe_failure_before_publication',
])
const planDispositions = new Set<PlanDisposition>([
  'noChange',
  'useIncoming',
  'removeForIncoming',
  'preserveInstalled',
  'preserveInstalledDeletion',
  'addIncoming',
  'preserveInstalledAddition',
  'converged',
  'convergedAddition',
  'convergedDeletion',
  'mergeCandidate',
  'conflictReview',
  'deleteVsModifyConflict',
  'modifyVsDeleteConflict',
  'addVsAddConflict',
  'policyReview',
  'policyConflictReview',
])
const planDeltas = new Set<PlanDelta>(['unchanged', 'added', 'modified', 'deleted'])
const planRequirements = new Set<PlanReviewRequirement>(['noDecisionRequired', 'decisionRequired'])
const planActions = new Set<PlanReviewedAction>([
  'notRequired',
  'pending',
  'useIncomingState',
  'preserveInstalledState',
  'queueMergeAnalysis',
  'manualReview',
])
const planDecisionChoices = new Set<PlanDecisionChoice>([
  'acceptRecommended',
  'useIncomingState',
  'preserveInstalledState',
  'queueMergeAnalysis',
  'manualReview',
])
const policyTransitions = new Set<PolicyTransitionKind>(['none', 'changed'])
const planFindingCodes = new Set<PlanFindingCode>([
  'decisionRequired',
  'manualReviewRequired',
  'mergeAnalysisQueued',
  'conflictReviewRequired',
  'policyReviewRequired',
])

function decodeEnum<T extends string>(value: unknown, allowed: Set<T>, name: string): T {
  if (typeof value === 'string' && allowed.has(value as T)) return value as T
  throw new Error(`malformed ${name}`)
}

function decodePlanSummary(value: unknown) {
  if (!hasExactOwnKeys(value, [
    'planHandle', 'status', 'installedResourceLabel', 'incomingResourceLabel',
    'totalChangeCount', 'noChangeCount', 'incomingActionCount', 'preservedLocalCount',
    'convergedCount', 'mergeCandidateCount', 'conflictCount', 'policyReviewCount',
    'decisionsRequiredCount', 'pendingDecisionCount', 'manualReviewCount',
  ])) throw new Error('malformed plan summary')
  const {
    planHandle,
    status,
    installedResourceLabel,
    incomingResourceLabel,
    totalChangeCount,
    noChangeCount,
    incomingActionCount,
    preservedLocalCount,
    convergedCount,
    mergeCandidateCount,
    conflictCount,
    policyReviewCount,
    decisionsRequiredCount,
    pendingDecisionCount,
    manualReviewCount,
  } = value
  if (
    !isCanonicalUuidV4Handle(planHandle) ||
    !isString(installedResourceLabel, 80) ||
    !isString(incomingResourceLabel, 80) ||
    !isSafeInteger(totalChangeCount, 100000) ||
    !isSafeInteger(noChangeCount, 100000) ||
    !isSafeInteger(incomingActionCount, 100000) ||
    !isSafeInteger(preservedLocalCount, 100000) ||
    !isSafeInteger(convergedCount, 100000) ||
    !isSafeInteger(mergeCandidateCount, 100000) ||
    !isSafeInteger(conflictCount, 100000) ||
    !isSafeInteger(policyReviewCount, 100000) ||
    !isSafeInteger(decisionsRequiredCount, 100000) ||
    !isSafeInteger(pendingDecisionCount, 100000) ||
    !isSafeInteger(manualReviewCount, 100000)
  ) {
    throw new Error('malformed plan summary')
  }
  return {
    planHandle,
    status: decodeEnum(status, planStatuses, 'plan status'),
    installedResourceLabel,
    incomingResourceLabel,
    totalChangeCount,
    noChangeCount,
    incomingActionCount,
    preservedLocalCount,
    convergedCount,
    mergeCandidateCount,
    conflictCount,
    policyReviewCount,
    decisionsRequiredCount,
    pendingDecisionCount,
    manualReviewCount,
  }
}

function decodeAllowedDecisions(value: unknown): AllowedPlanDecision[] {
  if (!Array.isArray(value) || value.length > 5) throw new Error('malformed allowed decisions')
  const seen = new Set<PlanDecisionChoice>()
  return value.map((decision) => {
    if (!hasExactOwnKeys(decision, ['choice', 'requiresPolicyAcknowledgement'])) {
      throw new Error('malformed allowed decision')
    }
    const choice = decodeEnum(decision.choice, planDecisionChoices, 'plan decision choice')
    if (typeof decision.requiresPolicyAcknowledgement !== 'boolean' || seen.has(choice)) {
      throw new Error('malformed allowed decision')
    }
    seen.add(choice)
    return { choice, requiresPolicyAcknowledgement: decision.requiresPolicyAcknowledgement }
  })
}

function decodePlanChangeSummary(value: unknown): PlanChangeSummary {
  const baseKeys = [
    'changeHandle', 'displayPath', 'disposition', 'reviewRequirement', 'reviewedAction',
    'localDelta', 'incomingDelta', 'policyTransition', 'blocksAutomaticApply',
    'allowedDecisions', 'findingCount',
  ] as const
  const keys = isRecord(value) && Object.prototype.hasOwnProperty.call(value, 'recommendedAction')
    ? [...baseKeys, 'recommendedAction']
    : baseKeys
  if (!hasExactOwnKeys(value, keys)) throw new Error('malformed plan change summary')
  const {
    changeHandle,
    displayPath,
    disposition,
    reviewRequirement,
    reviewedAction,
    localDelta,
    incomingDelta,
    policyTransition,
    blocksAutomaticApply,
    recommendedAction,
    allowedDecisions,
    findingCount,
  } = value
  if (
    !isCanonicalUuidV4Handle(changeHandle) ||
    !isPlanDisplayPath(displayPath) ||
    typeof blocksAutomaticApply !== 'boolean' ||
    !isSafeInteger(findingCount, 100000)
  ) {
    throw new Error('malformed plan change summary')
  }
  const summary: PlanChangeSummary = {
    changeHandle,
    displayPath,
    disposition: decodeEnum(disposition, planDispositions, 'plan disposition'),
    reviewRequirement: decodeEnum(reviewRequirement, planRequirements, 'plan requirement'),
    reviewedAction: decodeEnum(reviewedAction, planActions, 'plan action'),
    localDelta: decodeEnum(localDelta, planDeltas, 'plan delta'),
    incomingDelta: decodeEnum(incomingDelta, planDeltas, 'plan delta'),
    policyTransition: decodeEnum(policyTransition, policyTransitions, 'policy transition'),
    blocksAutomaticApply,
    allowedDecisions: decodeAllowedDecisions(allowedDecisions),
    findingCount,
  }
  if (recommendedAction !== undefined) {
    summary.recommendedAction = decodeEnum(recommendedAction, planActions, 'plan action')
  }
  return summary
}

function decodePlanFindings(value: unknown) {
  if (!Array.isArray(value) || value.length > 50) throw new Error('malformed plan findings')
  return value.map((finding) => {
    if (!isRecord(finding)) throw new Error('malformed plan finding')
    const { code, severity, message } = finding
    if (!['info', 'warning'].includes(String(severity)) || !isString(message, 160)) {
      throw new Error('malformed plan finding')
    }
    return {
      code: decodeEnum(code, planFindingCodes, 'plan finding code'),
      severity: severity as 'info' | 'warning',
      message,
    }
  })
}

function decodePlanChangeDetail(value: unknown): PlanChangeDetail {
  const baseKeys = [
    'changeHandle', 'displayPath', 'disposition', 'reviewRequirement', 'reviewedAction',
    'localDelta', 'incomingDelta', 'policyTransition', 'blocksAutomaticApply',
    'baselineState', 'installedState', 'incomingState', 'allowedDecisions', 'findings',
    'omittedFindingCount',
  ] as const
  const keys = isRecord(value) && Object.prototype.hasOwnProperty.call(value, 'recommendedAction')
    ? [...baseKeys, 'recommendedAction']
    : baseKeys
  if (!hasExactOwnKeys(value, keys)) throw new Error('malformed plan change detail')
  const {
    changeHandle,
    displayPath,
    disposition,
    reviewRequirement,
    reviewedAction,
    localDelta,
    incomingDelta,
    policyTransition,
    blocksAutomaticApply,
    baselineState,
    installedState,
    incomingState,
    recommendedAction,
    allowedDecisions,
    findings,
    omittedFindingCount,
  } = value
  const fileStates = new Set<FilePresenceState>(['absent', 'present'])
  if (
    !isCanonicalUuidV4Handle(changeHandle) ||
    !isPlanDisplayPath(displayPath) ||
    !(recommendedAction === undefined || decodeEnum(recommendedAction, planActions, 'plan action')) ||
    !fileStates.has(baselineState as FilePresenceState) ||
    !fileStates.has(installedState as FilePresenceState) ||
    !fileStates.has(incomingState as FilePresenceState) ||
    typeof blocksAutomaticApply !== 'boolean' ||
    !isSafeInteger(omittedFindingCount, 100000)
  ) {
    throw new Error('malformed plan change detail')
  }
  const detail: PlanChangeDetail = {
    changeHandle,
    displayPath,
    disposition: decodeEnum(disposition, planDispositions, 'plan disposition'),
    reviewRequirement: decodeEnum(reviewRequirement, planRequirements, 'plan requirement'),
    reviewedAction: decodeEnum(reviewedAction, planActions, 'plan action'),
    localDelta: decodeEnum(localDelta, planDeltas, 'plan delta'),
    incomingDelta: decodeEnum(incomingDelta, planDeltas, 'plan delta'),
    policyTransition: decodeEnum(policyTransition, policyTransitions, 'policy transition'),
    blocksAutomaticApply,
    baselineState: baselineState as FilePresenceState,
    installedState: installedState as FilePresenceState,
    incomingState: incomingState as FilePresenceState,
    allowedDecisions: decodeAllowedDecisions(allowedDecisions),
    findings: decodePlanFindings(findings),
    omittedFindingCount,
  }
  if (recommendedAction !== undefined) detail.recommendedAction = decodeEnum(recommendedAction, planActions, 'plan action')
  return detail
}

export function decodeCreateUpdatePlanResponse(value: unknown): CreateUpdatePlanResponse {
  if (!isRecord(value) || !isCanonicalUuidV4Handle(value.planHandle)) {
    throw new Error('malformed create plan response')
  }
  const summary = decodePlanSummary(value.summary)
  if (summary.planHandle !== value.planHandle) throw new Error('malformed create plan response')
  return {
    planHandle: value.planHandle,
    summary,
  }
}

export function decodeUpdatePlanGetSummaryResponse(value: unknown): UpdatePlanGetSummaryResponse {
  if (!isRecord(value)) throw new Error('malformed plan summary response')
  return { summary: decodePlanSummary(value.summary) }
}

export function decodeUpdatePlanListChangesResponse(value: unknown): UpdatePlanListChangesResponse {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.total, 100000) ||
    !isSafeInteger(value.offset, 100000) ||
    !isSafeInteger(value.limit, 50) ||
    !Array.isArray(value.changes) ||
    value.changes.length > 50
  ) {
    throw new Error('malformed plan list response')
  }
  return {
    total: value.total,
    offset: value.offset,
    limit: value.limit,
    changes: value.changes.map(decodePlanChangeSummary),
  }
}

export function decodeUpdatePlanGetChangeDetailResponse(value: unknown): UpdatePlanGetChangeDetailResponse {
  if (!isRecord(value)) throw new Error('malformed plan change detail response')
  return { change: decodePlanChangeDetail(value.change) }
}

const diffAvailabilities = new Set<PlanDiffAvailability>([
  'available',
  'protected_content',
  'not_merged',
])
const diffLineOrigins = new Set<PlanDiffLineOrigin>([
  'baseline',
  'installed',
  'incoming',
  'converged',
])
/** Mirrors the backend's own per-file and per-line ceilings; anything larger is malformed. */
const MAX_DIFF_LINES = 400
const MAX_DIFF_LINE_CHARS = 240

function decodePlanDiffLine(value: unknown): PlanDiffLine {
  if (
    !isRecord(value) ||
    !isString(value.origin, 32) ||
    !diffLineOrigins.has(value.origin as PlanDiffLineOrigin) ||
    typeof value.text !== 'string' ||
    value.text.length > MAX_DIFF_LINE_CHARS ||
    typeof value.truncated !== 'boolean'
  ) {
    throw new Error('malformed plan diff line')
  }
  return {
    origin: value.origin as PlanDiffLineOrigin,
    text: value.text,
    truncated: value.truncated,
  }
}

export function decodeUpdatePlanGetChangeDiffResponse(
  value: unknown,
): UpdatePlanGetChangeDiffResponse {
  if (
    !isRecord(value) ||
    !isString(value.availability, 32) ||
    !diffAvailabilities.has(value.availability as PlanDiffAvailability) ||
    !Array.isArray(value.lines) ||
    value.lines.length > MAX_DIFF_LINES ||
    typeof value.truncated !== 'boolean'
  ) {
    throw new Error('malformed plan change diff response')
  }
  const availability = value.availability as PlanDiffAvailability
  if (availability !== 'available' && value.lines.length > 0) {
    throw new Error('malformed plan change diff response')
  }
  return {
    availability,
    lines: value.lines.map(decodePlanDiffLine),
    truncated: value.truncated,
  }
}

export function decodeUpdatePlanReleaseResponse(value: unknown): UpdatePlanReleaseResponse {
  if (!isRecord(value) || value.released !== true) {
    throw new Error('malformed plan release response')
  }
  return { released: true }
}

export function decodeUpdatePlanSubmitDecisionsResponse(
  value: unknown,
): UpdatePlanSubmitDecisionsResponse {
  if (!hasExactOwnKeys(value, ['planHandle', 'summary']) || !isCanonicalUuidV4Handle(value.planHandle)) {
    throw new Error('malformed submit plan decisions response')
  }
  const summary = decodePlanSummary(value.summary)
  if (summary.planHandle !== value.planHandle) throw new Error('malformed submit plan decisions response')
  return { planHandle: value.planHandle, summary }
}

export function decodeUpdatePlanApplyResponse(value: unknown): UpdatePlanApplyResponse {
  const outcome = exactOwnDataProperty(value, 'outcome')
  if (outcome === undefined) throw new Error('malformed plan apply response')
  return { outcome: decodeEnum(outcome.value, applyOutcomes, 'apply outcome') }
}

const recoveryStatuses = new Set<RecoveryStatus>([
  'clear',
  'recovery_available',
  'committed',
  'rolled_back',
  'safe_restart',
  'recovery_required',
  'manual_attention',
  'ambiguous',
  'unsupported',
])
const recoveryOverviewDispositions = new Set<RecoveryOverviewDisposition>([
  'clear',
  'attention_required',
])
const recoveryCandidateStates = new Set<RecoveryCandidateState>([
  'recoverable',
  'committed',
  'rolled_back',
  'safe_restart',
  'recovery_required',
])
const recoveryActionHints = new Set<RecoveryActionHint>(['recover', 'none'])
const recoveryOutcomes = new Set<RecoveryOutcome>([
  'recovered_committed',
  'recovered_rolled_back',
  'safe_restart',
  'recovery_still_required',
])

export function decodeUpdateRecoveryStatusResponse(value: unknown): UpdateRecoveryStatusResponse {
  if (!hasExactOwnKeys(value, ['recoveryHandle', 'resourceLabel', 'status', 'candidateCount'])) {
    throw new Error('malformed recovery status response')
  }
  if (
    !isCanonicalUuidV4Handle(value.recoveryHandle) ||
    !isString(value.resourceLabel, 80) ||
    !isSafeInteger(value.candidateCount, 8)
  ) {
    throw new Error('malformed recovery status response')
  }
  return {
    recoveryHandle: value.recoveryHandle,
    resourceLabel: value.resourceLabel,
    status: decodeEnum(value.status, recoveryStatuses, 'recovery status'),
    candidateCount: value.candidateCount,
  }
}

export function decodeUpdateRecoveryOverviewResponse(
  value: unknown,
): UpdateRecoveryOverviewResponse {
  if (!hasExactOwnKeys(value, [
    'disposition',
    'activeRecovery',
    'terminalEvidence',
    'manualAttention',
    'unsupportedEvidence',
  ])) {
    throw new Error('malformed recovery overview response')
  }
  const activeRecovery = value.activeRecovery
  const terminalEvidence = value.terminalEvidence
  const manualAttention = value.manualAttention
  const unsupportedEvidence = value.unsupportedEvidence
  if (typeof activeRecovery !== 'boolean' || typeof terminalEvidence !== 'boolean' ||
      typeof manualAttention !== 'boolean' || typeof unsupportedEvidence !== 'boolean') {
    throw new Error('malformed recovery overview response')
  }
  const disposition = decodeEnum(
    value.disposition,
    recoveryOverviewDispositions,
    'recovery overview disposition',
  )
  const hasAttention = activeRecovery || terminalEvidence || manualAttention || unsupportedEvidence
  if ((disposition === 'clear') === hasAttention) {
    throw new Error('malformed recovery overview response')
  }
  return {
    disposition,
    activeRecovery,
    terminalEvidence,
    manualAttention,
    unsupportedEvidence,
  }
}

export function decodeUpdateRecoveryRetireTerminalResponse(
  value: unknown,
): UpdateRecoveryRetireTerminalResponse {
  if (!hasExactOwnKeys(value, ['retiredCount', 'alreadyRetiredCount'])) {
    throw new Error('malformed terminal retirement response')
  }
  if (
    !isSafeInteger(value.retiredCount, 10_000) ||
    !isSafeInteger(value.alreadyRetiredCount, 10_000)
  ) {
    throw new Error('malformed terminal retirement response')
  }
  return {
    retiredCount: value.retiredCount,
    alreadyRetiredCount: value.alreadyRetiredCount,
  }
}

function decodeRecoveryCandidate(value: unknown): RecoveryCandidateSummary {
  if (
    !hasExactOwnKeys(value, [
      'candidateHandle',
      'resourceLabel',
      'state',
      'recoverable',
      'actionHint',
    ]) ||
    !isCanonicalUuidV4Handle(value.candidateHandle) ||
    !isString(value.resourceLabel, 80) ||
    typeof value.recoverable !== 'boolean'
  ) {
    throw new Error('malformed recovery candidate')
  }
  const state = decodeEnum(value.state, recoveryCandidateStates, 'recovery candidate state')
  const actionHint = decodeEnum(value.actionHint, recoveryActionHints, 'recovery action hint')
  if (value.recoverable !== (state === 'recoverable' || state === 'recovery_required')) {
    throw new Error('malformed recovery candidate')
  }
  if (actionHint !== (value.recoverable ? 'recover' : 'none')) {
    throw new Error('malformed recovery candidate')
  }
  return {
    candidateHandle: value.candidateHandle,
    resourceLabel: value.resourceLabel,
    state,
    recoverable: value.recoverable,
    actionHint,
  }
}

export function decodeUpdateRecoveryListCandidatesResponse(
  value: unknown,
): UpdateRecoveryListCandidatesResponse {
  const candidates = exactOwnDataProperty(value, 'candidates')
  if (
    candidates === undefined ||
    !Array.isArray(candidates.value) ||
    candidates.value.length > 8
  ) {
    throw new Error('malformed recovery candidate list')
  }
  return { candidates: candidates.value.map(decodeRecoveryCandidate) }
}

export function decodeUpdateRecoveryExecuteResponse(
  value: unknown,
): UpdateRecoveryExecuteResponse {
  const outcome = exactOwnDataProperty(value, 'outcome')
  if (outcome === undefined) throw new Error('malformed recovery execute response')
  return { outcome: decodeEnum(outcome.value, recoveryOutcomes, 'recovery outcome') }
}

export function decodeUpdateRecoveryReleaseResponse(
  value: unknown,
): UpdateRecoveryReleaseResponse {
  const released = exactOwnDataProperty(value, 'released')
  if (released?.value !== true) throw new Error('malformed recovery release response')
  return { released: true }
}

// --- The two-way update ------------------------------------------------------------------------

const twoWayDispositions = new Set<TwoWayFileDisposition>([
  'unchanged',
  'take_from_update',
  'review',
  'keep_local_only',
])
/** Mirrors the backend's own listing cap; anything larger is malformed. */
const MAX_TWO_WAY_FILES = 4096
const MAX_TWO_WAY_PATH_CHARS = 512
/** A declared manifest version longer than this is not one. */
const MAX_VERSION_CHARS = 64

function decodeTwoWayFile(value: unknown): TwoWayFile {
  if (
    !isRecord(value) ||
    !isString(value.path, MAX_TWO_WAY_PATH_CHARS) ||
    !isString(value.disposition, 32) ||
    !twoWayDispositions.has(value.disposition as TwoWayFileDisposition) ||
    typeof value.editable !== 'boolean' ||
    typeof value.untouched !== 'boolean' ||
    typeof value.mergedByKey !== 'boolean' ||
    !isSafeInteger(value.blockCount, MAX_TWO_WAY_FILE_BLOCKS)
  ) {
    throw new Error('malformed two-way file')
  }
  return {
    path: value.path,
    disposition: value.disposition as TwoWayFileDisposition,
    editable: value.editable,
    untouched: value.untouched,
    mergedByKey: value.mergedByKey,
    blockCount: value.blockCount,
  }
}

function decodeTwoWaySummary(value: unknown): TwoWaySummary {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.unchanged, MAX_TWO_WAY_FILES) ||
    !isSafeInteger(value.takeFromUpdate, MAX_TWO_WAY_FILES) ||
    !isSafeInteger(value.review, MAX_TWO_WAY_FILES) ||
    !isSafeInteger(value.keepLocalOnly, MAX_TWO_WAY_FILES) ||
    !isSafeInteger(value.total, MAX_TWO_WAY_FILES)
  ) {
    throw new Error('malformed two-way summary')
  }
  return {
    unchanged: value.unchanged,
    takeFromUpdate: value.takeFromUpdate,
    review: value.review,
    keepLocalOnly: value.keepLocalOnly,
    total: value.total,
  }
}

export function decodeTwoWayPreviewResponse(value: unknown): TwoWayPreviewResponse {
  if (
    !isRecord(value) ||
    !isCanonicalUuidV4Handle(value.handle) ||
    !isString(value.resource, 256) ||
    !Array.isArray(value.files) ||
    value.files.length > MAX_TWO_WAY_FILES ||
    !isSafeInteger(value.omittedFileCount) ||
    !Array.isArray(value.unmergeable) ||
    value.unmergeable.length > MAX_TWO_WAY_FILES
  ) {
    throw new Error('malformed two-way preview response')
  }
  const unmergeable = value.unmergeable.map((entry) => {
    if (!isString(entry, MAX_TWO_WAY_PATH_CHARS)) throw new Error('malformed two-way preview response')
    return entry
  })
  for (const key of ['installedVersion', 'incomingVersion'] as const) {
    if (value[key] !== undefined && !isString(value[key], MAX_VERSION_CHARS)) {
      throw new Error('malformed two-way preview response')
    }
  }
  return {
    handle: value.handle,
    resource: value.resource,
    ...(value.installedVersion === undefined
      ? {}
      : { installedVersion: value.installedVersion as string }),
    ...(value.incomingVersion === undefined
      ? {}
      : { incomingVersion: value.incomingVersion as string }),
    summary: decodeTwoWaySummary(value.summary),
    files: value.files.map(decodeTwoWayFile),
    omittedFileCount: value.omittedFileCount,
    unmergeable,
    usedRememberedBaseline: value.usedRememberedBaseline === true,
    ...(isString(value.rememberedBaselineVersion, MAX_VERSION_CHARS)
      ? { rememberedBaselineVersion: value.rememberedBaselineVersion }
      : {}),
  }
}

const twoWayRowKinds = new Set<TwoWayRowKind>(['context', 'yours', 'theirs', 'gap'])
/** Mirrors the backend's own per-file ceiling on separately decidable changes. */
/** Raster kinds a viewer draws. Markup a browser would run is deliberately not among them. */
const RASTER_MEDIA_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/bmp',
  'image/x-icon',
])
const WHOLE_FILE_REASONS = new Set(['not_text', 'too_far_apart', 'too_large'])
/** The backend sends at most forty; anything longer is not the response this expects. */
const MAX_KEPT_KEYS = 40
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/
/** A megabyte of bytes is about 1.4 million base64 characters; this is the ceiling for two. */
const MAX_IMAGE_BASE64_CHARS = 1_400_000
const MAX_TWO_WAY_BLOCKS = 2048
/**
 * The most decisions one file can hold.
 *
 * A file whose lines were too many to draw still holds every decision it has, and the file list
 * reports them so the operator can answer it as a whole. That count is bounded by the lines the
 * merge will read at all, not by the smaller number a view is allowed to render.
 */
const MAX_TWO_WAY_FILE_BLOCKS = 20000

function decodeTwoWayDiffRow(value: unknown): TwoWayDiffRow {
  if (
    !isRecord(value) ||
    !isString(value.kind, 32) ||
    !twoWayRowKinds.has(value.kind as TwoWayRowKind) ||
    typeof value.text !== 'string' ||
    value.text.length > MAX_DIFF_LINE_CHARS + 1 ||
    typeof value.truncated !== 'boolean' ||
    (value.block !== undefined && !isSafeInteger(value.block, MAX_TWO_WAY_BLOCKS)) ||
    (value.skipped !== undefined && !isSafeInteger(value.skipped)) ||
    (value.installedLine !== undefined && !isSafeInteger(value.installedLine)) ||
    (value.incomingLine !== undefined && !isSafeInteger(value.incomingLine))
  ) {
    throw new Error('malformed two-way diff row')
  }
  const kind = value.kind as TwoWayRowKind
  // Only a line of a change belongs to a decision. A row that carries neither, or claims both,
  // would be drawn against a control that decides nothing.
  const decides = kind === 'yours' || kind === 'theirs'
  if (decides !== (value.block !== undefined)) {
    throw new Error('malformed two-way diff row')
  }
  if ((kind === 'gap') !== (value.skipped !== undefined)) {
    throw new Error('malformed two-way diff row')
  }
  return {
    kind,
    ...(value.block === undefined ? {} : { block: value.block as number }),
    text: value.text,
    truncated: value.truncated,
    ...(value.skipped === undefined ? {} : { skipped: value.skipped as number }),
    ...(value.installedLine === undefined
      ? {}
      : { installedLine: value.installedLine as number }),
    ...(value.incomingLine === undefined ? {} : { incomingLine: value.incomingLine as number }),
  }
}

export function decodeTwoWayGetDiffResponse(value: unknown): TwoWayGetDiffResponse {
  if (
    !isRecord(value) ||
    typeof value.available !== 'boolean' ||
    !Array.isArray(value.rows) ||
    value.rows.length > MAX_DIFF_LINES ||
    !isSafeInteger(value.blockCount, MAX_TWO_WAY_BLOCKS) ||
    !Array.isArray(value.defaultChoices) ||
    value.defaultChoices.length !== value.blockCount ||
    !value.defaultChoices.every((choice) => typeof choice === 'boolean') ||
    typeof value.truncated !== 'boolean' ||
    typeof value.omitted !== 'boolean'
  ) {
    throw new Error('malformed two-way diff response')
  }
  if (!value.available && value.rows.length > 0) {
    throw new Error('malformed two-way diff response')
  }
  const rows = value.rows.map(decodeTwoWayDiffRow)
  // Every decision the response promises must actually be reachable from a row, or the operator
  // would be shipping a tick for a change they were never shown.
  const blocks = new Set(rows.flatMap((row) => (row.block === undefined ? [] : [row.block])))
  if (!value.truncated && blocks.size !== value.blockCount) {
    throw new Error('malformed two-way diff response')
  }
  // A picture is handed to the page as a data URL and nothing else. The media type is the
  // backend's, from a fixed list of raster kinds, and the payload is checked to be base64 before
  // it is ever put in an `src` — a page that renders whatever a string says is a page that runs it.
  const mediaType = isString(value.imageMediaType, 32) ? value.imageMediaType : undefined
  const image = (side: unknown): string | undefined => {
    if (mediaType === undefined || !RASTER_MEDIA_TYPES.has(mediaType)) return undefined
    // An empty payload is not a picture. Handing one to an `img` draws a broken frame where the
    // page promised a picture, which is worse than saying there is none.
    if (!isString(side, MAX_IMAGE_BASE64_CHARS) || side.length === 0 || !BASE64.test(side)) {
      return undefined
    }
    return `data:${mediaType};base64,${side}`
  }
  const installedImage = image(value.installedImage)
  const incomingImage = image(value.incomingImage)
  return {
    available: value.available,
    rows,
    blockCount: value.blockCount,
    defaultChoices: value.defaultChoices as boolean[],
    truncated: value.truncated,
    omitted: value.omitted,
    ...(value.mergedByKey === true ? { mergedByKey: true } : {}),
    ...(Array.isArray(value.keptKeys) &&
    value.keptKeys.length <= MAX_KEPT_KEYS &&
    value.keptKeys.every((key) => isString(key, MAX_TWO_WAY_PATH_CHARS))
      ? { keptKeys: value.keptKeys as string[] }
      : {}),
    ...(isSafeInteger(value.keptKeyCount, MAX_TWO_WAY_FILE_BLOCKS)
      ? { keptKeyCount: value.keptKeyCount }
      : {}),
    ...(WHOLE_FILE_REASONS.has(value.wholeFileReason as string)
      ? { wholeFileReason: value.wholeFileReason as TwoWayWholeFileReason }
      : {}),
    ...(installedImage === undefined ? {} : { installedImage }),
    ...(incomingImage === undefined ? {} : { incomingImage }),
  }
}

export function decodeTwoWayApplyResponse(value: unknown): TwoWayApplyResponse {
  if (!isRecord(value) || !isString(value.outcome, 64)) {
    throw new Error('malformed two-way apply response')
  }
  return { outcome: value.outcome, summary: decodeTwoWaySummary(value.summary) }
}

export function decodeTwoWayReleaseResponse(value: unknown): TwoWayReleaseResponse {
  if (!isRecord(value) || value.released !== true) {
    throw new Error('malformed two-way release response')
  }
  return { released: true }
}

/** Mirrors the backend's own ceilings on the remembered update list. */
const MAX_HISTORY_ENTRIES = 200
const MAX_HISTORY_RESOURCE_CHARS = 128

function decodeUpdateHistoryEntry(value: unknown): UpdateHistoryEntry {
  if (
    !isRecord(value) ||
    !isString(value.resource, MAX_HISTORY_RESOURCE_CHARS) ||
    typeof value.undoable !== 'boolean' ||
    !isString(value.outcome, 64) ||
    !isSafeInteger(value.appliedAtMs) ||
    !isSafeInteger(value.reviewed) ||
    !isSafeInteger(value.replaced) ||
    !isSafeInteger(value.total)
  ) {
    throw new Error('malformed update history entry')
  }
  for (const key of ['fromVersion', 'toVersion'] as const) {
    if (value[key] !== undefined && !isString(value[key], MAX_VERSION_CHARS)) {
      throw new Error('malformed update history entry')
    }
  }
  if (value.id !== undefined && !isString(value.id, 64)) {
    throw new Error('malformed update history entry')
  }
  return {
    id: value.id === undefined ? '' : (value.id as string),
    undoable: value.undoable,
    resource: value.resource,
    outcome: value.outcome,
    appliedAtMs: value.appliedAtMs,
    reviewed: value.reviewed,
    replaced: value.replaced,
    total: value.total,
    ...(value.fromVersion === undefined ? {} : { fromVersion: value.fromVersion as string }),
    ...(value.toVersion === undefined ? {} : { toVersion: value.toVersion as string }),
  }
}

/** More kept packages than one machine accumulates, and a bound on the list either way. */
const MAX_HELD_BASELINES = 512

function decodeHeldBaseline(value: unknown): HeldBaseline {
  if (
    !isRecord(value) ||
    !isString(value.resource, MAX_HISTORY_RESOURCE_CHARS) ||
    !isSafeInteger(value.bytes)
  ) {
    throw new Error('malformed held baseline')
  }
  if (value.version !== undefined && !isString(value.version, MAX_VERSION_CHARS)) {
    throw new Error('malformed held baseline')
  }
  // Absent is the answer that matters — it is what makes one releasable — so an unexpected value
  // is refused rather than read as absence.
  if (value.neededFor !== undefined && value.neededFor !== 'installation' && value.neededFor !== 'undo') {
    throw new Error('malformed held baseline')
  }
  return {
    resource: value.resource,
    bytes: value.bytes,
    ...(value.version === undefined ? {} : { version: value.version as string }),
    ...(value.neededFor === undefined
      ? {}
      : { neededFor: value.neededFor as 'installation' | 'undo' }),
  }
}

export function decodeStorageReportResponse(value: unknown): StorageReportResponse {
  if (
    !isRecord(value) ||
    !Array.isArray(value.baselines) ||
    value.baselines.length > MAX_HELD_BASELINES ||
    !isSafeInteger(value.heldBytes) ||
    !isSafeInteger(value.releasableBytes) ||
    !isSafeInteger(value.stagedCount) ||
    !isSafeInteger(value.stagedBytes) ||
    !isSafeInteger(value.stagedReleasableBytes)
  ) {
    throw new Error('malformed storage report')
  }
  return {
    baselines: value.baselines.map(decodeHeldBaseline),
    heldBytes: value.heldBytes,
    releasableBytes: value.releasableBytes,
    stagedCount: value.stagedCount,
    stagedBytes: value.stagedBytes,
    stagedReleasableBytes: value.stagedReleasableBytes,
  }
}

export function decodeStorageReleaseResponse(value: unknown): StorageReleaseResponse {
  if (!isRecord(value) || !isSafeInteger(value.released) || !isSafeInteger(value.bytes)) {
    throw new Error('malformed storage release response')
  }
  return { released: value.released, bytes: value.bytes }
}

export function decodeUpdateHistoryUndoResponse(value: unknown): UpdateHistoryUndoResponse {
  if (
    !isRecord(value) ||
    !isSafeInteger(value.restored) ||
    !isSafeInteger(value.removed) ||
    !isSafeInteger(value.unchanged) ||
    !isSafeInteger(value.skipped) ||
    !isSafeInteger(value.missing)
  ) {
    throw new Error('malformed undo response')
  }
  return {
    restored: value.restored,
    removed: value.removed,
    unchanged: value.unchanged,
    skipped: value.skipped,
    missing: value.missing,
  }
}

export function decodeUpdateHistoryListResponse(value: unknown): UpdateHistoryListResponse {
  if (!isRecord(value) || !Array.isArray(value.entries) || value.entries.length > MAX_HISTORY_ENTRIES) {
    throw new Error('malformed update history response')
  }
  return { entries: value.entries.map(decodeUpdateHistoryEntry) }
}
