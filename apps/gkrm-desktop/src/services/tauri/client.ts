import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import {
  decodeAppInfo,
  decodeCreateUpdatePlanResponse,
  decodeDesktopError,
  decodeListSelectionsResponse,
  decodeReleaseSelectionResponse,
  decodeScanGetResourceDetailResponse,
  decodeScanGetSummaryResponse,
  decodeScanListResourcesResponse,
  decodeScanReleaseResponse,
  decodeSelectionDialogResult,
  decodeStartScanResponse,
  decodeUpdatePlanGetChangeDetailResponse,
  decodeUpdatePlanGetChangeDiffResponse,
  decodeUpdatePlanGetSummaryResponse,
  decodeUpdatePlanApplyResponse,
  decodeUpdatePlanListChangesResponse,
  decodeUpdatePlanReleaseResponse,
  decodeUpdatePlanSubmitDecisionsResponse,
  decodeUpdateRecoveryExecuteResponse,
  decodeUpdateRecoveryListCandidatesResponse,
  decodeUpdateRecoveryOverviewResponse,
  decodeUpdateRecoveryRetireTerminalResponse,
  decodeUpdateRecoveryReleaseResponse,
  decodeUpdateRecoveryStatusResponse,
  decodeUpdateSourceMatchResponse,
  decodeUpdateBaselineStatusResponse,
  decodeUpdateBaselineCaptureResponse,
  decodeUpdateBaselineReleaseResponse,
  decodeTwoWayApplyResponse,
  decodeTwoWayGetDiffResponse,
  decodeTwoWayPreviewResponse,
  decodeTwoWayReleaseResponse,
  decodeStorageReleaseResponse,
  decodeStorageReportResponse,
  decodeUpdateHistoryListResponse,
  decodeUpdateHistoryUndoResponse,
  genericDesktopError,
  isCanonicalUuidV4Handle,
} from './decoders'
import type {
  AppInfo,
  StorageReleaseResponse,
  StorageReportResponse,
  UpdateHistoryListResponse,
  UpdateHistoryUndoResponse,
  TwoWayApplyRequest,
  TwoWayApplyResponse,
  TwoWayGetDiffRequest,
  TwoWayGetDiffResponse,
  TwoWayPreviewRequest,
  TwoWayPreviewResponse,
  TwoWayReleaseRequest,
  TwoWayReleaseResponse,
  CreateUpdatePlanRequest,
  CreateUpdatePlanResponse,
  DesktopError,
  InspectPackageRequest,
  ListSelectionsRequest,
  ListSelectionsResponse,
  PlanDisposition,
  PlanDecisionChoice,
  PlanReviewRequirement,
  ReleaseSelectionRequest,
  ReleaseSelectionResponse,
  ScanGetResourceDetailRequest,
  ScanGetResourceDetailResponse,
  ScanGetSummaryRequest,
  ScanGetSummaryResponse,
  ScanInstalledRootRequest,
  ScanListResourcesRequest,
  ScanListResourcesResponse,
  ScanReleaseRequest,
  ScanReleaseResponse,
  SelectionDialogResult,
  SelectionKind,
  StartScanResponse,
  UpdatePlanGetChangeDetailRequest,
  UpdatePlanGetChangeDetailResponse,
  UpdatePlanGetChangeDiffRequest,
  UpdatePlanGetChangeDiffResponse,
  UpdatePlanGetSummaryRequest,
  UpdatePlanGetSummaryResponse,
  UpdatePlanApplyRequest,
  UpdatePlanApplyResponse,
  UpdatePlanListChangesRequest,
  UpdatePlanListChangesResponse,
  UpdatePlanReleaseRequest,
  UpdatePlanReleaseResponse,
  UpdatePlanSubmitDecisionsRequest,
  UpdatePlanSubmitDecisionsResponse,
  UpdateRecoveryExecuteRequest,
  UpdateRecoveryExecuteResponse,
  UpdateRecoveryListCandidatesRequest,
  UpdateRecoveryListCandidatesResponse,
  UpdateRecoveryOverviewResponse,
  UpdateRecoveryRetireTerminalRequest,
  UpdateRecoveryRetireTerminalResponse,
  UpdateRecoveryReleaseRequest,
  UpdateRecoveryReleaseResponse,
  UpdateRecoveryStatusRequest,
  UpdateRecoveryStatusResponse,
  UpdateSourceMatchRequest,
  UpdateSourceMatchResponse,
  UpdateBaselineStatusRequest,
  UpdateBaselineStatusResponse,
  UpdateBaselineCaptureRequest,
  UpdateBaselineCaptureResponse,
  UpdateBaselineReleaseRequest,
  UpdateBaselineReleaseResponse,
} from '@/types/commands'

const commands = {
  appGetInfo: 'app_get_info',
  selectInstalledRoot: 'select_installed_root',
  selectPackageFile: 'select_package_file',
  sessionListSelections: 'session_list_selections',
  sessionReleaseSelection: 'session_release_selection',
  scanInstalledRoot: 'scan_installed_root',
  scanGetSummary: 'scan_get_summary',
  scanListResources: 'scan_list_resources',
  scanGetResourceDetail: 'scan_get_resource_detail',
  scanRelease: 'scan_release',
  updateRecoveryOverview: 'update_recovery_overview',
  updateRecoveryRetireTerminal: 'update_recovery_retire_terminal',
  updateRecoveryStatus: 'update_recovery_status',
  updateRecoveryListCandidates: 'update_recovery_list_candidates',
  updateRecoveryExecute: 'update_recovery_execute',
  updateRecoveryRelease: 'update_recovery_release',
  updateTwoWayPreview: 'update_two_way_preview',
  updateTwoWayGetDiff: 'update_two_way_get_diff',
  updateTwoWayApply: 'update_two_way_apply',
  updateTwoWayRelease: 'update_two_way_release',
  storageReport: 'storage_report',
  storageRelease: 'storage_release',
  updateHistoryList: 'update_history_list',
  updateHistoryUndo: 'update_history_undo',
} as const

function invoke(command: string, args: Record<string, unknown>): Promise<unknown> {
  return tauriInvoke(command, args)
}

class TauriClientError extends Error {
  readonly desktopError: DesktopError

  constructor(error: DesktopError) {
    super(error.message)
    this.name = 'TauriClientError'
    this.desktopError = error
  }
}

function isSelectionKind(value: unknown): value is SelectionKind {
  return value === 'installedRoot' || value === 'packageFile'
}

function validateHandle(handle: unknown): handle is string {
  return isCanonicalUuidV4Handle(handle)
}

function validatePage(request: ScanListResourcesRequest): boolean {
  return (
    validateHandle(request.scanHandle) &&
    Number.isSafeInteger(request.offset) &&
    request.offset >= 0 &&
    Number.isSafeInteger(request.limit) &&
    request.limit > 0 &&
    request.limit <= 50 &&
    (request.query === undefined ||
      (typeof request.query === 'string' &&
        request.query.length <= 128 &&
        [...request.query].length <= 64 &&
        !/[\u0000-\u001f\u007f]/u.test(request.query))) &&
    (request.status === undefined || request.status === 'available' || request.status === 'warnings')
  )
}

function isPlanRequirement(value: unknown): value is PlanReviewRequirement {
  return value === 'noDecisionRequired' || value === 'decisionRequired'
}

function isPlanDisposition(value: unknown): value is PlanDisposition {
  return (
    value === 'noChange' ||
    value === 'useIncoming' ||
    value === 'removeForIncoming' ||
    value === 'preserveInstalled' ||
    value === 'preserveInstalledDeletion' ||
    value === 'addIncoming' ||
    value === 'preserveInstalledAddition' ||
    value === 'converged' ||
    value === 'convergedAddition' ||
    value === 'convergedDeletion' ||
    value === 'mergeCandidate' ||
    value === 'conflictReview' ||
    value === 'deleteVsModifyConflict' ||
    value === 'modifyVsDeleteConflict' ||
    value === 'addVsAddConflict' ||
    value === 'policyReview' ||
    value === 'policyConflictReview'
  )
}

function isPlanDecisionChoice(value: unknown): value is PlanDecisionChoice {
  return value === 'acceptRecommended' || value === 'useIncomingState' ||
    value === 'preserveInstalledState' || value === 'queueMergeAnalysis' || value === 'manualReview'
}

function validatePlanPage(request: UpdatePlanListChangesRequest): boolean {
  return (
    validateHandle(request.planHandle) &&
    Number.isSafeInteger(request.offset) &&
    request.offset >= 0 &&
    Number.isSafeInteger(request.limit) &&
    request.limit > 0 &&
    request.limit <= 50 &&
    (request.query === undefined ||
      (typeof request.query === 'string' &&
        request.query.length <= 128 &&
        [...request.query].length <= 64 &&
        !/[\u0000-\u001f\u007f]/u.test(request.query))) &&
    (request.reviewRequirement === undefined || isPlanRequirement(request.reviewRequirement)) &&
    (request.disposition === undefined || isPlanDisposition(request.disposition))
  )
}

function invalidRequestError(): TauriClientError {
  return new TauriClientError({
    code: 'invalid_request',
    category: 'input',
    message: 'The desktop request is invalid.',
    recoverable: true,
  })
}

function normalizeError(error: unknown): DesktopError {
  return decodeDesktopError(error)
}

async function invokeDecoded<T>(
  command: string,
  args: Record<string, unknown>,
  decode: (value: unknown) => T,
): Promise<T> {
  try {
    const result = await invoke(command, args)
    return decode(result)
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('malformed')) {
      throw new TauriClientError(genericDesktopError)
    }
    throw new TauriClientError(normalizeError(error))
  }
}

export function asDesktopError(error: unknown): DesktopError {
  return error instanceof TauriClientError ? error.desktopError : genericDesktopError
}

export { isCanonicalUuidV4Handle }

export function appGetInfo(): Promise<AppInfo> {
  return invokeDecoded(commands.appGetInfo, {}, decodeAppInfo)
}

export function selectInstalledRoot(): Promise<SelectionDialogResult> {
  return invokeDecoded(commands.selectInstalledRoot, {}, decodeSelectionDialogResult)
}

export function selectPackageFile(): Promise<SelectionDialogResult> {
  return invokeDecoded(commands.selectPackageFile, {}, decodeSelectionDialogResult)
}

export function sessionListSelections(
  request: ListSelectionsRequest = {},
): Promise<ListSelectionsResponse> {
  if (request.kind !== undefined && !isSelectionKind(request.kind)) {
    throw new TauriClientError({
      code: 'invalid_request',
      category: 'input',
      message: 'The desktop request is invalid.',
      recoverable: true,
    })
  }
  return invokeDecoded(commands.sessionListSelections, { request }, decodeListSelectionsResponse)
}

export function sessionReleaseSelection(
  request: ReleaseSelectionRequest,
): Promise<ReleaseSelectionResponse> {
  if (!validateHandle(request.handle)) {
    throw invalidRequestError()
  }
  return invokeDecoded(commands.sessionReleaseSelection, { request }, decodeReleaseSelectionResponse)
}

export function scanInstalledRoot(request: ScanInstalledRootRequest): Promise<StartScanResponse> {
  if (!validateHandle(request.selectionHandle)) throw invalidRequestError()
  return invokeDecoded(commands.scanInstalledRoot, { request }, decodeStartScanResponse)
}

export function scanGetSummary(request: ScanGetSummaryRequest): Promise<ScanGetSummaryResponse> {
  if (!validateHandle(request.scanHandle)) throw invalidRequestError()
  return invokeDecoded(commands.scanGetSummary, { request }, decodeScanGetSummaryResponse)
}

export function scanListResources(
  request: ScanListResourcesRequest,
): Promise<ScanListResourcesResponse> {
  if (!validatePage(request)) throw invalidRequestError()
  return invokeDecoded(commands.scanListResources, { request }, decodeScanListResourcesResponse)
}

export function scanGetResourceDetail(
  request: ScanGetResourceDetailRequest,
): Promise<ScanGetResourceDetailResponse> {
  if (!validateHandle(request.scanHandle) || !validateHandle(request.resourceHandle)) {
    throw invalidRequestError()
  }
  return invokeDecoded(commands.scanGetResourceDetail, { request }, decodeScanGetResourceDetailResponse)
}

export function scanRelease(request: ScanReleaseRequest): Promise<ScanReleaseResponse> {
  if (!validateHandle(request.scanHandle)) throw invalidRequestError()
  return invokeDecoded(commands.scanRelease, { request }, decodeScanReleaseResponse)
}

function validateSourceRequest(request: UpdateSourceMatchRequest): boolean {
  return validateHandle(request.installedSelectionHandle) &&
    validateHandle(request.installedScanHandle) &&
    validateHandle(request.installedResourceHandle) &&
    validateHandle(request.packageSelectionHandle) &&
    validateHandle(request.packageScanHandle) &&
    validateHandle(request.packageResourceHandle)
}

export function updateRecoveryOverview(): Promise<UpdateRecoveryOverviewResponse> {
  return invokeDecoded(commands.updateRecoveryOverview, {}, decodeUpdateRecoveryOverviewResponse)
}

export function updateRecoveryRetireTerminal(
  request: UpdateRecoveryRetireTerminalRequest,
): Promise<UpdateRecoveryRetireTerminalResponse> {
  if (request.acknowledged !== true) throw invalidRequestError()
  return invokeDecoded(
    commands.updateRecoveryRetireTerminal,
    { request: { acknowledged: true } },
    decodeUpdateRecoveryRetireTerminalResponse,
  )
}

export function updateRecoveryStatus(
  request: UpdateRecoveryStatusRequest,
): Promise<UpdateRecoveryStatusResponse> {
  if (
    !validateHandle(request.installedSelectionHandle) ||
    !validateHandle(request.installedScanHandle) ||
    !validateHandle(request.installedResourceHandle)
  ) {
    throw invalidRequestError()
  }
  return invokeDecoded(
    commands.updateRecoveryStatus,
    {
      request: {
        installedSelectionHandle: request.installedSelectionHandle,
        installedScanHandle: request.installedScanHandle,
        installedResourceHandle: request.installedResourceHandle,
      },
    },
    decodeUpdateRecoveryStatusResponse,
  )
}

export function updateRecoveryListCandidates(
  request: UpdateRecoveryListCandidatesRequest,
): Promise<UpdateRecoveryListCandidatesResponse> {
  if (!validateHandle(request.recoveryHandle)) throw invalidRequestError()
  return invokeDecoded(
    commands.updateRecoveryListCandidates,
    { request: { recoveryHandle: request.recoveryHandle } },
    decodeUpdateRecoveryListCandidatesResponse,
  )
}

export function updateRecoveryExecute(
  request: UpdateRecoveryExecuteRequest,
): Promise<UpdateRecoveryExecuteResponse> {
  if (!validateHandle(request.recoveryHandle) || !validateHandle(request.candidateHandle)) {
    throw invalidRequestError()
  }
  return invokeDecoded(
    commands.updateRecoveryExecute,
    {
      request: {
        recoveryHandle: request.recoveryHandle,
        candidateHandle: request.candidateHandle,
      },
    },
    decodeUpdateRecoveryExecuteResponse,
  )
}

export function updateRecoveryRelease(
  request: UpdateRecoveryReleaseRequest,
): Promise<UpdateRecoveryReleaseResponse> {
  if (!validateHandle(request.recoveryHandle)) throw invalidRequestError()
  return invokeDecoded(
    commands.updateRecoveryRelease,
    { request: { recoveryHandle: request.recoveryHandle } },
    decodeUpdateRecoveryReleaseResponse,
  )
}

// --- The two-way update ------------------------------------------------------------------------

/** The most characters a resource-relative path may carry across the boundary. */
const MAX_TWO_WAY_PATH_CHARS = 512

export function updateTwoWayPreview(
  request: TwoWayPreviewRequest,
): Promise<TwoWayPreviewResponse> {
  if (
    !validateHandle(request.installedSelectionHandle) ||
    !validateHandle(request.packageSelectionHandle) ||
    (request.baselineSelectionHandle !== undefined &&
      !validateHandle(request.baselineSelectionHandle))
  ) {
    throw invalidRequestError()
  }
  return invokeDecoded(
    commands.updateTwoWayPreview,
    {
      request: {
        installedSelectionHandle: request.installedSelectionHandle,
        packageSelectionHandle: request.packageSelectionHandle,
        // Absent rather than null: the backend reads a missing field as "no baseline", and a null
        // would be a value it has to have an opinion about.
        ...(request.baselineSelectionHandle === undefined
          ? {}
          : { baselineSelectionHandle: request.baselineSelectionHandle }),
      },
    },
    decodeTwoWayPreviewResponse,
  )
}

export function updateTwoWayGetDiff(request: TwoWayGetDiffRequest): Promise<TwoWayGetDiffResponse> {
  if (
    !validateHandle(request.handle) ||
    typeof request.path !== 'string' ||
    request.path.length === 0 ||
    [...request.path].length > MAX_TWO_WAY_PATH_CHARS
  ) {
    throw invalidRequestError()
  }
  return invokeDecoded(
    commands.updateTwoWayGetDiff,
    { request: { handle: request.handle, path: request.path } },
    decodeTwoWayGetDiffResponse,
  )
}

/** The most files, and the most decisions per file, one apply may carry. */
const MAX_TWO_WAY_CHOICE_FILES = 4096
const MAX_TWO_WAY_CHOICES = 2048

export function updateTwoWayApply(request: TwoWayApplyRequest): Promise<TwoWayApplyResponse> {
  const choicesAreSound =
    Array.isArray(request.choices) &&
    request.choices.length <= MAX_TWO_WAY_CHOICE_FILES &&
    request.choices.every(
      (choice) =>
        typeof choice.path === 'string' &&
        choice.path.length > 0 &&
        [...choice.path].length <= MAX_TWO_WAY_PATH_CHARS &&
        Array.isArray(choice.takeFromUpdate) &&
        choice.takeFromUpdate.length <= MAX_TWO_WAY_CHOICES &&
        choice.takeFromUpdate.every((take) => typeof take === 'boolean'),
    )
  if (
    !validateHandle(request.handle) ||
    typeof request.keepSettings !== 'boolean' ||
    !choicesAreSound
  ) {
    throw invalidRequestError()
  }
  return invokeDecoded(
    commands.updateTwoWayApply,
    {
      request: {
        handle: request.handle,
        keepSettings: request.keepSettings,
        choices: request.choices.map((choice) => ({
          path: choice.path,
          takeFromUpdate: [...choice.takeFromUpdate],
        })),
      },
    },
    decodeTwoWayApplyResponse,
  )
}

export function updateTwoWayRelease(
  request: TwoWayReleaseRequest,
): Promise<TwoWayReleaseResponse> {
  if (!validateHandle(request.handle)) throw invalidRequestError()
  return invokeDecoded(
    commands.updateTwoWayRelease,
    { request: { handle: request.handle } },
    decodeTwoWayReleaseResponse,
  )
}

/** What the workspace is holding, and how much of it nothing needs. Reads nothing of the operator's. */
export function storageReport(): Promise<StorageReportResponse> {
  return invokeDecoded(commands.storageReport, {}, decodeStorageReportResponse)
}

/** Let go of every kept package nothing reaches for. */
export function storageRelease(): Promise<StorageReleaseResponse> {
  return invokeDecoded(commands.storageRelease, {}, decodeStorageReleaseResponse)
}

export function updateHistoryList(): Promise<UpdateHistoryListResponse> {
  return invokeDecoded(commands.updateHistoryList, {}, decodeUpdateHistoryListResponse)
}

export function updateHistoryUndo(request: { id: string }): Promise<UpdateHistoryUndoResponse> {
  return invokeDecoded(
    commands.updateHistoryUndo,
    { request: { id: request.id } },
    decodeUpdateHistoryUndoResponse,
  )
}
