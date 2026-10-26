import { defineStore } from 'pinia'

import {
  asDesktopError,
  updateRecoveryExecute,
  updateRecoveryListCandidates,
  updateRecoveryOverview,
  updateRecoveryRelease,
  updateRecoveryRetireTerminal,
  updateRecoveryStatus,
} from '@/services/tauri/client'
import { useAppStore } from '@/stores/app'
import { startDurableInvocation } from '@/stores/durableInvocation'
import type { ScanPlanningIntent } from '@/stores/scan'
import type {
  DesktopError,
  RecoveryCandidateSummary,
  RecoveryOutcome,
  RecoveryStatus,
  UpdateRecoveryOverviewResponse,
  UpdateRecoveryRetireTerminalResponse,
} from '@/types/commands'

export type RecoveryOverviewPhase = 'unknown' | 'checking' | 'ready' | 'error' | 'reconciling'
export type DurableUpdateOperation = 'apply' | 'undo' | 'recovery' | 'finalize'

interface DurableOperationResult {
  operation: DurableUpdateOperation
  responseReceived: boolean
  error: DesktopError | undefined
  retirement: UpdateRecoveryRetireTerminalResponse | undefined
}

interface RecoveryLoadingState {
  status: boolean
  execute: boolean
  release: boolean
}

interface RecoveryState {
  overviewPhase: RecoveryOverviewPhase
  overview: UpdateRecoveryOverviewResponse | undefined
  overviewError: DesktopError | undefined
  overviewGeneration: number
  durableOperation: DurableUpdateOperation | undefined
  durableOperationGeneration: number
  lastDurableResult: DurableOperationResult | undefined
  recoveryHandle: string | undefined
  resourceLabel: string | undefined
  status: RecoveryStatus | undefined
  candidates: RecoveryCandidateSummary[]
  outcome: RecoveryOutcome | undefined
  error: DesktopError | undefined
  loading: RecoveryLoadingState
  generation: number
  pendingReleaseHandles: string[]
}

const MAX_PENDING_RELEASES = 2

export const useRecoveryStore = defineStore('recovery', {
  state: (): RecoveryState => ({
    overviewPhase: 'unknown',
    overview: undefined,
    overviewError: undefined,
    overviewGeneration: 0,
    durableOperation: undefined,
    durableOperationGeneration: 0,
    lastDurableResult: undefined,
    recoveryHandle: undefined,
    resourceLabel: undefined,
    status: undefined,
    candidates: [],
    outcome: undefined,
    error: undefined,
    loading: { status: false, execute: false, release: false },
    generation: 0,
    pendingReleaseHandles: [],
  }),
  getters: {
    overviewIsClear: (state): boolean =>
      state.overviewPhase === 'ready' && state.overview?.disposition === 'clear',
    overviewNeedsAttention: (state): boolean =>
      state.overviewPhase === 'ready' && state.overview?.disposition === 'attention_required',
    durableOperationInProgress: (state): boolean => state.durableOperation !== undefined,
    canFinalizeTerminal(state): boolean {
      return state.overviewPhase === 'ready' &&
        state.durableOperation === undefined &&
        !state.loading.status &&
        !state.loading.execute &&
        !state.loading.release &&
        state.overview?.terminalEvidence === true &&
        state.overview.activeRecovery === false &&
        state.overview.manualAttention === false &&
        state.overview.unsupportedEvidence === false
    },
  },
  actions: {
    async refreshOverview() {
      if (this.durableOperation !== undefined) return
      await this.loadOverview('checking')
    },
    async loadOverview(phase: 'checking' | 'reconciling', operationGeneration?: number) {
      if (
        operationGeneration !== undefined &&
        (this.durableOperation === undefined || operationGeneration !== this.durableOperationGeneration)
      ) return
      const requestGeneration = ++this.overviewGeneration
      this.overviewPhase = phase
      this.overview = undefined
      this.overviewError = undefined
      try {
        const response = await updateRecoveryOverview()
        if (requestGeneration !== this.overviewGeneration ||
            (operationGeneration !== undefined && operationGeneration !== this.durableOperationGeneration)) return
        this.overview = response
        this.overviewPhase = 'ready'
      } catch (error) {
        if (requestGeneration !== this.overviewGeneration ||
            (operationGeneration !== undefined && operationGeneration !== this.durableOperationGeneration)) return
        const desktopError = asDesktopError(error)
        this.overview = undefined
        this.overviewError = desktopError
        this.overviewPhase = 'error'
        useAppStore().setError(desktopError)
      }
    },
    beginDurableOperation(operation: DurableUpdateOperation): number | undefined {
      if (this.durableOperation !== undefined || this.overviewPhase !== 'ready') return undefined
      const generation = ++this.durableOperationGeneration
      this.durableOperation = operation
      this.lastDurableResult = undefined
      return generation
    },
    markDurableInvocationStarted(generation: number) {
      if (generation !== this.durableOperationGeneration || this.durableOperation === undefined) return
      this.overviewGeneration += 1
      this.overviewPhase = 'reconciling'
      this.overview = undefined
      this.overviewError = undefined
    },
    async finishDurableOperation(
      generation: number,
      result: Omit<DurableOperationResult, 'operation'>,
    ) {
      if (generation !== this.durableOperationGeneration || this.durableOperation === undefined) return
      const operation = this.durableOperation
      this.lastDurableResult = { operation, ...result }
      try {
        const invalidated = await this.invalidateMutationSensitiveUpdateSession()
        if (!invalidated) throw new Error('mutation-sensitive session remained active')
      } catch (invalidationError) {
        const desktopError = asDesktopError(invalidationError)
        this.overviewGeneration += 1
        this.overview = undefined
        this.overviewError = desktopError
        this.overviewPhase = 'error'
        this.durableOperation = undefined
        useAppStore().setError(desktopError)
        return
      }
      try {
        await this.loadOverview('reconciling', generation)
      } finally {
        if (generation === this.durableOperationGeneration) this.durableOperation = undefined
      }
    },
    async invalidateMutationSensitiveUpdateSession(): Promise<boolean> {
      const recoveryHandle = this.recoveryHandle
      // A durable transition invalidates backend recovery authority even when
      // this frontend holds no handle yet, so an inspection that is still in
      // flight must not be allowed to publish its response afterwards.
      this.generation += 1
      if (recoveryHandle !== undefined) {
        this.clearLocal(recoveryHandle)
        await this.tryRelease(recoveryHandle)
      }
      const { useSessionStore } = await import('@/stores/session')
      return useSessionStore().invalidateAfterDurableMutation()
    },
    async finalizeTerminal(acknowledged: boolean) {
      if (acknowledged !== true || !this.canFinalizeTerminal) return
      const generation = this.beginDurableOperation('finalize')
      if (generation === undefined) return
      let responseReceived = false
      let error: DesktopError | undefined
      let retirement: UpdateRecoveryRetireTerminalResponse | undefined
      const invocation = startDurableInvocation(() =>
        updateRecoveryRetireTerminal({ acknowledged: true }),
      )
      this.markDurableInvocationStarted(generation)
      try {
        retirement = await invocation
        responseReceived = true
      } catch (unknownError) {
        error = asDesktopError(unknownError)
        useAppStore().setError(error)
      } finally {
        await this.finishDurableOperation(generation, { responseReceived, error, retirement })
      }
    },
    async inspect(intent: ScanPlanningIntent) {
      if (this.durableOperation !== undefined || this.loading.status || this.loading.execute ||
          intent.resourceHandle === undefined) return
      const requestGeneration = ++this.generation
      const previous = this.recoveryHandle
      let unpublishedHandle: string | undefined
      this.loading.status = true
      this.error = undefined
      this.outcome = undefined
      try {
        await this.retryPendingReleases()
        const response = await updateRecoveryStatus({
          installedSelectionHandle: intent.selectionHandle,
          installedScanHandle: intent.scanHandle,
          installedResourceHandle: intent.resourceHandle,
        })
        unpublishedHandle = response.recoveryHandle
        if (requestGeneration !== this.generation) {
          await this.tryRelease(response.recoveryHandle)
          return
        }
        const listed = await updateRecoveryListCandidates({
          recoveryHandle: response.recoveryHandle,
        })
        if (requestGeneration !== this.generation) {
          await this.tryRelease(response.recoveryHandle)
          return
        }
        if (listed.candidates.length !== response.candidateCount) {
          await this.tryRelease(response.recoveryHandle)
          this.loading.status = false
          this.captureError(new Error('malformed desktop response'))
          return
        }
        this.recoveryHandle = response.recoveryHandle
        this.resourceLabel = response.resourceLabel
        this.status = response.status
        this.candidates = listed.candidates
        unpublishedHandle = undefined
        if (previous !== undefined && previous !== response.recoveryHandle) {
          await this.tryRelease(previous)
        }
        await this.retryPendingReleases()
      } catch (error) {
        if (unpublishedHandle !== undefined && unpublishedHandle !== this.recoveryHandle) {
          await this.tryRelease(unpublishedHandle)
        }
        if (requestGeneration === this.generation) this.captureError(error)
      } finally {
        // Only one inspection can be in flight, so this request always owns the
        // flag. A generation bump from a concurrent durable transition discards
        // the response but must never strand the view in a loading state.
        this.loading.status = false
      }
    },
    async execute(candidateHandle: string) {
      if (this.durableOperation !== undefined || this.loading.execute || this.loading.status ||
          this.recoveryHandle === undefined) return
      const candidate = this.candidates.find(
        (value) => value.candidateHandle === candidateHandle && value.recoverable,
      )
      if (candidate === undefined) return
      const recoveryHandle = this.recoveryHandle
      const operationGeneration = this.beginDurableOperation('recovery')
      if (operationGeneration === undefined) return
      this.loading.execute = true
      this.error = undefined
      let responseReceived = false
      let operationError: DesktopError | undefined
      const invocation = startDurableInvocation(() =>
        updateRecoveryExecute({ recoveryHandle, candidateHandle }),
      )
      this.markDurableInvocationStarted(operationGeneration)
      this.clearLocal(recoveryHandle)
      try {
        const response = await invocation
        responseReceived = true
        this.outcome = response.outcome
      } catch (error) {
        this.captureError(error)
        operationError = this.error
      } finally {
        this.loading.execute = false
        await this.tryRelease(recoveryHandle)
        await this.finishDurableOperation(operationGeneration, {
          responseReceived,
          error: operationError,
          retirement: undefined,
        })
      }
    },
    async releaseCurrent() {
      if (this.recoveryHandle === undefined || this.loading.execute || this.loading.release) return
      const handle = this.recoveryHandle
      this.loading.release = true
      try {
        await updateRecoveryRelease({ recoveryHandle: handle })
        this.clearLocal(handle)
        await this.retryPendingReleases()
      } catch (error) {
        const desktopError = asDesktopError(error)
        if (desktopError.code === 'recovery_session_stale') {
          this.clearLocal(handle)
        } else {
          this.captureError(error)
        }
      } finally {
        this.loading.release = false
      }
    },
    async tryRelease(handle: string): Promise<boolean> {
      try {
        await updateRecoveryRelease({ recoveryHandle: handle })
        this.pendingReleaseHandles = this.pendingReleaseHandles.filter((value) => value !== handle)
        return true
      } catch (error) {
        if (asDesktopError(error).code === 'recovery_session_stale') {
          this.pendingReleaseHandles = this.pendingReleaseHandles.filter((value) => value !== handle)
          return true
        }
        if (!this.pendingReleaseHandles.includes(handle) && this.pendingReleaseHandles.length < MAX_PENDING_RELEASES) {
          this.pendingReleaseHandles.push(handle)
        }
        return false
      }
    },
    async retryPendingReleases() {
      for (const handle of [...this.pendingReleaseHandles]) await this.tryRelease(handle)
    },
    clearLocal(handle?: string) {
      if (handle !== undefined && this.recoveryHandle !== handle) return
      this.generation += 1
      this.recoveryHandle = undefined
      this.resourceLabel = undefined
      this.status = undefined
      this.candidates = []
      this.outcome = undefined
      this.error = undefined
    },
    captureError(error: unknown) {
      const desktopError = asDesktopError(error)
      this.error = desktopError
      useAppStore().setError(desktopError)
    },
  },
})
