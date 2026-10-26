import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useRecoveryStore } from './recovery'
import type { DesktopError, RecoveryOutcome, RecoveryStatus } from '@/types/commands'

const recoveryHandle = '123e4567-e89b-42d3-a456-426614174050'
const secondRecoveryHandle = '123e4567-e89b-42d3-a456-426614174051'
const candidateHandle = '123e4567-e89b-42d3-a456-426614174052'

const api = vi.hoisted(() => ({
  asDesktopError: vi.fn((error: unknown): DesktopError => {
    if (typeof error === 'object' && error !== null && 'code' in error) return error as DesktopError
    return { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
  }),
  updateRecoveryStatus: vi.fn(),
  updateRecoveryOverview: vi.fn(),
  updateRecoveryRetireTerminal: vi.fn(),
  updateRecoveryListCandidates: vi.fn(),
  updateRecoveryExecute: vi.fn(),
  updateRecoveryRelease: vi.fn(),
}))

vi.mock('@/services/tauri/client', () => api)

const intent = {
  selectionHandle: '123e4567-e89b-42d3-a456-426614174000',
  scanHandle: '123e4567-e89b-42d3-a456-426614174010',
  resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
  sourceLabel: 'installed',
  resourceLabel: 'phone',
}

function status(value: RecoveryStatus, handle = recoveryHandle, candidateCount = 0) {
  return { recoveryHandle: handle, resourceLabel: 'phone', status: value, candidateCount }
}

function candidate(recoverable = true) {
  return {
    candidateHandle,
    resourceLabel: 'phone',
    state: recoverable ? ('recovery_required' as const) : ('committed' as const),
    recoverable,
    actionHint: recoverable ? ('recover' as const) : ('none' as const),
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

const clearOverview = {
  disposition: 'clear' as const,
  activeRecovery: false,
  terminalEvidence: false,
  manualAttention: false,
  unsupportedEvidence: false,
}

const terminalOverview = {
  disposition: 'attention_required' as const,
  activeRecovery: false,
  terminalEvidence: true,
  manualAttention: false,
  unsupportedEvidence: false,
}

function establishActiveOverview() {
  const store = useRecoveryStore()
  store.overviewPhase = 'ready'
  store.overview = {
    disposition: 'attention_required',
    activeRecovery: true,
    terminalEvidence: false,
    manualAttention: false,
    unsupportedEvidence: false,
  }
}

describe('recovery store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    for (const mock of Object.values(api)) if ('mockReset' in mock) mock.mockReset()
    api.asDesktopError.mockImplementation((error: unknown): DesktopError => {
      if (typeof error === 'object' && error !== null && 'code' in error) return error as DesktopError
      return { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
    })
    api.updateRecoveryRelease.mockResolvedValue({ released: true })
    api.updateRecoveryOverview.mockResolvedValue(clearOverview)
    api.updateRecoveryRetireTerminal.mockResolvedValue({
      retiredCount: 1,
      alreadyRetiredCount: 0,
    })
  })

  it('starts unknown, establishes clear startup truth, and never executes recovery automatically', async () => {
    const store = useRecoveryStore()
    expect(store.overviewPhase).toBe('unknown')
    expect(store.overviewIsClear).toBe(false)
    api.updateRecoveryOverview.mockResolvedValueOnce({
      disposition: 'clear',
      activeRecovery: false,
      terminalEvidence: false,
      manualAttention: false,
      unsupportedEvidence: false,
    })
    await store.refreshOverview()
    expect(store.overviewPhase).toBe('ready')
    expect(store.overviewIsClear).toBe(true)
    expect(api.updateRecoveryExecute).not.toHaveBeenCalled()
  })

  it('keeps active and terminal evidence blocked and rejects a stale overview response', async () => {
    const first = deferred<{
      disposition: 'clear'
      activeRecovery: false
      terminalEvidence: false
      manualAttention: false
      unsupportedEvidence: false
    }>()
    api.updateRecoveryOverview
      .mockReturnValueOnce(first.promise)
      .mockResolvedValueOnce({
        disposition: 'attention_required',
        activeRecovery: false,
        terminalEvidence: true,
        manualAttention: false,
        unsupportedEvidence: false,
      })
    const store = useRecoveryStore()
    const h1 = store.refreshOverview()
    const h2 = store.refreshOverview()
    await h2
    first.resolve({ disposition: 'clear', activeRecovery: false, terminalEvidence: false, manualAttention: false, unsupportedEvidence: false })
    await h1
    expect(store.overviewNeedsAttention).toBe(true)
    expect(store.overview?.terminalEvidence).toBe(true)
    expect(api.updateRecoveryExecute).not.toHaveBeenCalled()
  })

  it('fails closed when overview cannot be established', async () => {
    const error: DesktopError = { code: 'recovery_busy', category: 'busy', message: 'Unavailable.', recoverable: true }
    api.updateRecoveryOverview.mockRejectedValueOnce(error)
    const store = useRecoveryStore()
    await store.refreshOverview()
    expect(store.overviewPhase).toBe('error')
    expect(store.overviewIsClear).toBe(false)
    expect(store.overviewError).toEqual(error)
  })

  it('stores a clear status without candidates', async () => {
    api.updateRecoveryStatus.mockResolvedValue(status('clear'))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [] })
    const store = useRecoveryStore()
    await store.inspect(intent)
    expect(store.status).toBe('clear')
    expect(store.candidates).toEqual([])
  })

  it('stores only sanitized recovery candidates', async () => {
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    const store = useRecoveryStore()
    await store.inspect(intent)
    expect(store.candidates).toEqual([candidate()])
    expect(JSON.stringify(store.$state)).not.toMatch(/transaction|artifact|journal|sha256|C:\\|\/tmp\//i)
  })

  it.each(['manual_attention', 'ambiguous', 'unsupported'] as const)(
    'represents %s without inventing a candidate',
    async (value) => {
      api.updateRecoveryStatus.mockResolvedValue(status(value))
      api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [] })
      const store = useRecoveryStore()
      await store.inspect(intent)
      expect(store.status).toBe(value)
      expect(store.candidates).toHaveLength(0)
    },
  )

  it.each([
    'recovered_committed',
    'recovered_rolled_back',
    'safe_restart',
    'recovery_still_required',
  ] as RecoveryOutcome[])('stores trusted outcome %s', async (outcome) => {
    establishActiveOverview()
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    api.updateRecoveryExecute.mockResolvedValue({ outcome })
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.execute(candidateHandle)
    expect(store.outcome).toBe(outcome)
  })

  it('prevents duplicate execution while one request is pending', async () => {
    establishActiveOverview()
    let resolve!: (value: { outcome: RecoveryOutcome }) => void
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    api.updateRecoveryExecute.mockReturnValue(new Promise((done) => { resolve = done }))
    const store = useRecoveryStore()
    await store.inspect(intent)
    const first = store.execute(candidateHandle)
    await store.execute(candidateHandle)
    expect(api.updateRecoveryExecute).toHaveBeenCalledTimes(1)
    resolve({ outcome: 'safe_restart' })
    await first
  })

  it('marks stale candidate state as refresh required', async () => {
    establishActiveOverview()
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    api.updateRecoveryExecute.mockRejectedValue({
      code: 'recovery_candidate_stale', category: 'selection', message: 'Refresh recovery status.', recoverable: true,
    })
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.execute(candidateHandle)
    expect(store.status).toBeUndefined()
    expect(store.error?.code).toBe('recovery_candidate_stale')
  })

  it('reconciles a lost recovery response and never keeps the old candidate actionable', async () => {
    establishActiveOverview()
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    api.updateRecoveryExecute.mockRejectedValue({
      code: 'internal', category: 'internal', message: 'Response unavailable.', recoverable: false,
    })
    api.updateRecoveryOverview.mockResolvedValueOnce(terminalOverview)
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.execute(candidateHandle)
    expect(api.updateRecoveryExecute).toHaveBeenCalledTimes(1)
    expect(store.recoveryHandle).toBeUndefined()
    expect(store.candidates).toEqual([])
    expect(store.overview).toEqual(terminalOverview)
    expect(store.canFinalizeTerminal).toBe(true)
  })

  it('keeps active recovery authoritative after a lost recovery response', async () => {
    establishActiveOverview()
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    api.updateRecoveryExecute.mockRejectedValue({
      code: 'internal', category: 'internal', message: 'Response unavailable.', recoverable: false,
    })
    api.updateRecoveryOverview.mockResolvedValueOnce({
      disposition: 'attention_required', activeRecovery: true, terminalEvidence: false,
      manualAttention: false, unsupportedEvidence: false,
    })
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.execute(candidateHandle)
    expect(api.updateRecoveryExecute).toHaveBeenCalledTimes(1)
    expect(store.overview?.activeRecovery).toBe(true)
    expect(store.recoveryHandle).toBeUndefined()
  })

  it('reconciles a synchronously rejected recovery instead of blocking every later operation', async () => {
    establishActiveOverview()
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    api.updateRecoveryExecute.mockImplementationOnce(() => {
      throw {
        code: 'invalid_request', category: 'validation', message: 'The request was rejected.', recoverable: false,
      }
    })
    api.updateRecoveryOverview.mockResolvedValueOnce(terminalOverview)
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.execute(candidateHandle)
    expect(store.durableOperationInProgress).toBe(false)
    expect(store.overviewPhase).toBe('ready')
    expect(store.lastDurableResult?.error?.code).toBe('invalid_request')
    expect(store.error?.code).toBe('invalid_request')
  })

  it('finalizes only after acknowledgement and trusts the following overview', async () => {
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview
    await store.finalizeTerminal(false)
    expect(api.updateRecoveryRetireTerminal).not.toHaveBeenCalled()

    api.updateRecoveryOverview.mockResolvedValueOnce(clearOverview)
    await store.finalizeTerminal(true)
    expect(api.updateRecoveryRetireTerminal).toHaveBeenCalledTimes(1)
    expect(api.updateRecoveryOverview).toHaveBeenCalledTimes(1)
    expect(store.overviewIsClear).toBe(true)
  })

  it('reconciles a lost finalize response without retrying the mutation', async () => {
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview
    api.updateRecoveryRetireTerminal.mockRejectedValueOnce({
      code: 'internal', category: 'internal', message: 'Response unavailable.', recoverable: false,
    })
    api.updateRecoveryOverview.mockResolvedValueOnce(clearOverview)
    await store.finalizeTerminal(true)
    expect(api.updateRecoveryRetireTerminal).toHaveBeenCalledTimes(1)
    expect(store.overviewIsClear).toBe(true)
    await store.refreshOverview()
    expect(api.updateRecoveryRetireTerminal).toHaveBeenCalledTimes(1)
  })

  it('leaves terminal evidence retryable after a lost finalize response', async () => {
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview
    api.updateRecoveryRetireTerminal.mockRejectedValueOnce({
      code: 'internal', category: 'internal', message: 'Response unavailable.', recoverable: false,
    })
    api.updateRecoveryOverview.mockResolvedValueOnce(terminalOverview)
    await store.finalizeTerminal(true)
    expect(api.updateRecoveryRetireTerminal).toHaveBeenCalledTimes(1)
    expect(store.canFinalizeTerminal).toBe(true)
  })

  it('fails closed when finalize reconciliation overview fails and Retry is read-only', async () => {
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview
    api.updateRecoveryOverview.mockRejectedValueOnce({
      code: 'recovery_busy', category: 'busy', message: 'State unavailable.', recoverable: true,
    })
    await store.finalizeTerminal(true)
    expect(store.overviewPhase).toBe('error')
    expect(store.overviewIsClear).toBe(false)
    api.updateRecoveryOverview.mockResolvedValueOnce(terminalOverview)
    await store.refreshOverview()
    expect(api.updateRecoveryRetireTerminal).toHaveBeenCalledTimes(1)
    expect(api.updateRecoveryOverview).toHaveBeenCalledTimes(2)
  })

  it('refuses finalization while an inspection is still in flight', async () => {
    const pending = deferred<ReturnType<typeof status>>()
    api.updateRecoveryStatus.mockReturnValueOnce(pending.promise)
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview

    const inspecting = store.inspect(intent)
    expect(store.canFinalizeTerminal).toBe(false)
    await store.finalizeTerminal(true)
    expect(api.updateRecoveryRetireTerminal).not.toHaveBeenCalled()

    pending.resolve(status('recovery_required', recoveryHandle, 1))
    await inspecting
    expect(store.recoveryHandle).toBe(recoveryHandle)
    expect(store.canFinalizeTerminal).toBe(true)
  })

  it('invalidates in-flight inspection authority even without a process-local handle', async () => {
    const store = useRecoveryStore()
    const before = store.generation
    await store.invalidateMutationSensitiveUpdateSession()
    expect(store.generation).toBeGreaterThan(before)
  })

  it('never strands the inspection loading state when a durable transition discards it', async () => {
    const pending = deferred<ReturnType<typeof status>>()
    api.updateRecoveryStatus.mockReturnValueOnce(pending.promise)
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate()] })
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview

    const inspecting = store.inspect(intent)
    expect(store.loading.status).toBe(true)
    await store.invalidateMutationSensitiveUpdateSession()
    pending.resolve(status('recovery_required', recoveryHandle, 1))
    await inspecting

    expect(store.loading.status).toBe(false)
    expect(store.recoveryHandle).toBeUndefined()
    expect(store.canFinalizeTerminal).toBe(true)
  })

  it('reconciles a synchronously rejected finalize and keeps the workspace check usable', async () => {
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = terminalOverview
    api.updateRecoveryRetireTerminal.mockImplementationOnce(() => {
      throw {
        code: 'invalid_request', category: 'validation', message: 'The request was rejected.', recoverable: false,
      }
    })
    api.updateRecoveryOverview.mockResolvedValueOnce(terminalOverview)
    await store.finalizeTerminal(true)
    expect(store.durableOperationInProgress).toBe(false)
    expect(store.canFinalizeTerminal).toBe(true)
    expect(store.lastDurableResult?.error?.code).toBe('invalid_request')
    await store.refreshOverview()
    expect(api.updateRecoveryRetireTerminal).toHaveBeenCalledTimes(1)
    expect(api.updateRecoveryOverview).toHaveBeenCalledTimes(2)
  })

  it.each([
    { activeRecovery: true, manualAttention: false, unsupportedEvidence: false },
    { activeRecovery: false, manualAttention: true, unsupportedEvidence: false },
    { activeRecovery: false, manualAttention: false, unsupportedEvidence: true },
  ])('does not finalize mixed blocking evidence: $activeRecovery/$manualAttention/$unsupportedEvidence', async (flags) => {
    const store = useRecoveryStore()
    store.overviewPhase = 'ready'
    store.overview = { ...terminalOverview, ...flags }
    await store.finalizeTerminal(true)
    expect(api.updateRecoveryRetireTerminal).not.toHaveBeenCalled()
  })

  it('releases and clears process-local session state', async () => {
    api.updateRecoveryStatus.mockResolvedValue(status('clear'))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [] })
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.releaseCurrent()
    expect(api.updateRecoveryRelease).toHaveBeenCalledWith({ recoveryHandle })
    expect(store.recoveryHandle).toBeUndefined()
  })

  it('refresh replaces the session and releases the old opaque handle', async () => {
    api.updateRecoveryStatus
      .mockResolvedValueOnce(status('clear'))
      .mockResolvedValueOnce(status('committed', secondRecoveryHandle, 1))
    api.updateRecoveryListCandidates
      .mockResolvedValueOnce({ candidates: [] })
      .mockResolvedValueOnce({ candidates: [candidate(false)] })
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.inspect(intent)
    expect(store.recoveryHandle).toBe(secondRecoveryHandle)
    expect(api.updateRecoveryRelease).toHaveBeenCalledWith({ recoveryHandle })
  })

  it('rejects inconsistent candidate counts and releases the new session', async () => {
    api.updateRecoveryStatus.mockResolvedValue(status('recovery_required', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [] })
    const store = useRecoveryStore()
    await store.inspect(intent)
    expect(api.updateRecoveryRelease).toHaveBeenCalledWith({ recoveryHandle })
    expect(store.error?.code).toBe('internal')
  })

  it('does not execute retained terminal evidence from the store', async () => {
    api.updateRecoveryStatus.mockResolvedValue(status('committed', recoveryHandle, 1))
    api.updateRecoveryListCandidates.mockResolvedValue({ candidates: [candidate(false)] })
    const store = useRecoveryStore()
    await store.inspect(intent)
    await store.execute(candidateHandle)
    expect(api.updateRecoveryExecute).not.toHaveBeenCalled()
  })
})
