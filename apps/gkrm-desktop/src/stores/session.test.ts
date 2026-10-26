import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useRecoveryStore } from './recovery'
import { useScanStore } from './scan'
import { useSessionStore } from './session'
import type { DesktopError, SelectionSummary, UpdatePlanSummary } from '@/types/commands'
import { establishClearRecoveryOverview } from '@/test/recoveryOverview'

const api = vi.hoisted(() => ({
  asDesktopError: vi.fn((error: unknown): DesktopError => error as DesktopError),
  isCanonicalUuidV4Handle: vi.fn(() => true),
  selectInstalledRoot: vi.fn(),
  selectPackageFile: vi.fn(),
  sessionListSelections: vi.fn(),
  sessionReleaseSelection: vi.fn(),
  scanRelease: vi.fn(),
  updatePlanRelease: vi.fn(),
  updatePlanApply: vi.fn(),
  updateSourceMatch: vi.fn(),
}))

vi.mock('@/services/tauri/client', () => api)

const oldInstalled: SelectionSummary = {
  handle: '123e4567-e89b-42d3-a456-426614174000',
  kind: 'installedRoot',
  displayLabel: 'old-resources',
}
const newInstalled: SelectionSummary = {
  handle: '123e4567-e89b-42d3-a456-426614174002',
  kind: 'installedRoot',
  displayLabel: 'new-resources',
}
const oldPackage: SelectionSummary = {
  handle: '123e4567-e89b-42d3-a456-426614174001',
  kind: 'packageFile',
  displayLabel: 'old-package.zip',
}
const newPackage: SelectionSummary = {
  handle: '123e4567-e89b-42d3-a456-426614174003',
  kind: 'packageFile',
  displayLabel: 'new-package.zip',
}

function planSummary(handle: string): UpdatePlanSummary {
  return {
    planHandle: handle,
    status: 'readyToApply',
    installedResourceLabel: 'phone',
    incomingResourceLabel: 'phone',
    totalChangeCount: 1,
    noChangeCount: 0,
    incomingActionCount: 1,
    preservedLocalCount: 0,
    convergedCount: 0,
    mergeCandidateCount: 0,
    conflictCount: 0,
    policyReviewCount: 0,
    decisionsRequiredCount: 0,
    pendingDecisionCount: 0,
    manualReviewCount: 0,
  }
}

function installDerivedState(selection: SelectionSummary, scanHandle: string) {
  const scan = useScanStore()
  const intent = {
    selectionHandle: selection.handle,
    scanHandle,
    resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
    sourceLabel: selection.displayLabel,
    resourceLabel: 'phone',
  }
  if (selection.kind === 'installedRoot') scan.installedIntent = intent
  if (selection.kind === 'packageFile') scan.packageIntent = intent
  scan.scanHandle = scanHandle
  scan.summary = {
    sourceKind: selection.kind,
    sourceLabel: selection.displayLabel,
    resourceCount: 1,
    warningCount: 0,
    totalFileCount: 1,
    totalBytes: 1,
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}

describe('session store deterministic replacement', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    establishClearRecoveryOverview()
    vi.clearAllMocks()
    api.sessionListSelections.mockResolvedValue({ selections: [] })
    api.sessionReleaseSelection.mockResolvedValue({ released: true })
    api.scanRelease.mockResolvedValue({ released: true })
  })

  it('replaces the installed source and invalidates exact derived state before cleanup', async () => {
    const session = useSessionStore()
    session.selections = [oldInstalled, oldPackage]
    session.currentInstalledSelectionHandle = oldInstalled.handle
    session.currentPackageSelectionHandle = oldPackage.handle
    installDerivedState(oldInstalled, '123e4567-e89b-42d3-a456-426614174010')
    api.selectInstalledRoot.mockResolvedValueOnce({ cancelled: false, selection: newInstalled })

    await session.chooseInstalledRoot()

    expect(session.currentInstalledSelection).toEqual(newInstalled)
    expect(session.currentPackageSelection).toEqual(oldPackage)
    expect(useScanStore().installedIntent).toBeUndefined()
    expect(api.scanRelease).toHaveBeenCalledWith({ scanHandle: '123e4567-e89b-42d3-a456-426614174010' })
    expect(api.sessionReleaseSelection).toHaveBeenCalledWith({ handle: oldInstalled.handle })
  })

  it('replaces the package independently', async () => {
    const session = useSessionStore()
    session.selections = [oldInstalled, oldPackage]
    session.currentInstalledSelectionHandle = oldInstalled.handle
    session.currentPackageSelectionHandle = oldPackage.handle
    installDerivedState(oldPackage, '123e4567-e89b-42d3-a456-426614174020')
    api.selectPackageFile.mockResolvedValueOnce({ cancelled: false, selection: newPackage })

    await session.choosePackageFile()

    expect(session.currentInstalledSelection).toEqual(oldInstalled)
    expect(session.currentPackageSelection).toEqual(newPackage)
    expect(useScanStore().packageIntent).toBeUndefined()
    expect(api.sessionReleaseSelection).toHaveBeenCalledWith({ handle: oldPackage.handle })
  })

  it('allows installed recovery scoping while attention blocks incoming package selection', async () => {
    const recovery = useRecoveryStore()
    recovery.overview = {
      disposition: 'attention_required',
      activeRecovery: true,
      terminalEvidence: false,
      manualAttention: false,
      unsupportedEvidence: false,
    }
    api.selectInstalledRoot.mockResolvedValueOnce({ cancelled: false, selection: newInstalled })
    const session = useSessionStore()

    await session.chooseInstalledRoot()
    await session.choosePackageFile()

    expect(api.selectInstalledRoot).toHaveBeenCalledTimes(1)
    expect(session.currentInstalledSelection).toEqual(newInstalled)
    expect(api.selectPackageFile).not.toHaveBeenCalled()
    expect(session.currentPackageSelection).toBeUndefined()
  })

  it('preserves all current state when the native selector is cancelled', async () => {
    const session = useSessionStore()
    session.selections = [oldInstalled]
    session.currentInstalledSelectionHandle = oldInstalled.handle
    installDerivedState(oldInstalled, '123e4567-e89b-42d3-a456-426614174010')
    api.selectInstalledRoot.mockResolvedValueOnce({ cancelled: true })

    await session.chooseInstalledRoot()

    expect(session.currentInstalledSelection).toEqual(oldInstalled)
    expect(useScanStore().installedIntent?.selectionHandle).toBe(oldInstalled.handle)
    expect(api.scanRelease).not.toHaveBeenCalled()
    expect(api.sessionReleaseSelection).not.toHaveBeenCalled()
  })

  it('never rebinds old state when cleanup fails', async () => {
    const session = useSessionStore()
    session.selections = [oldInstalled]
    session.currentInstalledSelectionHandle = oldInstalled.handle
    installDerivedState(oldInstalled, '123e4567-e89b-42d3-a456-426614174010')
    api.selectInstalledRoot.mockResolvedValueOnce({ cancelled: false, selection: newInstalled })
    api.scanRelease.mockRejectedValueOnce({ code: 'scan_busy', category: 'busy', message: 'busy', recoverable: true })
    api.updatePlanRelease.mockRejectedValueOnce({ code: 'plan_busy', category: 'busy', message: 'busy', recoverable: true })
    api.sessionReleaseSelection.mockRejectedValueOnce({ code: 'selection_busy', category: 'busy', message: 'busy', recoverable: true })

    await session.chooseInstalledRoot()

    expect(session.currentInstalledSelection).toEqual(newInstalled)
    expect(useScanStore().installedIntent).toBeUndefined()
    expect(session.pendingReleaseHandles).toContain(oldInstalled.handle)
  })

  it('repeated normal replacement releases old entries instead of approaching the registry limit', async () => {
    const session = useSessionStore()
    for (let index = 1; index <= 20; index += 1) {
      const suffix = index.toString(16).padStart(12, '0')
      api.selectInstalledRoot.mockResolvedValueOnce({
        cancelled: false,
        selection: {
          handle: `123e4567-e89b-42d3-a456-${suffix}`,
          kind: 'installedRoot',
          displayLabel: `resources-${index}`,
        },
      })
      await session.chooseInstalledRoot()
    }

    expect(session.selections.filter((selection) => selection.kind === 'installedRoot')).toHaveLength(1)
    expect(session.pendingReleaseHandles).toEqual([])
    expect(api.sessionReleaseSelection).toHaveBeenCalledTimes(19)
  })

  it('single-flights native selection so a late duplicate cannot replace the active request', async () => {
    let resolve!: (value: { cancelled: false; selection: SelectionSummary }) => void
    api.selectInstalledRoot.mockReturnValueOnce(new Promise((done) => { resolve = done }))
    const session = useSessionStore()

    const first = session.chooseInstalledRoot()
    await Promise.resolve()
    await session.chooseInstalledRoot()
    resolve({ cancelled: false, selection: newInstalled })
    await first

    expect(api.selectInstalledRoot).toHaveBeenCalledTimes(1)
    expect(session.currentInstalledSelection).toEqual(newInstalled)
  })

  it('ignores a late selection-list response after a successful replacement', async () => {
    let resolveList!: (value: { selections: SelectionSummary[] }) => void
    api.sessionListSelections.mockReturnValueOnce(new Promise((done) => { resolveList = done }))
    api.selectInstalledRoot.mockResolvedValueOnce({ cancelled: false, selection: newInstalled })
    const session = useSessionStore()
    session.selections = [oldInstalled]
    session.currentInstalledSelectionHandle = oldInstalled.handle

    const listing = session.listSelections()
    await Promise.resolve()
    await session.chooseInstalledRoot()
    resolveList({ selections: [oldInstalled] })
    await listing

    expect(session.currentInstalledSelection).toEqual(newInstalled)
    expect(session.selections).not.toContainEqual(oldInstalled)
  })

  it('refuses source selection while a durable operation still reconciles', async () => {
    expect(useRecoveryStore().beginDurableOperation('apply')).toBeDefined()
    const session = useSessionStore()

    await session.chooseInstalledRoot()
    await session.choosePackageFile()

    expect(api.selectInstalledRoot).not.toHaveBeenCalled()
    expect(api.selectPackageFile).not.toHaveBeenCalled()
  })

  it('reports a refused derived-state invalidation so reconciliation can fail closed', async () => {
    // Reconciliation after a durable write must fail closed: if the scan bound to the old source
    // survives, the caller has to hear about it rather than carry on with stale authority.
    const session = useSessionStore()
    vi.spyOn(useScanStore(), 'invalidateSource').mockResolvedValue(false)

    expect(await session.invalidateAfterDurableMutation()).toBe(false)
  })

})
