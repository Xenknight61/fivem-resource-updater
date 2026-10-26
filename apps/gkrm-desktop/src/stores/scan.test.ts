import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useScanStore } from './scan'
import { useRecoveryStore } from './recovery'
import type {
  DesktopError,
  ResourceDetail,
  ScanListResourcesResponse,
  ScanSummary,
  UpdatePlanSummary,
} from '@/types/commands'
import { establishClearRecoveryOverview } from '@/test/recoveryOverview'

const validScanHandle = '123e4567-e89b-42d3-a456-426614174010'
const oldScanHandle = '123e4567-e89b-42d3-a456-426614174020'

const api = vi.hoisted(() => {
  const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
  return {
    asDesktopError: vi.fn((error: unknown): DesktopError => {
      if (typeof error === 'object' && error !== null && 'desktopError' in error) {
        return (error as { desktopError: DesktopError }).desktopError
      }
      if (typeof error === 'object' && error !== null && 'code' in error) return error as DesktopError
      return { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
    }),
    inspectPackage: vi.fn(),
    isCanonicalUuidV4Handle: vi.fn((value: unknown) => typeof value === 'string' && uuidV4.test(value)),
    scanGetResourceDetail: vi.fn(),
    scanInstalledRoot: vi.fn(),
    scanListResources: vi.fn(),
    scanRelease: vi.fn(),
    updatePlanApply: vi.fn(),
    updatePlanRelease: vi.fn(),
  }
})

vi.mock('@/services/tauri/client', () => api)

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

async function flushPromises() {
  await Promise.resolve()
  await Promise.resolve()
}

function summary(): ScanSummary {
  return {
    sourceKind: 'installedRoot',
    sourceLabel: 'resources',
    resourceCount: 0,
    warningCount: 0,
    totalFileCount: 0,
    totalBytes: 0,
  }
}

function readyPlanSummary(): UpdatePlanSummary {
  return {
    planHandle: '123e4567-e89b-42d3-a456-426614174030',
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

function page(name: string, offset = 0): ScanListResourcesResponse {
  return {
    total: 1,
    offset,
    limit: 25,
    resources: [
      {
        resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
        sourceKind: 'installedRoot',
        displayName: name,
        status: 'available',
        fileCount: 1,
        totalBytes: 1,
        warningCount: 0,
      },
    ],
  }
}

function warningsPage(name: string): ScanListResourcesResponse {
  return {
    total: 1,
    offset: 0,
    limit: 25,
    resources: [
      {
        resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
        sourceKind: 'installedRoot',
        displayName: name,
        status: 'warnings',
        fileCount: 1,
        totalBytes: 1,
        warningCount: 1,
      },
    ],
  }
}

function detailFor(resourceHandle: string, displayName = 'visible'): ResourceDetail {
  return {
    resourceHandle,
    sourceKind: 'installedRoot',
    displayName,
    status: 'available',
    manifest: {
      kind: 'fxmanifest',
      clientScriptCount: 0,
      serverScriptCount: 0,
      sharedScriptCount: 0,
      dataFileCount: 0,
      hasUiPage: false,
    },
    escrow: { state: 'none', protectedFileCount: 0, ignoredFileCount: 0, unsupportedFileCount: 0 },
    statistics: { fileCount: 1, totalBytes: 1 },
    findings: [],
    omittedFindingCount: 0,
  }
}

function installVisiblePage(store: ReturnType<typeof useScanStore>, name = 'visible', offset = 0) {
  store.installScan(validScanHandle, summary())
  store.resources = page(name, offset).resources
  store.total = 1
  store.offset = offset
}

describe('scan store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    establishClearRecoveryOverview()
    vi.clearAllMocks()
    api.scanRelease.mockResolvedValue({ released: true })
    api.updatePlanRelease.mockResolvedValue({ released: true })
  })

  it('queues the latest query while a list request is pending and discards stale rows', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const first = deferred<ScanListResourcesResponse>()
    const second = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)

    const firstList = store.listResources(0)
    await flushPromises()
    expect(store.resources).toEqual([])
    store.resources = page('old visible').resources
    store.total = 1
    store.setQuery('phone')
    expect(store.query).toBe('phone')
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.offset).toBe(0)
    first.resolve(page('old'))
    await flushPromises()

    expect(store.resources).toEqual([])
    expect(api.scanListResources).toHaveBeenCalledTimes(2)
    expect(api.scanListResources.mock.calls[1]?.[0]).toMatchObject({ query: 'phone' })

    second.resolve(page('phone'))
    await firstList
    await flushPromises()
    expect(store.query).toBe('phone')
    expect(store.resources.map((resource) => resource.displayName)).toEqual(['phone'])
    expect(store.loading.list).toBe(false)
  })

  it('replaces rapid pending list requests with the newest filter state', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const first = deferred<ScanListResourcesResponse>()
    const second = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)

    void store.listResources(0)
    store.setQuery('a')
    expect(store.resources).toEqual([])
    store.setQuery('ab')
    store.setStatus('warnings')
    first.resolve(page('stale'))
    await flushPromises()

    expect(api.scanListResources).toHaveBeenCalledTimes(2)
    expect(api.scanListResources.mock.calls[1]?.[0]).toMatchObject({ query: 'ab', status: 'warnings' })
    second.resolve(warningsPage('ab'))
    await flushPromises()
    expect(store.query).toBe('ab')
    expect(store.status).toBe('warnings')
    expect(store.resources.map((resource) => resource.displayName)).toEqual(['ab'])
  })

  it('clears visible rows for status changes and leaves an empty truthful state when latest request fails', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const first = deferred<ScanListResourcesResponse>()
    const latest = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise).mockReturnValueOnce(latest.promise)

    void store.listResources(0)
    await flushPromises()
    store.resources = page('old visible').resources
    store.total = 1
    store.setStatus('warnings')

    expect(store.status).toBe('warnings')
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    first.resolve(page('stale'))
    await flushPromises()
    latest.reject({ code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false })
    await flushPromises()

    expect(store.status).toBe('warnings')
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.offset).toBe(0)
    expect(store.error?.code).toBe('internal')
    expect(store.loading.list).toBe(false)
  })

  it('clears visible rows for page changes while loading and installs only the latest page', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'page one', 0)
    store.total = 75
    const first = deferred<ScanListResourcesResponse>()
    const latest = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise).mockReturnValueOnce(latest.promise)

    void store.listResources(0)
    await flushPromises()
    store.resources = page('old page', 0).resources
    store.total = 75
    void store.listResources(25)

    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.offset).toBe(25)
    first.reject({ code: 'internal', category: 'internal', message: 'stale', recoverable: false })
    await flushPromises()
    expect(store.error).toBeUndefined()

    latest.resolve({ ...page('page two', 25), total: 75 })
    await flushPromises()
    expect(store.offset).toBe(25)
    expect(store.total).toBe(75)
    expect(store.resources.map((resource) => resource.displayName)).toEqual(['page two'])
    expect(store.loading.list).toBe(false)
  })

  it('invalidates pending lists when the scan is cleared', async () => {
    const store = useScanStore()
    store.installScan(validScanHandle, summary())
    const first = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise)

    void store.listResources(0)
    await flushPromises()
    expect(store.loading.list).toBe(true)
    expect(store.activeListGeneration).toBeDefined()
    store.clearScan()
    expect(store.scanHandle).toBeUndefined()
    expect(store.loading.list).toBe(false)
    expect(store.activeListGeneration).toBeUndefined()
    expect(store.pendingListOffset).toBeUndefined()
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.offset).toBe(0)
    first.resolve(page('old'))
    await flushPromises()

    expect(store.scanHandle).toBeUndefined()
    expect(store.resources).toEqual([])
    expect(store.loading.list).toBe(false)
    expect(api.scanListResources).toHaveBeenCalledTimes(1)
  })

  it('drops active and pending list work when a scan is cleared', async () => {
    const store = useScanStore()
    store.installScan(validScanHandle, summary())
    const first = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise)

    void store.listResources(0)
    await flushPromises()
    void store.listResources(25)
    expect(store.pendingListOffset).toBe(25)

    store.clearScan()
    first.resolve(page('old'))
    await flushPromises()

    expect(store.scanHandle).toBeUndefined()
    expect(store.loading.list).toBe(false)
    expect(store.activeListGeneration).toBeUndefined()
    expect(store.pendingListOffset).toBeUndefined()
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.offset).toBe(0)
    expect(api.scanListResources).toHaveBeenCalledTimes(1)
  })

  it('clears list execution after release while old list work is unresolved', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const first = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(first.promise)

    void store.listResources(0)
    await flushPromises()
    void store.listResources(25)
    expect(store.loading.list).toBe(true)
    expect(store.pendingListOffset).toBe(25)

    await store.releaseCurrentScan()
    expect(store.scanHandle).toBeUndefined()
    expect(store.loading.list).toBe(false)
    expect(store.activeListGeneration).toBeUndefined()
    expect(store.pendingListOffset).toBeUndefined()
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.offset).toBe(0)

    first.resolve(page('old'))
    await flushPromises()
    expect(store.scanHandle).toBeUndefined()
    expect(store.resources).toEqual([])
    expect(store.loading.list).toBe(false)
    expect(api.scanListResources).toHaveBeenCalledTimes(1)
  })

  it('prevents stale list finalization from clearing newer scan loading', async () => {
    const store = useScanStore()
    store.installScan(validScanHandle, summary())
    const oldList = deferred<ScanListResourcesResponse>()
    const newList = deferred<ScanListResourcesResponse>()
    const newScanHandle = '123e4567-e89b-42d3-a456-426614174030'
    api.scanListResources.mockReturnValueOnce(oldList.promise).mockReturnValueOnce(newList.promise)

    void store.listResources(0)
    await flushPromises()
    expect(store.loading.list).toBe(true)

    store.installScan(newScanHandle, summary())
    void store.listResources(0)
    await flushPromises()
    expect(store.loading.list).toBe(true)

    oldList.resolve(page('old'))
    await flushPromises()
    expect(store.scanHandle).toBe(newScanHandle)
    expect(store.loading.list).toBe(true)
    expect(store.resources).toEqual([])

    newList.resolve(page('new'))
    await flushPromises()
    expect(store.loading.list).toBe(false)
    expect(store.resources.map((resource) => resource.displayName)).toEqual(['new'])
  })

  it('does not restore stale detail after a filter change', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const detail = deferred<{ resource: never }>()
    const list = deferred<ScanListResourcesResponse>()
    api.scanGetResourceDetail.mockReturnValueOnce(detail.promise)
    api.scanListResources.mockReturnValueOnce(list.promise)

    void store.selectResource('123e4567-e89b-42d3-a456-426614174011')
    store.setQuery('new')
    detail.resolve({
      resource: {
        resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
        sourceKind: 'installedRoot',
        displayName: 'visible',
        status: 'available',
        manifest: { kind: 'fxmanifest', clientScriptCount: 0, serverScriptCount: 0, sharedScriptCount: 0, dataFileCount: 0, hasUiPage: false },
        escrow: { state: 'none', protectedFileCount: 0, ignoredFileCount: 0, unsupportedFileCount: 0 },
        statistics: { fileCount: 1, totalBytes: 1 },
        findings: [],
        omittedFindingCount: 0,
      },
    } as never)
    await flushPromises()

    expect(store.selectedResourceHandle).toBeUndefined()
    expect(store.detail).toBeUndefined()
    expect(store.loading.detail).toBe(false)
  })

  it('rejects a detail response with a mismatched resource handle', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const requestedHandle = '123e4567-e89b-42d3-a456-426614174011'
    const unexpectedHandle = '123e4567-e89b-42d3-a456-426614174012'
    api.scanGetResourceDetail.mockResolvedValueOnce({ resource: detailFor(unexpectedHandle) })

    await store.selectResource(requestedHandle)

    expect(store.selectedResourceHandle).toBe(requestedHandle)
    expect(store.detail).toBeUndefined()
    expect(store.loading.detail).toBe(false)
    expect(store.error?.code).toBe('internal')
    expect(JSON.stringify(store.$state)).not.toContain(unexpectedHandle)
  })

  it('does not install detail for an older resource selection', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const resourceA = '123e4567-e89b-42d3-a456-426614174011'
    const resourceB = '123e4567-e89b-42d3-a456-426614174012'
    const first = deferred<{ resource: ResourceDetail }>()
    const second = deferred<{ resource: ResourceDetail }>()
    api.scanGetResourceDetail.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)

    void store.selectResource(resourceA)
    await flushPromises()
    void store.selectResource(resourceB)
    await flushPromises()
    first.resolve({ resource: detailFor(resourceA, 'A') })
    await flushPromises()

    expect(store.selectedResourceHandle).toBe(resourceB)
    expect(store.detail).toBeUndefined()
    expect(store.loading.detail).toBe(true)

    second.resolve({ resource: detailFor(resourceB, 'B') })
    await flushPromises()
    expect(store.detail?.resourceHandle).toBe(resourceB)
    expect(store.loading.detail).toBe(false)
  })

  it('does not let stale detail finalization clear newer detail loading', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const resourceA = '123e4567-e89b-42d3-a456-426614174011'
    const resourceB = '123e4567-e89b-42d3-a456-426614174012'
    const first = deferred<{ resource: ResourceDetail }>()
    const second = deferred<{ resource: ResourceDetail }>()
    api.scanGetResourceDetail.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)

    void store.selectResource(resourceA)
    await flushPromises()
    void store.selectResource(resourceB)
    await flushPromises()
    first.reject({ code: 'internal', category: 'internal', message: 'stale', recoverable: false })
    await flushPromises()

    expect(store.selectedResourceHandle).toBe(resourceB)
    expect(store.loading.detail).toBe(true)
    expect(store.error).toBeUndefined()

    second.resolve({ resource: detailFor(resourceB, 'B') })
    await flushPromises()
    expect(store.detail?.resourceHandle).toBe(resourceB)
    expect(store.loading.detail).toBe(false)
  })

  it('does not install detail after scan clear or replacement', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const resourceA = '123e4567-e89b-42d3-a456-426614174011'
    const resourceB = '123e4567-e89b-42d3-a456-426614174012'
    const clearDetail = deferred<{ resource: ResourceDetail }>()
    const replaceDetail = deferred<{ resource: ResourceDetail }>()
    api.scanGetResourceDetail.mockReturnValueOnce(clearDetail.promise).mockReturnValueOnce(replaceDetail.promise)

    void store.selectResource(resourceA)
    await flushPromises()
    store.clearScan()
    clearDetail.resolve({ resource: detailFor(resourceA, 'A') })
    await flushPromises()
    expect(store.scanHandle).toBeUndefined()
    expect(store.detail).toBeUndefined()
    expect(store.loading.detail).toBe(false)

    store.installScan(validScanHandle, summary())
    void store.selectResource(resourceB)
    await flushPromises()
    store.installScan('123e4567-e89b-42d3-a456-426614174030', summary())
    replaceDetail.resolve({ resource: detailFor(resourceB, 'B') })
    await flushPromises()
    expect(store.scanHandle).toBe('123e4567-e89b-42d3-a456-426614174030')
    expect(store.selectedResourceHandle).toBeUndefined()
    expect(store.detail).toBeUndefined()
    expect(store.loading.detail).toBe(false)
  })

  it('scan replacement invalidates the previous scan even when the new inspection fails', async () => {
    const store = useScanStore()
    installVisiblePage(store, 'visible')
    const list = deferred<ScanListResourcesResponse>()
    api.scanListResources.mockReturnValueOnce(list.promise)
    api.scanInstalledRoot.mockRejectedValueOnce({
      code: 'inspection_rejected',
      category: 'filesystem',
      message: 'The inspection was rejected.',
      recoverable: true,
    })

    void store.listResources(0)
    await store.scanInstalled('123e4567-e89b-42d3-a456-426614174000')
    list.resolve(page('stale'))
    await flushPromises()

    expect(store.scanHandle).toBeUndefined()
    expect(store.installedIntent).toBeUndefined()
    expect(store.resources).toEqual([])
    expect(store.total).toBe(0)
    expect(store.error?.code).toBe('inspection_rejected')
    expect(api.scanRelease).toHaveBeenCalledWith({ scanHandle: validScanHandle })
  })

  it('releases the exact scan returned after its source generation became stale', async () => {
    const store = useScanStore()
    const pendingScan = deferred<{ scanHandle: string; summary: ScanSummary }>()
    api.scanInstalledRoot.mockReturnValueOnce(pendingScan.promise)

    const scanning = store.scanInstalled('123e4567-e89b-42d3-a456-426614174000')
    await flushPromises()
    await store.invalidateSource('installedRoot')
    pendingScan.resolve({ scanHandle: validScanHandle, summary: summary() })
    await scanning

    expect(store.scanHandle).toBeUndefined()
    expect(store.installedIntent).toBeUndefined()
    expect(api.scanRelease).toHaveBeenCalledWith({ scanHandle: validScanHandle })
  })

  it('releases repeated stale scan successes beyond registry capacity', async () => {
    const store = useScanStore()
    const staleHandles = Array.from(
      { length: 9 },
      (_, index) => `123e4567-e89b-42d3-a456-${(index + 40).toString().padStart(12, '0')}`,
    )

    for (const handle of staleHandles) {
      const pendingScan = deferred<{ scanHandle: string; summary: ScanSummary }>()
      api.scanInstalledRoot.mockReturnValueOnce(pendingScan.promise)
      const scanning = store.scanInstalled('123e4567-e89b-42d3-a456-426614174000')
      await flushPromises()
      await store.invalidateSource('installedRoot')
      pendingScan.resolve({ scanHandle: handle, summary: summary() })
      await scanning
    }

    expect(store.scanHandle).toBeUndefined()
    expect(store.pendingReleaseHandles).toEqual([])
    expect(api.scanRelease.mock.calls.map(([value]) => value)).toEqual(
      staleHandles.map((handle) => ({ scanHandle: handle })),
    )
  })

  it('never releases a newer current scan while cleaning an older stale success', async () => {
    const store = useScanStore()
    const staleScan = deferred<{ scanHandle: string; summary: ScanSummary }>()
    const currentHandle = '123e4567-e89b-42d3-a456-426614174050'
    api.scanInstalledRoot
      .mockReturnValueOnce(staleScan.promise)
      .mockResolvedValueOnce({ scanHandle: currentHandle, summary: summary() })
    api.scanListResources.mockResolvedValueOnce(page('current'))

    const oldRequest = store.scanInstalled('123e4567-e89b-42d3-a456-426614174000')
    await flushPromises()
    await store.invalidateSource('installedRoot')
    await store.scanInstalled('123e4567-e89b-42d3-a456-426614174001')
    staleScan.resolve({ scanHandle: validScanHandle, summary: summary() })
    await oldRequest

    expect(store.scanHandle).toBe(currentHandle)
    expect(store.resources[0]?.displayName).toBe('current')
    expect(api.scanRelease).toHaveBeenCalledWith({ scanHandle: validScanHandle })
    expect(api.scanRelease).not.toHaveBeenCalledWith({ scanHandle: currentHandle })
  })

  it('queues stale scan cleanup failure without replacing the current route error', async () => {
    const store = useScanStore()
    const pendingScan = deferred<{ scanHandle: string; summary: ScanSummary }>()
    const currentError: DesktopError = {
      code: 'inspection_rejected',
      category: 'filesystem',
      message: 'The current inspection was rejected.',
      recoverable: true,
    }
    store.error = currentError
    api.scanInstalledRoot.mockReturnValueOnce(pendingScan.promise)
    api.scanRelease.mockRejectedValueOnce({
      code: 'scan_busy',
      category: 'busy',
      message: 'The scan is busy.',
      recoverable: true,
    })

    const scanning = store.scanInstalled('123e4567-e89b-42d3-a456-426614174000')
    await flushPromises()
    await store.invalidateSource('installedRoot')
    store.error = currentError
    pendingScan.resolve({ scanHandle: validScanHandle, summary: summary() })
    await scanning

    expect(store.scanHandle).toBeUndefined()
    expect(store.pendingReleaseHandles).toEqual([validScanHandle])
    expect(store.error).toEqual(currentError)
  })

  it('tracks failed previous-scan releases and retries them', async () => {
    const store = useScanStore()
    store.installScan(validScanHandle, summary())
    const transientReleaseError = {
      code: 'internal',
      category: 'internal',
      message: 'The desktop adapter failed.',
      recoverable: true,
    }
    api.scanRelease
      .mockRejectedValueOnce(transientReleaseError)
      .mockRejectedValueOnce(transientReleaseError)
      .mockRejectedValueOnce(transientReleaseError)

    await store.releasePreviousScan(oldScanHandle)
    await store.releasePreviousScan(oldScanHandle)

    expect(store.pendingReleaseHandles).toEqual([oldScanHandle])
    expect(store.error?.message).toBe('A previous read-only scan cleanup is pending.')

    api.scanRelease.mockResolvedValueOnce({ released: true })
    await store.retryPendingReleases()
    expect(store.pendingReleaseHandles).toEqual([])
  })

  it('treats scan_not_found pending release retries as already released', async () => {
    const store = useScanStore()
    store.installScan(validScanHandle, summary())
    api.scanRelease.mockRejectedValueOnce({
      code: 'scan_not_found',
      category: 'selection',
      message: 'The scan is not available.',
      recoverable: true,
    })

    await store.releasePreviousScan(oldScanHandle)

    expect(store.pendingReleaseHandles).toEqual([])
  })
})
