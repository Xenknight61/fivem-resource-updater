import { defineStore } from 'pinia'

import {
  asDesktopError,
  isCanonicalUuidV4Handle,
  scanGetResourceDetail,
  scanInstalledRoot,
  scanListResources,
  scanRelease,
} from '@/services/tauri/client'
import { useAppStore } from '@/stores/app'
import { useSessionStore } from '@/stores/session'
import { useRecoveryStore } from '@/stores/recovery'
import type {
  DesktopError,
  ResourceDetail,
  ResourceStatus,
  ResourceSummary,
  ScanListResourcesRequest,
  ScanSummary,
} from '@/types/commands'

interface ScanLoadingState {
  scanInstalledRoot: boolean
  inspectPackage: boolean
  list: boolean
  detail: boolean
  release: boolean
}

export interface ScanPlanningIntent {
  selectionHandle: string
  scanHandle: string
  resourceHandle: string | undefined
  sourceLabel: string
  resourceLabel: string | undefined
}

interface ScanState {
  scanHandle: string | undefined
  sourceSelectionHandle: string | undefined
  summary: ScanSummary | undefined
  installedIntent: ScanPlanningIntent | undefined
  packageIntent: ScanPlanningIntent | undefined
  resources: ResourceSummary[]
  total: number
  offset: number
  limit: number
  query: string
  status: ResourceStatus | undefined
  selectedResourceHandle: string | undefined
  detail: ResourceDetail | undefined
  error: DesktopError | undefined
  loading: ScanLoadingState
  generation: number
  listGeneration: number
  activeListGeneration: number | undefined
  pendingListOffset: number | undefined
  detailGeneration: number
  pendingReleaseHandles: string[]
}

interface MutableScanState extends ScanState {
  invalidateListRequests(): void
  clearActiveListExecution(): void
  invalidateDetailRequests(): void
}

function invalidateSourceState(state: MutableScanState, kind: 'installedRoot' | 'packageFile') {
  const intent = kind === 'installedRoot' ? state.installedIntent : state.packageIntent
  if (kind === 'installedRoot') state.installedIntent = undefined
  if (kind === 'packageFile') state.packageIntent = undefined
  if (intent !== undefined && state.scanHandle === intent.scanHandle) {
    state.invalidateListRequests()
    state.clearActiveListExecution()
    state.invalidateDetailRequests()
    state.scanHandle = undefined
    state.sourceSelectionHandle = undefined
    state.summary = undefined
    state.resources = []
    state.total = 0
    state.offset = 0
  }
}

function clearPlanningResourceForCurrentScan(state: ScanState) {
  const installedIntent = state.installedIntent
  const packageIntent = state.packageIntent
  if (installedIntent !== undefined && installedIntent.scanHandle === state.scanHandle) {
    installedIntent.resourceHandle = undefined
    installedIntent.resourceLabel = undefined
  }
  if (packageIntent !== undefined && packageIntent.scanHandle === state.scanHandle) {
    packageIntent.resourceHandle = undefined
    packageIntent.resourceLabel = undefined
  }
}

function updatePlanningIntentResource(state: ScanState, resourceHandle: string, resourceLabel: string) {
  const installedIntent = state.installedIntent
  const packageIntent = state.packageIntent
  if (
    state.summary?.sourceKind === 'installedRoot' &&
    installedIntent !== undefined &&
    installedIntent.scanHandle === state.scanHandle
  ) {
    installedIntent.resourceHandle = resourceHandle
    installedIntent.resourceLabel = resourceLabel
  }
  if (
    state.summary?.sourceKind === 'packageFile' &&
    packageIntent !== undefined &&
    packageIntent.scanHandle === state.scanHandle
  ) {
    packageIntent.resourceHandle = resourceHandle
    packageIntent.resourceLabel = resourceLabel
  }
}

const MAX_PENDING_RELEASES = 8

export const useScanStore = defineStore('scan', {
  state: (): ScanState => ({
    scanHandle: undefined,
    sourceSelectionHandle: undefined,
    summary: undefined,
    installedIntent: undefined,
    packageIntent: undefined,
    resources: [],
    total: 0,
    offset: 0,
    limit: 25,
    query: '',
    status: undefined,
    selectedResourceHandle: undefined,
    detail: undefined,
    error: undefined,
    loading: {
      scanInstalledRoot: false,
      inspectPackage: false,
      list: false,
      detail: false,
      release: false,
    },
    generation: 0,
    listGeneration: 0,
    activeListGeneration: undefined,
    pendingListOffset: undefined,
    detailGeneration: 0,
    pendingReleaseHandles: [],
  }),
  actions: {
    clearError() {
      this.error = undefined
    },
    async scanInstalled(selectionHandle: string) {
      if (this.loading.scanInstalledRoot || this.loading.inspectPackage) return
      const session = useSessionStore()
      const sourceMutationToken = session.beginSourceMutation()
      if (sourceMutationToken === undefined) return
      let requestGeneration: number
      let previousHandle: string | undefined
      try {
        requestGeneration = ++this.generation
        this.invalidateListRequests()
        previousHandle = this.installedIntent?.scanHandle
        invalidateSourceState(this, 'installedRoot')
        this.loading.scanInstalledRoot = true
      } finally {
        session.endSourceMutation(sourceMutationToken)
      }
      if (previousHandle !== undefined) await this.releasePreviousScan(previousHandle)
      else await this.retryPendingReleases()
      this.error = undefined
      try {
        const response = await scanInstalledRoot({ selectionHandle })
        if (requestGeneration !== this.generation) {
          await this.releaseStaleScan(response.scanHandle)
          return
        }
        if (!this.installScan(response.scanHandle, response.summary, selectionHandle)) {
          await this.releaseStaleScan(response.scanHandle)
          return
        }
        await this.loadFirstPageForGeneration(requestGeneration)
      } catch (error) {
        if (requestGeneration === this.generation) this.captureError(error)
      } finally {
        if (requestGeneration === this.generation) this.loading.scanInstalledRoot = false
      }
    },
    async listResources(offset?: number) {
      await this.requestListResources(offset ?? this.offset)
    },
    async performListResources(offset: number, requestGeneration: number) {
      if (this.scanHandle === undefined) return
      const requestScanHandle = this.scanHandle
      this.loading.list = true
      this.activeListGeneration = requestGeneration
      this.error = undefined
      const request = this.buildListRequest(offset)
      try {
        const response = await scanListResources(request)
        if (requestGeneration !== this.listGeneration || request.scanHandle !== this.scanHandle) return
        this.resources = response.resources
        this.total = response.total
        this.offset = response.offset
        this.limit = response.limit
      } catch (error) {
        if (requestGeneration === this.listGeneration && this.scanHandle === requestScanHandle) this.captureError(error)
      } finally {
        if (this.scanHandle === requestScanHandle && this.activeListGeneration === requestGeneration) {
          this.loading.list = false
          this.activeListGeneration = undefined
        }
        if (
          this.scanHandle === requestScanHandle &&
          this.activeListGeneration === undefined &&
          this.pendingListOffset !== undefined &&
          !this.loading.list
        ) {
          const pendingOffset = this.pendingListOffset
          this.pendingListOffset = undefined
          void this.requestListResources(pendingOffset)
        }
      }
    },
    async loadFirstPageForGeneration(requestGeneration: number) {
      if (this.scanHandle === undefined) return
      if (requestGeneration !== this.generation) return
      await this.requestListResources(0)
    },
    async selectResource(resourceHandle: string) {
      if (this.scanHandle === undefined) return
      if (this.summary?.sourceKind === 'packageFile' && !useRecoveryStore().overviewIsClear) return
      const session = useSessionStore()
      const sourceMutationToken = session.beginSourceMutation()
      if (sourceMutationToken === undefined) return
      const requestedScanHandle = this.scanHandle
      const requestedResourceHandle = resourceHandle
      let requestGeneration: number
      try {
        requestGeneration = ++this.detailGeneration
        clearPlanningResourceForCurrentScan(this)
        this.selectedResourceHandle = resourceHandle
        this.detail = undefined
        this.loading.detail = true
        this.error = undefined
      } finally {
        session.endSourceMutation(sourceMutationToken)
      }
      try {
        const response = await scanGetResourceDetail({
          scanHandle: requestedScanHandle,
          resourceHandle: requestedResourceHandle,
        })
        if (
          requestGeneration !== this.detailGeneration ||
          this.scanHandle !== requestedScanHandle ||
          this.selectedResourceHandle !== requestedResourceHandle
        ) {
          return
        }
        if (response.resource.resourceHandle !== requestedResourceHandle) {
          this.detail = undefined
          this.captureError(new Error('malformed desktop response'))
          return
        }
        const responseMutationToken = session.beginSourceMutation()
        if (responseMutationToken === undefined) return
        try {
          if (
            requestGeneration !== this.detailGeneration ||
            this.scanHandle !== requestedScanHandle ||
            this.selectedResourceHandle !== requestedResourceHandle
          ) {
            return
          }
          this.detail = response.resource
          updatePlanningIntentResource(this, response.resource.resourceHandle, response.resource.displayName)
        } finally {
          session.endSourceMutation(responseMutationToken)
        }
      } catch (error) {
        if (
          requestGeneration === this.detailGeneration &&
          this.scanHandle === requestedScanHandle &&
          this.selectedResourceHandle === requestedResourceHandle
        ) {
          this.detail = undefined
          this.captureError(error)
        }
      } finally {
        if (
          requestGeneration === this.detailGeneration &&
          this.scanHandle === requestedScanHandle &&
          this.selectedResourceHandle === requestedResourceHandle
        ) {
          this.loading.detail = false
        }
      }
    },
    async releaseCurrentScan() {
      if (this.scanHandle === undefined || this.loading.release) return
      const session = useSessionStore()
      const sourceMutationToken = session.beginSourceMutation()
      if (sourceMutationToken === undefined) return
      const handle = this.scanHandle
      const kind = this.summary?.sourceKind
      try {
        this.loading.release = true
        this.clearScan(sourceMutationToken)
      } finally {
        session.endSourceMutation(sourceMutationToken)
      }
      try {
        await scanRelease({ scanHandle: handle })
        if (kind === 'installedRoot' && this.installedIntent?.scanHandle === handle) this.installedIntent = undefined
        if (kind === 'packageFile' && this.packageIntent?.scanHandle === handle) this.packageIntent = undefined
        await this.retryPendingReleases()
      } catch (error) {
        const desktopError = asDesktopError(error)
        if (desktopError.code !== 'scan_not_found') {
          this.addPendingRelease(handle)
          this.captureError(error)
        }
      } finally {
        this.loading.release = false
      }
    },
    setQuery(query: string) {
      this.invalidateListRequests()
      this.query = query
      this.clearVisibleListForRequest(0)
      void this.requestListResources(0)
    },
    setStatus(status?: ResourceStatus) {
      this.invalidateListRequests()
      this.status = status
      this.clearVisibleListForRequest(0)
      void this.requestListResources(0)
    },
    installScan(
      scanHandle: string,
      summary: ScanSummary,
      selectionHandle?: string,
      existingSourceMutationToken?: number,
    ): boolean {
      const session = useSessionStore()
      const sourceMutationToken = session.beginSourceMutation(existingSourceMutationToken)
      if (sourceMutationToken === undefined) return false
      const ownsSourceMutation = existingSourceMutationToken === undefined
      try {
        if (!isCanonicalUuidV4Handle(scanHandle)) {
          throw new Error('malformed scan handle')
        }
        if (selectionHandle !== undefined && !isCanonicalUuidV4Handle(selectionHandle)) {
          throw new Error('malformed selection handle')
        }
        this.invalidateListRequests()
        this.clearActiveListExecution()
        this.invalidateDetailRequests()
        this.scanHandle = scanHandle
        this.sourceSelectionHandle = selectionHandle
        this.summary = summary
        const intent: ScanPlanningIntent = {
          selectionHandle: selectionHandle ?? '',
          scanHandle,
          resourceHandle: undefined,
          sourceLabel: summary.sourceLabel,
          resourceLabel: undefined,
        }
        if (summary.sourceKind === 'installedRoot') this.installedIntent = intent
        if (summary.sourceKind === 'packageFile') this.packageIntent = intent
        this.resources = []
        this.total = 0
        this.offset = 0
        this.detail = undefined
        this.selectedResourceHandle = undefined
        return true
      } finally {
        if (ownsSourceMutation) session.endSourceMutation(sourceMutationToken)
      }
    },
    clearScan(existingSourceMutationToken?: number): boolean {
      const session = useSessionStore()
      const sourceMutationToken = session.beginSourceMutation(existingSourceMutationToken)
      if (sourceMutationToken === undefined) return false
      const ownsSourceMutation = existingSourceMutationToken === undefined
      try {
        const releasedHandle = this.scanHandle
        this.generation += 1
        this.loading.scanInstalledRoot = false
        this.loading.inspectPackage = false
        this.invalidateListRequests()
        this.clearActiveListExecution()
        this.invalidateDetailRequests()
        this.scanHandle = undefined
        this.sourceSelectionHandle = undefined
        this.summary = undefined
        this.resources = []
        this.total = 0
        this.offset = 0
        this.detail = undefined
        this.selectedResourceHandle = undefined
        this.error = undefined
        if (this.installedIntent?.scanHandle === releasedHandle) this.installedIntent = undefined
        if (this.packageIntent?.scanHandle === releasedHandle) this.packageIntent = undefined
        return true
      } finally {
        if (ownsSourceMutation) session.endSourceMutation(sourceMutationToken)
      }
    },
    async invalidateSource(kind: 'installedRoot' | 'packageFile', existingSourceMutationToken?: number): Promise<boolean> {
      const session = useSessionStore()
      const sourceMutationToken = session.beginSourceMutation(existingSourceMutationToken)
      if (sourceMutationToken === undefined) return false
      const ownsSourceMutation = existingSourceMutationToken === undefined
      try {
        const handle = kind === 'installedRoot' ? this.installedIntent?.scanHandle : this.packageIntent?.scanHandle
        this.generation += 1
        this.loading.scanInstalledRoot = false
        this.loading.inspectPackage = false
        invalidateSourceState(this, kind)
        if (handle !== undefined) await this.releasePreviousScan(handle)
        return true
      } finally {
        if (ownsSourceMutation) session.endSourceMutation(sourceMutationToken)
      }
    },
    async requestListResources(offset: number) {
      if (this.scanHandle === undefined) return
      const requestGeneration = ++this.listGeneration
      this.clearVisibleListForRequest(offset)
      if (this.loading.list) {
        this.pendingListOffset = offset
        return
      }
      await this.performListResources(offset, requestGeneration)
    },
    invalidateListRequests() {
      this.listGeneration += 1
      this.pendingListOffset = undefined
    },
    clearActiveListExecution() {
      this.loading.list = false
      this.activeListGeneration = undefined
      this.pendingListOffset = undefined
    },
    invalidateDetailRequests() {
      this.detailGeneration += 1
      this.detail = undefined
      this.selectedResourceHandle = undefined
      this.loading.detail = false
    },
    clearVisibleListForRequest(offset: number) {
      this.resources = []
      this.total = 0
      this.offset = offset
      this.invalidateDetailRequests()
    },
    async releasePreviousScan(handle: string) {
      if (handle === this.scanHandle) {
        await this.releaseCurrentScan()
        return
      }
      if (handle === this.installedIntent?.scanHandle) {
        await this.invalidateSource('installedRoot')
        return
      }
      if (handle === this.packageIntent?.scanHandle) {
        await this.invalidateSource('packageFile')
        return
      }
      await this.retryPendingReleases()
      const released = await this.tryReleaseScanHandle(handle)
      if (!released) this.addPendingRelease(handle)
    },
    async releaseStaleScan(handle: string) {
      if (
        handle === this.scanHandle ||
        handle === this.installedIntent?.scanHandle ||
        handle === this.packageIntent?.scanHandle
      ) {
        return
      }
      const released = await this.tryReleaseScanHandle(handle)
      if (!released) this.addPendingRelease(handle, false)
    },
    async retryPendingReleases() {
      const handles = [...this.pendingReleaseHandles]
      for (const handle of handles) {
        await this.tryReleaseScanHandle(handle)
      }
      if (this.pendingReleaseHandles.length > 0) this.showPendingReleaseWarning()
    },
    async tryReleaseScanHandle(handle: string): Promise<boolean> {
      if (
        handle === this.scanHandle ||
        handle === this.installedIntent?.scanHandle ||
        handle === this.packageIntent?.scanHandle
      ) {
        return false
      }
      try {
        await scanRelease({ scanHandle: handle })
        this.removePendingRelease(handle)
        if (this.installedIntent?.scanHandle === handle) this.installedIntent = undefined
        if (this.packageIntent?.scanHandle === handle) this.packageIntent = undefined
        return true
      } catch (error) {
        const desktopError = asDesktopError(error)
        if (desktopError.code === 'scan_not_found') {
          this.removePendingRelease(handle)
          if (this.installedIntent?.scanHandle === handle) this.installedIntent = undefined
          if (this.packageIntent?.scanHandle === handle) this.packageIntent = undefined
          return true
        }
        return false
      }
    },
    addPendingRelease(handle: string, announce = true) {
      if (!isCanonicalUuidV4Handle(handle) || handle === this.scanHandle || this.pendingReleaseHandles.includes(handle)) {
        if (announce && this.pendingReleaseHandles.length > 0) this.showPendingReleaseWarning()
        return
      }
      if (this.pendingReleaseHandles.length < MAX_PENDING_RELEASES) {
        this.pendingReleaseHandles.push(handle)
      }
      if (announce) this.showPendingReleaseWarning()
    },
    removePendingRelease(handle: string) {
      this.pendingReleaseHandles = this.pendingReleaseHandles.filter((pending) => pending !== handle)
    },
    showPendingReleaseWarning() {
      const warning: DesktopError = {
        code: 'scan_failed',
        category: 'internal',
        message: 'A previous read-only scan cleanup is pending.',
        recoverable: true,
      }
      this.error = warning
      useAppStore().setError(warning)
    },
    captureError(error: unknown) {
      const desktopError = asDesktopError(error)
      this.error = desktopError
      useAppStore().setError(desktopError)
    },
    buildListRequest(offset: number): ScanListResourcesRequest {
      if (this.scanHandle === undefined) {
        throw new Error('scan handle is required')
      }
      const request: ScanListResourcesRequest = {
        scanHandle: this.scanHandle,
        offset,
        limit: this.limit,
      }
      const query = this.query.trim()
      if (query !== '') request.query = query
      if (this.status !== undefined) request.status = this.status
      return request
    },
  },
})
