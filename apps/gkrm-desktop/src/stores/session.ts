import { defineStore } from 'pinia'

import {
  asDesktopError,
  selectInstalledRoot,
  selectPackageFile,
  sessionListSelections,
  sessionReleaseSelection,
} from '@/services/tauri/client'
import { useAppStore } from '@/stores/app'
import { useRecoveryStore } from '@/stores/recovery'
import { useScanStore } from '@/stores/scan'
import type { SelectionKind, SelectionSummary } from '@/types/commands'

interface SessionState {
  selections: SelectionSummary[]
  currentInstalledSelectionHandle: string | undefined
  currentPackageSelectionHandle: string | undefined
  pendingReleaseHandles: string[]
  revision: number
  /**
   * The one-at-a-time lock on changing a source.
   *
   * Changing a selection invalidates everything read from it, and two changes interleaving would
   * leave a scan bound to a source nobody selected. The lock used to live with the three-way plan
   * because that had the most to lose; it belongs with the selections themselves.
   */
  sourceMutationGeneration: number
  activeSourceMutationGeneration: number | undefined
  loading: {
    list: boolean
    selectInstalledRoot: boolean
    selectPackageFile: boolean
    release: boolean
  }
}

function upsertSelection(state: SessionState, selection: SelectionSummary) {
  state.selections = [
    ...state.selections.filter((candidate) => candidate.handle !== selection.handle),
    selection,
  ]
}

function removeSelection(state: SessionState, handle: string) {
  state.revision += 1
  state.selections = state.selections.filter((selection) => selection.handle !== handle)
  state.pendingReleaseHandles = state.pendingReleaseHandles.filter((pending) => pending !== handle)
}

export const useSessionStore = defineStore('session', {
  state: (): SessionState => ({
    selections: [],
    currentInstalledSelectionHandle: undefined,
    currentPackageSelectionHandle: undefined,
    pendingReleaseHandles: [],
    revision: 0,
    sourceMutationGeneration: 0,
    activeSourceMutationGeneration: undefined,
    loading: {
      list: false,
      selectInstalledRoot: false,
      selectPackageFile: false,
      release: false,
    },
  }),
  getters: {
    currentInstalledSelection(state): SelectionSummary | undefined {
      return state.selections.find(
        (selection) => selection.handle === state.currentInstalledSelectionHandle && selection.kind === 'installedRoot',
      )
    },
    currentPackageSelection(state): SelectionSummary | undefined {
      return state.selections.find(
        (selection) => selection.handle === state.currentPackageSelectionHandle && selection.kind === 'packageFile',
      )
    },
  },
  actions: {
    beginSourceMutation(existingToken?: number): number | undefined {
      if (existingToken !== undefined) {
        return this.activeSourceMutationGeneration === existingToken ? existingToken : undefined
      }
      // Deliberately not gated on a durable operation being in flight: the invalidation that
      // follows one is itself a source mutation, and refusing it there would leave a scan bound
      // to authority the backend has already discarded. Choosing a source is gated instead, at
      // the point where the operator chooses.
      if (this.activeSourceMutationGeneration !== undefined) return undefined
      const token = ++this.sourceMutationGeneration
      this.activeSourceMutationGeneration = token
      return token
    },
    endSourceMutation(token: number) {
      if (this.activeSourceMutationGeneration === token) {
        this.activeSourceMutationGeneration = undefined
      }
    },
    async invalidateAfterDurableMutation(): Promise<boolean> {
      const sourceMutationToken = this.beginSourceMutation()
      if (sourceMutationToken === undefined) return false
      const packageSelectionHandle = this.currentPackageSelectionHandle
      try {
        this.currentPackageSelectionHandle = undefined
        this.revision += 1
        const scan = useScanStore()
        const installedInvalidated = await scan.invalidateSource('installedRoot', sourceMutationToken)
        const packageInvalidated = await scan.invalidateSource('packageFile', sourceMutationToken)
        if (packageSelectionHandle !== undefined) {
          await this.releasePreviousSelection(packageSelectionHandle)
        }
        return installedInvalidated && packageInvalidated
      } finally {
        this.endSourceMutation(sourceMutationToken)
      }
    },
    async listSelections(kind?: SelectionKind) {
      if (this.loading.list) return
      const requestRevision = this.revision
      this.loading.list = true
      try {
        const response = await sessionListSelections(kind === undefined ? {} : { kind })
        if (requestRevision !== this.revision) return
        const nextSelections = kind === undefined
          ? response.selections
          : [
            ...this.selections.filter((selection) => selection.kind !== kind),
            ...response.selections,
          ]
        const currentAuthorityMissing =
          (this.currentInstalledSelectionHandle !== undefined &&
            !nextSelections.some((selection) =>
              selection.handle === this.currentInstalledSelectionHandle && selection.kind === 'installedRoot')) ||
          (this.currentPackageSelectionHandle !== undefined &&
            !nextSelections.some((selection) =>
              selection.handle === this.currentPackageSelectionHandle && selection.kind === 'packageFile'))
                const sourceMutationToken = currentAuthorityMissing ? this.beginSourceMutation() : undefined
        if (currentAuthorityMissing && sourceMutationToken === undefined) return
        try {
          this.selections = nextSelections
          await this.reconcileCurrentSelections(sourceMutationToken)
        } finally {
          if (sourceMutationToken !== undefined) this.endSourceMutation(sourceMutationToken)
        }
      } catch (error) {
        useAppStore().setError(asDesktopError(error))
      } finally {
        this.loading.list = false
      }
    },
    async chooseInstalledRoot() {
      if (useRecoveryStore().durableOperationInProgress) return
      if (this.loading.selectInstalledRoot) return
      this.loading.selectInstalledRoot = true
      try {
        const response = await selectInstalledRoot()
        if (!response.cancelled && response.selection !== undefined) {
          if (useRecoveryStore().durableOperationInProgress) {
            await this.releasePreviousSelection(response.selection.handle)
            return
          }
          await this.installCurrentSelection(response.selection)
        }
      } catch (error) {
        useAppStore().setError(asDesktopError(error))
      } finally {
        this.loading.selectInstalledRoot = false
      }
    },
    async choosePackageFile() {
      if (!useRecoveryStore().overviewIsClear) return
      if (useRecoveryStore().durableOperationInProgress) return
      if (this.loading.selectPackageFile) return
      this.loading.selectPackageFile = true
      try {
        const response = await selectPackageFile()
        if (!response.cancelled && response.selection !== undefined) {
          if (useRecoveryStore().durableOperationInProgress) {
            await this.releasePreviousSelection(response.selection.handle)
            return
          }
          await this.installCurrentSelection(response.selection)
        }
      } catch (error) {
        useAppStore().setError(asDesktopError(error))
      } finally {
        this.loading.selectPackageFile = false
      }
    },
    async releaseSelection(handle: string) {
      if (this.loading.release) return
      const currentKind: SelectionKind | undefined = handle === this.currentInstalledSelectionHandle
        ? 'installedRoot'
        : handle === this.currentPackageSelectionHandle
          ? 'packageFile'
          : undefined
            const sourceMutationToken = currentKind === undefined ? undefined : this.beginSourceMutation()
      if (currentKind !== undefined && sourceMutationToken === undefined) return
      this.loading.release = true
      try {
        await sessionReleaseSelection({ handle })
        if (currentKind !== undefined) await this.invalidateSelectionKind(currentKind, sourceMutationToken)
        removeSelection(this, handle)
      } catch (error) {
        useAppStore().setError(asDesktopError(error))
      } finally {
        this.loading.release = false
        if (sourceMutationToken !== undefined) this.endSourceMutation(sourceMutationToken)
      }
    },
    async installCurrentSelection(selection: SelectionSummary) {
            const sourceMutationToken = this.beginSourceMutation()
      if (sourceMutationToken === undefined) {
        await this.releasePreviousSelection(selection.handle)
        return
      }
      try {
        const previousHandle = selection.kind === 'installedRoot'
          ? this.currentInstalledSelectionHandle
          : this.currentPackageSelectionHandle
        upsertSelection(this, selection)
        this.revision += 1
        if (selection.kind === 'installedRoot') this.currentInstalledSelectionHandle = selection.handle
        if (selection.kind === 'packageFile') this.currentPackageSelectionHandle = selection.handle
        if (previousHandle === selection.handle) return

        await useScanStore().invalidateSource(selection.kind, sourceMutationToken)
        await this.retryPendingReleases()
        if (previousHandle !== undefined) await this.releasePreviousSelection(previousHandle)
      } finally {
        this.endSourceMutation(sourceMutationToken)
      }
    },
    async invalidateSelectionKind(kind: SelectionKind, existingSourceMutationToken?: number): Promise<boolean> {
            const sourceMutationToken = this.beginSourceMutation(existingSourceMutationToken)
      if (sourceMutationToken === undefined) return false
      const ownsSourceMutation = existingSourceMutationToken === undefined
      try {
        if (kind === 'installedRoot') this.currentInstalledSelectionHandle = undefined
        if (kind === 'packageFile') this.currentPackageSelectionHandle = undefined
        this.revision += 1
        await useScanStore().invalidateSource(kind, sourceMutationToken)
        return true
      } finally {
        if (ownsSourceMutation) this.endSourceMutation(sourceMutationToken)
      }
    },
    async reconcileCurrentSelections(existingSourceMutationToken?: number) {
      const installedMissing =
        this.currentInstalledSelectionHandle !== undefined &&
        !this.selections.some((selection) => selection.handle === this.currentInstalledSelectionHandle)
      const packageMissing =
        this.currentPackageSelectionHandle !== undefined &&
        !this.selections.some((selection) => selection.handle === this.currentPackageSelectionHandle)
      if (!installedMissing && !packageMissing) return
            const sourceMutationToken = this.beginSourceMutation(existingSourceMutationToken)
      if (sourceMutationToken === undefined) return
      const ownsSourceMutation = existingSourceMutationToken === undefined
      try {
        if (installedMissing) await this.invalidateSelectionKind('installedRoot', sourceMutationToken)
        if (packageMissing) await this.invalidateSelectionKind('packageFile', sourceMutationToken)
      } finally {
        if (ownsSourceMutation) this.endSourceMutation(sourceMutationToken)
      }
    },
    async releasePreviousSelection(handle: string) {
      if (handle === this.currentInstalledSelectionHandle || handle === this.currentPackageSelectionHandle) {
        await this.releaseSelection(handle)
        return
      }
      if (await this.tryReleaseSelection(handle)) return
      if (!this.pendingReleaseHandles.includes(handle) && this.pendingReleaseHandles.length < 16) {
        this.pendingReleaseHandles.push(handle)
      }
    },
    async retryPendingReleases() {
      for (const handle of [...this.pendingReleaseHandles]) {
        await this.tryReleaseSelection(handle)
      }
    },
    async tryReleaseSelection(handle: string): Promise<boolean> {
      if (handle === this.currentInstalledSelectionHandle || handle === this.currentPackageSelectionHandle) {
        return false
      }
      try {
        await sessionReleaseSelection({ handle })
        removeSelection(this, handle)
        return true
      } catch (error) {
        const desktopError = asDesktopError(error)
        if (desktopError.code === 'selection_not_found') {
          removeSelection(this, handle)
          return true
        }
        return false
      }
    },
  },
})
