import { defineStore } from 'pinia'

import {
  asDesktopError,
  selectInstalledRoot,
  selectPackagesFolder,
  sessionReleaseSelection,
  updateBatchApply,
  updateBatchOpenPackage,
  updateBatchPlan,
  updateBatchRelease,
} from '@/services/tauri/client'
import { startDurableInvocation } from '@/stores/durableInvocation'
import { useRecoveryStore } from '@/stores/recovery'
import { useUpdateStore } from '@/stores/update'
import type {
  BatchApplyResultKind,
  BatchEntry,
  BatchEntryKind,
  BatchPlanResponse,
  DesktopError,
  SelectionSummary,
} from '@/types/commands'

/**
 * Many resources from one folder of packages.
 *
 * Everything that matters here is decided by the backend: which package belongs to which
 * installed resource, and which updates need no answer. This store holds what the screen shows
 * and carries the one confirmed write. It never decides on the operator's behalf — a package that
 * needs an answer is handed to the Update screen, where the answer is given.
 */
export type BatchGroupKey = 'ready' | 'review' | 'blocked' | 'current'

export interface BatchGroup {
  key: BatchGroupKey
  label: string
  entries: BatchEntry[]
}

interface BatchState {
  installed: SelectionSummary | undefined
  packages: SelectionSummary | undefined
  plan: BatchPlanResponse | undefined
  /** What became of each entry, by id, once the batch has been applied. */
  results: Record<number, BatchApplyResultKind> | undefined
  confirming: boolean
  /** Whether an earlier update on record stands in the way. */
  blocked: 'unknown' | 'none' | 'finishable' | 'attention'
  error: DesktopError | undefined
  loading: { installed: boolean; packages: boolean; compare: boolean; apply: boolean }
}

function initialState(): BatchState {
  return {
    installed: undefined,
    packages: undefined,
    plan: undefined,
    results: undefined,
    confirming: false,
    blocked: 'unknown',
    error: undefined,
    loading: { installed: false, packages: false, compare: false, apply: false },
  }
}

/** Let go of a selection this screen made and no longer uses. See the Update store. */
async function releaseSelection(handle: string | undefined) {
  if (handle === undefined) return
  try {
    await sessionReleaseSelection({ handle })
  } catch {
    // Dropped with the session if it cannot be released now.
  }
}

async function releasePlan(handle: string | undefined) {
  if (handle === undefined) return
  try {
    await updateBatchRelease({ handle })
  } catch {
    // The backend drops the record with the session if it cannot be released now.
  }
}

/** Fixed order: what the operator can act on comes first. */
const GROUPS: ReadonlyArray<{ key: BatchGroupKey; label: string; kinds: BatchEntryKind[] }> = [
  { key: 'ready', label: 'Ready', kinds: ['ready'] },
  { key: 'review', label: 'Needs review', kinds: ['needs_review'] },
  {
    key: 'blocked',
    label: "Can't update",
    kinds: [
      'no_installed_resource',
      'duplicate_package',
      'not_a_single_resource',
      'blocked_by_earlier_update',
      'unreadable',
    ],
  },
  { key: 'current', label: 'Up to date', kinds: ['up_to_date'] },
]

export const useBatchStore = defineStore('batch', {
  state: initialState,
  getters: {
    canChooseSources(state): boolean {
      return (
        !state.loading.compare &&
        !state.loading.apply &&
        !useRecoveryStore().durableOperationInProgress
      )
    },
    canChoosePackages(state): boolean {
      return state.installed !== undefined && !state.loading.installed && this.canChooseSources
    },
    canCompare(state): boolean {
      return (
        state.installed !== undefined &&
        state.packages !== undefined &&
        !state.loading.installed &&
        !state.loading.packages &&
        this.canChooseSources
      )
    },
    groups(state): BatchGroup[] {
      const entries = state.plan?.entries ?? []
      return GROUPS.map((group) => ({
        key: group.key,
        label: group.label,
        entries: entries.filter((entry) => group.kinds.includes(entry.kind)),
      })).filter((group) => group.entries.length > 0)
    },
    readyEntries(state): BatchEntry[] {
      return (state.plan?.entries ?? []).filter((entry) => entry.kind === 'ready')
    },
    /** True while an earlier update is on record, finished or not, and has to be closed first. */
    blockedByEarlierUpdate(state): boolean {
      return state.blocked === 'finishable' || state.blocked === 'attention'
    },
    /** Updating is offered once, for a plan that has something to write and has not been used. */
    canApply(state): boolean {
      return (
        state.plan !== undefined &&
        state.plan.readyCount > 0 &&
        state.results === undefined &&
        // Offering the button while an earlier update stands in the way only led to a
        // confirmation whose last step quietly did nothing.
        !this.blockedByEarlierUpdate &&
        !state.loading.compare &&
        !state.loading.apply &&
        !useRecoveryStore().durableOperationInProgress
      )
    },
    /** True when something was tried and did not finish; the batch stopped there. */
    stopped(state): boolean {
      if (state.results === undefined) return false
      return Object.values(state.results).some((result) => result === 'failed')
    },
  },
  actions: {
    async chooseInstalled() {
      if (this.loading.installed || !this.canChooseSources) return
      this.loading.installed = true
      try {
        const response = await selectInstalledRoot()
        if (!response.cancelled && response.selection !== undefined) {
          const previous = this.installed
          this.installed = response.selection
          await this.discardPlan()
          await releaseSelection(previous?.handle)
        }
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.installed = false
      }
    },
    async choosePackages() {
      if (this.loading.packages || !this.canChoosePackages) return
      this.loading.packages = true
      try {
        const response = await selectPackagesFolder()
        if (!response.cancelled && response.selection !== undefined) {
          const previous = this.packages
          this.packages = response.selection
          await this.discardPlan()
          await releaseSelection(previous?.handle)
        }
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.packages = false
      }
    },
    /** Compare every package against the installation. Reads only. */
    async compare() {
      if (!this.canCompare || this.installed === undefined || this.packages === undefined) return
      this.loading.compare = true
      this.error = undefined
      const installedSelectionHandle = this.installed.handle
      const packagesSelectionHandle = this.packages.handle
      await this.discardPlan()
      try {
        const plan = await updateBatchPlan({ installedSelectionHandle, packagesSelectionHandle })
        // A reply for sources the operator has since changed must not become the list they see.
        if (
          this.installed?.handle !== installedSelectionHandle ||
          this.packages?.handle !== packagesSelectionHandle
        ) {
          await releasePlan(plan.handle)
          return
        }
        this.plan = plan
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.compare = false
      }
      await this.checkPreviousUpdate()
    },
    /** Ask the workspace whether an earlier update is still on record. */
    async checkPreviousUpdate() {
      await useRecoveryStore().refreshOverview()
      this.readBlockedFromOverview()
    },
    readBlockedFromOverview() {
      const recovery = useRecoveryStore()
      this.blocked = recovery.overviewIsClear
        ? 'none'
        : recovery.canFinalizeTerminal
          ? 'finishable'
          : 'attention'
    },
    /**
     * Close the finished updates so the next ones can start.
     *
     * The operator presses the button; nothing is closed on its own. Every backup is kept.
     */
    async finishPreviousUpdates() {
      const recovery = useRecoveryStore()
      if (!recovery.canFinalizeTerminal) return
      this.error = undefined
      await recovery.finalizeTerminal(true)
      this.readBlockedFromOverview()
      if (this.blocked === 'none' && this.canCompare) await this.compare()
    },
    /** Back to the list, nothing written. */
    requestApply() {
      if (this.canApply) this.confirming = true
    },
    cancelApply() {
      this.confirming = false
    },
    async apply() {
      if (this.plan === undefined || !this.canApply) return
      const recovery = useRecoveryStore()
      if (recovery.overviewPhase !== 'ready') await recovery.refreshOverview()
      if (!recovery.overviewIsClear) {
        // Say why instead of doing nothing: the screen shows what stands in the way.
        this.readBlockedFromOverview()
        this.confirming = false
        return
      }
      const generation = recovery.beginDurableOperation('apply')
      if (generation === undefined) {
        this.confirming = false
        return
      }
      const handle = this.plan.handle
      let responseReceived = false
      this.confirming = false
      this.loading.apply = true
      this.error = undefined
      const invocation = startDurableInvocation(() => updateBatchApply({ handle }))
      recovery.markDurableInvocationStarted(generation)
      try {
        const response = await invocation
        responseReceived = true
        this.results = Object.fromEntries(response.results.map((entry) => [entry.id, entry.result]))
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        await recovery.finishDurableOperation(generation, {
          responseReceived,
          error: this.error,
          retirement: undefined,
        })
        this.readBlockedFromOverview()
        this.loading.apply = false
      }
    },
    /**
     * Take one package that needs an answer to the Update screen, both sides already chosen.
     *
     * Returns whether the Update screen now holds them, so the caller knows whether to go there.
     */
    async openForReview(id: number): Promise<boolean> {
      if (this.plan === undefined || this.installed === undefined || !this.canChooseSources) {
        return false
      }
      try {
        const response = await updateBatchOpenPackage({ handle: this.plan.handle, id })
        // Selections of their own: the Update screen owns and releases them, and never lets go of
        // the ones this screen is still using.
        const update = useUpdateStore()
        await update.reset()
        update.folder = response.installed
        update.package = response.package
        return true
      } catch (error) {
        this.error = asDesktopError(error)
        return false
      }
    },
    /** Choose the sources again. Whatever was compared is dropped; nothing is written. */
    async changeSources() {
      if (!this.canChooseSources) return
      await this.discardPlan()
    },
    async discardPlan() {
      const handle = this.plan?.handle
      this.plan = undefined
      this.results = undefined
      this.confirming = false
      await releasePlan(handle)
    },
    dismissError() {
      this.error = undefined
    },
    async reset() {
      const held = [this.installed, this.packages]
      await this.discardPlan()
      Object.assign(this, initialState())
      for (const selection of held) await releaseSelection(selection?.handle)
    },
  },
})
