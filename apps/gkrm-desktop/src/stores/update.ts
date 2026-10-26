import { defineStore } from 'pinia'

import {
  asDesktopError,
  selectInstalledRoot,
  selectPackageFile,
  updateTwoWayApply,
  updateTwoWayGetDiff,
  updateTwoWayPreview,
  updateTwoWayRelease,
} from '@/services/tauri/client'
import { useRecoveryStore } from '@/stores/recovery'
import { startDurableInvocation } from '@/stores/durableInvocation'
import type {
  DesktopError,
  SelectionSummary,
  TwoWayFile,
  TwoWayFileChoice,
  TwoWayGetDiffResponse,
  TwoWayPreviewResponse,
} from '@/types/commands'

/**
 * The two-way update, as the operator meets it: pick the installed resource, pick the new package,
 * look at what would change, tick the files the update may have, and press Update.
 *
 * This store deliberately holds no three-way state. There is no baseline, no second package, and
 * no decision document — the whole question is which files the update may have.
 */
interface UpdateState {
  folder: SelectionSummary | undefined
  package: SelectionSummary | undefined
  /**
   * The package the operator installed from, when they still have it.
   *
   * Optional, and read only for evidence: it says which of the editable files the operator has
   * actually edited, so the ones only the developer touched stop being questions. Without it
   * every editable file that differs has to be asked about, because there is nothing to tell the
   * two apart with.
   */
  baseline: SelectionSummary | undefined
  preview: TwoWayPreviewResponse | undefined
  selectedPath: string | undefined
  diff: TwoWayGetDiffResponse | undefined
  /**
   * The files the operator has handed to the update, by path.
   *
   * A file is answered as a whole or not at all. Answering it means every one of its decisions
   * goes to the update, which is why the value is a tick per decision rather than a single
   * boolean: the backend refuses a list that no longer matches the file, and that refusal is what
   * stops a decision made against one preview from being applied to a file that has since
   * changed underneath it.
   *
   * A file absent from here is not undecided — it takes the merge the button describes, which
   * keeps the operator's own lines and lets in what the update adds beside them.
   */
  choices: Record<string, boolean[]>
  outcome: string | undefined
  /**
   * What the apply was asked to do, kept so the screen can say what happened.
   *
   * The plan's own counts describe what each file *is*, not what became of it: after a clean
   * sweep nothing was merged, and after a rollback nothing happened at all. Reading either off the
   * plan tells the operator something that is not true of their installation.
   */
  applied: { sweep: boolean; fromUpdate: number; merged: number } | undefined
  /**
   * Whether the operator is being asked to confirm handing files to the update.
   *
   * Every file starts handed over, so pressing Update without reading the list is the ordinary
   * way to arrive here — and that must not be the way an operator's own work goes quietly. The
   * files are named back to them before anything is written. Handing over nothing needs no
   * confirming: there is nothing of theirs to replace.
   */
  confirming: boolean
  /**
   * Whether durable evidence from an earlier update stands in the way.
   *
   * A finished update stays on record until the operator closes it, so the next one cannot start
   * on top of a transaction nobody has accounted for. `finishable` is the ordinary case — the
   * previous update committed and only needs acknowledging. `attention` means real recovery work,
   * which this screen deliberately does not perform.
   */
  blocked: 'unknown' | 'none' | 'finishable' | 'attention'
  error: DesktopError | undefined
  loading: {
    folder: boolean
    package: boolean
    baseline: boolean
    compare: boolean
    diff: boolean
    apply: boolean
  }
}

function initialState(): UpdateState {
  return {
    folder: undefined,
    package: undefined,
    baseline: undefined,
    preview: undefined,
    selectedPath: undefined,
    diff: undefined,
    choices: {},
    outcome: undefined,
    applied: undefined,
    confirming: false,
    blocked: 'unknown',
    error: undefined,
    loading: {
      folder: false,
      package: false,
      baseline: false,
      compare: false,
      diff: false,
      apply: false,
    },
  }
}

export const useUpdateStore = defineStore('update', {
  state: initialState,
  getters: {
    /** True once both sides are chosen and nothing is in flight. */
    canCompare(state): boolean {
      return (
        state.folder !== undefined &&
        state.package !== undefined &&
        !state.loading.folder &&
        !state.loading.package &&
        !state.loading.baseline &&
        !state.loading.compare &&
        !state.loading.apply && !useRecoveryStore().durableOperationInProgress
      )
    },
    /**
     * Whether a package can be chosen yet.
     *
     * Both packages are answers about one installation: the one it is going to, and the one it
     * came from. Neither means anything until there is an installation to mean it about, and
     * offering them first invites the operator to pick two ZIPs and then wonder what happened.
     */
    canChoosePackages(state): boolean {
      return state.folder !== undefined && !state.loading.folder && this.canChooseSources
    },
    /**
     * Whether any source may be changed at all.
     *
     * Not while a comparison is in flight. The reply carries the handles it was asked about, so a
     * source changed underneath it lands as a preview of one folder under the name of another —
     * and the apply that follows re-resolves the preview's own handles, so nothing downstream
     * catches it.
     */
    canChooseSources(state): boolean {
      return !state.loading.compare && !state.loading.apply && !useRecoveryStore().durableOperationInProgress
    },
    canApply(state): boolean {
      return state.preview !== undefined && !state.loading.apply && state.outcome === undefined &&
        !useRecoveryStore().durableOperationInProgress
    },
    /** Files worth showing: everything the update would touch, quietest last. */
    changedFiles(state): TwoWayFile[] {
      if (state.preview === undefined) return []
      const rank: Record<string, number> = {
        review: 0,
        take_from_update: 1,
        keep_local_only: 2,
        unchanged: 3,
      }
      return [...state.preview.files].sort(
        (a, b) => (rank[a.disposition] ?? 9) - (rank[b.disposition] ?? 9) || a.path.localeCompare(b.path),
      )
    },
    /**
     * Decisions to send with the apply: the files handed to the update, and only those.
     *
     * A file the operator left alone is not sent. Sending nothing is exactly "keep my settings",
     * which is the preset the button describes.
     */
    decidedFiles(state): TwoWayFileChoice[] {
      return Object.entries(state.choices).map(([path, takeFromUpdate]) => ({
        path,
        takeFromUpdate: [...takeFromUpdate],
      }))
    },
    /** True once any file has been handed to the update. */
    hasOwnChoices(): boolean {
      return this.decidedFiles.length > 0
    },
    /**
     * Editable files the baseline settled, so the operator never had to look at them.
     *
     * Worth counting out loud: it is the difference between an update that asks two dozen
     * questions and one that asks the one the operator can answer.
     */
    untouchedFiles(): TwoWayFile[] {
      return this.changedFiles.filter(
        (file: TwoWayFile) =>
          file.untouched && file.editable && file.disposition === 'take_from_update',
      )
    },
    /**
     * The files the operator answers.
     *
     * Every reviewed file, whether or not it has lines to show. An image or a JSON the merge
     * cannot combine still has an answer — the whole of one side or the whole of the other — and
     * leaving it off the list was how a file nobody could tick ended up decided by default.
     */
    decidableFiles(): TwoWayFile[] {
      return this.changedFiles.filter((file: TwoWayFile) => file.disposition === 'review')
    },
    /**
     * True once every file that can be handed to the update has been.
     *
     * This is the clean sweep the second button used to be, said in ticks instead. An operator who
     * has given the update every file is not asking for a merge that happens to take every line
     * and then writes it back in their own newline style — they are asking for what the developer
     * shipped, so the apply is served from the package's own bytes. It is also the only answer
     * that reaches a file too far apart to be combined line by line.
     */
    everyFileTaken(): boolean {
      return (
        this.decidableFiles.length > 0 &&
        this.decidableFiles.every((file: TwoWayFile) => this.choices[file.path] !== undefined)
      )
    },
    /**
     * Whether handing over every listed file means handing over the whole update.
     *
     * A listing that had to stop short is not a list of everything, and ticking all of what it
     * showed cannot mean "and the rest too". The head of the list still shows what the ticks say —
     * tying the two together left a checkbox that could never be cleared.
     */
    sweepIsWholeUpdate(state): boolean {
      return (
        this.everyFileTaken &&
        state.preview !== undefined &&
        state.preview.omittedFileCount === 0
      )
    },
    /**
     * Reviewed files with nothing to merge: an image, a JSON, two sides too far apart to diff.
     *
     * They are answered whole rather than line by line, so unticked they stay exactly as the
     * operator has them. Worth counting separately: calling them merged would be a tidy lie.
     */
    wholeFileAnswers(): TwoWayFile[] {
      return this.changedFiles.filter(
        (file: TwoWayFile) =>
          file.disposition === 'review' && file.blockCount === 0 && !file.mergedByKey,
      )
    },
    /**
     * The files whose own content the update would replace, named so they can be read back.
     *
     * Every file on this list is one where what the operator has differs from what the package
     * ships and the operator could have written the difference — which is the whole of what being
     * asked about means. Handing one over is answering "the developer's version, then".
     */
    filesHandedOver(): TwoWayFile[] {
      return this.decidableFiles.filter(
        (file: TwoWayFile) => this.choices[file.path] !== undefined,
      )
    },
    /** Reviewed files that are merged, whether by line or by key. */
    mergeableFiles(): TwoWayFile[] {
      return this.decidableFiles.filter(
        (file: TwoWayFile) => file.blockCount > 0 || file.mergedByKey,
      )
    },
  },
  actions: {
    async chooseFolder() {
      if (this.loading.folder || !this.canChooseSources) return
      this.loading.folder = true
      try {
        const response = await selectInstalledRoot()
        if (!response.cancelled && response.selection !== undefined) {
          this.folder = response.selection
          await this.discardPreview()
        }
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.folder = false
      }
    },
    async choosePackage() {
      if (!this.canChoosePackages || this.loading.package) return
      this.loading.package = true
      try {
        const response = await selectPackageFile()
        if (!response.cancelled && response.selection !== undefined) {
          this.package = response.selection
          await this.discardPreview()
        }
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.package = false
      }
    },
    /** Point at the package this installation was installed from. */
    async chooseBaseline() {
      if (!this.canChoosePackages || this.loading.baseline) return
      this.loading.baseline = true
      try {
        const response = await selectPackageFile()
        if (!response.cancelled && response.selection !== undefined) {
          this.baseline = response.selection
          await this.discardPreview()
        }
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.baseline = false
      }
    },
    /** Go back to comparing two sides, with nothing said about who changed what. */
    async forgetBaseline() {
      if (this.loading.baseline || !this.canChooseSources || this.baseline === undefined) return
      this.baseline = undefined
      await this.discardPreview()
    },
    async compare() {
      if (!this.canCompare || this.folder === undefined || this.package === undefined) return
      this.loading.compare = true
      this.error = undefined
      const installedSelectionHandle = this.folder.handle
      const packageSelectionHandle = this.package.handle
      const baselineSelectionHandle = this.baseline?.handle
      // Deciding to keep a file is the operator's, and comparing again does not unmake it.
      // Re-ticking everything turned "keep mine" back into "hand it over" under the very button
      // they had just pressed — after an update the primary button becomes Compare again in the
      // same place — leaving only the confirmation between a second press and the edits they
      // had just protected. The decisions are carried across instead.
      const kept = this.decidableFiles
        .filter((file: TwoWayFile) => this.choices[file.path] === undefined)
        .map((file: TwoWayFile) => file.path)
      try {
        await this.discardPreview()
        this.preview = await updateTwoWayPreview({
          installedSelectionHandle,
          packageSelectionHandle,
          ...(baselineSelectionHandle === undefined ? {} : { baselineSelectionHandle }),
        })
        // Every file starts handed to the update, so the plain answer to "I want the new
        // version" is to press Update. Untick the ones whose edits are worth keeping. Nothing is
        // lost quietly for it: handing over a file the operator has edited is confirmed before
        // anything is written, and named file by file.
        this.setEveryFileChoice(true)
        // Only a file this comparison still asks about can carry an answer. `setFileChoice`
        // refuses every other path, so a file that is gone, or that the update no longer offers
        // a decision on, starts from the default rather than from a stale answer.
        for (const path of kept) this.setFileChoice(path, false)
        const first = this.preview.files.find((file) => file.disposition === 'review')
        if (first !== undefined) await this.openFile(first.path)
      } catch (error) {
        const failure = asDesktopError(error)
        // "Recovery is required" is not something the operator can act on from an error banner,
        // and reporting it twice — once raw, once explained — is worse than once. Find out
        // whether the previous update merely needs closing, and let that banner be the report.
        if (failure.code === 'recovery_required') {
          await this.checkPreviousUpdate()
        } else {
          this.error = failure
        }
      } finally {
        this.loading.compare = false
      }
    },
    /** Ask the workspace whether an earlier update is still on record. */
    async checkPreviousUpdate() {
      const recovery = useRecoveryStore()
      await recovery.refreshOverview()
      this.readBlockedFromOverview()
    },
    /** Classify the overview the recovery store already holds. Makes no call of its own. */
    readBlockedFromOverview() {
      const recovery = useRecoveryStore()
      this.blocked = recovery.overviewIsClear
        ? 'none'
        : recovery.canFinalizeTerminal
          ? 'finishable'
          : 'attention'
    },
    /**
     * Close a finished update so the next one can start.
     *
     * Nothing is cleaned up automatically anywhere in this product, and this is no exception: the
     * operator presses the button. The evidence itself is kept; only its hold on new work ends.
     */
    async finishPreviousUpdate() {
      const recovery = useRecoveryStore()
      if (!recovery.canFinalizeTerminal) return
      this.error = undefined
      await recovery.finalizeTerminal(true)
      // Finalizing reloads the overview itself. Asking again would be a second trusted call
      // racing the first, and the backend serves one at a time: the loser is reported to the
      // operator as "a recovery operation is already running", which they did not cause.
      this.readBlockedFromOverview()
      if (this.blocked === 'none' && this.folder !== undefined && this.package !== undefined) {
        await this.compare()
      }
    },
    async openFile(path: string) {
      if (this.preview === undefined || this.loading.diff) return
      this.selectedPath = path
      this.diff = undefined
      this.loading.diff = true
      const handle = this.preview.handle
      try {
        const diff = await updateTwoWayGetDiff({ handle, path })
        // A slower reply for a file the operator has already navigated away from must not
        // overwrite the one they are looking at now.
        if (this.selectedPath !== path || this.preview?.handle !== handle) return
        // Opening a file reads it. What becomes of it is answered in the list, so looking at a
        // diff can never quietly commit the operator to anything.
        this.diff = diff
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.loading.diff = false
      }
    },
    /**
     * Hand one file to the update, or take it back.
     *
     * The file does not have to have been opened. Its decision count comes from the preview, so a
     * file can be answered from the list — which is the point: an operator who edited one file
     * should not have to walk through the two dozen they never touched.
     */
    setFileChoice(path: string, take: boolean) {
      if (this.outcome !== undefined) return
      const file = this.preview?.files.find((candidate) => candidate.path === path)
      if (file === undefined || file.disposition !== 'review') return
      if (take) {
        this.choices[path] = new Array<boolean>(file.blockCount).fill(true)
        return
      }
      delete this.choices[path]
    },
    /** Hand every file to the update, or take them all back. */
    setEveryFileChoice(take: boolean) {
      for (const file of this.decidableFiles) {
        this.setFileChoice(file.path, take)
      }
    },
    /**
     * Run the update the ticks describe.
     *
     * There is one button because there is one question, and the file list has already answered
     * it. Having given the update every file, the operator gets the package's own bytes; having
     * given it some or none, the rest are merged and the lines they wrote stay theirs.
     */
    /**
     * What the Update button does: ask first when the operator's own files are being handed over.
     *
     * Every file starts handed over, so an operator who never opened the list arrives here having
     * chosen nothing — and that is exactly when their work would go without their having said so.
     * Handing over nothing goes straight through: there is nothing of theirs to replace, and an
     * update that keeps all of it has nothing to warn about.
     */
    async requestApply() {
      if (!this.canApply) return
      if (this.hasOwnChoices) {
        this.confirming = true
        return
      }
      await this.apply()
    },
    /** Back to the list, nothing written. */
    cancelApply() {
      this.confirming = false
    },
    async apply() {
      if (this.preview === undefined || !this.canApply) return
      const recovery = useRecoveryStore()
      if (recovery.overviewPhase !== 'ready') await recovery.refreshOverview()
      if (!recovery.overviewIsClear) return
      const generation = recovery.beginDurableOperation('apply')
      if (generation === undefined) return
      const handle = this.preview.handle
      let responseReceived = false
      this.confirming = false
      const sweep = this.sweepIsWholeUpdate
      const summary = this.preview.summary
      const handed = this.decidedFiles.length
      const asked = {
        sweep,
        fromUpdate: sweep ? summary.review + summary.takeFromUpdate : handed + summary.takeFromUpdate,
        // Only a file that is actually merged is reported as merged. A file kept whole was not.
        merged: sweep
          ? 0
          : this.mergeableFiles.filter((file: TwoWayFile) => this.choices[file.path] === undefined)
              .length,
      }
      this.loading.apply = true
      this.error = undefined
      const invocation = startDurableInvocation(() => updateTwoWayApply({
        handle,
        keepSettings: !sweep,
        choices: sweep ? [] : this.decidedFiles,
      }))
      recovery.markDurableInvocationStarted(generation)
      try {
        const response = await invocation
        responseReceived = true
        this.outcome = response.outcome
        // Only a committed update did any of it. Anything else left the installation alone.
        this.applied = response.outcome === 'committed' ? asked : undefined
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        // A lost response may still mean live files changed. Never retain decisions
        // from before a durable invocation, even when the command rejected.
        if (this.outcome === undefined) {
          this.preview = undefined
          this.diff = undefined
          this.selectedPath = undefined
          this.choices = {}
        }
        await recovery.finishDurableOperation(generation, {
          responseReceived, error: this.error, retirement: undefined,
        })
        this.readBlockedFromOverview()
        this.loading.apply = false
      }
    },
    /** Release the backend's held preview. A failure here is not the operator's problem. */
    async discardPreview() {
      const handle = this.preview?.handle
      this.preview = undefined
      this.selectedPath = undefined
      this.diff = undefined
      this.choices = {}
      this.outcome = undefined
      this.applied = undefined
      this.confirming = false
      if (handle === undefined) return
      try {
        await updateTwoWayRelease({ handle })
      } catch {
        // The record is dropped with the session either way.
      }
    },
    dismissError() {
      this.error = undefined
    },
    async reset() {
      await this.discardPreview()
      Object.assign(this, initialState())
    },
  },
})
