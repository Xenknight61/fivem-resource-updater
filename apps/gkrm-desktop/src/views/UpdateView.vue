<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'

import ActionBar from '@/components/ActionBar.vue'
import Disclosure from '@/components/Disclosure.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusNotice from '@/components/StatusNotice.vue'
import { useRecoveryStore } from '@/stores/recovery'
import { useUpdateStore } from '@/stores/update'
import { presentManifestChanges } from '@/views/manifestPresentation'
import type {
  TwoWayDiffRow,
  TwoWayFile,
  TwoWayFileDisposition,
} from '@/types/commands'

const update = useUpdateStore()
const recovery = useRecoveryStore()
const setupStatus = computed(() => {
  if (update.loading.compare) return 'Comparing your installation with the selected package…'
  if (update.folder === undefined) return 'Choose your installed resource to begin.'
  if (update.package === undefined) return 'Choose the new ZIP package to continue.'
  return 'Ready to compare. Your installation stays unchanged.'
})
const fileGroups = computed(() => [
  { disposition: 'review', label: 'Review' },
  { disposition: 'take_from_update', label: 'From update' },
  { disposition: 'keep_local_only', label: 'Only installed' },
  { disposition: 'unchanged', label: 'Unchanged' },
].map((group) => ({
  ...group,
  files: update.changedFiles.filter((file) => file.disposition === group.disposition),
})).filter((group) => group.files.length > 0))

function preserveLabel(file: TwoWayFile): string {
  return file.blockCount > 0 || file.mergedByKey
    ? 'Merge · preserve my edits'
    : 'Keep installed file'
}

function pendingChoice(path: string): boolean {
  return !applied.value && update.pendingWholeFiles.some((file) => file.path === path)
}

function chooseOutcome(path: string, event: Event) {
  if (event.target instanceof HTMLSelectElement) {
    update.setFileChoice(path, event.target.value === 'replace')
  }
}

function chooseBulkOutcome(event: Event) {
  if (event.target instanceof HTMLSelectElement) {
    update.setEveryFileChoice(event.target.value === 'replace')
  }
}

async function navigateFiles(event: KeyboardEvent) {
  if (!(event.target instanceof HTMLButtonElement) || !event.target.matches('.file')) return
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  if (update.loading.compare) return
  const buttons = Array.from(event.currentTarget instanceof HTMLElement
    ? event.currentTarget.querySelectorAll<HTMLButtonElement>('details[open] .file') : [])
  const index = buttons.indexOf(event.target)
  const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1
    : Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)))
  const target = buttons[next]
  if (target === undefined) return
  target.focus()
  const path = target.dataset.path
  if (path !== undefined) await update.openFile(path)
}
/**
 * Leaving a finished update for the next one.
 *
 * A finished update stays on record until it is closed, and nothing else can be written meanwhile.
 * The operator is on their way to another resource, so this is the moment to ask — not after they
 * have chosen it and found the button closed.
 */
const leaving = ref(false)
const leavePrompt = ref<HTMLElement>()
let leaveReturnFocus: HTMLElement | undefined
const resourceName = computed(() => update.preview?.resource ?? 'This resource')

function requestChangeSources() {
  if (update.blockedByEarlierUpdate && update.blocked === 'finishable') {
    leaveReturnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : undefined
    leaving.value = true
    void nextTick(() => leavePrompt.value?.querySelector<HTMLButtonElement>('button')?.focus())
    return
  }
  void update.changeSources()
}

function dismissLeave() {
  leaving.value = false
  leaveReturnFocus?.focus()
  leaveReturnFocus = undefined
}

async function leaveAndKeepOpen() {
  leaving.value = false
  await update.changeSources()
}

async function leaveAndClose() {
  leaving.value = false
  await update.closePreviousUpdateAndChangeSources()
}

function leaveKey(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.preventDefault()
    dismissLeave()
  } else if (event.key === 'Tab') {
    const buttons = leavePrompt.value?.querySelectorAll<HTMLButtonElement>('button')
    const first = buttons?.[0]
    const last = buttons?.[buttons.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last?.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first?.focus()
    }
  }
}

const confirmation = ref<HTMLElement>()
let returnFocus: HTMLElement | undefined
watch(() => update.confirming, async (open) => {
  if (open) {
    returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : undefined
    await nextTick()
    confirmation.value?.querySelector<HTMLButtonElement>('button')?.focus()
  } else {
    returnFocus?.focus()
    returnFocus = undefined
  }
})
onBeforeUnmount(() => returnFocus?.focus())
function confirmationKey(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.preventDefault()
    update.cancelApply()
  } else if (event.key === 'Tab') {
    const buttons = confirmation.value?.querySelectorAll<HTMLButtonElement>('button')
    const first = buttons?.[0]
    const last = buttons?.[buttons.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last?.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first?.focus()
    }
  }
}

const selected = computed(() =>
  update.preview?.files.find((file) => file.path === update.selectedPath),
)

/**
 * Why a file has no line view.
 *
 * What the file is comes before how it is protected: an encrypted file that is identical on both
 * sides is not being replaced, and saying so would describe a change that is not happening.
 */
const noDiffReason = computed(() => {
  const file = selected.value
  if (file === undefined) return ''
  if (update.diff?.omitted === true) return 'This file is too large to show line by line.'
  switch (file.disposition) {
    case 'unchanged':
      return 'This file is already identical. Nothing happens to it.'
    case 'keep_local_only':
      return 'Only you have this file. The update leaves it alone.'
    case 'take_from_update':
      if (file.untouched) {
        return 'This file is exactly what you installed, so the developer is the only one who has changed it. The update replaces it, and there is nothing here for you to decide.'
      }
      return file.editable
        ? "The update's version of this file will be used."
        : 'This file is encrypted by the developer. You could not have edited it, so the update replaces it.'
    case 'review':
      if (takesUpdate(file.path) && update.diff?.mergedByKey === true) {
        return 'The update replaces this entire file. Your existing values are not kept.'
      }
      if (update.preview?.unmergeable.includes(file.path) !== true) {
        return 'There is nothing to show for this file.'
      }
      return wholeFileReason.value
    default:
      return 'There is nothing to show for this file.'
  }
})

const outcomeMessage = computed(() => {
  switch (update.outcome) {
    case undefined:
      return ''
    case 'already_up_to_date':
      return 'Nothing to do — your installation already matches this package.'
    case 'committed':
      return 'Updated. The list shows what was applied.'
    case 'rolled_back':
      return 'Nothing was changed. The update was rolled back and your files are as they were.'
    default:
      return `The update stopped as "${update.outcome}". Your files were left recoverable — run a recovery check.`
  }
})

/**
 * The list describes an update that has already run once the outcome is in.
 *
 * Leaving it in the future tense would read as work still waiting, which is exactly the state the
 * operator must not be talked into repeating.
 */
const applied = computed(() => update.outcome !== undefined)

/**
 * True when the package would change nothing.
 *
 * Offering "Update" for an installation that already matches the package invites a press that can
 * only report that there was nothing to press it for.
 */
const nothingToDo = computed(
  () =>
    update.preview !== undefined &&
    update.preview.summary.review === 0 &&
    update.preview.summary.takeFromUpdate === 0,
)

/** What this comparison reached for by itself, as something to name on the screen. */
const rememberedBaseline = computed(() => {
  const version = update.preview?.rememberedBaselineVersion
  return version === undefined ? 'the version you had' : `version ${version}`
})

/**
 * Why the open file has no line view, said as the thing that is actually true of it.
 *
 * "An image, or content this cannot read as text" is a fair description of a PNG and a plainly
 * false one of a UTF-8 JSON that is merely too different to line up. Telling an operator something
 * untrue about their own file is worse than telling them nothing.
 */
const wholeFileReason = computed(() => {
  if (update.diff?.mergedByKey === true) {
    return 'These two are too far apart to line up — the developer laid the whole file out differently — so they were combined by key instead: this file keeps the values you changed and takes everything else, including its new keys, from the update.'
  }
  switch (update.diff?.wholeFileReason) {
    case 'not_text':
      return 'This file is not text — a picture, or content this cannot read as lines.'
    case 'too_far_apart':
      return 'Both versions are text, but too far apart to line up: too much of it changed at once.'
    case 'too_large':
      return 'This file is larger than this will hold in memory to compare.'
    default:
      return 'This file differs but cannot be combined line by line.'
  }
})

/**
 * What a key merge actually kept, so the operator can see it rather than be told about it.
 *
 * These two documents have no diff to show — every line of one differs from every line of the
 * other, which is why keys were used at all. The keys are what happened.
 */
const keptKeys = computed(() => {
  const diff = update.diff
  if (diff?.mergedByKey !== true || (selected.value !== undefined && takesUpdate(selected.value.path))) return undefined
  const shown = diff.keptKeys ?? []
  const total = diff.keptKeyCount ?? shown.length
  return { shown, more: Math.max(0, total - shown.length), total }
})

/** The two versions of a picture, when the open file is one. */
const images = computed(() => {
  const diff = update.diff
  if (diff?.installedImage === undefined && diff?.incomingImage === undefined) return undefined
  return { installed: diff?.installedImage, incoming: diff?.incomingImage }
})

/**
 * Whether the baseline is part of a comparison that could actually be run.
 *
 * It describes what a comparison will do, and there is no comparison to describe until both sides
 * of one have been chosen. Announcing it before then is a promise about work nobody has asked for
 * yet.
 */
const baselineInPlay = computed(
  () =>
    update.baseline !== undefined &&
    update.folder !== undefined &&
    update.package !== undefined,
)

/** True when this file has been handed to the update whole. */
function takesUpdate(path: string): boolean {
  return update.choices[path] !== undefined
}

/**
 * Whether one change of the open file ends up as the update wrote it.
 *
 * The view is read only, but it is not silent about the outcome: a file handed to the update
 * takes every change in it, and a file left to the merge takes the ones the operator has no line
 * of their own for. Drawing that is what lets an operator check a merge before running it rather
 * than after.
 */
function blockTaken(block: number | undefined): boolean {
  if (block === undefined || selected.value === undefined) return false
  if (takesUpdate(selected.value.path)) return true
  return update.diff?.defaultChoices[block] ?? false
}

/** What this file will be once the update runs, said as an outcome rather than as a kind. */
function outcomeFor(file: {
  path: string
  disposition: TwoWayFileDisposition
  blockCount: number
  mergedByKey: boolean
}): string {
  switch (file.disposition) {
    case 'unchanged':
      return 'identical'
    case 'keep_local_only':
      return 'stays yours'
    case 'take_from_update':
      return 'from the update'
    case 'review':
      if (pendingChoice(file.path)) return 'Decision required'
      if (takesUpdate(file.path) || update.sweepIsWholeUpdate) return 'from the update'
      if (file.blockCount > 0) return 'merged, your lines kept'
      // A document combined by key is merged too, just not by line.
      return file.mergedByKey ? 'merged, your values kept' : 'stays yours whole'
    default:
      return ''
  }
}

function marker(kind: TwoWayDiffRow['kind']): string {
  if (kind === 'yours') return '-'
  return kind === 'theirs' ? '+' : ' '
}

/**
 * Changes this file has that the view did not reach.
 *
 * They still happen, with whatever the file's own answer says, so saying nothing about them would
 * be the one thing worse than saying they are there.
 */
const undisplayedChanges = computed(() => {
  const diff = update.diff
  if (diff === undefined || !diff.available) return 0
  const shown = new Set(diff.rows.flatMap((row) => (row.block === undefined ? [] : [row.block])))
  return Math.max(0, diff.blockCount - shown.size)
})

/**
 * A failure the operator can act on, where the backend's own sentence is not enough.
 *
 * A transaction is identified by the work it does and the state it does it from, so running the
 * same update again from the same starting point asks for something that has already happened.
 * Nothing is wrong with their files, and saying only "already applied" would not make that clear.
 */
const errorMessage = computed(() => {
  if (update.error === undefined) return ''
  if (update.error.code === 'update_already_applied') {
    return `${update.error.message} Your files are untouched, and running it again would produce the same result.`
  }
  return update.error.message
})

/**
 * The version this update moves between, when both manifests declare one.
 *
 * A manifest is read, never executed. Where a side declares nothing, or declares several, this
 * says nothing rather than guessing: a wrong version label is worse than none.
 */
const versionMove = computed(() => {
  const from = update.preview?.installedVersion
  const to = update.preview?.incomingVersion
  if (from === undefined && to === undefined) return ''
  if (from === undefined) return `to ${to}`
  if (to === undefined) return `from ${from}`
  return from === to ? `${from} — the same version` : `${from} → ${to}`
})

/**
 * Both sides declaring the same version is how picking the wrong file looks from here.
 *
 * It is not an error: a developer can ship a fix without moving the number, and such an update
 * is real work. But the far likelier reading is that the package chosen is the one already
 * installed, and the quiet label above the file list was not enough to catch it — so it is said
 * again where the decision is made, next to the button. A side that declares no version, or
 * several, is not guessed at and says nothing here.
 */
const sameVersion = computed(() => {
  const from = update.preview?.installedVersion
  const to = update.preview?.incomingVersion
  return from !== undefined && to !== undefined && from === to ? from : undefined
})

/**
 * What the update's manifest declares differently, so a new dependency or script is seen before
 * it is applied. Nothing here is acted on: the manifest is only read.
 */
const manifestChanges = computed(() => presentManifestChanges(update.preview?.manifestChanges))

const manifestChangesLabel = computed(() => manifestChanges.value?.label ?? '')

const applyLabel = computed(() => (update.loading.apply ? 'Updating…' : 'Apply update'))

const summaryLine = computed(() => {
  const summary = update.preview?.summary
  if (summary === undefined) return ''
  if (nothingToDo.value && !applied.value) {
    // Files only the operator has are not in the package at all, so they cannot match it.
    const matching = summary.total - summary.keepLocalOnly
    return summary.keepLocalOnly > 0
      ? `All ${matching} files this package has already match. ${summary.keepLocalOnly} more are yours alone.`
      : `Every one of the ${summary.total} files already matches this package.`
  }
  if (applied.value) {
    const done = update.applied
    if (done === undefined) return 'Nothing was written.'
    return done.sweep
      ? `Updated · ${done.fromUpdate} files came from the update, exactly as shipped`
      : `Updated · ${done.fromUpdate} files from the update · ${done.merged} merged, your lines kept`
  }
  if (update.sweepIsWholeUpdate) {
    return `All ${summary.review + summary.takeFromUpdate} changed files come from the update, exactly as shipped`
  }
  const handed = update.decidedFiles.length
  const merged = update.mergeableFiles.filter(
    (file) => update.choices[file.path] === undefined,
  ).length
  const parts = [
    `${handed + summary.takeFromUpdate} files from the update`,
    `${merged} merged, your lines kept`,
  ]
  // The baseline's whole worth, said as a number: files the operator would otherwise have had to
  // answer for and did not have to look at.
  if (update.untouchedFiles.length > 0) {
    parts.push(`${update.untouchedFiles.length} you never changed`)
  }
  // A file nothing can be merged for is not merged. Counting it as one would be the tidy lie.
  const wholeFile = update.wholeFileAnswers.filter((file) =>
    update.choices[file.path] === undefined && update.reviewedWholeFiles.includes(file.path),
  )
  if (wholeFile.length > 0) {
    parts.push(`${wholeFile.length} stays yours whole`)
  }
  return parts.join(' · ')
})
</script>

<template>
  <section class="update" :class="{ 'is-setup': !update.preview }" aria-labelledby="update-heading">
    <PageHeader v-if="!update.preview" class="setup-header" heading-id="update-heading" title="Update a resource" description="Choose your installation and new package to review what changes.">
      <template #actions>
        <span class="header-actions">
          <a class="button-link" href="#/batch">Update several at once</a>
          <a class="button-link" href="#/history">View history</a>
        </span>
      </template>
    </PageHeader>
    <h1 v-else id="update-heading" class="sr-only">Update a resource</h1>

    <!-- Step 1 and 2: the two things the operator actually has. -->
    <header v-if="update.preview" class="source-summary">
      <div>
        <strong>{{ update.preview.resource }}</strong>
        <span v-if="versionMove" class="versions">{{ versionMove }}</span>
        <p class="muted">{{ update.folder?.displayLabel }} · {{ update.package?.displayLabel }}</p>
      </div>
      <button type="button" :disabled="!update.canChooseSources" @click="requestChangeSources()">Change sources</button>
    </header>
    <div v-else class="sources setup-sources">
      <button
        type="button"
        class="source"
        :class="{ chosen: update.folder !== undefined }"
        :disabled="update.loading.folder || !update.canChooseSources"
        @click="update.chooseFolder()"
      >
        <span class="source-copy">
          <span class="step">1. Installed resource</span>
          <span class="source-hint">The folder with your resources, or one resource inside it.</span>
        </span>
        <span class="value">{{ update.folder?.displayLabel ?? 'Choose folder…' }}</span>
      </button>
      <button
        type="button"
        class="source"
        :class="{ chosen: update.package !== undefined }"
        :disabled="!update.canChoosePackages || update.loading.package"
        @click="update.choosePackage()"
      >
        <span class="source-copy">
          <span class="step">2. New package</span>
          <span class="source-hint">The ZIP you downloaded from the developer.</span>
        </span>
        <span class="value">
          {{ update.package?.displayLabel ?? (update.canChoosePackages ? 'Choose ZIP…' : 'Choose the resource first') }}
        </span>
      </button>
      <button
        type="button"
        class="source optional"
        :class="{ chosen: update.baseline !== undefined }"
        :disabled="!update.canChoosePackages || update.loading.baseline"
        @click="update.chooseBaseline()"
      >
        <span class="source-copy">
          <span class="step">Add original package — optional</span>
          <span class="source-hint">The ZIP you originally installed. Fewer files to review.</span>
        </span>
        <span class="value">
          {{
            update.baseline?.displayLabel ?? (update.canChoosePackages ? 'Choose original ZIP…' : 'Choose the resource first')
          }}
        </span>
      </button>
    </div>

    <StatusNotice v-if="update.loading.compare && update.preview">Comparing sources… Your installation stays unchanged.</StatusNotice>

    <Disclosure v-if="manifestChanges" class="manifest-changes" :label="manifestChangesLabel">
      <p v-if="manifestChanges.fx" class="muted">fx_version: {{ manifestChanges.fx }}</p>
      <div v-for="group in manifestChanges.groups" :key="group.kind" class="manifest-group">
        <strong>{{ group.label }}</strong>
        <ul>
          <li v-for="entry in group.added" :key="`+${entry}`"><span class="sr-only">Added </span>+ {{ entry }}</li>
          <li v-for="entry in group.removed" :key="`-${entry}`"><span class="sr-only">Removed </span>− {{ entry }}</li>
        </ul>
      </div>
      <p v-if="manifestChanges.omittedCount > 0" class="muted">
        {{ manifestChanges.omittedCount }} more entries are not listed.
      </p>
    </Disclosure>

    <details v-if="baselineInPlay" class="source-details">
      <summary>Original package · {{ update.baseline?.displayLabel }}</summary>
      <p class="banner baseline">
        <span>
          Comparing against <strong>{{ update.baseline?.displayLabel }}</strong> to tell the files you
          edited from the ones the developer changed. Nothing is read from it but its own versions of
          the files.
        </span>
        <button type="button" :disabled="!update.canChooseSources" @click="update.forgetBaseline()">
          Forget it
        </button>
      </p>
    </details>

    <details v-if="update.preview?.usedRememberedBaseline === true" class="source-details">
      <summary>Using the saved original package</summary>
      <p class="banner baseline">
        <span>
          Comparing against
          <strong>{{ rememberedBaseline }}</strong>, which is what this was last updated from. Your
          edits are told from the developer's without your having to find that package again.
        </span>
      </p>
    </details>

    <StatusNotice v-if="update.error" class="banner error" tone="danger">
      {{ errorMessage }}
      <template #actions><button type="button" @click="update.dismissError()">Dismiss</button></template>
    </StatusNotice>

    <StatusNotice v-if="update.outcome" class="banner done" :tone="update.outcome === 'committed' ? 'success' : update.outcome === 'rolled_back' || update.outcome === 'already_up_to_date' ? 'neutral' : 'warning'">
      {{ outcomeMessage }}
      <template #actions><a class="text-link" href="#/history">View history</a></template>
    </StatusNotice>

    <div v-if="update.blocked === 'finishable'" class="banner blocked" role="status">
      <span v-if="update.outcome === 'committed'">
        This update is finished but still open. Close it when you are ready to update another
        resource — its backups and history are kept either way.
      </span>
      <span v-else>
        Your previous update is still on record. Close it to start another one — its backups and
        history are kept either way.
      </span>
      <button
        type="button"
        :disabled="!recovery.canFinalizeTerminal"
        @click="update.finishPreviousUpdate()"
      >
        Close previous update
      </button>
    </div>

    <p v-else-if="update.blocked === 'attention'" class="banner error" role="alert">
      An earlier update is still on record and this version cannot close it. Your files and every
      backup are untouched, but no further update can start until it is dealt with. The History tab
      shows what is there.
    </p>

    <div v-if="update.preview === undefined" class="setup-note">
      <Disclosure label="Why add the original package?">
        <p>
          It helps tell your edits from the developer’s changes, so there are fewer files to review.
          You can continue without it. After an update, this app saves the package to use next time.
        </p>
      </Disclosure>
    </div>

    <div v-else class="panes">
      <!-- The file list, review work first. -->
      <nav class="files" aria-label="Files in this update" @keydown="navigateFiles">
        <p class="rail-title">
          <span>{{ update.preview.summary.total }} files</span>
          <span v-if="!applied && update.pendingWholeFiles.length > 0" class="pending-count">{{ update.pendingWholeFiles.length }} {{ update.pendingWholeFiles.length === 1 ? 'needs' : 'need' }} a choice</span>
        </p>
        <div
          v-if="!applied && update.decidableFiles.length > 0"
          class="take-all"
        >
          <label for="bulk-outcome">Listed review files · {{ update.decidableFiles.length }}</label>
          <select
            id="bulk-outcome"
            aria-label="Outcome for all listed review files"
            :value="update.pendingWholeFiles.length > 0 ? 'mixed' : update.everyFileTaken ? 'replace' : update.hasOwnChoices ? 'mixed' : 'preserve'"
            :disabled="!update.canEditChoices"
            @change="chooseBulkOutcome"
          >
            <option disabled value="mixed">{{ update.pendingWholeFiles.length > 0 ? 'Choose outcomes…' : 'Mixed outcomes' }}</option>
            <option value="preserve">Preserve edits in all listed review files</option>
            <option value="replace">Replace all {{ update.decidableFiles.length }} listed review files with update</option>
          </select>
        </div>
        <details
          v-for="group in fileGroups"
          :key="group.disposition"
          class="file-group"
          :open="group.disposition !== 'unchanged'"
        >
          <summary>{{ group.label }} <span>{{ group.files.length }}</span></summary>
          <ul>
            <li
              v-for="file in group.files"
              :key="file.path"
              :class="[
                'file-row',
                file.disposition,
                { current: file.path === update.selectedPath, taken: takesUpdate(file.path), applied },
              ]"
            >
              <button
                type="button"
                class="file"
              :disabled="update.loading.compare"
                :data-path="file.path"
                :aria-current="file.path === update.selectedPath ? 'true' : undefined"
                @click="update.openFile(file.path)"
              >
                <span class="path" :title="file.path">{{ file.path }}</span>
                <span v-if="file.disposition !== 'review' || applied" class="tag">{{ outcomeFor(file) }}</span>
              </button>
              <select
                v-if="!applied && file.disposition === 'review'"
                class="file-outcome"
                :aria-label="`Outcome for ${file.path}`"
                :value="pendingChoice(file.path) ? '' : takesUpdate(file.path) ? 'replace' : 'preserve'"
                :disabled="!update.canEditChoices"
                @change="chooseOutcome(file.path, $event)"
              >
                <option v-if="pendingChoice(file.path)" disabled value="">Choose outcome…</option>
                <option value="preserve">{{ preserveLabel(file) }}</option>
                <option value="replace">Replace with update</option>
              </select>
            </li>
          </ul>
        </details>
        <p v-if="update.preview.omittedFileCount > 0" class="note">
          {{ update.preview.omittedFileCount }} more files are not listed. The update still applies
          to them.
        </p>
      </nav>

      <!-- The diff for whichever file is selected. -->
      <article class="diff" aria-live="polite">
        <header v-if="selected">
          <div>
            <h2>{{ selected.path }}</h2>
            <p class="muted">{{ outcomeFor(selected) }}</p>
            <p v-if="pendingChoice(selected.path)" class="choice-required">This file cannot be merged. Choose whether to keep your installed file or replace it.</p>
            <Disclosure v-else-if="selected.disposition === 'review' && !applied" class="decision-help" label="How this was decided">
              <p v-if="takesUpdate(selected.path)">The package replaces this entire file, including your edits.</p>
              <p v-else-if="selected.blockCount > 0 || selected.mergedByKey">Your changed {{ selected.mergedByKey ? 'values' : 'lines' }} stay. Other changes come from the update.</p>
              <p v-else>Your installed file stays exactly as it is. Changes from the package are not applied to this file.</p>
            </Disclosure>
          </div>
        </header>
        <p v-if="update.loading.diff" class="muted pad">Loading…</p>
        <template v-else-if="update.diff?.available">
          <ol class="lines">
            <li
              v-for="(row, index) in update.diff.rows"
              :key="index"
              :class="[row.kind, { taken: blockTaken(row.block), decided: row.block !== undefined }]"
            >
              <template v-if="row.kind === 'gap'">
                <span class="fold">{{ row.skipped }} identical lines</span>
              </template>
              <template v-else>
                <span class="number">{{ row.installedLine ?? '' }}</span>
                <span class="number">{{ row.incomingLine ?? '' }}</span>
                <span class="marker" aria-hidden="true">{{ marker(row.kind) }}</span>
                <code>{{ row.text }}</code>
              </template>
            </li>
          </ol>
          <p v-if="undisplayedChanges > 0" class="note">
            {{ undisplayedChanges }} more changes in this file are past the end of this view. They
            follow the same answer as the rest of the file.
          </p>
          <p v-if="!applied" class="legend">− Installed · + Update · Dimmed changes are not applied.</p>
          <p v-else class="legend">This is what the update did to this file.</p>
        </template>
        <template v-else-if="selected && keptKeys !== undefined">
          <p class="muted pad">{{ noDiffReason }}</p>
          <p class="kept-title">
            {{ keptKeys.total }} of your values are kept in it:
          </p>
          <ul class="kept">
            <li v-for="key in keptKeys.shown" :key="key">{{ key }}</li>
            <li v-if="keptKeys.more > 0" class="muted">and {{ keptKeys.more }} more</li>
          </ul>
        </template>
        <template v-else-if="selected && images !== undefined">
          <p class="muted pad">{{ noDiffReason }}</p>
          <div class="pictures">
            <figure>
              <figcaption>Yours</figcaption>
              <img v-if="images.installed" :src="images.installed" alt="Your version of this file" />
              <p v-else class="muted">Not shown.</p>
            </figure>
            <figure>
              <figcaption>The update's</figcaption>
              <img v-if="images.incoming" :src="images.incoming" alt="The update's version of this file" />
              <p v-else class="muted">Not shown.</p>
            </figure>
          </div>
        </template>
        <p v-else-if="selected" class="muted pad">{{ noDiffReason }}</p>
        <p v-else class="muted pad">Choose a file on the left.</p>
      </article>
    </div>

    <ActionBar v-if="!update.preview" class="setup-actions">
        <p class="setup-status" role="status">{{ setupStatus }}</p>
        <p class="setup-assurance">Nothing is written until you review and confirm the update. Every replaced file is backed up first.</p>
      <template #actions>
      <button
        type="button"
        class="primary compare"
        :disabled="!update.canCompare"
        @click="update.compare()"
      >
        {{ update.loading.compare ? 'Comparing…' : 'Compare' }}
      </button>
      </template>
    </ActionBar>

    <!-- The button, until it has been pressed. -->
    <ActionBar v-if="update.preview" class="actions">
      <p v-if="sameVersion !== undefined && !applied" class="caution">
        This package declares version {{ sameVersion }}, the one already installed. If you meant
        to move to a newer version, check which file you chose.
      </p>
      <p v-if="update.blockedByEarlierUpdate && !applied" class="caution" role="status">
        {{ update.blocked === 'finishable'
          ? 'Close the previous update above before applying this one.'
          : 'An earlier update needs attention before anything new can be applied.' }}
      </p>
      <p class="summary">{{ summaryLine }}</p>
      <p v-if="!applied && update.pendingWholeFiles.length > 0" class="choice-required">Choose an outcome for {{ update.pendingWholeFiles.length }} {{ update.pendingWholeFiles.length === 1 ? 'file' : 'files' }} to continue.</p>
      <template #actions>
      <template v-if="applied">
        <button type="button" :disabled="!update.canCompare" @click="update.compare()">
          {{ update.loading.compare ? 'Comparing…' : 'Compare again' }}
        </button>
      </template>
      <template v-else-if="nothingToDo">
        <span class="settled">Already up to date</span>
      </template>
      <template v-else>
        <button
          type="button"
          class="primary"
          :disabled="!update.canApply"
          @click="update.requestApply()"
        >
          {{ update.loading.apply ? 'Updating…' : 'Review update' }}
        </button>
      </template>
      </template>
    </ActionBar>

    <!-- On the way to another resource: offer to close the update that just finished. -->
    <div
      v-if="leaving"
      ref="leavePrompt"
      class="confirm-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="leave-heading"
      @keydown="leaveKey"
    >
      <article class="confirm">
        <h2 id="leave-heading">Close this update before you go on?</h2>
        <p>
          {{ resourceName }} is finished but still open. Close it to update another resource —
          until you do, nothing else can be written.
        </p>
        <p class="muted">
          Its backups stay, and History → Undo can still put it back.
        </p>
        <div class="confirm-actions">
          <button type="button" @click="dismissLeave()">Stay here</button>
          <button type="button" @click="leaveAndKeepOpen()">Keep it open</button>
          <button type="button" class="primary" @click="leaveAndClose()">Close it and continue</button>
        </div>
      </article>
    </div>

    <!-- Review the complete outcome and name editable files being replaced before any write. -->
    <div
      v-if="update.confirming"
      ref="confirmation"
      class="confirm-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirm-heading"
      @keydown="confirmationKey"
    >
      <article class="confirm">
        <h2 id="confirm-heading">Apply update to {{ update.preview?.resource }}?</h2>
        <p>{{ summaryLine }}</p>
        <p v-if="update.filesHandedOver.length > 0">
          {{ update.filesHandedOver.length }}
          {{ update.filesHandedOver.length === 1 ? 'file takes' : 'files take' }} the update's
          version
        </p>
        <p v-if="update.filesHandedOver.length > 0">
          What you have in {{ update.filesHandedOver.length === 1 ? 'this file' : 'these files' }}
          is replaced by what the package ships. Go back and change its outcome to preserve your edits.
        </p>
        <ul v-if="update.filesHandedOver.length > 0" class="confirm-files">
          <li v-for="file in update.filesHandedOver" :key="file.path">{{ file.path }}</li>
        </ul>
        <p class="muted">
          Every file is backed up first, and History → Undo puts this update back byte for byte.
        </p>
        <div class="confirm-actions">
          <button type="button" @click="update.cancelApply()">Back — nothing is written</button>
          <button type="button" class="primary" @click="update.apply()">{{ applyLabel }}</button>
        </div>
      </article>
    </div>
  </section>
</template>

<style scoped>
.update {
  display: flex;
  position: relative;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
  background: var(--background);
}

.is-setup {
  overflow-y: auto;
}

.is-setup > * {
  flex-shrink: 0;
}

.setup-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-24);
  border-bottom: 1px solid var(--border);
  padding: var(--space-20) var(--space-24);
}

.setup-header h1 {
  margin: 0;
  font-size: var(--text-page-title);
  line-height: 1.2;
}

.setup-header p {
  margin: var(--space-8) 0 0;
  color: var(--text-muted);
  font-size: 0.86rem;
  line-height: 1.5;
}

.setup-header .button-link {
  flex: none;
  font-size: 0.84rem;
}

.header-actions {
  display: flex;
  gap: var(--space-8);
}

.source-copy {
  display: grid;
  gap: var(--space-8);
  min-width: 0;
}

.setup-sources.sources {
  grid-template-columns: minmax(0, 1fr);
  gap: 0;
  width: min(880px, calc(100% - 48px));
  margin: var(--space-24) auto 0;
  padding: 0;
  border-bottom: 0;
}

.setup-sources .source {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(200px, 40%);
  gap: var(--space-24);
  align-items: center;
  padding: var(--space-20) 0;
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
  opacity: 1;
}

.setup-sources .step {
  color: var(--text);
  font-size: 0.86rem;
  font-weight: 600;
  letter-spacing: normal;
  text-transform: none;
}

.source-hint {
  color: var(--text-muted);
  font-size: 0.8rem;
  line-height: 1.5;
}

.setup-sources .value {
  display: block;
  width: 100%;
  border: 1px solid var(--control-border);
  border-radius: var(--radius-md);
  padding: var(--space-12);
  background: var(--surface);
  font-size: 0.84rem;
  font-weight: 500;
}

.setup-sources .source:disabled .value {
  opacity: 0.5;
}

.setup-sources .source:not(:disabled):hover .value {
  background: var(--surface-raised);
}

.setup-note {
  flex: 1 0 auto;
  width: min(880px, calc(100% - 48px));
  margin: 0 auto;
  padding: var(--space-20) 0 var(--space-32);
  color: var(--text-muted);
  font-size: 0.8rem;
}

.setup-note summary {
  width: fit-content;
}

.setup-note p {
  max-width: 68ch;
  margin: var(--space-12) 0 0;
  line-height: 1.6;
}

.setup-actions {
  position: sticky;
  bottom: 0;
  z-index: 1;
}

.setup-status {
  margin: 0;
  color: var(--text);
  font-size: 0.84rem;
}

.setup-assurance {
  max-width: 72ch;
  margin: 0;
  color: var(--text-muted);
  font-size: 0.78rem;
  line-height: 1.5;
}

.setup-actions .compare {
  flex: none;
  min-width: 110px;
}

.sources {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: var(--space-12);
  align-items: stretch;
  border-bottom: 1px solid var(--border);
  padding: var(--space-12) var(--space-16);
}

.source-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-16);
  padding: var(--space-12) var(--space-16);
  border-bottom: 1px solid var(--border);
}

.source-summary .versions {
  margin-left: var(--space-12);
}

.source-summary p {
  margin-top: var(--space-4);
  font-size: 0.8rem;
  overflow-wrap: anywhere;
}

.source-summary button {
  flex: none;
}

summary {
  cursor: pointer;
}

summary:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: -2px;
}

.manifest-group ul {
  margin: var(--space-4, 4px) 0 var(--space-12);
  padding-left: var(--space-16);
  font-family: var(--font-mono, monospace);
  font-size: var(--text-caption);
  list-style: none;
}

.source-details > summary {
  padding: var(--space-8) var(--space-16);
  color: var(--text-muted);
  font-size: 0.8rem;
}

.file-group > summary {
  padding: var(--space-12) var(--space-16) var(--space-8);
  color: var(--text-muted);
  font-size: 0.78rem;
  font-weight: 620;
}

.file-group > summary span {
  margin-left: var(--space-8);
  font-variant-numeric: tabular-nums;
}

.take-all select,
.file-outcome {
  min-width: 0;
  max-width: 100%;
  border: 1px solid var(--control-border);
  border-radius: var(--radius-md);
  padding: var(--space-4);
  color: var(--text);
  background: var(--surface);
  font-size: var(--text-code);
}

.file-outcome {
  width: calc(100% - 32px);
  margin: 0 var(--space-16) var(--space-12);
}

.decision-help {
  margin-top: var(--space-8);
  color: var(--text-muted);
  font-size: 0.8rem;
  max-width: 65ch;
}

.decision-help p {
  margin: var(--space-8) 0 0;
  line-height: 1.5;
}

.source {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  align-items: flex-start;
  min-width: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-8) var(--space-12);
  background: var(--surface);
  text-align: left;
}

/* The third source is not needed for an update to run, and reads as the quieter of the three
   until it has been given something. */
.source.optional:not(.chosen) {
  border-style: dashed;
  opacity: 0.75;
}

/* Both packages are answers about an installation, so until there is one they are not questions
   yet. Dimmed past the ordinary disabled button, and the value reads as the reason rather than as
   a thing that has been chosen. */
/* Listed after `.source.optional`, and matching its specificity, so being unusable wins over
   being optional. The other way round, the optional card rendered at 0.75 while the required one
   it waits on rendered at 0.45 — the card you cannot use looked the more available of the two. */
.source.optional:disabled,
.source:disabled {
  border-style: dashed;
  opacity: 0.45;
}

.source:disabled .value {
  color: var(--text-muted);
  font-weight: 400;
}

.source.chosen {
  border-color: var(--control-border);
}

.setup-sources .source.optional,
.setup-sources .source:disabled {
  border-style: solid;
  opacity: 1;
}

.step {
  color: var(--text-muted);
  font-size: 0.76rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.value {
  max-width: 100%;
  overflow: hidden;
  color: var(--text);
  font-size: 0.94rem;
  font-weight: 620;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.compare {
  align-self: center;
  padding: var(--space-12) var(--space-20);
  font-weight: 640;
}

.banner.baseline,
.banner.blocked {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-16);
  border-bottom: 1px solid var(--border);
  padding: var(--space-12) var(--space-16);
  margin: 0;
}

.banner.error {
  border-bottom-color: var(--danger);
  background: rgba(227, 93, 91, 0.1);
}

.banner.done {
  border-bottom-color: var(--success);
  border-left: 3px solid var(--success);
  background: rgba(47, 203, 117, 0.1);
  color: var(--text);
  font-weight: 620;
}

.banner.baseline {
  justify-content: space-between;
  gap: var(--space-16);
  align-items: center;
  border-left: 3px solid var(--accent);
  color: var(--text-muted);
}

.banner.baseline strong {
  color: var(--text);
  font-weight: 620;
}

.banner.blocked {
  border-bottom-color: var(--warning);
  background: rgba(226, 169, 59, 0.1);
}

.banner.blocked button {
  flex: none;
}

.panes {
  display: grid;
  /* The rail grows into the width a wide window has going spare, because what it holds — the
     path you are deciding about — is the thing that must stay readable. */
  grid-template-columns: minmax(0, clamp(260px, 28%, 460px)) minmax(0, 1fr);
  flex: 1;
  min-height: 0;
}

.files {
  display: flex;
  flex-direction: column;
  min-width: 0;
  border-right: 1px solid var(--border);
  background: var(--surface);
  overflow-y: auto;
}

.rail-title {
  display: grid;
  gap: 2px;
  border-bottom: 1px solid var(--border);
  padding: var(--space-12) var(--space-16);
  margin: 0;
  color: var(--text-muted);
  font-size: 0.82rem;
}

.versions {
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.84rem;
  font-weight: 620;
}

.files ul {
  list-style: none;
  padding: 0;
  margin: 0;
}

/* Review files have room for an explicit outcome beneath their path. */
.file-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  align-items: center;
}

.file-row:not(.review) .file {
  grid-template-columns: minmax(0, 1fr) auto;
}

.file-row.current {
  background: var(--surface-raised);
}

.file-row.taken {
  background: rgba(93, 168, 116, 0.1);
}

.file-row.taken.current {
  background: rgba(93, 168, 116, 0.16);
}

/* The head of the list answers every file at once, so it sits above the list rather than in it. */
.take-all {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
  align-items: stretch;
  border-bottom: 1px solid var(--border);
  padding: var(--space-8) var(--space-16);
  color: var(--text-muted);
  font-size: 0.8rem;
  cursor: pointer;
}

.file {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--space-8);
  align-items: baseline;
  min-width: 0;
  border: 0;
  border-radius: 0;
  padding: var(--space-8) var(--space-16);
  background: transparent;
  text-align: left;
}

.path {
  overflow: hidden;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: var(--text-code);
  text-overflow: ellipsis;
  white-space: nowrap;
  /* Ellipsis at the front, so a path that does not fit loses its directories and keeps its file
     name. Cut from the other end, `client/apps/phone/contacts.lua` becomes `client/apps/pho…`,
     and the operator is deciding about a file the list no longer names. */
  direction: rtl;
  text-align: left;
}

/* Only the files the operator has a say in are set in full strength; the rest are context. */
.file-row.review .path {
  color: var(--text);
}

.tag {
  overflow: hidden;
  min-width: 0;
  color: var(--text-muted);
  font-size: var(--text-caption);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-row.review .tag {
  color: var(--yours);
}

.file-row.take_from_update .tag,
.file-row.taken .tag {
  color: var(--from-update);
}

.pending-count,
.choice-required {
  color: var(--warning);
  font-size: var(--text-caption);
  line-height: 1.5;
}

.choice-required { margin: var(--space-8) 0 0; }

.diff {
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: auto;
}

.diff header {
  display: flex;
  gap: var(--space-16);
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border);
  padding: var(--space-12) var(--space-16);
}

/* What a key merge kept, which for these two documents is the only readable account of it. */
.kept-title {
  padding: 0 var(--space-16);
  margin: 0 0 var(--space-8);
  color: var(--text);
  font-size: 0.84rem;
}

.kept {
  list-style: none;
  padding: 0 var(--space-16) var(--space-16);
  margin: 0;
  display: grid;
  gap: 2px;
  font-family: var(--font-mono);
  font-size: 0.82rem;
  color: var(--yours);
}

.kept li.muted {
  color: var(--text-muted);
}

/* The two versions of a picture, side by side and the same size, because the whole question is
   which of them the operator wants. A checkerboard behind them so transparency reads as
   transparency rather than as whatever the theme happens to be. */
.pictures {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-16);
  padding: 0 var(--space-16) var(--space-16);
}

.pictures figure {
  display: grid;
  gap: var(--space-8);
  margin: 0;
  min-width: 0;
}

.pictures figcaption {
  color: var(--text-muted);
  font-size: 0.78rem;
}

.pictures img {
  display: block;
  width: 100%;
  max-height: 420px;
  object-fit: contain;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background-color: var(--surface);
  background-image:
    linear-gradient(45deg, rgba(127, 127, 127, 0.18) 25%, transparent 25%),
    linear-gradient(-45deg, rgba(127, 127, 127, 0.18) 25%, transparent 25%),
    linear-gradient(45deg, transparent 75%, rgba(127, 127, 127, 0.18) 75%),
    linear-gradient(-45deg, transparent 75%, rgba(127, 127, 127, 0.18) 75%);
  background-size: 16px 16px;
  background-position: 0 0, 0 8px, 8px -8px, -8px 0;
}

.diff h2 {
  margin: 0;
  font-family: var(--font-mono);
  font-size: var(--text-section);
}

.lines {
  padding: var(--space-8) 0;
  margin: 0;
  list-style: none;
  overflow-x: auto;
}

.lines li {
  display: grid;
  grid-template-columns: 44px 44px 12px minmax(0, 1fr);
  align-items: center;
  padding-right: var(--space-16);
  font-family: var(--font-mono);
  font-size: var(--text-code);
  line-height: 1.7;
  white-space: pre;
}

.number {
  color: var(--text-muted);
  font-size: 0.74rem;
  text-align: right;
  padding-right: var(--space-8);
  opacity: 0.7;
  font-variant-numeric: tabular-nums;
}

.marker {
  color: var(--text-muted);
  text-align: center;
}

/* What your file has, and what the update has instead. A side that is not what the file will end
   up holding is shown at rest rather than at full strength, so the outcome can be read off the
   diff without having to work it out. */
.lines li.yours {
  background: rgba(227, 93, 91, 0.09);
}

.lines li.theirs {
  background: rgba(37, 192, 109, 0.09);
}

.lines li.yours.taken {
  background: rgba(227, 93, 91, 0.2);
}

.lines li.theirs.taken {
  background: rgba(37, 192, 109, 0.2);
}

.lines li.decided:not(.taken) code {
  color: var(--text-muted);
}

.lines li.gap {
  grid-template-columns: minmax(0, 1fr);
  padding: var(--space-4) var(--space-16);
}

.fold {
  display: flex;
  gap: var(--space-12);
  align-items: center;
  color: var(--text-muted);
  font-family: system-ui, sans-serif;
  font-size: 0.74rem;
  letter-spacing: 0.03em;
}

.fold::before,
.fold::after {
  content: '';
  flex: 1;
  border-top: 1px dashed var(--border);
}

.tick-cell {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
}

.tick-cell input {
  width: 13px;
  height: 13px;
  margin: 0;
  accent-color: var(--accent);
}

.context {
  padding: 0;
  margin: 0;
  list-style: none;
}

.context li,
.side-lines li {
  font-family: var(--font-mono);
  font-size: 0.84rem;
  line-height: 1.55;
  white-space: pre;
}

.context li {
  color: var(--text-muted);
  padding-left: 26px;
}

/* Lines both sides already agree on, stood in for rather than scrolled past. */
.gap {
  display: flex;
  gap: var(--space-12);
  align-items: center;
  padding-left: 26px;
  margin: 0;
  color: var(--text-muted);
  font-size: 0.76rem;
  letter-spacing: 0.03em;
}

.gap::before,
.gap::after {
  content: '';
  flex: 1;
  border-top: 1px dashed var(--border);
}

/* Two outcomes, and the one that is picked is the one the file will hold. */
.decision {
  display: grid;
  gap: 1px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 0;
  margin: 0;
  background: var(--border);
  overflow: hidden;
}

.option {
  display: grid;
  grid-template-columns: 14px auto minmax(0, 1fr);
  gap: var(--space-12);
  align-items: baseline;
  padding: var(--space-8) var(--space-12);
  background: var(--surface);
}

.option input {
  width: 13px;
  height: 13px;
  margin: 0;
  accent-color: var(--accent);
}

.side {
  color: var(--text-muted);
  font-size: 0.76rem;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  white-space: nowrap;
}

.side-lines {
  padding: 0;
  margin: 0;
  list-style: none;
  min-width: 0;
}

.side-lines.empty {
  color: var(--text-muted);
  font-size: 0.82rem;
  font-style: italic;
}

/* Unpicked is not struck through: it is a live alternative, not a deletion. */
.option:not(.chosen) code,
.option:not(.chosen) .side-lines.empty {
  color: var(--text-muted);
  opacity: 0.65;
}

.option.mine.chosen {
  background: rgba(107, 167, 255, 0.14);
}

.option.theirs.chosen {
  background: rgba(37, 192, 109, 0.14);
}

.option.mine.chosen .side {
  color: var(--yours);
}

.option.theirs.chosen .side {
  color: var(--accent);
}

.legend,
.note {
  padding: var(--space-8) var(--space-16);
  margin: 0;
  color: var(--text-muted);
  font-size: 0.78rem;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-12);
  align-items: center;
  flex: none;
  border-top: 1px solid var(--border);
  padding: var(--space-12) var(--space-16);
  background: var(--surface);
}

/* The caution takes the whole row above the action. It is about whether to press the button at
   all, so it must not sit beside the line describing what pressing it does and read as part of
   the same sentence. */
.caution {
  flex-basis: 100%;
  margin: 0;
  color: var(--warning);
  font-size: 0.84rem;
}

.settled {
  color: var(--success);
  font-weight: 620;
}

.confirm-backdrop {
  display: grid;
  position: absolute;
  inset: 0;
  place-items: center;
  z-index: 10;
  padding: var(--space-16);
  background: rgb(0 0 0 / 55%);
}

.confirm {
  display: flex;
  flex-direction: column;
  gap: var(--space-12);
  max-width: 34rem;
  max-height: 100%;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-20);
  background: var(--surface);
}

.confirm h2 {
  margin: 0;
  font-size: var(--text-section);
}

.confirm p {
  margin: 0;
  color: var(--text-muted);
  font-size: 0.86rem;
}

/* The names are the point of asking, so they scroll rather than being cut off. */
.confirm-files {
  overflow-y: auto;
  margin: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-8) var(--space-8) var(--space-8) var(--space-24);
  background: var(--surface-raised);
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.8rem;
}

.confirm-actions {
  display: flex;
  gap: var(--space-8);
  justify-content: flex-end;
}

.summary {
  flex: 1;
  margin: 0;
  color: var(--text-muted);
  font-size: 0.84rem;
}

.primary {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--on-accent);
  font-weight: 660;
}

/* The filled button carries its own colours, so the shared disabled rule cannot dim it. A
   full-strength button that does nothing when pressed reads as a broken app. */
.primary:disabled {
  border-color: var(--border);
  background: var(--surface-raised);
  color: var(--text-muted);
}

.muted {
  color: var(--text-muted);
  margin: 0;
}

.pad {
  padding: var(--space-16);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}</style>
