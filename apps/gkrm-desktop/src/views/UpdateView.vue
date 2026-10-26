<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'

import { useRecoveryStore } from '@/stores/recovery'
import { useUpdateStore } from '@/stores/update'
import type { TwoWayDiffRow, TwoWayFileDisposition } from '@/types/commands'

const update = useUpdateStore()
const recovery = useRecoveryStore()
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
      if (update.preview?.unmergeable.includes(file.path) !== true) {
        return 'There is nothing to show for this file.'
      }
      return update.diff?.mergedByKey === true
        ? `${wholeFileReason.value} Tick it on the left to take the update’s version untouched instead.`
        : `${wholeFileReason.value} Tick it on the left to take the update’s version whole; left unticked, yours stays exactly as it is.`
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
      return 'Updated. The list below is what was applied, not what is still pending.'
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
  if (diff?.mergedByKey !== true) return undefined
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

/**
 * Whether this file is one the operator can answer.
 *
 * Every file that differs and is theirs to have edited. Identical, encrypted, or theirs alone is
 * already settled, and offering a tick for one of those would promise a choice that does not
 * exist. A file with no lines to show is still a choice: the whole of one side or the other.
 */
function decidable(file: { disposition: TwoWayFileDisposition }): boolean {
  return file.disposition === 'review'
}

/** True when this file has been handed to the update whole. */
function takesUpdate(path: string): boolean {
  return update.choices[path] !== undefined
}

/**
 * Hand one file to the update, or take it back.
 *
 * A file is answered whole. Half of one side and half of the other is a file neither the operator
 * nor the developer ever had, and nothing downstream — not Lua, not the resource — is obliged to
 * survive it. Unticked, the file is merged: what the update adds arrives, and the lines the
 * operator wrote stay theirs.
 */
function toggleFile(path: string) {
  if (applied.value) return
  update.setFileChoice(path, !takesUpdate(path))
}

function toggleEveryFile() {
  if (applied.value) return
  update.setEveryFileChoice(!update.everyFileTaken)
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

const applyLabel = computed(() => (update.loading.apply ? 'Updating…' : 'Update'))

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
  const wholeFile = update.wholeFileAnswers.filter((file) => update.choices[file.path] === undefined)
  if (wholeFile.length > 0) {
    parts.push(`${wholeFile.length} stays yours whole`)
  }
  return parts.join(' · ')
})
</script>

<template>
  <section class="update" aria-labelledby="update-heading">
    <h1 id="update-heading" class="sr-only">Update a resource</h1>

    <!-- Step 1 and 2: the two things the operator actually has. -->
    <header class="sources">
      <button
        type="button"
        class="source"
        :class="{ chosen: update.folder !== undefined }"
        :disabled="update.loading.folder || !update.canChooseSources"
        @click="update.chooseFolder()"
      >
        <span class="step">1. Installed resource</span>
        <span class="value">{{ update.folder?.displayLabel ?? 'Choose folder…' }}</span>
      </button>
      <button
        type="button"
        class="source"
        :class="{ chosen: update.package !== undefined }"
        :disabled="!update.canChoosePackages || update.loading.package"
        @click="update.choosePackage()"
      >
        <span class="step">2. New package</span>
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
        <span class="step">3. Installed from — optional</span>
        <span class="value">
          {{
            update.baseline?.displayLabel ??
            (update.canChoosePackages ? 'Choose the ZIP you installed…' : 'Choose the resource first')
          }}
        </span>
      </button>
      <button
        type="button"
        class="compare"
        :disabled="!update.canCompare"
        @click="update.compare()"
      >
        {{ update.loading.compare ? 'Comparing…' : 'Compare' }}
      </button>
    </header>

    <p v-if="baselineInPlay" class="banner baseline" role="status">
      <span>
        Comparing against <strong>{{ update.baseline?.displayLabel }}</strong> to tell the files you
        edited from the ones the developer changed. Nothing is read from it but its own versions of
        the files.
      </span>
      <button type="button" :disabled="!update.canChooseSources" @click="update.forgetBaseline()">
        Forget it
      </button>
    </p>

    <p v-if="update.preview?.usedRememberedBaseline === true" class="banner baseline" role="status">
      <span>
        Comparing against
        <strong>{{ rememberedBaseline }}</strong>, which is what this was last updated from. Your
        edits are told from the developer's without your having to find that package again.
      </span>
    </p>

    <p v-if="update.error" class="banner error" role="alert">
      <span>{{ errorMessage }}</span>
      <button type="button" @click="update.dismissError()">Dismiss</button>
    </p>

    <p v-if="update.outcome" class="banner done" role="status">{{ outcomeMessage }}</p>

    <div v-if="update.blocked === 'finishable'" class="banner blocked" role="status">
      <span>
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
      backup are untouched, but no further update can start until it is dealt with. The Console tab
      shows what is there.
    </p>

    <div v-if="update.preview === undefined" class="empty">
      <p>Point at the resource folder you installed and the ZIP you just downloaded.</p>
      <p class="muted">
        Nothing is written until you press Update, and every write is backed up first.
      </p>
      <p class="muted">
        The first time, point at the ZIP this was installed from as well: without it, every file
        you could have edited has to be asked about, and with it only the ones you actually did.
        After that this keeps the package for you and reaches for it itself.
      </p>
    </div>

    <div v-else class="panes">
      <!-- The file list, review work first. -->
      <nav class="files" aria-label="Files in this update">
        <p class="rail-title">
          <span>{{ update.preview.resource }} · {{ update.preview.summary.total }} files</span>
          <span v-if="versionMove" class="versions">{{ versionMove }}</span>
        </p>
        <label
          v-if="!applied && update.decidableFiles.length > 0"
          class="take-all"
        >
          <input
            type="checkbox"
            :checked="update.everyFileTaken"
            @change="toggleEveryFile()"
          />
          <span>Take every file from the update</span>
        </label>
        <ul>
          <li
            v-for="file in update.changedFiles"
            :key="file.path"
            :class="[
              'file-row',
              file.disposition,
              { current: file.path === update.selectedPath, taken: takesUpdate(file.path), applied },
            ]"
          >
            <span v-if="!applied" class="tick">
              <input
                v-if="decidable(file)"
                type="checkbox"
                :checked="takesUpdate(file.path)"
                :aria-label="`Take ${file.path} from the update`"
                @change="toggleFile(file.path)"
              />
            </span>
            <button
              type="button"
              class="file"
              :aria-current="file.path === update.selectedPath ? 'true' : undefined"
              @click="update.openFile(file.path)"
            >
              <span class="path" :title="file.path">{{ file.path }}</span>
              <span class="tag">{{ outcomeFor(file) }}</span>
            </button>
          </li>
        </ul>
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
          <p v-if="!applied" class="legend">
            This is what differs. Tick the file on the left to take the update's version of it
            whole; left unticked, it is merged and the lines you wrote stay yours.
          </p>
          <!-- There are no ticks any more, so the instruction to tick would be describing a
               choice the operator no longer has. -->
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

    <!-- The button, until it has been pressed. -->
    <footer v-if="update.preview" class="actions">
      <p v-if="sameVersion !== undefined && !applied" class="caution">
        This package declares version {{ sameVersion }}, the one already installed. If you meant
        to move to a newer version, check which file you chose.
      </p>
      <p class="summary">{{ summaryLine }}</p>
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
          {{ applyLabel }}
        </button>
      </template>
    </footer>

    <!--
      Every file starts ticked, so an operator can reach the update without having read the list.
      What they are handing over is named back to them before anything is written.
    -->
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
        <h2 id="confirm-heading">
          {{ update.filesHandedOver.length }}
          {{ update.filesHandedOver.length === 1 ? 'file takes' : 'files take' }} the update's
          version
        </h2>
        <p>
          What you have in {{ update.filesHandedOver.length === 1 ? 'this file' : 'these files' }}
          is replaced by what the package ships. Untick one to keep your own lines in it instead.
        </p>
        <ul class="confirm-files">
          <li v-for="file in update.filesHandedOver" :key="file.path">{{ file.path }}</li>
        </ul>
        <p class="muted">
          Every file is backed up first, and History → Undo puts this update back byte for byte.
        </p>
        <div class="confirm-actions">
          <button type="button" @click="update.cancelApply()">Back to the list</button>
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

.sources {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) minmax(0, 1fr) auto;
  gap: var(--space-12);
  align-items: stretch;
  border-bottom: 1px solid var(--border);
  padding: var(--space-12) var(--space-16);
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
  border-color: var(--accent);
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

.banner {
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

.empty {
  display: flex;
  flex: 1;
  flex-direction: column;
  gap: var(--space-8);
  align-items: center;
  justify-content: center;
  padding: var(--space-32);
  text-align: center;
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

/* One grid per row so every path starts at the same place whether or not the file can be
   ticked, and the tag never pushes the path into an ellipsis before it has to. The tick column is
   stated at a fixed width so a file that cannot be answered still lines up with one that can. */
.file-row {
  display: grid;
  grid-template-columns: 26px minmax(0, 1fr);
  align-items: center;
}

/* Once the update has run there is nothing to tick, so the column that held the ticks goes with
   them rather than leaving every row indented against an empty gutter. */
.file-row.applied {
  grid-template-columns: minmax(0, 1fr);
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
  gap: var(--space-8);
  align-items: center;
  border-bottom: 1px solid var(--border);
  padding: var(--space-8) var(--space-16);
  color: var(--text-muted);
  font-size: 0.8rem;
  cursor: pointer;
}

.take-all input {
  width: 13px;
  height: 13px;
  margin: 0;
  accent-color: var(--accent);
}

.file {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, auto);
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
  font-size: 0.84rem;
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
  font-size: 0.74rem;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.file-row.review .tag {
  color: var(--yours);
}

.file-row.take_from_update .tag,
.file-row.taken .tag {
  color: var(--accent);
}

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
  font-size: 0.84rem;
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

.tick {
  display: flex;
  align-items: center;
  justify-content: center;
}

.tick input {
  width: 13px;
  height: 13px;
  margin: 0;
  accent-color: var(--accent);
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
