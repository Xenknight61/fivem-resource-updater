<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import LoadingState from '@/components/LoadingState.vue'
import {
  asDesktopError,
  storageRelease,
  storageReport,
  updateHistoryList,
  updateHistoryUndo,
} from '@/services/tauri/client'
import { startDurableInvocation } from '@/stores/durableInvocation'
import { useRecoveryStore } from '@/stores/recovery'
import { useScanStore } from '@/stores/scan'
import { useSessionStore } from '@/stores/session'
import type {
  DesktopError,
  HeldBaseline,
  RecoveryOutcome,
  RecoveryStatus,
  StorageReleaseResponse,
  StorageReportResponse,
  UpdateHistoryEntry,
  UpdateHistoryUndoResponse,
} from '@/types/commands'

/**
 * What earlier updates left behind, and the only place recovery is performed.
 *
 * The update screen carries the whole ordinary workflow. This one exists for the days it does not
 * go to plan: a machine that lost power mid-write, a finished update nobody closed, evidence
 * somebody needs to look at. Nothing here ever runs on its own.
 *
 * The wording is deliberately one vocabulary. The same act was called "closing" on the update
 * screen, "finalizing" on its button, and "preserving as history" in the paragraph above it —
 * three names for one press, which is how an operator learns to distrust a screen.
 */
const session = useSessionStore()
const scan = useScanStore()
const recovery = useRecoveryStore()

/**
 * The updates this operator has already run.
 *
 * Asking them to point at a folder to be told something the application itself did is the kind of
 * question a screen should not have to ask. Choosing a folder is kept for the one thing that
 * genuinely needs it: recovery writes to the live installation and must bind to it.
 */
const entries = ref<UpdateHistoryEntry[]>([])
const selected = ref<string | undefined>(undefined)
const loadingHistory = ref(false)

/**
 * What names one update in the list.
 *
 * The same resource is updated more than once, so the resource name alone picks out several rows
 * at a time — and one of them can be put back while the others cannot.
 */
function keyOf(entry: UpdateHistoryEntry): string {
  return entry.id === '' ? `${entry.resource}-${entry.appliedAtMs}` : entry.id
}

const selectedEntry = computed(() => entries.value.find((entry) => keyOf(entry) === selected.value))

async function loadHistory() {
  loadingHistory.value = true
  try {
    entries.value = (await updateHistoryList()).entries
    const first = entries.value[0]
    if (selected.value === undefined && first !== undefined) selected.value = keyOf(first)
  } catch {
    // The list is a convenience; the workspace state below is what actually matters.
    entries.value = []
  } finally {
    loadingHistory.value = false
  }
}

onMounted(() => {
  if (recovery.overviewPhase === 'unknown') void recovery.refreshOverview()
  void loadHistory()
  void loadStorage()
})

const outcomeLabel: Record<string, string> = {
  committed: 'Updated',
  rolled_back: 'Rolled back',
  undone: 'Undone',
  undone_partial: 'Undone · your later changes kept',
  recovery_required: 'Needs recovery',
}

/** Which version this update moved between, when both manifests declared one. */
function versionMove(entry: UpdateHistoryEntry): string {
  const { fromVersion: from, toVersion: to } = entry
  if (from === undefined && to === undefined) return ''
  if (from === undefined) return `to ${to}`
  if (to === undefined) return `from ${from}`
  return from === to ? from : `${from} → ${to}`
}

function when(entry: UpdateHistoryEntry): string {
  // An update found in the workspace rather than watched as it ran. The evidence says it
  // happened and does not say when, so neither does this.
  if (entry.appliedAtMs === 0) return 'time not recorded'
  const date = new Date(entry.appliedAtMs)
  return Number.isNaN(date.getTime())
    ? 'unknown time'
    : date.toLocaleString('en-GB', {
        day: 'numeric',
        month: 'short',
        hour: '2-digit',
        minute: '2-digit',
      })
}

/**
 * Putting an update back.
 *
 * This writes to the operator's installation, so it is asked for twice: once to say what it will
 * do, once to do it. What it reports afterwards is counted from what actually happened on disk,
 * not from what was intended.
 */
const confirmingUndo = ref(false)
const undoing = ref(false)
const undone = ref<UpdateHistoryUndoResponse | undefined>(undefined)
const undoError = ref<string | undefined>(undefined)

const canUndo = computed(() => recovery.overviewPhase === 'ready' &&
  !recovery.durableOperationInProgress && recovery.overview?.activeRecovery === false &&
  recovery.overview.manualAttention === false && recovery.overview.unsupportedEvidence === false)

function askToUndo() {
  if (!canUndo.value) return
  confirmingUndo.value = true
  undone.value = undefined
  undoError.value = undefined
}

async function confirmUndo() {
  const entry = selectedEntry.value
  if (entry === undefined || undoing.value || !canUndo.value) return
  const generation = recovery.beginDurableOperation('undo')
  if (generation === undefined) return
  undoing.value = true
  undoError.value = undefined
  let responseReceived = false
  let failure: DesktopError | undefined
  const invocation = startDurableInvocation(() => updateHistoryUndo({ id: entry.id }))
  recovery.markDurableInvocationStarted(generation)
  try {
    undone.value = await invocation
    responseReceived = true
  } catch (error) {
    failure = asDesktopError(error)
    undoError.value = failure.message
    undone.value = undefined
  } finally {
    confirmingUndo.value = false
    await recovery.finishDurableOperation(generation, { responseReceived, error: failure, retirement: undefined })
    await loadHistory()
    undoing.value = false
  }
}

/** What putting it back amounted to, in the operator's words rather than field names. */
const undoneSummary = computed(() => {
  const result = undone.value
  if (result === undefined) return ''
  const parts: string[] = []
  if (result.restored > 0) parts.push(`${result.restored} put back`)
  if (result.removed > 0) parts.push(`${result.removed} removed`)
  if (result.unchanged > 0) parts.push(`${result.unchanged} already as they were`)
  if (result.skipped > 0) parts.push(`${result.skipped} left alone — you changed them since`)
  if (result.missing > 0) parts.push(`${result.missing} could not be found in the backups`)
  return parts.length === 0 ? 'Nothing needed changing.' : `${parts.join(', ')}.`
})

const busy = computed(
  () => recovery.overviewPhase === 'checking' || recovery.overviewPhase === 'reconciling',
)

/** One sentence for the whole workspace, worst first. */
const state = computed(() => {
  if (busy.value) return { tone: 'muted', text: 'Checking…' }
  if (recovery.overviewPhase !== 'ready' || recovery.overview === undefined) {
    return { tone: 'danger', text: 'The state of this workspace could not be established.' }
  }
  const overview = recovery.overview
  if (overview.manualAttention || overview.unsupportedEvidence) {
    return { tone: 'danger', text: 'Something here needs a person to look at it.' }
  }
  if (overview.activeRecovery) {
    return { tone: 'danger', text: 'An update did not finish. It can be recovered below.' }
  }
  if (overview.terminalEvidence) {
    return { tone: 'warning', text: 'One finished update is still on record.' }
  }
  return { tone: 'ok', text: 'Nothing outstanding. Every update here is closed.' }
})

/**
 * Whether anything here can actually be recovered.
 *
 * Recovery needs the live installation, so it needs a folder — a question worth asking only when
 * there is something to recover. Offering the whole procedure under the words "nothing
 * outstanding" reads as a chore the operator has failed to do.
 */
const somethingToRecover = computed(
  () =>
    recovery.overviewPhase === 'ready' &&
    recovery.overview !== undefined &&
    (recovery.overview.activeRecovery ||
      recovery.overview.manualAttention ||
      recovery.overview.unsupportedEvidence),
)

const installedSelection = computed(() => session.currentInstalledSelection)
const installedIntent = computed(() =>
  scan.installedIntent?.selectionHandle === installedSelection.value?.handle
    ? scan.installedIntent
    : undefined,
)
const canInspect = computed(
  () =>
    installedIntent.value?.resourceHandle !== undefined &&
    !recovery.durableOperationInProgress &&
    !recovery.loading.status &&
    !recovery.loading.execute,
)
const canRecover = computed(
  () =>
    recovery.overviewPhase === 'ready' &&
    !recovery.durableOperationInProgress &&
    !recovery.loading.execute &&
    !recovery.loading.status &&
    recovery.outcome === undefined,
)

/** What an inspection found, in the operator's terms rather than the journal's. */
const statusCopy: Record<RecoveryStatus, string> = {
  clear: 'Nothing is on record for this resource.',
  recovery_available: 'An unfinished update is here and can be recovered.',
  committed: 'The last update finished and its files were written.',
  rolled_back: 'The last update was undone. Your files are as they were.',
  safe_restart: 'The last update stopped before touching anything.',
  recovery_required: 'An unfinished update is here and needs recovering.',
  manual_attention: 'This evidence needs a person to look at it. It cannot be recovered here.',
  ambiguous: 'More than one record matches, so none was chosen.',
  unsupported: 'This app cannot recover this evidence.',
}

const outcomeCopy: Record<RecoveryOutcome, string> = {
  recovered_committed: 'Recovered. The update had finished, and its files stand.',
  recovered_rolled_back: 'Recovered. The update was undone and your files are as they were.',
  safe_restart: 'Recovered. The update had stopped before touching anything.',
  recovery_still_required: 'Recovery ran but is still needed. Check again before trying once more.',
}

function inspect() {
  const intent = scan.installedIntent
  if (intent === undefined || intent.resourceHandle === undefined) return
  void recovery.inspect(intent)
}

function recover(candidateHandle: string) {
  if (!canRecover.value) return
  if (!window.confirm('Recover this update? Your files will be put back the way it left them.')) {
    return
  }
  void recovery.execute(candidateHandle)
}

/**
 * What is kept so later updates can tell the operator's work from the developer's.
 *
 * It belongs on this screen because this screen is already the one about what updates leave behind
 * — and it is by a wide margin the largest of those things. Nothing is offered for release but the
 * copies nothing reaches for, so there is no size to weigh against a risk and no policy to choose:
 * either something still needs a package or it does not.
 */
const storage = ref<StorageReportResponse | undefined>(undefined)
const releasing = ref(false)
const released = ref<StorageReleaseResponse | undefined>(undefined)

async function loadStorage() {
  try {
    storage.value = await storageReport()
  } catch {
    // Knowing what is held is a convenience. Failing to say costs nothing that matters.
    storage.value = undefined
  }
}

async function release() {
  if (releasing.value) return
  releasing.value = true
  released.value = undefined
  try {
    released.value = await storageRelease()
    await loadStorage()
  } catch {
    // Reported by what is still held rather than by a banner: the number is the honest answer.
    await loadStorage()
  } finally {
    releasing.value = false
  }
}

/** Sizes an operator reads at a glance. Bytes on a disk, so the units are the ones a disk uses. */
function megabytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`
  return `${(bytes / (1024 * 1024)).toFixed(bytes < 100 * 1024 * 1024 ? 1 : 0)} MB`
}

/** Both halves together: what the two of them occupy, and what a release would actually free. */
const totalHeld = computed(
  () => (storage.value?.heldBytes ?? 0) + (storage.value?.stagedBytes ?? 0),
)
const totalReleasable = computed(
  () => (storage.value?.releasableBytes ?? 0) + (storage.value?.stagedReleasableBytes ?? 0),
)

/** What one kept package is still owed to, said as the reason rather than as a category. */
function keptFor(held: HeldBaseline): string {
  switch (held.neededFor) {
    case 'installation':
      return 'an installation is on it'
    case 'undo':
      return 'an update can still be put back onto it'
    default:
      return 'nothing needs it'
  }
}
</script>

<template>
  <section class="history" aria-labelledby="history-heading">
    <header class="page">
      <h1 id="history-heading">History</h1>
      <p class="lede">
        Every update keeps its backups and its journal. Recovering and closing are always something
        you start — nothing here happens on its own.
      </p>
    </header>

    <!-- The whole workspace in one line, and the one action it offers. -->
    <div :class="['state', state.tone]" role="status">
      <span>{{ state.text }}</span>
      <span class="state-actions">
        <button
          v-if="recovery.canFinalizeTerminal"
          type="button"
          class="primary"
          @click="recovery.finalizeTerminal(true)"
        >
          Close it
        </button>
        <button type="button" :disabled="busy" @click="recovery.refreshOverview()">
          {{ busy ? 'Checking…' : 'Check again' }}
        </button>
      </span>
    </div>
    <p v-if="recovery.canFinalizeTerminal" class="hint">
      Closing it lets the next update start. Its backups and journal are kept either way.
    </p>
    <p v-if="recovery.overviewPhase === 'error'" class="hint danger" role="alert">
      {{ recovery.overviewError?.message }}
    </p>

    <div class="panes">
      <!-- What you have already done. No folder to point at: the app did these. -->
      <nav class="past" aria-label="Updates you have run">
        <p class="rail-title">Your updates</p>
        <LoadingState v-if="loadingHistory" label="Reading your updates" />
        <p v-else-if="entries.length === 0" class="hint pad">
          Nothing yet. Updates you run appear here.
        </p>
        <ul v-else>
          <li v-for="entry in entries" :key="keyOf(entry)">
            <button
              type="button"
              :class="{ current: keyOf(entry) === selected }"
              :aria-current="keyOf(entry) === selected ? 'true' : undefined"
              @click="selected = keyOf(entry); confirmingUndo = false; undone = undefined"
            >
              <span class="name">{{ entry.resource }}</span>
              <span class="meta">
                <template v-if="versionMove(entry)">{{ versionMove(entry) }} · </template
                >{{ when(entry) }}
              </span>
            </button>
          </li>
        </ul>
      </nav>

      <article class="detail">
        <template v-if="selectedEntry">
          <h2>{{ selectedEntry.resource }}</h2>
          <p v-if="versionMove(selectedEntry)" class="versions">
            {{ versionMove(selectedEntry) }}
          </p>
          <p class="hint">
            {{ outcomeLabel[selectedEntry.outcome] ?? selectedEntry.outcome }} ·
            {{ when(selectedEntry) }} · {{ selectedEntry.total }} files ·
            {{ selectedEntry.reviewed }} you decided · {{ selectedEntry.replaced }} replaced
          </p>

          <!-- Putting it back writes to the live installation, so it asks before it does. -->
          <div v-if="selectedEntry.undoable" class="undo">
            <template v-if="!confirmingUndo">
              <button type="button" :disabled="!canUndo" @click="askToUndo()">Undo this update</button>
              <p class="hint">
                Puts every file this update replaced back exactly as it was. Files you have changed
                since are left alone.
              </p>
            </template>
            <template v-else>
              <p class="hint warn">
                This writes to {{ selectedEntry.resource }} in the folder you updated. Files you
                have edited since this update are left as you left them.
              </p>
              <div class="undo-actions">
                <button type="button" class="primary" :disabled="undoing || !canUndo" @click="confirmUndo()">
                  {{ undoing ? 'Putting it back…' : 'Yes, put it back' }}
                </button>
                <button type="button" :disabled="undoing" @click="confirmingUndo = false">
                  Cancel
                </button>
              </div>
            </template>
          </div>
          <p v-else-if="selectedEntry.outcome === 'committed'" class="hint">
            This one cannot be put back: there is no record of what it replaced.
          </p>
          <p v-if="undoneSummary" class="hint ok" role="status">{{ undoneSummary }}</p>
          <p v-if="undoError" class="hint danger" role="alert">{{ undoError }}</p>
        </template>
        <p v-else class="hint">Choose an update on the left to see what it did.</p>

        <!-- Recovery is the one thing that needs the folder: it writes to the live installation
             and has to bind to it at the moment it runs. It appears only when there is something
             to recover. -->
        <section
          v-if="somethingToRecover"
          class="recover"
          aria-labelledby="recover-heading"
        >
          <h3 id="recover-heading">Recover an unfinished update</h3>
          <p class="hint">
            Point at the folder that holds your resource directories, then the resource inside it.
          </p>

          <div class="steps">
            <button
              type="button"
              :disabled="session.loading.selectInstalledRoot || recovery.durableOperationInProgress"
              @click="session.chooseInstalledRoot()"
            >
              {{ installedSelection?.displayLabel ?? 'Choose folder…' }}
            </button>
            <button
              type="button"
              :disabled="
                installedSelection === undefined ||
                scan.loading.scanInstalledRoot ||
                recovery.durableOperationInProgress
              "
              @click="installedSelection && scan.scanInstalled(installedSelection.handle)"
            >
              {{ scan.loading.scanInstalledRoot ? 'Reading…' : 'Read folder' }}
            </button>
            <button type="button" class="primary" :disabled="!canInspect" @click="inspect()">
              {{ recovery.recoveryHandle === undefined ? 'Look' : 'Look again' }}
            </button>
          </div>

          <LoadingState v-if="scan.loading.list" label="Reading the folder" />
          <ul v-else-if="scan.resources.length > 0" class="resources">
            <li v-for="resource in scan.resources" :key="resource.resourceHandle">
              <button
                type="button"
                :class="{ current: resource.resourceHandle === scan.selectedResourceHandle }"
                :aria-current="
                  resource.resourceHandle === scan.selectedResourceHandle ? 'true' : undefined
                "
                @click="scan.selectResource(resource.resourceHandle)"
              >
                {{ resource.displayName }}
              </button>
            </li>
          </ul>

          <LoadingState v-if="recovery.loading.status" label="Looking at this resource" />
          <LoadingState v-else-if="recovery.loading.execute" label="Recovering" />
          <p v-else-if="recovery.error" class="hint danger" role="alert">
            {{ recovery.error.message }}
          </p>
          <p v-else-if="recovery.outcome" class="found">{{ outcomeCopy[recovery.outcome] }}</p>
          <p v-else-if="recovery.status" class="found">{{ statusCopy[recovery.status] }}</p>

          <ul v-if="recovery.candidates.length > 0" class="candidates">
            <li v-for="candidate in recovery.candidates" :key="candidate.candidateHandle">
              <span class="name">{{ candidate.resourceLabel }}</span>
              <button
                v-if="candidate.recoverable"
                type="button"
                class="primary"
                :disabled="!canRecover"
                @click="recover(candidate.candidateHandle)"
              >
                Recover
              </button>
              <span v-else class="hint">Cannot be recovered here.</span>
            </li>
          </ul>
        </section>
      </article>
    </div>

    <!--
      What updates keep, in the same shape as the state line above: one sentence and the one action
      it offers. The accounting is a disclosure rather than a list, because the only thing most
      operators want from it is the number.
    -->
    <div v-if="storage && totalHeld > 0" class="kept">
      <div class="kept-line">
        <span>
          <strong>{{ megabytes(totalHeld) }}</strong> left behind by past updates —
          <template v-if="totalReleasable > 0">
            {{ megabytes(totalReleasable) }} of it is no longer needed.
          </template>
          <template v-else>all of it is still in use.</template>
        </span>
        <span class="kept-actions">
          <span v-if="released" class="done" role="status">
            Released {{ megabytes(released.bytes) }}.
          </span>
          <!-- Not the filled primary. Letting go of storage is housekeeping, and it was the
               loudest thing on a screen whose actual subject is putting an update back. -->
          <button
            v-if="totalReleasable > 0"
            type="button"
            :disabled="releasing || recovery.durableOperationInProgress"
            @click="release()"
          >
            {{ releasing ? 'Releasing…' : `Release ${megabytes(totalReleasable)}` }}
          </button>
        </span>
      </div>
      <details>
        <summary>What is kept, and what for</summary>
        <ul class="kept-list">
          <li v-for="held in storage.baselines" :key="`${held.resource}-${held.bytes}`">
            <span class="name">{{ held.version ? `${held.resource} ${held.version}` : held.resource }}</span>
            <span class="meta">{{ megabytes(held.bytes) }} · {{ keptFor(held) }}</span>
          </li>
          <li v-if="storage.stagedCount > 0">
            <span class="name">
              {{ storage.stagedCount }} staged
              {{ storage.stagedCount === 1 ? 'copy' : 'copies' }}
            </span>
            <span class="meta">
              {{ megabytes(storage.stagedBytes) }} ·
              {{
                storage.stagedReleasableBytes > 0
                  ? `${megabytes(storage.stagedReleasableBytes)} of it no longer needed`
                  : 'an update on record could still be recovered from them'
              }}
            </span>
          </li>
        </ul>
        <p class="hint">
          A package an installation is on is what its next update compares against, one an undo
          would put an installation back onto is what that undo needs, and a staged copy is what an
          update still on record would be recovered from — none of those is ever removed.
        </p>
      </details>
    </div>
  </section>
</template>

<style scoped>
.undo {
  display: flex;
  flex-direction: column;
  gap: var(--space-8);
  margin-top: var(--space-12);
  padding-top: var(--space-12);
  border-top: 1px solid var(--border);
}

/* Sized by its label, like every other button on this screen. Stretched across the pane it read
   as a banner rather than as the one consequential thing here, and it was the only button in the
   product that did. The hint below it still takes the full width, because that is prose. */
.undo > button {
  align-self: start;
}

.undo-actions {
  display: flex;
  gap: var(--space-8);
}

.hint.warn {
  color: var(--warning);
}

/* The palette's own green for "this went well". `--ok` was never a token, so this rendered a
   second, slightly different green that nothing else in the product uses. */
.hint.ok {
  color: var(--success);
}

/*
 * A column that scrolls, rather than a grid that apportions rows.
 *
 * As a grid the sections were rows sized against a container with a height of its own, and a row
 * could come out shorter than the section in it — which does not clip, it draws over whatever
 * follows. The kept-packages line was painted across the list of updates. Here each section keeps
 * its own content height and the page scrolls past them, which is the behaviour that was always
 * meant.
 */
.history {
  display: flex;
  flex-direction: column;
  gap: var(--space-16);
  width: min(100%, 900px);
  flex: 1;
  min-height: 0;
  min-width: 0;
  padding: var(--space-24);
  margin: 0 auto;
  overflow-y: auto;
}

/* Nothing here is squeezed to make the page fit: the page scrolls instead. */
.history > * {
  flex: none;
}

/* The one row that should grow. Without this every child is fixed, so a tall window put the
   whole screen in its top third and left the rest blank. */
.history > .panes {
  flex: 1;
}

.page h1 {
  margin: 0;
  font-size: var(--text-page-title);
  line-height: 1.2;
}

.lede {
  max-width: 68ch;
  margin: var(--space-8) 0 0;
  color: var(--text-muted);
  line-height: 1.55;
}

.state {
  display: flex;
  gap: var(--space-16);
  align-items: center;
  justify-content: space-between;
  border: 1px solid var(--border);
  border-left-width: 3px;
  border-radius: var(--radius-md);
  padding: var(--space-12) var(--space-16);
  background: var(--surface);
  font-weight: 600;
}

.state.ok {
  border-left-color: var(--success);
}

.state.warning {
  border-left-color: var(--warning);
}

.state.danger {
  border-left-color: var(--danger);
}

.state.muted {
  color: var(--text-muted);
  font-weight: 500;
}

.state-actions {
  display: flex;
  gap: var(--space-8);
  flex: none;
}

.hint {
  max-width: 68ch;
  margin: 0;
  color: var(--text-muted);
  font-size: 0.86rem;
  line-height: 1.5;
}

.hint.danger {
  color: var(--danger);
}

/* The two columns are separated by a rule that runs the height of the taller one, so the list
   and what it describes read as two places rather than one wrapped paragraph. */
.panes {
  display: grid;
  grid-template-columns: minmax(0, 240px) minmax(0, 1fr);
  align-items: stretch;
  min-height: 160px;
  /* Bounded, so the row this occupies cannot be sized by however many updates have been run. */
  min-width: 0;
  border-top: 1px solid var(--border);
  padding-top: var(--space-20);
}

/* Said in the same shape as the state line above it: one sentence, one action. */
.kept {
  border-top: 1px solid var(--border);
  padding-top: var(--space-16);
  color: var(--text-muted);
  font-size: 0.86rem;
}

.kept-line {
  display: flex;
  gap: var(--space-16);
  align-items: center;
  justify-content: space-between;
}

.kept-line strong {
  color: var(--text);
}

.kept-actions {
  display: flex;
  gap: var(--space-12);
  align-items: center;
  flex: none;
}

.kept .done {
  color: var(--success);
  font-weight: 600;
}

.kept summary {
  cursor: pointer;
  margin-top: var(--space-8);
  color: var(--text-muted);
  font-size: 0.8rem;
}

.kept-list {
  margin: var(--space-8) 0;
  padding: 0;
  list-style: none;
}

.kept-list li {
  display: flex;
  gap: var(--space-12);
  justify-content: space-between;
  padding: var(--space-4) 0;
  border-bottom: 1px solid var(--border);
}

.kept-list .name {
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.8rem;
}

.past {
  display: flex;
  flex-direction: column;
  min-height: 0;
  border-right: 1px solid var(--border);
  padding-right: var(--space-20);
}

.rail-title {
  margin: 0 0 var(--space-8);
  color: var(--text-muted);
  font-size: 0.78rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

/*
 * The one thing on this screen that grows without limit: an operator who has run forty updates has
 * forty rows here. Left unbounded it decided the height of the whole page, which pushed everything
 * below it — the kept-packages line included — off the end of a default-sized window.
 */
.past ul {
  display: grid;
  gap: var(--space-4);
  /* Takes the room the row has rather than a fixed twenty lines of it. */
  flex: 1;
  align-content: start;
  min-height: 0;
  overflow-y: auto;
  padding: 0;
  margin: 0;
  list-style: none;
}

.past button {
  display: grid;
  gap: 2px;
  width: 100%;
  border-color: transparent;
  padding: var(--space-8) var(--space-12);
  background: transparent;
  text-align: left;
}

.past button.current {
  border-color: var(--border);
  background: var(--surface);
}

.past .meta {
  color: var(--text-muted);
  font-size: 0.76rem;
}

.detail {
  min-height: 0;
  overflow-y: auto;
  display: grid;
  gap: var(--space-12);
  align-content: start;
  min-width: 0;
  padding-left: var(--space-20);
}

.detail h2 {
  margin: 0;
  font-family: var(--font-mono);
  font-size: var(--text-section);
}

.versions {
  margin: 0;
  color: var(--text);
  font-family: var(--font-mono);
  font-size: 0.92rem;
  font-weight: 620;
}

.recover {
  display: grid;
  gap: var(--space-12);
  align-content: start;
  border-top: 1px solid var(--border);
  padding-top: var(--space-16);
}

.recover h3 {
  margin: 0;
  font-size: 0.95rem;
}

.pad {
  padding: var(--space-8) var(--space-12);
}

@media (max-width: 900px) {
  .panes {
    grid-template-columns: 1fr;
    gap: var(--space-16);
  }

  /* Stacked, the rule belongs between them rather than beside them. */
  .past {
    border-right: 0;
    border-bottom: 1px solid var(--border);
    padding-right: 0;
    padding-bottom: var(--space-16);
  }

  .detail {
    padding-left: 0;
  }
}

/* The three steps read left to right in the order they are taken. */
.steps {
  display: flex;
  gap: var(--space-8);
  flex-wrap: wrap;
}

.resources {
  display: flex;
  gap: var(--space-8);
  flex-wrap: wrap;
  padding: 0;
  margin: 0;
  list-style: none;
}

.resources button {
  font-family: var(--font-mono);
  font-size: 0.84rem;
}

.resources button.current {
  border-color: var(--accent);
  color: var(--text);
}

.found {
  margin: 0;
  color: var(--text);
}

.candidates {
  display: grid;
  gap: var(--space-8);
  padding: 0;
  margin: 0;
  list-style: none;
}

.candidates li {
  display: flex;
  gap: var(--space-12);
  align-items: center;
  justify-content: space-between;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: var(--space-12) var(--space-16);
  background: var(--surface);
}

.name {
  font-family: var(--font-mono);
  font-size: 0.86rem;
}

.primary {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--on-accent);
  font-weight: 640;
}

.primary:disabled {
  border-color: var(--border);
  background: var(--surface-raised);
  color: var(--text-muted);
}</style>
