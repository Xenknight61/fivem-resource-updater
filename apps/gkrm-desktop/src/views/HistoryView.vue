<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue'

import LoadingState from '@/components/LoadingState.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusNotice from '@/components/StatusNotice.vue'
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
const historyError = ref<string>()
const search = ref('')
const filteredEntries = computed(() => {
  const query = search.value.trim().toLocaleLowerCase()
  return entries.value.filter((entry) =>
    `${entry.resource} ${versionMove(entry)} ${outcomeLabel[entry.outcome] ?? entry.outcome}`
      .toLocaleLowerCase().includes(query),
  )
})

watch(filteredEntries, (visible) => {
  if (!visible.some((entry) => keyOf(entry) === selected.value)) {
    selected.value = visible[0] === undefined ? undefined : keyOf(visible[0])
    confirmingUndo.value = false
    undone.value = undefined
    undoError.value = undefined
  }
})

function selectEntry(entry: UpdateHistoryEntry) {
  if (undoing.value || recovery.durableOperationInProgress) return
  selected.value = keyOf(entry)
  confirmingUndo.value = false
  undone.value = undefined
  undoError.value = undefined
}

async function navigateHistory(event: KeyboardEvent) {
  if (!(event.target instanceof HTMLButtonElement) || !event.target.matches('[data-history-entry]')) return
  if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  if (undoing.value || recovery.durableOperationInProgress) return
  const index = filteredEntries.value.findIndex((entry) => keyOf(entry) === selected.value)
  const next = event.key === 'Home' ? 0 : event.key === 'End' ? filteredEntries.value.length - 1
    : Math.max(0, Math.min(filteredEntries.value.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)))
  const entry = filteredEntries.value[next]
  if (entry === undefined) return
  const list = event.currentTarget
  selectEntry(entry)
  await nextTick()
  if (list instanceof HTMLElement) {
    list.querySelector<HTMLButtonElement>('[aria-current="true"]')?.focus()
  }
}

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
  historyError.value = undefined
  try {
    entries.value = (await updateHistoryList()).entries
    const first = entries.value[0]
    if (selected.value === undefined && first !== undefined) selected.value = keyOf(first)
  } catch (error) {
    historyError.value = asDesktopError(error).message
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
        year: 'numeric',
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
const undoPanel = ref<HTMLElement>()
const detailPanel = ref<HTMLElement>()
let undoTrigger: HTMLElement | undefined
let undoEntryKey: string | undefined
watch(confirmingUndo, async (open) => {
  if (open) {
    undoEntryKey = selected.value
    undoTrigger = document.activeElement instanceof HTMLElement ? document.activeElement : undefined
    await nextTick()
    undoPanel.value?.querySelector<HTMLButtonElement>('[data-cancel-undo]')?.focus()
  } else {
    await nextTick()
    if (selected.value === undoEntryKey) {
      if (undoTrigger?.isConnected) undoTrigger.focus()
      else detailPanel.value?.focus()
    }
    undoTrigger = undefined
    undoEntryKey = undefined
  }
})
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
    <PageHeader class="page" heading-id="history-heading" title="History" description="Review past updates, restore files, and manage what is kept.">
      <template #actions><a class="button-link" href="#/">New update</a></template>
    </PageHeader>

    <!-- The whole workspace in one line, and the one action it offers. -->
    <StatusNotice class="state" :tone="state.tone === 'danger' ? 'warning' : state.tone === 'warning' ? 'warning' : 'neutral'">
      <div class="workspace-state">
        <span class="state-label">Workspace</span>
        <span>{{ state.text }}</span>
      </div>
      <template #actions>
        <button
          v-if="recovery.canFinalizeTerminal"
          type="button"
          class="primary"
          @click="recovery.finalizeTerminal(true)"
        >
          Close previous update
        </button>
        <button type="button" :disabled="busy" @click="recovery.refreshOverview()">
          {{ busy ? 'Checking…' : 'Check again' }}
        </button>
      </template>
    </StatusNotice>
    <p v-if="recovery.canFinalizeTerminal" class="hint">
      Closing it lets the next update start. Its backups and journal are kept either way.
    </p>
    <p v-if="recovery.overviewPhase === 'error'" class="hint danger" role="alert">
      {{ recovery.overviewError?.message }}
    </p>

    <div class="panes">
      <!-- What you have already done. No folder to point at: the app did these. -->
      <nav class="past" aria-label="Updates you have run" @keydown="navigateHistory">
        <div class="list-toolbar">
          <p class="rail-title">Your updates <span>{{ entries.length }}</span></p>
          <label class="search-label" for="history-search">Find an update</label>
          <input
            id="history-search"
            v-model="search"
            type="search"
            placeholder="Resource, version, or outcome…"
            :disabled="undoing || recovery.durableOperationInProgress"
          />
        </div>
        <LoadingState v-if="loadingHistory" label="Reading your updates" />
        <div v-else-if="historyError" class="history-error pad" role="alert">
          <p class="hint danger">Could not read your updates. {{ historyError }}</p>
          <button type="button" @click="loadHistory()">Try again</button>
        </div>
        <p v-else-if="entries.length === 0" class="hint pad">
          Nothing yet. Updates you run appear here. <a class="text-link" href="#/">Start an update</a>
        </p>
        <p v-else-if="filteredEntries.length === 0" class="hint pad" role="status">
          No updates match “{{ search }}”. Try another resource, version, or outcome.
        </p>
        <ul v-else>
          <li v-for="entry in filteredEntries" :key="keyOf(entry)">
            <button
              type="button"
              data-history-entry
              :class="{ current: keyOf(entry) === selected }"
              :aria-current="keyOf(entry) === selected ? 'true' : undefined"
              :disabled="undoing || recovery.durableOperationInProgress"
              @click="selectEntry(entry)"
            >
              <span class="name">{{ entry.resource }}</span>
              <span :class="['entry-outcome', { attention: entry.outcome === 'recovery_required' }]">
                {{ outcomeLabel[entry.outcome] ?? entry.outcome }}
              </span>
              <span class="meta">
                <template v-if="versionMove(entry)">{{ versionMove(entry) }} · </template
                >{{ when(entry) }}
              </span>
            </button>
          </li>
        </ul>
      </nav>

      <article ref="detailPanel" class="detail" tabindex="-1" aria-label="Update details">
        <!-- Recovery is the one thing that needs the folder: it writes to the live installation
             and has to bind to it at the moment it runs. It appears only when there is something
             to recover. -->
        <section
          v-if="somethingToRecover"
          class="recover"
          aria-labelledby="recover-heading"
        >
          <p class="section-label">Needs attention</p>
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
              {{ recovery.recoveryHandle === undefined ? 'Inspect resource' : 'Inspect again' }}
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
        <template v-if="selectedEntry">
          <header class="detail-header">
            <p class="section-label">Update details</p>
            <h2>{{ selectedEntry.resource }}</h2>
            <p v-if="versionMove(selectedEntry)" class="versions">{{ versionMove(selectedEntry) }}</p>
            <p class="hint">{{ when(selectedEntry) }}</p>
            <span :class="['result-label', { attention: selectedEntry.outcome === 'recovery_required' }]">
              {{ outcomeLabel[selectedEntry.outcome] ?? selectedEntry.outcome }}
            </span>
          </header>
          <dl class="update-facts" aria-label="Files in this update">
            <div><dt>Total files</dt><dd>{{ selectedEntry.total }}</dd></div>
            <div><dt>You decided</dt><dd>{{ selectedEntry.reviewed }}</dd></div>
            <div><dt>Replaced</dt><dd>{{ selectedEntry.replaced }}</dd></div>
          </dl>

          <!-- Putting it back writes to the live installation, so it asks before it does. -->
          <div v-if="selectedEntry.undoable" class="undo">
            <h3>Restore the previous files</h3>
            <template v-if="!confirmingUndo">
              <p class="hint">
                Puts every file this update replaced back exactly as it was. Files you have changed
                since are left alone.
              </p>
              <button type="button" :disabled="!canUndo" @click="askToUndo()">Undo this update</button>
              <p v-if="!canUndo" class="hint">Resolve the workspace state above before restoring files.</p>
            </template>
            <div v-else ref="undoPanel" class="undo-confirm" role="group" aria-label="Confirm restoring files" @keydown.esc="!undoing && (confirmingUndo = false)">
              <p class="hint warn">
                This writes to {{ selectedEntry.resource }} in the folder you updated. Files you
                have edited since this update are left as you left them.
              </p>
              <div class="undo-actions">
                <button type="button" data-cancel-undo :disabled="undoing" @click="confirmingUndo = false">
                  Cancel
                </button>
                <button type="button" class="primary" :disabled="undoing || !canUndo" @click="confirmUndo()">
                  {{ undoing ? 'Putting it back…' : 'Yes, put it back' }}
                </button>
              </div>
            </div>
          </div>
          <p v-else-if="selectedEntry.outcome === 'committed'" class="hint">
            This one cannot be put back: there is no record of what it replaced.
          </p>
          <p v-if="undoneSummary" class="hint ok" role="status">{{ undoneSummary }}</p>
          <p v-if="undoError" class="hint danger" role="alert">{{ undoError }}</p>
        </template>
        <div v-else class="detail-empty">
          <template v-if="historyError">
            <h2>History is unavailable</h2>
            <p class="hint">Try reading your updates again using the button in the list.</p>
          </template>
          <template v-else-if="loadingHistory">
            <h2>Reading your updates…</h2>
          </template>
          <template v-else>
            <h2>{{ entries.length === 0 ? 'Your update history starts here' : 'Choose an update' }}</h2>
            <p class="hint">{{ entries.length === 0 ? 'After your first update, its result and available backups appear here.' : 'Select an update from the list to see its result and restoration options.' }}</p>
          </template>
        </div>


      </article>
    </div>

    <!--
      What updates keep, in the same shape as the state line above: one sentence and the one action
      it offers. The accounting is a disclosure rather than a list, because the only thing most
      operators want from it is the number.
    -->
    <div v-if="storage && totalHeld > 0" class="kept">
      <div class="kept-line">
        <div>
          <h2>Local storage</h2>
        <span class="storage-summary">
          <strong>{{ megabytes(totalHeld) }}</strong> left behind by past updates —
          <template v-if="totalReleasable > 0">
            {{ megabytes(totalReleasable) }} of it is no longer needed.
          </template>
          <template v-else>all of it is still in use.</template>
        </span>
        </div>
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
.history {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
  overflow-y: auto;
}

.history > * {
  flex: none;
}

.workspace-state {
  display: flex;
  align-items: baseline;
  gap: var(--space-16);
}

.state-label {
  color: var(--text-muted);
  font-size: 0.78rem;
}

.history > .hint {
  padding: var(--space-8) var(--space-24);
  border-bottom: 1px solid var(--border);
  max-width: none;
}

.hint {
  max-width: 68ch;
  margin: 0;
  color: var(--text-muted);
  font-size: 0.84rem;
  line-height: 1.6;
}

.hint.danger {
  color: var(--danger);
}

.hint.warn {
  color: var(--warning);
}

.hint.ok {
  color: var(--success);
}

.panes {
  display: grid;
  grid-template-columns: minmax(260px, 28%) minmax(0, 1fr);
  flex: 1 0 auto;
  min-height: 300px;
  min-width: 0;
}

.past {
  display: flex;
  flex-direction: column;
  min-height: 0;
  min-width: 0;
  border-right: 1px solid var(--border);
  background: var(--surface);
}

.list-toolbar {
  display: grid;
  gap: var(--space-8);
  padding: var(--space-16);
  border-bottom: 1px solid var(--border);
}

.rail-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: 0;
  font-size: 0.8rem;
  font-weight: 600;
}

.rail-title span {
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}

.search-label {
  color: var(--text-muted);
  font-size: 0.76rem;
}

#history-search {
  width: 100%;
  min-width: 0;
  padding: var(--space-8);
  border: 1px solid var(--control-border);
  border-radius: var(--radius-md);
  background: var(--background);
  color: var(--text);
  font-size: 0.8rem;
}

#history-search::placeholder {
  color: var(--text-muted);
}

.history-error {
  display: grid;
  gap: var(--space-12);
}

.history-error button {
  justify-self: start;
}

.past ul {
  display: grid;
  gap: 2px;
  align-content: start;
  flex: 1;
  min-height: 0;
  max-height: 60vh;
  overflow-y: auto;
  padding: var(--space-8);
  margin: 0;
  list-style: none;
}

.past button {
  display: grid;
  gap: var(--space-4);
  width: 100%;
  min-width: 0;
  border: 1px solid transparent;
  padding: var(--space-12);
  background: transparent;
  text-align: left;
}

.past button:hover {
  background: var(--surface-raised);
}

.past button.current {
  border-color: var(--border);
  background: var(--surface-raised);
}

.past .name {
  overflow-wrap: anywhere;
}

.meta {
  color: var(--text-muted);
  font-size: 0.76rem;
  line-height: 1.5;
}

.entry-outcome {
  color: var(--text-muted);
  font-size: 0.76rem;
}

.attention {
  color: var(--warning);
}

.detail {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: var(--space-24);
  min-width: 0;
  padding: var(--space-24) var(--space-32);
}

.detail:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: -2px;
}

.detail-header {
  display: grid;
  gap: var(--space-8);
}

.section-label {
  margin: 0;
  color: var(--text-muted);
  font-size: 0.76rem;
}

.detail h2 {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 1.2rem;
  overflow-wrap: anywhere;
}

.detail h3, .kept h2 {
  margin: 0;
  font-size: var(--text-section);
  font-weight: 600;
}

.versions {
  margin: 0;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 0.86rem;
}

.result-label {
  justify-self: start;
  padding: var(--space-4) var(--space-8);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--surface);
  font-size: 0.78rem;
}

.update-facts {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-24);
  margin: 0;
  padding: var(--space-16) 0;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}

.update-facts div {
  display: grid;
  gap: var(--space-8);
  min-width: 80px;
}

.update-facts dt {
  color: var(--text-muted);
  font-size: 0.78rem;
}

.update-facts dd {
  margin: 0;
  font-size: 1.1rem;
  font-variant-numeric: tabular-nums;
}

.undo {
  display: grid;
  justify-items: start;
  gap: var(--space-12);
}

.undo > button {
  margin-top: var(--space-4);
  font-size: 0.84rem;
}

.undo-confirm {
  display: grid;
  gap: var(--space-16);
  width: 100%;
  padding: var(--space-16);
  border: 1px solid var(--border);
  border-left: 3px solid var(--warning);
  border-radius: var(--radius-md);
  background: var(--surface);
}

.undo-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: var(--space-8);
}

.detail-empty {
  display: grid;
  align-content: center;
  gap: var(--space-12);
  min-height: 220px;
}

.detail-empty h2 {
  font-family: inherit;
  font-size: var(--text-section);
}

.recover {
  display: grid;
  gap: var(--space-12);
  align-content: start;
  padding-bottom: var(--space-24);
  border-bottom: 1px solid var(--border);
}

.steps, .resources {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-8);
}

.resources {
  list-style: none;
  padding: 0;
  margin: 0;
}

.resources button {
  font-family: var(--font-mono);
  font-size: 0.84rem;
}

.resources button.current {
  border-color: var(--control-border);
  background: var(--surface-raised);
}

.found {
  margin: 0;
  color: var(--text);
  font-size: 0.86rem;
  line-height: 1.5;
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
  align-items: center;
  justify-content: space-between;
  gap: var(--space-12);
  padding: var(--space-12);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--surface);
}

.name {
  font-family: var(--font-mono);
  font-size: 0.86rem;
}

.kept {
  padding: var(--space-16) var(--space-24);
  border-top: 1px solid var(--border);
  background: var(--surface);
  color: var(--text-muted);
  font-size: 0.82rem;
}

.kept-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-16);
}

.kept h2 {
  color: var(--text);
  font-size: 0.86rem;
  margin-bottom: var(--space-8);
}

.storage-summary {
  line-height: 1.5;
}

.kept-line strong {
  color: var(--text);
  font-weight: 600;
}

.kept-actions {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: var(--space-8);
  align-items: center;
  flex: none;
}

.kept-actions button {
  font-size: 0.8rem;
}

.kept .done {
  color: var(--success);
}

.kept summary {
  cursor: pointer;
  margin-top: var(--space-12);
  font-size: 0.78rem;
}

.kept summary:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 3px;
}

.kept-list {
  list-style: none;
  padding: 0;
  margin: var(--space-12) 0;
}

.kept-list li {
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: var(--space-8) var(--space-16);
  padding: var(--space-8) 0;
  border-bottom: 1px solid var(--border);
}

.kept-list .name {
  color: var(--text);
  font-size: 0.8rem;
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
}

.pad {
  padding: var(--space-16);
}

@media (max-width: 900px) {
  .page {
    padding: var(--space-16);
  }
  .state {
    padding: var(--space-12) var(--space-16);
  }
  .workspace-state {
    display: grid;
    gap: var(--space-4);
  }
  .detail {
    padding: var(--space-24) var(--space-20);
  }
  .kept {
    padding: var(--space-16);
  }
  .kept-line {
    align-items: flex-start;
  }
}
</style>
