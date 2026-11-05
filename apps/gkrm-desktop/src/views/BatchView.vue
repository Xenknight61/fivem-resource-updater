<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { useRouter } from 'vue-router'

import ActionBar from '@/components/ActionBar.vue'
import Disclosure from '@/components/Disclosure.vue'
import PageHeader from '@/components/PageHeader.vue'
import StatusNotice from '@/components/StatusNotice.vue'
import { useBatchStore } from '@/stores/batch'
import { useUpdateStore } from '@/stores/update'
import type { BatchApplyResultKind, BatchEntry } from '@/types/commands'
import { presentManifestChanges } from '@/views/manifestPresentation'

const batch = useBatchStore()
const update = useUpdateStore()
const router = useRouter()

const applied = computed(() => batch.results !== undefined)

/** One short sentence for why a row is not simply ready. */
function reasonFor(entry: BatchEntry): string | undefined {
  switch (entry.kind) {
    case 'needs_review': {
      const files = entry.review + entry.unmergeable
      return `${files} ${files === 1 ? 'file was' : 'files were'} changed by both you and the developer.`
    }
    case 'no_installed_resource':
      return 'Not installed.'
    case 'duplicate_package':
      return 'Two packages in this folder are for this resource. Remove one and compare again.'
    case 'not_a_single_resource':
      return 'This package does not hold exactly one resource.'
    case 'blocked_by_earlier_update':
      return 'An earlier update to this resource is still open. Close it first.'
    case 'unreadable':
      return 'This package could not be read.'
    default:
      return undefined
  }
}

/** The package's file name is shown only where the resource name alone would not say which row. */
function showsPackage(entry: BatchEntry): boolean {
  return entry.resource === undefined || reasonFor(entry) !== undefined
}

function nameOf(entry: BatchEntry): string {
  return entry.resource ?? entry.packageName
}

function versionMove(entry: BatchEntry): string {
  // A missing version leaves the cell empty: a wrong label is worse than none.
  if (entry.installedVersion === undefined || entry.incomingVersion === undefined) return ''
  return `${entry.installedVersion} → ${entry.incomingVersion}`
}

interface Badge {
  label: string
  tone: 'ready' | 'warning' | 'blocked' | 'quiet'
}

function badgeFor(entry: BatchEntry): Badge {
  const result: BatchApplyResultKind | undefined = batch.results?.[entry.id]
  if (result === 'committed') return { label: 'Updated', tone: 'ready' }
  if (result === 'failed') return { label: 'Failed', tone: 'blocked' }
  if (result === 'not_attempted') return { label: 'Not attempted', tone: 'quiet' }
  switch (entry.kind) {
    case 'ready':
      return { label: 'Ready', tone: 'ready' }
    case 'needs_review':
      return { label: 'Needs review', tone: 'warning' }
    case 'up_to_date':
      return { label: 'Up to date', tone: 'quiet' }
    default:
      return { label: "Can't update", tone: 'blocked' }
  }
}

function resultFor(entry: BatchEntry): BatchApplyResultKind | undefined {
  return batch.results?.[entry.id]
}

async function review(entry: BatchEntry) {
  if (await batch.openForReview(entry.id)) {
    await router.push('/')
    // Both sides are already chosen; comparing only reads.
    await update.compare()
  }
}

const countLine = computed(() => {
  const plan = batch.plan
  if (plan === undefined) return ''
  const count = (kinds: string[]) => plan.entries.filter((entry) => kinds.includes(entry.kind)).length
  const parts: string[] = []
  if (applied.value) {
    parts.push(`${batch.results ? Object.values(batch.results).filter((r) => r === 'committed').length : 0} updated`)
  } else {
    const ready = count(['ready'])
    if (ready > 0) parts.push(`${ready} ready`)
  }
  const review = count(['needs_review'])
  if (review > 0) parts.push(`${review} ${review === 1 ? 'needs' : 'need'} review`)
  const blocked = count([
    'no_installed_resource',
    'duplicate_package',
    'not_a_single_resource',
    'blocked_by_earlier_update',
    'unreadable',
  ])
  if (blocked > 0) parts.push(`${blocked} can't be updated`)
  const current = count(['up_to_date'])
  if (current > 0) parts.push(`${current} up to date`)
  return parts.length > 0 ? parts.join(' · ') : 'No packages found in that folder.'
})

const setupStatus = computed(() => {
  if (batch.loading.compare) return 'Comparing every package with your installation…'
  if (batch.installed === undefined) return 'Choose your resources folder to begin.'
  if (batch.packages === undefined) return 'Choose the folder with your update packages.'
  return 'Ready to compare. Your installation stays unchanged.'
})

const failedEntry = computed(() =>
  batch.plan?.entries.find((entry) => batch.results?.[entry.id] === 'failed'),
)

const updatedCount = computed(() =>
  batch.results === undefined
    ? 0
    : Object.values(batch.results).filter((result) => result === 'committed').length,
)

const applyLabel = computed(() => {
  if (batch.loading.apply) return 'Updating…'
  const count = batch.plan?.readyCount ?? 0
  return `Update ${count} ${count === 1 ? 'resource' : 'resources'}`
})

const confirmation = ref<HTMLElement>()
let returnFocus: HTMLElement | undefined
watch(
  () => batch.confirming,
  async (open) => {
    if (open) {
      returnFocus = document.activeElement instanceof HTMLElement ? document.activeElement : undefined
      await nextTick()
      confirmation.value?.querySelector<HTMLButtonElement>('button')?.focus()
    } else {
      returnFocus?.focus()
      returnFocus = undefined
    }
  },
)
onBeforeUnmount(() => returnFocus?.focus())
function confirmationKey(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.preventDefault()
    batch.cancelApply()
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
</script>

<template>
  <section class="batch" aria-labelledby="batch-heading">
    <PageHeader
      heading-id="batch-heading"
      title="Update several resources"
      description="Choose your installation and a folder of packages. Resources that need no answer are updated together. The rest wait for you."
    >
      <template #actions>
        <span class="header-actions">
          <a class="button-link" href="#/">Update one resource</a>
          <a class="button-link" href="#/history">View history</a>
        </span>
      </template>
    </PageHeader>

    <StatusNotice v-if="batch.error" tone="danger">
      {{ batch.error.message }}
      <template #actions>
        <button type="button" @click="batch.dismissError()">Dismiss</button>
      </template>
    </StatusNotice>

    <StatusNotice
      v-if="batch.plan && batch.blocked === 'finishable'"
      :tone="applied ? 'neutral' : 'warning'"
    >
      <template v-if="applied">
        These updates are finished but still open. Close them when you are ready to update or
        review anything else.
      </template>
      <template v-else>
        An earlier update is finished but still open, so the resources it touched cannot be
        updated yet.
      </template>
      <template #actions>
        <button type="button" :disabled="!batch.canChooseSources" @click="batch.finishPreviousUpdates()">
          Close finished updates
        </button>
      </template>
    </StatusNotice>
    <StatusNotice v-else-if="batch.plan && batch.blocked === 'attention'" tone="warning">
      An earlier update needs attention before anything new can be written.
      <template #actions><a class="button-link" href="#/history">Open History</a></template>
    </StatusNotice>

    <StatusNotice v-if="applied && batch.stopped" tone="danger">
      The batch stopped at {{ failedEntry ? nameOf(failedEntry) : 'one resource' }}. Resources after
      it were not tried. {{ updatedCount }} {{ updatedCount === 1 ? 'resource was' : 'resources were' }}
      updated before it.
    </StatusNotice>
    <StatusNotice v-else-if="applied" tone="success">
      {{ updatedCount }} {{ updatedCount === 1 ? 'resource' : 'resources' }} updated. Every file was
      backed up first.
    </StatusNotice>

    <!-- Before a comparison: the two things the operator has. -->
    <div v-if="!batch.plan" class="sources">
      <button
        type="button"
        class="source"
        :disabled="batch.loading.installed || !batch.canChooseSources"
        @click="batch.chooseInstalled()"
      >
        <span class="source-copy">
          <span class="step">1. Installed resources</span>
          <span class="source-hint">The folder that holds your resources on the server.</span>
        </span>
        <span class="value">{{ batch.installed?.displayLabel ?? 'Choose folder…' }}</span>
      </button>
      <button
        type="button"
        class="source"
        :disabled="!batch.canChoosePackages || batch.loading.packages"
        @click="batch.choosePackages()"
      >
        <span class="source-copy">
          <span class="step">2. Update packages</span>
          <span class="source-hint">The folder with the ZIPs you downloaded.</span>
        </span>
        <span class="value">
          {{ batch.packages?.displayLabel ?? (batch.canChoosePackages ? 'Choose folder…' : 'Choose the resources first') }}
        </span>
      </button>
    </div>
    <p v-else class="source-line">{{ batch.installed?.displayLabel }} · {{ batch.packages?.displayLabel }}</p>

    <!-- The list is the only region that scrolls. -->
    <div v-if="batch.plan" class="list">
      <p v-if="batch.plan.entries.length === 0" class="empty">
        There are no ZIP packages in that folder.
      </p>
      <section
        v-for="group in batch.groups"
        :key="group.key"
        class="group"
        :aria-labelledby="`group-${group.key}`"
      >
        <component :is="group.key === 'current' ? 'details' : 'div'" class="group-body">
          <component
            :is="group.key === 'current' ? 'summary' : 'h2'"
            :id="`group-${group.key}`"
            class="group-header"
          >
            {{ group.label }} <span class="count">{{ group.entries.length }}</span>
          </component>
          <ul class="rows">
            <li v-for="entry in group.entries" :key="entry.id" class="row">
              <div class="row-main">
                <span class="name">{{ nameOf(entry) }}</span>
                <span v-if="showsPackage(entry) && entry.resource !== undefined" class="secondary">
                  <span class="package">{{ entry.packageName }}</span>
                  <template v-if="reasonFor(entry)"> · {{ reasonFor(entry) }}</template>
                </span>
                <span v-else-if="reasonFor(entry)" class="secondary">{{ reasonFor(entry) }}</span>
              </div>
              <span class="versions">{{ versionMove(entry) }}</span>
              <span class="state">
                <span
                  class="status-badge"
                  :class="{
                    'status--ready': badgeFor(entry).tone === 'ready',
                    'status--warning': badgeFor(entry).tone === 'warning',
                    'status--blocked': badgeFor(entry).tone === 'blocked',
                  }"
                >
                  <span class="sr-only">{{ badgeFor(entry).label }}: </span>{{ badgeFor(entry).label }}
                </span>
              </span>
              <div
                v-if="
                  entry.kind === 'needs_review' ||
                  resultFor(entry) === 'committed' ||
                  resultFor(entry) === 'failed' ||
                  resultFor(entry) === 'not_attempted' ||
                  presentManifestChanges(entry.manifestChanges)
                "
                class="row-extra"
              >
                <a
                  v-if="entry.kind === 'needs_review'"
                  class="text-link"
                  href="#/"
                  @click.prevent="review(entry)"
                  >Review in Update</a
                >
                <a v-if="resultFor(entry) === 'committed'" class="text-link" href="#/history"
                  >View in History</a
                >
                <span v-if="resultFor(entry) === 'failed'" class="secondary">
                  This update did not finish. Open History to check this resource.
                </span>
                <span v-if="resultFor(entry) === 'not_attempted'" class="secondary">
                  An earlier update failed.
                </span>
                <Disclosure
                  v-if="presentManifestChanges(entry.manifestChanges)"
                  class="manifest-changes"
                  :label="presentManifestChanges(entry.manifestChanges)!.label"
                >
                  <p v-if="presentManifestChanges(entry.manifestChanges)!.fx" class="secondary">
                    fx_version: {{ presentManifestChanges(entry.manifestChanges)!.fx }}
                  </p>
                  <div
                    v-for="changed in presentManifestChanges(entry.manifestChanges)!.groups"
                    :key="changed.kind"
                    class="manifest-group"
                  >
                    <strong>{{ changed.label }}</strong>
                    <ul>
                      <li v-for="added in changed.added" :key="`+${added}`">
                        <span class="sr-only">Added </span>+ {{ added }}
                      </li>
                      <li v-for="removed in changed.removed" :key="`-${removed}`">
                        <span class="sr-only">Removed </span>− {{ removed }}
                      </li>
                    </ul>
                  </div>
                </Disclosure>
              </div>
            </li>
          </ul>
        </component>
      </section>
    </div>
    <div v-else class="list list--setup" aria-hidden="true" />

    <ActionBar v-if="!batch.plan">
      <p class="status" role="status">{{ setupStatus }}</p>
      <p class="assurance">
        Nothing is written until you review and confirm. Every replaced file is backed up first.
      </p>
      <template #actions>
        <button type="button" class="primary" :disabled="!batch.canCompare" @click="batch.compare()">
          {{ batch.loading.compare ? 'Comparing…' : 'Compare' }}
        </button>
      </template>
    </ActionBar>
    <ActionBar v-else>
      <p class="status" role="status">{{ countLine }}</p>
      <p v-if="batch.blockedByEarlierUpdate && !applied" class="blocked-hint" role="status">
        {{
          batch.blocked === 'finishable'
            ? 'Close the finished update above before updating.'
            : 'An earlier update needs attention before anything new can be updated.'
        }}
      </p>
      <template #actions>
        <button type="button" :disabled="!batch.canChooseSources" @click="batch.changeSources()">
          Change sources
        </button>
        <button
          v-if="!applied"
          type="button"
          class="primary"
          :disabled="!batch.canApply"
          @click="batch.requestApply()"
        >
          {{ applyLabel }}
        </button>
      </template>
    </ActionBar>

    <!-- Review what will be written before anything is. Back writes nothing. -->
    <div
      v-if="batch.confirming"
      ref="confirmation"
      class="confirm-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="batch-confirm-heading"
      @keydown="confirmationKey"
    >
      <article class="confirm">
        <h2 id="batch-confirm-heading">{{ applyLabel }}?</h2>
        <p>
          Each one takes what the developer changed and keeps what you edited. Resources that need
          an answer are left alone.
        </p>
        <ul class="confirm-files">
          <li v-for="entry in batch.readyEntries" :key="entry.id">
            {{ nameOf(entry) }}
            <span v-if="versionMove(entry)" class="confirm-version">{{ versionMove(entry) }}</span>
          </li>
        </ul>
        <p>Every file is backed up first, and History → Undo puts each update back byte for byte.</p>
        <div class="confirm-actions">
          <button type="button" @click="batch.cancelApply()">Back — nothing is written</button>
          <button type="button" class="primary" @click="batch.apply()">{{ applyLabel }}</button>
        </div>
      </article>
    </div>
  </section>
</template>

<style scoped>
.batch {
  display: flex;
  position: relative;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  min-width: 0;
  background: var(--background);
}

.header-actions {
  display: flex;
  gap: var(--space-8);
}

.source-line {
  margin: 0;
  padding: var(--space-8) var(--space-24);
  color: var(--text-muted);
  font-size: var(--text-caption);
}

.sources {
  display: grid;
  width: min(880px, calc(100% - 48px));
  margin: var(--space-24) auto 0;
}

.source {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(200px, 40%);
  gap: var(--space-24);
  align-items: center;
  padding: var(--space-20) 0;
  border: 0;
  border-bottom: 1px solid var(--border);
  border-radius: 0;
  background: transparent;
  text-align: left;
}

.source:disabled {
  opacity: 1;
}

.source-copy {
  display: grid;
  gap: var(--space-8);
  min-width: 0;
}

.step {
  font-size: var(--text-body);
  font-weight: 620;
}

.source-hint {
  color: var(--text-muted);
  font-size: var(--text-caption);
  line-height: 1.5;
}

.value {
  display: block;
  border: 1px solid var(--control-border);
  border-radius: var(--radius-md);
  padding: var(--space-12);
  background: var(--surface);
  font-size: var(--text-body);
}

.source:disabled .value {
  opacity: 0.5;
}

.source:not(:disabled):hover .value {
  background: var(--surface-raised);
}

.list {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  padding: var(--space-8) var(--space-16) var(--space-16);
  background: var(--surface);
}

.list--setup {
  background: transparent;
}

.empty {
  margin: var(--space-16);
  color: var(--text-muted);
}

.group + .group {
  margin-top: var(--space-16);
}

.group-header {
  display: block;
  margin: 0;
  padding: var(--space-12) var(--space-16) var(--space-8);
  color: var(--text-muted);
  font-size: var(--text-caption);
  font-weight: 620;
  cursor: default;
}

summary.group-header {
  cursor: pointer;
}

.group-header:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}

.count {
  font-weight: 400;
}

.rows {
  margin: 0;
  padding: 0;
  list-style: none;
}

.row {
  display: grid;
  /* Fixed tracks, so versions and badges form columns down the whole list rather than per row. */
  grid-template-columns: minmax(0, 1fr) 16ch 18ch;
  column-gap: var(--space-16);
  align-items: center;
  padding: var(--space-8) var(--space-16);
}

@media (prefers-reduced-motion: no-preference) {
  .row {
    transition: background-color var(--motion-fast);
  }
}

.row:hover {
  background: var(--surface-raised);
}

.row-main {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
}

.name {
  overflow: hidden;
  font-size: var(--text-body);
  font-weight: 620;
  line-height: 1.5;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.secondary {
  color: var(--text-muted);
  font-size: var(--text-caption);
  line-height: 1.5;
}

.package {
  font-family: var(--font-mono);
  font-size: var(--text-code);
}

.versions {
  font-family: var(--font-mono);
  font-size: var(--text-code);
  font-weight: 620;
  text-align: right;
}

.state {
  display: flex;
  justify-content: flex-end;
}

.row-extra {
  display: flex;
  grid-column: 1 / -1;
  flex-wrap: wrap;
  gap: var(--space-4) var(--space-16);
  align-items: center;
  padding-top: var(--space-4);
  font-size: var(--text-caption);
}

.row-extra :deep(.disclosure) {
  flex-basis: 100%;
}

.manifest-group ul {
  margin: var(--space-4) 0 var(--space-12);
  padding-left: var(--space-16);
  font-family: var(--font-mono);
  font-size: var(--text-caption);
  list-style: none;
}

.status {
  margin: 0;
  font-size: var(--text-body);
}

.blocked-hint {
  margin: 0;
  color: var(--warning);
  font-size: var(--text-caption);
}

.assurance {
  margin: 0;
  color: var(--text-muted);
  font-size: var(--text-caption);
}

.primary {
  border-color: var(--accent);
  background: var(--accent);
  color: var(--on-accent);
  font-weight: 660;
}

.primary:disabled {
  border-color: var(--border);
  background: var(--surface-raised);
  color: var(--text-muted);
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
  border-radius: var(--radius-lg);
  padding: var(--space-20);
  background: var(--surface-raised);
}

.confirm h2 {
  margin: 0;
  font-size: var(--text-section);
}

.confirm p {
  margin: 0;
  color: var(--text-muted);
  font-size: var(--text-body);
}

.confirm-files {
  overflow-y: auto;
  margin: 0;
  padding: var(--space-8) var(--space-8) var(--space-8) var(--space-24);
  background: var(--surface);
  border-radius: var(--radius-md);
  font-family: var(--font-mono);
  font-size: var(--text-code);
}

.confirm-version {
  margin-left: var(--space-8);
  color: var(--text-muted);
}

.confirm-actions {
  display: flex;
  gap: var(--space-8);
  justify-content: flex-end;
}

@media (max-width: 900px) {
  .source-line {
    padding: var(--space-8) var(--space-16);
  }
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
}
</style>
