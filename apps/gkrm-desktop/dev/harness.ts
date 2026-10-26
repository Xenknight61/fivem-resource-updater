/**
 * A development harness for looking at the real interface without a Tauri backend.
 *
 * It mounts the actual application with `mockIPC`, so every component, style and store is the one
 * that ships; only the answers from the backend are stood in for. That makes the screens
 * reviewable — layout, spacing, hierarchy, state feedback — and screenshottable in a plain
 * browser. It is not a test and proves nothing about the backend.
 *
 * Never part of a production build: Vite builds `index.html` alone, and this lives outside it.
 *
 *   npm run dev:harness      then open /dev/harness.html?state=<name>
 */
import { mockIPC } from '@tauri-apps/api/mocks'
import { createPinia } from 'pinia'
import { createApp } from 'vue'

import App from '@/App.vue'
import { router } from '@/router'
import '@/styles/tokens.css'
import '@/styles/base.css'

const FOLDER = '123e4567-e89b-42d3-a456-426614174000'
const PACKAGE = '123e4567-e89b-42d3-a456-426614174001'
const PREVIEW = '123e4567-e89b-42d3-a456-426614174002'

const preview = {
  handle: PREVIEW,
  resource: 'gksphone',
  installedVersion: '1.0.0',
  incomingVersion: '2.0.0',
  summary: { unchanged: 1, takeFromUpdate: 3, review: 2, keepLocalOnly: 1, total: 7 },
  files: [
    { path: 'config.lua', disposition: 'review', editable: true, untouched: false, mergedByKey: false, blockCount: 2 },
    { path: 'client/custom.lua', disposition: 'review', editable: true, untouched: false, mergedByKey: false, blockCount: 1 },
    { path: 'client/main.lua', disposition: 'take_from_update', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'client/new_feature.lua', disposition: 'take_from_update', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'fxmanifest.lua', disposition: 'take_from_update', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'data/customer_notes.txt', disposition: 'keep_local_only', editable: true, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'server/main.lua', disposition: 'unchanged', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
  ],
  omittedFileCount: 0,
  unmergeable: [],
  usedRememberedBaseline: false,
}

const diff = {
  available: true,
  truncated: false,
  omitted: false,
  blockCount: 2,
  defaultChoices: [false, true],
  rows: [
    { kind: 'context', text: 'Config = {}', truncated: false },
    { kind: 'context', text: '', truncated: false },
    { kind: 'yours', block: 0, text: "Config.Locale = 'tr'", truncated: false },
    { kind: 'theirs', block: 0, text: "Config.Locale = 'en'", truncated: false },
    { kind: 'context', text: "Config.Currency = 'USD'", truncated: false },
    { kind: 'yours', block: 1, text: 'Config.MaxContacts = 250', truncated: false },
    { kind: 'theirs', block: 1, text: 'Config.MaxContacts = 100', truncated: false },
    { kind: 'context', text: 'Config.EnableDebug = false', truncated: false },
    { kind: 'theirs', block: 1, text: 'Config.EnableVoiceMail = true', truncated: false },
  ],
}

const clearOverview = {
  disposition: 'clear',
  activeRecovery: false,
  terminalEvidence: false,
  manualAttention: false,
  unsupportedEvidence: false,
}

const historyEntries = [
  {
    id: '123e4567-e89b-42d3-a456-426614174010',
    resource: 'gksphone',
    outcome: 'committed',
    appliedAtMs: 1_700_000_000_000,
    reviewed: 2,
    replaced: 3,
    total: 7,
    fromVersion: '1.0.0',
    toVersion: '2.0.0',
    undoable: true,
  },
  {
    id: 'recovered-9f2c4a1b8e7d6c5a4b3f2e1d0c9b8a76',
    resource: 'gks-tablet',
    outcome: 'committed',
    appliedAtMs: 0,
    reviewed: 1,
    replaced: 12,
    total: 48,
    undoable: true,
  },
  {
    id: '123e4567-e89b-42d3-a456-426614174011',
    resource: 'gks-banking',
    outcome: 'undone_partial',
    appliedAtMs: 1_690_000_000_000,
    reviewed: 4,
    replaced: 31,
    total: 96,
    fromVersion: '3.1.0',
    toVersion: '3.2.0',
    undoable: false,
  },
]

const storage = {
  baselines: [
    { resource: 'gksphone', version: '2.0.0', bytes: 28 * 1024 * 1024, neededFor: 'installation' },
    { resource: 'gksphone', version: '1.0.0', bytes: 16 * 1024 * 1024, neededFor: 'undo' },
    // No `neededFor`: nothing reaches for this one, which is what makes it releasable.
    { resource: 'gks-tablet', version: '0.9.4', bytes: 12 * 1024 * 1024 },
  ],
  heldBytes: 56 * 1024 * 1024,
  releasableBytes: 12 * 1024 * 1024,
  stagedCount: 2,
  stagedBytes: 40 * 1024 * 1024,
  stagedReleasableBytes: 20 * 1024 * 1024,
}

const answers: Record<string, unknown> = {
  app_get_info: {
    schemaVersion: 1,
    appVersion: '1.0.0',
    coreVersion: '1.0.0',
    platform: 'windows',
    buildProfile: 'debug',
  },
  select_installed_root: {
    cancelled: false,
    selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' },
  },
  select_package_file: {
    cancelled: false,
    selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'gksphone-update.zip' },
  },
  session_list_selections: { selections: [] },
  session_release_selection: { released: true },
  update_recovery_overview: clearOverview,
  update_two_way_preview: preview,
  update_two_way_get_diff: diff,
  update_two_way_apply: { outcome: 'committed', summary: preview.summary },
  update_two_way_release: { released: true },
  update_history_list: { entries: historyEntries },
  storage_report: storage,
}

mockIPC(async (command) => {
  const answer = answers[command]
  if (answer === undefined) {
    // Loud on purpose: a screen reaching for something the harness does not answer should be
    // obvious in the console rather than silently rendering an error state.
    console.warn(`[harness] no answer for ${command}`)
    throw { code: 'internal', category: 'internal', message: command, recoverable: false }
  }
  return answer
})

const pinia = createPinia()
const app = createApp(App)
app.use(pinia)
app.use(router)
app.mount('#app')

/** Put the app into the state named by `?state=`, so each screen can be looked at directly. */
async function arrange() {
  const state = new URLSearchParams(window.location.search).get('state') ?? 'start'
  await router.isReady()

  if (state === 'about') {
    await router.push('/about')
    return
  }
  if (state === 'history') {
    await router.push('/history')
    return
  }

  await router.push('/')
  if (state === 'start') return

  const { useUpdateStore } = await import('@/stores/update')
  const update = useUpdateStore(pinia)
  await update.chooseFolder()
  await update.choosePackage()
  if (state === 'sources') return

  await update.compare()
  if (state === 'compared') return

  if (state === 'kept') {
    update.setFileChoice('config.lua', false)
    update.setFileChoice('client/custom.lua', false)
    return
  }
  if (state === 'confirming') {
    update.setFileChoice('config.lua', false)
    await update.requestApply()
    return
  }
  if (state === 'applied') {
    await update.apply()
    return
  }
}

void arrange().catch((error) => console.error('[harness] arrange failed', error))
