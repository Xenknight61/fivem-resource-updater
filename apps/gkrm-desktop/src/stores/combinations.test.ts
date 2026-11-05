import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { useBatchStore } from '@/stores/batch'
import { useRecoveryStore } from '@/stores/recovery'
import { useUpdateStore } from '@/stores/update'

/**
 * Every state the workspace can be in when the operator presses the button that writes, on both
 * screens, reached both ways.
 *
 * The rule is the one that was broken twice: a press either writes or leaves the screen saying why
 * it did not. It never does nothing. Writing is only ever allowed when the workspace is clear.
 */

const INSTALLED = '123e4567-e89b-42d3-a456-426614174000'
const PACKAGE = '123e4567-e89b-42d3-a456-426614174001'
const PACKAGES = '123e4567-e89b-42d3-a456-426614174002'
const PREVIEW = '123e4567-e89b-42d3-a456-426614174003'
const PLAN = '123e4567-e89b-42d3-a456-426614174004'

const preview = {
  handle: PREVIEW,
  resource: 'gksphone',
  installedVersion: '1.0.0',
  incomingVersion: '2.0.0',
  summary: { unchanged: 1, takeFromUpdate: 1, review: 0, keepLocalOnly: 0, total: 2 },
  files: [
    { path: 'client/main.lua', disposition: 'take_from_update', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'server/main.lua', disposition: 'unchanged', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
  ],
  omittedFileCount: 0,
  unmergeable: [],
  usedRememberedBaseline: false,
}

const plan = {
  handle: PLAN,
  readyCount: 1,
  entries: [
    { id: 0, packageName: 'a.zip', resource: 'a', kind: 'ready', review: 0, unmergeable: 0 },
  ],
}

const clear = {
  disposition: 'clear',
  activeRecovery: false,
  terminalEvidence: false,
  manualAttention: false,
  unsupportedEvidence: false,
}

/** Every way the workspace's durable state can read, and what the screen should call it. */
const STATES: Array<{
  name: string
  overview: Record<string, unknown> | 'fails'
  blocked: 'none' | 'finishable' | 'attention'
}> = [
  { name: 'clear', overview: clear, blocked: 'none' },
  {
    name: 'a finished update is on record',
    overview: { ...clear, disposition: 'attention_required', terminalEvidence: true },
    blocked: 'finishable',
  },
  {
    name: 'an update did not finish',
    overview: { ...clear, disposition: 'attention_required', activeRecovery: true },
    blocked: 'attention',
  },
  {
    name: 'it needs manual attention',
    overview: { ...clear, disposition: 'attention_required', manualAttention: true },
    blocked: 'attention',
  },
  {
    name: 'it holds evidence this version cannot read',
    overview: { ...clear, disposition: 'attention_required', unsupportedEvidence: true },
    blocked: 'attention',
  },
  {
    name: 'a finished update and one that did not finish',
    overview: {
      ...clear,
      disposition: 'attention_required',
      terminalEvidence: true,
      activeRecovery: true,
    },
    blocked: 'attention',
  },
  { name: 'it cannot be read at all', overview: 'fails', blocked: 'attention' },
]

let overview: Record<string, unknown> | 'fails' = clear

const invoke = vi.hoisted(() => vi.fn())
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

function backend(command: string): unknown {
  switch (command) {
    case 'select_installed_root':
      return { cancelled: false, selection: { handle: INSTALLED, kind: 'installedRoot', displayLabel: 'resources' } }
    case 'select_package_file':
      return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'one.zip' } }
    case 'select_packages_folder':
      return { cancelled: false, selection: { handle: PACKAGES, kind: 'packagesFolder', displayLabel: 'packages' } }
    case 'update_two_way_preview':
      return preview
    case 'update_two_way_apply':
      return { outcome: 'committed', summary: preview.summary }
    case 'update_two_way_release':
    case 'update_batch_release':
      return { released: true }
    case 'update_batch_plan':
      return plan
    case 'update_batch_apply':
      return { results: [{ id: 0, result: 'committed' }], committedCount: 1 }
    case 'session_release_selection':
      return { released: true }
    case 'update_recovery_overview':
      if (overview === 'fails') {
        throw { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
      }
      return overview
    case 'update_recovery_retire_terminal':
      overview = { ...clear }
      return { retired: 1, alreadyRetired: 0 }
    default:
      throw { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
  }
}

const called = (command: string) => invoke.mock.calls.filter(([c]) => c === command).length

async function readyUpdate() {
  const store = useUpdateStore()
  await store.chooseFolder()
  await store.choosePackage()
  await store.compare()
  return store
}

async function readyBatch() {
  const store = useBatchStore()
  await store.chooseInstalled()
  await store.choosePackages()
  await store.compare()
  return store
}

/** Put the workspace into a state after the screen was prepared, as a finished update would. */
async function becomes(state: (typeof STATES)[number]) {
  overview = state.overview
  // What the screen knows is what it last read, so it is made stale on purpose.
  useRecoveryStore().overviewPhase = 'unknown'
}

describe('pressing the button that writes', () => {
  beforeEach(() => {
    invoke.mockReset()
    invoke.mockImplementation(async (command: string) => backend(command))
    overview = clear
    setActivePinia(createPinia())
  })

  describe.each(STATES)('when $name', (state) => {
    describe('on the Update screen', () => {
      it('writes only when the workspace is clear, and otherwise says why', async () => {
        const store = await readyUpdate()
        await store.requestApply()
        await becomes(state)
        await store.apply()
        await flushPromises()

        if (state.blocked === 'none') {
          expect(called('update_two_way_apply')).toBe(1)
          expect(store.outcome).toBe('committed')
        } else {
          expect(called('update_two_way_apply')).toBe(0)
          // Never silent: the confirmation is closed and the screen knows what stands in the way.
          expect(store.confirming).toBe(false)
          expect(store.blocked).toBe(state.blocked)
          expect(store.blockedByEarlierUpdate).toBe(true)
          expect(store.canApply).toBe(false)
        }
      })

      it('does not even offer to write when it already knows', async () => {
        overview = state.overview
        const store = await readyUpdate()
        // What a refused comparison of another resource leaves behind.
        await store.checkPreviousUpdate()
        await store.requestApply()

        if (state.blocked === 'none') {
          expect(store.canApply).toBe(true)
          expect(store.confirming).toBe(true)
        } else {
          expect(store.canApply).toBe(false)
          expect(store.confirming).toBe(false)
        }
        expect(called('update_two_way_apply')).toBe(0)
      })

      it('a second press cannot write twice', async () => {
        const store = await readyUpdate()
        await store.requestApply()
        await becomes(state)
        await Promise.all([store.apply(), store.apply()])
        await flushPromises()
        expect(called('update_two_way_apply')).toBe(state.blocked === 'none' ? 1 : 0)
      })
    })

    describe('on the Batch screen', () => {
      it('writes only when the workspace is clear, and otherwise says why', async () => {
        const store = await readyBatch()
        store.requestApply()
        await becomes(state)
        await store.apply()
        await flushPromises()

        if (state.blocked === 'none') {
          expect(called('update_batch_apply')).toBe(1)
          expect(store.results).toEqual({ 0: 'committed' })
        } else {
          expect(called('update_batch_apply')).toBe(0)
          expect(store.confirming).toBe(false)
          expect(store.blocked).toBe(state.blocked)
          expect(store.blockedByEarlierUpdate).toBe(true)
          expect(store.canApply).toBe(false)
        }
      })

      it('does not even offer to write when it already knows', async () => {
        overview = state.overview
        const store = await readyBatch()
        store.requestApply()
        if (state.blocked === 'none') {
          expect(store.canApply).toBe(true)
          expect(store.confirming).toBe(true)
        } else {
          expect(store.canApply).toBe(false)
          expect(store.confirming).toBe(false)
        }
        expect(called('update_batch_apply')).toBe(0)
      })

      it('a second press cannot write twice', async () => {
        const store = await readyBatch()
        store.requestApply()
        await becomes(state)
        await Promise.all([store.apply(), store.apply()])
        await flushPromises()
        expect(called('update_batch_apply')).toBe(state.blocked === 'none' ? 1 : 0)
      })
    })
  })

  describe('closing a finished update', () => {
    const finished = STATES[1]!

    it('lets the Update screen write afterwards', async () => {
      overview = finished.overview
      const store = await readyUpdate()
      await store.checkPreviousUpdate()
      expect(store.canApply).toBe(false)
      await store.finishPreviousUpdate()
      await flushPromises()
      expect(store.blocked).toBe('none')
      await store.requestApply()
      await store.apply()
      expect(called('update_two_way_apply')).toBe(1)
    })

    it('lets the Batch screen write afterwards', async () => {
      overview = finished.overview
      const store = await readyBatch()
      expect(store.canApply).toBe(false)
      await store.finishPreviousUpdates()
      await flushPromises()
      expect(store.blocked).toBe('none')
      store.requestApply()
      await store.apply()
      expect(called('update_batch_apply')).toBe(1)
    })

    it('cannot close what is not finished', async () => {
      overview = STATES[2]!.overview
      const store = await readyBatch()
      await store.finishPreviousUpdates()
      expect(called('update_recovery_retire_terminal')).toBe(0)
      expect(store.blocked).toBe('attention')
    })
  })

  describe('choosing sources over and over', () => {
    it('never holds more selections than are in use, on either screen', async () => {
      let next = 0
      const live = new Set<string>()
      const owner = new Map<string, string>()
      invoke.mockImplementation(async (command: string, args?: unknown) => {
        if (command.startsWith('select_')) {
          const handle = `123e4567-e89b-42d3-a456-${String(next++).padStart(12, '0')}`
          live.add(handle)
          owner.set(handle, command)
          const kind =
            command === 'select_installed_root'
              ? 'installedRoot'
              : command === 'select_packages_folder'
                ? 'packagesFolder'
                : 'packageFile'
          return { cancelled: false, selection: { handle, kind, displayLabel: 'x' } }
        }
        if (command === 'session_release_selection') {
          live.delete((args as { request: { handle: string } }).request.handle)
          return { released: true }
        }
        return backend(command)
      })

      const update = useUpdateStore()
      const batch = useBatchStore()
      for (let round = 0; round < 40; round += 1) {
        await update.chooseFolder()
        await update.choosePackage()
        await update.chooseBaseline()
        await batch.chooseInstalled()
        await batch.choosePackages()
      }
      const byCommand: Record<string, number> = {}
      for (const handle of live) {
        const command = owner.get(handle) ?? '?'
        byCommand[command] = (byCommand[command] ?? 0) + 1
      }
      // Two on the Update screen's folder and package, one for the original, two for the batch.
      expect(
        (byCommand.select_installed_root ?? 0) +
          (byCommand.select_package_file ?? 0) +
          (byCommand.select_packages_folder ?? 0),
      ).toBeLessThanOrEqual(5)
      expect(byCommand.select_installed_root).toBeLessThanOrEqual(2)
      expect(byCommand.select_package_file).toBeLessThanOrEqual(2)
      expect(byCommand.select_packages_folder).toBeLessThanOrEqual(1)
      // And far below the backend's limit however long the session runs.
      expect(live.size).toBeLessThan(16)
    })
  })
})
