import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import HistoryView from './HistoryView.vue'
import { useRecoveryStore } from '@/stores/recovery'

const clear = {
  disposition: 'clear',
  activeRecovery: false,
  terminalEvidence: false,
  manualAttention: false,
  unsupportedEvidence: false,
}

const undoable = {
  id: '123e4567-e89b-42d3-a456-426614174000',
  resource: 'gksphone',
  outcome: 'committed',
  appliedAtMs: 1_700_000_000_000,
  reviewed: 27,
  replaced: 549,
  total: 715,
  fromVersion: '2.4.0',
  toVersion: '2.7.1',
  undoable: true,
}

/** An update remembered before undo existed: there is no record of what it replaced. */
const older = {
  id: '',
  resource: 'gks-tablet',
  outcome: 'committed',
  appliedAtMs: 1_600_000_000_000,
  reviewed: 1,
  replaced: 2,
  total: 9,
  undoable: false,
}

let entries: unknown[] = []
let undoResult: unknown = { restored: 24, removed: 1, unchanged: 2, skipped: 0, missing: 0 }
let undoFails = false
let undoAttempted = false
let overviewAfterUndo: unknown = clear
let entriesAfterUndo: unknown[] | undefined

/** What the workspace is holding. Two packages something needs, one nothing does. */
const heldNothingNeeds = {
  resource: 'gksphone',
  version: '2.0.15',
  bytes: 12 * 1024 * 1024,
}
let storage: unknown = {
  baselines: [
    { resource: 'gksphone', version: '2.7.1', bytes: 28 * 1024 * 1024, neededFor: 'installation' },
    { resource: 'gksphone', version: '2.4.2', bytes: 16 * 1024 * 1024, neededFor: 'undo' },
    heldNothingNeeds,
  ],
  heldBytes: 56 * 1024 * 1024,
  releasableBytes: 12 * 1024 * 1024,
  stagedCount: 2,
  stagedBytes: 40 * 1024 * 1024,
  stagedReleasableBytes: 20 * 1024 * 1024,
}
let releaseResult: unknown = { released: 1, bytes: 12 * 1024 * 1024 }

const invoke = vi.hoisted(() =>
  vi.fn(async (command: string) => {
    switch (command) {
      case 'update_recovery_overview':
        return undoAttempted ? overviewAfterUndo : clear
      case 'update_history_list':
        return { entries }
      case 'storage_report':
        return storage
      case 'storage_release':
        return releaseResult
      case 'update_history_undo':
        undoAttempted = true
        if (entriesAfterUndo !== undefined) entries = entriesAfterUndo
        if (undoFails) {
          throw {
            code: 'undo_installation_missing',
            category: 'filesystem',
            message: 'The folder this update was applied to is not there any more.',
            recoverable: true,
          }
        }
        return undoResult
      default:
        throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
    }
  }),
)
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

function button(wrapper: { findAll: (selector: string) => Array<{ text: () => string }> }, text: string) {
  return wrapper.findAll('button').find((candidate) => candidate.text().includes(text))
}

describe('the history screen', () => {
  beforeEach(() => {
    invoke.mockClear()
    entries = [undoable, older]
    undoFails = false
    undoAttempted = false
    overviewAfterUndo = clear
    entriesAfterUndo = undefined
    undoResult = { restored: 24, removed: 1, unchanged: 2, skipped: 0, missing: 0 }
    storage = {
      baselines: [
        { resource: 'gksphone', version: '2.7.1', bytes: 28 * 1024 * 1024, neededFor: 'installation' },
        { resource: 'gksphone', version: '2.4.2', bytes: 16 * 1024 * 1024, neededFor: 'undo' },
        heldNothingNeeds,
      ],
      heldBytes: 56 * 1024 * 1024,
      releasableBytes: 12 * 1024 * 1024,
      stagedCount: 2,
      stagedBytes: 40 * 1024 * 1024,
      stagedReleasableBytes: 20 * 1024 * 1024,
    }
    releaseResult = { released: 1, bytes: 12 * 1024 * 1024 }
    setActivePinia(createPinia())
  })

  it('says the time is not recorded for an update it found rather than watched', async () => {
    // The workspace proves the update happened; nothing proves when, so nothing claims it.
    entries = [{ ...undoable, appliedAtMs: 0 }]
    const wrapper = mount(HistoryView)
    await flushPromises()

    expect(wrapper.text()).toContain('time not recorded')
    expect(button(wrapper, 'Undo this update')).toBeDefined()
  })

  it('offers to put back an update it still has the record for', async () => {
    const wrapper = mount(HistoryView)
    await flushPromises()

    expect(wrapper.text()).toContain('2.4.0 → 2.7.1')
    expect(button(wrapper, 'Undo this update')).toBeDefined()
  })

  it('asks before writing to the installation', async () => {
    // Undo writes to the operator's live files. One press says what it will do; the second does
    // it, so a mis-click cannot rewrite a folder.
    const wrapper = mount(HistoryView)
    await flushPromises()

    await (button(wrapper, 'Undo this update') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    expect(wrapper.text()).toContain('This writes to gksphone')
    expect(invoke).not.toHaveBeenCalledWith('update_history_undo', expect.anything())

    await (button(wrapper, 'Yes, put it back') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()
    expect(invoke).toHaveBeenCalledWith('update_history_undo', {
      request: { id: undoable.id },
    })
  })

  it('reports what putting it back actually did, file by file', async () => {
    undoResult = { restored: 24, removed: 1, unchanged: 2, skipped: 3, missing: 1 }
    const wrapper = mount(HistoryView)
    await flushPromises()
    await (button(wrapper, 'Undo this update') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await (button(wrapper, 'Yes, put it back') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('24 put back')
    expect(text).toContain('1 removed')
    expect(text).toContain('3 left alone')
    expect(text).toContain('1 could not be found')
  })

  it('says why an older update cannot be put back instead of offering it', async () => {
    entries = [older]
    const wrapper = mount(HistoryView)
    await flushPromises()

    expect(button(wrapper, 'Undo this update')).toBeUndefined()
    expect(wrapper.text()).toContain('no record of what it replaced')
  })

  it('shows the failure rather than claiming it worked', async () => {
    undoFails = true
    const wrapper = mount(HistoryView)
    await flushPromises()
    await (button(wrapper, 'Undo this update') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await (button(wrapper, 'Yes, put it back') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('is not there any more')
    expect(wrapper.text()).not.toContain('put back,')
  })

  it('reconciles a lost Undo response and never retries the mutation automatically', async () => {
    undoFails = true
    overviewAfterUndo = { disposition: 'attention_required', activeRecovery: true,
      terminalEvidence: false, manualAttention: false, unsupportedEvidence: false }
    const recovery = useRecoveryStore()
    const invalidate = vi.spyOn(recovery, 'invalidateMutationSensitiveUpdateSession').mockResolvedValue(true)
    const wrapper = mount(HistoryView)
    await flushPromises()
    await (button(wrapper, 'Undo this update') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await (button(wrapper, 'Yes, put it back') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()
    expect(invalidate).toHaveBeenCalledOnce()
    expect(recovery.lastDurableResult?.operation).toBe('undo')
    expect(recovery.lastDurableResult?.responseReceived).toBe(false)
    expect(recovery.overview?.activeRecovery).toBe(true)
    expect(recovery.durableOperation).toBeUndefined()
    expect(invoke.mock.calls.filter(([command]) => command === 'update_history_undo')).toHaveLength(1)
    expect(wrapper.findAll('button').find((candidate) => candidate.text() === 'Undo this update')?.attributes('disabled')).toBeDefined()
  })

  it('reconciles a malformed Undo response instead of showing a successful reversal', async () => {
    undoResult = { restored: 'untrusted', removed: 0, unchanged: 0, skipped: 0, missing: 0 }
    const recovery = useRecoveryStore()
    const invalidate = vi.spyOn(recovery, 'invalidateMutationSensitiveUpdateSession').mockResolvedValue(true)
    const wrapper = mount(HistoryView)
    await flushPromises()
    await (button(wrapper, 'Undo this update') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await (button(wrapper, 'Yes, put it back') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()
    expect(invalidate).toHaveBeenCalledOnce()
    expect(recovery.lastDurableResult?.responseReceived).toBe(false)
    expect(wrapper.text()).not.toContain('put back,')
    expect(invoke.mock.calls.filter(([command]) => command === 'update_history_undo')).toHaveLength(1)
  })

  it('shows verified completion after a lost response without offering another Undo', async () => {
    undoFails = true
    entriesAfterUndo = [{ ...undoable, outcome: 'undone', undoable: false }]
    overviewAfterUndo = { disposition: 'attention_required', activeRecovery: false,
      terminalEvidence: true, manualAttention: false, unsupportedEvidence: false }
    const wrapper = mount(HistoryView)
    await flushPromises()
    await (button(wrapper, 'Undo this update') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await (button(wrapper, 'Yes, put it back') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Undone')
    expect(button(wrapper, 'Undo this update')).toBeUndefined()
    expect(wrapper.text()).not.toContain('no record of what it replaced')
    expect(invoke.mock.calls.filter(([command]) => command === 'update_history_undo')).toHaveLength(1)
  })

  it('distinguishes a completed Undo that preserved later customer changes', async () => {
    entries = [{ ...undoable, outcome: 'undone_partial', undoable: false }]
    const wrapper = mount(HistoryView)
    await flushPromises()
    expect(wrapper.text()).toContain('your later changes kept')
    expect(button(wrapper, 'Undo this update')).toBeUndefined()
  })

  it('says what is kept and offers only the part nothing needs', async () => {
    // The kept packages are the largest thing this application holds and nothing ever removed one.
    // What may go is not a matter of size or age: it is whether anything still reaches for it.
    const wrapper = mount(HistoryView)
    await flushPromises()

    const text = wrapper.text()
    // Both halves together, because both are what an update left behind and both are the size of a
    // package. Naming one and quietly freeing the other would be a number nobody could check.
    expect(text).toContain('96.0 MB left behind by past updates')
    expect(text).toContain('32.0 MB of it is no longer needed')
    expect(text).toContain('2 staged copies')
    expect(text).toContain('20.0 MB of it no longer needed')
    // Named as a person would read it. Vue collapses whitespace between a mustache and a tag, so
    // a version written as a neighbouring node ran into the resource name: "gksphone2.7.1".
    const named = wrapper.findAll('.kept-list .name').map((row) => row.text())
    expect(named).toEqual([
      'gksphone 2.7.1',
      'gksphone 2.4.2',
      'gksphone 2.0.15',
      '2 staged copies',
    ])
    // Named with the reason, so the two that stay are not a mystery.
    expect(text).toContain('an installation is on it')
    expect(text).toContain('an update can still be put back onto it')
    expect(text).toContain('nothing needs it')
    // The button offers exactly what is releasable, not the total.
    expect(button(wrapper, 'Release 32.0 MB')).toBeDefined()
    expect(button(wrapper, 'Release 96.0 MB')).toBeUndefined()
  })

  it('says a staged copy is kept for the update it could recover, not that it is spare', async () => {
    // A staged copy is what a recovery replays from, so one an update on record still names is not
    // spare space — and saying how much it occupies without saying that would read as an offer.
    storage = {
      baselines: [],
      heldBytes: 0,
      releasableBytes: 0,
      stagedCount: 1,
      stagedBytes: 20 * 1024 * 1024,
      stagedReleasableBytes: 0,
    }
    const wrapper = mount(HistoryView)
    await flushPromises()

    expect(wrapper.text()).toContain('20.0 MB left behind by past updates')
    expect(wrapper.text()).toContain('all of it is still in use')
    expect(wrapper.text()).toContain('an update on record could still be recovered from them')
    expect(button(wrapper, 'Release')).toBeUndefined()
  })

  it('offers nothing to release when every kept package is still in use', async () => {
    storage = {
      baselines: [
        { resource: 'gksphone', version: '2.7.1', bytes: 28 * 1024 * 1024, neededFor: 'installation' },
      ],
      heldBytes: 28 * 1024 * 1024,
      releasableBytes: 0,
      stagedCount: 1,
      stagedBytes: 20 * 1024 * 1024,
      stagedReleasableBytes: 0,
    }
    const wrapper = mount(HistoryView)
    await flushPromises()

    expect(wrapper.text()).toContain('all of it is still in use')
    expect(button(wrapper, 'Release')).toBeUndefined()
  })

  it('reports what a release actually let go of, and reads the store again', async () => {
    const wrapper = mount(HistoryView)
    await flushPromises()

    // What is held changes underneath the screen, so the number afterwards is read, not computed.
    storage = {
      baselines: [heldNothingNeeds],
      heldBytes: 12 * 1024 * 1024,
      releasableBytes: 0,
      stagedCount: 1,
      stagedBytes: 20 * 1024 * 1024,
      stagedReleasableBytes: 0,
    }
    releaseResult = { released: 3, bytes: 32 * 1024 * 1024 }
    await (button(wrapper, 'Release 32.0 MB') as unknown as { trigger: (e: string) => Promise<void> }).trigger('click')
    await flushPromises()

    expect(invoke).toHaveBeenCalledWith('storage_release', {})
    expect(wrapper.text()).toContain('Released 32.0 MB')
    expect(wrapper.text()).toContain('32.0 MB left behind by past updates')
    expect(button(wrapper, 'Release')).toBeUndefined()
  })

  it('says nothing about storage it could not read', async () => {
    // A screen that cannot say what is held says nothing, rather than a zero that reads as "empty".
    storage = { nonsense: true }
    const wrapper = mount(HistoryView)
    await flushPromises()

    expect(wrapper.text()).not.toContain('kept so updates')
    expect(button(wrapper, 'Release')).toBeUndefined()
  })
})
