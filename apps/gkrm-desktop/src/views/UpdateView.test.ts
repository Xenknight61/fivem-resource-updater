import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import UpdateView from './UpdateView.vue'
import { useRecoveryStore } from '@/stores/recovery'
import { useUpdateStore } from '@/stores/update'

const FOLDER = '123e4567-e89b-42d3-a456-426614174000'
const PACKAGE = '123e4567-e89b-42d3-a456-426614174001'
const PREVIEW = '123e4567-e89b-42d3-a456-426614174002'
const BASELINE = '123e4567-e89b-42d3-a456-426614174003'

const preview = {
  handle: PREVIEW,
  resource: 'gksphone',
  installedVersion: '1.0.0',
  incomingVersion: '2.0.0',
  summary: { unchanged: 1, takeFromUpdate: 3, review: 2, keepLocalOnly: 1, total: 7 },
  files: [
    { path: 'client/main.lua', disposition: 'take_from_update', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'config.lua', disposition: 'review', editable: true, untouched: false, mergedByKey: false, blockCount: 2 },
    { path: 'data/notes.txt', disposition: 'keep_local_only', editable: true, untouched: false, mergedByKey: false, blockCount: 0 },
    { path: 'server/settings.lua', disposition: 'review', editable: true, untouched: false, mergedByKey: false, blockCount: 1 },
    { path: 'server/main.lua', disposition: 'unchanged', editable: false, untouched: false, mergedByKey: false, blockCount: 0 },
  ],
  omittedFileCount: 0,
  unmergeable: [],
  usedRememberedBaseline: false,
}

/** Two decisions: a changed Locale, and a new line the update adds. */
const diff = {
  available: true,
  truncated: false,
  omitted: false,
  blockCount: 2,
  defaultChoices: [false, true],
  rows: [
    { kind: 'context', text: 'Config = {}', truncated: false },
    { kind: 'yours', block: 0, text: "Config.Locale = 'tr'", truncated: false },
    { kind: 'theirs', block: 0, text: "Config.Locale = 'en'", truncated: false },
    { kind: 'theirs', block: 1, text: 'Config.EnableVoiceMail = true', truncated: false },
  ],
}

/** The workspace's durable state. Tests swap this to stand in front of a blocked update. */
const clear = {
  disposition: 'clear',
  activeRecovery: false,
  terminalEvidence: false,
  manualAttention: false,
  unsupportedEvidence: false,
}
let overview: Record<string, unknown> = { ...clear }

/**
 * The adapter every test starts from.
 *
 * Kept as a value rather than baked into the spy: a test that stands something else in front of
 * one command replaces the whole implementation, and without putting this back the next test
 * inherits it. That is how a passing suite starts asserting against the previous test's answers.
 */
const defaultInvoke = vi.hoisted(
  () => async (command: string) => {
    switch (command) {
      case 'select_installed_root':
        return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
      case 'select_package_file':
        return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'gksphone-v2.zip' } }
      case 'update_two_way_preview':
        return preview
      case 'update_two_way_get_diff':
        return diff
      case 'update_two_way_apply':
        return { outcome: 'committed', summary: preview.summary }
      case 'update_two_way_release':
        return { released: true }
      case 'update_recovery_overview':
        return overview
      case 'update_recovery_retire_terminal':
        overview = { ...clear }
        return { retired: 1, alreadyRetired: 0 }
      default:
        throw { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
    }
  },
)
const invoke = vi.hoisted(() => vi.fn())
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

/**
 * The one button whose label contains `text`.
 *
 * Typed by what it uses rather than by what a mounted component is. Naming that type means
 * writing down `mount`'s own instantiation, which is not the one a real `mount(UpdateView)`
 * produces — under `exactOptionalPropertyTypes` the two do not match, and every call site
 * reports it.
 */
function button<T extends { text(): string }>(
  wrapper: { findAll(selector: string): T[] },
  text: string,
): T | undefined {
  return wrapper.findAll('button').find((candidate) => candidate.text().includes(text))
}

/**
 * Take every file back, as an operator does who wants their own work kept.
 *
 * A comparison starts with every file handed to the update, so a test about what a merge does has
 * to say so first. Written out here rather than in each test: what is being set up is the
 * operator's intent, not an implementation detail of the default.
 */
function keepEveryFile(store: ReturnType<typeof useUpdateStore>) {
  store.setEveryFileChoice(false)
}

describe('the update screen', () => {
  beforeEach(() => {
    invoke.mockReset()
    invoke.mockImplementation(defaultInvoke)
    overview = { ...clear }
    setActivePinia(createPinia())
  })

  it('invalidates a lost apply response and reconciles before allowing another operation', async () => {
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    let rejectApply!: (reason: unknown) => void
    invoke.mockImplementation((command: string) => command === 'update_two_way_apply'
      ? new Promise((_resolve, reject) => { rejectApply = reject })
      : defaultInvoke(command))
    const applying = store.apply()
    await flushPromises()
    expect(store.canChooseSources).toBe(false)
    expect(store.canCompare).toBe(false)
    expect(store.canApply).toBe(false)
    rejectApply(new Error('response lost'))
    await applying
    expect(store.preview).toBeUndefined()
    expect(store.choices).toEqual({})
    expect(useRecoveryStore().overviewPhase).toBe('ready')
    expect(invoke.mock.calls.filter(([command]) => command === 'update_recovery_overview')).toHaveLength(2)
  })

  it('keeps keyboard focus in confirmation and Escape returns to the list', async () => {
    const wrapper = mount(UpdateView, { attachTo: document.body })
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    const original = wrapper.find('.actions button.primary')
    ;(original.element as HTMLElement).focus()
    await store.requestApply()
    await flushPromises()
    const buttons = wrapper.find('[role="dialog"]').findAll('button')
    expect(document.activeElement).toBe(buttons[0]?.element)
    await buttons[0]?.trigger('keydown', { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(buttons[1]?.element)
    await buttons[1]?.trigger('keydown', { key: 'Escape' })
    expect(store.confirming).toBe(false)
    expect(document.activeElement).toBe(original.element)
    wrapper.unmount()
  })

  it('asks for a folder and a package before it will compare', async () => {
    const wrapper = mount(UpdateView)
    expect(button(wrapper, 'Compare')?.attributes('disabled')).toBeDefined()

    await button(wrapper, 'Choose folder')?.trigger('click')
    await flushPromises()
    expect(button(wrapper, 'Compare')?.attributes('disabled')).toBeDefined()

    await button(wrapper, 'Choose ZIP')?.trigger('click')
    await flushPromises()
    expect(button(wrapper, 'Compare')?.attributes('disabled')).toBeUndefined()
  })

  it('asks which installation before it asks about any package', async () => {
    // Both packages are answers about one installation: the one it is going to and the one it
    // came from. Offered first, they invite the operator to pick two ZIPs and then wonder what
    // they picked them for.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()

    const packageButton = () => wrapper.findAll('button').find((b) => b.text().includes('2. New package'))
    const baselineButton = () => wrapper.findAll('button').find((b) => b.text().includes('3. Installed from'))

    expect(packageButton()?.attributes('disabled')).toBeDefined()
    expect(baselineButton()?.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('Choose the resource first')

    // A disabled button is a courtesy, not the rule: the action refuses too.
    await store.choosePackage()
    await store.chooseBaseline()
    expect(store.package).toBeUndefined()
    expect(store.baseline).toBeUndefined()

    await store.chooseFolder()
    await flushPromises()
    expect(packageButton()?.attributes('disabled')).toBeUndefined()
    expect(baselineButton()?.attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).not.toContain('Choose the resource first')
  })

  it('says nothing about the baseline until there is a comparison for it to describe', async () => {
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()

    await store.chooseFolder()
    await store.chooseBaseline()
    await flushPromises()
    // Chosen, but there is no second side yet, so there is no comparison to announce.
    expect(store.baseline).toBeDefined()
    expect(wrapper.text()).not.toContain('Comparing against')

    await store.choosePackage()
    await flushPromises()
    expect(wrapper.text()).toContain('Comparing against')
  })

  it('reads as a diff that decides nothing by being opened', async () => {
    // Opening a file is reading it. A tick per line offered a precision the operator does not
    // have — a file half from each side is one neither side ever had — so the lines only show
    // what will happen, and the answer is given for the file as a whole.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    // Comparing opens the first file the operator has to look at.
    expect(store.selectedPath).toBe('config.lua')
    // And every file starts handed over, so "I want the new version" is one press.
    expect(store.choices).toEqual({ 'config.lua': [true, true], 'server/settings.lua': [true] })

    keepEveryFile(store)
    await flushPromises()
    const rows = wrapper.findAll('.lines li')
    expect(rows).toHaveLength(4)

    // What their file has, and what the update has instead — both visible, in file order.
    expect(rows[1]?.classes()).toContain('yours')
    expect(rows[1]?.text()).toContain("Config.Locale = 'tr'")
    expect(rows[2]?.classes()).toContain('theirs')
    expect(rows[2]?.text()).toContain("Config.Locale = 'en'")

    // No line decides anything, and looking commits the operator to nothing.
    expect(wrapper.findAll('.lines input[type="checkbox"]')).toHaveLength(0)
    expect(store.choices).toEqual({})

    // The merge is still drawn: their own setting is kept, the line the update adds is taken.
    expect(rows[1]?.classes()).not.toContain('taken')
    expect(rows[3]?.classes()).toContain('taken')
  })

  it('hands one file to the update from the list, without opening it', async () => {
    // The operator who edited one file should not have to walk through the ones they never
    // touched. The decision count comes from the preview, so the row answers on its own.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()
    keepEveryFile(store)
    await flushPromises()

    const tick = wrapper.find('.file-row.review input[type="checkbox"]')
    expect(tick.exists()).toBe(true)
    await tick.setValue(true)
    await flushPromises()

    expect(store.choices['config.lua']).toEqual([true, true])
    // One of the two answerable files, so this is a merge with a decision in it rather than the
    // clean sweep that asks for the package's own bytes.
    expect(store.everyFileTaken).toBe(false)

    await store.apply()
    const applied = invoke.mock.calls.find(([command]) => command === 'update_two_way_apply')
    expect(applied?.[1]).toEqual({
      request: {
        handle: PREVIEW,
        keepSettings: true,
        choices: [{ path: 'config.lua', takeFromUpdate: [true, true] }],
      },
    })
  })

  it('starts with every file handed to the update, and takes one back on a tick', async () => {
    // The operator who wants the new version presses Update; the one with work to protect unticks
    // the file that holds it. Both are one gesture, and neither is the wrong way round.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(store.everyFileTaken).toBe(true)
    expect(store.sweepIsWholeUpdate).toBe(true)
    const rows = wrapper.findAll('.file-row.review input[type="checkbox"]')
    expect(rows).toHaveLength(2)
    expect(rows.every((tick) => (tick.element as HTMLInputElement).checked)).toBe(true)

    await rows[0]?.setValue(false)
    await flushPromises()
    expect(store.choices).toEqual({ 'server/settings.lua': [true] })
    // One file back is no longer the whole update, so the rest is a merge again.
    expect(store.sweepIsWholeUpdate).toBe(false)
    expect(wrapper.text()).toContain('1 merged, your lines kept')
  })

  it('takes a file back by unticking it, rather than by a second kind of answer', async () => {
    // Unticked is not "keep the whole file": it is the merge the button describes. Sending
    // nothing for a file is exactly that, so taking a file back sends nothing rather than a row
    // of falses that would freeze it at what it already holds.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    keepEveryFile(store)
    store.setFileChoice('config.lua', true)
    expect(store.choices['config.lua']).toEqual([true, true])

    store.setFileChoice('config.lua', false)
    expect(store.choices).toEqual({})
    expect(store.decidedFiles).toEqual([])
    await flushPromises()
    expect(wrapper.text()).toContain('2 merged, your lines kept')
  })

  it('answers every file it can from the head of the list', async () => {
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    await wrapper.find('.take-all input[type="checkbox"]').setValue(true)
    await flushPromises()

    // Only the file that holds a decision is answered. An unchanged file, an encrypted one and a
    // file only the operator has are already settled, and a tick for them would be a lie.
    expect(store.choices).toEqual({ 'config.lua': [true, true], 'server/settings.lua': [true] })
    expect(store.everyFileTaken).toBe(true)
  })

  it('offers one way to apply, and reports the outcome', async () => {
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(button(wrapper, 'Replace everything')).toBeUndefined()
    keepEveryFile(store)
    await flushPromises()

    await button(wrapper, 'Update')?.trigger('click')
    await flushPromises()

    const applied = invoke.mock.calls.find(([command]) => command === 'update_two_way_apply')
    // No file was handed over, so nothing of the operator's is being replaced: there is nothing to
    // confirm, and the apply carries no decisions.
    expect(store.confirming).toBe(false)
    expect(applied?.[1]).toEqual({
      request: { handle: PREVIEW, keepSettings: true, choices: [] },
    })
    expect(wrapper.text()).toContain('Updated.')
    // The applied update is history, not pending work: the button is not offered again, and the
    // list stops describing changes that have already happened.
    expect(button(wrapper, 'Update')).toBeUndefined()
    // What it says happened is what it asked for, not what the plan described.
    expect(wrapper.text()).toContain('Updated · 3 files from the update · 2 merged, your lines kept')
    expect(button(wrapper, 'Compare again')).toBeDefined()
  })

  it('names the files whose own content is being replaced before it writes anything', async () => {
    // Every file starts handed over, so an operator can reach Update without having read the list.
    // That is the point of the default and the reason it has to be said out loud: their own work
    // is what would go, and it goes named or not at all.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    await button(wrapper, 'Update')?.trigger('click')
    await flushPromises()

    // Asked, not applied.
    expect(store.confirming).toBe(true)
    expect(invoke.mock.calls.some(([command]) => command === 'update_two_way_apply')).toBe(false)

    // Named, so the operator can tell whether it is the file they care about.
    const named = wrapper.findAll('.confirm-files li').map((row) => row.text())
    expect(named).toEqual(['config.lua', 'server/settings.lua'])
    expect(wrapper.text()).toContain("2 files take the update's version")

    await button(wrapper, 'Back to the list')?.trigger('click')
    await flushPromises()
    expect(store.confirming).toBe(false)
    // Backing out changed nothing: the ticks are as they were, and nothing was written.
    expect(store.choices).toEqual({ 'config.lua': [true, true], 'server/settings.lua': [true] })
    expect(invoke.mock.calls.some(([command]) => command === 'update_two_way_apply')).toBe(false)
  })

  it('runs the update once the operator says so, having asked once', async () => {
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    await button(wrapper, 'Update')?.trigger('click')
    await flushPromises()
    // The confirmation's own button, not the footer's.
    await wrapper.find('.confirm-actions .primary').trigger('click')
    await flushPromises()

    expect(store.confirming).toBe(false)
    const applied = invoke.mock.calls.find(([command]) => command === 'update_two_way_apply')
    // Every file handed over is the whole update, served from the package's own bytes.
    expect(applied?.[1]).toEqual({
      request: { handle: PREVIEW, keepSettings: false, choices: [] },
    })
    expect(wrapper.text()).toContain('Updated.')
  })

  it('does not claim a merge after a clean sweep, or any work after a rollback', async () => {
    // The plan's counts say what each file IS. After a sweep nothing was merged, and after a
    // rollback nothing happened at all — reading either off the plan tells the operator something
    // that is not true of their installation.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    store.setEveryFileChoice(true)
    await store.apply()
    await flushPromises()
    const summary = () => wrapper.find('.actions .summary').text()
    expect(summary()).toBe('Updated · 5 files came from the update, exactly as shipped')
    expect(summary()).not.toContain('merged')

    // A rollback wrote nothing, and the screen must not describe work.
    store.outcome = 'rolled_back'
    store.applied = undefined
    await flushPromises()
    expect(summary()).toBe('Nothing was written.')
  })

  it('will not let a source be changed while a comparison is in flight', async () => {
    // The reply carries the handles it was asked about. A source changed underneath it lands as a
    // preview of one folder under the name of another, and the apply re-resolves the preview's own
    // handles, so nothing downstream catches it.
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    const chosen = store.folder?.handle

    store.loading.compare = true
    expect(store.canChooseSources).toBe(false)
    await store.chooseFolder()
    await store.choosePackage()
    await store.chooseBaseline()
    expect(store.folder?.handle).toBe(chosen)
    expect(store.baseline).toBeUndefined()

    store.loading.compare = false
    expect(store.canChooseSources).toBe(true)
  })

  it('counts only the questions the baseline actually removed', async () => {
    // "Untouched" is true of every identical file and every file only the operator has. Counting
    // those as work the baseline saved inflates it past the number of files in the resource.
    const store = useUpdateStore()
    invoke.mockImplementation(async (command: string) => {
      if (command === 'update_two_way_preview') {
        return {
          ...preview,
          files: preview.files.map((file) => ({ ...file, untouched: true })),
        }
      }
      return defaultInvoke(command)
    })
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    // Only the editable file the update replaces was a question the baseline answered.
    expect(store.untouchedFiles.map((file) => file.path)).toEqual([])
  })

  it('says an unchanged file is unchanged, encrypted or not', async () => {
    // An encrypted file that is identical on both sides is not being replaced. Reporting the
    // escrow rule here would describe a change that is not happening.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    invoke.mockImplementationOnce(async () => ({
      available: false, lines: [], truncated: false, omitted: false,
    }))
    await store.openFile('server/main.lua')
    await flushPromises()

    expect(wrapper.text()).toContain('already identical')
    expect(wrapper.text()).not.toContain('encrypted by the developer')
  })

  it('dims the filled button when it cannot be pressed', async () => {
    // The filled button carries its own colours, so it must be dimmed explicitly or a dead
    // control still looks live.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    const apply = button(wrapper, 'Update')
    expect(apply?.attributes('disabled')).toBeUndefined()
    store.loading.apply = true
    await flushPromises()
    expect(button(wrapper, 'Updating')?.attributes('disabled')).toBeDefined()
  })

  it('serves a file handed over alone through the merge, and every file through the package', async () => {
    // Handing over some files is a merge with decisions. Handing over all of them is not: it asks
    // for what the developer shipped, and a merge that happens to take every line would write it
    // back in the operator's newline style instead. The ticks say which of the two it is.
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    store.setEveryFileChoice(true)
    expect(store.everyFileTaken).toBe(true)
    await store.apply()

    const applied = invoke.mock.calls.find(([command]) => command === 'update_two_way_apply')
    expect(applied?.[1]).toEqual({
      request: { handle: PREVIEW, keepSettings: false, choices: [] },
    })
  })

  it('holds no filesystem path in its own state', async () => {
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()

    // Resource-relative paths are the addresses the operator sees; absolute ones never cross.
    const serialized = JSON.stringify(store.$state)
    expect(serialized).not.toMatch(/[A-Za-z]:\\\\/)
    expect(serialized).not.toMatch(/"[\\/]/)
    expect(serialized).not.toContain('\\\\')
  })

  it('drops a stale preview when either side is chosen again', async () => {
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    expect(store.preview).toBeDefined()

    await store.choosePackage()
    expect(store.preview).toBeUndefined()
    expect(store.selectedPath).toBeUndefined()
    expect(invoke.mock.calls.some(([command]) => command === 'update_two_way_release')).toBe(true)
  })

  it('offers to close a finished update rather than reporting a dead end', async () => {
    // A committed update stays on record until it is acknowledged. Left as a raw error, that
    // reads as a broken app: the operator has no way to act on "recovery is required".
    overview = {
      disposition: 'attention_required',
      activeRecovery: false,
      terminalEvidence: true,
      manualAttention: false,
      unsupportedEvidence: false,
    }
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.checkPreviousUpdate()
    await flushPromises()

    expect(store.blocked).toBe('finishable')
    expect(wrapper.text()).toContain('still on record')
    expect(button(wrapper, 'Close previous update')).toBeDefined()
  })

  it('sends the operator to recovery when the previous update did not finish', async () => {
    // Real recovery is not this screen's job, and pretending it is one click away would be a lie.
    overview = {
      disposition: 'attention_required',
      activeRecovery: true,
      terminalEvidence: false,
      manualAttention: false,
      unsupportedEvidence: false,
    }
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.checkPreviousUpdate()
    await flushPromises()

    expect(store.blocked).toBe('attention')
    expect(wrapper.text()).toContain('cannot close it')
    expect(button(wrapper, 'Close previous update')).toBeUndefined()
  })

  it('says nothing about recovery when the workspace is clear', async () => {
    const wrapper = mount(UpdateView)
    await useUpdateStore().checkPreviousUpdate()
    await flushPromises()

    expect(useUpdateStore().blocked).toBe('none')
    expect(wrapper.text()).not.toContain('still on record')
    expect(wrapper.text()).not.toContain('cannot close it')
  })

  it('closes the previous update without a second trusted call racing the first', async () => {
    // The backend serves one trusted operation at a time. Closing already refreshes the workspace
    // overview, so asking a second time would lose that race and report "a recovery operation is
    // already running" — a collision between this app's own screens, blamed on the operator.
    overview = {
      disposition: 'attention_required',
      activeRecovery: false,
      terminalEvidence: true,
      manualAttention: false,
      unsupportedEvidence: false,
    }
    const store = useUpdateStore()
    const recovery = useRecoveryStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.checkPreviousUpdate()
    expect(store.blocked).toBe('finishable')

    const refresh = vi.spyOn(recovery, 'refreshOverview')
    const finalize = vi.spyOn(recovery, 'finalizeTerminal').mockImplementation(async () => {
      overview = { ...clear }
      recovery.overview = { ...clear } as never
      recovery.overviewPhase = 'ready'
    })
    await store.finishPreviousUpdate()

    expect(finalize).toHaveBeenCalledWith(true)
    expect(refresh).not.toHaveBeenCalled()
    expect(store.blocked).toBe('none')
    // Closing it leads straight back into the comparison the operator was trying to make.
    expect(invoke.mock.calls.some(([c]) => c === 'update_two_way_preview')).toBe(true)
    expect(store.error).toBeUndefined()
  })

  it('reports a blocked comparison once, not as a raw failure and an explanation', async () => {
    overview = {
      disposition: 'attention_required',
      activeRecovery: false,
      terminalEvidence: true,
      manualAttention: false,
      unsupportedEvidence: false,
    }
    invoke.mockImplementationOnce(async () => ({
      cancelled: false,
      selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' },
    }))
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    invoke.mockImplementationOnce(async () => {
      throw {
        code: 'recovery_required',
        category: 'filesystem',
        message: 'Recovery is required before planning can continue.',
        recoverable: true,
      }
    })
    await store.compare()
    await flushPromises()

    expect(store.error).toBeUndefined()
    expect(wrapper.text()).not.toContain('Recovery is required')
    expect(wrapper.text()).toContain('still on record')
  })

  it('offers nothing to press when the package would change nothing', async () => {
    // A button whose only possible result is "there was nothing to do" is a button that should
    // not be there.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'gksphone-v2.zip' } }
        case 'update_two_way_preview':
          return {
            ...preview,
            summary: { unchanged: 7, takeFromUpdate: 0, review: 0, keepLocalOnly: 0, total: 7 },
            files: preview.files.map((file) => ({ ...file, disposition: 'unchanged' })),
          }
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(button(wrapper, 'Update, keep my settings')).toBeUndefined()
    expect(button(wrapper, 'Replace everything')).toBeUndefined()
    expect(wrapper.text()).toContain('Already up to date')
    expect(wrapper.text()).toContain('already matches this package')
  })

  it('says which version this update moves to', async () => {
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(wrapper.text()).toContain('1.0.0 → 2.0.0')
  })

  it('keeps the files the operator took back when it compares again', async () => {
    // After an update the primary button becomes "Compare again" in the same place. Re-ticking
    // every file there turns "keep mine" back into "hand it over" under the button they just
    // pressed, leaving only the confirmation between a second press and the edits they had
    // chosen to protect.
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    store.setFileChoice('config.lua', false)
    expect(store.choices['config.lua']).toBeUndefined()
    expect(store.choices['server/settings.lua']).toBeDefined()

    // Awaited rather than clicked: the apply settles its durable-operation permit through a
    // dynamically imported store, which a flushed microtask queue does not reach.
    await store.apply()
    await flushPromises()
    expect(store.outcome).toBe('committed')
    expect(useRecoveryStore().durableOperation).toBeUndefined()
    // Present, and deliberately not the filled button: comparing again is not what to do next
    // after an update, and it was the only filled button on the screen.
    expect(button(wrapper, 'Compare again')).toBeDefined()
    expect(wrapper.find('.actions .primary').exists()).toBe(false)

    await store.compare()
    await flushPromises()

    expect(store.choices['config.lua']).toBeUndefined()
    expect(store.choices['server/settings.lua']).toBeDefined()
  })

  it('says a package declaring the installed version may be the wrong file', async () => {
    // Both sides declaring the same version is how choosing the wrong package looks from here.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'z.zip' } }
        case 'update_two_way_preview':
          return { ...preview, incomingVersion: preview.installedVersion }
        case 'update_two_way_get_diff':
          return diff
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(wrapper.text()).toContain('the one already installed')
    // It is a caution, not a refusal: shipping a fix without moving the number is real work.
    expect(button(wrapper, 'Update')).toBeDefined()
  })

  it('says nothing about versions when a manifest declares none', async () => {
    // A wrong version label is worse than none, so a side that declares nothing gets no claim.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'z.zip' } }
        case 'update_two_way_preview': {
          const { installedVersion, incomingVersion, ...rest } = preview
          void installedVersion
          void incomingVersion
          return rest
        }
        case 'update_two_way_get_diff':
          return diff
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(wrapper.text()).not.toContain('→')
    expect(wrapper.text()).toContain('gksphone · 7 files')
  })
  it('passes the package installed from, and reports what it settled', async () => {
    // Without it, every editable file that differs is a question. With it, only the ones the
    // operator actually edited are — and the count says so, or its worth is invisible.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: BASELINE, kind: 'packageFile', displayLabel: 'gksphone-v1.zip' } }
        case 'update_two_way_preview':
          return {
            ...preview,
            files: preview.files.map((file) =>
              file.path === 'server/settings.lua'
                ? { ...file, disposition: 'take_from_update', untouched: true, blockCount: 0 }
                : file,
            ),
          }
        // A file the baseline settled has no line view: there is no question to draw.
        case 'update_two_way_get_diff':
          return { available: false, truncated: false, omitted: false, blockCount: 0, defaultChoices: [], rows: [] }
        case 'update_two_way_release':
          return { released: true }
        case 'update_recovery_overview':
          return overview
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.chooseBaseline()
    await store.compare()
    await flushPromises()

    const previewed = invoke.mock.calls.findLast(([command]) => command === 'update_two_way_preview')
    expect(previewed?.[1]).toEqual({
      request: {
        installedSelectionHandle: FOLDER,
        packageSelectionHandle: BASELINE,
        baselineSelectionHandle: BASELINE,
      },
    })
    expect(store.untouchedFiles.map((file) => file.path)).toEqual(['server/settings.lua'])
    // Said against a merge, where the count is the difference the baseline made. Handing every
    // file over is one number and settles nothing worth counting.
    keepEveryFile(store)
    await flushPromises()
    expect(wrapper.text()).toContain('1 you never changed')

    // The row says which of the two reasons kept it out of the questions.
    await store.openFile('server/settings.lua')
    await flushPromises()
    expect(wrapper.text()).toContain('exactly what you installed')
  })

  it('asks about everything editable again once the baseline is forgotten', async () => {
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.chooseBaseline()
    await store.compare()
    await flushPromises()

    await store.forgetBaseline()
    expect(store.baseline).toBeUndefined()
    // Dropping it drops the preview it decided, so nothing on screen outlives the evidence.
    expect(store.preview).toBeUndefined()

    await store.compare()
    await flushPromises()
    const previewed = invoke.mock.calls.findLast(([command]) => command === 'update_two_way_preview')
    expect(previewed?.[1]).toEqual({
      request: { installedSelectionHandle: FOLDER, packageSelectionHandle: PACKAGE },
    })
  })

  it('answers files it cannot combine the same way it answers the rest', async () => {
    // They used to have no tick at all, which left them decided by the mode: kept, whatever the
    // operator wanted. An image or a JSON is answered whole rather than line by line, but it is
    // still answered.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'z.zip' } }
        case 'update_two_way_preview':
          return {
            ...preview,
            files: preview.files.map((file) =>
              file.disposition === 'review' ? { ...file, blockCount: 0 } : file,
            ),
            unmergeable: ['config.lua', 'server/settings.lua'],
          }
        case 'update_two_way_get_diff':
          return { available: false, truncated: false, omitted: false, blockCount: 0, defaultChoices: [], rows: [] }
        case 'update_two_way_apply':
          return { outcome: 'committed', summary: preview.summary }
        case 'update_recovery_overview':
          return overview
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    expect(store.decidableFiles.map((file) => file.path)).toEqual([
      'config.lua',
      'server/settings.lua',
    ])

    // One of them, answered on its own: the empty list is the whole-file answer.
    keepEveryFile(store)
    store.setFileChoice('config.lua', true)
    expect(store.choices).toEqual({ 'config.lua': [] })
    expect(store.everyFileTaken).toBe(false)

    await store.apply()
    let applied = invoke.mock.calls.findLast(([command]) => command === 'update_two_way_apply')
    expect(applied?.[1]).toEqual({
      request: {
        handle: PREVIEW,
        keepSettings: true,
        choices: [{ path: 'config.lua', takeFromUpdate: [] }],
      },
    })

    // And all of them, which is the clean sweep.
    store.outcome = undefined
    store.setEveryFileChoice(true)
    expect(store.everyFileTaken).toBe(true)

    await store.apply()
    applied = invoke.mock.calls.findLast(([command]) => command === 'update_two_way_apply')
    expect(applied?.[1]).toEqual({
      request: { handle: PREVIEW, keepSettings: false, choices: [] },
    })
  })

  it('keeps the head of the list clearable even when it cannot sweep the whole update', async () => {
    // Tying the header tick to "this is the whole update" left a checkbox that could never be
    // cleared: with files past the end of the listing it read unchecked however many rows were
    // ticked, so unticking it ticked them all again.
    invoke.mockImplementation(async (command: string) => {
      if (command === 'update_two_way_preview') return { ...preview, omittedFileCount: 4 }
      return defaultInvoke(command)
    })
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    const takeAll = () => wrapper.find('.take-all input[type="checkbox"]')
    await takeAll().setValue(true)
    await flushPromises()
    expect(store.everyFileTaken).toBe(true)
    expect((takeAll().element as HTMLInputElement).checked).toBe(true)
    // ...and it still is not a sweep, because the list is not the whole list.
    expect(store.sweepIsWholeUpdate).toBe(false)

    await takeAll().setValue(false)
    await flushPromises()
    expect(store.choices).toEqual({})

    // Applying sends the decisions rather than a wholesale replacement.
    store.setEveryFileChoice(true)
    await store.apply()
    const applied = invoke.mock.calls.findLast(([command]) => command === 'update_two_way_apply')
    expect((applied?.[1] as { request: { keepSettings: boolean } }).request.keepSettings).toBe(true)
  })

  it('calls merged only what is merged, and kept whole only what is kept whole', async () => {
    // A file with no line view is not always kept: one combined by key is merged too. Counting
    // either as the other makes the row and the footer contradict each other.
    invoke.mockImplementation(async (command: string) => {
      if (command === 'update_two_way_preview') {
        return {
          ...preview,
          files: preview.files.map((file) => {
            if (file.path === 'config.lua') {
              return { ...file, blockCount: 0, mergedByKey: true }
            }
            if (file.path === 'server/settings.lua') return { ...file, blockCount: 0 }
            return file
          }),
          unmergeable: ['config.lua', 'server/settings.lua'],
        }
      }
      return defaultInvoke(command)
    })
    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    // Said of a merge: a file handed to the update is neither merged nor kept, it is replaced.
    keepEveryFile(store)
    await flushPromises()

    const row = (path: string) =>
      wrapper.findAll('.file-row').find((candidate) => candidate.text().includes(path))
    expect(row('config.lua')?.text()).toContain('merged, your values kept')
    expect(row('server/settings.lua')?.text()).toContain('stays yours whole')

    const summary = () => wrapper.find('.actions .summary').text()
    expect(summary()).toContain('1 merged, your lines kept')
    expect(summary()).toContain('1 stays yours whole')

    await store.apply()
    await flushPromises()
    expect(summary()).toBe('Updated · 3 files from the update · 1 merged, your lines kept')
  })

  it('shows what a key merge kept rather than describing it', async () => {
    // These two documents have no diff to show: every line of one differs from every line of the
    // other, which is why keys were used at all. Without this the operator approves a document
    // nothing showed them.
    invoke.mockImplementation(async (command: string) => {
      if (command === 'update_two_way_preview') {
        return {
          ...preview,
          files: preview.files.map((file) =>
            file.path === 'config.lua'
              ? { ...file, path: 'locales/tr.json', blockCount: 0, mergedByKey: true }
              : file,
          ),
          unmergeable: ['locales/tr.json'],
        }
      }
      if (command === 'update_two_way_get_diff') {
        return {
          available: false,
          truncated: false,
          omitted: false,
          blockCount: 0,
          defaultChoices: [],
          rows: [],
          wholeFileReason: 'too_far_apart',
          mergedByKey: true,
          keptKeys: ['PHONE.PHONE_SCREEN_LOADING', 'Squawk.APP_SQUAWK_SIGNUP'],
          keptKeyCount: 7,
        }
      }
      return defaultInvoke(command)
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await store.openFile('locales/tr.json')
    await flushPromises()

    const kept = wrapper.findAll('.kept li').map((item) => item.text())
    expect(kept).toEqual([
      'PHONE.PHONE_SCREEN_LOADING',
      'Squawk.APP_SQUAWK_SIGNUP',
      'and 5 more',
    ])
    expect(wrapper.text()).toContain('7 of your values are kept in it')
    expect(wrapper.text()).toContain('combined by key')
  })

  it('will not compare while a source dialog is open', async () => {
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    store.loading.package = true
    expect(store.canCompare).toBe(false)
    await store.compare()
    expect(store.preview).toBeUndefined()
  })

  it('shows the two pictures rather than describing them', async () => {
    // A one-pixel PNG, which is all this has to be: the page is handed a data URL built from a
    // media type the backend chose and a payload checked to be base64.
    const pixel =
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'z.zip' } }
        case 'update_two_way_preview':
          return {
            ...preview,
            files: preview.files.map((file) =>
              file.path === 'config.lua'
                ? { ...file, path: 'html/img/bank.png', blockCount: 0 }
                : file,
            ),
            unmergeable: ['html/img/bank.png'],
          }
        case 'update_two_way_get_diff':
          return {
            available: false,
            truncated: false,
            omitted: false,
            blockCount: 0,
            defaultChoices: [],
            rows: [],
            wholeFileReason: 'not_text',
            imageMediaType: 'image/png',
            installedImage: pixel,
            incomingImage: pixel,
          }
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await store.openFile('html/img/bank.png')
    await flushPromises()

    const pictures = wrapper.findAll('.pictures img')
    expect(pictures).toHaveLength(2)
    expect(pictures[0]?.attributes('src')).toBe(`data:image/png;base64,${pixel}`)
    expect(wrapper.text()).toContain('not text')
  })

  it('says a file that is merely too different is too different, not unreadable', async () => {
    // The message used to call every whole-file case an image. For a UTF-8 JSON that is simply
    // untrue, and an operator reading it learns the wrong thing about their own file.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'z.zip' } }
        case 'update_two_way_preview':
          return {
            ...preview,
            files: preview.files.map((file) =>
              file.path === 'config.lua' ? { ...file, blockCount: 0 } : file,
            ),
            unmergeable: ['config.lua'],
          }
        case 'update_two_way_get_diff':
          return {
            available: false,
            truncated: false,
            omitted: false,
            blockCount: 0,
            defaultChoices: [],
            rows: [],
            wholeFileReason: 'too_far_apart',
          }
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await store.openFile('config.lua')
    await flushPromises()

    expect(wrapper.text()).toContain('too far apart to line up')
    expect(wrapper.text()).not.toContain('not text')
    expect(wrapper.findAll('.pictures img')).toHaveLength(0)
  })

  it('says what becomes of a file it cannot combine, either way it is answered', async () => {
    // The row has to say it, because there is no diff to read it off. Left alone, the whole of
    // the operator's copy stays; ticked, the whole of the update's arrives.
    invoke.mockImplementation(async (command: string) => {
      switch (command) {
        case 'select_installed_root':
          return { cancelled: false, selection: { handle: FOLDER, kind: 'installedRoot', displayLabel: 'resources' } }
        case 'select_package_file':
          return { cancelled: false, selection: { handle: PACKAGE, kind: 'packageFile', displayLabel: 'z.zip' } }
        case 'update_two_way_preview':
          return {
            ...preview,
            // A file that cannot be split holds no decisions to count.
            files: preview.files.map((file) =>
              file.path === 'config.lua' ? { ...file, blockCount: 0 } : file,
            ),
            unmergeable: ['config.lua'],
          }
        case 'update_two_way_get_diff':
          return { available: false, truncated: false, omitted: false, blockCount: 0, defaultChoices: [], rows: [] }
        case 'update_two_way_release':
          return { released: true }
        default:
          throw { code: 'internal', category: 'internal', message: 'x', recoverable: false }
      }
    })

    const wrapper = mount(UpdateView)
    const store = useUpdateStore()
    await store.chooseFolder()
    await store.choosePackage()
    await store.compare()
    await flushPromises()

    keepEveryFile(store)
    await flushPromises()

    const row = () =>
      wrapper.findAll('.file-row').find((candidate) => candidate.text().includes('config.lua'))
    expect(row()?.find('input[type="checkbox"]').exists()).toBe(true)
    expect(row()?.text()).toContain('stays yours whole')
    expect(wrapper.text()).toContain('1 stays yours whole')

    await row()?.find('input[type="checkbox"]').setValue(true)
    await flushPromises()
    expect(store.choices).toEqual({ 'config.lua': [] })
    expect(row()?.text()).toContain('from the update')
    expect(wrapper.text()).not.toContain('stays yours whole')

    await store.openFile('config.lua')
    await flushPromises()
    expect(wrapper.text()).toContain('cannot be combined line by line')
  })
})
