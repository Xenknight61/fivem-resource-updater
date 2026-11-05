import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import BatchView from './BatchView.vue'
import { decodeBatchApplyResponse, decodeBatchPlanResponse } from '@/services/tauri/decoders'
import { useBatchStore } from '@/stores/batch'
import { useUpdateStore } from '@/stores/update'

const INSTALLED = '123e4567-e89b-42d3-a456-426614174000'
const PACKAGES = '123e4567-e89b-42d3-a456-426614174001'
const PLAN = '123e4567-e89b-42d3-a456-426614174002'
const OPENED = '123e4567-e89b-42d3-a456-426614174003'
const OPENED_INSTALLED = '123e4567-e89b-42d3-a456-426614174006'

const push = vi.hoisted(() => vi.fn())
vi.mock('vue-router', () => ({ useRouter: () => ({ push }) }))

function entry(id: number, resource: string, kind: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    packageName: `${resource}.zip`,
    resource,
    kind,
    review: 0,
    unmergeable: 0,
    ...extra,
  }
}

const plan = {
  handle: PLAN,
  readyCount: 2,
  entries: [
    entry(0, 'alpha', 'ready', { installedVersion: '1.0.0', incomingVersion: '2.0.0' }),
    entry(1, 'beta', 'ready', { installedVersion: '1.0.0', incomingVersion: '1.1.0' }),
    entry(2, 'gamma', 'needs_review', { review: 2 }),
    entry(3, 'delta', 'no_installed_resource'),
    entry(4, 'epsilon', 'up_to_date'),
  ],
}

const clear = {
  disposition: 'clear',
  activeRecovery: false,
  terminalEvidence: false,
  manualAttention: false,
  unsupportedEvidence: false,
}
let overview: Record<string, unknown> = { ...clear }
let applyResults: Array<{ id: number; result: string }> = []

const defaultInvoke = vi.hoisted(() => async (command: string) => {
  switch (command) {
    case 'select_installed_root':
      return {
        cancelled: false,
        selection: { handle: INSTALLED, kind: 'installedRoot', displayLabel: 'resources' },
      }
    case 'select_packages_folder':
      return {
        cancelled: false,
        selection: { handle: PACKAGES, kind: 'packagesFolder', displayLabel: 'downloads' },
      }
    case 'update_batch_release':
      return { released: true }
    case 'update_two_way_release':
      return { released: true }
    default:
      throw { code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false }
  }
})
const invoke = vi.hoisted(() => vi.fn())
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

function answer(command: string) {
  switch (command) {
    case 'update_batch_plan':
      return plan
    case 'update_batch_apply':
      return {
        results: applyResults,
        committedCount: applyResults.filter((r) => r.result === 'committed').length,
      }
    case 'update_batch_open_package':
      return {
        package: { handle: OPENED, kind: 'packageFile', displayLabel: 'gamma.zip' },
        installed: { handle: OPENED_INSTALLED, kind: 'installedRoot', displayLabel: 'resources' },
      }
    case 'update_recovery_overview':
      return overview
    case 'update_recovery_retire_terminal':
      overview = { ...clear }
      return { retired: 1, alreadyRetired: 0 }
    case 'update_two_way_preview':
      throw { code: 'internal', category: 'internal', message: 'not under test', recoverable: false }
    default:
      return defaultInvoke(command)
  }
}

function button<T extends { text(): string }>(
  wrapper: { findAll(selector: string): T[] },
  text: string,
): T | undefined {
  return wrapper.findAll('button').find((candidate) => candidate.text().includes(text))
}

async function compared() {
  const wrapper = mount(BatchView, { attachTo: document.body })
  const store = useBatchStore()
  await store.chooseInstalled()
  await store.choosePackages()
  await store.compare()
  await flushPromises()
  return { wrapper, store }
}

const commandsCalled = () => invoke.mock.calls.map(([command]) => command as string)

describe('the batch screen', () => {
  beforeEach(() => {
    invoke.mockReset()
    invoke.mockImplementation(async (command: string) => answer(command))
    push.mockReset()
    overview = { ...clear }
    applyResults = [
      { id: 0, result: 'committed' },
      { id: 1, result: 'committed' },
      { id: 2, result: 'skipped' },
      { id: 3, result: 'skipped' },
      { id: 4, result: 'skipped' },
    ]
    setActivePinia(createPinia())
  })

  it('asks for both folders before it will compare', async () => {
    const wrapper = mount(BatchView)
    expect(button(wrapper, 'Compare')?.attributes('disabled')).toBeDefined()
    await button(wrapper, 'Choose folder')?.trigger('click')
    await flushPromises()
    expect(button(wrapper, 'Compare')?.attributes('disabled')).toBeDefined()
    const packages = wrapper.findAll('button.source')[1]
    await packages?.trigger('click')
    await flushPromises()
    expect(button(wrapper, 'Compare')?.attributes('disabled')).toBeUndefined()
    // Choosing and comparing read; nothing was asked to write.
    expect(commandsCalled()).not.toContain('update_batch_apply')
  })

  it('lists packages in a fixed order and says what each group is', async () => {
    const { wrapper } = await compared()
    const headers = wrapper.findAll('.group-header').map((header) => header.text())
    expect(headers).toEqual(['Ready 2', 'Needs review 1', "Can't update 1", 'Up to date 1'])
    expect(wrapper.find('.status').text()).toBe(
      "2 ready · 1 needs review · 1 can't be updated · 1 up to date",
    )
    expect(button(wrapper, 'Update 2 resources')?.attributes('disabled')).toBeUndefined()
    // The up-to-date group is collapsed: there is nothing to do there.
    expect(wrapper.find('details.group-body').attributes('open')).toBeUndefined()
    // A row whose resource name alone would not say which package it is names the package.
    expect(wrapper.text()).toContain('delta.zip')
    expect(wrapper.text()).toContain('Not installed.')
    wrapper.unmount()
  })

  it('names what will be written first, and Back writes nothing', async () => {
    const { wrapper, store } = await compared()
    await button(wrapper, 'Update 2 resources')?.trigger('click')
    await flushPromises()
    const dialog = wrapper.find('[role="dialog"]')
    expect(dialog.text()).toContain('Update 2 resources?')
    expect(dialog.text()).toContain('alpha')
    expect(dialog.text()).toContain('beta')
    expect(dialog.text()).not.toContain('gamma')

    await button(dialog, 'Back')?.trigger('click')
    expect(store.confirming).toBe(false)
    expect(commandsCalled()).not.toContain('update_batch_apply')
    wrapper.unmount()
  })

  it('updates once and leaves each row where it was with its new state', async () => {
    const { wrapper } = await compared()
    await button(wrapper, 'Update 2 resources')?.trigger('click')
    await flushPromises()
    await button(wrapper.find('[role="dialog"]'), 'Update 2 resources')?.trigger('click')
    await flushPromises()

    expect(commandsCalled().filter((command) => command === 'update_batch_apply')).toHaveLength(1)
    const badges = wrapper.findAll('.status-badge').map((badge) => badge.text())
    expect(badges.filter((text) => text.includes('Updated'))).toHaveLength(2)
    expect(wrapper.text()).toContain('2 resources updated')
    expect(wrapper.text()).toContain('View in History')
    // It cannot be pressed twice: the button is gone once it has been used.
    expect(button(wrapper, 'Update 2 resources')).toBeUndefined()
    wrapper.unmount()
  })

  it('says plainly where a batch stopped and what was not tried', async () => {
    applyResults = [
      { id: 0, result: 'committed' },
      { id: 1, result: 'failed' },
      { id: 2, result: 'skipped' },
      { id: 3, result: 'skipped' },
      { id: 4, result: 'skipped' },
    ]
    const { wrapper } = await compared()
    await useBatchStore().apply()
    await flushPromises()
    expect(wrapper.text()).toContain('The batch stopped at beta')
    expect(wrapper.text()).toContain('1 resource was updated before it')
    const badges = wrapper.findAll('.status-badge').map((badge) => badge.text())
    expect(badges.some((text) => text.includes('Updated'))).toBe(true)
    expect(badges.some((text) => text.includes('Failed'))).toBe(true)
    wrapper.unmount()
  })

  it('still offers the review of a package that needs one after the others were updated', async () => {
    // What is left to do once the batch has run is exactly the packages it left for the operator,
    // so the way to them cannot go away with the button that ran the batch.
    const { wrapper, store } = await compared()
    await store.apply()
    await flushPromises()
    expect(store.results).toBeDefined()
    expect(wrapper.find('.row-extra a.text-link[href="#/"]').exists()).toBe(true)
    wrapper.unmount()
  })

  it('offers to close the finished updates after a batch, so the next one can go on', async () => {
    const { wrapper, store } = await compared()
    // The batch leaves its updates on record until the operator closes them.
    overview = { ...clear, disposition: 'attention_required', terminalEvidence: true }
    await store.apply()
    await flushPromises()
    expect(store.blocked).toBe('finishable')
    expect(wrapper.text()).toContain('Close finished updates')
    wrapper.unmount()
  })

  it('takes a package that needs an answer to the Update screen with both sides chosen', async () => {
    const { wrapper } = await compared()
    await wrapper.find('.row-extra a.text-link').trigger('click')
    await flushPromises()

    expect(invoke).toHaveBeenCalledWith('update_batch_open_package', {
      request: { handle: PLAN, id: 2 },
    })
    const update = useUpdateStore()
    // Selections of its own, so neither screen can release what the other is still using.
    expect(update.folder?.handle).toBe(OPENED_INSTALLED)
    expect(update.folder?.handle).not.toBe(INSTALLED)
    expect(update.package?.handle).toBe(OPENED)
    expect(push).toHaveBeenCalledWith('/')
    wrapper.unmount()
  })

  it('does not offer to update while an earlier update is on record, and says why', async () => {
    // Comparing is allowed while an earlier update is on record, but writing is not. The button
    // used to open a confirmation whose last step quietly did nothing.
    overview = { ...clear, disposition: 'attention_required', terminalEvidence: true }
    const { wrapper, store } = await compared()
    expect(store.blocked).toBe('finishable')
    expect(button(wrapper, 'Update 2 resources')?.attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('Close the finished update above')
    store.requestApply()
    expect(store.confirming).toBe(false)
    wrapper.unmount()
  })

  it('never leaves the confirmation open and silent when the workspace is not clear at apply time', async () => {
    const { wrapper, store } = await compared()
    store.requestApply()
    expect(store.confirming).toBe(true)

    // An earlier update lands on record after the confirmation was opened.
    overview = { ...clear, disposition: 'attention_required', terminalEvidence: true }
    const { useRecoveryStore } = await import('@/stores/recovery')
    useRecoveryStore().overviewPhase = 'unknown'
    await store.apply()
    await flushPromises()

    expect(store.confirming).toBe(false)
    expect(store.blocked).toBe('finishable')
    expect(commandsCalled()).not.toContain('update_batch_apply')
    expect(wrapper.text()).toContain('Close the finished update above')
    wrapper.unmount()
  })

  it('offers to close a finished update that is blocking, and compares again after', async () => {
    overview = { ...clear, disposition: 'attention_required', terminalEvidence: true }
    const { wrapper } = await compared()
    expect(wrapper.text()).toContain('An earlier update is finished but still open')
    await button(wrapper, 'Close finished updates')?.trigger('click')
    await flushPromises()
    expect(commandsCalled()).toContain('update_recovery_retire_terminal')
    expect(commandsCalled().filter((command) => command === 'update_batch_plan')).toHaveLength(2)
    wrapper.unmount()
  })
})

describe('the batch decoders', () => {
  it('refuse a plan whose ready count disagrees with its rows', () => {
    expect(() => decodeBatchPlanResponse({ ...plan, readyCount: 1 })).toThrow()
  })

  it('refuse an entry kind they do not know', () => {
    expect(() =>
      decodeBatchPlanResponse({ ...plan, entries: [entry(0, 'alpha', 'overwrite_everything')], readyCount: 0 }),
    ).toThrow()
  })

  it('refuse a result count that disagrees with its results', () => {
    expect(() =>
      decodeBatchApplyResponse({ results: [{ id: 0, result: 'failed' }], committedCount: 1 }),
    ).toThrow()
  })

  it('read the plan the backend sends', () => {
    const decoded = decodeBatchPlanResponse(plan)
    expect(decoded.entries).toHaveLength(5)
    expect(decoded.readyCount).toBe(2)
  })
})
