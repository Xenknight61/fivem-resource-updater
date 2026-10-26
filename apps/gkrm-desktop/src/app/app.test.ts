import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Pinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import AppLayout from '@/layouts/AppLayout.vue'
import App from '@/App.vue'
import { router } from '@/router'
import { useAppStore } from '@/stores/app'
import { useScanStore } from '@/stores/scan'
import { useSessionStore } from '@/stores/session'
import { useRecoveryStore } from '@/stores/recovery'

const invoke = vi.hoisted(() => vi.fn(async (command: string) => {
  if (command === 'app_get_info') {
    return {
      schemaVersion: 1,
      appVersion: '1.0.0',
      coreVersion: '1.0.0',
      platform: 'windows',
      buildProfile: 'debug',
    }
  }
  if (command === 'update_recovery_overview') {
    return {
      disposition: 'clear', activeRecovery: false, terminalEvidence: false,
      manualAttention: false, unsupportedEvidence: false,
    }
  }
  if (command === 'select_installed_root') {
    return {
      cancelled: false,
      selection: { handle: '123e4567-e89b-42d3-a456-426614174000', kind: 'installedRoot', displayLabel: 'resources' },
    }
  }
  if (command === 'select_package_file') {
    return { cancelled: true }
  }
  if (command === 'session_list_selections') {
    return {
      selections: [{ handle: '123e4567-e89b-42d3-a456-426614174000', kind: 'installedRoot', displayLabel: 'resources' }],
    }
  }
  if (command === 'session_release_selection') {
    return { released: true }
  }
  if (command === 'scan_installed_root') {
    return {
      scanHandle: '123e4567-e89b-42d3-a456-426614174010',
      sourceKind: 'installedRoot',
      summary: {
        sourceKind: 'installedRoot',
        sourceLabel: 'resources',
        resourceCount: 1,
        warningCount: 0,
        totalFileCount: 2,
        totalBytes: 12,
      },
    }
  }
  if (command === 'scan_list_resources') {
    return {
      total: 1,
      offset: 0,
      limit: 25,
      resources: [
        {
          resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
          sourceKind: 'installedRoot',
          displayName: 'phone',
          status: 'available',
          fileCount: 2,
          totalBytes: 12,
          warningCount: 0,
        },
      ],
    }
  }
  if (command === 'scan_get_resource_detail') {
    return {
      resource: {
        resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
        sourceKind: 'installedRoot',
        displayName: 'phone',
        status: 'available',
        manifest: {
          kind: 'fxmanifest',
          clientScriptCount: 0,
          serverScriptCount: 0,
          sharedScriptCount: 0,
          dataFileCount: 0,
          hasUiPage: false,
        },
        escrow: {
          state: 'notAvailable',
          protectedFileCount: 0,
          ignoredFileCount: 0,
          unsupportedFileCount: 0,
        },
        statistics: { fileCount: 2, totalBytes: 12 },
        findings: [],
        omittedFindingCount: 0,
      },
    }
  }
  if (command === 'scan_release') {
    return { released: true }
  }
  throw {
    code: 'internal',
    category: 'internal',
    message: 'The desktop adapter failed.',
    recoverable: false,
  }
}))
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

const productionSourceRoot = join(process.cwd(), 'src')
const obsoleteProductCopy = [
  'LOCAL DESKTOP SHELL',
  'Desktop foundation',
  'Inspection and update workflows are intentionally not available in Task 27.',
  'READ-ONLY UPDATE REVIEW',
  'Create read-only plan',
  'Persistent configuration is intentionally not part of the Task 27 local desktop shell.',
]

function productionFrontendFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name)
    if (statSync(path).isDirectory()) return productionFrontendFiles(path)
    if ((!path.endsWith('.ts') && !path.endsWith('.vue')) || path.endsWith('.test.ts')) return []
    return [path]
  })
}

describe('desktop shell', () => {
  let pinia: Pinia

  beforeEach(async () => {
    invoke.mockClear()
    pinia = createPinia()
    setActivePinia(pinia)
    await router.push('/history')
    await router.isReady()
  })

  function mountShell() {
    return mount(AppLayout, {
      global: {
        plugins: [router, pinia],
      },
    })
  }


  it('renders product routes with one primary heading and active navigation', async () => {
    const wrapper = mountShell()

    for (const path of ['/', '/history', '/about']) {
      await router.push(path)
      await flushPromises()
      expect(wrapper.text()).toContain('Resource Manager')
      expect(wrapper.find('[aria-current="page"]').exists()).toBe(true)
      expect(wrapper.findAll('h1')).toHaveLength(1)
    }
  })

  it('uses About navigation, redirects legacy Settings, and omits build metadata from chrome', async () => {
    const wrapper = mountShell()
    expect(wrapper.find('nav').text()).toContain('About')
    expect(wrapper.find('nav').text()).not.toContain('Settings')
    expect(wrapper.text()).not.toContain('release · windows')
    expect(wrapper.text()).not.toContain('debug · windows')

    await router.push('/settings')
    await flushPromises()
    expect(router.currentRoute.value.path).toBe('/about')
    expect(wrapper.find('[aria-current="page"]').text()).toContain('About')
    expect(wrapper.findAll('h1')).toHaveLength(1)
  })

  it('provides semantic shell landmarks and a skip link', () => {
    const wrapper = mountShell()
    expect(wrapper.find('nav').exists()).toBe(true)
    expect(wrapper.find('main#main-content').exists()).toBe(true)
    expect(wrapper.get('a.skip-link').attributes('href')).toBe('#main-content')
  })

  it('announces a workflow error once even when it is also the global error', async () => {
    // The console reports workflow errors beside the control that produced them. The frame must
    // not repeat the same failure, or a screen reader reads one problem as two.
    const error = {
      code: 'recovery_evidence_invalid' as const,
      category: 'filesystem' as const,
      message: 'Recovery evidence could not be read.',
      recoverable: true,
    }
    const recovery = useRecoveryStore()
    recovery.error = error
    recovery.overviewPhase = 'ready'
    recovery.overview = {
      disposition: 'attention_required', activeRecovery: true, terminalEvidence: false,
      manualAttention: false, unsupportedEvidence: false,
    }
    useAppStore().setError(error)
    const wrapper = mountShell()
    await flushPromises()

    expect(wrapper.findAll('[role="alert"]')).toHaveLength(1)
    expect(wrapper.text()).toContain(error.message)
  })

  it('still announces a global error no screen is showing', async () => {
    useAppStore().setError({
      code: 'internal',
      category: 'internal',
      message: 'The desktop adapter failed.',
      recoverable: false,
    })
    const wrapper = mountShell()
    await flushPromises()

    expect(wrapper.findAll('[role="alert"]')).toHaveLength(1)
    expect(wrapper.text()).toContain('The desktop adapter failed.')
  })

  it('keeps rendered and production frontend source free of obsolete product copy', () => {
    const wrapper = mountShell()
    const sourceOffenders = productionFrontendFiles(productionSourceRoot).filter((path) =>
      obsoleteProductCopy.some((copy) => readFileSync(path, 'utf8').toLowerCase().includes(copy.toLowerCase())) ||
      /Task\s*(27|28|29|30|31)/i.test(readFileSync(path, 'utf8')),
    )

    for (const copy of obsoleteProductCopy) {
      expect(wrapper.text().toLowerCase()).not.toContain(copy.toLowerCase())
    }
    expect(wrapper.text()).not.toMatch(/Task\s*(27|28|29|30|31)/i)
    expect(sourceOffenders.map((path) => relative(productionSourceRoot, path))).toEqual([])
  })

  it('renders all routes without raw path state in the shell', async () => {
    const wrapper = mount(AppLayout, {
      global: {
        plugins: [router, pinia],
      },
    })

    for (const path of ['/', '/console', '/about']) {
      await router.push(path)
      await flushPromises()
      expect(wrapper.text()).not.toContain('C:\\')
    }
  })

  it('initializes app info and exposes global error dismissal', async () => {
    const store = useAppStore()
    await store.initialize()
    expect(store.info?.platform).toBe('windows')
    store.setError({ code: 'internal', category: 'internal', message: 'The desktop adapter failed.', recoverable: false })
    expect(store.error).not.toBeNull()
    store.dismissError()
    expect(store.error).toBeNull()
  })

  it('starts recovery truth unknown and performs the path-free overview on frontend startup', async () => {
    const recovery = useRecoveryStore()
    expect(recovery.overviewPhase).toBe('unknown')
    mount(App, { global: { plugins: [router, pinia] } })
    await flushPromises()
    expect(recovery.overviewIsClear).toBe(true)
    expect(invoke).toHaveBeenCalledWith('update_recovery_overview', {})
  })

  it('reports the workspace state on the history screen, worst first', async () => {
    // Saying "one update is waiting to be closed" while something needs manual attention would
    // tell the operator the workspace is closer to usable than it is.
    const recovery = useRecoveryStore()
    recovery.$reset()
    recovery.overviewPhase = 'ready'
    recovery.overview = {
      disposition: 'attention_required',
      activeRecovery: true,
      terminalEvidence: true,
      manualAttention: true,
      unsupportedEvidence: false,
    }
    await router.push('/history')
    const wrapper = mountShell()
    await flushPromises()

    expect(wrapper.text()).toContain('needs a person to look at it')
    expect(wrapper.text()).not.toContain('still on record')
  })

  it('says so plainly when nothing is outstanding', async () => {
    const recovery = useRecoveryStore()
    recovery.$reset()
    recovery.overviewPhase = 'ready'
    recovery.overview = {
      disposition: 'clear', activeRecovery: false, terminalEvidence: false,
      manualAttention: false, unsupportedEvidence: false,
    }
    await router.push('/history')
    const wrapper = mountShell()
    await flushPromises()

    expect(wrapper.text()).toContain('Nothing outstanding')
  })

  it('handles selection success, cancellation, listing, release and loading flags', async () => {
    const store = useSessionStore()
    await store.chooseInstalledRoot()
    expect(store.selections).toHaveLength(1)
    expect(JSON.stringify(store.$state)).not.toContain('C:\\')
    await store.choosePackageFile()
    await store.listSelections()
    await store.releaseSelection(store.selections[0]?.handle ?? '')
    expect(store.loading.release).toBe(false)
  })

  it('chooses an installed folder for history without exposing path state', async () => {
    // The folder is only asked for when there is actually something to recover.
    const recovery = useRecoveryStore()
    recovery.$reset()
    recovery.overviewPhase = 'ready'
    recovery.overview = {
      disposition: 'attention_required', activeRecovery: true, terminalEvidence: false,
      manualAttention: false, unsupportedEvidence: false,
    }
    const wrapper = mountShell()
    await flushPromises()

    await wrapper.findAll('button').find((b) => b.text().startsWith('Choose folder'))?.trigger('click')
    await flushPromises()
    await wrapper.findAll('button').find((b) => b.text() === 'Read folder')?.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('phone')
    expect(wrapper.text()).not.toContain('C:\\')
    // The install root's own label is safe to show; the trusted path behind it never is.
    expect(JSON.stringify(useSessionStore().$state)).not.toContain('C:\\')
  })
})
