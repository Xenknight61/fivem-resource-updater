import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { describe, expect, it } from 'vitest'

import AboutView from './AboutView.vue'
import { useAppStore } from '@/stores/app'

describe('AboutView', () => {
  it('presents safe application metadata as structured product information', () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    const app = useAppStore()
    app.info = {
      schemaVersion: 1,
      appVersion: '1.0.0',
      coreVersion: '1.0.0',
      platform: 'windows',
      buildProfile: 'release',
    }

    const wrapper = mount(AboutView, { global: { plugins: [pinia] } })

    expect(wrapper.findAll('h1')).toHaveLength(1)
    expect(wrapper.text()).toContain('Application version')
    expect(wrapper.text()).toContain('Core version')
    expect(wrapper.text()).toContain('Windows')
    expect(wrapper.text()).toContain('Release build')
    expect(wrapper.findAll('dl.metadata-list')).toHaveLength(1)
    expect(wrapper.text()).not.toMatch(/C:\\|123e4567|sha256|capabilit/i)
  })
})
