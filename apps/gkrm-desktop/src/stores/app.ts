import { defineStore } from 'pinia'

import { appGetInfo, asDesktopError } from '@/services/tauri/client'
import type { AppInfo, DesktopError } from '@/types/commands'

interface AppState {
  info: AppInfo | null
  initializing: boolean
  error: DesktopError | null
}

export const useAppStore = defineStore('app', {
  state: (): AppState => ({
    info: null,
    initializing: false,
    error: null,
  }),
  actions: {
    async initialize() {
      if (this.initializing || this.info) return
      this.initializing = true
      try {
        this.info = await appGetInfo()
      } catch (error) {
        this.error = asDesktopError(error)
      } finally {
        this.initializing = false
      }
    },
    setError(error: DesktopError) {
      this.error = error
    },
    dismissError() {
      this.error = null
    },
  },
})
