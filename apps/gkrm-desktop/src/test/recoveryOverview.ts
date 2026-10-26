import { useRecoveryStore } from '@/stores/recovery'

export function establishClearRecoveryOverview(): void {
  const recovery = useRecoveryStore()
  recovery.overviewPhase = 'ready'
  recovery.overview = {
    disposition: 'clear',
    activeRecovery: false,
    terminalEvidence: false,
    manualAttention: false,
    unsupportedEvidence: false,
  }
  recovery.overviewError = undefined
}
