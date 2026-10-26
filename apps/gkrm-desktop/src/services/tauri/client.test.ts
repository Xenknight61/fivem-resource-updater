import { beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  appGetInfo,
  asDesktopError,
  scanGetResourceDetail,
  scanInstalledRoot,
  scanListResources,
  sessionListSelections,
  updateRecoveryExecute,
  updateRecoveryListCandidates,
  updateRecoveryOverview,
  updateRecoveryRetireTerminal,
  updateRecoveryRelease,
  updateRecoveryStatus,
} from './client'

const invoke = vi.hoisted(() => vi.fn())
vi.mock('@tauri-apps/api/core', () => ({ invoke }))

function task29Fixture(name: string) {
  const path = join(process.cwd(), 'src', 'services', 'tauri', 'fixtures', 'task29', name)
  return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
}

describe('typed tauri client', () => {
  beforeEach(() => {
    invoke.mockReset()
  })

  it('decodes valid app info', async () => {
    invoke.mockResolvedValueOnce({
      schemaVersion: 1,
      appVersion: '0.1.0',
      coreVersion: '0.1.0',
      platform: 'linux',
      buildProfile: 'release',
    })
    await expect(appGetInfo()).resolves.toMatchObject({ platform: 'linux' })
  })

  it('normalizes malformed responses to generic errors', async () => {
    invoke.mockResolvedValueOnce({ schemaVersion: 2 })
    await expect(appGetInfo()).rejects.toMatchObject({
      desktopError: { code: 'internal', message: 'The desktop adapter failed.' },
    })
  })

  it('normalizes backend errors', async () => {
    invoke.mockRejectedValueOnce({
      code: 'selection_not_found',
      category: 'selection',
      message: 'The selection is not available.',
      recoverable: true,
    })
    try {
      await sessionListSelections()
    } catch (error) {
      expect(asDesktopError(error)).toMatchObject({ code: 'selection_not_found' })
    }

    invoke.mockRejectedValueOnce({
      code: 'baseline_package_changed',
      category: 'filesystem',
      message: 'The previous official package changed after it was inspected. Inspect it again before capturing the baseline.',
      recoverable: true,
    })
    try {
      await sessionListSelections()
    } catch (error) {
      expect(asDesktopError(error)).toEqual({
        code: 'baseline_package_changed',
        category: 'filesystem',
        message: 'The previous official package changed after it was inspected. Inspect it again before capturing the baseline.',
        recoverable: true,
      })
    }
  })

  it('rejects invalid request values before invocation', async () => {
    expect(() => sessionListSelections({ kind: 'bad' as never })).toThrowError(
      expect.objectContaining({
        desktopError: expect.objectContaining({ code: 'invalid_request' }),
      }),
    )
    expect(invoke).not.toHaveBeenCalledWith('session_list_selections', expect.anything())
  })

  it('decodes valid scan responses and rejects invalid pages', async () => {
    invoke.mockResolvedValueOnce({
      scanHandle: '123e4567-e89b-42d3-a456-426614174010',
      sourceKind: 'installedRoot',
      summary: {
        sourceKind: 'installedRoot',
        sourceLabel: 'resources',
        resourceCount: 0,
        warningCount: 0,
        totalFileCount: 0,
        totalBytes: 0,
      },
    })
    await expect(
      scanInstalledRoot({ selectionHandle: '123e4567-e89b-42d3-a456-426614174000' }),
    ).resolves.toMatchObject({ sourceKind: 'installedRoot' })

    expect(() =>
      scanListResources({
        scanHandle: '123e4567-e89b-42d3-a456-426614174010',
        offset: 0,
        limit: 0,
      }),
    ).toThrowError(expect.objectContaining({ desktopError: expect.objectContaining({ code: 'invalid_request' }) }))
  })

  it('rejects malformed handles in scan and resource responses without partial success', async () => {
    invoke.mockResolvedValueOnce({
      scanHandle: 'xxxxxxxx-xxxx-4xxx-axxx-xxxxxxxxxxxx',
      sourceKind: 'installedRoot',
      summary: {
        sourceKind: 'installedRoot',
        sourceLabel: 'resources',
        resourceCount: 0,
        warningCount: 0,
        totalFileCount: 0,
        totalBytes: 0,
      },
    })
    await expect(
      scanInstalledRoot({ selectionHandle: '123e4567-e89b-42d3-a456-426614174000' }),
    ).rejects.toMatchObject({ desktopError: { code: 'internal' } })

    invoke.mockResolvedValueOnce({
      total: 1,
      offset: 0,
      limit: 25,
      resources: [
        {
          resourceHandle: '123e4567-e89b-12d3-a456-426614174011',
          sourceKind: 'installedRoot',
          displayName: 'phone',
          status: 'available',
          fileCount: 1,
          totalBytes: 1,
          warningCount: 0,
        },
      ],
    })
    await expect(
      scanListResources({
        scanHandle: '123e4567-e89b-42d3-a456-426614174010',
        offset: 0,
        limit: 25,
      }),
    ).rejects.toMatchObject({ desktopError: { code: 'internal' } })

    invoke.mockResolvedValueOnce({
      resource: {
        resourceHandle: '123e4567-e89b-42d3-c456-426614174011',
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
        statistics: { fileCount: 1, totalBytes: 1 },
        findings: [],
        omittedFindingCount: 0,
      },
    })
    await expect(
      scanGetResourceDetail({
        scanHandle: '123e4567-e89b-42d3-a456-426614174010',
        resourceHandle: '123e4567-e89b-42d3-a456-426614174011',
      }),
    ).rejects.toMatchObject({ desktopError: { code: 'internal' } })
  })

  it('invokes the path-free overview and four resource-bound recovery commands', async () => {
    const selection = '123e4567-e89b-42d3-a456-426614174000'
    const scan = '123e4567-e89b-42d3-a456-426614174010'
    const resource = '123e4567-e89b-42d3-a456-426614174011'
    const recovery = '123e4567-e89b-42d3-a456-426614174050'
    const candidate = '123e4567-e89b-42d3-a456-426614174051'
    invoke
      .mockResolvedValueOnce({ disposition: 'attention_required', activeRecovery: true, terminalEvidence: false, manualAttention: false, unsupportedEvidence: false })
      .mockResolvedValueOnce({ recoveryHandle: recovery, resourceLabel: 'phone', status: 'recovery_required', candidateCount: 1 })
      .mockResolvedValueOnce({ candidates: [{ candidateHandle: candidate, resourceLabel: 'phone', state: 'recovery_required', recoverable: true, actionHint: 'recover' }] })
      .mockResolvedValueOnce({ outcome: 'recovery_still_required' })
      .mockResolvedValueOnce({ released: true })
    await updateRecoveryOverview()
    await updateRecoveryStatus({ installedSelectionHandle: selection, installedScanHandle: scan, installedResourceHandle: resource })
    await updateRecoveryListCandidates({ recoveryHandle: recovery })
    await updateRecoveryExecute({ recoveryHandle: recovery, candidateHandle: candidate })
    await updateRecoveryRelease({ recoveryHandle: recovery })
    expect(invoke.mock.calls.map(([command]) => command)).toEqual([
      'update_recovery_overview',
      'update_recovery_status',
      'update_recovery_list_candidates',
      'update_recovery_execute',
      'update_recovery_release',
    ])
    expect(invoke.mock.calls[0]).toEqual(['update_recovery_overview', {}])
  })

  it('rejects inconsistent or identity-bearing recovery overview responses', async () => {
    invoke.mockResolvedValueOnce({ disposition: 'clear', activeRecovery: true, terminalEvidence: false, manualAttention: false, unsupportedEvidence: false })
    await expect(updateRecoveryOverview()).rejects.toMatchObject({ desktopError: { code: 'internal' } })
    invoke.mockResolvedValueOnce({ disposition: 'attention_required', activeRecovery: false, terminalEvidence: true, manualAttention: false, unsupportedEvidence: false, transactionId: 'secret' })
    await expect(updateRecoveryOverview()).rejects.toMatchObject({ desktopError: { code: 'internal' } })
  })

  it('invokes explicit path-free terminal retirement and strictly decodes aggregates', async () => {
    invoke.mockResolvedValueOnce({
      retiredCount: 2,
      alreadyRetiredCount: 1,
    })
    await expect(updateRecoveryRetireTerminal({ acknowledged: true })).resolves.toEqual({
      retiredCount: 2,
      alreadyRetiredCount: 1,
    })
    expect(invoke).toHaveBeenCalledWith('update_recovery_retire_terminal', {
      request: { acknowledged: true },
    })
  })

  it('rejects missing intent and identity-bearing or inconsistent retirement responses', async () => {
    expect(() => updateRecoveryRetireTerminal({ acknowledged: false })).toThrowError(
      expect.objectContaining({ desktopError: expect.objectContaining({ code: 'invalid_request' }) }),
    )
    expect(invoke).not.toHaveBeenCalled()
    invoke.mockResolvedValueOnce({
      retiredCount: 1,
      alreadyRetiredCount: 0,
      transactionId: 'secret',
    })
    await expect(updateRecoveryRetireTerminal({ acknowledged: true })).rejects.toMatchObject({
      desktopError: { code: 'internal' },
    })
    invoke.mockResolvedValueOnce({
      retiredCount: 10_001,
      alreadyRetiredCount: 0,
    })
    await expect(updateRecoveryRetireTerminal({ acknowledged: true })).rejects.toMatchObject({
      desktopError: { code: 'internal' },
    })
  })

  it('rejects malformed and over-broad recovery responses', async () => {
    const recovery = '123e4567-e89b-42d3-a456-426614174050'
    invoke.mockResolvedValueOnce({ recoveryHandle: recovery, resourceLabel: 'phone', status: 'clear', candidateCount: 0, rawPath: 'C:\\secret' })
    await expect(updateRecoveryStatus({
      installedSelectionHandle: '123e4567-e89b-42d3-a456-426614174000',
      installedScanHandle: '123e4567-e89b-42d3-a456-426614174010',
      installedResourceHandle: '123e4567-e89b-42d3-a456-426614174011',
    })).rejects.toMatchObject({ desktopError: { code: 'internal' } })

    invoke.mockResolvedValueOnce({ candidates: new Array(9).fill({}) })
    await expect(updateRecoveryListCandidates({ recoveryHandle: recovery })).rejects.toMatchObject({
      desktopError: { code: 'internal' },
    })
  })

  it('rejects invalid recovery handles before IPC', () => {
    expect(() => updateRecoveryExecute({ recoveryHandle: 'invalid', candidateHandle: 'invalid' }))
      .toThrowError(expect.objectContaining({ desktopError: expect.objectContaining({ code: 'invalid_request' }) }))
    expect(() => updateRecoveryRelease({ recoveryHandle: '' }))
      .toThrowError(expect.objectContaining({ desktopError: expect.objectContaining({ code: 'invalid_request' }) }))
  })
})
