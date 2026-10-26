import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

import { describe, expect, it } from 'vitest'

const root = process.cwd()
const srcRoot = join(root, 'src')

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}

function isAuditedSource(path: string): boolean {
  if (!path.endsWith('.ts') && !path.endsWith('.vue')) return false
  return !path.endsWith('.test.ts')
}

describe('frontend source security audit', () => {
  it('imports tauri core only from typed tauri services', () => {
    const offenders = files(srcRoot).filter((path) => {
      if (!isAuditedSource(path)) return false
      const rel = relative(srcRoot, path).replaceAll('\\', '/')
      const text = readFileSync(path, 'utf8')
      return text.includes('@tauri-apps/api/core') && !rel.startsWith('services/tauri/')
    })
    expect(offenders).toEqual([])
  })

  it('does not use browser network APIs or frontend tauri plugins', () => {
    const forbidden = [
      'fetch(',
      'XMLHttpRequest',
      'WebSocket',
      'EventSource',
      'navigator.sendBeacon',
      '@tauri-apps/plugin-dialog',
      '@tauri-apps/plugin-fs',
      '@tauri-apps/plugin-shell',
      '@tauri-apps/plugin-http',
      '@tauri-apps/plugin-opener',
    ]
    const offenders = files(srcRoot).flatMap((path) => {
      if (!isAuditedSource(path)) return []
      const text = readFileSync(path, 'utf8')
      return forbidden.filter((needle) => text.includes(needle)).map((needle) => `${relative(srcRoot, path)}:${needle}`)
    })
    expect(offenders).toEqual([])
  })

  it('keeps the presentation layer free of raw backend command names', () => {
    // Views and components must reach the backend only through the typed wrappers in
    // services/tauri. Test files are excluded here for the same reason as the audits above:
    // they are not shipped, and mocking IPC necessarily names the commands being mocked.
    const presentationRoots = [join(srcRoot, 'views'), join(srcRoot, 'components')]
    const offenders = presentationRoots.flatMap((dir) =>
      files(dir).flatMap((path) => {
        if (!isAuditedSource(path)) return []
        const text = readFileSync(path, 'utf8')
        return ['update_recovery_', 'update_plan_', 'scan_installed_root', 'inspect_package']
          .filter((needle) => text.includes(needle))
          .map((needle) => `${relative(srcRoot, path)}:${needle}`)
      }),
    )
    expect(offenders).toEqual([])
  })
})
