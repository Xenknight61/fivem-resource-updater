// The release checklist pins the installed dependency graph to the patched nanoid. `npm ci`
// installs exactly what the lockfile names, so the lockfile is read directly: it is
// deterministic, needs no subprocess, and reports every nanoid in the graph rather than only
// the one a tree view happens to print.
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const EXPECTED = '3.3.20'

const lockfile = fileURLToPath(
  new URL('../../apps/gkrm-desktop/package-lock.json', import.meta.url),
)
const lock = JSON.parse(readFileSync(lockfile, 'utf8'))

const installed = Object.entries(lock.packages ?? {})
  .filter(([path]) => path === 'node_modules/nanoid' || path.endsWith('/node_modules/nanoid'))
  .map(([path, entry]) => [path, entry.version])

if (installed.length === 0) {
  console.error('nanoid is absent from the lockfile; the pinned expectation is now stale')
  process.exit(1)
}

const unexpected = installed.filter(([, version]) => version !== EXPECTED)
if (unexpected.length > 0) {
  for (const [path, version] of unexpected) {
    console.error(`${path}: expected nanoid ${EXPECTED}, found ${version}`)
  }
  process.exit(1)
}

console.log(`Lockfile pins nanoid ${EXPECTED} (${installed.length} entry).`)
