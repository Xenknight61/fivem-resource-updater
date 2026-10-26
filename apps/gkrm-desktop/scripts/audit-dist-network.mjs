import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const distRoot = join(process.cwd(), 'dist')

const executablePatterns = [
  { name: 'fetch', pattern: /\bfetch\s*\(/ },
  { name: 'XMLHttpRequest', pattern: /\b(?:new\s+)?XMLHttpRequest\b/ },
  { name: 'WebSocket', pattern: /\b(?:new\s+)?WebSocket\b/ },
  { name: 'EventSource', pattern: /\b(?:new\s+)?EventSource\b/ },
  { name: 'navigator.sendBeacon', pattern: /\bnavigator\s*\.\s*sendBeacon\s*\(/ },
  { name: 'importScripts', pattern: /\bimportScripts\s*\(/ },
  { name: 'serviceWorker', pattern: /\bnavigator\s*\.\s*serviceWorker\b/ },
]

const remoteUrlPattern = /\b(?:https?:)?\/\/[^\s"'`<>]+/

function files(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? files(path) : [path]
  })
}

function stripNonExecutableText(source) {
  let output = ''
  let i = 0
  while (i < source.length) {
    const c = source[i]
    const next = source[i + 1]
    if (c === '/' && next === '/') {
      while (i < source.length && source[i] !== '\n') i += 1
      output += '\n'
    } else if (c === '/' && next === '*') {
      i += 2
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i += 1
      i += 2
      output += ' '
    } else if (c === '"' || c === "'" || c === '`') {
      const quote = c
      output += '""'
      i += 1
      while (i < source.length) {
        if (source[i] === '\\') {
          i += 2
        } else if (source[i] === quote) {
          i += 1
          break
        } else {
          i += 1
        }
      }
    } else {
      output += c
      i += 1
    }
  }
  return output
}

if (!existsSync(distRoot)) {
  console.error('dist/ is missing. Run npm run build before auditing generated output.')
  process.exit(1)
}

const offenders = []
for (const file of files(distRoot)) {
  if (file.endsWith('.map')) continue
  const rel = relative(distRoot, file).replaceAll('\\', '/')
  const text = readFileSync(file, 'utf8')
  const executable = file.endsWith('.js') ? stripNonExecutableText(text) : text
  if (remoteUrlPattern.test(executable)) offenders.push(`${rel}:remote-url`)
  if (!file.endsWith('.js')) continue
  for (const { name, pattern } of executablePatterns) {
    if (pattern.test(text)) offenders.push(`${rel}:${name}`)
  }
}

if (offenders.length > 0) {
  console.error(`Generated output contains forbidden browser networking: ${offenders.join(', ')}`)
  process.exit(1)
}

// The development harness answers every command with a fixture. Shipping it would be a build of
// the application that cannot touch a file and says an update succeeded anyway. Vite builds
// `index.html` alone, so it stays out by construction; this fails loudly if that ever changes.
const harness = []
for (const file of files(distRoot)) {
  const rel = relative(distRoot, file).replaceAll('\\', '/')
  if (rel.startsWith('dev/') || /harness/i.test(rel)) harness.push(rel)
  else if (!file.endsWith('.map') && readFileSync(file, 'utf8').includes('mockIPC')) {
    harness.push(`${rel}:mockIPC`)
  }
}

if (harness.length > 0) {
  console.error(`Generated output contains the development harness: ${harness.join(', ')}`)
  process.exit(1)
}

console.log('Generated output network audit passed.')
