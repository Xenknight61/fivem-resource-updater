import { existsSync, readdirSync, statSync } from 'node:fs'
import { basename, join, relative, resolve } from 'node:path'

const repoRoot = resolve(process.cwd(), '../..')
const roots = [
  join(repoRoot, 'target', 'release'),
  join(process.cwd(), 'src-tauri', 'target', 'release'),
].filter(existsSync)

const forbidden = [
  { name: 'bundle directory', matches: (path, isDir) => isDir && basename(path).toLowerCase() === 'bundle' },
  { name: 'msi installer', matches: (path) => path.toLowerCase().endsWith('.msi') },
  { name: 'setup exe', matches: (path) => basename(path).toLowerCase().endsWith('-setup.exe') },
  { name: 'nsis archive', matches: (path) => basename(path).toLowerCase().endsWith('.nsis.zip') },
  { name: 'appx package', matches: (path) => path.toLowerCase().endsWith('.appx') },
  { name: 'msix package', matches: (path) => path.toLowerCase().endsWith('.msix') },
  { name: 'dmg image', matches: (path) => path.toLowerCase().endsWith('.dmg') },
  { name: 'deb package', matches: (path) => path.toLowerCase().endsWith('.deb') },
  { name: 'rpm package', matches: (path) => path.toLowerCase().endsWith('.rpm') },
  { name: 'AppImage package', matches: (path) => path.endsWith('.AppImage') },
  { name: 'updater artifact', matches: (path) => basename(path).toLowerCase().includes('updater') },
]

function walk(path, findings) {
  const stat = statSync(path)
  for (const rule of forbidden) {
    if (rule.matches(path, stat.isDirectory())) {
      findings.push(`${relative(repoRoot, path).replaceAll('\\', '/')}:${rule.name}`)
    }
  }
  if (!stat.isDirectory()) return
  for (const name of readdirSync(path)) {
    walk(join(path, name), findings)
  }
}

const findings = []
for (const root of roots) {
  walk(root, findings)
}

if (findings.length > 0) {
  console.error(`Installer or bundle output detected: ${findings.join(', ')}`)
  process.exit(1)
}

console.log('No installer, bundle, or updater output detected.')
