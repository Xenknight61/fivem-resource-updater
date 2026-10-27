// Collect the licence notices of everything that ships inside the binaries.
//
// Distributing a build means distributing its dependencies, and MIT, Apache-2.0, BSD and the
// rest ask that their copyright notices travel with it. This writes one file that carries them.
//
// Only what actually ships is listed: the Rust crates reachable through normal dependencies
// from the workspace members, and the npm packages that survive into the frontend bundle.
// Development and build-time dependencies are not in the product and are not listed.
//
//   node .github/scripts/generate-third-party-notices.mjs > THIRD-PARTY-NOTICES.txt

import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Resolved from this file, so the script works whatever directory it is run from. */
const repoRoot = fileURLToPath(new URL('../..', import.meta.url))

const LICENCE_FILE = /^(licen[cs]e|copying|notice)([-_.].*)?$/i

function run(command, args, cwd = repoRoot) {
  return execFileSync(command, args, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'inherit'],
  })
}

/** The licence texts a package ships beside its manifest, in filename order. */
function licenceTexts(packageDir) {
  if (!packageDir || !existsSync(packageDir)) return []
  return readdirSync(packageDir)
    .filter((entry) => LICENCE_FILE.test(entry))
    .filter((entry) => {
      try {
        return statSync(join(packageDir, entry)).isFile()
      } catch {
        return false
      }
    })
    .sort()
    .map((entry) => readFileSync(join(packageDir, entry), 'utf8').replace(/\r\n/g, '\n').trim())
    .filter((text) => text.length > 0)
}

/**
 * Crates reachable from the workspace members through normal dependencies only.
 *
 * `cargo metadata` lists every package the lockfile knows, development and build-time ones
 * included. Those are not in the product, so the resolve graph is walked instead and only the
 * edges that are neither dev nor build are followed.
 */
function rustPackages() {
  // Filtered to the target that is actually shipped and left on default features, so a crate
  // that only builds for another platform, or only under a feature this does not enable, is not
  // claimed to be in the product.
  const metadata = JSON.parse(
    run('cargo', [
      'metadata',
      '--format-version',
      '1',
      '--filter-platform',
      'x86_64-pc-windows-msvc',
    ]),
  )
  const byId = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]))
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]))
  const members = new Set(metadata.workspace_members)

  const shipped = new Set()
  const queue = [...members]
  while (queue.length > 0) {
    const id = queue.pop()
    if (shipped.has(id)) continue
    shipped.add(id)
    for (const dep of nodes.get(id)?.deps ?? []) {
      const kinds = dep.dep_kinds ?? []
      // A null kind is an ordinary dependency; "dev" and "build" never reach the binary.
      if (!kinds.some((entry) => entry.kind === null || entry.kind === undefined)) continue
      queue.push(dep.pkg)
    }
  }

  return [...shipped]
    .filter((id) => !members.has(id))
    .map((id) => byId.get(id))
    .filter(Boolean)
    .map((pkg) => ({
      name: pkg.name,
      version: pkg.version,
      licence: pkg.license ?? pkg.license_file ?? 'see the texts below',
      origin: pkg.repository ?? '',
      texts: licenceTexts(dirname(pkg.manifest_path)),
    }))
}

/**
 * npm packages that survive into the frontend bundle: production dependencies only.
 *
 * Read from the lockfile rather than by asking npm, because `npm ci` installs exactly what the
 * lockfile names and because Node on Windows cannot spawn `npm.cmd` without a shell. Entries
 * that exist only for development carry `dev: true` and are not in the product.
 */
function npmPackages(appDir) {
  // The lockfile names the packages, but their licence texts are only on disk once they are
  // installed. Without that, every entry below would resolve to nothing and the notices would
  // come out missing the whole frontend -- silently, and for a file that exists to satisfy a
  // licence obligation. So this stops instead.
  if (!existsSync(join(appDir, 'node_modules'))) {
    throw new Error(
      `${join(appDir, 'node_modules')} is not there, so no npm licence text can be read; ` +
        'run `npm ci` in apps/gkrm-desktop first',
    )
  }

  const lock = JSON.parse(readFileSync(join(appDir, 'package-lock.json'), 'utf8'))
  const paths = Object.entries(lock.packages ?? {})
    .filter(([path, entry]) => path.startsWith('node_modules/') && entry.dev !== true)
    .map(([path]) => join(appDir, path))

  const packages = [...new Set(paths)]
    .map((dir) => {
      const manifest = join(dir, 'package.json')
      // A production entry can legitimately be absent: the lockfile names optional packages for
      // every platform, and npm installs only the ones this one needs. What is not installed is
      // not in the product.
      if (!existsSync(manifest)) return null
      const pkg = JSON.parse(readFileSync(manifest, 'utf8'))
      const licence =
        typeof pkg.license === 'string' ? pkg.license : (pkg.license?.type ?? 'see the texts below')
      return {
        name: pkg.name,
        version: pkg.version,
        licence,
        origin: typeof pkg.repository === 'string' ? pkg.repository : (pkg.repository?.url ?? ''),
        texts: licenceTexts(dir),
      }
    })
    .filter(Boolean)

  if (paths.length > 0 && packages.length === 0) {
    throw new Error(
      `the lockfile names ${paths.length} production packages and none of them is installed ` +
        'under node_modules; run `npm ci` in apps/gkrm-desktop first',
    )
  }

  return packages
}

function section(title, packages) {
  const lines = [title, '='.repeat(title.length), '']
  for (const pkg of packages.sort((a, b) => a.name.localeCompare(b.name))) {
    lines.push(`${pkg.name} ${pkg.version} — ${pkg.licence}`)
    if (pkg.origin) lines.push(`    ${pkg.origin.replace(/^git\+/, '').replace(/\.git$/, '')}`)
  }
  lines.push('')
  return lines.join('\n')
}

/** Every distinct licence text, once, with the packages that carry it. */
function texts(all) {
  const byText = new Map()
  for (const pkg of all) {
    for (const text of pkg.texts) {
      if (!byText.has(text)) byText.set(text, new Set())
      byText.get(text).add(`${pkg.name} ${pkg.version}`)
    }
  }
  const lines = ['Licence texts', '=============', '']
  const entries = [...byText.entries()].sort((a, b) =>
    [...a[1]][0].localeCompare([...b[1]][0]),
  )
  for (const [text, packages] of entries) {
    lines.push('-'.repeat(78))
    lines.push(`For: ${[...packages].sort().join(', ')}`)
    lines.push('-'.repeat(78))
    lines.push('')
    lines.push(text)
    lines.push('')
  }
  const missing = all.filter((pkg) => pkg.texts.length === 0)
  if (missing.length > 0) {
    lines.push('-'.repeat(78))
    lines.push('These ship no licence file of their own; the licence named above each is the')
    lines.push('one its manifest declares.')
    lines.push('-'.repeat(78))
    lines.push('')
    for (const pkg of missing.sort((a, b) => a.name.localeCompare(b.name))) {
      lines.push(`  ${pkg.name} ${pkg.version} — ${pkg.licence}`)
    }
    lines.push('')
  }
  return lines.join('\n')
}

const rust = rustPackages()
const npm = npmPackages(join(repoRoot, 'apps/gkrm-desktop'))
const all = [...rust, ...npm]

process.stdout.write(
  [
    'Third-party notices',
    '===================',
    '',
    'FiveM Resource Updater is MIT licensed; see LICENSE. It is built from the components',
    'listed here, each under its own licence, and their notices are reproduced below as those',
    'licences ask.',
    '',
    `${rust.length} Rust crates and ${npm.length} npm packages reach the product. Development and`,
    'build-time dependencies are not listed because they are not in it.',
    '',
    'Components under the Mozilla Public License 2.0 are used unmodified. Their source is',
    'available from the origin given beside each, and from the MPL itself.',
    '',
    section('Rust crates', rust),
    section('npm packages', npm),
    texts(all),
  ].join('\n'),
)
