import { existsSync, readdirSync, rmdirSync, statSync, unlinkSync } from 'node:fs'
import { resolve, sep } from 'node:path'

const projectRoot = resolve(process.cwd())
const distRoot = resolve(projectRoot, 'dist')
const expectedDistRoot = resolve(projectRoot, 'dist')

if (distRoot !== expectedDistRoot || !distRoot.startsWith(`${projectRoot}${sep}`)) {
  console.error('Refusing to clean an unexpected dist path.')
  process.exit(1)
}

function removeTree(path) {
  const stat = statSync(path)
  if (!stat.isDirectory()) {
    unlinkSync(path)
    return
  }
  for (const name of readdirSync(path)) {
    removeTree(resolve(path, name))
  }
  rmdirSync(path)
}

if (existsSync(distRoot)) {
  removeTree(distRoot)
}

console.log('Cleaned desktop dist output.')
