const supported = {
  node: '>=22.18.0 <23',
  npm: '>=10 <12',
}

function parseVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-.+)?$/.exec(version)
  if (!match) return null
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  }
}

function atLeast(version, major, minor, patch) {
  if (version.major !== major) return version.major > major
  if (version.minor !== minor) return version.minor > minor
  return version.patch >= patch
}

function nodeSupported(version) {
  return version.major === 22 && atLeast(version, 22, 18, 0)
}

function npmSupported(version) {
  return version.major >= 10 && version.major < 12
}

const nodeVersion = parseVersion(process.versions.node)
if (!nodeVersion || !nodeSupported(nodeVersion)) {
  console.error(`Unsupported Node.js runtime. Supported range: ${supported.node}.`)
  process.exit(1)
}

const npmUserAgent = process.env.npm_config_user_agent ?? ''
const npmMatch = /npm\/(\d+\.\d+\.\d+)/.exec(npmUserAgent)
if (npmMatch) {
  const npmVersion = parseVersion(npmMatch[1])
  if (!npmVersion || !npmSupported(npmVersion)) {
    console.error(`Unsupported npm runtime. Supported range: ${supported.npm}.`)
    process.exit(1)
  }
}

console.log(`Runtime supported: Node ${process.versions.node}`)
