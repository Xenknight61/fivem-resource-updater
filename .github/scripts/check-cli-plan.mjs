// Assert the per-file dispositions the release checklist requires from `gkrm plan`.
// `config.lua` keeping the customer's edits is the product's core promise, so a drift in these
// recommendations should fail the gate rather than be noticed during a manual run.
import { readFileSync } from 'node:fs'

const [source] = process.argv.slice(2)
if (!source) {
  console.error('usage: check-cli-plan.mjs <plan.json>')
  process.exit(2)
}

const plan = JSON.parse(readFileSync(source, 'utf8'))

const expected = {
  'config.lua': 'merge_candidate',
  'client/custom.lua': 'merge_candidate',
  'client/main.lua': 'replace_candidate',
  'client/new_feature.lua': 'add_candidate',
  'data/customer_notes.txt': 'preserve',
  'fxmanifest.lua': 'replace_candidate',
}

const files = (plan.resources ?? []).flatMap((resource) => resource.files ?? [])
if (files.length === 0) {
  console.error('the plan reported no files; the fixture or the JSON schema changed')
  process.exit(1)
}

const failures = []
for (const [path, want] of Object.entries(expected)) {
  const got = files.find((file) => file.path === path)?.disposition
  if (got !== want) {
    failures.push(`${path}: expected ${want}, got ${got ?? '(absent)'}`)
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure)
  process.exit(1)
}

console.log(`CLI plan dispositions match the release checklist (${files.length} files).`)
