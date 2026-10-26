# Contributing

Issues and pull requests are welcome.

This tool writes to directories people care about, and the thing that makes it worth using is
that it does not lose their work. Most of what follows is about keeping that true.

## The rules the codebase is held to

**Where the logic lives**

* Every decision about the filesystem belongs in `crates/gkrm-core`. The CLI and the desktop app
  are interfaces over it, and neither may contain update logic.
* The desktop Rust adapter stays a thin local adapter. The core remains the authority for
  validation, inspection, planning, staging, apply and recovery.
* The frontend never receives a trusted filesystem path, and never reaches the filesystem, a
  shell, the network, a dialog plugin or the clipboard on its own. Every call goes through the
  typed services in `apps/gkrm-desktop/src/services/tauri/`.

**Reading a resource**

* Never execute `fxmanifest.lua`. Parse only the structures the application needs.
* Treat an incoming ZIP as untrusted input. Reject absolute paths, parent-directory traversal,
  unsafe symlinks, and any write that would land outside staging.

**Changing an installation**

* Never modify the live installation while producing a plan.
* Build the complete proposed installation in staging before applying any of it.
* Create and verify a backup before the first write.
* Every mutating operation supports rollback.
* Preserve unknown customer-created files by default. A file missing from the package is not a
  file to delete.
* Do not silently resolve an ambiguous merge. An overlap is a conflict, and conflicts are
  reported rather than guessed at.

**Writing it down**

* Prefer explicit domain types over maps and strings.
* Return structured errors. Do not panic for an expected runtime failure.
* Avoid premature crate fragmentation.

## How files are classified

* Escrow-protected files not matched by `escrow_ignore` are replaced from the package.
* Files matched by `escrow_ignore` are editable, and are the operator's to decide about.
* Generated NUI output under known build directories is replaced as a unit.
* An editable text file changed by one side only keeps that side.
* An editable text file changed by both is merged when a baseline exists; overlapping changes are
  a conflict.
* Binary files are compared by hash and never text-merged.

## Tests

New behaviour needs tests, and so does the way it fails. The suites must cover at least ZIP
traversal and absolute-path rejection, manifest parsing, `escrow_ignore` expansion, protected and
editable classification, customer-only preservation, plan determinism, interrupted-transaction
recovery, and rollback restoring the original hash tree.

Use small synthetic fixtures and temporary directories. A test must never depend on a real FiveM
installation, and nothing real belongs in `fixtures/` — no commercial resources, no escrow
content, no customer data, no credentials.

Test-only hooks, injected faults and barriers are `#[cfg(test)]`, and are either thread-local with
an RAII `Drop` that restores, or serialised behind one guard that clears on drop. No
process-global counters another test can reset, and no sleeps to synchronise.

## Before you open a pull request

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

```bash
cargo test --workspace
```

```bash
npm --prefix apps/gkrm-desktop run test:unit
```

```bash
npm --prefix apps/gkrm-desktop run build
```

CI runs these too, along with the serial suites and the generated-output audits.

To look at the interface while you work on it:

```bash
npm --prefix apps/gkrm-desktop run dev:harness
```

That mounts the real screens against mocked IPC, so you can see and click through them without a
backend. It is never part of a build.

## Scope

Pull requests that add network access, telemetry, an auto-updater, a shell or filesystem plugin,
SQL execution, or anything that decrypts escrow content are out of scope and will be declined.
The product is local, offline, and works with escrow rather than around it.
