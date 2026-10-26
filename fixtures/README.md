# Fixtures

Only synthetic test fixtures belong here. Do not commit real GKSHOP commercial resources, escrow-protected files, customer installations, credentials, or production ZIP packages.

## Layout

```text
fixtures/
  installed/                     installation root passed to --installed
    gksphone/                    the installed resource
  packages/                      generated ZIPs passed to --package
    gksphone-official-v1.zip     previous official release (baseline source)
    gksphone-update.zip          incoming official release
  sources/                       plaintext trees the ZIPs are built from
    gksphone-v1/gksphone/
    gksphone-v2/gksphone/
  build-fixture-packages.ps1     rebuilds packages/ from sources/
```

The ZIPs are generated artifacts. Their contents are committed in plaintext under `sources/` so
the fixture data stays auditable, and `build-fixture-packages.ps1` regenerates the ZIPs with
forward-slash entry names and deterministic ordering:

```powershell
powershell -ExecutionPolicy Bypass -File fixtures/build-fixture-packages.ps1
```

## What the `gksphone` fixture exercises

The installed tree is official v1 plus customer changes, and `gksphone-update.zip` is official v2.
Each file covers one update case:

| File | Baseline v1 | Installed | Incoming v2 | Case |
| --- | --- | --- | --- | --- |
| `fxmanifest.lua` | v1 | v1 | v2 | protected file changed officially |
| `config.lua` | defaults | customer edited two values | one setting appended | editable file changed on both sides |
| `client/main.lua` | v1 | v1 | v2 | protected file changed officially |
| `client/custom.lua` | placeholder | customer edited | unchanged placeholder | customer edit that must survive |
| `client/new_feature.lua` | absent | absent | present | new official file |
| `server/main.lua` | v1 | v1 | v1 | unchanged |
| `data/customer_notes.txt` | absent | present | absent | customer-owned file that must not be deleted |

`config.lua` is the case the product exists for: the customer's `Locale` and `MaxContacts` edits and
the official `EnableVoiceMail` addition must both survive the same update.
