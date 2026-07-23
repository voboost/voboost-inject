## Why

The `incremental-delta` spec describes OTA diffing by per-file sha256 and
re-verifying staged material. It references "the inject binary is large but
rarely updated" as the rationale for whole-file download. The inject update is
now multi-file (daemon ELF + per-ABI native payload — see `ota`,
`release-manifest`), so the diff and re-verify must cover the payload files
too, not just one binary. The mechanism (diff by sha256, download changed
files whole, re-verify staged material) is unchanged; only the file set it
operates over widens.

## What Changes

- **MODIFIED**:
  - "Diff by hash and download only changed files" — the diff covers all
    `inject`-channel files (daemon ELF + payload), so a payload-only update
    downloads only the changed `.so`/`.a` files, not the whole ELF.
  - "Download changed files whole" — the rationale updates: the inject update
    is now a set of files (ELF + per-ABI payload), each downloaded whole.
  - "Verify every fetched artifact and re-verify staged material" — the
    daemon re-verifies staged payload files' sha256 against the release
    manifest (in addition to the agent manifest), per `trust-verification`.
- **Unchanged**: "Reject downloads whose size disagrees with the manifest"
  (size guard is file-agnostic).

## Capabilities

### Modified Capabilities

- `incremental-delta`: the OTA diff and re-verify cover the full inject update
  (daemon ELF + per-ABI native payload files), not just one binary. The
  diff-by-sha256 and whole-file-download mechanisms are unchanged; the file
  set widens.
