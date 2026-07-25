## Why

The `ci-release` spec publishes the signed inject payload (appended-sig ELF)
plus the release manifest and its signature. The inject payload is now a set
of files — the daemon ELF *and* the per-ABI native payload (`libimplant.so`,
`liblsplant.so`, `liblsplt.so`, `libdobby.a`) — listed in the release manifest
(see `release-manifest`). The release artifacts must include the payload
files, not just the ELF, or the OTA client has nothing to stage for the
payload half of the update.

## What Changes

- **MODIFIED**:
  - "Publish signed release artifacts" — CI stages the signed daemon ELF
    *and* the per-ABI native payload files, alongside the release manifest and
    its detached signature. The payload files are release artifacts, not build
    intermediates.
- **Unchanged**: "No CI daemon manifest step" (the per-agent manifest is still
  app-owned; the inject payload carries no per-agent manifest).

## Capabilities

### Modified Capabilities

- `ci-release`: the published release artifacts now include the per-ABI native
  payload files alongside the signed daemon ELF, the release manifest, and its
  signature, so the OTA client can stage the full inject update.
