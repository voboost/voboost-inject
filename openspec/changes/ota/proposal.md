## Why

The `ota` spec describes self-update for a single daemon ELF (appended-sig
`VOBSIG1`) and agents shipped as `.js` inside the app APK. Two things change
with the ptrace migration:

1. **The inject update is no longer one file.** The daemon ELF is still one
   appended-sig file, but it is now accompanied by a native payload —
   `libimplant.so`, `liblsplant.so`, `liblsplt.so`, `libdobby.a` per ABI
   (see `native-payload`). These ride with the daemon release, not the app
   APK, and the self-update must swap them atomically alongside the ELF. The
   existing "single appended-sig ELF" requirement is true for the daemon
   binary but no longer describes the whole inject update.
2. **Agents are `.dex`, not `.js`.** The hooking layer moved from frida's
   QuickJS to LSPlant inside the JVM (see `native-payload`), so agents ship as
   `.dex` and load via `InMemoryDexClassLoader`. The OTA carrier channel is
   unchanged (agents are still app-APK assets, still staged by the app, still
   verified against the agent manifest); only the artifact format changes.

The self-update flow (staging → verify → preserve `.prev` → atomic swap →
marker → SIGTERM → init-restart → confirm/rollback) is language- and
artifact-agnostic and carries over. This change extends it to cover the
multi-file payload and restates the agent format.

## What Changes

- **MODIFIED**:
  - "Two APKs, app-owned OTA client, daemon-owned core self-update" — the
    daemon self-update now covers the daemon ELF *and* the native payload
    files; the app stages all `inject`-channel files, not just the ELF.
  - "Re-verify the staged APK's embedded manifest before self-replace" —
    re-verify now covers the ELF (appended signature, unchanged) *and* the
    payload files (sha256 against the verified release manifest — see
    `trust-verification`, `release-manifest`).
  - "Apply a staged core APK update before the first injection" — the staged
    update now includes the payload files; the first injection uses the new
    ELF *and* the new payload.
  - "Inject payload is a single appended-sig ELF" — restated: the daemon
    binary is a single appended-sig ELF; the *full inject update* is the ELF
    plus the per-ABI native payload files, whose integrity comes from the
    release manifest.
- **Unchanged**: "Consume the core-update-ready marker before the apply",
  "Atomic self-replace with .prev rollback", "Core rollback on a degraded
  restart", "Boot recovery of the daemon manifest", "Never end up broken",
  "Release manifest lists APKs", "Release-manifest size and entry bounds",
  "Persistence across a system OTA". The staging/marker/rollback machinery is
  artifact-agnostic.

## Capabilities

### Modified Capabilities

- `ota`: the inject self-update is extended from a single daemon ELF to the
  ELF plus the per-ABI native payload files. Re-verification covers the ELF
  (appended signature) and the payload (sha256 via the release manifest). The
  staged update is applied before the first injection so the first injection
  uses the new ELF and payload. Agents ship as `.dex` (same carrier channel,
  same agent-manifest verification). The staging/marker/rollback flow is
  unchanged.
