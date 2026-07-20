## Why

<!-- Design date: 2026-06-28. Supersedes the unapplied `ota` change (file-level
     incremental core-update + agent manifest-swap). Aligns voboost-inject with
     the APK-level core self-update contract agreed with the sibling voboost
     app repo (`ota-client` change). -->

Voboost ships as **two APKs**: `voboost` (the app, release-manifest channel
`app`) and `voboost-inject` (the root daemon, channel `core`). The voboost app
owns the OTA client: it fetches a signed release manifest, compares versions,
downloads the newer APK(s) whole, verifies each (size + sha256), and applies
per channel. For the `app` channel it installs its own APK; for the `core`
channel it **never** installs the daemon — it stages the verified daemon APK
into the app-zone `staging/` directory and creates a single-use
`core-update-ready` marker as the last atomic step.

The previous `ota` change designed a **file-level** core update (the app
downloaded the raw daemon binary + a signed release manifest, and the daemon
installed it content-addressed and repointed a symlink) plus a runtime agent
manifest-swap. That design is obsolete: under the APK-level contract the daemon
APK is the atomic update unit, the daemon's per-agent `manifest.json`+`.sig` is
**build-time inside the daemon APK** (not runtime-produced by the client), and
agents ride inside the APK and are applied at VERIFY_SELF from the APK's
embedded manifest. This change replaces the file-level design with APK-level
core self-update owned entirely by the daemon.

## What Changes

- **Remove** the file-level core update: `apply_core_update` (content-addressed
  `voboost-inject-<sha>` install + symlink repoint), the `core_switch_pending`/
  `confirm_core_switch`/`rollback_core_switch` symlink-based rollback, and the
  `release-manifest.json`-driven core sha256 lookup. The release manifest is no
  longer consumed by the daemon at apply time (the app already verified the APK
  size+sha256 against it before staging).
- **Remove** the runtime agent manifest-swap: `apply_agent_update` (staged
  `manifest.json`+agents + atomic `manifest.json.prev` swap). Agents now ride
  inside the daemon APK; their `manifest.json`+`manifest.sig` is build-time
  inside the APK and is verified by the daemon at VERIFY_SELF against
  `EMBEDDED_PUBKEY`. There is no runtime agent plane.
- **Remove** the `update-ready` marker (it was the file-level "complete staged
  set" signal for both planes). The single remaining marker is
  `core-update-ready` (core-only, single-use).
- **Add** APK-level core self-update: `apply_core_apk_update(staging_dir)` —
  observe the `core-update-ready` marker (consume it first, single-use), find
  the staged daemon APK in `staging/`, re-verify its **embedded**
  `manifest.json`+`manifest.sig` against `EMBEDDED_PUBKEY` (the APK itself is
  Android-signed, but the daemon trusts the embedded manifest, not the APK
  v2/v3 signature), extract the daemon ELF binary from the APK, atomically
  self-replace `/data/voboost/voboost-inject` (keeping the previous binary as
  `voboost-inject.prev`), set the `core-switch-pending` marker, and exit so
  init restarts the new binary. On a DEGRADED restart, restore from
  `voboost-inject.prev`.
- **Keep**: `ReleaseManifest`/`ReleaseFile`/`verify_release_manifest` (the
  release-manifest verify primitive, still used by `make release-manifest` and
  host tests), `manifest_verifies`, `recover_manifest`, `TrustStore` usage,
  and `EMBEDDED_PUBKEY`.
- **Update** `make release-manifest` to list APKs (path/channel=core/sha256/
  size/version), not individual binaries. The daemon APK is the single `core`
  entry.
- **Update** `src/app_zone_watcher.vala` to observe `core-update-ready`
  (core-only). `src/supervisor.vala`'s update handler calls
  `apply_core_apk_update` and self-shuts down on success; the boot
  VERIFY_SELF path resolves a pending core switch (READY -> confirm, DEGRADED
  -> rollback from `.prev`).

## Capabilities

### New Capabilities
- `ota`: the APK-level core self-update — observe `core-update-ready`, re-verify
  the staged APK's embedded manifest against `EMBEDDED_PUBKEY`, extract the
  daemon binary, atomic self-replace with `.prev` rollback, init restart,
  DEGRADED rollback. Subsumes the file-level `release-manifest`,
  `incremental-delta`, `update-planes`, `atomic-apply-rollback`, and
  `system-ota-survival` capabilities of the superseded `ota` change.

### Modified Capabilities
None. (The `ota` capability is added here because the superseded `ota` change
was never applied — its specs lived only under `openspec/changes/ota/specs/`.)

## Impact

- **This repo**: rewrites `src/ota.vala` (remove file-level core-update + agent
  manifest-swap; add `apply_core_apk_update` + APK embedded-manifest verify +
  ZIP binary extraction + `.prev` self-replace/rollback); updates
  `src/supervisor.vala` and `src/app_zone_watcher.vala` to the `core-update-ready`
  marker and the new apply API; updates `make release-manifest` to list the
  daemon APK as the single `core` entry; rewrites `test/ota_test.vala` and
  fixtures for the APK-level APIs.
- **voboost app** (`ru.voboost`): owns the OTA client (fetch/diff/download/
  verify/stage) and creates `core-update-ready` as the last atomic step after
  staging the verified daemon APK. The app NEVER installs the daemon. (Parallel
  task in the sibling repo.)
- **Build/release/CI**: `make release-manifest` lists APKs (the daemon APK is
  `core`); `make sign`/`make verify-sig` (existing) sign and check the manifest.
  The daemon APK's embedded `manifest.json`+`manifest.sig` is produced at the
  daemon APK build (build-time, signed with the same key family).
- **Platform**: relies on the root init hook restarting the daemon on exit (the
  self-replace + exit -> init restart pattern), and `/data/voboost` surviving a
  system OTA (unchanged from the superseded design).
