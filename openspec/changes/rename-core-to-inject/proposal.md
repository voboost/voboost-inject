## Why

The daemon self-update channel is named `core` in voboost-inject but the repo
is `voboost-inject`, the daemon binary is `voboost-inject`, and the sibling
voboost-app repo already maps the channel wire value to `inject`
(`OtaModels.kt`: `"inject" -> Channel.CORE`, `Channel.CORE -> "inject"`). The
name `core` is a leftover from an earlier design where the repo did not yet
have its final name; the voboost-app side has already moved to `inject`. The
split name is a recurring source of confusion (the on-disk marker is
`core-update-ready` but the staged file is `voboost-inject.apk`; the channel
literal is `"core"` but the binary is `voboost-inject`).

This change renames the Voboost-specific `core` channel/plane/markers/identifiers to `inject` across the daemon code, the release-manifest wire contract, the
build (Makefile/CI), the test fixtures, and the specs, so the daemon and the
app agree on a single name and the code reads consistently with the repo and
binary name. The rename is mechanical: no behaviour, no trust boundary, no
on-disk format change beyond the renamed marker/filename strings.

## What Changes

- **Wire channel** `core` → `inject`: the release-manifest `channel` value for
  the daemon APK, the `find_core` lookup (`channel == "core"` → `== "inject"`),
  the `verify_release_manifest` whitelist (`"core"` → `"inject"`), the Makefile
  `CHANNEL=core` → `CHANNEL=inject`, the CI `make release-manifest
  CHANNEL=core`, and the fixture release-manifest JSONs.
- **On-disk contract names**:
  - marker `core-update-ready` → `voboost-inject-update-ready`
  - marker `run/core-switch-pending` → `run/voboost-inject-switch-pending`
- **Code identifiers** in `src/ota.vala`, `src/app_zone_watcher.vala`,
  `src/supervisor.vala`:
  - constants `CORE_BINARY`→`INJECT_BINARY`, `CORE_PREV`→`INJECT_PREV`,
    `CORE_MARKER`→`INJECT_MARKER`, `CORE_UPDATE_READY`→`INJECT_UPDATE_READY`
  - enum `CoreApplyOutcome`→`InjectApplyOutcome`
  - methods `find_core`→`find_inject`, `apply_core_apk_update`→`apply_inject_update`,
    `core_update_ready`→`inject_update_ready`,
    `consume_core_update_ready`→`consume_inject_update_ready`,
    `core_switch_pending`→`inject_switch_pending`,
    `confirm_core_switch`→`confirm_inject_switch`,
    `rollback_core_switch`→`rollback_inject_switch`,
    `apply_staged_core_apk`→`apply_staged_inject_update`,
    `find_staged_apk`→`find_staged_inject`
  - field `core_self_shutdown_requested`→`inject_self_shutdown_requested`
  - signal `core_update_ready`→`inject_update_ready`
- **Makefile target** `core-apk` → `inject-apk` (the daemon APK packaging
  target).
- **Log messages and comments**: every daemon-self-update `core` reference in
  log strings and comments → `inject`.
- **Test suite**: `test/ota_test.vala`, `test/app_zone_watcher_test.vala`,
  `test/fixtures/gen-fixtures.sh` and the generated fixture JSONs renamed to
  match the new identifiers/strings.
- **Specs**: reword the daemon-self-update `core` references to `inject` in the
  canonical specs `ota`, `update-planes`, `atomic-apply-rollback`,
  `release-manifest`, `ci-release`, `system-ota-survival`, `incremental-delta`.

## What Does NOT Change

- **`frida-core` is untouched.** The library name `frida-core` (meson option
  `frida-core:compat`, `subproject('frida-core')`, `frida-core-1.0`, the
  `frida_core_*` meson variables, the `frida-core 17.x` comments) is a
  third-party dependency name, not the Voboost channel. None of these are
  renamed.
- **The per-agent daemon manifest** `manifest.json`/`manifest.sig`/
  `manifest.json.prev`/`manifest.sig.prev` filenames are unchanged — these are
  the agent manifest, not the daemon-core manifest. (There is no separate
  "core manifest" file; the daemon's manifest IS the per-agent manifest.)
- **No behaviour, trust, or on-disk format change** beyond renamed marker and
  channel strings. The `.prev` rollback scheme, the APK-level self-update, the
  ZIP reader, and the single-use marker contract are all unchanged.
- **The staged APK filename** stays `voboost-inject.apk` for now (it is
  renamed to a bare `voboost-inject` ELF only in the later Step 3B when ZIP is
  removed).

## Capabilities

### Modified Capabilities
- `ota`: the channel name `core` → `inject`; marker `core-update-ready` →
  `voboost-inject-update-ready`; marker `core-switch-pending` →
  `voboost-inject-switch-pending`; `core self-update` → `inject self-update`;
  `core APK` → `inject APK` in requirements and scenarios.
- `update-planes`: `core` channel/plane → `inject`; `core-update-ready` →
  `voboost-inject-update-ready`.
- `atomic-apply-rollback`: `core update`/`core-switch-pending`/`core rollback`
  → `inject`.
- `release-manifest`: the `channel` value set `{agents, core, app}` →
  `{agents, inject, app}`; the daemon channel `core` → `inject`.
- `ci-release`: the channel enum `{agents, core, app}` →
  `{agents, inject, app}`.
- `system-ota-survival`: `core apply`/`core self-update` → `inject`.
- `incremental-delta`: `core binary` → `inject binary`.

## Impact

- **This repo (voboost-inject):** mechanical rename in `src/ota.vala`,
  `src/app_zone_watcher.vala`, `src/supervisor.vala`, the tests, `Makefile`,
  `.github/workflows/release.yml`, `test/fixtures/gen-fixtures.sh` and the
  generated fixtures, and the canonical specs. `make build` and `make test`
  pass unchanged after the rename.
- **voboost app:** the wire value is already `inject`; only the internal enum
  constant `Channel.CORE` → `Channel.INJECT` and the derived identifier names
  (`stageCoreApk`, `CORE_APK_NAME`, `createCoreUpdateReadyMarker`,
  `downloadAndApplyCore`, etc.) are renamed for consistency. No wire-contract
  change.
- **Build/release/CI:** `make release-manifest CHANNEL=inject`; the published
  release-manifest now lists the daemon APK as `channel: "inject"`. A device
  running an older daemon that still parses `channel == "core"` would reject
  the new manifest's daemon entry — this is a coordinated release: the new
  daemon and the new manifest ship together.
- **On-device upgrade path:** a device running the current `core`-named daemon
  receives the next OTA as a single coordinated release (new daemon APK with
  `channel: "inject"` in the manifest, parsed by the new daemon). There is no
  mixed-version window because the daemon only ever consumes its own channel's
  APK.
