## Context

The daemon self-update was designed when the repo was tentatively named with a
"core" theme; the repo has since been renamed `voboost-inject`, the binary is
`voboost-inject`, and the sibling voboost-app repo already uses `inject` as the
wire value for the daemon channel (`OtaModels.kt` maps `"inject"` ↔
`Channel.CORE`). The voboost-inject side never caught up: the channel literal
is still `"core"`, the markers are `core-update-ready` / `core-switch-pending`,
and every identifier (constants, enum, methods, signal) carries `core`. This
split is a recurring confusion source and a trap for anyone reading the code.

This change is a mechanical, repo-wide rename of the Voboost-specific `core`
vocabulary to `inject`, including the wire channel value, so both repos agree
on a single name. No behaviour, trust, or on-disk format changes beyond the
renamed strings.

## Goals / Non-Goals

**Goals:**
- The daemon and the app agree on the channel name `inject` end-to-end (wire,
  code, markers, specs).
- The code reads consistently with the repo/binary name `voboost-inject`.
- The rename is one coordinated, atomic, mechanical change — no half-renamed
  state.

**Non-Goals:**
- Changing the on-disk format of the staged daemon payload (still
  `voboost-inject.apk`; becomes a bare `voboost-inject` ELF only in Step 3B).
- Changing the `.prev` rollback scheme, the ZIP reader, or the single-use
  marker contract.
- Renaming `frida-core` (third-party library name — out of scope).
- Renaming the per-agent `manifest.json`/`manifest.sig` filenames (these are
  the agent manifest, not a "core manifest").

## Decisions

### D1. Rename the wire value `core` → `inject` (not just the identifiers)
The wire channel value `core` is renamed to `inject`, matching what voboost-app
already sends/expects. This is a coordinated release: the new daemon and the
new release-manifest ship together. There is no mixed-version window because
the daemon only consumes its own channel's APK — an old daemon that sees a new
`channel: "inject"` manifest simply finds no `core` entry and applies no
daemon update (it does not crash); a new daemon that sees an old
`channel: "core"` manifest likewise finds no `inject` entry. The app-side
manifest producer is updated in lockstep.

### D2. Rename the on-disk marker and switch-pending strings
- `core-update-ready` → `voboost-inject-update-ready` (the producer's "a
  verified daemon APK is staged" marker, in the app-zone `staging/` dir).
- `run/core-switch-pending` → `run/voboost-inject-switch-pending` (the
  daemon's rollback trigger marker, in the root-zone `run/` dir).

These are file-visible names; a device upgrading from the `core`-named daemon
will not have the old markers after the new daemon takes over (the new daemon
consumes the new marker; the old markers are single-use and were already
consumed or are stale). The upgrade is a single coordinated OTA.

### D3. Rename identifiers mechanically; keep the comment style
Every Voboost-specific `core` identifier is renamed to its `inject`
counterpart (constants `CORE_*` → `INJECT_*`, enum `CoreApplyOutcome` →
`InjectApplyOutcome`, methods `*_core_*` → `*_inject_*`, signal
`core_update_ready` → `inject_update_ready`, field
`core_self_shutdown_requested` → `inject_self_shutdown_requested`). Log
messages and comments are reworded to match. The code structure, control flow,
and invariant comments are unchanged — this is a search-and-replace rename,
not a refactor.

### D4. What stays `core` (the exclusion list)
- `frida-core` everywhere (meson options, subproject name, dependency name,
  `frida_core_*` variables, `frida-core 17.x` comments).
- The per-agent manifest filenames `manifest.json` / `manifest.sig` /
  `manifest.json.prev` / `manifest.sig.prev` (agent manifest, not a "core
  manifest").
- `coredata.dat` (meson/frida internal).
- The English word "core" in unrelated phrases (none in the Voboost-specific
  code, but called out to prevent over-eager replacement).

### D5. Coordinated release, no compatibility shim
No dual-parse (`channel == "core" || channel == "inject"`) is added. The
rename is clean: the daemon accepts only `inject`, the manifest carries only
`inject`. A compatibility shim would defeat the purpose (the split name would
persist forever) and the OTA model already guarantees a coordinated release
(the daemon consumes only its own channel's APK, so there is no
mixed-version window).

### D6. Makefile target `core-apk` → `inject-apk`
The Makefile target that packages the daemon APK is renamed `core-apk` →
`inject-apk`. The CI workflow (`release.yml`) is updated in lockstep
(`make core-apk` → `make inject-apk`). The staged APK filename stays
`voboost-inject.apk` until Step 3B.

## Renaming table (canonical)

| Old | New |
|---|---|
| wire `channel == "core"` | `channel == "inject"` |
| whitelist `"core"` | `"inject"` |
| `CORE_BINARY` (`voboost-inject`) | `INJECT_BINARY` |
| `CORE_PREV` (`voboost-inject.prev`) | `INJECT_PREV` |
| `CORE_MARKER` (`run/core-switch-pending`) | `INJECT_MARKER` (`run/voboost-inject-switch-pending`) |
| `CORE_UPDATE_READY` (`core-update-ready`) | `INJECT_UPDATE_READY` (`voboost-inject-update-ready`) |
| `CoreApplyOutcome` | `InjectApplyOutcome` |
| `find_core` | `find_inject` |
| `apply_core_apk_update` | `apply_inject_update` |
| `core_update_ready` (method + signal) | `inject_update_ready` |
| `consume_core_update_ready` | `consume_inject_update_ready` |
| `core_switch_pending` | `inject_switch_pending` |
| `confirm_core_switch` | `confirm_inject_switch` |
| `rollback_core_switch` | `rollback_inject_switch` |
| `apply_staged_core_apk` | `apply_staged_inject_update` |
| `find_staged_apk` | `find_staged_inject` |
| `core_self_shutdown_requested` | `inject_self_shutdown_requested` |
| marker `core-update-ready` | `voboost-inject-update-ready` |
| marker `run/core-switch-pending` | `run/voboost-inject-switch-pending` |
| temp `.ota.core.tmp` | `.ota.inject.tmp` |
| Makefile `core-apk` | `inject-apk` |
| CI `CHANNEL=core` | `CHANNEL=inject` |
| fixture seed `fake-core-binary-v1` | `fake-inject-binary-v1` |

## voboost-app side (parallel, sibling repo)

The wire value is already `inject`. Only the internal Kotlin identifiers are
renamed for consistency:
- `enum Channel { APP, CORE }` → `{ APP, INJECT }`
- `CORE_APK_NAME` → `INJECT_FILE_NAME` (value `voboost-inject.apk`, unchanged)
- `CORE_UPDATE_READY_MARKER` → `INJECT_UPDATE_READY_MARKER` (value
  `voboost-inject-update-ready`, the renamed marker — must match the daemon)
- `stageCoreApk` → `stageInjectApk`, `createCoreUpdateReadyMarker` →
  `createInjectUpdateReadyMarker`, `hasCoreUpdateReadyMarker` →
  `hasInjectUpdateReadyMarker`, `clearCoreUpdateReadyMarker` →
  `clearInjectUpdateReadyMarker`, `downloadAndApplyCore` →
  `downloadAndApplyInject`

The app-side marker value MUST change from `core-update-ready` to
`voboost-inject-update-ready` to match the daemon — this is part of the
coordinated rename, not optional.
