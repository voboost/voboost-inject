## Why

<!-- Design date: 2026-06-07. Source plan: plans/2026-06-07/2026-06-07-00-14-inject-ota*.md -->

Voboost currently injects Frida agents by having the unprivileged app shell out to
`su 0 frida-inject`: the app holds root, attaches late (after the target has already run
code), performs no signature verification, and has no resident supervisor. On a user's car
this is both unsafe (an injection failure can hang a system process or boot) and weak
(nothing stops a tampered agent from running).

This change introduces **voboost-inject**: a single minimal root component — a native Vala
binary that embeds `frida-core` and drives it in-process — that becomes the *only* root-holding
part of the system. It verifies every agent against a signed manifest (embedded public-key trust
anchor), injects as early as possible via spawn-gating, and is built to never break the user's
device (fail-open, guaranteed `resume()`, per-agent isolation). The unprivileged app is demoted
to writing config/plan and reading status.

## What Changes

- **BREAKING**: Root moves out of the app. The app no longer runs `su 0 frida-inject`; injection
  is performed only by the resident `voboost-inject` daemon launched at boot from the
  `/system` init hook.
- New native **Vala** binary embedding **frida-core** (QuickJS build, no V8), driven in-process
  with **no socket**, using **spawn-gating** (inject before target code runs) + attach for
  already-running processes.
- **Signature/trust enforcement**: an embedded public key verifies a signed manifest; each agent
  is verified by sha256 before injection. An agent's target process and `kind` come only from the
  manifest, never from the app-written plan.
- **Files-only IPC**: app writes `inject.json` (the single app→daemon hand-off: `startup` gate,
  `disabled`, per-agent `enabled` + opaque `config`) and a `staging/` area; daemon reads them and
  writes `inject-status.json`. The daemon does NOT read `config.yaml` (the app owns it and derives
  `inject.json`). No listening socket.
- **Device-safety guarantees**: guaranteed `resume()` of every spawn-gated process, per-agent
  isolation, reinjection rate-limit + quarantine, coexistence skip (another Frida tool already in a
  process), global panic-quarantine, single-instance via pidfile + `flock`.
- **Two independent stop mechanisms**: a **startup-gate** (the daemon reads the `startup` field of
  `inject.json`; `startup: none` → daemon exits immediately, mirroring the app's intent) and a
  runtime **kill-switch** (`/data/voboost/run/disable`
  or a plan flag → stop all injections, resume, idle) acting as a runtime circuit-breaker.
- **On-disk trust boundary**: root-only zone `/data/voboost` (root:root, 700); the public key is
  **embedded in the binary and NOT stored on disk** (`key.pub` removed from the design).
- **Logging** to the root-only zone `/data/voboost/logs/inject-YYYY-MM-DD.log` (600), shared format
  with the app, 7-day retention. (Not the app zone — preserves the trust boundary.)
- **Build**: meson, **release-only** (no debug build), frida-core as a meson subproject built from
  a pinned git wrap (provisioned by the `init` change; no hardcoded local path), QuickJS-only,
  static link, LTO, strip. Building that wrap requires frida's patched Vala compiler (`valac`
  version suffix `-frida`), meson >= 1.1.0, and explicit subproject option pinning (V8 disabled at
  the gum level, static libs, local backend only, `frida_version` supplied because the wrap
  checkout has no `releng`); `make init` is extended to provision the transitively-pinned valac
  fork (design D10c). This change sets the project's `meson.build` version baseline
  `1.0.0-beta1`. On completion, `make build` produces a host binary for testing and
  `make build-android` produces the device binary (arm64-v8a via `config/android-cross.ini`).
- **Signing model for an open-source repo**: the private signing key lives only in CI secrets; the
  public key is committed in source. Local developers generate their own dev keypair and bake their
  own public key into a local build; signature verification is always on, even in dev builds. (The
  real CI release pipeline that signs this binary's manifest with the secret key is implemented by
  the `ci` change, which lands after `inject`; the signing *invariant* here is unchanged.) The
  per-agent `manifest.json` is signed by the **app build pipeline** (`ru.voboost` repo), not by
  this repo's CI.

Out of scope (covered by the separate `ota` change): incremental/delta OTA, the signed
release-manifest, the staging→trusted swap *mechanics*, and post-system-OTA re-arm.

## Capabilities

### New Capabilities
- `daemon-lifecycle`: process model and state machine (INIT → VERIFY_SELF → READY/DEGRADED →
  per-target GATE/ATTACH → INJECT → MONITOR), startup-gate (`inject.json` `startup` field),
  single-instance, SIGTERM shutdown, GMainLoop/async error model.
- `trust-verification`: embedded public-key trust anchor, signed-manifest signature verification,
  per-agent sha256 verification, the manifest data contract, and the rule that process/kind derive
  from the manifest only.
- `injection-control`: embedding frida-core in-process, spawn-gating + attach, per-process
  sessions, js/native agent routing with lazy (per-process) QuickJS init, process watching
  (event-driven inject on spawn, reinject on death), opaque config delivery (rpc.init for js,
  data-arg for native), and the inject-plan (`inject.json`) data contract.
- `device-safety`: guaranteed resume, per-agent isolation, reinjection rate-limit + quarantine,
  global panic-quarantine, coexistence skip, kill-switch, capability-detection over version strings.
- `app-interface`: files-only IPC contract — app-zone vs root-zone layout, `inject.json`
  (untrusted, validated), `inject-status.json` (daemon-written, app-readable), `staging/` +
  `update-ready` read boundary, and logging.
- `build-and-signing`: meson release-only build, frida-core QuickJS subproject from local
  pinned git wrap (with the toolchain precondition: frida-patched valac, pinned subproject
  options — D10c), static/LTO/strip, and the open-source signing-key model (CI secret private
  key, committed public key, local dev keypair, verification always on).

### Modified Capabilities
- `provisioning`: `make init` additionally fetches the pinned wraps up front
  (`meson subprojects download`) and builds the frida-patched Vala compiler (transitively pinned
  via the frida-core checkout's `releng` gitlink + `deps.toml`) into the tools prefix; the
  Makefile prepends that prefix to `PATH`. Required to configure the frida-core subproject
  (design D10c).

## Impact

- **New project** `voboost/voboost-inject` (Vala + meson). This change implements the daemon: it
  writes `src/*.vala`, wires the meson build target, sets the version baseline `1.0.0-beta1`, and on
  completion `make build` produces the binary `voboost-inject`.
- **voboost app** (`ru.voboost`): loses root and the `su 0 frida-inject` path; gains the
  obligation to write `inject.json` (incl. each agent's `config` and the `startup` field) and
  `staging/` and to read `inject-status.json`.
  (FridaManagerAndroid.kt-style direct injection is superseded.)
- **Platform**: depends on the existing root init hook `/system/etc/init.logcat.sh`; SELinux is
  permissive and `ro.debuggable=1`, but the design relies only on Unix permissions + parent-dir
  ownership, not on permissive mode.
- **Dependencies**: frida-core / frida-gum / frida sources via a pinned git wrap (provisioned by
  the `init` change); the frida-patched Vala compiler, transitively pinned and built by
  `make init` (design D10c); the Monocypher ed25519 verifier as a pinned meson subproject
  (`subprojects/monocypher.wrap`, added by this change, fetched at `meson setup`); ed25519 signing.
- **Cross-repo design context** (read-only): voboost `docs/architecture.md`, `frida.md`,
  `coexistence.md`, `script-hook-map.md`, `a9-a11-verification.md`.
