# voboost-inject

**voboost-inject** is the root injection component of Voboost: a single native
Vala binary that embeds [frida-core](https://frida.re) (QuickJS engine, no V8),
runs as **root**, and injects cryptographically **signed** agents into target
Android processes — typically `system_server` and other framework processes the
unprivileged [Voboost app](https://github.com/voboost/voboost) cannot touch.

It is launched once at boot by a `/system` init hook and runs as a single
resident daemon for the whole session. The Voboost app tells it *which* signed
agents to inject; voboost-inject verifies every byte before injecting it and
never trusts the app for anything security-critical.

> Behavioral detail lives under `openspec/specs/`. This README is the
> user-facing overview; the specs are the source of truth.

## The Voboost project

voboost-inject is one component of a multi-repo system:

- [`voboost`](https://github.com/voboost/voboost) — the unprivileged Android app
  (`ru.voboost`); ships the agents in its APK and writes `inject.json`.
- **`voboost-inject`** *(this repo)* — the root daemon; verifies and injects
  signed agents.
- [`voboost-agent`](https://github.com/voboost/voboost-agent) — the Frida agents
  (js/native) and the **signed agent-set manifest** they ship in.
- [`voboost-install`](https://github.com/voboost/voboost-install) — device
  bring-up: first install of the daemon binary, agents, and the `/system` init
  hook.

This README covers the daemon's contract and build. Agent authoring and signing
live in [`voboost-agent`](https://github.com/voboost/voboost-agent); end-to-end
device bring-up lives in
[`voboost-install`](https://github.com/voboost/voboost-install).

## Quick start

```sh
make init     # provision toolchain, dev key, and the frida subprojects
make build    # host release build (release, LTO, frida-core static)
make test     # host-side tests, device-free
```

A device build and first-time install are covered further below.

## What it does

- **Root daemon.** A single resident root process, launched at boot by a
  `/system` init hook. Single-instance is enforced with a pidfile guarded by
  `flock` (not by process-name matching); a second instance logs the conflict
  and exits without injecting.
- **Embedded frida-core.** Drives frida-core in-process over a local device —
  no socket, no per-injection helper process. frida-core is statically linked
  into the binary with LTO; there is no separate frida library on disk.
- **Signed agents only.** Every agent is verified twice before it runs: the
  agent-set manifest is checked against a public key compiled into the binary
  (ed25519), and each agent file is checked by sha256 against that verified
  manifest. Verification is always on — there is no skip-verify mode.
- **Earliest injection.** Not-yet-started targets are spawn-gated so the agent
  loads before the target runs its own code; already-running targets are
  attached. Non-target processes caught by global spawn-gating are resumed
  immediately with no attach cost.
- **Device safety.** A spawn-gated process is always resumed, even if its
  injection fails (fail-open). Agents are isolated per agent; a failing agent
  is rate-limited and quarantined, and a mass-death threshold trips a global
  panic-quarantine that stops all injections. A runtime kill-switch
  (`/data/voboost/run/disable`) stops everything and idles. (Mechanics and
  exact thresholds: *Architecture → Device safety*.)
- **OTA without a device reboot.** Agents and the daemon binary itself update
  on-device: agents via an atomic manifest swap, the core binary via a
  content-addressed install plus a clean self-shutdown that Android init turns
  into a restart of the new binary — no reboot required, with automatic
  rollback if the new binary comes up degraded. (Details: *OTA update planes*.)

## How it works with the Voboost app

The Voboost app ([`voboost`](https://github.com/voboost/voboost), package
`ru.voboost`) is an ordinary, unprivileged user-space app. It self-distributes
(not via Play) and ships the Frida agents inside its own APK.
The daemon and the app never share a socket — they communicate **only through
files**, across two strictly separated trust zones on the device:

| Zone | Path | Owner | Who writes |
|------|------|-------|------------|
| Root zone (trusted) | `/data/voboost` | root:root, `700` | daemon only |
| App zone (untrusted) | `/data/user/0/ru.voboost` | the app | app; daemon writes status only |

The app **cannot** read, rename, or replace anything in `/data/voboost`. The
daemon (running as root) can read the app zone, but treats every byte it reads
there as untrusted and re-verifies it before acting.

### The hand-off files

All three files are specified in `openspec/specs/app-interface`.

- **`inject.json`** *(app → daemon, app zone)* — the app's single instruction
  file. It carries the `startup` gate, the `disabled` kill-switch, and a
  per-agent list of `enabled` flags plus an opaque `config` blob the daemon
  forwards verbatim to each agent:

  ```json
  {
    "startup": "auto",
    "disabled": false,
    "agents": [
      { "id": "wm-viewport", "enabled": true, "config": { "scale": 1.2 } }
    ]
  }
  ```

  `"startup": "none"` makes the daemon exit without injecting; any other
  value (or a missing field) lets it run. The daemon resolves each agent's
  target `process` and `kind` (`js` or `native`) from the **verified
  manifest**, never from this plan; `config` is opaque bytes, size-bounded
  only (64 KiB per agent, 1 MiB for the whole file).

- **`inject-status.json`** *(daemon → app, app zone)* — the daemon's outbound
  status, written atomically (temp + rename, never following a symlink):

  ```json
  {
    "daemon": "1.0.0-beta1",
    "manifest": 1,
    "state": "ready",
    "killed": false,
    "panic": false,
    "injections": [
      { "id": "wm-viewport", "process": "system_server", "state": "active" }
    ]
  }
  ```

  `daemon` is the daemon version; `manifest` is the active manifest's `version`
  (see *Writing agents*); `state` is `ready` or `degraded`; `injections[].state`
  is one of `active`, `failed`, `skipped-coexist`, `waiting`, `quarantined`.

- **`staging/` + `update-ready`** *(app → daemon, app zone)* — the OTA staging
  area. The app downloads updated agents/manifest, writes them into
  `staging/`, and creates the `update-ready` marker last. The daemon
  re-verifies everything against its embedded key before swapping it into the
  trusted zone.

### Trust model

The daemon's only trust anchor is a public key **compiled into the binary**.
It never reads a key from disk. The agent-set manifest is signed with the
matching private key and verified by the embedded public key; each agent file
is then verified by sha256 against that verified manifest. The same key family
signs the OTA release manifest. The app signs nothing the daemon trusts on
faith — it only delivers material the daemon re-verifies against the embedded
key.

## Architecture

### Daemon state machine

```
INIT -> VERIFY_SELF -> READY
                    \-> DEGRADED (observe-only, injects nothing)
```

On boot the daemon:

1. Acquires an exclusive `flock` on the pidfile (single-instance).
2. Reads the `startup` field from `inject.json` — `"none"` exits immediately.
3. Enters VERIFY_SELF: verifies the manifest ed25519 signature against the
   embedded key, then checks every agent sha256.
4. On success, enters READY, enables spawn-gating, and begins injecting.
5. On failure (bad signature, hash mismatch, or frida-core open failure),
   enters DEGRADED — observe-only, no injections.

### Per-target lifecycle

```
GATE (spawn-gated) or ATTACH (already running)
  -> INJECT (js via QuickJS script, native via library injection)
  -> MONITOR (watch for death, reinject within safety budget)
```

- **js agents** run on frida-core's QuickJS runtime via `create_script`.
- **native agents** are injected as compiled `.so` files via
  `inject_library_blob` — no JavaScript engine loaded.
- QuickJS is loaded per-process only when at least one `js` agent targets that
  process; a process receiving only `native` agents never loads QuickJS.
- **Native-only restart detection is deferred.** A target receiving *only*
  `native` agents has no frida session (no JS engine), so the robust death /
  restart path for such targets is not wired yet — it lands with the future
  JS->native migration. Targets carrying at least one `js` agent are
  unaffected.
- An agent with `boot: true` in the manifest is deferred until
  `sys.boot_completed=1`; other agents inject immediately.

### Device safety

- **Guaranteed resume.** A spawn-gated process is always resumed, even on
  injection failure or timeout.
- **Per-agent isolation.** One agent failing does not affect others or crash
  the target.
- **Rate-limit + quarantine.** Repeated target deaths for the same
  (agent, process) pair trigger exponential backoff, then quarantine (the
  agent stops injecting; the target runs unmodified).
- **Panic-quarantine.** Mass target deaths across the device trip a global
  stop — all injections halt.
- **Coexistence skip.** If `/proc/PID/maps` shows a foreign Frida agent
  already present, injection is skipped for that process.
- **Runtime kill-switch.** The file `/data/voboost/run/disable` or the plan
  flag `disabled` stops all injections and idles the daemon. Deactivating the
  kill-switch requires a daemon restart; injections do not resume
  automatically.

### Safety thresholds

The device-safety rules above fire at fixed thresholds compiled into the daemon
(full semantics in `openspec/specs/device-safety`):

- **Reinjection rate-limit.** At most **3** injection attempts per **5-minute**
  window per (agent, process) pair; a 4th within the window quarantines that
  agent (fail-open — the target keeps running unmodified).
- **Exponential backoff.** Each failed attempt delays the next by a doubling
  interval capped at **30 minutes**; a successful injection resets it.
- **Panic-quarantine.** **8** target deaths within a **5-minute** sliding window
  trips a global stop of all injections until the daemon is restarted.

### OTA update planes

| Plane | Mechanism | Restart? |
|-------|-----------|----------|
| Agents | Atomic manifest swap + re-inject | No |
| Core | Content-addressed install + self-shutdown; init restarts the new binary | Yes |

- Agent updates apply immediately (before the first injection on boot, or at
  runtime when the `update-ready` marker appears).
- Core updates install the new binary as `voboost-inject-<sha>`, repoint the
  stable launch path, and self-shutdown; Android init restarts the service.
- If the new binary starts DEGRADED, it rolls back to the previous binary
  automatically.
- The `update-ready` marker is single-use: consumed after any apply attempt
  (success or verified failure).

## Security

- **Trust anchor is compiled in.** The only verification key is baked into the
  binary at build time; the daemon never loads a key from disk, and signature +
  sha256 verification is always on — there is no skip-verify mode.
- **Defense-in-depth on the root zone.** `/data/voboost` and its whole parent
  chain are root-owned, so the unprivileged app cannot read, rename, or replace
  trusted state. VERIFY_SELF additionally re-checks that the root zone is
  root-owned and not group/world-writable, entering DEGRADED (injects nothing) if
  it fails. SELinux is permissive on this device, so these Unix-permission
  guarantees are the load-bearing layer, not a secondary check.
- **Untrusted app zone.** Everything the daemon reads from the app zone
  (`inject.json`, `staging/`) is re-verified before use. The one daemon-written
  file there — `inject-status.json` — is written atomically to a temp opened with
  `O_NOFOLLOW` and renamed into place, so a symlink the app pre-places cannot
  redirect the write at a root-owned file.
- **ed25519 via Monocypher.** Signature verification is the Monocypher subproject
  (no system crypto on the device); frida-core is statically linked, so there is
  no separate frida library to tamper with.
- **Minimal attack surface.** The daemon opens no listening socket and runs no
  per-injection helper process — all frida-core work is in-process over the
  local device.

## Writing agents

Agents are authored, built, and signed in
[`voboost-agent`](https://github.com/voboost/voboost-agent); this section
describes the per-agent contract the daemon verifies, so a manifest is
recognizable from the daemon's side. The tooling to assemble the manifest and
sign it with the matching private key is part of
[`voboost-agent`](https://github.com/voboost/voboost-agent).

An agent is `js` (JavaScript on QuickJS) or `native` (a compiled `frida-gum`
`.so`, no JS engine) — see *Per-target lifecycle* above. Either way it is
verified by manifest signature + sha256 and receives the same opaque `config`.
**Every shipped agent today is `js`** (see
[`voboost-agent`](https://github.com/voboost/voboost-agent)); `native` is a
supported path the daemon implements end-to-end (`inject_library_blob`), kept
available but not yet exercised — no native agent is in the set yet.

The agent-set manifest (`manifest.json`, signed into `manifest.sig` and shipped
inside the app's APK) is an object with a `version`, an optional `daemon`, and
an `agents` array:

```json
{
  "version": 1,
  "daemon": "1.0.0-beta1",
  "agents": [
    {
      "id": "wm-viewport",
      "channel": "agents",
      "file": "agents/wm-viewport.js",
      "sha256": "86e413ce702abb872718569c06a2e01c52553ad35953c6df122e007d3146a87a",
      "process": "system_server",
      "kind": "js",
      "entrypoint": "",
      "boot": false
    }
  ]
}
```

`version` is the manifest version reported back as `"manifest"` in
`inject-status.json`; `kind` is `js` or `native`; `entrypoint` names the
exported symbol of a native `.so` (empty and ignored for `js`); `boot: true`
defers the agent until the device finishes booting. The manifest is signed with
the private key matching the daemon's embedded public key; the daemon verifies
the signature, then each agent's sha256 against it (see
`openspec/specs/trust-verification`).

### js agent (QuickJS)

```js
// agents/wm-viewport.js — runs on the embedded QuickJS engine.
// The daemon calls rpc.exports.init(stage, parameters) on load,
// with parameters.config = this agent's "config" from inject.json.
rpc.exports = {
  init(stage, parameters) {
    const { scale } = parameters.config;   // e.g. { "scale": 1.2 }
    Java.perform(() => {
      // ...install hooks on a framework class...
    });
  }
};
```

### native agent (no JS engine)

```c
/* agents/wm-viewport.c — build to a .so with the Android NDK. No JavaScript
   engine is loaded. The manifest "entrypoint" names this exported symbol; the
   daemon passes the agent's config JSON as the null-terminated `data` string. */
void
wm_viewport_entry (const char * data, int * unload_policy, void * injector_state)
{
  (void) data;             /* the agent's config from inject.json (JSON text) */
  (void) injector_state;

  *unload_policy = 1;      /* FRIDA_UNLOAD_POLICY_RESIDENT — stay resident */

  /* ...install frida-gum hooks (Interceptor, etc.) here... */
}
```

### Building a native agent

A native agent is a C source compiled to a position-independent `.so` and linked
against `frida-gum` (the same engine pinned in `subprojects/`).
[`voboost-agent`](https://github.com/voboost/voboost-agent) ships only `js`
agents today; the build below is how a `native` `.so` would be
produced when one is added. Cross-compile for arm64-v8a with the NDK; the
exported symbol in the source is the manifest `entrypoint`:

```sh
CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android28-clang
$CC -shared -fPIC -O2 -std=c11 \
    -I"$GUM" \
    -o agents/wm-viewport.so agents/wm-viewport.c \
    "$GUM/build/libfrida-gum-1.0.a" -lm -ldl -lpthread
```

`GUM` is a built `frida-gum` tree (`gum.h` under its root, the static library in
its build directory). The exact library name/path follows your frida-gum build;
alternatively build the agent as a meson `shared_library` depending on the
`frida-gum` subproject — the same way frida-gum's own test agents are built.

### Agent ↔ daemon messaging

The daemon talks to a `js` agent over frida's `frida:rpc` protocol on top of
`Script.post`/`message`:

- **daemon → agent:** on load the daemon calls `rpc.exports.init(stage,
  parameters)` with `parameters.config` set to the agent's `config` from
  `inject.json` (it posts the `["frida:rpc", …, "call", "init", …]` message
  itself — you only define the `init` export).
- **agent → daemon:** `send(payload)` from inside the agent lands on the daemon's
  `script.message` handler and is written to the root-only log under
  `agent/<id>`. It is a one-way observe channel — the daemon does not call back
  beyond `init`.

```js
rpc.exports = {
  init(stage, parameters) {
    const { scale } = parameters.config;
    send({ event: 'ready', scale });        // agent -> daemon (logged)
    Java.perform(() => {
      // ...install hooks on a framework class...
    });
  }
};
```

## Build

### Prerequisites

All required tools are installed or built by `make init`:

- Vala compiler (`valac`) — the frida-patched build (version suffix `-frida`)
- meson (>= 1.1.0), ninja, git
- openssl (ed25519 keys/signing), bsdiff, uncrustify
- `io.elementary.vala-lint` — built from a pinned source revision (tag
  `0.1.0`); there is **no Homebrew/apt package** for it
- Android NDK — external; set `ANDROID_NDK_HOME` for device builds

Verify everything is present:

```sh
make check
```

### From a fresh clone

```sh
make init     # provision the whole environment (OS pkgs, vala-lint, frida valac, dev key, setup)
make build    # build the daemon binary (host, release, LTO, frida-core static)
make test     # host-side tests (device-free)
```

`make init` runs three steps in order:

1. **toolchain** — installs OS-package tools, builds `io.elementary.vala-lint`
   from the pinned source tag, builds the frida-patched `valac` (frida-core
   requires it), and fetches the pinned frida subproject wraps. Tools install
   into `.tools/` (project-local, gitignored); the Makefile prepends it to
   `PATH`.
2. **key-dev** — generates a local ed25519 dev keypair at
   `config/key-dev-private.pem` (gitignored) and `config/key-dev-public.pem`
   (committed), used to bake the public key into the binary.
3. **setup** — runs `meson setup build`.

### Per-OS notes

**macOS (Homebrew)** — `make init` runs
`brew install vala meson ninja bsdiff uncrustify json-glib glib pkg-config`,
then builds vala-lint and the frida-patched valac from source.

**Linux (Ubuntu/Debian)** — `make init` runs `apt-get` (via `sudo`) for the
equivalent packages (incl. `libvala-dev`, `libgee-0.8-dev`,
`libjson-glib-dev`), then builds vala-lint and the frida-patched valac from
source.

**Windows** — use WSL2 + Ubuntu (the Android cross toolchain is Linux-native):

```pwsh
wsl --install -d Ubuntu
```

then follow the Linux path inside WSL2.

### Host vs. device build

Builds are release-only (no debug configuration):

```sh
make build          # host build: release, LTO, frida-core static, dynamic host libs (for tests)
make build-android  # device build: arm64-v8a, frida/glib stack static, bionic dynamic
```

`make build` keeps the symbol table (host tests need it); strip is applied at
install time (`meson install --strip`). The device build is self-contained for
the frida/glib stack: every bundled subproject (frida-core, glib, gio,
json-glib, monocypher, ...) is statically linked via the global
`default_library=static`, so no glib/gio/json-glib is provisioned on the device.
The bionic system libs (libc, liblog, libz, libm, libdl) link dynamically — NDK
r29 ships no static bionic, and bionic is always present on Android. The daemon
is local-backend-only, so `frida-core:connectivity` (TLS/ICE) is disabled.

`make build-android` needs the Android NDK in `ANDROID_NDK_HOME`; the NDK
toolchain PATH is derived automatically from it (no manual PATH setup). CI pins
NDK **r29** — frida-core 17.11.0's releng requires exactly major version 29
(`NDK_REQUIRED=29`); r27/r27d are rejected. Use the same locally for
reproducible device builds.

Both `make setup` and `make build-android` configure via frida's own meson fork
(provisioned by `make init` from `frida-core`'s `releng/meson` submodule), not
the system meson — frida-gum's `quickcompile` (`native: true`) needs its QuickJS
subproject built for the build machine, which only frida's meson does. frida-meson
is launched via `PYTHON_FOR_MESON` (default `/usr/bin/python3`), which must ship
the stdlib `distutils` module (removed in Python 3.12) — glib's `gdbus-codegen`
imports it.

### Lint and test

```sh
make lint      # io.elementary.vala-lint + uncrustify --check (gate)
make lint-fix  # uncrustify --replace (canonical style in place)
make test      # meson test (host-side, silent on success)
```

`make lint` first checks that both linters are on `PATH`; if either is missing
it tells you to run `make init` instead of failing with `command not found`.

## Install / deploy

### Device layout

On a provisioned device the daemon owns the root zone `/data/voboost`:

```
/data/voboost/
  voboost-inject                stable launch path the init hook execs
  voboost-inject-<sha>          content-addressed core binary (OTA)
  manifest.json + manifest.sig  active signed agent-set manifest
  manifest.json.prev + .sig     one-deep rollback copy
  agents/<...>                  verified agent payloads
  run/disable                   runtime kill-switch (presence = stop all)
  run/core-switch-pending       OTA core-swap marker
  logs/inject-YYYY-MM-DD.log    root-only daily log (retained 7 days)
```

The app zone `/data/user/0/ru.voboost/` holds `inject.json`,
`inject-status.json`, and the `staging/` OTA area.

### Initial provisioning

End-to-end device bring-up — placing the verified binary at
`/data/voboost/voboost-inject`, laying down the agents and signed manifest, and
installing the `/system` init hook — lives in
[`voboost-install`](https://github.com/voboost/voboost-install). This repo only
defines the contract the provisioned device must satisfy: the init hook execs
the stable launch path once, configured to **restart on exit** (not `oneshot`).
The no-reboot core update and clean crash recovery both depend on init
relaunching the daemon.

### Releases, signing, and the release manifest

CI builds the release binary, generates and signs the OTA release manifest, and
publishes both. The production signing public key is
`config/release-public.pem` (committed by a maintainer); the matching private
key lives only in the CI secret `SIGNING_KEY` and is never committed.

Generate a release keypair:

```sh
openssl genpkey -algorithm ed25519 -out config/release-private.pem
openssl pkey -in config/release-private.pem -pubout -out config/release-public.pem
# store config/release-private.pem as the CI secret SIGNING_KEY, then delete it locally
```

The release manifest is produced and signed by the maintainers' Make targets
(CI calls them automatically):

```sh
make release-manifest DIR=<release-dir> CHANNEL=<agents|core|app> VERSION=<semver>
make sign         KEY=<private.pem> FILE=build/release-manifest.json
make verify-sig   KEY=<public.pem>  FILE=build/release-manifest.json
```

For `beta1` the dev keypair (`config/key-dev-*`) may be reused as the release
keypair — rotate before a real release.

### After a system OTA

A system OTA reverts only `/system`, so the init hook is lost while
`/data/voboost`, the daemon, and all agents survive. An operator restores the
hook over `adb` (idempotent — a hook that already contains the block is left
untouched):

```sh
make device-rearm HOOK=<on-device init-hook path>
```

Nothing is re-downloaded; the incremental app/agents OTA is independent of the
system OTA cadence.

## Logging

The daemon logs to `/data/voboost/logs/inject-YYYY-MM-DD.log` (mode `600`,
root-only) and retains logs for **7 days**. Each line follows the shared format
`yyyy-MM-dd HH:mm:ss.SSS [tag] src: msg`, where the tag is `[*]` (info), `[+]`
(ok), or `[-]` (error). Example:

```
2026-06-26 07:52:13.042 [*] main: SIGTERM: clean shutdown
2026-06-26 07:52:14.101 [+] frida: injected native wm-viewport
```

The log stays in the root zone — the app cannot read it, and the daemon never
writes its log into the app zone.

## Diagnostics

On a rooted device (or `adb root` on a userdebug build) an operator can observe
and control the daemon directly:

```sh
# Daemon status (app zone — also what the app reads):
adb shell cat /data/user/0/ru.voboost/inject-status.json

# Today's daemon log (root zone):
adb shell cat /data/voboost/logs/inject-$(date +%F).log

# Stop all injections now (runtime kill-switch); gated processes resume:
adb shell touch /data/voboost/run/disable

# Resume: remove the kill-switch, then relaunch the daemon — injections do NOT
# resume on their own, a restart is required:
adb shell rm /data/voboost/run/disable
#   then restart the init service (or reboot) to relaunch the daemon
```

- `"state": "degraded"` in `inject-status.json` means VERIFY_SELF or the
  frida-core open failed — the daemon is observe-only until restarted.
- `"panic": true` means the global panic-quarantine tripped; it clears only on a
  daemon restart.
- A single instance is enforced via `flock` on
  `/data/voboost/run/inject.pid`; a second launch logs the conflict and exits.

## CI

### Push / PR (`ci.yml`)

Every push and pull request runs on `ubuntu-latest`:

1. `make init` — provision (cached across runs keyed on pinned revisions)
2. `make lint` — both linters
3. `make test` — host-side unit tests
4. `make build` — release-only host build for validation

### Release (`release.yml`)

Triggered by a `v*` tag:

1. `make init` — provision (cached)
2. **Version gate** — fails if the tag does not match `v$version` from
   `meson.build`
3. `make lint` + `make test` — quality gates re-run (a tag cannot bypass them)
4. Android NDK setup (`r27d`, SHA-pinned action)
5. `make build-android` — arm64-v8a, fully static
6. `llvm-strip` the device binary
7. `make release-manifest` — generates `build/release-manifest.json`
8. `make sign` + `make verify-sig` — signs with the CI secret `SIGNING_KEY`
9. Publishes `voboost-inject`, `release-manifest.json`, and `.sig` as workflow
   artifacts

## Versioning

The version lives in `meson.build` `project(version: ...)` (single source of
truth, baseline `1.0.0-beta1`). CI consumes it and never defines it elsewhere.
Bump the pre-release postfix before each release tag, then push the matching
tag; the release workflow validates `v$version == $tag` and fails if they
diverge.

    1.0.0-beta1 -> 1.0.0-beta2 -> ... -> 1.0.0-rc1 -> 1.0.0

## Project layout

```
src/            Vala daemon source (modules + VAPI bindings)
test/           Host-side unit tests + fixtures + integration test plan
config/         Build configs (uncrustify, vala-lint, cross-file, dev/release keys)
openspec/specs/ Behavioral specifications (source of truth)
subprojects/    Pinned frida git wraps (fetched by make init)
.tools/         Built tools (frida-patched valac, vala-lint; gitignored)
```

Frida is provisioned from pinned git wraps in `subprojects/` (frida,
frida-core, frida-gum, all pinned to tag `17.11.0`), fetched and cached on
`make init`; there is no hardcoded local frida source path.

## Source modules

| File | Purpose |
|------|---------|
| `main.vala` | Entry point: single-instance lock, startup gate, GMainLoop, SIGTERM |
| `supervisor.vala` | State machine (INIT→VERIFY_SELF→READY/DEGRADED), injection orchestration |
| `frida_controller.vala` | In-process frida-core driving: spawn-gating, attach, inject, resume |
| `manifest.vala` | Verified manifest parser (ed25519 sig + JSON; agent id/process/kind) |
| `plan_reader.vala` | Untrusted `inject.json` parser, validated against the manifest |
| `trust_store.vala` | Ed25519 signature verify (Monocypher), sha256 agent verify |
| `safety.vala` | Rate-limit, quarantine, panic-quarantine, coexistence skip, kill-switch |
| `status.vala` | Atomic `inject-status.json` writer (temp + rename, no symlink follow) |
| `ota.vala` | OTA apply/rollback: agent manifest swap, core install + self-shutdown |
| `app_zone_watcher.vala` | GFileMonitor on `inject.json` and `staging/update-ready` |
| `process_watcher.vala` | Event-driven target tracking via frida spawn/death signals |
| `log.vala` | Root-only daily log, 7-day retention, shared format |

## License

GNU General Public License v3. See [LICENSE](LICENSE).
