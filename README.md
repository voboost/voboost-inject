# voboost-inject

**English** | [Русский](README.ru.md)

**voboost-inject** is the root injection component of Voboost: a Rust daemon
that drives a ptrace injector and an LSPlant C++ implant, runs as **root**, and
injects cryptographically **signed** agents into target Android processes —
typically `system_server` and other framework processes the unprivileged
[Voboost app](https://github.com/voboost/voboost) cannot touch.

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
- [`voboost-script`](https://github.com/voboost/voboost-script) — the signed
  `.dex` agents (LSPlant hooks) and the **signed agent-set manifest** they
  ship in.
- [`voboost-install`](https://github.com/voboost/voboost-install) — device
  bring-up: first install of the daemon binary, agents, and the `/system` init
  hook.

This README covers the daemon's contract and build. Agent authoring and signing
live in [`voboost-script`](https://github.com/voboost/voboost-script); end-to-end
device bring-up lives in
[`voboost-install`](https://github.com/voboost/voboost-install).

## Quick start

```sh
make init     # provision Rust toolchain + cargo-ndk + NDK r29 verify + dev key
make build    # host build of the daemon (cargo)
make test     # host-side Rust tests, device-free
```

A device build and first-time install are covered further below.

## What it does

- **Root daemon.** A single resident root process, launched at boot by a
  `/system` init hook. Single-instance is enforced with a pidfile guarded by
  `flock` (not by process-name matching); a second instance logs the conflict
  and exits without injecting.
- **Ptrace injection + LSPlant implant.** The daemon ptrace-attaches to a
  target, dlopens a small C++ implant (`libimplant.so`), which attaches to ART,
  initializes LSPlant, and loads the signed `.dex` agent via
  `InMemoryDexClassLoader`. No socket, no per-injection helper process, no
  frida — the implant and its Dobby/LSPlant dependencies ship per ABI and are
  verified by sha256 against the signed release manifest before use.
- **Signed agents only.** Every agent is verified twice before it runs: the
  agent-set manifest is checked against a public key compiled into the binary
  (ed25519), and each agent file is checked by sha256 against that verified
  manifest. Verification is always on — there is no skip-verify mode.
- **Early injection.** The daemon launches `on nonencrypted` (before
  `system_server` rises) and ptrace-attaches to targets as soon as they appear
  in `/proc`, so agents load early in the target's lifetime. There is no
  spawn-gating — targets are already running when injected.
- **Device safety.** Agents are isolated per agent; a failing agent is
  rate-limited and quarantined, a per-target circuit breaker trips on repeated
  crashes, and a mass-death threshold trips a global panic-quarantine that
  stops all injections. A runtime kill-switch
  (`/data/voboost-inject/run/disable`) stops everything and idles. (Mechanics
  and exact thresholds: *Architecture → Device safety*.)
- **OTA without a device reboot.** Agents and the daemon binary itself update
  on-device: agents via an atomic manifest swap, the core binary via a
  content-addressed install plus a clean self-shutdown that Android init turns
  into a restart of the new binary — no reboot required, with automatic
  rollback if the new binary comes up degraded. (Details: *OTA update planes*.)

## How it works with the Voboost app

The Voboost app ([`voboost`](https://github.com/voboost/voboost), package
`ru.voboost`) is an ordinary, unprivileged user-space app. It self-distributes
(not via Play) and ships the signed `.dex` agents inside its own APK.
The daemon and the app never share a socket — they communicate **only through
files**, across two strictly separated trust zones on the device:

| Zone | Path | Owner | Who writes |
|------|------|-------|------------|
| Root zone (trusted) | `/data/voboost-inject` | root:root, `700` | daemon only |
| App zone (untrusted) | `/data/user/0/ru.voboost` | the app | app; daemon writes status only |

The app **cannot** read, rename, or replace anything in `/data/voboost-inject`. The
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
  target `process` from the **verified manifest**, never from this plan;
  `config` is opaque bytes, size-bounded only (64 KiB per agent, 1 MiB for
  the whole file).

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

- **`staging/` + `core-update-ready`** *(app → daemon, app zone)* — the OTA
  staging area. The app downloads updated agents/manifest, writes them into
  `staging/`, and creates the `core-update-ready` marker last. The daemon
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
3. Recovers the manifest from `.prev` if the active copy is bad (boot
   recovery), then enters VERIFY_SELF: verifies the manifest ed25519 signature
   against the embedded key, then checks every agent sha256.
4. On success, enters READY; applies any staged inject update (OTA) before the
   first injection, then begins the poll loop.
5. On failure (bad signature or hash mismatch), enters DEGRADED — observe-only,
   no injections. A pending inject switch is rolled back first.

### Per-target lifecycle

```
ATTACH (ptrace an already-running target)
  -> VERIFY PAYLOAD (sha256 against the verified release manifest)
  -> INJECT (ptrace dlopen libimplant.so -> ART attach -> LSPlant -> load .dex agent)
  -> MONITOR (watch for death, reinject within safety budget)
```

- The poll loop watches `/proc` for target appearances/deaths every 2 s and
  ptrace-attaches to new appearances (no spawn-gating — targets are already
  running when injected).
- An agent with `boot: true` in the manifest is deferred until
  `sys.boot_completed=1`; other agents inject immediately.

### Device safety

- **Per-agent isolation.** One agent failing does not affect others or crash
  the target.
- **Rate-limit + quarantine.** Repeated target deaths for the same
  (agent, process) pair trigger exponential backoff, then quarantine (the
  agent stops injecting; the target runs unmodified).
- **Per-target circuit breaker.** Repeated crashes of one target (more
  conservative for `system_server`) mark it degraded and stop injecting it.
- **Panic-quarantine.** Mass target deaths across the device trip a global
  stop — all injections halt.
- **Coexistence skip.** If `/proc/PID/maps` shows a foreign hooking agent
  already present (frida, xposed, shadowhook), injection is skipped for that
  process.
- **Runtime kill-switch.** The file `/data/voboost-inject/run/disable` or the plan
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
  runtime when the `core-update-ready` marker appears).
- Core updates rename the running binary aside to `voboost-inject.prev`,
  install the new binary at the stable launch path `voboost-inject`, and
  self-shutdown; Android init restarts the service. The previous binary is
  kept as `.prev` for rollback.
- If the new binary starts DEGRADED, it rolls back to the previous binary
  automatically.
- The `core-update-ready` marker is single-use: consumed after any apply
  attempt (success or verified failure).

## Security

- **Trust anchor is compiled in.** The only verification key is baked into the
  binary at build time; the daemon never loads a key from disk, and signature +
  sha256 verification is always on — there is no skip-verify mode.
- **Defense-in-depth on the root zone.** `/data/voboost-inject` and its whole parent
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
- **ed25519 via ed25519-dalek.** Signature verification is the `ed25519-dalek`
  crate (compiled into the daemon); sha256 via the `sha2` crate. The native
  payload files (no appended signature of their own) are verified by sha256
  against the signed release manifest.
- **Minimal attack surface.** The daemon opens no listening socket and runs no
  per-injection helper process — injection is ptrace + an in-process implant
  (`libimplant.so`), all in-process over the local device.

## Writing agents

Agents are authored, built, and signed in
[`voboost-script`](https://github.com/voboost/voboost-script); this section
describes the per-agent contract the daemon verifies, so a manifest is
recognizable from the daemon's side. The tooling to assemble the manifest and
sign it with the matching private key is part of
[`voboost-script`](https://github.com/voboost/voboost-script).

An agent is compiled Java (`.dex`) loaded into the target process via LSPlant
(see *Per-target lifecycle* above). The implant resolves the agent entry class
`ru/voboost/agents/AgentEntry` and calls its `init(String configPath)` method
(see `implant/include/agent_entry_seam.h`). It is verified by manifest
signature + sha256 and receives its `config` from `inject.json` via the
channel-B config file. Agent authoring lives in
[`voboost-script`](https://github.com/voboost/voboost-script).

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
      "file": "agents/wm-viewport.dex",
      "sha256": "86e413ce702abb872718569c06a2e01c52553ad35953c6df122e007d3146a87a",
      "process": "system_server",
      "boot": false
    }
  ]
}
```

`version` is the manifest version reported back as `"manifest"` in
`inject-status.json`; `boot: true` defers the agent until the device finishes
booting. The manifest is signed with the private key matching the daemon's
embedded public key; the daemon verifies the signature, then each agent's
sha256 against it (see `openspec/specs/trust-verification`).

### Agent (.dex on LSPlant)

```java
// agents/wm-viewport — compiled to wm-viewport.dex, loaded via
// InMemoryDexClassLoader. The implant calls AgentEntry.init(configPath),
// where configPath is the channel-B config file holding this agent's
// "config" from inject.json.
package ru.voboost.agents;

public class AgentEntry {
    public static void init(String configPath) {
        // read config, install LSPlant hooks on a framework class...
    }
}
```

### Agent ↔ daemon messaging

The daemon delivers each agent's `config` (from `inject.json`) over channel B
(a per-process JSON config file in the shared dir), and aggregates per-agent
status back from a per-process agent-status file:

- **daemon → agent:** the daemon writes the per-process config to
  `/data/voboost-inject/shared/<process>-config.json`; the implant reads it at
  load and passes the path to `AgentEntry.init`.
- **agent → daemon:** the agent writes status to
  `/data/voboost-inject/shared/<process>-agent-status.json`; the daemon
  aggregates it into `inject-status.json`. (The agent-authoring side of this
  contract lives in `voboost-script`.)

## Build

The stack is **Rust** (the daemon, via `cargo` + `cargo-ndk`) and **C/C++**
(the ptrace injector + LSPlant implant, via NDK `ndk-build`). There is no
meson, Vala, or frida. The Android NDK r29 is the single cross-build
prerequisite.

### Prerequisites

All required tools are installed by `make init`:

- Rust toolchain (`cargo`/`rustup`), pinned via `rust-toolchain.toml`
- `cargo-ndk` (Android cross-build), installed by `make init`
- openssl (ed25519 keys/signing), uncrustify (C/C++ lint), git
- Android NDK r29 — external; set `ANDROID_NDK_HOME` for device builds

Verify everything is present:

```sh
make check
```

### From a fresh clone

```sh
make init     # provision Rust toolchain + cargo-ndk + NDK r29 verify + dev key
make build    # host build of the daemon (cargo)
make test     # host-side Rust tests (device-free)
```

`make init` provisions the Rust toolchain (from `rust-toolchain.toml`),
installs `cargo-ndk`, verifies NDK r29 is present, and generates the local dev
keypair at `config/key-dev-private.pem` (gitignored) /
`config/key-dev-public.pem` (committed, baked into the binary by `build.rs`).

### Per-OS notes

**macOS (Homebrew)** — `make init` runs
`brew install uncrustify openssl@3 curl git`, then installs the Rust toolchain
via rustup (or relies on an existing one) and `cargo-ndk`.

**Linux (Ubuntu/Debian)** — `make init` runs `apt-get` (via `sudo`) for
`build-essential uncrustify openssl curl git pkg-config`, then the Rust
toolchain and `cargo-ndk`.

**Windows** — use WSL2 + Ubuntu (the Android cross toolchain is Linux-native):

```pwsh
wsl --install -d Ubuntu
```

then follow the Linux path inside WSL2.

### Host vs. device build

```sh
make build          # host build: daemon (cargo), for tests
make build-android  # device build: daemon ELF (cargo-ndk) + native payload (ndk-build)
```

`make build-android` needs the Android NDK in `ANDROID_NDK_HOME` (r29). It
delegates to `make build-new`, which builds:

- the native artifacts: the injector (`libinjector.a`, C, arm64-v8a) and the
  implant (`libimplant.so`, C++, arm64-v8a + armeabi-v7a) via `ndk-build`;
- the daemon ELF via `cargo ndk -t arm64-v8a build --release`.

CI pins NDK **r29** — LSPlant's C++23 modules fail on r27. Use the same locally
for reproducible device builds. LTO is disabled for the native artifacts
(LSPlant C++23 modules); the daemon uses `lto = false` too.

### Lint and test

```sh
make lint      # cargo fmt --check + cargo clippy (deny warnings) + uncrustify --check (gate)
make lint-fix  # cargo fmt + uncrustify --replace (canonical style in place)
make test      # cargo test (host-side, silent on success)
```

`make lint` lints Rust (`cargo clippy` + `cargo fmt --check`) and C/C++
(`uncrustify --check` over `injector/` and `implant/`). `make test` runs the
Rust test suite on the host (the FFI extern blocks to the injector are not
linked under `check`/`test`, so pure-Rust tests run without the NDK).

## Install / deploy

### Device layout

On a provisioned device the daemon owns the root zone `/data/voboost-inject`:

```
/data/voboost-inject/
  voboost-inject                stable launch path the init hook execs
  voboost-inject.prev           previous core binary, kept for OTA rollback
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
`/data/voboost-inject/voboost-inject`, laying down the agents and signed manifest, and
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
`/data/voboost-inject`, the daemon, and all agents survive. An operator restores the
hook over `adb` (idempotent — a hook that already contains the block is left
untouched):

```sh
make device-rearm HOOK=<on-device init-hook path>
```

Nothing is re-downloaded; the incremental app/agents OTA is independent of the
system OTA cadence.

## Logging

The daemon logs to `/data/voboost-inject/logs/inject-YYYY-MM-DD.log` (mode `600`,
root-only) and retains logs for **7 days**. Each line follows the shared format
`yyyy-MM-dd HH:mm:ss.SSS [tag] src: msg`, where the tag is `[*]` (info), `[+]`
(ok), or `[-]` (error). Example:

```
2026-06-26 07:52:13.042 [*] main: SIGTERM: clean shutdown
2026-06-26 07:52:14.101 [+] injector: injected pid=1234
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
adb shell cat /data/voboost-inject/logs/inject-$(date +%F).log

# Stop all injections now (runtime kill-switch); gated processes resume:
adb shell touch /data/voboost-inject/run/disable

# Resume: remove the kill-switch, then relaunch the daemon — injections do NOT
# resume on their own, a restart is required:
adb shell rm /data/voboost-inject/run/disable
#   then restart the init service (or reboot) to relaunch the daemon
```

- `"state": "degraded"` in `inject-status.json` means VERIFY_SELF failed
  (manifest signature or agent sha256 mismatch) — the daemon is observe-only
  until restarted.
- `"panic": true` means the global panic-quarantine tripped; it clears only on a
  daemon restart.
- A single instance is enforced via `flock` on
  `/data/voboost-inject/run/inject.pid`; a second launch logs the conflict and exits.

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
   `Cargo.toml`
3. `make lint` + `make test` — quality gates re-run (a tag cannot bypass them)
4. Android NDK setup (`r29`, SHA-pinned action)
5. `make build-android` — daemon ELF (cargo-ndk, arm64-v8a) + native payload
   (ndk-build, LTO disabled)
6. `llvm-strip` the daemon ELF; `make sign-elf` builds the signed inject payload
7. Stage the inject payload + per-ABI payload files
8. `make release-manifest` — generates `build/release-manifest.json`
9. `make sign` + `make verify-sig` — signs with the CI secret `SIGNING_KEY`
10. Publishes the inject payload, per-ABI payload, `release-manifest.json`,
    and `.sig` as workflow artifacts

## Versioning

The version lives in `Cargo.toml` `[package].version` (single source of truth,
baseline `1.0.0-beta1`). CI consumes it and never defines it elsewhere. Bump
the pre-release postfix before each release tag, then push the matching tag;
the release workflow validates `v$version == $tag` and fails if they diverge.

    1.0.0-beta1 -> 1.0.0-beta2 -> ... -> 1.0.0-rc1 -> 1.0.0

## Project layout

```
daemon/         Rust daemon source (poll loop, trust, safety, OTA, status)
injector/       C ptrace injector (ndk-build -> libinjector.a)
implant/        C++ LSPlant implant (ndk-build -> libimplant.so per ABI)
third_party/    git submodules: Dobby + LSPlant (built from source, NDK r29)
prebuilt/       generated libdobby.a + liblsplant.so per ABI (make build-third-party)
selinux/        voboost-inject.te + file_contexts (ptrace allow rules)
config/         Build configs (uncrustify), init .rc, dev/release keys
test/           Host-side unit tests + fixtures + integration test plan
openspec/specs/ Behavioral specifications (source of truth)
```

The native payload toolchain is NDK r29 (Clang 21) for all C/C++ artifacts;
LSPlant's C++23 modules fail on older NDKs. Dobby + LSPlant are built from
source via `make build-third-party` (c++_static, gated by `make check-prebuilt`
to ban libc++_shared). liblsplt.so is not used (not in DT_NEEDED of
liblsplant.so, not dlopened by the implant) and is no longer produced.

## Source modules

| File | Purpose |
|------|---------|
| `daemon/src/main.rs` | Entry point: single-instance lock, startup gate, VERIFY_SELF, OTA apply, SIGTERM, poll loop |
| `daemon/src/injector.rs` | FFI to the C injector (`vbi_inject`): ptrace attach → dlopen `libimplant.so` |
| `daemon/src/manifest.rs` | Verified agent-manifest parser (ed25519 sig + JSON; agent id/process) |
| `daemon/src/release_manifest.rs` | Signed release-manifest parser (native payload sha256 + per-ABI `abi` coverage) |
| `daemon/src/plan.rs` | Untrusted `inject.json` parser, validated against the manifest |
| `daemon/src/trust.rs` | Ed25519 signature verify (ed25519-dalek), sha256 agent/payload verify |
| `daemon/src/safety.rs` | Rate-limit, circuit breaker, panic-quarantine, coexistence skip, kill-switch |
| `daemon/src/reconcile.rs` | Maps marker (already injected?), foreign-footprint skip, bitness detect |
| `daemon/src/process_watcher.rs` | `/proc` polling: find target pids, track appearances/deaths |
| `daemon/src/ota.rs` | Atomic apply/rollback + inject self-update (ELF + payload swap, `.prev` rollback) |
| `daemon/src/status.rs` | Atomic `inject-status.json` writer (temp + rename, no symlink follow) |
| `daemon/src/control_plane.rs` | Channel B: per-process config delivery + agent-status aggregation |
| `daemon/src/boot.rs` | Boot-state gate (`sys.boot_completed`), env-var escape hatch |
| `injector/*.c` | C ptrace injector → `libinjector.a` (attach, remote_call64/32, `__loader_dlopen`) |
| `implant/*.cpp` | C++ LSPlant implant → `libimplant.so` (ART attach, hidden-API exempt, dex load) |

## License

Dual-licensed:

- [PolyForm Noncommercial 1.0.0](https://github.com/voboost/voboost-license/blob/main/LICENSE) — free for personal use
- [Commercial license](https://github.com/voboost/voboost-license/blob/main/COMMERCIAL.md) — required otherwise
