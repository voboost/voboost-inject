## Context

The car runs a virtualized Android guest (no flashable boot partition, no fastboot), so LSPosed/
Magisk are unavailable; persistence is only possible via a root init hook in `/system`
(`/system/etc/init.logcat.sh`) that a system OTA reverts (re-arm is covered by the `ota` change).
SELinux is permissive and `ro.debuggable=1`, but the design must not rely on permissive mode for
its security — only Unix permissions and parent-directory ownership.

Today the unprivileged app (`ru.voboost`, UID `u0_aXX`) holds root via `su 0 frida-inject` and
attaches late. The chosen runtime architecture (voboost `docs/architecture.md`, `frida.md`,
`coexistence.md`) moves root into a single minimal native daemon that embeds frida-core. This
change designs that daemon. Agents are Java-method hooks shipped inside the voboost APK, currently
`js` (QuickJS), migrating `js → hybrid → native` (frida-gum) via a per-agent `kind` field. They
must work on both Android 9 (production target) and Android 11 (verified baseline).

Frida sources are provisioned by the `init` change as a pinned git wrap under `subprojects/`
(fetched and cached by `make init`); this design assumes them present and does not hardcode a
local path. The dev public key (`config/key-dev-public.pem`, from `make key-dev`) is likewise present.

## Goals / Non-Goals

**Goals:**
- Be the *only* root-holding component; the app becomes unprivileged config/plan/status I/O.
- Earliest possible injection (spawn-gating before target code runs) with smallest footprint
  (QuickJS not V8; static link, LTO, strip; release-only).
- Never break the device: fail-open, guaranteed `resume()`, per-agent isolation, quarantine.
- Verify everything against an embedded public-key trust anchor before acting.
- Files-only IPC; no listening socket.
- Open-source-friendly signing: no private key in the repo; builds work for devs and CI.

**Non-Goals:**
- Incremental/delta OTA, the signed release-manifest, staging→trusted swap mechanics, and
  post-system-OTA re-arm — all owned by the separate `ota` change.
- Feature logic / config interpretation. The daemon is a verify + validate + inject executor; the
  app owns `config.yaml` and its feature logic and derives `inject.json` (including each agent's
  opaque `config` object). The daemon does **not** read `config.yaml` and does **not** interpret
  agent `config` — it validates identity + size and forwards config verbatim to the agent (D11).
- Provisioning/installer for the root zone (how files first land in `/data/voboost`).
- Vehicle motion / ignition gating. The daemon does NOT gate injection on vehicle motion
  or ignition state; agents are UI/WindowManager hooks that are safe to inject regardless
  of vehicle state. The device-safety guarantees (resume, quarantine, fail-open) are the
  correct safeguard, not a motion sensor gate.

## Decisions

### D1. Embedded frida-core, in-process, no socket (vs frida-inject / frida-server)
Link `libfrida-core` and drive it in-process. Enables spawn-gating (earliest reach) and multiple
sessions per process with no exec and no socket. *Rejected:* `frida-inject` (attach-only, late,
~50 MB V8 binary); `frida-server` (root socket = attack surface, conflicts with files-only model).

### D2. Language Vala (vs C/C++/Rust)
frida-core is itself Vala and ships a `.vapi`, so Vala uses its GObject/async API directly —
no FFI,
idiomatic `yield` over a GMainLoop, native binary the same size as C. C/C++ are FFI-free but less
idiomatic for the async API; Rust would need an FFI layer.

### D3. QuickJS instead of V8; per-process lazy runtime; native = no-JS gum agent
Build frida-core with QuickJS (not V8), dropping the in-target JS runtime from tens of MB to a few
MB. Two distinct, layered footprint wins:
- **Lazy attachment (per-process):** the frida runtime is loaded only in a process we actually
  inject; a process we do not target is never attached and loads nothing (global spawn-gating
  resumes it untouched, see D7).
- **`kind` routing:** a `js` agent runs JavaScript on QuickJS via a session script
  (`create_script`); a `native` agent is a **frida-gum native `.so` injected via
  `inject_library_blob`/`inject_library_file`** (with an exported entrypoint) and runs with **no JS
  engine at all**. So a process that receives only `native` agents never loads QuickJS — the
  original lazy-engine claim holds, because `native` here is a real native library, NOT QuickJS
  bytecode. (`create_script_from_bytes` would be precompiled QuickJS bytecode — still JS on
  QJS — and is therefore NOT the `native` path.)
- **End state (JS→hybrid→native migration, `frida.md`):** as agents are rewritten from `js` to
  native gum `.so` and their `kind` flips to `native`, QuickJS is needed in fewer processes; once
  no `js` agents remain, frida-core is built **without any JS engine** (QuickJS compiled out of the
  binary entirely — the smallest footprint). That binary-level compile-out needs a separate
  frida-core build option and belongs to that future migration change, not this one.

The build-level win realized in *this* change is QuickJS-instead-of-V8 plus lazy attachment; the
full JS-drop is the migration's end state.

### D4. Trust anchor = public key embedded in the binary; no `key.pub` on disk
The only anchor is the compiled-in public key. An on-disk `key.pub` is removed — it would be a
confusing second anchor and dead weight. The signed manifest (ed25519, detached `manifest.sig`)
ships inside the APK; the daemon verifies the manifest signature, then each agent's sha256, before
injecting. An agent's target `process` and `kind` come only from the manifest, never from the
app-written plan (the plan is untrusted input).

### D5. Two independent stop mechanisms — startup-gate AND kill-switch
They serve different roles and do not conflict:
- **startup-gate** = *intent*. On startup the daemon reads the top-level `startup` field of the
  app-written `inject.json` (the single app→daemon hand-off file). If its value is `none`
  (case-insensitive) the daemon exits immediately without acting; absent file, absent `startup`, or
  any other value → start normally. The app mirrors its own startup intent into `inject.json` when
  it derives the plan. Reading untrusted app input here is safe: the gate can only move behavior in
  the fail-safe direction (skip injection), and everything injected is still signature-verified.
  *Decision (revised):* the gate lives in `inject.json`, NOT in `config.yaml`. The daemon
  therefore does **not** read `config.yaml` at all — it reads no YAML and parses no feature
  config. This keeps
  all app→daemon intent in one already-watched JSON file and removes the YAML line-scan entirely.
  *Rejected:* reading `config.yaml` (couples the daemon to the app's config format) and a root-zone
  marker (the unprivileged app cannot write the root zone).
- **kill-switch** = *runtime circuit-breaker*. `/data/voboost/run/disable` or a plan flag stops all
  injections, resumes all gated processes, and idles — even when the startup gate said run. Plus a
  global panic-quarantine when target-death thresholds are exceeded. *Recovery:* deactivating the
  kill-switch (deleting the file or setting `disabled: false`) does NOT automatically re-open frida
  or resume injections; a daemon restart is required (a one-way teardown keeps the circuit-breaker
  simple).

### D6. Device safety as hard invariants
Guaranteed `resume()` of every spawn-gated process even on failed/timed-out injection (never hang
boot); per-agent isolation (a failing agent never aborts others or crashes the target);
reinjection rate-limit (N per M minutes per (agent,process), exponential backoff) → quarantine
→ fail-open; target-side async ops on the GMainLoop are bounded with timeouts
(resume and local control ops are not — resume must complete to guarantee it, per
daemon-lifecycle). Capability-detection (does the
class/method/overload exist) over `ro.build.version.release` strings for A9↔A11 differences.

### D7. Coexistence and single-instance
Before injecting a process, check `/proc/PID/maps` for an already-present Frida agent (another root
tool); if present, skip + status. Confirming *our own* injection needs no `/proc/maps` — embedded
frida-core returns the load result directly. The corollary: the check applies only to processes
the daemon has not injected itself. After our own injection the target's maps contain our frida
agent, so a plan-change re-injection into a pid the daemon already tracks in memory skips the
coexistence scan instead of mistaking its own footprint for a foreign tool.
Single-instance via pidfile + `flock`, not process-name
matching. Injection state (pid, attempts, quarantine) lives in memory in the resident daemon; the
model is event-driven (spawn-gating / process events), not polling — no file markers.

### D8. Logging to the root-only zone
`/data/voboost/logs/inject-YYYY-MM-DD.log` (600), shared format with the app
(`yyyy-MM-dd HH:mm:ss.SSS [tag] source: message`, tags `[-]`/`[+]`/`[*]`), 7-day retention. The
daemon runs as root; writing into the app zone would let the unprivileged app read/delete/tamper
the daemon's log and would cross the trust boundary, so the log stays root-only. Note:
`script.message` events from loaded agents are logged at the same per-line granularity with no
daemon-side throttle; agents SHOULD NOT use `send()` as a high-rate debug channel — high-frequency
logging is the agent's responsibility to avoid.

### D9. Open-source signing model
Private signing key only in CI secrets (e.g. GitHub Actions secret / KMS); public key committed in
source. A local developer generates a personal dev keypair, bakes their own public key into a local
build, and signs their own test agents with it. Signature verification is **always on**, including
dev builds — there is no "skip verify" mode. The CI release pipeline that actually signs this
binary's manifest with the secret key on a tag is implemented by the `ci` change (after `inject`);
this design only fixes the trust model, not the pipeline.

### D9b. Public-key embedding mechanism
The trust anchor is compiled in, not read from disk. At build time a meson `custom_target` runs
a small generator that reads `config/key-dev-public.pem` (locally) or the committed release public key
(in CI) and emits `embedded-pubkey.vala` — a single `const uint8[] EMBEDDED_PUBKEY` (raw 32-byte
ed25519 key) consumed by `TrustStore`. The PEM is parsed at generation time, so the binary
carries only raw key bytes and no PEM/file dependency at runtime. Changing the baked key is a
rebuild, never a config flip. *Alternative rejected:* reading `key.pub` at runtime — a second,
on-disk trust anchor that contradicts D4.

### D9c. Per-agent manifest is signed by the app build, not this CI
The per-agent `manifest.json` (with per-agent `id`/`process`/`kind`/`sha256`) ships inside the
voboost APK and is signed during the **app build pipeline** in the `ru.voboost` repository, not by
this repo's CI. This repo's `ci` change signs only the OTA `release-manifest.json` (per-file
hashes/sizes/channels). Both manifests use the same ed25519 key family.

### D9d. ed25519 verify via the Monocypher meson subproject (no system crypto lib)
Signature verification uses **Monocypher** (single-file, audited, public-domain) pinned as a
**meson subproject** statically linked. Its optional `monocypher-ed25519` module implements
RFC 8032 Ed25519. A minimal `src/ed25519.vapi` binds `crypto_ed25519_check` directly. No
system crypto library (gnutls/openssl) is linked. This matters for the static device build:
frida-core already bundles dependencies statically; the only "extra" dependency a
gnutls-based verifier would add is exactly the one frida dropped.

### D10. Build: meson, release-only
No debug build configuration. `buildtype=release`, frida-core statically linked into the daemon,
LTO, strip. The full `-static` link is applied **only to the Android device build**
(`make build-android`) so the deployed daemon is self-contained on a device that has no
glib/gio/json-glib; it is NOT applied to the host build (`make build`), where a full `-static`
link is unsupported on the macOS dev host and would break the host test build.
The split is `meson.is_cross_build() ? ['-static'] : []`.
This change sets the `project()` version baseline `1.0.0-beta1` in `meson.build` (the single
source of truth the `ci` change later bumps and tags; the daemon reads its own version from there
via a generated constant, never hardcoding it).

### D10a. Frida-lib integrity: waiver
frida-core is statically linked into the daemon binary. There is no separate frida lib file on
disk to verify at runtime. The daemon binary itself is root-owned and can only be replaced via the
root-zone trust chain. *Decision:* frida-lib integrity is guaranteed by static linking; the
VERIFY_SELF state machine verifies the manifest signature and each agent sha256 only — it does not
attempt a separate frida-lib check because no such file exists. This waiver is recorded here so
the omission is deliberate and not an oversight.

### D10b. Android cross-compilation target
The daemon runs on an Android device (arm64-v8a). The `init` change provides a meson cross-file
`config/android-cross.ini` targeting `aarch64-linux-android` via the Android NDK. `make build`
defaults to a host build (for tests); `make build-android` invokes `meson setup` with
`--cross-file config/android-cross.ini` and produces the device binary. CI uses `build-android`
for the release artifact.

### D10c. frida-core subproject: toolchain and option pinning
Building the pinned frida-core wrap as a meson subproject has three hard preconditions:
- **Patched Vala compiler.** frida-core's `meson.build` hard-errors unless `valac` version ends
  in `-frida`. `make init` builds the frida Vala fork and prepends it to `PATH`.
- **`releng` is absent from the wrap checkout.** frida-core's only unconditional releng use is
  computing `frida_version`, bypassed by pinning `frida-core:frida_version=17.11.0`.
- **meson >= 1.1.0** (frida-core's floor).

Option pinning (root `default_options`, prefixed per subproject) keeps the build QuickJS-only,
static, and minimal. Pinned: `frida-core:default_library=static`,
`frida-core:frida_version=17.11.0`, `frida-gum:v8=disabled` (QuickJS stays enabled by gum's own
default).

### D11. Parameter transport — RPC for js, data-arg for native; opaque config
The app produces each agent's full `config` object and writes it into `inject.json`.
The daemon forwards it **verbatim**:
- **js agents:** the daemon delivers config via `rpc.exports.init(stage, parameters)` with
  `parameters.config = <config>`. The daemon implements the `frida:rpc` protocol itself:
  post `["frida:rpc", id, "call", "init", [stage, {config}]]` after `script.load()`.
- **native agents:** config is passed as the `data` string argument of `inject_library_blob`.

*Validation = opaque pass-through + size cap.* The daemon validates only that the agent `id` is
manifest-whitelisted and that `config` is within `MAX_CONFIG_BYTES` — a memory/DoS guard,
not a schema check.

## Data Contracts

Two JSON documents drive the daemon. The **manifest** is signed and trusted; the **inject plan**
(`inject.json`) is written by the unprivileged app and is untrusted input validated against the
manifest.

### Signed manifest (`manifest.json` + detached `manifest.sig`)
Verified as a whole against the embedded public key, then each agent's file is verified by `sha256`
before injection. The agent's target `process` and `kind` come **only** from here, never from the
plan.

- `version` (int): manifest schema version.
- `daemon` (string): target daemon version; informational compatibility hint, not enforced.
- `agents[].id` (string): stable agent key referenced by the plan.
- `agents[].channel` (string): agent channel (`agents`, `core`, or `app`); defaults to `agents`. Organizational, not security-relevant.
- `agents[].file` (path): the agent payload; the daemon resolves it against `/data/voboost`.
- `agents[].sha256` (64-hex): verified before injection.
- `agents[].process` (string): target process name — trusted, manifest-only.
- `agents[].kind` (enum `js|native`): runtime routing. `js` runs on QuickJS via a session
  script; `native` is a frida-gum `.so` injected via `inject_library_blob`.
- `agents[].entrypoint` (string): exported init symbol of native `.so`.
- `agents[].boot` (bool, default false): per-agent boot gate. When true the daemon defers
  injection until `sys.boot_completed=1`; default false injects as soon as the target is
  reachable (earliest). Trusted, manifest-only.

### Inject plan (`inject.json`, untrusted, app-written)
The single app→daemon hand-off file. It carries the startup gate, the plan-level kill-switch,
and the per-agent enable flags + opaque config. Validated against the manifest: every `id` must
exist in the manifest and each `config` must be within the size bound; the plan carries **no**
`process`/`kind`/`sha256`/`entrypoint`.

- `version` (int): plan schema version.
- `startup` (string): the startup gate. `none` → daemon exits immediately; any other value →
  start normally. Replaces `config.yaml`.
- `disabled` (bool): plan-level kill-switch; when true the daemon stops all injections and idles.
- `agents[].id` (string): must match a manifest agent.
- `agents[].enabled` (bool): whether to inject this agent.
- `agents[].config` (object, opaque): the agent's configuration object. The daemon forwards
  it verbatim and never interprets it. Bounded by a per-agent size cap (`MAX_CONFIG_BYTES`);
  the whole file is bounded by `MAX_PLAN_BYTES`.

### Status (`inject-status.json`, daemon-written, app-readable)
Atomic write reporting the daemon state (`ready`/`degraded`), daemon/manifest versions,
kill-switch state, and per-injection state (`active|failed|skipped-coexist|waiting|quarantined`).

## Risks / Trade-offs

- [Injecting into system_server] → by default inject as soon as reachable (earliest),
  letting agents defer hook installation until classes are available (`Java.perform`).
- [A bad agent could repeatedly crash a target] → rate-limit + quarantine → fail-open.
- [Static-linking frida-core / running a GMainLoop] → accepted; the only mode that wins on
  earliest/fastest/smallest/safest simultaneously.
- [A9↔A11 hook divergence] → capability-detection at runtime.
- [Trust boundary depends on parent-dir ownership, not SELinux] → `/data/voboost` is root:root
700;
  the app cannot rename/replace/read it.
- [Manifest replay] → mitigated by the root-only zone (700 root:root); write access to
  `/data/voboost` requires root compromise, which is out of scope.

## Migration Plan

This change implements the daemon: `tasks.md` writes `src/*.vala`, wires the meson target and the
key-embedding `custom_target`, sets the version baseline, and adds host-side tests, so that
`make build` produces the `voboost-inject` binary and `make test` runs green.
Device rollout sequencing: provision the root zone, append the guarded init-hook block, then the
app drops its `su 0 frida-inject` path. Rollback is fail-open by construction — if the daemon
is absent or in DEGRADED state, no injection happens and targets run unmodified.

## Open Questions

- Provisioning/installer for the root zone (binary, signed manifest, agents) — out of scope of
  this project; assumed present here.
