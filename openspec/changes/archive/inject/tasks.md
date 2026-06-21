## 1. Project scaffold and build (build-and-signing)

- [x] 1.1 Create the Vala project layout (`src/`, `test/`) and the daemon `meson.build` target;
      set the `project()` version baseline `1.0.0-beta1` (single source of truth)
- [x] 1.2 Configure meson release-only: `buildtype=release`, static link, LTO, strip; no debug
      target
- [x] 1.3 Wire frida-core as a meson subproject from the pinned git wrap (provisioned by `init`)
      via explicit `subproject()` + the overridden `frida-core-1.0` dependency, with pinned
      options: `default_library=static`, `frida_version`, local backend only,
      `frida-gum:v8=disabled` (QuickJS-only must be pinned — gum's `v8` defaults to `auto`);
      add `[provide]` to the frida wraps; raise the root `meson_version` floor to >= 1.1.0
- [x] 1.4 Extend `make init` to build the frida-patched Vala compiler (`valac` `-frida`,
      transitively pinned via the frida-core checkout's `releng` gitlink + `deps.toml`) into the
      tools prefix, fetching wraps up front (`meson subprojects download`); prepend the prefix
      `bin` to `PATH` in the Makefile (see the `provisioning` spec delta)
- [x] 1.5 Verify a minimal binary links against frida-core's `.vapi` and runs a bare GMainLoop
- [x] 1.6 Confirm `.gitignore` covers build artifacts, subproject checkouts, generated fixtures,
      and private keys (from `init`); commit only the public key

## 2. Trust and signing (trust-verification, build-and-signing)

- [x] 2.0 Define the manifest and `inject.json` JSON schemas per design "Data Contracts" (manifest
      has no params_schema; plan carries `startup`, `disabled`, per-agent `enabled` + opaque
      `config`); add example fixtures used by tests
- [x] 2.1 Implement the key-embedding `custom_target`: a generator reads `config/key-dev-public.pem` and
      emits `embedded-pubkey.vala` (`const uint8[] EMBEDDED_PUBKEY`, raw 32-byte ed25519)
- [x] 2.2 Implement `TrustStore`: consume `EMBEDDED_PUBKEY`; ed25519 detached-signature verify;
      file sha256
- [x] 2.3 Ensure verification is always on — no skip-verify code path in any build configuration
- [x] 2.4 Implement `Manifest`: parse and hold the manifest only after signature verification,
      per the schema
- [x] 2.5 Enforce that agent target `process` and `kind` come from the manifest, never the plan

## 3. App interface and contracts (app-interface)

- [x] 3.1 Define the on-disk layout: root zone `/data/voboost` (700) and app zone, with the trust
      boundary
- [x] 3.2 Implement `PlanReader`: read `inject.json` (untrusted); validate id-whitelist + config
      size bound; store each agent's `config` opaque (verbatim) for forwarding (no schema check)
- [x] 3.3 Implement `Status`: atomic (temp+rename) write of `inject-status.json` with the daemon
      state (`ready`/`degraded`) and all per-injection states
- [x] 3.4 Implement `AppZoneWatcher`: GFileMonitor on plan + `staging/update-ready` marker, with
      debounce
- [x] 3.5 Implement `Log`: shared format, `/data/voboost/logs/inject-YYYY-MM-DD.log` (600), 7-day
      retention. Note: `script.message` events from agents are logged without daemon-side
      throttling; high-frequency logging is the agent's responsibility to avoid (see design D8).

## 4. Injection control (injection-control)

- [x] 4.1 Implement `FridaController`: local device, spawn-gate + attach, js/native routing —
      js via a per-process session script (`create_script`), native via `inject_library_blob`
      (a frida-gum `.so`, no session, no JS); resume non-target gated spawns without attaching
- [x] 4.2 Implement lazy QuickJS: a session (and QuickJS) opens only when a process receives a
      `js` agent; a `native`-only process never opens a session and never loads QuickJS; a process
      with no agent is never attached (per-process lazy init, not a link-time omission)
- [x] 4.3 Implement `ProcessWatcher`: event-driven inject on spawn, reinject on death (bounded by
      safety rules)
- [x] 4.4 Deliver opaque `config` to agents: implement the `frida:rpc` protocol to call
      `rpc.exports.init(stage, {config})` for js agents (fire-and-forget after `script.load`);
      pass `config` as the `inject_library_blob` `data` argument for native agents
- [x] 4.5 Apply the validated plan on change: idempotently (re)inject newly-enabled agents into
      running targets (reuse the session, skip already-loaded agents — the daemon's own footprint
      is not a coexistence skip); a disabled agent stops being reinjected and clears on the
      target's next restart; `disabled` stops all injections at once

## 5. Device safety (device-safety)

- [x] 5.1 Guarantee `resume()` of every gated process on success, failure, or timeout
- [x] 5.2 Implement per-agent isolation: catch and contain Script errors without crashing the
      target
- [x] 5.3 Implement reinjection rate-limit (N/M, exponential backoff) and per-(agent,process)
      quarantine → fail-open
- [x] 5.4 Implement global panic-quarantine on target-death threshold
- [x] 5.5 Implement coexistence check via `/proc/PID/maps` and skip + status
- [x] 5.6 Implement the runtime kill-switch (`run/disable` file / plan flag): stop all, resume
      gated processes (including pending gated spawns via `enumerate_pending_spawn`), idle
- [x] 5.7 Establish capability-detection helpers for A9↔A11 differences (version string is a
      hint only)

## 6. Daemon lifecycle (daemon-lifecycle)

- [x] 6.1 Implement `main.vala` entry: init Log, TrustStore, Daemon; run GMainLoop; SIGTERM clean
      shutdown
- [x] 6.2 Implement single-instance via pidfile + `flock`
- [x] 6.3 Implement the startup-gate: read the `startup` field of the app-zone `inject.json`
      (JSON); if its value is `none` (case-insensitive) → immediate exit; absent file/field/other
      → start normally. The daemon reads no `config.yaml` and parses no YAML
- [x] 6.4 Implement `Supervisor` state machine: INIT → VERIFY_SELF → READY/DEGRADED →
      GATE/ATTACH → INJECT → MONITOR
- [x] 6.5 Implement the async error model: every async op wrapped/timed-out; no error breaks the
      GMainLoop
- [x] 6.6 Per-agent boot-readiness gate: inject on reachability by default; an agent with `boot`
      waits for `sys.boot_completed=1` + frida readiness (poll until boot, then inject the
      deferred agents); agents without the flag inject immediately

## 7. Tests (host-side, no device)

- [x] 7.0 Generate a test fixture: a manifest signed with the dev keypair (`make key-dev`) plus a
      matching agent payload, wired into meson (fixture `custom_target` + test `depends`) so
      `make test` after `make init` passes on a fresh clone with no manual step (quality-gates)
- [x] 7.1 Manifest parse + signature verification (key/manifest/signature fixtures)
- [x] 7.2 Plan validation against manifest (agent whitelist, config size bound, opaque config
      retained) — pure logic
- [x] 7.3 Rate-limit / quarantine state transitions — pure logic
- [x] 7.4 Status serialization (atomic write, all states) — pure logic
- [x] 7.5 Document on-device integration tests: spawn-gating, attach, js/native inject,
      guaranteed resume, coexistence skip, fail-open
