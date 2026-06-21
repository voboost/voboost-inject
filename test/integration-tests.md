# On-device integration tests (voboost-inject)

These scenarios require a rooted Android target (A9 production, A11 baseline) with the daemon
provisioned into `/data/voboost` and the app zone populated. Host-side `meson test` does not
cover them; run them manually on-device after `make build-android` and deployment.

## Preconditions
- Daemon binary, signed `manifest.json` + `manifest.sig`, and agents under `/data/voboost` (700).
- App zone `/data/user/0/ru.voboost/` with `inject.json` (carries `startup`, `disabled`,
  per-agent `enabled` + opaque `config`). The daemon does not read `config.yaml`.
- Watch `/data/voboost/logs/inject-YYYY-MM-DD.log` and `inject-status.json` for outcomes.

## Scenarios
1. Spawn-gating (earliest reach): a gated target receives its agents before it runs its own
   code, then resumes. Verify the agent's effect is present from process start.
2. Attach (already running): a target alive at READY is attached and injected.
3. js / native routing: a `js` agent loads on QuickJS via a session script and receives its
   config through `rpc.exports.init`; a `native` agent is injected as a frida-gum `.so` via
   `inject_library_blob` (config in the `data` arg) with no QuickJS in a native-only process.
4. Guaranteed resume: force an injection failure/timeout on a gated process; confirm it is
   resumed anyway and never left suspended (boot never hangs).
5. Coexistence skip: pre-load another Frida tool into a target; the daemon skips it and records
   `skipped-coexist` in status.
6. Fail-open under quarantine: make a target keep dying after an agent injects; confirm rate-
   limit → quarantine → the target then runs unmodified, and `quarantined` appears in status.
7. Kill-switch: create `/data/voboost/run/disable` at runtime; all injections stop and gated
   processes resume.
8. Startup-gate: set `"startup": "none"` in `inject.json`; the daemon exits without acting.
9. Per-agent boot gate: an agent with `boot:true` is not injected into `system_server`
   until `sys.boot_completed=1`; an agent without the flag injects as soon as the process appears.
10. Config delivery: a `js` agent's `rpc.exports.init` receives `parameters.config`; changing
    `config` in `inject.json` re-applies on the next plan-change.
