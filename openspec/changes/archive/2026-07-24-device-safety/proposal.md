## Why

`device-safety` is written for the frida daemon: guaranteed resume of
spawn-gated processes, per-agent isolation phrased as "Frida Script errors",
coexistence detection that scans `/proc/maps` for a "Frida agent", and a
kill-switch that "re-opens frida" on restart. The new daemon injects via ptrace
(see `native-payload`, `injection-control`), has no spawn-gating and no frida, so
these need re-rooting. The safety *intent* — never brick the head unit — is
unchanged; the mechanisms move to the ptrace/LSPlant world.

Two substantive changes beyond wording:

1. **A per-target circuit breaker is added.** The rate-limit is per
   `(agent, process)`; what protects the *device* from an injection that keeps
   killing a target is a per-target breaker: M crashes within N seconds after
   injection → stop injecting that target and report it degraded. `system_server`
   is treated more conservatively (M = 1–2) because its death is a framework
   soft-reboot.
2. **Guaranteed resume is removed.** There is no spawn-gating, so no process is
   ever left suspended; the resume guarantee has nothing to guard.

## What Changes

- **ADDED**:
  - "Per-target circuit breaker" — M crashes / N seconds after injection → stop
    injecting that target, report degraded; `system_server` conservative
    (M = 1–2).
- **MODIFIED**:
  - "Per-agent isolation" — an agent failure is contained by the agent runtime's
    per-agent `try/catch` and the implant's defensive seam invocation (see
    `agent-entry-seam`); one agent failing never crashes the target or the
    others. (Was: "Frida Script errors".)
  - "Coexistence skip" — skip a target already carrying a *foreign* injection
    footprint; the daemon's own footprint is the `libimplant.so` marker it
    tracks, not treated as foreign on re-injection. (Was: frida-agent-specific.)
  - "Runtime kill-switch" — the `run/disable` file (now under
    `/data/voboost-inject`) or the `inject.json` `enabled:false` flag stops all
    new injections and idles; deactivation does not auto-resume (restart
    required); there is no frida to re-open, and existing injections are torn
    down only via a no-agents plan (see `update-planes`).
- **REMOVED**:
  - "Guaranteed resume of gated processes" — no spawn-gating, nothing to resume.
- **Unchanged**: "No vehicle motion or ignition gating", "Reinjection rate-limit
  and quarantine", "Global panic-quarantine", "Capability detection over version
  strings".

## Capabilities

### Modified Capabilities

- `device-safety`: safety is re-rooted for ptrace/LSPlant. A per-target circuit
  breaker (M crashes / N seconds, `system_server` conservative) is added;
  per-agent isolation, coexistence skip, and the kill-switch are restated without
  frida (agent-runtime `try/catch`, `libimplant.so` own-footprint marker,
  no-frida kill-switch). Guaranteed resume of gated processes is removed because
  there is no spawn-gating.
