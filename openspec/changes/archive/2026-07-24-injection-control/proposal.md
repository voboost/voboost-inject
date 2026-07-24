## Why

The `injection-control` spec describes how the daemon drives `frida-core`:
in-process local device, global spawn-gating, per-process QuickJS sessions,
`create_script`, frida signals for death detection, and `rpc.exports.init` for
config delivery. The new voboost-inject removes frida entirely. Injection is now
a ptrace entry through `libinjector` that loads `libimplant.so` (see
`native-payload`);
control between the daemon and the injected process is files, not frida-RPC (see
`update-planes` channel B).

Two facts flip the daemon's whole injection model and must be re-specified:

1. **The injected code outlives the daemon.** With ptrace+dlopen, `libimplant.so`
   and its agents live in the target independently of the daemon. A daemon
   restart — including an OTA self-update — must *reconcile* (scan
   `/proc/<pid>/maps` for the real `libimplant.so` path) rather than re-inject,
   and must not tear hooks down. This is the opposite of frida, where the
   session died with the daemon.
2. **No spawn rail is needed.** All 16 agents work in attach mode;
   `system_server` is a long-lived attach target and its event hook covers
   future `onDisplayChanged`.
   Global spawn-gating, its non-target resume, and the emulator escape hatch
   (all frida-specific) are removed.

This change rewrites `injection-control` from "drive frida" to "drive
`libinjector`, reconcile by the maps marker, route per-injection ABI, deliver
opaque config over channel B." It depends on `native-payload` (the mechanism it
drives) and does not touch that contract.

## What Changes

- **REMOVED** (frida-specific, no successor mechanism):
  - "In-process frida-core driving" — replaced by ptrace via `libinjector`.
  - "Spawn-gating for earliest injection" — attach-only; no spawn rail.
  - "Per-agent runtime routing and per-process lazy runtime" — no QuickJS; the
    implant loads DEX agents (see `native-payload`, `agent-entry-seam`).
  - "Emulator spawn-gating escape hatch" — the frida-gum abort it worked around
    no longer exists.
- **ADDED**:
  - "Ptrace injection via libinjector" — the daemon drives `vbi_inject(pid,
    so_path, init_sym)`, no socket, no frida.
  - "Reconciliation by the libimplant.so maps marker" — startup/plan-change
    reconcile; injected code outlives the daemon; no teardown storm.
- **MODIFIED**:
  - "Process watching and bounded reinjection" — `/proc` polling for
    death/restart (no frida signals); marker-based idempotency; safety-bounded.
  - "Opaque config delivery to agents" — config delivered verbatim over channel
    B (a watched file), not `rpc.exports.init`; opacity principle unchanged.
  - "Running targets resolved by package id via /proc" — resolve pid purely from
    `/proc/<pid>/cmdline` argv[0] (and `comm` for native/system targets); the
    frida `enumerate_processes` name match is gone.
  - "32-bit target process support" — delivered by `native-payload` runtime
    bitness detection + both-ABI carriage, not frida `compat=auto`.
- **Unchanged**: "Injection plan validation" (language-agnostic; whitelist +
  size bounds + opaque config).

## Capabilities

### Modified Capabilities

- `injection-control`: the daemon drives ptrace injection via `libinjector`
  instead of frida-core. It reconciles existing injections by the real
  `libimplant.so` path in `/proc/<pid>/maps` (injected code outlives the daemon;
  restart/OTA does not tear down hooks), watches targets by `/proc` polling,
  selects the per-ABI implant from runtime bitness detection, and delivers opaque
  config over channel B. Spawn-gating, per-process QuickJS routing, the emulator
  escape hatch, and frida-RPC config delivery are removed.
