## Why

The `daemon-lifecycle` spec is written around the Vala + frida-core daemon: a
GMainLoop with `yield`, `Frida.init()` before any frida object, spawn-gating in
the state machine, a frida page-size fix for the emulator, and DEGRADED reached
by "frida device cannot be opened". The new daemon is a Rust 64-bit ELF that
injects via ptrace (see `native-payload`, `injection-control`) and has no frida
at all, so these requirements must be re-rooted.

Three lifecycle facts change:

1. **Boot trigger.** The daemon starts from an init `.rc` service triggered
   `on nonencrypted` (fallback `on boot`) so it is resident ~18s in, before
   `system_server`, rather than waiting on `sys.boot_completed`. (The SELinux
   domain transition is owned by `selinux-domain`; the *timing* is owned here.)
2. **Runtime.** GMainLoop + `yield` becomes an async Rust runtime (tokio). The
   only target-side blocking operation to bound with a timeout is the ptrace
   inject, not frida session/script calls.
3. **Shutdown does not tear down.** Because injected code outlives the daemon,
   SIGTERM must stop the loop and release the pidfile *without* tearing down
   existing hooks — the opposite of the frida daemon, whose sessions died with
   it.

This change rewrites the lifecycle requirements accordingly and removes the two
frida-only requirements. The startup gate, single-instance flock, per-agent
boot-readiness gate, and host-testable boot state are preserved with frida
references stripped.

## What Changes

- **MODIFIED**:
  - "Single resident root daemon launched at boot" — Rust ELF; init `.rc`
    triggered `on nonencrypted`; flock single-instance unchanged.
  - "Startup gate via the `inject.json` `startup` field" — drop "or enabling
    spawn-gating"; gate semantics otherwise unchanged.
  - "Daemon state machine" — INIT → VERIFY_SELF → READY/DEGRADED; when READY,
    reconcile then ATTACH → INJECT → MONITOR; no GATE/spawn-gating; DEGRADED via
    verify-self failure or injector-unavailable.
  - "Asynchronous non-blocking execution" — async Rust runtime; bound only the
    ptrace inject; SIGTERM shuts down without tearing down hooks.
  - "Per-agent boot-readiness gate" — `boot: true` waits on `sys.boot_completed`
    AND daemon READY (no frida device open); poll + env hatch unchanged.
  - "Host-testable boot-completion state" — `BootState` unit-testable on host
    without the injector (was: without frida-core).
- **REMOVED** (frida-only):
  - "Daemon initialises frida-core before constructing any frida object".
  - "Emulator embedded-backend frida via page-size fix".

## Capabilities

### Modified Capabilities

- `daemon-lifecycle`: the daemon is a Rust ELF launched by an init `.rc` service
  `on nonencrypted`, runs on an async Rust runtime, and progresses INIT →
  VERIFY_SELF → READY/DEGRADED, reconciling existing injections and then
  attaching/injecting targets (no spawn-gating). SIGTERM shuts the daemon down
  without tearing down injected hooks. The frida-init ordering and the emulator
  frida page-size fix are removed.
