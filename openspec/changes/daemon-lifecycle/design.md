# Design — daemon-lifecycle (Vala/frida → Rust/ptrace)

<!-- Date: 2026-07-23. Records why the lifecycle is re-rooted in Rust + an init
     on-nonencrypted trigger, and why SIGTERM must not tear down. -->

## D1 — Why `on nonencrypted` rather than `sys.boot_completed`

**Choice:** launch from an init `.rc` service triggered `on nonencrypted`
(fallback `on boot`).

**Reasoning:** the daemon must be resident before `system_server` so it can
attach to it (app-viewport hooks `system_server`, which is born early). Waiting on
`sys.boot_completed` starts the daemon too late. `on nonencrypted` fires ~18s in,
after the data partition is available (so the root zone is readable) but before
the framework is up. `on boot` is the fallback where `on nonencrypted` is not
available. The precise trigger difference is confirmed when the init.rc is wired;
the requirement fixes the intent (resident before system_server) not a tick count.

**Note on ownership:** this requirement owns *when* init starts the service; the
SELinux domain the service enters (`init_daemon_domain`, exec type) is owned by
`selinux-domain`. Two specs would otherwise both claim the init service.

## D2 — Why SIGTERM must not tear down injections

**Choice:** SIGTERM stops the loop, releases the pidfile, and exits, leaving
injected hooks running.

**Reasoning:** with ptrace+dlopen the implant and its agents live in the target
independently of the daemon. Tearing hooks down on SIGTERM would be actively
wrong: it would drop working instrumentation every time the daemon restarts —
including on OTA self-update — producing a teardown/re-inject storm. Instead the
daemon reconciles on the next start (see `injection-control`). Teardown, when
wanted, is driven by a "no agents" plan over channel B (see `update-planes`), not
by daemon exit. This inverts the frida daemon, whose sessions died with it, so the
old "resume gated processes on SIGTERM" behavior is gone (there is no gating).

## D3 — Why the async runtime detail stays light

**Choice:** require "an asynchronous Rust runtime" and bound only the ptrace
inject, without naming tokio primitives in the spec.

**Reasoning:** the load-bearing invariants are (a) nothing target-side blocks the
loop unbounded and (b) no error kills the loop. The frida spec had to enumerate
which frida calls were local vs target-side and carve out `resume()`; the ptrace
model has exactly one target-side blocking call (the inject), so the spec says
that and no more. The concrete runtime (tokio) is an implementation choice
recorded in the design doc, not a spec constraint.

## D4 — Why keep the boot-readiness gate and BootState

**Choice:** retain `boot: true` deferral and the host-testable `BootState`,
stripping only the frida coupling.

**Reasoning:** boot-readiness is orthogonal to the injection mechanism — some
agents must not run until the framework is up regardless of how they are injected.
The only frida-specific clause was "AND frida-core is ready (local device open)",
which becomes "AND the daemon is READY". `BootState` was already extracted to be
host-testable without frida; the same module is now host-testable without the
injector. The monotonic-cache / hatch-first / negative-re-poll behavior is
unchanged because it never depended on frida in the first place.
