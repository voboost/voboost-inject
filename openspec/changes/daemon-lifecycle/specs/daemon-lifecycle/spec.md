## MODIFIED Requirements

### Requirement: Single resident root daemon launched at boot

voboost-inject SHALL run as a single resident root process — a Rust 64-bit ELF —
launched at boot by an Android init `.rc` service triggered `on nonencrypted`
(fallback `on boot`), so it becomes resident before `system_server` rather than
waiting on `sys.boot_completed`. It SHALL enforce single-instance via a pidfile
guarded by `flock`, not by process-name matching. (The SELinux domain the
service enters is owned by `selinux-domain`.)

#### Scenario: First instance acquires the lock

- **WHEN** the daemon starts and no other instance holds the pidfile lock
- **THEN** it acquires the `flock`, records its pid, and proceeds to start up

#### Scenario: Second instance refuses to run

- **WHEN** a second daemon instance starts while the pidfile lock is held
- **THEN** it logs the conflict and exits without injecting

#### Scenario: Started before system_server

- **WHEN** init reaches the `on nonencrypted` trigger
- **THEN** the daemon service launches then, ahead of `system_server`, without
  waiting for `sys.boot_completed`

### Requirement: Startup gate via the `inject.json` `startup` field

On startup the daemon SHALL read the top-level `startup` field of the app-written
`inject.json` in the app zone (the daemon runs as root and can read the app zone;
the reverse is denied). If that value equals `none` (case-insensitive), the
daemon SHALL exit immediately without performing any injection. If `inject.json`
is absent, has no `startup` field, or the field holds any other value, the daemon
SHALL start normally. The app mirrors its own startup intent into `inject.json`.
The daemon SHALL NOT read `config.yaml` at all — it parses no YAML and no feature
configuration.

The gate reads untrusted app-zone input, which is safe because it can only move
behavior in the fail-safe direction (skip injection); everything actually
injected is still signature-verified.

#### Scenario: Startup is none

- **WHEN** the daemon starts and `inject.json` has `"startup": "none"`
- **THEN** it logs the gated exit and terminates without acting

#### Scenario: inject.json is absent or has no startup field

- **WHEN** the daemon starts and `inject.json` is missing or has no `startup`
  field
- **THEN** it continues to the self-verification phase

#### Scenario: Startup permits running

- **WHEN** the daemon starts and the `startup` value is anything other than
  `none`
- **THEN** it continues to the self-verification phase

### Requirement: Daemon state machine

The daemon SHALL progress through the states INIT → VERIFY_SELF → (READY or
DEGRADED) and, when READY, SHALL reconcile existing injections (scan
`/proc/<pid>/maps` for the `libimplant.so` marker — see `injection-control`) and
then process each target through ATTACH → INJECT → MONITOR. There is no
spawn-gating GATE state.

#### Scenario: Self-verification succeeds

- **WHEN** VERIFY_SELF confirms the manifest ed25519 signature and every agent
  sha256
- **THEN** the daemon enters READY, reconciles existing injections, and injects
  outstanding targets

#### Scenario: Self-verification fails

- **WHEN** VERIFY_SELF fails the manifest signature or any agent sha256
- **THEN** the daemon enters DEGRADED, logs and reports status
  (`state: degraded`), observes only, and injects nothing

#### Scenario: Injector unavailable

- **WHEN** the daemon passed VERIFY_SELF but `libinjector` cannot be loaded or
  initialized
- **THEN** it transitions to DEGRADED, reports status (`state: degraded`), and
  injects nothing

### Requirement: Asynchronous non-blocking execution

The daemon SHALL run on an asynchronous Rust runtime, SHALL bound with a timeout
every operation that performs target-side work (the ptrace attach/inject via
`libinjector`), and SHALL never let any error terminate the run loop. It SHALL
perform a clean shutdown on SIGTERM that does NOT tear down existing injections:
because injected code outlives the daemon (see `injection-control`), SIGTERM
stops the loop, releases the pidfile lock, and exits, leaving hooks running.

#### Scenario: Recoverable error during an operation

- **WHEN** a target-side operation raises a recoverable error or exceeds its
  timeout
- **THEN** the error is caught, logged, and reported, the run loop keeps running,
  and the per-agent failure is treated as a quarantine candidate (fail-open)

#### Scenario: SIGTERM received

- **WHEN** the process receives SIGTERM
- **THEN** it stops making new injections, releases the pidfile lock, and exits
  cleanly, and it does NOT tear down injections already live in targets

### Requirement: Per-agent boot-readiness gate

By default the daemon SHALL inject an agent as soon as its target process is
reachable (attached), so injection happens as early as possible. An agent MAY
declare `boot: true` in the verified manifest; such an agent SHALL NOT be
injected until `sys.boot_completed=1` (read via `getprop`) AND the daemon is
READY. While a `boot` agent waits it is marked `waiting` in status, and other
agents for the same process are injected immediately. Because boot completion has
no signal to subscribe to, the daemon SHALL poll for it while any `boot` agent is
waiting and inject the deferred agents once boot completes. The check falls back
to an env-var escape hatch in host test environments where `getprop` is
unavailable.

Agents that hook framework classes which load late SHOULD instead defer their own
hook installation so they install the instant the class is available; `boot` is
for agents that must not run at all until boot completes.

#### Scenario: Agent requires boot, boot not completed

- **WHEN** an agent with `boot` is reachable and `sys.boot_completed != 1`
- **THEN** the daemon does not inject it and marks it `waiting`, while injecting
  the other agents for that process

#### Scenario: Agent requires boot, boot completed

- **WHEN** a `boot` agent is reachable, `sys.boot_completed=1`, and the daemon is
  READY
- **THEN** the daemon injects it

#### Scenario: Agent does not require boot

- **WHEN** an agent without `boot` is reachable
- **THEN** the daemon injects it immediately, without waiting for boot completion

### Requirement: Host-testable boot-completion state

The daemon SHALL implement its boot-completion check (the monotonic cache of
`sys.boot_completed`, the `getprop` fork, and the `VOBOOST_BOOT_COMPLETED`
host-test escape hatch) in a self-contained module (`BootState`) so it can be
unit-tested on a host without the injector or a live target. The supervisor SHALL
delegate its `boot_completed()` call to a `BootState` instance. The behavior SHALL
be unchanged: the escape hatch is checked first (so host tests never fork
`getprop`), a positive result is cached monotonically (never forks again), and a
negative result re-polls on the next call.

#### Scenario: Host test with the escape hatch set

- **WHEN** `VOBOOST_BOOT_COMPLETED=1` is in the environment
- **THEN** `BootState.boot_completed()` returns true without forking `getprop`
- **AND** the result is cached: a second call returns true even after the env var
  is cleared

#### Scenario: Host test with an empty environment

- **WHEN** `VOBOOST_BOOT_COMPLETED` is unset and `getprop` is unavailable
  (non-Android host)
- **THEN** `BootState.boot_completed()` returns false without throwing or
  blocking, and re-polls on the next call (a negative result is not cached)

## REMOVED Requirements

### Requirement: Daemon initialises frida-core before constructing any frida object

Removed: the daemon no longer links or initializes frida-core. There is no
`Frida.init()` and no frida object to construct; injection is ptrace via
`libinjector` (see `native-payload`).

### Requirement: Emulator embedded-backend frida via page-size fix

Removed: there is no frida-gum embedded backend, so the `gum_query_page_size`
zero-page abort and its `subprojects/frida-gum.wrap` patch no longer exist.
