## Purpose
Specify the daemon's startup sequence, state machine, single-instance enforcement, startup gate,
async execution model, and per-agent boot-readiness gate.
## Requirements
### Requirement: Single resident root daemon launched at boot
voboost-inject SHALL run as a single resident root process launched at boot by the
`/system` init hook. It SHALL enforce single-instance via a pidfile guarded by `flock`,
not by process-name matching.

#### Scenario: First instance acquires the lock
- **WHEN** the daemon starts and no other instance holds the pidfile lock
- **THEN** it acquires the `flock`, records its pid, and proceeds to start up

#### Scenario: Second instance refuses to run
- **WHEN** a second daemon instance starts while the pidfile lock is held
- **THEN** it logs the conflict and exits without injecting

### Requirement: Startup gate via the `inject.json` `startup` field
On startup the daemon SHALL read the top-level `startup` field of the app-written `inject.json`
in the app zone (the daemon runs as root and can read the app zone; the reverse is denied). If
that value equals `none` (case-insensitive), the daemon SHALL exit immediately without performing
any injection or enabling spawn-gating. If `inject.json` is absent, has no `startup` field, or the
field holds any other value, the daemon SHALL start normally. The app mirrors its own startup
intent into `inject.json`. The daemon SHALL NOT read `config.yaml` at all — it parses no YAML and
no feature configuration.

The gate reads untrusted app-zone input, which is safe because it can only move behavior in the
fail-safe direction (skip injection); everything actually injected is still signature-verified.

#### Scenario: Startup is none
- **WHEN** the daemon starts and `inject.json` has `"startup": "none"`
- **THEN** it logs the gated exit and terminates without acting

#### Scenario: inject.json is absent or has no startup field
- **WHEN** the daemon starts and `inject.json` is missing or has no `startup` field
- **THEN** it continues to the self-verification phase

#### Scenario: Startup permits running
- **WHEN** the daemon starts and the `startup` value is anything other than `none`
- **THEN** it continues to the self-verification phase

### Requirement: Daemon state machine
The daemon SHALL progress through the states INIT → VERIFY_SELF → (READY or DEGRADED) and,
when READY, enable spawn-gating and process each target through
GATE or ATTACH → INJECT → MONITOR.

#### Scenario: Self-verification succeeds
- **WHEN** VERIFY_SELF confirms the manifest ed25519 signature and every agent sha256
- **THEN** the daemon enters READY and enables spawn-gating
- **NOTE** frida-core is statically linked; there is no separate frida lib to verify at runtime
  (see design D10a — waiver recorded there)

#### Scenario: Self-verification fails
- **WHEN** VERIFY_SELF fails the manifest signature or any agent sha256
- **THEN** the daemon enters DEGRADED, logs and reports status (`state: degraded`), observes only,
  and injects nothing

#### Scenario: frida-core local device cannot be opened
- **WHEN** the daemon passed VERIFY_SELF but opening the embedded frida-core local device fails
- **THEN** it transitions to DEGRADED, reports status (`state: degraded`), and injects nothing

### Requirement: Asynchronous non-blocking execution
The daemon SHALL run all frida-core operations asynchronously on a GMainLoop using `yield`,
SHALL bound with a timeout every async operation that performs target-side work (session
attach, script creation and load, library injection) — the operations that can block waiting
on the target — and SHALL never let any error terminate the GMainLoop. Local-device control
operations (opening the device, enabling/disabling spawn-gating, enumerating processes or
pending spawns, detaching a session) are synchronous local operations that do not wait on the
target and are not bounded. `resume()` SHALL NOT be bounded by a timeout: a timed-out resume
could leave a spawn-gated process suspended, conflicting with the guaranteed-resume invariant
(see device-safety); resume must be allowed to complete. It SHALL perform a clean shutdown on
SIGTERM.

#### Scenario: Recoverable error during an operation
- **WHEN** a target-side async frida operation raises a recoverable error or exceeds its timeout
- **THEN** the error is caught, logged, and reported, the GMainLoop keeps running, and the
  per-agent failure is treated as a quarantine candidate (fail-open)

#### Scenario: Resume is not bounded by a timeout
- **WHEN** the daemon resumes a spawn-gated process
- **THEN** the resume is not cancelled by a timeout, so it always completes and the process is
  never left suspended (guaranteed resume)

#### Scenario: SIGTERM received
- **WHEN** the process receives SIGTERM
- **THEN** it stops injections, resumes any gated processes,
  releases the pidfile lock, and exits cleanly

### Requirement: Per-agent boot-readiness gate
By default the daemon SHALL inject an agent as soon as its target process is reachable
(spawn-gated or attached), so injection happens as early as possible. An agent MAY declare
`boot: true` in the verified manifest; such an agent SHALL NOT be injected until
`sys.boot_completed=1` (read via `getprop`) AND frida-core is ready (local device open). While a
`boot` agent waits it is marked `waiting` in status, and other agents for the same
process are injected immediately. Because boot completion has no signal to subscribe to, the
daemon SHALL poll for it while any `boot` agent is waiting and inject the deferred agents
once boot completes. The check falls back to an env-var escape hatch in host test environments
where `getprop` is unavailable.

Agents that hook framework classes which load late SHOULD instead defer their own hook
installation (e.g. `Java.perform` / capability detection) so they install the instant the class
is available; `boot` is for agents that must not run at all until boot completes.

#### Scenario: Agent requires boot, boot not completed
- **WHEN** an agent with `boot` is reachable and `sys.boot_completed != 1`
- **THEN** the daemon does not inject it, resumes any gated process, and marks it `waiting`

#### Scenario: Agent requires boot, boot completed
- **WHEN** a `boot` agent is reachable, `sys.boot_completed=1`, and the device is open
- **THEN** the daemon injects it

#### Scenario: Agent does not require boot
- **WHEN** an agent without `boot` is reachable
- **THEN** the daemon injects it immediately, without waiting for boot completion

### Requirement: Host-testable boot-completion state

The daemon SHALL implement its boot-completion check (the monotonic cache of
`sys.boot_completed`, the `getprop` fork, and the
`VOBOOST_BOOT_COMPLETED` host-test escape hatch) in a frida-free module
(`BootState`) so it can be unit-tested on a host without linking frida-core.
The `Supervisor` SHALL delegate its `boot_completed()` call to a `BootState`
instance. The behavior SHALL be unchanged: the escape hatch is checked first
(so host tests never fork `getprop`), a positive result is cached monotonically
(never forks again), and a negative result re-polls on the next call.

Context: the boot logic previously lived inside `Supervisor`, which depends on
`FridaController` (frida-core). The host test harness cannot link frida-core
(no device), so the INJ-02 monotonic-cache fix had no host integration test
(R4-X-02). Extracting the frida-free logic is the only way to test it on host.

#### Scenario: Host test with the escape hatch set
- **WHEN** `VOBOOST_BOOT_COMPLETED=1` is in the environment
- **THEN** `BootState.boot_completed()` returns true without forking `getprop`
- **AND** the result is cached: a second call returns true even after the
  env var is cleared

#### Scenario: Host test with an empty environment
- **WHEN** `VOBOOST_BOOT_COMPLETED` is unset and `getprop` is unavailable
  (non-Android host)
- **THEN** `BootState.boot_completed()` returns false without throwing or
  blocking, and re-polls on the next call (a negative result is not cached)

