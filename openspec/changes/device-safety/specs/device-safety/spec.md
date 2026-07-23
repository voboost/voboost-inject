## ADDED Requirements

### Requirement: Per-target circuit breaker

The daemon SHALL run a per-target circuit breaker: if a target process crashes M
times within N seconds after the daemon injects it, the daemon SHALL stop
injecting that target and report it `degraded`, leaving the target to run
unmodified. The default SHALL start at M = 3 within N ≈ 30 seconds. For
`system_server` the breaker SHALL be more conservative (M = 1–2), because its
death is a framework soft-reboot rather than a single app restart. The breaker is
per-target and complements, rather than replaces, the per-`(agent, process)`
rate-limit and the global panic-quarantine.

#### Scenario: A target keeps crashing after injection

- **WHEN** a target crashes M times within N seconds after the daemon injects it
- **THEN** the daemon stops injecting that target and reports it `degraded`, and
  the target runs unmodified

#### Scenario: system_server is treated conservatively

- **WHEN** `system_server` crashes after injection
- **THEN** the breaker trips at a lower threshold (M = 1–2) than for an ordinary
  app target, because a `system_server` death is a framework soft-reboot

## MODIFIED Requirements

### Requirement: Per-agent isolation

A failure in one agent SHALL NOT abort other agents and SHALL NOT crash the
target process. Agent failures SHALL be contained per agent by the agent
runtime's per-agent `try/catch` (owned by `voboost-script`, behind the seam) and
by the implant's defensive invocation of the entry seam (see `agent-entry-seam`),
so a throwing agent — or a throwing seam — leaves the target and the other agents
running.

#### Scenario: One agent throws during init

- **WHEN** one agent fails while initializing in a target
- **THEN** other agents for that target are unaffected and the target keeps
  running

#### Scenario: The entry seam itself throws

- **WHEN** `AgentEntry.init` throws or cannot be resolved
- **THEN** the implant contains the failure (clears the exception, reports it)
  and the target keeps running (see `agent-entry-seam`)

### Requirement: Coexistence skip

Before injecting a process the daemon SHALL check `/proc/<pid>/maps` for an
already-present **foreign** injection footprint (e.g. another root tool's agent)
and SHALL skip injection for that process if one is found, recording a
coexistence skip in status. The daemon's own footprint is the `libimplant.so`
marker it tracks in memory (see `injection-control`); its own marker SHALL NOT be
treated as foreign coexistence on a re-injection (e.g. after a plan change).
Confirming the daemon's own injection SHALL use its tracked marker, not a
foreign-agent heuristic.

#### Scenario: Another tool's agent already present

- **WHEN** `/proc/<pid>/maps` shows a foreign injection footprint in a target the
  daemon has not injected
- **THEN** the daemon skips injecting that process and records a coexistence skip
  in status

#### Scenario: Re-injection into a target the daemon already injected

- **WHEN** a plan change targets a process whose only injection footprint is the
  daemon's own `libimplant.so` marker
- **THEN** the daemon does not classify it as coexistence and proceeds
  idempotently (reconcile, config update — not a second injection)

### Requirement: Runtime kill-switch

The daemon SHALL stop all new injections and idle when the runtime kill-switch is
active — either the `/data/voboost-inject/run/disable` file or the `inject.json`
`enabled:false` plan flag — regardless of the configured startup intent. Because
injected code outlives the daemon, the kill-switch stops *new* injections; tearing
down injections already live is done via a no-agents plan over channel B (see
`update-planes`), not by the kill-switch. When the kill-switch is deactivated the
daemon SHALL NOT auto-resume injecting; a daemon restart is required.

#### Scenario: Kill-switch activates at runtime

- **WHEN** the `/data/voboost-inject/run/disable` file appears, or a plan sets
  `enabled:false`, while the daemon is running
- **THEN** the daemon stops all new injections and idles

#### Scenario: Kill-switch is deactivated

- **WHEN** the kill-switch is removed (`run/disable` deleted or plan `enabled`
  set back to true) while the daemon is running
- **THEN** the daemon does NOT resume injecting automatically; a daemon restart
  is required to resume normal operation

## REMOVED Requirements

### Requirement: Guaranteed resume of gated processes

Removed: there is no spawn-gating in the ptrace daemon, so no process is ever
suspended by the daemon and there is nothing to guarantee resuming. Attach-only
injection never suspends the target (see `injection-control`).
