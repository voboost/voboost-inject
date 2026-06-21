## Purpose
Specify device-safety guarantees: guaranteed resume of gated processes, per-agent isolation,
reinjection rate-limiting and quarantine, global panic-quarantine, coexistence detection,
runtime kill-switch, and capability detection.

## Requirements

### Requirement: No vehicle motion or ignition gating
The daemon SHALL NOT gate, delay, or withhold any injection decision on vehicle motion, speed, or
ignition state. Agents are UI/WindowManager hooks; the correct device-safety mechanism is guaranteed
`resume()`, per-agent isolation, and quarantine — not a vehicle-state sensor. Adding a motion gate
would introduce an unpredictable startup dependency with no safety benefit for the agent kinds in
scope.

#### Scenario: Vehicle state does not affect injection
- **WHEN** the vehicle is in any motion, speed, or ignition state and a target process is reachable
- **THEN** the daemon makes no injection decision based on that vehicle state, and the device-safety
  guarantees (resume, isolation, quarantine) apply unchanged

### Requirement: Guaranteed resume of gated processes
The daemon SHALL always resume a spawn-gated process, even when its injection fails, errors, or
exceeds a timeout. It SHALL never leave a process or the boot sequence suspended.

#### Scenario: Injection fails on a gated process
- **WHEN** injection into a spawn-gated process fails or times out
- **THEN** the daemon resumes the process anyway so it runs unmodified

### Requirement: Per-agent isolation
A failure in one agent SHALL NOT abort other agents and SHALL NOT crash the target process.
Frida Script errors SHALL be caught and contained per agent.

#### Scenario: One agent throws during load
- **WHEN** one agent fails while loading into a target
- **THEN** other agents for that target are unaffected and the target keeps running

### Requirement: Reinjection rate-limit and quarantine
The daemon SHALL rate-limit reinjection to at most N attempts per M minutes per (agent, process)
with exponential backoff, and SHALL quarantine an agent that a target keeps dying soon after.
A quarantined agent SHALL stop being injected, leaving the target running unmodified (fail-open).
The daemon SHALL reset the backoff counter for an (agent, process) pair after a successful
injection, so that stable injections do not accumulate delay toward a false quarantine.

#### Scenario: Target keeps dying right after an agent injects
- **WHEN** a target repeatedly dies shortly after a given agent is injected, beyond the budget
- **THEN** the daemon quarantines that agent and stops reinjecting it,
  and the target runs unmodified

### Requirement: Global panic-quarantine
The daemon SHALL enter a global panic-quarantine when target deaths exceed a configured threshold,
stopping all injections to protect the device.

#### Scenario: Mass target deaths
- **WHEN** target-death counts exceed the panic threshold
- **THEN** the daemon stops all injections globally and reports the panic-quarantine in status

### Requirement: Coexistence skip
Before injecting a process the daemon SHALL check `/proc/PID/maps` for an already-present Frida
agent (e.g. another root tool) and SHALL skip injection for that process if one is found.
Confirming the daemon's own injection SHALL NOT depend on `/proc/maps`. The check applies only to
processes the daemon has not yet injected itself: the daemon tracks its own injections in memory,
and its own agent footprint in a target SHALL NOT be treated as foreign coexistence on a
re-injection (e.g. after a plan change).

#### Scenario: Another Frida agent already present
- **WHEN** `/proc/PID/maps` shows a Frida agent already loaded in a target
- **THEN** the daemon skips injecting that process and records a coexistence skip in status

#### Scenario: Re-injection into a target the daemon already injected
- **WHEN** a plan change re-injects into a process whose only Frida footprint is the daemon's own
- **THEN** the daemon does not classify it as coexistence and proceeds idempotently

### Requirement: Runtime kill-switch
The daemon SHALL stop all injections, resume all gated processes, and idle when the runtime
kill-switch is active (the `/data/voboost/run/disable` file or a plan flag), regardless of the
configured startup intent.

#### Scenario: Kill-switch file appears at runtime
- **WHEN** the `/data/voboost/run/disable` file appears while the daemon is running
- **THEN** the daemon stops all injections, resumes any gated processes, and idles

#### Scenario: Kill-switch is deactivated
- **WHEN** the kill-switch is removed (`run/disable` deleted or plan `disabled` set to false)
  while the daemon is running
- **THEN** the daemon does NOT resume injections automatically; a daemon restart is required to
  re-open frida and resume normal operation

### Requirement: Capability detection over version strings
The daemon and agents SHALL determine target-generation differences by detecting the actual
presence of a class/method/overload, using the OS version string only as a hint.

#### Scenario: A9 vs A11 hook target differs
- **WHEN** a hook target may differ between Android generations
- **THEN** the decision is made by capability detection, not by parsing `ro.build.version.release`
