## Purpose
Specify how the daemon drives frida-core for injection: in-process local device, spawn-gating,
per-agent runtime routing, process watching, plan validation, and opaque config delivery.

## Requirements

### Requirement: In-process frida-core driving
The daemon SHALL embed frida-core and drive it in-process over a local device, with no socket
and no per-injection process exec. It SHALL support multiple sessions, one per target process.

#### Scenario: Local device control
- **WHEN** the daemon needs to inject
- **THEN** it uses the embedded frida-core local device API directly,
  opening no socket and exec'ing no helper binary

### Requirement: Spawn-gating for earliest injection
The daemon SHALL spawn-gate not-yet-started targets so that injection happens before the target
runs its own code, and SHALL attach to targets that are already running. Because frida-core's
spawn-gating is **global** (it suspends every process the device spawns, with no per-program
filter), the daemon SHALL resume a non-target gated process immediately WITHOUT attaching a
session, so enabling spawn-gating adds no per-process attach cost to the rest of the device.

#### Scenario: Target not yet started
- **WHEN** a spawn-gated target process is created
- **THEN** the daemon injects its agents before the process executes its own code, then resumes it

#### Scenario: Target already running
- **WHEN** a target process is already running at READY time
- **THEN** the daemon attaches to it and injects its agents

#### Scenario: Non-target process is spawn-gated
- **WHEN** global spawn-gating suspends a process that is not a target of any enabled agent
- **THEN** the daemon resumes it immediately without attaching a session, and never tracks it as a
  target

### Requirement: Per-agent runtime routing and per-process lazy runtime
The daemon SHALL route each agent by its manifest `kind`. A `js` agent runs JavaScript on
frida-core's QuickJS runtime (GumJS) via a per-process session script (`create_script`). A
`native` agent is a frida-gum native agent — a compiled `.so` injected directly into the target
via frida-core's library-injection API (`inject_library_blob`/`inject_library_file`, with an
exported `entrypoint`) and runs with NO JavaScript engine. The QuickJS runtime SHALL be loaded in
a target process only when that process receives at least one `js` agent; a process that receives
only `native` agents SHALL never load QuickJS, and a process that receives no agent SHALL never be
attached (it is resumed immediately — see Spawn-gating).

NOTE: This is per-process lazy loading, not yet a link-time removal of QuickJS from the binary.
Dropping QuickJS from the binary entirely is the end state of the JS→hybrid→native migration
(`frida.md`): once no `js` agents remain, frida-core is built without any JS engine and the agents
run as pure frida-gum native libraries. That binary-level compile-out requires a separate
frida-core build option and is out of scope for this change; the footprint win realized here is
QuickJS-instead-of-V8 plus per-process lazy loading.

#### Scenario: Process receives no agent
- **WHEN** a spawned process is not a target of any enabled agent
- **THEN** frida is never attached to it and no runtime is loaded in it

#### Scenario: Process receives only native agents
- **WHEN** a target process receives only `native` agents
- **THEN** they are injected as frida-gum native libraries (no `Session` script) and QuickJS is
  never loaded in that process

#### Scenario: Process receives a js agent
- **WHEN** a target process receives a `js` agent
- **THEN** the QuickJS runtime is loaded in that process and the agent runs on it

### Requirement: Process watching and bounded reinjection
The daemon SHALL watch for target processes via process events (not polling): injecting on spawn,
and reinjecting on target death subject to the device-safety rate-limit and quarantine rules.

#### Scenario: Target appears after READY
- **WHEN** a watched target process spawns
- **THEN** the daemon injects its agents as soon as it appears

#### Scenario: Target dies and is restarted
- **WHEN** a watched target dies and reappears within the allowed reinjection budget
- **THEN** the daemon reinjects its agents

NOTE: `js` targets surface death via the frida `Session.detached` signal; `native`-only targets
(no session) surface a crash via the device `process_crashed` signal. Robust restart-detection for
clean exits of `native`-only targets is refined in the JS→native migration change.

#### Scenario: Re-injection into a still-running target is idempotent
- **WHEN** a plan change triggers re-injection into a target whose session already holds some of
  those agents
- **THEN** the daemon reuses the existing session and loads only the agents not already loaded,
  never opening a second session or loading an already-active agent twice

### Requirement: Injection plan validation
The daemon SHALL validate every entry of the app-written injection plan (`inject.json`) against the
verified manifest before acting: the agent `id` MUST be whitelisted in the manifest, and its
`config` MUST be within the size bound (`MAX_CONFIG_BYTES`); the whole file MUST be within
`MAX_PLAN_BYTES`. Entries failing these checks SHALL be rejected, not injected. The daemon SHALL
treat `config` as **opaque** — it SHALL NOT inspect or interpret its contents (no parameter
schema); config semantics belong to the app and the agent.

#### Scenario: Plan entry references unknown agent
- **WHEN** a plan entry names an agent absent from the manifest
- **THEN** the daemon rejects that entry and does not inject it. An unknown id
  has no manifest `process`, so it forms no known (agent, process) pair and
  carries no `inject-status.json` entry (status reports injection outcomes for
  known pairs only — see app-interface); the rejection is logged (root-only).

#### Scenario: Plan entry config exceeds the size bound
- **WHEN** a plan entry's `config` exceeds `MAX_CONFIG_BYTES` (or the file exceeds `MAX_PLAN_BYTES`)
- **THEN** the daemon rejects that entry and does not inject it
  (a memory/DoS guard, not a schema check)

### Requirement: Opaque config delivery to agents
The daemon SHALL deliver each agent's validated `config` verbatim, without interpreting it. For a
`js` agent it SHALL call the agent's `rpc.exports.init(stage, parameters)` with
`parameters.config` set to the config, implementing the `frida:rpc` protocol over `Script.post`/
`message`. For a `native` agent it SHALL pass the config as the `data` argument of
`inject_library_blob`.

#### Scenario: js agent receives config via RPC init
- **WHEN** a `js` agent is loaded
- **THEN** the daemon calls its `rpc.exports.init` with `parameters.config`
  set to the agent's config

#### Scenario: native agent receives config via data argument
- **WHEN** a `native` agent is injected
- **THEN** the daemon passes the agent's config as the `inject_library_blob` `data` argument
