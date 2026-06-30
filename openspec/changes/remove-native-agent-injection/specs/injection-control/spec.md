## MODIFIED Requirements

### Requirement: Per-agent runtime routing and per-process lazy runtime
The daemon SHALL run every agent as JavaScript on frida-core's QuickJS runtime
(GumJS) via a per-process session script (`create_script`). Every target
process that receives at least one agent SHALL be attached (a session opened)
and the QuickJS runtime SHALL be loaded in it. A process that receives no agent
SHALL never be attached (it is resumed immediately — see Spawn-gating).

#### Scenario: Process receives no agent
- **WHEN** a spawned process is not a target of any enabled agent
- **THEN** frida is never attached to it and no runtime is loaded in it

#### Scenario: Process receives an agent
- **WHEN** a target process receives an agent
- **THEN** the QuickJS runtime is loaded in that process and the agent runs on it

## REMOVED Requirements

### Requirement: Native agent receives config via data argument
This scenario described the removed `native` agent path. Config is now delivered
only via the js agent's `rpc.exports.init` (see "Opaque config delivery to
agents").
