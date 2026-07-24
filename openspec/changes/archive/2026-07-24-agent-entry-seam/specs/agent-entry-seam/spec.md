## ADDED Requirements

### Requirement: Fixed AgentEntry.init seam

The implant SHALL enter the Java agents through exactly one fixed seam: the
public static method `ru.voboost.agents.AgentEntry.init(String configPath)`,
invoked over JNI after LSPlant initialization. The class name, method name, and
signature are a fixed contract and SHALL NOT depend on which agents are present.
Everything reachable beyond `AgentEntry.init` — the `Agent` lifecycle,
`AgentContext`, hooking, config parsing, agent discovery — is owned by the
agents' repository (`voboost-script`) and is out of scope for voboost-inject.

#### Scenario: Implant calls the fixed seam

- **WHEN** the implant has initialized LSPlant in a target and is ready to run
  agents
- **THEN** it invokes `ru.voboost.agents.AgentEntry.init(configPath)` via JNI and
  performs no other call into Java agent code

### Requirement: Seam is the only C++→Java crossing

The implant SHALL reach the Java agents ONLY through `AgentEntry.init`, and
SHALL NOT reference any agent-specific class or method name. As a consequence the
implant is agent-set-independent: adding, removing, renaming, or reconfiguring an
agent SHALL NOT require rebuilding the implant, because none of those changes
touch the fixed seam.

#### Scenario: Agent set changes without an implant rebuild

- **WHEN** the agent set changes (an agent is added, removed, renamed, or its
  config changes) in the agents' repository
- **THEN** the same implant binary keeps working unchanged, because it calls only
  `AgentEntry.init` and names no agent-specific symbol

#### Scenario: Implant names no agent class

- **WHEN** the implant source is inspected
- **THEN** it contains no reference to any concrete agent class or method, only to
  `ru.voboost.agents.AgentEntry.init`

### Requirement: Hidden-API exemption applied before the seam

The implant SHALL apply the hidden-API exemption
(`setHiddenApiExemptions("L")`) before calling `AgentEntry.init`, so that agent
reflection against non-SDK members works immediately when agents run. The
exemption is fast (verified <1.2ms) and SHALL be established as a precondition of
the seam, not left to the agents.

#### Scenario: Reflection works in the first agent to run

- **WHEN** the first agent runs after `AgentEntry.init` is called
- **THEN** its reflection against hidden/non-SDK members succeeds, because the
  implant applied `setHiddenApiExemptions("L")` before invoking the seam

### Requirement: configPath points at the channel-B config file

The `configPath` string passed to `AgentEntry.init` SHALL be the filesystem path
of the target's channel-B config file (a `media_rw_data_file`, world-readable),
which voboost-inject writes at injection and rewrites atomically for live updates
(delivery is owned by `injection-control`; transport by `update-planes`). The
agent runtime reads it on init and watches it for live-update; voboost-inject
SHALL NOT pass a hardcoded per-agent path.

#### Scenario: Seam receives the channel-B path

- **WHEN** the implant calls `AgentEntry.init`
- **THEN** the `configPath` argument is the path of the target's channel-B config
  file that voboost-inject wrote, not a hardcoded or per-agent path

### Requirement: Defensive invocation of the seam

The implant SHALL invoke `AgentEntry.init` defensively: if the call throws
(pending JNI exception) or the class/method cannot be resolved, the implant SHALL
clear the exception, report the failure so device-safety can account it, and
SHALL NOT let it crash the target process. A failed seam invocation is an
injection failure for that target, not a process-fatal event.

#### Scenario: Seam throws and the target survives

- **WHEN** `AgentEntry.init` throws or cannot be resolved
- **THEN** the implant clears the JNI exception, reports the failure for
  device-safety accounting, and the target process keeps running (it is not
  crashed by the seam failure)
