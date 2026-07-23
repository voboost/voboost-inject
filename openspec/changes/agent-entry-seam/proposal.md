## Why

The Java agents live in a separate repository (`voboost-script`), migrate on
their own schedule, and change set (16 agents today, more later). voboost-inject
must reach them without knowing anything about them — otherwise the C++ implant
would have to be rebuilt every time an agent is added, removed, or renamed.

The contract that makes this possible is a single, fixed JNI seam: after the
implant initializes LSPlant it calls one static Java method,
`ru.voboost.agents.AgentEntry.init(String configPath)`, and everything beyond
that method is the agents' repo. Nothing in the current specs describes this
seam — with frida the daemon injected agent *source* directly via
`create_script`, so there was no fixed Java entry point and the daemon was
coupled to each agent's script. The move to DEX + `InMemoryDexClassLoader`
removes that coupling, but only if the seam is pinned as a contract.

This change adds the `agent-entry-seam` capability: the fixed seam signature,
the fact that it is the *only* C++→Java crossing, the preconditions the implant
must establish before calling it (hidden-API exemption applied; `configPath`
pointing at the target's channel-B config file), and the defensive-invocation
rule (a throwing seam is reported, never crashes the target). It is additive and
touches no live frida spec.

## What Changes

- **New capability `agent-entry-seam`** — specifies:
  - the fixed seam `ru.voboost.agents.AgentEntry.init(String configPath)`
    (public static), the single C++→Java entry the implant calls;
  - that the implant reaches the agents *only* through this seam, never by any
    agent-specific class or method name, so the implant is agent-set-independent
    and is not rebuilt when the agent set changes;
  - that the implant applies the hidden-API exemption
    (`setHiddenApiExemptions("L")`) before calling the seam, so agent reflection
    works immediately;
  - that `configPath` is the path to the target's channel-B config file
    (`media_rw_data_file`, world-readable), which the agent runtime reads on
    init and watches for live-update;
  - defensive invocation: a seam that throws is reported to device-safety and
    does not crash the target.
- **No existing spec is modified.** The Java-side `Agent`/`AgentContext`/`Hooker`
  runtime and the agent lifecycle are owned by `voboost-script`; DEX loading and
  `JavaVM` acquisition by `native-payload`; config transport by `update-planes`.

## Capabilities

### Added Capabilities

- `agent-entry-seam`: the fixed C++→Java call convention
  `ru.voboost.agents.AgentEntry.init(String configPath)` — the single entry from
  the implant into the Java agents, the preconditions the implant must establish
  (hidden-API exemption, channel-B config path), and the defensive-invocation
  rule. Keeping the seam fixed and agent-set-independent lets the agents evolve in
  their own repo without rebuilding the implant.
