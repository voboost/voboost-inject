# Design — agent-entry-seam

<!-- Date: 2026-07-23. Records why voboost-inject owns only the JNI seam and
     deliberately nothing behind it, and why the agents-manifest bundle-vs-per-agent
     question does not affect this spec. -->

## D1 — Why voboost-inject owns only the seam

**Choice:** specify exactly one fixed method,
`ru.voboost.agents.AgentEntry.init(String configPath)`, and nothing behind it.

**Reasoning:** the agents live in a separate repo, on a separate release cadence,
with a changing set. If voboost-inject knew any agent-specific class, the C++
implant would be recompiled every time an agent changed — coupling the native
mechanism to the agent catalog. A single fixed seam decouples them: the implant
is agent-set-independent, and the entire `Agent`/`AgentContext`/`Hooker`/
`Scheduler`/`Reflect`/`Config` surface, agent discovery, and fault isolation are
owned by `voboost-script`, behind the seam. This spec draws the boundary at the
JNI call and stops.

**Rejected — richer C++/Java contract (pass an agent list, a per-agent struct):**
every added field re-couples the implant to agent structure and forces rebuilds.
A single opaque `configPath` keeps the contract minimal and stable.

## D2 — Why the preconditions live on the voboost-inject side of the seam

**Choice:** the implant applies the hidden-API exemption and hands over a
channel-B `configPath` *before* calling the seam.

**Reasoning:** both are things only the native/root side can do reliably. The
hidden-API exemption (`setHiddenApiExemptions("L")`) must be in place before any
agent reflects against non-SDK members; making it a seam precondition means every
agent gets it for free and none has to (or can) manage the process-global policy.
The `configPath` is a root-written channel-B file — the agent cannot know where
it is unless the seam tells it, and hardcoded per-agent paths are exactly what
channel B replaces. Putting both on the implant side keeps the agents oblivious
to root concerns.

## D3 — Why defensive invocation is a voboost-inject requirement

**Choice:** a throwing or unresolvable seam is reported to device-safety and does
not crash the target.

**Reasoning:** the seam runs inside a live vendor process. An uncaught JNI
exception or a missing `AgentEntry` (wrong/absent DEX) must not take the target
down — that is precisely the "injection crashes the target" scenario the circuit
breaker exists for. Per-agent fault isolation *inside* `AgentEntry` is the agents'
concern; surviving a total seam failure is the implant's, because only the
implant can clear the pending exception and return control without aborting.

## D4 — Why the agents-manifest bundle-vs-per-agent question does not touch this spec

The open cross-repo decision — whether agents ship as one bundle DEX (manifest
keyed by `class`) or one DEX per agent (manifest keyed by `file`) — changes the
agents-manifest shape (owned jointly by the manifest specs and the app repo) and
how the implant loads DEX (owned by `native-payload`, via
`InMemoryDexClassLoader`). It does **not** touch the seam: `AgentEntry.init` is
called the same way regardless of how many DEX files carry the agents or how the
manifest keys them. The recommendation on the agents' side is a single bundle DEX
(DEX + reflection removes frida's whole-source `create_script` limitation, so one
bundle can instantiate the right classes per process), with per-agent
enable/quarantine by `id` and sha256 over the bundle — but this spec is
deliberately agnostic to that outcome so it need not change when the decision
lands. The decision itself is tracked where it belongs: the agents-manifest and
`native-payload` DEX-loading specs, not here.
