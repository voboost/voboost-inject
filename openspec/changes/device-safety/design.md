# Design — device-safety (frida → ptrace/LSPlant)

<!-- Date: 2026-07-23. Records why a per-target circuit breaker is added, why
     guaranteed resume is removed, and why the kill-switch no longer re-opens
     anything. -->

## D1 — Why add a per-target circuit breaker

**Choice:** a per-target breaker (M crashes / N seconds → stop injecting that
target, report degraded), distinct from the per-`(agent, process)` rate-limit and
the global panic-quarantine.

**Reasoning:** the three mechanisms guard different failure scopes. The rate-limit
throttles reinjection of one agent into one process (a flapping agent). The global
panic-quarantine stops everything when deaths spike device-wide. Neither directly
expresses "this injection keeps killing this one target" — which is the exact,
observed failure mode (a cluster of frida crashes: 3 in 24s). The per-target
breaker names that scope. `system_server` gets a lower threshold (M = 1–2) because
one `system_server` death is a framework soft-reboot, not a single app restart, so
the cost of a second attempt is far higher. Thresholds are a starting point
(M = 3 / N ≈ 30s) to be calibrated under LSPlant after the agents are ported;
the requirement fixes the mechanism and the conservative-system_server rule, not
final numbers.

## D2 — Why remove guaranteed resume

**Choice:** drop "Guaranteed resume of gated processes" entirely.

**Reasoning:** the guarantee existed because frida's global spawn-gating suspended
processes, and a failed injection could leave one suspended — bricking the boot
sequence. Attach-only ptrace never suspends the target: it attaches, injects, and
detaches, and the target runs throughout. With nothing suspended there is nothing
to guarantee resuming, so the requirement is not "moved" — it is obsolete.

## D3 — Why the kill-switch no longer re-opens anything

**Choice:** the kill-switch stops new injections and idles; deactivation requires a
restart; there is no frida to re-open, and it does not tear down live injections.

**Reasoning:** the frida kill-switch could "resume all gated processes" and needed
a restart "to re-open frida" — both frida artifacts. In the ptrace model there is
no gating and no device handle, so the kill-switch is purely "stop making new
injections". It deliberately does NOT tear down existing injections: those outlive
the daemon and are torn down only by an explicit no-agents plan over channel B
(see `update-planes`). Keeping deactivation manual (restart required) preserves the
original fail-safe stance: a kill-switch is an operator action, not a flapping
auto-toggle.

## D4 — What stays unchanged and why

"No vehicle motion or ignition gating", "Reinjection rate-limit and quarantine",
"Global panic-quarantine", and "Capability detection over version strings" are
mechanism-agnostic: they never referenced frida internals, and they apply
identically whether injection is frida or ptrace. Restating them would only risk
drift, so they are left untouched. The `oneshot`+`disabled` init service (a
reboot-loop guard) is a safety property too, but it is owned by `daemon-lifecycle`
(service definition) and the self-update flow, not duplicated here.
