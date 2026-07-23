# Design — atomic-apply-rollback (path + payload swap)

<!-- Date: 2026-07-23. Path rename + payload files join the atomic swap. -->

## D1 — Why the path changes and the payload joins the swap

**Choice:** the stable launch path becomes `/data/voboost-inject/voboost-inject`,
and the inject core update swaps the payload files atomically alongside the ELF
repoint.

**Reasoning:** the zone rename (see `provisioning`) moves the stable launch
path, so the content-addressed install and rollback requirements must reference
the new path. The inject update is now multi-file (ELF + payload — see `ota`),
so the atomic install must treat the ELF repoint and the payload swap as one
indivisible operation: both happen, or neither does (the "never end up broken"
invariant). The agent-set swap, boot recovery, and marker semantics are
artifact-agnostic and need no change — they operate on the agent manifest, which
is unaffected by the payload addition.
