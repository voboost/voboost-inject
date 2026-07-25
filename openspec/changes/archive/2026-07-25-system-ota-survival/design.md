# Design — system-ota-survival (zone path rename)

<!-- Date: 2026-07-23. Path rename only; survival semantics are unchanged. -->

## D1 — Why only the path changes

**Choice:** every `/data/voboost` reference becomes `/data/voboost-inject`.

**Reasoning:** the zone rename (see `provisioning`, `daemon-lifecycle`) is a
cosmetic-but-required consistency fix: if this spec keeps the old path while
every other Wave 2 spec uses the new one, the spec set is internally
contradictory. The survival mechanism (system OTA reverts `/system`, leaves
`/data`) is path-independent — it works identically regardless of the zone
name. The restart-on-exit and re-arm requirements point at the stable launch
path, which moved with the zone. No semantic change, only the path string.
