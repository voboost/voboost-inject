## 1. Per-target circuit breaker

- [ ] 1.1 `safety.rs` — per-target crash counter over a sliding window; trip at
      M = 3 / N ≈ 30s → stop injecting that target, report `degraded`
- [ ] 1.2 Conservative threshold (M = 1–2) for `system_server`
- [ ] 1.3 Keep it distinct from the per-`(agent, process)` rate-limit and global
      panic-quarantine

## 2. Per-agent isolation (restated)

- [ ] 2.1 Rely on the agent runtime's per-agent `try/catch` (voboost-script) and
      the implant's defensive seam invocation (`agent-entry-seam`); a throwing
      agent or seam does not crash the target or the others

## 3. Coexistence skip (restated)

- [ ] 3.1 Skip a target carrying a foreign injection footprint; treat the
      daemon's own `libimplant.so` marker as own, not foreign, on re-injection

## 4. Kill-switch (restated)

- [ ] 4.1 `/data/voboost-inject/run/disable` file OR `inject.json`
      `enabled:false` → stop new injections, idle
- [ ] 4.2 Deactivation does not auto-resume (restart required); do not tear down
      live injections (that is a no-agents plan, `update-planes`)

## 5. Remove guaranteed-resume

- [ ] 5.1 Delete the spawn-gating guaranteed-resume path (no gating exists)

## 6. Validate

- [ ] 6.1 `npx @fission-ai/openspec validate device-safety --strict`
- [ ] 6.2 Device test: breaker trips on a target that keeps crashing; kill-switch
      stops new injections; foreign-agent coexistence skip
