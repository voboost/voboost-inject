## 1. Path rename

- [ ] 1.1 Stable launch path → `/data/voboost-inject/voboost-inject`

## 2. Payload joins the atomic swap

- [ ] 2.1 Inject core update swaps payload files atomically alongside the ELF
      repoint (all or nothing — see `ota`)
- [ ] 2.2 Rollback restores the previous payload alongside the ELF repoint

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate atomic-apply-rollback --strict`
