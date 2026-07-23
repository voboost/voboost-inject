## 1. Zone path rename

- [ ] 1.1 `/data/voboost` → `/data/voboost-inject` in all requirements
- [ ] 1.2 Stable launch path → `/data/voboost-inject/voboost-inject`
- [ ] 1.3 `make device-rearm` restores launch of the new path

## 2. Validate

- [ ] 2.1 `npx @fission-ai/openspec validate system-ota-survival --strict`
