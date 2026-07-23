## 1. Diff covers the payload files

- [ ] 1.1 OTA client diffs all `inject`-channel files (daemon ELF + per-ABI
      payload) by sha256
- [ ] 1.2 A payload-only update downloads only the changed `.so`/`.a` files

## 2. Re-verify covers payload sha256

- [ ] 2.1 Daemon re-verifies staged payload files' sha256 against the release
      manifest (in addition to the agent manifest — see `trust-verification`)

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate incremental-delta --strict`
