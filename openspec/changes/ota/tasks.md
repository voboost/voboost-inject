## 1. Inject self-update covers the payload files

- [ ] 1.1 The app stages all `inject`-channel files (daemon ELF + per-ABI
      payload `.so`/`.a`) into staging, not just the ELF
- [ ] 1.2 The daemon self-update swaps the ELF *and* the payload files as one
      atomic unit (all verified, all swapped, or none — same marker)
- [ ] 1.3 `.prev` rollback covers the payload directory alongside the ELF

## 2. Re-verify covers the payload sha256

- [ ] 2.1 ELF: appended `VOBSIG1` signature re-verified against `EMBEDDED_PUBKEY`
      (unchanged)
- [ ] 2.2 Payload files: sha256 re-verified against the release manifest
      (verified with `EMBEDDED_PUBKEY` at apply time — see `trust-verification`,
      `release-manifest`)
- [ ] 2.3 A payload file that fails sha256 aborts the apply (never end up broken)

## 3. Apply before first injection

- [ ] 3.1 The staged update (ELF + payload) is applied after VERIFY_SELF and
      before the first injection, so the first injection uses the new ELF and
      the new payload

## 4. Agents .dex on the same carrier channel

- [ ] 4.1 Agents ship as `assets/agents/*.dex` in the app APK (was `.js`)
- [ ] 4.2 `ScriptExtractor` → `AgentExtractor`; staging via `agents-update-ready`
      (unchanged marker)
- [ ] 4.3 Agent manifest per-file sha256 covers `.dex` (signed by key-root — see
      `trust-verification`)

## 5. Validate

- [ ] 5.1 `npx @fission-ai/openspec validate ota --strict`
- [ ] 5.2 Device test: an inject OTA swaps ELF + payload atomically; a
      tampered payload file aborts the apply; agents load as `.dex`
