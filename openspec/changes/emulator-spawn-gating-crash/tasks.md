## 1. OpenSpec change (emulator-spawn-gating-crash)

- [x] 1.1 `proposal.md`: why (frida-gum g_assert SIGABRT on emulator), what
      changes (no code change; document analysis + spec the env-var), impact
- [x] 1.2 `design.md`: D1 root cause (gum_alloc_n_pages g_assert); D2 why
      narrow patch insufficient (memcpy NULL-deref); D3 why full patch too
      invasive (6 callers, API contract); D4 why Vala siglongjmp rejected
      (async UB); D5 why fork rejected; D6 why _exit+restart rejected;
      D7 chosen fix (env-var); D8 standalone frida-server works; D9 upstream
      path forward
- [x] 1.3 `specs/injection-control/spec.md`: ADDED requirement for the
      emulator spawn-gating escape hatch (env-var scope, non-effect on attach)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-06-28`

## 2. No code change

- [x] 2.1 `VOBOOST_SKIP_SPAWN_GATING` env-var already in `src/supervisor.vala`
      (commits 46ad097, d857b10). No further code change in this change.
- [x] 2.2 `make build` unaffected (no source change)

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate emulator-spawn-gating-crash
      --strict` passes
- [ ] 3.2 `make build` passes (no code change expected)
