## 1. OpenSpec change (emulator-frida-page-size-fix)

- [x] 1.1 `proposal.md`: why (page_size==0 root cause; guards are no-ops),
      what changes (frida-gum patch + wrap + supervisor opt-in + docs), impact
- [x] 1.2 `design.md`: D1 deduction; D2 why guards no-op; D3 reconcile D8;
      D4 the fix; D5 persistence; D6 emulator opt-in; D7 rejected alternatives
- [x] 1.3 `specs/daemon-lifecycle/spec.md`: ADDED requirement (page_size never
      0; emulator frida opt-in)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-01`

## 2. Code

- [x] 2.1 `subprojects/frida-gum/gum/gummemory.c`: `gum_query_page_size`
      lazily (re-)queries + 4 KiB fallback (never 0)
- [x] 2.2 `subprojects/packagefiles/frida-gum-qemu-page-size.patch`: generated
      from `git -C subprojects/frida-gum diff` (gummemory.c + gummemory-posix.c)
- [x] 2.3 `subprojects/frida-gum.wrap`: `diff_files =
      frida-gum-qemu-page-size.patch`
- [x] 2.4 `src/supervisor.vala`: remove the emulator DEGRADED gate
      (`run()` block, `is_emulator()` method, cache fields)
- [x] 2.5 `docs/EMULATOR_DEGRADED_MODE.md`: Resolution section

## 3. Validate

- [x] 3.1 `npx @fission-ai/openspec validate emulator-frida-page-size-fix
      --strict` passes
- [x] 3.2 `make build` and `make test` pass (host)
- [x] 3.3 `make build-android` passes
- [x] 3.4 Emulator verification: no `gum_alloc_n_pages` abort under strace;
      `daemon_state: ready`; spawn-gating enabled, no SIGSEGV. (Target agent
      delivery on API 28 is a separate Linjector/BPF concern — out of scope,
      tracked separately; not asserted here.)
