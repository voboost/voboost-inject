## 1. OpenSpec change (find-pid-package-match)

- [x] 1.1 `proposal.md`: why (frida reports label not package; running app
      targets stuck at waiting), what (/proc cmdline fallback), impact
- [x] 1.2 `design.md`: D1 label-vs-package FACT; D2 why /proc; D3 keep frida
      first; D4 robustness; D5 rejected alternatives
- [x] 1.3 `specs/injection-control/spec.md`: ADDED requirement (running target
      resolved by package via /proc)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-02`

## 2. Code

- [x] 2.1 `src/frida_controller.vala` `find_pid`: keep frida name match, add
      `/proc/<pid>/cmdline` `argv[0]` fallback (skip non-numeric, tolerate
      unreadable entries)

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate find-pid-package-match --strict`
      passes
- [ ] 3.2 `make build`, `make test`, `make lint` pass (host)
- [ ] 3.3 `make build-android` passes
- [ ] 3.4 Emulator: a running app target resolves to a pid and injects
      (`state: active`), e.g. `attach-launcher` with the launcher-echo fixture
