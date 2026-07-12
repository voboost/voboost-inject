## 1. OpenSpec change (daemon-frida-init)

- [x] 1.1 `proposal.md`: why (Frida.init () never called — git log -S empty;
      gum_init + asset paths never run), what (add Frida.init () in main),
      impact
- [x] 1.2 `design.md`: D1 deduction; D2 why production tolerated it; D3 the
      fix; D4 relationship to the frida-gum patch; D5 out of scope (target
      injection); D6 rejected alternatives
- [x] 1.3 `specs/daemon-lifecycle/spec.md`: ADDED requirement (Frida.init ()
      before any frida object)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-01`

## 2. Code

- [x] 2.1 `src/main.vala`: `Frida.init ()` in `main ()` right after
      `Log.init ()`, before `new Daemon (...)`

## 3. Validate

- [x] 3.1 `npx @fission-ai/openspec validate daemon-frida-init --strict` passes
- [x] 3.2 `make build`, `make test`, `make lint` pass (host)
- [x] 3.3 `make build-android` passes
- [x] 3.4 Emulator: daemon reaches `ready`, no abort, no GLib-CRITICAL;
      spawn-gating enabled. (Target injection failure on API 28 is a separate
      Linjector/BPF concern — out of scope, see design D5.)
