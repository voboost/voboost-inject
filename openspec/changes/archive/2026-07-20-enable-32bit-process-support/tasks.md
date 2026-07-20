## 1. OpenSpec change (enable-32bit-process-support)

- [x] 1.1 `proposal.md`: why (target device runs 6/8 processes as 32-bit;
      13/16 agents route at them; old build failed with
      `Unable to handle 32-bit processes`), what (`frida-core:compat=disabled`
      -> `auto`, build-time only), capabilities, impact
- [x] 1.2 `design.md`: measured platform fact (process ABI table); D1 `auto`
      not `enabled`; D2 what enters the binary (frida-helper-32 + armv7
      frida-agent.so, ~8 MB growth); D3 build-time only, no runtime change;
      D4 no trust boundary crossed
- [x] 1.3 `specs/build-and-signing/spec.md`: MODIFIED frida-core subproject
      requirement — compat `disabled` -> `auto`, with the 32-bit-helper
      scenario
- [x] 1.4 `specs/injection-control/spec.md`: ADDED `32bit-target-support`
      requirement with 3 scenarios (32-bit injected, 64-bit unaffected,
      build-without-helper fails)
- [x] 1.5 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-20`

## 2. Code

- [x] 2.1 `meson.build`: `frida-core:compat=disabled` -> `frida-core:compat=auto`
      (already in the working tree; committed with this change)
- [x] 2.2 No `src/` change — the `device.attach(pid)` / spawn-gating /
      `create_script` path is ABI-agnostic; frida picks the helper per target

## 3. Validate + build

- [x] 3.1 `npx @fission-ai/openspec validate enable-32bit-process-support --strict`
      passes
- [x] 3.2 `make build` (host) compiles — no Vala change, option is cross-only
- [x] 3.3 `make build-android` produces a binary with `frida-helper-32` present
      (size ~24 MB; optional — long build, needs NDK r29)
- [x] 3.4 On-device: agents routed at 32-bit processes (e.g.
      `pedestrian-warning` at `com.qinggan.systemservice`) reach
      `state: active` — verified earlier on the car (see `CURRENT.md`)
