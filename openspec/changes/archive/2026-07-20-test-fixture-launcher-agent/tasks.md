## 1. OpenSpec change (test-fixture-launcher-agent)

- [x] 1.1 `proposal.md`: why (attach-launcher had no launcher agent in the
      fixture manifest), what (launcher-echo agent in gen-fixtures.sh), impact
- [x] 1.2 `design.md`: D1 fixture manifest not plan; D2 gen-fixtures.sh source;
      D3 stub payload; D4 separate from find-pid fix
- [x] 1.3 `specs/quality-gates/spec.md`: ADDED requirement (fixture manifest
      covers scenario targets)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-02`

## 2. Code

- [x] 2.1 `test/fixtures/gen-fixtures.sh`: emit `launcher-echo` agent
      (`com.qinggan.app.launcher`, `send({ ok: true, agent: 'launcher-echo' })`)
- [x] 2.2 regenerated `test/fixtures/manifest.json` + `manifest.sig` +
      `agents/launcher-echo.js` (+ APK/release-manifest fixtures that embed the
      manifest)

## 3. Validate

- [x] 3.1 `npx @fission-ai/openspec validate test-fixture-launcher-agent --strict`
      passes
- [x] 3.2 `make test` passes (host — agents lookup by id, count-independent)
- [x] 3.3 Emulator: provision the new manifest+agent, `attach-launcher` reaches
      `state: active` (with the `find-pid-package-match` fix)
