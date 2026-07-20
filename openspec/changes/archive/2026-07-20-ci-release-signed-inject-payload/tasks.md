# Tasks: CI publishes the signed inject payload

## 1. OpenSpec change (ci-release-signed-inject-payload)
- [x] 1.1 `proposal.md`: why (publish list stale after appended-sig; dead
      daemon-manifest step), what (MODIFIED publish, ADDED no-manifest-step),
      impact, non-goals
- [x] 1.2 `design.md`: D1 published binary is appended-sig ELF; D2 no
      per-agent daemon manifest produced here; D3 Makefile sign/verify-sig
      kept; D4 publish list
- [x] 1.3 `specs/ci-release/spec.md`: MODIFIED `Publish signed release
      artifacts` (build/voboost-inject, not build-android); ADDED
      `No CI daemon manifest step`
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-20`

## 2. Release workflow
- [x] 2.1 `.github/workflows/release.yml`: delete the `Build and sign daemon
      manifest` step (the `build/manifest.json` + `.sig` generation with the
      empty `agents` list)
- [x] 2.2 Confirm `build/manifest.json` / `.sig` are not referenced by any
      remaining step and are absent from the publish list

## 3. Validate
- [x] 3.1 `npx @fission-ai/openspec validate ci-release-signed-inject-payload
      --strict` passes
- [x] 3.2 `npx @fission-ai/openspec validate --all --strict` passes
- [x] 3.3 `make build`, `make test` pass (no code change; workflow YAML lint)
