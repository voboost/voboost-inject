## 1. OpenSpec change (make-test-uses-frida-meson)

- [x] 1.1 `proposal.md`: why (test target used system meson → pickle
      incompatibility with frida-meson coredata.dat), what changes (route `test`
      through FRIDA_MESON), impact
- [x] 1.2 `design.md`: D1 pickle incompatibility; D2 why build was unaffected;
      D3 the fix; D4 scope; D5 rejected alternatives
- [x] 1.3 `specs/build-and-signing/spec.md`: ADDED requirement (all build-dir
      meson commands use frida-meson; make test scenario)
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-01`

## 2. Code

- [x] 2.1 `Makefile` `test` target: `$(PYTHON_FOR_MESON) $(FRIDA_MESON) test -C
      $(BUILD_DIR)` (matching setup/build-android) + documenting comment

## 3. Validate

- [x] 3.1 `npx @fission-ai/openspec validate make-test-uses-frida-meson
      --strict` passes
- [x] 3.2 `make test` passes (9/9 host unit tests) after `make setup`
