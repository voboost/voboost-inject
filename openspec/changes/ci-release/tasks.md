## 1. Publish payload files as release artifacts

- [ ] 1.1 CI stages the signed daemon ELF, the per-ABI payload files
      (`libimplant.so`, `liblsplant.so`, `liblsplt.so`, `libdobby.a`), the
      release manifest, and its detached signature as release artifacts
- [ ] 1.2 The raw `build-android/` objects are build intermediates and are not
      published
- [ ] 1.3 No release artifacts are published if any earlier step fails

## 2. Validate

- [ ] 2.1 `npx @fission-ai/openspec validate ci-release --strict`
