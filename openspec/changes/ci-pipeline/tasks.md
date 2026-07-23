## 1. Pipeline matches the new toolchain

- [ ] 1.1 Provision step: Rust toolchain from `rust-toolchain.toml`; NDK r29
      verified (no frida wrap, no patched valac, no meson)
- [ ] 1.2 Validation build: `make build` over the Cargo + ndk-build/CMake stack
- [ ] 1.3 `make lint` runs `cargo clippy` + uncrustify; `make test` runs host
      tests

## 2. Cache keyed on the new pins

- [ ] 2.1 Cache key: `rust-toolchain.toml` hash + NDK version
- [ ] 2.2 Cached artifact: Cargo registry/`target/` prefix + fetched NDK

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate ci-pipeline --strict`
