## 1. Cross-build matches the new toolchain

- [ ] 1.1 Release cross-build: `cargo-ndk` (aarch64) + NDK r29
      `ndk-build`/CMake (not meson)
- [ ] 1.2 LTO disabled for the native artifacts (see `build-and-signing`)
- [ ] 1.3 Daemon ELF stripped via `llvm-strip` for the published artifact

## 2. Release-manifest signing (unchanged)

- [ ] 2.1 Sign `build/release-manifest.json` with the ed25519 key from CI
      secrets; committed public key verifies the detached `.sig`
- [ ] 2.2 Private key in a 0600 temp file, deleted via `trap`; never committed
      or logged

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate ci-signing --strict`
