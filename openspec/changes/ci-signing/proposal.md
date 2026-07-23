## Why

The `ci-signing` spec cross-builds the daemon (`make build-android`, meson,
arm64-v8a, static, LTO) and strips it, then signs the release manifest. The
build moved to `cargo-ndk` + NDK r29 `ndk-build`/CMake (see
`build-and-signing`); the cross-build description and strip details must
update. The signing of the release manifest is unchanged (the manifest now
lists more files — the payload — but the signing act is the same).

## What Changes

- **MODIFIED**:
  - "Real release build on release/tag" — the cross-build is now
    `cargo-ndk` (aarch64) + NDK r29 `ndk-build`/CMake (not meson); LTO is
    disabled for the native artifacts (see `build-and-signing`); strip applies
    to the daemon ELF (via `llvm-strip`).
- **Unchanged**: "Release signing from CI secrets" (the release manifest is
  signed with the ed25519 key from secrets; the manifest now covers the payload
  files but the signing mechanism is identical), "Non-release builds do not
  sign".

## Capabilities

### Modified Capabilities

- `ci-signing`: the release cross-build uses `cargo-ndk` + NDK r29 (not meson);
  the native artifacts are built without LTO; the daemon ELF is stripped for
  the published artifact. Release-manifest signing is unchanged.
