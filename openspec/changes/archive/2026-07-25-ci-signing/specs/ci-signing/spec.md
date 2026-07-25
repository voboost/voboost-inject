## MODIFIED Requirements

### Requirement: Real release build on release/tag

On a release/tag, CI SHALL cross-build the `inject` daemon target for Android
(`make build-android`: the daemon via `cargo-ndk` targeting
`aarch64-linux-android`, and the native artifacts via NDK r29
`ndk-build`/CMake — see `build-and-signing`) and strip the daemon ELF for the
release artifact: the published device binary is stripped (`llvm-strip`),
since `make build-android` leaves symbols in and strip is install-time. The
native artifacts SHALL be built without LTO (see `build-and-signing`). This
happens before signing.

#### Scenario: Release tag triggers the build

- **WHEN** a release/tag build runs
- **THEN** CI builds the daemon via `cargo-ndk` (aarch64) and the native
  artifacts via NDK r29 `ndk-build`/CMake, without LTO, and strips the daemon
  ELF for the published artifact
