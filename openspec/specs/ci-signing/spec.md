# ci-signing Specification

## Purpose
Specify release-time signing of the OTA release manifest with the ed25519 key from CI secrets:
private-key hygiene, committed-public-key verification, and no signing on non-release builds.
## Requirements
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

### Requirement: Release signing from CI secrets
On a release/tag build, CI SHALL sign the OTA release manifest (`build/release-manifest.json`,
whose schema is defined by the `ota` change) with the ed25519 private key drawn from CI secrets.
Signing this single manifest transitively authenticates every listed file via its in-manifest
sha256 (the OTA trust model). The private key SHALL never be committed and SHALL never be printed
in logs. The private key SHALL be written to a temporary file with mode 0600 and deleted via a
`trap` so that it is removed even if a subsequent command fails.

#### Scenario: Release build signs the OTA release manifest
- **WHEN** a release/tag build runs
- **THEN** CI signs `build/release-manifest.json` using the private key from secrets and the
  committed public key verifies the detached `.sig`

#### Scenario: Private key absent from repo and logs
- **WHEN** the repository and CI logs are inspected
- **THEN** no private key material is present in either

### Requirement: Non-release builds do not sign
Push/PR builds that are not releases SHALL NOT require the signing key and SHALL still lint, test,
and build.

#### Scenario: PR build without signing
- **WHEN** a non-release push/PR build runs
- **THEN** it lints, tests, and builds release-only without accessing the signing key

