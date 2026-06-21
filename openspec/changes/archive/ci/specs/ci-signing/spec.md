## ADDED Requirements

### Requirement: Real release build on release/tag
On a release/tag, CI SHALL cross-build the `inject` daemon target for Android (`make build-android`,
arm64-v8a, fully static, LTO) and strip it for the release artifact: the published device binary is
stripped (`llvm-strip`), since `make build-android` leaves symbols in and strip is install-time per
`inject/build-and-signing`. This happens before signing.

#### Scenario: Release tag triggers the build
- **WHEN** a release/tag build runs
- **THEN** CI builds the daemon target with the release configuration (static, LTO) and strips it for
  the published artifact

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
