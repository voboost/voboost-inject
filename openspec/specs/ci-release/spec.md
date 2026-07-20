# ci-release Specification

## Purpose
Specify publishing the signed device binary, the OTA release manifest, and its detached signature as
release artifacts, with nothing published on earlier failure.
## Requirements
### Requirement: Publish signed release artifacts
On a release, CI SHALL stage the signed inject payload (an appended-sig ELF),
the OTA release manifest, and its detached signature as release artifacts so
they are available for hand-off to the OTA transport. The signed inject
payload is `build/voboost-inject` — the stripped daemon ELF with an appended
ed25519 signature, produced by `make sign-elf` (the format defined by the
`ota` change). CI signs the OTA release manifest and stages the three
artifacts. The raw `build-android/voboost-inject` is a build intermediate and
is not published. Durable publication/hosting for the OTA fetch transport is
out of scope for this step and is deferred (a design Open Question); this step
stages the signed artifacts as a workflow-run artifact, which also proves the
build and sign pipeline end-to-end.

#### Scenario: Release publishes artifacts
- **WHEN** a release build completes successfully
- **THEN** CI stages `build/voboost-inject`,
  `build/release-manifest.json`, and `build/release-manifest.json.sig` as
  release artifacts (a workflow-run artifact; durable hosting is deferred)

#### Scenario: Build fails before publish
- **WHEN** any earlier pipeline step fails
- **THEN** no release artifacts are published

### Requirement: No CI daemon manifest step
CI SHALL NOT generate or sign a per-agent daemon manifest. The per-agent
`manifest.json` is produced and carried by the app APK; the inject payload
is a single appended-sig ELF and carries no manifest, so this repo's release
pipeline has nothing to sign on the daemon-manifest axis.

#### Scenario: No daemon manifest is produced
- **WHEN** a release build runs
- **THEN** CI does not create `build/manifest.json` or `build/manifest.json.sig`,
  and neither file is a release artifact

