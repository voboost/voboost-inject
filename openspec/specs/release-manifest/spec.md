# release-manifest Specification

## Purpose
TBD - created by archiving change ota. Update Purpose after archive.
## Requirements
### Requirement: Signed release manifest, distinct from the daemon manifest
The OTA system SHALL define a release manifest (`release-manifest.json` + detached
`.sig`, ed25519) that is produced and signed by this repo's CI via
`make release-manifest` + `make sign`. It SHALL be distinct from the daemon's
`manifest.json` (per-agent id/process/kind/sha256, app-signed, daemon-verified
against the embedded key). The OTA client (the voboost app) SHALL verify the
release manifest's signature against the committed public key
(`config/release-public.pem`, same key family as the daemon's `EMBEDDED_PUBKEY`)
before trusting any of its contents; the daemon SHALL re-verify it with
`EMBEDDED_PUBKEY` when applying a core update.

#### Scenario: Valid release-manifest signature
- **WHEN** the OTA client fetches a new release manifest whose detached signature
  verifies against the committed public key
- **THEN** the client trusts its file list and proceeds to diff

#### Scenario: Invalid release-manifest signature
- **WHEN** the release manifest's signature is missing or fails verification
- **THEN** the client rejects it, performs no update, and does NOT persist it as
  the current manifest

### Requirement: Per-file metadata with change-frequency channels
The release manifest SHALL list each component file with `path`, `channel`,
`sha256`, `size`, and `version`, where `channel` is one of `agents`, `core`, or
`app`. This repo's CI emits only the `core` channel (the device binary); the
`agents` and `app` channels are produced by the voboost app repo. An entry that
is missing any required field, or whose `channel` value is not in {agents, core,
app}, SHALL be rejected even if the manifest signature is otherwise valid. `size`
is an advisory DoS guard (a quick reject of an obviously-truncated or oversized
download before hashing); `sha256` is the authoritative integrity check.

#### Scenario: Manifest entry is well-formed
- **WHEN** the release manifest is parsed
- **THEN** every file entry carries a path, a channel in {agents, core, app}, a
  sha256, a size, and a version

#### Scenario: Entry missing a required field (negative)
- **WHEN** a manifest entry is missing one or more of path, channel, sha256,
  size, version
- **THEN** the client rejects the entire manifest and performs no update, even if
  the signature is valid

#### Scenario: Entry with invalid channel (negative)
- **WHEN** a manifest entry's channel value is not one of agents, core, app
- **THEN** the client rejects the entire manifest and performs no update, even if
  the signature is valid

### Requirement: Release-manifest size and entry bounds
The release-manifest parser SHALL enforce a maximum manifest byte size and a
maximum entry count (mirroring the daemon plan's size bound), so a
pathologically large but legitimately signed manifest cannot exhaust memory. A
manifest exceeding either bound SHALL be rejected.

#### Scenario: Manifest within bounds
- **WHEN** a signed release manifest is at or below the size and entry-count caps
- **THEN** it is parsed and used normally

#### Scenario: Oversized manifest rejected (negative)
- **WHEN** a signed release manifest exceeds the byte-size or entry-count cap
- **THEN** the client rejects it and performs no update

