## MODIFIED Requirements

### Requirement: Signed release manifest, distinct from the daemon manifest

The OTA system SHALL define a release manifest (`release-manifest.json` +
detached `.sig`, ed25519) that is produced and signed by this repo's CI via
`make release-manifest` + `make sign`. It SHALL be distinct from the daemon's
`manifest.json` (per-agent id/process/kind/sha256, app-signed,
daemon-verified against the embedded key). The release manifest SHALL list
every `inject`-channel file with its sha256: the daemon ELF *and* each runtime
native payload file (`libimplant.so`, `liblsplant.so`) for every ABI
(`arm64-v8a` and `armeabi-v7a`), because the native payload is a set of files
that a single ELF appended signature cannot cover (see `native-payload`).
`libdobby.a` (build-time only, statically linked into `libimplant.so`) and
`liblsplt.so` (unused) SHALL NOT be listed. The OTA client (the voboost app)
SHALL verify the release manifest's signature against the committed public key
(`config/release-public.pem`, same key family as the daemon's
`EMBEDDED_PUBKEY`) before trusting any of its contents; the daemon SHALL
re-verify it with `EMBEDDED_PUBKEY` when applying an inject update, and SHALL
verify each listed payload file's sha256 against the verified manifest before
using that file. The daemon ELF retains its appended ed25519 signature for
self-verification at apply time (see `ota`); the payload `.so` files are
verified through the manifest, not by an appended signature.

#### Scenario: Valid release-manifest signature

- **WHEN** the OTA client fetches a new release manifest whose detached
  signature verifies against the committed public key
- **THEN** the client trusts its file list (daemon ELF + the per-ABI
  `libimplant.so` and `liblsplant.so`) and proceeds to diff

#### Scenario: Invalid release-manifest signature

- **WHEN** the release manifest's signature is missing or fails verification
- **THEN** the client rejects it, performs no update, and does NOT persist it
  as the current manifest

#### Scenario: Payload file hash verified before use

- **WHEN** the daemon is about to inject a target and selects the per-ABI
  `libimplant.so` (and its hooker dependency `liblsplant.so`)
- **THEN** it verifies each payload file's sha256 against the verified release
  manifest first and SHALL NOT use a file whose hash does not match

### Requirement: Release-manifest size and entry bounds

The release-manifest parser SHALL enforce a maximum manifest byte size and a
maximum entry count (mirroring the daemon plan's size bound), so a
pathologically large but legitimately signed manifest cannot exhaust memory. A
manifest exceeding either bound SHALL be rejected. The entry-count bound SHALL
accommodate the native payload's per-ABI runtime files (≈2 files × 2 ABIs:
`libimplant.so` and `liblsplant.so`) in addition to the daemon ELF and any
`agents`/`app` entries, while still rejecting an abnormally large manifest.

#### Scenario: Manifest within bounds

- **WHEN** a signed release manifest is at or below the size and entry-count
  caps (including the native payload's per-ABI runtime entries)
- **THEN** it is parsed and used normally

#### Scenario: Oversized manifest rejected (negative)

- **WHEN** a signed release manifest exceeds the byte-size or entry-count cap
- **THEN** the client rejects it and performs no update
