# release-manifest Specification

## Purpose
TBD - created by archiving change ota. Update Purpose after archive.
## Requirements
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

### Requirement: Per-file metadata with change-frequency channels

The release manifest SHALL list each component file with `path`, `channel`,
`sha256`, `size`, `version`, and — for per-ABI native payload files — `abi`
(`arm64-v8a` | `armeabi-v7a`), where `channel` is one of `agents`,
`inject`, or `app`. This repo's CI emits only the `inject` channel (the daemon
ELF and the native payload files); the `agents` and `app` channels are
produced by the voboost app repo. A per-ABI payload entry missing its `abi`
field, an entry missing any other required field, or whose `channel` value is
not in {agents, inject, app}, SHALL be rejected even if the manifest signature
is otherwise valid. The manifest SHALL list both ABIs of each native payload
file; a manifest that lists one ABI's payload but not the other's SHALL be
rejected as a deployment gap, so the daemon never injects into a target whose
ABI payload is absent. `size` is an advisory DoS guard (a quick reject of an
obviously-truncated or oversized download before hashing); `sha256` is the
authoritative integrity check.

#### Scenario: Manifest entry is well-formed

- **WHEN** the release manifest is parsed
- **THEN** every file entry carries a path, a channel in {agents, inject,
  app}, a sha256, a size, and a version; and every per-ABI payload entry also
  carries an `abi`

#### Scenario: Per-ABI entry missing abi (negative)

- **WHEN** a payload entry known to be per-ABI (e.g. `libimplant.so`) lacks an
  `abi` field
- **THEN** the client rejects the entire manifest and performs no update, even
  if the signature is valid

#### Scenario: Entry missing a required field (negative)

- **WHEN** a manifest entry is missing one or more of path, channel, sha256,
  size, version
- **THEN** the client rejects the entire manifest and performs no update, even
  if the signature is valid

#### Scenario: Entry with invalid channel (negative)

- **WHEN** a manifest entry's channel value is not one of agents, inject, app
- **THEN** the client rejects the entire manifest and performs no update, even
  if the signature is valid

#### Scenario: Only one ABI listed (negative)

- **WHEN** the manifest lists `libimplant.so` for `arm64-v8a` but not for
  `armeabi-v7a` (or vice versa)
- **THEN** the manifest is rejected as an incomplete payload before the daemon
  attempts any injection

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

### Requirement: Streaming APK entry inflate
The daemon's inject-payload reader SHALL verify an appended ed25519 signature
over the ELF bytes of the staged inject file (trailing `VOBSIG1` block), not
inflate a ZIP entry. There is no APK ZIP reader, no central-directory walk, no
deflate/inflate path, and no per-entry uncompressed-size handling in the
trusted code path. The trailing 64-byte raw ed25519 signature is verified via
Monocypher's `Ed25519.check` (detached, over the raw ELF bytes — the library
hashes internally with SHA-512); the daemon does not compute a separate sha256
for signature verification.

#### Scenario: Appended signature over the ELF bytes
- **WHEN** the daemon reads the staged inject file
- **THEN** it locates the trailing block by the `VOBSIG1` magic, reads
  `SIG_OFFSET`, slices the ELF bytes `[0..SIG_OFFSET)`, and verifies the
  64-byte signature over those bytes against `EMBEDDED_PUBKEY` — no ZIP
  parsing and no inflate step is involved

