## MODIFIED Requirements

### Requirement: Re-verify the staged APK's embedded manifest before self-replace
The daemon SHALL NOT trust the app's verification for material it installs
into the trusted zone. Before self-replacing, the daemon SHALL read the staged
inject file (a single ELF with an appended ed25519 signature), locate the
trailing signature block by its `VOBSIG1` magic, read the authoritative
`SIG_OFFSET` (LE uint64) naming the end of the ELF part, slice the ELF bytes
`[0..SIG_OFFSET)`, and re-verify the trailing 64-byte ed25519 signature over
those ELF bytes against `EMBEDDED_PUBKEY`. A bad magic, a `SIG_OFFSET` outside
`[1 .. file_size - 80)`, a truncated file, or a signature that fails to verify
SHALL abort the apply and leave the current binary active. The inject payload
carries no embedded per-agent manifest — the per-agent manifest rides in the
app APK and is delivered by a separate plane.

#### Scenario: Inject ELF appended signature re-verifies
- **WHEN** the daemon reads the staged inject file and the trailing ed25519
  signature over the ELF bytes verifies against `EMBEDDED_PUBKEY`
- **THEN** the daemon proceeds to install the ELF bytes and self-replace

#### Scenario: Inject ELF appended signature fails re-verification
- **WHEN** the staged inject file's trailing signature does not verify
  against `EMBEDDED_PUBKEY`, or the `VOBSIG1` magic is absent, or the file is
  truncated, or `SIG_OFFSET` is out of bounds
- **THEN** the daemon aborts the apply, leaves the current binary active, and
  consumes the marker (the bad payload is dropped, not retried every boot)

### Requirement: Apply a staged core APK update before the first injection
On boot the daemon SHALL apply a complete, verified staged inject update (one
whose `voboost-inject-update-ready` marker is present and whose appended
ed25519 signature re-verifies with the embedded key) right after VERIFY_SELF
and BEFORE the first injection, so the first injection uses the new binary.
It SHALL consume the marker before the apply. If the staged inject file does
not re-verify, the daemon SHALL ignore it (the marker is already consumed) and
proceed with the current binary (never broken). A pending inject-switch marker
is resolved on boot (READY -> confirm, DEGRADED -> rollback).

#### Scenario: Staged inject update applied before first inject
- **WHEN** the daemon boots and a complete staged inject file's appended
  signature re-verifies
- **THEN** it is applied (self-replace + marker + self-shutdown) before any
  agent is injected, and init restarts the new binary

#### Scenario: Staged inject update fails re-verification
- **WHEN** the daemon boots and a staged inject file's re-verification fails
- **THEN** the daemon ignores it (marker already consumed) and runs the
  current binary

## ADDED Requirements

### Requirement: Inject payload is a single appended-sig ELF
The staged inject update payload SHALL be a single file named `voboost-inject`
(one file, no extension) consisting of the daemon ELF bytes followed by an
80-byte trailing signature block: 8 bytes magic `"VOBSIG1\0"`, 8 bytes
`SIG_OFFSET` (LE uint64) naming the byte offset where the ELF part ends, and
64 bytes raw ed25519 signature over the ELF bytes `[0..SIG_OFFSET)`. The
Linux/Android kernel loads the ELF by its header and ignores the trailing
bytes at exec; the daemon's self-update reads the trailing block to re-verify
the signature before installing the ELF portion. There is no ZIP container and
no embedded per-agent manifest in this payload.

#### Scenario: Staged inject file naming
- **WHEN** the OTA client has downloaded and verified a newer daemon ELF
- **THEN** it stages exactly one file named `voboost-inject` (no `.apk`
  extension) into the app-zone `staging/` directory and creates the
  `voboost-inject-update-ready` marker as the last atomic step

#### Scenario: Trailing block is 80 bytes
- **WHEN** the daemon inspects the staged inject file's trailing bytes
- **THEN** it finds an 8-byte magic, an 8-byte LE uint64 offset, and a 64-byte
  raw ed25519 signature (80 bytes total, the only trailing content in v1)

#### Scenario: SIG_OFFSET is authoritative
- **WHEN** the daemon reads `SIG_OFFSET` from the trailing block
- **THEN** it slices `[0..SIG_OFFSET)` as the ELF part; it does NOT compute
  the ELF length as `file_size - 80`. An out-of-bounds `SIG_OFFSET` (zero,
  negative as a signed read, or leaving no room for the 80-byte block) is
  rejected

## REMOVED Requirements

### Requirement: Build-time embedded daemon manifest inside the APK
Superseded by the appended-sig ELF format. The per-agent manifest no longer
rides inside the inject payload; it rides in the app APK next to the agents
(architectural shift, `docs/17-ota-architecture.md` §4.1). The daemon still
verifies the per-agent manifest against `EMBEDDED_PUBKEY` at VERIFY_SELF —
that requirement lives in the trust-verification capability and covers the
root-zone active copy, regardless of how the manifest was delivered.
