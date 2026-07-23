## MODIFIED Requirements

### Requirement: Two APKs, app-owned OTA client, daemon-owned core self-update

Voboost SHALL ship as two APKs: `voboost` (the app, release-manifest channel
`app`) and `voboost-inject` (the root daemon, channel `inject`). The voboost
app SHALL own the OTA client: fetch a signed release manifest, compare
versions, download the newer files whole, verify each (size + sha256), and
apply per channel. For the `inject` channel the app SHALL stage the verified
daemon ELF *and* the native payload files (`libimplant.so`, `liblsplant.so`,
`liblsplt.so`, `libdobby.a` per ABI — see `native-payload`) into the app-zone
`staging/` directory and create the `voboost-inject-update-ready` marker as
the last atomic step; the app SHALL NEVER install the daemon. The daemon SHALL
own its own inject self-update: observe the marker, re-verify the staged files
(the ELF via its appended signature, the payload via the release manifest),
self-replace the ELF and swap the payload files atomically, and exit so init
restarts the new binary. Because the injected code outlives the daemon (see
`native-payload`), an inject self-update does not tear down live hooks; the
new daemon reconciles existing injections by the `libimplant.so` maps marker
(see `injection-control`).

#### Scenario: App stages the daemon ELF and payload

- **WHEN** the OTA client has downloaded and verified a newer inject update
- **THEN** it stages the daemon ELF and all per-ABI payload files into the
  app-zone `staging/` directory and creates `voboost-inject-update-ready` as
  the last atomic step, and does not install the daemon

#### Scenario: Daemon owns the inject self-update

- **WHEN** the `voboost-inject-update-ready` marker is present
- **THEN** the daemon (not the app) re-verifies the staged files, self-replaces
  the ELF, swaps the payload files, and exits so init restarts the new binary

#### Scenario: Self-update does not tear down live hooks

- **WHEN** the daemon self-updates while targets are injected
- **THEN** the injected `libimplant.so` and hooks remain live in the targets;
  the restarted daemon reconciles them by the maps marker rather than
  re-injecting

### Requirement: Re-verify the staged APK's embedded manifest before self-replace

The daemon SHALL NOT trust the app's verification for material it installs
into the trusted zone. Before self-replacing, the daemon SHALL read the staged
inject ELF (a single ELF with an appended ed25519 signature), locate the
trailing signature block by its `VOBSIG1` magic, read the authoritative
`SIG_OFFSET` (LE uint64) naming the end of the ELF part, slice the ELF bytes
`[0..SIG_OFFSET)`, and re-verify the trailing 64-byte ed25519 signature over
those ELF bytes against `EMBEDDED_PUBKEY`. The daemon SHALL additionally
re-verify each staged native payload file's sha256 against the release
manifest, which it verifies with `EMBEDDED_PUBKEY` at apply time (see
`trust-verification`, `release-manifest`). A bad magic, a `SIG_OFFSET` outside
`[1 .. file_size - 80)`, a truncated file, a payload sha256 mismatch, or a
signature that fails to verify SHALL abort the apply and leave the current
binary and payload active. The inject payload carries no embedded per-agent
manifest — the per-agent manifest rides in the app APK and is delivered by a
separate plane.

#### Scenario: Inject ELF appended signature re-verifies

- **WHEN** the daemon reads the staged inject ELF and the trailing ed25519
  signature over the ELF bytes verifies against `EMBEDDED_PUBKEY`
- **THEN** the daemon proceeds to verify the payload files and self-replace

#### Scenario: Inject ELF appended signature fails re-verification

- **WHEN** the staged inject ELF's trailing signature does not verify against
  `EMBEDDED_PUBKEY`, or the `VOBSIG1` magic is absent, or the file is
  truncated, or `SIG_OFFSET` is out of bounds
- **THEN** the daemon aborts the apply, leaves the current binary active, and
  consumes the marker (the bad payload is dropped, not retried every boot)

#### Scenario: Payload file sha256 fails re-verification

- **WHEN** a staged native payload file's sha256 does not match the release
  manifest value
- **THEN** the daemon aborts the apply, leaves the current binary and payload
  active, and consumes the marker

### Requirement: Apply a staged core APK update before the first injection

On boot the daemon SHALL apply a complete, verified staged inject update (one
whose `voboost-inject-update-ready` marker is present, whose ELF appended
ed25519 signature re-verifies with the embedded key, and whose payload files'
sha256 re-verify against the release manifest) right after VERIFY_SELF and
BEFORE the first injection, so the first injection uses the new ELF and the
new payload files. It SHALL consume the marker before the apply. If the staged
inject ELF does not re-verify, or any payload file's sha256 does not match,
the daemon SHALL ignore the update (the marker is already consumed) and
proceed with the current binary and payload (never broken). A pending
inject-switch marker is resolved on boot (READY -> confirm, DEGRADED ->
rollback).

#### Scenario: Staged inject update applied before first inject

- **WHEN** the daemon boots and a complete staged inject update's ELF
  signature and payload sha256 values re-verify
- **THEN** it is applied (self-replace ELF + swap payload + marker +
  self-shutdown) before any agent is injected, and init restarts the new
  binary

#### Scenario: Staged inject update fails re-verification

- **WHEN** the daemon boots and a staged inject update's ELF re-verification or
  a payload file's sha256 fails
- **THEN** the daemon ignores it (marker already consumed) and runs the
  current binary and payload

### Requirement: Inject payload is a single appended-sig ELF

The daemon binary SHALL be a single file named `voboost-inject` (one file, no
extension) consisting of the daemon ELF bytes followed by an 80-byte trailing
signature block: 8 bytes magic `"VOBSIG1\0"`, 8 bytes `SIG_OFFSET` (LE uint64)
naming the byte offset where the ELF part ends, and 64 bytes raw ed25519
signature over the ELF bytes `[0..SIG_OFFSET)`. The Linux/Android kernel loads
the ELF by its header and ignores the trailing bytes at exec; the daemon's
self-update reads the trailing block to re-verify the signature before
installing the ELF portion. The full inject update, however, SHALL consist of
this ELF *plus* the per-ABI native payload files (`libimplant.so`,
`liblsplant.so`, `liblsplt.so`, `libdobby.a` — see `native-payload`), whose
integrity is established by the release manifest (see `release-manifest`),
not by an appended signature. There is no ZIP container and no embedded
per-agent manifest in the ELF payload.

#### Scenario: Staged inject ELF naming

- **WHEN** the OTA client has downloaded and verified a newer daemon ELF
- **THEN** it stages the file named `voboost-inject` (no `.apk` extension) into
  the app-zone `staging/` directory alongside the per-ABI payload files, and
  creates the `voboost-inject-update-ready` marker as the last atomic step

#### Scenario: Trailing block is 80 bytes

- **WHEN** the daemon inspects the staged inject ELF's trailing bytes
- **THEN** it finds an 8-byte magic, an 8-byte LE uint64 offset, and a 64-byte
  raw ed25519 signature (80 bytes total, the only trailing content in v1)

#### Scenario: SIG_OFFSET is authoritative

- **WHEN** the daemon reads `SIG_OFFSET` from the trailing block
- **THEN** it slices `[0..SIG_OFFSET)` as the ELF part; it does NOT compute
  the ELF length as `file_size - 80`. An out-of-bounds `SIG_OFFSET` (zero,
  negative as a signed read, or leaving no room for the 80-byte block) is
  rejected

#### Scenario: Payload files are separate, manifest-verified

- **WHEN** the daemon applies the inject update
- **THEN** the per-ABI payload files are separate files (not appended to the
  ELF), and their integrity is verified via the release manifest sha256, not
  via an appended signature
