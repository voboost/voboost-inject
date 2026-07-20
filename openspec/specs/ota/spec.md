# ota Specification

## Purpose
TBD - created by archiving change ota-core-selfupdate. Update Purpose after archive.
## Requirements
### Requirement: Two APKs, app-owned OTA client, daemon-owned core self-update
Voboost SHALL ship as two APKs: `voboost` (the app, release-manifest channel
`app`) and `voboost-inject` (the root daemon, channel `inject`). The voboost
app SHALL own the OTA client: fetch a signed release manifest, compare
versions, download the newer APK(s) whole, verify each (size + sha256), and
apply per channel. For the `inject` channel the app SHALL stage the verified
daemon APK into the app-zone `staging/` directory and create the
`voboost-inject-update-ready` marker as the last atomic step; the app SHALL
NEVER install the daemon. The daemon SHALL own its own inject self-update:
observe the marker, re-verify the staged APK, self-replace, and exit so init
restarts the new binary.

#### Scenario: App stages the daemon APK
- **WHEN** the OTA client has downloaded and verified a newer daemon APK
- **THEN** it stages the APK into the app-zone `staging/` directory and creates
  `voboost-inject-update-ready` as the last atomic step, and does not install
  the daemon

#### Scenario: Daemon owns the inject self-update
- **WHEN** the `voboost-inject-update-ready` marker is present
- **THEN** the daemon (not the app) re-verifies the staged APK, self-replaces
  the running binary, and exits so init restarts the new binary

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

### Requirement: Consume the core-update-ready marker before the apply
The daemon SHALL treat the `voboost-inject-update-ready` marker as a
single-use signal: it SHALL consume (remove) it BEFORE applying the staged
APK, so a successful self-replace + self-shutdown + init-restart does not
re-apply the same APK on every boot (which would crash-loop via self-shutdown
+ init restart until init's restart budget exhausts). A present marker implies
a complete, verified staged APK (the producer creates it last), so consuming
it before the apply is safe: the apply proceeds from the re-verified APK
alone.

#### Scenario: Marker consumed before a successful apply
- **WHEN** the daemon begins applying a staged APK
- **THEN** it removes the `voboost-inject-update-ready` marker first, then
  proceeds with re-verify and self-replace, so the post-restart boot does not
  re-apply it

#### Scenario: Marker consumed before a verified-failed apply
- **WHEN** the staged APK's embedded manifest fails re-verification
- **THEN** the marker is already consumed (removed before the apply), the bad
  APK is dropped, and the current binary stays active

### Requirement: Atomic self-replace with .prev rollback
An inject self-update SHALL extract the daemon ELF binary from the staged APK,
write it to a root-zone temp file (fsync, fchmod 0755), then atomically
self-replace: `rename(2)` the running binary aside to `voboost-inject.prev`
and the verified temp into `voboost-inject`. `rename(2)` of a running binary
is safe on Linux/Android: the running process keeps its inode until exit. The
daemon SHALL then write the `voboost-inject-switch-pending` marker and perform
a clean self-shutdown so Android init restarts the service on the new binary.
The running binary is never replaced in place by overwriting its bytes; the
switch takes effect at the next daemon (re)start via the renamed pathname. The
daemon SHALL stat-pre-check the staged APK size against a bound before reading
it into memory (a DoS guard against an oversized staged payload).

#### Scenario: Inject self-update applied
- **WHEN** the daemon re-verifies the staged APK, extracts the binary, renames
  the running binary to `.prev`, installs the new binary, writes the marker,
  and self-shuts down
- **THEN** init restarts the service and the new binary launches without a car
  reboot

#### Scenario: Power-loss between the two renames
- **WHEN** power is lost after the running binary is renamed to `.prev` but
  before the new binary is installed
- **THEN** the next start finds no `voboost-inject` (or the old one if the
  second rename completed) and no marker; the daemon stays DEGRADED rather than
  exec a missing binary, and the operator restores `.prev` via adb

#### Scenario: Power-loss after the marker write but before exit
- **WHEN** power is lost after the marker is written but before the
  self-shutdown
- **THEN** the next start launches the new binary with the marker present; a
  READY restart confirms (clears the marker, removes `.prev`)

### Requirement: Core rollback on a degraded restart
The daemon SHALL roll back a pending inject switch on a (re)start that would
enter DEGRADED: it `rename(2)`s `voboost-inject.prev` back to
`voboost-inject` (overwriting the bad new binary), clears the
`voboost-inject-switch-pending` marker, and self-shuts down so init restarts
the previous binary. If the daemon reaches READY with the marker present, it
clears the marker (switch confirmed) and removes `voboost-inject.prev`. If
`voboost-inject.prev` is absent at rollback (first-update edge, or power-loss
between the rename and the marker write), the daemon SHALL stay DEGRADED
rather than exec a known-bad binary with no rollback target.

#### Scenario: Degraded restart rolls back
- **WHEN** the daemon restarts DEGRADED with a `voboost-inject-switch-pending`
  marker and `voboost-inject.prev` exists
- **THEN** it renames `.prev` back to `voboost-inject`, clears the marker, and
  self-shuts down; init restarts the previous binary

#### Scenario: Ready restart confirms the switch
- **WHEN** the daemon restarts READY with a `voboost-inject-switch-pending`
  marker
- **THEN** it clears the marker and removes `voboost-inject.prev`

#### Scenario: No rollback target
- **WHEN** the daemon restarts DEGRADED with a `voboost-inject-switch-pending`
  marker but `voboost-inject.prev` is absent
- **THEN** the daemon stays DEGRADED (observe-only, injects nothing) rather
  than exec a known-bad binary with no rollback target

### Requirement: Boot recovery of the daemon manifest
The daemon SHALL restore `manifest.json.prev` to `manifest.json` on boot when
the active manifest is absent or fails signature verification against the
embedded key, provided `manifest.json.prev` (+`manifest.sig.prev`) exists and
verifies. This recovers from an interrupted manifest write. (The embedded
manifest is build-time inside the APK; this recovery covers the root-zone
active copy written at provisioning/VERIFY_SELF.)

#### Scenario: Boot recovery from manifest.json.prev
- **WHEN** the daemon starts and the active manifest is absent or fails
  signature verification, but `manifest.json.prev` verifies
- **THEN** `manifest.json.prev` (+`.sig.prev`) is renamed to `manifest.json`
  (+`manifest.sig`) and the daemon runs with the prior working set

#### Scenario: No recovery target
- **WHEN** the active manifest fails verification and no verifying
  `manifest.json.prev` exists
- **THEN** the daemon enters DEGRADED (observe-only, injects nothing) per the
  daemon-lifecycle self-verification failure path

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

### Requirement: Never end up broken
Any verification or apply failure SHALL leave the system in its prior working
state rather than a partially-applied one. The running binary is never
overwritten in place; the self-replace is two atomic renames, and a failure
between them leaves either the old binary active or no binary (DEGRADED), never
a corrupt binary.

#### Scenario: Update aborts mid-way
- **WHEN** an update aborts due to a verification or apply error
- **THEN** the prior working binary remains in effect and no partial state is
  active

### Requirement: Release manifest lists APKs
The release manifest SHALL be a signed document
(`release-manifest.json` + detached `.sig`, ed25519) listing each component
APK with `path`, `channel`, `sha256`, `size`, and `version`, where `channel`
is one of `agents`, `inject`, or `app`. This repo's CI SHALL emit only the
`inject` channel (the daemon APK); the `agents` and `app` channels are
produced by the voboost app repo. The OTA client (the voboost app) SHALL
verify the release manifest's signature against the committed public key
(`config/release-public.pem`, same key family as `EMBEDDED_PUBKEY`) before
trusting any of its contents. The daemon re-verifies the staged APK's embedded
manifest (not the release manifest) at apply time; the release manifest is the
client's trust source for the APK size+sha256 before staging.

#### Scenario: Release manifest lists the daemon APK
- **WHEN** this repo's CI runs `make release-manifest`
- **THEN** it emits a single `inject`-channel entry for the daemon APK with
  its path, sha256, size, and version

#### Scenario: Invalid release-manifest signature
- **WHEN** the release manifest's signature is missing or fails verification
- **THEN** the client rejects it, performs no update, and does NOT persist it
  as the current manifest

### Requirement: Release-manifest size and entry bounds
The release-manifest parser SHALL enforce a maximum manifest byte size and a
maximum entry count (mirroring the daemon plan's size bound), so a
pathologically large but legitimately signed manifest cannot exhaust memory. A
manifest exceeding either bound SHALL be rejected. An entry that is missing
any required field, or whose `channel` value is not in {agents, inject, app},
SHALL be rejected even if the manifest signature is otherwise valid. `size` is
an advisory DoS guard; `sha256` is the authoritative integrity check.

#### Scenario: Manifest within bounds
- **WHEN** a signed release manifest is at or below the size and entry-count
  caps
- **THEN** it is parsed and used normally

#### Scenario: Oversized manifest rejected
- **WHEN** a signed release manifest exceeds the byte-size or entry-count cap
- **THEN** the client rejects it and performs no update

#### Scenario: Entry missing a required field
- **WHEN** a manifest entry is missing one or more of path, channel, sha256,
  size, version
- **THEN** the client rejects the entire manifest and performs no update, even
  if the signature is valid

### Requirement: Persistence across a system OTA
A system OTA SHALL NOT require re-downloading voboost components:
`/data/voboost`, the daemon, and the agents SHALL survive it; only the
`/system` init hook is lost. The init hook SHALL configure the daemon service
to be restarted by Android init when it exits (not `oneshot`/`disabled`); this
is what the no-reboot inject self-update depends on. After a system OTA the
guarded init-hook block SHALL be restored by an operator-invoked re-arm step
(`make device-rearm HOOK=<path>` via adb); it is not automatic. The
incremental app/agents OTA SHALL operate independently of the system OTA
cadence.

#### Scenario: System OTA completes
- **WHEN** a system OTA reverts `/system`
- **THEN** `/data/voboost`, the daemon binary, and the agent set remain intact
  and nothing is re-downloaded

#### Scenario: Daemon exit is restarted
- **WHEN** the daemon exits (clean self-shutdown after an inject self-update,
  or a crash)
- **THEN** Android init restarts the service, launching
  `/data/voboost/voboost-inject` (which an inject self-update may have
  replaced)

#### Scenario: Re-arm after OTA
- **WHEN** the init hook is missing following a system OTA
- **THEN** the operator runs `make device-rearm HOOK=<path>` via adb, the
  guarded hook block is restored, and the daemon launches on the next boot

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

