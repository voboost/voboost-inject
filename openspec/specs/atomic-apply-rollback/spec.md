# atomic-apply-rollback Specification

## Purpose
TBD - created by archiving change ota. Update Purpose after archive.
## Requirements
### Requirement: Content-addressed agent file paths
A changed agent SHALL ship at a new, sha-derived `file` path in the daemon
manifest, distinct from every path the previously-active manifest references, so
an agent update never overwrites a payload file the active manifest still
verifies against. This is the precondition for the manifest swap being the
atomic unit: with content-addressed paths, a mid-apply failure leaves the prior
manifest's referenced files byte-identical and untouched. A producer that reuses
a stable path for changed agent content violates this contract and the
stay-on-old invariant cannot hold.

#### Scenario: Changed agent at a new path
- **WHEN** an agent's content changes between releases
- **THEN** the new daemon manifest references it at a new, sha-derived `file`
  path, and the prior manifest's path for that agent remains on disk unchanged
  until it is garbage-collected after a confirmed switch

### Requirement: Atomic agent-set swap with rollback
Applying a new agent set SHALL atomically swap the signed daemon manifest: the
verified staged `manifest.json`+`manifest.sig` (copied into the root zone as
TOCTOU-safe temp files and re-verified on the root-owned inode) are moved into
place using rename(2) as the atomicity primitive, while the previous verified
manifest is retained one-deep as `manifest.json.prev` (+`manifest.sig.prev`). Any
failure during apply SHALL leave the daemon on the old manifest.

#### Scenario: Successful agent swap
- **WHEN** a verified new agent set is applied
- **THEN** the previous manifest is moved aside to `manifest.json.prev` and the
  verified staged manifest becomes active, both via rename(2)

#### Scenario: Failure during agent swap
- **WHEN** applying a new agent set fails at any step
- **THEN** the daemon remains on the previous working manifest and reports the
  failure

#### Scenario: Power-loss mid-apply (agents)
- **WHEN** power is lost during the manifest-swap renames
- **THEN** the next boot finds either the old manifest intact, the new manifest
  active, or an inconsistent active manifest — and boot recovery restores the
  prior working set from `manifest.json.prev` when the rollback pair is intact;
  otherwise the daemon enters DEGRADED (observe-only, no partial set active)

### Requirement: Boot recovery after interrupted agent apply
The daemon SHALL restore `manifest.json.prev` to `manifest.json` on boot when
the active manifest is absent or fails signature verification against the embedded
key, provided `manifest.json.prev` (+`manifest.sig.prev`) exists and verifies.
This recovers from power-loss during the swap.

#### Scenario: Boot recovery from manifest.json.prev
- **WHEN** the daemon starts and the active manifest is absent or fails signature
  verification, but `manifest.json.prev` verifies
- **THEN** `manifest.json.prev` (+`.sig.prev`) is renamed to `manifest.json`
  (+`manifest.sig`) and the daemon runs with the prior working set

#### Scenario: No recovery target
- **WHEN** the active manifest fails verification and no verifying
  `manifest.json.prev` exists
- **THEN** the daemon enters DEGRADED (observe-only, injects nothing) per the
  daemon-lifecycle self-verification failure path

### Requirement: Apply staged agent updates before the first injection
On boot the daemon SHALL apply a complete, verified staged agent update (one
whose `update-ready` marker is present and whose staged daemon manifest
re-verifies with the embedded key) right after VERIFY_SELF and BEFORE the first
injection, so the first injection uses the new agent set. It SHALL apply only
while the `update-ready` marker is present, and SHALL consume it after the
attempt (see "Consume the update-ready marker after apply"). If the staged update
does not verify, the daemon SHALL ignore it, consume the marker, and proceed
with the current manifest (never broken).

#### Scenario: Staged agent update applied before first inject
- **WHEN** the daemon boots and a complete staged agent update re-verifies
- **THEN** it is applied before any agent is injected, the first injection uses
  the new set, and the `update-ready` marker is consumed

#### Scenario: Staged agent update fails verification
- **WHEN** the daemon boots and a staged agent update's re-verification fails
- **THEN** the daemon ignores it, consumes the marker, and injects the current
  (old) set

### Requirement: Consume the update-ready marker after apply
The daemon SHALL treat the `update-ready` marker as a single-use signal: it
SHALL remove it after any apply attempt on a staged set (agent or core, whether
the apply succeeded or the set failed verification). A present marker implies a
complete staged set (the producer creates it last), so a verified failure is a
genuinely bad set the producer must re-stage to retry, not one the daemon
retries on every boot. Consuming the marker on success prevents the boot
early-apply from re-applying the same set every boot (which for the core plane
would crash-loop via self-shutdown + init restart).

#### Scenario: Marker consumed after a successful apply
- **WHEN** the daemon applies a staged update (agent or core) successfully
- **THEN** the `update-ready` marker is removed, so the next boot does not
  re-apply the same set

#### Scenario: Marker consumed after a verified-failed apply
- **WHEN** a staged update fails re-verification
- **THEN** the `update-ready` marker is removed (the bad set is dropped, not
  retried), and the current set remains active

### Requirement: Core update via content-addressed install and init restart
A core update SHALL verify the staged binary's sha256 against the
daemon-re-verified release manifest, install it as `voboost-inject-<sha>` in the
root zone, write a `core-switch-pending` marker naming the previous active file,
and atomically repoint the stable launch path `/data/voboost/voboost-inject` to
the new file, then perform a clean self-shutdown so Android init restarts the
service on the new binary. The running binary is never replaced in place; the
switch takes effect at the next daemon (re)start. The daemon SHALL stat-pre-check
the staged binary's size against the trusted release-manifest `size` before
reading it into memory (a DoS guard against an oversized staged payload).

#### Scenario: Core update applied
- **WHEN** the daemon verifies and installs a staged core binary, repoints the
  launch path, and self-shuts down
- **THEN** init restarts the service and the new binary launches

#### Scenario: Core staged binary fails sha256 verification
- **WHEN** the staged core binary's sha256 does not match the daemon-re-verified
  release-manifest entry, or its size disagrees with the manifest `size`
- **THEN** the install does not proceed, no marker is written, and the current
  binary stays active

#### Scenario: Power-loss during core apply
- **WHEN** power is lost after the new file is written but the launch path is not
  yet repointed
- **THEN** the next start launches the current (unchanged) binary; the orphaned
  `voboost-inject-<sha>` is ignored and may be garbage-collected

### Requirement: Core rollback on a degraded restart
The daemon SHALL roll back a pending core switch on a (re)start that would enter
DEGRADED: it repoints the launch path back to the previous file named in the
`core-switch-pending` marker, clears the marker, and self-shuts down so init
restarts the previous binary. If the daemon reaches READY with the marker present,
it clears the marker (switch confirmed) and garbage-collects the previous binary
only when the launch path no longer points at it — if the launch path still
points at the previous file (power was lost between writing the marker and
repointing), the previous file is still the active binary and MUST be kept.

#### Scenario: Degraded restart rolls back
- **WHEN** the daemon restarts DEGRADED with a `core-switch-pending` marker
- **THEN** it repoints the launch path to the previous file, clears the marker,
  and self-shuts down; init restarts the previous binary

#### Scenario: Ready restart confirms the switch
- **WHEN** the daemon restarts READY with a `core-switch-pending` marker
- **THEN** it clears the marker and garbage-collects the previous binary only if
  the launch path no longer points at it

### Requirement: Never end up broken
Any verification or apply failure on either plane SHALL leave the system in its
prior working state rather than a partially-applied one.

#### Scenario: Update aborts mid-way
- **WHEN** an update aborts due to a verification or apply error
- **THEN** the prior working configuration remains in effect and no partial set
  is active

