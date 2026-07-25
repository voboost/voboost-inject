## MODIFIED Requirements

### Requirement: Core update via content-addressed install and init restart

An inject update SHALL verify the staged binary's sha256 against the
daemon-re-verified release manifest, install it as `voboost-inject-<sha>` in
the root zone (`/data/voboost-inject/`), write a
`voboost-inject-switch-pending` marker naming the previous active file, and
atomically repoint the stable launch path
`/data/voboost-inject/voboost-inject` to the new file, then perform a clean
self-shutdown so Android init restarts the service on the new binary. The
running binary is never replaced in place; the switch takes effect at the
next daemon (re)start. The update SHALL atomically swap the per-ABI native
payload files alongside the ELF repoint (see `ota`): both the ELF repoint and
the payload swap happen as one indivisible operation, so a partial swap is
never observable. The daemon SHALL stat-pre-check the staged binary's size
against the trusted release-manifest `size` before reading it into memory (a
DoS guard against an oversized staged payload).

#### Scenario: Inject update applied

- **WHEN** the daemon verifies and installs a staged inject binary, repoints
  the launch path, swaps the payload files, and self-shuts down
- **THEN** init restarts the service and the new binary launches with the new
  payload

#### Scenario: Inject staged binary fails sha256 verification

- **WHEN** the staged inject binary's sha256 does not match the
  daemon-re-verified release-manifest entry, or its size disagrees with the
  manifest `size`
- **THEN** the install does not proceed, no marker is written, and the current
  binary and payload stay active

#### Scenario: Power-loss during inject apply

- **WHEN** power is lost after the new file is written but the launch path is
  not yet repointed
- **THEN** the next start launches the current (unchanged) binary with the
  current payload; the orphaned `voboost-inject-<sha>` is ignored and may be
  garbage-collected

### Requirement: Core rollback on a degraded restart

The daemon SHALL roll back a pending inject switch on a (re)start that would
enter DEGRADED: it repoints the launch path back to the previous file named
in the `voboost-inject-switch-pending` marker, restores the previous payload
files, clears the marker, and self-shuts down so init restarts the previous
binary. If the daemon reaches READY with the marker present, it clears the
marker (switch confirmed) and garbage-collects the previous binary only when
the launch path no longer points at it — if the launch path still points at
the previous file (power was lost between writing the marker and repointing),
the previous file is still the active binary and MUST be kept.

#### Scenario: Degraded restart rolls back

- **WHEN** the daemon restarts DEGRADED with a `voboost-inject-switch-pending`
  marker
- **THEN** it repoints the launch path to the previous file, restores the
  previous payload, clears the marker, and self-shuts down; init restarts the
  previous binary

#### Scenario: Ready restart confirms the switch

- **WHEN** the daemon restarts READY with a `voboost-inject-switch-pending`
  marker
- **THEN** it clears the marker and garbage-collects the previous binary only
  if the launch path no longer points at it
