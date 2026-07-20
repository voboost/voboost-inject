## MODIFIED Requirements

### Requirement: Consume the voboost-inject-update-ready marker after apply
The daemon SHALL treat the `voboost-inject-update-ready` marker as a
single-use signal: it SHALL remove it after any apply attempt on a staged set
(agent or inject, whether the apply succeeded or the set failed
verification). A present marker implies a complete staged set (the producer
creates it last), so a verified failure is a genuinely bad set the producer
must re-stage to retry, not one the daemon retries on every boot. Consuming
the marker on success prevents the boot early-apply from re-applying the same
set every boot (which for the inject plane would crash-loop via self-shutdown
+ init restart).

#### Scenario: Marker consumed after a successful apply
- **WHEN** the daemon applies a staged update (agent or inject) successfully
- **THEN** the `voboost-inject-update-ready` marker is removed, so the next
  boot does not re-apply the same set

#### Scenario: Marker consumed after a verified-failed apply
- **WHEN** a staged update fails re-verification
- **THEN** the `voboost-inject-update-ready` marker is removed (the bad set is
  dropped, not retried), and the current set remains active

### Requirement: Inject update via content-addressed install and init restart
An inject update SHALL verify the staged binary's sha256 against the
daemon-re-verified release manifest, install it as `voboost-inject-<sha>` in
the root zone, write a `voboost-inject-switch-pending` marker naming the
previous active file, and atomically repoint the stable launch path
`/data/voboost/voboost-inject` to the new file, then perform a clean
self-shutdown so Android init restarts the service on the new binary. The
running binary is never replaced in place; the switch takes effect at the
next daemon (re)start. The daemon SHALL stat-pre-check the staged binary's
size against the trusted release-manifest `size` before reading it into
memory (a DoS guard against an oversized staged payload).

#### Scenario: Inject update applied
- **WHEN** the daemon verifies and installs a staged inject binary, repoints
  the launch path, and self-shuts down
- **THEN** init restarts the service and the new binary launches

#### Scenario: Inject staged binary fails sha256 verification
- **WHEN** the staged inject binary's sha256 does not match the
  daemon-re-verified release-manifest entry, or its size disagrees with the
  manifest `size`
- **THEN** the install does not proceed, no marker is written, and the current
  binary stays active

#### Scenario: Power-loss during inject apply
- **WHEN** power is lost after the new file is written but the launch path is
  not yet repointed
- **THEN** the next start launches the current (unchanged) binary; the
  orphaned `voboost-inject-<sha>` is ignored and may be garbage-collected

### Requirement: Inject rollback on a degraded restart
The daemon SHALL roll back a pending inject switch on a (re)start that would
enter DEGRADED: it repoints the launch path back to the previous file named
in the `voboost-inject-switch-pending` marker, clears the marker, and
self-shuts down so init restarts the previous binary. If the daemon reaches
READY with the marker present, it clears the marker (switch confirmed) and
garbage-collects the previous binary only when the launch path no longer
points at it — if the launch path still points at the previous file (power
was lost between writing the marker and repointing), the previous file is
still the active binary and MUST be kept.

#### Scenario: Degraded restart rolls back
- **WHEN** the daemon restarts DEGRADED with a `voboost-inject-switch-pending`
  marker
- **THEN** it repoints the launch path to the previous file, clears the
  marker, and self-shuts down; init restarts the previous binary

#### Scenario: Ready restart confirms the switch
- **WHEN** the daemon restarts READY with a `voboost-inject-switch-pending`
  marker
- **THEN** it clears the marker and garbage-collects the previous binary only
  if the launch path no longer points at it
