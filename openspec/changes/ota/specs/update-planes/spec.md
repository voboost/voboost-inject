## ADDED Requirements

### Requirement: App-plus-agents update plane
Agents and their signed daemon manifest SHALL be delivered inside the voboost
APK; updating agents SHALL be a new voboost release. This plane SHALL be covered
by the APK's own signature in addition to the daemon-manifest signature. A staged
app+agents update SHALL be applied immediately (atomic manifest swap + re-inject),
not deferred to a restart.

#### Scenario: Agent change ships as a release
- **WHEN** an agent is changed
- **THEN** it is delivered as a new voboost release carrying the updated agent
  and a re-signed daemon manifest inside the APK

#### Scenario: Agent update applies immediately
- **WHEN** the daemon consumes a verified staged agent update
- **THEN** it swaps the manifest and re-injects without restarting the daemon

### Requirement: Core update plane (on-device, no car reboot)
The `voboost-inject` binary (the `core` channel) SHALL be updatable on-device
without a car reboot: the app downloads the binary and stages it; the daemon
verifies it against the daemon-re-verified release manifest, installs it under a
content-addressed name (`voboost-inject-<sha>`), writes a switch-pending marker
naming the previous active file, repoints the stable launch path
(`/data/voboost/voboost-inject`) to the new file, and performs a clean
self-shutdown; Android init then restarts the service, launching the new binary.
This repo's CI emits only the `core` release-manifest channel; the `agents`/`app`
channels are produced by the voboost app repo.

#### Scenario: Core binary update applied without a reboot
- **WHEN** the daemon verifies and installs a staged core binary, repoints the
  launch path, and self-shuts down
- **THEN** Android init restarts the service and the new binary launches without
  a car reboot

#### Scenario: Core binary update rolled back on a degraded restart
- **WHEN** the new binary restarts DEGRADED with a switch-pending marker present
- **THEN** the daemon repoints the launch path back to the previous binary,
  clears the marker, and self-shuts down, and init restarts the previous binary

### Requirement: Producer side of the staging contract
For app+agents updates the app SHALL write the new daemon manifest and agents
into the app-zone `staging/` directory and SHALL create the `update-ready` marker
only after all staged files are fully written, so the daemon never reads a
partial set. The `update-ready` marker is a single-use signal: the daemon SHALL
apply only while it is present and SHALL consume (remove) it after the attempt,
whether the apply succeeded or the set failed verification (see
atomic-apply-rollback "Consume the update-ready marker after apply"). This keeps
a successful update from being re-applied on every boot.

#### Scenario: Staging completes before the marker
- **WHEN** the app stages a new daemon manifest and agents
- **THEN** it writes all files first and creates `update-ready` last as a single
  atomic step

#### Scenario: Daemon reads staged content
- **WHEN** the `update-ready` marker exists
- **THEN** the staged set is complete and consistent for the daemon to re-verify
  with its embedded key

#### Scenario: Daemon consumes the marker after apply
- **WHEN** the daemon finishes applying a staged set (success or verified failure)
- **THEN** it removes the `update-ready` marker, so the next boot or a re-fire of
  the staging watch does not re-apply the same set

#### Scenario: One plane per marker
- **WHEN** a single `update-ready` marker is staged with material for more than
  one plane (a core binary AND an agent daemon manifest)
- **THEN** the producer has violated the contract; the daemon applies exactly one
  plane per marker — the core plane when a staged core binary is present
  (precedence), then consumes the marker — and the agent half is not applied
  until the producer re-stages it under a fresh marker
