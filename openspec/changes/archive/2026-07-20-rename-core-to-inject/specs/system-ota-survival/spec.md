## MODIFIED Requirements

### Requirement: Init hook restarts the daemon on exit
The init hook SHALL configure the daemon service to be restarted by Android
init when it exits (not `oneshot`/`disabled`). This is what the no-reboot
inject update depends on: an inject-apply self-shutdown results in init
launching the new binary. The hook MUST launch
`/data/voboost/voboost-inject` once without a fork-loop; init/watchdog
manages restarts (the daemon enforces single-instance via its pidfile +
flock).

#### Scenario: Daemon exit is restarted
- **WHEN** the daemon exits (clean self-shutdown after an inject apply, or a
  crash)
- **THEN** Android init restarts the service, launching
  `/data/voboost/voboost-inject` (which an inject apply may have repointed to
  a new binary)
