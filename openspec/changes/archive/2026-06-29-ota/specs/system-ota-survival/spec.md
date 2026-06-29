## ADDED Requirements

### Requirement: Persistence across a system OTA
A system OTA SHALL NOT require re-downloading voboost components: `/data/voboost`,
the daemon, and the agents SHALL survive it; only the `/system` init hook is lost.

#### Scenario: System OTA completes
- **WHEN** a system OTA reverts `/system`
- **THEN** `/data/voboost`, the daemon binary, and the agent set remain intact
  and nothing is re-downloaded

### Requirement: Init hook restarts the daemon on exit
The init hook SHALL configure the daemon service to be restarted by Android init
when it exits (not `oneshot`/`disabled`). This is what the no-reboot core update
depends on: a core-apply self-shutdown results in init launching the new binary.
The hook MUST launch `/data/voboost/voboost-inject` once without a fork-loop;
init/watchdog manages restarts (the daemon enforces single-instance via its
pidfile + flock).

#### Scenario: Daemon exit is restarted
- **WHEN** the daemon exits (clean self-shutdown after a core apply, or a crash)
- **THEN** Android init restarts the service, launching `/data/voboost/voboost-inject`
  (which a core apply may have repointed to a new binary)

### Requirement: Init-hook re-arm (operator-invoked)
After a system OTA the guarded init-hook block SHALL be restored by an
operator-invoked re-arm step so the daemon is launched again at boot. The re-arm
step is provided by this change as `make device-rearm HOOK=<path>` and is executed
via `adb` by the operator; it is not automatic.

Degradation risk: if a system OTA also wipes `/data` (non-standard but possible),
the daemon binary and agents are lost; recovery requires re-provisioning from the
APK.

`make device-rearm` appends a guarded shell-style launch block (`exec
/data/voboost/voboost-inject`) to `HOOK`. The exact on-device init mechanism that
sources this block (an init.d-style shell hook vs an Android init `.rc` `service`
definition) is device-specific and is the open question tracked below; the re-arm
step restores the launch of the stable path, and the restart-on-exit service
definition itself is set up by initial device provisioning (out of scope).

#### Scenario: Re-arm after OTA
- **WHEN** the init hook is missing following a system OTA
- **THEN** the operator runs `make device-rearm HOOK=<path>` via adb, the guarded
  hook block is restored, and the daemon launches on the next boot

#### Scenario: Re-arm is idempotent
- **WHEN** the re-arm step is run on a hook that already contains the guarded
  block
- **THEN** the step exits successfully without modifying the hook

### Requirement: Independence from system OTA cadence
The incremental app/agents OTA SHALL operate independently of the system OTA;
neither blocks or requires the other.

#### Scenario: App update without a system OTA
- **WHEN** an incremental app/agents update is applied
- **THEN** it proceeds without any system OTA, and a system OTA does not trigger
  an app/agents re-download
