## ADDED Requirements

### Requirement: Host-testable boot-completion state

The daemon SHALL implement its boot-completion check (the monotonic cache of
`sys.boot_completed`, the `getprop` fork, and the
`VOBOOST_BOOT_COMPLETED` host-test escape hatch) in a frida-free module
(`BootState`) so it can be unit-tested on a host without linking frida-core.
The `Supervisor` SHALL delegate its `boot_completed()` call to a `BootState`
instance. The behavior SHALL be unchanged: the escape hatch is checked first
(so host tests never fork `getprop`), a positive result is cached monotonically
(never forks again), and a negative result re-polls on the next call.

Context: the boot logic previously lived inside `Supervisor`, which depends on
`FridaController` (frida-core). The host test harness cannot link frida-core
(no device), so the INJ-02 monotonic-cache fix had no host integration test
(R4-X-02). Extracting the frida-free logic is the only way to test it on host.

#### Scenario: Host test with the escape hatch set
- **WHEN** `VOBOOST_BOOT_COMPLETED=1` is in the environment
- **THEN** `BootState.boot_completed()` returns true without forking `getprop`
- **AND** the result is cached: a second call returns true even after the
  env var is cleared

#### Scenario: Host test with an empty environment
- **WHEN** `VOBOOST_BOOT_COMPLETED` is unset and `getprop` is unavailable
  (non-Android host)
- **THEN** `BootState.boot_completed()` returns false without throwing or
  blocking, and re-polls on the next call (a negative result is not cached)
