## ADDED Requirements

### Requirement: 32-bit target process support
The daemon SHALL be able to inject its agents into **32-bit (armv7)** target processes on a
mixed-ABI device, not only into 64-bit (arm64) ones. On the target head-unit most system services
run as 32-bit processes (vehicle settings, system service, IME, bluetooth phone, media,
keymanager), so the majority of agents are routed at 32-bit targets; a daemon that can only reach
64-bit processes is not viable on-device. This capability is delivered at build time by the
`frida-core:compat=auto` option (see `build-and-signing`), which embeds frida's 32-bit helper
(`frida-helper-32`) and the armv7 `frida-agent.so` in the daemon ELF. At runtime the existing
`device.attach(pid)` / spawn-gating / `create_script` path is used unchanged — frida selects the
matching-ABI helper per target process automatically once the helper is present in the binary.

#### Scenario: 32-bit target is injected
- **WHEN** the daemon injects an agent into a 32-bit (armv7) target process on the device
- **THEN** the agent reaches `state: active` (not `state: failed` with
  `Unable to handle 32-bit processes`), because the daemon binary carries frida's 32-bit helper

#### Scenario: 64-bit target is unaffected
- **WHEN** the daemon injects an agent into a 64-bit (arm64) target process
- **THEN** injection behaves exactly as before this capability — the 32-bit helper is present in
  the binary but is not used for a 64-bit target

#### Scenario: Build without the 32-bit helper cannot inject into 32-bit targets
- **WHEN** the daemon is built with `frida-core:compat=disabled` (the 32-bit helper omitted) and
  attempts to inject into a 32-bit target process on the device
- **THEN** the injection fails with `Unable to handle 32-bit processes due to build configuration`,
  because the binary carries no 32-bit helper (this is the failure mode this capability removes)
