## MODIFIED Requirements

### Requirement: Ptrace injection via libinjector

The daemon SHALL inject by calling `libinjector`'s flat C-ABI entry
`vbi_inject(pid, so_path, init_sym, config_path)` (see `native-payload`),
opening no socket and driving no frida device. It SHALL pass the matching-ABI
`libimplant.so` path as `so_path`, `"implant_init"` as `init_sym`, and the
target's channel-B config file path (see "Opaque config delivery to agents")
as `config_path` — NOT a reused copy of `so_path`. The injector SHALL write
`config_path` into the target's memory and pass its address as
`implant_init`'s `cfg` argument. The daemon SHALL NOT link `libimplant.so` or
any LSPlant/Dobby symbol; its only native seam is the `extern "C"` call to
`libinjector`. The `vbi_inject` return value (ok / denied / target-gone /
dlopen-failed / init-failed) SHALL be surfaced to device-safety for
rate-limit and quarantine accounting.

#### Scenario: Daemon injects through the injector

- **WHEN** the daemon needs to inject an agent set into a target
- **THEN** it calls `vbi_inject(pid, libimplant_<abi>.so, "implant_init",
  <channel-B config path>)`, opening no socket and using no frida

#### Scenario: Injection failure is accounted by safety

- **WHEN** `vbi_inject` returns a non-ok code (denied / target-gone /
  dlopen-failed / init-failed)
- **THEN** the daemon records the outcome for the target and feeds it to the
  device-safety rate-limit and quarantine logic, and does not treat it as a
  successful injection

#### Scenario: implant_init receives the config path, not the .so path

- **WHEN** the injector calls `implant_init(cfg)` after resolving it via
  `__loader_dlsym`
- **THEN** `cfg` points at the channel-B config file path passed as
  `config_path`, not at the `.so` path used to `dlopen` the implant
