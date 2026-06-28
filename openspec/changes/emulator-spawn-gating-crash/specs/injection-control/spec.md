## ADDED Requirements

### Requirement: Emulator spawn-gating escape hatch

The daemon SHALL provide a `VOBOOST_SKIP_SPAWN_GATING` environment-variable
escape hatch that, when set to `1`, skips the `enable_spawn_gating` call
entirely so the daemon survives in attach-only mode for emulator integration
testing. The escape hatch SHALL NOT be set on production devices. Skipping
spawn-gating SHALL NOT affect attach injection, which uses Linjector
(`inject_running` -> `linjector.inject_library_resource`), not Zymbiote.

Context: frida-core 17.11.0's embedded local-device `enable_spawn_gating`
SIGABRTs the daemon on Android API 28 arm64 emulators. The in-process
Zymbiote prep for zygote loads the `linker64` ELF module, which calls
`gum_metal_array_append` -> `gum_alloc_n_pages(GUM_PAGE_RW)` ->
`g_assert(result != NULL)` -> `abort()`. The abort is in C (frida-gum) and
cannot be caught by Vala `try/catch`, so the documented attach-only graceful
degradation (`enable_gating()` returning `false`) never runs — the process is
gone before the `yield` returns. The escape hatch mirrors the existing
`VOBOOST_BOOT_COMPLETED` test hatch: an emulator-only test affordance.
Production runs on real hardware where the frida-gum `g_assert` does not fire.
The root cause is a frida-gum design choice (OOM-is-fatal in the
metal-allocator); a real fix belongs upstream (a `gum_metal_array` try-variant
with `GError` propagation through `gum_elf_module_load`) and is tracked as
future work.

#### Scenario: Emulator with escape hatch set
- **WHEN** the daemon starts on an Android API 28 arm64 emulator with
  `VOBOOST_SKIP_SPAWN_GATING=1` in its environment
- **THEN** the supervisor skips `enable_spawn_gating`, logs "spawn-gating
  skipped (VOBOOST_SKIP_SPAWN_GATING=1); attach-only mode", reaches READY, and
  stays alive
- **AND** attach injection of running targets continues to work via Linjector

#### Scenario: Emulator without escape hatch
- **WHEN** the daemon starts on an Android API 28 arm64 emulator without
  `VOBOOST_SKIP_SPAWN_GATING` set
- **THEN** the daemon SIGABRTs at `enable_spawn_gating` (frida-gum
  `g_assert(result != NULL)` in `gum_alloc_n_pages`) before reaching READY

#### Scenario: Production device
- **WHEN** the daemon starts on a production device (real hardware)
- **THEN** `VOBOOST_SKIP_SPAWN_GATING` is not set, `enable_spawn_gating`
  succeeds, and spawn-gating operates normally (the frida-gum `g_assert` does
  not fire on real hardware)
