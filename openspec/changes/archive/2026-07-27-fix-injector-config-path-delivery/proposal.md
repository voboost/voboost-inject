## Why

`vbi_inject(pid, so_path, init_sym)` never carried the channel-B config path
to the target. Instead it passed the address of the `.so` path string itself
as `implant_init`'s `cfg` argument — the code's own comment admitted this was
a placeholder ("For the initial port we pass the same so_path as cfg"). As a
result `AgentEntry.init(configPath)` always received either the `.so` path
(not a config file — `ClassNotFoundException`-style "config file missing"
errors) or, after a first attempted fix, an empty string (a second bug: the
new string slot was placed too close to SP and got clobbered by the
`__loader_dlopen`/`__loader_dlsym` remote calls' own stack usage before
`implant_init` ran). Neither agent (`pedestrian-warning`, `settings-menu`)
could ever read its config — this was never exercised end-to-end before this
change's emulator verification pass.

The existing `injection-control` spec already documents (elsewhere) that "the
daemon writes the per-process config file... and passes its path to
`implant_init`", but its own "Injector invocation contract" requirement
described `vbi_inject` with only 3 parameters (no config path) — the spec was
internally inconsistent, not just the code.

## What Changes

- `vbi_inject` gains a fourth parameter, `config_path`, written into a new
  memory slot in the target and passed as `implant_init`'s `cfg` argument
  (replacing the previous so_path-reused placeholder). **BREAKING** (C ABI):
  the `vbi_inject` signature changes; the sole caller (`daemon/src/injector.rs`)
  is updated in the same change.
- The daemon (`main.rs`) now passes the real channel-B config file path
  (`control_plane::config_file_for(process)`) to `injector::inject`, which
  forwards it to `vbi_inject`.
- The new config-path memory slot is placed on the same "far from SP" side as
  the `.so` path (not between the `.so` path and SP), so it survives the
  `__loader_dlopen`/`__loader_dlsym` remote calls that run before
  `implant_init` is invoked.
- Incidental build-hygiene fix surfaced while rebuilding the injector for this
  change: an unused-variable warning-as-error in the 32-bit register-read
  branch (only unused when the `VBI_DBG` trace macro is compiled out) broke a
  clean `arm64-v8a` build; fixed with an explicit `(void)` discard. No
  behavior change.

## Capabilities

### New Capabilities
(none)

### Modified Capabilities
- `injection-control`: "Injector invocation contract" now documents the
  4-parameter `vbi_inject(pid, so_path, init_sym, config_path)` signature and
  that `config_path` is the real channel-B file, not a reused `so_path`.
- `native-payload`: "Single implant entry point implant_init" is clarified to
  state that `cfg` arrives via the injector's dedicated `config_path` argument
  (not the `.so` path), and a new requirement documents the memory-safety
  constraint on where that string is written in the target's stack.

## Impact

- `injector/injector.h`, `injector/injector.c`: `vbi_inject` signature +
  implementation (new config-path memory slot, safe placement).
- `daemon/src/injector.rs`: FFI declaration + `inject()` signature gain
  `config_path`.
- `daemon/src/main.rs`: injection call site passes the real config path.
- No change to the manifest format, the channel-B file format, or the
  `AgentEntry.init` Java-side contract (`agent-entry-seam` is unaffected —
  it already specified `configPath` must be the channel-B path; this change
  makes the native layer actually deliver that, closing the gap between that
  spec and the code).
- Verified end-to-end on `emulator-5554`: both agents now log
  `started agent <id>` (previously `config file missing` / `configPath is
  empty`).
