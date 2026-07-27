## 1. Injector C-ABI change

- [x] 1.1 Add `config_path` as a fourth parameter to `vbi_inject` in
  `injector/injector.h` and `injector/injector.c`.
- [x] 1.2 Write `config_path` into a new target-memory slot placed further
  below the stack pointer than the `.so` path (`str_addr - 4096`), not
  between the `.so` path and SP.
- [x] 1.3 Pass that slot's address (not the `.so` path's address) as
  `implant_init`'s `cfg` argument in the final remote-call.
- [x] 1.4 Fix the incidental `-Werror -Wunused-variable` build break in the
  32-bit register-read branch (`(void)gr` discard) uncovered while rebuilding
  the injector for this change.

## 2. Daemon-side plumbing

- [x] 2.1 Add `config_path: &str` to `daemon/src/injector.rs::inject()` and
  the `vbi_inject` FFI declaration.
- [x] 2.2 Update `daemon/src/main.rs`'s injection call site to pass
  `control_plane::config_file_for(process)` as the config path.

## 3. Gate the fix

- [x] 3.1 `cargo test` in `daemon/` — 27 tests pass, no regression.
- [x] 3.2 Rebuild `libinjector.a` (`make build-injector`) and the daemon
  (`make build-daemon`) from a clean state (this surfaced task 1.4).
- [x] 3.3 Verify end-to-end on `emulator-5554`: before the fix, agents logged
  `config file missing: <garbage>` (bug 1) then `configPath is empty` (bug 2,
  after the SP-relative placement mistake); after the fix, both
  `pedestrian-warning` and `settings-menu` log `started agent <id>` and read
  their real per-process config (`com-qinggan-systemservice-config.json` /
  `com-qinggan-app-vehiclesetting-config.json`).

## 4. Spec sync

- [x] 4.1 Update `injection-control`'s "Ptrace injection via libinjector" to
  document the 4-parameter `vbi_inject` signature.
- [x] 4.2 Update `native-payload`'s "Runtime ELF symbol resolution in the
  target" to document the `config_path` slot's safe placement.

## 5. Follow-up (explicitly deferred, not part of this change)

- [ ] 5.1 Bring `injector.c`'s `DBG` macro to the same leveled-logging
  convention as `daemon/src/log.rs` (`[*]`/`[+]`/`[-]`/`[#]`) and the Kotlin
  `Logger.kt` (`[-]`/`[+]`/`[*]`), instead of one compile-time verbose/silent
  toggle. Deferred at the requester's direction; recorded here and in
  `plans/2026-07-27-07-41-mvp-java-agents-handoff.md` so it isn't lost.
