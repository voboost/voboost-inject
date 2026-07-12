## ADDED Requirements

### Requirement: Emulator embedded-backend frida via page-size fix

The frida-gum embedded local backend SHALL NOT abort the daemon on an Android
emulator due to a zero-length `mmap`. `gum_query_page_size()` SHALL NEVER
return 0: it lazily (re-)queries the backend and falls back to a 4 KiB page,
so `(1 + n_pages) * page_size` and the `size==0` allocation guards can never
collapse to a `mmap(NULL, 0)`. The patch SHALL be persisted via
`subprojects/frida-gum.wrap` `diff_files` so clean clones apply it.

The daemon SHALL NOT special-case emulators: the `is_emulator()` DEGRADED
escape hatch is removed, so on an emulator the daemon opens the embedded
frida-core local device exactly as on a real device. `DaemonState.DEGRADED`
remains reachable only via verify_self failure, frida-open failure, and plan
rejections. The `gum_query_page_size` fix is a no-op once the page-size cache
is initialized, so it does not affect real devices or `frida-server`.

#### Scenario: Emulator opens frida
- **WHEN** the daemon starts on an Android emulator (`ro.kernel.qemu=1`)
- **THEN** it opens the embedded frida-core local device without a
  `gum_alloc_n_pages` abort and reaches READY with spawn-gating enabled (the
  `page_size == 0` / uninitialised-heap abort is gone). Target agent delivery
  on the emulator is a separate Linjector/BPF concern and is not asserted here.

#### Scenario: Production device
- **WHEN** the daemon starts on a production device (real hardware)
- **THEN** frida opens normally and the `gum_query_page_size` fix is a no-op
  (the page-size cache is already set), unchanged from before the fix

#### Scenario: frida device cannot be opened
- **WHEN** the embedded frida-core local device fails to open (on any host)
- **THEN** the daemon transitions to DEGRADED and injects nothing (the
  non-emulator DEGRADED path is unchanged)
