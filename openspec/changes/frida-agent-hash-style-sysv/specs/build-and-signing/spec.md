## ADDED Requirements

### Requirement: Android frida-agent .so keeps a Bionic-loadable hash table

The Android cross-build of the frida agent SHALL link the raw agent with
`-Wl,--hash-style=sysv` so the final `frida-agent-64.so` (after frida-core's
`post_process` runs `termux-elf-cleaner`) retains a `DT_HASH` section the Bionic
linker can resolve symbols from at `dlopen`. The NDK default (`--hash-style=gnu`)
emits only `.gnu.hash`, which termux-elf-cleaner strips, leaving a hashless .so
that Bionic rejects with `empty/missing DT_HASH/DT_GNU_HASH`. The patch SHALL be
persisted via `subprojects/frida-core.wrap` `diff_files` so clean clones apply it.

#### Scenario: Final agent carries DT_HASH
- **WHEN** `make build-android` produces the embedded `frida-agent-64.so`
- **THEN** `llvm-readelf -d` on it lists `DT_HASH` (the cleaner stripped any
  `.gnu.hash` but left the SysV `.hash`)

#### Scenario: Target injection loads the agent
- **WHEN** the daemon injects an agent into a spawned/attached target on an
  Android emulator (API 28)
- **THEN** `dlopen` of the agent succeeds (no `empty/missing DT_HASH/DT_GNU_HASH`),
  the agent loads, and `inject-status.json` reports `state: active`

#### Scenario: Patch applies after the libc-shim patch
- **WHEN** a clean clone fetches frida-core and applies the wrap `diff_files`
- **THEN** the `--hash-style=sysv` patch applies after the libc-shim patch
  (both touch the Android `if host_os == 'android'` block in
  `lib/agent/meson.build`) and the build configures without conflict
