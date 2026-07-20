## Why

With the frida-gum heap initialisation fixed (`emulator-frida-page-size-fix` +
`daemon-frida-init`), the daemon opens frida and reaches READY on the Android
emulator, but injecting an agent into a target failed at `dlopen`:

```
frida: attach <pid> failed: dlopen failed: empty/missing DT_HASH/DT_GNU_HASH
  in "/memfd:frida-agent-64.so (deleted)" (new hash type from the future?)
```

`llvm-readelf -d` on the build outputs showed the chain: `libfrida-agent-raw.so`
and `libfrida-agent-modulated.so` carry `DT_GNU_HASH`, but the final
`frida-agent.so` / embedded `frida-agent-64.so` have **no** hash entry at all.
The drop happens in frida-core's `tools/post-process.py`, which runs
`termux-elf-cleaner --api-level 21` on the agent for old-Android compatibility.
termux-elf-cleaner strips `.gnu.hash` (which some old Android linkers mishandle)
but preserves `.hash` (SysV `DT_HASH`). The NDK r29 default is `--hash-style=gnu`
(only `.gnu.hash`), so after the cleaner runs the agent is left hashless. The
API 28 Bionic linker needs a hash table to resolve the agent's symbols at
`dlopen`, so it rejects the hashless ELF and injection fails. (A real device's
newer linker also wants a hash table — this is not emulator-specific — but the
crash was only reached once the earlier init-order aborts were fixed.)

## What Changes

- **frida-core patch (persisted via wrap `diff_files`):** in
  `lib/agent/meson.build`, add `-Wl,--hash-style=sysv` to the Android agent
  link args, so the raw agent emits a SysV `.hash` (DT_HASH) instead of the
  default `.gnu.hash`. termux-elf-cleaner leaves `.hash` in place, so the final
  agent .so keeps a hash table and the Bionic linker can resolve symbols.
- Persisted at `subprojects/packagefiles/frida-core-android-agent-link-args.patch`
  and wired into `subprojects/frida-core.wrap` `diff_files`.

## Impact

- **Emulator injection:** target agent delivery now succeeds — the agent loads
  and runs in the spawned/attached process (`inject-status.json` reports
  `state: active`, daemon log shows `frida: loaded <agent>`).
- **Production devices:** no behaviour change. A real device's linker accepts
  `DT_HASH` (the older format) just as well as `DT_GNU_HASH`; the agent simply
  uses the SysV hash table. The symbol set and export script are unchanged.
- **Build:** the agent .so is marginally larger (SysV `.hash` is less compact
  than `.gnu.hash`), which is negligible for an embedded asset.
