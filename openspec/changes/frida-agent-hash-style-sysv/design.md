# Design: frida-agent SysV hash style

## D1. Where the hash table disappears

FACT (`llvm-readelf -d` on the Android build outputs):
- `libfrida-agent-raw.so`: `SYMTAB`, `STRTAB`, `GNU_HASH` (present)
- `libfrida-agent-modulated.so`: `SYMTAB`, `STRTAB`, `GNU_HASH` (present)
- `frida-agent.so` (final) / embedded `frida-agent-64.so`: `SYMTAB`, `STRTAB`,
  **no hash entry**

So the `DT_GNU_HASH` is present through `modulate` (which only moves the
constructor/destructor) and is dropped by the final `post_process` step.

FACT (`subprojects/frida-core/lib/agent/meson.build`): the agent build chain is
`raw_agent` (shared_library) -> `modulated_agent` (custom_target, `modulate`) ->
`agent` (custom_target, `post_process`).

FACT (`subprojects/frida-core/tools/post-process.py:66`): for `host_os ==
'android'` it runs `termux-elf-cleaner --api-level 21 --quiet <so>`. termux-elf-cleaner
removes `.gnu.hash` (and `.gnu.version*`, build-id notes) for compatibility with
old Android linkers, but leaves the SysV `.hash` section.

## D2. Why the cleaned .so is hashless

The NDK r29 linker default is `--hash-style=gnu` (only `.gnu.hash`, no SysV
`.hash`). After termux-elf-cleaner strips `.gnu.hash`, nothing remains. The
Bionic linker needs a hash table to resolve the agent's exported symbol
(`_frida_agent_main` and the version-scripted exports) at `dlopen`; with none
present it fails with `empty/missing DT_HASH/DT_GNU_HASH (new hash type from
the future?)` and the daemon records the injection as failed.

## D3. The fix: emit a .hash the cleaner preserves

Adding `-Wl,--hash-style=sysv` to the Android agent link args makes the raw
agent emit only the SysV `.hash` (`DT_HASH`). termux-elf-cleaner does not touch
`.hash`, so it survives into the final `frida-agent-64.so`, and the Bionic
linker resolves symbols normally. Verified end to end on `emulator-5554`:
`DT_HASH` is present in the final agent and target injection succeeds
(`state: active`, `frida: loaded low-speed-sound`).

## D4. Why sysv, not both

`--hash-style=both` would emit `.hash` + `.gnu.hash`; the cleaner strips
`.gnu.hash` and leaves `.hash`, so `both` also works. `sysv` is chosen because
it is strictly what is needed (no `.gnu.hash` to generate and then strip) and
keeps the agent smallest. A real device's linker accepts `DT_HASH` (the older
format), so there is no compatibility cost on production hardware.

## D5. Patch is layered after the libc-shim patch

The existing `frida-core-libc-shim-opaque-file-bionic.patch` already adds an
Android `if host_os == 'android'` block to `lib/agent/meson.build` (the
`-Wl,-u,malloc` emutls fix). This change's patch adds the `--hash-style=sysv`
line inside that same block, so it is ordered after the libc-shim patch in
`diff_files` and applies cleanly on a fresh clone (validated: `git reset --hard
HEAD` -> apply libc-shim -> apply this -> both present).
