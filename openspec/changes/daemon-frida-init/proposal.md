## Why

`voboost-inject` never called `Frida.init()` — confirmed by
`git log -S "Frida.init" -- src/` returning nothing (absent since the
initial `feat: frida-core root daemon` commit). `Frida.init()` (Vala binding
for C `frida_init()` in `subprojects/frida-core/src/frida-glue.c`) runs the
one-time `gum_init()` (full frida-gum heap: page-size cache, cloak's
`GumMetalArray`s, the dlmalloc mspaces) plus `_frida_init_asset_paths()`,
guarded by `g_once`.

Without it, the embedded local backend reaches frida-gum subsystems before
`gum_internal_heap_ref ()` has run. On a production device this was masked
(the kernel tolerates the half-initialised state in the paths exercised), but
on an Android emulator it manifested as the daemon SIGABRT/SIGSEGV on
`frida.open ()` / `enable_spawn_gating ()` / `attach ()`, plus two
`GLib-CRITICAL ... g_hash_table_insert_internal: assertion 'hash_table != NULL'
failed` warnings at startup (a frida-core hash table used before init).

The `emulator-frida-page-size-fix` change patched `gum_query_page_size ()` to
lazily call `gum_internal_heap_ref ()`, which stopped the abort and the
SIGSEGV but left the frida-core subsystems uninitialised (the GLib-CRITICAL
warnings persisted, and injection into a target still failed). Calling
`Frida.init ()` is the real root-cause fix: it runs the full, idempotent
`gum_init ()` plus frida-core asset init before any frida object is created, so
the frida-gum patch becomes a defence-in-depth no-op rather than the primary
fix.

## What Changes

- **`src/main.vala`**: call `Frida.init ()` once at the very start of
  `main ()`, immediately after `Log.init ()` and before `new Daemon (...)`,
  so `gum_init ()` runs before any frida object (DeviceManager, device, etc.)
  is constructed.
- The `emulator-frida-page-size-fix` frida-gum patch stays as
  defence-in-depth (harmless no-op once `gum_init ()` has set the cache), but
  the daemon now works on an emulator *without relying on it*.

## Impact

- **Emulator:** the daemon no longer aborts on `frida.open ()`, the two
  `GLib-CRITICAL` startup warnings disappear, and `daemon_state` reaches
  `ready` with spawn-gating functional. (Target injection itself is a separate
  frida-Linjector/BPF concern on API 28, out of scope for this change.)
- **Production devices:** `Frida.init ()` is `g_once`-idempotent and was the
  intended entry point all along; calling it explicitly removes the latent
  half-initialised state that real hardware happened to tolerate. No behaviour
  change beyond correct initialisation.
- **frida-gum patch:** remains in place but is no longer load-bearing on this
  code path.
