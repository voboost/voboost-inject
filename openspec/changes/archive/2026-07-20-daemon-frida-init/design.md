# Design: daemon Frida.init ()

## D1. Deduction: Frida.init () was never called

FACT (`git log -S "Frida.init" -- src/`): empty — `Frida.init ()` has never
appeared in `src/`, since the initial daemon commit.

FACT (`subprojects/frida-core/src/frida.vala:3`): the binding declares
`public extern void init ();` and `subprojects/frida-core/src/frida-glue.c:25`
implements `frida_init () -> frida_init_with_runtime ()`, which is `g_once`
guarded and calls `gum_init ()` then `_frida_init_asset_paths ()`.

FACT: `src/frida_controller.vala` `open ()` constructs `new Frida.DeviceManager
()` and `get_device_by_type (LOCAL)` with no preceding `Frida.init ()`.

Therefore the embedded local backend has always run against an uninitialised
frida-gum heap. This is a DEDUCTION from recorded facts, not a premise.

## D2. Why production tolerated it

`gum_init ()` sets `gum_cached_page_size`, initialises cloak's `GumMetalArray`s
and the dlmalloc mspaces. On real Android hardware the kernel tolerates
`mmap (NULL, 0)` (undefined per POSIX but not rejected), and the
half-initialised frida-core hash tables happened not to be hit on the paths
exercised, so the daemon limped along. QEMU (the emulator) follows strict
POSIX and rejects `length == 0`, and the uninitialised hash table is hit on
the emulator's spawn-gating/attach path, so the latent bug fired there.

## D3. The fix: explicit Frida.init ()

`src/main.vala` `main ()`:

```vala
Log.init (...);
Frida.init ();
var loop = new MainLoop ();
var daemon = new Daemon (loop);
```

`Frida.init ()` runs `gum_init ()` (full heap) + `_frida_init_asset_paths ()`
once, before any frida object exists. `g_once` makes it idempotent, so a later
`frida_init` from inside frida-core (if any) is a no-op.

Verified on `emulator-5554` (API 28, arm64-v8a): after this call, the two
`GLib-CRITICAL` startup warnings disappear and `daemon_state` reaches `ready`
with spawn-gating enabled and no abort.

## D4. Relationship to the frida-gum page-size patch

The `emulator-frida-page-size-fix` change made `gum_query_page_size ()` lazily
call `gum_internal_heap_ref ()`. With `Frida.init ()` now running first,
`gum_cached_page_size` is already set by the time any code queries it, so the
lazy path is never taken — it is a pure no-op defence-in-depth. It is kept
(rather than reverted) because it is harmless and protects any future caller
that reaches `gum_query_page_size ()` before `Frida.init ()` (e.g. a static
ctor or a future frida-core build that defers init).

## D5. Follow-up: target injection (now fixed separately)

Correct init alone was not enough for target injection: the daemon then failed
at `dlopen failed: empty/missing DT_HASH/DT_GNU_HASH in "frida-agent-64.so"`.
That is a separate frida-core agent-build issue (termux-elf-cleaner strips the
NDK-default `.gnu.hash`, leaving a hashless .so), fixed by the
`frida-agent-hash-style-sysv` change — not by this change. With both, target
injection succeeds on the emulator (`state: active`).

## D6. Rejected alternatives

- **Rely only on the frida-gum patch (heap_ref lazy init):** stopped the abort
  but left frida-core uninitialised (GLib-CRITICAL persisted, injection
  failed). Insufficient.
- **Call `gum_init ()` directly from Vala:** not exported in the vapi;
  `Frida.init ()` is the public, intended entry point and also runs
  `_frida_init_asset_paths ()`.
- **Defer `Frida.init ()` into `FridaController.open ()`:** works, but `main ()`
  is the conventional single init site and runs strictly before any frida
  object construction, leaving no window for a half-initialised reach.
