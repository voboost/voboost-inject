## ADDED Requirements

### Requirement: Daemon initialises frida-core before constructing any frida object

The daemon SHALL call `Frida.init ()` exactly once at process startup, before
any frida object (`Frida.DeviceManager`, device, session) is constructed. This
runs frida-core's `g_once`-guarded `gum_init ()` (which sets the page-size
cache, initialises cloak's `GumMetalArray`s, and creates the dlmalloc mspaces)
plus `_frida_init_asset_paths ()`, so the embedded local backend never reaches
frida-gum or frida-core subsystems in a half-initialised state.

#### Scenario: main() calls Frida.init () first
- **WHEN** the daemon process starts
- **THEN** `main ()` calls `Frida.init ()` after `Log.init ()` and before
  constructing the `Daemon` / `Supervisor` / `FridaController`

#### Scenario: No GLib-CRITICAL at startup on an emulator
- **WHEN** the daemon starts on an Android emulator (`ro.kernel.qemu=1`)
- **THEN** no `GLib-CRITICAL ... g_hash_table_insert_internal: assertion
  'hash_table != NULL'` warning is emitted at startup (frida-core hash tables
  are initialised before use)

#### Scenario: Frida.init () is idempotent
- **WHEN** `Frida.init ()` is called and frida-core later calls it again
  internally
- **THEN** the second call is a `g_once` no-op (no double-init, no leak)
