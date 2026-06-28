## Why

The build does not work end-to-end from a clean clone. Two independent groups of
defects block it; this change fixes both.

### A. `make init` aborts at `meson subprojects download` (clean clone)

`ERROR: wrap-redirect subprojects/frida-core/subprojects/usrsctp.wrap filename
does not exist`. Two causes:

1. Seven `[wrap-redirect]` wraps (`usrsctp`, `libgee`, `libnice`, `libsoup`,
   `libpsl`, `quickjs`, `tinycc`) point at bundled wraps inside `frida-core/`,
   `frida-gum/`, `libsoup/`. Meson resolves every redirect eagerly while loading
   the wrap set (before any download), so the command fails until those target
   subprojects are already fetched. The redirects are also redundant: transitive
   deps resolve from each subproject's own bundled wraps during `meson setup`.
2. `monocypher.wrap` declares `patch_directory = monocypher`, but the patch is not
   in git and `subprojects/.gitignore` excludes `packagefiles/` contents.

### B. `make build-android` (arm64 cross-build) fails past subsystem

Three causes, found by peeling the onion (each fix verified by re-running setup):

1. `config/android-cross.ini [host_machine]` has no `subsystem`. frida-core's
   `meson.build` calls `host_machine.subsystem()` and branches on
   `host_os == 'android'`; for a cross machine `subsystem` is read only from the
   cross-file, so meson raises `Subsystem not defined or could not be
   autodetected`.
2. frida-gum's `quickcompile` (`native: true` build tool) needs QuickJS built for
   the **build** machine. Standard meson 1.11.1 builds the quickjs subproject
   once (host) and does not re-invoke it for the build machine; only frida's own
   meson fork (`github.com/frida/meson`, pinned by `frida-core`'s `releng/meson`
   submodule) does (`Executing subproject quickjs for machine: build`). frida's
   `releng` defaults to this internal meson; `make init` does not provision it.
3. `config/android-cross.ini [binaries]` has no `readelf`; for a non-darwin host
   (`android`→`linux` family) frida-core does `find_program('readelf')`, absent
   on macOS.

## What Changes

- **A.** Remove the seven `[wrap-redirect]` wraps; commit the monocypher patch at
  `subprojects/packagefiles/monocypher/meson.build`; fix `subprojects/.gitignore`
  (`!packagefiles/**`).
- **B.** In `config/android-cross.ini`: add `subsystem = 'android'` to
  `[host_machine]` and `readelf = 'llvm-readelf'` to `[binaries]` (the NDK ships
  `llvm-readelf` and is already required on PATH for the cross-compiler).
- **B.** `make init` SHALL provision frida's meson (the `frida/meson` commit pinned
  by the fetched `frida-core`'s `releng/meson` submodule, alongside the existing
  frida-valac provisioning) and `make build-android` SHALL configure via that
  meson (not the system meson).

## Capabilities

### Modified Capabilities
- `provisioning`: `subprojects/` wraps are clean-clone bootstrappable (direct git
  wraps only; every `patch_directory` committed under `packagefiles/`); and
  `make init` provisions frida's meson alongside frida-valac.
- `build-and-signing`: the Android cross-build SHALL configure with frida's meson
  and a cross-file that sets `subsystem = 'android'` and a `readelf` binary.

### New Capabilities
None.

## Impact

- **This repo**: `make init` and `make build-android` work from a clean clone
  (meson setup reaches 195 targets, exit 0, on macOS with NDK r27). No
  source/runtime behavior change; same pinned revisions.
- **Build/CI**: the CI `provision` + `release` steps must install frida's meson
  (the README's "frida-patched toolchain" includes meson — this makes `make init`
  match that). On linux CI `llvm-readelf` resolves via the NDK already on PATH.
- **Dependencies**: adds frida's meson fork as a provisioned build tool (no
  runtime dependency change).
