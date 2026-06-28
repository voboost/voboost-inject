## MODIFIED Requirements

### Requirement: Release-only meson build
The project SHALL build with meson in release configuration only (`buildtype=release`), with
frida-core statically linked into the daemon binary (so there is no separate frida shared library
on disk — design D10a), LTO (`b_lto=true`), and strip (`install_strip`). These SHALL be set in the
project `default_options` and the executable target's frida-core dependency wiring so no manual
flag is required. There SHALL be no debug build configuration. The full `-static` (static-libc)
link SHALL be applied only to the Android device (cross) build, so `make build-android` yields a
self-contained device binary, while the host build (`make build`) stays linkable for tests. The
Android device build links every bundled subproject (frida-core, glib, gio, json-glib, monocypher,
…) statically via the global `default_library=static` (set in the root `default_options`), and links
the bionic system libs (libc, liblog, libz, libm, libdl) dynamically — NDK r29 ships no static
bionic, and bionic is always present on Android. The daemon's `frida-core:connectivity` feature
(TLS/ICE) SHALL be disabled in the Android build (the daemon is local-backend-only: no socket, no
TLS, no ICE — see `frida_controller.vala`); this avoids pulling in the unused `gioopenssl`/
`glib-networking`/`nice`/`usrsctp` stack. frida's meson fork does not auto-derive `--pkg` flags
from `dependencies:` the way upstream meson does, so the executable's `vala_args` SHALL name
`--pkg=gio-2.0` and `--pkg=json-glib-1.0` explicitly (frida-core does the same in its own
`meson.build`). Tests are host-only: the root `meson.build` SHALL skip `subdir('test')` in a cross
build.

#### Scenario: Host build for tests
- **WHEN** `make build` runs on the host (no cross-file)
- **THEN** it produces a release, LTO'd binary with frida-core statically
  linked, links dynamically against host libs, and offers no debug build
  target. Strip is an install-time step (`meson install --strip`), not a
  `make build` step: `make build` leaves the symbol table in place (host
  tests need it); only the installed release artifact is stripped. `make setup`
  configures via frida-meson (not the system meson) so frida-core's
  `compat/build.py` (run during ninja) can load the `coredata.dat` it wrote.

#### Scenario: Device build is self-contained
- **WHEN** `make build-android` runs with the Android cross-file
- **THEN** it produces an arm64-v8a binary with the frida/glib stack statically
  linked (no glib/gio/json-glib on the device) and bionic dynamically linked,
  with `frida-core:connectivity=disabled`, and nothing to provision on the
  device (ed25519 verify is the Monocypher subproject — design D9d)

#### Scenario: Device build disables unused connectivity
- **WHEN** `make build-android` configures the cross build
- **THEN** it passes `-Dfrida-core:connectivity=disabled` (the daemon is
  local-backend-only; TLS/ICE is unused), and `default_library=static` is set
  globally so every transitive subproject builds a static archive

#### Scenario: Vala packages are named explicitly
- **WHEN** the daemon's Vala sources are compiled
- **THEN** `vala_args` includes `--pkg=gio-2.0` and `--pkg=json-glib-1.0`
  (frida's meson fork does not auto-derive `--pkg` from `dependencies:`)

#### Scenario: Tests are skipped in a cross build
- **WHEN** `make build-android` configures the cross build
- **THEN** `subdir('test')` is guarded by `not meson.is_cross_build()` (tests
  are host-only; no test runner on the device)
