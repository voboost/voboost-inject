## Purpose
Specify build configuration, static linking, public-key embedding, frida-core subproject wiring,
and signing key management.
## Requirements
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

### Requirement: Project version baseline in meson.build
This change SHALL set the `project()` `version` in `meson.build` to the semver baseline
`1.0.0-beta1` as the single source of truth; on a successful build `make build` SHALL produce the
binary `voboost-inject`.

#### Scenario: Version baseline is set
- **WHEN** `meson.build` is examined after this change
- **THEN** its `project()` version is `1.0.0-beta1`

#### Scenario: make build produces the binary
- **WHEN** `make build` runs after `make init` on a provisioned clone
- **THEN** it produces the `voboost-inject` binary

### Requirement: Public key embedded via build-time generation
The public key SHALL be compiled into the binary by a meson `custom_target` that reads
`config/key-dev-public.pem` (locally) or the committed release public key (in CI) and emits a generated
Vala source carrying the raw ed25519 key bytes. The binary SHALL NOT read the public key from disk
at runtime.

#### Scenario: Build bakes the key
- **WHEN** the daemon is built
- **THEN** a `custom_target` generates the embedded-key source from the PEM, and the binary carries
  the raw key bytes with no runtime file dependency on the key

#### Scenario: Changing the key requires a rebuild
- **WHEN** the baked public key must change
- **THEN** it is changed by rebuilding with a different PEM, not by editing a runtime config or file

### Requirement: frida-core QuickJS subproject from the provisioned wrap
The build SHALL produce frida-core as a meson subproject built from the pinned git wrap provisioned
by the `init` change (no hardcoded local path) and statically linked into the daemon, with the
subproject options pinned explicitly rather than left to frida defaults:
`frida-gum:v8=disabled` (gum's `v8` option defaults to `auto` with a v8 wrap available, so
QuickJS-only must be pinned, not assumed; QuickJS stays enabled by gum's default),
`frida-core:default_library=static`, `frida-core:frida_version` supplied (the wrap checkout has no
`releng` submodule to compute it), only the local backend enabled, and frida-core's bundled
tools/tests/compat helpers disabled. Configuring the subproject SHALL use the frida-patched Vala
compiler (`valac` version suffix `-frida`, provisioned by `make init` — see provisioning) and
meson >= 1.1.0 (frida-core's floor); the root `meson.build` SHALL declare that `meson_version`
floor. Dependency wiring SHALL be an explicit `subproject('frida-core')` plus
`dependency('frida-core-1.0', static: true)` resolved via frida-core's `meson.override_dependency`.

#### Scenario: frida-core is built
- **WHEN** the daemon is built
- **THEN** frida-core is compiled from the provisioned `subprojects/` wrap with the QuickJS engine
  and V8 disabled, and linked statically

#### Scenario: Toolchain is the patched valac
- **WHEN** `meson setup` configures the build after `make init`
- **THEN** the Vala compiler in use reports a `-frida` version suffix and the frida-core
  subproject configures successfully

### Requirement: Private signing key never in the repository
The private signing key SHALL exist only in CI secrets (e.g. CI secret store / KMS) and SHALL NOT
be committed to the open-source repository. The corresponding public key SHALL be committed in
source and compiled into the binary.

#### Scenario: CI signs a release
- **WHEN** CI builds a release
- **THEN** it signs the manifest with the private key drawn from CI secrets,
  and the committed public key verifies it

#### Scenario: Repository is inspected
- **WHEN** the repository contents are examined
- **THEN** no private signing key is present; only the public key is committed

### Requirement: Local developer dev keypair
A local developer SHALL be able to build and run by generating a personal dev keypair, baking their
own public key into a local build, and signing their own test agents with it. Signature verification
SHALL always be enabled, including in dev builds — there SHALL be no mode that skips verification.

#### Scenario: Developer builds locally with a dev keypair
- **WHEN** a developer bakes their own dev public key into a local build
  and signs test agents with the matching private key
- **THEN** the local daemon verifies those agents normally and injects them

#### Scenario: No skip-verify mode exists
- **WHEN** any build (dev or release) runs
- **THEN** signature and hash verification are enforced and cannot be disabled

### Requirement: Android cross-build uses frida's meson and a complete cross-file
`make build-android` SHALL configure the arm64-v8a device build with frida's own
meson (the `frida/meson` commit pinned by the fetched `frida-core`'s `releng/meson`
submodule), not the system meson, because frida-gum's `quickcompile` (`native:
true`) requires its QuickJS subproject to be built for the build machine — only
frida's meson re-invokes a `[provide]` subproject for the build machine. The
cross-file `config/android-cross.ini` SHALL set `subsystem = 'android'` in
`[host_machine]` (frida-core derives `host_os` from `host_machine.subsystem()` and
gates Android on it) and SHALL name a `readelf` binary in `[binaries]` (frida-core
does `find_program('readelf')` for the non-darwin `host_os_family`; the NDK's
`llvm-readelf` is already on PATH for the cross-compiler). The NDK SHALL be r29 —
frida-core 17.11.0's releng requires exactly major version 29
(`releng/env_android.py NDK_REQUIRED=29`, checked when building the embedded
agent); r27/r27d are rejected with `NdkVersionError`. `make build-android` SHALL
derive the NDK toolchain PATH automatically from `ANDROID_NDK_HOME` (the glob
`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin`), so the cross-compiler and
LLVM tools resolve without the developer manually configuring PATH. It SHALL fail
early with a clear message if `ANDROID_NDK_HOME` is not set or the toolchain bin
is not found.

#### Scenario: Cross-file declares the Android subsystem
- **WHEN** `config/android-cross.ini` is examined
- **THEN** its `[host_machine]` sets `subsystem = 'android'`, and its `[binaries]`
  names a `readelf` (e.g. `llvm-readelf`)

#### Scenario: NDK version satisfies frida-core
- **WHEN** `make build-android` runs
- **THEN** `ANDROID_NDK_HOME` points at an NDK whose major version is 29 (the
  release workflow pins `ndk-version: r29`; r27/r27d fail the releng check)

#### Scenario: NDK toolchain PATH is derived automatically
- **WHEN** `make build-android` runs with `ANDROID_NDK_HOME` set to a valid NDK root
- **THEN** it derives the toolchain bin directory from
  `$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin`, adds it to PATH for the
  build, and the cross-compiler and LLVM tools resolve without requiring the
  developer to configure PATH manually

#### Scenario: Missing ANDROID_NDK_HOME fails early
- **WHEN** `make build-android` runs without `ANDROID_NDK_HOME`
- **THEN** it fails immediately with the message
  `build-android: ANDROID_NDK_HOME not set` (exit 1), before invoking meson

#### Scenario: Invalid NDK path fails early
- **WHEN** `make build-android` runs with `ANDROID_NDK_HOME` set to a path that
  has no `toolchains/llvm/prebuilt/*/bin`
- **THEN** it fails with `build-android: NDK toolchain not found` (exit 1), before
  invoking meson

