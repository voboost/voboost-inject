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
self-contained device binary, while the host build (`make build`) stays linkable for tests.

#### Scenario: Host build for tests
- **WHEN** `make build` runs on the host (no cross-file)
- **THEN** it produces a release, LTO'd binary with frida-core statically
  linked, links dynamically against host libs, and offers no debug build
  target. Strip is an install-time step (`meson install --strip`), not a
  `make build` step: `make build` leaves the symbol table in place (host
  tests need it); only the installed release artifact is stripped.

#### Scenario: Device build is self-contained
- **WHEN** `make build-android` runs with the Android cross-file
- **THEN** it produces a fully static (`-static`) arm64-v8a binary with no
  system crypto library and nothing to provision on the device (frida-core
  bundles glib/gio/json-glib; ed25519 verify is the Monocypher subproject
  — design D9d)

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
