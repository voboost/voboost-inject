## MODIFIED Requirements

### Requirement: frida-core QuickJS subproject from the provisioned wrap
The build SHALL produce frida-core as a meson subproject built from the pinned git wrap provisioned
by the `init` change (no hardcoded local path) and statically linked into the daemon, with the
subproject options pinned explicitly rather than left to frida defaults:
`frida-gum:v8=disabled` (gum's `v8` option defaults to `auto` with a v8 wrap available, so
QuickJS-only must be pinned, not assumed; QuickJS stays enabled by gum's default),
`frida-core:default_library=static`, `frida-core:frida_version` supplied (the wrap checkout has no
`releng` submodule to compute it), only the local backend enabled, frida-core's bundled
tools/tests disabled, and `frida-core:compat=auto` so frida's 32-bit helper
(`frida-helper-32`) and the armv7 `frida-agent.so` are linked into the daemon ELF — the target
device runs a mix of 64-bit and 32-bit (armv7) processes, and the daemon must be able to inject
into the 32-bit ones (see `32bit-target-support`). Configuring the subproject SHALL use the
frida-patched Vala compiler (`valac` version suffix `-frida`, provisioned by `make init` — see
provisioning) and meson >= 1.1.0 (frida-core's floor); the root `meson.build` SHALL declare that
`meson_version` floor. Dependency wiring SHALL be an explicit `subproject('frida-core')` plus
`dependency('frida-core-1.0', static: true)` resolved via frida-core's `meson.override_dependency`.

#### Scenario: frida-core is built
- **WHEN** the daemon is built
- **THEN** frida-core is compiled from the provisioned `subprojects/` wrap with the QuickJS engine
  and V8 disabled, and linked statically

#### Scenario: 32-bit helper is built into the device binary
- **WHEN** `make build-android` runs the Android cross build
- **THEN** the daemon ELF embeds frida's 32-bit helper (`frida-helper-32` and the armv7
  `frida-agent.so`) because `frida-core:compat=auto`, and the daemon can inject into 32-bit
  (armv7) target processes on a mixed-ABI device

#### Scenario: Toolchain is the patched valac
- **WHEN** `meson setup` configures the build after `make init`
- **THEN** the Vala compiler in use reports a `-frida` version suffix and the frida-core
  subproject configures successfully
