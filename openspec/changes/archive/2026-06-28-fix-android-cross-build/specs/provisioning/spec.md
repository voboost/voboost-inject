## MODIFIED Requirements

### Requirement: Subproject wraps are clean-clone bootstrappable
The wraps committed under `subprojects/` SHALL let `meson subprojects download` and
`meson setup` succeed on a clean clone with no manual pre-fetching. Only top-level
**direct**-dependency git wraps (for this project: `frida`, `frida-core`,
`frida-gum`, `monocypher`) SHALL be committed; a wrap SHALL NOT be a
`[wrap-redirect]` whose target lives inside another, not-yet-fetched subproject —
transitive dependencies resolve from each subproject's own bundled wraps during
`meson setup`. Any `patch_directory` referenced by a wrap SHALL be committed under
`subprojects/packagefiles/<name>/` and SHALL be git-tracked (not excluded by
`subprojects/.gitignore`). A top-level `subprojects/<name>.wrap` SHALL take
precedence over the wrap of the same name inside a fetched subproject (e.g.
`frida-core/subprojects/`), so the project can override a transitive subproject's
wrap with one carrying a `patch_directory` or `diff_files` (e.g. the committed
`subprojects/selinux.wrap` overrides frida-core's selinux wrap with a
`patch_directory = selinux` that fixes libselinux's missing libsepol dependency;
`subprojects/frida-core.wrap` carries a `diff_files` patch for bionic compat).

#### Scenario: No redirect wraps into not-yet-fetched subprojects
- **WHEN** the committed `subprojects/*.wrap` files are enumerated
- **THEN** every committed wrap is a `[wrap-git]` direct dependency, and none is a `[wrap-redirect]` pointing into a sibling subproject directory

#### Scenario: Wrap patch sources are committed and tracked
- **WHEN** a wrap declares `patch_directory = <name>` or `diff_files = <patch>`
- **THEN** the patch directory/file exists under `subprojects/packagefiles/` and is returned by `git ls-files` (tracked, not gitignored)

#### Scenario: Top-level wrap overrides a transitive subproject's wrap
- **WHEN** a top-level `subprojects/<name>.wrap` and a `subprojects/frida-core/subprojects/<name>.wrap` both exist
- **THEN** meson resolves the top-level one (it searches the root `subprojects/` first), applying its `patch_directory`/`diff_files`

#### Scenario: Clean clone provisions wraps without error
- **WHEN** `make init` runs `meson subprojects download` on a clean clone
- **THEN** the command exits 0, fetching the top-level wraps and applying their committed patches, with no `wrap-redirect … does not exist` and no `patch directory does not exist` error

### Requirement: make init provisions frida's meson for cross-builds
`make init` SHALL provision frida's meson (the `frida/meson` commit pinned by the
fetched `frida-core`'s `releng/meson` submodule), alongside the frida-patched
valac, because the Android cross-build (frida-gum's `quickcompile` `native: true`
tool) requires a `[provide]` subproject to be built for the build machine — only
frida's meson does this; standard meson does not. The provisioned frida-meson SHALL
be the meson used by `make setup` and `make build-android` (so the `coredata.dat`
is written by the same meson frida-core's `compat/build.py` imports during ninja).
After checking out the releng submodule, `make init` SHALL apply the committed
`subprojects/packagefiles/frida-meson-libcpp-hardening-mode.patch` to frida-meson's
`cpp.py` — frida-meson emits `-D_LIBCPP_ENABLE_ASSERTIONS=1` for clang 15-17, which
was removed in libc++ (LLVM 18+ / the macOS 26.2 SDK); the patch uses
`_LIBCPP_HARDENING_MODE` (supported since LLVM 15) unconditionally for clang >= 15.
`make setup` and `make build-android` SHALL launch frida-meson via `PYTHON_FOR_MESON`
(default `/usr/bin/python3`), which MUST still ship the stdlib `distutils` module
(removed in Python 3.12, PEP 0632) — glib's `gdbus-codegen` (a build-machine tool
run during ninja) imports `distutils.version.LooseVersion`.

#### Scenario: frida-meson is provisioned alongside frida-valac
- **WHEN** `make init` completes on a clean clone
- **THEN** frida's meson is available at the pinned `frida/meson` commit, and
  `make setup`/`make build-android` resolve and use it instead of the system meson

#### Scenario: frida-meson is patched for libc++ hardening
- **WHEN** `make init` checks out the `releng/meson` submodule
- **THEN** it applies `frida-meson-libcpp-hardening-mode.patch` so the build-machine
  C++ compile does not emit the removed `_LIBCPP_ENABLE_ASSERTIONS` macro

#### Scenario: frida-meson runs under a distutils-bearing python
- **WHEN** `make setup`/`make build-android` launches frida-meson
- **THEN** it uses `PYTHON_FOR_MESON` (default `/usr/bin/python3`), which ships
  `distutils` (glib's gdbus-codegen imports `distutils.version`)
