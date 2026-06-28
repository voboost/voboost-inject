## Purpose
Specify requirements for environment provisioning, toolchain checks, and Android cross-compilation.
## Requirements
### Requirement: Pinned frida git wrap
The project SHALL provide `subprojects/{frida,frida-core,frida-gum}.wrap` as `wrap-git` entries
pinned to a fixed frida tag/commit, fetched and cached into `subprojects/` by `meson setup`, with no
hardcoded local path and no offline override.

#### Scenario: First meson setup fetches the pinned sources
- **WHEN** `meson setup` runs on a fresh clone
- **THEN** it fetches the pinned frida sources into `subprojects/` and caches them for reuse

#### Scenario: Subsequent setup reuses the cache
- **WHEN** `meson setup` runs again with the sources already fetched
- **THEN** it reuses the cached checkout without re-fetching

### Requirement: Documented build toolchain including both linters
The project SHALL document the complete toolchain required to build, lint, and test: a Vala
compiler, meson, ninja, git, openssl (ed25519), bsdiff, an Android cross toolchain/NDK,
**`uncrustify`**, and **`io.elementary.vala-lint`** — with versions or minimums.

#### Scenario: Developer reads the toolchain list
- **WHEN** a developer opens the developer docs
- **THEN** they find the complete list of required tools, explicitly including both `uncrustify` and
  `io.elementary.vala-lint`, with versions or minimums

### Requirement: Deterministic tool installation via make init
`make init` SHALL provision the environment deterministically: install the OS-package tools
(including `uncrustify` and the libraries `vala-lint` needs), build `io.elementary.vala-lint` from a
pinned git revision into the install prefix, fetch the pinned wraps up front
(`meson subprojects download`), build the frida-patched Vala compiler
(`valac` version suffix `-frida`) into the same install prefix from its
transitively-pinned revision — the `[vala]` entry of
frida's `releng` `deps.toml` at the releng commit recorded by the pinned frida-core checkout
(`git ls-tree HEAD releng`), so bumping the frida pin updates the valac pin with no second
hand-maintained number — then run `meson setup`, and generate the local dev keypair. The Makefile
SHALL prepend the install prefix's `bin` to `PATH` so the provisioned tools (vala-lint, forked
valac) are found by every `make` target without shell-profile edits. It SHALL work identically on a
developer machine and in CI.

#### Scenario: Fresh clone is provisioned
- **WHEN** a developer runs `make init` on a clean clone
- **THEN** the OS-package tools and `uncrustify` are installed, `io.elementary.vala-lint` and the
  frida-patched `valac` are built from their pinned revisions into the prefix, the pinned wraps are
  fetched, and a dev keypair exists

#### Scenario: vala-lint has no OS package
- **WHEN** provisioning runs on a system where `io.elementary.vala-lint` is not available via
  Homebrew or apt
- **THEN** `make init` builds it from the pinned git revision rather than assuming a package exists

#### Scenario: Provisioned tools resolve without profile edits
- **WHEN** any `make` target that needs a provisioned tool runs after `make init`
- **THEN** the tool resolves via the Makefile-prepended prefix `bin` on `PATH`, with no manual
  shell-profile setup

### Requirement: Per-OS installation instructions
The developer documentation SHALL include installation guidance for macOS (Homebrew), Linux (apt),
and Windows (WSL2). Each platform section SHALL be sufficient to provision all required tools, and
SHALL state that `make init` automates the OS-package install plus the vala-lint source build.

#### Scenario: Developer installs on macOS
- **WHEN** a developer follows the macOS instructions
- **THEN** Homebrew provides Vala, meson, ninja, bsdiff, uncrustify, and vala-lint's libraries, and
  `make init` builds `io.elementary.vala-lint` from source

#### Scenario: Developer installs on Linux
- **WHEN** a developer follows the Linux (Ubuntu/Debian) instructions
- **THEN** apt provides the OS-package tools and `make init` builds `io.elementary.vala-lint` from
  source

#### Scenario: Developer installs on Windows
- **WHEN** a developer follows the Windows instructions
- **THEN** they learn that WSL2 + Ubuntu is recommended and can follow the Linux path inside it

### Requirement: Toolchain check reports any missing tool
`make check` SHALL verify that every required tool is present — including both
`uncrustify` and `io.elementary.vala-lint` — and SHALL report any missing tool by name with a
non-zero exit, rather than failing opaquely later during lint or build.

#### Scenario: A linter is missing
- **WHEN** `make check` runs and `io.elementary.vala-lint` (or `uncrustify`) is absent
- **THEN** it reports that tool by name and exits non-zero

#### Scenario: All tools present
- **WHEN** `make check` runs and every required tool, both linters included, is present
- **THEN** it reports success and the environment is ready to build, lint, and test

### Requirement: Local dev keypair with verification always on
`make key-dev` SHALL generate a personal ed25519 dev keypair (idempotently). The public key is for a
local build to bake in; the private key SHALL be gitignored. Signature verification SHALL always be
enabled — there SHALL be no skip-verify mode in any build.

#### Scenario: Developer generates a keypair
- **WHEN** a developer runs `make key-dev` with no existing key
- **THEN** an ed25519 keypair is generated, the private key is gitignored, and the public key is
  available for `inject` to bake into a local build

#### Scenario: No skip-verify mode exists
- **WHEN** any build (dev or release) runs
- **THEN** signature and hash verification are enforced and cannot be disabled

### Requirement: Android cross-compilation via meson cross-file
The project SHALL provide `config/android-cross.ini`, a meson cross-file targeting
`aarch64-linux-android` (arm64-v8a) via the Android NDK. `make build-android` SHALL invoke meson
with this cross-file to produce a device binary. The cross-file SHALL be committed; the Android NDK
itself is an external prerequisite documented in the README.

#### Scenario: Developer cross-compiles for the device
- **WHEN** a developer runs `make build-android` with a working Android NDK
- **THEN** it produces an arm64-v8a binary for the target device

#### Scenario: Host build remains the default
- **WHEN** a developer runs `make build` without any cross-file
- **THEN** it produces a host binary (for running tests locally)

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

