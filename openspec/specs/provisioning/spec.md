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
