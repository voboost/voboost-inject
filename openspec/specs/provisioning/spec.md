## Purpose
Specify requirements for environment provisioning, toolchain checks, and Android cross-compilation.
## Requirements
### Requirement: Documented build toolchain including both linters

The project SHALL document the complete toolchain required to build, lint, and
test: the Rust toolchain (`cargo`/`rustup`, pinned via `rust-toolchain.toml`),
Android NDK r29, `uncrustify` (C/C++ lint), `git`, and `openssl` (ed25519 key
generation) — with versions or minimums. `io.elementary.vala-lint` is no longer
required (there is no Vala source).

#### Scenario: Developer reads the toolchain list

- **WHEN** a developer opens the developer docs
- **THEN** they find the complete list of required tools: the Rust toolchain,
  NDK r29, `uncrustify`, `git`, and `openssl`, with versions or minimums, and
  no mention of Vala or vala-lint

### Requirement: Deterministic tool installation via make init

`make init` SHALL provision the environment deterministically: install the
OS-package tools (including `uncrustify`), install the Rust toolchain from the
pinned `rust-toolchain.toml`, verify that NDK r29 is available
(`ANDROID_NDK_HOME` set and the toolchain bin found), generate the local dev
keypair, and prepend the install prefix's `bin` to `PATH`. It SHALL NOT fetch
frida wraps, build a frida-patched `valac`, build `io.elementary.vala-lint`, or
run `meson setup` (those were frida/meson-specific and are removed). It SHALL
work identically on a developer machine and in CI.

#### Scenario: Fresh clone is provisioned

- **WHEN** a developer runs `make init` on a clean clone
- **THEN** the OS-package tools and `uncrustify` are installed, the Rust
  toolchain is installed from `rust-toolchain.toml`, NDK r29 is verified, and
  a dev keypair exists

#### Scenario: NDK r29 verified

- **WHEN** `make init` runs
- **THEN** it verifies `ANDROID_NDK_HOME` points at an NDK whose major version
  is 29, and fails early with a clear message if it is not set or the version
  is wrong

#### Scenario: vala-lint has no OS package

- **WHEN** the build moved off the frida/meson/Vala toolchain
- **THEN** `make init` no longer builds `io.elementary.vala-lint` from source
  (the Vala linter is removed with the Vala stack); linting is `cargo clippy`/
  `cargo fmt` for Rust and `uncrustify` for C/C++ (see `quality-gates`)

#### Scenario: Provisioned tools resolve without profile edits

- **WHEN** any `make` target that needs a provisioned tool runs after `make init`
- **THEN** the tool resolves via the Makefile-prepended prefix `bin` on `PATH`,
  with no manual shell-profile setup

### Requirement: Per-OS installation instructions

The developer documentation SHALL include installation guidance for macOS
(Homebrew), Linux (apt), and Windows (WSL2). Each platform section SHALL be
sufficient to provision all required tools (the Rust toolchain, NDK r29,
`uncrustify`, `openssl`), and SHALL state that `make init` automates the
OS-package install and Rust toolchain setup.

#### Scenario: Developer installs on macOS

- **WHEN** a developer follows the macOS instructions
- **THEN** Homebrew provides the OS packages and `rustup` installs the Rust
  toolchain, and `make init` verifies NDK r29

#### Scenario: Developer installs on Linux

- **WHEN** a developer follows the Linux (Ubuntu/Debian) instructions
- **THEN** apt provides the OS-package tools and the Rust toolchain is
  installed via `rustup`

#### Scenario: Developer installs on Windows

- **WHEN** a developer follows the Windows instructions
- **THEN** they learn that WSL2 + Ubuntu is recommended and can follow the
  Linux path inside it

### Requirement: Toolchain check reports any missing tool

`make check` SHALL verify that every required tool is present — including
`cargo` (the Rust toolchain), `uncrustify`, and NDK r29 — and SHALL report any
missing tool by name with a non-zero exit, rather than failing opaquely later
during lint or build.

#### Scenario: A linter is missing

- **WHEN** `make check` runs and `cargo` (or `uncrustify`, or NDK r29) is
  absent
- **THEN** it reports that tool by name and exits non-zero

#### Scenario: All tools present

- **WHEN** `make check` runs and every required tool is present
- **THEN** it reports success and the environment is ready to build, lint, and
  test

### Requirement: Local dev keypair with verification always on

`make key-dev` SHALL generate a personal ed25519 dev keypair (idempotently).
The public key is for a local build to bake in (via `build.rs` — see
`build-and-signing`); the private key SHALL be gitignored. Signature
verification SHALL always be enabled — there SHALL be no skip-verify mode in
any build.

#### Scenario: Developer generates a keypair

- **WHEN** a developer runs `make key-dev` with no existing key
- **THEN** an ed25519 keypair is generated, the private key is gitignored, and
  the public key is available for the daemon `build.rs` to bake into a local
  build

#### Scenario: No skip-verify mode exists

- **WHEN** any build (dev or release) runs
- **THEN** signature and hash verification are enforced and cannot be disabled

### Requirement: Android cross-compilation via meson cross-file

The project SHALL cross-compile for Android via `cargo-ndk` (the daemon,
targeting `aarch64-linux-android`) and NDK r29 `ndk-build`/CMake (the native
artifacts — see `build-and-signing`). `make build-android` SHALL invoke these
to produce a device binary and the per-ABI native artifacts. The Android NDK
(version r29) is an external prerequisite documented in the README and verified
by `make init`; `ANDROID_NDK_HOME` SHALL be set so the toolchain resolves.
There is no meson cross-file.

#### Scenario: Developer cross-compiles for the device

- **WHEN** a developer runs `make build-android` with `ANDROID_NDK_HOME` set to
  a valid NDK r29
- **THEN** it produces the daemon ELF (aarch64) and the per-ABI native
  artifacts for the target device

#### Scenario: Host build remains the default

- **WHEN** a developer runs `make build` without any cross configuration
- **THEN** it produces a host binary (for running tests locally)

### Requirement: Device zone provisioning

The device root zone SHALL be `/data/voboost-inject/` (not `/data/voboost`),
provisioned with the subdirectories the daemon and its consumers require:
`logs/` (the log sink), `run/` (the kill-switch file location — see
`device-safety`), `shared/` (the channel-B watched-file directory, labeled
`media_rw_data_file` via `file_contexts` — see `selinux-domain`,
`update-planes`), and `payload/` (the native payload files the daemon verifies
and hands to the injector — see `trust-verification`, `native-payload`). The
zone and its subdirectories SHALL be owned by root with permissions that allow
the daemon to read and write. Provisioning SHALL create the directories and
apply the correct SELinux labels (the `shared/` label is load-bearing: without
`media_rw_data_file`, the injected process cannot read channel-B files without
extra SELinux allow rules — see `selinux-domain`).

#### Scenario: Zone is provisioned on the device

- **WHEN** the device is provisioned
- **THEN** `/data/voboost-inject/` exists with `logs/`, `run/`, `shared/`, and
  `payload/` subdirectories, owned by root

#### Scenario: Shared dir is media_rw_data_file

- **WHEN** the `shared/` directory is provisioned
- **THEN** it is labeled `media_rw_data_file` via `file_contexts` so the
  injected process can read channel-B files without extra SELinux allow rules

### Requirement: Init hook for boot trigger

The daemon SHALL be installed as an Android init service triggered
`on nonencrypted` (with a fallback `on boot`), so it starts before
`system_server` rises and can reconcile/inject early (see `daemon-lifecycle`).
The service SHALL be configured `oneshot` + `disabled` as a reboot-loop guard:
a crashing daemon does not enter an infinite restart loop that would exhaust
init's restart budget. The self-update restart behavior (init restarting the
daemon after a clean self-shutdown) is owned by `ota` and is not affected by
this provisioning-time guard.

#### Scenario: Daemon starts on nonencrypted

- **WHEN** the device boots past the `on nonencrypted` trigger
- **THEN** the daemon service starts before `system_server` rises

#### Scenario: Crashing daemon does not loop

- **WHEN** the daemon crashes repeatedly on boot
- **THEN** the `oneshot` + `disabled` configuration prevents an infinite
  restart loop

