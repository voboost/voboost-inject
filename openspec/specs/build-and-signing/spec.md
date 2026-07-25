## Purpose
Specify build configuration, static linking, public-key embedding, frida-core subproject wiring,
and signing key management.
## Requirements
### Requirement: Project version baseline in meson.build

The project SHALL carry a semantic version in `Cargo.toml`
`[package].version` as the single source of truth, with the baseline value
`1.0.0-beta1`. CI SHALL consume this value and SHALL NOT define the version
elsewhere. On a successful build `make build` SHALL produce the binary
`voboost-inject`.

#### Scenario: Version baseline is set

- **WHEN** `Cargo.toml` is examined after this change
- **THEN** its `[package].version` is `1.0.0-beta1`

#### Scenario: make build produces the binary

- **WHEN** `make build` runs after `make init` on a provisioned clone
- **THEN** it produces the `voboost-inject` binary

### Requirement: Public key embedded via build-time generation

The public key SHALL be compiled into the binary by a Rust `build.rs` that
reads `config/key-dev-public.pem` (locally) or the committed release public key
(in CI) and emits a generated Rust source carrying the raw ed25519 key bytes.
The binary SHALL NOT read the public key from disk at runtime.

#### Scenario: Build bakes the key

- **WHEN** the daemon is built
- **THEN** a `build.rs` generates the embedded-key source from the PEM, and the
  binary carries the raw key bytes with no runtime file dependency on the key

#### Scenario: Changing the key requires a rebuild

- **WHEN** the baked public key must change
- **THEN** it is changed by rebuilding with a different PEM, not by editing a
  runtime config or file

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

### Requirement: Cargo + ndk-build/CMake mixed build

The project SHALL build via a top-level `Makefile` orchestrating two native
toolchains: the daemon crate (`daemon/`, Rust) via `cargo-ndk` targeting
`aarch64-linux-android` (API 28), and the native artifacts via NDK r29
`ndk-build`/CMake — `injector/` (C) producing `libinjector.a`, `implant/`
(C++) producing `libimplant.so` per ABI, and Dobby (C++) producing
`libdobby.a` per ABI. The daemon crate SHALL link `libinjector.a` (C, static)
via its `build.rs` FFI; it SHALL NOT link `libimplant.so` or any hooker symbol
(the daemon hands payload files by path — see `native-payload`). The Makefile
SHALL provide `build` (host, for tests), `build-daemon`, `build-native`,
`build-android` (all), `sign-elf`, `release-manifest`, `test`, `check`, and
`lint` targets. The `build-android` target SHALL derive the NDK toolchain PATH
from `ANDROID_NDK_HOME` (`$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/*/bin`)
and SHALL fail early with a clear message if `ANDROID_NDK_HOME` is not set or
the toolchain bin is not found. Tests SHALL be host-only (no test runner on the
device); the cross build SHALL skip test compilation.

#### Scenario: Device build produces all artifacts

- **WHEN** `make build-android` runs with `ANDROID_NDK_HOME` set to a valid
  NDK r29 root
- **THEN** it produces the daemon ELF (cargo-ndk, aarch64), the per-ABI
  `libimplant.so`, and the per-ABI `libdobby.a`, `liblsplant.so`,
  `liblsplt.so`

#### Scenario: Daemon links only the injector

- **WHEN** the daemon crate is built
- **THEN** its `build.rs` links `libinjector.a` (C, static) and declares the
  single `extern "C" fn vbi_inject(...)` seam; it does NOT link `libimplant.so`
  or any LSPlant/Dobby symbol

#### Scenario: Missing ANDROID_NDK_HOME fails early

- **WHEN** `make build-android` runs without `ANDROID_NDK_HOME`
- **THEN** it fails immediately with the message
  `build-android: ANDROID_NDK_HOME not set` (exit 1), before invoking any build

#### Scenario: Tests are host-only

- **WHEN** `make build-android` configures the cross build
- **THEN** test compilation is skipped (no test runner on the device)

### Requirement: Native payload toolchain constraints

The native artifacts (`libimplant.so`, LSPlant, Dobby) SHALL be built with NDK
r29 (Clang 21); NDK r27/r27d SHALL be rejected because LSPlant's C++23 modules
fail under r27. The C++ runtime SHALL be `c++_static` (the system
`libc++_shared.so` on Android 9 conflicts by ABI). The hooker SHALL be built
with `LOG_DISABLED` defined at directory scope via
`add_compile_definitions(LOG_DISABLED)` (not `target_compile_definitions`,
which does not reach BMI C++23 modules), and any unguarded
`__android_log_print` (e.g. in `jni_helper.hpp`) SHALL be wrapped in
`#ifndef LOG_DISABLED`. LSPlant SHALL be built from source using the committed
`lsplant.hpp` header (the Maven-published `InitInfo` ABI diverged — it is
missing `Allocator`/`Recycler` fields). Link-time optimization (`-flto`) SHALL
be disabled for the native artifacts.

#### Scenario: NDK r29 is required

- **WHEN** the native artifacts are built
- **THEN** the build uses NDK r29 (Clang 21); NDK r27 is rejected because
  LSPlant's C++23 modules do not build under it

#### Scenario: c++_static runtime

- **WHEN** the implant and hooker are linked
- **THEN** they use `c++_static`, not `c++_shared` (the system
  `libc++_shared.so` on Android 9 conflicts by ABI)

#### Scenario: LOG_DISABLED at directory scope

- **WHEN** the hooker is compiled
- **THEN** `LOG_DISABLED` is defined via `add_compile_definitions` at directory
  scope (reaching C++23-module BMIs), and unguarded `__android_log_print` is
      wrapped in `#ifndef LOG_DISABLED`

#### Scenario: lsplant.hpp from source

- **WHEN** LSPlant is built
- **THEN** it uses the committed source `lsplant.hpp`, not the Maven-published
  header (whose `InitInfo` ABI lacks `Allocator`/`Recycler`)

#### Scenario: LTO disabled

- **WHEN** the native artifacts are linked
- **THEN** `-flto` is not applied

### Requirement: Rust and C/C++ lint

The project SHALL lint Rust code with `cargo clippy` configured to deny
warnings, and SHALL lint C/C++ code with `uncrustify` (using the committed
config). `make lint` SHALL run both linters; `make check` SHALL verify that
every required tool (including `cargo`, `uncrustify`, and the NDK) is present
and report any missing tool by name with a non-zero exit. A lint failure SHALL
fail the build.

#### Scenario: Rust lint runs

- **WHEN** `make lint` runs
- **THEN** it invokes `cargo clippy` with warnings denied, and a clippy
  warning fails the lint step

#### Scenario: C/C++ lint runs

- **WHEN** `make lint` runs
- **THEN** it invokes `uncrustify` over the C/C++ sources, and a style
  violation fails the lint step

#### Scenario: Missing tool reported by name

- **WHEN** `make check` runs and a required tool (`cargo`, `uncrustify`, or the
  NDK) is absent
- **THEN** it reports that tool by name and exits non-zero

