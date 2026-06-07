# voboost-inject

Root injection component for Voboost: a single native Vala binary that embeds
frida-core (QuickJS, no V8), drives it in-process, runs as root, and injects
signed agents into target processes.

This repository is spec-driven. The source of truth for behavior lives under
`openspec/`. Implementation is staged across changes in the order
`init -> inject -> ci -> ota`. This document covers the developer environment
provisioned by the `init` change.

## Quick start (fresh clone)

```sh
make init     # provision the whole environment (see below)
make build    # build the binary (daemon targets land with the inject change)
```

`make init` runs three steps in order: installs the toolchain, runs setup,
then generates the dev keypair:

- **toolchain install** installs the OS-package tools and builds
  `io.elementary.vala-lint` from a pinned source revision (tag `0.1.0`). It has
  **no Homebrew and no apt package**, so it cannot be installed any other way.
  The build is installed into `$(HOME)/.local`; make sure `$(HOME)/.local/bin`
  is on your `PATH`.
- **setup** runs `meson setup build`, fetching the pinned frida sources into
  `subprojects/`.
- **key-dev** generates a local ed25519 dev keypair (private key gitignored).

## Toolchain

Required tools (all installed or built by `make init`):

- Vala compiler (`valac`)
- meson (>= 0.60.0)
- ninja
- git (fetches the pinned frida wraps; clones vala-lint)
- openssl (ed25519 dev keypair)
- bsdiff (OTA binary diffs)
- uncrustify (Vala formatter / `make lint` check)
- io.elementary.vala-lint (Vala linter; built from source, no OS package)
- Android cross toolchain / NDK for the target device

Verify everything is present:

```sh
make check
```

It reports each missing tool by name — including both `uncrustify` and
`io.elementary.vala-lint` — and exits non-zero if any is missing.

## Installing per OS

`make init` automates all installation: OS-package tools and the vala-lint source build.

**macOS** (Homebrew): `make init` runs
`brew install vala meson ninja bsdiff uncrustify json-glib glib pkg-config`,
then builds vala-lint from source.

**Linux** (Ubuntu/Debian): `make init` runs `apt-get` for the equivalent
packages (incl. `libvala-dev`, `libgee-0.8-dev`, `libjson-glib-dev`), then
builds vala-lint from source. The apt step uses `sudo`.

**Windows**: WSL2 + Ubuntu is recommended (the Android cross toolchain is
Linux-native). Install once in PowerShell (Admin):

```pwsh
wsl --install -d Ubuntu
```

Then follow the Linux path inside WSL2.

## Frida sources

Frida is provisioned from pinned git wraps in `subprojects/` (frida, frida-core,
frida-gum, all pinned to tag `17.11.0`). They are fetched and cached on
`make setup`; there is no hardcoded local source path.

## Lint, fix, test

```sh
make lint      # io.elementary.vala-lint + uncrustify --check (gate)
make lint-fix  # uncrustify --replace (canonical style in place)
make test      # meson test (host-side, silent on success)
```

`make lint` first checks that both linters are on `PATH`; if either is missing
it tells you to run `make init` instead of failing with `command not found`.

## Build

Builds are release-only (no debug configuration):

```sh
make build
```

The daemon build targets, the frida-core linkage, and the project version are
added by the `inject` change; until then `make setup` only provisions the
environment.

## Signing and verification

The private signing key is never committed. Production signing uses a key held
only in CI secrets; locally you use the dev keypair from `make key-dev`. The
public key is baked into the binary. Signature and hash verification is always
enabled — there is no mode that disables it.

## Android cross-compilation

The daemon runs on an Android device (arm64-v8a). A meson cross-file is
provided at `config/android-cross.ini`, targeting `aarch64-linux-android`
via the Android NDK.

```sh
# Host build (for local tests):
make build

# Device build (arm64-v8a, requires Android NDK):
make build-android
```

The NDK is an external prerequisite; set `ANDROID_NDK_HOME` to its path.
