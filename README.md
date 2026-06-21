# voboost-inject

Root injection component for Voboost: a single native Vala binary that embeds
frida-core (QuickJS, no V8), drives it in-process, runs as root, and injects
signed agents into target processes.

This repository is spec-driven. The source of truth for behavior lives under
`openspec/`. Implementation is staged across changes in the order
`init -> inject -> ci -> ota`. The `init`, `inject`, and `ci` changes are
implemented; the `ota` change is planned in `openspec/changes/`.

## Quick start (fresh clone)

```sh
make init     # provision the whole environment
make build    # build the daemon binary
make test     # host-side tests (device-free)
```

`make init` runs three steps in order: installs the toolchain, generates the
dev keypair, then runs setup:

- **toolchain install** installs the OS-package tools, builds
  `io.elementary.vala-lint` from a pinned source revision (tag `0.1.0`),
  builds the frida-patched `valac` (frida-core requires it), and fetches the
  frida subproject wraps. Tools are installed into `.tools/` (project-local,
  gitignored). The frida-patched valac is prepended to `PATH` via the Makefile.
- **key-dev** generates a local ed25519 dev keypair at
  `config/key-dev-private.pem` (gitignored) and `config/key-dev-public.pem`
  (committed). It runs before setup because `meson setup` bakes the public key
  into the binary via a custom_target.
- **setup** runs `meson setup build`.

## Project layout

```
src/                  Vala daemon source (11 modules + VAPI bindings)
test/                 Host-side unit tests + integration test plan
config/               Build configs (uncrustify, vala-lint, cross-file, dev keys)
openspec/specs/       Main specifications (13 specs)
openspec/changes/     OpenSpec changes (init, inject, ci archived; ota planned)
subprojects/          Pinned frida git wraps (fetched by make init)
.tools/               Built tools (frida-patched valac, vala-lint; gitignored)
```

## Toolchain

Required tools (all installed or built by `make init`):

- Vala compiler (`valac`) — the frida-patched build (version suffix `-frida`)
- meson (>= 1.1.0, frida-core's floor)
- ninja
- git (fetches pinned frida wraps; clones vala-lint)
- openssl (ed25519 dev keypair generation)
- bsdiff (OTA binary diffs, used by the `ota` change)
- uncrustify (Vala formatter / `make lint-fix`)
- io.elementary.vala-lint (Vala linter; built from source, no OS package)
- Android NDK for device cross-compilation

Verify everything is present:

```sh
make check
```

## Installing per OS

`make init` automates all installation: OS packages, vala-lint source build,
and frida-patched valac build.

**macOS** (Homebrew): `make init` runs
`brew install vala meson ninja bsdiff uncrustify json-glib glib pkg-config`,
then builds vala-lint and the frida-patched valac from source.

**Linux** (Ubuntu/Debian): `make init` runs `apt-get` for the equivalent
packages (incl. `libvala-dev`, `libgee-0.8-dev`, `libjson-glib-dev`), then
builds vala-lint and the frida-patched valac from source. The apt step uses
`sudo`.

**Windows**: WSL2 + Ubuntu is recommended (the Android cross toolchain is
Linux-native). Install once in PowerShell (Admin):

```pwsh
wsl --install -d Ubuntu
```

Then follow the Linux path inside WSL2.

## Frida sources

Frida is provisioned from pinned git wraps in `subprojects/` (frida, frida-core,
frida-gum, all pinned to tag `17.11.0`). They are fetched and cached on
`make init`; there is no hardcoded local source path.

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

The daemon links frida-core statically with LTO. Strip is applied at install
time (`meson install --strip`), not by `make build`, so the host build keeps
its symbol table for tests; the host build links dynamically against host
libs, while the Android device build is fully static (`-static`).

## Signing and verification

The private signing key is never committed. Production signing uses a key held
only in CI secrets; locally you use the dev keypair from `make key-dev`. The
public key (`config/key-dev-public.pem`) is baked into the binary at build time
via a meson `custom_target`. Signature and hash verification is always
enabled — there is no mode that disables it.

## Versioning

The project version lives in `meson.build` `project(version: ...)` (single source
of truth, baseline `1.0.0-beta1`, set by the `inject` change). CI consumes it and
never defines it elsewhere. During early development the pre-release postfix is
bumped manually before each release tag:

    1.0.0-beta1 -> 1.0.0-beta2 -> ... -> 1.0.0-rc1 -> 1.0.0

Steps for each release:

1. Edit `meson.build`: increment the postfix (e.g. `1.0.0-beta1` -> `1.0.0-beta2`).
2. Commit, then push the matching tag (e.g. `v1.0.0-beta2`).
3. The release workflow validates `v$version == $tag` and fails if they diverge.

## Release keys

The production signing public key is `config/release-public.pem`, committed by a
maintainer; the matching private key lives only in the CI secret `SIGNING_KEY`
and is never committed or printed. Generate a release keypair:

    openssl genpkey -algorithm ed25519 -out config/release-private.pem
    openssl pkey -in config/release-private.pem -pubout -out config/release-public.pem
    # store config/release-private.pem as the CI secret SIGNING_KEY, then delete it locally

For `beta1` the dev keypair (`config/key-dev-*`, from `make key-dev`) may be
reused as the release keypair — rotate before a real release.

## Android cross-compilation

The daemon runs on an Android device (arm64-v8a). A meson cross file is
provided at `config/android-cross.ini`, targeting `aarch64-linux-android`
via the Android NDK.

```sh
# Host build (for local tests):
make build

# Device build (arm64-v8a, requires Android NDK):
make build-android
```

The NDK is an external prerequisite; set `ANDROID_NDK_HOME` to its path.
