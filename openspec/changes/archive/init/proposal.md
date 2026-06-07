## Why

<!-- Design date: 2026-06-08. Ordering: init → inject → ci → ota (init is first). -->

`voboost-inject` is open source and self-distributed. A fresh clone must become buildable and
lintable without access to the original author's machine — and it must do so *deterministically*,
because some required tools are not available as OS packages. In particular `vala-lint`
(`io.elementary.vala-lint`) has **no Homebrew and no apt package**: it can only be built from
source. If provisioning is not made explicit and automatic, `make lint` fails with
`command not found` and the project is stuck — "no vala-lint is fine in dev" is **not** acceptable.

This change stands up the complete developer environment as a single first stage, `init`: it
provisions the pinned frida sources and the full toolchain (including both linters), generates a
local dev keypair, and establishes the Makefile entrypoint, the quality gates (lint/format/test),
and the developer docs. It merges what were previously two separate stages (`setup` and `quality`)
into one, so that after `make init` a developer — or CI — has everything needed to build, lint, and
test, with nothing left implicit.

`init` comes first in the sequence `init → inject → ci → ota`. `inject` writes the daemon source
against the gates `init` establishes; `ci` runs `make init`, `make lint`, `make test`, and the
release build; `ota` consumes the signed artifacts `ci` produces.

## What Changes

- **Single `make init` entrypoint that provisions everything**: as the first step it installs the
  OS-package tools (Vala, meson, ninja, git, openssl, bsdiff, **uncrustify**, plus the libs
  vala-lint needs) and builds **`io.elementary.vala-lint` from a pinned git revision** into the
  install prefix; then runs `meson setup` (fetching the pinned frida wraps into `subprojects/`);
  then generates the dev keypair. One command takes a clean clone to a ready environment,
  identically locally and in CI. There is no separate `make install-tools` step.
- **Pinned frida git wraps**: `subprojects/{frida,frida-core,frida-gum}.wrap` (wrap-git) pinned to a
  fixed tag, fetched and cached into `subprojects/` by `meson setup`; no hardcoded local path.
- **Toolchain documented and fully checkable**: `make check` verifies every required tool
  by name — including **both** `uncrustify` **and** `io.elementary.vala-lint` — and reports any
  missing one with a non-zero exit, rather than failing opaquely later. Per-OS install guidance
  (macOS Homebrew, Linux apt, Windows WSL2).
- **Makefile as the only entrypoint**: targets `init`, `setup`, `build`, `lint`, `lint-fix`,
  `test`, `check`, `key-dev`. No `scripts/` directory.
- **Quality gates, enforced**: `vala-lint` enforces the hard 100-character line cap and inherited
  style rules (English source, single trailing newline, no commented-out code); `uncrustify`
  enforces formatting (braces on all control-flow bodies, 4-space indent, spaces-not-tabs).
  `make lint` runs both, **first verifying the linters are present and pointing the developer to
  `make init` if not** — never a bare `command not found`. `make lint-fix` applies `uncrustify`
  in-place.
- **Host-side test harness**: a `meson test` target in `test/`, silent on success and loud on
  failure, ready for `inject`/`ota` to add real cases and for `ci` to run.
- **Local dev keypair, verify always on**: `make key-dev` generates a personal ed25519 keypair; the
  public half is baked into a local build by `inject`. Private keys are gitignored. There is no
  skip-verify mode in any build.
- **Android cross-compilation**: `config/android-cross.ini` (meson cross-file for arm64-v8a via
  Android NDK) and `make build-android` target. `make build` remains a host build for tests.
- **Developer docs**: a `README.md` taking a fresh clone all the way to a built binary (explicitly
  via `make init`), and a concise, token-economical `AGENTS.md` carrying durable repo rules.

## Capabilities

### New Capabilities
- `provisioning`: the pinned frida wraps, the documented+checkable toolchain, the deterministic
  `make init` that installs both linters (uncrustify via OS package, vala-lint built from a pinned
  git revision), and the local dev keypair with verification always on.
- `quality-gates`: the Makefile entrypoint, `vala-lint` + `uncrustify` configuration and the
  100-char cap, `make lint` (with a present-linters guard) / `make lint-fix`, and the host-side
  `meson test` harness that is silent on success.
- `developer-docs`: the `README.md` (fresh clone → built binary, via `make init`) and the concise
  `AGENTS.md`.

### Modified Capabilities
<!-- Greenfield project: no existing specs in openspec/specs/. None modified. -->

## Impact

- **New project** `voboost/voboost-inject`: establishes the entire developer environment and quality
  gates as the first stage, before any daemon code is written.
- **inject change**: writes `src/*.vala` against these gates from the first commit; consumes the
  pinned frida wrap and the dev public key; sets the project version (`1.0.0-beta1`).
- **ci change**: runs `make init`, `make lint`, `make test`, and the release build; **caches the
  result of `make init`** (installed tools incl. the source-built vala-lint, and the `subprojects/`
  frida checkout) so it is restored from cache rather than rebuilt every run.
- **ota change**: indirectly depends, via `ci`, on the environment established here.
- **Dependencies**: Homebrew/apt for OS-package tools; `git`/`meson`/`ninja` to build vala-lint from
  source; ed25519 (openssl) and bsdiff tooling; GitHub Actions consumes the same `make init`.
