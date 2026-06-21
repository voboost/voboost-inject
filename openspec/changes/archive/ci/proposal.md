## Why

<!-- Design date: 2026-06-08. Ordering: init → inject → ci → ota. -->

`voboost-inject` is open source and self-distributed: releases must be built reproducibly and signed
without ever exposing the private key. This change stands up the **complete** CI/CD pipeline on
GitHub Actions and lands **after `inject`**, when a real daemon target and a real signed manifest
exist — so there is no scaffolding phase: the pipeline lints, tests, and builds on every push/PR,
and on a release/tag it versions, builds the real daemon release-only, signs the real manifest with
a key held only in CI secrets, and publishes the signed artifacts the `ota` change consumes.

It comes after `inject` (it needs the daemon target, the manifest contract, and the committed public
key) and before `ota` (which consumes the signed release artifacts this change produces).

## What Changes

- **GitHub Actions on push/PR**: provision the environment with **`make init`** (which installs the
  toolchain, builds `io.elementary.vala-lint` from its pinned source revision, builds the
  frida-patched `valac`, and fetches the pinned frida wrap — exactly as locally), run `make lint`
  and `make test`, and build the daemon **release-only** (static, LTO, strip). Any failed step fails
  the pipeline. No debug build job.
- **Cache the `make init` result**: the installed tools in the project-local `.tools/` prefix
  (notably the source-built `io.elementary.vala-lint` and the frida-patched `valac`) and the fetched
  `subprojects/` frida checkout are cached between runs and restored from cache, so the environment
  is not rebuilt every run. A cache miss reinstalls and rebuilds the same pinned revisions.
- **Semantic versioning**: the project carries a semver version in `meson.build`, baseline
  `1.0.0-beta1` (set by `inject`). During early development the pre-release postfix is bumped
  **manually** per release (`1.0.0-beta1` → `1.0.0-beta2` → … → `1.0.0-rc1` → `1.0.0`); the release
  tag matches the `meson.build` version exactly.
- **Real release build on release/tag**: CI cross-builds the `inject` daemon target for Android
  (`make build-android`, arm64-v8a, fully static) release-only.
- **Sign the OTA release manifest**: the OTA release manifest (`build/release-manifest.json`,
  whose schema is defined by the `ota` change) is signed with the ed25519 private key drawn from
  CI secrets; signing it transitively authenticates every listed file via its in-manifest sha256
  (the OTA trust model). The committed public key verifies the result. The private key is never
  committed and never printed. Non-release push/PR builds do not require it.
- **Stage signed artifacts**: the signed device binary (`build-android/voboost-inject`), the signed
  OTA release manifest (`build/release-manifest.json`), and its detached signature are staged as
  release artifacts (a workflow-run artifact). Durable publication/hosting for the OTA fetch
  transport is deferred (a design Open Question); this step proves the build+sign pipeline and hands
  the artifacts off. The manifest's `channel` field (`agents`, `core`, `app`) already groups files
  logically. Nothing is staged if any earlier step fails.

## Capabilities

### New Capabilities
- `ci-pipeline`: the GitHub Actions workflow — provision via `make init`, lint, test, release-only
  build on push/PR, with **caching of the `make init` result** (installed tools in `.tools/` incl.
  the source-built vala-lint and the frida-patched valac, and the frida `subprojects/` checkout);
  any failed step fails the pipeline; no debug job.
- `ci-versioning`: the project's semantic version (baseline `1.0.0-beta1`) in `meson.build` as the
  single source of truth; the pre-release postfix is bumped manually per release; the release tag
  matches the version.
- `ci-signing`: release-time signing of the OTA release manifest (defined by `ota`) with the
  ed25519 private key from CI secrets; private key never in the repo or logs, cleaned up via
  `trap` on failure; committed public key verifies; non-release builds do not sign.
- `ci-release`: staging the signed binary, the OTA release manifest, and its detached signature as
  release artifacts (a workflow-run artifact; durable hosting/transport deferred); nothing staged if
  any earlier step fails.

### Modified Capabilities
<!-- Greenfield project: no existing specs in openspec/specs/. None modified. -->

## Impact

- **Depends on `inject`**: requires the daemon build target, the real signed-manifest data contract,
  the committed public key, and the `meson.build` version (`1.0.0-beta1`).
- **Consumes `init`**: runs the same `make init` developers run, and caches its result.
- **Feeds `ota`**: produces the signed release artifacts (binary + signed manifest(s)) that the
  `ota` change's client diffs and consumes, grouped by channel.
- **Dependencies**: GitHub Actions; the Android NDK for the release cross-build (provisioned by the
  release workflow, not `make init`); a CI secret holding the ed25519 private key; ed25519 (openssl)
  in the runner (provisioned by `make init`). bsdiff is an `ota` concern (delta patching) and is not
  a CI dependency.
