## Context

`voboost-inject` is open source and self-distributed; releases must be reproducible and signed
without exposing the private key. This change stands up the complete CI/CD pipeline and lands
**after `inject`** in the sequence `init → inject → ci → ota`. Because it lands after `inject`, a
real daemon target and a real signed manifest already exist — so unlike an early scaffolding
pipeline, this one builds and signs real artifacts from the start. It consumes `init` (it runs the
same `make init` developers run) and `inject` (daemon target, manifest contract, committed public
key, project version), and it produces the signed artifacts `ota` consumes. It merges what were two
earlier draft stages (a push/PR scaffold and a separate release pipeline) into one pipeline.

## Goals / Non-Goals

**Goals:**
- Every push/PR: provision via `make init`, lint, test, and build release-only; any failure fails
  the pipeline; no debug job.
- Cache the `make init` result (installed tools incl. the source-built vala-lint, and the frida
  `subprojects/` checkout) so it is restored, not rebuilt, each run.
- A semver version in `meson.build` (single source of truth), baseline `1.0.0-beta1`, with a
  manually bumped pre-release postfix so successive signed builds are distinguishable.
- On release/tag: build the daemon release-only, sign the real manifest with the ed25519 CI-secret
  key, verify with the committed public key, and publish artifacts grouped by channel.

**Non-Goals:**
- The toolchain/linters/frida-wrap definition and `make init` itself (owned by `init`).
- The daemon build target, the manifest data contract, the embedded trust anchor, and the
  `meson.build` version value (owned by `inject`; this change only consumes and bumps it).
- The per-agent manifest (`manifest.json`) signing — owned by the app build pipeline
  (`ru.voboost`); this CI signs only the OTA `release-manifest.json`.
- The OTA release manifest schema and `make release-manifest` target (owned by `ota`); this change
  calls `make release-manifest` and signs its output, but does not define the manifest format or
  generation logic. The delta/apply mechanics and client diff/fetch remain `ota`'s concern.
- An automated version-bump policy beyond the manual postfix (deferred until close to `1.0.0`).

## Decisions

### D1. Provision via `make init`, cache its result
The pipeline provisions the runner by calling **`make init`** — the same command developers run —
so the CI environment is identical to local: same toolchain, the same `io.elementary.vala-lint`
built from the same pinned revision, the same frida-patched `valac`, and the same pinned frida wrap.
To avoid rebuilding the source-built tools and re-fetching frida on every run, CI **caches the
result of `make init`**: the project-local tools prefix (`.tools/`, holding vala-lint and the
frida-patched `valac`) and the fetched `subprojects/` checkout are saved and restored keyed on the
pinned revisions; a cache miss reinstalls/rebuilds the same pinned revisions.
*Alternative rejected:* a bespoke CI-only install script — it would drift from the local `make init`
and reintroduce the "works locally, not in CI" gap.

### D2. Push/PR: lint, test, release-only build; no debug job
On push/PR the pipeline runs `make lint` and `make test`, then builds release-only on the host
(`make build`: release, LTO; dynamically linked, unstripped — strip is install-time per
`inject/build-and-signing`), consistent with the release-only invariant. There is no debug build
job. Any failed step fails the pipeline. The release job uses `make build-android` (arm64-v8a
cross-compilation via `config/android-cross.ini` from `init`), then `llvm-strip`s the binary, for the
published artifact; push/PR builds use `make build` (host) for validation. Because `ci.yml` and
`release.yml` are independent workflows that both fire on a tag push, the release workflow also
re-runs `make lint` and `make test` before building — a tag cannot bypass the quality gates and
publish a red commit.

### D3. Semver in `meson.build`, manual pre-release postfix
The canonical version lives in the `project()` `version` field of `meson.build` (single source of
truth), baseline `1.0.0-beta1` (set by `inject`). During early development the pre-release postfix is
bumped by hand per release (`1.0.0-beta1` → `1.0.0-beta2` → … → `1.0.0-rc1` → `1.0.0`), keeping
successive signed builds distinguishable. The release tag matches the `meson.build` version exactly.
*Alternative rejected:* deriving the version from `git describe` — unnecessary complexity for the
early-development cadence and harder to audit than an explicit committed value.

### D4. Sign the OTA release manifest from CI secrets
On a release/tag the pipeline builds the daemon release-only and signs the OTA release manifest
(`build/release-manifest.json`, whose schema is defined by the `ota` change) with the ed25519
private key from CI secrets. Signing this single manifest transitively authenticates every listed
file via its in-manifest sha256 (the OTA trust model). The private key is never committed and never
printed; a `trap` ensures it is removed from the temp file even if a subsequent step fails; the
committed public key verifies the result. Non-release push/PR builds do not require the key.
*Alternative rejected:* signing locally and uploading — would spread the private key beyond CI.

**Prerequisite:** `config/release-public.pem` must be committed before the first release. A
maintainer generates a release ed25519 keypair, commits the public half, and stores the private
half as the CI secret `SIGNING_KEY`. For beta1 the dev keypair may be reused.

### D5. Generate, sign, and stage the release artifacts
`ci` first stages only the intended release artifact(s) into a clean directory (`dist/`) — copying
them out of the meson build tree so the manifest generator never scans build noise (`build.ninja`,
`meson-info/`, object files, subproject artefacts). The OTA release manifest
(`build/release-manifest.json`, whose schema is defined by the `ota` change) is then generated by
calling `make release-manifest DIR=<clean-staging-dir> CHANNEL=<core|agents|app> VERSION=<v>` — a
target owned by `ota` that scans the clean staging directory and writes the unsigned manifest with
per-file sha256/size/version, labelling every file with the given channel. For this repository's
release the single artifact is the device binary (`build-android/voboost-inject`) staged at
`dist/voboost-inject` under channel `core`, so the call is `make release-manifest DIR=dist
CHANNEL=core VERSION=<v>`. `ci` then signs that file with the CI-secret key and verifies it (D4). The
signed device binary, the signed manifest, and its detached signature are staged as release artifacts
(a workflow-run artifact). Durable publication/hosting for the OTA fetch transport is deferred (Open
Questions); this step proves the build+sign pipeline and hands the artifacts off. The manifest's
`channel` field (`agents`, `core`, `app`) groups files logically; no directory-per-channel layout is
required. Nothing is staged if any earlier step fails.

## Risks / Trade-offs

- [A leaked CI secret would expose the signing key] → least-privilege secret scope, only on
  protected release workflows, never echoed; rotate on suspicion.
- [Stale `make init` cache yields wrong tool versions] → the cache key includes the pinned
  frida and vala-lint revisions; bumping a pin invalidates the cache and triggers a rebuild.
- [Forgetting to bump the postfix yields two builds with the same version] → the release checklist
  requires bumping the `meson.build` postfix before tagging; tag and version must match.
- [Cross-compiling for the Android target in CI] → the release workflow provisions the Android NDK
  (pinned LTS, via `nttld/setup-ndk`); `make build-android` cross-compiles via
  `config/android-cross.ini`. `make init` does not provision the NDK (external prerequisite).
- [The release workflow calls `make release-manifest`, owned by the `ota` change] → this is an
  intentional forward dependency in the `init → inject → ci → ota` sequence: `ci` owns the signing
  target (`make sign`/`verify-sig`), versioning, caching, stripping, staging, and the publish
  scaffolding — all complete — while `ota` (task 1.2, planned next) defines the manifest schema and
  implements the `make release-manifest` generator. Until `ota` lands, a release tag fails at the
  manifest-generation step by design; `ci`'s own deliverables are complete and verified in isolation
  (lint, test, build, sign/verify round-trip, version gate). This mirrors how `inject` (archived)
  produces artifacts that only become consumable once `ota` ships.

## Migration Plan

Implementation order: add the push/PR workflow (provision via `make init` + cache, lint, test,
release-only build) → set up the `make init` result cache keyed on the pinned revisions → add the
release/tag workflow (the version already lives in `meson.build` from `inject`; bump the postfix per
release) that builds the daemon release-only, stages the device binary into a clean `dist/`, calls
`make release-manifest DIR=dist CHANNEL=core VERSION=<v>` (owned by `ota`) to generate the unsigned
`build/release-manifest.json`, signs it with the CI-secret key, verifies with the committed public
key, and stages the signed binary + manifest + `.sig` as a workflow-run artifact (durable hosting
deferred). Then `ota` consumes the artifacts. Each subsequent release bumps the pre-release postfix
in `meson.build` and tags to match.

## Open Questions

- Runner OS is `ubuntu-latest`; the Android NDK is provisioned in the release workflow via
  `nttld/setup-ndk` (pinned LTS), not by `make init`.
- The exact policy for graduating the postfix (`betaN` → `rc` → `1.0.0`) as the project stabilizes.
- Where published release artifacts are hosted/served for the OTA client (transport is out of scope
  for `ota` too; CI just publishes).
