## Why

<!-- Design date: 2026-06-07 (original). Rewritten 2026-06-24 to match the
     implemented inject + ci code and the finalized OTA model. Source plan:
     plans/2026-06-24/2026-06-24-18-28-code-review-ota-spec.md -->

Voboost is self-distributed (not via Play): one app distributes and updates
itself, and the Frida agents ship inside its APK. Re-downloading the whole
payload to change one script is wasteful over a car's connection. This change
designs **incremental OTA** so editing one agent downloads only that changed file
(kilobytes), and so the root daemon binary itself can be updated on-device
without a car reboot.

It also defines how verified material crosses the trust boundary into the root
daemon's trusted zone — the producer side of the `staging/` + `update-ready`
contract the implemented `inject` daemon already observes (and currently only
logs; this change adds the apply) — and how everything survives a system OTA.

## What Changes

- New **signed release manifest** (ed25519, detached, produced by this repo's CI
  via a new `make release-manifest`): per-file `sha256`/`size`/`version`,
  labelled with a change-frequency `channel`. This repo emits the `core` channel
  (the device binary); the voboost app repo emits `agents`/`app`. Distinct from
  the daemon's signed `manifest.json` (per-agent metadata, app-signed,
  daemon-verified against the embedded key) — design D1.
- **Incremental client diff (app-owned contract)**: the app keeps its current
  release manifest, fetches the new signed one, diffs by `sha256`, and downloads
  only changed files **whole** (agents are small; the core binary is large but
  rare). No binary diffing.
- **Verification of every fetched file** against the signed manifest's `sha256`;
  the manifest verified by the same key family; the daemon re-verifies staged
  material with its embedded key before trusting it (it never trusts the app's
  verification for the trusted zone).
- **Two update planes**:
  - **app+agents (frequent)**: agents + signed daemon manifest inside the APK.
    Applied **immediately** (atomic manifest swap + re-inject). Agent payloads are
    content-addressed (a changed agent ships at a new sha-derived path) so the
    manifest swap is the atomic unit; the `update-ready` marker is single-use
    (the daemon gates on it and consumes it after the apply).
  - **core (rare)**: the `voboost-inject` binary. The daemon verifies the staged
    binary against the daemon-re-verified release manifest, installs it under a
    content-addressed name, repoints the stable launch path, and performs a clean
    self-shutdown; Android init restarts the service, launching the **new**
    binary — **no car reboot**. On a degraded restart the daemon rolls back to the
    previous binary by the same mechanism.
- **System-OTA interaction**: a system OTA reverts only `/system` (the init hook);
  `/data/voboost`, the daemon, and agents survive. A new `make device-rearm`
  restores the init hook; nothing is re-downloaded.

Out of scope (owned elsewhere): the daemon's verification primitives and embedded
trust anchor (implemented by `inject`); the OTA client fetch/diff/download/
staging-writer (owned by the voboost app repo `ru.voboost`, which also produces
the `agents`/`app` channel manifests). This change defines the release-manifest
contract, the producer-side CI generator, the daemon-side apply/rollback, and the
post-system-OTA re-arm.

## Capabilities

### New Capabilities
- `release-manifest`: the signed release-manifest data contract — per-file
  sha256/size/version and the `agents`/`core`/`app` channels — its signature
  trust, and the CI `make release-manifest` generator.
- `incremental-delta`: the app-side client contract — keep current manifest,
  fetch the new signed manifest, download only changed files whole, per-file hash
  verification, size pre-check; the daemon re-verifies staged material.
- `update-planes`: the app+agents plane (immediate apply) and the core plane
  (no-reboot apply via content-addressed install + init restart), and the
  producer side of the `staging/` + `update-ready` contract.
- `atomic-apply-rollback`: atomic apply with rollback for both planes —
  `manifest.json.prev` for agents, content-addressed binary + marker + init
  restart for core, stay-on-old on any error, boot recovery.
- `system-ota-survival`: surviving a system OTA — `/data/voboost` persistence,
  init-hook re-arm via `make device-rearm`, independence from the OTA.

### Modified Capabilities
None. This change adds new capabilities. (The `inject` daemon already observes
`staging/` + `update-ready` and delegates the swap here — app-interface "Staging
read boundary".)

## Impact

- **This repo**: adds the OTA specs, `make release-manifest`, `make device-rearm`,
  and the daemon-side apply/rollback (consume `update-ready`, re-verify, atomic
  manifest swap for agents, content-addressed core install + self-shutdown for
  the binary). Builds on the implemented `inject` daemon and `ci` release
  workflow (which already calls `make release-manifest`/`make sign`).
- **voboost app** (`ru.voboost`): gains the OTA client obligation — fetch/diff,
  download deltas, populate `staging/`, set `update-ready` — and produces the
  `agents`/`app` channel manifests.
- **Build/release/CI**: `make release-manifest` scans the clean release `DIR`,
  labels every file with `CHANNEL`, stamps `VERSION`, and emits unsigned
  `build/release-manifest.json`; `make sign`/`make verify-sig` (existing) sign
  and check it against `config/release-public.pem` (same key family as
  `EMBEDDED_PUBKEY`).
- **Dependencies**: ed25519 signing (already in via `inject`); openssl/sha256
  (already used). No `bsdiff`/`bspatch` (the core binary is downloaded whole).
- **Platform**: relies on the root init hook restarting the daemon on exit, and
  the measured fact that a system OTA keeps root and `/data` while reverting
  `/system`.
