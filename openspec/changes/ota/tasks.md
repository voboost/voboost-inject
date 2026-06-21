## 1. Release manifest and signing (release-manifest)

- [x] 1.1 Define the release-manifest data contract (path, channel, sha256, size,
      version per file) — distinct from the daemon manifest (inject design D1/D9c)
- [x] 1.2 Implement `make release-manifest` (this repo): scan `DIR`, label every
      file with `CHANNEL`, stamp `VERSION`, emit unsigned
      `build/release-manifest.json` (per-file sha256/size/version). Signing is the
      existing `make sign`/`make verify-sig` (the `ci` release workflow already
      calls both); `ota` only generates and the daemon re-verifies
- [x] 1.3 Daemon re-verification of a staged `release-manifest.json` signature
      against `EMBEDDED_PUBKEY` (Monocypher) to obtain a trusted core sha256

## 2. Incremental diff and fetch (incremental-delta) — app-owned contract

- [ ] 2.1 Define the app client contract: compare current vs new release manifest
      by per-file sha256 (the implementation lives in the voboost app repo)
- [ ] 2.2 Define the download contract: only changed files, downloaded whole;
      reject a downloaded file whose size differs from the manifest before hashing
- [ ] 2.3 Verify every fetched file against the manifest sha256; the daemon
      re-verifies staged material with the embedded key before trusting it
      (daemon side done in `Ota.apply_*`; client fetch-verify is app-owned)

## 3. Update planes and staging producer (update-planes)

- [ ] 3.1 Agents + signed daemon manifest inside the APK (app+agents plane);
      document that this repo's CI emits only the `core` release-manifest channel
- [ ] 3.2 App staging writer contract: write all files, then create `update-ready`
      last (the daemon already observes it)
- [x] 3.3 Core plane: the app downloads the binary to staging; the daemon installs
      it content-addressed and repoints the stable launch path, then self-shuts
      down so init restarts the new binary (no car reboot)

## 4. Atomic apply and rollback (atomic-apply-rollback)

- [x] 4.1 Daemon agent-set apply: consume `update-ready`, re-verify staged
      `manifest.json`+`manifest.sig` (+ agent sha256) with `EMBEDDED_PUBKEY`,
      TOCTOU-safe root-temp copy, atomic manifest swap (old →
      `manifest.json.prev`), re-inject, stay-on-old on failure
- [x] 4.2 Boot recovery: if active `manifest.json` is absent/fails-sig but
      `manifest.json.prev` verifies, restore it before running
- [x] 4.3 Core apply: verify staged binary against the daemon-re-verified release
      manifest sha256; install `voboost-inject-<sha>`; write `core-switch-pending`
      marker naming the previous file; repoint the stable launch path; clean
      self-shutdown -> init restarts the new binary (no car reboot)
- [x] 4.4 Core rollback: on a degraded restart with the marker present, repoint
      the launch path back to the previous file, clear the marker, self-shutdown ->
      init restarts the previous binary
- [x] 4.5 Early apply: a complete staged agent update is applied right after
      VERIFY_SELF, before the first injection; a pending core-switch marker is
      resolved on boot (READY -> confirm/GC, DEGRADED -> rollback)
- [x] 4.6 Verify the never-broken invariant across simulated mid-update
      interruptions (host-side state-machine test)
- [x] 4.7 Content-addressed agent file paths are a normative producer requirement
      (a changed agent ships at a new sha-derived path), so a mid-apply failure
      never overwrites a file the active manifest verifies against
- [x] 4.8 The `update-ready` marker is single-use: the daemon gates on it and
      consumes it after any apply attempt (success or verified-failure), so a
      successful core apply does not crash-loop via self-shutdown + init restart
      and the agent plane is not re-applied on every boot
- [x] 4.9 `confirm_core_switch` garbage-collects the previous binary only when
      the launch path no longer points at it (power-loss between marker-write and
      repoint must not delete the still-active binary)

## 5. System-OTA survival (system-ota-survival)

- [x] 5.1 Implement `make device-rearm HOOK=<path>` (operator adb step, idempotent)
- [ ] 5.2 Confirm `/data/voboost` + daemon + agents persist across a system OTA
      (no re-download) — device verification, not host-side
- [ ] 5.3 Confirm app/agents OTA is independent of the system OTA cadence — device
      verification, not host-side

## 6. Tests (host-side, no device — pure logic, meson, silent on success)

- [x] 6.1 Release-manifest generator: correct sha256/size/version/channel for a
      fixture file set (dev key) — pure logic
- [x] 6.2 Signature + per-file hash verification (fixtures) — pure logic
- [x] 6.3 Agent manifest-swap atomic state machine: success / mid-swap failure /
      power-loss between renames / boot-recovery from `manifest.json.prev` /
      never-broken — pure logic
- [x] 6.4 Core apply state machine: staged sha256 mismatch -> reject; apply ->
      repoint + marker; degraded-restart -> rollback — pure logic
- [x] 6.5 OTA review hardening (host-side): release-manifest oversize /
      missing-field / invalid-channel rejection; agent partial-failure
      stay-on-old (content-addressed); boot recovery with an active-but-bad
      manifest; core size pre-check rejection; confirm keeps the active binary
      after a power-loss-before-repoint — pure logic
