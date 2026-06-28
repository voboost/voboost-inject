## 1. OpenSpec change (ota-core-selfupdate)

- [x] 1.1 `proposal.md`: why (APK-level), what changes (remove file-level
      core-update + agent manifest-swap; add APK-level core self-update),
      capabilities, impact
- [x] 1.2 `design.md`: D1 APK verify = embedded manifest re-verify; D2
      self-replace = extract + atomic rename + init restart; D3 rollback-on-
      DEGRADED from `.prev`; D4 marker single-use (consume before apply); D5
      minimal bounded ZIP reader; D6 system-OTA re-arm; D7 signing reuse
- [x] 1.3 `specs/ota/spec.md`: APK-level core self-update requirements
- [x] 1.4 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-06-28`

## 2. Rewrite src/ota.vala (ota)

- [ ] 2.1 Keep `ReleaseManifest`/`ReleaseFile`/`verify_release_manifest`,
      `manifest_verifies`, `recover_manifest`, `TrustStore` usage,
      `EMBEDDED_PUBKEY`
- [ ] 2.2 Remove `apply_agent_update` (agent manifest-swap), `apply_core_update`
      (content-addressed install), `core_switch_pending`/`confirm_core_switch`/
      `rollback_core_switch` (symlink-based), `CoreApplyOutcome`, the
      `update-ready` marker, and the symlink/repoint/`previous_core_name`
      helpers
- [ ] 2.3 Add `core_update_ready(staging_dir)`/`consume_core_update_ready` for
      the `core-update-ready` marker (single-use, consumed before apply)
- [ ] 2.4 Add a minimal bounded ZIP central-directory reader
      (`extract_apk_entry(apk_path, name)`) to extract the embedded
      `manifest.json`+`manifest.sig` and the daemon ELF binary (inflate
      deflated entries via `ZlibDecompressor`); size/entry bounds
- [ ] 2.5 Add `apply_core_apk_update(staging_dir)`: consume the marker first,
      find the staged APK, re-verify its embedded `manifest.json`+`.sig`
      against `EMBEDDED_PUBKEY`, extract the daemon binary, atomic self-replace
      (`voboost-inject` -> `.prev`, temp -> `voboost-inject`, fsync 0755),
      write `core-switch-pending` marker, return APPLIED (caller self-shuts
      down)
- [ ] 2.6 Add `core_switch_pending`/`confirm_core_switch`/`rollback_core_switch`
      for the `.prev`-based scheme (rename `.prev` back on DEGRADED; clear
      marker + remove `.prev` on READY)

## 3. Update supervisor + app_zone_watcher (ota)

- [ ] 3.1 `src/app_zone_watcher.vala`: observe `core-update-ready` (core-only);
      emit `core_update_ready` signal (rename from `update_ready`)
- [ ] 3.2 `src/supervisor.vala`: VERIFY_SELF -> resolve pending core switch
      (READY -> confirm, DEGRADED -> rollback from `.prev`); boot early-apply
      calls `apply_core_apk_update`; runtime `core_update_ready` handler calls
      `apply_core_apk_update` and self-shuts down on APPLIED
- [ ] 3.3 Remove the file-level `apply_staged_core`/`do_agent_apply` paths and
      the `release-manifest.json` staged-read in the supervisor

## 4. Makefile release-manifest (ota)

- [ ] 4.1 `make release-manifest` lists APKs (the daemon APK is the single
      `core` entry); document the APK-level channel in the recipe comment

## 5. Tests + fixtures (ota)

- [ ] 5.1 `test/fixtures/gen-fixtures.sh`: produce a signed daemon manifest +
      a minimal daemon APK (ZIP with embedded `manifest.json`+`manifest.sig`+
      the daemon binary) + a bad-embedded-sig APK + a bad-binary APK
- [ ] 5.2 `test/ota_test.vala`: rewrite for the APK-level APIs — release-
      manifest verify (keep), APK embedded-manifest re-verify, self-replace
      success (`.prev` kept, marker set), rollback on DEGRADED (`.prev`
      restored), confirm on READY (`.prev` removed), bad embedded sig
      rejected, no-rollback-target stays DEGRADED, boot recovery (keep)
- [ ] 5.3 Tests silent on success; never-broken invariant across simulated
      mid-update interruptions

## 6. Validate + build

- [ ] 6.1 `npx @fission-ai/openspec validate ota-core-selfupdate --strict`
- [ ] 6.2 `make lint-fix`
- [ ] 6.3 `make build` compiles (host build; stub APK extraction if needed,
      but the Vala must compile)
