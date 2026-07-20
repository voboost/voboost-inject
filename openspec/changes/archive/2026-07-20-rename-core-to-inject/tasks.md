## 1. OpenSpec change (rename-core-to-inject)

- [x] 1.1 `proposal.md`: why (repo is voboost-inject, binary is voboost-inject,
      voboost-app wire is already `inject`; the split name is a confusion
      source), what (wire `core`->`inject`, markers, identifiers, specs),
      capabilities, impact, non-goals (frida-core untouched)
- [x] 1.2 `design.md`: D1 rename wire value (coordinated release, no shim);
      D2 on-disk marker strings; D3 mechanical identifier rename; D4
      exclusion list (frida-core, agent manifest filenames); D5 no compat
      shim; D6 Makefile core-apk->inject-apk; full renaming table
- [x] 1.3 `specs/ota/spec.md`: MODIFIED requirements (channel `core`->
      `inject`, markers `core-update-ready`->`voboost-inject-update-ready`,
      `core-switch-pending`->`voboost-inject-switch-pending`, `core
      self-update`->`inject self-update`)
- [x] 1.4 `specs/update-planes/spec.md`: MODIFIED (Core update plane ->
      Inject update plane; producer staging marker)
- [x] 1.5 `specs/atomic-apply-rollback/spec.md`: MODIFIED (Consume marker,
      Inject update via content-addressed install, Inject rollback)
- [x] 1.6 `specs/release-manifest/spec.md`: MODIFIED (channel set
      {agents,core,app} -> {agents,inject,app})
- [x] 1.7 `specs/ci-release/spec.md`: MODIFIED (channel enum)
- [x] 1.8 `specs/system-ota-survival/spec.md`: MODIFIED (init restart after
      inject apply)
- [x] 1.9 `specs/incremental-delta/spec.md`: MODIFIED (`core binary` ->
      `inject binary`)
- [x] 1.10 `.openspec.yaml`: `schema: spec-driven`, `created: 2026-07-20`

## 2. Rename in src/ (voboost-inject)

- [x] 2.1 `src/ota.vala`: `CORE_BINARY`->`INJECT_BINARY`, `CORE_PREV`->
      `INJECT_PREV`, `CORE_MARKER`->`INJECT_MARKER` (value
      `run/voboost-inject-switch-pending`), `CORE_UPDATE_READY`->
      `INJECT_UPDATE_READY` (value `voboost-inject-update-ready`); enum
      `CoreApplyOutcome`->`InjectApplyOutcome`; `find_core`->`find_inject`
      (`channel == "core"`->`channel == "inject"`); whitelist `"core"`->
      `"inject"`; `apply_core_apk_update`->`apply_inject_update`;
      `core_update_ready`/`consume_core_update_ready`->
      `inject_update_ready`/`consume_inject_update_ready`;
      `core_switch_pending`/`confirm_core_switch`/`rollback_core_switch`->
      `inject_switch_pending`/`confirm_inject_switch`/`rollback_inject_switch`;
      `find_staged_apk`->`find_staged_inject`; temp `.ota.core.tmp`->
      `.ota.inject.tmp`; log messages and comments
- [x] 2.2 `src/app_zone_watcher.vala`: signal `core_update_ready`->
      `inject_update_ready`; marker `"core-update-ready"`->
      `"voboost-inject-update-ready"` (3 sites)
- [x] 2.3 `src/supervisor.vala`: `core_self_shutdown_requested`->
      `inject_self_shutdown_requested`; `apply_staged_core_apk`->
      `apply_staged_inject_update`; all renamed method calls; log messages
      and comments

## 3. Rename in tests + fixtures (voboost-inject)

- [x] 3.1 `test/ota_test.vala`: `stage_core_apk`->`stage_inject_apk`;
      `test_core_*`->`test_inject_*`; `/ota/core-apk-apply/*` test paths->
      `/ota/inject-apply/*`; all renamed API calls; marker strings
- [x] 3.2 `test/app_zone_watcher_test.vala`: `core_update_ready`->
      `inject_update_ready`; marker `"core-update-ready"`->
      `"voboost-inject-update-ready"`; test names/paths
- [x] 3.3 `test/fixtures/gen-fixtures.sh`: `"channel": "core"`->
      `"channel": "inject"` (release-manifest.json, manifest-multi.json,
      bad-channel/entry); `fake-core-binary-v1`->`fake-inject-binary-v1`,
      `fake-core-binary-BAD`->`fake-inject-binary-BAD`; comments
- [x] 3.4 Regenerate `test/fixtures/release-manifest*.json` from the renamed
      script (the `channel` value flips to `inject`)

## 4. Rename in Makefile + CI (voboost-inject)

- [x] 4.1 `Makefile`: target `core-apk`->`inject-apk`; `CHANNEL=core`->
      `CHANNEL=inject` in `release-manifest`; comments
- [x] 4.2 `.github/workflows/release.yml`: `make core-apk`->`make inject-apk`;
      `CHANNEL=core`->`CHANNEL=inject`; comments/log strings

## 5. Rename in voboost-app (sibling repo, parallel)

- [x] 5.1 `OtaModels.kt`: `enum Channel { APP, CORE }`->`{ APP, INJECT }`;
      all `Channel.CORE`->`Channel.INJECT`; comments
- [x] 5.2 `ApkStager.kt`: `CORE_UPDATE_READY_MARKER`->
      `INJECT_UPDATE_READY_MARKER` (value `voboost-inject-update-ready`,
      MUST match daemon); `CORE_APK_NAME`->`INJECT_FILE_NAME`;
      `stageCoreApk`->`stageInjectApk`;
      `createCoreUpdateReadyMarker`->`createInjectUpdateReadyMarker`;
      `hasCoreUpdateReadyMarker`->`hasInjectUpdateReadyMarker`;
      `clearCoreUpdateReadyMarker`->`clearInjectUpdateReadyMarker`
- [x] 5.3 `OtaClient.kt`: `downloadAndApplyCore`->`downloadAndApplyInject`;
      `coreEntry`/`coreUpdateAvailable`->`injectEntry`/`injectUpdateAvailable`;
      failed-channel tag `"core"`->`"inject"`; log messages and comments
- [x] 5.4 Tests: `ApkStagerTest.kt`, `OtaClientTest.kt`, `OtaDownloaderTest.kt`,
      `OtaVerifierTest.kt`, `OtaVersionTest.kt`, `OtaTestUtils.kt` — rename
      identifiers to match the renamed APIs

## 6. Validate + build

- [x] 6.1 `npx @fission-ai/openspec validate rename-core-to-inject --strict`
      passes
- [x] 6.2 `make build`, `make test` pass (voboost-inject host)
- [x] 6.3 `cd ../voboost && ANDROID_HOME=/Users/vitaly/Library/Android/sdk
      ./gradlew testUnit` passes (voboost-app)
- [x] 6.4 `npx @fission-ai/openspec validate --all --strict` passes in both
      repos
