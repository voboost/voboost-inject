# Tasks — fix-build-native-wired-source

## 1. Spec changes

- [x] 1.1 `openspec/changes/fix-build-native-wired-source/proposal.md`
- [x] 1.2 `openspec/changes/fix-build-native-wired-source/design.md`
- [x] 1.3 `openspec/changes/fix-build-native-wired-source/tasks.md`
- [x] 1.4 delta `build-and-signing` spec (wired from-source build, c++_static
      gate, liblsplt removed, armv7 Dobby `## Unverified`)
- [x] 1.5 delta `native-payload` spec (runtime payload =
      libimplant.so + liblsplant.so only)
- [x] 1.6 delta `release-manifest` spec (list only runtime payload files)
- [x] 1.7 delta `incremental-delta` spec (diff only runtime payload files)
- [ ] 1.8 `npx @fission-ai/openspec validate fix-build-native-wired-source
      --strict` passes

## 2. Build wiring

- [x] 2.1 `third_party/lsplant` + `third_party/dobby` git submodules inited
- [x] 2.2 Dobby r29 patches applied (asm, weak, Cpu.h drop, platform.h,
      module.base)
- [x] 2.3 LSPlant patches applied (LOG_DISABLED, -flto off, jni_helper wrap,
      DEBUG_SYMBOLS_PATH guard)
- [x] 2.4 `make build-third-party` produces `prebuilt/<abi>/liblsplant.so`
      (both ABIs, from source) + `prebuilt/arm64-v8a/libdobby.a` (from source)
- [x] 2.5 `make check-prebuilt` gate (DT_NEEDED without libc++_shared)
- [x] 2.6 `make build-native` chains build-third-party → build-injector →
      build-implant → check-prebuilt

## 3. Payload slimming

- [x] 3.1 `daemon/src/release_manifest.rs` `PAYLOAD_FILES` = libimplant.so +
      liblsplant.so (removed libdobby.a, liblsplt.so)
- [x] 3.2 `git rm prebuilt/<abi>/liblsplt.so`
- [x] 3.3 gitignore generated prebuilts (liblsplant.so both ABIs, arm64
      libdobby.a); keep committed armeabi-v7a/libdobby.a fallback
- [x] 3.4 update `prebuilt/README.md`, `README.md`, `AGENTS.md`

## 4. Gates

- [ ] 4.1 `make build-native` (from clean: `git submodule update --init
      --recursive`)
- [ ] 4.2 `make build-android` (consumes fresh prebuilts)
- [ ] 4.3 `cd daemon && cargo fmt --check && cargo clippy --all-targets &&
      cargo test`
- [ ] 4.4 `make test` + `make lint`

## 5. Apply + finalize

- [ ] 5.1 apply + archive change (after offline gates green)
- [ ] 5.2 commit submodules + Makefile + payload slimming + specs (on user
      confirmation)
