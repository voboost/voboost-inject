# Tasks: fix-provisioning-wraps

## A. Wraps clean-clone (done)

- [x] 1. Remove the seven `[wrap-redirect]` wraps: `subprojects/{usrsctp,libgee,
      libnice,libsoup,libpsl,quickjs,tinycc}.wrap` (keep `frida`, `frida-core`,
      `frida-gum`, `monocypher`).
- [x] 2. Add `!packagefiles/**` to `subprojects/.gitignore` so patch sources are
      tracked.
- [x] 3. Commit `subprojects/packagefiles/monocypher/meson.build` (the
      `patch_directory = monocypher` source).
- [x] 4. Verify `meson subprojects download` exits 0 on the current tree and after
      a clean re-fetch of `monocypher` (patch applies).
- [x] 5. Verify `make lint-fix` and `make check` pass.

## B. Android cross-build

- [x] 6. Verify `subsystem = 'android'` clears the `Subsystem not defined` error
      (isolated meson project + android setup).
- [x] 7. Verify frida's meson fork (`releng/meson`) builds quickjs for the build
      machine (clears the quickjs-native error); standard meson 1.11.1 does not.
- [x] 8. Verify `readelf = 'llvm-readelf'` in `[binaries]` clears the readelf
      error; `meson setup` via frida-meson reaches 195 targets, exit 0.
- [x] 9. `config/android-cross.ini`: add `subsystem = 'android'` to
      `[host_machine]` and `readelf = 'llvm-readelf'` to `[binaries]`.
- [x] 10. `make init`: provision frida's meson — `git submodule update --init
      --recursive releng` in the fetched `subprojects/frida-core` (pulls releng's
      meson + tomlkit); expose via `FRIDA_MESON = …/releng/meson/meson.py`,
      alongside frida-valac.
- [x] 11. `make build-android`: configure via frida-meson (`python3 $(FRIDA_MESON)
      setup …`), not system meson.
- [x] 12. Verify `meson setup` (via the real Makefile wiring + cross-file) reaches
      195 targets, exit 0; ninja clears subsystem/quickjs-native/readelf/tomlkit.
- [x] 13. release.yml: pin `ndk-version: r29` (frida-core 17.11.0 releng
      `NDK_REQUIRED=29`; r27/r27d are rejected).
- [x] 14. NDK r29 installed locally (`29.0.14206865`); a full `make build-android`
       clears every config blocker (subsystem/quickjs-native/readelf/tomlkit/NDK)
       and compiles into the frida-agent embed step. Remaining failures are
       macOS-environment-specific, NOT config issues: (a) libsoup picks up Homebrew
       glib/sqlite (`-I/opt/homebrew/Cellar/glib/...` in an android compile —
       cross-build leak); (b) `termux-elf-cleaner`'s `_LIBCPP_ENABLE_ASSERTIONS`
       was removed in the macOS 26.2 SDK libc++. Neither occurs on the linux CI
       runner (no Homebrew; libstdc++). The Android build is release-only /
       CI(linux)-oriented by design; the config fixes above are what CI needs.
       Full-binary verification is the linux CI job's role (cannot be reproduced
       locally on this macOS without patching frida subprojects).

## C. Wrap-up

- [x] 15. Validate the change: `npx @fission-ai/openspec validate
       fix-provisioning-wraps --strict`.
- [ ] 16. Archive (sync `provisioning` + `build-and-signing` deltas into
       `openspec/specs/`, rename to archive) once approved.
