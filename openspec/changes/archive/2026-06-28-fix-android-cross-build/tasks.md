# Tasks: fix-android-cross-build

## A. meson.build + src/meson.build + test/meson.build

- [x] 1. `meson.build`: add global `default_library=static` to `default_options`.
- [x] 2. `meson.build`: guard `subdir('test')` with `not meson.is_cross_build()`.
- [x] 3. `src/meson.build`: add `--pkg=gio-2.0` and `--pkg=json-glib-1.0` to
      `inject_vala_args`.
- [x] 4. `src/meson.build`: replace `-static` with `-Wl,-Bstatic -Wl,-Bdynamic`.
- [x] 5. `test/meson.build`: add `--pkg=gio-2.0` and `--pkg=json-glib-1.0` to
      `inject_test_vala_args`.

## B. Makefile

- [x] 6. Add `PYTHON_FOR_MESON ?= /usr/bin/python3` (ships `distutils`).
- [x] 7. `init`: after releng submodule checkout, apply
      `subprojects/packagefiles/frida-meson-libcpp-hardening-mode.patch`.
- [x] 8. `build-android`: launch frida-meson via `$(PYTHON_FOR_MESON)` and pass
      `-Dfrida-core:connectivity=disabled`.
- [x] 8a. `setup`: configure via frida-meson (`$(PYTHON_FOR_MESON) $(FRIDA_MESON)`),
       not the system meson, so `coredata.dat` is written by the same meson
       frida-core's `compat/build.py` imports (host `make build` fix).

## C. Subproject patches (committed under packagefiles/)

- [x] 9. `subprojects/frida-core.wrap`: add `diff_files` pointing at
      `frida-core-libc-shim-opaque-file-bionic.patch` (libc-shim.c opaque FILE
      + non-const stdio for bionic; modulate.py relax static-reloc assert;
      agent meson.build `-Wl,-u` for emutls allocators; agent version script
      export allocators).
- [x] 10. `subprojects/selinux.wrap` (new): override frida-core's with the same
       source + `patch_directory = selinux` (reorder libsepol before
       libselinux; add libsepol_dep to libselinux).
- [x] 11. `subprojects/packagefiles/frida-meson-libcpp-hardening-mode.patch`:
       use `_LIBCPP_HARDENING_MODE` for clang >= 15 (macOS 26.2 SDK compat).

## D. Verify

- [x] 12. `make build-android` (with `ANDROID_NDK_HOME` set to NDK r29)
       produces `build-android/src/voboost-inject` (ELF 64-bit ARM aarch64,
       2011/2011 targets, exit 0).
- [x] 12a. `make build` (host, macOS) produces `build/src/voboost-inject`
        (Mach-O 64-bit arm64, 761/761 targets, exit 0) — `make setup` uses
        frida-meson so `compat/build.py`'s `coredata.dat` loads.

## E. Wrap-up

- [x] 13. Validate the change: `npx @fission-ai/openspec validate
       fix-android-cross-build --strict`.
- [ ] 14. Archive (sync `build-and-signing` + `provisioning` deltas into
       `openspec/specs/`, rename to archive) once approved.
