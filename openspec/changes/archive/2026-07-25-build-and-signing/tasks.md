## 1. Remove meson/Vala/frida build

- [ ] 1.1 Delete `meson.build`, `meson_options.txt`, `config/android-cross.ini`
      and all frida subproject wraps
- [ ] 1.2 Remove the frida-patched `valac` and frida-meson provisioning
      (owned by `provisioning` change for the `make init` path)
- [ ] 1.3 Remove the frida-agent `--hash-style=sysv` patch (no frida-agent)

## 2. Cargo workspace + daemon crate

- [ ] 2.1 Root `Cargo.toml` workspace; `daemon/` crate `voboost-inject`
- [ ] 2.2 `rust-toolchain.toml` pinning the toolchain
- [ ] 2.3 `daemon/build.rs` — generate `version.rs` and embed `EMBEDDED_PUBKEY`
      from the PEM (replaces the meson `custom_target`)
- [ ] 2.4 `daemon/build.rs` — link `libinjector.a` (C, static) via FFI; declare
      the single `extern "C" fn vbi_inject(...)` seam (see `native-payload`)

## 3. Native artifacts via ndk-build/CMake (NDK r29)

- [ ] 3.1 `injector/` — `Android.mk`/`CMakeLists.txt` → `libinjector.a`
      (C, 64-bit, cross-injects 32/64)
- [ ] 3.2 `implant/` — `Android.mk`/`Application.mk` (c++_static, C++20,
      android-28) → `libimplant.so` per ABI
- [ ] 3.3 Dobby from source via NDK r29 CMake → `libdobby.a` per ABI
- [ ] 3.4 LSPlant + lsplt prebuilts from source per ABI into
      `prebuilt/{arm64-v8a,armeabi-v7a}/`

## 4. Native-payload toolchain constraints (owned here)

- [ ] 4.1 NDK r29 (Clang 21) for all native artifacts; r27 rejected (LSPlant
      C++23 modules fail)
- [ ] 4.2 `c++_static` (system `libc++_shared.so` on Android 9 conflicts by ABI)
- [ ] 4.3 `LOG_DISABLED` at dir scope (`add_compile_definitions`, not
      `target_compile_definitions` — does not reach BMI C++23 modules)
- [ ] 4.4 `#ifndef LOG_DISABLED` guard around `jni_helper.hpp` unguarded
      `__android_log_print`
- [ ] 4.5 `lsplant.hpp` from source (Maven InitInfo ABI diverged — missing
      Allocator/Recycler)
- [ ] 4.6 `-flto` removed

## 5. Makefile orchestration

- [ ] 5.1 `make build` (host, tests), `make build-daemon` (cargo-ndk aarch64),
      `make build-native` (implant+injector+dobby), `make build-android` (all),
      `make sign-elf`, `make release-manifest`, `make test`, `make check`,
      `make lint`
- [ ] 5.2 `make build-android` derives the NDK toolchain PATH from
      `ANDROID_NDK_HOME`; fails early if unset/toolchain not found

## 6. Version + embedded key (restated)

- [ ] 6.1 `Cargo.toml` `[package].version` = `1.0.0-beta1` (single source of
      truth, replaces `meson.build project().version`)
- [ ] 6.2 Embedded key via `build.rs`; no runtime key-file dependency

## 7. Lint

- [ ] 7.1 `cargo clippy` (deny warnings) for Rust
- [ ] 7.2 uncrustify for C/C++ (config exists)
- [ ] 7.3 `make lint` runs both; `make check` verifies tool presence

## 8. Validate

- [ ] 8.1 `npx @fission-ai/openspec validate build-and-signing --strict`
- [ ] 8.2 Device build: `make build-android` produces the daemon ELF + all
      per-ABI payload files; `cargo clippy` clean
