## 1. implant/implant.cpp — payload-path dlopen

- [x] 1.1 `dirname_of(const char *path)` — pure string helper (std::string,
      last `/`), returns the directory prefix or empty if no `/`
- [x] 1.2 `payload_dir()` — `dladdr(&implant_init, &info)` →
      `dirname_of(info.dli_fname)`; empty on `dladdr` failure / no slash
- [x] 1.3 `load_native_libs()` — dlopen `<payload_dir>/liblsplant.so` by full
      path (RTLD_NOW | RTLD_GLOBAL); log the full path on error; leave
      `dlopen("libart.so")` unchanged
- [x] 1.4 Fail closed: empty `payload_dir` → IMPLANT_LOGE + return false (no
      bogus dlopen, no target crash)

## 2. Host unit-test for dirname_of

- [x] 2.1 `implant/dirname_test.cpp` — edge cases: full path, trailing slash,
      no slash, empty string, root-only
- [x] 2.2 Makefile target (host c++ from NDK toolchain or `c++`), silent on
      success; wire into `make test` if clean

## 3. Gates

- [x] 3.1 `make build-implant` — -Werror clean (LOG_DISABLED kept for
      production; drop locally for device-debug, restore before commit)
- [x] 3.2 `make build-android`
- [x] 3.3 `cd daemon && cargo fmt --check && cargo clippy --all-targets && cargo test`
- [x] 3.4 `make test-injector` + the new dirname host-test
- [x] 3.5 `make lint` (uncrustify)
- [x] 3.6 Device: re-deploy libimplant + daemon, inject system_server, logcat
      shows no `dlopen liblsplant failed`; `lsplant::Init` proceeds (next
      blocker, if any, is a separate change)

## 4. Finalize

- [x] 4.1 Restore `-DLOG_DISABLED` in `implant/Android.mk` if dropped locally
- [x] 4.2 `npx @fission-ai/openspec validate fix-implant-liblsplant-payload-path --strict`
- [x] 4.3 Apply + archive the change; commit on user confirmation
