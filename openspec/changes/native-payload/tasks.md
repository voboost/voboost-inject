## 1. injector/ — hybrid ptrace injector (C)

- [ ] 1.1 Scaffold `injector/` with `Android.mk`/`CMakeLists.txt`, `injector.h`
      exposing `int vbi_inject(int pid, const char* so_path, const char* init_sym)`
- [ ] 1.2 `regs.c` — cross-bitness regsets: `arm64_regs` (64) and `user_regs`
      (32, Thumb bit; `uregs[0]`=ret, `[15]`=pc, `[13]`=sp)
- [ ] 1.3 Runtime bitness detection: `/proc/<pid>/exe` (`app_process32`/`64`)
      with `/proc/<pid>/maps` `/lib64/` scan fallback
- [ ] 1.4 `elf_resolve.c` — resolve `__loader_dlopen`/`__loader_dlsym` from the
      target's `PT_DYNAMIC` (`DT_SYMTAB`/`DT_STRTAB`); use the `r-xp` segment
      base for function addresses (linker64 split r--p/r-xp)
- [ ] 1.5 Remote call: `PTRACE_CONT` + `LR=0` trap (no SINGLESTEP/hw-bp); write
      the `.so` path ~8KB below SP; `caller_addr` inside `app_process`
- [ ] 1.6 Load via `__loader_dlopen`, resolve init symbol via `__loader_dlsym`,
      explicit remote-call to `implant_init`
- [ ] 1.7 Return codes: ok / denied / target-gone / dlopen-failed / init-failed
      (consumed by daemon safety in a later change)

## 2. implant/ — libimplant.so (C++)

- [ ] 2.1 Scaffold `implant/` with `Android.mk`/`Application.mk` (c++_static,
      C++20, android-28), `include/` with source `lsplant.hpp` and `dobby.h`
- [ ] 2.2 `implant.cpp` — single `extern "C" void implant_init(const char* cfg)`
      entry with a re-entry guard; no startup from ctor/`JNI_OnLoad`
- [ ] 2.3 Acquire `JavaVM` via `JNI_GetCreatedJavaVMs`; load agent dex via
      `InMemoryDexClassLoader` (pure JNI)
- [ ] 2.4 `safe_resolve.cpp` — `dlsym(RTLD_DEFAULT)` first, file-based
      `.symtab`/`.strtab` fallback via `dl_iterate_phdr`+mmap; count via
      `DT_HASH`; return `load_bias + st_value`
- [ ] 2.5 `dobby_adapter.cpp` — `inline_hooker`/`inline_unhooker` lambdas over
      `DobbyHook`/`DobbyDestroy`
- [ ] 2.6 `lsplant::Init` wiring `art_symbol_resolver = safe_resolve_symbol` and
      the Dobby slots
- [ ] 2.7 No-op `log_internal_impl`; build with `LOG_DISABLED`; `-flto` removed
- [ ] 2.8 Call the fixed Java seam after LSPlant init (contract defined in
      `agent-entry-seam`)
- [ ] 2.9 Production cleanups: strip, drop PoC debug counters
      (`g_hook_calls`/`g_hook_ok`/`g_resolver_calls`)

## 3. Hooker prebuilts (LSPlant + Dobby)

- [ ] 3.1 `prebuilt/{arm64-v8a,armeabi-v7a}/` with `liblsplant.so`,
      `liblsplt.so`, `libdobby.a` built from source per ABI (toolchain owned by
      `build-and-signing`)

## 4. Bitness / both-ABI carriage

- [ ] 4.1 Produce `libimplant.so` for both `arm64-v8a` and `armeabi-v7a`
- [ ] 4.2 Confirm the daemon carries both ABIs of every native payload and the
      injector selects by detected bitness (daemon wiring lands in
      `injection-control`)

## 5. Validate

- [ ] 5.1 `npx @fission-ai/openspec validate native-payload --strict`
- [ ] 5.2 Re-verify the mechanism end-to-end on the vendor-Android 9 target
      (inject 32- and 64-bit, marker in `/proc/<pid>/maps`, LSPlant hook fires)
