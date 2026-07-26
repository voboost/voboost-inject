## 1. injector/elf_resolve.c — runtime PT_DYNAMIC resolver

- [x] 1.1 `find_linker_rxp_base(pid, is64)` — generalize `find_linker64_rxp_base`
      to find the `r-xp` base of `linker64` (64-bit) or `linker` (32-bit) in
      `/proc/<pid>/maps`; returns `load_bias`
- [x] 1.2 `resolve_elf64_symbol(image, load_bias, name)` — pure parser:
      read `Elf64_Ehdr` (e_phoff/e_phnum/e_phentsize), find `PT_DYNAMIC`,
      read `DT_SYMTAB`/`DT_STRTAB`/`DT_SYMENT`/`DT_STRSZ`, `nsym = (strtab -
      symtab)/syment`, linear `.dynsym` scan skipping `SHN_UNDEF`, return
      `load_bias + st_value` (0 if not found)
- [x] 1.3 `resolve_elf32_symbol(image, load_bias, name)` — Elf32 path
      (`Elf32_Ehdr`/`Elf32_Phdr`/`Elf32_Sym`, syment=16)
- [x] 1.4 `resolve_loader_symbol(pid, bitness, name)` — read the needed image
      regions from the target via `target_read_mem`, delegate to the pure
      parser; remove hardcoded offsets (0x14244/0x14294/0x1412c) and the
      Phase 1 TODO
- [x] 1.5 Bound the symbol scan safely (fail closed → 0, never jump to a
      bogus address) when `DT_HASH` is absent or adjacency breaks

## 2. injector/injector.c — bitness plumbing

- [x] 2.1 Pass `bitness` (already detected) into `resolve_loader_symbol` for
      `__loader_dlopen`, `__loader_dlsym`, `__loader_dlerror`
- [x] 2.2 Keep the dlerror logging path and `LOCAL_LDLIBS := -llog` (committed
      diagnostics)

## 3. Host unit-test

- [x] 3.1 Commit real `linker64`/`linker` binaries to `test/fixtures/linker/`
      (from the test device)
- [x] 3.2 `injector/elf_resolve_test.c` — assert resolved offsets match
      `llvm-nm` for both ABIs (`dlsym`/`dlopen`/`dlerror`); unknown symbol → 0
- [x] 3.3 `make test-injector` target (host clang from NDK toolchain), silent
      on success; wire into `make test`

## 4. Gates

- [x] 4.1 `make build-injector` — `-Werror` clean
- [x] 4.2 `make build-android` — daemon + libimplant × 2 ABI + libinjector
- [x] 4.3 `cd daemon && cargo fmt --check && cargo clippy --all-targets && cargo test`
- [x] 4.4 `make test-injector`
- [x] 4.5 Device integration: re-deploy injector+daemon, inject `system_server`,
      confirm `IMPLANT_LOGI("start")` reaches logcat (success signal for this
      change; later hang is a separate change)

## 5. Finalize

- [x] 5.1 Restore `-DLOG_DISABLED` in `implant/Android.mk` if dropped locally
- [x] 5.2 `npx @fission-ai/openspec validate fix-native-payload-dlsym-resolver --strict`
- [x] 5.3 Apply + archive the change; commit the full set (resolver, test,
      fixtures, injector.c diagnostics, Android.mk -llog, daemon/build.rs)
