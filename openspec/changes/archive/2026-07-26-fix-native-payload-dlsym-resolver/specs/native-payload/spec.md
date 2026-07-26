## MODIFIED Requirements

### Requirement: Runtime ELF symbol resolution in the target

The injector SHALL resolve the symbols it calls in the target
(`__loader_dlopen`, `__loader_dlsym`, `__loader_dlerror`) at runtime from the
target's own memory via `PT_DYNAMIC` (`DT_SYMTAB`/`DT_STRTAB`), NOT from a
hardcoded offset. When the target's `linker64` (or 32-bit `linker`) is mapped as
split segments (`r--p` header/data + `r-xp` code, both at file-offset 0 on
Android 9), function addresses SHALL be computed from the `r-xp` (code) base as
`load_bias`, with `load_bias + p_vaddr` reaching the `PT_DYNAMIC` segment and
the `.dynsym`/`.dynstr` tables. The symbol count for the linear `.dynsym` scan
SHALL be derived from `DT_SYMTAB`/`DT_STRTAB` adjacency
(`(DT_STRTAB - DT_SYMTAB) / DT_SYMENT`) when `DT_HASH` is absent (the Android 9
linker exposes only `DT_GNU_HASH`); symbols with `st_shndx == SHN_UNDEF` SHALL
be skipped. The `caller_addr` passed to `__loader_dlopen` SHALL resolve the
caller's primary namespace (a registered soinfo such as `libart.so`), with a
fallback to `app_process`. The `.so` path string SHALL be written into the
target ~8KB below the stack pointer (closer placement is clobbered by the
`dlopen` call frame).

#### Scenario: dlopen symbol resolved from target memory

- **WHEN** the injector needs `__loader_dlopen` in the target
- **THEN** it walks the target `linker64`/`linker` `PT_DYNAMIC`
  (`DT_SYMTAB`/`DT_STRTAB`/`DT_SYMENT`/`DT_STRSZ`) to find the symbol, using the
  `r-xp` segment base as `load_bias` for the function address, and does not use
  a build-time offset

#### Scenario: dlsym symbol resolved from target memory

- **WHEN** the injector needs `__loader_dlsym` to resolve `implant_init`
- **THEN** it walks the same target `PT_DYNAMIC` to find `__loader_dlsym`, and
  does not use a build-time offset

#### Scenario: Symbol count without DT_HASH

- **WHEN** the target `linker64`/`linker` carries `DT_GNU_HASH` but no `DT_HASH`
- **THEN** the injector derives the `.dynsym` count from
  `(DT_STRTAB - DT_SYMTAB) / DT_SYMENT` and scans linearly, skipping
  `SHN_UNDEF` entries

#### Scenario: Path string survives the call frame

- **WHEN** the injector writes the `libimplant.so` path into the target before
  calling `__loader_dlopen`
- **THEN** it places the string ~8KB below the target's stack pointer so the
  `dlopen` call frame does not overwrite it
