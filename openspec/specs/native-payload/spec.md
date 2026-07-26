# native-payload Specification

## Purpose
TBD - created by archiving change native-payload. Update Purpose after archive.
## Requirements
### Requirement: Three native artifacts and their boundaries

The native payload SHALL consist of exactly three kinds of artifact with fixed
language and bitness boundaries:

- `libinjector` — C, ptrace entry mechanism, linked into the 64-bit daemon,
  cross-injecting both 32- and 64-bit targets from one 64-bit binary;
- `libimplant.so` — C++, per-ABI, injected into the target process, the
  in-process loader of the hooker and the Java agents;
- the hooker — LSPlant + Dobby (C++, per-ABI), loaded by `libimplant.so`.

Only a flat C-ABI SHALL cross the Rust↔native boundary. The daemon's sole
`extern "C"` seam SHALL be to `libinjector`; the daemon SHALL NOT link
`libimplant.so`. LSPlant `std::function` hook callbacks SHALL NOT cross the
language boundary — they remain inside C++.

#### Scenario: Daemon links only the injector

- **WHEN** the daemon is built
- **THEN** it links `libinjector` (C) and declares one `extern "C"` inject
  entry, and it does NOT link `libimplant.so` or any LSPlant/Dobby symbol

#### Scenario: Implant is delivered as a file, not linked

- **WHEN** the daemon needs `libimplant.so` in a target
- **THEN** it hands the file path to `libinjector` for in-process load, never
  calling any implant symbol from daemon code

### Requirement: Runtime per-injection bitness detection

The injector SHALL detect the target process bitness at runtime, immediately
before each injection, by inspecting the live process (`/proc/<pid>/exe`
`app_process32`/`app_process64`, or scanning `/proc/<pid>/maps` for `/lib64/`).
It SHALL NEVER take bitness from a static agent→bitness table. The daemon SHALL
carry both ABIs (`arm64-v8a` and `armeabi-v7a`) of every native payload
(`libimplant`, `liblsplant`, `liblsplt`, `libdobby`) and select the payload
whose ABI matches the detected target bitness.

An ABI mismatch crashes the target; bitness is a property of the
device/build, not of the agent (the same app is 32-bit on Android 9 and may be
64-bit on Android 11), so detection MUST be per-injection.

#### Scenario: 32-bit target selects the armv7 payload

- **WHEN** the injector targets a process whose `/proc/<pid>/exe` resolves to
  `app_process32` (or whose maps show no `/lib64/`)
- **THEN** it selects the `armeabi-v7a` `libimplant.so` and uses the 32-bit
  regset for the remote call

#### Scenario: 64-bit target selects the arm64 payload

- **WHEN** the injector targets a process resolving to `app_process64`
- **THEN** it selects the `arm64-v8a` `libimplant.so` and uses the 64-bit regset

#### Scenario: Bitness is re-detected each injection, not cached per agent

- **WHEN** the same agent id is injected into targets of different bitness on
  the same or different builds
- **THEN** the injector detects bitness from each live target and never routes
  the ABI from a per-agent table

### Requirement: Hybrid ptrace remote-call mechanism

The injector SHALL perform remote calls in the target via `PTRACE_CONT` with a
return trap set by pointing the link register at address `0` (`LR=0`), catching
the resulting fault as the call-return signal. It SHALL use cross-bitness
regsets: `arm64_regs` for 64-bit targets, `user_regs` for 32-bit targets
(including the Thumb bit; `uregs[0]`=return, `uregs[15]`=pc, `uregs[13]`=sp).

`PTRACE_SINGLESTEP` and hardware breakpoints SHALL NOT be used: they do not work
on the target kernel (`4.14.156-perf+`), which is why a single-step-based
injector (AndKittyInjector) is rejected despite building and detecting bitness
correctly.

#### Scenario: Remote call returns via the LR=0 trap

- **WHEN** the injector invokes a remote function in the target
- **THEN** it sets `LR=0`, resumes with `PTRACE_CONT`, and treats the fault at
  address `0` as the return of the call, reading the result from the return
  register of the ABI-appropriate regset

#### Scenario: Single-step path is not used

- **WHEN** the injector runs on kernel `4.14.156-perf+`
- **THEN** it does not rely on `PTRACE_SINGLESTEP` or hardware breakpoints for
  remote-call return detection (they do not fire on this kernel)

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

### Requirement: Load via __loader_dlopen and explicit implant_init remote-call

The injector SHALL load `libimplant.so` via `__loader_dlopen` (NOT libdl
`dlopen`, which drops arguments in this context), resolve `implant_init` via
`__loader_dlsym`, and then make an **explicit** remote-call to `implant_init`.
It SHALL NOT rely on `libimplant.so` constructors running on load: under
ptrace-dlopen (a hijacked-thread context) constructors do not run, so the entry
point must be called explicitly.

#### Scenario: Implant entry is called explicitly, not via constructor

- **WHEN** `libimplant.so` is loaded into the target via ptrace-dlopen
- **THEN** the injector explicitly remote-calls `implant_init`, because
  `__attribute__((constructor))` and `JNI_OnLoad` do not run in the
  hijacked-thread context

#### Scenario: Loader dlopen is used, not libdl dlopen

- **WHEN** the injector loads the implant
- **THEN** it calls `__loader_dlopen` with a caller address inside
  `app_process`, not libdl `dlopen`

### Requirement: Single implant entry point implant_init

`libimplant.so` SHALL expose exactly one entry point,
`extern "C" void implant_init(const char* cfg)`, taking the channel-B config
path. The implant SHALL run its startup from `implant_init` only, NOT from
`__attribute__((constructor))` or `JNI_OnLoad`, and SHALL guard against a second
entry so a re-load does not run startup twice (which raised `UnsatisfiedLinkError`
in the PoC when the chain ran twice).

#### Scenario: Startup runs once from implant_init

- **WHEN** `implant_init` is called
- **THEN** the implant runs its full startup (JavaVM acquisition, dex load,
  LSPlant init, agent seam) exactly once and ignores or guards any redundant
  constructor/`JNI_OnLoad`/second `implant_init` entry

### Requirement: Implant loads agents via InMemoryDexClassLoader over JNI

Inside the target, `libimplant.so` SHALL acquire the process `JavaVM` via
`JNI_GetCreatedJavaVMs` and load the agent `.dex` via `InMemoryDexClassLoader`
using pure JNI. It SHALL then reach the Java agents only through the fixed seam
(`agent-entry-seam`), never by any agent-specific symbol.

#### Scenario: Agents loaded through the JVM already in the process

- **WHEN** the implant initializes in a target that hosts an ART runtime
- **THEN** it obtains the `JavaVM` via `JNI_GetCreatedJavaVMs` and loads the
  agent dex via `InMemoryDexClassLoader`, without spawning a new VM

### Requirement: LSPlant init with Dobby inline-hooker slots

The implant SHALL initialize LSPlant with `lsplant::Init`, supplying the
`inline_hooker` and `inline_unhooker` slots as lambdas over Dobby's `DobbyHook`
and `DobbyDestroy`. It SHALL use `lsplant.hpp` from source (the Maven-published
ABI of `InitInfo` diverged — it gained `Allocator`/`Recycler` fields), and SHALL
build with `-flto` removed.

#### Scenario: LSPlant hooks through Dobby

- **WHEN** LSPlant needs to install or remove an inline hook
- **THEN** it calls the implant-provided `inline_hooker`/`inline_unhooker`
  lambdas, which delegate to `DobbyHook`/`DobbyDestroy`

### Requirement: ART symbol resolution via safe_resolve_symbol

The implant SHALL provide LSPlant's `art_symbol_resolver` as
`safe_resolve_symbol`, and SHALL NOT use `DobbySymbolResolver` (which crashes in
`elf_ctx_init`). `safe_resolve_symbol` SHALL try `dlsym(RTLD_DEFAULT)` first (for
`.dynsym` exports), then fall back to a file-based resolver: `dl_iterate_phdr`
yields the `.so` path and `load_bias` (`dlpi_addr`); the file is mmapped, its
section headers parsed for `.symtab`/`.strtab`, and scanned linearly, returning
`load_bias + st_value`. The symbol count SHALL be derived from `DT_HASH` (NOT
`DT_GNU_HASH`). File-based resolution depends on `libart.so` not being stripped
on the target (verified: 29 sections, `.symtab` present).

#### Scenario: Non-exported ART symbol resolved from file

- **WHEN** LSPlant requests an ART symbol not present in `.dynsym`
- **THEN** `safe_resolve_symbol` falls back to mmapping the on-disk `.so`,
  parses `.symtab`/`.strtab` (count via `DT_HASH`), and returns
  `load_bias + st_value`

#### Scenario: DobbySymbolResolver is not used

- **WHEN** the implant configures LSPlant's `art_symbol_resolver`
- **THEN** it installs `safe_resolve_symbol`, never `DobbySymbolResolver`
  (which faults in `elf_ctx_init`)

### Requirement: Dobby logger silenced

The implant SHALL neutralize Dobby's internal logger by providing a no-op
`log_internal_impl` and building the hooker with `LOG_DISABLED`. Dobby's log gate
is an unsigned `b.hi` comparison, so a `severity = -1` message is not suppressed
by log level and must be silenced at the sink.

#### Scenario: Dobby emits no log output

- **WHEN** Dobby would log internally (including `severity = -1`)
- **THEN** the message reaches a no-op `log_internal_impl` and nothing is
  written, and the hooker is compiled with `LOG_DISABLED`

### Requirement: Idempotency marker is the real libimplant.so path

The presence marker for "this target is already injected" SHALL be the real
filesystem path of `libimplant.so` appearing in `/proc/<pid>/maps`. Because
ptrace-dlopen loads a real file (not an anonymous `memfd`), the marker is a
stable real path, unlike frida's `memfd:frida-agent (deleted)`. Consumers of
this contract (reconciliation in `injection-control`) SHALL treat that path in
maps as proof of an existing injection and SHALL NOT re-inject.

#### Scenario: Already-injected target is recognized

- **WHEN** `/proc/<pid>/maps` for a target contains the real `libimplant.so`
  path
- **THEN** the target is treated as already injected and is not re-injected

### Requirement: Hook stacking and multiple agents per process

The hooker SHALL support stacking multiple hooks on a single method (LSPlant
chains hooks rather than overwriting, unlike frida's `.implementation=` which
clobbered a prior hook). A single injection into one process SHALL be able to
carry multiple agents (one implant + one dex load serving several agents), so
that co-resident agents targeting one process share the injection.

#### Scenario: Two agents hook the same method

- **WHEN** two agents install a hook on the same Java method in one process
- **THEN** LSPlant stacks both hooks and both run, neither overwriting the other

#### Scenario: One process, multiple agents, one injection

- **WHEN** several agents target the same process
- **THEN** they are served by a single implant/dex load in that process, not by
  one injection per agent

### Requirement: Implant loads payload-shipped native deps by full path

The implant SHALL load its payload-shipped native dependencies (e.g.
`liblsplant.so`) by their full path resolved from the implant's own loaded
location, NOT by a bare `dlopen` name and NOT relying on the target linker's
search paths. The implant resolves its own path via `dladdr` on an address
within `libimplant.so` (the `dli_fname` matches the real path in
`/proc/<pid>/maps`), takes its directory, and dlopens
`<payload_dir>/<dep>.so` by that full path. A bare `dlopen` name is permitted
only for system libraries that live in the linker's search paths (e.g.
`libart.so`). The implant SHALL fail closed (log and abort, never dlopen a
bogus path) when the payload directory cannot be resolved.

#### Scenario: liblsplant loaded from the payload directory

- **WHEN** the implant needs to load `liblsplant.so` to initialize LSPlant
- **THEN** it resolves `libimplant.so`'s directory via `dladdr`, and dlopens
  `<payload_dir>/liblsplant.so` by full path, not the bare name `liblsplant.so`

#### Scenario: System lib loaded by bare name

- **WHEN** the implant needs a system library such as `libart.so`
- **THEN** it may dlopen it by bare name, since it resides in the linker's
  search paths

#### Scenario: Unresolvable payload directory fails closed

- **WHEN** `dladdr` returns no path or the path has no directory component
- **THEN** the implant logs the failure and aborts the dependency load, and
  does not attempt a bogus `dlopen` that could crash the target

