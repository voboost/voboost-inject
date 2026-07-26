## Context

The injector loads `libimplant.so` into the target via `__loader_dlopen` with
its full path (`/data/voboost-inject/payload/<abi>/libimplant.so`), so the
implant appears in `/proc/<pid>/maps` under that real path. `liblsplant.so`
sits in the same payload directory, but the `system_server` linker does not
search `/data/voboost-inject/payload/<abi>/` for bare-name dlopens, so the
implant's `dlopen("liblsplant.so")` fails with "library not found".

### Verified facts (test device `1234567`, Android 9, arm64-v8a)

- `libimplant.so` is mapped in `system_server` at the full path
  `/data/voboost-inject/payload/arm64-v8a/libimplant.so` (r-xp/r--p/rw-p).
- Payload dir `/data/voboost-inject/payload/arm64-v8a/` holds `liblsplant.so`,
  `liblsplt.so`, `libdobby.a`, `libimplant.so` (0755 files; parent dir 0711).
- `liblsplant.so` `DT_NEEDED`: only system libs (`liblog`, `libz`, `libm`,
  `libc++_shared`, `libdl`, `libc`). `liblsplt` is NOT in `DT_NEEDED` and
  `liblsplant` does not dlopen `liblsplt` by name (strings checked). So the
  only payload-shipped dep the implant must dlopen itself is `liblsplant.so`.
- `libc++_shared.so` and `libz.so` are present in `/system/lib64/`, so
  `liblsplant.so`'s system deps resolve via the normal search after the
  payload-path dlopen.

## Design

### Resolve payload dir via `dladdr`

`dladdr((void *)&implant_init, &info)` fills `info.dli_fname` with the full
path of the shared object containing `implant_init` — i.e. `libimplant.so`'s
real path as seen in maps. The payload directory is everything up to the last
`/`. Implemented as a pure string helper `dirname_of(const char *path)` over a
`std::string` (find last `/`, return the prefix; empty if no `/`), so the
string logic is unit-testable on the host without `dladdr`.

`payload_dir()` calls `dladdr` then `dirname_of(info.dli_fname)`. If `dladdr`
returns 0 or no `/` is found, it returns an empty string and the caller logs +
aborts (fail closed — never dlopens a bogus path).

### Why not cfg

`cfg` is currently passed as the libimplant path (injector placeholder), but
the `cfg` contract is the channel-B config path consumed by the agent
(update-planes). Relying on `cfg` for payload-dir resolution couples the
implant to a placeholder that will change. `dladdr` depends only on the
implant being loaded by its real path — which is the spec's idempotency
marker (`/proc/<pid>/maps` real path) — so it is stable.

### Why `dlopen` (not `android_dlopen_ext`/namespace)

A plain `dlopen` with the full path works because the file is on disk and
readable/traversable by the target (uid 1000) under the 0711/0755 policy
(verified: dlopen of `libimplant.so` itself already succeeded). No linker
namespace dance is needed for a full-path dlopen of a real file. If a future
device's namespace policy blocks it, `android_dlopen_ext` with a namespace
can be added; not needed now.

## Risks

- **`dladdr` under ptrace**: `dladdr` is a synchronous libdl call that does
  not touch ART and does not block; it runs after `implant_init: start` already
  proved the implant executes. Low risk.
- **`dli_fname` is a basename**: if a loader ever returns a bare basename,
  `dirname_of` returns empty and the implant aborts cleanly (no crash). On
  Android the linker returns the full path (matches maps).
- **Next blocker**: after `liblsplant.so` loads, `lsplant::Init` may surface
  a new issue (Dobby hook install, ART symbol resolution), or
  `load_and_call_agent` (InMemoryDexClassLoader) may fail/hang. Those are
  separate changes; this change's scope is the liblsplant payload-path dlopen.
