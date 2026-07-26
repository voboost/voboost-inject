## Why

After the runtime dlsym resolver landed, injection reaches `implant_init` and
`system_server` survives. The next blocker is inside the implant:
`dlopen("liblsplant.so")` is called with a bare name, but `liblsplant.so`
lives in `/data/voboost-inject/payload/<abi>/` — not in any search path the
`system_server` (uid 1000) linker consults. So dlopen returns "library not
found", LSPlant init aborts, and no agent loads.

The `native-payload` spec covers the three artifacts and the injection
mechanism, but it does not say how the implant locates its native dependencies
(`liblsplant.so`) at runtime. Without that requirement the implant relied on a
bare `dlopen` name, which only works for system libs (e.g. `libart.so`), never
for a payload-shipped `.so` placed under `/data`.

## What Changes

- **`implant/implant.cpp`** — `load_native_libs()` resolves the payload
  directory from the implant's own loaded path via `dladdr(&implant_init, ...)`
  (`dli_fname` is the full `/data/voboost-inject/payload/<abi>/libimplant.so`
  path seen in `/proc/<pid>/maps`), takes its directory, and dlopens
  `<payload_dir>/liblsplant.so` by full path (RTLD_NOW | RTLD_GLOBAL). The
  `dlopen("libart.so")` call is unchanged (it is a system lib, bare name is
  correct). Fails closed (logs + aborts) if `dladdr` returns no path.
- **`native-payload` spec** — adds a Requirement that the implant SHALL load
  its payload-shipped native dependencies by full path resolved from its own
  module location (not a bare name, not from system search paths), since they
  are delivered under `/data` outside the linker's search paths.

## Capabilities

### Modified Capabilities

- `native-payload`: the implant now resolves its payload-shipped native deps
  (liblsplant) by full path from its own module location via `dladdr`, not a
  bare dlopen name. Adds the Requirement and a scenario.
