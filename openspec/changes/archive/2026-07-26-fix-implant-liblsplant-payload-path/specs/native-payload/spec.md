## ADDED Requirements

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
