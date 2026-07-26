## MODIFIED Requirements

### Requirement: Runtime per-injection bitness detection

The injector SHALL detect the target process bitness at runtime, immediately
before each injection, by inspecting the live process (`/proc/<pid>/exe`
`app_process32`/`app_process64`, or scanning `/proc/<pid>/maps` for `/lib64/`).
It SHALL NEVER take bitness from a static agent→bitness table. The daemon SHALL
carry both ABIs (`arm64-v8a` and `armeabi-v7a`) of every runtime native
payload file (`libimplant.so`, `liblsplant.so`) and select the payload whose
ABI matches the detected target bitness. `libdobby.a` is a build-time-only
artifact (statically linked into `libimplant.so`); `liblsplt.so` is unused and
not carried. Only `libimplant.so` and `liblsplant.so` are runtime payload.

An ABI mismatch crashes the target; bitness is a property of the
device/build, not of the agent (the same app is 32-bit on Android 9 and may be
64-bit on Android 11), so detection MUST be per-injection.

#### Scenario: 32-bit target selects the armv7 payload

- **WHEN** the injector targets a process whose `/proc/<pid>/exe` resolves to
  `app_process32` (or whose maps show no `/lib64/`)
- **THEN** it selects the `armeabi-v7a` `libimplant.so` and `liblsplant.so`
  and uses the 32-bit regset for the remote call

#### Scenario: 64-bit target selects the arm64 payload

- **WHEN** the injector targets a process resolving to `app_process64`
- **THEN** it selects the `arm64-v8a` `libimplant.so` and `liblsplant.so` and
  uses the 64-bit regset

#### Scenario: Bitness is re-detected each injection, not cached per agent

- **WHEN** the same agent id is injected into targets of different bitness on
  the same or different builds
- **THEN** the injector detects bitness from each live target and never routes
  the ABI from a per-agent table

#### Scenario: Only runtime payload files are carried per ABI

- **WHEN** the daemon's payload directory is provisioned for an ABI
- **THEN** it contains `libimplant.so` and `liblsplant.so` for that ABI, and
  does NOT contain `libdobby.a` (build-time only) or `liblsplt.so` (unused)
