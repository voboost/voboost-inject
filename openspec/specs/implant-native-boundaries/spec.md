# Implant native boundaries specification

## Purpose

Define fail-closed native symbol, JNI and endpoint lifecycle boundaries.

## Requirements

### Requirement: Native symbol and lifecycle boundaries fail closed

The implant's exported C ABI SHALL contain every C++ exception and return `IMPLANT_INIT_FAILED` after deterministic no-throw cleanup.

#### Scenario: A bootstrap allocation throws

- **WHEN** any C++ allocation below `implant_init` raises an exception
- **THEN** no exception crosses the exported C ABI and the injector observes `IMPLANT_INIT_FAILED`

# Gate: make test-implant-production-host

Gate contract: Production-linked exported implant containment.
Maps: Requirement `Native symbol and lifecycle boundaries fail closed`; Scenario `A bootstrap allocation throws`.
Preconditions: A Linux host compiles the actual `implant.cpp` translation unit with the production bootstrap helpers, strict fake external Dobby/resolve symbols and one test-only exception trigger inside the exported `implant_init` try boundary.
Observable result: Invalid modes fail, phase-one creates real close-on-exec pipes, rejected handoff closes them, and an exception crossing phase two is caught as `IMPLANT_INIT_FAILED` after all pre-resident endpoints and bootstrap state are cleared.
Evidence boundary: Linux production top-level and POSIX descriptor cleanup; real ART/JNI, LSPlant/Dobby and Android loader execution remain unverified.

### Requirement: Implant ELF symbol resolution is exact and bounded

ELF section and symbol names SHALL be compared only after finding a NUL within their bounded string-table remainder, and loaded-module selection SHALL match the exact requested basename rather than a substring. A `dlsym(RTLD_DEFAULT, ...)` fast-path result SHALL be accepted only after `dladdr` proves that its defining mapped object's exact basename is the requested library; otherwise resolution SHALL continue through the bounded exact-library fallback. A failed `dlsym` sequence SHALL close the newly opened native-library handle and clear unpublished function pointers; the temporary `libart.so` reference SHALL be closed on every success and failure path after `JNI_GetCreatedJavaVMs` is consumed.

#### Scenario: An ELF name lacks a bounded terminator

- **WHEN** a section or symbol name has no NUL inside the remaining mapped string table
- **THEN** file-based resolution rejects it without reading beyond the mapping

#### Scenario: A global symbol comes from another library

- **WHEN** `RTLD_DEFAULT` resolves the requested symbol from an object whose exact basename differs from the requested library
- **THEN** the fast path rejects that address and continues with exact-library resolution


# Unverified: Android symbol provenance

# Gate: make test-implant-bounded-elf-string
Gate contract: Implant ELF symbol resolution is exact and bounded host contract.
Maps: Requirement `Implant ELF symbol resolution is exact and bounded`; Scenarios `An ELF name lacks a bounded terminator`, `A global symbol comes from another library`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: file-based resolution rejects it without reading beyond the mapping; the fast path rejects that address and continues with exact-library resolution.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: JNI initialization rejects exceptions and null results

Every JNI lookup, allocation and call used during initialization SHALL reject both a pending exception and a null result before the result is consumed. The failure path SHALL clear the pending exception and release local references through the scoped local frame. The bootstrap manifest parser SHALL reject an empty file inventory before claiming core index zero.

#### Scenario: JNI returns null without a usable handle

- **WHEN** a lookup, string, array, buffer, classloader or method creation returns null or raises
- **THEN** initialization clears the exception, releases scoped local references and reports failure before dereferencing the result

# Unverified: JNI initialization failure cleanup

### Requirement: JNI thread attachment ownership is exact

The implant SHALL attach the current thread only when `GetEnv` returns `JNI_EDETACHED`, remember that ownership and detach it on every successful, deferred, failed or exceptional exit. It SHALL never detach a thread that was already attached by the host. Detach failure SHALL be diagnostic and turn a normal result into `IMPLANT_INIT_FAILED`; no exception may cross the exported `noexcept` boundary. The host gate SHALL execute the same production attachment scope used by `implant.cpp` through narrow fake JNI operations and SHALL cover pre-attached, attach failure, owned success, owned failure, explicit finish and destructor cleanup. Source-text occurrence counting is not proof of this contract.

#### Scenario: Implant owns a temporary JNI attachment

- **WHEN** `GetEnv` returns `JNI_EDETACHED` and attach succeeds before initialization returns Ok, Deferred or Failed
- **THEN** the implant detaches exactly once, while a pre-attached Java thread is never detached

# Gate: make test-implant-runtime-safety
Gate contract: JNI thread attachment ownership is exact host contract.
Maps: Requirement `JNI thread attachment ownership is exact`; Scenario `Implant owns a temporary JNI attachment`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: the implant detaches exactly once, while a pre-attached Java thread is never detached.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Implant pipe writes preserve SIGPIPE process state

Every implant write to a daemon-owned pipe that may lose its reader SHALL preserve the process-wide SIGPIPE disposition. It SHALL block SIGPIPE only in the calling thread, preserve the exact prior mask, retry interrupted writes, leave any pre-existing pending SIGPIPE untouched and consume only a newly generated SIGPIPE after `EPIPE` with a bounded nonblocking mechanism.

#### Scenario: Daemon closes an adopted pipe

- **WHEN** an implant thread writes after the daemon-owned read end closes
- **THEN** the write reports `EPIPE` without changing the host SIGPIPE handler, consuming an older pending SIGPIPE or suppressing unrelated later SIGPIPE delivery

# Gate: make test-implant-runtime-safety
Gate contract: Implant pipe writes preserve SIGPIPE process state host contract.
Maps: Requirement `Implant pipe writes preserve SIGPIPE process state`; Scenario `Daemon closes an adopted pipe`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: the write reports `EPIPE` without changing the host SIGPIPE handler, consuming an older pending SIGPIPE or suppressing unrelated later SIGPIPE delivery.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Endpoint handoff requires the fixed acknowledgement

The implant's descriptor-handoff completion routine SHALL return one fixed nonzero magic acknowledgement after it has closed or retained the requested target-local endpoints. The injector SHALL publish adopted endpoints to Rust only after the exact acknowledgement; a missing, zero or different result SHALL close its duplicates and fail injection.

#### Scenario: Endpoint handoff completion does not acknowledge

- **WHEN** the remote handoff routine returns zero or any value other than the fixed handoff magic
- **THEN** the injector closes both daemon duplicates and exposes neither endpoint


# Unverified: Android endpoint handoff

# Gate: make test-injector-init-result
Gate contract: Endpoint handoff requires the fixed acknowledgement host contract.
Maps: Requirement `Endpoint handoff requires the fixed acknowledgement`; Scenario `Endpoint handoff completion does not acknowledge`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: the injector closes both daemon duplicates and exposes neither endpoint.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Implant target behavior requires correlated runtime evidence

Host execution SHALL not be reported as arm64 emulator, armv7 target, or vehicle runtime evidence. An emulator result SHALL identify the repository revision and exact native artifact tuple before it can verify the corresponding runtime claim.

#### Scenario: Emulator execution is not correlated to this revision

- **WHEN** an arm64 emulator run lacks immutable repository and artifact correlation
- **THEN** arm64 runtime behavior remains unverified alongside armv7 and vehicle behavior

# Unverified: Correlated implant target runtime
## Unverified

### Unverified: Android symbol provenance

Maps: Requirement `Implant ELF symbol resolution is exact and bounded`; Scenario `A global symbol comes from another library`.
Unavailable observation: Android `dlsym`, `dladdr`, and mapped-object fallback reject a same-named symbol from the wrong loaded object and close temporary handles on every path.
Reason: The host helper test covers bounded strings and exact basenames but not Android loader provenance or handle lifetime.
Required environment or artifact: A revision-correlated Android loader fixture that controls two mapped libraries and observes fallback selection and handle cleanup.

### Unverified: JNI initialization failure cleanup

Maps: Requirement `JNI initialization rejects exceptions and null results`; Scenario `JNI returns null without a usable handle`.
Unavailable observation: Every complete production JNI initialization call clears exceptions and releases its local frame before returning failure.
Reason: Current host tests exercise the attachment helper and manifest parser, not the full ART-backed JNI initialization path.
Required environment or artifact: A production-linked JNI fault-injection harness or a correlated rooted Android run with controllable JNI failures.

### Unverified: Android endpoint handoff

Maps: Requirement `Endpoint handoff requires the fixed acknowledgement`; Scenario `Endpoint handoff completion does not acknowledge`.
Unavailable observation: A wrong remote acknowledgement closes both daemon duplicates and publishes neither endpoint after real ptrace execution.
Reason: The host acknowledgement test covers value admission but cannot observe Android remote cleanup and Rust endpoint publication together.
Required environment or artifact: A revision-correlated rooted Android fault-injection run for missing, zero, and incorrect remote acknowledgements.

### Unverified: Correlated implant target runtime

Maps: Requirement `Implant target behavior requires correlated runtime evidence`; Scenario `Emulator execution is not correlated to this revision`.
Unavailable observation: The complete correlated implant executes its runtime contracts inside ART on arm64, armv7, and the vehicle.
Reason: A sibling rooted Android 9 arm64 emulator run is not immutably correlated to this repository revision and artifact tuple; no armv7 or vehicle result is available.
Required environment or artifact: Correlated signed artifacts and recorded arm64 emulator, armv7 target, and vehicle executions for the named scenario.
