# Injector process discovery specification

## Purpose

Define bounded process discovery, authority, identity attestation, and thread-group consistency.

## Requirements

### Requirement: Process discovery is exact and unambiguous

The daemon SHALL accept only an exact UTF-8 argv[0] terminated by NUL within the signed catalog's
255-byte process-name bound. Catalog targets SHALL be Android package processes, optionally with one
private-process suffix. The exact Android target `system_server` SHALL be admitted only for the signed logical agent `launcher` through a verified-generation watcher scope. Unbound lookup, another logical agent and every other native/system binary name SHALL be rejected. `system_server` SHALL never receive a restart or expected-death permit.
More than one live PID with that argv[0] SHALL authorize neither PID.

#### Scenario: Duplicate argv0 candidates are discovered

- **WHEN** more than one live PID has the exact requested argv0
- **THEN** discovery reports ambiguity and authorizes neither process

#### Scenario: Signed launcher requests system-server scope

- **WHEN** the verified catalog assigns Android system_server to the logical launcher agent
- **THEN** only that bound scope admits discovery, and another logical agent or bare process is rejected

#### Scenario: The critical process requests a restart

- **WHEN** a system_server endpoint has otherwise current restart authority
- **THEN** no expected-death permit is granted or consumed

# Gate: cargo test -p voboost-daemon --bin voboost-inject catalog::tests::system_server_is_scoped_to_signed_launcher_target -- --exact
Gate contract: Signed launcher process scope.
Maps: Requirement `Process discovery is exact and unambiguous`; Scenario `Signed launcher requests system-server scope`.
Preconditions: Catalog fixtures vary logical ID and exact bare process.
Observable result: Only launcher/system_server is admitted; another ID and another bare process fail closed.
Evidence boundary: Host parser, not Android injection or SELinux access.

# Gate: cargo test -p voboost-daemon process_restart::tests::system_server_never_receives_a_death_permit -- --exact
Gate contract: Critical process never-restart policy.
Maps: Requirement `Process discovery is exact and unambiguous`; Scenario `The critical process requests a restart`.
Preconditions: A fully bound endpoint requests restart for system_server.
Observable result: Authorization, pending lookup and death consumption reject it.
Evidence boundary: Host permit authority; guest injection readiness is separate.

# Gate: cargo test --manifest-path daemon/Cargo.toml process_watcher::tests::duplicate_argv0_candidates_are_ambiguous_not_first_match -- --exact
Gate contract: Process discovery is exact and unambiguous host contract.
Maps: Requirement `Process discovery is exact and unambiguous`; Scenario `Duplicate argv0 candidates are discovered`.
Preconditions: The exact Rust test runs its committed fixtures and selects only the named contract harness.
Observable result: discovery reports ambiguity and authorizes neither process.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.


# Gate: cargo test --manifest-path daemon/Cargo.toml process_watcher::tests::cmdline_argv0_is_bounded_nul_terminated_and_exact_utf8 -- --exact
Gate contract: Exact bounded process-name parsing.
Maps: Requirement `Process discovery is exact and unambiguous`.
Preconditions: The exact Rust test supplies terminated, unterminated, trailing, over-bound and invalid UTF-8 argv0 fixtures.
Observable result: Only the exact bounded NUL-terminated UTF-8 argv0 is accepted.
Evidence boundary: Host procfs parser fixtures; live Android process enumeration is not observed.

# Unverified: system-server-guest-loader-and-enforcing-admission

### Requirement: Process security identity is attested before injection

The daemon SHALL bind one leader starttime around its bounded maps snapshot and require exact bounded argv0. It SHALL observe one internally consistent set of four UID fields and one bounded SELinux context without comparing either value with a firmware-wide allowlist. Immediately before remote mutation, the injector SHALL re-read exact process name, leader PID/starttime, all UID fields and SELinux context, require equality with that same observation, and require the canonical Android app-process executable for the ABI. PID reuse or any changed observation SHALL fail before the native operation. OEM package, APK path, APK bytes, file stamp and signing certificate SHALL neither authorize nor reject the attempt.

`/proc/<pid>/maps` MAY support only existing-injection state, exact foreign-injector coexistence
detection, ABI detection and linker reconstruction. An APK mapping SHALL NOT be target identity or
an allowlist input.

#### Scenario: UID or SELinux domain changes during admission

- **WHEN** the UID fields cease to describe one identity or the observed UID or SELinux context changes before remote mutation
- **THEN** the attempt fails without invoking the native operation

#### Scenario: PID is reused after daemon observation

- **WHEN** the leader starttime or exact process name changes before the final native observation
- **THEN** the attempt fails without invoking the native operation

#### Scenario: Target executable is not the canonical app process for its ABI

- **WHEN** `/proc/<pid>/exe` is a wrong-ABI, vendor, prefix, suffix or unrelated path
- **THEN** the attempt fails before remote loading

# Gate: cargo test --manifest-path daemon/Cargo.toml target_identity::tests::wrong_process_and_reused_pid_fail_before_native_operation -- --exact
Gate contract: Final process-security operation fence.
Maps: Requirement `Process security identity is attested before injection`; Scenario `PID is reused after daemon observation`.
Preconditions: The exact Rust harness supplies valid and invalid process observations to a counted native-operation seam.
Observable result: Only the unchanged exact PID, starttime and process invokes the operation once; process or starttime mismatch invokes it zero times.
Evidence boundary: Host modeled observations and call counter only; live procfs, ptrace, Android SELinux Enforcing, device and vehicle behavior remain unverified.

# Gate: cargo test --manifest-path daemon/Cargo.toml target_identity::tests::uid_and_selinux_are_observed_identity_not_firmware_allowlists -- --exact
Gate contract: Dynamic process-security identity without firmware allowlists.
Maps: Requirement `Process security identity is attested before injection`; Scenario `UID or SELinux domain changes during admission`.
Preconditions: The exact Rust test supplies multiple valid UID and SELinux identities plus inconsistent UID and malformed context observations.
Observable result: Any internally consistent UID and bounded context shape is accepted as an observation, while inconsistent or ambiguous values are rejected without a fixed UID or domain allowlist.
Evidence boundary: Host value parsing only; repeated live procfs observation and native-operation fencing remain target evidence.

# Gate: make test-injector-target-process-profile
Gate contract: Canonical app-process executable profile.
Maps: Requirement `Process security identity is attested before injection`; Scenario `Target executable is not the canonical app process for its ABI`.
Preconditions: The exact C policy test exercises both supported ABI path pairs and wrong-ABI, vendor, prefix, suffix, null and invalid-bitness inputs.
Observable result: Only `/system/bin/app_process32`, `/system/bin/app_process32_real`, `/system/bin/app_process64` and `/system/bin/app_process64_real` match their declared ABI.
Evidence boundary: Host execution of the exact C path policy only; live procfs, ptrace and Android executable resolution remain unverified.

### Requirement: Runtime target topology excludes OEM binary identity

Target selection, daemon attestation, helper requests and the `vbi_inject` C ABI SHALL NOT open,
derive, compare or transport an OEM package, APK path, certificate, binary hash or file stamp. This
constraint SHALL NOT remove Voboost-owned APK verification from install or uninstall boundaries.

#### Scenario: Runtime target code regains an OEM identity field

- **WHEN** a runtime target source or native ABI transports an OEM APK, package, certificate, hash,
  path or stamp token
- **THEN** the repository topology gate rejects the source change

# Gate: node tools/test-no-oem-target-identity.ts
Gate contract: Runtime OEM target-identity exclusion topology.
Maps: Requirement `Runtime target topology excludes OEM binary identity`; Scenario `Runtime target code regains an OEM identity field`.
Preconditions: The exact Node test reads only catalog, process-discovery, runtime-orchestration, target-attestation, helper and injector ABI source files and excludes install and uninstall consumers.
Observable result: The test rejects every forbidden OEM target-identity token in the runtime target boundary while permitting Voboost-owned APK verification elsewhere.
Evidence boundary: Static source-topology maintenance constraint only; compilation, live process behavior, device behavior and absence of semantically equivalent future code are not inferred.

### Requirement: Thread-group authority is process scoped

Thread-group authority SHALL contain only selected agents whose signed `targets` declare the exact
process. Empty, unknown-agent, or cross-process authority SHALL fail before remote execution.

#### Scenario: Thread-group authority names another process

- **WHEN** the selected set is empty, unknown, or contains an agent for another process
- **THEN** the attempt fails without authorizing or executing in another process

# Unverified: Rejected thread-group authority execution fence

### Requirement: Thread-group attachment reaches one stable stopped set

The injector SHALL resolve a PID or TID to its TGID and leader starttime, accept only a strict
numeric bounded task inventory, and attach tasks until the stopped set stabilizes within a fixed
pass bound. Each stopped TID SHALL retain that TGID and starttime. One selected stopped TID SHALL
execute remote calls while peers remain stopped. A clone SHALL join the traced inventory before it
runs target code. Instability SHALL fail before remote loading and cleanup SHALL visit attached tasks.

#### Scenario: Task inventory remains unstable

- **WHEN** bounded inventories never reach one stable stopped set
- **THEN** attachment fails closed and cleanup visits every attached task

#### Scenario: The caller supplies a non-leader TID

- **WHEN** that TID belongs to a stable target thread group
- **THEN** the injector binds the leader identity and selects a verified stopped member

# Unverified: Live thread-group stop and remote-execution fence

# Gate: make test-injector-thread-group-unstable-inventory-cleanup
Gate contract: Unstable thread inventory cleanup.
Maps: Requirement `Thread-group attachment reaches one stable stopped set`; Scenario `Task inventory remains unstable`.
Preconditions: The named C harness selector supplies bounded inventories that never stabilize after partially attaching tasks.
Observable result: Attachment fails closed and cleanup visits every attached task.
Evidence boundary: Host fake-process operations; live procfs, ptrace stop state and Android clone events are not observed.


# Gate: make test-injector-thread-group-clone-cleanup
Gate contract: Clone discovery and cleanup.
Maps: Requirement `Thread-group attachment reaches one stable stopped set`; Scenario `Task inventory remains unstable`.
Preconditions: The named C harness selector introduces a clone while the modeled attachment operation is active.
Observable result: The clone joins the tracked inventory and cleanup visits it before the operation returns.
Evidence boundary: Host fake-process operations; kernel clone tracing and target code suspension are not observed.

# Gate: make test-injector-thread-group-stable-non-leader-input
Gate contract: Stable non-leader input normalization.
Maps: Requirement `Thread-group attachment reaches one stable stopped set`; Scenario `The caller supplies a non-leader TID`.
Preconditions: The named C harness selector starts from a non-leader TID in a stable modeled thread group.
Observable result: The operation binds the leader identity and selects a verified stopped member.
Evidence boundary: Host fake-process operations; live procfs and Android ptrace state are not observed.
## Unverified

### Unverified: Rejected thread-group authority execution fence

Maps: Requirement `Thread-group authority is process scoped`; Scenario `Thread-group authority names another process`.

Unavailable observation: No focused test observes attachment and remote-call counters after every
rejected selected-agent set.

Reason: The named test exercises only catalog policy.

Required environment or artifact: A daemon/native seam harness with attachment and remote-call
counters.

### Unverified: Live thread-group stop and remote-execution fence

Maps: Requirement `Thread-group attachment reaches one stable stopped set`; Scenarios `Task
inventory remains unstable` and `The caller supplies a non-leader TID` for live behavior.

Unavailable observation: No focused test proves real procfs enumeration, stopped peers, kernel clone
capture before execution, single-thread remote calls, or zero loading after live instability.

Reason: Named host gates use deterministic fake process operations.

Required environment or artifact: A focused Linux ptrace race harness followed by an Android device
gate.


### Unverified: system-server-guest-loader-and-enforcing-admission

Maps: Requirement `Process discovery is exact and unambiguous`; Scenario `Signed launcher requests system-server scope`.
Unavailable observation: Exact Android guest admission through the existing services.jar loader and SELinux Enforcing.
Reason: Host target-scope tests and both-ABI compilation do not execute those runtime paths.
Required environment or artifact: Supported exact Android guest and release-bound launcher artifacts, followed by physical acceptance.
