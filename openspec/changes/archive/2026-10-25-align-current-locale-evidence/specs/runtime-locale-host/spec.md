## ADDED Requirements

### Requirement: Locale readback identifies the actual owner and current UI frame

The optional `vbc_locale_host_v1` entry SHALL return a versioned size-checked C table. Admission SHALL use exact process roles and probes of the methods, RTTI, properties and behavior used by the capability, without APK, firmware or application hash gates. Observation SHALL wait for prepared identity and the owner UI frame, copy the current Screen's bounded Node.Locale through the OEM final value source and original GNU string API, release every acquired shared owner exactly once, and clear prior receipt fields on failure. Observation success SHALL NOT claim locale selection or resource registration.

#### Scenario: UI identity and actual property are observed

- **WHEN** a structurally admitted owner has a live UI frame and attached Screen
- **THEN** observation returns its actual bounded locale and Screen identity; absent identity, UI, symbol or valid value produces no successful receipt

# Unverified: Target locale readback and structural admission

### Requirement: Explicit locale preparation stays off the observation caller

The optional table SHALL append a size-checked prepare function. Resolving the table SHALL NOT start preparation. Explicit preparation SHALL share one detached worker and its eventual result across concurrent callers. Observation SHALL only query preparation state, without starting work or waiting. Pending preparation SHALL return WAITING_IDENTITY with cleared receipt fields; worker creation or probe failure SHALL remain rejected for that process lifetime. Unsupported owners and host platforms SHALL remain unadmitted.

#### Scenario: Concurrent preparation cannot block locale observation

- **WHEN** eight callers request preparation while its worker is blocked
- **THEN** one worker runs on another thread, repeated queries stay pending without waiting, and completion is cached

#### Scenario: Preparation failure cannot be retried in the same process

- **WHEN** worker creation or verification fails
- **THEN** subsequent requests remain rejected without launching a replacement worker

#### Scenario: An unsupported host cannot admit an owner

- **WHEN** an invalid owner or host-platform caller requests preparation
- **THEN** invalid owner IDs and the host preparation remain rejected

# Gate: cargo test --manifest-path cluster/native/Cargo.toml locale_identity::tests::concurrent_prepare_runs_once_off_caller_and_queries_do_not_wait -- --exact

Gate contract: Shared off-caller preparation.
Maps: Requirement `Explicit locale preparation stays off the observation caller`; Scenario `Concurrent preparation cannot block locale observation`.
Preconditions: Host pthread support and a test-owned blocked preparation worker.
Observable result: Eight requests share one detached worker; 1000 queries remain pending while blocked; release caches success without another worker.
Evidence boundary: Host preparation state machine and thread boundary; real OEM probing and C++ observation remain unverified.

# Gate: cargo test --manifest-path cluster/native/Cargo.toml locale_identity::tests::spawn_failure_and_failed_verification_stay_rejected -- --exact

Gate contract: Sticky preparation failure.
Maps: Requirement `Explicit locale preparation stays off the observation caller`; Scenario `Preparation failure cannot be retried in the same process`.
Preconditions: Fresh preparation state machines with injected creation and verification failure.
Observable result: Both failures remain rejected and replacement worker closures are never invoked.
Evidence boundary: Host failure-state logic; actual QNX thread and probe failures remain target observations.

# Gate: cargo test --manifest-path cluster/native/Cargo.toml locale_identity::tests::host_and_unproven_owners_are_never_admitted -- --exact

Gate contract: Host and invalid owner rejection.
Maps: Requirement `Explicit locale preparation stays off the observation caller`; Scenario `An unsupported host cannot admit an owner`.
Preconditions: A non-QNX host and the production preparation entrypoints.
Observable result: Invalid owner IDs are rejected; a valid pending owner becomes rejected when host preparation is requested.
Evidence boundary: Negative host admission only; no compatible firmware or actual QNX owner is established.

# Unverified: Locale preparation observation integration

## Unverified

### Unverified: Target locale readback and structural admission

Maps: Requirement `Locale readback identifies the actual owner and current UI frame`; Scenario `UI identity and actual property are observed`.
Unavailable observation: Actual process role, method/RTTI/property admission, current-frame Node.Locale value, shared owner lifetime and cleared failure receipts on QNX.
Reason: Existing Python-host wrapper is not an authorized gate and a host string fixture cannot establish real OEM admission. No replacement Java/Gradle named behavioral gate currently establishes the complete target claim.
Required environment or artifact: Compatible retained QNX owners and libraries, current SDK capability probes and bounded runtime readback evidence. Gauge, point and light require their own observations; absent owners remain unsupported. Resource registration, reversible selection and Android/QNX coordinated locale acceptance remain separate.

### Unverified: Locale preparation observation integration

Maps: Requirement `Explicit locale preparation stays off the observation caller`; Scenarios `Concurrent preparation cannot block locale observation`, `Preparation failure cannot be retried in the same process`, `An unsupported host cannot admit an owner`.
Unavailable observation: Table resolution without preparation, C++ observer pending receipt clearing and nonblocking integration with actual QNX structural probes.
Reason: Rust host state-machine tests do not execute the complete OEM C++ observation boundary; the former Python wrapper is not run.
Required environment or artifact: An authorized existing named native or Java/Gradle integration gate and QNX runtime observations. Resource loading and Russian selection are not established by preparation.

