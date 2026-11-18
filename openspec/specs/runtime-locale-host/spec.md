# Runtime locale host capability

## Purpose

Define optional locale observation and explicit structural preparation without changing HostV2 or NativeAgentV3. Resource registration and language selection remain separate capabilities.

## Requirements

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

### Requirement: Locale observer preserves its host boundary and borrowed value lifetime

The locale observation table SHALL expose its version and size, reject absent or undersized output, and wait for admitted identity and UI readiness before resolving or reading properties. For valid-sized output, pending and failed readback SHALL clear prior locale, capability and Screen receipt fields. The observer SHALL read through the object-host supplied PropertyObject and descriptor while the acquired Screen owner remains live, release that owner once on each acquired return path, and resolve observation symbols only once. Obtaining the table or observing pending identity SHALL NOT request preparation.

#### Scenario: Host observer waits without triggering preparation or property reads

- **WHEN** the table is obtained and observations attempt unsupported owners, pending identity or unavailable UI
- **THEN** ABI and size checks hold, observation does not request preparation, pending outputs contain no receipt, and no property reads or premature symbol resolution occur

#### Scenario: Host observer copies changing values while retaining their owner

- **WHEN** an admitted ready fixture supplies successive valid locale strings, absent object or descriptor, invalid strings, or a detached Screen
- **THEN** valid observations copy the changing values and Screen identity; acquired owners remain live during borrowed accesses and are released once; rejected valid-sized observations do not retain a prior successful receipt

#### Scenario: A missing observation symbol remains unsupported without repeated resolution

- **WHEN** a fresh process cannot resolve the Screen getter and observes twice
- **THEN** both observations are unsupported without reading or releasing a nonexistent Screen, and the second observation does not resolve symbols again

# Gate: make test-cluster-locale-observer

Gate contract: Native host observer boundary and borrowed lifetime.
Maps: Requirement `Locale observer preserves its host boundary and borrowed value lifetime`; Scenarios `Host observer waits without triggering preparation or property reads`, `Host observer copies changing values while retaining their owner`, `A missing observation symbol remains unsupported without repeated resolution`.
Preconditions: Host C++20 compiler, current SDK headers, production locale_observer.cpp and its test-owned object-host/identity/property interfaces; default and missing-symbol modes execute in separate processes with five-second alarms.
Observable result: ABI/size and owner/identity/UI rejection, explicit preparation without observer-triggered work, changing genuine host string readback, offset PropertyObject binding, missing object/descriptor rejection, bounded invalid-result clearing, one release per acquired Screen and one-time symbol resolution assertions all pass.
Evidence boundary: Host production observer control flow, borrowed host-object lifetime and output fields only. The fixture's addresses, prepared identity and UI booleans do not prove OEM method/RTTI/property admission, target layout, actual QNX Node.Locale, owner UI-thread execution or lifecycle. Native preparation concurrency has separate Rust gates.

## Unverified

### Unverified: Target locale readback and structural admission

Maps: Requirement `Locale readback identifies the actual owner and current UI frame`; Scenario `UI identity and actual property are observed`.
Unavailable observation: Actual process role, method/RTTI/property admission, current-frame Node.Locale value, shared owner lifetime and cleared failure receipts on QNX.
Reason: The named native host observer gate substitutes its process identity, UI readiness and property provider; genuine host strings do not establish actual OEM admission or target property access.
Required environment or artifact: Compatible retained QNX owners and libraries, current SDK capability probes and bounded runtime readback evidence. Gauge, point and light require their own observations; absent owners remain unsupported. Resource registration, reversible selection and Android/QNX coordinated locale acceptance remain separate.

### Unverified: Locale preparation observation integration

Maps: Requirement `Explicit locale preparation stays off the observation caller`; Scenarios `Concurrent preparation cannot block locale observation`, `Preparation failure cannot be retried in the same process`, `An unsupported host cannot admit an owner`.
Unavailable observation: Nonblocking observer integration with actual QNX structural probes and the verified owner UI lifecycle.
Reason: The native host observer and Rust preparation gates cover their respective host boundaries, but substitute the OEM process/property/UI environment and do not execute the combined QNX lifecycle.
Required environment or artifact: Current QNX structural preparation and observer integration with bounded UI-frame runtime observations. Resource loading and Russian selection are not established by preparation.
