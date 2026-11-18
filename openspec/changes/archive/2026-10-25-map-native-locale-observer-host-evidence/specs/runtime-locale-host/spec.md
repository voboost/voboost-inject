## ADDED Requirements

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
