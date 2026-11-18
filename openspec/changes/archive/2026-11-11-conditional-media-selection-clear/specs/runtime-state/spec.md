## ADDED Requirements

### Requirement: Conditional media cleanup preserves a newer selection

The runtime owner SHALL serialize `ClearControllerState` with all state writes and SHALL replace `media-apps`/`media-selected-package` with an empty string only when its current string equals the expected package. A missing or different value SHALL report false without mutation; a committed clear SHALL survive owner restart. The bounded `X|request-id|source|key|expected-package` state-pipe request SHALL retain endpoint ownership checks and reject another source/key, malformed input or an empty expected package, a token longer than 255 bytes, or characters outside ASCII alphanumeric, underscore and dot. Its existing correlated `R` reply SHALL distinguish a committed true, nonmatching false and unavailable error.

#### Scenario: New selection precedes stale cleanup

- **WHEN** the owner stores a newer package before processing an old-package clear
- **THEN** it preserves the newer value, while an exact conditional clear commits empty and remains empty after restart

#### Scenario: State-pipe conditional clear is admitted

- **WHEN** an owned state-pipe request sees missing, matching or newer selection
- **THEN** its correlated reply reports false, true or false respectively and only the matching case clears

#### Scenario: Conditional clear has malformed or unowned input

- **WHEN** the source/key, expected package, request ID or endpoint ownership is invalid
- **THEN** routing rejects the request without creating a state directory

# Gate: cargo test --release --offline --manifest-path daemon/Cargo.toml --bin voboost-daemon server::tests::conditional_media_clear_preserves_newer_selection_and_survives_restart -- --exact

Gate contract: Conditional media selection clear.
Maps: Requirement `Conditional media cleanup preserves a newer selection`; Scenario `New selection precedes stale cleanup`.
Preconditions: The real owner command handler runs with a project-local trusted state store.
Observable result: Missing state stays absent, a stale clear preserves the newer package, and an exact clear survives restart as empty.
Evidence boundary: Host owner and durable storage; JNI transport and live media catalogs remain separate target evidence.

# Gate: cargo test --release --offline --manifest-path daemon/Cargo.toml --bin voboost-inject agent_state::tests::conditional_clear_replies_with_exact_commit_status_and_preserves_newer_selection -- --exact

Gate contract: Conditional media selection clear.
Maps: Requirement `Conditional media cleanup preserves a newer selection`; Scenario `State-pipe conditional clear is admitted`.
Preconditions: The real state route and downlink queue use a real host pipe and secure state fixture.
Observable result: Exact correlated false/true/false replies match missing/matching/newer state, and only matching state becomes empty.
Evidence boundary: Host pipe and state route; JNI execution and device admission remain unverified.

# Gate: cargo test --release --offline --manifest-path daemon/Cargo.toml --bin voboost-inject agent_state::tests::conditional_clear_rejects_malformed_and_unowned_records_without_writes -- --exact

Gate contract: Conditional media selection clear.
Maps: Requirement `Conditional media cleanup preserves a newer selection`; Scenario `Conditional clear has malformed or unowned input`.
Preconditions: Malformed source, key, request ID, package and unauthorized endpoint records enter the real route.
Observable result: Every record is rejected without creating storage.
Evidence boundary: Host parser and endpoint authority; Android pipe identity remains separate target evidence.

# Unverified: Target media selection JNI delivery

## Unverified

### Unverified: Target media selection JNI delivery

Maps: Requirement `Conditional media cleanup preserves a newer selection`; Scenarios `New selection precedes stale cleanup`, `State-pipe conditional clear is admitted`, and `Conditional clear has malformed or unowned input`.
Unavailable observation: Actual Java native registration, device reply timing, cross-process catalog invalidation and UI adoption.
Reason: The production implant host test is Linux-only and skips on this macOS host; host state/pipe tests do not execute device JNI.
Required environment or artifact: The source-bound installer and supported Android host, followed by separate physical media, steering and phone-call acceptance.
