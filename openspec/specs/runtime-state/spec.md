# Runtime state specification

## Purpose

Define authenticated settings mutations and generation-fenced agent state.

## Requirements

### Requirement: Settings mutations are authenticated by endpoint context

A Settings event SHALL carry a monotonic bounded `u64` request ID and typed key/value mutation. Agent enum options SHALL use exact `option|<agent-id>/<option-key>:<enum-value>` payload grammar. The daemon SHALL verify the endpoint is the active Settings agent in the expected process and resident generation, and SHALL accept an option only when the selected signed catalog contains that exact agent, `enum` key and value. An option mutation SHALL replace only that canonical option and SHALL not change checkbox conflict relations. Dedupe SHALL use the daemon-owned endpoint epoch, request ID and canonical mutation fingerprint: an exact duplicate is idempotent, a conflicting reuse or evicted replay below the high-water mark fails closed, and endpoint teardown clears only that epoch. The daemon SHALL validate catalog keys, options and conflicts, atomically replace canonical intent and send a confirmed whole-state snapshot or bounded rejection.

#### Scenario: A non-Settings endpoint sends a mutation

- **WHEN** a bound endpoint lacks the required agent/process identity
- **THEN** the daemon rejects the event without changing canonical intent

#### Scenario: A request ID repeats

- **WHEN** the same mutation identity is received again
- **THEN** it does not apply a second state transition

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_log::tests::capability_gates_block_cross_endpoint_impersonation -- --exact
Gate contract: Settings endpoint mutation authority.
Maps: Requirement `Settings mutations are authenticated by endpoint context`; Scenario `A non-Settings endpoint sends a mutation`.
Preconditions: The exact Rust test sends Settings-shaped events through endpoints with wrong agent and process capabilities.
Observable result: Cross-endpoint impersonation is rejected without routing a canonical mutation.
Evidence boundary: Host endpoint-context routing; target pipe identity is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::typed_enum_option_is_catalog_bound_atomic_idempotent_and_conflict_neutral -- --exact
Gate contract: Typed option mutation idempotence.
Maps: Requirement `Settings mutations are authenticated by endpoint context`; Scenario `A request ID repeats`.
Preconditions: The exact Rust test commits a catalog-bound enum option, repeats it exactly and reuses the ID with conflicting data.
Observable result: The exact duplicate preserves bytes and acknowledges once more, while conflicting reuse fails closed.
Evidence boundary: Host mutation and canonical-file fixture; Settings UI is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::evicted_request_ids_remain_rejected_by_high_watermark -- --exact
Gate contract: Evicted mutation replay rejection.
Maps: Requirement `Settings mutations are authenticated by endpoint context`; Scenario `A request ID repeats`.
Preconditions: The exact Rust test advances one endpoint beyond the recent-request cache and replays the evicted lowest ID.
Observable result: The high-water mark rejects the replay after cache eviction.
Evidence boundary: Host request-cache logic; process restart persistence is outside scope.

### Requirement: Mutation acknowledgement is correlated, coalesced and retry-bounded

Mutation confirmation SHALL use only `A|<request-id>|<whole-state-json>` on the submitting endpoint. The preceding ordinary `D` applies that same document to `AgentRuntimeController` but SHALL never itself confirm an `E` request. Pending confirmation MAY coalesce per endpoint to the greatest ordered request ID because its fresh post-commit whole-state snapshot semantically covers earlier ordered commits. Implant retrieval by an issued request ID MAY return that same-or-newer correlated snapshot and SHALL retain the latest ACK for concurrent Settings panels until a newer ACK or endpoint reset. A preparation or atomic pair-admission failure SHALL retain only that latest pending ACK for a bounded retry count and lifetime; successful admission or endpoint teardown clears it. A stale epoch, lower acknowledgement ID or unrelated desired frame SHALL not confirm a request. Rebind SHALL clear partial framing and all retained acknowledgement state.

#### Scenario: Mutation acknowledgement delivery is interrupted

- **WHEN** an admitted correlated acknowledgement cannot be delivered immediately
- **THEN** only the latest endpoint-scoped acknowledgement is retried within its bounded count and lifetime

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::mutation_ack_targets_coalesce_monotonically_per_endpoint -- --exact
Gate contract: Endpoint-scoped acknowledgement coalescing.
Maps: Requirement `Mutation acknowledgement is correlated, coalesced and retry-bounded`; Scenario `Mutation acknowledgement delivery is interrupted`.
Preconditions: The exact Rust test queues out-of-order acknowledgement targets for one endpoint.
Observable result: Only the greatest ordered request ID remains pending for that endpoint.
Evidence boundary: Host pending-target state; implant retrieval is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::ack_retry_budget_and_lifetime_are_bounded -- --exact
Gate contract: Acknowledgement retry bounds.
Maps: Requirement `Mutation acknowledgement is correlated, coalesced and retry-bounded`; Scenario `Mutation acknowledgement delivery is interrupted`.
Preconditions: The exact Rust test reaches the retry-count boundary and exceeds the pending-age boundary.
Observable result: Both exhausted targets are discarded and no pending acknowledgement remains.
Evidence boundary: Host monotonic-clock and retry state; target scheduling delays are not exercised.

### Requirement: Settings mutation admission orders desired state before acknowledgement

A committed Settings mutation SHALL atomically admit an ordinary runtime `D` followed by the correlated `A` for the same whole-state document only to the submitting Settings endpoint. It SHALL register the `D` generation as awaiting runtime status acknowledgement. The pair SHALL be coalesced and bounded, and SHALL NOT be globally retried because another endpoint is blocked.

#### Scenario: Settings admission is backpressured

- **WHEN** the submitting Settings endpoint is draining an earlier downlink frame
- **THEN** the committed whole-state `D` and correlated `A` enter that endpoint queue once and in that order

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::settings_commit_during_drain_queues_runtime_d_before_correlated_a_once -- --exact
Gate contract: Ordered Settings `D` and `A` admission.
Maps: Requirement `Settings mutation admission orders desired state before acknowledgement`; Scenario `Settings admission is backpressured`.
Preconditions: The exact Rust daemon test commits during an earlier downlink drain on the submitting endpoint.
Observable result: One whole-state `D` followed by its correlated `A` enters only that endpoint queue.
Evidence boundary: Host queue state machine; injected runtime consumption is not exercised.

### Requirement: Live Settings startup confirmation retains the current profile

For an exact eligible resident Settings endpoint, live desired and correlated mutation confirmation SHALL retain Settings in the expected agent/status set and SHALL carry the current validated canonical startup/language profile under the resident generation. Hidden or none bootstrap without that owned eligibility SHALL omit Settings and profile. The daemon SHALL preserve the existing Settings/profile ownership invariant and SHALL NOT derive residency from caller status. A retained hidden Settings endpoint SHALL keep its authenticated Settings mutation authority within the active generation fence.

#### Scenario: A live Settings host switches to hidden

- **WHEN** an eligible interface Settings endpoint receives a committed hidden profile
- **THEN** its current profile and exact Settings status set are delivered and its next authorized Settings mutation can return interface

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml tests::live_settings_hidden_document_keeps_the_current_profile_and_exact_status_set -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `Live Settings startup confirmation retains the current profile`; Scenario `A live Settings host switches to hidden`.
Preconditions: A root-owned interface desired document and exact tracked endpoint switch to hidden/Chinese.
Observable result: The fresh hidden/Chinese projection retains Settings, accepts its exact status envelope, allows a production Settings event to commit interface, and a foreign epoch cannot claim Settings authority.
Evidence boundary: Host production Plan, tracker, status validator and canonical mutation route; native target delivery and visible OEM rendering remain separate runtime evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml tests::hidden_bootstrap_delivers_the_settings_module_dormant -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `Live Settings startup confirmation retains the current profile`; Scenario `A live Settings host switches to hidden`.
Preconditions: Fresh hidden, interface and none boot plans use the verified Settings generation.
Observable result: Hidden only registers the dormant Settings module, none omits its delivery, and unrelated processes receive no Settings module.
Evidence boundary: Host bootstrap construction only; guest boot process absence requires separate runtime evidence.

### Requirement: None startup retains only exact admitted live peers

For an ordinary committed none startup projection, expected agent IDs, semantic desired state and serialized desired/confirmation documents SHALL retain an enabled peer only when it belongs to the previous admitted agent set of the same PID, process starttime and endpoint epoch under the same immutable native generation and catalog. Disabled or unadmitted peers SHALL remain excluded. Fresh none construction and uninstall cleanup SHALL not inherit admitted live peers. Settings SHALL retain its separate authenticated loaded-host and profile ownership requirements. A startup-only projection SHALL not remove an otherwise enabled admitted peer and thereby request an OEM process restart.

#### Scenario: Enabled peers receive none in their current processes

- **WHEN** a live Settings, Launcher, navigation or keyboard process receives an ordinary none projection
- **THEN** its admitted enabled peer remains in the expected agent set and both desired representations, while disabled or unadmitted peers, fresh none and uninstall cleanup remain excluded

#### Scenario: A previous admitted set has stale endpoint or native authority

- **WHEN** the PID, starttime, epoch, native generation or catalog differs from the frozen admitted endpoint
- **THEN** the previous agent IDs cannot authorize peer retention

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml plan::tests::none_live_projection_retains_only_admitted_enabled_agents_in_every_process -- --exact

Gate contract: Exact admitted live peers survive a startup-only none projection.
Maps: Requirement `None startup retains only exact admitted live peers`; Scenario `Enabled peers receive none in their current processes`.
Preconditions: Receipt-bound catalog fixtures contain the actual font, launcher or keyboard peer ID in Settings, Launcher, navigation and keyboard target processes.
Observable result: The real serialized document, semantic representation and expected IDs retain the admitted enabled peer; disabled and unadmitted peers, fresh none and uninstall cleanup remain excluded, and the live Settings profile carries none.
Evidence boundary: Host production projection builders; guest selected radios, Android process behavior and vehicle readiness remain separate runtime evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml runtime::parallel_tests::none_admitted_ids_require_exact_endpoint_and_native_generation -- --exact

Gate contract: Frozen endpoint and native authority fence admitted peer retention.
Maps: Requirement `None startup retains only exact admitted live peers`; Scenario `A previous admitted set has stale endpoint or native authority`.
Preconditions: The production admitted-ID guard receives the frozen endpoint and resident generation with matching or independently mismatched PID, starttime, epoch, native generation and catalog.
Observable result: Only the exact matching endpoint and native identity return the previous IDs; stale or absent authority returns no admitted IDs.
Evidence boundary: Host production identity guard; native target admission and Android runtime behavior remain separate evidence.

### Requirement: Agent state is namespaced and generation-fenced

Persistent state writes SHALL be restricted to the sending resident agent, typed key and bounded value. Reads SHALL return only that namespace. Catalog agent IDs, state source IDs and state keys SHALL use aligned independent bounds, while the encoded source-plus-key storage basename SHALL have its own complete bound including separator and suffix; an over-bound source, key or composed filename SHALL propagate an error rather than alias another namespace.

#### Scenario: An agent writes another agent's state key

- **WHEN** the event identity and requested namespace differ
- **THEN** the daemon rejects the write

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::owner_is_stable_and_unauthorized_read_does_not_disclose_value -- --exact
Gate contract: Agent state namespace ownership.
Maps: Requirement `Agent state is namespaced and generation-fenced`; Scenario `An agent writes another agent's state key`.
Preconditions: The exact Rust test creates state under one owner and attempts unauthorized read and mutation through another identity.
Observable result: Ownership remains stable and the unauthorized endpoint receives neither mutation authority nor stored value.
Evidence boundary: Host state store; target endpoint transport is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::catalog_source_and_key_maxima_fit_one_unambiguous_storage_filename -- --exact
Gate contract: State storage filename boundary.
Maps: Requirement `Agent state is namespaced and generation-fenced`; Scenario `An agent writes another agent's state key`.
Preconditions: The exact Rust test composes maximum catalog source and key lengths with separator and suffix.
Observable result: The maximum valid pair has one unambiguous basename and over-bound compositions fail rather than alias.
Evidence boundary: Host filename encoding; target filesystem name limits are not exercised.

### Requirement: Fixed operational boolean state diagnostics are root-owned

The daemon SHALL append canonical INFO with daemon source, no source ID, component `agent-state` and message `vehicle-state-observed` only for accepted existing state operations on the exact pairs `vehicle-drive-forced-ev`/`forced-ev-armed` and `vehicle-drive-pedestrian-warning`/`pedestrian-warning-armed`. String fields SHALL contain `agentId`, `key`, `operation` as `read` or `write-readback`, `outcome` as `value`, `missing` or `unavailable`, and the endpoint-owned `process`, `targetPid` and `endpointEpoch`. Only an actual secure read of a JSON boolean SHALL produce `outcome=value` and `value` as `true` or `false`; missing SHALL remain missing and every nonboolean, malformed or untrusted read SHALL be unavailable without a value. Existing native read response and write routing semantics SHALL remain unchanged.

A write-readback value SHALL require successful trusted preparation, rename and directory fsync followed by a fresh secure read of the same typed boolean. Failed writes and mismatched readback SHALL NOT produce value evidence. Resident `generationId` and `catalogSha256` SHALL be included together only when available; `targetStarttime` SHALL come only from the exact tracker PID/process/epoch registration. Optional `documentGeneration` SHALL be the exact decimal daemon desired-context revision and SHALL NOT assert applied-agent state. `bootId` SHALL appear only after a successful canonical boot-ID read; `requestId` SHALL appear only for reads and preserve the exact decimal request ID. Records SHALL contain no generic state values, raw JSON, paths or private options and SHALL use only the existing bounded canonical log path. An operation-time record SHALL NOT claim a fresh on-demand state read.

#### Scenario: A fixed boolean is read or is missing

- **WHEN** an authorized endpoint reads either fixed pair containing a JSON boolean or no stored value
- **THEN** the persisted daemon INFO reports its actual boolean or missing outcome and the native reply retains its existing representation

#### Scenario: The stored scalar is not a trusted boolean

- **WHEN** a fixed pair contains a string, number, malformed document or an untrusted substituted leaf
- **THEN** the diagnostic reports unavailable without a value while preserving the existing native reply semantics

#### Scenario: A fixed boolean is committed and read back

- **WHEN** an authorized write completes durable storage and a new secure read returns the exact written boolean
- **THEN** the persisted daemon INFO reports that boolean and a mismatched later readback cannot prove the earlier requested value

#### Scenario: A write fails or a different pair is submitted

- **WHEN** storage rejects a fixed-pair write or the endpoint lacks ownership or submits another source/key pair
- **THEN** write failure produces no value evidence, unauthorized operations produce no diagnostic and another pair exposes no new diagnostic value

#### Scenario: Diagnostic metadata follows the resident endpoint

- **WHEN** the active generation differs from a resident endpoint or a PID/process/epoch registration does not match
- **THEN** metadata retains the resident generation and exact desired-context revision and omits any unmatched starttime

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml agent_state::tests::vehicle_state_read_logs_strict_booleans_and_missing -- --exact

Gate contract: Root-owned typed boolean read evidence.
Maps: Requirement `Fixed operational boolean state diagnostics are root-owned`; Scenario `A fixed boolean is read or is missing`.
Preconditions: The production read route uses both fixed namespaces, actual secure host files, real reply pipes and a scoped canonical log directory.
Observable result: Boolean and missing native replies match their persisted daemon INFO records after the canonical store is reopened, with exact decimal request identity and no generic payload.
Evidence boundary: Host production filesystem, pipe and canonical serializer; Android permissions and operation freshness require separate target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml agent_state::tests::vehicle_state_read_rejects_nonboolean_and_untrusted_store -- --exact

Gate contract: Invalid fixed-state diagnostics fail closed.
Maps: Requirement `Fixed operational boolean state diagnostics are root-owned`; Scenario `The stored scalar is not a trusted boolean`.
Preconditions: Actual host state files contain string true, a number, malformed JSON, a symlink, a hardlink or unsafe permissions.
Observable result: Every diagnostic is unavailable without a value and existing native response representations remain unchanged.
Evidence boundary: Host secure-store checks and canonical persistence; SELinux and Android file substitution are not exercised.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml agent_state::tests::vehicle_state_write_logs_only_durable_matching_readback -- --exact

Gate contract: Durable write requires independent typed readback.
Maps: Requirement `Fixed operational boolean state diagnostics are root-owned`; Scenario `A fixed boolean is committed and read back`.
Preconditions: Production writes persist true and false in both fixed namespaces; the production readback helper also sees subsequently replaced secure bytes.
Observable result: Only successful matching boolean write/readback produces value proof, private file modes remain intact and changed disk bytes cannot prove the earlier requested value.
Evidence boundary: Host production atomic storage, secure reread and reopened canonical logs; power loss and target lifecycle remain separate gates.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml agent_state::tests::vehicle_state_write_failure_and_other_keys_emit_no_success -- --exact

Gate contract: Failed and unrelated writes disclose no fixed-state success.
Maps: Requirement `Fixed operational boolean state diagnostics are root-owned`; Scenario `A write fails or a different pair is submitted`.
Preconditions: Production routes receive an unsafe store, unauthorized owner, crossed fixed pair and unrelated scalar key.
Observable result: Fixed write failure is unavailable without a value and unauthorized or other pairs emit no new diagnostic.
Evidence boundary: Host route authorization and filesystem rejection; live endpoint attestation is outside this gate.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml tests::vehicle_state_diagnostic_context_uses_exact_tracker_and_desired_identity -- --exact

Gate contract: Diagnostic context remains bound to the resident registration.
Maps: Requirement `Fixed operational boolean state diagnostics are root-owned`; Scenario `Diagnostic metadata follows the resident endpoint`.
Preconditions: A daemon-loop host fixture has an attested tracker registration, a 19-digit desired revision and a resident generation distinct from active.
Observable result: Context contains exact starttime, decimal revision and resident generation/catalog; wrong PID, process or epoch omits starttime.
Evidence boundary: Host daemon context/tracker lookup; actual Android procfs and applied-agent revision are not proven.

### Requirement: Runtime status is generation-fenced

Asynchronous readiness and status SHALL include process, PID, generation, agent identity and monotonic document generation; stale generation or epoch updates SHALL be rejected.

#### Scenario: Status arrives from an older document generation

- **WHEN** a later accepted status already exists for that endpoint and agent
- **THEN** the stale update is ignored or rejected

# Gate: cargo test --manifest-path daemon/Cargo.toml control_plane::tests::stale_unknown_and_duplicate_status_fail_closed -- --exact
Gate contract: Runtime status generation fence.
Maps: Requirement `Runtime status is generation-fenced`; Scenario `Status arrives from an older document generation`.
Preconditions: The exact Rust test submits accepted, stale, unknown and duplicate status identities and generations.
Observable result: Only the correlated monotonic status advances state; stale and duplicate updates fail closed.
Evidence boundary: Host status parser and correlation logic; live agent reporting is not exercised.

### Requirement: Injection batches service tracked state endpoints between targets

Both synchronous new-target and deferred-retry injection batches SHALL drain capability-scoped tracked agent pipes and flush downlinks before the batch and after every individual target attempt. A skipped, rejected, rebound, or failed target SHALL NOT bypass that service boundary. The last target SHALL receive the same service boundary without waiting for the next daemon poll pass. This boundary does not guarantee the native state RPC deadline for requests arising during one blocking native injection.

#### Scenario: A later injection blocks while an earlier endpoint awaits state

- **WHEN** a tracked endpoint has a pending state request before a later target operation blocks longer than the RPC budget
- **THEN** the batch services the request before entering that operation and services the final target's pending reply before returning

#### Scenario: Deferred retries are removed or retained

- **WHEN** a deferred retry returns early without retention and a later retry is retained
- **THEN** removal does not bypass state service before the later retry, retention preserves that retry, and the last pending reply is serviced before returning

#### Scenario: A target returns early or no targets appeared

- **WHEN** a target operation returns early or the batch is empty
- **THEN** early return preserves the between-target and final service boundaries, and the empty batch still services tracked endpoints once

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime_loop::tests::target_batch_replies_before_late_blocking_target_and_after_last_target -- --exact
Gate contract: Between-target state service.
Maps: Requirement `Injection batches service tracked state endpoints between targets`; Scenario `A later injection blocks while an earlier endpoint awaits state`.
Preconditions: The production batch seam drives an isolated request/reply endpoint with a 100 ms client budget and a later target blocking for 150 ms.
Observable result: The earlier client receives its missing-state reply before timeout, and the final pending reply is serviced before the batch returns.
Evidence boundary: Host synchronous batch scheduling with an isolated endpoint; JNI, native injection duration, capability routing, and physical persistence are outside this gate.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime_loop::tests::target_batch_services_early_return_and_empty_batch -- --exact
Gate contract: Every batch exit retains service.
Maps: Requirement `Injection batches service tracked state endpoints between targets`; Scenario `A target returns early or no targets appeared`.
Preconditions: The production batch seam receives an early-return target followed by an ordinary target and an empty batch.
Observable result: Service precedes and follows every target including the last, and the empty batch services once.
Evidence boundary: Host batch control flow; target state transport is outside this gate.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime_loop::tests::retry_batch_services_removed_and_retained_entries -- --exact
Gate contract: Deferred retry service and retention.
Maps: Requirement `Injection batches service tracked state endpoints between targets`; Scenario `Deferred retries are removed or retained`.
Preconditions: The production batch seam drives an isolated retry map with an early-return removed entry followed by a retained entry, each producing a pending reply.
Observable result: The earlier reply is serviced before the retained retry, the final reply is serviced before return, and only the retained retry remains in the map.
Evidence boundary: Host batch scheduling and retry-map ownership; native retry duration and physical state transport are outside this gate.

### Requirement: Public persistent vehicle snapshots contain closed secure readbacks

Every production atomic status publication SHALL freshly read only `vehicle-drive-forced-ev`/`forced-ev-armed` and `vehicle-drive-pedestrian-warning`/`pedestrian-warning-armed` through the existing trusted state reader and project the results into `persistentVehicleState`. Each flag SHALL contain exactly `outcome=value` with a JSON boolean `value`, or `outcome=missing` or `outcome=unavailable` without a value. Nonboolean, corrupt, substituted or untrusted state SHALL remain unavailable. Snapshot `bootId` and `observedAtBootMs` SHALL describe the observation using the canonical boot identity and boot uptime, with null metadata when unavailable. Existing status authority fields SHALL bind release, manifest, generation and catalog. The public status projection SHALL not alter private state ownership, state modes, write routes or stock privilege policy. The typed management reader SHALL preserve the projection in the emitter's exact canonical field order, including the independent optional native failure diagnostic.

#### Scenario: Fixed persistent booleans are observed

- **WHEN** the two trusted fixed state files contain true and false
- **THEN** the secure readback contains the exact two boolean values, while missing, malformed and untrusted files retain their distinct nonvalue outcomes

#### Scenario: A secure snapshot is atomically published and inspected

- **WHEN** real fixed state files are read and the resulting typed snapshot is atomically published
- **THEN** trusted public status readback passes canonical management validation and the production diagnostic consumer retains the two booleans

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::persistent_projection_reads_fixed_booleans_and_preserves_missing_unavailable -- --exact

Gate contract: Closed persistent vehicle readback.

Maps: Requirement `Public persistent vehicle snapshots contain closed secure readbacks`; Scenario `Fixed persistent booleans are observed`.

Preconditions: Real host files with trusted local ownership and exact modes contain true, false, strings, corrupt JSON, null, arrays, wrong permissions or substituted symlinks.

Observable result: Only secure booleans have values and missing remains distinct from unavailable.

Evidence boundary: Host trusted filesystem reader; Android SELinux and reboot behavior are separate.

# Gate: cargo test --manifest-path daemon/Cargo.toml management::tests::persistent_projection_real_io_to_production_consumer -- --ignored --exact

Gate contract: Closed persistent vehicle readback.

Maps: Requirement `Public persistent vehicle snapshots contain closed secure readbacks`; Scenario `A secure snapshot is atomically published and inspected`.

Preconditions: Real 0600 boolean files under a 0700 host state directory, fixture-only boot metadata because the macOS host lacks Android /proc identity, and the product Node consumer installed beside the native repository.

Observable result: Actual secure reads, atomic 0644 publication, trusted public read, typed canonical management validation and the production Node consumer preserve true and false.

Evidence boundary: Composed host filesystem and consumer behavior; boot metadata is an explicit host test seam and not an Android observation.

# Unverified: Public persistent snapshot runtime identity

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

### Unverified: Public persistent snapshot runtime identity

Maps: Requirement `Public persistent vehicle snapshots contain closed secure readbacks`; both scenarios.

Unavailable observation: Ordinary packaged diagnostics after a guest reboot with actual boot identity and uptime, public status readability while private state is denied, and unchanged canonical management health.

Reason: This stage performs no device run or Android build.

Required environment or artifact: One immutable kit after reboot with raw ordinary diagnostics, exact root-owned status, actual current boot identity and uptime, and independent OEM readbacks.

### Unverified: Target media selection JNI delivery

Maps: Requirement `Conditional media cleanup preserves a newer selection`; Scenarios `New selection precedes stale cleanup`, `State-pipe conditional clear is admitted`, and `Conditional clear has malformed or unowned input`.
Unavailable observation: Actual Java native registration, device reply timing, cross-process catalog invalidation and UI adoption.
Reason: The production implant host test is Linux-only and skips on this macOS host; host state/pipe tests do not execute device JNI.
Required environment or artifact: The source-bound installer and supported Android host, followed by separate physical media, steering and phone-call acceptance.
