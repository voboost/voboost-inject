# Runtime observability specification

## Purpose

Define structured runtime logging, bounded persistence and safe rotation behavior.

## Requirements

### Requirement: Uplink log batches retain explicit durability boundaries

Within one bounded uplink drain, canonical records SHALL receive their normal sequence, receive timestamp and source identity immediately and SHALL be appended in order. The drain SHALL synchronize the exact appended inode before returning; nested drain scopes SHALL synchronize at the outer boundary. Ordinary durable append, including app-batch processing, SHALL synchronize the preceding appended prefix. Rotation SHALL synchronize a pending prefix before publishing the old inode. No scope SHALL retain the canonical mutex across record routing or start another runtime thread. Leaf substitution SHALL be rejected before appending or synchronizing another inode; a failed synchronization SHALL remain unavailable evidence.

#### Scenario: Several records arrive in one bounded drain

- **WHEN** canonical records are appended in nested drain scopes
- **THEN** their sequence and physical lines remain ordered and one synchronization completes at the outer boundary

#### Scenario: Durable append or rotation interrupts a drain batch

- **WHEN** an ordinary durable record or rotation follows deferred records
- **THEN** the preceding prefix is synchronized before the durable append returns or the old inode is published

#### Scenario: The active leaf is replaced before batch completion

- **WHEN** the name points to another inode or a link after deferred append
- **THEN** synchronization and further append reject the replacement without changing its bytes

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::uplink_batch_syncs_once_and_preserves_order -- --exact
Gate contract: Uplink log batches retain explicit durability boundaries.
Maps: Requirement `Uplink log batches retain explicit durability boundaries`; Scenario `Several records arrive in one bounded drain`.
Preconditions: Actual production append and scoped batching use a trusted host directory.
Observable result: Nested scopes retain ordered canonical lines and complete one synchronization at the outer boundary.
Evidence boundary: Host filesystem and production durability calls; Android storage latency and process recreation remain runtime gates.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::uplink_batch_durable_append_and_rotation_flush_prior_prefix -- --exact
Gate contract: Uplink log batches retain explicit durability boundaries.
Maps: Requirement `Uplink log batches retain explicit durability boundaries`; Scenario `Durable append or rotation interrupts a drain batch`.
Preconditions: A trusted real file has deferred records before ordinary append or rotation.
Observable result: The prior prefix is synchronized, sequence order is retained and rotation publishes complete old records.
Evidence boundary: Host filesystem; sudden power loss is not simulated.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::uplink_batch_rejects_replaced_leaf_without_modifying_it -- --exact
Gate contract: Uplink log batches retain explicit durability boundaries.
Maps: Requirement `Uplink log batches retain explicit durability boundaries`; Scenario `The active leaf is replaced before batch completion`.
Preconditions: The active leaf is replaced after a deferred production append.
Observable result: Flush and append reject the replacement and its bytes remain unchanged.
Evidence boundary: Host inode and link checks; Android SELinux labels are not exercised.

### Requirement: Runtime status identity is explicit and current

The daemon SHALL serialize `status.json` as compact canonical schema-1 JSON with one terminal LF. Its exact top-level fields SHALL be `schemaVersion`, canonical product SemVer string `releaseIdentity`, exact active `manifestSha256`, current `generationId`, `catalogSha256`, `startupMode`, readiness flags and injections. It SHALL NOT publish a separate daemon component version or the legacy nested channel/base/beta identity. `startupMode` SHALL be `interface`, `hidden`, or `none`; `killed=true` is intentional only with `none`, while the other two modes require false. The obsolete unassigned `manifest` alias SHALL not be emitted. Unknown fields and a missing or non-current schema SHALL fail closed at strict consumers. For intentional `none` with `killed=true`, installed management SHALL accept retained injection observations without requiring injection liveness; canonical shape, current authority, ready state, kill-switch agreement, panic quarantine and package-execution admission SHALL remain strict. Interface and hidden health SHALL continue to require healthy injection observations.

#### Scenario: Status is serialized for a product beta

- **WHEN** the daemon serializes its verified active `1.0.0-beta1` product identity
- **THEN** the document contains `schemaVersion: 1`, the exact flat SemVer, manifest digest and startup mode, with no component version or `manifest` alias

#### Scenario: A final none status retains inactive target observations

- **WHEN** the current ready final status has `startupMode=none`, `killed=true` and retained waiting, failed, degraded or quarantined injection observations
- **THEN** injection liveness does not degrade management health, while interface and hidden reject the same unhealthy observations

#### Scenario: A final none status violates document admission

- **WHEN** none status has invalid canonical bytes, authority, injection shape, readiness, kill-switch agreement or panic quarantine
- **THEN** installed management rejects the document despite intentional inactivity

# Gate: cargo test --manifest-path daemon/Cargo.toml status::tests::serialization_preserves_agent_metadata -- --exact

Gate contract: Runtime status identity is explicit and current.
Maps: Requirement `Runtime status identity is explicit and current`; Scenario `Status is serialized for a product beta`.
Preconditions: The exact Rust test serializes the production status type with a verified product identity, manifest digest and one injection record.
Observable result: Parsing observes schema version 1, exact flat product identity, digest and startup mode; bytes are compact with terminal LF and omit component/manifest aliases.
Evidence boundary: Host serialization only; device publication and installer transport are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml status::tests::status_emitter_matches_the_product_wire_golden_bytes -- --exact

Gate contract: Runtime status identity is explicit and current.
Maps: Requirement `Runtime status identity is explicit and current`; Scenario `Status is serialized for a product beta`.
Preconditions: The product-owned `interface` and `none` status golden bytes are mirrored into the component repository.
Observable result: The production status emitter serializes byte-identically for both modes, including correlated product, manifest, generation and catalog identities, injection counters and intentional kill-switch state.
Evidence boundary: Cross-repository host serialization only; product mirror equality and Android publication are separate gates.

# Gate: cargo test --manifest-path daemon/Cargo.toml management::tests::management_consumes_the_product_status_golden_bytes -- --exact

Gate contract: Runtime status identity is explicit and current.
Maps: Requirement `Runtime status identity is explicit and current`; Scenario `Status is serialized for a product beta`.
Preconditions: The exact two product status documents are present in the byte-identical component mirror.
Observable result: The production installed-management verifier accepts both only against matching product, manifest, generation, catalog and startup identities.
Evidence boundary: Component host consumer interop only; resident process observation remains unverified.

# Gate: cargo test --manifest-path daemon/Cargo.toml management::tests::stopped_none_status_accepts_inactive_targets_without_weakening_running_modes -- --exact

Gate contract: Intentional none retains observations without requiring liveness.
Maps: Requirement `Runtime status identity is explicit and current`; Scenario `A final none status retains inactive target observations`.
Preconditions: The host test supplies correlated ready documents for none, interface and hidden with waiting, failed, degraded and quarantined observations.
Observable result: Only intentional none accepts each inactive observation under strict health verification.
Evidence boundary: Host management verifier only; Android final publication and service shutdown require runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml management::tests::stopped_none_status_still_requires_trusted_valid_ready_document -- --exact

Gate contract: Intentional inactivity preserves strict document admission.
Maps: Requirement `Runtime status identity is explicit and current`; Scenario `A final none status violates document admission`.
Preconditions: The host test mutates authority fields, shape, readiness, killed, panic and canonical bytes of a none document.
Observable result: Each invalid document is rejected.
Evidence boundary: Host byte verifier only; filesystem provenance and APK execution receipt admission are separate gates.

### Requirement: Logs are canonical, structured and bounded

The daemon SHALL assign one global monotonic sequence and receive timestamp to every accepted daemon, agent, or app record. Source identity SHALL come from the internal component, bound agent pipe, or verified app peer credentials and SHALL NOT be trusted from producer data. Only `debug`, `info`, and `error` are valid. Each producer API SHALL keep its declared level independent of the debug collection threshold: enabling debug SHALL NOT relabel an info record, and disabling debug SHALL only omit debug records. A canonical record SHALL not exceed 16 KiB. The root-owned log SHALL retain independent debug, info and error tiers, each with at most sixteen JSONL segments of at most 8 MiB and 128 MiB total. The debug tier SHALL retain all levels, the info tier SHALL retain info and error, and the error tier SHALL retain errors. Their combined disk payload SHALL remain bounded by 384 MiB; canonical queries and exports SHALL merge duplicate sequences. Unsafe filesystem objects SHALL put logging into a bounded error state without blocking runtime work.

#### Scenario: An agent floods log messages

- **WHEN** the log sink reaches its configured bounds
- **THEN** rotation and retention keep disk use bounded without blocking other endpoints

#### Scenario: A log path is replaced

- **WHEN** the configured directory or a daily or rotated leaf is substituted with a symlink, hard link or foreign inode
- **THEN** append, rotation and retention do not follow or modify that substitution

#### Scenario: Concurrent writes reach the rotation bound

- **WHEN** multiple daemon and agent records arrive while the active file becomes full
- **THEN** write and rotation are serialized and every accepted record remains one complete JSON physical line

#### Scenario: Debug collection changes at runtime

- **WHEN** debug collection is enabled or disabled around the same daemon info call
- **THEN** the accepted info record remains `info`, debug records remain `debug`, and no `warning` level is created

# Gate: cargo test --manifest-path daemon/Cargo.toml log::tests::level_mapping_never_relabels_info_as_debug -- --exact

Gate contract: Logs are canonical, structured and bounded.
Maps: Requirement `Logs are canonical, structured and bounded`; Scenario `Debug collection changes at runtime`.
Preconditions: The exact host test evaluates every internal daemon log tag through the production level mapper.
Observable result: Error, info, and debug map to their declared canonical levels with no warning or threshold-dependent relabeling.
Evidence boundary: Host pure mapping only; target log production and retention are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_log::tests::exact_record_bound_is_accepted_and_n_plus_one_is_discarded -- --exact
Gate contract: Logs are canonical, structured and bounded.
Maps: Requirement `Logs are canonical, structured and bounded`; Scenario `An agent floods log messages`.
Preconditions: The exact Rust test feeds records at N and N+1 bytes followed by a valid record.
Observable result: The N-byte record is accepted, the N+1 record is discarded through its newline and the following record remains available.
Evidence boundary: Host stream framing only; disk retention and Android agent transport are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml log::tests::rotation_is_serialized_with_concurrent_appends -- --exact
Gate contract: Logs are canonical, structured and bounded.
Maps: Requirement `Logs are canonical, structured and bounded`; Scenarios `An agent floods log messages` and `Concurrent writes reach the rotation bound`.
Preconditions: The exact Rust test starts with an almost-full bounded file and releases two concurrent appenders at one barrier.
Observable result: Rotation preserves the old bytes once and both accepted records remain complete JSON physical lines in the current file.
Evidence boundary: Host filesystem and in-process mutex behavior; device storage pressure and process crashes are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml log::tests::append_rejects_symlink_hardlink_and_foreign_metadata -- --exact
Gate contract: Logs are canonical, structured and bounded.
Maps: Requirement `Logs are canonical, structured and bounded`; Scenario `A log path is replaced`.
Preconditions: The exact Rust test substitutes the active log leaf with symlink, hard-link and foreign-metadata cases.
Observable result: Append rejects every substituted object without modifying its bytes.
Evidence boundary: Host filesystem inode and metadata checks; Android SELinux labels are not exercised.

### Requirement: Queued desired snapshot identity is root-owned

After successful admission of an ordinary desired `D` frame or the atomic confirmed `D` plus `A` group, the daemon SHALL append one canonical `info` record with daemon source, no source ID, component `runtime` and message `desired-snapshot-queued`. Its string fields SHALL identify the process, emitted generation and catalog, exact decimal `documentGeneration`, lowercase SHA-256 of the exact UTF-8 desired document bytes, `frames` as `D` or `D+A`, and canonical source plan language. Hashing SHALL exclude the frame prefixes and terminal LF and SHALL NOT reserialize the document. A confirmed group SHALL also include the exact decimal request ID and SHALL bind both frames to the same document bytes. Queue rejection SHALL emit no successful queued identity record and SHALL not add a pending acknowledgement.

The optional string fields `targetPid`, `targetStarttime` and `endpointEpoch` SHALL be present together only for the daemon tracker's exact process and downlink registration; starttime SHALL come from the attested registration. `profileLanguage` and `effectiveLanguage` SHALL be present together only when the emitted Settings profile exists and SHALL equal its language. The record SHALL contain metadata only, without the raw desired document, agent configuration, private option values or secrets, and SHALL use the existing bounded canonical log collection without another command or RPC. Queue admission evidence SHALL NOT claim that the target has applied the snapshot.

#### Scenario: An ordinary desired snapshot enters the queue

- **WHEN** an ordinary desired frame with a 19-digit revision above 2^53 is successfully admitted to a tracked endpoint
- **THEN** one daemon INFO record contains the exact revision string, exact-byte document digest, current generation and catalog identities, language and attested target registration, with no private payload

#### Scenario: A confirmed mutation queues D and A atomically

- **WHEN** the runtime desired frame and correlated mutation acknowledgement are successfully admitted as one group
- **THEN** both carry the same exact document bytes and one record binds that document digest and exact revision to the request ID and `D+A`

#### Scenario: The endpoint queue rejects delivery

- **WHEN** an invalid or capacity-poisoned endpoint rejects an ordinary or confirmed enqueue
- **THEN** no queued identity record or pending acknowledgement is created

#### Scenario: A downlink descriptor belongs to a different process

- **WHEN** a successful desired enqueue cannot match the exact process and descriptor registration
- **THEN** the queued document metadata omits all three target identity fields

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::queued_desired_snapshot_has_exact_canonical_identity -- --exact

Gate contract: Queued desired snapshot identity is root-owned.
Maps: Requirement `Queued desired snapshot identity is root-owned`; Scenario `An ordinary desired snapshot enters the queue`.
Preconditions: The production daemon loop enqueues a desired document with revision 1777777777777777779 through a real host pipe while canonical logging uses a scoped secure host directory.
Observable result: The persisted canonical record has daemon INFO identity, exact decimal revision, exact observed frame document hash, exact finite metadata fields, languages and the bound PID/starttime/epoch; reordering JSON keys changes the hash.
Evidence boundary: Production queue and canonical serializer on the host; target delivery, UI application, Android procfs and device behavior are not proven.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::queued_confirmed_update_proof_matches_both_exact_frames -- --exact

Gate contract: Queued desired snapshot identity is root-owned.
Maps: Requirement `Queued desired snapshot identity is root-owned`; Scenario `A confirmed mutation queues D and A atomically`.
Preconditions: The production confirmed-update enqueue sends one desired document through a real host pipe with request ID u64::MAX and revision 1777777777777777779.
Observable result: Drained D and A document bytes are identical and match one persisted metadata record, including exact string request ID, revision and hash.
Evidence boundary: Host daemon queue and canonical persistence only; target acknowledgement and UI rendering are separate observations.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::rejected_desired_queues_emit_no_proof_or_pending_ack -- --exact

Gate contract: Queued desired snapshot identity is root-owned.
Maps: Requirement `Queued desired snapshot identity is root-owned`; Scenario `The endpoint queue rejects delivery`.
Preconditions: The host test presents an invalid descriptor and a real endpoint poisoned by queue-capacity rejection to both production enqueue paths.
Observable result: Every enqueue fails, the canonical log contains no queued identity and the daemon has no pending acknowledgement.
Evidence boundary: Host queue rejection and logger persistence only; Android endpoint failures are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::queued_desired_snapshot_omits_unmatched_target_identity -- --exact

Gate contract: Queued desired snapshot identity is root-owned.
Maps: Requirement `Queued desired snapshot identity is root-owned`; Scenario `A downlink descriptor belongs to a different process`.
Preconditions: A real host pipe is registered under a different process before a successful production desired enqueue.
Observable result: The queued metadata record omits target PID, starttime and epoch together while retaining the actual desired document identity.
Evidence boundary: Host tracker binding and persisted canonical record only; real Android process identity attestation is a separate gate.

### Requirement: App ingress is peer-bound and replay-safe

The app endpoint SHALL accept only a peer bound to `ru.voboost`, reject producer-supplied source identity, validate at most 64 records and 256 KiB per batch, durably persist both canonical records and the 128-bit batch ID before returning the matching ACK, and return the same ACK without duplicates for a replay. Every accepted socket SHALL have bounded read and write deadlines so a client that connects and stops mid-frame cannot block later app batches.

#### Scenario: A producer spoofs app identity or replays a batch

- **WHEN** peer identity does not match or an accepted batch ID is submitted again
- **THEN** mismatch is rejected and replay returns the original ACK without another canonical record

#### Scenario: The app stops midway through a batch

- **WHEN** an accepted local connection sends only part of its length or body and then remains open
- **THEN** the daemon closes that connection after the fixed deadline and the listener remains available for later batches

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::spoof_and_replay_are_rejected_or_idempotent -- --exact

Gate contract: App ingress is peer-bound and replay-safe.
Maps: Requirement `App ingress is peer-bound and replay-safe`; Scenario `A producer spoofs app identity or replays a batch`.
Preconditions: The host fixture supplies one rejecting and one accepting peer verifier, then submits the accepted batch twice.
Observable result: The spoofed peer is rejected, both accepted calls return the same batch ID, and the canonical query contains one record.
Evidence boundary: Host verifier seam and descriptor-backed storage; Android SO_PEERCRED and packages.list are covered only structurally until an emulator or device gate runs.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::app_peer_files_reject_n_plus_one_before_unbounded_allocation -- --exact

Gate contract: App ingress is peer-bound and replay-safe.
Maps: Requirement `App ingress is peer-bound and replay-safe`; Scenario `A producer spoofs app identity or replays a batch`.
Preconditions: A host file contains exactly N and then N+1 bytes for the production bounded reader used by cmdline and packages.list.
Observable result: N is returned intact and N+1 is rejected without retaining bytes beyond the bound.
Evidence boundary: Host file reader only; Android procfs and PackageManager publication remain device evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::partial_app_frame_times_out_without_blocking_forever -- --exact

Gate contract: App ingress is peer-bound and replay-safe.
Maps: Requirement `App ingress is peer-bound and replay-safe`; Scenario `The app stops midway through a batch`.
Preconditions: A host Unix socket peer writes an incomplete frame and retains the connection while the production frame reader uses a short injected deadline.
Observable result: The reader returns a timeout error within the bound instead of waiting for peer close.
Evidence boundary: Host Unix socket timing only; Android listener scheduling and SELinux socket access remain emulator or device evidence.

### Requirement: Queries and follows are bounded and idempotent

`logs-query` SHALL return at most 200 filtered records and 256 KiB using a sequence-only cursor. `logs-follow` SHALL start at a sequence and `logs-stop` SHALL release it. Repeated request IDs SHALL return the cached response or an explicit stale result; invalid filters and bounds SHALL not change state.

The injected runtime SHALL carry these operations as capability-scoped `Q` frames over the existing endpoint-bound uplink and downlink. It SHALL preserve the existing `B/L/W/R/E/S` uplink and `D/A/R` downlink meanings. Only an endpoint whose verified resident set contains `logs` may issue the operations, and every response SHALL also fit the bounded downlink frame.

The resident endpoint SHALL authorize the read capability only. A non-empty agent-ID filter SHALL be validated against the complete selected set from the same authenticated active catalog, not only against agents resident in the Settings process. An absent, unselected, malformed, or foreign-catalog agent ID SHALL be rejected before query state changes.

#### Scenario: A query exceeds a response boundary

- **WHEN** the next matching record would exceed 200 records or 256 KiB
- **THEN** the response stops before that record and returns the last included sequence as cursor

#### Scenario: An endpoint without the logs capability submits a query

- **WHEN** the verified resident agent set does not contain `logs`
- **THEN** the daemon rejects the request before query state or a downlink response is created

#### Scenario: Logs filters an agent resident in another process

- **WHEN** the Settings endpoint contains `logs` and requests a selected keyboard or launcher agent ID that is not resident in Settings
- **THEN** the daemon accepts the filter through the same active catalog while still rejecting an absent or unselected ID

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::agent_rpc_is_capability_scoped_and_replay_safe -- --exact

Gate contract: Queries and follows are bounded and idempotent.
Maps: Requirement `Queries and follows are bounded and idempotent`; Scenario `An endpoint without the logs capability submits a query`.
Preconditions: A host fixture creates one daemon record and submits the same request with denied and allowed resident sets.
Observable result: The denied endpoint is rejected, an authorized replay returns identical bytes, and stop releases the request.
Evidence boundary: Host RPC dispatch and storage only; injected Android JNI scheduling requires emulator or device evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::agent_filter_uses_selected_catalog_not_settings_resident_set -- --exact

Gate contract: Queries and follows are bounded and idempotent.
Maps: Requirement `Queries and follows are bounded and idempotent`; Scenario `Logs filters an agent resident in another process`.
Preconditions: A host fixture gives the Settings endpoint resident `logs` capability and a larger selected active-catalog set containing an agent from another process.
Observable result: The selected cross-process ID is accepted while an absent ID is rejected before query state changes.
Evidence boundary: Host RPC authorization only; physical cross-process log production and Settings rendering require emulator or device evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::query_bounds_filters_and_stop -- --exact

Gate contract: Queries and follows are bounded and idempotent.
Maps: Requirement `Queries and follows are bounded and idempotent`; Scenario `A query exceeds a response boundary`.
Preconditions: A host fixture appends 210 matching records and requests a page of 200, then creates and stops one subscription.
Observable result: The page contains exactly 200 records, the cursor is the last included sequence, and a second stop reports no live subscription.
Evidence boundary: Host storage and registry only; injected Android JNI scheduling requires emulator or device evidence.

### Requirement: Fixed export is bounded and leaves no device residue

The exact `voboost-daemon --logs` mode SHALL accept no extra argument, verify its executable role and fixed log authority, and emit only a `VBOOSTLOG1` stream containing bounded JSONL plus runtime context. It SHALL work without a resident daemon, SHALL not read app-private batches, SHALL emit at most 400 MiB of payload plus the fixed protocol envelope, and SHALL create no archive or temporary export tree on the device.

#### Scenario: The resident daemon is unavailable

- **WHEN** the signed executable is invoked with exactly `--logs`
- **THEN** it exports previously accepted root-owned segments and a daemon-unavailable context without reading app-private storage or leaving export residue

#### Scenario: Sixteen 8 MiB retained segments need collection

- **WHEN** the producer encodes a payload larger than the former 32 MiB export limit
- **THEN** the 400 MiB payload budget accepts it, and the 32 MiB app ledger bound stays unchanged

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::export_is_bounded_and_has_fixed_magic -- --exact

Gate contract: Fixed export is bounded and leaves no device residue.
Maps: Requirement `Fixed export is bounded and leaves no device residue`; Scenario `The resident daemon is unavailable`.
Preconditions: The host fixture encodes bounded records and a non-resident context, then attempts one oversized payload.
Observable result: The valid stream begins with exact `VBOOSTLOG1` magic and the oversized payload is rejected without creating a device-side archive.
Evidence boundary: Host encoder only; signed `/proc/self/exe`, root-owned Android segments, and daemon-unavailable execution require emulator or device evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::diagnostic_retention_and_export_budgets_are_coherent -- --exact

Gate contract: Fixed export is bounded and leaves no device residue.
Maps: Requirement `Fixed export is bounded and leaves no device residue`; Scenario `Sixteen 8 MiB retained segments need collection`.
Preconditions: The host test checks exact segment count, segment byte bound, payload bound, and ledger bound, then encodes more than 32 MiB.
Observable result: The 400 MiB payload budget accepts it, and the 32 MiB app ledger bound stays unchanged.
Evidence boundary: Host encoder and budget contract; device memory and download timing require target evidence.

### Requirement: Injection helper failures are available in normal exported logs

The resident daemon SHALL capture at most2048 stderr input bytes from its signed helper with nonblocking reads and SHALL preserve unconditional helper termination/reaping on IPC failure. Error/info-visible records SHALL include the helper exit status and the precise reported failure phase/reason; debug records SHALL include bounded target identity and parent argv evidence when debug logging is enabled. Bootstrap contents and credentials SHALL NOT be logged. Both channels SHALL use the ordinary daemon log/export, without requiring an additional utility or a separate file read to diagnose the failure.

#### Scenario: A helper rejects its authenticated parent

- **WHEN** parent validation fails before injection
- **THEN** normal exported error records include authentication failure and helper exit evidence, while debug provides the bounded argv comparison evidence

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::helper_stderr_preserves_failure_reason_with_a_finite_safe_bound -- --exact

Gate contract:
Maps: Requirement `Injection helper failures are available in normal exported logs`; Scenario `A helper rejects its authenticated parent`.
Preconditions: Error text, control bytes, invalid UTF8 and oversized helper stderr are supplied to the production bounded reader.
Observable result: The phase/reason is retained, control bytes are neutralized and input remains bounded.
Evidence boundary: Host reader; actual helper-to-export integration requires target verification.

### Requirement: Optional LSPlant hook stage diagnostics

The pinned parent-owned LSPlant patch SHALL expose an optional null-by-default stage callback setter without changing InitInfo ABI, LOG_DISABLED or hook/suspend semantics. The callback SHALL report only fixed stage, PID, TID and elapsed milliseconds through the existing ordinary implant record channel. The diagnostic writer SHALL try the record mutex and require a nonblocking descriptor; mutex contention, unavailable channel or a full pipe SHALL drop the observation rather than wait for a peer. Missing stage records are unavailable evidence and do not prove that the stage was not reached.

#### Scenario: Stage callback is absent

- **WHEN** no callback is registered
- **THEN** diagnostic scopes emit no callback and preserve hook behavior

#### Scenario: Stage callback is registered

- **WHEN** a hook enters DEX/JNI construction, GC critical construction, SuspendAll construction and mutation
- **THEN** fixed begin/end markers identify those boundaries with PID/TID and elapsed time without method arguments, JNI calls or Android log output from the callback

#### Scenario: A frozen peer owns the record mutex or the pipe is full

- **WHEN** the diagnostic writer cannot acquire the mutex immediately or write the nonblocking record
- **THEN** it drops the observation and missing markers remain unavailable evidence

# Gate: make test-lsplant-stage-callback

Gate contract: Optional LSPlant hook stage diagnostics.
Maps: Requirement `Optional LSPlant hook stage diagnostics`; Scenarios `Stage callback is absent`, `Stage callback is registered`, `A frozen peer owns the record mutex or the pipe is full`.
Preconditions: Exact SHA-verified prepared LSPlant source supplies the actual callback/scope definitions to the host test; source boundaries are checked around unchanged constructors; the production diagnostic record writer sees a mutex held by another thread, a blocking descriptor and a full nonblocking pipe.
Observable result: Null callback emits nothing, registration emits fixed ordered markers with monotonic elapsed values, current scope retains its captured callback, the ordinary record contains only stage/PID/TID/elapsed, and contention/full/unavailable pipes return without waiting.
Evidence boundary: Host callback/writer execution and both ABI build; actual target markers, ART lock owner and Launcher crash cause remain unverified. Dropped records and cleanup SIGSTOP origin cannot establish whether an inner stage was reached.

### Requirement: Native post-init diagnostics dispatch to both UI hosts

After successful canonical Java initialization, the native handoff SHALL dispatch the optional main-thread diagnostic for exactly Launcher and Settings, passing the attested self-process name unchanged. It SHALL not dispatch for null or other process names. Missing or throwing optional Java diagnostics SHALL leave canonical initialization and desired/ACK setup unchanged. The native selector and callback dispatch SHALL share the production helper exercised by the host gate.

#### Scenario: Successful UI-host initialization reaches the optional Java seam

- **WHEN** the native path has completed canonical initialization for Launcher or Settings
- **THEN** its exact process name reaches the diagnostic callback once

#### Scenario: Another process is not a diagnostic target

- **WHEN** the selector receives another process name or null
- **THEN** no diagnostic callback is invoked

# Gate: make test-main-thread-snapshot-scope

Gate contract: Native UI-host diagnostic dispatch.

Maps: Requirement `Native post-init diagnostics dispatch to both UI hosts`; Scenarios `Successful UI-host initialization reaches the optional Java seam`, `Another process is not a diagnostic target`.

Preconditions: The host invokes the same callback-dispatch helper used after native init.

Observable result: Exact Launcher/Settings callback counts and attribution, with no null/foreign dispatch.

Evidence boundary: Host native dispatch only; real JNI and VM stack records require target evidence.

### Requirement: Accepted status belongs to the current registered endpoint

Each injection's optional `currentEndpoint` SHALL bind `targetPid`, `targetStarttime`, `endpointEpoch`, registration-frozen `generationId` and `catalogSha256`, and `desiredDocumentGeneration`. Integer identities SHALL use canonical decimal strings. Its optional `acceptedStatus` SHALL contain the actual accepted S `documentGeneration` and root receipt (`sequence`, `daemonPid`, `daemonStarttime`, `bootId`); the accepted revision SHALL equal the desired revision. Pending or unavailable receipt evidence SHALL omit `acceptedStatus`, rather than manufacture an acknowledgement. Resident generation SHALL remain the registered generation during passive cutover, independently of the top-level active generation.

#### Scenario: A process reconnects with the same PID and a new endpoint epoch

- **WHEN** the registration is replaced while the old endpoint has an accepted S
- **THEN** the old cached S cannot make the new endpoint active and a new accepted S is required

#### Scenario: Registration or desired revision changes

- **WHEN** PID, starttime, catalog, generation or desired revision differs from the cached S binding
- **THEN** the cached acknowledgement is invalidated

#### Scenario: Status is pending or its root receipt is unavailable

- **WHEN** no current S with a root receipt is available
- **THEN** the endpoint projection omits `acceptedStatus` and desired revision alone does not establish an acknowledgement

# Gate: cargo test --manifest-path daemon/Cargo.toml control_plane::tests::exact_endpoint_requires_new_ack_after_rebind_and_retains_receipt_without_logs -- --exact

Gate contract: Accepted status belongs to the current registered endpoint.
Maps: Requirement `Accepted status belongs to the current registered endpoint`; Scenario `A process reconnects with the same PID and a new endpoint epoch`.
Preconditions: Production registry receives exact endpoint bindings and accepted S with controlled root receipt availability.
Observable result: Replacement waits for its own S, retained acknowledgement does not depend on historical log retention, and the new epoch requires its own accepted S.
Evidence boundary: Host registry and projection; Android reconnect and vehicle application require runtime evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml control_plane::tests::unavailable_root_receipt_keeps_current_functional_ack_without_attestation -- --exact

Gate contract: Accepted status belongs to the current registered endpoint.
Maps: Requirement `Accepted status belongs to the current registered endpoint`; Scenario `Status is pending or its root receipt is unavailable`.
Preconditions: The actual registry accepts S without an available root receipt.
Observable result: Functional S remains bound to its endpoint, but accepted receipt evidence is absent and a new epoch cannot reuse it.
Evidence boundary: Host registry; device publication remains a runtime gate.

# Gate: cargo test --manifest-path daemon/Cargo.toml status::tests::current_endpoint_serializes_exact_producer_fixture_and_clears_with_generic_events -- --exact

Gate contract: Accepted status belongs to the current registered endpoint.
Maps: Requirement `Accepted status belongs to the current registered endpoint`; Scenario `Status is pending or its root receipt is unavailable`.
Preconditions: The real status serializer receives accepted and pending endpoint projections.
Observable result: Exact producer fixture fields are retained, pending omits acceptedStatus, and generic events clear the projection.
Evidence boundary: Host serializer, not Android publication.

# Gate: cargo test --manifest-path daemon/Cargo.toml control_plane::tests::pid_starttime_catalog_generation_and_desired_revision_changes_invalidate_ack -- --exact

Gate contract: Accepted status belongs to the current registered endpoint.
Maps: Requirement `Accepted status belongs to the current registered endpoint`; Scenario `Registration or desired revision changes`.
Preconditions: Accepted S is followed by each changed binding field.
Observable result: Every changed binding invalidates the old acknowledgement.
Evidence boundary: Host control-plane execution, not device process lifecycle acceptance.

### Requirement: Routed log context does not claim applied state

Root-attributed L metadata SHALL carry the registered endpoint identity and `desiredDocumentGeneration`; available `daemonPid`, `daemonStarttime` and `bootId` SHALL identify the same root incarnation used by accepted S receipts. These fields SHALL NOT turn desired state or an agent message into an applied acknowledgement. Missing root incarnation SHALL remain unavailable correlation evidence.

#### Scenario: A routed message supplies misleading identity text

- **WHEN** the daemon constructs metadata for an owned endpoint
- **THEN** trusted context identifies the daemon incarnation and desired revision independently of the message, without an applied revision field

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_log::tests::log_authority_binds_same_daemon_incarnation_and_desired_context_without_claiming_ack -- --exact

Gate contract: Routed log context does not claim applied state.
Maps: Requirement `Routed log context does not claim applied state`; Scenario `A routed message supplies misleading identity text`.
Preconditions: The real metadata constructor receives an owned endpoint and actual root identity provider.
Observable result: Root fields match accepted-S incarnation, preserve desired context and omit an applied acknowledgement; unavailable identity is omitted.
Evidence boundary: Host metadata construction; fresh Android log sampling and ordering remain runtime gates.

### Requirement: Resident diagnostics have an independent bounded budget

Trusted resident status readers SHALL admit at most 1048576 bytes and SHALL reject oversized or truncated JSON without truncating identity fields. The beta1 serializer budget SHALL include all 53 finite catalog targets, maximum allowed details and endpoint receipts. The release budget check SHALL compare the actual generated catalog to its reviewed inventory. Boot observations SHALL retain their separate 16384-byte payload bound.

#### Scenario: Normal management reads a large current status

- **WHEN** the real beta1 maximum fixture or a status at the one-MiB boundary is read
- **THEN** current endpoint identity survives ordinary management parsing, while one extra byte and truncated input are rejected

#### Scenario: The release catalog differs from the reviewed beta1 inventory

- **WHEN** the budget test receives the actual generated catalog
- **THEN** inventory drift is rejected instead of silently extending the reviewed budget

# Gate: cargo test --manifest-path daemon/Cargo.toml management::tests::resident_status_one_mib_boundary_is_inclusive_and_truncation_fails_closed -- --exact

Gate contract: Resident diagnostics have an independent bounded budget.
Maps: Requirement `Resident diagnostics have an independent bounded budget`; Scenario `Normal management reads a large current status`.
Preconditions: Production trusted reader receives exact-boundary, oversized and truncated files.
Observable result: The inclusive boundary is accepted and oversized or truncated status fails closed.
Evidence boundary: Host trusted-file reader; installer/device transport remains independently verified.

# Gate: cargo test --manifest-path daemon/Cargo.toml management::tests::resident_status_full_beta1_fixture_roundtrips_current_endpoint_contract -- --exact

Gate contract: Resident diagnostics have an independent bounded budget.
Maps: Requirement `Resident diagnostics have an independent bounded budget`; Scenario `Normal management reads a large current status`.
Preconditions: Actual serializer-generated maximum beta1 fixture enters the ordinary management parser.
Observable result: Strict typed parsing and canonical reserialization retain endpoint and accepted receipt fields.
Evidence boundary: Host parser, not a device installation or restore claim.

# Gate: cargo test --manifest-path daemon/Cargo.toml status::tests::current_signed_beta1_inventory_fits_resident_budget -- --exact

Gate contract: Resident diagnostics have an independent bounded budget.
Maps: Requirement `Resident diagnostics have an independent bounded budget`; Scenario `The release catalog differs from the reviewed beta1 inventory`.
Preconditions: The release pipeline sets `VOBOOST_ENDPOINT197_CATALOG_PATH` to its actual generated catalog path; signature verification is a separate existing gate.
Observable result: Exact reviewed inventory and maximum serializer fixture fit one MiB; changed catalog bytes are rejected.
Evidence boundary: Host serializer and inventory comparison, not signature trust or Android behavior.


### Requirement: Canonical inventory and interrupted publication remain bounded

Ordinary root enumeration SHALL admit at most 29 directory entries: sixteen canonical segments, nine reserved auxiliary names (`helper-error.log`, `remount-dbg.log`, `accepted-batches`, `accepted-batch.pending`, `.accepted-batches.tmp`, `.accepted-batch.pending.tmp`, `.segment-active.jsonl.tmp`, `product-system-error.json`, `.product-system-error.json.tmp`) and four reserved tier/publication slots. Auxiliary publications SHALL NOT enter exported canonical records. This directory-entry budget SHALL NOT increase the sixteen-segment, eight-MiB-per-segment retention limits.

Cold recovery SHALL validate the directory's exact effective UID, effective GID and mode `0700` before acquiring its mutation lock or repairing files. Recovery enumeration alone SHALL admit at most 30 entries to recognize one interrupted rotation publication. Only the recognized completed segment and active leaf naming the same trusted inode with exactly two links MAY be rolled back; unrelated aliases, a third link, foreign metadata, wrong modes and symlinks SHALL fail closed without data loss. Recovery SHALL restore the ordinary 29-entry bound before tail repair. General trusted reads SHALL retain the single-link requirement. A cut after completed-name publication and before active-name removal SHALL retain all accepted records and the next sequence across cold reopening.

Segment-read export diagnostics SHALL map only nine exact internal reasons to `segment-directory-entry-bound`, `segment-directory-entry-encoding`, `segment-file-kind-or-links`, `segment-file-owner`, `segment-file-mode`, `segment-file-size-bound`, `segment-file-size-changed`, `segment-file-metadata-changed` or `segment-export-size-bound`. Other segment-read failures SHALL remain `segment-read`; arbitrary paths, record payloads and error text SHALL NOT become public reasons. The paired installer consumer SHALL use the same closed reason vocabulary; existing stage reasons and errno handling remain separate.

#### Scenario: A complete retained inventory includes auxiliary publications

- **WHEN** sixteen segments coexist with ledger, pending batch, sidecars and reserved recovery temporary files
- **THEN** export succeeds within the 29-entry ordinary bound, excludes auxiliary contents and cold pending-batch recovery preserves accepted records

#### Scenario: Cold opening finds a publication cut

- **WHEN** a trusted completed segment and active leaf are the two names left by an interrupted publication
- **THEN** recovery rolls back only the completed alias, preserves all records and sequence continuity, and restores the ordinary bound before tail repair

#### Scenario: Recovery authority or aliases are untrusted

- **WHEN** directory authority, file mode, inode identity, link count or completed-name grammar does not match the recovery contract
- **THEN** recovery rejects the state before destructive repair and preserves original record bytes

#### Scenario: Export reports a closed diagnostic reason

- **WHEN** export encounters an exact recognized secure-file boundary or another failure
- **THEN** it returns only the closed reason and available errno, without exposing private payload or arbitrary text

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::export_retention_with_sidecars_pending_batch_and_recovery_temps -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `A complete retained inventory includes auxiliary publications`.
Preconditions: Sixteen real segments coexist with all nine reserved auxiliary publications and the four reserved slots.
Observable result: Export and cold pending-batch recovery retain canonical records; unrelated overflow is rejected.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::interrupted_rotation_cold_open_preserves_records_and_sequence -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Cold opening finds a publication cut`.
Preconditions: Production publication is interrupted before active unlink.
Observable result: Repeated cold reopening retains records and next sequence.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::interrupted_rotation_full_inventory_recovers_before_normal_bound -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Cold opening finds a publication cut`.
Preconditions: The 29-entry inventory receives its one recognized publication alias.
Observable result: Recovery accepts the temporary 30th entry and returns to the ordinary bound before tail repair.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::interrupted_rotation_rejects_external_third_alias_and_wrong_mode -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Recovery authority or aliases are untrusted`.
Preconditions: A publication cut has a third link or incorrect file mode.
Observable result: Cold open rejects the state and preserves the active leaf.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::interrupted_rotation_rejects_unrecognized_aliases_without_data_loss -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Recovery authority or aliases are untrusted`.
Preconditions: Publication candidates have another inode, symlink or malformed name.
Observable result: Cold open rejects all candidates without changing original record bytes.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::interrupted_rotation_rejects_untrusted_directory_before_mutation -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Recovery authority or aliases are untrusted`.
Preconditions: A publication cut resides in a directory changed to 0755 or 0777.
Observable result: Opening rejects before alias removal; restoring trusted authority recovers the record.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::export_segment_subreasons_are_closed_and_payload_free -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Export reports a closed diagnostic reason`.
Preconditions: Every exact secure-file diagnostic and an arbitrary secret-bearing string enters the production reason mapper.
Observable result: Nine exact subreasons are mapped; arbitrary text remains segment-read and no secret is emitted.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.

# Gate: cargo test --manifest-path daemon/Cargo.toml canonical_log::tests::export_segment_subreasons_reproduce_actual_file_boundaries -- --exact

Gate contract: Canonical inventory and interrupted publication remain bounded.
Maps: Requirement `Canonical inventory and interrupted publication remain bounded`; Scenario `Export reports a closed diagnostic reason`.
Preconditions: Actual files violate mode, link, size or directory-entry bounds.
Observable result: Production export returns the corresponding closed reason without payload leakage.
Evidence boundary: Host production filesystem and recovery code only; actual build150 Android export, cold restart and paired installer transport remain unverified runtime gates. The valid twenty-entry host regression establishes the former source bound defect, not the cause of the build149 device failure.


### Requirement: Startup diagnostics retain bounded authority-qualified receipt milestones

Existing root-owned status SHALL optionally carry normalized startupMilestones under the existing status envelope. A daemon incarnation SHALL use one daemon.monotonicSinceOwnerStart clock, keep pre-spawn samples only for successfully dispatched jobs, bind endpoint adoption to PID/starttime/epoch, and retain the first current document/lifecycle application receipt independently of subsequent status publications. Android elapsedRealtime values SHALL remain separate from root receipt times. A current signed producer SHALL qualify the selected contract semantics; ready status alone SHALL NOT assert application. Changed process, endpoint, document or lifecycle identity SHALL invalidate dependent evidence.

#### Scenario: A successful dispatch and application have retained first milestones

- **WHEN** an admitted target dispatches successfully and a current producer confirms its desired semantic set
- **THEN** the first pre-spawn sample and first qualified receipt remain unchanged by later events

#### Scenario: Stale, mismatched or baseline-only data cannot confirm a current application

- **WHEN** endpoint, document, lifecycle, clock, semantic equality or closed receipt shape differs
- **THEN** no current application confirmation is admitted

# Gate: cargo test --manifest-path daemon/Cargo.toml startup::tests::successful_dispatch_retains_pre_spawn_sample -- --exact
Gate contract: Startup diagnostics retain bounded authority-qualified receipt milestones.
Maps: Requirement `Startup diagnostics retain bounded authority-qualified receipt milestones`; Scenario `A successful dispatch and application have retained first milestones`.
Preconditions: The owning tracker receives admitted readiness and successful dispatch samples.
Observable result: An invalid or missing dispatch is not promoted and the first successful pre-spawn sample/rank remains immutable.
Evidence boundary: Host tracker and actual owner callsite source integration; Android process discovery or backend execution latency is not measured.

# Gate: cargo test --manifest-path daemon/Cargo.toml control_plane::tests::startup_first_owner_receipt_survives_repeated_status_and_resets_identity -- --exact
Gate contract: Startup diagnostics retain bounded authority-qualified receipt milestones.
Maps: Requirement `Startup diagnostics retain bounded authority-qualified receipt milestones`; Scenario `A successful dispatch and application have retained first milestones`.
Preconditions: The production acceptance cache receives exact endpoint-bound status documents and owner timestamps.
Observable result: Repeated or omitted optional application details preserve the first timestamp while endpoint/document identity changes invalidate stale evidence.
Evidence boundary: Host production acceptance cache; an actual Android boot and physical-car startup timing remain runtime observations.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup::tests::typed_receipt_rejects_stale_stamp_clock_unknown_fields_and_baseline -- --exact
Gate contract: Startup diagnostics retain bounded authority-qualified receipt milestones.
Maps: Requirement `Startup diagnostics retain bounded authority-qualified receipt milestones`; Scenario `Stale, mismatched or baseline-only data cannot confirm a current application`.
Preconditions: Exact and mutated producer-owned receipt fixtures enter the actual typed parser.
Observable result: Exact current receipt is accepted; stale document/lifecycle, mixed clock, numeric revision, unknown baseline field and semantic mismatch are rejected.
Evidence boundary: Host strict parsing; producer CAN readback is covered separately by owning agent tests.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup::tests::stale_endpoint_and_document_and_baseline_do_not_confirm -- --exact
Gate contract: Startup diagnostics retain bounded authority-qualified receipt milestones.
Maps: Requirement `Startup diagnostics retain bounded authority-qualified receipt milestones`; Scenario `Stale, mismatched or baseline-only data cannot confirm a current application`.
Preconditions: A tracker has an admitted current endpoint and member identity.
Observable result: Wrong endpoint/document, pre-adoption timestamp and mismatched actual semantics leave application absent.
Evidence boundary: Host tracker; no backend or vehicle event is fabricated.


### Requirement: Optional startup diagnostics preserve existing status budgets and commands

Startup diagnostics SHALL use normalized shared identity and target references, bounded retained rows and a 64 KiB byte cap. Exhaustion SHALL expose complete=false with reason=budget-exceeded and exact expected inventory counts without failing the daemon or narrowing the catalog. If optional diagnostics cannot fit the existing 1 MiB status envelope they SHALL be reduced or omitted while preserving the base status. Canonical management parsing SHALL accept valid optional diagnostics. Wide decimal identities and revisions SHALL serialize losslessly as strings.

#### Scenario: Current beta1 serializer and consumer remain compatible

- **WHEN** the current finite beta1 maximum-detail status includes retained startup diagnostics
- **THEN** its serialized bytes remain within the existing envelope and canonical management accepts them

#### Scenario: Hostile optional inventory cannot break base status

- **WHEN** legal maximum catalog combinations or optional serialized bytes exhaust diagnostic capacity
- **THEN** diagnostic evidence becomes unavailable without enlarging limits or losing the base status

# Gate: cargo test --manifest-path daemon/Cargo.toml status::tests::current_signed_beta1_inventory_fits_resident_budget -- --exact
Gate contract: Optional startup diagnostics preserve existing status budgets and commands.
Maps: Requirement `Optional startup diagnostics preserve existing status budgets and commands`; Scenario `Current beta1 serializer and consumer remain compatible`.
Preconditions: The actual Status serializer uses the retained signed beta1 catalog inventory, maximum base details and bounded typed startup rows.
Observable result: Current finite-target serialized bytes and canonical management admission match; string revisions retain their exact values and the existing 1 MiB limit holds.
Evidence boundary: Host actual serializer and native consumer. Fixture semantics are synthetic and do not constitute Android or CAN acceptance; the paired product host regression proves cross-language shape separately.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup::tests::hostile_max_catalog_cannot_exhaust_wire_budget -- --exact
Gate contract: Optional startup diagnostics preserve existing status budgets and commands.
Maps: Requirement `Optional startup diagnostics preserve existing status budgets and commands`; Scenario `Hostile optional inventory cannot break base status`.
Preconditions: 4096 maximal process names enter the bounded production tracker.
Observable result: The diagnostic projection clears retained tables and exposes budget-exceeded with preserved expected counts under 64 KiB.
Evidence boundary: Host byte bound; complete startup evidence for every theoretical catalog is not promised.

# Gate: cargo test --manifest-path daemon/Cargo.toml status::tests::optional_diagnostics_never_break_existing_near_limit_status -- --exact
Gate contract: Optional startup diagnostics preserve existing status budgets and commands.
Maps: Requirement `Optional startup diagnostics preserve existing status budgets and commands`; Scenario `Hostile optional inventory cannot break base status`.
Preconditions: A valid base status approaches the existing 1 MiB cap before optional diagnostics are added.
Observable result: Optional data is marked unavailable or omitted while the base details and original envelope remain intact.
Evidence boundary: Host serializer; existing oversized base status is not redefined or hidden by this optional feature.


### Requirement: Owner initialization exposes a separate trusted boot-clock anchor

Startup diagnostics SHALL retain an optional clockAnchor sampled next to the daemon-loop owner monotonic origin using the existing kernel boot-clock reader on Android/Linux. Its linux.bootElapsedRealtime sample SHALL preserve 10ms precision and its separate ownerBeforeMs/ownerAfterMs bracket under the common boot identity. Unavailable or invalid trusted boot time SHALL remain null; host MONOTONIC portability SHALL NOT substitute a boot anchor. The anchor SHALL identify owner initialization rather than process execution and SHALL NOT fabricate exact timestamps by subtracting different clock domains.

#### Scenario: A trusted owner initialization sample is available

- **WHEN** the trusted boot-clock reader supplies a valid centisecond sample inside an ordered owner bracket
- **THEN** the separate boot stamp, clock domain, bracket and precision remain explicit

#### Scenario: Boot-clock authority is unavailable or invalid

- **WHEN** the trusted clock fails, the bracket reverses, precision differs or the host has no supported boot-clock domain
- **THEN** no boot anchor is fabricated

# Gate: cargo test --manifest-path daemon/Cargo.toml startup::tests::owner_boot_anchor_is_separate_bounded_and_never_fabricated -- --exact
Gate contract: Owner initialization exposes a separate trusted boot-clock anchor.
Maps: Requirement `Owner initialization exposes a separate trusted boot-clock anchor`; Scenario `A trusted owner initialization sample is available`; Scenario `Boot-clock authority is unavailable or invalid`.
Preconditions: Actual anchor construction receives valid, missing, imprecise and reversed samples; unsupported host sampling uses its production branch.
Observable result: Valid data retains the independent clock/bracket/precision; unavailable or invalid data remains null and unsupported host MONOTONIC is never labelled boot time.
Evidence boundary: Host production constructor and type behavior. Android owner initialization timing and physical-car startup latency require fresh runtime observations; no timing SLA or process-exec conversion is inferred.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_state::tests::projection_clock_uses_kernel_boot_domain_and_centisecond_floor -- --exact
Gate contract: Owner initialization exposes a separate trusted boot-clock anchor.
Maps: Requirement `Owner initialization exposes a separate trusted boot-clock anchor`; Scenario `A trusted owner initialization sample is available`; Scenario `Boot-clock authority is unavailable or invalid`.
Preconditions: The existing production kernel clock reader uses its platform-selected clock and injected syscall results.
Observable result: Android/Linux select CLOCK_BOOTTIME, 123456999999ns input floors to 123450ms and clock errors return unavailable.
Evidence boundary: Host source/syscall seam; Android kernel runtime sampling is not replaced by this unit test.


### Requirement: Startup preparation logs retain bounded owner-clock observation intervals

The daemon SHALL emit preparation diagnostics only as canonical info log events with source.kind=daemon, component=startup and message=startup.preparation, independently of the status wire and application receipts. String-valued fields SHALL be the closed base set schemaVersion=1, clockDomain=daemon.monotonicSinceOwnerStart, bootId, daemonPid, daemonStarttime, manifestSha256, generationId, catalogSha256, process, targetPid, targetStarttime, attempt, observedScanBeginMs, observedScanEndMs, preflightBeginMs, preflightEndMs, outcome and stage. Outcomes SHALL be dispatched, failed or rebind; stages SHALL be maps, authority, desired, bootstrap, payload, final-attestation, dispatch or rebind. Accepted dispatched/rebind events SHALL additionally contain dispatchMs equal to the exact existing startup_ready pre-spawn sample and dispatchAcceptedMs sampled after accepted dispatch; failed events SHALL omit both dispatch fields. The observation interval SHALL bracket the existing single watcher inventory pass and remain the first interval for the exact process/PID/starttime identity across retries. A replacement identity SHALL receive a new interval, mismatched attestation SHALL suppress stale evidence, and the cache SHALL contain only signed inventory processes with at most eight diagnostic attempts per observed identity. Missing or unreadable observation SHALL remain unavailable without fabricated zero times or blocked dispatch. All milliseconds SHALL remain in the owner's monotonic domain, separate from Android boot/application clocks; target starttime SHALL remain kernel ticks rather than a process-birth timestamp.

#### Scenario: Accepted dispatch retains full preparation and exact legacy timing

- **WHEN** controlled owner samples observe scan 10..12, prepare 15..115 and accept dispatch 115..116
- **THEN** the production canonical log contains the closed success event with preflight duration 100 and observed-to-dispatch duration 103 while the legacy ready-to-dispatch interval remains zero

#### Scenario: Failed preparation has no accepted dispatch claim

- **WHEN** preparation exits unsuccessfully at the payload stage
- **THEN** the canonical failure event contains the eighteen base fields and omits dispatchMs and dispatchAcceptedMs

#### Scenario: Retry preserves first observation and replacement resets identity

- **WHEN** the same process identity is observed again before a retry and its PID is later reused with a new starttime
- **THEN** the retry keeps the original interval while the replacement obtains its own interval and attempt counter

#### Scenario: Missing observation and unsigned inventory cannot create evidence

- **WHEN** an unsigned process or an unreadable observation enters the diagnostic cache
- **THEN** no diagnostic attempt is available until a signed exact identity is observed, and temporary unreadability does not reset its first interval

#### Scenario: Attestation mismatch suppresses stale evidence and rebind retains its stage

- **WHEN** final identity differs from the observation or accepted resident dispatch preparation later fails
- **THEN** mismatched evidence is suppressed and a failed resident rebind remains stage=rebind

#### Scenario: Diagnostic retry retention has a fixed bound

- **WHEN** an exact identity reaches eight diagnostic attempts
- **THEN** further diagnostic attempts are unavailable while its retained first observation remains unchanged

#### Scenario: Absent preparation diagnostics cannot block bootstrap admission

- **WHEN** the runtime has no preparation observation for an otherwise dispatchable target
- **THEN** it still admits the bootstrap job through the existing worker path

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_preparation::tests::full_preflight_is_not_zero_legacy_ready_to_dispatch -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Accepted dispatch retains full preparation and exact legacy timing`.
Preconditions: Controlled owner samples enter the production attempt acceptance and canonical logging sink.
Observable result: Exactly twenty success fields retain the full preparation interval and existing dispatch sample.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_preparation::tests::failed_preflight_emits_closed_failure_through_real_log_sink -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Failed preparation has no accepted dispatch claim`.
Preconditions: The real attempt drop path exits at payload using a scoped production canonical sink.
Observable result: The failure has exactly eighteen fields without either dispatch timestamp.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_preparation::tests::observation_is_first_and_identity_reuse_does_not_inherit_it -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Retry preserves first observation and replacement resets identity`.
Preconditions: Repeated exact tuples and a reused PID with a new starttime enter the cache.
Observable result: Repeated observations preserve the first interval and replacement resets interval and attempt.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_preparation::tests::inventory_is_signed_and_missing_observation_is_unavailable -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Missing observation and unsigned inventory cannot create evidence`.
Preconditions: Unsigned, missing, temporarily unreadable and removed signed process observations enter the cache.
Observable result: Unsigned entries stay absent; unreadable entries cannot begin diagnostics; renewed exact identity preserves the first interval.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_preparation::tests::final_identity_replacement_suppresses_attempt_and_rebind_keeps_stage -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Attestation mismatch suppresses stale evidence and rebind retains its stage`.
Preconditions: An attempt receives a different attested starttime and a separate resident attempt enters ready state.
Observable result: Stale success/failure evidence is suppressed and failed rebind has stage=rebind.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_preparation::tests::retry_attempts_are_bounded_but_first_observation_is_stable -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Diagnostic retry retention has a fixed bound`.
Preconditions: One exact signed observation is retried through the production diagnostic bound.
Observable result: Attempts one through eight preserve the first interval and the ninth is unavailable.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::missing_preparation_observation_does_not_block_bootstrap_dispatch -- --exact

Gate contract: Startup preparation logs retain bounded owner-clock observation intervals.
Maps: Requirement `Startup preparation logs retain bounded owner-clock observation intervals`; Scenario `Absent preparation diagnostics cannot block bootstrap admission`.
Preconditions: An actual runtime fixture dispatches a bootstrap with no preparation observation.
Observable result: The existing injection job owner admits the target and drains normally.
Evidence boundary: Host production diagnostic/cache/logging or worker-admission path only. Android early-start scheduling, physical process birth, backend CAN execution and vehicle latency require separate runtime evidence; no status-wire extension or new admission policy is implied.
