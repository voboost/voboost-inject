# Daemon configuration specification

## Purpose

Define canonical user intent and passive generation versus live intent changes.

## Requirements

### Requirement: Canonical intent is one strict root document

`/data/voboost/agents.json` SHALL be the only persistent user-intent document. Every mutation SHALL validate and atomically replace the complete schema. An enabled agent SHALL not coexist with any enabled agent named by its catalog `disables` array; direct hostile documents with such a conflict SHALL fail closed as well as Settings mutations resolving the conflict atomically.

#### Scenario: One conflicting keyboard agent is enabled

- **WHEN** the canonical document previously enabled the other declared keyboard agent
- **THEN** one atomic replacement enables the requested agent and disables its conflict

#### Scenario: A hostile document enables both conflicts

- **WHEN** the daemon validates that complete document
- **THEN** it rejects the document and preserves last-known-good intent

# Gate: cargo test --manifest-path daemon/Cargo.toml plan::tests::enabled_conflicts_are_rejected_regardless_of_relation_order -- --exact
Gate contract: Hostile conflicting intent rejection.
Maps: Requirement `Canonical intent is one strict root document`; Scenario `A hostile document enables both conflicts`.
Preconditions: The exact Rust test validates documents containing both sides of a disable relation in each ordering.
Observable result: Every conflicting complete document is rejected without yielding a replacement plan.
Evidence boundary: Host intent validation only; persistent replacement durability is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::enabling_agent_atomically_disables_conflicts -- --exact
Gate contract: Atomic conflict-resolving Settings mutation.
Maps: Requirement `Canonical intent is one strict root document`; Scenario `One conflicting keyboard agent is enabled`.
Preconditions: The exact Rust test starts with the opposite declared keyboard agent enabled and applies one Settings enable request.
Observable result: The returned complete replacement enables the requested agent and disables its conflict together.
Evidence boundary: Host mutation and canonical document publication logic; live OEM Settings UI is not exercised.

### Requirement: Injection startup publishes resident admission before productive work

The first validated injection plan and effective startup-mode changes SHALL publish their current resident admission before productive work. Ordinary passes SHALL retain one final publication. This injection status publication SHALL NOT turn a saved next-boot startup choice into immediate application confirmation.

#### Scenario: Productive work blocks after a mode is admitted

- **WHEN** the first validated mode or a mode change reaches productive work
- **THEN** its status is published first, and ordinary later passes retain one final status publication

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml --bin voboost-inject runtime_loop::tests::startup_confirmation_is_published_before_blocked_productive_work -- --exact

Gate contract: Early validated injection publication.
Maps: Requirement `Injection startup publishes resident admission before productive work`; Scenario `Productive work blocks after a mode is admitted`.
Preconditions: Production pass scheduler receives a blocking productive action and a real host publication channel.
Observable result: Early publication arrives before releasing productive work, with final publication retained.
Evidence boundary: Host scheduler ordering; signed injection startup and init transitions require target evidence.

### Requirement: Catalog changes preserve canonical intent deterministically

Across a catalog change the daemon SHALL preserve still-valid values, add new selected agents with signed-catalog defaults, remove absent agents, resolve newly introduced disables deterministically and replace the complete document atomically before new-process bootstrap uses the new generation.

#### Scenario: An active catalog is replaced with a different selected set

- **WHEN** selected agents or their signed defaults and disables change across catalog activation
- **THEN** one atomic canonical replacement preserves valid values and applies the deterministic new selected set before bootstrap

# Unverified: Catalog replacement contract

### Requirement: Generation changes are passive and intent changes are live

Publishing a generation or changing canonical intent SHALL not signal, kill or force-restart an OEM process. A resident endpoint SHALL remain bound to its immutable generation until its process exits naturally. Canonical intent changes SHALL allocate a checked monotonic document generation and send one bounded whole-state `D` frame to every matching daemon-owned resident endpoint, including an empty agent set. Allocation SHALL fail closed before the reserved `i64` boundary instead of saturating or reusing a generation. Runtime `S` status may advance acknowledgement or the next-generation floor only when its process, resident generation, requested agent set and document generation correlate to the daemon-owned desired snapshot; raw mismatched status SHALL not enter either calculation. The daemon SHALL not count the change applied until the endpoint reports that document generation.

#### Scenario: Enabled composition changes for a live process

- **WHEN** canonical intent is replaced while the target remains alive
- **THEN** the target is not terminated and receives a correlated whole-state live update

#### Scenario: The last enabled agent is disabled

- **WHEN** the resident still reports the previous document generation
- **THEN** the daemon keeps the empty desired document unacknowledged rather than treating absence of desired agents as success

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::settings_commit_during_drain_queues_runtime_d_before_correlated_a_once -- --exact
Gate contract: Live whole-state intent update.
Maps: Requirement `Generation changes are passive and intent changes are live`; Scenario `Enabled composition changes for a live process`.
Preconditions: The exact Rust daemon test commits Settings intent while the resident endpoint drain is active.
Observable result: The process is retained and receives one whole-state `D` frame before its correlated acknowledgement advances state.
Evidence boundary: Host daemon endpoint state machine; target process liveness and pipe delivery are not observed on Android.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::enabled_to_empty_never_counts_acked_without_runtime_evidence -- --exact
Gate contract: Empty desired-state acknowledgement.
Maps: Requirement `Generation changes are passive and intent changes are live`; Scenario `The last enabled agent is disabled`.
Preconditions: The exact Rust test changes a resident process from one enabled agent to an empty desired set while status remains on the prior generation.
Observable result: The empty document remains unacknowledged until matching runtime evidence arrives.
Evidence boundary: Host correlation state machine; injected agent receipt is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::desired_generation_exhaustion_fails_without_saturation -- --exact
Gate contract: Desired-document generation exhaustion.
Maps: Requirement `Generation changes are passive and intent changes are live`; Scenario `Enabled composition changes for a live process`.
Preconditions: The exact Rust test places the generation counter at its reserved boundary before a new intent allocation.
Observable result: Allocation fails without saturation, wraparound or generation reuse.
Evidence boundary: Host counter arithmetic; persistent counter recovery is outside this gate.

### Requirement: A saved removal is an authoritative withdrawal only after its targets apply it

A durably saved removal of an agent and of its automatically disabled dependencies SHALL become an authoritative withdrawal only after the injection producer confirms that every Android target process of the source applied the desired document that removes it, or after one fixed bound expires. Until then the source SHALL keep its admission and its native slot, so an input already captured by the still-installed hook can still be executed as the compensating OEM write, while the durable document already denies the source. A removal whose durable save failed SHALL not create a pending withdrawal: it fences and revokes the source before the acknowledgement. Re-enabling the source during the pending window SHALL clear the pending withdrawal, and a confirmation for a source without a pending removal SHALL leave that source admitted.

#### Scenario: The user turns an agent off while its hooks are still installed

- **WHEN** a Settings removal is durably saved while the target processes still run the hook that captured the OEM input
- **THEN** the source keeps its admission and its native slot until every target process reports the document generation that removes it

#### Scenario: The producer dies before confirming a removal

- **WHEN** the removal was durably saved and no confirmation arrives within the bound
- **THEN** the source is withdrawn, revoked and loses its commands

#### Scenario: The user re-enables the agent before the removal is confirmed

- **WHEN** the agent is enabled again during the pending window
- **THEN** the pending withdrawal is cleared and a later confirmation leaves the re-enabled source admitted

#### Scenario: A removal that never became durable

- **WHEN** the durable save of the removal fails
- **THEN** no withdrawal is created and the source is fenced and revoked immediately

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::withdrawal_tests::a_saved_removal_keeps_the_source_admitted_until_its_targets_confirm -- --exact
Gate contract: Deferred authoritative withdrawal.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user turns an agent off while its hooks are still installed`.
Preconditions: An admitted native source, a durable Settings removal saved through the producer path, then an injected confirmation.
Observable result: The durable document denies the source while the owner still holds its admission and native slot; the confirmation revokes both.
Evidence boundary: Host owner state machine; the hook lifetime in a real target process requires runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::commands::tests::saved_checkbox_off_cancels_real_offered_and_running_native_on -- --exact
Gate contract: Settings checkbox removal keeps the compensating-write authority.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user turns an agent off while its hooks are still installed`.
Preconditions: The exact owner test saves a real Settings checkbox removal for a source with an issued native command.
Observable result: The durable removal cancels the issued command while the admission survives the refresh until the confirmation withdraws it.
Evidence boundary: Host owner command and admission state; the delivered OEM write on a vehicle is not observed here.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::desired::tests::saved_off_is_durable_while_the_product_operation_lock_is_held -- --exact
Gate contract: Durable removal is not authoritative.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user turns an agent off while its hooks are still installed`.
Preconditions: A canonical removal saved while the product operation lock is held.
Observable result: The durable document denies the source while the source stays admitted and carries a pending withdrawal.
Evidence boundary: Host durable-document and admission projection; real Settings UI timing is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject runtime::test_support::a_removal_is_reported_applied_only_on_positive_evidence -- --exact
Gate contract: Applied-removal evidence.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user turns an agent off while its hooks are still installed`.
Preconditions: A live target with and without the source in its desired document, and correlated observed generations below, equal to and above the removal generation.
Observable result: Only a live target whose desired document omits the source and whose observed generation reached that document counts as applied; a dead target and every unproven case do not.
Evidence boundary: Host pure decision function; real per-process document application requires runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::withdrawal_tests::an_unconfirmed_removal_is_forced_when_its_bound_expires -- --exact
Gate contract: Bounded pending withdrawal.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The producer dies before confirming a removal`.
Preconditions: A durably saved removal whose bound has already expired and a producer that never confirms.
Observable result: The owner loop expiry withdraws the source and revokes its admission.
Evidence boundary: Host bound arithmetic; a real producer crash is not replayed here.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::withdrawal_tests::re_enabling_during_the_window_keeps_the_source_admitted -- --exact
Gate contract: Re-enable clears the pending withdrawal.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user re-enables the agent before the removal is confirmed`.
Preconditions: A durably saved removal followed by a durable re-enable of the same source within the pending window.
Observable result: The durable document enables the source again and no pending withdrawal remains.
Evidence boundary: Host owner state machine; Settings UI ordering is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::withdrawal_tests::a_confirmation_without_a_pending_removal_is_inert -- --exact
Gate contract: Unmatched confirmation is inert.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user re-enables the agent before the removal is confirmed`.
Preconditions: An admitted source with no pending withdrawal and a producer confirmation.
Observable result: The source keeps its admission, its lease revision and its enabled projection.
Evidence boundary: Host owner state machine; a late producer confirmation after re-enable is not replayed end to end.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::withdrawal_tests::a_removal_that_never_persisted_stays_a_denial_without_a_withdrawal -- --exact
Gate contract: Failed save stays an immediate denial.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `A removal that never became durable`.
Preconditions: An injected durable-write failure during the removal save.
Observable result: The field is fenced, no pending withdrawal exists and the source loses its admission.
Evidence boundary: Host filesystem failure injection; real device write failures require runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::commands::tests::failed_saved_off_fsync_revokes_actual_running_native_command_before_ack -- --exact
Gate contract: Failed-save revocation precedes the acknowledgement.
Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `A removal that never became durable`.
Preconditions: An issued running native command and a removal whose durable save fails.
Observable result: The running command is revoked before the failure acknowledgement is returned.
Evidence boundary: Host owner command state; an actual OEM process is not involved.

# Unverified: Compensating OEM write after a deferred withdrawal

### Requirement: Installed management coexists with the resident daemon

The exact signed root-owned mode-0700 installed executables SHALL retain separate administrative roles. `voboost-inject` SHALL expose installed inspection and desktop uninstall publication before its injection singleton acquisition. `voboost-daemon` SHALL expose the closed startup-mode save command through the resident owner's SetStartup operation. A secondary administrative invocation SHALL NOT replace either resident singleton.

Inspection SHALL be read-only and retain the existing operation guard while checking signed installed closure and recovery authority, protected init and SELinux identities, the exact injection producer identity, active generation, canonical configuration, status and last operation. The bounded schema-1 installed-state result SHALL retain healthy, degraded, unrecoverable and unknown distinctions; inability to establish version or authority SHALL NOT fabricate mutation authority. Desktop uninstall SHALL retain its existing guarded signed publication route.

Startup-mode save SHALL validate the current complete schema and atomically change only startup under the owner operation guard. Every agent enable value and option SHALL survive unchanged. A busy Install, Update, Restore, Uninstall or generation operation SHALL reject the save before changing intent. The startup-mode receipt SHALL confirm persisted configuration, not immediate executor application. An existing same-boot startup-session fence SHALL remain unchanged; if absent for the current boot it SHALL capture the previous saved mode before mutation. A fresh boot SHALL use the preceding saved selection. Saving none SHALL NOT require the resident state/config/log owner to stop or report killed. Configuration and effective current-session startup SHALL remain distinct.

#### Scenario: Desktop inspection runs while the resident daemon owns its pidfile

- **WHEN** the installer invokes installed injection inspection while the resident services are running
- **THEN** inspection returns the closed installed-state document without acquiring or replacing a resident singleton

#### Scenario: Desktop changes only startup mode

- **WHEN** the owner receives one of the three exact startup values
- **THEN** one guarded atomic replacement changes only startup, confirms the saved value and leaves the complete remaining current-schema configuration and running-boot fence unchanged

#### Scenario: A product transaction races a startup-mode request

- **WHEN** operation.lock is retained by another privileged mutation
- **THEN** startup save returns busy without writing agents.json or claiming confirmation

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject management::tests::installed_management_dispatch_precedes_the_resident_singleton_lock -- --exact

Gate contract: Resident-compatible installed management dispatch.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `Desktop inspection runs while the resident daemon owns its pidfile`.
Preconditions: The compiled injection entrypoint contains management and singleton dispatch.
Observable result: Fixed management dispatch precedes injection singleton acquisition in the actual entrypoint.
Evidence boundary: Source-order host test; installed Android execution requires runtime evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::startup_projection_tests::startup_save_preserves_the_complete_current_configuration_and_running_boot -- --exact

Gate contract: Complete current-schema startup projection.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `Desktop changes only startup mode`.
Preconditions: Current-schema configuration with multiple agents and nested scalar options is stored in a private host root.
Observable result: Actual owner Store save changes only startup, preserves exact complete projected bytes and the running-boot fence, and captures the preceding saved mode at the next boot.
Evidence boundary: Real owner filesystem transaction body; peer admission, Android runtime application and OEM UI are not verified.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject management::tests::command_parser_accepts_only_the_closed_installed_management_surface -- --exact

Gate contract: Closed injection management CLI surface.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `Desktop inspection runs while the resident daemon owns its pidfile`.
Preconditions: The parser receives supported inspection/removal forms and invalid or foreign startup arguments.
Observable result: Only the closed injection management forms are admitted; startup save is not an injection command.
Evidence boundary: Host argument parsing; signed executable identity and Android execution remain separate.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon cli::tests::modes_are_exact_and_do_not_accept_injection_helpers -- --exact

Gate contract: Closed owner startup command.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `Desktop changes only startup mode`.
Preconditions: Owner CLI receives every exact startup mode and foreign injection helper arguments.
Observable result: Only declared owner CLI forms and exact startup values are admitted.
Evidence boundary: Host parser; no runtime mode change is performed.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject management::tests::installed_probe_emitter_matches_the_product_wire_golden_bytes -- --exact

Gate contract: Product-owned installed-inspection bytes.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `Desktop inspection runs while the resident daemon owns its pidfile`.
Preconditions: Installed-state golden documents are mirrored from the product corpus.
Observable result: Native serializers retain exact healthy and unknown inspection bytes.
Evidence boundary: Host producer interop; trusted running-service identity and installer runtime parsing remain separate.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon cli::tests::configuration_receipt_matches_installer_wire_fixture -- --exact

Gate contract: Persisted startup receipt bytes.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `Desktop changes only startup mode`.
Preconditions: The exact installer startup-mode wire fixture is available.
Observable result: The owner emits its exact persisted-configuration receipt without claiming immediate application.
Evidence boundary: Host serializer; actual resident request and OEM runtime remain separate.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-daemon server::tests::startup_save_rejects_busy_operation_without_changing_intent_or_boot -- --exact

Gate contract: Actual startup save respects the operation fence.
Maps: Requirement `Installed management coexists with the resident daemon`; Scenario `A product transaction races a startup-mode request`.
Preconditions: A retained privileged operation lease and current configuration/boot fence exist in a private host root.
Observable result: Actual owner Store save rejects busy admission and preserves configuration and boot bytes.
Evidence boundary: Host Store/filesystem behavior; concurrent Android processes require runtime evidence.

### Requirement: Ready vehicle and interface targets precede broad application hooks

The synchronous fresh-target and retry batches SHALL use the signed catalog startupPriority field in the order vehicle, interface, applications, background. A shared process SHALL use the highest priority of its enabled agents and executors. Priority SHALL use signed catalog target membership and canonical enabled intent, without special agent IDs or OEM process names. An absent optional field in an existing schema-one catalog SHALL mean applications; new beta1 producers declare the field explicitly. Unknown values SHALL fail parsing. Equal-priority fresh targets SHALL retain their observed order; missing priority targets SHALL NOT delay available targets. Existing identity and payload checks SHALL remain in the injection path.

#### Scenario: Multiple ready targets compete during boot

- **WHEN** vehicle-state, interface, launcher and ordinary targets appear in one batch
- **THEN** available vehicle targets run first, then interface, applications and background targets, preserving order within each class and servicing tracked pipes between targets

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime_loop::tests::startup_batch_prioritizes_ready_targets_without_starving_peers -- --exact

Gate contract: Synchronous startup dispatch order.
Maps: Requirement `Ready vehicle and interface targets precede broad application hooks`; Scenario `Multiple ready targets compete during boot`.
Preconditions: Mixed target priorities, duplicate priorities and a second batch with no vehicle target.
Observable result: Production batch dispatch visits every target once in stable priority order and services tracked pipes before and after injections.
Evidence boundary: Host scheduler ordering; vehicle startup latency and catalog-to-target classification need runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml plan::tests::startup_priority_uses_enabled_catalog_members_and_executor_targets -- --exact

Gate contract: Canonical startup priority classification.
Maps: Requirement `Ready vehicle and interface targets precede broad application hooks`; Scenario `Multiple ready targets compete during boot`.
Preconditions: Catalog target membership for each vehicle-state agent, launcher and broad font agent, enabled and disabled canonical entries, executor membership and absent processes.
Observable result: Only enabled vehicle and launcher entries receive their priorities, executors use signed target membership and foreign processes remain ordinary.
Evidence boundary: Host canonical plan projection; real boot latency requires runtime acceptance.

### Requirement: Settings startup selection takes effect at the next vehicle start

The Settings radio SHALL commit only next-boot intent. The running daemon, current tab visibility, enabled agents and APK execution SHALL retain the effective current-boot mode. Repeated radio selections and a daemon restart within the same kernel boot SHALL preserve that effective mode. A subsequent kernel boot SHALL apply the most recent committed selection. A rejected canonical commit SHALL restore the previous session fence. Malformed, symlinked, incorrectly owned or incorrectly permissioned session authority SHALL fail closed without substituting the next-boot choice for the active mode. Explicit installer mode changes and the authorized TBOX gesture SHALL remain live controls.

#### Scenario: A user selects Do not start while Voboost is running

- **WHEN** Settings commits `none` during an interface session
- **THEN** the confirmed radio shows `none`, the current session remains interface and a same-boot daemon restart retains interface
- **AND** the next vehicle boot applies `none`

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::startup_ui_commit_confirms_selection_without_changing_session -- --exact

Gate contract: Settings radio preserves the current session.
Maps: Requirement `Settings startup selection takes effect at the next vehicle start`; Scenario `A user selects Do not start while Voboost is running`.
Preconditions: Authenticated Settings endpoint and valid canonical interface document.
Observable result: Actual event routing atomically commits each radio choice, confirms its request and preserves the same-boot effective mode.
Evidence boundary: Host mutation/session authority; actual device boot and process execution require emulator acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml startup_session::tests::radio_changes_only_next_boot_including_daemon_recreation -- --exact

Gate contract: Boot identity scopes deferred startup selection.
Maps: Requirement `Settings startup selection takes effect at the next vehicle start`; Scenario `A user selects Do not start while Voboost is running`.
Preconditions: Trusted project-local run files and explicit canonical boot identities.
Observable result: Repeated choices and reconstructed readers retain the session; the next boot applies the latest intent.
Evidence boundary: Host filesystem contract; real init behavior requires runtime acceptance.

### Requirement: Owned FEV input handoff preserves captured user order

Recognized FEV ON and OFF inputs SHALL enter one process-owned native intent lane independently of the logical Java agent lifetime. Admission SHALL perform only a small memory handoff and nonblocking watcher notification on the OEM UI thread; transport IO, fsync and receipt waits SHALL run outside that thread and outside the lane mutex. Native admission SHALL mean pending, never durable acceptance or vehicle-side effect. Both choices SHALL carry a native CLOCK_BOOTTIME capture stamp; Java request ids SHALL be correlation identities, not a global chronological order.

The root route SHALL authenticate resident agent ownership, active generation and the signed FEV enum surface. It SHALL persist a bounded root-owned mode-0600 input WAL in the existing mode-0700 state directory before canonical intent publication. A newer captured input SHALL supersede an older input across processes, regardless of arrival order or daemon request-cache loss. Timestamp ordering SHALL be scoped to the kernel boot, reject future stamps, and use process/request identity only to break equal-stamp ties. Pending WAL recovery SHALL precede FEV runtime admission and merge only the FEV intent. Malformed or unavailable FEV recovery authority SHALL quarantine only FEV across fresh, retained-resident and previously-admitted projections; validated peer agents and Settings SHALL continue. The canonical enable choice SHALL remain unchanged, while operator status SHALL report FEV quarantined with an explicit recovery reason. A live fault SHALL publish a changed desired document removing FEV without restarting the OEM process. An independently invalid shared plan SHALL retain this FEV fence through last-valid fallback; only a valid recovered plan may lift it. The existing mode-0755 run contract SHALL remain unchanged.

The exact root receipt SHALL correlate request id, captured stamp, choice and committed/superseded status. Ordinary desired snapshots and coalesced Settings acknowledgements SHALL not substitute for this receipt. The native lane SHALL retain pending work across logical Java close, retry identical bytes, and let newer input supersede older work. Endpoint teardown before durable receipt SHALL remain uncertain. Input lost with process death before root durability SHALL not be represented as accepted. A root committed receipt SHALL not claim backend revocation, CAN application or exactly-once effects across a crash after the vehicle effect.

#### Scenario: Old OFF delivery follows a newer ON from another process

- **WHEN** a delayed Launcher OFF retry arrives after a newer VehicleSetting ON has committed
- **THEN** root returns a correlated superseded receipt and retains the newer ON

#### Scenario: Canonical publication is interrupted

- **WHEN** root has fsynced a pending input WAL but canonical publication or final WAL completion is interrupted
- **THEN** recovery applies the owned intent before admitting a runtime plan and preserves unrelated configuration

#### Scenario: FEV recovery fails while peer agents are healthy

- **WHEN** FEV recovery authority is corrupt or unavailable with an otherwise valid canonical plan
- **THEN** FEV is fenced in every target while other selected agents and Settings remain admitted, and a valid pending OFF is recovered before the fence is lifted

# Gate: make test-implant-downlink
Gate contract: Native owned input lane and exact receipts.
Maps: Requirement `Owned FEV input handoff preserves captured user order`; Scenario `Old OFF delivery follows a newer ON from another process`.
Preconditions: Pending ON/OFF identities, superseded worker copies, malformed/wrong/coalesced acknowledgements and nonblocking notification fixtures.
Observable result: Only an exact receipt completes a lane; new input displaces old retry work and notification is immediately readable.
Evidence boundary: Host native seam; Android scheduling and vehicle effects require runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::owned_fev_input_is_authenticated_durable_and_globally_latest -- --exact
Gate contract: Durable owned input ordering and recovery.
Maps: Requirement `Owned FEV input handoff preserves captured user order`; Scenario `Canonical publication is interrupted`.
Preconditions: Cross-process captured stamps, pending and committed WAL cuts, invalid authority and old-boot recovery fixtures.
Observable result: Stale input is superseded and interrupted canonical publication recovers before plan admission.
Evidence boundary: Host filesystem transaction tests; physical power loss and Android SELinux enforcement require runtime acceptance.

# Gate: cargo test --manifest-path uninstall/Cargo.toml transaction::tests::terminal_cleanup_removes_pending_owned_fev_input_journal -- --exact
Gate contract: Owned input WAL removal.
Maps: Requirement `Owned FEV input handoff preserves captured user order`; Scenario `Canonical publication is interrupted`.
Preconditions: A pending input WAL in the existing root state tree.
Observable result: Descriptor-relative terminal cleanup removes the pending WAL idempotently.
Evidence boundary: Host cleanup primitive; packaged CLI runtime removal requires acceptance.



# Gate: cargo test --manifest-path daemon/Cargo.toml plan::tests::wal_fault_fences_fev_without_blocking_six_other_agents_or_settings -- --exact
Gate contract: FEV-only cold-start recovery fence.
Maps: Requirement `Owned FEV input handoff preserves captured user order`; Scenario `FEV recovery fails while peer agents are healthy`.
Preconditions: Corrupt FEV WAL, persistent armed true, six peers and Settings, admitted NONE projections, repaired durable pending OFF.
Observable result: Shared plan remains valid; no FEV target is admitted until valid OFF recovery; peers and canonical enable intent survive.
Evidence boundary: Host canonical/desired projection; Android cold-boot effects require runtime acceptance.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::fev_recovery_fence_publishes_live_removal_and_scoped_quarantine_without_restart -- --exact
Gate contract: Live scoped recovery fault delivery.
Maps: Requirement `Owned FEV input handoff preserves captured user order`; Scenario `FEV recovery fails while peer agents are healthy`.
Preconditions: Active FEV and peer entries, unchanged canonical intent, runtime recovery fence and a resident UnixStream downlink.
Observable result: A newer D document removes FEV only, retains peers, preserves the tracked PID and reports FEV quarantine without claiming it active.
Evidence boundary: Host runtime/downlink delivery; injected Java stop and in-flight OEM write draining require runtime acceptance.


### Requirement: Canonical intent has no separate interface language

The canonical root document SHALL contain only schemaVersion, startup and agents. It SHALL reject language and other unknown root fields. Settings projections SHALL omit language, and the daemon SHALL reject voboost-language radio mutations.

#### Scenario: A canonical document retains a former language override

- **WHEN** an otherwise valid document contains language
- **THEN** validation rejects it without interpreting a language preference

#### Scenario: A Settings endpoint requests a former language mutation

- **WHEN** owned or foreign Settings events request a former language radio value
- **THEN** the daemon rejects the mutation and retains the canonical document unchanged

# Gate: cargo test --manifest-path daemon/Cargo.toml plan::tests::canonical_intent_follows_system_language_without_an_override -- --exact

Gate contract: Closed canonical intent shape.
Maps: Requirement `Canonical intent has no separate interface language`; Scenario `A canonical document retains a former language override`.
Preconditions: Production canonical parser receives the new shape and a former language field.
Observable result: The new document is valid and both language and unknown fields fail closed.
Evidence boundary: Host canonical parsing; actual Android locale is not observed by the daemon.

# Gate: cargo test --manifest-path daemon/Cargo.toml agent_events::tests::language_mutations_are_rejected_without_changing_canonical_intent -- --exact

Gate contract: Former Settings language mutations are rejected.
Maps: Requirement `Canonical intent has no separate interface language`; Scenario `A Settings endpoint requests a former language mutation`.
Preconditions: An owned Settings context, canonical plan and attempted canonical, alias and foreign language radio events.
Observable result: Every attempted language mutation returns no action and preserves the exact plan bytes.
Evidence boundary: Host event parser and plan write boundary; actual Android follow-system UI and reboot behavior require runtime evidence.

# Unverified: Follow-system Settings projection

## Unverified

### Unverified: Follow-system Settings projection

Maps: Requirement `Canonical intent has no separate interface language`; Scenarios `A canonical document retains a former language override`, `A Settings endpoint requests a former language mutation`.
Unavailable observation: Actual Settings projection contains no language control and follows the current Android system locale across UI recreation and reboot.
Reason: Parser and rejected-mutation gates do not execute the OEM Settings UI.
Required environment or artifact: Current injected Settings UI, observed Android locale changes, UI recreation and reboot evidence.

### Unverified: Catalog replacement contract

Maps: Requirement `Catalog changes preserve canonical intent deterministically`; Scenario `An active catalog is replaced with a different selected set`.
Unavailable observation: One catalog activation preserves still-valid values, inserts signed defaults, removes absent agents, resolves newly introduced conflicts and atomically publishes the resulting canonical document before bootstrap.
Reason: The current focused host inventory does not isolate that complete replacement transaction in one executable test.
Required environment or artifact: A focused replacement fixture containing old and new signed catalogs, prior canonical intent, injected publication failure and an observed bootstrap read after successful atomic replacement.

### Unverified: Compensating OEM write after a deferred withdrawal

Maps: Requirement `A saved removal is an authoritative withdrawal only after its targets apply it`; Scenario `The user turns an agent off while its hooks are still installed`.
Unavailable observation: The input captured by a still-installed hook is actually transmitted to the vehicle as a compensating OEM write during the pending window, and the observed vehicle state matches the saved removal afterwards.
Reason: The gates execute the host owner and inject decision state only; they do not run a real target process with an installed hook, the ptrace injection path or the vehicle transport.
Required environment or artifact: A running vehicle or instrumented vehicle bench with the current firmware, the installed product, a Settings removal issued while the target processes are live, and captured transport plus vehicle-state evidence across the pending window.
