# Implant rebind specification

## Purpose

Define resident implant rebinding after daemon restart.

## Requirements

### Requirement: Resident implants rebind after daemon restart

When a daemon discovers its implant already resident in a live OEM PID, it SHALL request an explicit transport rebind rather than reload the Java agent. The implant SHALL require successful nonblocking configuration, atomically replace stale log/downlink pipes, reset partial framing and stale confirmed state under the transport mutex, return a distinct rebound result and begin the new log stream with exact resident generation and catalog digests. The daemon SHALL verify that identity against an immutable installed generation before tracking the endpoint, retain that generation for status/config/GC decisions and, during ordinary lifecycle adoption, send a correlated desired snapshot on the fresh downlink. Cache-only uninstall maintenance SHALL use the separately specified maintenance context without ordinary desired-state activation. Unknown negative init returns, malformed identities and catalog mismatches SHALL fail closed and SHALL never fall through to generic injection success.

#### Scenario: Daemon restarts while an OEM PID remains alive

- **WHEN** the new daemon rebinds the resident implant
- **THEN** fresh status, event, state-reply and desired frames use new pipes without invoking the agent entry seam again

#### Scenario: Resident identity names the wrong catalog

- **WHEN** the generation exists but its verified catalog digest differs
- **THEN** the daemon closes both fresh endpoints and leaves the resident unowned

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::tests::resident_rebind_has_an_explicit_non_success_result -- --exact
Gate contract: Explicit rebind result.
Maps: Requirement `Resident implants rebind after daemon restart`; Scenario `Daemon restarts while an OEM PID remains alive`.
Preconditions: The exact Rust test receives the native resident-rebind result.
Observable result: The result remains distinct from initial injection success and selects the rebind path.
Evidence boundary: Host Rust result handling only; no Android resident implant is contacted.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::resident_rebind_identity_retains_exact_old_generation_and_rejects_wrong_catalog -- --exact
Gate contract: Resident catalog identity.
Maps: Requirement `Resident implants rebind after daemon restart`; Scenarios `Daemon restarts while an OEM PID remains alive` and `Resident identity names the wrong catalog`.
Preconditions: The exact Rust test supplies retained generation identity with matching and mismatched catalog digests.
Observable result: Matching old-generation identity is retained and the wrong catalog is rejected.
Evidence boundary: Host daemon identity logic; fresh target pipes and Java entry suppression are not observed.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::retained_rebind_rejects_ambiguous_or_mismatched_authority -- --exact
Gate contract: Rebind authority ambiguity.
Maps: Requirement `Resident implants rebind after daemon restart`; Scenario `Resident identity names the wrong catalog`.
Preconditions: The exact Rust test supplies ambiguous, missing, and mismatched retained authority.
Observable result: Each invalid authority fails closed without endpoint ownership.
Evidence boundary: Host authority selection only; target endpoint closure is not directly observed.

# Unverified: Resident target rebind
### Requirement: Rebind requires completed Java startup

A parsed generation identity and the native initialization guard SHALL NOT authorize resident rebind or idempotent bootstrap success. The implant SHALL publish a separate startup-complete flag only after AgentEntry initialization returns and sealed payload ownership is published. Partial or in-progress startup SHALL reject reuse without reloading hooks.

#### Scenario: Identity is parsed but an executor has not finished

- **WHEN** native initialization has begun and generation hashes are present but Java startup has not completed
- **THEN** rebind and duplicate bootstrap success are rejected

# Gate: make test-implant-runtime-safety

Gate contract: Completed resident startup predicate.
Maps: Requirement `Rebind requires completed Java startup`; Scenario `Identity is parsed but an executor has not finished`.
Preconditions: Initialized/in-progress, empty identity and completed startup states are supplied to the production resident predicate.
Observable result: Only completed startup with both exact identity sizes may authorize reuse.
Evidence boundary: Host native policy; ART startup completion and target rebind remain Android evidence.

### Requirement: Settings eligibility comes from the owned native runtime

The native resident identity SHALL retain one Settings-loaded eligibility bit only after an owned successful bootstrap with Settings enabled in interface mode, or an accepted native interface desired update. A dormant module, signed catalog membership, caller status snapshot or arbitrary public Java input SHALL NOT create it. Hidden and none desired updates MAY preserve an existing bit; uninstall cleanup, rejected native application and pre-resident reset SHALL revoke it. Rebind SHALL carry the bit in the existing identity frame as exact `0` or `1` after the two lowercase SHA-256 identities, followed by the accepted desired revision when available, within a 155-byte complete frame bound. A legacy frame without the bit SHALL mean false; malformed bits and fields beyond the accepted revision SHALL fail closed. The daemon SHALL bind admitted eligibility only to the exact tracked PID, starttime, process, endpoint epoch and verified resident generation/catalog; replacement SHALL revoke the prior registration.

#### Scenario: Resident eligibility is carried through rebind

- **WHEN** the owned native runtime has eligible Settings or a legacy identity has no proof
- **THEN** the bounded identity admits exact true or conservative false without consulting agent status

#### Scenario: An endpoint registration or identity differs

- **WHEN** PID, starttime registration, process, epoch, generation or catalog differs, or identity fields are malformed
- **THEN** the prior Settings eligibility cannot authorize that endpoint

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml injector::tests::resident_identity_accepts_native_settings_eligibility_and_rejects_other_bits -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `Settings eligibility comes from the owned native runtime`; Scenarios `Resident eligibility is carried through rebind` and `An endpoint registration or identity differs`.
Preconditions: Exact 134-byte identity frames contain both eligibility values and malformed/extra values.
Observable result: Strict 0/1 values parse and every malformed or extra value is rejected.
Evidence boundary: Host identity parser only; target-native provenance is independently guarded by the owned rebind path.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml injector::tests::resident_identity_is_exact_and_rejects_malformed_or_wrong_shape -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `Settings eligibility comes from the owned native runtime`; Scenario `Resident eligibility is carried through rebind`.
Preconditions: A legacy exact generation/catalog frame and malformed identities are supplied.
Observable result: Legacy identity has false eligibility and malformed identity is rejected.
Evidence boundary: Host native identity parser; actual ART rebind remains separate target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml process_watcher::tests::settings_eligibility_is_exact_and_registration_replacement_revokes_it -- --exact

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `Settings eligibility comes from the owned native runtime`; Scenario `An endpoint registration or identity differs`.
Preconditions: One registration receives owned eligibility, then each bound identity differs and the same PID is registered with a new starttime/epoch.
Observable result: Only the exact registration matches, and replacement and explicit revocation clear its authority.
Evidence boundary: Host tracker state; real target attestation uses the existing independent native gates.

# Gate: make test-implant-downlink

Gate contract: Native startup profile and endpoint delivery.
Maps: Requirement `Settings eligibility comes from the owned native runtime`; Scenario `Resident eligibility is carried through rebind`.
Preconditions: The actual production eligibility helper receives owned module-load and accepted desired documents.
Observable result: Fresh hidden/none or unloaded Settings cannot create eligibility, interface can create it, hidden/none retain it, and cleanup/reset/wrong identity revoke it.
Evidence boundary: Host native helper and real pipe; Android owned loading and rebind remain independent target evidence.

### Requirement: Resident identity preserves the accepted desired revision

The native resident rebind identity SHALL include the last accepted desired document revision after the Settings eligibility bit. The revision SHALL come only from the owned bootstrap document or a successful native desired-document application, independently of whether the Settings module is loaded. A rejected application, malformed revision or foreign generation/catalog SHALL NOT replace the last accepted revision; pre-resident reset SHALL remove it. The complete identity frame SHALL remain bounded to 155 bytes. The daemon SHALL reject malformed, negative other than the absent sentinel `-1`, overflowing or extra revision fields. An identity without an accepted revision SHALL NOT authorize cache-only maintenance.

#### Scenario: Launcher revision survives transport loss without Settings

- **WHEN** an owned launcher bootstrap without the Settings module accepts a revision, later applications are rejected or foreign, and a later valid application is accepted
- **THEN** the accepted revision remains available independently of Settings eligibility, advances only on the valid application, and becomes absent on reset

#### Scenario: Rebound identity carries an exact maintenance revision

- **WHEN** the resident identity includes an exact numeric revision or a malformed, overflowing or extra revision field
- **THEN** the exact revision is admitted and malformed identities are rejected without sending a new desired document

# Gate: make test-implant-downlink

Gate contract: The named native `cache_maintenance_revision_test` preserves accepted maintenance revision independently of Settings eligibility.
Maps: Requirement `Resident identity preserves the accepted desired revision`; Scenario `Launcher revision survives transport loss without Settings`.
Preconditions: The production SettingsLoaded owner receives bootstrap without Settings, rejected, malformed, foreign, valid and reset inputs.
Observable result: The exact accepted revision persists across rejected inputs, advances on valid input and becomes absent after reset.
Evidence boundary: Host native owner behavior; live ART transport recovery remains target evidence.

# Gate: cargo test --locked --manifest-path daemon/Cargo.toml injector::tests::resident_cache_maintenance_revision_survives_transport_rebind -- --exact

Gate contract: Exact bounded resident identity revision parsing.
Maps: Requirement `Resident identity preserves the accepted desired revision`; Scenario `Rebound identity carries an exact maintenance revision`.
Preconditions: A complete resident identity carries a large exact integer revision; malformed, negative, overflowing and extra-field variants follow.
Observable result: Only the exact bounded identity is admitted and every malformed variant is rejected.
Evidence boundary: Host owner parser; transport authenticity and accepted Java revision remain separate target observations.

### Requirement: Failed resident transport recovery is bounded

Ordinary resident transport recovery SHALL admit at most three consecutive attempts for one process PID, starttime, current generation, catalog and desired semantics between qualified ready receipts. Failed attempts SHALL wait one second after the first completion and five seconds after the second. Exhaustion SHALL report failure without replaying Java bootstrap, restarting the target or blocking other targets. A changed identity SHALL end the old recovery lifecycle. Successful pipe adoption or desired enqueue alone SHALL NOT reset attempts. Reset SHALL require a registry-owned accepted current status receipt matching the live PID/starttime, endpoint epoch, exact owned resident generation/catalog, current desired revision, budget identity and exact selected agent set, with every selected agent active and ready or an accepted empty desired acknowledgement. Current global generation and plan semantics SHALL still fence the budget; a verified retained older resident MAY reset it only through its exact current desired-document and native endpoint identity, never through an arbitrary receipt generation. A disabled mapped resident with possible prior hooks SHALL retain bounded cleanup transport until that current empty acknowledgement; a mapped quiescent endpoint with confirmed no desired work SHALL NOT create a new recovery budget. Stale success and failure completions SHALL NOT adopt endpoints, publish desired state or consume a newer identity budget.

#### Scenario: A resident repeatedly rejects transport adoption

- **WHEN** 1600 polling opportunities observe the same failing resident identity
- **THEN** at most three transport attempts occur and the result remains failed after exhaustion

#### Scenario: Resident authority changes

- **WHEN** PID, starttime, generation, catalog or desired semantics changes
- **THEN** the old exhausted budget cannot prevent a new identity attempt

#### Scenario: A successful transport still awaits agent readiness

- **WHEN** pipes have been adopted but no accepted current ready status exists
- **THEN** the recovery budget remains pending until the exact current ready receipt, and healthy recovery cycles can reset it repeatedly

#### Scenario: A disabled mapped resident may still own hooks

- **WHEN** the daemon publishes an empty desired state for a prior resident
- **THEN** a stale or absent empty acknowledgement cannot end cleanup, while the accepted current empty acknowledgement ends it without a new budget

# Gate: cargo test --manifest-path daemon/Cargo.toml resident_recovery::tests::captured_1600_failure_storm_is_bounded_without_bootstrap_replay -- --exact

Gate contract: Bounded resident recovery.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `A resident repeatedly rejects transport adoption`.
Preconditions: The captured failure count is modeled as 1600 same-identity polling opportunities.
Observable result: Exactly three attempts are admitted and exhaustion remains terminal for that identity.
Evidence boundary: Host recovery policy; Android recovery of the font is not proven.

# Gate: cargo test --manifest-path daemon/Cargo.toml resident_recovery::tests::every_identity_field_fences_budget_and_identical_identity_cannot_reset_it -- --exact

Gate contract: Resident authority budget fence.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `Resident authority changes`.
Preconditions: Each identity field changes independently after exhaustion.
Observable result: Each changed identity receives a fresh budget; identical authority stays exhausted.
Evidence boundary: Host policy; Android lifecycle delivery remains separate evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::failed_rebind_completion_never_dispatches_full_bootstrap -- --exact

Gate contract: Failed rebind does not replay bootstrap.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `A resident repeatedly rejects transport adoption`.
Preconditions: A real daemon job completes with InitFailed and current recovery identity.
Observable result: The daemon applies backoff without creating a bootstrap job or claiming owned pipes.
Evidence boundary: Host daemon completion path; actual native helper is not invoked.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::stale_rebind_completion_cannot_change_newer_recovery_budget_or_status -- --exact

Gate contract: Stale completion cannot mutate newer recovery.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `Resident authority changes`.
Preconditions: An old failed rebind completes after a newer starttime budget is installed.
Observable result: The newer exhausted budget and current status remain unchanged; no bootstrap job appears.
Evidence boundary: Host daemon completion path; no Android process is contacted.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::stale_successful_rebind_closes_endpoints_without_adopting_or_resetting_budget -- --exact

Gate contract: Stale successful transport cannot adopt authority.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `Resident authority changes`.
Preconditions: A rebound result owns real descriptors but belongs to an older budget identity.
Observable result: Both descriptors close; tracker, desired revision, status and newer exhausted budget remain unchanged.
Evidence boundary: Host production completion helper with a supplied proc lifetime observation; native helper and Android proc reads are separate gates.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::recovery_reset_requires_current_accepted_ready_receipt_and_preserves_stale_or_waiting -- --exact

Gate contract: Only current accepted readiness resets recovery.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `A successful transport still awaits agent readiness`.
Preconditions: Real owned endpoints and the production accepted-status registry receive waiting, unreceipted, stale and current ready snapshots.
Observable result: Only the current ready receipt resets attempts; four successful recovery cycles do not exhaust a healthy identity.
Evidence boundary: Host daemon and registry; proc lifetime observation is supplied because macOS has no Android proc filesystem.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::disabled_mapped_target_preserves_pending_cleanup_and_ends_only_after_current_empty_ack -- --exact

Gate contract: Disabled mapped cleanup waits for exact quiescence.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `A disabled mapped resident may still own hooks`.
Preconditions: Ordinary-hook and executor lifecycle fixtures publish empty desired state on real owned transport.
Observable result: Missing or stale empty status retains cleanup; current accepted empty acknowledgement ends recovery without another budget or bootstrap.
Evidence boundary: Host daemon lifecycle and accepted-status registry; target hook removal remains Android evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml runtime::parallel_tests::retained_old_resident_ready_resets_only_current_global_budget_with_owned_endpoint_proof -- --exact

Gate contract: Retained resident readiness preserves current request authority.
Maps: Requirement `Failed resident transport recovery is bounded`; Scenario `Resident authority changes`.
Preconditions: Global generation advances while a verified older resident retains owned transport and current desired state.
Observable result: Only the exact owned old-resident ready receipt resets the current global budget; stale global budget, forged resident generation and stale desired revision cannot reset it.
Evidence boundary: Host daemon and accepted-status registry; Android passive cutover remains separate target evidence.

### Requirement: Successful register restoration is not a restore failure

Native failure diagnostics SHALL distinguish an interrupted or timed-out remote call from successfully completed register restoration. A completed TLS restore SHALL retain the remote-call failure stage; a genuine TLS comparison failure SHALL retain register-restore diagnostics.

#### Scenario: The remote call stops after registers are restored

- **WHEN** the native diagnostic reports remote-call-stop or remote-call-timeout and restore=tls/complete
- **THEN** the failure stage identifies the remote call and does not report a register restore failure

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::resident_transport_regression_tests::actual_cold_boot_remote_failure_does_not_claim_tls_restore_failure -- --exact

Gate contract: Accurate completed restore diagnostic.
Maps: Requirement `Successful register restoration is not a restore failure`; Scenario `The remote call stops after registers are restored`.
Preconditions: Captured cold-start stop and timeout diagnostic tokens are classified.
Observable result: Both preserve the remote-call stage and successful restore operation.
Evidence boundary: Host diagnostic parser; initial target timeout cause is unproven.

### Requirement: Bootstrap success requires owned transport endpoints

Phase-one bootstrap success SHALL require both owned log and downlink endpoints. A native success result without either endpoint SHALL become an explicit initialization failure with a bounded endpoint-adoption diagnostic.

#### Scenario: Native phase one returns success without both pipes

- **WHEN** either or both owned endpoints are missing
- **THEN** the result is initialization failure rather than untracked success

# Gate: cargo test --manifest-path daemon/Cargo.toml injector::resident_transport_regression_tests::phase_one_success_requires_both_owned_endpoints -- --exact

Gate contract: Both endpoints required for bootstrap success.
Maps: Requirement `Bootstrap success requires owned transport endpoints`; Scenario `Native phase one returns success without both pipes`.
Preconditions: Both-present and each missing endpoint combination are supplied to the production classifier.
Observable result: Only both-present success remains successful; unsafe cleanup is preserved.
Evidence boundary: Host result classifier; target descriptor adoption remains Android evidence.


## Unverified

### Unverified: Resident target rebind

Maps: Requirement `Resident implants rebind after daemon restart`; Scenario `Daemon restarts while an OEM PID remains alive`.
Unavailable observation: A live Android OEM process accepts fresh pipes, emits all fresh frame types, and does not invoke the Java entry seam again.
Reason: Host state-machine tests cannot observe an already injected ART process across a real daemon restart.
Required environment or artifact: A revision-correlated rooted arm64 target run, followed by armv7 and vehicle runs where those environments are required.
