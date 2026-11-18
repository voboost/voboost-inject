# Agent generation publication specification

## Purpose

Define generation freshness, daemon-owned facts and crash-safe publication.

## Requirements

### Requirement: Generation freshness is product-manifest-owned

The independently signed `agents.json` SHALL contain no component version. Product freshness SHALL come only from signed `voboost.json` and its canonical product SemVer. Initial install MAY create the first valid generation without a predecessor only while the matching install operation and frozen product manifest authorize it. Direct app-authored generation staging SHALL be disabled. An exact catalog and computed-selection replay SHALL be accepted only as the idempotent recovery path for the activation-to-acknowledgement crash window.

#### Scenario: App authors a standalone generation

- **WHEN** no correlated install operation or product candidate authority exists
- **THEN** production activation rejects app-owned generation staging without changing `current`

#### Scenario: The accepted catalog is replayed after an acknowledgement loss

- **WHEN** catalog digest, verified inventory and computed selection match the active generation
- **THEN** activation is an idempotent no-op and an accepted acknowledgement can be republished

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::production_generation_source_requires_correlated_install_authority -- --exact
Gate contract: Initial generation source admission.
Maps: Requirement `Generation freshness is product-manifest-owned`; Scenario `App authors a standalone generation`.
Preconditions: The host test evaluates production admission with and without a correlated install authority.
Observable result: Only the install-authorized branch is admitted.
Evidence boundary: Host admission predicate only; Android UID, filesystem ownership and product signature are covered by separate gates.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::same_catalog_new_root_selection_activates_and_retains_prior_generation -- --exact
Gate contract: Exact named verification for product-manifest-owned generation freshness.
Maps: Requirement `Generation freshness is product-manifest-owned`; Scenario `The accepted catalog is replayed after an acknowledgement loss`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Agent applicability uses frozen daemon-owned facts

The device installer SHALL resolve and atomically persist bounded typed chip, vehicle, Android, powertrain and market facts in root-owned `vehicle.json` before publishing the init service definition. Normal daemon startup SHALL read the existing trusted facts without NVRAM access or automatic rewriting. Explicit `--recompute-profile` SHALL be the diagnostic refresh path. Native powertrain admission SHALL reject missing, corrupt, contradictory or identity-mismatched cached facts without a hybrid default. Schema-1 selection SHALL use only each agent's signed broad applicability matrix and those root-owned facts. APK identity SHALL NOT change applicability, select an agent or select an in-process adapter. Java capability SHALL be decided only inside the agent's signed target process by that agent's runtime contracts, and one Java contract failure SHALL remain isolated to that agent.

Initial publication and diagnostic recomputation of `vehicle.json` SHALL write a fresh root-owned mode `0644` single-link temporary inode, fsync it, atomically rename it over the final name and fsync the parent directory. Any failure before rename SHALL preserve the prior final file. Property resolution SHALL examine declared sources in authority order: recognized higher-authority vehicle identity wins over documented neutral generic values, unknown noise SHALL NOT mask a later recognized fallback, and conflicting recognized identities SHALL produce `conflicting-sources`.

Market resolution SHALL normalize only ASCII case and surrounding whitespace, recognize exactly `zh-CN` as China and `ru-RU` or `ar-SA` as global, and reject every prefix, suffix, embedded, malformed or otherwise unrecognized locale. In particular, the observed `en-US` value from the Chinese NXP firmware SHALL remain unknown because it does not identify that firmware's market.

The resolver regression evidence SHALL contain exactly 14 unique Free/Dreamer firmware identities. Every row SHALL pin unique canonical OEM property-file provenance paths and lowercase SHA-256 values, exact raw chip, vehicle, Android and locale inputs, and the expected product facts. Host tests SHALL consume only the committed offline table and SHALL NOT require the external OEM source tree. Evidence hashes SHALL NOT become a runtime firmware allowlist or participate in applicability or selection.

#### Scenario: Powertrain is unknown

- **WHEN** all known facts match an agent matrix and powertrain is unavailable
- **THEN** the agent remains `unknown`, enters the immutable generation and receives the exact unknown reason without consulting APK bytes

#### Scenario: A known fact mismatches

- **WHEN** one known root fact is outside an agent's signed applicability matrix
- **THEN** that agent is `unsupported` and excluded without changing unrelated agents

# Gate: cargo test --release --manifest-path shared/Cargo.toml vehicle_profile::tests::known_probes_map_to_catalog_vocabulary -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml selection::tests::known_mismatch_wins_over_unknown -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --release --manifest-path shared/Cargo.toml vehicle_profile::tests::failed_atomic_profile_publication_preserves_old_file -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --release --manifest-path shared/Cargo.toml vehicle_profile::tests::vehicle_a11_authority_ignores_documented_generic_product -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --release --manifest-path shared/Cargo.toml vehicle_profile::tests::chip_falls_through_unknown_noise_and_rejects_recognized_conflict -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --release --manifest-path shared/Cargo.toml vehicle_profile::tests::market_exact_allowlist_accepts_case_and_surrounding_whitespace -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --release --manifest-path shared/Cargo.toml vehicle_profile::tests::market_exact_allowlist_rejects_prefix_suffix_embedded_and_unreliable_locale -- --exact
Gate contract: Exact named verification for Agent applicability uses frozen daemon-owned facts.
Maps: Requirement `Agent applicability uses frozen daemon-owned facts`; Scenarios `Powertrain is unknown`, `A known fact mismatches`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
### Requirement: Selection receipts freeze exact applicability evidence

The schema-1 selection receipt SHALL freeze the exact catalog digest, facts, ordered agent set, result and ordered unknown-axis reasons. It SHALL contain no firmware profile, APK identity or compatibility fingerprint and SHALL remain unsigned because it is machine-specific daemon output derived from signed catalog and root-owned facts. Initial install SHALL never consume an app-authored receipt. Any other schema version SHALL be rejected.

#### Scenario: A selection receipt changes applicability evidence

- **WHEN** receipt facts, agent order, result or unknown-axis reasons differ from the computed selection
- **THEN** generation verification rejects the receipt

# Gate: cargo test --manifest-path daemon/Cargo.toml selection::tests::verify_rejects_every_receipt_correlation_forgery -- --exact
Gate contract: Exact named verification for Selection receipts freeze exact applicability evidence.
Maps: Requirement `Selection receipts freeze exact applicability evidence`; Scenario `A selection receipt changes applicability evidence`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Generation publication proves every wire budget before mutation

Signed `agents.json` SHALL be non-empty and at most 1,048,576 exact bytes in the producer, daemon, app, installer and release tooling. The daemon SHALL accept N bytes and reject N+1 bytes before parsing or mutation. Before any activation journal or pointer mutation, the daemon SHALL also prove that the maximum catalog-valid desired `D`, acknowledgement `A`, and bootstrap manifest fit their exact 60 KiB, 60 KiB, and 2 MiB wire limits. Those proofs SHALL cover the N-1, N and N+1 boundaries.

#### Scenario: Generation wire content exceeds one exact budget

- **WHEN** the maximum valid desired document, acknowledgement or bootstrap manifest is one byte over its limit
- **THEN** activation fails before journal or pointer publication

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject catalog::tests::catalog_byte_bound_is_exactly_one_mib_inclusive -- --exact
Gate contract: Exact catalog byte-bound verification before generation mutation.
Maps: Requirement `Generation publication proves every wire budget before mutation`; Scenario `Generation wire content exceeds one exact budget`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The named test accepts the exact one-MiB catalog boundary and rejects the first byte beyond it before catalog parsing or generation mutation.
Evidence boundary: Host parser boundary evidence only; app and installer producers, Android filesystem mutation, publication, and vehicle behavior are not inferred.

# Gate: cargo test --manifest-path daemon/Cargo.toml bootstrap_pipe::tests::manifest_budget_accepts_n_minus_one_and_n_but_rejects_n_plus_one -- --exact
Gate contract: Exact named verification for Generation publication proves every wire budget before mutation.
Maps: Requirement `Generation publication proves every wire budget before mutation`; Scenario `Generation wire content exceeds one exact budget`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml tests::exact_downlink_budget_accepts_n_minus_one_and_n_but_rejects_n_plus_one -- --exact
Gate contract: Exact named verification for Generation publication proves every wire budget before mutation.
Maps: Requirement `Generation publication proves every wire budget before mutation`; Scenario `Generation wire content exceeds one exact budget`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Immutable generation copy contains the complete signed closure

Every target DEX in the independently signed catalog SHALL enter staging and the root-owned immutable generation together with catalog, signature and common core. Agents with `supported` or `unknown` applicability SHALL enter the selected injection set; unsupported agents SHALL remain unselected but their signed DEX bytes SHALL stay materialized for later daemon-owned applicability changes without a download. The daemon SHALL verify the exact complete signed inventory before publication and SHALL load only files reachable from the current verified selection.

#### Scenario: Immutable generation copy differs from the signed catalog closure

- **WHEN** the temporary generation contains a missing, extra or linked inventory member
- **THEN** verification rejects the copy before pointer publication

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::exact_inventory_rejects_missing_extra_and_linked_entries -- --exact
Gate contract: Exact named verification for Immutable generation copy contains the complete signed closure.
Maps: Requirement `Immutable generation copy contains the complete signed closure`; Scenario `Immutable generation copy differs from the signed catalog closure`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.
# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::required_artifact_closure_accepts_exact_and_rejects_missing_or_extra -- --exact
Gate contract: Exact named verification for Immutable generation copy contains the complete signed closure.
Maps: Requirement `Immutable generation copy contains the complete signed closure`; Scenario `Immutable generation copy differs from the signed catalog closure`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Shared module generation inventory preserves target authority

An immutable generation SHALL contain each unique target module filename once. Repeated target rows SHALL preserve their signed per-process entry class and module authority. Product correlation SHALL compare the exact unique module filename, size and SHA-256 set, and SHALL reject duplicate product artifact rows. Reserved catalog, receipt, signature and core inventory filenames SHALL retain hard collision rejection.

#### Scenario: Multiple target processes share one module

- **WHEN** a verified logical agent repeats one exact module identity across distinct processes
- **THEN** generation import materializes one module and each process bootstrap carries the verified module bytes and entry class

#### Scenario: Product module closure is ambiguous

- **WHEN** a product manifest repeats a module artifact row or differs from the catalog module identity
- **THEN** correlation rejects the product generation

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject generation::tests::shared_agent_module_is_materialized_once_and_bootstrapped_for_each_process -- --exact
Gate contract: One immutable file retains each target bootstrap authority.
Maps: Requirement `Shared module generation inventory preserves target authority`; Scenario `Multiple target processes share one module`.
Preconditions: A signed two-process host catalog references one physical module.
Observable result: Production product materialization and retained-generation reload contain one module file; both real bootstrap envelopes contain the exact core/module bytes and entry class.
Evidence boundary: Host generation filesystem and production bootstrap serializer; Android injection and OTA from a native version that rejects shared modules are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml --bin voboost-inject generation::tests::product_generation_correlates_unique_modules_and_rejects_duplicate_artifacts -- --exact
Gate contract: Product correlation uses a unique exact module set.
Maps: Requirement `Shared module generation inventory preserves target authority`; Scenario `Product module closure is ambiguous`.
Preconditions: A two-target shared module matches one product row; mutations duplicate that product row or change its size, and repeat a reserved inventory filename.
Observable result: Exact correlation succeeds; each ambiguity fails.
Evidence boundary: Host product correlation and inventory collision checks only.

### Requirement: Generation pointer publication preserves the prior current generation

After immutable-copy verification, the daemon SHALL fsync and atomically replace bounded `current` and `previous` pointer files. Failure SHALL preserve the prior current generation.

#### Scenario: Publication fails before pointer replacement

- **WHEN** copy, identity, fsync or rename fails
- **THEN** `current` continues to identify the prior complete generation

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::every_activation_crash_window_recovers_exact_pointer_plan_and_ack -- --exact
Gate contract: Exact named verification for Generation pointer publication preserves the prior current generation.
Maps: Requirement `Generation pointer publication preserves the prior current generation`; Scenario `Publication fails before pointer replacement`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Retained generation verification uses its frozen receipt facts

Current root facts SHALL authorize only an incoming selection. Every retained generation SHALL reverify against the facts frozen in its own canonical receipt so a later profile recomputation cannot corrupt it.

#### Scenario: Root facts change after a generation is retained

- **WHEN** a later vehicle-profile recomputation differs from the receipt stored in a retained generation
- **THEN** retained verification uses its own frozen receipt rather than applying the new root facts retroactively

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::frozen_pair_snapshots_survive_mutation_through_preopened_app_fds -- --exact
Gate contract: Exact named verification for Retained generation verification uses its frozen receipt facts.
Maps: Requirement `Retained generation verification uses its frozen receipt facts`; Scenario `Root facts change after a generation is retained`.
Preconditions: The exact named command runs with committed host fixtures and its required local toolchain.
Observable result: The command passes only when its named assertions accept the required branch and reject the mapped failure condition.
Evidence boundary: Exact host-test evidence for the mapped assertions; CI, protected keys, Android device, SELinux Enforcing, live injection, publication and vehicle behavior are not inferred.

### Requirement: Validated install acknowledgement retains continuation liveness

While the correlated install WAL remains `install-agents` with one recorded boot, the synchronous watcher SHALL retry only the fixed `ctl.start voboost-install` request after validating the durable acknowledgement against its transaction, APK, catalog, selection, and active generation. This retry SHALL NOT restage a generation or rewrite the acknowledgement or WAL. A start request accepted while the original oneshot service is running SHALL NOT permanently suppress continuation after that service exits. Malformed or mismatched acknowledgement, foreign operation, or advanced install WAL SHALL NOT request a continuation. A rejected start callback SHALL remain observable and retryable without changing the durable acknowledgement.

#### Scenario: Initial continuation request is an already-running no-op

- **WHEN** acknowledgement publication succeeds but the original service is still running, then that service exits while the install WAL remains at the generation handoff
- **THEN** the next watcher preparation retries the fixed continuation with unchanged acknowledgement and WAL bytes and no generation restaging

#### Scenario: Acknowledgement or install authority differs

- **WHEN** acknowledgement is malformed or its transaction, APK, catalog, selection, or generation differs, or a foreign operation or advanced WAL is current
- **THEN** watcher preparation requests no service start

#### Scenario: Fixed continuation request fails

- **WHEN** the start callback rejects a validated acknowledgement retry
- **THEN** preparation reports the failure, preserves acknowledgement bytes, and a later preparation retries successfully

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::validated_install_ack_retriggers_after_initial_start_is_a_running_noop -- --exact
Gate contract: Named install acknowledgement liveness branch.
Maps: Requirement `Validated install acknowledgement retains continuation liveness`; Scenario `Initial continuation request is an already-running no-op`.
Preconditions: Production ACK publication calls an isolated init-service callback while running; the original service then stops before the production watcher preparation seam.
Observable result: The next preparation wakes continuation once without restaging or changing acknowledgement/WAL bytes.
Evidence boundary: Host production state-store/sequencing with an isolated init-service callback; real Android init execution requires target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::install_ack_retrigger_rejects_malformed_mismatched_foreign_and_advanced_authority -- --exact
Gate contract: Named install acknowledgement liveness branch.
Maps: Requirement `Validated install acknowledgement retains continuation liveness`; Scenario `Acknowledgement or install authority differs`.
Preconditions: A valid pending install fixture is mutated across every named acknowledgement identity plus malformed data, foreign operation, and advanced WAL.
Observable result: Each preparation rejects before the callback, with zero starts.
Evidence boundary: Host trusted-file authority parsing and generation correlation only; target SELinux/init behavior is outside this gate.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::install_ack_retrigger_failure_remains_observable_and_retries_unchanged_ack -- --exact
Gate contract: Named install acknowledgement liveness branch.
Maps: Requirement `Validated install acknowledgement retains continuation liveness`; Scenario `Fixed continuation request fails`.
Preconditions: Valid pending install first has a rejecting start callback and then a succeeding callback.
Observable result: First preparation returns the error; later preparation starts once and retains identical ACK bytes.
Evidence boundary: Host production retry/error propagation; target property-service availability is not simulated as proof.

### Requirement: Install handoff observations serialize operation pointer and WAL

Startup handoff and public initial-generation preparation SHALL observe pointer and WAL under the retained existing shared `operation.lock`. Only actual writer lock contention SHALL produce typed Busy; Busy SHALL wait without requesting an installer or staging/activating a generation. A stable digest or I/O violation SHALL remain an error. A lockless absence observation SHALL remain None and SHALL NOT be re-read as unlocked install authority. Preparation SHALL retain observation through staging reads/writes and release it before fixed continuation callbacks. Internal reads already owned by an exclusive generation guard SHALL NOT acquire a nested observer lock.

#### Scenario: Writer pauses between WAL and pointer publication

- **WHEN** an exclusive writer has replaced the WAL and has not published the new pointer
- **THEN** serialized observation returns Busy instead of reading a mixed pair, and after publication and release returns the exact new pair

#### Scenario: Corruption or observer lock identity differs

- **WHEN** no writer holds the lock and the WAL differs from the pointer, or observer lock mode, nofollow identity, named inode, or required existence is violated
- **THEN** observation rejects rather than classifying the condition as Busy or an unlocked snapshot

#### Scenario: Startup or preparation observes Busy

- **WHEN** startup or initial preparation encounters a retained operation writer
- **THEN** startup waits with zero fixed start requests for Busy, preparation leaves staging unchanged, and a later validated ACK wake can immediately claim the operation lease

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::serialized_observation_reports_busy_during_wal_pointer_cut_and_rejects_stable_corruption -- --exact
Gate contract: Serialized two-file publication observation.
Maps: Requirement `Install handoff observations serialize operation pointer and WAL`; Scenarios `Writer pauses between WAL and pointer publication`, `Corruption or observer lock identity differs`.
Preconditions: A real host thread holds the production EX lease, atomically replaces WAL, pauses before pointer publication, then publishes and releases; a later stable corruption is introduced without a writer.
Observable result: Legacy unlocked read reproduces digest failure at the cut; the new observer returns Busy, later sees the exact new pointer, and rejects the stable corruption.
Evidence boundary: Host production file-lock and reader/writer protocol only; target boot scheduling remains emulator evidence.

# Gate: cargo test --manifest-path contract/Cargo.toml operation::tests::serialized_observation_preserves_lock_identity_and_absence_boundaries -- --exact
Gate contract: Observer lock and lockless absence boundaries.
Maps: Requirement `Install handoff observations serialize operation pointer and WAL`; Scenario `Corruption or observer lock identity differs`.
Preconditions: Host observes an empty root, later publishes an operation, then replaces the retained lock inode and exercises wrong mode, symlink and missing-lock cases.
Observable result: Empty snapshot remains None without creating a lock; each lock violation rejects rather than exposing unlocked authority.
Evidence boundary: Host trusted-file/inode/nofollow behavior; Android ownership policy remains target evidence.

# Gate: cargo test --manifest-path daemon/Cargo.toml tests::install_handoff_busy_waits_without_start_and_stable_errors_fail -- --exact
Gate contract: Busy handoff admission.
Maps: Requirement `Install handoff observations serialize operation pointer and WAL`; Scenario `Startup or preparation observes Busy`.
Preconditions: The production wait loop receives Busy, authenticated Pending, and Ready; a separate call receives a stable error.
Observable result: Busy waits without start, only Pending starts once, and stable error returns without waiting or another start.
Evidence boundary: Host startup control flow only; property service is isolated.

# Gate: cargo test --manifest-path daemon/Cargo.toml generation::tests::initial_install_preparation_busy_preserves_staging_and_drops_reader_before_wake -- --exact
Gate contract: Preparation serialization and callback lock release.
Maps: Requirement `Install handoff observations serialize operation pointer and WAL`; Scenario `Startup or preparation observes Busy`.
Preconditions: Valid pending install first has a retained EX writer, then releases it and uses a wake callback that immediately acquires the real install-generation lease.
Observable result: Busy causes zero starts and byte-identical staging; after release the callback acquires the lease and starts exactly once.
Evidence boundary: Host production preparation and file-lock ordering; actual Android continuation remains target evidence.
