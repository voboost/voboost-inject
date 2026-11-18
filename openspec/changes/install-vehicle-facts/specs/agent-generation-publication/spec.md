## MODIFIED Requirements

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
# Unverified: Android installation and physical vehicle cache acceptance remain required.
