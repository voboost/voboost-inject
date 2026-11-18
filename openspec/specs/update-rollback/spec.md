# Update rollback specification

## Purpose

Define crash-safe rollback for the single product candidate transaction.

## Requirements

### Requirement: Product activation converges to one complete release

Before the first live mutation, `product_candidate` SHALL preserve every replaced native, generation, restore, APK and protected-system authority in the transaction recovery directory and publish one canonical `product-proposal.json` under the global operation lease. Every restart SHALL continue from that WAL. Failure SHALL restore the complete previous product; success SHALL verify the complete candidate product. Neither outcome may accept mixed artifact identities.

#### Scenario: Native activation is interrupted at any durable cut

- **WHEN** a crash occurs during native candidate preparation, member switching, reboot publication, post-boot verification, inventory publication or product-manifest publication
- **THEN** recovery converges to the complete old or complete new signed product

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::native_only_reboot_and_rollback_cuts_converge_old_or_new -- --exact
Gate contract: Native product crash convergence.
Maps: Requirement `Product activation converges to one complete release`; Scenario `Native activation is interrupted at any durable cut`.
Preconditions: The host test injects every modeled durable native activation and rollback cut.
Observable result: Each cut converges to one verified old or new product closure.
Evidence boundary: Host filesystem and boot-ID fixtures; target power-loss durability is not exercised.

### Requirement: Mixed APK/native activation failure converges forward

For a mixed transaction whose APK was already replaced out-of-band (the host APK observation proves the candidate APK identity with `ApkObserved` or later durable phase), a native activation failure SHALL NOT roll the native members back to the previous release: the previous manifest names the previous APK identity and cannot be republished without accepting a mixed old/new product. The transaction SHALL converge forward to the complete candidate release by re-deriving every live member from the verified complete closure (idempotent re-publication of native members, restore pair, uninstall inventory and manifest pair, signature-first/manifest-last) and terminate. The invoking pass SHALL report `ActivationFailed` while the durable product is the complete candidate release. When the live host APK observation cannot prove the candidate APK identity, the failure SHALL fail closed with an explicit error: the transaction stays durable pending supersede by a newer channel release.

#### Scenario: Commit verification fails after the APK was replaced

- **WHEN** a mixed APK/native transaction fails commit verification after the new APK is live on the host
- **THEN** the transaction converges to the complete candidate release without ever accepting the previous manifest pair with the new APK

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::mixed_apk_native_activation_failure_rolls_forward_to_the_observed_candidate_apk -- --exact
Gate contract: Mixed activation forward convergence.
Maps: Requirement `Mixed APK/native activation failure converges forward`; Scenario `Commit verification fails after the APK was replaced`.
Preconditions: The host test drives a mixed transaction through APK install, observation, native member switching and post-reboot commit, then fails commit verification on the uninstall inventory.
Observable result: The failed pass reports `ActivationFailed`, the active product is the complete candidate release, the terminal result later reads `Accepted`, and no durable proposal remains.
Evidence boundary: Host filesystem and boot-ID fixtures; out-of-band PackageInstaller behavior is modeled by the durable host APK observation.

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::mixed_apk_native_rollback_fails_closed_without_the_observed_candidate_apk -- --exact
Gate contract: Mixed failure fail-closed without the observed candidate APK.
Maps: Requirement `Mixed APK/native activation failure converges forward`; Scenario `Commit verification fails after the APK was replaced`.
Preconditions: The host test removes the host APK observation before failing commit verification.
Observable result: The recovery fails closed with an explicit error; neither a mixed product nor the previous manifest pair is accepted.
Evidence boundary: Host filesystem and boot-ID fixtures; out-of-band PackageInstaller behavior is modeled by the durable host APK observation.

### Requirement: Running daemon verification binds the opened inode

Post-reboot verification SHALL open the running executable once, require a regular single-link root-owned mode-`0700` file, hash exactly the manifest-declared size from that descriptor and reject metadata change, growth or digest mismatch. Product SemVer SHALL not participate in native executable verification.

#### Scenario: Running executable changes during verification

- **WHEN** its metadata, size or bytes differ from the `voboost.json` daemon row
- **THEN** product activation rejects the running daemon identity

# Gate: cargo test --manifest-path daemon/Cargo.toml native_binary::tests::running_executable_rejects_growth_and_wrong_digest -- --exact
Gate contract: Running daemon exact-inode verification.
Maps: Requirement `Running daemon verification binds the opened inode`; Scenario `Running executable changes during verification`.
Preconditions: The host test grows one opened executable after the first stat and checks a same-size wrong digest.
Observable result: Both substitutions are rejected.
Evidence boundary: Host descriptor semantics; Android `/proc/self/exe` is not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml native_binary::tests::running_executable_rejects_wrong_mode_or_link_count -- --exact
Gate contract: Running daemon metadata verification.
Maps: Requirement `Running daemon verification binds the opened inode`; Scenario `Running executable changes during verification`.
Preconditions: The host test changes executable mode and creates a second hard link.
Observable result: Each unsafe identity is rejected.
Evidence boundary: Host filesystem metadata; Android SELinux context is not exercised.

### Requirement: Product manifest is committed last

After all changed artifacts, generation pointers, restore authority and uninstall inventory are durable and verified, activation SHALL publish `voboost.json.sig` followed by `voboost.json`. It SHALL then reload the active signed manifest, verify the complete installed closure and publish the terminal result. Rollback SHALL use the preserved previous manifest pair in the same signature-first, manifest-last order.

#### Scenario: Execution stops after product signature publication

- **WHEN** the candidate signature is live but `voboost.json` still names the previous product
- **THEN** restart uses the WAL and converges without accepting the mixed manifest pair as terminal

# Gate: cargo test --manifest-path daemon/Cargo.toml product_candidate::tests::generation_only_crash_cuts_converge_and_accept_only_terminal_replay -- --exact
Gate contract: Product manifest-last recovery.
Maps: Requirement `Product manifest is committed last`; Scenario `Execution stops after product signature publication`.
Preconditions: The host test injects restore, generation, inventory, manifest-signature and terminal-result cuts.
Observable result: Replay stays pending until one complete product and terminal result are durable.
Evidence boundary: Host crash-cut model; target fsync hardware durability is not exercised.
