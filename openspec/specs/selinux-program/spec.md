# SELinux program specification

## Purpose

Define the signed `voboost-selinux` release, execution, source, and watchdog boundaries.

## Requirements

### Requirement: The SELinux program is a flat unsigned product input

The component export SHALL contain one ARM64 `voboost-selinux` executable under that exact flat name. It SHALL be a regular non-symlink AArch64 non-PIE static executable (ET_EXEC, linked `-static`; NDK r29 bionic has no static-PIE self-relocator, so a static PIE SIGSEGVs during `__libc_init` before `main` on kernels such as the API 30 emulator's android11-5.4 that neither load interpreter-less ET_DYN at its link base nor apply its relocations), contain no debug section, executable stack, dynamic dependency, host path, temporary-key path or appended role signature, and use output mode `0755`. Product release tooling outside this repository SHALL assign its product-manifest role, size, SHA-256 and protected signature.

#### Scenario: Release inputs are collected

- **WHEN** the product-neutral adapter receives the complete native build output
- **THEN** it exports exactly one `voboost-selinux` input with the canonical identity and mode

# Gate: make test-prepare-beta1-unsigned

Gate contract: Flat unsigned SELinux product input.
Maps: Requirement `The SELinux program is a flat unsigned product input`; Scenario `Release inputs are collected`.
Preconditions: The canonical NDK r29 build and inspection tools are available.
Observable result: The exact ARM64 static executable is exported once as `voboost-selinux` with mode `0755`; missing, linked, dynamic, debug-bearing, path-leaking, signed and non-empty-output cases are rejected.
Evidence boundary: Local Android ELF and host adapter behavior; product-manifest signing, publication and device execution are not observed.

### Requirement: SELinux programs use the shared executable key with role selinux

`voboost-selinux` SHALL be signed by the one `native-executable` key over the exact role-bound transcript `selinux`. A signature for `daemon`, `install`, `restore`, or `uninstall` SHALL be rejected before execution. There is no separate SELinux signing key.

#### Scenario: A restore signature is placed on voboost-selinux

- **WHEN** the caller expects role `selinux` and the signed transcript contains `restore`
- **THEN** verification fails before policy bytes are opened or changed

# Gate: cargo test --manifest-path shared/Cargo.toml native_executable_signature::tests::role_signatures_are_not_interchangeable -- --exact

Gate contract: SELinux executable role separation.
Maps: Requirement `SELinux programs use the shared executable key with role selinux`; Scenario `A restore signature is placed on voboost-selinux`.
Preconditions: The disposable test key signs one fixture for each exact native executable role and verifies all expected and actual role combinations.
Observable result: Only the `selinux` transcript verifies when the caller expects `selinux`; every cross-role signature fails.
Evidence boundary: Host cryptographic behavior only; Android execution and protected publication remain separate evidence.

### Requirement: SELinux program updates use the product-system transaction

`voboost.json` SHALL list one flat `voboost-selinux` artifact with its exact role, size and SHA-256. A changed SELinux program SHALL require the protected-system activation class, the fixed init-owned Restore helper baton and the same `product-proposal.json` WAL. The daemon SHALL reject a changed SELinux program from generation-only, APK-only or ordinary native-only activation.

#### Scenario: A native-only plan selects a SELinux program

- **WHEN** an otherwise valid native-only changed set contains `voboost-selinux`
- **THEN** product planning requires protected-system activation before mutation

# Gate: cargo test --manifest-path contract/Cargo.toml product_update::tests::system_plan_requires_changed_init_or_policy_and_restore_pair -- --exact

Gate contract: SELinux protected-system activation classification.
Maps: Requirement `SELinux program updates use the product-system transaction`; Scenario `A native-only plan selects a SELinux program`.
Preconditions: The shared planner receives changed init, SELinux and restore-authority combinations.
Observable result: SELinux change is accepted only with the complete protected-system and recovery-authority class set.
Evidence boundary: Host product planning only; target policy transformation and switching are not observed.

### Requirement: Policy transformation accepts no caller path

The signed `voboost-selinux` program SHALL accept an empty argument list for policy transformation. It SHALL read the root-owned canonical `/data/voboost/operation.json`, require operation `install` at phase `install-policy-apply` or operation `restore` at phase `restore-policy-backup`, verify the SHA-256 and transaction identity of the exact correlated journal, and derive the input and output only below the fixed policy path and `/data/voboost/recovery/<transactionId>`. It SHALL expose no command that accepts an input or output path.

#### Scenario: A caller tries to select another policy file

- **WHEN** the operation phase, journal digest, transaction identity, or derived path differs from the fixed active operation
- **THEN** the SELinux program exits before opening a policy input or creating an output

# Gate: make test-selinux-policy-backup

Gate contract: Fixed policy transformation paths.
Maps: Requirement `Policy transformation accepts no caller path`; Scenario `A caller tries to select another policy file`.
Preconditions: The host fixture publishes one exact operation and correlated journal, then substitutes the phase.
Observable result: The resolver derives only the fixed transaction paths for the valid pair and rejects the substituted pair.
Evidence boundary: Host parser and path derivation only; Android ownership, SELinux labels, policy publication, and reboot remain target evidence.

### Requirement: SELinux publication is product-manifest-bound

Protected product release workflows SHALL bind the exact signed SELinux bytes and role into `voboost.json`. A publisher SHALL verify the appended `selinux` role signature, product-manifest membership, size and SHA-256 before publishing the correlated kit. A missing, extra, differently signed or cross-release SELinux artifact SHALL reject the whole kit.

#### Scenario: A SELinux release artifact is substituted

- **WHEN** the publisher receives correctly signed `voboost-selinux` bytes from another release request
- **THEN** native role and product-manifest binding reject the kit

# Unverified: SELinux external publication

### Requirement: SELinux libsepol source is reproducible

The parent repository SHALL pin the exact libsepol gitlink and Android source URL. A parent-owned patch with pinned SHA-256 SHALL carry the required xperms layout and expander regression. A clean checkout SHALL accept that patch, an exact reverse-applicable checkout MAY reuse it, and any other tracked or untracked source change SHALL fail before compilation. Compiler residue SHALL not count as source evidence.

#### Scenario: A clean libsepol checkout is prepared

- **WHEN** the pinned gitlink has no source changes
- **THEN** the source-contract gate applies the exact parent-owned patch and rejects subsequent tracked or untracked source mutation

# Gate: make test-third-party-source-contract

Gate contract: Reproducible libsepol source.
Maps: Requirement `SELinux libsepol source is reproducible`; Scenario `A clean libsepol checkout is prepared`.
Preconditions: The exact pinned gitlink and parent patch are present.
Observable result: Only clean or exact reverse-applicable source passes before compilation.
Evidence boundary: Host source identity only.

### Requirement: SELinux watchdog is async-signal-safe and bounded

`voboost-selinux` SHALL bound every invocation with a watchdog installed through `sigaction`; its signal handler SHALL call only `_exit` and perform no diagnostic I/O. Alarm delivery while ordinary logging or policy-library code holds internal locks, or while a diagnostic descriptor is blocked, SHALL not enter those facilities from the handler or prevent bounded process termination.

#### Scenario: Watchdog expires during unsafe ordinary code

- **WHEN** a subprocess holds a libc lock and invokes the production alarm handler
- **THEN** it exits with the fixed watchdog status within the host test deadline

# Gate: make test-selinux-watchdog

Gate contract: Bounded async-signal-safe watchdog.
Maps: Requirement `SELinux watchdog is async-signal-safe and bounded`; Scenario `Watchdog expires during unsafe ordinary code`.
Preconditions: The host subprocess installs the production handler while ordinary code holds a lock.
Observable result: The process exits with the fixed status inside the deadline.
Evidence boundary: Host signal behavior only; Android SELinux mutation remains separate evidence.

### Requirement: Initial helper publication retains a stock executable inode

Before product policy activation, native install SHALL publish only the verified SELinux helper from a newly reserved private directory below `/data/local/tmp`. It SHALL verify the inherited `shell_data_file` label on the retained executable FD on Android, preserve root ownership and mode `0700`, verify exact bytes, and use directory-relative atomic rename to the fixed `/data/voboost/voboost-selinux` path. Rejection SHALL remove only its own temporary and preserve a foreign destination. Installation SHALL remain Enforcing.

#### Scenario: The initial helper has a wrong label or hostile destination

- **WHEN** label verification fails or the destination is a symlink
- **THEN** publication fails, foreign bytes remain unchanged and the owned temporary is removed

#### Scenario: A verified helper is published

- **WHEN** the retained FD passes label and byte verification
- **THEN** the same inode reaches the fixed path with mode `0700` and no temporary remains

# Gate: cargo test --manifest-path install/Cargo.toml runtime::tests::stock_executable_label_rejection_and_hostile_target_preserve_foreign_bytes -- --exact

Gate contract: Initial stock executable publication.
Maps: Requirement `Initial helper publication retains a stock executable inode`; Scenario `The initial helper has a wrong label or hostile destination`
Preconditions: an injected retained-FD verifier rejects the label, or a symlink occupies the destination
Observable result: both cases fail without changing foreign bytes and leave no private temporary
Evidence boundary: host inode and cleanup semantics; Android inherited context and execution require emulator evidence.

# Gate: cargo test --manifest-path install/Cargo.toml runtime::tests::stock_executable_publication_retains_the_verified_inode_and_cleans_its_temporary -- --exact

Gate contract: Initial stock executable publication.
Maps: Requirement `Initial helper publication retains a stock executable inode`; Scenario `A verified helper is published`
Preconditions: private stock and live directories plus exact helper bytes
Observable result: retained and published inode identities match, bytes and mode match, and temporary directory is empty
Evidence boundary: host publication semantics; OEM policy access remains target evidence.

### Requirement: Policy failures preserve bounded diagnostics

The one-shot SELinux helper SHALL emit its fixed diagnostic messages to inherited stderr. Native install SHALL retain its exit code and at most 512 diagnostic characters in the failed operation and progress message. Diagnostic capture SHALL remain bounded and SHALL NOT authorize another executable or path.

#### Scenario: Policy input cannot be read

- **WHEN** the helper fails with exit code 3 and a fixed input diagnostic
- **THEN** the caller preserves both the exit code and cause in its failed operation

# Gate: cargo test --manifest-path install/Cargo.toml policy::tests::failed_policy_transformation_preserves_the_bounded_exit_and_diagnostic -- --exact

Gate contract: One-shot policy failure diagnostics.
Maps: Requirement `Policy failures preserve bounded diagnostics`; Scenario `Policy input cannot be read`.
Preconditions: a failed bounded subprocess result contains exit code 3 and the fixed policy path diagnostic.
Observable result: the native failure message contains that exit code and diagnostic.
Evidence boundary: host error propagation; the reason for a live policy failure requires emulator evidence.

### Requirement: Initial policy reconstruction preserves the stock boot source

When reading the loaded kernel policy fails with EACCES or EPERM, the signed helper SHALL derive its base only from fixed trusted firmware files using the Android 9 or 11 boot decision. It SHALL prefer ODM precompiled policy over vendor and require all applicable platform, system_ext and product hash pairs to match before accepting that binary. Otherwise it SHALL use the fixed stock compiler and immutable snapshots of every required or present optional CIL fragment. Input ownership, regular single-link identity, modes and byte bounds SHALL be verified. Snapshot integrity SHALL use sealing where permitted or private unlinked root-zone files with exact byte, SHA-256 and creation-stamp revalidation after compiler execution. Vendor mapping names SHALL be canonical supported versions. It SHALL NOT enable Permissive, grant broader su rights, omit a present unsafe fragment or silently lower an unsupported policy format. Android compiler execution SHALL retain the verified program inode; watchdog expiry SHALL stop its child. All anonymous snapshot descriptors SHALL close after success or failure.

#### Scenario: Sidecars differ or optional CIL contributes to the boot policy

- **WHEN** precompiled hashes do not match or system_ext, product, compat or ODM CIL is present
- **THEN** reconstruction preserves each selected fragment and rejects unsafe or missing required input

#### Scenario: Compiler execution fails or exceeds its deadline

- **WHEN** the stock compiler exits unsuccessfully or remains active beyond the watchdog
- **THEN** reconstruction fails without leaked descriptors or a running compiler child

# Gate: make test-selinux-boot-source

Gate contract: Stock boot source selection and immutable compiler inputs.
Maps: Requirement `Initial policy reconstruction preserves the stock boot source`; Scenarios `Sidecars differ or optional CIL contributes to the boot policy` and `Compiler execution fails or exceeds its deadline`.
Preconditions: isolated trusted-firmware fixtures cover Android 9 and 11, modern and legacy vendor CIL, matching and mismatching precompiled sidecars, ODM priority, unsafe inputs, unsupported version and a stalled compiler.
Observable result: every selected fragment reaches the compiler, mismatches do not select stale vendor bytes, unsafe inputs fail, descriptor count returns to baseline and watchdog kills the owned compiler.
Evidence boundary: host selection, snapshots and process ownership; real stock compiler behavior under OEM Enforcing requires emulator evidence.

## Unverified

### Unverified: SELinux external publication

Maps: Requirement `SELinux publication is product-manifest-bound`; Scenario `A SELinux release artifact is substituted`.

Unavailable observation: A protected signing job binds the exact SELinux artifact to `voboost.json` and publishes one correlated external release.

Reason: Host tests have no protected product key or external publication authority.

Required environment or artifact: Protected signing and publication records, final signed product manifest, correlated artifacts, and attestation for one exact release request.
