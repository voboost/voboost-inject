# Injector linker reconstruction specification

## Purpose

Define bounded proc-maps and linker reconstruction.

## Requirements

### Requirement: Proc maps and linker reconstruction are bounded

Rust reconciliation SHALL read and fully parse `/proc/<pid>/maps` once per target attempt as one bounded immutable snapshot, then use that same snapshot for implant, foreign-footprint and bitness classification. An over-cap, incomplete, malformed or invalid UTF-8 document SHALL fail without classifying a partial prefix. The implant marker SHALL be only the exact canonical per-ABI payload path, optionally followed by the exact kernel ` (deleted)` suffix; foreign markers SHALL match complete known basenames or path tokens. Bitness SHALL use only an exact recognized `app_process` executable basename or exact Android 9/system-APEX linker or libc path, and conflicting 32/64 evidence SHALL fail closed.

Target-controlled maps text SHALL never authorize a different process, library or artifact identity. Within the fixed snapshot and retry bounds it can only make that injection attempt fail closed; repeated rejection is a bounded availability failure, not identity authority.

#### Scenario: A daemon maps snapshot is incomplete

- **WHEN** the bounded maps document is truncated, malformed or contains conflicting bitness evidence
- **THEN** daemon classification fails without using a partial prefix or authorizing another identity

#### Scenario: Maps evidence is ambiguous or only a substring match

- **WHEN** a path merely contains an implant or foreign marker, or exact map entries provide conflicting ABI evidence
- **THEN** the daemon does not classify that substring as an implant or foreign footprint and does not choose an ABI from ambiguous evidence

# Gate: cargo test --manifest-path daemon/Cargo.toml reconcile::tests::snapshot_rejects_over_cap_incomplete_malformed_and_invalid_utf8_documents -- --exact
Gate contract: Bounded maps snapshot admission.
Maps: Requirement `Proc maps and linker reconstruction are bounded`; Scenario `A daemon maps snapshot is incomplete`.
Preconditions: The exact Rust test supplies over-cap, incomplete, malformed and invalid UTF-8 maps documents.
Observable result: Every invalid document is rejected without returning a partial snapshot.
Evidence boundary: Host Rust parsing only; live `/proc` mutation and Android process identity are not exercised.

# Gate: cargo test --manifest-path daemon/Cargo.toml reconcile::tests::one_snapshot_drives_exact_injected_foreign_and_bitness_classifiers -- --exact
Gate contract: Exact maps classification.
Maps: Requirement `Proc maps and linker reconstruction are bounded`; Scenario `Maps evidence is ambiguous or only a substring match`.
Preconditions: The exact Rust test feeds one immutable snapshot containing exact, substring and conflicting classification evidence.
Observable result: Only exact canonical entries classify, and conflicting ABI evidence fails closed.
Evidence boundary: Host classification over a synthetic snapshot; no Android target attempt is performed.

### Requirement: Native linker ELF reconstruction is bounded

The native resolver SHALL accept only the exact canonical dynamic-linker pathname for the target build: Android 9 `/system/bin/linker64` or `/system/bin/linker`, or Android 10+ `/apex/com.android.runtime/bin/linker64` or `/apex/com.android.runtime/bin/linker`. It SHALL reject deleted or basename-only matches, bound maps bytes and line count, bound linker mapping count and total mapped bytes, and use checked range/offset arithmetic before allocating at most 32 MiB. The resolver SHALL derive load bias by matching every `PT_LOAD` file offset to its live mapping and SHALL reject inconsistent or ambiguous mappings. The reconstructed ELF parser SHALL require exact program-header and symbol-entry sizes, keep every table inside its checked image range, require `DT_NULL` inside the exact `PT_DYNAMIC` file range, require resolved loader exports to lie in an executable `PT_LOAD`, and reject overflow while combining string-table or symbol-address fields.

#### Scenario: A linker-like basename appears outside the canonical path

- **WHEN** the maps entry is not the exact canonical Android linker pathname
- **THEN** it contributes neither load bias nor reconstructed linker bytes

#### Scenario: A reconstructed ELF table is malformed

- **WHEN** a header, dynamic entry, string table or symbol address exceeds its checked range or arithmetic bound
- **THEN** resolution fails without returning a symbol address

# Gate: make test-injector-elf-parse
Gate contract: Native linker ELF reconstruction is bounded host contract.
Maps: Requirement `Native linker ELF reconstruction is bounded`; Scenarios `A linker-like basename appears outside the canonical path`, `A reconstructed ELF table is malformed`.
Preconditions: The dedicated Make test target runs its committed fixtures and selects only the named contract harness.
Observable result: it contributes neither load bias nor reconstructed linker bytes; resolution fails without returning a symbol address.
Evidence boundary: Host execution of the named harness; Android device, SELinux Enforcing, protected CI configuration, publication and vehicle behavior are not inferred.

### Requirement: Namespace loading uses typed target-ABI contracts

The injector SHALL resolve the target linker's namespace exports before the
first namespace mutation and SHALL load the verified payload through one
isolated namespace with an explicit `ANDROID_DLEXT_USE_NAMESPACE` extinfo.
The namespace SHALL link only the reviewed platform SONAME allowlist and SHALL
not use SHARED, link-all-libs, a global linker-configuration mutation, a
nativeLibraryDir copy, or a manual ELF loader. ARM64 arguments SHALL use the
target register layout. ARM32 namespace creation SHALL use the AAPCS32 aligned
uint64 stack layout, preserve temporary stack bytes, and serialize extinfo with
the target pointer width. A null remote handle or false remote bool SHALL be
treated as a failed operation, independently of the remote-call transport
status.

#### Scenario: ARM32 namespace creation has an aligned uint64 argument

- **WHEN** the injector prepares `__loader_android_create_namespace` for an
  ARM32 target
- **THEN** the first three pointers are placed in r0-r2, r3 remains unused,
  the uint64 type occupies stack words 0-1, and the remaining pointers occupy
  stack words 2-4; the original bytes are restored after the call

# Gate: make test-injector-namespace-abi
Gate contract: Namespace target-ABI serialization and ARM32 argument placement.
Maps: Requirement `Namespace loading uses typed target-ABI contracts`; Scenario `ARM32 namespace creation has an aligned uint64 argument`.
Preconditions: The host harness exercises the fixed ARM64/ARM32 extinfo layouts, pointer-width rejection, isolated namespace constants and AAPCS32 stack layout.
Observable result: The serialized buffers and register/stack words match the target ABI and invalid wide ARM32 pointers are rejected.
Evidence boundary: Host serialization only; Android private linker export availability, ptrace execution, SELinux Enforcing and vehicle behavior are not inferred.
