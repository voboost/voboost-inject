# SELinux root zone specification

## Purpose

Define the root-zone staging exception and filesystem-label boundary.

## Requirements

### Requirement: Generated label authority

The build SHALL generate file-context ordering and native relabel constants
from one typed native label contract and SHALL NOT write generated files into
a sibling checkout. Exact entries for `voboost_exec`,
`voboost_install_exec`, stock-labeled `voboost-restore`,
`voboost_uninstall_exec`, `voboost_operation_file`,
`voboost_install_staging_file`, `voboost_recovery_file`,
`voboost_agent_state_file`, and `voboost_uninstall_data_file` SHALL precede
the root-zone catch-all. The SELinux program SHALL be verified as
`voboost_selinux_exec`.

#### Scenario: Restorecon and the native walker agree on narrow labels

- **WHEN** generated file contexts or the descriptor-bound relabel walker classify committed root-zone members
- **THEN** each executable and purpose-owned tree receives its exact target type, restore receives stock `system_file`, and none is classified by the root-zone catch-all

# Gate: make test-selinux-label-contract
Gate contract: Generated file-context completeness and order.
Maps: Requirement `Generated label authority`; Scenario `Restorecon and the native walker agree on narrow labels`.
Preconditions: Node loads the typed contract and the committed generated `file_contexts` output.
Observable result: Every target entry precedes the catch-all, restore is stock-labeled, and the SELinux program uses its dedicated exec label.
Evidence boundary: Static generated-source comparison; Android restorecon and target filesystem labels are not observed.

# Gate: make test-selinux-relabel-walk
Gate contract: Generated native relabel classification.
Maps: Requirement `Generated label authority`; Scenario `Restorecon and the native walker agree on narrow labels`.
Preconditions: The host C harness creates exact executable and purpose-owned tree names beneath a descriptor-retained root.
Observable result: The walker applies the generated target labels and stock restore label instead of the root catch-all.
Evidence boundary: Host fd/xattr seams; Android restorecon and live SELinux enforcement are not observed.

### Requirement: The root zone has one hostile staging exception

`/data/voboost` SHALL be root-owned. `generations/next` SHALL be the only app-owned subtree in that namespace and SHALL not grant app or OEM access to siblings. Runtime intent, state, status, logs, payloads and immutable generations SHALL remain daemon-owned; injected processes SHALL use inherited anonymous pipes. The signed SELinux program SHALL open the root zone and every traversed member descriptor-relative without following links. The root and every recursively traversed directory or regular file SHALL be root-owned and not group- or other-writable; regular files SHALL have exactly one link. It SHALL compare the parent entry with the opened inode before and after labeling and before and after recursion. Any encountered symlink, special file, linked regular file, identity mismatch, or ownership/mode mismatch SHALL fail the fixed labeling operation. The fixed `generations/next` directory SHALL be a mode `0700`, non-root, same-UID/GID Android user-0 application directory with a valid directory link count. The SELinux program SHALL read that opened inode's bounded `security.selinux` context, reject a malformed user, role, type or MLS range, and construct a new context that replaces only the type with `voboost_incoming_file` while preserving the exact user, role and MLS range. It SHALL label the same opened directory with that context but SHALL NOT descend into its untrusted contents. Root-owned active and immutable generation trees SHALL still be traversed.

#### Scenario: An OEM process rewrites canonical intent

- **WHEN** a `system_app` or untrusted app process attempts to write `/data/voboost/agents.json`
- **THEN** DAC and the effective injected real-firmware policy deny the complete file and directory rewrite closure while its bound pipes remain usable, and relabeling does not follow a renamed member, lose the app MLS range or descend into app-owned staging contents

# Gate: cargo test --manifest-path shared/Cargo.toml secure_fs::tests::untrusted_read_rejects_owner_and_writable_mode -- --exact
Gate contract: Root-owned daemon input admission.
Maps: Requirement `The root zone has one hostile staging exception`; Scenario `An OEM process rewrites canonical intent`.
Preconditions: The exact Rust test presents canonical input files with foreign ownership and writable mode substitutions.
Observable result: Secure input opening rejects each substituted file before reading intent.
Evidence boundary: Host filesystem metadata checks; Android DAC and SELinux enforcement are not exercised.

# Gate: make test-selinux-real-policy
Gate contract: Real firmware policy rewrite denial.
Maps: Requirement `The root zone has one hostile staging exception`; Scenario `An OEM process rewrites canonical intent`.
Preconditions: The exact SHA-256-pinned f0506h policy-v30 fixture is readable and libsepol injects the generated rules into that policy.
Observable result: The isolated real-policy harness accepts the round trip and injection while effective decisions deny app and `system_app` rewrite authority over daemon-owned data.
Evidence boundary: Host libsepol evaluation of one pinned firmware policy; target kernel enforcement is not observed.

# Gate: make test-selinux-relabel-walk
Gate contract: Descriptor-bound root-zone relabel traversal.
Maps: Requirement `The root zone has one hostile staging exception`; Scenario `An OEM process rewrites canonical intent`.
Preconditions: The isolated relabel harness supplies root-owned members, renamed substitutions and an app-owned `generations/next` directory with an MLS-bearing context.
Observable result: Traversal rejects substitution, preserves the app MLS range, labels the opened staging directory and does not descend into its contents.
Evidence boundary: Host descriptor and extended-attribute seams; Android filesystem labels and live concurrent actors are not observed.
