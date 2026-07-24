## ADDED Requirements

### Requirement: Dedicated SELinux domain entered from init

The daemon SHALL run in a dedicated SELinux domain named `voboost-inject`,
entered from init via `init_daemon_domain`, with a distinct exec type
`voboost-inject_exec` labeled on the daemon binary through `file_contexts`. The
domain SHALL NOT be a shared/generic domain (e.g. `shell`, `su`) — the
`process:ptrace` allow (below) attaches to this domain specifically. A hyphen in
the domain name is syntactically valid. The boot-trigger *timing*
(`on nonencrypted`) is specified by `daemon-lifecycle`; this requirement covers
only the domain and its entry.

#### Scenario: Daemon transitions into its own domain at launch

- **WHEN** init starts the daemon service
- **THEN** the process executes from `voboost-inject_exec` and transitions into
  the `voboost-inject` domain via `init_daemon_domain`, not into a generic
  domain

### Requirement: Ptrace allow to target domains

The policy SHALL grant `allow voboost-inject <target_domains>:process ptrace;`
for every SELinux domain the daemon must inject into. This is the load-bearing
rule: on an Enforcing device `ptrace(PTRACE_ATTACH)` from an ordinary domain is
denied, so without this allow the daemon cannot attach to or inject any target.
The set of `<target_domains>` SHALL cover the domains of the processes named in
the manifest (app and system/native targets).

#### Scenario: Injection into a target domain is permitted on Enforcing

- **WHEN** the daemon injects a target whose domain is in `<target_domains>` on
  an Enforcing device
- **THEN** the `PTRACE_ATTACH` succeeds because the policy allows
  `voboost-inject <that_domain>:process ptrace`

#### Scenario: Missing ptrace allow blocks injection on Enforcing

- **WHEN** the daemon attempts to ptrace a target domain not covered by the
  policy on an Enforcing device
- **THEN** the attach is denied by SELinux (AVC), and injection into that target
  fails until the domain is added to `<target_domains>`

### Requirement: Read access to target /proc entries

The policy SHALL allow the `voboost-inject` domain to read the `/proc/<pid>`
entries the injector and daemon depend on for target domains: `maps` (bitness
detection and the reconcile marker), `cmdline` (pid resolution by `argv[0]`),
and `exe` (bitness detection). Denial of these reads SHALL be treated as a
policy gap, not a runtime error to route around.

#### Scenario: Injector reads a target's maps and cmdline

- **WHEN** the daemon detects bitness, resolves a pid, or reconciles the
  `libimplant.so` marker for a target
- **THEN** it reads that target's `/proc/<pid>/maps`, `/proc/<pid>/cmdline`, and
  `/proc/<pid>/exe` without an SELinux denial

### Requirement: Root-zone access

The policy SHALL allow the `voboost-inject` domain read/write access to the root
zone `/data/voboost-inject` (manifests, agents, logs, run state). Only the
`voboost-inject` domain SHALL have write access to the root zone; the trust
boundary of the zone is owned by `provisioning` and `app-interface`, and this
requirement provides the SELinux backing for it.

#### Scenario: Daemon reads and writes its root zone

- **WHEN** the daemon reads a manifest or writes a log or run-state file under
  `/data/voboost-inject`
- **THEN** the access is permitted by the `voboost-inject` domain policy with no
  denial

### Requirement: Channel-B shared directory labeled via file_contexts

The policy SHALL label the channel-B shared directory
`/data/voboost-inject/shared/` as `media_rw_data_file` through `file_contexts`,
NOT via a runtime `chcon`. This type is readable and writable symmetrically from
`untrusted_app_all` without any extra allow rule, so the app-side and
injected-process-side of channel B communicate through plain files with no
per-app SELinux change (the file semantics — atomic write-tmp+rename,
inotify — are owned by `update-planes`). A world-readable file (`0644`) in this
directory is readable from any domain, which is why channel B is files, not a
socket (an abstract socket from `untrusted_app` would need allow rules).

#### Scenario: App and injected process exchange channel-B files without extra allow

- **WHEN** the app or an injected process reads or writes a file in
  `/data/voboost-inject/shared/`
- **THEN** the access succeeds via the `media_rw_data_file` label with no per-app
  allow rule and no runtime `chcon`

#### Scenario: Shared dir type is set at provisioning, not at runtime

- **WHEN** the shared directory is created
- **THEN** its `media_rw_data_file` type comes from `file_contexts`, and the
  daemon does not `chcon` it at runtime

### Requirement: Permissive masks the blocker; validate on Enforcing

The `process:ptrace` allow SHALL be treated as load-bearing even though the
development emulator runs SELinux **Permissive**, which masks the denial. The
capability SHALL be validated on Enforcing hardware before it is considered
proven; a green run on the Permissive emulator SHALL NOT be taken as evidence
that the policy is correct.

#### Scenario: Permissive emulator does not exercise the policy

- **WHEN** the daemon injects on the Permissive emulator
- **THEN** injection succeeds regardless of the SELinux policy (denials are
  logged, not enforced), so the run does not prove the `voboost-inject.te`
  rules

#### Scenario: Enforcing hardware exercises the policy

- **WHEN** the daemon injects on an Enforcing device
- **THEN** injection succeeds only if `voboost-inject.te` grants the required
  `process:ptrace`, `/proc` read, root-zone, and shared-dir access, which is the
  real validation of this capability
