## Why

On the target head-unit SELinux runs **Enforcing**, and there
`ptrace(PTRACE_ATTACH)` is denied to a process in an ordinary domain — verified
on the machine (`setenforce 1`). The new injection mechanism is
ptrace (see `native-payload`, `injection-control`), so without a dedicated
SELinux domain that is allowed to ptrace its target domains, the daemon cannot
inject at all on a real device. This is the migration's single hard blocker.

frida did not need this: frida-core's injection ran through its own helper and
did not require a caller-side `process:ptrace` allow of the same shape. Nothing
in the current specs describes an SELinux domain — the daemon has always run in
whatever domain init gave it. The development emulator is **Permissive**, which
*masks* the blocker, so it will never surface in emulator testing; the rule is
nonetheless load-bearing on production hardware. A draft `voboost-inject.te`
already exists.

This change adds the `selinux-domain` capability: the `voboost-inject.te`
contract — a dedicated domain entered from init, the `process:ptrace` allow to
target domains, the `/proc/<pid>` reads the injector needs, root-zone access,
and the `file_contexts` label that makes channel B readable/writable across
domains without per-app allow rules. It is additive and does not touch the live
frida specs.

## What Changes

- **New capability `selinux-domain`** — specifies:
  - a dedicated `voboost-inject` domain, entered from init via
    `init_daemon_domain` with an exec type (`voboost-inject_exec`) labeled on
    the daemon binary;
  - `allow voboost-inject <target_domains>:process ptrace;` — the load-bearing
    rule for Enforcing;
  - read access to targets' `/proc/<pid>/maps`, `/proc/<pid>/cmdline`,
    `/proc/<pid>/exe` (bitness detect, pid resolution, reconcile marker);
  - read/write to the root zone `/data/voboost-inject`;
  - the channel-B shared dir `/data/voboost-inject/shared/` labeled
    `media_rw_data_file` via `file_contexts` (not runtime `chcon`), so
    `untrusted_app_all` reads/writes it symmetrically with no extra allow;
  - the invariant that Permissive (emulator) masks the blocker and the rule
    MUST be validated on Enforcing hardware.
- **No existing spec is modified.** The boot-trigger *timing*
  (`on nonencrypted`) is owned by `daemon-lifecycle`; channel-B *file
  semantics* (atomic write, inotify) by `update-planes`; this capability owns
  only the SELinux policy.

## Capabilities

### Added Capabilities

- `selinux-domain`: the `voboost-inject.te` SELinux policy contract — a
  dedicated domain entered from init, the `process:ptrace` allow to target
  domains (the Enforcing hard blocker), the `/proc/<pid>` read access the
  injector needs, root-zone access, and the `file_contexts` label that makes the
  channel-B shared directory cross-domain readable/writable without per-app
  allow rules.
