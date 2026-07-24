# Design — selinux-domain

<!-- Date: 2026-07-23. Records why the ptrace-allow domain is its own capability,
     why the shared dir is labeled via file_contexts, and why Permissive testing
     cannot prove it. -->

## D1 — Why a standalone `selinux-domain` capability

**Choice:** specify the `voboost-inject.te` policy as its own capability rather
than folding it into `daemon-lifecycle` or `provisioning`.

**Reasoning:** the policy is the migration's single hard blocker for Enforcing and
it is cross-cutting — it backs injection (`injection-control`), the reconcile/pid
reads (`native-payload`), the root zone (`provisioning`/`app-interface`), and
channel B (`update-planes`). Giving it one owner keeps the `process:ptrace` allow
and the target-domain set in one place instead of scattered across four specs. It
also makes the blocker impossible to lose: it is a named capability with its own
change, not a footnote in a lifecycle spec.

## D2 — Why the domain must not be generic

**Choice:** a dedicated `voboost-inject` domain with its own exec type, not
`shell`/`su`.

**Reasoning:** the `process:ptrace` allow is granted *to the source domain*.
Granting ptrace to a shared domain like `shell` would over-privilege every
process in that domain, and on this device the `u:r:su:s0` domain does not even
exist in the policy. A dedicated domain scopes the powerful allow to exactly the
daemon. (The emulator provisioning uses a `shell`-domain shell-wrapper as a test
affordance because it is Permissive and cannot enter a custom domain; that is a
testing hack, not the production contract — see D4.)

## D3 — Why the shared dir is labeled via file_contexts, not chcon

**Choice:** `/data/voboost-inject/shared/` gets `media_rw_data_file` from
`file_contexts`, and channel B is files, not a socket.

**Reasoning:** `media_rw_data_file` is symmetrically read/write from
`untrusted_app_all` with no extra allow, so the app and the injected process
(which may live in `untrusted_app`) exchange config/status through plain files
without a per-app policy change (machine-verified). A runtime `chcon`
would be fragile (must re-run after every recreate, races with first use) and is
unnecessary when `file_contexts` sets the type at creation. A socket was rejected
because an abstract socket from `untrusted_app` would require allow rules on both
ends — exactly the per-app policy churn the file approach avoids. The *file
semantics* (atomic write-tmp+rename to avoid partial reads, inotify filtering)
are `update-planes`' concern; this capability only fixes the label.

## D4 — Why Permissive testing cannot prove the policy

**Choice:** treat the allow as load-bearing and require Enforcing validation; do
not trust a green Permissive run.

**Reasoning:** the development emulator is Permissive (`setenforce 0` does not even
persist across reboots on it), so every denial is logged but not enforced —
injection succeeds no matter what `.te` says. That makes the emulator useless for
proving the policy and dangerous if a green run were read as proof. The rule was
verified as *necessary* by flipping the machine to Enforcing (`setenforce 1`) and
observing the ptrace denial; the *sufficiency* of the target-domain set is what
Enforcing hardware must confirm. The spec states this explicitly so no one archives
the capability on emulator evidence alone.

## D5 — What this capability deliberately does NOT own

- **Boot-trigger timing** (`on nonencrypted` vs `sys.boot_completed`): owned by
  `daemon-lifecycle`. This spec covers the domain transition
  (`init_daemon_domain`, exec type), not *when* init starts the service.
- **Channel-B file semantics**: owned by `update-planes`.
- **Root-zone provisioning** (paths, ownership, modes): owned by `provisioning`;
  this spec provides only the SELinux backing (which domain may write).

Keeping these boundaries prevents two specs from both claiming to define the init
service or the shared-file protocol.
