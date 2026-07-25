# Design — provisioning (Rust + NDK toolchain + device zone)

<!-- Date: 2026-07-23. Records why provisioning follows the build system, why
     the device zone and init hook are added, and why the shared dir is
     provisioned here. -->

## D1 — Why provisioning follows the build system

**Choice:** `make init` provisions the Rust toolchain and NDK r29 instead of
the frida wrap, patched valac, and frida-meson.

**Reasoning:** provisioning exists to make `make build` work. When the build
system changes (meson/Vala/frida → Cargo/ndk-build — see `build-and-signing`),
provisioning must change with it or it installs tools that are unused and
omits tools that are required. The frida wraps, the frida-patched valac, and
frida's meson fork were all load-bearing *only* because frida-core was a meson
subproject needing a patched compiler and a forked meson — none of that exists
under Cargo + ndk-build. The Rust toolchain is provisioned from
`rust-toolchain.toml` (the standard Cargo pinning mechanism); the NDK is an
external prerequisite verified by `make init`. The `make init` / `make check` /
per-OS docs entry points are preserved (the developer surface is stable); only
what they install changes.

## D2 — Why the device zone and shared dir are provisioned here

**Choice:** the root zone `/data/voboost-inject/` is provisioned with
subdirectories `logs/`, `run/` (kill-switch), `shared/` (channel B,
`media_rw_data_file`), and `payload/` (native payload files).

**Reasoning:** the zone path changed from `/data/voboost` to
`/data/voboost-inject` (see `daemon-lifecycle`, `update-planes`). The
subdirectories are consumed by specs that depend on this one: `shared/` is the
channel-B watched-file dir (see `update-planes`, `selinux-domain` —
`media_rw_data_file` via `file_contexts`), `run/disable` is the kill-switch
(see `device-safety`), `logs/` is the log sink, and `payload/` holds the native
payload files the daemon verifies and hands to the injector (see
`trust-verification`, `native-payload`). Provisioning the zone (creating the
directories with the right ownership and SELinux labels) is a device-setup
concern, so it lives in the provisioning spec, not in each consumer spec.

## D3 — Why the init hook is `on nonencrypted`

**Choice:** the daemon service is installed as an init hook triggered
`on nonencrypted` (fallback `on boot`), with `oneshot` + `disabled` as a
reboot-loop guard.

**Reasoning:** the daemon must start before `system_server` to catch the
`app-viewport` agent's target early enough (see `daemon-lifecycle`). The
trigger `on nonencrypted` fires ~18s into boot, before `system_server` rises
(earlier than the old `sys.boot_completed=1`). The `oneshot` + `disabled`
flags are a safety property: a crashing daemon does not enter an infinite
restart loop (init's restart budget would exhaust). The self-update restart
behavior (init restarting the daemon after a clean self-shutdown) is owned by
`ota` and uses a different service configuration at the apply boundary; this
requirement covers the initial provisioning of the hook, not the self-update
restart semantics.
