// config.rs — paths and constants for the voboost-inject daemon.
//
// Ported 1:1 from Vala main.vala ROOT_ZONE/APP_ZONE, plus the new zone
// path /data/voboost-inject (design §3.1).

/// Root zone — trusted, root-owned (mode 0700).
pub const ROOT_ZONE: &str = "/data/voboost-inject";

/// App zone — untrusted, app-writable.
pub const APP_ZONE: &str = "/data/user/0/ru.voboost";

/// Channel-B shared directory (world-readable files, media_rw_data_file).
pub const SHARED_DIR: &str = "/data/voboost-inject/shared";

/// Payload directory (native .so files the daemon verifies and injects).
pub const PAYLOAD_DIR: &str = "/data/voboost-inject/payload";

/// Run directory (pidfile + kill-switch).
pub const RUN_DIR: &str = "/data/voboost-inject/run";

/// Log directory.
pub const LOG_DIR: &str = "/data/voboost-inject/logs";

/// The app→daemon plan file (channel A input).
pub fn plan_file() -> String {
    format!("{APP_ZONE}/inject.json")
}

/// The daemon→app status file (channel A output).
pub fn status_file() -> String {
    format!("{APP_ZONE}/inject-status.json")
}

/// The pidfile (single-instance lock).
pub fn pidfile() -> String {
    format!("{RUN_DIR}/inject.pid")
}

/// The kill-switch file.
pub fn kill_switch_file() -> String {
    format!("{RUN_DIR}/disable")
}

/// Path to the per-ABI libimplant.so.
pub fn libimplant_path(abi: &str) -> String {
    format!("{PAYLOAD_DIR}/{abi}/libimplant.so")
}

/// The untrusted app-zone staging directory where the OTA client stages a
/// verified inject update (daemon ELF + per-ABI payload) before the daemon
/// applies it.
pub fn staging_dir() -> String {
    format!("{APP_ZONE}/staging")
}

/// The stable launch path init execs (root zone). The inject self-update never
/// replaces this in place; it repoints via an atomic rename (ota spec).
pub fn inject_binary_file() -> String {
    format!("{ROOT_ZONE}/voboost-inject")
}

/// The previous daemon binary, kept one-deep for rollback (ota spec).
pub fn inject_prev_file() -> String {
    format!("{ROOT_ZONE}/voboost-inject.prev")
}

/// The switch-pending marker, written after an inject self-replace so a
/// DEGRADED restart can roll back (atomic-apply-rollback / ota spec).
pub fn inject_switch_pending_marker() -> String {
    format!("{RUN_DIR}/voboost-inject-switch-pending")
}

/// The producer's "a verified inject update is staged" marker (single-use,
/// created last in the staging dir). Owned by the daemon as the consumer.
pub fn inject_update_ready_marker(staging: &str) -> String {
    format!("{staging}/voboost-inject-update-ready")
}

/// DoS bound for the staged inject payload (a single appended-sig ELF).
/// 64 MiB is a generous upper bound (a typical daemon ELF is tens of MB).
pub const MAX_INJECT_BYTES: usize = 67_108_864;

/// Path to the root-zone manifest.
pub fn manifest_file() -> String {
    format!("{ROOT_ZONE}/manifest.json")
}

/// Path to the root-zone manifest signature.
pub fn manifest_sig_file() -> String {
    format!("{ROOT_ZONE}/manifest.sig")
}

/// Path to the root-zone release manifest (native-payload integrity envelope).
pub fn release_manifest_file() -> String {
    format!("{ROOT_ZONE}/release-manifest.json")
}

/// Path to the root-zone release manifest signature (detached ed25519).
pub fn release_manifest_sig_file() -> String {
    format!("{ROOT_ZONE}/release-manifest.json.sig")
}

/// Device-safety defaults (ported from Vala main.vala).
pub const SAFETY_MAX_ATTEMPTS: u32 = 3;
pub const SAFETY_WINDOW_MIN: u32 = 5;
pub const SAFETY_PANIC_THRESHOLD: u32 = 8;
pub const SAFETY_PANIC_WINDOW_SEC: u32 = 300;

/// Per-target circuit breaker defaults (device-safety spec).
pub const BREAKER_THRESHOLD: u32 = 3;
pub const BREAKER_WINDOW_SEC: u32 = 30;
pub const BREAKER_THRESHOLD_SYSTEM_SERVER: u32 = 2;

/// Plan validation size bounds (ported from Vala plan_reader.vala).
pub const MAX_CONFIG_BYTES: usize = 65536; // 64 KiB
pub const MAX_PLAN_BYTES: usize = 1048576; // 1 MiB

/// The libimplant.so marker to look for in /proc/<pid>/maps.
pub const IMPLANT_MARKER: &str = "libimplant.so";
