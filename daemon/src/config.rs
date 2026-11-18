// Fixed paths and bounds for the injection runtime.
//
// The root zone is the runtime authority. The app sandbox is used only for
// hostile network/update staging and never mirrors runtime control or status.

/// Root zone — trusted, root:root mode 0755. The app needs traversal only to
/// its separately app-owned `generations/next` subtree.
pub use voboost_contract::runtime_owner::ROOT_ZONE;

/// Fixed privileged flat generation import directory.
pub const INCOMING_DIR: &str = "/data/voboost/generations/next";

/// App sandbox — untrusted, app-writable network/update staging only.
pub const APP_ZONE: &str = "/data/user/0/ru.voboost";

/// Per-key agent state directory. The owner daemon is the only writer;
/// injection events reach it through the private bounded IPC.
pub use voboost_contract::runtime_owner::STATE_DIR;

pub const IMPLANT_PATH_ARM64: &str = "/data/voboost/libimplant-arm64-v8a.so";
pub const IMPLANT_PATH_ARM32: &str = "/data/voboost/libimplant-armeabi-v7a.so";

pub use voboost_contract::runtime_owner::INJECT_PID_NAME as PID_NAME;
/// Root-owned mode 0755 run directory (pidfile + kill-switch). The fixed mode
/// is part of the daemon's directory contract: the pidfile acquisition, the
/// desktop uninstall request publication, and resident status inspection
/// all validate it, so the three must never drift apart.
pub use voboost_contract::runtime_owner::{RUN_DIR, RUN_DIR_MODE};

pub fn pid_file() -> String {
    format!("{RUN_DIR}/{PID_NAME}")
}

/// Log directory.
pub use voboost_contract::runtime_owner::LOG_DIR;

/// Canonical, root-owned user intent. The daemon is its only programmatic
/// writer; trusted operators may still edit the strict JSON atomically.
pub fn plan_file() -> String {
    format!("{ROOT_ZONE}/agents.json")
}

/// Root-owned operator/installer diagnostic status.
pub fn status_file() -> String {
    format!("{ROOT_ZONE}/status.json")
}

/// Root compatibility state file for one already-sanitized key.
pub fn state_file(safe_key: &str) -> String {
    format!("{STATE_DIR}/{safe_key}.json")
}

/// The pidfile (single-instance lock).
pub fn pidfile() -> String {
    format!("{RUN_DIR}/pid")
}

/// The kill-switch file.
pub fn kill_switch_file() -> String {
    format!("{RUN_DIR}/disable")
}

/// Path to the per-ABI libimplant.so.
pub fn libimplant_path(abi: &str) -> String {
    format!("{ROOT_ZONE}/libimplant-{abi}.so")
}

/// Stable app-owned directory containing root-level transaction documents and
/// the uninstall request marker. Purpose-specific staging directories are
/// flat siblings and may be atomically replaced independently.
pub fn app_staging_dir() -> String {
    APP_ZONE.to_string()
}

/// The stable launch path init execs (root zone). Update never
/// replaces this in place; it repoints via an atomic rename (ota spec).
pub fn inject_binary_file() -> String {
    format!("{ROOT_ZONE}/voboost-inject")
}

/// Root-owned transient update candidate transactions.
pub fn install_transactions_dir() -> String {
    format!("{ROOT_ZONE}/install")
}

/// Root-owned transient update rollback transactions.
pub fn recovery_transactions_dir() -> String {
    format!("{ROOT_ZONE}/recovery")
}

/// Bound for one role-signed native executable.
pub use voboost_contract::runtime_owner::MAX_NATIVE_EXECUTABLE_BYTES;

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
pub const MAX_AGENT_STATUS_BYTES: usize = 65536; // 64 KiB
pub const MAX_AGENT_STATE_BYTES: usize = crate::state::MAX_BYTES;
pub const MAX_AGENT_STATE_KEY_BYTES: usize = crate::state::MAX_KEY_BYTES;
pub const MAX_AGENT_STATE_SOURCE_BYTES: usize = crate::state::MAX_SOURCE_BYTES;
pub const MAX_AGENT_STATE_STORAGE_KEY_BYTES: usize = crate::state::MAX_STORAGE_KEY_BYTES;
pub const MAX_AGENT_STATE_FILENAME_BYTES: usize = crate::state::MAX_FILENAME_BYTES;
pub const MAX_AGENT_STATE_RESPONSE_BYTES: usize = 4352;
pub const MAX_DOWNLINK_FRAME_BYTES: usize = 60 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_file_is_root_owned() {
        assert!(plan_file().starts_with(ROOT_ZONE));
        assert!(plan_file().ends_with("agents.json"));
    }

    #[test]
    fn status_file_is_root_owned() {
        assert!(status_file().starts_with(ROOT_ZONE));
        assert!(status_file().ends_with("status.json"));
    }

    #[test]
    fn libimplant_path_includes_abi() {
        assert_eq!(libimplant_path("arm64-v8a"), IMPLANT_PATH_ARM64);
        assert_eq!(libimplant_path("armeabi-v7a"), IMPLANT_PATH_ARM32);
    }

    #[test]
    fn app_staging_path_is_exact() {
        assert_eq!(app_staging_dir(), "/data/user/0/ru.voboost");
    }

    #[test]
    fn update_transactions_stay_inside_the_root_zone() {
        assert_eq!(install_transactions_dir(), "/data/voboost/install");
        assert_eq!(recovery_transactions_dir(), "/data/voboost/recovery");
    }

    #[test]
    fn state_files_use_root_state_dir() {
        assert_eq!(
            state_file("ivi-soc-modeset"),
            format!("{STATE_DIR}/ivi-soc-modeset.json")
        );
    }
}
