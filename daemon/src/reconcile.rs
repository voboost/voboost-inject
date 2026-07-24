// reconcile.rs — reconciliation by the libimplant.so maps marker.
//
// Ported from the injection-control spec. The daemon treats injected code as
// outliving it: libimplant.so lives in the target independently. On startup
// and on every plan change, for each target the daemon reads /proc/<pid>/maps
// and checks for the real libimplant.so path. If present, the target is
// already injected → do NOT re-inject, only update config over channel B.

use std::fs;

use crate::config;
use crate::log;

/// Check whether a target already carries the libimplant.so marker.
///
/// Reads /proc/<pid>/maps and looks for the IMPLANT_MARKER string.
/// Tolerates the /proc entry disappearing mid-read (returns false).
pub fn is_injected(pid: i32) -> bool {
    let maps_path = format!("/proc/{pid}/maps");
    match fs::read_to_string(&maps_path) {
        Ok(contents) => contents.contains(config::IMPLANT_MARKER),
        Err(e) => {
            log::debug("reconcile", &format!("read {maps_path}: {e}"));
            false
        }
    }
}

/// Check for a foreign injection footprint (coexistence skip).
///
/// Looks for known foreign tool markers (NOT the daemon's own libimplant.so).
/// Returns true if a foreign footprint is found.
pub fn has_foreign_footprint(pid: i32) -> bool {
    let maps_path = format!("/proc/{pid}/maps");
    let Ok(contents) = fs::read_to_string(&maps_path) else {
        return false;
    };
    // Check for common foreign injection tools (NOT our libimplant.so).
    contents.contains("frida-agent")
        || contents.contains("gum-js-loop")
        || contents.contains("frida-gadget")
        || contents.contains("libxposed")
        || contents.contains("libshadowhook") // foreign shadowhook, not ours
}

/// Detect the target process bitness at runtime (delegates to /proc).
///
/// Returns Some("arm64-v8a") for 64-bit, Some("armeabi-v7a") for 32-bit,
/// or None if detection fails.
pub fn detect_bitness(pid: i32) -> Option<&'static str> {
    // Method 1: readlink /proc/<pid>/exe
    let exe_path = format!("/proc/{pid}/exe");
    if let Ok(target) = fs::read_link(&exe_path) {
        let name = target.to_string_lossy();
        if name.contains("app_process32") {
            return Some("armeabi-v7a");
        }
        if name.contains("app_process64") || name.contains("app_process") {
            return Some("arm64-v8a");
        }
    }

    // Method 2: scan maps for /lib64/ (64-bit) vs absence (32-bit)
    let maps_path = format!("/proc/{pid}/maps");
    if let Ok(contents) = fs::read_to_string(&maps_path) {
        if contents.contains("/lib64/") {
            return Some("arm64-v8a");
        }
        return Some("armeabi-v7a"); // no /lib64/ → likely 32-bit
    }

    log::err("reconcile", &format!("bitness detection failed for pid={pid}"));
    None
}
