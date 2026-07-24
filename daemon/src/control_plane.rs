// control_plane.rs — channel B: root daemon ↔ injected process communication.
//
// Replaces frida-RPC with watched files in /data/voboost-inject/shared/
// (media_rw_data_file, world-readable). The daemon writes config files; the
// agent runtime reads them and watches with inotify for live updates.
// Status flows back as per-process <pkg>-agent-status.json files.
//
// Key mechanics (update-planes spec):
//   - Config delivery: write per-process config file, pass path to implant_init
//   - Live update: atomic write-tmp+rename (never a partial read)
//   - Teardown: a no-agents plan → agent self-teardown (NOT daemon exit)
//   - Status aggregation: per-process status files → inject-status.json
//   - Liveness: /proc/<pid> existence (not status file alone)

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use crate::config;
use crate::log;

/// The channel-B shared directory.
fn shared_dir() -> PathBuf {
    PathBuf::from(config::SHARED_DIR)
}

/// The per-process config file path for a target.
///
/// Named by process name (sanitized) so the agent runtime can find it
/// deterministically. Format: /data/voboost-inject/shared/<process>-config.json
pub fn config_file_for(process: &str) -> PathBuf {
    let safe = sanitize_name(process);
    shared_dir().join(format!("{safe}-config.json"))
}

/// The per-process agent status file path.
///
/// The injected process writes its own status here; the daemon reads + aggregates.
/// Format: /data/voboost-inject/shared/<process>-agent-status.json
pub fn agent_status_file_for(process: &str) -> PathBuf {
    let safe = sanitize_name(process);
    shared_dir().join(format!("{safe}-agent-status.json"))
}

/// Write a per-process config file atomically (write-tmp + rename).
///
/// Called at injection (seed config) and on live updates (plan change for
/// an already-injected target). The agent runtime reads it on init and
/// watches it with inotify (filtered by filename).
pub fn write_config(process: &str, config_json: &str) -> Result<(), String> {
    let target = config_file_for(process);
    let dir = target.parent().ok_or("no parent dir")?;

    // Ensure shared dir exists.
    fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;

    // Write to a temp file in the same directory, then rename (atomic).
    let tmp = dir.join(format!(".{}-config.tmp", sanitize_name(process)));
    let mut f = fs::File::create(&tmp).map_err(|e| format!("temp create: {e}"))?;
    f.write_all(config_json.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync: {e}"))?;
    drop(f);

    // chmod 0644 (world-readable, per media_rw_data_file symmetric access).
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));

    // Atomic rename.
    fs::rename(&tmp, &target).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("rename: {e}")
    })?;

    log::debug(
        "control_plane",
        &format!("wrote config for {process} ({})", config_json.len()),
    );
    Ok(())
}

/// Read the per-process agent status file (written by the injected process).
///
/// Returns the raw JSON string, or None if the file doesn't exist.
pub fn read_agent_status(process: &str) -> Option<String> {
    let path = agent_status_file_for(process);
    fs::read_to_string(path).ok()
}

/// Check if a target process is alive via /proc/<pid>.
pub fn is_process_alive(pid: i32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

/// Write a no-agents plan for a process (teardown signal).
///
/// The agent runtime sees an empty agents list and performs its own teardown
/// (unhook + release). The daemon does NOT unload code out-of-band.
pub fn write_no_agents_plan(process: &str) -> Result<(), String> {
    write_config(process, r#"{"agents":[]}"#)?;
    log::info(
        "control_plane",
        &format!("wrote no-agents plan for {process} (teardown signal)"),
    );
    Ok(())
}

/// Aggregate per-process agent statuses into the channel-A inject-status.json.
///
/// Reads each <process>-agent-status.json from the shared dir, checks liveness
/// via /proc, and merges into the Status object. A process whose /proc/<pid>
/// is gone is NOT reported as active (liveness from /proc, not the status file).
pub fn aggregate_agent_statuses(status: &mut crate::status::Status, tracked: &[(i32, String)]) {
    for (pid, process) in tracked {
        // Liveness check: /proc/<pid> must exist.
        if !is_process_alive(*pid) {
            // Process gone — don't report active based on stale status file.
            continue;
        }

        // Read the per-process agent status file.
        if let Some(status_json) = read_agent_status(process) {
            // Parse and merge. The status file is agent-written (untrusted);
            // we only extract the state field for reporting.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&status_json) {
                if let Some(state_str) = v.get("state").and_then(|s| s.as_str()) {
                    let state = match state_str {
                        "active" => crate::status::InjectionState::Active,
                        "failed" => crate::status::InjectionState::Failed,
                        "waiting" => crate::status::InjectionState::Waiting,
                        _ => crate::status::InjectionState::Active,
                    };
                    status.set_injection("", process, state);
                }
            }
        }
    }
}

/// Sanitize a process name for use in a filename (replace non-alphanumeric).
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_package_id() {
        assert_eq!(
            sanitize_name("com.qinggan.app.launcher"),
            "com-qinggan-app-launcher"
        );
        assert_eq!(sanitize_name("system_server"), "system_server");
    }
}
