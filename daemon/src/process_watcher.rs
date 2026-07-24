// process_watcher.rs — /proc polling for target process appearance/disappearance.
//
// Replaces frida's event-driven spawn/process signals with /proc polling.
// The daemon watches for target processes by polling /proc, injecting when a
// target appears and reinjecting after a target dies and reappears (subject
// to device-safety limits). Target death is detected by /proc/<pid>
// disappearance. The scan tolerates entries vanishing mid-scan.

use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use crate::log;

/// Resolve a target process pid by scanning /proc and matching cmdline argv[0].
///
/// Takes the bytes up to the first NUL as argv[0] and compares directly
/// against `process`. Resolves both app targets (package id) and
/// native/system targets (binary name like "system_server").
pub fn find_pid(process: &str) -> Option<i32> {
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return None,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid: i32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Read /proc/<pid>/cmdline — argv[0] is up to the first NUL.
        let cmdline_path = format!("/proc/{pid}/cmdline");
        let Ok(bytes) = fs::read(&cmdline_path) else {
            continue; // process may have exited mid-scan
        };

        // argv[0] = bytes up to first NUL.
        let nul_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let argv0 = String::from_utf8_lossy(&bytes[..nul_pos]);

        if argv0 == process {
            return Some(pid);
        }
    }

    None
}

/// Check whether a /proc/<pid> entry exists (process is alive).
pub fn is_alive(pid: i32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

/// Tracks the pids the daemon has injected, mapping them to process names.
/// Used to detect death (pid disappears from /proc) and reinject on reappearance.
#[derive(Default)]
pub struct ProcessTracker {
    /// pid → process name (only targets the daemon actually injected).
    tracked: HashMap<i32, String>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the daemon injected this pid.
    pub fn track(&mut self, process: &str, pid: i32) {
        self.tracked.insert(pid, process.to_string());
    }

    /// Forget a pid (e.g. before reuse so a stale death signal is not misattributed).
    pub fn clear(&mut self, pid: i32) {
        self.tracked.remove(&pid);
    }

    /// Returns the pids that have died since the last call (their /proc entry
    /// is gone), along with their process names.
    pub fn reap_dead(&mut self) -> Vec<(i32, String)> {
        let mut dead = Vec::new();
        self.tracked.retain(|&pid, process| {
            if is_alive(pid) {
                true
            } else {
                dead.push((pid, process.clone()));
                false
            }
        });
        dead
    }

    /// Returns all tracked (pid, process) pairs.
    pub fn tracked_targets(&self) -> Vec<(i32, String)> {
        self.tracked.iter().map(|(&p, s)| (p, s.clone())).collect()
    }
}

/// Configuration for the /proc polling loop.
pub struct ProcessWatcher {
    pub poll_interval: Duration,
    tracker: ProcessTracker,
}

impl ProcessWatcher {
    pub fn new() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            tracker: ProcessTracker::new(),
        }
    }

    pub fn tracker_mut(&mut self) -> &mut ProcessTracker {
        &mut self.tracker
    }

    /// One pass of the poll loop: find all target processes, report
    /// appearances (new pids for known targets) and deaths (tracked pids
    /// gone from /proc).
    ///
    /// Returns (appeared, died) where appeared = (process, pid) pairs to
    /// inject, and died = (pid, process) pairs that were tracked and died.
    pub fn poll_pass(
        &mut self,
        target_processes: &[String],
    ) -> (Vec<(String, i32)>, Vec<(i32, String)>) {
        let mut appeared = Vec::new();

        for process in target_processes {
            if let Some(pid) = find_pid(process) {
                // Target is running. If we haven't tracked it, it's new.
                appeared.push((process.clone(), pid));
            }
        }

        let died = self.tracker.reap_dead();

        if !died.is_empty() {
            for (pid, process) in &died {
                log::debug("watcher", &format!("target died: {process} pid={pid}"));
            }
        }

        (appeared, died)
    }
}
