// process_watcher.rs — /proc polling for target process appearance/disappearance.
//
// Discovers target processes through bounded /proc polling.
// The daemon watches for target processes by polling /proc, injecting when a
// target appears and reinjecting after a target dies and reappears (subject
// to device-safety limits). Target death is detected by a missing, unreadable,
// or changed /proc/<pid>/stat starttime. The scan tolerates entries vanishing
// mid-scan.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::sync::Mutex;
use std::time::Duration;

use crate::log;

#[path = "process_watcher/epoch.rs"]
mod epoch;

const MAX_ARGV0_BYTES: usize = crate::catalog::MAX_TARGET_PROCESS_BYTES;

pub(crate) fn read_bounded_argv0<R: Read>(mut reader: R) -> io::Result<Option<String>> {
    let mut bytes = [0u8; MAX_ARGV0_BYTES + 1];
    let mut used = 0usize;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => break,
            Ok(count) => used += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let Some(nul) = bytes[..used].iter().position(|byte| *byte == 0) else {
        return Ok(None);
    };
    if nul == 0 || nul > MAX_ARGV0_BYTES {
        return Ok(None);
    }
    let Ok(argv0) = std::str::from_utf8(&bytes[..nul]) else {
        return Ok(None);
    };
    Ok(Some(argv0.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: i32,
    starttime: u64,
}

#[derive(Default)]
struct ProcInventory {
    targets: HashMap<String, ProcessIdentity>,
    starttimes: HashMap<i32, u64>,
}

// Only these domains have the target-process permissions in the runtime policy.
// This prefilter never authenticates a target; argv0 and starttime still do that.
fn candidate_context(value: &[u8]) -> bool {
    let value = value.strip_suffix(&[0]).unwrap_or(value);
    [
        b"u:r:system_app:".as_slice(),
        b"u:r:system_server:",
        b"u:r:bluetooth:",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

/// Resolve a target process pid by scanning /proc and matching a stable
/// starttime-bound cmdline argv[0].
///
/// Takes the bytes up to the first NUL as argv[0] and compares directly
/// against `process`. Only Android package processes admitted by the signed
/// catalog grammar reach this watcher; native/system processes require a
/// separate explicit security profile before they can become targets.
pub fn find_pid(process: &str) -> Option<i32> {
    if crate::catalog::validate_process(process).is_err() {
        return None;
    }
    scan_process_inventory(&[process.to_string()], &HashSet::new())
        .targets
        .remove(process)
        .map(|identity| identity.pid)
}

pub fn find_pid_in_generation(
    generation: &crate::generation::VerifiedGeneration,
    process: &str,
) -> Option<i32> {
    let system_server =
        process == "system_server" && generation.catalog.has_target("launcher", process);
    if !system_server {
        return find_pid(process);
    }
    scan_process_inventory_scoped(&[process.into()], &HashSet::new(), true)
        .targets
        .remove(process)
        .map(|i| i.pid)
}

/// Scan /proc once and bind every exact argv[0] candidate to a stable kernel
/// process identity. The starttime reads bracket cmdline, so PID reuse or an
/// unreadable identity cannot turn argv[0] alone into a target appearance.
trait ProcReader {
    fn pids(&self) -> Vec<i32>;
    fn context(&self, pid: i32) -> io::Result<Vec<u8>>;
    fn stat(&self, pid: i32) -> anyhow::Result<crate::target_identity::ProcStat>;
    fn argv0(&self, pid: i32) -> io::Result<Option<String>>;
}

struct SystemProc;

impl ProcReader for SystemProc {
    fn pids(&self) -> Vec<i32> {
        fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
            .collect()
    }

    fn context(&self, pid: i32) -> io::Result<Vec<u8>> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let path = std::ffi::CString::new(format!("/proc/{pid}")).unwrap();
            let mut value = [0_u8; 256];
            let count = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    c"security.selinux".as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(value[..count as usize].to_vec())
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = pid;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    fn stat(&self, pid: i32) -> anyhow::Result<crate::target_identity::ProcStat> {
        crate::target_identity::read_stat(pid)
    }

    fn argv0(&self, pid: i32) -> io::Result<Option<String>> {
        read_bounded_argv0(fs::File::open(format!("/proc/{pid}/cmdline"))?)
    }
}

// A failure is never a permanent exclusion: re-probe within the existing
// 500ms process-discovery cadence. This also bounds PID-reuse delay when the
// old process was unreadable. Kernel labels are re-read every pass, not cached
// as authority for a replacement PID.
const DENIED_PROBE_BACKOFF: Duration = Duration::from_millis(500);

#[derive(Default)]
struct ScanCache {
    denied_until: HashMap<i32, std::time::Instant>,
    context_denied_until: HashMap<i32, std::time::Instant>,
    denied_probes: u64,
    next_diagnostic: Option<std::time::Instant>,
}

fn scan_process_inventory(target_processes: &[String], tracked: &HashSet<i32>) -> ProcInventory {
    scan_process_inventory_scoped(target_processes, tracked, false)
}
fn scan_process_inventory_scoped(
    target_processes: &[String],
    tracked: &HashSet<i32>,
    system_server: bool,
) -> ProcInventory {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<ScanCache>> = std::sync::OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    scan_inventory_tracked_scoped(
        &SystemProc,
        target_processes,
        tracked,
        &mut cache,
        std::time::Instant::now(),
        system_server,
    )
}

#[cfg(test)]
fn scan_inventory(
    reader: &impl ProcReader,
    target_processes: &[String],
    cache: &mut ScanCache,
    now: std::time::Instant,
) -> ProcInventory {
    scan_inventory_tracked(reader, target_processes, &HashSet::new(), cache, now)
}

#[cfg(test)]
fn scan_inventory_tracked(
    reader: &impl ProcReader,
    target_processes: &[String],
    tracked: &HashSet<i32>,
    cache: &mut ScanCache,
    now: std::time::Instant,
) -> ProcInventory {
    scan_inventory_tracked_scoped(reader, target_processes, tracked, cache, now, false)
}
fn scan_inventory_tracked_scoped(
    reader: &impl ProcReader,
    target_processes: &[String],
    tracked: &HashSet<i32>,
    cache: &mut ScanCache,
    now: std::time::Instant,
    system_server: bool,
) -> ProcInventory {
    let wanted: HashSet<&str> = target_processes
        .iter()
        .map(String::as_str)
        .filter(|process| {
            crate::catalog::validate_process(process).is_ok()
                || (system_server && *process == "system_server")
        })
        .collect();
    let mut inventory = ProcInventory::default();
    let mut ambiguous = HashSet::new();
    if wanted.is_empty() && tracked.is_empty() {
        return inventory;
    }
    let pids = reader.pids();
    let live: HashSet<i32> = pids.iter().copied().collect();
    cache
        .denied_until
        .retain(|pid, until| live.contains(pid) && *until > now);
    cache
        .context_denied_until
        .retain(|pid, until| live.contains(pid) && *until > now);
    for pid in pids {
        // The signed target grammar admits Android application processes only.
        // PID 1 is init and cannot be one of those targets.
        if pid <= 1 || (!tracked.contains(&pid) && cache.denied_until.contains_key(&pid)) {
            continue;
        }
        let context = if cache.context_denied_until.contains_key(&pid) {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        } else {
            let result = reader.context(pid);
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
            {
                cache.denied_probes += 1;
            }
            result
        };
        if !tracked.contains(&pid)
            && context
                .as_deref()
                .is_ok_and(|value| !candidate_context(value))
        {
            continue;
        }
        let context_denied = context
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied);
        if context_denied && !cache.context_denied_until.contains_key(&pid) {
            cache
                .context_denied_until
                .insert(pid, now + DENIED_PROBE_BACKOFF);
        }
        // Full stat performs ptrace/SELinux checks even when Linux returns a
        // redacted successful result. Avoid it for unrelated untracked PIDs.
        // This is only a prefilter: discovery still requires a fresh argv0
        // inside the original stat/argv0/stat identity bracket below.
        if !tracked.contains(&pid) {
            match reader.argv0(pid) {
                Ok(Some(argv0)) if wanted.contains(argv0.as_str()) => {}
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    cache.denied_probes += 1;
                    cache.denied_until.insert(pid, now + DENIED_PROBE_BACKOFF);
                    continue;
                }
                _ => continue,
            }
        }
        let Ok(before) = reader.stat(pid) else {
            cache.denied_probes += 1;
            cache.denied_until.insert(pid, now + DENIED_PROBE_BACKOFF);
            continue;
        };
        if before.kernel_thread {
            continue;
        }
        // Preserve arbitrary comm values and application subprocesses: only
        // exact argv[0], bracketed by matching starttimes, admits a target.
        let argv0 = reader.argv0(pid);
        let Ok(after) = reader.stat(pid) else {
            cache.denied_probes += 1;
            cache.denied_until.insert(pid, now + DENIED_PROBE_BACKOFF);
            continue;
        };
        if before.starttime != after.starttime || after.kernel_thread {
            continue;
        }
        inventory.starttimes.insert(pid, before.starttime);
        if argv0
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        {
            cache.denied_probes += 1;
            cache.denied_until.insert(pid, now + DENIED_PROBE_BACKOFF);
        }
        if let Some(argv0) = argv0
            .ok()
            .flatten()
            .filter(|argv0| wanted.contains(argv0.as_str()))
        {
            record_candidate(
                &mut inventory.targets,
                &mut ambiguous,
                argv0,
                ProcessIdentity {
                    pid,
                    starttime: before.starttime,
                },
            );
        }
    }
    if cache.denied_probes > 0 && cache.next_diagnostic.is_none_or(|deadline| now >= deadline) {
        log::debug(
            "watcher",
            &format!(
                "proc discovery unreadable probes={} retry_bound_ms={}",
                cache.denied_probes,
                DENIED_PROBE_BACKOFF.as_millis()
            ),
        );
        cache.denied_probes = 0;
        cache.next_diagnostic = Some(now + Duration::from_secs(5));
    }
    inventory
}

fn record_candidate(
    found: &mut HashMap<String, ProcessIdentity>,
    ambiguous: &mut HashSet<String>,
    process: String,
    identity: ProcessIdentity,
) {
    if ambiguous.contains(process.as_str()) {
        return;
    }
    if found.insert(process.clone(), identity).is_some() {
        found.remove(&process);
        ambiguous.insert(process);
    }
}

/// Check whether a /proc/<pid> entry exists. Used only by bounded uninstall
/// cleanup; tracker identity and retry decisions use starttime instead.
pub fn is_alive(pid: i32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

/// Tracks the pids the daemon has injected, mapping them to process names and
/// attested starttimes plus each target's daemon-owned endpoints. Used to
/// detect death or PID reuse and reinject on reappearance.
#[derive(Default)]
pub struct ProcessTracker {
    /// pid → one daemon-owned endpoint registration.
    /// Fds are independently optional so diagnostics from failed injection can
    /// still be drained even when the reply channel was never adopted.
    tracked: HashMap<i32, TrackedProcess>,
    #[cfg(test)]
    next_epoch_error: Option<io::ErrorKind>,
}

struct TrackedProcess {
    process: String,
    starttime: u64,
    record_read_fd: Option<i32>,
    state_reply_fd: Option<i32>,
    endpoint_epoch: u64,
    settings_identity: Option<(String, String)>,
    log_generation: Option<(String, String)>,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
const ENDPOINT_CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
#[cfg(not(any(target_os = "android", target_os = "linux")))]
const ENDPOINT_CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

fn endpoint_clock() -> io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(ENDPOINT_CLOCK, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    epoch::clock_value(i128::from(time.tv_sec), i128::from(time.tv_nsec))
}

fn next_endpoint_epoch() -> io::Result<u64> {
    static EPOCHS: Mutex<epoch::Epochs> = Mutex::new(epoch::Epochs::new());
    EPOCHS
        .lock()
        .map_err(|_| io::Error::other("endpoint epoch allocator poisoned"))?
        .next(endpoint_clock, std::thread::yield_now)
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the daemon injected this pid, with its log-pipe read-end fd.
    /// `log_read_fd` is None when agent logging is disabled.
    pub fn track(
        &mut self,
        process: &str,
        pid: i32,
        starttime: u64,
        record_read_fd: Option<i32>,
        state_reply_fd: Option<i32>,
    ) -> io::Result<()> {
        #[cfg(test)]
        let epoch = self
            .next_epoch_error
            .take()
            .map_or_else(next_endpoint_epoch, |kind| Err(kind.into()));
        #[cfg(not(test))]
        let epoch = next_endpoint_epoch();
        self.track_with_epoch(
            process,
            pid,
            starttime,
            record_read_fd,
            state_reply_fd,
            epoch,
        )
    }

    #[cfg(test)]
    pub(crate) fn fail_next_epoch_allocation(&mut self, kind: io::ErrorKind) {
        self.next_epoch_error = Some(kind);
    }

    fn track_with_epoch(
        &mut self,
        process: &str,
        pid: i32,
        starttime: u64,
        record_read_fd: Option<i32>,
        state_reply_fd: Option<i32>,
        epoch: io::Result<u64>,
    ) -> io::Result<()> {
        let epoch = match epoch {
            Ok(epoch) if epoch != 0 && epoch <= epoch::MAX_EPOCH => epoch,
            result => {
                close_downlink_fd(state_reply_fd);
                if record_read_fd != state_reply_fd {
                    close_optional_fd(record_read_fd);
                }
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid endpoint epoch")
                }));
            }
        };
        debug_assert!(starttime > 0);
        let endpoint = TrackedProcess {
            process: process.to_string(),
            starttime,
            record_read_fd,
            state_reply_fd,
            endpoint_epoch: epoch,
            settings_identity: None,
            log_generation: None,
        };
        if let Some(old) = self.tracked.insert(pid, endpoint) {
            crate::control_plane::forget_agent_status(&old.process);
            crate::agent_events::forget_endpoint(old.endpoint_epoch);
            close_optional_fd(old.record_read_fd);
            close_downlink_fd(old.state_reply_fd);
        }
        if let Some(endpoint) = self.tracked.get(&pid) {
            crate::bootstrap_worker::bind_endpoint(pid, endpoint.endpoint_epoch);
        }
        Ok(())
    }

    pub fn status_epoch(&self, pid: i32, process: &str) -> Option<u64> {
        let endpoint = self.tracked.get(&pid)?;
        (endpoint.process == process && endpoint.record_read_fd.is_some())
            .then_some(endpoint.endpoint_epoch)
    }

    pub fn is_tracked(&self, pid: i32) -> bool {
        self.tracked.contains_key(&pid)
    }

    /// True when the existing track carries a live agent log pipe — i.e. a
    /// phase-1 injection actually reached a running agent. A Deferred entry
    /// (no pipes, agent never started) must NOT suppress same-PID retries.
    pub fn is_tracked_with_pipes(&self, pid: i32) -> bool {
        self.tracked
            .get(&pid)
            .is_some_and(|tracked| tracked.record_read_fd.is_some())
    }

    fn is_tracked_identity(&self, identity: ProcessIdentity) -> bool {
        self.tracked
            .get(&identity.pid)
            .is_some_and(|tracked| tracked.starttime == identity.starttime)
    }

    /// Forget a pid (e.g. before reuse so a stale death signal is not
    /// misattributed). Closes the log-pipe read-end fd if held.
    pub fn clear(&mut self, pid: i32) {
        crate::bootstrap_worker::forget(pid);
        if let Some(old) = self.tracked.remove(&pid) {
            crate::control_plane::forget_agent_status(&old.process);
            crate::agent_events::forget_endpoint(old.endpoint_epoch);
            close_optional_fd(old.record_read_fd);
            close_downlink_fd(old.state_reply_fd);
        }
    }

    /// Returns registrations whose exact `(pid, starttime)` identity is no
    /// longer readable, along with their process names. Closes each dead
    /// target's log-pipe read-end fd (the implant scopes SIGPIPE suppression
    /// to each daemon-pipe write, so its next write gets EPIPE and logging
    /// silently becomes a no-op).
    pub fn reap_dead(&mut self) -> Vec<(i32, String)> {
        self.reap_dead_with(|pid| {
            crate::target_identity::read_starttime(pid)
                .map_err(|error| io::Error::other(error.to_string()))
        })
    }

    fn reap_dead_with<F>(&mut self, mut read_starttime: F) -> Vec<(i32, String)>
    where
        F: FnMut(i32) -> io::Result<u64>,
    {
        self.reap_dead_with_close(&mut read_starttime, |record_read_fd, state_reply_fd| {
            close_optional_fd(record_read_fd);
            close_downlink_fd(state_reply_fd);
        })
    }

    fn reap_dead_with_close<F, C>(
        &mut self,
        mut read_starttime: F,
        mut close_endpoint: C,
    ) -> Vec<(i32, String)>
    where
        F: FnMut(i32) -> io::Result<u64>,
        C: FnMut(Option<i32>, Option<i32>),
    {
        let mut dead = Vec::new();
        self.tracked.retain(|&pid, endpoint| {
            if read_starttime(pid).is_ok_and(|starttime| starttime == endpoint.starttime) {
                true
            } else {
                dead.push((pid, endpoint.process.clone()));
                crate::bootstrap_worker::forget(pid);
                crate::control_plane::forget_agent_status(&endpoint.process);
                crate::agent_events::forget_endpoint(endpoint.endpoint_epoch);
                close_endpoint(endpoint.record_read_fd, endpoint.state_reply_fd);
                false
            }
        });
        dead.sort_by_key(|(pid, _)| *pid);
        dead
    }

    /// Returns all tracked (pid, process) pairs.
    pub fn tracked_targets(&self) -> Vec<(i32, String)> {
        self.tracked
            .iter()
            .map(|(&p, endpoint)| (p, endpoint.process.clone()))
            .collect()
    }

    /// Returns the (pid, process, read-end fd) tuples for all tracked targets
    /// whose agent log-pipe is enabled, for the poll-loop drain pass.
    pub fn log_pipes(&self) -> Vec<(i32, String, u64, i32, Option<i32>)> {
        self.tracked
            .iter()
            .filter_map(|(&p, endpoint)| {
                endpoint.record_read_fd.map(|fd| {
                    (
                        p,
                        endpoint.process.clone(),
                        endpoint.endpoint_epoch,
                        fd,
                        endpoint.state_reply_fd,
                    )
                })
            })
            .collect()
    }

    /// Returns the (pid, process, downlink fd) tuples for confirmed-`D`
    /// snapshot pushes (the state-reply pipe doubles as the daemon→target
    /// downlink; see injector.rs).
    pub fn downlinks(&self) -> Vec<(i32, String, u64, i32)> {
        self.tracked
            .iter()
            .filter_map(|(&p, endpoint)| {
                endpoint
                    .state_reply_fd
                    .map(|fd| (p, endpoint.process.clone(), endpoint.endpoint_epoch, fd))
            })
            .collect()
    }

    /// Return only the attested registration for this exact process/downlink.
    pub fn downlink_identity(&self, process: &str, fd: i32) -> Option<(i32, u64, u64)> {
        self.tracked.iter().find_map(|(&pid, endpoint)| {
            (endpoint.process == process && endpoint.state_reply_fd == Some(fd)).then_some((
                pid,
                endpoint.starttime,
                endpoint.endpoint_epoch,
            ))
        })
    }

    /// Read only the exact registered endpoint's attested process starttime.
    pub fn endpoint_starttime(&self, pid: i32, process: &str, epoch: u64) -> Option<u64> {
        let endpoint = self.tracked.get(&pid)?;
        (endpoint.process == process && endpoint.endpoint_epoch == epoch)
            .then_some(endpoint.starttime)
    }

    /// Freeze verified native load identity; later desired delivery cannot replace it.
    pub fn bind_log_generation(&mut self, pid: i32, generation: &str, catalog: &str) {
        if let Some(endpoint) = self.tracked.get_mut(&pid) {
            if endpoint.log_generation.is_none() && !generation.is_empty() && !catalog.is_empty() {
                endpoint.log_generation = Some((generation.into(), catalog.into()));
            }
        }
    }

    pub fn log_generation(&self, pid: i32, process: &str, epoch: u64) -> Option<(String, String)> {
        let endpoint = self.tracked.get(&pid)?;
        (endpoint.process == process && endpoint.endpoint_epoch == epoch)
            .then(|| endpoint.log_generation.clone())
            .flatten()
    }

    /// Called only after owned bootstrap or exact native rebind admission.
    pub fn bind_settings(&mut self, pid: i32, generation: &str, catalog: &str, loaded: bool) {
        if let Some(endpoint) = self.tracked.get_mut(&pid) {
            endpoint.settings_identity = loaded.then(|| (generation.into(), catalog.into()));
        }
    }

    pub fn settings_loaded(
        &self,
        pid: i32,
        process: &str,
        epoch: u64,
        generation: &str,
        catalog: &str,
    ) -> bool {
        self.tracked.get(&pid).is_some_and(|endpoint| {
            endpoint.process == process
                && endpoint.endpoint_epoch == epoch
                && endpoint
                    .settings_identity
                    .as_ref()
                    .is_some_and(|(id, hash)| id == generation && hash == catalog)
        })
    }

    /// Disable and close one poisoned downlink while retaining process/log
    /// tracking. No later frame may be written after a hard-error partial.
    pub fn disable_downlink(&mut self, fd: i32) -> bool {
        for endpoint in self.tracked.values_mut() {
            if endpoint.state_reply_fd == Some(fd) {
                close_downlink_fd(endpoint.state_reply_fd.take());
                return true;
            }
        }
        crate::downlink::forget_fd(fd);
        false
    }
}

fn close_optional_fd(fd: Option<i32>) {
    if let Some(fd) = fd {
        unsafe {
            libc::close(fd);
        }
    }
}

fn close_downlink_fd(fd: Option<i32>) {
    if let Some(fd) = fd {
        crate::downlink::forget_fd(fd);
        unsafe {
            libc::close(fd);
        }
    }
}

/// A poll pass result: targets that appeared (process, pid) and targets that
/// died (pid, process).
pub type PollResult = (Vec<(String, i32)>, Vec<(i32, String)>);

/// Configuration for the /proc polling loop.
pub struct ProcessWatcher {
    pub poll_interval: Duration,
    tracker: ProcessTracker,
    // Diagnostics reuse the existing validated inventory; no additional /proc scan.
    observed: Vec<(String, i32, u64)>,
    next_scan: Option<std::time::Instant>,
    scanned_targets: Vec<String>,
}

impl Default for ProcessWatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessWatcher {
    pub fn new() -> Self {
        Self {
            // 500ms: /proc must be polled (inotify does not work on procfs, so
            // a poll loop is unavoidable for process appearance/death detection),
            // and the same loop re-reads the plan — a 500ms cadence keeps both
            // process-discovery and plan-change latency low. 2s was too coarse
            // (visible delay on theme/feature-flag changes). Profiling pending.
            poll_interval: Duration::from_millis(500),
            tracker: ProcessTracker::new(),
            observed: Vec::new(),
            next_scan: None,
            scanned_targets: Vec::new(),
        }
    }

    pub fn tracker_mut(&mut self) -> &mut ProcessTracker {
        &mut self.tracker
    }

    pub fn tracker(&self) -> &ProcessTracker {
        &self.tracker
    }

    pub(crate) fn observed_targets(&self) -> &[(String, i32, u64)] {
        &self.observed
    }

    /// One pass of the poll loop: find all target processes, report
    /// appearances (new pids for known targets) and deaths (tracked pids
    /// gone from /proc).
    ///
    /// Returns (appeared, died) where appeared = (process, pid) pairs to
    /// inject, and died = (pid, process) pairs that were tracked and died.
    pub fn poll_pass_generation(
        &mut self,
        generation: &crate::generation::VerifiedGeneration,
        target_processes: &[String],
    ) -> PollResult {
        let tracked = self.tracker.tracked.keys().copied().collect();
        let system_server = generation.catalog.has_target("launcher", "system_server");
        self.poll_pass_at(target_processes, std::time::Instant::now(), |targets| {
            scan_process_inventory_scoped(targets, &tracked, system_server)
        })
    }
    pub fn poll_pass(&mut self, target_processes: &[String]) -> PollResult {
        let tracked = self.tracker.tracked.keys().copied().collect();
        self.poll_pass_with_inventory(target_processes, |targets| {
            scan_process_inventory(targets, &tracked)
        })
    }

    // The daemon services pipes and worker results every 50ms. Process discovery
    // has its own 500ms cadence; do not rescan /proc on every service iteration.
    // A changed catalog target list bypasses the wait. Between scans we preserve
    // observations, but emit no appearances/deaths from stale identities.
    fn poll_pass_at<F>(
        &mut self,
        target_processes: &[String],
        now: std::time::Instant,
        inventory: F,
    ) -> PollResult
    where
        F: FnOnce(&[String]) -> ProcInventory,
    {
        if self.scanned_targets == target_processes
            && self.next_scan.is_some_and(|deadline| now < deadline)
        {
            return (Vec::new(), Vec::new());
        }
        self.scanned_targets = target_processes.to_vec();
        self.next_scan = Some(now + self.poll_interval);
        self.poll_pass_with_inventory(target_processes, inventory)
    }

    fn poll_pass_with_inventory<F>(
        &mut self,
        target_processes: &[String],
        inventory: F,
    ) -> PollResult
    where
        F: FnOnce(&[String]) -> ProcInventory,
    {
        let mut appeared = Vec::new();
        let inventory = inventory(target_processes);
        self.observed = target_processes
            .iter()
            .filter_map(|process| {
                inventory
                    .targets
                    .get(process)
                    .map(|identity| (process.clone(), identity.pid, identity.starttime))
            })
            .collect();

        // Reap against the same kernel-identity snapshot used for appearances.
        // A reused PID therefore reports the old death before exposing the new
        // exact target, both in this pass and without a duplicate registration.
        let died = self.tracker.reap_dead_with(|pid| {
            inventory
                .starttimes
                .get(&pid)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "identity unreadable"))
        });

        for process in target_processes {
            if let Some(identity) = inventory.targets.get(process) {
                if !self.tracker.is_tracked_identity(*identity) {
                    appeared.push((process.clone(), identity.pid));
                }
            }
        }

        if !died.is_empty() {
            for (pid, process) in &died {
                log::debug("watcher", &format!("target died: {process} pid={pid}"));
            }
        }

        (appeared, died)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::Cursor;

    #[test]
    fn epoch_failure_closes_new_fds_without_replacing_the_existing_endpoint() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        use std::os::unix::net::UnixStream;
        let mut tracker = ProcessTracker::new();
        tracker
            .track_with_epoch("target", 42, 55, None, None, Ok(101))
            .unwrap();
        for epoch in [
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            Ok(0),
            Ok(epoch::MAX_EPOCH + 1),
        ] {
            let (record, _record_peer) = UnixStream::pair().unwrap();
            let (downlink, _downlink_peer) = UnixStream::pair().unwrap();
            let record_fd = record.as_raw_fd();
            let downlink_fd = downlink.as_raw_fd();
            assert!(tracker
                .track_with_epoch(
                    "target",
                    42,
                    55,
                    Some(record.into_raw_fd()),
                    Some(downlink.into_raw_fd()),
                    epoch
                )
                .is_err());
            assert_eq!(tracker.tracked[&42].endpoint_epoch, 101);
            assert_eq!(unsafe { libc::fcntl(record_fd, libc::F_GETFD) }, -1);
            assert_eq!(unsafe { libc::fcntl(downlink_fd, libc::F_GETFD) }, -1);
        }
    }

    struct FixtureProc {
        pids: Vec<i32>,
        contexts: HashMap<i32, Vec<u8>>,
        stats: HashMap<i32, Vec<(u64, bool)>>,
        argv: HashMap<i32, String>,
        argv_sequence: HashMap<i32, Vec<Option<String>>>,
        calls: std::cell::RefCell<Vec<(i32, &'static str)>>,
    }

    impl ProcReader for FixtureProc {
        fn pids(&self) -> Vec<i32> {
            self.pids.clone()
        }
        fn context(&self, pid: i32) -> io::Result<Vec<u8>> {
            self.calls.borrow_mut().push((pid, "context"));
            self.contexts
                .get(&pid)
                .cloned()
                .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
        }
        fn stat(&self, pid: i32) -> anyhow::Result<crate::target_identity::ProcStat> {
            let mut calls = self.calls.borrow_mut();
            let count = calls.iter().filter(|call| **call == (pid, "stat")).count();
            calls.push((pid, "stat"));
            let values = self
                .stats
                .get(&pid)
                .ok_or_else(|| anyhow::anyhow!("unreadable stat"))?;
            let (starttime, kernel_thread) = values[count.min(values.len() - 1)];
            Ok(crate::target_identity::ProcStat {
                starttime,
                kernel_thread,
            })
        }
        fn argv0(&self, pid: i32) -> io::Result<Option<String>> {
            let count = self
                .calls
                .borrow()
                .iter()
                .filter(|call| **call == (pid, "argv0"))
                .count();
            self.calls.borrow_mut().push((pid, "argv0"));
            if let Some(values) = self.argv_sequence.get(&pid) {
                return Ok(values[count.min(values.len() - 1)].clone());
            }
            self.argv
                .get(&pid)
                .cloned()
                .map(Some)
                .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
        }
    }

    fn proc_fixture() -> FixtureProc {
        FixtureProc {
            pids: vec![1, 2, 3, 42, 43, 44, 45],
            contexts: HashMap::from([
                (2, b"u:r:kernel:s0\0".to_vec()),
                (3, b"u:r:platform_app:s0".to_vec()),
            ]),
            stats: HashMap::from([
                (3, vec![(10, true)]),
                (42, vec![(20, false)]),
                (43, vec![(30, false), (31, false)]),
                (44, vec![(40, false)]),
            ]),
            argv: HashMap::from([
                (42, "com.example.target:worker".into()),
                (43, "com.example.other".into()),
            ]),
            argv_sequence: HashMap::new(),
            calls: Default::default(),
        }
    }

    #[test]
    fn clear_pid_reuse_and_unreadable_birth_revoke_cached_status() {
        use crate::control_plane::{resident_generation, store_agent_status, ResidentGeneration};
        let process = "com.example.endpoint146-death";
        let raw = br#"{"schemaVersion":1,"generationId":"g","catalogSha256":"c","process":"com.example.endpoint146-death","documentGeneration":17,"agents":[]}"#;
        let mut tracker = ProcessTracker::default();
        for mode in 0..3 {
            tracker.track(process, 146, 900, None, None).unwrap();
            store_agent_status(process, raw);
            assert_eq!(
                resident_generation(process, "g", "c"),
                ResidentGeneration::Matching
            );
            match mode {
                0 => tracker.clear(146),
                1 => {
                    tracker.reap_dead_with(|_| Ok(901));
                }
                _ => {
                    tracker.reap_dead_with(|_| Err(io::Error::from(io::ErrorKind::NotFound)));
                }
            }
            assert_eq!(
                resident_generation(process, "g", "c"),
                ResidentGeneration::Unknown
            );
        }
    }

    #[test]
    fn same_pid_rebind_must_not_reuse_previous_status_ack() {
        let process = "com.example.endpoint146-red";
        let mut tracker = ProcessTracker::default();
        tracker.track(process, 146, 900, None, None).unwrap();
        crate::control_plane::store_agent_status(process, br#"{"schemaVersion":1,"generationId":"g","catalogSha256":"c","process":"com.example.endpoint146-red","documentGeneration":17,"agents":[]}"#);
        assert_eq!(
            crate::control_plane::observed_document_generation(process, "g", "c", &[]),
            Some(17)
        );
        tracker.track(process, 146, 900, None, None).unwrap();
        assert_eq!(
            crate::control_plane::observed_document_generation(process, "g", "c", &[]),
            None,
            "new same-PID endpoint must await its own S"
        );
    }

    #[test]
    fn inventory_avoids_init_kernel_file_reads_and_preserves_exact_targets() {
        let proc = proc_fixture();
        let result = scan_inventory(
            &proc,
            &["com.example.target:worker".into()],
            &mut ScanCache::default(),
            std::time::Instant::now(),
        );
        assert_eq!(
            result.targets["com.example.target:worker"],
            ProcessIdentity {
                pid: 42,
                starttime: 20
            }
        );
        let calls = proc.calls.borrow();
        assert!(!calls.iter().any(|(pid, _)| *pid == 1));
        assert_eq!(
            calls
                .iter()
                .filter(|(pid, _)| *pid == 2)
                .copied()
                .collect::<Vec<_>>(),
            vec![(2, "context")]
        );
        assert!(!calls.contains(&(3, "argv0")));
        assert!(!calls.contains(&(3, "stat")));
        assert_eq!(
            calls.iter().filter(|call| **call == (42, "stat")).count(),
            2
        );
        assert!(!result.starttimes.contains_key(&43));
    }

    #[test]
    fn unreadable_probes_back_off_but_reused_pid_is_discovered_within_poll_cadence() {
        let mut proc = proc_fixture();
        let now = std::time::Instant::now();
        let mut cache = ScanCache::default();
        scan_inventory(
            &proc,
            &["com.example.target:worker".into()],
            &mut cache,
            now,
        );
        proc.calls.borrow_mut().clear();
        scan_inventory(
            &proc,
            &["com.example.target:worker".into()],
            &mut cache,
            now + Duration::from_millis(1),
        );
        assert!(!proc
            .calls
            .borrow()
            .iter()
            .any(|(pid, _)| [44, 45].contains(pid)));
        // A new app PID is never permanently excluded by the old denied read.
        proc.stats.insert(45, vec![(50, false)]);
        proc.argv.insert(45, "com.example.new".into());
        let result = scan_inventory(
            &proc,
            &["com.example.new".into()],
            &mut cache,
            now + DENIED_PROBE_BACKOFF,
        );
        assert_eq!(result.targets["com.example.new"].starttime, 50);
    }

    #[test]
    fn known_non_target_domains_are_skipped_without_opening_their_files() {
        for context in [
            "u:r:vendor_init:s0",
            "u:r:ueventd:s0",
            "u:r:logd:s0",
            "u:r:bootwatchd:s0",
            "u:r:ais_v4l2_proxy:s0",
            "u:r:kernel:s0",
        ] {
            let mut proc = proc_fixture();
            proc.contexts.insert(42, context.as_bytes().to_vec());
            let mut cache = ScanCache::default();
            let now = std::time::Instant::now();
            let result = scan_inventory(
                &proc,
                &["com.example.target:worker".into()],
                &mut cache,
                now,
            );
            assert!(result.targets.is_empty());
            assert!(!proc
                .calls
                .borrow()
                .iter()
                .any(|(pid, call)| *pid == 42 && *call != "context"));
            proc.contexts.insert(42, b"u:r:system_app:s0".to_vec());
            let result = scan_inventory(
                &proc,
                &["com.example.target:worker".into()],
                &mut cache,
                now,
            );
            assert_eq!(result.targets["com.example.target:worker"].pid, 42);
        }
        for context in [
            "u:r:system_app:s0",
            "u:r:system_server:s0",
            "u:r:bluetooth:s0:c1,c2",
        ] {
            assert!(candidate_context(context.as_bytes()));
        }
        assert!(!candidate_context(b"u:r:system_app_other:s0"));
    }

    #[test]
    fn denied_context_never_hides_readable_target_or_marks_it_dead() {
        let proc = proc_fixture();
        let now = std::time::Instant::now();
        let mut cache = ScanCache::default();
        for delta in [0, 1, 100, 500] {
            let result = scan_inventory(
                &proc,
                &["com.example.target:worker".into()],
                &mut cache,
                now + Duration::from_millis(delta),
            );
            assert_eq!(result.starttimes[&42], 20);
            assert_eq!(result.targets["com.example.target:worker"].pid, 42);
        }
        assert_eq!(
            proc.calls
                .borrow()
                .iter()
                .filter(|call| **call == (42, "context"))
                .count(),
            2
        );
    }

    #[test]
    fn prefilter_skips_full_stat_for_unrelated_empty_and_denied_argv0() {
        let mut proc = proc_fixture();
        proc.argv_sequence.insert(3, vec![None]);
        scan_inventory(
            &proc,
            &["com.example.target:worker".into()],
            &mut ScanCache::default(),
            std::time::Instant::now(),
        );
        let calls = proc.calls.borrow();
        for pid in [3, 43, 44, 45] {
            assert!(
                !calls.contains(&(pid, "stat")),
                "unexpected full stat for {pid}"
            );
        }
        let target_calls: Vec<_> = calls
            .iter()
            .filter(|(pid, _)| *pid == 42)
            .map(|(_, call)| *call)
            .collect();
        assert_eq!(target_calls, ["context", "argv0", "stat", "argv0", "stat"]);
    }

    #[test]
    fn prefilter_is_not_authority_across_pid_reuse_or_argv0_mutation() {
        for reused in [false, true] {
            let mut proc = proc_fixture();
            proc.argv_sequence.insert(
                42,
                vec![
                    Some("com.example.target:worker".into()),
                    Some(
                        if reused {
                            "com.example.target:worker"
                        } else {
                            "com.example.other"
                        }
                        .into(),
                    ),
                ],
            );
            if reused {
                proc.stats.insert(42, vec![(20, false), (21, false)]);
            }
            let inventory = scan_inventory(
                &proc,
                &["com.example.target:worker".into()],
                &mut ScanCache::default(),
                std::time::Instant::now(),
            );
            assert!(inventory.targets.is_empty());
        }
    }

    #[test]
    fn tracked_liveness_survives_argv0_mutation_and_discovery_backoff() {
        let mut proc = proc_fixture();
        proc.argv.insert(42, "com.example.other".into());
        let now = std::time::Instant::now();
        let mut cache = ScanCache::default();
        cache.denied_until.insert(42, now + DENIED_PROBE_BACKOFF);
        let inventory = scan_inventory_tracked(&proc, &[], &HashSet::from([42]), &mut cache, now);
        assert_eq!(inventory.starttimes[&42], 20);
        let mut tracker = ProcessTracker::new();
        tracker
            .track("com.example.target:worker", 42, 20, None, None)
            .unwrap();
        assert!(tracker
            .reap_dead_with(|pid| Ok(inventory.starttimes[&pid]))
            .is_empty());
        proc.stats.insert(42, vec![(21, false)]);
        let inventory = scan_inventory_tracked(&proc, &[], &HashSet::from([42]), &mut cache, now);
        assert_eq!(
            tracker
                .reap_dead_with(|pid| Ok(inventory.starttimes[&pid]))
                .len(),
            1
        );
    }

    #[test]
    fn cmdline_argv0_is_bounded_nul_terminated_and_exact_utf8() {
        assert_eq!(
            read_bounded_argv0(Cursor::new(b"com.qinggan.app.setting\0ignored"))
                .unwrap()
                .as_deref(),
            Some("com.qinggan.app.setting")
        );

        let mut maximum = vec![b'a'; MAX_ARGV0_BYTES];
        maximum.push(0);
        assert_eq!(
            read_bounded_argv0(Cursor::new(maximum))
                .unwrap()
                .unwrap()
                .len(),
            MAX_ARGV0_BYTES
        );

        let mut oversized = vec![b'a'; MAX_ARGV0_BYTES + 1];
        oversized.push(0);
        assert!(read_bounded_argv0(Cursor::new(oversized))
            .unwrap()
            .is_none());
        assert!(read_bounded_argv0(Cursor::new(b"no-terminator"))
            .unwrap()
            .is_none());
        assert!(read_bounded_argv0(Cursor::new([0xff, 0]))
            .unwrap()
            .is_none());
    }

    #[test]
    fn duplicate_argv0_candidates_are_ambiguous_not_first_match() {
        let mut found = HashMap::new();
        let mut ambiguous = HashSet::new();
        for pid in [10, 11, 12] {
            record_candidate(
                &mut found,
                &mut ambiguous,
                "target".to_string(),
                ProcessIdentity {
                    pid,
                    starttime: pid as u64,
                },
            );
        }
        assert!(!found.contains_key("target"));
        assert!(ambiguous.contains("target"));
    }

    #[test]
    fn native_system_process_names_are_not_watcher_targets() {
        assert_eq!(find_pid("system_server"), None);
        assert_eq!(find_pid("surfaceflinger"), None);
    }

    // Regression guard: the poll interval was 2s, which made plan changes
    // (theme/feature-flag) and process discovery visibly slow. It MUST stay at
    // 500ms (or lower) until profiling proves otherwise — do not silently
    // raise it back to seconds.
    #[test]
    fn default_poll_interval_is_500ms_or_lower() {
        let watcher = ProcessWatcher::new();
        assert!(
            watcher.poll_interval <= Duration::from_millis(500),
            "poll_interval must be <=500ms (was {}ms); 2s is too slow",
            watcher.poll_interval.as_millis()
        );
    }

    #[test]
    fn tracker_distinguishes_existing_pid() {
        let mut tracker = ProcessTracker::new();
        assert!(!tracker.is_tracked(17));
        tracker
            .track("com.example.service", 17, 170, None, None)
            .unwrap();
        assert!(tracker.is_tracked(17));
        assert!(tracker.is_tracked_identity(ProcessIdentity {
            pid: 17,
            starttime: 170,
        }));
        assert!(!tracker.is_tracked_identity(ProcessIdentity {
            pid: 17,
            starttime: 171,
        }));
    }

    #[test]
    fn fast_service_passes_do_not_rescan_or_emit_stale_process_events() {
        let mut watcher = ProcessWatcher::new();
        let now = std::time::Instant::now();
        let targets = vec!["com.example.service".to_string()];
        let snapshot = |starttime| ProcInventory {
            targets: HashMap::from([(targets[0].clone(), ProcessIdentity { pid: 41, starttime })]),
            starttimes: HashMap::from([(41, starttime)]),
        };
        let appeared = watcher.poll_pass_at(&targets, now, |_| snapshot(10)).0;
        assert_eq!(appeared, vec![(targets[0].clone(), 41)]);
        watcher
            .tracker
            .track(&targets[0], 41, 10, None, None)
            .unwrap();
        for elapsed in [1, 50, 100, 499] {
            let result =
                watcher.poll_pass_at(&targets, now + Duration::from_millis(elapsed), |_| {
                    panic!("service pass must not enumerate /proc before discovery deadline")
                });
            assert_eq!(result, (vec![], vec![]));
            assert_eq!(watcher.observed_targets(), &[(targets[0].clone(), 41, 10)]);
        }
        // A reused PID is reported as old death + new appearance at the deadline.
        let (appeared, died) =
            watcher.poll_pass_at(&targets, now + Duration::from_millis(500), |_| snapshot(11));
        assert_eq!(appeared, vec![(targets[0].clone(), 41)]);
        assert_eq!(died, vec![(41, targets[0].clone())]);
    }

    #[test]
    fn changed_targets_bypass_process_discovery_deadline() {
        let mut watcher = ProcessWatcher::new();
        let now = std::time::Instant::now();
        let targets = vec!["com.example.service".to_string()];
        watcher.poll_pass_at(&targets, now, |_| ProcInventory::default());
        let changed = vec!["com.example.vehicle".to_string()];
        let calls = Cell::new(0);
        watcher.poll_pass_at(&changed, now + Duration::from_millis(1), |requested| {
            calls.set(calls.get() + 1);
            assert_eq!(requested, changed);
            ProcInventory::default()
        });
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn one_poll_uses_one_inventory_snapshot_for_all_targets() {
        let mut watcher = ProcessWatcher::new();
        let calls = Cell::new(0);
        let targets = vec!["one.process".to_string(), "two.process".to_string()];

        let (appeared, died) = watcher.poll_pass_with_inventory(&targets, |requested| {
            calls.set(calls.get() + 1);
            assert_eq!(targets, requested);
            ProcInventory {
                targets: HashMap::from([
                    (
                        "one.process".to_string(),
                        ProcessIdentity {
                            pid: 11,
                            starttime: 110,
                        },
                    ),
                    (
                        "two.process".to_string(),
                        ProcessIdentity {
                            pid: 22,
                            starttime: 220,
                        },
                    ),
                ]),
                starttimes: HashMap::from([(11, 110), (22, 220)]),
            }
        });

        assert_eq!(1, calls.get());
        assert_eq!(
            watcher.observed_targets(),
            &[
                ("one.process".to_string(), 11, 110),
                ("two.process".to_string(), 22, 220),
            ]
        );
        assert_eq!(
            vec![
                ("one.process".to_string(), 11),
                ("two.process".to_string(), 22)
            ],
            appeared
        );
        assert!(died.is_empty());
    }

    fn inventory(process: Option<(&str, i32, u64)>, observed: &[(i32, u64)]) -> ProcInventory {
        ProcInventory {
            targets: process
                .map(|(process, pid, starttime)| {
                    HashMap::from([(process.to_string(), ProcessIdentity { pid, starttime })])
                })
                .unwrap_or_default(),
            starttimes: observed.iter().copied().collect(),
        }
    }

    #[test]
    fn same_pid_and_starttime_is_retained_without_duplicate_appearance() {
        let mut watcher = ProcessWatcher::new();
        watcher
            .tracker_mut()
            .track("exact.target", 41, 1001, None, None)
            .unwrap();
        let targets = vec!["exact.target".to_string()];

        let (appeared, died) = watcher.poll_pass_with_inventory(&targets, |_| {
            inventory(Some(("exact.target", 41, 1001)), &[(41, 1001)])
        });

        assert!(appeared.is_empty());
        assert!(died.is_empty());
        assert!(watcher.tracker().is_tracked_identity(ProcessIdentity {
            pid: 41,
            starttime: 1001,
        }));
    }

    #[test]
    fn reused_pid_reaps_old_registration_and_appears_exact_target_in_same_pass() {
        let mut watcher = ProcessWatcher::new();
        watcher
            .tracker_mut()
            .track("exact.target", 41, 1001, None, None)
            .unwrap();
        let targets = vec!["exact.target".to_string()];

        let (appeared, died) = watcher.poll_pass_with_inventory(&targets, |_| {
            inventory(Some(("exact.target", 41, 2002)), &[(41, 2002)])
        });

        assert_eq!(died, vec![(41, "exact.target".to_string())]);
        assert_eq!(appeared, vec![("exact.target".to_string(), 41)]);
        assert_eq!(
            watcher.observed_targets(),
            &[("exact.target".to_string(), 41, 2002)]
        );
        assert!(!watcher.tracker().is_tracked(41));
    }

    #[test]
    fn unrelated_process_reusing_pid_clears_stale_registration() {
        let mut watcher = ProcessWatcher::new();
        watcher
            .tracker_mut()
            .track("exact.target", 41, 1001, None, None)
            .unwrap();
        let targets = vec!["exact.target".to_string()];

        let (appeared, died) =
            watcher.poll_pass_with_inventory(&targets, |_| inventory(None, &[(41, 2002)]));

        assert!(appeared.is_empty());
        assert_eq!(died, vec![(41, "exact.target".to_string())]);
        assert!(!watcher.tracker().is_tracked(41));
    }

    #[test]
    fn unreadable_identity_fails_closed_forgets_and_closes_endpoint() {
        let mut tracker = ProcessTracker::new();
        tracker
            .track("exact.target", 41, 1001, Some(101), Some(202))
            .unwrap();
        let mut closed = Vec::new();

        let died = tracker.reap_dead_with_close(
            |_| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "stat unreadable",
                ))
            },
            |record_read_fd, state_reply_fd| closed.push((record_read_fd, state_reply_fd)),
        );

        assert_eq!(died, vec![(41, "exact.target".to_string())]);
        assert!(!tracker.is_tracked(41));
        assert_eq!(closed, vec![(Some(101), Some(202))]);
    }

    #[test]
    fn log_generation_is_frozen_to_exact_registration_and_revoked_on_reuse() {
        let mut tracker = ProcessTracker::new();
        tracker.track("target", 41, 1001, None, None).unwrap();
        let epoch = tracker.tracked[&41].endpoint_epoch;
        assert_eq!(tracker.log_generation(41, "target", epoch), None);
        tracker.bind_log_generation(41, "old", "old-catalog");
        tracker.bind_log_generation(41, "new", "new-catalog");
        assert_eq!(
            tracker.log_generation(41, "target", epoch),
            Some(("old".into(), "old-catalog".into()))
        );
        assert_eq!(tracker.log_generation(41, "foreign", epoch), None);
        assert_eq!(tracker.log_generation(41, "target", epoch + 1), None);
        tracker.track("target", 41, 2002, None, None).unwrap();
        assert_eq!(tracker.log_generation(41, "target", epoch), None);
        let fresh = tracker.tracked[&41].endpoint_epoch;
        assert_eq!(tracker.log_generation(41, "target", fresh), None);
        tracker.bind_log_generation(41, "new", "new-catalog");
        assert_eq!(
            tracker.log_generation(41, "target", fresh),
            Some(("new".into(), "new-catalog".into()))
        );
    }

    #[test]
    fn settings_eligibility_is_exact_and_registration_replacement_revokes_it() {
        let mut tracker = ProcessTracker::new();
        tracker
            .track("com.qinggan.app.setting", 41, 1001, None, None)
            .unwrap();
        let epoch = tracker.tracked.get(&41).unwrap().endpoint_epoch;
        assert!(!tracker.settings_loaded(41, "com.qinggan.app.setting", epoch, "g", "c"));
        tracker.bind_settings(41, "g", "c", true);
        assert!(tracker.settings_loaded(41, "com.qinggan.app.setting", epoch, "g", "c"));
        for (pid, process, candidate_epoch, generation, catalog) in [
            (42, "com.qinggan.app.setting", epoch, "g", "c"),
            (41, "other.process", epoch, "g", "c"),
            (41, "com.qinggan.app.setting", epoch + 1, "g", "c"),
            (41, "com.qinggan.app.setting", epoch, "other", "c"),
            (41, "com.qinggan.app.setting", epoch, "g", "other"),
        ] {
            assert!(!tracker.settings_loaded(pid, process, candidate_epoch, generation, catalog));
        }
        tracker
            .track("com.qinggan.app.setting", 41, 1002, None, None)
            .unwrap();
        assert!(!tracker.settings_loaded(41, "com.qinggan.app.setting", epoch, "g", "c"));
        let fresh_epoch = tracker.tracked.get(&41).unwrap().endpoint_epoch;
        assert!(!tracker.settings_loaded(41, "com.qinggan.app.setting", fresh_epoch, "g", "c"));
        tracker.bind_settings(41, "g", "c", true);
        tracker.bind_settings(41, "g", "c", false);
        assert!(!tracker.settings_loaded(41, "com.qinggan.app.setting", fresh_epoch, "g", "c"));
    }
    #[test]
    fn scoped_system_server_scan_rejects_unbound_and_other_bare_processes() {
        let mut proc = proc_fixture();
        proc.argv.insert(42, "system_server".into());
        let targets = vec![
            "system_server".into(),
            "surfaceflinger".into(),
            "bare".into(),
        ];
        let now = std::time::Instant::now();
        assert!(scan_inventory_tracked_scoped(
            &proc,
            &targets,
            &HashSet::new(),
            &mut ScanCache::default(),
            now,
            false
        )
        .targets
        .is_empty());
        let inventory = scan_inventory_tracked_scoped(
            &proc,
            &targets,
            &HashSet::new(),
            &mut ScanCache::default(),
            now,
            true,
        );
        assert_eq!(inventory.targets.len(), 1);
        assert_eq!(inventory.targets["system_server"].pid, 42);
        let generation = crate::plan::test_fixtures::settings_generation();
        assert!(!generation.catalog.has_target("launcher", "system_server"));
    }
}
