use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Diagnostic labels never contain caller-provided arguments, paths or input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Cmd(&'static str),
    Pm(&'static str),
}

impl Operation {
    pub fn program(self) -> &'static str {
        match self {
            Self::Cmd(_) => "/system/bin/cmd",
            Self::Pm(_) => "/system/bin/pm",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Cmd(name) | Self::Pm(name) => name,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Started,
    Exit(i32),
    Signal(i32),
    Timeout,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub struct Observation {
    pub operation_id: u64,
    pub operation: Operation,
    pub parent_pid: u32,
    /// Direct child only: a pm wrapper may start an unobserved cmd descendant.
    pub child_pid: u32,
    pub monotonic_ns: Option<u64>,
    pub elapsed_ms: u128,
    /// OS process status only, not output/input transport or operation acceptance.
    pub outcome: Outcome,
}

const OBSERVATION_CAPACITY: usize = 128;
static ENABLED: AtomicBool = AtomicBool::new(false);
static NEXT_OPERATION: AtomicU64 = AtomicU64::new(1);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static OBSERVATIONS: Mutex<ObservationRing> = Mutex::new(ObservationRing::new());

struct ObservationRing {
    records: [Option<Observation>; OBSERVATION_CAPACITY],
    next: usize,
    len: usize,
    overwritten: u64,
}

pub struct ObservationSnapshot {
    pub records: [Option<Observation>; OBSERVATION_CAPACITY],
    pub dropped: u64,
    pub overwritten: u64,
}

impl ObservationRing {
    const fn new() -> Self {
        Self {
            records: [None; OBSERVATION_CAPACITY],
            next: 0,
            len: 0,
            overwritten: 0,
        }
    }

    fn push(&mut self, observation: Observation) {
        self.records[self.next] = Some(observation);
        self.next = (self.next + 1) % OBSERVATION_CAPACITY;
        if self.len == OBSERVATION_CAPACITY {
            self.overwritten = self.overwritten.saturating_add(1);
        } else {
            self.len += 1;
        }
    }

    fn snapshot(&self, dropped: u64) -> ObservationSnapshot {
        let mut records = [None; OBSERVATION_CAPACITY];
        let first = (self.next + OBSERVATION_CAPACITY - self.len) % OBSERVATION_CAPACITY;
        for (offset, slot) in records.iter_mut().take(self.len).enumerate() {
            *slot = self.records[(first + offset) % OBSERVATION_CAPACITY];
        }
        ObservationSnapshot {
            records,
            dropped,
            overwritten: self.overwritten,
        }
    }
}

/// Daemon-only opt in. Enqueue never invokes a logger, allocator or user callback.
pub fn enable_observations() {
    ENABLED.store(true, Ordering::Relaxed);
}

fn enqueue(observation: Observation) {
    if let Ok(mut ring) = OBSERVATIONS.try_lock() {
        ring.push(observation);
    } else {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Copy retained observations only at an existing status publication; never consume them.
pub fn snapshot_observations() -> Option<ObservationSnapshot> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    snapshot_ring(&OBSERVATIONS, DROPPED.load(Ordering::Relaxed))
}

fn snapshot_ring(ring: &Mutex<ObservationRing>, dropped: u64) -> Option<ObservationSnapshot> {
    let ring = ring.try_lock().ok()?;
    (ring.len != 0 || dropped != 0).then(|| ring.snapshot(dropped))
}

/// Validate a diagnostic label against the same fixed command allowlist.
pub fn known_operation(program: &str, label: &str) -> bool {
    if program == "/system/bin/cmd" && label == "activity.get-config" {
        return true;
    }
    let arguments = label.split('.').collect::<Vec<_>>();
    operation(program, &arguments).is_some_and(|operation| operation.name() == label)
}

fn operation(program: &str, arguments: &[&str]) -> Option<Operation> {
    let label = match (program, arguments) {
        ("/system/bin/cmd", ["user", "list", ..]) => "user.list",
        ("/system/bin/cmd", ["overlay", "list", ..]) => "overlay.list",
        ("/system/bin/cmd", ["overlay", "enable", ..]) => "overlay.enable",
        ("/system/bin/cmd", ["overlay", "disable", ..]) => "overlay.disable",
        ("/system/bin/cmd", ["package", "list", ..]) => "package.list",
        ("/system/bin/cmd", ["package", "enable", ..]) => "package.enable",
        ("/system/bin/cmd", ["package", "disable-user", ..]) => "package.disable-user",
        ("/system/bin/cmd", ["jobscheduler", "cancel", ..]) => "jobscheduler.cancel",
        ("/system/bin/cmd", ["jobscheduler", "get-job-state", ..]) => "jobscheduler.get-job-state",
        ("/system/bin/cmd", ["activity", "get-config", "--proto"]) => "activity.get-config",
        ("/system/bin/cmd", ["activity", "force-stop", ..]) => "activity.force-stop",
        ("/system/bin/cmd", ["activity", "get-uid-state", ..]) => "activity.get-uid-state",
        ("/system/bin/cmd", ["activity", "broadcast", ..]) => "activity.broadcast",
        ("/system/bin/pm", ["path", ..]) => return Some(Operation::Pm("path")),
        ("/system/bin/pm", ["list", "packages", ..]) => {
            return Some(Operation::Pm("list.packages"))
        }
        ("/system/bin/pm", ["install", ..]) => return Some(Operation::Pm("install")),
        _ => return None,
    };
    Some(Operation::Cmd(label))
}

fn monotonic_ns() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return None;
    }
    u64::try_from(time.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(time.tv_nsec).ok()?)
}

struct ProcessObservation<'a> {
    observer: &'a dyn Fn(Observation),
    record: Observation,
    started: Instant,
}

impl<'a> ProcessObservation<'a> {
    fn start(operation: Operation, child_pid: u32, observer: &'a dyn Fn(Observation)) -> Self {
        let record = Observation {
            operation_id: NEXT_OPERATION.fetch_add(1, Ordering::Relaxed),
            operation,
            parent_pid: std::process::id(),
            child_pid,
            monotonic_ns: monotonic_ns(),
            elapsed_ms: 0,
            outcome: Outcome::Started,
        };
        let started = Instant::now();
        observer(record);
        Self {
            observer,
            record: Observation {
                outcome: Outcome::Error,
                ..record
            },
            started,
        }
    }
}

impl Drop for ProcessObservation<'_> {
    fn drop(&mut self) {
        self.record.monotonic_ns = monotonic_ns();
        self.record.elapsed_ms = self.started.elapsed().as_millis();
        (self.observer)(self.record);
    }
}

#[derive(Debug)]
pub struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn reader(
    mut pipe: impl Read + AsRawFd + Send + 'static,
    maximum: usize,
    deadline: Instant,
) -> std::thread::JoinHandle<Result<Vec<u8>, String>> {
    std::thread::spawn(move || {
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err("cannot bound fixed process output".into());
        }
        let mut bytes = Vec::with_capacity(maximum.min(4096));
        let mut buffer = [0_u8; 4096];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => return Ok(bytes),
                Ok(count) => {
                    if count > maximum.saturating_sub(bytes.len()) {
                        return Err("fixed process output exceeds its bound".into());
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("fixed process output timed out".into());
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(format!("read fixed process output: {error}")),
            }
        }
    })
}

pub fn output(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
    maximum: usize,
) -> Result<BoundedOutput, String> {
    output_with_input(program, arguments, None, timeout, maximum)
}

#[allow(dead_code)]
pub fn output_with_input(
    program: &str,
    arguments: &[&str],
    input: Option<std::fs::File>,
    timeout: Duration,
    maximum: usize,
) -> Result<BoundedOutput, String> {
    let observer = ENABLED
        .load(Ordering::Relaxed)
        .then_some(enqueue as fn(Observation));
    let observation =
        operation(program, arguments).zip(observer.as_ref().map(|f| f as &dyn Fn(Observation)));
    run(program, arguments, input, timeout, maximum, observation)
}

/// Run only the fixed signed None helper with Linux capabilities removed in the child.
/// Artifact authorization remains the caller's responsibility. Parent privileges are unchanged.
pub fn output_private_java_without_capabilities(
    classpath: &str,
    timeout: Duration,
    maximum: usize,
) -> Result<BoundedOutput, String> {
    output_private_java_for_owner_without_capabilities(classpath, "i18n-ru", timeout, maximum)
}

pub fn output_private_java_for_owner_without_capabilities(
    classpath: &str,
    owner: &str,
    timeout: Duration,
    maximum: usize,
) -> Result<BoundedOutput, String> {
    let class = match owner {
        "i18n-ru" => voboost_contract::resource_none_helper::I18N_RU_NONE_CLEANUP_CLASS,
        "i18n-en" => voboost_contract::resource_none_helper::I18N_EN_NONE_CLEANUP_CLASS,
        _ => return Err("none helper owner unsupported".into()),
    };
    run_with_setup(
        "/system/bin/app_process",
        &[classpath, "/system/bin", class],
        None,
        timeout,
        maximum,
        None,
        Some(crate::child_privileges::drop_for_exec),
    )
}

fn run(
    program: &str,
    arguments: &[&str],
    input: Option<std::fs::File>,
    timeout: Duration,
    maximum: usize,
    observation: Option<(Operation, &dyn Fn(Observation))>,
) -> Result<BoundedOutput, String> {
    run_with_setup(
        program,
        arguments,
        input,
        timeout,
        maximum,
        observation,
        None,
    )
}

fn run_with_setup(
    program: &str,
    arguments: &[&str],
    input: Option<std::fs::File>,
    timeout: Duration,
    maximum: usize,
    observation: Option<(Operation, &dyn Fn(Observation))>,
    setup: Option<fn() -> std::io::Result<()>>,
) -> Result<BoundedOutput, String> {
    let mut command = Command::new(program);
    if let Some(setup) = setup {
        unsafe {
            command.pre_exec(setup);
        }
    }
    let mut child = command
        // The child runs in its own session and process group: a timed-out
        // child is killed by group (kill(0, ...)), which also reaches shell
        // wrappers' descendants (e.g. `pm` spawned by `sh`) that outlive the
        // direct child and would otherwise hold the output pipes open forever.
        .process_group(0)
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("run {program}: {error}"))?;
    let deadline = Instant::now() + timeout;
    let mut observation = observation
        .map(|(operation, observer)| ProcessObservation::start(operation, child.id(), observer));
    let writer = if let Some(mut input) = input {
        let mut pipe = child.stdin.take().ok_or("fixed process stdin is absent")?;
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err("cannot bound fixed process input".into());
        }
        Some(std::thread::spawn(move || -> Result<(), String> {
            let mut buffer = [0u8; 65536];
            loop {
                let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
                if count == 0 {
                    return Ok(());
                }
                let mut offset = 0;
                while offset < count {
                    if Instant::now() >= deadline {
                        return Err("fixed process input timed out".into());
                    }
                    match pipe.write(&buffer[offset..count]) {
                        Ok(0) => return Err("fixed process input closed".into()),
                        Ok(written) => offset += written,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(format!("fixed process input: {error}")),
                    }
                }
            }
        }))
    } else {
        None
    };
    let stdout = reader(
        child
            .stdout
            .take()
            .ok_or("fixed process stdout is absent")?,
        maximum,
        deadline,
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .ok_or("fixed process stderr is absent")?,
        maximum,
        deadline,
    );
    // Kill the child's whole process group (negative pid): the timed-out
    // child is a group leader (process_group(0) above), and only a group
    // kill reaches descendants that inherited the pipes without being
    // direct children of this process. The same owned-group rule applies on hosts.
    fn kill_descendants(child: &mut std::process::Child) {
        let pid = child.id() as i32;
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Some(observation) = &mut observation {
                    observation.record.outcome = match (status.code(), status.signal()) {
                        (Some(code), _) => Outcome::Exit(code),
                        (_, Some(signal)) => Outcome::Signal(signal),
                        _ => Outcome::Error,
                    };
                }
                break Ok(status);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                if let Some(observation) = &mut observation {
                    observation.record.outcome = Outcome::Timeout;
                }
                kill_descendants(&mut child);
                let _ = child.wait();
                break Err(format!("{program} timed out"));
            }
            Err(error) => {
                kill_descendants(&mut child);
                let _ = child.wait();
                break Err(format!("wait for {program}: {error}"));
            }
        }
    };
    let stdout = stdout
        .join()
        .map_err(|_| "fixed process stdout reader panicked".to_string())?;
    let stderr = stderr
        .join()
        .map_err(|_| "fixed process stderr reader panicked".to_string())?;
    if stdout.is_err() || stderr.is_err() {
        kill_descendants(&mut child);
        if Instant::now() >= deadline {
            if let Some(observation) = &mut observation {
                observation.record.outcome = Outcome::Timeout;
            }
        }
    }
    if let Some(writer) = writer {
        let written = writer
            .join()
            .map_err(|_| "fixed process input writer panicked".to_string())?;
        // A rejected command may close stdin early. Preserve its stderr/status;
        // a successful command must still consume the complete input.
        if status.as_ref().is_ok_and(|status| status.success()) {
            written?;
        }
    }
    Ok(BoundedOutput {
        status: status?,
        stdout: stdout?,
        stderr: stderr?,
    })
}

#[allow(dead_code)]
pub fn status(program: &str, arguments: &[&str], timeout: Duration) -> Result<bool, String> {
    let output = output(program, arguments, timeout, 4096)?;
    Ok(output.status.success())
}

#[cfg(target_os = "android")]
#[allow(dead_code)]
pub fn set_property(name: &str, value: &str) -> Result<(), String> {
    use std::ffi::CString;
    unsafe extern "C" {
        fn __system_property_set(
            name: *const libc::c_char,
            value: *const libc::c_char,
        ) -> libc::c_int;
    }
    let name = CString::new(name).map_err(|_| "property name contains NUL".to_string())?;
    let value = CString::new(value).map_err(|_| "property value contains NUL".to_string())?;
    if unsafe { __system_property_set(name.as_ptr(), value.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err("Android property service rejected the fixed request".to_string())
    }
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub fn set_property(_name: &str, _value: &str) -> Result<(), String> {
    Err("Android property service is unavailable on this host".to_string())
}

/// The one fixed multimedia reboot request, shared by install and restore
/// (their journals both end in a machine reboot through sys.powerctl).
#[cfg(target_os = "android")]
pub fn request_reboot() -> Result<(), String> {
    set_property("sys.powerctl", "reboot")
        .map_err(|_| "multimedia reboot request failed".to_string())
}

#[cfg(not(target_os = "android"))]
pub fn request_reboot() -> Result<(), String> {
    Err("multimedia reboot requires Android".to_string())
}

/// Terminal forced reboot: the init property handshake first (a graceful
/// machine reboot through sys.powerctl), then the direct reboot(2) syscall as
/// the in-process fallback. init's shutdown path proved non-terminating in the
/// post-uninstall state (it stops services, kills vold, then hangs in its
/// volume-shutdown wait forever), so a plain set-property success does not
/// guarantee a machine restart. The syscall path is attempted after a fixed
/// grace window: reboot(2) never returns on success, so any return is a
/// failure that carries errno.
#[cfg(target_os = "android")]
fn flush_terminal_filesystems() {
    // syncfs targets exactly the filesystems the terminal teardown wrote:
    // the exact-zero /data zone and the restored vendor policy (through its
    // overlay upperdirs). Dead unrelated volumes cannot pin this flush the
    // way they pin a global sync(). Errors are ignored the same way the
    // global sync() result would be: the bounded join below either saw the
    // flush finish or fires reboot(2) regardless.
    for directory in ["/data", "/vendor", "/system", "/"] {
        let name = match std::ffi::CString::new(directory) {
            Ok(name) => name,
            Err(_) => continue,
        };
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY,
            )
        };
        if fd < 0 {
            continue;
        }
        unsafe {
            libc::syscall(libc::SYS_syncfs as libc::c_long, fd as libc::c_long);
            libc::close(fd);
        }
    }
    // A last global round for everything mounted after the targeted pass.
    unsafe { libc::sync() }
}

#[cfg(target_os = "android")]
pub fn request_forced_reboot(grace: Duration) -> Result<(), String> {
    let _ = set_property("sys.powerctl", "reboot");
    std::thread::sleep(grace);
    // The direct reboot(2) skips init's shutdown, which is also where a
    // graceful reboot would have flushed every filesystem. The terminal
    // teardown (restored pristine policy, exact-zero zone) was written with
    // ordinary cached writes, so the buffers must be flushed before the
    // kernel restarts or the fresh boot mounts the stale pre-teardown disk
    // state (the v89b gate rebooted but then reported voboost still present
    // in the freshly loaded SELinux policy). A plain sync() blocks until
    // every buffer is written and wedges forever in the terminal state
    // (vold already gone, / remounted read-only — the v89c gate never
    // reached reboot(2) because sync() never returned), so the flush runs
    // on its own thread and the machine restarts after a bounded wait even
    // if the flush is still stuck on a dead volume.
    let flush = std::thread::spawn(flush_terminal_filesystems);
    // Bounded join: std has no join-with-timeout, and sleep-polling is fine
    // here because the machine restarts on the very next line either way.
    // The global sync() wedges forever in the terminal state (a dead volume
    // among the mounted filesystems holds it — v89c), and waiting for it
    // never made the restored vendor policy survive reboot(2): v95/v96
    // bounded 60 s + 20 s rounds still rebooted with the pagecache flush
    // stuck behind the dead volume and the fresh boot mounted the stale
    // patched policy. syncfs() on the filesystems the terminal teardown
    // actually wrote (data and vendor overlays, /) flushes those without
    // being pinned by unrelated dead volumes.
    let flush_deadline = std::time::Instant::now() + Duration::from_secs(60);
    while !flush.is_finished() && std::time::Instant::now() < flush_deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    // Raw reboot(2) syscall: the libc crate does not export the reboot(2)
    // wrapper for Android targets, so the full signature is issued directly
    // with the kernel reboot magic (LINUX_REBOOT_MAGIC1/MAGIC2) and
    // LINUX_REBOOT_CMD_RESTART (RB_AUTOBOOT = 0x01234567).
    let args = linux_restart_arguments();
    let result = unsafe {
        libc::syscall(
            libc::SYS_reboot as libc::c_long,
            args[0],
            args[1],
            args[2],
            args[3],
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        Err(format!("forced reboot syscall failed: {errno}"))
    }
}

#[cfg(any(target_os = "android", test))]
fn linux_restart_arguments() -> [libc::c_long; 4] {
    [0xfee1dead_u32 as libc::c_long, 0x28121969, 0x01234567, 0]
}

#[cfg(not(target_os = "android"))]
pub fn request_forced_reboot(_grace: Duration) -> Result<(), String> {
    Err("forced reboot requires Android".to_string())
}

#[cfg(test)]
mod tests {
    fn record() -> Observation {
        Observation {
            operation_id: 1,
            operation: Operation::Pm("path"),
            parent_pid: 1,
            child_pid: 2,
            monotonic_ns: Some(3),
            elapsed_ms: 0,
            outcome: Outcome::Started,
        }
    }

    #[test]
    fn root_overlay_operations_enter_the_existing_diagnostic_ring() {
        for (verb, label) in [
            ("list", "overlay.list"),
            ("enable", "overlay.enable"),
            ("disable", "overlay.disable"),
        ] {
            assert_eq!(
                operation("/system/bin/cmd", &["overlay", verb, "--user", "0"]),
                Some(Operation::Cmd(label))
            );
        }
    }
    #[test]
    fn observation_ring_retains_latest_and_busy_enqueue_or_snapshot_never_waits() {
        let mut ring = ObservationRing::new();
        for operation_id in 1..=(OBSERVATION_CAPACITY as u64 + 3) {
            ring.push(Observation {
                operation_id,
                ..record()
            });
        }
        let snapshot = ring.snapshot(7);
        assert_eq!(snapshot.records[0].unwrap().operation_id, 4);
        assert_eq!(snapshot.records[127].unwrap().operation_id, 131);
        assert_eq!(snapshot.overwritten, 3);
        assert_eq!(snapshot.dropped, 7);
        assert_eq!(ring.snapshot(7).records[0].unwrap().operation_id, 4);
        let local = Mutex::new(ring);
        let guard = local.lock().unwrap();
        assert!(snapshot_ring(&local, 0).is_none());
        drop(guard);
        assert!(snapshot_ring(&local, 0).is_some());
        let guard = OBSERVATIONS.lock().unwrap();
        let before = DROPPED.load(Ordering::Relaxed);
        enqueue(record());
        assert_eq!(DROPPED.load(Ordering::Relaxed), before + 1);
        drop(guard);
        let source = include_str!("fixed_process.rs");
        let enqueue_body = source
            .split("fn enqueue(observation:")
            .nth(1)
            .unwrap()
            .split("/// Copy retained")
            .next()
            .unwrap();
        for forbidden in [
            "std::fs",
            "canonical_log",
            "Vec",
            "thread",
            "format!",
            ".lock()",
        ] {
            assert!(!enqueue_body.contains(forbidden));
        }
    }

    #[test]
    fn observation_labels_never_include_arguments_or_unknown_programs() {
        assert_eq!(
            operation(
                "/system/bin/cmd",
                &["activity", "broadcast", "secret\ninput"]
            ),
            Some(Operation::Cmd("activity.broadcast"))
        );
        assert_eq!(
            operation("/system/bin/pm", &["install", "-S", "secret"]),
            Some(Operation::Pm("install"))
        );
        assert_eq!(operation("/bin/cmd", &["package", "list"]), None);
        assert_eq!(operation("/system/bin/cmd", &["unknown", "secret"]), None);
        assert_eq!(operation("/system/bin/pm", &["unknown"]), None);
    }

    #[test]
    fn observations_preserve_output_exit_signal_and_timeout() {
        use std::cell::RefCell;
        for (command, timeout, expected) in [
            (
                "printf unchanged; exit 7",
                Duration::from_secs(1),
                Outcome::Exit(7),
            ),
            (
                "kill -TERM $$",
                Duration::from_secs(1),
                Outcome::Signal(libc::SIGTERM),
            ),
            (
                "exec /bin/sleep 1",
                Duration::from_millis(1),
                Outcome::Timeout,
            ),
        ] {
            let records = RefCell::new(Vec::new());
            let observer = |record| records.borrow_mut().push(record);
            let result = run(
                "/bin/sh",
                &["-c", command],
                None,
                timeout,
                100,
                Some((Operation::Cmd("package.list"), &observer)),
            );
            if expected == Outcome::Timeout {
                assert!(result.unwrap_err().ends_with("timed out"));
            } else {
                let result = result.unwrap();
                if expected == Outcome::Exit(7) {
                    assert_eq!(result.status.code(), Some(7));
                    assert_eq!(result.stdout, b"unchanged");
                } else {
                    assert_eq!(result.status.signal(), Some(libc::SIGTERM));
                }
            }
            let records = records.into_inner();
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].outcome, Outcome::Started);
            assert_eq!(records[1].outcome, expected);
            assert_eq!(records[0].operation_id, records[1].operation_id);
            assert_eq!(records[0].child_pid, records[1].child_pid);
            assert_ne!(records[0].child_pid, records[0].parent_pid);
            assert_eq!(records[0].parent_pid, std::process::id());
            assert!(records[1].monotonic_ns >= records[0].monotonic_ns);
        }
    }

    #[test]
    fn exited_child_cannot_extend_deadline_by_leaving_output_pipes_open() {
        let started = Instant::now();
        let result = output(
            "/bin/sh",
            &["-c", "(sleep 10) &"],
            Duration::from_millis(50),
            1024,
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn successful_process_observation_does_not_hide_output_bound_error() {
        let records = std::cell::RefCell::new(Vec::new());
        let observer = |record| records.borrow_mut().push(record);
        let error = run(
            "/usr/bin/printf",
            &["12345"],
            None,
            Duration::from_secs(1),
            4,
            Some((Operation::Pm("path"), &observer)),
        )
        .unwrap_err();
        assert_eq!(error, "fixed process output exceeds its bound");
        assert_eq!(records.borrow()[1].outcome, Outcome::Exit(0));
    }

    #[test]
    fn forced_restart_matches_linux_uapi_instead_of_a_truncated_command() {
        // linux/reboot.h in the pinned NDK r29 defines RESTART as 0x01234567.
        assert_eq!(
            super::linux_restart_arguments(),
            [0xfee1dead_u32 as libc::c_long, 672274793, 0x01234567, 0]
        );
    }
    use super::*;

    #[test]
    fn input_rejection_preserves_child_diagnostic_instead_of_broken_pipe() {
        let path = std::env::temp_dir().join(format!("voboost-input-test-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 1024 * 1024]).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let result = output_with_input(
            "/bin/sh",
            &["-c", "echo rejected >&2; exit 2"],
            Some(file),
            Duration::from_secs(2),
            100,
        )
        .unwrap();
        assert!(!result.status.success());
        assert_eq!(result.stderr, b"rejected\n");
    }

    #[test]
    fn output_and_wait_are_bounded() {
        let exact = output("/usr/bin/printf", &["1234"], Duration::from_secs(1), 4).unwrap();
        assert!(exact.status.success());
        assert_eq!(exact.stdout, b"1234");
        assert!(output("/usr/bin/printf", &["12345"], Duration::from_secs(1), 4,).is_err());
        assert!(output("/bin/sleep", &["1"], Duration::from_millis(1), 4).is_err());
    }
}

#[cfg(test)]
mod observed_locale_operation_tests {
    use super::*;
    #[test]
    fn exact_framework_observation_label() {
        assert!(known_operation("/system/bin/cmd", "activity.get-config"));
        assert_eq!(
            operation("/system/bin/cmd", &["activity", "get-config", "--proto"]),
            Some(Operation::Cmd("activity.get-config"))
        );
        assert_eq!(
            operation("/system/bin/cmd", &["activity", "get-config", "--device"]),
            None
        );
    }
}

#[cfg(test)]
#[path = "fixed_process_restricted_tests.rs"]
mod restricted_child_tests;
