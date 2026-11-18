// injector.rs — FFI wrapper over libinjector (the ptrace injection rail).
//
// The daemon's sole extern "C" seam to the native layer. Calls vbi_inject
// (defined in injector/injector.h) to inject libimplant.so into a target
// process via ptrace. The daemon never links libimplant.so or any
// LSPlant/Dobby symbol.

#[cfg(target_os = "android")]
use serde::{Deserialize, Serialize};
use std::ffi::CString;
#[cfg(any(target_os = "android", test))]
use std::io::Read;
#[cfg(target_os = "android")]
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::raw::{c_char, c_int};
#[cfg(target_os = "android")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use crate::config;
use crate::log;

#[repr(C)]
struct AgentPipeFds {
    record_read_fd: c_int,
    state_reply_fd: c_int,
}

const INTERNAL_HELPER_ARG: &str = "--internal-inject-helper";

fn owned_fd_if_valid(fd: c_int) -> Option<OwnedFd> {
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}
#[cfg(target_os = "android")]
const HELPER_PROTOCOL_MAX: u64 = 16 * 1024;
#[cfg(target_os = "android")]
const HELPER_IPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

#[cfg(target_os = "android")]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperRequest {
    schema_version: u32,
    pid: i32,
    so_path: String,
    init_symbol: String,
    bootstrap_path: String,
    expected_argv0: String,
    expected_starttime: u64,
    expected_uid: u32,
    expected_selinux_context: String,
}

#[cfg(target_os = "android")]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HelperResponse {
    schema_version: u32,
    code: i32,
    record_read_fd: i32,
    state_reply_fd: i32,
    dlerror: String,
    #[serde(skip)]
    staged_cleanup: Option<crate::bootstrap_worker::DetachedStaged>,
}

/// vbi_inject return codes (matching injector/injector.h).
pub const INJECT_OK: c_int = 0;
pub const INJECT_DENIED: c_int = -1;
pub const INJECT_TARGET_GONE: c_int = -2;
pub const INJECT_DLOPEN_FAILED: c_int = -3;
pub const INJECT_INIT_FAILED: c_int = -4;
pub const INJECT_BITNESS_FAILED: c_int = -5;
/// Native payload loaded and implant_init ran, but the agent could not
/// initialize yet (early boot: host Application not bound). Retryable on the
/// same live PID. The daemon SHALL NOT mark the agent active on this alone.
pub const INJECT_AGENT_PENDING: c_int = -6;
/// Stopped target's argv[0] did not match the name the pid was selected by
/// (pid reuse or argv spoofing) — injection refused before any remote dlopen.
pub const INJECT_IDENTITY_MISMATCH: c_int = -7;
/// Native cleanup could not prove safe register restore and detach.
pub const INJECT_UNSAFE_CLEANUP: c_int = -8;
pub const INJECT_RESIDENT_REBOUND: c_int = -9;
pub const INJECT_WORKER_STAGED: c_int = -10;
pub const INJECT_REGISTER_DEFERRED: c_int = -11;
pub const INJECT_LOADER_UNRESOLVED: c_int = -12;

#[cfg(target_os = "android")]
extern "C" {
    fn vbi_inject(
        pid: c_int,
        so_path: *const c_char,
        init_sym: *const c_char,
        config_path: *const c_char,
        expect_argv0: *const c_char,
        expect_starttime: u64,
        expect_uid: u32,
        expect_selinux_context: *const c_char,
        pipe_fds: *mut AgentPipeFds,
        dlerr_out: *mut c_char,
        dlerr_out_sz: usize,
    ) -> c_int;
}

// A host build is a compile/link validation artifact only. Android's
// libinjector.a cannot be linked into a host executable, so fail closed if a
// host binary is accidentally run far enough to request injection.
#[cfg(not(target_os = "android"))]
#[allow(clippy::too_many_arguments)]
unsafe fn vbi_inject(
    _pid: c_int,
    _so_path: *const c_char,
    _init_sym: *const c_char,
    _config_path: *const c_char,
    _expect_argv0: *const c_char,
    _expect_starttime: u64,
    _expect_uid: u32,
    _expect_selinux_context: *const c_char,
    _pipe_fds: *mut AgentPipeFds,
    _dlerr_out: *mut c_char,
    _dlerr_out_sz: usize,
) -> c_int {
    INJECT_DENIED
}

/// The result of an injection attempt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectResult {
    Ok,
    Staged,
    /// No target memory/register mutation; retry at a natural register stop.
    RegisterDeferred,
    /// Native load succeeded but the agent is deferred (Application not bound
    /// in early boot). Retryable on the same live PID; never mark Active.
    Pending,
    Denied,
    TargetGone,
    DlopenFailed,
    /// Executed loader timed out; register restoration is not loader rollback.
    LoaderUnresolved,
    InitFailed,
    BitnessFailed,
    /// argv[0] of the stopped target did not match the selected process
    /// name (pid reuse / spoofing). Not retryable on this pid.
    IdentityMismatch,
    /// Tracee cleanup could not safely restore and detach.
    UnsafeCleanup,
    /// Existing implant kept its agent/classloader generation and replaced
    /// only daemon transport endpoints.
    Rebound,
}

/// Two-word borrowed view: the bootstrap writer never owns a second
/// envelope-sized buffer.
#[cfg(test)]
struct BorrowedEnvelope<'a>(&'a [u8]);

impl InjectResult {
    #[cfg(any(target_os = "android", test))]
    fn log_level(self) -> crate::canonical_log::Level {
        match self {
            Self::Ok | Self::Staged | Self::Rebound | Self::Pending | Self::RegisterDeferred => {
                crate::canonical_log::Level::Debug
            }
            _ => crate::canonical_log::Level::Error,
        }
    }

    pub fn from_code(code: c_int) -> Self {
        match code {
            INJECT_OK => Self::Ok,
            INJECT_AGENT_PENDING => Self::Pending,
            INJECT_WORKER_STAGED => Self::Staged,
            INJECT_REGISTER_DEFERRED => Self::RegisterDeferred,
            INJECT_DENIED => Self::Denied,
            INJECT_TARGET_GONE => Self::TargetGone,
            INJECT_DLOPEN_FAILED => Self::DlopenFailed,
            INJECT_LOADER_UNRESOLVED => Self::LoaderUnresolved,
            INJECT_INIT_FAILED => Self::InitFailed,
            INJECT_BITNESS_FAILED => Self::BitnessFailed,
            INJECT_IDENTITY_MISMATCH => Self::IdentityMismatch,
            INJECT_UNSAFE_CLEANUP => Self::UnsafeCleanup,
            INJECT_RESIDENT_REBOUND => Self::Rebound,
            _ => Self::InitFailed,
        }
    }

    /// True only when the native payload loaded AND the agent was reached.
    /// `Pending` (native load OK but agent deferred) is NOT a success.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Pending => "agent-pending",
            Self::Staged => "worker-staged",
            Self::RegisterDeferred => "register-baseline-deferred",
            Self::Denied => "denied",
            Self::TargetGone => "target-gone",
            Self::DlopenFailed => "dlopen-failed",
            Self::LoaderUnresolved => "loader-unresolved",
            Self::InitFailed => "init-failed",
            Self::BitnessFailed => "bitness-failed",
            Self::IdentityMismatch => "identity-mismatch",
            Self::UnsafeCleanup => "unsafe-cleanup",
            Self::Rebound => "resident-rebound",
        }
    }
}

#[cfg(any(target_os = "android", test))]
fn daemon_parent_argv_matches(bytes: &[u8], expected: &[u8]) -> bool {
    bytes == expected
        || bytes
            .strip_suffix(&[0])
            .is_some_and(|value| value == expected)
}

#[cfg(test)]
fn bounded_helper_stderr(reader: impl Read) -> String {
    drain_helper_stderr(reader, |_| {})
}
#[cfg(any(target_os = "android", test))]
fn drain_helper_stderr(mut reader: impl Read, mut observe: impl FnMut(&str)) -> String {
    let mut first_error: Option<String> = None;
    let mut last_error: Option<String> = None;
    let mut debug = std::collections::VecDeque::new();
    let mut line = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let mut ended_newline = false;
    let mut consume = |bytes: &[u8]| {
        let mut text: String = String::from_utf8_lossy(bytes)
            .chars()
            .map(|c| if c.is_control() && c != '\t' { '?' } else { c })
            .collect();
        while text.len() > 2048 {
            text.pop();
        }
        if text.is_empty() {
            return;
        }
        observe(&text);
        let is_debug = text.starts_with("[helper-debug] ")
            || serde_json::from_str::<crate::canonical_log::ProducerRecord>(&text)
                .is_ok_and(|record| record.level == crate::canonical_log::Level::Debug);
        if is_debug {
            while text.len() > 512 {
                text.pop();
            }
            if debug.len() == 2 {
                debug.pop_front();
            }
            debug.push_back(text);
        } else {
            if first_error.is_none() {
                first_error = Some(text.clone());
            }
            last_error = Some(text);
        }
    };
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => {
                for byte in &chunk[..count] {
                    ended_newline = *byte == b'\n';
                    if *byte == b'\n' {
                        consume(&line);
                        line.clear();
                    } else if line.len() < 2048 {
                        line.push(*byte);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    if !line.is_empty() {
        consume(&line);
    }
    let mut result = Vec::new();
    if let Some(first) = first_error {
        result.push(first);
    }
    if let Some(last) = last_error {
        if result.last() != Some(&last) {
            result.push(last);
        }
    }
    result.extend(debug);
    let mut result = result.join("\n");
    if ended_newline && !result.is_empty() {
        result.push('\n');
    }
    result
}
#[cfg(any(target_os = "android", test))]
fn collect_helper_record(line: &str) {
    if let Ok(record) = serde_json::from_str::<crate::canonical_log::ProducerRecord>(line) {
        log::producer(record);
    } else if let Some(message) = line.strip_prefix("[helper-debug] ") {
        log::debug("injector", message);
    } else {
        log::err(
            "injector",
            line.strip_prefix("[helper-error] ").unwrap_or(line),
        );
    }
}

#[cfg(any(target_os = "android", test))]
fn helper_result_record(
    pid: i32,
    code: i32,
    dlerror: &str,
) -> crate::canonical_log::ProducerRecord {
    crate::canonical_log::ProducerRecord {
        level: InjectResult::from_code(code).log_level(),
        component: "injector".into(),
        message: format!("vbi_inject pid={pid} code={code} dlerror={dlerror}"),
        fields: Default::default(),
    }
}

/// Consume only the exact private helper invocation. The normal daemon is the
/// sole authorized parent; every other argv shape continues through ordinary
/// startup and is rejected by the existing CLI boundary.
pub fn handle_internal_helper_cli() -> Option<i32> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() != 2 || args[1] != INTERNAL_HELPER_ARG {
        return None;
    }
    #[cfg(target_os = "android")]
    {
        Some(run_internal_helper().unwrap_or_else(|error| {
            log::helper_record(crate::canonical_log::Level::Error, "injector", &error);
            126
        }))
    }
    #[cfg(not(target_os = "android"))]
    {
        Some(126)
    }
}

#[cfg(target_os = "android")]
fn authenticate_helper_process() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("inject helper requires root".to_string());
    }
    let fixed = std::path::Path::new(&config::inject_binary_file()).to_path_buf();
    let current = std::fs::read_link("/proc/self/exe")
        .map_err(|error| format!("read helper executable: {error}"))?;
    if current != fixed {
        return Err("inject helper executable path is not fixed".to_string());
    }
    crate::native_binary::verify_current_role(
        crate::native_executable_signature::NativeExecutableRole::Inject,
    )?;
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err("inject helper parent is absent".to_string());
    }
    let self_meta = std::fs::metadata("/proc/self/exe")
        .map_err(|error| format!("stat helper executable: {error}"))?;
    let parent_meta = std::fs::metadata(format!("/proc/{parent}/exe"))
        .map_err(|error| format!("stat helper parent executable: {error}"))?;
    if (self_meta.dev(), self_meta.ino()) != (parent_meta.dev(), parent_meta.ino()) {
        return Err("inject helper parent executable differs".to_string());
    }
    let mut parent_cmdline = Vec::with_capacity(fixed.as_os_str().as_encoded_bytes().len() + 1);
    std::fs::File::open(format!("/proc/{parent}/cmdline"))
        .map_err(|error| format!("open helper parent argv: {error}"))?
        .take((fixed.as_os_str().as_encoded_bytes().len() + 2) as u64)
        .read_to_end(&mut parent_cmdline)
        .map_err(|error| format!("read helper parent argv: {error}"))?;
    if std::env::var_os("VOBOOST_HELPER_DEBUG").as_deref() == Some(std::ffi::OsStr::new("1")) {
        log::helper_record(crate::canonical_log::Level::Debug, "injector",
            &format!("stage=authentication parent={parent} expected={} actual_cmdline={parent_cmdline:?}", fixed.display()));
    }
    if !daemon_parent_argv_matches(&parent_cmdline, fixed.as_os_str().as_encoded_bytes()) {
        return Err("inject helper parent argv is not the daemon argv".to_string());
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn run_internal_helper() -> Result<i32, String> {
    authenticate_helper_process().map_err(|error| format!("stage=authentication {error}"))?;
    let input_fd = std::io::stdin().as_raw_fd();
    set_nonblocking(input_fd)?;
    let line = read_line_deadline(input_fd, HELPER_IPC_TIMEOUT)
        .map_err(|error| format!("read inject helper request: {error}"))?;
    let request: HelperRequest =
        serde_json::from_str(&line).map_err(|error| format!("parse helper request: {error}"))?;
    if request.schema_version != 1
        || request.pid <= 1
        || request.init_symbol != "implant_init"
        || !matches!(
            request.so_path.as_str(),
            path if path == config::libimplant_path("arm64-v8a")
                || path == config::libimplant_path("armeabi-v7a")
        )
        || !(request.bootstrap_path.starts_with("/data/voboost/")
            || matches!(
                request.bootstrap_path.as_str(),
                "@pipe-bootstrap-init"
                    | "@pipe-bootstrap-load"
                    | "@pipe-bootstrap-abort"
                    | "@pipe-rebind"
            ))
        || request.expected_argv0.is_empty()
        || request.expected_argv0.len() > 255
        || request.expected_starttime == 0
        || request.expected_selinux_context.is_empty()
        || request.expected_selinux_context.len() > 255
    {
        return Err("inject helper request contract is invalid".to_string());
    }
    let c_so = CString::new(request.so_path.as_str()).map_err(|_| "helper so path contains NUL")?;
    let c_sym =
        CString::new(request.init_symbol.as_str()).map_err(|_| "helper symbol contains NUL")?;
    let c_cfg = CString::new(request.bootstrap_path.as_str())
        .map_err(|_| "helper bootstrap contains NUL")?;
    let c_argv0 =
        CString::new(request.expected_argv0.as_str()).map_err(|_| "helper argv0 contains NUL")?;
    let c_context = CString::new(request.expected_selinux_context.as_str())
        .map_err(|_| "helper SELinux context contains NUL")?;
    let mut fds = AgentPipeFds {
        record_read_fd: -1,
        state_reply_fd: -1,
    };
    let mut dlerror = [0_u8; 256];
    let code = unsafe {
        vbi_inject(
            request.pid,
            c_so.as_ptr(),
            c_sym.as_ptr(),
            c_cfg.as_ptr(),
            c_argv0.as_ptr(),
            request.expected_starttime,
            request.expected_uid,
            c_context.as_ptr(),
            &mut fds,
            dlerror.as_mut_ptr().cast(),
            dlerror.len(),
        )
    };
    if code != 0 {
        let record = helper_result_record(
            request.pid,
            code,
            &c_string_from_buf(&dlerror).unwrap_or_default(),
        );
        log::helper_record(record.level, &record.component, &record.message);
    }

    let record = owned_fd_if_valid(fds.record_read_fd);
    let reply = owned_fd_if_valid(fds.state_reply_fd);
    let response = HelperResponse {
        schema_version: 1,
        code,
        record_read_fd: record.as_ref().map_or(-1, AsRawFd::as_raw_fd),
        state_reply_fd: reply.as_ref().map_or(-1, AsRawFd::as_raw_fd),
        dlerror: c_string_from_buf(&dlerror).unwrap_or_default(),
        staged_cleanup: None,
    };
    let mut encoded = serde_json::to_vec(&response)
        .map_err(|error| format!("serialize helper response: {error}"))?;
    encoded.push(b'\n');
    if encoded.len() >= HELPER_PROTOCOL_MAX as usize {
        return Err("inject helper response envelope is invalid".to_string());
    }
    let output_fd = std::io::stdout().as_raw_fd();
    set_nonblocking(output_fd)?;
    write_all_deadline(output_fd, &encoded, HELPER_IPC_TIMEOUT)
        .map_err(|error| format!("publish helper response: {error}"))?;
    // Keep helper-owned result descriptors alive until the daemon has reopened
    // them. Parent death yields EOF only after ptrace cleanup has completed.
    let acknowledgement = read_line_deadline(input_fd, HELPER_IPC_TIMEOUT)
        .map_err(|error| format!("read helper acknowledgement: {error}"))?;
    if acknowledgement != "ack\n" {
        return Ok(125);
    }
    Ok(0)
}

#[cfg(target_os = "android")]
fn open_helper_fd(pid: u32, fd: i32, flags: i32) -> Option<OwnedFd> {
    if fd < 0 {
        log::debug("injector", &format!("stage=helper-fd-export helper_pid={pid} fd={fd} flags={flags} reason=descriptor-not-returned"));
        return None;
    }
    let mut options = std::fs::OpenOptions::new();
    if flags == libc::O_WRONLY {
        options.write(true);
    } else {
        options.read(true);
    }
    match options
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(format!("/proc/{pid}/fd/{fd}"))
    {
        Ok(file) => Some(file.into()),
        Err(error) => {
            log::err("injector", &format!("stage=helper-fd-reopen helper_pid={pid} fd={fd} flags={flags} errno={:?} reason={error}", error.raw_os_error()));
            None
        }
    }
}

/// Last-resort termination for a misbehaving inject helper: SIGKILL (the
/// helper blocks SIGTERM/SIGINT/SIGHUP around the ptrace window, so a
/// graceful signal cannot be relied on) and reap it unconditionally. A
/// helper that dies while ptrace-attached makes the kernel auto-detach the
/// tracee, so this is the guaranteed "no helper remains attached to the
/// target after the daemon gives up" backstop (live ANR 2026-09-18: an
/// orphaned helper left the target frozen in ptrace_stop until kill -9).
/// Returns the reaped exit status, or None if the child was already gone.
#[cfg(any(target_os = "android", test))]
fn kill_and_reap_child(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let _ = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
    let deadline = std::time::Instant::now() + timeout;
    retain_child_until_reaped(
        || child.try_wait(),
        deadline,
        || std::thread::sleep(std::time::Duration::from_millis(5)),
        || {
            log::err(
                "injector",
                "helper reap deadline expired; retaining ownership until exit",
            )
        },
    )
}

#[cfg(any(target_os = "android", test))]
fn retain_child_until_reaped(
    mut observe: impl FnMut() -> std::io::Result<Option<std::process::ExitStatus>>,
    deadline: std::time::Instant,
    mut wait: impl FnMut(),
    mut report_deadline: impl FnMut(),
) -> Option<std::process::ExitStatus> {
    let mut reported = false;
    loop {
        match observe() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            // ECHILD means the kernel has already reaped this child. Other
            // observation errors cannot prove that an attached helper is gone.
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return None,
            Err(_) => {}
        }
        if !reported && std::time::Instant::now() >= deadline {
            reported = true;
            report_deadline();
        }
        // Ordinary IPC/native deadlines still trigger SIGKILL. A cleanup
        // deadline never authorizes abandoning the child or releasing the
        // daemon's singleton while the kernel cannot prove its termination.
        wait();
    }
}

#[cfg(target_os = "android")]
fn inject_through_helper(
    request: &HelperRequest,
) -> Result<(HelperResponse, Option<OwnedFd>, Option<OwnedFd>), String> {
    let mut child = spawn_internal_inject_helper()
        .map_err(|error| format!("spawn signed inject helper: {error}"))?;
    log::debug(
        "injector",
        &format!(
            "helper attempt target={} pid={} uid={} context={} helper_pid={}",
            request.expected_argv0,
            request.pid,
            request.expected_uid,
            request.expected_selinux_context,
            child.id()
        ),
    );
    // Start owned stderr draining before IPC; stdout protocol stays unchanged.
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            kill_and_reap_child(&mut child, HELPER_IPC_TIMEOUT);
            return Err("inject helper stderr unavailable".into());
        }
    };
    let diagnostics = match std::thread::Builder::new()
        .name("inject-helper-logs".into())
        .spawn(move || drain_helper_stderr(stderr, collect_helper_record))
    {
        Ok(worker) => worker,
        Err(error) => {
            kill_and_reap_child(&mut child, HELPER_IPC_TIMEOUT);
            return Err(format!("start helper diagnostic reader: {error}"));
        }
    };
    let attempt = inject_helper_round(&mut child, request);
    let status = if attempt.is_err() {
        kill_and_reap_child(&mut child, HELPER_IPC_TIMEOUT)
    } else {
        child.try_wait().ok().flatten()
    };
    // Both paths reap the original helper before EOF/join.
    let details = diagnostics
        .join()
        .unwrap_or_else(|_| "helper diagnostic reader failed".into());
    if let Err(cause) = attempt {
        return Err(format!(
            "{cause}; helper_exit={}; {}",
            status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".into()),
            details
        ));
    }

    attempt
}

#[cfg(target_os = "android")]
fn inject_helper_round(
    child: &mut std::process::Child,
    request: &HelperRequest,
) -> Result<(HelperResponse, Option<OwnedFd>, Option<OwnedFd>), String> {
    let stdin = child
        .stdin
        .take()
        .ok_or("inject helper stdin unavailable")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("inject helper stdout unavailable")?;
    let mut encoded = serde_json::to_vec(request)
        .map_err(|error| format!("serialize helper request: {error}"))?;
    encoded.push(b'\n');
    if encoded.len() >= HELPER_PROTOCOL_MAX as usize {
        return Err("inject helper request envelope is invalid".to_string());
    }
    set_nonblocking(stdin.as_raw_fd())?;
    set_nonblocking(stdout.as_raw_fd())?;
    write_all_deadline(stdin.as_raw_fd(), &encoded, HELPER_IPC_TIMEOUT)
        .map_err(|error| format!("send helper request: {error}"))?;
    let line = read_line_deadline(stdout.as_raw_fd(), HELPER_IPC_TIMEOUT)
        .map_err(|error| format!("read helper response: {error}"))?;
    let mut response: HelperResponse =
        serde_json::from_str(&line).map_err(|error| format!("parse helper response: {error}"))?;
    if response.schema_version != 1 || response.dlerror.len() > 255 {
        return Err("inject helper response contract is invalid".to_string());
    }
    let record = open_helper_fd(child.id(), response.record_read_fd, libc::O_RDONLY);
    let reply = open_helper_fd(child.id(), response.state_reply_fd, libc::O_WRONLY);
    write_all_deadline(stdin.as_raw_fd(), b"ack\n", HELPER_IPC_TIMEOUT)
        .map_err(|error| format!("acknowledge helper result: {error}"))?;
    drop(stdin);
    drop(stdout);
    let status = wait_child_deadline(child, HELPER_IPC_TIMEOUT)?;
    if !status.success() {
        return Err("inject helper exited unsuccessfully".to_string());
    }
    response.staged_cleanup = crate::bootstrap_worker::DetachedStaged::after_helper_exit(
        response.code,
        status,
        request.pid,
        request.expected_starttime,
    );
    Ok((response, record, reply))
}

#[cfg(target_os = "android")]
fn spawn_internal_inject_helper() -> std::io::Result<std::process::Child> {
    std::process::Command::new("/data/voboost/voboost-inject")
        .arg("--internal-inject-helper")
        .env_clear()
        .env(
            "VOBOOST_HELPER_DEBUG",
            if log::is_debug() { "1" } else { "0" },
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
}

#[cfg(target_os = "android")]
fn set_nonblocking(fd: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(format!(
            "set helper fd nonblocking: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn poll_deadline(fd: i32, events: i16, deadline: std::time::Instant) -> Result<(), String> {
    loop {
        let timeout = remaining_poll_ms(deadline, std::time::Instant::now());
        if timeout <= 0 {
            return Err("helper IPC deadline expired".to_string());
        }
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if result != 1 || descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("helper control fd closed or failed".to_string());
        }
        return Ok(());
    }
}

#[cfg(target_os = "android")]
fn read_line_deadline(fd: i32, timeout: std::time::Duration) -> Result<String, String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut bytes = Vec::with_capacity(256);
    while bytes.len() < HELPER_PROTOCOL_MAX as usize {
        poll_deadline(fd, libc::POLLIN, deadline)?;
        let mut chunk = [0u8; 256];
        let count = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count > 0 {
            for byte in &chunk[..count as usize] {
                bytes.push(*byte);
                if *byte == b'\n' {
                    return String::from_utf8(bytes)
                        .map_err(|_| "helper envelope is not UTF-8".to_string());
                }
                if bytes.len() >= HELPER_PROTOCOL_MAX as usize {
                    break;
                }
            }
            continue;
        }
        if count < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            )
        {
            continue;
        }
        return Err("helper control fd reached EOF".to_string());
    }
    Err("helper envelope exceeds bound".to_string())
}

#[cfg(target_os = "android")]
fn write_all_deadline(fd: i32, bytes: &[u8], timeout: std::time::Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut offset = 0;
    while offset < bytes.len() {
        poll_deadline(fd, libc::POLLOUT, deadline)?;
        let count =
            unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            )
        {
            continue;
        }
        return Err("helper control write failed".to_string());
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn wait_child_deadline(
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> Result<std::process::ExitStatus, String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("wait inject helper: {error}"))?
        {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            return Err("inject helper exit deadline expired".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Inject libimplant.so into a target process, then call implant_init.
///
/// `abi` selects the per-ABI payload ("arm64-v8a" or "armeabi-v7a").
/// The daemon passes the matching-ABI path based on runtime bitness detection.
/// `bootstrap_path` is the daemon-authored bootstrap descriptor path; it names
/// the immutable core/module DEX files and the separate live config path.
/// On success, returns the injection result and the daemon-owned read-end of
/// the pipe created by the implant in the target process.
pub fn inject(
    pid: i32,
    abi: &str,
    bootstrap_path: &str,
    expect_argv0: &str,
    authority: &crate::target_identity::AttestedTarget,
) -> (InjectResult, Option<i32>, Option<i32>) {
    let so_path = config::libimplant_path(abi);

    // Verify the payload file exists before attempting injection.
    if !std::path::Path::new(&so_path).exists() {
        log::err(
            "injector",
            &format!("payload not found for {abi}: {so_path}"),
        );
        return (InjectResult::DlopenFailed, None, None);
    }

    let boot = match std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        Ok(boot) => boot,
        Err(_) => return (InjectResult::LoaderUnresolved, None, None),
    };
    let call = match crate::loader_quarantine::Call::begin(
        std::path::Path::new(config::ROOT_ZONE),
        boot.trim(),
        pid,
        authority.starttime,
        expect_argv0,
    ) {
        Ok(call) => call,
        Err(error) => {
            log::err(
                "injector",
                &format!("loader safety admission denied pid={pid}: {error}"),
            );
            return (InjectResult::LoaderUnresolved, None, None);
        }
    };
    log::info("injector", &format!("injecting pid={pid} abi={abi}"));

    // Stable result codes and dlerror out-parameters carry the native outcome.
    // Native diagnostics use owned helper stderr producer frames; the parent
    // collects them into the same canonical sink without changing stdout IPC.
    #[cfg(target_os = "android")]
    let (code, log_pipe, state_reply_pipe, dlerror) = {
        let request = HelperRequest {
            schema_version: 1,
            pid,
            so_path,
            init_symbol: "implant_init".to_string(),
            bootstrap_path: bootstrap_path.to_string(),
            expected_argv0: expect_argv0.to_string(),
            expected_starttime: authority.starttime,
            expected_uid: authority.uid,
            expected_selinux_context: authority.selinux_context.clone(),
        };
        match inject_through_helper(&request) {
            Ok((response, record, reply)) => {
                if let Some(proof) = response.staged_cleanup {
                    crate::bootstrap_worker::record_receipt(pid, proof);
                }
                (
                    response.code,
                    record.map(IntoRawFd::into_raw_fd),
                    reply.map(IntoRawFd::into_raw_fd),
                    Some(response.dlerror),
                )
            }
            Err(error) => {
                retain_native_failure(InjectResult::UnsafeCleanup, &error);
                log::err(
                    "injector",
                    &format!("inject helper failed pid={pid}: {error}"),
                );
                (INJECT_UNSAFE_CLEANUP, None, None, None)
            }
        }
    };
    #[cfg(not(target_os = "android"))]
    let (code, log_pipe, state_reply_pipe, dlerror) = {
        let c_so = CString::new(so_path).unwrap_or_default();
        let c_sym = CString::new("implant_init").unwrap();
        let c_cfg = CString::new(bootstrap_path).unwrap_or_default();
        let c_argv0 = CString::new(expect_argv0).unwrap_or_default();
        let c_context = CString::new(authority.selinux_context.as_str()).unwrap_or_default();
        let mut dlerr_buf = [0_u8; 256];
        let mut pipe_fds = AgentPipeFds {
            record_read_fd: -1,
            state_reply_fd: -1,
        };
        let code = unsafe {
            vbi_inject(
                pid,
                c_so.as_ptr(),
                c_sym.as_ptr(),
                c_cfg.as_ptr(),
                c_argv0.as_ptr(),
                authority.starttime,
                authority.uid,
                c_context.as_ptr(),
                &mut pipe_fds,
                dlerr_buf.as_mut_ptr().cast(),
                dlerr_buf.len(),
            )
        };
        (
            code,
            (pipe_fds.record_read_fd >= 0).then_some(pipe_fds.record_read_fd),
            (pipe_fds.state_reply_fd >= 0).then_some(pipe_fds.state_reply_fd),
            c_string_from_buf(&dlerr_buf),
        )
    };
    let result = InjectResult::from_code(code);
    let unresolved = matches!(
        result,
        InjectResult::LoaderUnresolved | InjectResult::UnsafeCleanup
    );
    if let Err(error) = call.complete(unresolved) {
        close_optional(log_pipe);
        close_optional(state_reply_pipe);
        log::err(
            "injector",
            &format!("loader safety completion denied pid={pid}: {error}"),
        );
        return (InjectResult::LoaderUnresolved, None, None);
    }
    if !result.is_ok()
        && result != InjectResult::Pending
        && result != InjectResult::Staged
        && result != InjectResult::RegisterDeferred
    {
        retain_native_failure(result, dlerror.as_deref().unwrap_or(""));
    }

    match result {
        InjectResult::Ok => log::ok("injector", &format!("injected pid={pid} (agent reached)")),
        InjectResult::Staged => log::info(
            "injector",
            &format!("owned worker staged pid={pid}; not agent-ready"),
        ),
        InjectResult::RegisterDeferred => log::info(
            "injector",
            &format!("inject deferred pid={pid}: register baseline requires a natural stop"),
        ),
        InjectResult::Pending => log::info(
            "injector",
            &format!("inject pending pid={pid}: agent deferred (early boot)"),
        ),
        InjectResult::Rebound => {
            log::info("injector", &format!("resident transport rebound pid={pid}"))
        }
        _ => {
            let label = result.label();
            // Surface the remote linker reason when the injector provided it
            // (dlopen failure). dlerr_buf is NUL-terminated by the injector.
            if let Some(reason) = dlerror.filter(|value| !value.is_empty()) {
                log::err(
                    "injector",
                    &format!("inject failed pid={pid}: {label}: {reason}"),
                );
            } else {
                log::err("injector", &format!("inject failed pid={pid}: {label}"));
            }
        }
    }

    if result.is_ok() && log_pipe.is_none() {
        if bootstrap_path == "@pipe-bootstrap-load" {
            log::debug(
                "injector",
                &format!("agent load retained bootstrap transport pid={pid}"),
            );
        } else {
            log::err("injector", &format!("agent log-pipe unavailable pid={pid}"));
        }
    }
    (result, log_pipe, state_reply_pipe)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentIdentity {
    pub generation_id: String,
    pub catalog_sha256: String,
    pub settings_loaded: bool,
    pub document_generation: Option<i64>,
}

/// Reconnect to an already initialized implant without streaming a bootstrap
/// or invoking the Java agent seam again.
pub fn rebind_resident(
    pid: i32,
    abi: &str,
    expect_argv0: &str,
    authority: &crate::target_identity::AttestedTarget,
) -> (
    InjectResult,
    Option<i32>,
    Option<i32>,
    Option<ResidentIdentity>,
) {
    let Some(target_lock) = target_bootstrap_lock(pid) else {
        return (InjectResult::InitFailed, None, None, None);
    };
    let Ok(_guard) = target_lock.lock() else {
        return (InjectResult::InitFailed, None, None, None);
    };
    let (result, record_fd, downlink_fd) =
        inject(pid, abi, "@pipe-rebind", expect_argv0, authority);
    if result != InjectResult::Rebound {
        close_optional(record_fd);
        close_optional(downlink_fd);
        return (result, None, None, None);
    }
    let Some(record) = record_fd else {
        close_optional(downlink_fd);
        return (InjectResult::InitFailed, None, None, None);
    };
    let Some(downlink) = downlink_fd else {
        close_optional(Some(record));
        return (InjectResult::InitFailed, None, None, None);
    };
    match read_resident_identity(record) {
        Some(identity) => (result, Some(record), Some(downlink), Some(identity)),
        None => {
            close_optional(Some(record));
            close_optional(Some(downlink));
            (InjectResult::InitFailed, None, None, None)
        }
    }
}

fn parse_resident_identity(line: &[u8]) -> Option<ResidentIdentity> {
    let text = std::str::from_utf8(line).ok()?.strip_suffix('\n')?;
    let mut fields = text.split('|');
    if fields.next()? != "B" {
        return None;
    }
    let generation_id = fields.next()?;
    let catalog_sha256 = fields.next()?;
    let settings_loaded = match fields.next() {
        None | Some("0") => false,
        Some("1") => true,
        _ => return None,
    };
    let document_generation = match fields.next() {
        None | Some("-1") => None,
        Some(value) => {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            Some(value.parse::<i64>().ok()?)
        }
    };
    if fields.next().is_some()
        || ![generation_id, catalog_sha256].iter().all(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return None;
    }
    Some(ResidentIdentity {
        generation_id: generation_id.to_string(),
        catalog_sha256: catalog_sha256.to_string(),
        settings_loaded,
        document_generation,
    })
}

fn read_resident_identity(fd: i32) -> Option<ResidentIdentity> {
    const MAX_IDENTITY_BYTES: usize = 155;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut line = Vec::with_capacity(MAX_IDENTITY_BYTES);
    while line.len() < MAX_IDENTITY_BYTES {
        let timeout = remaining_poll_ms(deadline, std::time::Instant::now());
        if timeout <= 0 {
            return None;
        }
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, timeout) };
        if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if ready != 1 || poll_fd.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
            return None;
        }
        let mut byte = 0u8;
        let count = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if count != 1 {
            return None;
        }
        line.push(byte);
        if byte == b'\n' {
            return parse_resident_identity(&line);
        }
    }
    None
}

/// Serialize complete bootstrap/rebind operations for one PID, including reuse.
fn target_bootstrap_lock(pid: i32) -> Option<std::sync::Arc<std::sync::Mutex<()>>> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    static LOCKS: OnceLock<Mutex<HashMap<i32, Weak<Mutex<()>>>>> = OnceLock::new();
    if pid <= 0 {
        return None;
    }
    let mut locks = LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()?;
    locks.retain(|_, lock| lock.strong_count() != 0);
    if let Some(lock) = locks.get(&pid).and_then(Weak::upgrade) {
        return Some(lock);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(pid, Arc::downgrade(&lock));
    Some(lock)
}

/// Bounded diagnostics extracted only from the signed native helper. Unknown
/// text is deliberately discarded; no linker paths, argv or envelopes persist.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct NativeFailure {
    result: String,
    stage: &'static str,
    restore_part: &'static str,
    operation: &'static str,
    reason: &'static str,
    pstate_expected: Option<u64>,
    pstate_observed: Option<u64>,
    pstate_xor: Option<u64>,
    first_mismatch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_failure: Option<Box<NativeFailure>>,
}
impl NativeFailure {
    pub(crate) fn classify(result: InjectResult, text: &str) -> Self {
        let mut value = Self {
            result: result.label().into(),
            stage: "unclassified",
            restore_part: "unclassified",
            operation: "unclassified",
            reason: "unclassified",
            pstate_expected: None,
            pstate_observed: None,
            pstate_xor: None,
            first_mismatch: None,
            initial_failure: None,
        };
        // The native diagnostic is <=256 bytes. Reject oversized input entirely.
        if text.len() > 2048 {
            return value;
        }
        if text == "transport-missing-endpoints" {
            value.stage = "endpoint-adoption";
            value.operation = "missing";
            value.reason = "missing-endpoints";
            return value;
        }
        let words: Vec<_> = text.split_ascii_whitespace().collect();
        for word in &words {
            if let Some(part) = word.strip_prefix("restore=") {
                if let Some((part, operation)) = part.split_once('/') {
                    value.stage = if operation == "complete" {
                        match words.first().copied() {
                            Some("remote-call-stop") => "remote-call-stop",
                            Some("remote-call-timeout") => "remote-call-timeout",
                            _ => "unclassified",
                        }
                    } else {
                        "register-restore"
                    };
                    value.restore_part = match part {
                        "gpr" => "gpr",
                        "fp" => "fp",
                        "tls" => "tls",
                        "stack" => "stack",
                        _ => "unclassified",
                    };
                    value.operation = match operation {
                        "complete" => "complete",
                        "set" => "set",
                        "get" => "get",
                        "length" => "length",
                        "compare" => "compare",
                        "unavailable" => "unavailable",
                        _ => "unclassified",
                    };
                }
            }
            if let Some(reason) = word.strip_prefix("reason=") {
                value.reason = match reason {
                    "none" => "none",
                    "syscall" => "syscall",
                    "length" => "length",
                    "mismatch" => "mismatch",
                    "no-snapshot" => "no-snapshot",
                    _ => "unclassified",
                };
            }
        }
        if value.stage == "register-restore" {
            let number = |key: &str| {
                words
                    .iter()
                    .filter_map(|word| word.strip_prefix(key))
                    .next()
                    .and_then(|v| {
                        if let Some(hex) = v.strip_prefix("0x") {
                            if hex.len() > 16 {
                                None
                            } else {
                                u64::from_str_radix(hex, 16).ok()
                            }
                        } else if v.len() <= 20 {
                            v.parse::<u64>().ok()
                        } else {
                            None
                        }
                    })
            };
            if words.contains(&"pstate-valid=1") {
                value.pstate_expected = number("expected=");
                value.pstate_observed = number("observed=");
                value.pstate_xor = value
                    .pstate_expected
                    .zip(value.pstate_observed)
                    .map(|(a, b)| a ^ b);
            }
            value.first_mismatch = number("first=").filter(|n| *n <= 65536);
        }
        value
    }
}
thread_local! {
    static ATTEMPT_FAILURE: std::cell::RefCell<Option<NativeFailure>> = const { std::cell::RefCell::new(None) };
}
fn retain_native_failure(result: InjectResult, text: &str) {
    ATTEMPT_FAILURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(NativeFailure::classify(result, text));
        } else if result == InjectResult::UnsafeCleanup
            && slot
                .as_ref()
                .is_some_and(|first| first.result != InjectResult::UnsafeCleanup.label())
        {
            let mut unsafe_failure = NativeFailure::classify(result, text);
            unsafe_failure.initial_failure = slot.take().map(Box::new);
            *slot = Some(unsafe_failure);
        }
    });
}

/// Completed native ownership transfer. Dropping a result closes unadopted endpoints.
pub(crate) struct BootstrapOutcome {
    pub result: InjectResult,
    pub failure: Option<NativeFailure>,
    pub record: Option<OwnedFd>,
    pub downlink: Option<OwnedFd>,
    pub binding: Option<crate::bootstrap_worker::Binding>,
}

/// Establish both pipe phases under one PID lock. The synchronous owner alone
/// registers the staged binding and adopts the returned descriptors.
pub(crate) fn inject_pipe_bootstrap(
    pid: i32,
    abi: &str,
    envelope: &[u8],
    expect_argv0: &str,
    authority: &crate::target_identity::AttestedTarget,
) -> BootstrapOutcome {
    ATTEMPT_FAILURE.with(|slot| *slot.borrow_mut() = None);
    let (result, record, downlink, binding) =
        inject_pipe_bootstrap_raw(pid, abi, envelope, expect_argv0, authority);
    // cleanup_failure may promote a non-unsafe helper result when the abort
    // could not establish cleanup. Preserve that fencing result explicitly.
    if result == InjectResult::UnsafeCleanup {
        retain_native_failure(result, "");
    }
    BootstrapOutcome {
        failure: ATTEMPT_FAILURE
            .with(|slot| slot.borrow_mut().take())
            .or_else(|| {
                (!result.is_ok()
                    && result != InjectResult::Pending
                    && result != InjectResult::Staged
                    && result != InjectResult::RegisterDeferred)
                    .then(|| NativeFailure::classify(result, ""))
            }),
        result,
        record: record.and_then(owned_fd_if_valid),
        downlink: downlink.and_then(owned_fd_if_valid),
        binding,
    }
}

fn phase_one_result(result: InjectResult, record: bool, downlink: bool) -> InjectResult {
    if result == InjectResult::Ok && (!record || !downlink) {
        InjectResult::InitFailed
    } else {
        result
    }
}

fn inject_pipe_bootstrap_raw(
    pid: i32,
    abi: &str,
    envelope: &[u8],
    expect_argv0: &str,
    authority: &crate::target_identity::AttestedTarget,
) -> (
    InjectResult,
    Option<i32>,
    Option<i32>,
    Option<crate::bootstrap_worker::Binding>,
) {
    // Keep both phases and their PID-keyed receipts under one target lock.
    // Unrelated processes have independent helpers and bootstrap ownership.
    let Some(target_lock) = target_bootstrap_lock(pid) else {
        return (InjectResult::InitFailed, None, None, None);
    };
    let Ok(_inject_guard) = target_lock.lock() else {
        return (InjectResult::InitFailed, None, None, None);
    };
    let Some(binding) = crate::bootstrap_worker::new_binding(pid, authority.starttime, envelope)
    else {
        return (InjectResult::InitFailed, None, None, None);
    };
    let stage_frame = binding.frame(false);
    let (phase, record_fd, downlink_fd) =
        inject(pid, abi, "@pipe-bootstrap-init", expect_argv0, authority);
    if phase != InjectResult::Ok || record_fd.is_none() || downlink_fd.is_none() {
        if phase == InjectResult::Ok {
            retain_native_failure(InjectResult::InitFailed, "transport-missing-endpoints");
        }
        close_optional(record_fd);
        close_optional(downlink_fd);
        return (
            phase_one_result(phase, record_fd.is_some(), downlink_fd.is_some()),
            None,
            None,
            None,
        );
    }
    let Some(downlink) = downlink_fd else {
        // The guard above proves this branch unreachable today. Preserve the
        // original partial result rather than making a future refactor a
        // daemon panic at the injection boundary.
        return (phase, record_fd, downlink_fd, None);
    };
    let writer_fd = duplicate_cloexec(downlink);
    if writer_fd < 0 {
        close_optional(record_fd);
        close_optional(Some(downlink));
        let cleanup = abort_pipe_bootstrap(pid, abi, expect_argv0, authority);
        return (cleanup_failure(phase, cleanup), None, None, None);
    }
    // Non-blocking + poll with a hard deadline: if the target never reads
    // the envelope (e.g. its load phase failed and the retry guard state is
    // inconsistent), the daemon must not block forever on writer.join().
    let flags = unsafe { libc::fcntl(writer_fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(writer_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        close_optional(record_fd);
        close_optional(Some(downlink));
        close_optional(Some(writer_fd));
        let cleanup = abort_pipe_bootstrap(pid, abi, expect_argv0, authority);
        return (cleanup_failure(phase, cleanup), None, None, None);
    }
    // The scoped writer borrows the original caller-owned envelope while the
    // remote load runs. Pending retry keeps that same Vec; no envelope-sized
    // thread copy is allocated.
    let (result, extra_record, extra_downlink, written) = std::thread::scope(|scope| {
        let writer = scope.spawn(|| write_bootstrap_parts(writer_fd, &[envelope, &stage_frame]));
        let (result, extra_record, extra_downlink) =
            inject(pid, abi, "@pipe-bootstrap-load", expect_argv0, authority);
        (
            result,
            extra_record,
            extra_downlink,
            writer.join().unwrap_or(false),
        )
    });
    // Drain implant diagnostics from the phase-two log pipe before closing.
    // The implant writes its init-failure reason (e.g. "pipe bootstrap read
    // failed", "dlopen libart.so failed") into the log pipe via write_pipe_record.
    // Without draining, the daemon never sees WHY phase two failed.
    if let Some(log_fd) = extra_record.filter(|_| result != InjectResult::Staged) {
        // Poll briefly: the implant may not have flushed its diagnostics yet.
        let mut pfd = libc::pollfd {
            fd: log_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe { libc::poll(&mut pfd, 1, 2000) };
        let mut buf = crate::agent_log::DrainState::default();
        crate::agent_log::drain_diagnostics(log_fd, &mut buf);
    }
    close_optional(extra_record);
    close_optional(extra_downlink);
    if !written {
        log::err(
            "injector",
            &format!(
                "stage=bootstrap-envelope pid={pid} result={} bytes={} reason=writer-incomplete",
                result.label(),
                envelope.len()
            ),
        );
        close_optional(record_fd);
        close_optional(Some(downlink));
        let cleanup = abort_pipe_bootstrap(pid, abi, expect_argv0, authority);
        return (cleanup_failure(result, cleanup), None, None, None);
    }
    if result == InjectResult::Staged {
        let proof = crate::bootstrap_worker::take_receipt(pid);
        let commit = proof
            .as_ref()
            .and_then(|proof| binding.commit_after_detach(proof, written, &binding));
        let delivered = commit.is_some_and(|frame| {
            let fd = duplicate_cloexec(downlink);
            fd >= 0 && write_bootstrap_parts(fd, &[&frame])
        });
        if delivered {
            return (result, record_fd, Some(downlink), Some(binding));
        }
        log::err("injector", &format!("stage=bootstrap-commit pid={pid} starttime={} receiptPresent={} proofAccepted={} delivered=false", authority.starttime, proof.is_some(), commit.is_some()));
        close_optional(record_fd);
        close_optional(Some(downlink));
        let cleanup = abort_pipe_bootstrap(pid, abi, expect_argv0, authority);
        return (cleanup_failure(result, cleanup), None, None, None);
    }
    if result == InjectResult::Ok {
        (result, record_fd, Some(downlink), None)
    } else {
        // Drain the phase-one log pipe before closing: the implant wrote its
        // init-failure diagnostics (e.g. "pipe bootstrap read failed") into the
        // write-end (g_agent_log_fd, still open in the target). The phase-one
        // record_fd is the matching read-end the daemon owns.
        if let Some(log_fd) = record_fd {
            let mut pfd = libc::pollfd {
                fd: log_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let _ = unsafe { libc::poll(&mut pfd, 1, 2000) };
            let mut buf = crate::agent_log::DrainState::default();
            crate::agent_log::drain_diagnostics(log_fd, &mut buf);
        }
        close_optional(record_fd);
        close_optional(Some(downlink));
        let cleanup = abort_pipe_bootstrap(pid, abi, expect_argv0, authority);
        (
            if result == InjectResult::RegisterDeferred {
                cleanup_failure(result, cleanup)
            } else if cleanup == InjectResult::UnsafeCleanup {
                cleanup
            } else {
                result
            },
            None,
            None,
            None,
        )
    }
}

fn abort_pipe_bootstrap(
    pid: i32,
    abi: &str,
    expect_argv0: &str,
    authority: &crate::target_identity::AttestedTarget,
) -> InjectResult {
    let (result, record, downlink) =
        inject(pid, abi, "@pipe-bootstrap-abort", expect_argv0, authority);
    close_optional(record);
    close_optional(downlink);
    result
}

fn cleanup_failure(native: InjectResult, cleanup: InjectResult) -> InjectResult {
    if native == InjectResult::UnsafeCleanup || cleanup == InjectResult::UnsafeCleanup {
        InjectResult::UnsafeCleanup
    } else if native == InjectResult::RegisterDeferred && cleanup == InjectResult::Ok {
        // Phase two left phase-one transport ownership behind. Retry only
        // after the abort entry point actually completed.
        InjectResult::RegisterDeferred
    } else {
        InjectResult::InitFailed
    }
}

fn duplicate_cloexec(fd: i32) -> i32 {
    unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) }
}

fn remaining_poll_ms(deadline: std::time::Instant, now: std::time::Instant) -> i32 {
    deadline
        .checked_duration_since(now)
        .map(|remaining| remaining.as_millis().min(i32::MAX as u128) as i32)
        .unwrap_or(0)
}

#[cfg(all(test, target_os = "linux"))]
fn write_bootstrap_envelope(writer_fd: i32, envelope: BorrowedEnvelope<'_>) -> bool {
    write_bootstrap_parts(writer_fd, &[envelope.0])
}

fn write_bootstrap_parts(writer_fd: i32, parts: &[&[u8]]) -> bool {
    const WRITE_TIMEOUT_MS: i32 = 10_000;
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_millis(WRITE_TIMEOUT_MS as u64);
    for part in parts {
        let mut offset = 0usize;
        while offset < part.len() {
            let mut poll_fd = libc::pollfd {
                fd: writer_fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let remaining_ms = remaining_poll_ms(deadline, std::time::Instant::now());
            if remaining_ms <= 0 {
                close_optional(Some(writer_fd));
                return false;
            }
            let ready = unsafe { libc::poll(&mut poll_fd, 1, remaining_ms) };
            if ready == 0 {
                close_optional(Some(writer_fd));
                return false;
            }
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                close_optional(Some(writer_fd));
                return false;
            }
            let count = unsafe {
                libc::write(
                    writer_fd,
                    part[offset..].as_ptr().cast(),
                    part.len() - offset,
                )
            };
            if count > 0 {
                offset += count as usize;
                continue;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            close_optional(Some(writer_fd));
            return false;
        }
    }
    close_optional(Some(writer_fd));
    true
}

fn close_optional(fd: Option<i32>) {
    if let Some(fd) = fd {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Decode the first NUL-terminated string from a C out-param buffer.
/// Returns None when the buffer is empty/uninitialized (no detail available).
fn c_string_from_buf(buf: &[u8]) -> Option<String> {
    let end = buf.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&buf[..end]).ok().map(|s| s.to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reap_deadline_retains_ownership_until_terminal_observation() {
        use std::cell::Cell;
        use std::os::unix::process::ExitStatusExt;
        let observations = Cell::new(0);
        let waits = Cell::new(0);
        let reports = Cell::new(0);
        let status = super::retain_child_until_reaped(
            || {
                observations.set(observations.get() + 1);
                match observations.get() {
                    1 => Ok(None),
                    2 => Err(std::io::Error::from_raw_os_error(libc::EINTR)),
                    _ => Ok(Some(std::process::ExitStatus::from_raw(0))),
                }
            },
            std::time::Instant::now() - std::time::Duration::from_secs(1),
            || waits.set(waits.get() + 1),
            || reports.set(reports.get() + 1),
        )
        .unwrap();
        assert!(status.success());
        assert_eq!(observations.get(), 3);
        assert_eq!(waits.get(), 2);
        assert_eq!(reports.get(), 1);
    }

    #[test]
    fn bootstrap_abort_preserves_unsafe_cleanup_failure() {
        assert_eq!(
            super::cleanup_failure(super::InjectResult::UnsafeCleanup, super::InjectResult::Ok),
            super::InjectResult::UnsafeCleanup
        );
        assert_eq!(
            super::cleanup_failure(super::InjectResult::Ok, super::InjectResult::UnsafeCleanup),
            super::InjectResult::UnsafeCleanup
        );
        for result in [
            super::InjectResult::Ok,
            super::InjectResult::Denied,
            super::InjectResult::InitFailed,
        ] {
            assert_eq!(
                super::cleanup_failure(super::InjectResult::Ok, result),
                super::InjectResult::InitFailed
            );
        }
    }

    #[test]
    fn bootstrap_lock_excludes_same_pid_and_allows_different_pid() {
        let first = super::target_bootstrap_lock(181001).unwrap();
        let held = first.lock().unwrap();
        let same = super::target_bootstrap_lock(181001).unwrap();
        assert!(std::sync::Arc::ptr_eq(&first, &same));
        assert!(same.try_lock().is_err());
        let other = super::target_bootstrap_lock(181002).unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _owned = other.lock().unwrap();
            done_tx.send(()).unwrap();
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        drop(held);
        assert!(same.try_lock().is_ok());
        worker.join().unwrap();
        assert!(super::target_bootstrap_lock(0).is_none());
    }

    use super::*;

    #[cfg(not(target_os = "android"))]
    #[test]
    fn native_callee_producer_survives_helper_drain_and_error_retention() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("diagnostic");
        let mut compiler = Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-"])
            .arg("-I")
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../injector"))
            .arg("-o")
            .arg(&executable)
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(
                br#"#include "native_diagnostic.h"
int main(void) {
    vbi_native_diagnostic("error", "injector.callee", "remote signal=11\n");
    return 0;
}
"#,
            )
            .unwrap();
        let compilation = compiler.wait_with_output().unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        let mut producer = Command::new(&executable)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let logs = directory.path().join("logs");
        crate::canonical_log::with_test_log(&logs, || {
            drain_helper_stderr(producer.stderr.take().unwrap(), collect_helper_record);
        });
        let producer = producer.wait_with_output().unwrap();
        assert!(producer.status.success());
        assert!(producer.stdout.is_empty());
        let errors = std::fs::read_to_string(logs.join("error/segment-active.jsonl")).unwrap();
        let rows = errors
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["component"], "injector.callee");
        assert_eq!(rows[0]["message"], "remote signal=11\n");
    }

    #[test]
    fn helper_results_keep_expected_progress_out_of_error_retention() {
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        let codes = [
            INJECT_WORKER_STAGED,
            INJECT_RESIDENT_REBOUND,
            INJECT_AGENT_PENDING,
            INJECT_REGISTER_DEFERRED,
            INJECT_DENIED,
            INJECT_DLOPEN_FAILED,
            -999,
        ];
        crate::canonical_log::with_test_log(&logs, || {
            let mut producer = Vec::new();
            for code in codes {
                serde_json::to_writer(&mut producer, &helper_result_record(42, code, "reason"))
                    .unwrap();
                producer.push(b'\n');
            }
            drain_helper_stderr(producer.as_slice(), collect_helper_record);
        });
        let rows = crate::canonical_log::CanonicalLog::open(&logs)
            .unwrap()
            .query(&crate::canonical_log::Query {
                after_sequence: 0,
                limit: 200,
                levels: vec![],
                kinds: vec![],
                agent_ids: vec![],
                search: None,
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap()
            .records;
        assert_eq!(rows.len(), codes.len());
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(
                row.level,
                if index < 4 {
                    crate::canonical_log::Level::Debug
                } else {
                    crate::canonical_log::Level::Error
                }
            );
        }
        let errors = std::fs::read_to_string(logs.join("error/segment-active.jsonl")).unwrap();
        assert_eq!(errors.lines().count(), 3);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn helper_parent_accepts_oem_eof_or_single_nul_but_never_extra_arguments() {
        let path = b"/data/voboost/voboost-inject";
        assert!(daemon_parent_argv_matches(path, path));
        assert!(daemon_parent_argv_matches(
            &[path.as_slice(), b"\0"].concat(),
            path
        ));
        for bad in [
            b"".as_slice(),
            b"voboost-inject",
            b"/data/voboost/voboost-inject\0\0",
            b"/data/voboost/voboost-inject\0--internal-inject-helper\0",
            b"/data/voboost/voboost-inject-extra",
            b"/other/voboost-inject",
        ] {
            assert!(!daemon_parent_argv_matches(bad, path));
        }
    }

    #[test]
    fn helper_diagnostics_keep_first_last_errors_and_drain_beyond_pipe_capacity() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let pump = std::thread::spawn(move || bounded_helper_stderr(reader));
        let producer = std::thread::spawn(move || {
            writer.write_all(b"[helper-error] first failure\n").unwrap();
            for _ in 0..1024 {
                writer.write_all(&vec![b'x'; 2048]).unwrap();
                writer.write_all(b"\n").unwrap();
            }
            writer
                .write_all("[helper-error] last failure: Кириллица\n".as_bytes())
                .unwrap();
        });
        producer.join().unwrap();
        let retained = pump.join().unwrap();
        assert!(retained.contains("first failure"));
        assert!(retained.contains("last failure"));
        assert!(retained.contains("Кириллица"));
        assert!(retained.len() <= 64 * 1024);
        assert!(!retained.contains('\0'));
    }

    #[test]
    fn helper_stderr_preserves_failure_reason_with_a_finite_safe_bound() {
        let reason = b"[helper-error] stage=authentication parent argv rejected\n";
        assert!(bounded_helper_stderr(reason.as_slice()).contains("stage=authentication"));
        assert_eq!(
            bounded_helper_stderr(b"bad\0\xff\n".as_slice()),
            "bad?\u{fffd}\n"
        );
        assert_eq!(
            bounded_helper_stderr(std::io::Cursor::new(vec![b'x'; 5000])).len(),
            2048
        );
    }

    #[test]
    fn host_injector_stub_fails_closed() {
        let mut pipe_fds = AgentPipeFds {
            record_read_fd: -1,
            state_reply_fd: -1,
        };
        let mut dlerr = [0 as c_char; 8];
        let code = unsafe {
            vbi_inject(
                1,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
                &mut pipe_fds,
                dlerr.as_mut_ptr(),
                dlerr.len(),
            )
        };

        assert_eq!(code, INJECT_DENIED);
        assert_eq!(pipe_fds.record_read_fd, -1);
        assert_eq!(pipe_fds.state_reply_fd, -1);
        assert_eq!(dlerr, [0; 8]);
    }

    // Regression guard: a native-load success that leaves
    // the agent deferred (early boot, currentApplication null) MUST surface as
    // a distinct Pending result, not as Ok. Native injection success alone
    // must not be indistinguishable from a fully-initialized agent.
    #[test]
    fn agent_pending_code_maps_to_pending_not_ok() {
        let r = InjectResult::from_code(INJECT_AGENT_PENDING);
        assert_eq!(r, InjectResult::Pending);
        assert!(!r.is_ok(), "Pending must not be reported as a success");
        assert_eq!(r.label(), "agent-pending");
    }

    #[test]
    fn register_deferral_requires_clean_bootstrap_ownership() {
        let deferred = InjectResult::from_code(INJECT_REGISTER_DEFERRED);
        assert_eq!(deferred, InjectResult::RegisterDeferred);
        assert!(!deferred.is_ok());
        assert_eq!(deferred.label(), "register-baseline-deferred");
        assert_eq!(cleanup_failure(deferred, InjectResult::Ok), deferred);
        assert_eq!(
            cleanup_failure(deferred, deferred),
            InjectResult::InitFailed
        );
        assert_eq!(
            cleanup_failure(deferred, InjectResult::UnsafeCleanup),
            InjectResult::UnsafeCleanup
        );
    }

    #[test]
    fn ok_maps_to_ok() {
        assert_eq!(InjectResult::from_code(INJECT_OK), InjectResult::Ok);
        assert!(InjectResult::from_code(INJECT_OK).is_ok());
    }

    #[test]
    fn hard_failures_map_correctly() {
        assert_eq!(
            InjectResult::from_code(INJECT_INIT_FAILED),
            InjectResult::InitFailed
        );
        assert_eq!(
            InjectResult::from_code(INJECT_DLOPEN_FAILED),
            InjectResult::DlopenFailed
        );
        assert!(!InjectResult::from_code(INJECT_INIT_FAILED).is_ok());
    }

    #[test]
    fn resident_cache_maintenance_revision_survives_transport_rebind() {
        let frame = format!(
            "B|{}|{}|0|1770000000000000000\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(
            parse_resident_identity(frame.as_bytes()).is_some(),
            "accepted revision must survive daemon loss without sending a new desired document"
        );
        for revision in ["", "-2", "1e3", "9223372036854775808", "1|extra"] {
            let frame = format!("B|{}|{}|0|{revision}\n", "a".repeat(64), "b".repeat(64));
            assert!(parse_resident_identity(frame.as_bytes()).is_none());
        }
    }
    #[test]
    fn resident_rebind_has_an_explicit_non_success_result() {
        assert_eq!(
            InjectResult::from_code(INJECT_RESIDENT_REBOUND),
            InjectResult::Rebound
        );
        assert!(!InjectResult::Rebound.is_ok());
    }

    #[test]
    fn resident_identity_is_exact_and_rejects_malformed_or_wrong_shape() {
        let valid = format!("B|{}|{}\n", "a".repeat(64), "b".repeat(64));
        let parsed = parse_resident_identity(valid.as_bytes()).unwrap();
        assert_eq!(parsed.generation_id, "a".repeat(64));
        assert!(
            !parsed.settings_loaded,
            "legacy identity never proves Settings eligibility"
        );
        assert!(
            parse_resident_identity(format!("B|{}|short\n", "a".repeat(64)).as_bytes()).is_none()
        );
        assert!(parse_resident_identity(
            format!("X|{}|{}\n", "a".repeat(64), "b".repeat(64)).as_bytes()
        )
        .is_none());
    }

    #[test]
    fn resident_identity_accepts_native_settings_eligibility_and_rejects_other_bits() {
        for bit in ["0", "1"] {
            let frame = format!("B|{}|{}|{bit}\n", "a".repeat(64), "b".repeat(64));
            assert_eq!(frame.len(), 134);
            assert_eq!(
                parse_resident_identity(frame.as_bytes())
                    .unwrap()
                    .settings_loaded,
                bit == "1"
            );
        }
        for bit in ["true", "2", "", "1|extra"] {
            let frame = format!("B|{}|{}|{bit}\n", "a".repeat(64), "b".repeat(64));
            assert!(parse_resident_identity(frame.as_bytes()).is_none());
        }
    }

    #[test]
    fn bootstrap_writer_duplicate_is_cloexec() {
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let duplicate = duplicate_cloexec(fds[1]);
        assert!(duplicate >= 0);
        assert_ne!(
            unsafe { libc::fcntl(duplicate, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        close_optional(Some(fds[0]));
        close_optional(Some(fds[1]));
        close_optional(Some(duplicate));
    }

    #[test]
    fn owned_helper_endpoint_guard_keeps_fd_count_stable_on_fault_paths() {
        let before = std::fs::read_dir("/proc/self/fd")
            .map(|fds| fds.count())
            .ok();
        for _ in 0..64 {
            let mut fds = [-1, -1];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let guarded = owned_fd_if_valid(fds[0]).unwrap();
            close_optional(Some(fds[1]));
            drop(guarded);
        }
        let after = std::fs::read_dir("/proc/self/fd")
            .map(|fds| fds.count())
            .ok();
        if let (Some(before), Some(after)) = (before, after) {
            assert_eq!(after, before);
        }
    }

    #[test]
    fn unknown_code_defaults_to_init_failed() {
        assert_eq!(InjectResult::from_code(-999), InjectResult::InitFailed);
    }

    #[test]
    fn c_string_from_buf_decodes_nul_terminated_string() {
        let buf = b"library not found\0garbage";
        assert_eq!(
            c_string_from_buf(buf),
            Some("library not found".to_string())
        );
    }

    #[test]
    fn c_string_from_buf_none_for_all_zero_buffer() {
        // The injector initializes dlerr_out to all-zero on entry; a non-dlopen
        // failure leaves the buffer all-zeros, which must map to None (no reason).
        let buf = [0u8; 256];
        assert_eq!(c_string_from_buf(&buf), None);
    }

    #[test]
    fn c_string_from_buf_none_for_empty_string() {
        let buf = b"\0rest";
        assert_eq!(c_string_from_buf(buf), None);
    }

    #[test]
    fn c_string_from_buf_none_for_invalid_utf8() {
        // 0xff is invalid UTF-8 before the NUL → None (not a panic).
        let buf = [0xff, 0x00, 0x00];
        assert_eq!(c_string_from_buf(&buf), None);
    }

    #[test]
    fn c_string_from_buf_full_buffer_without_nul_is_none() {
        // No NUL terminator in the buffer → position()? returns None.
        let buf = [b'a'; 8];
        assert_eq!(c_string_from_buf(&buf), None);
    }

    #[test]
    fn kill_and_reap_child_terminates_and_reaps_a_live_helper() {
        // The unsafe-cleanup backstop: a helper that ignores graceful
        // shutdown must be SIGKILLed and reaped so it can never remain
        // ptrace-attached to a target after the daemon gives up.
        let mut child = std::process::Command::new("/usr/bin/sleep")
            .arg("300")
            .stdout(std::process::Stdio::null())
            .spawn()
            .or_else(|_| {
                std::process::Command::new("/bin/sleep")
                    .arg("300")
                    .stdout(std::process::Stdio::null())
                    .spawn()
            })
            .expect("spawn sleep");
        let pid = child.id();
        let started = std::time::Instant::now();
        let status = kill_and_reap_child(&mut child, std::time::Duration::from_secs(10));
        assert!(status.is_some(), "helper must be reaped, not abandoned");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        // Reaped: no zombie remains and a second reap reports the same exit.
        let again = kill_and_reap_child(&mut child, std::time::Duration::from_secs(1));
        assert!(again.is_some());
        assert!(std::fs::metadata(format!("/proc/{pid}/stat")).is_err());
    }

    #[test]
    fn kill_and_reap_child_tolerates_already_exited_helper() {
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .or_else(|_| std::process::Command::new("/bin/true").spawn())
            .expect("spawn true");
        // Let it exit on its own first.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let status = kill_and_reap_child(&mut child, std::time::Duration::from_secs(5));
        assert!(status.is_some());
        assert!(status.unwrap().success());
    }

    #[test]
    fn stalled_scheduler_deadline_saturates_instead_of_panicking() {
        let now = std::time::Instant::now();
        let deadline = now + std::time::Duration::from_millis(1);
        assert_eq!(
            remaining_poll_ms(deadline, now + std::time::Duration::from_secs(1)),
            0
        );
    }

    #[test]
    fn bootstrap_writer_transaction_is_only_a_borrowed_slice() {
        let envelope = vec![7u8; 1024];
        let borrowed = BorrowedEnvelope(&envelope);
        assert_eq!(borrowed.0.as_ptr(), envelope.as_ptr());
        assert_eq!(
            std::mem::size_of_val(&borrowed),
            std::mem::size_of::<&[u8]>()
        );
    }
}

#[cfg(test)]
mod retained_native_failure_tests {
    #[test]
    fn unsafe_cleanup_supersedes_initial_failure_but_keeps_bounded_secondary() {
        ATTEMPT_FAILURE.with(|slot| *slot.borrow_mut() = None);
        retain_native_failure(InjectResult::InitFailed, "initial arbitrary SECRET_TOKEN");
        retain_native_failure(InjectResult::UnsafeCleanup, "restore=gpr/compare reason=mismatch pstate-valid=1 expected=0x0 observed=0x400 first=265");
        let value = ATTEMPT_FAILURE
            .with(|slot| slot.borrow_mut().take())
            .unwrap();
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["result"], InjectResult::UnsafeCleanup.label());
        assert_eq!(
            json["initial_failure"]["result"],
            InjectResult::InitFailed.label()
        );
        assert_eq!(json["pstate_xor"], 1024);
        assert!(!json.to_string().contains("SECRET_TOKEN"));
    }

    use super::*;
    #[test]
    fn bounded_diagnostics_drop_unknown_text_and_preserve_first_failure_per_worker() {
        let handles: Vec<_> = (0..8).map(|n| std::thread::spawn(move || {
            ATTEMPT_FAILURE.with(|slot| *slot.borrow_mut() = None);
            retain_native_failure(InjectResult::UnsafeCleanup, &format!("restore=gpr/compare reason=mismatch pstate-valid=1 expected=0x60000000 observed=0x60000400 first={} SECRET_TOKEN", n));
            retain_native_failure(InjectResult::Denied, "cleanup later failed SECRET_TOKEN");
            let first = ATTEMPT_FAILURE.with(|slot| slot.borrow_mut().take()).unwrap();
            let value = serde_json::to_value(&first).unwrap();
            assert_eq!(value["first_mismatch"], n);
            assert_eq!(value["reason"], "mismatch");
            assert!(!serde_json::to_string(&first).unwrap().contains("SECRET_TOKEN"));
            assert!(ATTEMPT_FAILURE.with(|slot| slot.borrow_mut().take()).is_none());
        })).collect();
        for handle in handles {
            handle.join().unwrap();
        }
        for input in [
            "".to_string(),
            "attemptToken=SECRET_TOKEN".into(),
            "x".repeat(2049),
        ] {
            let value = serde_json::to_value(NativeFailure::classify(InjectResult::Denied, &input))
                .unwrap();
            assert_eq!(value["stage"], "unclassified");
            assert_eq!(value["pstate_expected"], serde_json::Value::Null);
            assert!(!value.to_string().contains("SECRET_TOKEN"));
        }
    }
}

#[cfg(test)]
mod resident_transport_regression_tests {
    use super::*;
    #[test]
    fn actual_cold_boot_remote_failure_does_not_claim_tls_restore_failure() {
        for call in ["stop", "timeout"] {
            let text = format!("remote-call-{call} restore=tls/complete reason=none pstate-valid=0 expected=0x0 observed=0x0 changed=0x0 errno-valid=0 restore-errno=0 length=8/8 mismatch=0 first=0 helper=10331 pid=2866 phase=native");
            let failure = NativeFailure::classify(InjectResult::DlopenFailed, &text);
            assert_eq!(failure.stage, format!("remote-call-{call}"));
            assert_eq!(failure.restore_part, "tls");
            assert_eq!(failure.operation, "complete");
            assert_eq!(failure.reason, "none");
            assert_eq!(failure.first_mismatch, None);
        }
    }
    #[test]
    fn actual_tls_failure_keeps_restore_diagnostics() {
        let failure = NativeFailure::classify(
            InjectResult::UnsafeCleanup,
            "remote-call-stop restore=tls/compare reason=mismatch first=1",
        );
        assert_eq!(failure.stage, "register-restore");
        assert_eq!(failure.operation, "compare");
        assert_eq!(failure.reason, "mismatch");
        assert_eq!(failure.first_mismatch, Some(1));
    }
    #[test]
    fn phase_one_success_requires_both_owned_endpoints() {
        assert_eq!(
            phase_one_result(InjectResult::Ok, true, true),
            InjectResult::Ok
        );
        for (record, downlink) in [(false, false), (true, false), (false, true)] {
            assert_eq!(
                phase_one_result(InjectResult::Ok, record, downlink),
                InjectResult::InitFailed
            );
        }
        assert_eq!(
            phase_one_result(InjectResult::UnsafeCleanup, false, false),
            InjectResult::UnsafeCleanup
        );
        assert_eq!(
            phase_one_result(InjectResult::Staged, true, true),
            InjectResult::Staged
        );
    }
    #[test]
    fn missing_endpoints_has_closed_specific_diagnostic() {
        let failure =
            NativeFailure::classify(InjectResult::InitFailed, "transport-missing-endpoints");
        assert_eq!(failure.stage, "endpoint-adoption");
        assert_eq!(failure.reason, "missing-endpoints");
    }
}
