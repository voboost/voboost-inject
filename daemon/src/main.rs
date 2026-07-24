// main.rs — daemon entry point.
//
// The new Rust daemon. For Wave 1.1 (injection-control) this wires up the
// shared modules and the injection/reconcile/process-watcher/safety logic.
// The full lifecycle (state machine, SIGTERM handling, boot trigger) is
// completed in Wave 1.2 (daemon-lifecycle).

pub mod boot;
pub mod config;
pub mod control_plane;
pub mod injector;
pub mod log;
pub mod manifest;
pub mod plan;
pub mod process_watcher;
pub mod reconcile;
pub mod safety;
pub mod status;
pub mod trust;

pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    log::init();
    log::info(
        "main",
        &format!("voboost-inject {DAEMON_VERSION} starting (new stack)"),
    );

    // --- Single-instance via pidfile + flock ---
    if !acquire_single_instance() {
        log::err("main", "another instance holds the pidfile lock");
        std::process::exit(1);
    }

    // --- Startup gate ---
    if !startup_permitted() {
        log::info("main", "startup intent is none: gated exit");
        release_lock();
        std::process::exit(0);
    }

    // --- Verify self (manifest sig + agent sha256) ---
    let manifest = match verify_self() {
        Some(m) => m,
        None => {
            log::err("main", "DEGRADED: self-verification failed");
            write_degraded_status();
            run_degraded_loop();
            return;
        }
    };
    log::ok("main", &format!("READY ({} agents)", manifest.agents.len()));

    // --- Run the daemon loop ---
    run_daemon(manifest);
}

/// Acquire single-instance lock via pidfile + flock.
fn acquire_single_instance() -> bool {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::PermissionsExt;

    let run_dir = config::RUN_DIR;
    let _ = fs::create_dir_all(run_dir);
    let _ = fs::set_permissions(run_dir, fs::Permissions::from_mode(0o700));

    let pidfile = config::pidfile();
    let file = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&pidfile)
    {
        Ok(f) => f,
        Err(_) => return false,
    };

    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    // LOCK_EX | LOCK_NB = 2 | 4
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 {
        return false;
    }

    // Write our pid (informational — the lock is the real guard).
    let _ = fs::write(&pidfile, format!("{}\n", std::process::id()));

    // Keep the file handle alive for the process lifetime.
    // Leak it intentionally — the lock must persist until exit.
    std::mem::forget(file);
    true
}

fn release_lock() {
    // The flock is released automatically when the process exits.
    // The pidfile is left on disk (informational).
}

/// Startup gate: read inject.json `startup` field.
fn startup_permitted() -> bool {
    let path = config::plan_file();
    let Ok(content) = std::fs::read_to_string(&path) else {
        return true; // absent → permitted
    };
    if content.len() > config::MAX_PLAN_BYTES {
        return true; // oversized → permitted (fail-safe)
    }
    let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(&content) else {
        return true; // malformed → permitted
    };
    let startup = v.get("startup").and_then(|s| s.as_str()).unwrap_or("");
    !startup.eq_ignore_ascii_case("none")
}

/// VERIFY_SELF: load + verify manifest.
fn verify_self() -> Option<manifest::Manifest> {
    let json_bytes = std::fs::read(config::manifest_file()).ok()?;
    let sig = std::fs::read(config::manifest_sig_file()).ok()?;

    if !trust::verify_signature(&json_bytes, &sig) {
        log::err("main", "manifest signature rejected");
        return None;
    }

    let manifest = manifest::Manifest::parse(&json_bytes)?;

    // Verify every agent sha256.
    for agent in &manifest.agents {
        let agent_path = format!("{}/{}", config::ROOT_ZONE, agent.file);
        if !trust::verify_agent(&agent_path, &agent.sha256) {
            log::err("main", &format!("sha256 mismatch: {}", agent.id));
            return None;
        }
    }

    Some(manifest)
}

fn write_degraded_status() {
    let mut status = status::Status::default();
    status.daemon_version = DAEMON_VERSION.to_string();
    status.daemon_state = "degraded".to_string();
    status.write_atomic();
}

/// Run the daemon loop: poll /proc, reconcile, inject, monitor.
///
/// daemon-lifecycle: runs on the main thread (blocking poll). SIGTERM is
/// caught by a signal handler that sets a shutdown flag — the poll loop
/// checks it each iteration and exits cleanly WITHOUT tearing down hooks
/// (injected code outlives the daemon).
fn run_daemon(manifest: manifest::Manifest) {
    let mut safety = safety::Safety::new();
    let mut watcher = process_watcher::ProcessWatcher::new();
    let boot_state = boot::BootState::new();
    let mut status = status::Status::default();
    status.daemon_version = DAEMON_VERSION.to_string();
    status.daemon_state = "ready".to_string();
    status.manifest_version = manifest.manifest_version;

    // Install SIGTERM handler — sets the shutdown flag, does NOT kill hooks.
    install_sigterm_handler();

    log::ok(
        "main",
        "daemon loop started (ptrace injection, /proc polling)",
    );
    status.write_atomic();

    // Poll loop. The first iteration discovers and injects every already-running
    // target (the tracker starts empty, so poll_pass reports them as appeared).
    let poll_interval = std::time::Duration::from_secs(2);
    loop {
        // Check shutdown flag (set by SIGTERM handler).
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
            log::info("main", "SIGTERM: clean shutdown (hooks left running)");
            release_lock();
            break;
        }

        std::thread::sleep(poll_interval);

        // Reload plan (detect changes).
        let plan = plan::read_and_validate(&manifest);
        log::set_debug(plan.log_level == "debug");
        safety.set_plan_disable_all(plan.disable_all);

        if safety.kill_switch_active() {
            if !status.kill_switch {
                log::info("main", "kill-switch active; idling");
                status.kill_switch = true;
                status.write_atomic();
            }
            continue;
        }
        if status.kill_switch {
            status.kill_switch = false;
            log::info("main", "kill-switch cleared but restart required to resume");
            status.write_atomic();
            continue;
        }

        // Get target processes from the plan.
        let target_processes: Vec<String> = plan
            .group_by_process(&manifest)
            .keys()
            .map(|s| s.to_string())
            .collect();

        if target_processes.is_empty() {
            continue;
        }

        // Poll for appearances and deaths.
        let (appeared, died) = watcher.poll_pass(&target_processes);

        // Record deaths.
        for (_pid, process) in &died {
            safety.note_target_death();
            safety.note_target_crash(process);
        }
        if safety.panic_quarantined() && !status.panic_quarantine {
            status.panic_quarantine = true;
            log::err("main", "panic-quarantine active");
        }

        // Check boot completion for boot-deferred agents.
        let boot_done = boot_state.boot_completed();

        // Inject new appearances.
        for (process, pid) in &appeared {
            // Skip degraded targets.
            if safety.is_target_degraded(process) {
                status.set_injection("", process, status::InjectionState::Degraded);
                continue;
            }

            // Reconcile: already injected?
            if reconcile::is_injected(*pid) {
                log::debug(
                    "main",
                    &format!("reconcile: {process} pid={pid} already injected"),
                );
                continue;
            }

            // Foreign coexistence skip.
            if reconcile::has_foreign_footprint(*pid) {
                log::info("main", &format!("coexistence skip: {process} pid={pid}"));
                status.set_injection("", process, status::InjectionState::SkippedCoexist);
                continue;
            }

            // Boot-readiness gate: agents with boot:true wait for boot_completed.
            if !boot_done {
                // Check if this process has any boot-deferred agents.
                let has_boot_agents = manifest
                    .agents
                    .iter()
                    .any(|a| a.process == *process && a.requires_boot);
                if has_boot_agents {
                    log::debug(
                        "main",
                        &format!("boot-deferred: {process} pid={pid} waiting"),
                    );
                    status.set_injection("", process, status::InjectionState::Waiting);
                    continue;
                }
            }

            // Detect bitness → select ABI.
            let Some(abi) = reconcile::detect_bitness(*pid) else {
                log::err(
                    "main",
                    &format!("bitness detection failed: {process} pid={pid}"),
                );
                status.set_injection("", process, status::InjectionState::Failed);
                continue;
            };

            // Inject.
            // First, write the per-process config to channel B (all enabled
            // agents mapped to this process).
            let config_json = plan.config_for_process(process, &manifest);
            let _ = control_plane::write_config(process, &config_json);

            let result = injector::inject(*pid, abi);
            match result {
                injector::InjectResult::Ok => {
                    watcher.tracker_mut().track(process, *pid);
                    safety.note_success("", process);
                    status.set_injection("", process, status::InjectionState::Active);
                }
                _ => {
                    safety.note_failure("", process);
                    safety.note_target_crash(process);
                    status.set_injection("", process, status::InjectionState::Failed);
                }
            }
        }

        // Aggregate per-process agent statuses from channel B into status.
        let tracked = watcher.tracker().tracked_targets();
        control_plane::aggregate_agent_statuses(&mut status, &tracked);

        status.write_atomic();
    }
}

/// Global shutdown flag, set by the SIGTERM handler.
static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install a SIGTERM handler that sets the shutdown flag.
/// The poll loop checks it each iteration and exits cleanly.
/// SIGTERM does NOT tear down hooks — injected code outlives the daemon.
extern "C" fn handle_sigterm(_sig: i32) {
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn install_sigterm_handler() {
    unsafe {
        let handler: extern "C" fn(i32) = handle_sigterm;
        libc::signal(libc::SIGTERM, handler as usize as libc::sighandler_t);
    }
}

/// Run in degraded mode (observe-only, inject nothing).
fn run_degraded_loop() {
    log::info("main", "running in DEGRADED mode (observe-only)");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}
