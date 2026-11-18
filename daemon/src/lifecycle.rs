//! Daemon process lifecycle and init-owned restart handoff.

use super::*;
use crate::product_candidate::Admission;
use crate::runtime::{DaemonLoop, DaemonPollDisposition};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonIterationOutcome {
    Continue,
    RebootForUpdate,
    /// Committed `startup: none`: stop the init-owned service and exit. The
    /// loop must not poll again afterwards.
    SelfStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductRecoveryDisposition {
    Continue,
    RebootRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductRecoveryPollOutcome {
    Deferred,
    Accepted,
    RolledBack,
    RebootRequired,
    NoWork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StartupProductRecoveryDisposition {
    Continue,
    ProductDegraded,
    RebootRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductRecoveryTerminal {
    Accepted,
    RolledBack,
    NoWork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductDegradedIterationOutcome {
    Wait(std::time::Duration),
    RestartNormal(ProductRecoveryTerminal),
    RebootHandedOff,
}

const PRODUCT_RECOVERY_INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);
const PRODUCT_RECOVERY_MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(30);
const PRODUCT_RECOVERY_IDLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
type DiscoveryStamp = Option<(u64, u64, i64, i64)>;

struct ProductRecoveryPoll {
    next_poll: std::time::Instant,
    backoff: std::time::Duration,
    discovery: Option<Vec<DiscoveryStamp>>,
}

impl ProductRecoveryPoll {
    fn new(now: std::time::Instant) -> Self {
        Self {
            next_poll: now,
            backoff: PRODUCT_RECOVERY_INITIAL_BACKOFF,
            discovery: None,
        }
    }

    fn after_deferred_attempt(now: std::time::Instant) -> Self {
        let mut poll = Self::new(now);
        poll.defer(now);
        poll
    }

    fn poll_at(
        &mut self,
        now: std::time::Instant,
        recover: impl FnOnce() -> Result<Option<Admission>, String>,
    ) -> ProductRecoveryPollOutcome {
        if now < self.next_poll {
            return ProductRecoveryPollOutcome::Deferred;
        }
        match recover() {
            Ok(Some(Admission::RebootRequired)) => ProductRecoveryPollOutcome::RebootRequired,
            Ok(Some(Admission::Pending | Admission::InstallApk)) => {
                self.defer(now);
                ProductRecoveryPollOutcome::Deferred
            }
            Ok(Some(Admission::Accepted)) => {
                log::ok("main", "autonomous product activation recovery completed");
                self.reset(now);
                ProductRecoveryPollOutcome::Accepted
            }
            Ok(Some(Admission::ActivationFailed)) => {
                log::err("main", "autonomous product activation recovery rolled back");
                self.reset(now);
                ProductRecoveryPollOutcome::RolledBack
            }
            Ok(Some(outcome)) => {
                log::err(
                    "main",
                    &format!("autonomous product activation stopped: {outcome:?}"),
                );
                self.defer(now);
                ProductRecoveryPollOutcome::Deferred
            }
            Ok(None) => {
                self.reset(now);
                self.next_poll = now + PRODUCT_RECOVERY_IDLE_INTERVAL;
                ProductRecoveryPollOutcome::NoWork
            }
            Err(error) => {
                log::err(
                    "main",
                    &format!("autonomous product activation recovery deferred: {error}"),
                );
                self.defer(now);
                ProductRecoveryPollOutcome::Deferred
            }
        }
    }

    fn defer(&mut self, now: std::time::Instant) {
        self.next_poll = now + self.backoff;
        self.backoff = self
            .backoff
            .saturating_mul(2)
            .min(PRODUCT_RECOVERY_MAX_BACKOFF);
    }

    fn reset(&mut self, now: std::time::Instant) {
        self.next_poll = now + PRODUCT_RECOVERY_INITIAL_BACKOFF;
        self.backoff = PRODUCT_RECOVERY_INITIAL_BACKOFF;
    }

    fn observe_discovery(&mut self, root: &std::path::Path, now: std::time::Instant) {
        use std::os::unix::fs::MetadataExt;
        let stamps = [root.join("recovery"), root.join("operation.json")]
            .iter()
            .map(|path| {
                std::fs::symlink_metadata(path).ok().map(|metadata| {
                    (
                        metadata.dev(),
                        metadata.ino(),
                        metadata.ctime(),
                        metadata.ctime_nsec(),
                    )
                })
            })
            .collect::<Vec<_>>();
        if self
            .discovery
            .as_ref()
            .is_some_and(|previous| previous != &stamps)
        {
            self.next_poll = now;
        }
        self.discovery = Some(stamps);
    }
}

pub(super) fn startup_product_recovery_disposition(
    recovery: &Result<Option<Admission>, String>,
) -> StartupProductRecoveryDisposition {
    match recovery {
        Ok(Some(Admission::RebootRequired)) => StartupProductRecoveryDisposition::RebootRequired,
        Err(_) => StartupProductRecoveryDisposition::ProductDegraded,
        Ok(_) => StartupProductRecoveryDisposition::Continue,
    }
}

fn run_product_degraded_iteration(
    poll: &mut ProductRecoveryPoll,
    now: std::time::Instant,
    recover: impl FnOnce() -> Result<Option<Admission>, String>,
    request_reboot: impl FnOnce() -> bool,
) -> ProductDegradedIterationOutcome {
    match poll.poll_at(now, recover) {
        ProductRecoveryPollOutcome::Deferred => {
            ProductDegradedIterationOutcome::Wait(poll.next_poll.saturating_duration_since(now))
        }
        ProductRecoveryPollOutcome::Accepted => {
            ProductDegradedIterationOutcome::RestartNormal(ProductRecoveryTerminal::Accepted)
        }
        ProductRecoveryPollOutcome::RolledBack => {
            ProductDegradedIterationOutcome::RestartNormal(ProductRecoveryTerminal::RolledBack)
        }
        ProductRecoveryPollOutcome::NoWork => {
            ProductDegradedIterationOutcome::RestartNormal(ProductRecoveryTerminal::NoWork)
        }
        ProductRecoveryPollOutcome::RebootRequired if request_reboot() => {
            ProductDegradedIterationOutcome::RebootHandedOff
        }
        ProductRecoveryPollOutcome::RebootRequired => {
            poll.defer(now);
            ProductDegradedIterationOutcome::Wait(poll.next_poll.saturating_duration_since(now))
        }
    }
}

trait DaemonIterationActions {
    fn injection_jobs_active(&mut self) -> bool;
    fn poll_ota(&mut self, mutations_allowed: bool);
    fn poll_product_recovery(&mut self) -> ProductRecoveryDisposition;
    fn active_generation_differs(&mut self) -> bool;
    fn adopt_active_generation(&mut self) -> Result<(), String>;
    fn uninstall_frozen(&mut self) -> bool;
    fn prepared_uninstall(&mut self) -> bool;
    fn uninstall_requested(&mut self) -> bool;
    fn activate_incoming(&mut self) -> Result<(), String>;
    fn poll_runtime(&mut self) -> DaemonPollDisposition;
    fn cleanup_logs(&mut self);
}

fn run_daemon_iteration(actions: &mut impl DaemonIterationActions) -> DaemonIterationOutcome {
    let uninstall_frozen = actions.uninstall_frozen();
    let prepared_uninstall = actions.prepared_uninstall();
    let uninstall_requested = actions.uninstall_requested();
    // Flat native files cannot change while a dispatched helper consumes them.
    // Runtime collection and pipe service continue until all jobs are joined.
    let injection_jobs_active = actions.injection_jobs_active();
    // The courier shares this socket with OTA and must return Cluster removal
    // receipts while uninstall is pending. The transport rejects OTA in that state.
    actions.poll_ota(!injection_jobs_active);
    let product_recovery = if injection_jobs_active {
        ProductRecoveryDisposition::Continue
    } else {
        actions.poll_product_recovery()
    };
    if actions.active_generation_differs() {
        if let Err(error) = actions.adopt_active_generation() {
            log::err(
                "main",
                &format!("product generation cutover adoption failed: {error}"),
            );
        }
    }
    if !injection_jobs_active && !uninstall_frozen && !prepared_uninstall && !uninstall_requested {
        if let Err(error) = actions.activate_incoming() {
            log::err(
                "main",
                &format!("incoming generation activation failed: {error}"),
            );
        }
    }
    let runtime = actions.poll_runtime();
    let outcome = if product_recovery == ProductRecoveryDisposition::RebootRequired
        || runtime == DaemonPollDisposition::RebootForUpdate
    {
        DaemonIterationOutcome::RebootForUpdate
    } else if runtime == DaemonPollDisposition::SelfStopForNone {
        DaemonIterationOutcome::SelfStop
    } else {
        DaemonIterationOutcome::Continue
    };
    if outcome == DaemonIterationOutcome::Continue {
        actions.cleanup_logs();
    }
    outcome
}

fn run_daemon_iteration_then_wait<A: DaemonIterationActions>(
    actions: &mut A,
    interval: std::time::Duration,
    mut wait: impl FnMut(&mut A, std::time::Duration),
) -> DaemonIterationOutcome {
    let outcome = run_daemon_iteration(actions);
    if outcome == DaemonIterationOutcome::Continue {
        wait(actions, interval);
    }
    outcome
}

struct DeviceDaemonIteration<'a> {
    daemon_loop: &'a mut DaemonLoop,
    ota_transport: &'a mut Option<crate::ota_transport::OtaTransport>,
    product_recovery: &'a mut ProductRecoveryPoll,
    generation_store: &'a generation::GenerationStore,
}

impl DaemonIterationActions for DeviceDaemonIteration<'_> {
    fn injection_jobs_active(&mut self) -> bool {
        self.daemon_loop.injection_jobs_active()
    }

    fn poll_ota(&mut self, mutations_allowed: bool) {
        if let Some(transport) = self.ota_transport.as_mut() {
            transport.poll_once(mutations_allowed);
        }
    }

    fn poll_product_recovery(&mut self) -> ProductRecoveryDisposition {
        self.product_recovery.observe_discovery(
            std::path::Path::new(crate::config::ROOT_ZONE),
            std::time::Instant::now(),
        );
        let outcome = self
            .product_recovery
            .poll_at(std::time::Instant::now(), || {
                product_candidate::ProductCandidateStore::production().recover_product_activation()
            });
        if matches!(
            outcome,
            ProductRecoveryPollOutcome::Accepted | ProductRecoveryPollOutcome::RolledBack
        ) {
            match crate::installed_product::load_identity() {
                Ok(identity) => self.daemon_loop.set_product_identity(identity),
                Err(error) => log::err(
                    "main",
                    &format!("active product identity refresh failed: {error}"),
                ),
            }
        }
        match outcome {
            ProductRecoveryPollOutcome::RebootRequired => {
                ProductRecoveryDisposition::RebootRequired
            }
            _ => ProductRecoveryDisposition::Continue,
        }
    }

    fn active_generation_differs(&mut self) -> bool {
        self.generation_store.active_id().as_deref() != Some(self.daemon_loop.generation_id())
    }

    fn adopt_active_generation(&mut self) -> Result<(), String> {
        self.generation_store
            .active()
            .map(|fresh| self.daemon_loop.adopt_generation(fresh))
            .map_err(|error| error.to_string())
    }

    fn uninstall_frozen(&mut self) -> bool {
        self.daemon_loop.uninstall_frozen()
    }

    fn prepared_uninstall(&mut self) -> bool {
        uninstall::prepared_marker_valid()
    }

    fn uninstall_requested(&mut self) -> bool {
        uninstall::request_present()
    }

    fn activate_incoming(&mut self) -> Result<(), String> {
        self.generation_store
            .set_log_generation(self.daemon_loop.generation_id());
        if let Some(fresh) = activate_incoming_for_loop(self.generation_store) {
            self.daemon_loop.adopt_generation(fresh);
        }
        Ok(())
    }

    fn poll_runtime(&mut self) -> DaemonPollDisposition {
        self.daemon_loop.poll_once()
    }

    fn cleanup_logs(&mut self) {
        log::maybe_cleanup();
    }
}

/// Run the daemon loop on the main thread. Injected code outlives this
/// process, so shutdown only closes daemon-owned endpoints.
pub(super) fn run_daemon(
    generation: generation::VerifiedGeneration,
    uninstall_frozen: bool,
    product_identity: crate::installed_product::ProductIdentity,
) {
    let mut daemon_loop =
        DaemonLoop::new_with_product_identity(generation, uninstall_frozen, product_identity);
    daemon_loop.set_uninstall_frozen(uninstall_frozen);

    install_sigterm_handler();
    log::ok(
        "main",
        "daemon loop started (ptrace injection, /proc polling)",
    );
    let generation_store = generation::GenerationStore::production();
    let mut ota_transport = match crate::ota_transport::OtaTransport::bind() {
        Ok(transport) => Some(transport),
        Err(error) => {
            log::err("ota", &format!("OTA transport unavailable: {error}"));
            None
        }
    };
    let poll_interval = std::time::Duration::from_millis(50);
    let mut product_recovery = ProductRecoveryPoll::new(std::time::Instant::now());
    loop {
        crate::install_acceptance::poll();
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
            log::info(
                "main",
                "SIGTERM: waiting for injection cleanup (hooks left running)",
            );
            daemon_loop.stop_injections();
            daemon_loop.stop_package_execution();
            daemon_loop.fence_native_restart_endpoints();
            release_lock();
            break;
        }

        let outcome = run_daemon_iteration_then_wait(
            &mut DeviceDaemonIteration {
                daemon_loop: &mut daemon_loop,
                ota_transport: &mut ota_transport,
                product_recovery: &mut product_recovery,
                generation_store: &generation_store,
            },
            poll_interval,
            |_, delay| std::thread::sleep(delay),
        );

        if outcome == DaemonIterationOutcome::RebootForUpdate {
            log::ok(
                "main",
                "update drain complete; requesting one multimedia reboot",
            );
            daemon_loop.fence_native_restart_endpoints();
            if !request_reboot() {
                log::err(
                    "main",
                    "update reboot request exhausted; exiting for init-owned retry",
                );
                release_lock();
                std::process::exit(12);
            }
            // A successful property write should reboot immediately. Exit if
            // init has not yet acted so its restart policy re-enters the
            // journal-fenced update-reboot phase instead of sleeping forever.
            release_lock();
            std::process::exit(0);
        }

        if outcome == DaemonIterationOutcome::SelfStop {
            log::ok(
                "main",
                "startup=none committed: stopping the init-owned service (ctl.stop)",
            );
            if request_self_stop() {
                // init delivers SIGTERM as part of the stop; a bounded grace
                // covers a delayed signal before the clean exit below so the
                // exit can never race ahead of init's stop handling.
                let deadline = std::time::Instant::now() + SELF_STOP_SIGTERM_GRACE;
                while std::time::Instant::now() < deadline {
                    if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                log::ok("main", "startup=none: self-stop complete");
            } else {
                // The property service refused the stop: exit through init's
                // restart policy (the service is not oneshot) so the next
                // pass retries the committed stop from a fresh boot of the
                // daemon.
                log::err(
                    "main",
                    "ctl.stop voboost-inject failed; exiting for init-owned retry",
                );
            }
            release_lock();
            std::process::exit(0);
        }
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn bounded_reboot_request(
    mut request: impl FnMut() -> bool,
    mut backoff: impl FnMut(std::time::Duration),
) -> bool {
    let mut delay = std::time::Duration::from_millis(100);
    for attempt in 0..5 {
        if request() {
            return true;
        }
        if attempt != 4 {
            backoff(delay);
            delay = delay.saturating_mul(2);
        }
    }
    false
}

pub(super) fn request_reboot() -> bool {
    #[cfg(target_os = "android")]
    {
        set_android_property("ctl.start", "voboost-reboot")
    }
    #[cfg(not(target_os = "android"))]
    {
        log::err("main", "update reboot handoff requires Android");
        false
    }
}

/// Bounded wait for init's SIGTERM after a successful `ctl.stop` request.
/// Covers a delayed property delivery so the explicit clean exit can never
/// race ahead of init marking the service stopped.
const SELF_STOP_SIGTERM_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Stop this daemon's own init service through the property service. The
/// service is deliberately not oneshot (init-owned crash recovery), so a plain
/// exit would be restarted; `ctl.stop` makes init own the stop: it delivers
/// SIGTERM and never restarts a service it stopped. The uninstall one-shot
/// uses the same rail (`ctl.stop voboost-inject`).
pub(super) fn request_self_stop() -> bool {
    #[cfg(target_os = "android")]
    {
        set_android_property("ctl.stop", "voboost-inject")
    }
    #[cfg(not(target_os = "android"))]
    {
        log::err("main", "startup=none self-stop requires Android");
        false
    }
}

pub(super) fn perform_reboot() -> bool {
    #[cfg(target_os = "android")]
    {
        bounded_reboot_request(
            || set_android_property("sys.powerctl", "reboot"),
            std::thread::sleep,
        )
    }
    #[cfg(not(target_os = "android"))]
    {
        log::err("main", "update multimedia reboot requires Android");
        false
    }
}

#[cfg(target_os = "android")]
fn set_android_property(name: &str, value: &str) -> bool {
    use std::ffi::CString;
    unsafe extern "C" {
        fn __system_property_set(
            name: *const libc::c_char,
            value: *const libc::c_char,
        ) -> libc::c_int;
    }
    let (Ok(name), Ok(value)) = (CString::new(name), CString::new(value)) else {
        return false;
    };
    unsafe { __system_property_set(name.as_ptr(), value.as_ptr()) == 0 }
}

fn wait_uninstall_retry(
    mut shutting_down: impl FnMut() -> bool,
    mut now: impl FnMut() -> std::time::Instant,
    mut wait: impl FnMut(std::time::Duration),
) -> bool {
    let deadline = now() + std::time::Duration::from_secs(30);
    loop {
        if shutting_down() {
            return false;
        }
        let remaining = deadline.saturating_duration_since(now());
        if remaining.is_zero() {
            return true;
        }
        wait(remaining.min(std::time::Duration::from_millis(50)));
    }
}

pub(super) fn run_uninstall_frozen_loop() {
    log::info(
        "main",
        "uninstall freeze active; update, activation, and injection work disabled",
    );
    install_sigterm_handler();
    let generation_store = generation::GenerationStore::production();
    loop {
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
            release_lock();
            return;
        }
        if !wait_uninstall_retry(
            || SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed),
            std::time::Instant::now,
            std::thread::sleep,
        ) {
            release_lock();
            return;
        }
        if uninstall::prepared_marker_valid() {
            if let Err(error) = uninstall::retry_committed_prepared(&generation_store) {
                log::err(
                    "main",
                    &format!("bounded prepared uninstall freeze/trigger retry failed: {error}"),
                );
            }
        }
    }
}

static SHUTTING_DOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn handle_sigterm(_sig: i32) {
    SHUTTING_DOWN.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn install_sigterm_handler() {
    unsafe {
        let handler: extern "C" fn(i32) = handle_sigterm;
        libc::signal(libc::SIGTERM, handler as usize as libc::sighandler_t);
    }
}

const DEGRADED_FAST_INTERVAL_SECS: u64 = 30;
const DEGRADED_SLOW_INTERVAL_SECS: u64 = 600;
const DEGRADED_FAST_TRIES: u32 = 120;

pub(super) fn run_product_recovery_degraded_loop() {
    log::info(
        "main",
        "running in product recovery DEGRADED mode (product-only polling armed)",
    );
    install_sigterm_handler();
    let store = product_candidate::ProductCandidateStore::production();
    let mut poll = ProductRecoveryPoll::after_deferred_attempt(std::time::Instant::now());
    loop {
        if SHUTTING_DOWN.load(std::sync::atomic::Ordering::Relaxed) {
            release_lock();
            return;
        }
        match run_product_degraded_iteration(
            &mut poll,
            std::time::Instant::now(),
            || store.recover_product_activation(),
            request_reboot,
        ) {
            ProductDegradedIterationOutcome::Wait(delay) => std::thread::sleep(delay),
            ProductDegradedIterationOutcome::RestartNormal(terminal) => {
                log::info(
                    "main",
                    &format!(
                        "product recovery DEGRADED terminal {terminal:?}; restarting through init"
                    ),
                );
                write_degraded_status();
                release_lock();
                std::process::exit(0);
            }
            ProductDegradedIterationOutcome::RebootHandedOff => {
                release_lock();
                std::process::exit(0);
            }
        }
    }
}

pub(super) fn run_degraded_loop() {
    log::info(
        "main",
        "running in DEGRADED mode (observe-only, auto-recovery armed)",
    );
    let store = generation::GenerationStore::production();
    let mut fast_tries = 0u32;
    loop {
        if let Some(generation) = activate_incoming_for_loop(&store) {
            log::ok(
                "main",
                &format!(
                    "DEGRADED recovery: incoming generation {} activated; restarting",
                    generation.id
                ),
            );
            write_degraded_status();
            release_lock();
            std::process::exit(0);
        }
        if let Ok(generation) = store.active() {
            log::ok(
                "main",
                &format!(
                    "DEGRADED recovery: active generation {} now valid; restarting",
                    generation.id
                ),
            );
            write_degraded_status();
            release_lock();
            std::process::exit(0);
        }
        let interval = if store.install_generation_waiting() {
            1
        } else if fast_tries < DEGRADED_FAST_TRIES {
            fast_tries += 1;
            DEGRADED_FAST_INTERVAL_SECS
        } else {
            DEGRADED_SLOW_INTERVAL_SECS
        };
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

#[cfg(test)]
mod reboot_tests {
    use super::*;

    struct ScriptedIteration {
        injections_active: bool,
        changed: bool,
        frozen: bool,
        prepared: bool,
        requested: bool,
        product_recovery: ProductRecoveryDisposition,
        disposition: DaemonPollDisposition,
        events: Vec<&'static str>,
    }

    impl DaemonIterationActions for ScriptedIteration {
        fn injection_jobs_active(&mut self) -> bool {
            self.injections_active
        }
        fn poll_ota(&mut self, mutations_allowed: bool) {
            assert_eq!(mutations_allowed, !self.injections_active);
            self.events.push("ota");
        }
        fn poll_product_recovery(&mut self) -> ProductRecoveryDisposition {
            self.events.push("product-recovery");
            self.product_recovery
        }
        fn active_generation_differs(&mut self) -> bool {
            self.events.push("compare-generation");
            self.changed
        }
        fn adopt_active_generation(&mut self) -> Result<(), String> {
            self.events.push("adopt-generation");
            Ok(())
        }
        fn uninstall_frozen(&mut self) -> bool {
            self.frozen
        }
        fn prepared_uninstall(&mut self) -> bool {
            self.prepared
        }
        fn uninstall_requested(&mut self) -> bool {
            self.requested
        }
        fn activate_incoming(&mut self) -> Result<(), String> {
            self.events.push("activate-incoming");
            Ok(())
        }
        fn poll_runtime(&mut self) -> DaemonPollDisposition {
            self.events.push("runtime");
            self.disposition
        }
        fn cleanup_logs(&mut self) {
            self.events.push("cleanup-logs");
        }
    }

    #[test]
    fn active_injection_jobs_fence_native_product_mutations_but_keep_runtime_service() {
        let mut actions = ScriptedIteration {
            injections_active: true,
            changed: false,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::Continue,
            disposition: DaemonPollDisposition::Continue,
            events: Vec::new(),
        };
        assert_eq!(
            run_daemon_iteration(&mut actions),
            DaemonIterationOutcome::Continue
        );
        assert!(actions.events.contains(&"ota"));
        assert!(!actions.events.contains(&"activate-incoming"));
        assert!(!actions.events.contains(&"product-recovery"));
        assert!(actions.events.contains(&"runtime"));
        actions.events.clear();
        actions.injections_active = false;
        assert_eq!(
            run_daemon_iteration(&mut actions),
            DaemonIterationOutcome::Continue
        );
        assert_eq!(&actions.events[..2], ["ota", "product-recovery"]);
    }

    #[test]
    fn production_daemon_iteration_adopts_before_activation_and_runtime_poll() {
        let mut actions = ScriptedIteration {
            injections_active: false,
            changed: true,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::Continue,
            disposition: DaemonPollDisposition::Continue,
            events: Vec::new(),
        };
        assert_eq!(
            run_daemon_iteration(&mut actions),
            DaemonIterationOutcome::Continue
        );
        assert_eq!(
            actions.events,
            [
                "ota",
                "product-recovery",
                "compare-generation",
                "adopt-generation",
                "activate-incoming",
                "runtime",
                "cleanup-logs",
            ]
        );
    }

    #[test]
    fn production_daemon_iteration_excludes_activation_for_every_uninstall_authority() {
        for (frozen, prepared, requested) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (true, true, true),
        ] {
            let mut actions = ScriptedIteration {
                injections_active: false,
                changed: false,
                frozen,
                prepared,
                requested,
                product_recovery: ProductRecoveryDisposition::Continue,
                disposition: DaemonPollDisposition::Continue,
                events: Vec::new(),
            };
            run_daemon_iteration(&mut actions);
            assert!(actions.events.contains(&"ota"));
            assert!(!actions.events.contains(&"activate-incoming"));
            assert!(actions.events.contains(&"runtime"));
        }
    }

    #[test]
    fn production_daemon_iteration_returns_reboot_without_post_poll_cleanup() {
        let mut actions = ScriptedIteration {
            injections_active: false,
            changed: false,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::Continue,
            disposition: DaemonPollDisposition::RebootForUpdate,
            events: Vec::new(),
        };
        assert_eq!(
            run_daemon_iteration(&mut actions),
            DaemonIterationOutcome::RebootForUpdate
        );
        assert_eq!(actions.events.last(), Some(&"runtime"));
        assert!(!actions.events.contains(&"cleanup-logs"));
    }

    #[test]
    fn committed_none_maps_to_a_terminal_self_stop_without_cleanup_or_wait() {
        let mut actions = ScriptedIteration {
            injections_active: false,
            changed: false,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::Continue,
            disposition: DaemonPollDisposition::SelfStopForNone,
            events: Vec::new(),
        };
        let waited = std::cell::Cell::new(false);
        assert_eq!(
            run_daemon_iteration_then_wait(&mut actions, std::time::Duration::from_millis(1), {
                |_, _| waited.set(true)
            }),
            DaemonIterationOutcome::SelfStop
        );
        assert_eq!(actions.events.last(), Some(&"runtime"));
        assert!(!actions.events.contains(&"cleanup-logs"));
        // A terminal stop never waits for the next poll interval.
        assert!(!waited.get());
    }

    #[test]
    fn pending_reboot_outranks_the_committed_none_self_stop() {
        let mut actions = ScriptedIteration {
            injections_active: false,
            changed: false,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::RebootRequired,
            disposition: DaemonPollDisposition::SelfStopForNone,
            events: Vec::new(),
        };
        assert_eq!(
            run_daemon_iteration(&mut actions),
            DaemonIterationOutcome::RebootForUpdate
        );
    }

    #[test]
    fn production_daemon_polls_before_its_first_wait() {
        let mut actions = ScriptedIteration {
            injections_active: false,
            changed: false,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::Continue,
            disposition: DaemonPollDisposition::Continue,
            events: Vec::new(),
        };
        let interval = std::time::Duration::from_millis(500);

        assert_eq!(
            run_daemon_iteration_then_wait(&mut actions, interval, |actions, delay| {
                assert_eq!(delay, interval);
                assert_eq!(actions.events.last(), Some(&"cleanup-logs"));
                actions.events.push("wait");
            }),
            DaemonIterationOutcome::Continue
        );
        assert_eq!(actions.events.last(), Some(&"wait"));
        assert_eq!(actions.events[actions.events.len() - 2], "cleanup-logs");
        assert!(
            actions
                .events
                .iter()
                .position(|event| *event == "runtime")
                .unwrap()
                < actions
                    .events
                    .iter()
                    .position(|event| *event == "wait")
                    .unwrap()
        );
    }

    #[test]
    fn product_reboot_keeps_ota_and_runtime_available_until_handoff() {
        let mut actions = ScriptedIteration {
            injections_active: false,
            changed: false,
            frozen: false,
            prepared: false,
            requested: false,
            product_recovery: ProductRecoveryDisposition::RebootRequired,
            disposition: DaemonPollDisposition::Continue,
            events: Vec::new(),
        };
        assert_eq!(
            run_daemon_iteration(&mut actions),
            DaemonIterationOutcome::RebootForUpdate
        );
        assert_eq!(actions.events.first(), Some(&"ota"));
        assert!(actions.events.contains(&"product-recovery"));
        assert_eq!(actions.events.last(), Some(&"runtime"));
    }

    #[test]
    fn product_recovery_poll_uses_bounded_backoff_and_accepts_late_completion() {
        let mut now = std::time::Instant::now();
        let mut poll = ProductRecoveryPoll::new(now);
        let mut calls = 0;
        let expected = [500_u64, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000];
        for delay_ms in expected {
            assert_eq!(
                poll.poll_at(now, || {
                    calls += 1;
                    Ok(Some(Admission::Pending))
                }),
                ProductRecoveryPollOutcome::Deferred
            );
            assert_eq!(
                poll.next_poll.duration_since(now),
                std::time::Duration::from_millis(delay_ms)
            );
            assert_eq!(
                poll.poll_at(
                    poll.next_poll - std::time::Duration::from_millis(1),
                    || panic!("recovery ran before its backoff elapsed")
                ),
                ProductRecoveryPollOutcome::Deferred
            );
            now = poll.next_poll;
        }
        assert_eq!(calls, expected.len());
        assert_eq!(
            poll.poll_at(now, || {
                calls += 1;
                Ok(Some(Admission::Accepted))
            }),
            ProductRecoveryPollOutcome::Accepted
        );
        assert_eq!(calls, expected.len() + 1);
        assert_eq!(poll.backoff, PRODUCT_RECOVERY_INITIAL_BACKOFF);
    }

    #[test]
    fn product_recovery_poll_retries_receipt_error_after_backoff() {
        let now = std::time::Instant::now();
        let mut poll = ProductRecoveryPoll::new(now);
        assert_eq!(
            poll.poll_at(now, || Err("receipt identity differs".into())),
            ProductRecoveryPollOutcome::Deferred
        );
        let retry = poll.next_poll;
        assert_eq!(
            poll.poll_at(retry, || Ok(Some(Admission::Accepted))),
            ProductRecoveryPollOutcome::Accepted
        );
        assert_eq!(poll.backoff, PRODUCT_RECOVERY_INITIAL_BACKOFF);
    }

    #[test]
    fn idle_recovery_scans_are_bounded_but_new_operation_wakes_discovery() {
        let now = std::time::Instant::now();
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let mut poll = ProductRecoveryPoll::new(now);
        poll.observe_discovery(root.path(), now);
        assert_eq!(
            poll.poll_at(now, || Ok(None)),
            ProductRecoveryPollOutcome::NoWork
        );
        assert_eq!(poll.next_poll, now + PRODUCT_RECOVERY_IDLE_INTERVAL);
        std::fs::write(root.path().join("operation.json"), b"new operation").unwrap();
        let changed = now + std::time::Duration::from_millis(50);
        poll.observe_discovery(root.path(), changed);
        assert_eq!(poll.next_poll, changed);
    }

    #[test]
    fn startup_receipt_error_selects_product_only_degraded_recovery() {
        let recovery = Err("product helper receipt identity differs".into());
        assert_eq!(
            startup_product_recovery_disposition(&recovery),
            StartupProductRecoveryDisposition::ProductDegraded
        );
        assert_eq!(
            startup_product_recovery_disposition(&Ok(Some(Admission::RebootRequired))),
            StartupProductRecoveryDisposition::RebootRequired
        );
        assert_eq!(
            startup_product_recovery_disposition(&Ok(Some(Admission::Accepted))),
            StartupProductRecoveryDisposition::Continue
        );
    }

    #[test]
    fn degraded_product_recovery_retries_with_capped_backoff() {
        let mut now = std::time::Instant::now();
        let mut poll = ProductRecoveryPoll::after_deferred_attempt(now);
        let mut recoveries = 0;
        for (index, delay_ms) in [
            500_u64, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000,
        ]
        .into_iter()
        .enumerate()
        {
            let outcome = run_product_degraded_iteration(
                &mut poll,
                now,
                || {
                    recoveries += 1;
                    Err("malformed product helper receipt".into())
                },
                || panic!("invalid receipt cannot request a reboot"),
            );
            let delay = std::time::Duration::from_millis(delay_ms);
            assert_eq!(outcome, ProductDegradedIterationOutcome::Wait(delay));
            assert_eq!(recoveries, index);
            now += delay;
        }
        assert_eq!(recoveries, 8);
    }

    #[test]
    fn corrected_receipt_selects_forward_rollback_and_reboot_handoffs() {
        for (admission, expected) in [
            (
                Admission::Accepted,
                ProductDegradedIterationOutcome::RestartNormal(ProductRecoveryTerminal::Accepted),
            ),
            (
                Admission::ActivationFailed,
                ProductDegradedIterationOutcome::RestartNormal(ProductRecoveryTerminal::RolledBack),
            ),
        ] {
            let now = std::time::Instant::now();
            let mut poll = ProductRecoveryPoll::after_deferred_attempt(now);
            assert_eq!(
                run_product_degraded_iteration(
                    &mut poll,
                    now,
                    || panic!("startup error must be followed by a 500 ms delay"),
                    || panic!("wrong receipt cannot request a reboot"),
                ),
                ProductDegradedIterationOutcome::Wait(PRODUCT_RECOVERY_INITIAL_BACKOFF)
            );
            assert_eq!(
                run_product_degraded_iteration(
                    &mut poll,
                    now + PRODUCT_RECOVERY_INITIAL_BACKOFF,
                    || Ok(Some(admission)),
                    || panic!("terminal non-reboot recovery cannot request a reboot"),
                ),
                expected
            );
        }

        let now = std::time::Instant::now();
        let mut poll = ProductRecoveryPoll::new(now);
        let mut reboot_requests = 0;
        assert_eq!(
            run_product_degraded_iteration(
                &mut poll,
                now,
                || Ok(Some(Admission::RebootRequired)),
                || {
                    reboot_requests += 1;
                    true
                },
            ),
            ProductDegradedIterationOutcome::RebootHandedOff
        );
        assert_eq!(reboot_requests, 1);
    }

    #[test]
    fn failed_reboot_handoff_retries_with_the_same_capped_backoff() {
        let mut now = std::time::Instant::now();
        let mut poll = ProductRecoveryPoll::after_deferred_attempt(now);
        let mut requests = 0;
        for (index, delay_ms) in [
            500_u64, 1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000,
        ]
        .into_iter()
        .enumerate()
        {
            let delay = std::time::Duration::from_millis(delay_ms);
            assert_eq!(
                run_product_degraded_iteration(
                    &mut poll,
                    now,
                    || Ok(Some(Admission::RebootRequired)),
                    || {
                        requests += 1;
                        false
                    },
                ),
                ProductDegradedIterationOutcome::Wait(delay)
            );
            assert_eq!(requests, index);
            now += delay;
        }
        assert_eq!(requests, 8);
    }

    #[test]
    fn persistent_invalid_receipt_has_no_generation_runtime_or_network_path() {
        let mut now = std::time::Instant::now();
        let mut poll = ProductRecoveryPoll::after_deferred_attempt(now);
        let mut recoveries = 0;
        assert_eq!(
            run_product_degraded_iteration(
                &mut poll,
                now,
                || {
                    recoveries += 1;
                    Err("receipt remains invalid".into())
                },
                || panic!("invalid receipt cannot request a reboot"),
            ),
            ProductDegradedIterationOutcome::Wait(PRODUCT_RECOVERY_INITIAL_BACKOFF)
        );
        assert_eq!(recoveries, 0);
        now += PRODUCT_RECOVERY_INITIAL_BACKOFF;
        assert_eq!(
            run_product_degraded_iteration(
                &mut poll,
                now,
                || {
                    recoveries += 1;
                    Err("receipt remains invalid".into())
                },
                || panic!("invalid receipt cannot request a reboot"),
            ),
            ProductDegradedIterationOutcome::Wait(std::time::Duration::from_secs(1))
        );
        assert_eq!(recoveries, 1);

        let source = include_str!("lifecycle.rs");
        let product_loop = source
            .split("pub(super) fn run_product_recovery_degraded_loop()")
            .nth(1)
            .unwrap()
            .split("pub(super) fn run_degraded_loop()")
            .next()
            .unwrap();
        for forbidden in [
            "GenerationStore",
            "activate_incoming",
            "OtaTransport",
            "DaemonLoop",
            ".poll_once()",
        ] {
            assert!(
                !product_loop.contains(forbidden),
                "product degraded loop contains forbidden work: {forbidden}"
            );
        }
    }

    #[test]
    fn reboot_request_is_bounded_and_stops_after_success() {
        let mut attempts = 0;
        let mut delays = Vec::new();
        assert!(bounded_reboot_request(
            || {
                attempts += 1;
                attempts == 3
            },
            |delay| delays.push(delay),
        ));
        assert_eq!(attempts, 3);
        assert_eq!(delays.len(), 2);

        attempts = 0;
        delays.clear();
        assert!(!bounded_reboot_request(
            || {
                attempts += 1;
                false
            },
            |delay| delays.push(delay),
        ));
        assert_eq!(attempts, 5);
        assert_eq!(delays.len(), 4);
    }

    #[test]
    fn reboot_handoff_has_no_external_executable_path() {
        let source = include_str!("lifecycle.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("Command::new"));
        assert!(!production.contains("/system/bin/setprop"));
        assert!(production.contains("__system_property_set"));
    }

    #[test]
    fn reboot_service_and_argument_are_exact() {
        let init = include_str!("../../config/voboost.rc");
        assert!(init.lines().any(|line| {
            line == "service voboost-reboot /data/voboost/voboost-inject --reboot"
        }));
        assert!(!init.contains("internal-update-reboot"));

        let main = include_str!("main.rs");
        assert!(main.contains("[\"--reboot\"]"));
        assert!(!main.contains("internal-update-reboot"));
    }
}

#[cfg(test)]
mod uninstall_wait_tests {
    use super::wait_uninstall_retry;
    use std::cell::Cell;
    use std::time::Duration;

    #[test]
    fn frozen_uninstall_stop_interrupts_retry_wait() {
        let elapsed = Cell::new(Duration::ZERO);
        let start = std::time::Instant::now();
        assert!(!wait_uninstall_retry(
            || elapsed.get() >= Duration::from_millis(50),
            || start + elapsed.get(),
            |delay| elapsed.set(elapsed.get() + delay),
        ));
        assert!(elapsed.get() <= Duration::from_millis(100));
    }

    #[test]
    fn frozen_uninstall_retry_keeps_full_period() {
        let elapsed = Cell::new(Duration::ZERO);
        let start = std::time::Instant::now();
        assert!(wait_uninstall_retry(
            || false,
            || start + elapsed.get(),
            |delay| elapsed.set(elapsed.get() + delay),
        ));
        assert_eq!(elapsed.get(), Duration::from_secs(30));
    }
}
