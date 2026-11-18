//! One bounded queue; kernel I/O never runs on the storage owner's poll thread.
use super::Admission;
use crate::native_api::{Command as SemanticCommand, Failure, Lease, Transmission, Wait};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::sync::Arc;

pub(super) struct Freshness {
    pub issued: super::clock::Stamp,
    pub feedback: Vec<super::clock::Stamp>,
    pub inputs: Option<super::clock::Stamp>,
}
impl Freshness {
    fn current(&self) -> bool {
        self.current_at(super::clock::Stamp::now())
    }
    fn current_at(&self, now: super::clock::Stamp) -> bool {
        !self.issued.interrupted(now)
            && self.issued.fresh_at(now, std::time::Duration::from_secs(2))
            && self
                .feedback
                .iter()
                .all(|sample| sample.fresh_at(now, std::time::Duration::from_secs(2)))
            && self
                .inputs
                .is_none_or(|sample| sample.fresh_at(now, std::time::Duration::from_secs(1)))
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Operation {
    source: &'static str,
    lease: Lease,
    semantic: SemanticCommand,
    frame: [u8; 10],
}
struct Request {
    command: Operation,
    admission: Admission,
    inputs: Arc<std::sync::atomic::AtomicU64>,
    input_revision: u64,
    cancelled: Arc<AtomicBool>,
    freshness: Freshness,
}
impl Request {
    fn current(&self) -> bool {
        self.admission.current()
            && self.inputs.load(Ordering::Acquire) == self.input_revision
            && !self.cancelled.load(Ordering::Acquire)
            && self.freshness.current()
    }
}
enum Reply {
    Ready(io::Result<()>),
    Completed {
        result: Result<Transmission, Failure>,
        reason: Option<(String, bool)>,
        service_seen: bool,
    },
}

pub(super) struct Sender {
    requests: Option<SyncSender<Request>>,
    replies: Receiver<Reply>,
    worker: std::thread::JoinHandle<()>,
    ready: bool,
    command: Option<Operation>,
    result: Option<Result<Transmission, Failure>>,
    cancelled: Option<Arc<AtomicBool>>,
    withdrawn: bool,
    failed: bool,
    unknown: std::collections::BTreeMap<&'static str, u64>,
    error: Option<(String, bool)>,
    late: bool,
    retry_at: std::time::Instant,
}
impl Sender {
    pub(super) fn start() -> io::Result<Self> {
        Self::spawn(Device::open)
    }
    fn spawn<D: Driver>(open: impl FnOnce() -> io::Result<D> + Send + 'static) -> io::Result<Self> {
        let (requests, receive) = mpsc::sync_channel::<Request>(1);
        let (send, replies) = mpsc::sync_channel(2);
        let worker = std::thread::Builder::new()
            .name("voboost-can".into())
            .spawn(move || {
                let mut driver = match open() {
                    Ok(driver) => driver,
                    Err(error) => {
                        let _ = send.send(Reply::Ready(Err(error)));
                        return;
                    }
                };
                if send.send(Reply::Ready(Ok(()))).is_err() {
                    return;
                }
                while let Ok(request) = receive.recv() {
                    let mut reason = None;
                    let mut service_seen = false;
                    let result = if !request.current() {
                        Err(Failure::Cancelled)
                    } else {
                        match driver.bootstrap_ready() {
                            Ok(false) => {
                                service_seen = true;
                                Err(Failure::Cancelled)
                            }
                            Err(error) => {
                                let expected = super::inputs::transient(&error);
                                reason =
                                    Some((format!("OEM CAN service discovery: {error}"), expected));
                                Ok(Transmission::Waiting(Wait::Inputs))
                            }
                            Ok(true) if !request.current() => Err(Failure::Cancelled),
                            Ok(true) => driver
                                .send(request.command.frame)
                                .map(|()| Transmission::Accepted)
                                .map_err(|error| {
                                    reason = Some((error.to_string(), false));
                                    Failure::TransportUnavailable
                                }),
                        }
                    };
                    if send
                        .send(Reply::Completed {
                            result,
                            reason,
                            service_seen,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(requests),
            replies,
            worker,
            ready: false,
            command: None,
            result: None,
            cancelled: None,
            withdrawn: false,
            failed: false,
            unknown: Default::default(),
            error: None,
            late: false,
            retry_at: std::time::Instant::now(),
        })
    }
    pub(super) fn poll(&mut self) -> bool {
        let mut drained = false;
        loop {
            match self.replies.try_recv() {
                Ok(Reply::Ready(result)) => {
                    self.ready = result.is_ok();
                    self.failed = result.is_err();
                    self.error = result.err().map(|error| {
                        let expected = super::inputs::transient(&error);
                        (error.to_string(), expected)
                    });
                }
                Ok(Reply::Completed {
                    result,
                    reason,
                    service_seen,
                }) => {
                    if result == Ok(Transmission::Waiting(Wait::Inputs)) {
                        self.retry_at = std::time::Instant::now()
                            + if reason.as_ref().is_some_and(|(_, expected)| *expected) {
                                std::time::Duration::from_millis(250)
                            } else {
                                std::time::Duration::from_secs(1)
                            };
                    }
                    self.error = reason;
                    self.late |= service_seen;
                    if result == Err(Failure::TransportUnavailable) {
                        if let Some(command) = &self.command {
                            self.unknown.insert(command.source, command.lease.revision);
                        }
                    }
                    if self.command.is_some() && self.result.is_none() {
                        self.result = Some(result);
                        drained = result != Ok(Transmission::Waiting(Wait::Inputs));
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if self.requests.is_some() {
                        self.failed = true;
                        self.ready = false;
                    }
                    break;
                }
            }
        }
        drained
    }
    pub(super) fn error(&self) -> Option<&(String, bool)> {
        self.error.as_ref()
    }
    pub(super) fn ready(&self) -> bool {
        self.ready && !self.failed && self.requests.is_some()
    }
    pub(super) fn late_required(&self) -> bool {
        self.late
    }
    pub(super) fn in_flight(&self) -> bool {
        self.command.is_some() && self.result.is_none()
    }
    pub(super) fn owns(&self, source: &str, lease: Lease) -> bool {
        self.command.as_ref().is_some_and(|command| {
            command.source == source && command.lease == lease && !self.withdrawn
        })
    }
    pub(super) fn terminal(&self) -> bool {
        self.worker.is_finished() && self.command.is_none() && self.unknown.is_empty()
    }
    pub(super) fn uncertain(&self, source: &str, lease: Lease) -> bool {
        self.unknown.get(source) == Some(&lease.revision)
    }
    pub(super) fn retire(&mut self) {
        self.requests = None;
        if let Some(cancelled) = &self.cancelled {
            cancelled.store(true, Ordering::Release);
        }
    }
    pub(super) fn withdraw(&mut self, source: &str, lease: Lease, completed: bool) {
        if completed && !self.in_flight() && self.unknown.get(source) == Some(&lease.revision) {
            self.unknown.remove(source);
        }
        if self
            .command
            .as_ref()
            .is_some_and(|command| command.source == source && command.lease == lease)
        {
            if self.result.is_some() {
                if completed {
                    self.command = None;
                    self.result = None;
                    self.cancelled = None;
                    self.withdrawn = false;
                }
                return;
            }
            self.withdrawn = true;
            if let Some(cancelled) = &self.cancelled {
                cancelled.store(true, Ordering::Release);
            }
        }
    }
    pub(super) fn finish(
        &mut self,
        source: &str,
        lease: Lease,
        semantic: SemanticCommand,
    ) -> Option<Result<Transmission, Failure>> {
        if !self.command.as_ref().is_some_and(|command| {
            command.source == source && command.lease == lease && command.semantic == semantic
        }) {
            return None;
        }
        let result = self.result.take()?;
        self.command = None;
        self.cancelled = None;
        if std::mem::take(&mut self.withdrawn) {
            return None;
        }
        Some(result)
    }
    pub(super) fn send(
        &mut self,
        source: &'static str,
        admission: Admission,
        semantic: SemanticCommand,
        frame: [u8; 10],
        inputs: Arc<std::sync::atomic::AtomicU64>,
        freshness: Freshness,
    ) -> Result<Transmission, Failure> {
        if !admission.current() {
            return Err(Failure::Cancelled);
        }
        if let Some(result) = self.finish(source, admission.lease, semantic) {
            return result;
        }
        if std::time::Instant::now() < self.retry_at {
            return Ok(Transmission::Waiting(Wait::Inputs));
        }
        if self.in_flight() {
            return Ok(if self.owns(source, admission.lease) {
                Transmission::Pending
            } else {
                Transmission::Waiting(Wait::Transport)
            });
        }
        if self.uncertain(source, admission.lease) {
            return Err(Failure::TransportUnavailable);
        }
        self.command = None;
        self.result = None;
        self.cancelled = None;
        self.withdrawn = false;
        if !self.ready() {
            return Ok(Transmission::Waiting(Wait::Transport));
        }
        let command = Operation {
            source,
            lease: admission.lease,
            semantic,
            frame,
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        self.requests
            .as_ref()
            .ok_or(Failure::Cancelled)?
            .try_send(Request {
                command: command.clone(),
                admission,
                input_revision: inputs.load(Ordering::Acquire),
                inputs,
                cancelled: cancelled.clone(),
                freshness,
            })
            .map_err(|_| Failure::TransportUnavailable)?;
        self.cancelled = Some(cancelled);
        self.command = Some(command);
        Ok(Transmission::Pending)
    }
}
trait Driver: Send + 'static {
    fn bootstrap_ready(&self) -> io::Result<bool> {
        Ok(true)
    }
    fn send(&mut self, frame: [u8; 10]) -> io::Result<()>;
}
struct Device(std::fs::File);
impl Device {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn open() -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/cis_can")?;
        if !file.metadata()?.file_type().is_char_device() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OEM CAN character device unavailable",
            ));
        }
        Ok(Self(file))
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    fn open() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OEM CAN requires Linux",
        ))
    }
}
impl Driver for Device {
    fn bootstrap_ready(&self) -> io::Result<bool> {
        super::inputs::bootstrap_ready()
    }
    fn send(&mut self, mut frame: [u8; 10]) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let result = unsafe { libc::ioctl(self.0.as_raw_fd(), 1, frame.as_mut_ptr()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::time::{Duration, Instant};

    struct Blocked {
        entered: SyncSender<[u8; 10]>,
        release: Receiver<()>,
    }
    impl Driver for Blocked {
        fn send(&mut self, frame: [u8; 10]) -> io::Result<()> {
            self.entered.send(frame).unwrap();
            self.release.recv().unwrap();
            Ok(())
        }
    }
    struct Count(Arc<AtomicU64>);
    impl Driver for Count {
        fn send(&mut self, _: [u8; 10]) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    fn command(value: i32) -> SemanticCommand {
        SemanticCommand {
            state: "fixture",
            value,
        }
    }
    fn admission(revision: u64) -> Admission {
        Admission {
            lease: Lease { revision },
            fence: Arc::new(AtomicU64::new(revision)),
        }
    }
    fn fresh() -> Freshness {
        Freshness {
            issued: super::super::clock::Stamp::now(),
            feedback: Vec::new(),
            inputs: None,
        }
    }
    fn until(sender: &mut Sender, done: impl Fn(&Sender) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done(sender) {
            assert!(
                Instant::now() < deadline,
                "worker did not reach the expected state"
            );
            sender.poll();
            std::thread::yield_now();
        }
    }
    fn blocked() -> (Sender, Receiver<[u8; 10]>, SyncSender<()>) {
        let (entered, frames) = mpsc::sync_channel(2);
        let (release, released) = mpsc::sync_channel(2);
        let mut sender = Sender::spawn(move || {
            Ok(Blocked {
                entered,
                release: released,
            })
        })
        .unwrap();
        until(&mut sender, Sender::ready);
        (sender, frames, release)
    }
    #[test]
    fn unavailable_bootstrap_waits_then_recovers_without_replaying_old_work() {
        struct Preparing {
            available: Arc<AtomicBool>,
            calls: Arc<AtomicU64>,
        }
        impl Driver for Preparing {
            fn bootstrap_ready(&self) -> io::Result<bool> {
                if self.available.load(Ordering::Acquire) {
                    Ok(true)
                } else {
                    Err(io::ErrorKind::WouldBlock.into())
                }
            }
            fn send(&mut self, _: [u8; 10]) -> io::Result<()> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }
        let available = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicU64::new(0));
        let driver = Preparing {
            available: available.clone(),
            calls: calls.clone(),
        };
        let mut sender = Sender::spawn(move || Ok(driver)).unwrap();
        until(&mut sender, Sender::ready);
        let owner = admission(1);
        for disabled in [false, true] {
            sender
                .send(
                    "fixture",
                    owner.clone(),
                    command(1),
                    [1; 10],
                    owner.fence.clone(),
                    fresh(),
                )
                .unwrap();
            until(&mut sender, |sender| !sender.in_flight());
            assert_eq!(
                sender.finish("fixture", owner.lease, command(1)),
                Some(Ok(Transmission::Waiting(Wait::Inputs)))
            );
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            assert_eq!(
                sender.send(
                    "fixture",
                    owner.clone(),
                    command(1),
                    [1; 10],
                    owner.fence.clone(),
                    fresh()
                ),
                Ok(Transmission::Waiting(Wait::Inputs))
            );
            if disabled {
                owner.fence.store(0, Ordering::Release);
                available.store(true, Ordering::Release);
                sender.retry_at = Instant::now();
                assert_eq!(
                    sender.send(
                        "fixture",
                        owner.clone(),
                        command(1),
                        [1; 10],
                        owner.fence.clone(),
                        fresh()
                    ),
                    Err(Failure::Cancelled)
                );
                assert_eq!(calls.load(Ordering::Relaxed), 0);
            } else {
                sender.retry_at = Instant::now();
            }
        }
        owner.fence.store(1, Ordering::Release);
        assert_eq!(
            sender.send(
                "fixture",
                owner.clone(),
                command(2),
                [2; 10],
                owner.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Pending)
        );
        until(&mut sender, |sender| !sender.in_flight());
        assert_eq!(
            sender.finish("fixture", owner.lease, command(2)),
            Some(Ok(Transmission::Accepted))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn denied_bootstrap_keeps_waiting_without_dispatch_or_discarding_feedback() {
        struct Denied;
        impl Driver for Denied {
            fn bootstrap_ready(&self) -> io::Result<bool> {
                Err(io::ErrorKind::PermissionDenied.into())
            }
            fn send(&mut self, _: [u8; 10]) -> io::Result<()> {
                panic!("unproven CAN service absence must never reach ioctl");
            }
        }
        let mut sender = Sender::spawn(|| Ok(Denied)).unwrap();
        until(&mut sender, Sender::ready);
        let owner = admission(1);
        sender
            .send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh(),
            )
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while sender.in_flight() {
            assert!(Instant::now() < deadline);
            assert!(
                !sender.poll(),
                "no command was sent, so feedback remains valid"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            sender.finish("fixture", owner.lease, command(1)),
            Some(Ok(Transmission::Waiting(Wait::Inputs)))
        );
        assert!(sender.error().is_some_and(|(_, expected)| !*expected));
        assert!(sender.retry_at > Instant::now());
        assert_eq!(
            sender.send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Waiting(Wait::Inputs))
        );
    }

    #[test]
    fn pending_is_not_acceptance_and_exact_poll_never_duplicates_the_ioctl() {
        let (mut sender, frames, release) = blocked();
        let owner = admission(1);
        assert_eq!(
            sender.send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Pending)
        );
        assert_eq!(
            frames.recv_timeout(Duration::from_secs(2)).unwrap(),
            [1; 10]
        );
        for _ in 0..10 {
            assert_eq!(
                sender.send(
                    "fixture",
                    owner.clone(),
                    command(1),
                    [1; 10],
                    owner.fence.clone(),
                    fresh()
                ),
                Ok(Transmission::Pending)
            );
        }
        assert!(frames.try_recv().is_err());
        release.send(()).unwrap();
        until(&mut sender, |sender| !sender.in_flight());
        assert_eq!(
            sender.finish("fixture", owner.lease, command(1)),
            Some(Ok(Transmission::Accepted))
        );
        assert_eq!(sender.finish("fixture", owner.lease, command(1)), None);
    }
    #[test]
    fn changed_lease_cannot_replace_an_ioctl_in_flight_and_drain_is_observable() {
        let (mut sender, frames, release) = blocked();
        let old = admission(1);
        sender
            .send(
                "fixture",
                old.clone(),
                command(1),
                [1; 10],
                old.fence.clone(),
                fresh(),
            )
            .unwrap();
        frames.recv_timeout(Duration::from_secs(2)).unwrap();
        old.fence.store(2, Ordering::Release);
        let new = Admission {
            lease: Lease { revision: 2 },
            fence: old.fence.clone(),
        };
        assert_eq!(
            sender.send(
                "fixture",
                new.clone(),
                command(2),
                [2; 10],
                new.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Waiting(Wait::Transport))
        );
        assert!(frames.try_recv().is_err());
        release.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !sender.poll() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(!sender.in_flight());
        assert_eq!(
            sender.send(
                "fixture",
                new.clone(),
                command(2),
                [2; 10],
                new.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Pending)
        );
        assert_eq!(
            frames.recv_timeout(Duration::from_secs(2)).unwrap(),
            [2; 10]
        );
        release.send(()).unwrap();
        until(&mut sender, |sender| !sender.in_flight());
    }
    #[test]
    fn queued_command_rechecks_both_owner_and_input_fences_before_driver_entry() {
        for revoked in 0..2 {
            let calls = Arc::new(AtomicU64::new(0));
            let driver_calls = calls.clone();
            let (begin, begun) = mpsc::sync_channel(1);
            let mut sender = Sender::spawn(move || {
                begun.recv().unwrap();
                Ok(Count(driver_calls))
            })
            .unwrap();
            sender.ready = true;
            let owner = admission(1);
            let inputs = Arc::new(AtomicU64::new(3));
            sender
                .send(
                    "fixture",
                    owner.clone(),
                    command(1),
                    [1; 10],
                    inputs.clone(),
                    fresh(),
                )
                .unwrap();
            if revoked == 0 {
                owner.fence.store(0, Ordering::Release);
            } else {
                inputs.store(4, Ordering::Release);
            }
            begin.send(()).unwrap();
            until(&mut sender, |sender| sender.result.is_some());
            assert_eq!(sender.result, Some(Err(Failure::Cancelled)));
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        }
    }
    #[test]
    fn unknown_ioctl_error_is_latched_without_automatic_replay() {
        struct Failed(Arc<AtomicU64>);
        impl Driver for Failed {
            fn send(&mut self, _: [u8; 10]) -> io::Result<()> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::other("unknown driver outcome"))
            }
        }
        let calls = Arc::new(AtomicU64::new(0));
        let driver_calls = calls.clone();
        let mut sender = Sender::spawn(move || Ok(Failed(driver_calls))).unwrap();
        until(&mut sender, Sender::ready);
        let owner = admission(1);
        sender
            .send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh(),
            )
            .unwrap();
        until(&mut sender, |sender| sender.result.is_some());
        for _ in 0..10 {
            assert_eq!(
                sender.send(
                    "fixture",
                    owner.clone(),
                    command(1),
                    [1; 10],
                    owner.fence.clone(),
                    fresh()
                ),
                Err(Failure::TransportUnavailable)
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        owner.fence.store(2, Ordering::Release);
        let new = Admission {
            lease: Lease { revision: 2 },
            fence: owner.fence.clone(),
        };
        assert_eq!(
            sender.send(
                "fixture",
                new.clone(),
                command(2),
                [2; 10],
                new.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Pending)
        );
        until(&mut sender, |sender| sender.result.is_some());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn queued_expired_observations_cannot_enter_the_driver_before_the_owner_polls() {
        for expired in 0..3 {
            let calls = Arc::new(AtomicU64::new(0));
            let driver_calls = calls.clone();
            let (begin, begun) = mpsc::sync_channel(1);
            let mut sender = Sender::spawn(move || {
                begun.recv().unwrap();
                Ok(Count(driver_calls))
            })
            .unwrap();
            sender.ready = true;
            let owner = admission(1);
            let old = super::super::clock::Stamp {
                at: Instant::now() - Duration::from_secs(3),
                boot_ms: crate::startup::boot_ms()
                    .ok()
                    .and_then(|now| now.checked_sub(3000)),
            };
            let mut proof = fresh();
            match expired {
                0 => proof.issued = old,
                1 => proof.feedback.push(old),
                _ => proof.inputs = Some(old),
            }
            sender
                .send(
                    "fixture",
                    owner.clone(),
                    command(1),
                    [1; 10],
                    owner.fence.clone(),
                    proof,
                )
                .unwrap();
            begin.send(()).unwrap();
            until(&mut sender, |sender| sender.result.is_some());
            assert_eq!(sender.result, Some(Err(Failure::Cancelled)));
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        }
    }
    #[test]
    fn queued_proof_rejects_suspend_and_keeps_original_boot_input_age() {
        let at = Instant::now();
        let issued = super::super::clock::Stamp {
            at,
            boot_ms: Some(1000),
        };
        let proof = Freshness {
            issued,
            feedback: vec![issued],
            inputs: Some(issued),
        };
        assert!(proof.current_at(super::super::clock::Stamp {
            at: at + Duration::from_millis(20),
            boot_ms: Some(1020)
        }));
        assert!(!proof.current_at(super::super::clock::Stamp {
            at: at + Duration::from_millis(1),
            boot_ms: Some(1500)
        }));
        let proof = Freshness {
            issued: super::super::clock::Stamp {
                at: at + Duration::from_millis(900),
                boot_ms: Some(1900),
            },
            feedback: Vec::new(),
            inputs: Some(issued),
        };
        assert!(!proof.current_at(super::super::clock::Stamp {
            at: at + Duration::from_millis(1100),
            boot_ms: Some(2100)
        }));
    }
    #[test]
    fn retirement_keeps_real_matching_result_and_disables_new_raw_dispatch() {
        let (mut sender, frames, release) = blocked();
        let owner = admission(1);
        sender
            .send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh(),
            )
            .unwrap();
        frames.recv_timeout(Duration::from_secs(2)).unwrap();
        sender.retire();
        assert!(sender.in_flight());
        release.send(()).unwrap();
        until(&mut sender, |sender| !sender.in_flight());
        assert_eq!(
            sender.finish("fixture", owner.lease, command(1)),
            Some(Ok(Transmission::Accepted))
        );
        assert_eq!(
            sender.send(
                "fixture",
                owner.clone(),
                command(2),
                [2; 10],
                owner.fence.clone(),
                fresh()
            ),
            Ok(Transmission::Waiting(Wait::Transport))
        );
        assert!(frames.try_recv().is_err());
    }
    #[test]
    fn feedback_wait_does_not_consume_terminal_ack_but_completed_policy_does() {
        let calls = Arc::new(AtomicU64::new(0));
        let driver_calls = calls.clone();
        let mut sender = Sender::spawn(move || Ok(Count(driver_calls))).unwrap();
        until(&mut sender, Sender::ready);
        let owner = admission(1);
        sender
            .send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh(),
            )
            .unwrap();
        until(&mut sender, |sender| !sender.in_flight());
        sender.withdraw("fixture", owner.lease, false);
        assert_eq!(
            sender.finish("fixture", owner.lease, command(1)),
            Some(Ok(Transmission::Accepted))
        );
        sender
            .send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh(),
            )
            .unwrap();
        until(&mut sender, |sender| !sender.in_flight());
        sender.withdraw("fixture", owner.lease, true);
        assert_eq!(sender.finish("fixture", owner.lease, command(1)), None);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn policy_withdrawal_cancels_queued_ticket_before_driver() {
        let calls = Arc::new(AtomicU64::new(0));
        let driver_calls = calls.clone();
        let (begin, begun) = mpsc::sync_channel(1);
        let mut sender = Sender::spawn(move || {
            begun.recv().unwrap();
            Ok(Count(driver_calls))
        })
        .unwrap();
        sender.ready = true;
        let owner = admission(1);
        sender
            .send(
                "fixture",
                owner.clone(),
                command(1),
                [1; 10],
                owner.fence.clone(),
                fresh(),
            )
            .unwrap();
        sender.withdraw("fixture", owner.lease, false);
        begin.send(()).unwrap();
        until(&mut sender, |sender| sender.result.is_some());
        assert_eq!(sender.finish("fixture", owner.lease, command(1)), None);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
