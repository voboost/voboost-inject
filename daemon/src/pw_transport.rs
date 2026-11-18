//! Daemon-owned private-pipe actor; the child uses platform JSSE, never app jobs.
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use voboost_shared::pw_transport_process::VerifiedCode;

pub use voboost_shared::pw_transport_process::actor::Config;
use voboost_shared::pw_transport_process::actor::{Actor, Slot};

static SLOT: Slot = Slot::new();

pub fn reap() {
    SLOT.reap();
}

#[derive(PartialEq, Eq)]
struct WorkerKey {
    generation: String,
    desired: String,
}
struct Worker {
    key: WorkerKey,
    cancel: Arc<AtomicBool>,
    finished: std::sync::mpsc::Receiver<()>,
}
fn supervisor() -> &'static std::sync::Mutex<Option<Worker>> {
    static VALUE: std::sync::OnceLock<std::sync::Mutex<Option<Worker>>> =
        std::sync::OnceLock::new();
    VALUE.get_or_init(|| std::sync::Mutex::new(None))
}
pub fn cancel() {
    if let Some(worker) = supervisor()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
    {
        worker.cancel.store(true, Ordering::Release);
    }
}
/// Runtime only computes current desired/binding and cancels; all artifact/TLS
/// I/O stays off the vehicle scheduling thread. No foreground Android app loop.
pub fn reconcile(generation: &crate::generation::VerifiedGeneration, plan: &crate::plan::Plan) {
    reap();
    let key =
        crate::cluster_control::pw_worker_selection(generation, plan).map(|desired| WorkerKey {
            generation: generation.id.clone(),
            desired,
        });
    let mut current = supervisor().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(worker) = current.as_ref() {
        if key.as_ref() != Some(&worker.key) {
            worker.cancel.store(true, Ordering::Release);
        }
        if matches!(
            worker.finished.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ) {
            return;
        }
        // An admission failure/panic is terminal for this exact source/config.
        // A cancelled worker may restart after a genuine lifecycle recovery.
        if key.as_ref() == Some(&worker.key) && !worker.cancel.load(Ordering::Acquire) {
            return;
        }
        current.take();
    }
    let Some(key) = key else {
        return;
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let generation = generation.clone();
    let plan = plan.clone();
    let (finished, receive) = std::sync::mpsc::sync_channel(1);
    let launch = std::thread::Builder::new()
        .name("pw-tls-courier".into())
        .spawn(move || {
            let mut delay = Duration::from_millis(250);
            let core = &generation.catalog.core;
            let code = VerifiedCode::admit(
                &generation.directory.join(&core.file),
                core.size,
                &core.sha256,
            )
            .map(Arc::new);
            let Ok(code) = code else {
                let _ = finished.try_send(());
                return;
            };
            while !worker_cancel.load(Ordering::Acquire) {
                let attempt = (|| -> io::Result<()> {
                    let config = crate::cluster_control::pw_actor_config(&generation, &plan)
                        .ok_or_else(|| failure("PW configuration unavailable"))?;
                    let actor = Actor::spawn(&SLOT, code.clone(), config, worker_cancel.clone())?;
                    while !worker_cancel.load(Ordering::Acquire) {
                        exchange(
                            &actor,
                            voboost_contract::cluster_pw_live::HELLO,
                            &worker_cancel,
                        )?;
                        if !pause(&worker_cancel, Duration::from_millis(250)) {
                            break;
                        }
                    }
                    Ok(())
                })();
                if attempt.is_ok() || worker_cancel.load(Ordering::Acquire) {
                    break;
                }
                if !pause(&worker_cancel, delay) {
                    break;
                }
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            let _ = finished.try_send(());
        });
    if launch.is_ok() {
        *current = Some(Worker {
            key,
            cancel,
            finished: receive,
        });
    }
}
fn pause(cancel: &AtomicBool, duration: Duration) -> bool {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        if cancel.load(Ordering::Acquire) {
            return false;
        }
        std::thread::sleep(
            Duration::from_millis(20).min(end.saturating_duration_since(Instant::now())),
        );
    }
    !cancel.load(Ordering::Acquire)
}
fn failure(message: &'static str) -> io::Error {
    io::Error::other(message)
}
/// One bounded native TLS session. Runtime signing stays in a separate loop.
/// A failure invalidates this actor; caller drops it before retry/backoff.
fn exchange(actor: &Actor, hello: &[u8], cancel: &AtomicBool) -> io::Result<Vec<u8>> {
    if hello.is_empty() || hello.len() > 1024 {
        return Err(failure("PW hello bound"));
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    actor.integer(1, deadline)?;
    actor.write(hello, deadline)?;
    if actor.number(deadline)? != 1 {
        return Err(failure("PW child handshake failed"));
    }
    let challenge = actor.read(3072, deadline)?;
    let challenge = voboost_contract::domain_core::parse_canonical(&challenge, 3072)
        .map_err(|_| failure("PW native challenge invalid"))?;
    let mut proof = super::pw_live::proof(challenge, deadline, cancel)?;
    let sent = actor.write(&proof, deadline);
    proof.fill(0);
    sent?;
    if actor.number(deadline)? != 2 {
        return Err(failure("PW native response failed"));
    }
    let response = actor.read(1024, deadline)?;
    if response != voboost_contract::cluster_pw_live::ACK {
        return Err(failure("PW native acknowledgement invalid"));
    }
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsRawFd, unix::net::UnixStream};
    use voboost_shared::pw_transport_process::actor::transfer;
    #[test]
    fn supervisor_cancels_disabled_native_selection_and_releases_disconnected_worker() {
        let generation = crate::plan::test_fixtures::vehicle_fault_generation();
        let plan = crate::plan::Plan::defaults_for(&generation);
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = std::sync::mpsc::channel();
        *supervisor().lock().unwrap() = Some(Worker {
            key: WorkerKey {
                generation: generation.id.clone(),
                desired: "x".into(),
            },
            cancel: cancel.clone(),
            finished: receiver,
        });
        reconcile(&generation, &plan);
        assert!(cancel.load(Ordering::Acquire));
        assert!(supervisor().lock().unwrap().is_some());
        drop(sender); // A panic/disconnected worker must not occupy the slot forever.
        reconcile(&generation, &plan);
        assert!(supervisor().lock().unwrap().is_none());
    }
    #[test]
    fn private_pipe_cancel_timeout_and_eof_are_bounded() {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let mut bytes = [0u8; 4];
        let cancel = AtomicBool::new(true);
        assert!(transfer(
            a.as_raw_fd(),
            &mut bytes,
            false,
            Instant::now() + Duration::from_secs(1),
            &cancel
        )
        .is_err());
        cancel.store(false, Ordering::Release);
        assert_eq!(
            transfer(
                a.as_raw_fd(),
                &mut bytes,
                false,
                Instant::now() + Duration::from_millis(20),
                &cancel
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        drop(b);
        assert_eq!(
            transfer(
                a.as_raw_fd(),
                &mut bytes,
                false,
                Instant::now() + Duration::from_secs(1),
                &cancel
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[test]
    fn private_pipe_delivers_exact_bounded_bytes() {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(1);
        let reader = std::thread::spawn(move || {
            let mut bytes = vec![0u8; 65536];
            transfer(
                b.as_raw_fd(),
                &mut bytes,
                false,
                deadline,
                &AtomicBool::new(false),
            )
            .unwrap();
            bytes
        });
        let mut sent = vec![0x5au8; 65536];
        transfer(a.as_raw_fd(), &mut sent, true, deadline, &cancel).unwrap();
        let received = reader.join().unwrap();
        assert_eq!(sent, received);
    }
}
