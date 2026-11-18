//! Paired QNX log pull independent of the PW worker, plan and delivery slot.
use super::{
    generation_catalog,
    log::{
        qnx::{Failure, Journal, Status},
        Log,
    },
    STOP,
};
use std::{
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use voboost_contract::cluster_log::{self, Request, Response};
use voboost_shared::{
    cluster_mailbox::Provision,
    pw_transport_process::{
        actor::{Actor, Config, Slot},
        VerifiedCode,
    },
    secure_fs::Directory,
};

static SLOT: Slot = Slot::new();

struct Connection {
    generation: String,
    state: State,
}

enum State {
    Unpaired,
    Ready {
        pairing: (String, String),
        actor: Actor,
    },
}

fn pairing(provision: &Provision) -> (&str, &str) {
    (&provision.pair_id, &provision.authority_epoch)
}

impl Connection {
    fn matches(&self, generation: &str, provision: Option<&Provision>) -> bool {
        self.generation == generation
            && match (&self.state, provision) {
                (State::Unpaired, None) => true,
                (
                    State::Ready {
                        pairing: identity, ..
                    },
                    Some(provision),
                ) => pairing(provision) == (identity.0.as_str(), identity.1.as_str()),
                _ => false,
            }
    }
}

pub(super) fn start(root: &Path, boot: &str, logger: Arc<Mutex<Log>>) {
    let mut journal = Journal::new(Path::new(super::config::LOG_DIR), boot);
    let root = root.to_path_buf();
    let _ = std::thread::Builder::new()
        .name("qnx-log-pull".into())
        .spawn(move || {
            let mut connection = None;
            let mut retry = Duration::from_millis(250);
            let cancel = Arc::new(AtomicBool::new(false));
            let mut maintenance_at = Instant::now() + Duration::from_secs(60);
            while !STOP.load(Ordering::Relaxed) {
                if Instant::now() >= maintenance_at {
                    let _ = journal.maintain();
                    maintenance_at = Instant::now() + Duration::from_secs(60);
                }
                let result = poll(&root, &logger, &mut journal, &mut connection, &cancel);
                let wait = match result {
                    Ok(result) => {
                        retry = Duration::from_millis(250);
                        let (status, wait) = result;
                        let _ = journal.set_status(status);
                        wait
                    }
                    Err(failure) => {
                        connection = None;
                        let delay = retry;
                        retry = (retry * 2).min(Duration::from_secs(5));
                        let _ = journal.set_failure(failure);
                        delay
                    }
                };
                let until = Instant::now() + wait;
                while !STOP.load(Ordering::Relaxed) && Instant::now() < until {
                    std::thread::sleep(
                        Duration::from_millis(50)
                            .min(until.saturating_duration_since(Instant::now())),
                    );
                }
            }
            cancel.store(true, Ordering::Release);
        });
}

fn poll(
    root: &Path,
    logger: &Mutex<Log>,
    journal: &mut Journal,
    connection: &mut Option<Connection>,
    cancel: &Arc<AtomicBool>,
) -> Result<(Status, Duration), Failure> {
    SLOT.reap();
    let root_dir = Directory::open(root).map_err(|_| Failure::Configuration)?;
    root_dir
        .validate_owner_mode(0, 0, 0o755)
        .map_err(|_| Failure::Configuration)?;
    let (generations, id) = generation_catalog::active(root).map_err(|_| Failure::Configuration)?;
    let directory = match root_dir.open_child("cluster") {
        Ok(directory) => Some(directory),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(Failure::Configuration),
    };
    let provision = directory
        .as_ref()
        .map(paired)
        .transpose()
        .map_err(|_| Failure::Configuration)?
        .flatten();
    if !connection
        .as_ref()
        .is_some_and(|current| current.matches(&id, provision.as_ref()))
    {
        *connection = None;
        let state = match (directory, provision) {
            (Some(directory), Some(provision)) => {
                let catalog = generation_catalog::read(&generations, &id)
                    .map_err(|_| Failure::Configuration)?;
                let pairing = (provision.pair_id, provision.authority_epoch);
                let config = Config::read_paired(&directory, provision.transport)
                    .map_err(|_| Failure::Configuration)?;
                let core = catalog.core;
                let code = Arc::new(
                    VerifiedCode::admit(
                        &generation_catalog::core_path(root, &id, &core.file),
                        core.size,
                        &core.sha256,
                    )
                    .map_err(|_| Failure::Configuration)?,
                );
                let actor =
                    Actor::spawn(&SLOT, code, config, cancel.clone()).map_err(transport_failure)?;
                State::Ready { pairing, actor }
            }
            _ => State::Unpaired,
        };
        *connection = Some(Connection {
            generation: id,
            state,
        });
    }
    let actor = match connection.as_ref().map(|current| &current.state) {
        Some(State::Ready { actor, .. }) => actor,
        _ => return Ok((Status::Unpaired, Duration::from_secs(5))),
    };
    let ack = journal.position().map_err(|_| Failure::Storage)?;
    let request = Request { ack }.encode().map_err(|_| Failure::Protocol)?;
    let response = exchange(actor, &request)?;
    let wait = match response {
        Response::Idle => Duration::from_secs(2),
        Response::Batch(batch) => {
            journal
                .append(logger, &batch)
                .map_err(|_| Failure::Storage)?;
            Duration::from_millis(250)
        }
    };
    Ok((Status::Connected, wait))
}

fn paired(directory: &Directory) -> io::Result<Option<Provision>> {
    directory.validate_owner_mode(0, 0, 0o700)?;
    let bytes = match directory.read_trusted("provision.json", 16 * 1024, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let provision: Provision = voboost_contract::domain_core::parse_canonical(&bytes, 16 * 1024)
        .map_err(io::Error::other)?;
    provision.validate().map_err(io::Error::other)?;
    Ok(Some(provision))
}

fn transport_failure(error: io::Error) -> Failure {
    if error.kind() == io::ErrorKind::TimedOut {
        Failure::Timeout
    } else {
        Failure::Transport
    }
}

fn exchange(actor: &Actor, request: &[u8]) -> Result<Response, Failure> {
    const CLUSTER_LOG_REQUEST: u32 = 2;
    if request.len() > cluster_log::MAX_REQUEST_BYTES {
        return Err(Failure::Protocol);
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    actor
        .integer(CLUSTER_LOG_REQUEST, deadline)
        .map_err(transport_failure)?;
    actor.write(request, deadline).map_err(transport_failure)?;
    let bytes = actor
        .read(cluster_log::MAX_FRAME_BYTES, deadline)
        .map_err(transport_failure)?;
    Response::parse(&bytes).map_err(|_| Failure::Protocol)
}
