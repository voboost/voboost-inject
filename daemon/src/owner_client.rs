//! Current-session client. A lost mutation reply is never replayed locally or remotely.
#![cfg_attr(test, allow(dead_code))]
#[cfg(not(test))]
use crate::native_executable_signature::NativeExecutableRole;
use std::io;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use voboost_contract::runtime_owner::{Command, Outcome};
#[cfg(test)]
use voboost_contract::runtime_owner::{Reply, Request, SCHEMA};
const EXCHANGE: Duration = Duration::from_millis(500);

pub(crate) fn call(command: Command) -> io::Result<Outcome> {
    call_until(command, Instant::now() + EXCHANGE)
}

fn call_until(command: Command, deadline: Instant) -> io::Result<Outcome> {
    let mut stream = connect(deadline)?;
    crate::owner_io::request::<voboost_contract::runtime_owner::Outcome>(
        &mut stream,
        command,
        deadline,
    )
}

#[cfg(not(test))]
pub(crate) fn connect(deadline: Instant) -> io::Result<std::os::unix::net::UnixStream> {
    let stream = crate::owner_io::connect(
        &Path::new(crate::config::RUN_DIR).join("owner.sock"),
        deadline,
    )?;
    crate::owner_peer::verify(&stream, NativeExecutableRole::Daemon)?;
    Ok(stream)
}

#[cfg(test)]
type Connection = Box<dyn FnMut() -> io::Result<UnixStream>>;

#[cfg(test)]
thread_local! {
    static CONNECTION: std::cell::RefCell<Option<Connection>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn connect(_deadline: Instant) -> io::Result<UnixStream> {
    CONNECTION.with(|connection| {
        connection
            .borrow_mut()
            .as_mut()
            .ok_or(io::ErrorKind::NotConnected)?()
    })
}

#[cfg(test)]
pub(crate) fn with_connection<T>(
    connection: impl FnMut() -> io::Result<UnixStream> + 'static,
    action: impl FnOnce() -> T,
) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CONNECTION.with(|slot| slot.borrow_mut().take());
        }
    }
    CONNECTION.with(|slot| {
        assert!(slot.borrow().is_none(), "nested composition connector");
        *slot.borrow_mut() = Some(Box::new(connection));
    });
    let _reset = Reset;
    action()
}

pub(crate) fn wait_ready(limit: Duration) -> io::Result<()> {
    wait_for_config(limit, |deadline| {
        call_until(
            Command::ReadConfig {},
            deadline.min(Instant::now() + EXCHANGE),
        )
    })
}

fn wait_for_config(
    limit: Duration,
    mut read: impl FnMut(Instant) -> io::Result<Outcome>,
) -> io::Result<()> {
    let deadline = Instant::now() + limit;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "runtime owner readiness deadline exceeded",
            ));
        }
        match read(deadline) {
            Ok(Outcome::Config { .. }) => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "runtime owner readiness rejected",
                ))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                std::thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(20)),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
fn exchange(stream: &mut UnixStream, command: Command, limit: Duration) -> io::Result<Outcome> {
    crate::owner_io::request::<voboost_contract::runtime_owner::Outcome>(
        stream,
        command,
        Instant::now() + limit,
    )
}

fn unavailable() -> io::Error {
    io::Error::other("runtime owner did not confirm the operation")
}
/// The authenticated owner validates current native state and signs each challenge once.
pub(crate) fn cluster_pw_proof(
    challenge: voboost_contract::cluster_pw_live::Challenge,
    deadline: Instant,
) -> io::Result<Option<Vec<u8>>> {
    match call_until(
        Command::ReadClusterPwProof { challenge },
        deadline.min(Instant::now() + EXCHANGE),
    )? {
        Outcome::ClusterPwProof { proof: None } => Ok(None),
        Outcome::ClusterPwProof { proof: Some(bytes) } => Ok(Some(bytes)),
        _ => Err(unavailable()),
    }
}

pub(crate) fn cluster_epoch() -> io::Result<String> {
    match call(Command::ReadClusterEpoch {})? {
        Outcome::ClusterEpoch { value } => Ok(value),
        _ => Err(unavailable()),
    }
}
pub(crate) fn publish_injection_status(bytes: &str) -> io::Result<()> {
    match call(Command::PublishInjectionStatus {
        bytes: bytes.into(),
    })? {
        Outcome::Written {} => Ok(()),
        _ => Err(unavailable()),
    }
}
pub(crate) fn append_app_batch(bytes: &[u8]) -> io::Result<String> {
    let batch = voboost_contract::runtime_log::AppBatch::decode(bytes).map_err(io::Error::other)?;
    match call(Command::AppendAppBatch {
        bytes: String::from_utf8(bytes.to_vec()).map_err(io::Error::other)?,
    })? {
        Outcome::BatchLogged { batch_id } if batch_id == batch.batch_id => Ok(batch_id),
        _ => Err(unavailable()),
    }
}
pub(crate) fn append_log(
    source: voboost_contract::runtime_log::Source,
    record: voboost_contract::runtime_log::Record,
) -> io::Result<u64> {
    match call(Command::AppendLog { source, record })? {
        Outcome::Logged { sequence, .. } => Ok(sequence),
        _ => Err(unavailable()),
    }
}
pub(crate) fn require_config(path: &Path) -> io::Result<()> {
    if path != Path::new(voboost_contract::runtime_owner::ROOT_ZONE).join("agents.json") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration target rejected",
        ));
    }
    Ok(())
}
pub(crate) fn read_config(path: &Path) -> io::Result<Vec<u8>> {
    require_config(path)?;
    match call(Command::ReadConfig {})? {
        Outcome::Config { bytes: Some(bytes) } => Ok(bytes.into_bytes()),
        Outcome::Config { bytes: None } => Err(io::ErrorKind::NotFound.into()),
        _ => Err(unavailable()),
    }
}
pub(crate) fn replace_config(
    path: &Path,
    expected: Option<Vec<u8>>,
    bytes: &[u8],
) -> io::Result<()> {
    require_config(path)?;
    let expected = expected
        .map(String::from_utf8)
        .transpose()
        .map_err(io::Error::other)?;
    let next = String::from_utf8(bytes.to_vec()).map_err(io::Error::other)?;
    match call(Command::ReplaceConfig { expected, next })? {
        Outcome::Written {} => Ok(()),
        Outcome::Conflict {} => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "configuration changed",
        )),
        _ => Err(unavailable()),
    }
}
pub(crate) fn save_desired(
    field: voboost_contract::desired::Field,
    value: serde_json::Value,
    input: voboost_contract::desired::Input,
) -> io::Result<Outcome> {
    match call(Command::SaveDesired {
        field,
        value,
        input,
    })? {
        saved @ Outcome::DesiredSaved { .. } => Ok(saved),
        _ => Err(unavailable()),
    }
}
pub(crate) fn confirm_agent_withdrawn(source: &str) -> io::Result<()> {
    match call(Command::ConfirmAgentWithdrawn {
        source: source.to_string(),
    })? {
        Outcome::Withdrawn {} => Ok(()),
        _ => Err(unavailable()),
    }
}
pub(crate) fn reconcile_desired(defaults: &[u8]) -> io::Result<Vec<u8>> {
    let proposal = String::from_utf8(defaults.to_vec()).map_err(io::Error::other)?;
    match call(Command::ReconcileDesired { defaults: proposal })? {
        Outcome::DesiredReconciled { revision, config } => {
            let result = voboost_contract::desired::Config::decode(config.as_bytes())?;
            if result.user_revision != revision {
                return Err(io::Error::other("reconciled desired revision differs"));
            }
            result.verify_defaults(defaults)?;
            Ok(config.into_bytes())
        }
        Outcome::Conflict {} => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "configuration changed",
        )),
        _ => Err(unavailable()),
    }
}
pub(crate) fn read_desired(field: voboost_contract::desired::Field) -> io::Result<Outcome> {
    match call(Command::ReadDesired { field })? {
        saved @ Outcome::DesiredSaved { .. } => Ok(saved),
        _ => Err(unavailable()),
    }
}
pub(crate) fn read_startup_session() -> io::Result<Option<Vec<u8>>> {
    match call(Command::ReadStartupSession {})? {
        Outcome::StartupSession { bytes } => Ok(bytes.map(String::into_bytes)),
        _ => Err(unavailable()),
    }
}
pub(crate) fn replace_startup_session(
    expected: Option<Vec<u8>>,
    next: Option<Vec<u8>>,
) -> io::Result<()> {
    let decode = |bytes| String::from_utf8(bytes).map_err(io::Error::other);
    match call(Command::ReplaceStartupSession {
        expected: expected.map(decode).transpose()?,
        next: next.map(decode).transpose()?,
    })? {
        Outcome::Written {} => Ok(()),
        Outcome::Conflict {} => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "startup session changed",
        )),
        _ => Err(unavailable()),
    }
}
#[cfg(test)]
pub(crate) fn prepare_intent(
    source: &str,
    key: &str,
    record: voboost_contract::runtime_owner::CapturedIntent,
) -> io::Result<voboost_contract::runtime_owner::IntentAdmission> {
    match call(Command::PrepareIntent {
        source: source.into(),
        key: key.into(),
        record,
    })? {
        Outcome::IntentPrepared { admission } => Ok(admission),
        _ => Err(unavailable()),
    }
}

#[cfg(test)]
pub(crate) fn finish_intent(
    source: &str,
    key: &str,
    record: voboost_contract::runtime_owner::CapturedIntent,
) -> io::Result<()> {
    match call(Command::FinishIntent {
        source: source.into(),
        key: key.into(),
        record,
    })? {
        Outcome::Written {} => Ok(()),
        _ => Err(unavailable()),
    }
}

pub(crate) fn recover_intent(source: &str, key: &str) -> io::Result<()> {
    match call(Command::RecoverIntent {
        source: source.into(),
        key: key.into(),
    })? {
        Outcome::Written {} => Ok(()),
        _ => Err(unavailable()),
    }
}

pub(crate) fn register_native_transport(
    source: &str,
    pid: i32,
    endpoint_epoch: u64,
    available: bool,
) -> io::Result<Outcome> {
    let outcome = call(Command::RegisterNativeTransport {
        source: source.into(),
        pid,
        endpoint_epoch,
        available,
    })?;
    match &outcome {
        Outcome::NativeTransportRegistered { receipt }
            if receipt.source == source
                && receipt.pid == pid
                && receipt.endpoint_epoch == endpoint_epoch
                && receipt.available == available =>
        {
            Ok(outcome)
        }
        _ => Err(unavailable()),
    }
}

pub(crate) fn observe_native_vehicle(
    source: &str,
    pid: i32,
    endpoint_epoch: u64,
    observation: voboost_contract::runtime_owner::NativeVehicleObservation,
) -> io::Result<Outcome> {
    let outcome = call(Command::ObserveNativeVehicle {
        source: source.into(),
        pid,
        endpoint_epoch,
        observation,
    })?;
    match &outcome {
        Outcome::NativeVehicleObserved {
            source: returned, ..
        } if returned == source => Ok(outcome),
        _ => Err(unavailable()),
    }
}

pub(crate) fn poll_native_command(
    source: &str,
    pid: i32,
    endpoint_epoch: u64,
) -> io::Result<Outcome> {
    let outcome = call(Command::PollNativeCommand {
        source: source.into(),
        pid,
        endpoint_epoch,
    })?;
    match &outcome {
        Outcome::NativeCommand {
            source: returned, ..
        } if returned == source => Ok(outcome),
        _ => Err(unavailable()),
    }
}

pub(crate) fn report_native_command(
    identity: voboost_contract::runtime_owner::NativeCommandIdentity,
    pid: i32,
    endpoint_epoch: u64,
    status: voboost_contract::runtime_owner::NativeCommandStatus,
) -> io::Result<Outcome> {
    use voboost_contract::runtime_owner::{NativeCommandPhase, NativeCommandStatus};
    let outcome = call(Command::ReportNativeCommand {
        identity: identity.clone(),
        pid,
        endpoint_epoch,
        status,
    })?;
    let valid = match &outcome {
        Outcome::NativeCommand {
            source,
            command: None,
        } if status == NativeCommandStatus::Claim => source == &identity.source,
        Outcome::NativeCommand {
            source,
            command: Some(command),
        } if status == NativeCommandStatus::Claim => {
            source == &identity.source
                && command.identity == identity
                && matches!(
                    command.phase,
                    NativeCommandPhase::Execute | NativeCommandPhase::Cancelled
                )
        }
        Outcome::NativeCommandReported {
            identity: returned,
            result,
        } => status != NativeCommandStatus::Claim && returned == &identity && *result == status,
        _ => false,
    };
    if valid {
        Ok(outcome)
    } else {
        Err(unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    #[test]
    fn readiness_retries_only_transient_reads_and_never_authentication_rejection() {
        let mut count = 0;
        wait_for_config(Duration::from_secs(1), |_| {
            count += 1;
            if count < 3 {
                Err(io::ErrorKind::ConnectionRefused.into())
            } else {
                Ok(Outcome::Config { bytes: None })
            }
        })
        .unwrap();
        assert_eq!(count, 3);
        let mut rejected = 0;
        assert!(wait_for_config(Duration::from_secs(1), |_| {
            rejected += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        })
        .is_err());
        assert_eq!(rejected, 1);
        assert!(wait_for_config(Duration::ZERO, |_| panic!(
            "expired readiness must not dispatch"
        ))
        .is_err());
        assert!(wait_for_config(Duration::from_secs(1), |_| Ok(Outcome::Written {})).is_err());
    }
    fn send(stream: &mut UnixStream, id: u64, session: &str, outcome: Outcome) {
        let reply = Reply {
            schema_version: SCHEMA,
            session: session.into(),
            request_id: id,
            outcome,
        };
        crate::owner_io::write(
            stream,
            &serde_json::to_vec(&reply).unwrap(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    }
    #[test]
    fn real_socket_exchange_binds_session_request_and_scalar() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            send(&mut server, 0, SESSION, Outcome::Ready {});
            let request = Request::decode(
                &crate::owner_io::read(&mut server, Instant::now() + Duration::from_secs(1))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(request.session, SESSION);
            assert_eq!(request.request_id, 1);
            assert!(matches!(
                request.command,
                Command::WriteState {
                    value: serde_json::Value::Bool(false),
                    ..
                }
            ));
            send(&mut server, 1, SESSION, Outcome::Written {});
        });
        let result = exchange(
            &mut client,
            Command::WriteState {
                source: "media-apps".into(),
                key: "armed".into(),
                value: false.into(),
            },
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(matches!(result, Outcome::Written {}));
        worker.join().unwrap();
    }
    #[test]
    fn session_change_and_lost_mutation_reply_never_replay() {
        for lost in [false, true] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                send(&mut server, 0, SESSION, Outcome::Ready {});
                let request = Request::decode(
                    &crate::owner_io::read(&mut server, Instant::now() + Duration::from_secs(1))
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(request.request_id, 1);
                if lost {
                    server.shutdown(std::net::Shutdown::Write).unwrap();
                } else {
                    send(
                        &mut server,
                        1,
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                        Outcome::Written {},
                    );
                }
                let mut extra = [0; 1];
                use std::io::Read;
                server
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                assert!(matches!(server.read(&mut extra), Ok(0) | Err(_)));
            });
            assert!(exchange(
                &mut client,
                Command::WriteState {
                    source: "media-apps".into(),
                    key: "armed".into(),
                    value: false.into()
                },
                Duration::from_secs(1)
            )
            .is_err());
            drop(client);
            worker.join().unwrap();
        }
    }
    #[test]
    fn bounded_exchange_and_wrong_configuration_target_fail_closed() {
        let (_server, mut client) = UnixStream::pair().unwrap();
        let before = Instant::now();
        assert!(exchange(
            &mut client,
            Command::ReadConfig {},
            Duration::from_millis(20)
        )
        .is_err());
        assert!(before.elapsed() < Duration::from_secs(1));
        for path in [
            "/tmp/agents.json",
            "/data/voboost/elsewhere.json",
            "/data/voboost/sub/../agents.json",
        ] {
            assert!(require_config(Path::new(path)).is_err());
        }
    }
    fn semantic_identity() -> voboost_contract::runtime_owner::NativeCommandIdentity {
        voboost_contract::runtime_owner::NativeCommandIdentity {
            owner_session: SESSION.into(),
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            source: "vehicle-drive-forced-ev".into(),
            command_id: 7,
            revision: 2,
            state: "IVI_SOC_MODESET".into(),
            value: 5,
        }
    }

    #[test]
    fn native_command_reports_require_exact_identity_and_terminal_status() {
        use voboost_contract::runtime_owner::NativeCommandStatus;
        for variant in 0..4 {
            let (client, mut server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                send(&mut server, 0, SESSION, Outcome::Ready {});
                let request = Request::decode(
                    &crate::owner_io::read(&mut server, Instant::now() + Duration::from_secs(1))
                        .unwrap(),
                )
                .unwrap();
                assert!(matches!(
                    request.command,
                    Command::ReportNativeCommand {
                        status: NativeCommandStatus::Accepted,
                        ..
                    }
                ));
                let mut identity = semantic_identity();
                match variant {
                    1 => identity.command_id += 1,
                    2 => identity.value = 2,
                    _ => {}
                }
                send(
                    &mut server,
                    request.request_id,
                    SESSION,
                    Outcome::NativeCommandReported {
                        identity,
                        result: if variant == 3 {
                            NativeCommandStatus::Failed
                        } else {
                            NativeCommandStatus::Accepted
                        },
                    },
                );
            });
            let mut socket = Some(client);
            let result = with_connection(
                move || {
                    socket
                        .take()
                        .ok_or_else(|| io::ErrorKind::NotConnected.into())
                },
                || {
                    report_native_command(
                        semantic_identity(),
                        20,
                        30,
                        NativeCommandStatus::Accepted,
                    )
                },
            );
            assert_eq!(result.is_ok(), variant == 0);
            worker.join().unwrap();
        }
    }

    #[test]
    fn native_command_claim_requires_an_execute_or_cancelled_grant() {
        use voboost_contract::runtime_owner::{
            NativeCommandEnvelope, NativeCommandPhase, NativeCommandStatus,
        };
        for phase in [
            NativeCommandPhase::Offered,
            NativeCommandPhase::Execute,
            NativeCommandPhase::Cancelled,
        ] {
            let (client, mut server) = UnixStream::pair().unwrap();
            let worker = std::thread::spawn(move || {
                send(&mut server, 0, SESSION, Outcome::Ready {});
                let request = Request::decode(
                    &crate::owner_io::read(&mut server, Instant::now() + Duration::from_secs(1))
                        .unwrap(),
                )
                .unwrap();
                send(
                    &mut server,
                    request.request_id,
                    SESSION,
                    Outcome::NativeCommand {
                        source: "vehicle-drive-forced-ev".into(),
                        command: Some(NativeCommandEnvelope {
                            schema_version: SCHEMA,
                            identity: semantic_identity(),
                            phase,
                        }),
                    },
                );
            });
            let mut socket = Some(client);
            let result = with_connection(
                move || {
                    socket
                        .take()
                        .ok_or_else(|| io::ErrorKind::NotConnected.into())
                },
                || report_native_command(semantic_identity(), 20, 30, NativeCommandStatus::Claim),
            );
            assert_eq!(result.is_ok(), phase != NativeCommandPhase::Offered);
            worker.join().unwrap();
        }
    }

    #[test]
    fn native_command_claim_can_wait_without_an_execution_grant() {
        use voboost_contract::runtime_owner::NativeCommandStatus;
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            send(&mut server, 0, SESSION, Outcome::Ready {});
            let request = Request::decode(
                &crate::owner_io::read(&mut server, Instant::now() + Duration::from_secs(1))
                    .unwrap(),
            )
            .unwrap();
            send(
                &mut server,
                request.request_id,
                SESSION,
                Outcome::NativeCommand {
                    source: "vehicle-drive-forced-ev".into(),
                    command: None,
                },
            );
        });
        let mut socket = Some(client);
        let result = with_connection(
            move || {
                socket
                    .take()
                    .ok_or_else(|| io::ErrorKind::NotConnected.into())
            },
            || report_native_command(semantic_identity(), 20, 30, NativeCommandStatus::Claim),
        )
        .unwrap();
        assert!(matches!(
            result,
            Outcome::NativeCommand { command: None, .. }
        ));
        worker.join().unwrap();
    }

    #[test]
    fn lost_native_command_report_never_reconnects_or_replays() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        use voboost_contract::runtime_owner::NativeCommandStatus;
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            send(&mut server, 0, SESSION, Outcome::Ready {});
            let request = Request::decode(
                &crate::owner_io::read(&mut server, Instant::now() + Duration::from_secs(1))
                    .unwrap(),
            )
            .unwrap();
            assert!(matches!(
                request.command,
                Command::ReportNativeCommand { .. }
            ));
            server.shutdown(std::net::Shutdown::Write).unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let mut byte = [0];
            use std::io::Read;
            assert!(matches!(server.read(&mut byte), Ok(0) | Err(_)));
        });
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let mut socket = Some(client);
        with_connection(
            move || {
                seen.fetch_add(1, Ordering::SeqCst);
                socket
                    .take()
                    .ok_or_else(|| io::ErrorKind::NotConnected.into())
            },
            || {
                assert!(report_native_command(
                    semantic_identity(),
                    20,
                    30,
                    NativeCommandStatus::Accepted
                )
                .is_err())
            },
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        worker.join().unwrap();
    }
}
