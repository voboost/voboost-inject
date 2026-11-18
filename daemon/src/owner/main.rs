//! Resident owner entry. Native agent behavior is supplied by agent executors.
#[cfg(test)]
#[path = "../owner_client.rs"]
mod owner_client;
#[cfg(test)]
use io as owner_io;
mod cli;
mod client;
mod cluster;
#[cfg(test)]
mod composition;
mod config;
mod generation_catalog;
#[path = "../generation_layout.rs"]
#[allow(dead_code)]
mod generation_layout;
mod initial_seeding;
mod io;
mod log;
#[path = "../log_archive.rs"]
mod log_archive;
#[path = "../log_export.rs"]
mod log_export;
mod logs;
pub mod native;
#[cfg(not(test))]
pub use voboost_contract::native_agent as native_api;
#[cfg(test)]
#[path = "../../../contract/native_agent.rs"]
pub mod native_api;
#[cfg(target_os = "android")]
const _: () = assert!(
    !native::CODECS.is_empty(),
    "Android daemon requires a native registry"
);
#[path = "signature.rs"]
mod native_binary;
mod peer;
#[path = "../pidfile.rs"]
mod pidfile;
mod qnx_log;
mod server;
mod startup;
mod state;
mod state_outage;
mod state_outage_auth;
#[path = "../strict_json.rs"]
mod strict_json;
use native_executable_signature::NativeExecutableRole;
use std::collections::BTreeMap;
use std::io::{self as stdio, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use voboost_contract::runtime_owner::{Outcome, Reply, Request, SCHEMA};
use voboost_shared::{native_executable_signature, secure_fs};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn main() {
    if let Err(error) = run() {
        voboost_shared::diagnostic_log::stderr(
            voboost_shared::diagnostic_log::Service::Daemon,
            voboost_shared::diagnostic_log::Level::Error,
            "daemon",
            "resident owner unavailable",
            &[("reason", &error.to_string())],
        );
        std::process::exit(1);
    }
}
fn run() -> stdio::Result<()> {
    let started = Instant::now();
    let started_boot = startup::boot_ms();
    let mode = cli::parse(&std::env::args_os().skip(1).collect::<Vec<_>>())?;
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(stdio::Error::new(
            stdio::ErrorKind::PermissionDenied,
            "resident owner requires its init service",
        ));
    }
    native_binary::verify_current_role(NativeExecutableRole::Daemon).map_err(|_| {
        stdio::Error::new(
            stdio::ErrorKind::PermissionDenied,
            "resident executable signature rejected",
        )
    })?;
    match mode {
        cli::Mode::Logs => {
            return logs::write(Path::new(config::ROOT_ZONE), &mut stdio::stdout().lock())
        }
        cli::Mode::Startup(startup) => {
            return cli::save_startup(
                Path::new(config::ROOT_ZONE),
                startup,
                &mut stdio::stdout().lock(),
            )
        }
        cli::Mode::NativeCan(cursor) => {
            return cli::native_can(
                Path::new(config::ROOT_ZONE),
                cursor,
                &mut stdio::stdout().lock(),
            )
        }
        cli::Mode::Resident => (),
    }
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
    }
    if !startup::wait_data(|| STOP.load(Ordering::Relaxed))? {
        return Ok(());
    }
    pidfile::acquire_process_lock()?;
    let boot = voboost_contract::operation::current_boot_id().map_err(stdio::Error::other)?;
    let mut random = [0; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let session = hex::encode(random);
    let root = secure_fs::Directory::open(Path::new(config::ROOT_ZONE))?;
    root.validate_owner_mode(0, 0, 0o755)?;
    root.open_or_create_private_child("logs")?;
    let logger = log::Log::create(Path::new(config::LOG_DIR), &boot, &session)?;
    let logger = std::sync::Arc::new(std::sync::Mutex::new(logger));
    // If evidence initialization fails, disarm it before serving any state
    // request so a later owner cannot claim to have observed the first read.
    match initial_seeding::initialize(
        Path::new(config::ROOT_ZONE),
        &boot,
        &session,
        logger.clone(),
    ) {
        Ok(()) => (),
        Err(error)
            if matches!(
                error.kind(),
                stdio::ErrorKind::NotFound
                    | stdio::ErrorKind::AlreadyExists
                    | stdio::ErrorKind::WouldBlock
            ) => {}
        Err(_) => {
            initial_seeding::disarm(Path::new(config::ROOT_ZONE))?;
            root.sync_all()?;
        }
    }
    let path = Path::new(config::RUN_DIR).join("owner.sock");
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket()
            || meta.uid() != 0
            || meta.gid() != 0
            || meta.mode() & 0o7777 != 0o600
        {
            return Err(stdio::Error::new(
                stdio::ErrorKind::PermissionDenied,
                "owner socket metadata rejected",
            ));
        }
        match io::connect(&path, Instant::now() + Duration::from_millis(500)) {
            Err(e) if e.kind() == stdio::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(&path)?
            }
            _ => {
                return Err(stdio::Error::new(
                    stdio::ErrorKind::AddrInUse,
                    "owner socket is active",
                ))
            }
        }
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
    }
    logger
        .lock()
        .map_err(|_| stdio::Error::other("logging lock poisoned"))?
        .append(
            log::Level::Debug,
            log::Source::daemon(),
            "native",
            "native codecs loaded",
            BTreeMap::from([("count".into(), native::CODECS.len().to_string())]),
        )?;
    let mut store = server::Store::new(Path::new(config::ROOT_ZONE), &session)?
        .with_shared_logger(logger.clone())?;
    let mut maintenance_at = Instant::now() + Duration::from_secs(60);
    let mut maintenance_failed = false;
    let mut native = native::Runtime::default();
    if let Err(error) = store.initialize_native(&boot) {
        let _ = store.write_log(
            log::Source::daemon(),
            voboost_contract::runtime_log::Record {
                level: log::Level::Error,
                component: "native".into(),
                message: "Native configuration unavailable".into(),
                fields: std::collections::HashMap::from([("reason".into(), error.to_string())]),
            },
        );
    }
    let mut timing = BTreeMap::from([(
        "startupDurationMs".into(),
        started.elapsed().as_millis().to_string(),
    )]);
    match (started_boot, startup::boot_ms()) {
        (Ok(start), Ok(ready)) if ready >= start => {
            timing.insert("processStartedBootMs".into(), start.to_string());
            timing.insert("endpointReadyBootMs".into(), ready.to_string());
        }
        (Err(error), _) | (_, Err(error)) => {
            timing.insert("bootClockUnavailable".into(), error.to_string());
        }
        _ => {
            timing.insert(
                "bootClockUnavailable".into(),
                "kernel boot clock regressed".into(),
            );
        }
    }
    store.write_log(
        log::Source::daemon(),
        voboost_contract::runtime_log::Record {
            level: log::Level::Debug,
            component: "owner".into(),
            message: "storage endpoint available".into(),
            fields: timing.into_iter().collect(),
        },
    )?;
    qnx_log::start(Path::new(config::ROOT_ZONE), &boot, logger);
    while !STOP.load(Ordering::Relaxed) {
        // A producer that died before confirming must not leave a source admitted.
        store.expire_withdrawals();
        native.configure(store.native_configured());
        if store.take_pw_drain() {
            native.begin_pw_readback();
        }
        let mut events = native.poll();
        events.extend(native.step(&mut store));
        store.observe_pw(native.pw_source_epoch(), native.pw_sample());
        for event in events {
            if let native::Event::Datagram {
                capture,
                sequence,
                epoch,
            } = event
            {
                let _ = store.write_native_can_log(capture.records(sequence, epoch));
                continue;
            }
            let level = if matches!(
                &event,
                native::Event::Controller { result: Err(_), .. }
                    | native::Event::InputsUnavailable {
                        expected: false,
                        ..
                    }
                    | native::Event::TransmitterUnavailable {
                        expected: false,
                        ..
                    }
                    | native::Event::CapabilityUnavailable { .. }
                    | native::Event::ReceiverUnavailable(_)
            ) {
                log::Level::Error
            } else {
                log::Level::Debug
            };
            let (message, mut fields) = match event {
                native::Event::Datagram { .. } => unreachable!("raw receive handled above"),
                native::Event::InputsUnavailable { reason, .. } => (
                    "native OEM inputs unavailable",
                    BTreeMap::from([("reason".into(), reason)]),
                ),
                native::Event::TransmitterUnavailable { reason, .. } => (
                    "native CAN transmitter unavailable",
                    BTreeMap::from([("reason".into(), reason)]),
                ),
                native::Event::CapabilityUnavailable { source, reason } => (
                    "native agent capability unavailable",
                    BTreeMap::from([("agent".into(), source.into()), ("reason".into(), reason)]),
                ),

                native::Event::Controller { source, result } => (
                    "native controller state changed",
                    BTreeMap::from([
                        ("agent".into(), source.into()),
                        ("result".into(), format!("{result:?}")),
                    ]),
                ),
                native::Event::ReceiverAvailable => {
                    ("native CAN receiver available", BTreeMap::new())
                }
                native::Event::ReceiverUnavailable(reason) => (
                    "native CAN receiver unavailable",
                    BTreeMap::from([("reason".into(), reason)]),
                ),
                native::Event::Sample { source, key, value } => (
                    "native CAN sample received",
                    BTreeMap::from([
                        ("agent".into(), source.into()),
                        ("signal".into(), key.into()),
                        ("value".into(), value.to_string()),
                    ]),
                ),
            };
            match startup::boot_ms() {
                Ok(observed) => {
                    fields.insert("observedBootMs".into(), observed.to_string());
                }
                Err(error) => {
                    fields.insert("observationClockUnavailable".into(), error.to_string());
                }
            }
            let _ = store.write_log(
                log::Source::daemon(),
                voboost_contract::runtime_log::Record {
                    level,
                    component: "native".into(),
                    message: message.into(),
                    fields: fields.into_iter().collect(),
                },
            );
        }
        if Instant::now() >= maintenance_at {
            let result = store.maintain_logs();
            if result.is_err() && !maintenance_failed {
                let _ = store.write_log(
                    log::Source::daemon(),
                    voboost_contract::runtime_log::Record {
                        level: log::Level::Error,
                        component: "logs".into(),
                        message: "Log retention is unavailable".into(),
                        fields: Default::default(),
                    },
                );
            }
            maintenance_failed = result.is_err();
            maintenance_at = Instant::now() + Duration::from_secs(60);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // A rejected client exchange used to be dropped silently, so
                // the closed client only ever saw "owner frame ended". The
                // refusing stage is logged once per connection; each CLI
                // connection is bounded, so the record stays bounded too.
                if let Err(error) = serve(&mut stream, &mut store, &mut native) {
                    let _ = store.write_log(
                        log::Source::daemon(),
                        voboost_contract::runtime_log::Record {
                            level: log::Level::Error,
                            component: "owner".into(),
                            message: "client exchange rejected".into(),
                            fields: std::collections::HashMap::from([(
                                "reason".into(),
                                error.to_string(),
                            )]),
                        },
                    );
                }
            }
            Err(e) if e.kind() == stdio::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) if e.kind() == stdio::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    store.write_log(
        log::Source::daemon(),
        voboost_contract::runtime_log::Record {
            level: log::Level::Debug,
            component: "owner".into(),
            message: "storage endpoint stopped".into(),
            fields: Default::default(),
        },
    )?;
    Ok(())
}
fn serve(
    stream: &mut UnixStream,
    store: &mut server::Store,
    native: &mut native::Runtime,
) -> stdio::Result<()> {
    let producer = match peer::process_identity(stream) {
        Ok(value) => Some(value),
        // The bounded-su kernel (free-09-chinese 6.0.3) denies the owner's
        // /proc/<pid>/stat read of an adb-spawned CLI peer even as root —
        // the same restriction resident_inject_status already documents for
        // task hooks and the exe link. The producer incarnation then cannot
        // be observed, but the peer is still SO_PEERCRED-bound to pid:0:0
        // and the role check below verifies the exact installed executable
        // signature. Those CLI exchanges are the fixed adb administration
        // surface (--inspect-installed and siblings) of the same signed
        // binary the resident runs; admit them with an unverified-incarnation
        // producer so its api journal records the limitation instead of
        // dropping the only diagnostic channel available on that kernel.
        Err(error)
            if error.kind() == stdio::ErrorKind::PermissionDenied
                && error.to_string().starts_with("peer stat:") =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let role = peer::verify_roles(
        stream,
        &[NativeExecutableRole::Daemon, NativeExecutableRole::Inject],
    )?;
    if let Some(bound) = producer {
        if bound != peer::process_identity(stream)? {
            return Err(stdio::Error::new(
                stdio::ErrorKind::PermissionDenied,
                "owner peer incarnation changed",
            ));
        }
    }
    // A missing incarnation is never substituted with a synthetic one: the
    // producer identity is authoritative input for the commands that bind a
    // user choice, and Input::bound() rejects a placeholder. The unverified
    // path is therefore admitted only for the read-only administration
    // surface, and any producer-bound command is refused with a named stage.
    serve_admitted_with_producer(stream, store, role, producer, Some(native))
}

/// Commands whose durable result binds the producing process incarnation.
fn producer_required(command: &voboost_contract::runtime_owner::Command) -> bool {
    use voboost_contract::runtime_owner::Command;
    matches!(
        command,
        Command::ElectricClick { .. }
            | Command::SaveDesired { .. }
            | Command::SaveLauncherDesired { .. }
            | Command::ConfirmAgentWithdrawn { .. }
            | Command::SaveStartupRecovery { .. }
            | Command::SetStartup { .. }
            | Command::BeginNativeStateOutage { .. }
            | Command::SnapshotNativeStateOutage { .. }
            | Command::ReleaseNativeStateOutage { .. }
            | Command::CloseNativeStateOutage { .. }
    )
}

#[cfg(test)]
fn serve_admitted(
    stream: &mut UnixStream,
    store: &mut server::Store,
    role: NativeExecutableRole,
) -> stdio::Result<()> {
    serve_admitted_with_producer(stream, store, role, Some((42, 100)), None)
}

fn serve_admitted_with_producer(
    stream: &mut UnixStream,
    store: &mut server::Store,
    role: NativeExecutableRole,
    producer: Option<(i32, u64)>,
    native: Option<&mut native::Runtime>,
) -> stdio::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(500);
    let greeting = Reply {
        schema_version: SCHEMA,
        session: store.session().into(),
        request_id: 0,
        outcome: Outcome::Ready {},
    };
    io::write(
        stream,
        &serde_json::to_vec(&greeting).map_err(stdio::Error::other)?,
        deadline,
    )?;
    let bytes = io::read(stream, deadline)?;
    let request = Request::decode(&bytes).map_err(stdio::Error::other)?;
    if !client_command_allowed(role, &request.command) {
        return Err(stdio::Error::new(
            stdio::ErrorKind::PermissionDenied,
            "owner client command rejected",
        ));
    }
    let producer = match (producer, producer_required(&request.command)) {
        (Some(producer), _) => producer,
        (None, false) => (0, 0),
        (None, true) => {
            return Err(stdio::Error::new(
                stdio::ErrorKind::PermissionDenied,
                "owner peer incarnation unavailable for a producer-bound command",
            ))
        }
    };
    let reply = match (&request.command, native) {
        (voboost_contract::runtime_owner::Command::ReadNativeCan { cursor }, Some(native)) => {
            native.touch_rx();
            Reply {
                schema_version: SCHEMA,
                session: store.session().into(),
                request_id: request.request_id,
                outcome: Outcome::NativeCan {
                    value: native.rx_snapshot(*cursor, store.native_boot(), store.session()),
                },
            }
        }
        (
            voboost_contract::runtime_owner::Command::ElectricClick {
                input,
                poll,
                cancel,
            },
            Some(native),
        ) => {
            let mut input = input.clone();
            input.injector_pid = producer.0;
            input.injector_starttime = producer.1;
            let status = if request.session == store.session()
                && store.native_boot() == input.boot_id.as_str()
            {
                native.electric_click_request(store, input, *poll, *cancel)
            } else {
                voboost_contract::runtime_owner::ElectricClickStatus::Unknown
            };
            Reply {
                schema_version: SCHEMA,
                session: store.session().into(),
                request_id: request.request_id,
                outcome: Outcome::ElectricClick { result: status },
            }
        }
        _ => store.dispatch_from(request, producer),
    };
    io::write(
        stream,
        &serde_json::to_vec(&reply).map_err(stdio::Error::other)?,
        deadline,
    )
}
fn client_command_allowed(
    role: NativeExecutableRole,
    command: &voboost_contract::runtime_owner::Command,
) -> bool {
    match role {
        NativeExecutableRole::Inject => !matches!(
            command,
            voboost_contract::runtime_owner::Command::SetStartup { .. }
        ),
        NativeExecutableRole::Daemon => matches!(
            command,
            voboost_contract::runtime_owner::Command::ReadLogSession {}
                | voboost_contract::runtime_owner::Command::ReadNativeCan { .. }
                | voboost_contract::runtime_owner::Command::SetStartup { .. }
        ),
        _ => false,
    }
}

#[cfg(test)]
mod client_authorization_tests {
    use super::*;
    use voboost_contract::runtime_owner::Command;
    #[test]
    fn native_can_read_uses_the_authenticated_owner_exchange() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut store =
            server::Store::new(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut native = native::Runtime::default();
            serve_admitted_with_producer(
                &mut server,
                &mut store,
                NativeExecutableRole::Daemon,
                None,
                Some(&mut native),
            )
            .unwrap();
        });
        let result = io::request::<voboost_contract::runtime_owner::Outcome>(
            &mut client,
            Command::ReadNativeCan { cursor: 0 },
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        let Outcome::NativeCan { value } = result else {
            panic!("wrong outcome")
        };
        assert_eq!(value["producer"], "actual_kernel_rx");
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["writerId"], "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        worker.join().unwrap();
    }
    #[test]
    fn electric_click_owner_wire_binds_producer_and_replay() {
        use voboost_contract::runtime_owner::ElectricClickStatus;
        let root = tempfile::Builder::new()
            .prefix(".fev-owner-wire-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut store = server::Store::new(root.path(), &"d".repeat(32)).unwrap();
        store
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        let mut pairs = Vec::new();
        for _ in 0..3 {
            pairs.push(UnixStream::pair().unwrap());
        }
        let (clients, servers): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let worker = std::thread::spawn(move || {
            let mut native = native::Runtime::default();
            for mut server in servers {
                serve_admitted_with_producer(
                    &mut server,
                    &mut store,
                    NativeExecutableRole::Inject,
                    Some((42, 100)),
                    Some(&mut native),
                )
                .unwrap();
            }
        });
        for (index, mut client) in clients.into_iter().enumerate() {
            let input = voboost_contract::desired::Input {
                boot_id: "11111111-1111-4111-8111-111111111111".into(),
                endpoint_epoch: if index == 2 { 8 } else { 7 },
                request_id: 10,
                injector_pid: 0,
                injector_starttime: 0,
            };
            let result = io::request::<voboost_contract::runtime_owner::Outcome>(
                &mut client,
                Command::ElectricClick {
                    input,
                    poll: index != 0,
                    cancel: false,
                },
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
            let Outcome::ElectricClick { result } = result else {
                panic!("wrong outcome")
            };
            assert_eq!(
                result,
                if index == 2 {
                    ElectricClickStatus::Drained
                } else {
                    ElectricClickStatus::NotSubmitted
                }
            );
        }
        worker.join().unwrap();
    }

    /// Exercises the real framed owner dispatcher and controller hooks. Host
    /// fixture bypasses peer signature admission and Android marker authority.
    #[test]
    fn native_outage_wire_hooks_release_and_replay_are_one_owner_session() {
        use crate::native::Host;
        use crate::native_api::{Lease, Progress, Read, Wait};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut store = server::Store::new(root.path(), &"d".repeat(32)).unwrap();
        store.arm_outage_fixture();
        fn exchange(store: &mut server::Store, command: Command, producer: (i32, u64)) -> Outcome {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    let mut native = native::Runtime::default();
                    serve_admitted_with_producer(
                        &mut server,
                        store,
                        NativeExecutableRole::Inject,
                        Some(producer),
                        Some(&mut native),
                    )
                    .unwrap();
                });
                let result = io::request::<voboost_contract::runtime_owner::Outcome>(
                    &mut client,
                    command,
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
                worker.join().unwrap();
                result
            })
        }
        let token = "a".repeat(64);
        let snapshot = || Command::SnapshotNativeStateOutage {
            token: token.clone(),
        };
        assert!(matches!(
            exchange(&mut store, snapshot(), (42, 101)),
            Outcome::Unavailable {}
        ));
        assert!(matches!(
            exchange(
                &mut store,
                Command::CloseNativeStateOutage {
                    token: token.clone()
                },
                (42, 100)
            ),
            Outcome::Unavailable {}
        ));
        for _ in 0..2 {
            assert!(store.diagnostic_state_read(
                "vehicle-drive-pedestrian-warning",
                Lease { revision: 7 },
                "pedestrian-warning-disarm-pending"
            ));
            store.diagnostic_progress(
                "vehicle-drive-pedestrian-warning",
                Lease { revision: 7 },
                Ok(Progress::Waiting(Wait::State)),
            );
        }
        let Outcome::NativeStateOutage { receipt: pending } =
            exchange(&mut store, snapshot(), (42, 100))
        else {
            panic!("missing pending receipt")
        };
        assert_eq!(
            (
                pending.reads,
                pending.dropped_reads,
                pending.wait_state_steps
            ),
            (2, 2, 2)
        );
        store.diagnostic_stopped("vehicle-drive-pedestrian-warning");
        let Outcome::NativeStateOutage { receipt: stopped } =
            exchange(&mut store, snapshot(), (42, 100))
        else {
            panic!("missing stop receipt")
        };
        assert!(stopped.stopped);
        let Outcome::NativeStateOutage { receipt: released } = exchange(
            &mut store,
            Command::ReleaseNativeStateOutage {
                token: token.clone(),
            },
            (42, 100),
        ) else {
            panic!("missing release")
        };
        assert!(released.released);
        assert!(!store.diagnostic_state_read(
            "vehicle-drive-pedestrian-warning",
            Lease { revision: 8 },
            "pedestrian-warning-armed"
        ));
        store.diagnostic_state_read_complete(
            "vehicle-drive-pedestrian-warning",
            Lease { revision: 8 },
            "pedestrian-warning-armed",
            &Read::Value(false),
        );
        let Outcome::NativeStateOutage { receipt: recovered } =
            exchange(&mut store, snapshot(), (42, 100))
        else {
            panic!("missing recovery")
        };
        assert_eq!(
            (recovered.recovered_values, recovered.recovered_value),
            (1, Some(false))
        );
        let Outcome::NativeStateOutage { receipt: terminal } = exchange(
            &mut store,
            Command::CloseNativeStateOutage {
                token: token.clone(),
            },
            (42, 100),
        ) else {
            panic!("missing terminal")
        };
        assert!(terminal.closed);
        assert!(matches!(
            exchange(&mut store, snapshot(), (42, 100)),
            Outcome::Unavailable {}
        ));
        assert!(matches!(
            exchange(
                &mut store,
                Command::BeginNativeStateOutage {
                    token: token.clone()
                },
                (42, 100)
            ),
            Outcome::Unavailable {}
        ));
        assert!(!client_command_allowed(
            NativeExecutableRole::Daemon,
            &snapshot()
        ));
    }

    #[test]
    fn daemon_cli_has_only_declared_log_and_startup_authority() {
        assert!(client_command_allowed(
            NativeExecutableRole::Daemon,
            &Command::ReadLogSession {}
        ));
        assert!(client_command_allowed(
            NativeExecutableRole::Daemon,
            &Command::SetStartup {
                startup: "none".into()
            }
        ));
        assert!(!client_command_allowed(
            NativeExecutableRole::Inject,
            &Command::SetStartup {
                startup: "none".into()
            }
        ));
        let captured = voboost_contract::runtime_owner::CapturedIntent {
            schema_version: 1,
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            capture_ns: 1,
            pid: 10,
            request_id: 1,
            choice: "off".into(),
            pending: true,
        };
        assert!(!client_command_allowed(
            NativeExecutableRole::Daemon,
            &Command::PrepareIntent {
                source: "agent".into(),
                key: "intent".into(),
                record: captured.clone(),
            }
        ));
        let mut completed = captured;
        completed.pending = false;
        assert!(!client_command_allowed(
            NativeExecutableRole::Daemon,
            &Command::FinishIntent {
                source: "agent".into(),
                key: "intent".into(),
                record: completed,
            }
        ));
        for command in [
            Command::ReadConfig {},
            Command::RecoverIntent {
                source: "agent".into(),
                key: "intent".into(),
            },
            Command::WriteState {
                source: "agent".into(),
                key: "value".into(),
                value: true.into(),
            },
            Command::ReplaceConfig {
                expected: None,
                next: "{}".into(),
            },
            Command::PublishInjectionStatus { bytes: "{}".into() },
        ] {
            assert!(!client_command_allowed(
                NativeExecutableRole::Daemon,
                &command
            ));
            assert!(client_command_allowed(
                NativeExecutableRole::Inject,
                &command
            ));
        }
        assert!(!client_command_allowed(
            NativeExecutableRole::Install,
            &Command::ReadLogSession {}
        ));
    }
}
