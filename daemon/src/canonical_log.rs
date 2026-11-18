use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::secure_fs::Directory;
use voboost_contract::runtime_log::redact;
pub use voboost_contract::runtime_log::{AppBatch, Level, Record as ProducerRecord, Source};

pub const MAX_RECORD_BYTES: usize = 16 * 1024;
pub const MAX_BATCH_RECORDS: usize = 64;
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
pub const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SEGMENTS: usize = 16;
// The bounded directory also contains fixed non-canonical publications.
// Temporary names are reserved for interrupted atomic publication/recovery;
// none of these files are exported as canonical records.
const LOG_AUXILIARY_NAMES: [&str; 9] = [
    "helper-error.log",
    "remount-dbg.log",
    "accepted-batches",
    "accepted-batch.pending",
    ".accepted-batches.tmp",
    ".accepted-batch.pending.tmp",
    ".segment-active.jsonl.tmp",
    "product-system-error.json",
    ".product-system-error.json.tmp",
];
const MAX_LOG_DIRECTORY_ENTRIES: usize =
    MAX_SEGMENTS + LOG_AUXILIARY_NAMES.len() + 4 + crate::log_archive::MAX_SESSIONS;
pub const MAX_QUERY_RECORDS: usize = 200;
pub const MAX_QUERY_BYTES: usize = 256 * 1024;
pub use crate::log_export::{encode as encode_export, MAX_EXPORT_BYTES};
// Retention/export growth must not expand the app deduplication ledger.
const MAX_BATCH_LEDGER_BYTES: usize = 32 * 1024 * 1024;
/// Ledger admission bound: one accepted app batch (64 records max) is ~200
/// bytes of ledger line, so the 32 MiB ledger bound is exhausted long before
/// this admission ceiling is reached; refusing here admits no orphaning.
pub const MAX_ACCEPTED_BATCHES: usize = 4 * 1024 * 1024;
#[cfg(test)]
use crate::log_export::MAGIC;
static GLOBAL: OnceLock<Mutex<CanonicalLog>> = OnceLock::new();
static AGENT_RPC: OnceLock<Mutex<AgentRpcState>> = OnceLock::new();
thread_local! {
    static UPLINK_BATCH_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn in_uplink_batch() -> bool {
    UPLINK_BATCH_DEPTH.with(|depth| depth.get() != 0)
}

pub(crate) struct UplinkLogBatch(std::marker::PhantomData<std::rc::Rc<()>>);

pub(crate) fn begin_uplink_batch() -> UplinkLogBatch {
    UPLINK_BATCH_DEPTH.with(|depth| depth.set(depth.get() + 1));
    UplinkLogBatch(std::marker::PhantomData)
}

impl Drop for UplinkLogBatch {
    fn drop(&mut self) {
        let outer = UPLINK_BATCH_DEPTH.with(|depth| {
            depth.set(depth.get() - 1);
            depth.get() == 0
        });
        if outer && flush_global_batch().is_err() {
            crate::log::report_unavailable();
        }
    }
}

fn flush_global_batch() -> io::Result<()> {
    #[cfg(test)]
    if let Some(result) =
        TEST_LOG.with(|log| log.borrow_mut().as_mut().map(CanonicalLog::flush_pending))
    {
        return result;
    }
    match GLOBAL.get() {
        Some(log) => log
            .lock()
            .map_err(|_| invalid("canonical logger lock poisoned"))?
            .flush_pending(),
        None => Ok(()),
    }
}
/// The inject-owned app gateway. Two peer classes connect: the Voboost app
/// delivers canonical log batches and the Settings host delivers the
/// uninstall-request RPC; every accepted frame is attested per operation
/// through SO_PEERCRED plus the peer's exact process identity.
pub const DAEMON_SOCKET: &str = "/data/voboost/run/daemon.sock";
const APP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_APP_CMDLINE_BYTES: usize = 256;
const MAX_PACKAGES_LIST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RPC_OPERATION_BYTES: usize = 64;
/// The Settings host is the fixed system uid; only its process may deliver
/// the uninstall-request operation.
const SETTINGS_PEER_UID: u32 = 1000;
const SETTINGS_PEER_PROCESS: &[u8] = b"com.qinggan.app.setting";

pub fn init_global(directory: &str) -> io::Result<()> {
    #[cfg(test)]
    let _ = GLOBAL.set(Mutex::new(CanonicalLog::open(directory)?));
    #[cfg(not(test))]
    if directory != crate::config::LOG_DIR {
        return Err(invalid("log target rejected"));
    }
    start_app_listener(DAEMON_SOCKET)
}

/// Initialize the canonical logger WITHOUT the Android daemon socket:
/// the OEM offline test driver runs on a host (macOS/Linux CI) where
/// `/data/voboost/run` does not exist. Record append/query/RPC paths are
/// production; only the peer discovery transport is not started.
#[cfg(test)]
pub fn init_global_without_app_listener(directory: &str) -> io::Result<()> {
    let _ = GLOBAL.set(Mutex::new(CanonicalLog::open(directory)?));
    Ok(())
}

pub fn append_global(source: Source, record: ProducerRecord) -> io::Result<u64> {
    #[cfg(not(test))]
    {
        crate::owner_client::append_log(source, record)
    }
    #[cfg(test)]
    {
        if let Some(result) = TEST_LOG.with(|log| {
            log.borrow_mut()
                .as_mut()
                .map(|log| log.append_uplink(source.clone(), record.clone()))
        }) {
            return result;
        }
        GLOBAL
            .get()
            .ok_or_else(|| invalid("canonical logger is not initialized"))?
            .lock()
            .map_err(|_| invalid("canonical logger lock poisoned"))?
            .append_uplink(source, record)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_LOG: std::cell::RefCell<Option<CanonicalLog>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Scope only the host backing directory; append, canonical serialization,
/// source identity, bounds and persistence remain the production paths.
#[cfg(test)]
pub(crate) fn with_test_log<T>(directory: &std::path::Path, operation: impl FnOnce() -> T) -> T {
    struct RestoreLog(Option<CanonicalLog>);

    impl Drop for RestoreLog {
        fn drop(&mut self) {
            TEST_LOG.with(|log| *log.borrow_mut() = self.0.take());
        }
    }

    let log = CanonicalLog::open(directory).expect("open scoped host log");
    let _restore = RestoreLog(TEST_LOG.with(|current| current.replace(Some(log))));
    operation()
}

#[derive(Default)]
struct AgentRpcState {
    responses: HashMap<String, String>,
    subscriptions: HashSet<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireQuery {
    after_sequence: u64,
    limit: usize,
    sources: Vec<String>,
    agent_ids: Vec<String>,
    levels: Vec<Level>,
    from_epoch_millis: u64,
    to_epoch_millis: u64,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WireResponse<'a> {
    request_id: &'a str,
    next_sequence: u64,
    records: Vec<CanonicalRecord>,
}

pub fn dispatch_agent_rpc(
    operation: &str,
    request_id: &str,
    request_json: &str,
    resident_agent_ids: &HashSet<String>,
    selected_agent_ids: &HashSet<String>,
) -> io::Result<String> {
    if !valid_request_id(request_id) || !resident_agent_ids.contains("logs") {
        return Err(invalid("logs capability denied"));
    }
    let state = AGENT_RPC.get_or_init(|| Mutex::new(AgentRpcState::default()));
    let mut state = state
        .lock()
        .map_err(|_| invalid("logs RPC lock poisoned"))?;
    if operation == "logs-stop" {
        state.subscriptions.remove(request_id);
        state.responses.remove(request_id);
        return Ok(format!(
            r#"{{"requestId":"{request_id}","nextSequence":0,"records":[]}}"#
        ));
    }
    if operation != "logs-query" && operation != "logs-follow" {
        return Err(invalid("unknown logs operation"));
    }
    if let Some(response) = state.responses.get(request_id) {
        return Ok(response.clone());
    }
    if state.responses.len() >= 128 {
        return Err(invalid("stale logs request"));
    }
    let wire: WireQuery = serde_json::from_str(request_json).map_err(invalid_json)?;
    if wire.text.len() > 256
        || wire.from_epoch_millis > wire.to_epoch_millis
        || wire
            .agent_ids
            .iter()
            .any(|id| !valid_agent_id(id) || !selected_agent_ids.contains(id))
        || wire
            .sources
            .iter()
            .any(|value| !matches!(value.as_str(), "app" | "daemon" | "agent"))
    {
        return Err(invalid("invalid logs filters"));
    }
    let query = Query {
        after_sequence: wire.after_sequence,
        limit: wire.limit,
        levels: wire.levels,
        kinds: wire.sources,
        agent_ids: wire.agent_ids,
        search: (!wire.text.is_empty()).then_some(wire.text),
        from_epoch_millis: wire.from_epoch_millis,
        to_epoch_millis: wire.to_epoch_millis,
    };
    let mut response = GLOBAL
        .get()
        .ok_or_else(|| invalid("canonical logger is not initialized"))?
        .lock()
        .map_err(|_| invalid("canonical logger lock poisoned"))?
        .query(&query)?;
    let encoded = loop {
        let bytes = serde_json::to_vec(&WireResponse {
            request_id,
            next_sequence: response.cursor,
            records: response.records.clone(),
        })
        .map_err(invalid_json)?;
        if bytes.len() + request_id.len() + 8 <= crate::config::MAX_DOWNLINK_FRAME_BYTES {
            break String::from_utf8(bytes).map_err(|_| invalid("logs response UTF-8"))?;
        }
        if response.records.pop().is_none() {
            return Err(invalid("logs response exceeds downlink bound"));
        }
        response.cursor = response
            .records
            .last()
            .map(|record| record.sequence)
            .unwrap_or(query.after_sequence);
    };
    if operation == "logs-follow" {
        state.subscriptions.insert(request_id.to_string());
    }
    state
        .responses
        .insert(request_id.to_string(), encoded.clone());
    Ok(encoded)
}

fn listener_startup_error(stage: &'static str, error: io::Error) -> io::Error {
    let cause = error
        .to_string()
        .chars()
        .take(256)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>();
    crate::log::err(
        "runtime-transport",
        &format!("daemon listener startup failed stage={stage}: {cause}"),
    );
    // Preserve caller-visible kind, raw errno and source; diagnosis is additive.
    error
}
fn listener_startup_stage(stage: &'static str) -> impl FnOnce(io::Error) -> io::Error {
    move |error| listener_startup_error(stage, error)
}
fn start_app_listener(path: &str) -> io::Result<()> {
    let path = PathBuf::from(path);
    let parent = path.parent().ok_or_else(|| {
        listener_startup_error("socket-parent", invalid("daemon socket has no parent"))
    })?;
    let run = Directory::open(parent).map_err(listener_startup_stage("run-open"))?;
    run.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )
    .map_err(listener_startup_stage("run-authority"))?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_socket() {
            return Err(listener_startup_error(
                "existing-socket-authority",
                invalid("daemon socket path is not a socket"),
            ));
        }
        fs::remove_file(&path).map_err(listener_startup_stage("remove-stale-socket"))?;
    }
    let app_uid =
        installed_app_uid("ru.voboost").map_err(listener_startup_stage("installed-app-uid"))?;
    let listener = UnixListener::bind(&path).map_err(listener_startup_stage("socket-bind"))?;
    let path_c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| listener_startup_error("socket-path", invalid("invalid socket path")))?;
    if unsafe { libc::lchown(path_c.as_ptr(), 0, app_uid) } != 0 {
        return Err(listener_startup_error(
            "socket-owner",
            io::Error::last_os_error(),
        ));
    }
    // World-writable connect: besides the Voboost app (own uid) the Settings
    // host (system uid 1000) connects to deliver its uninstall request. DAC
    // only admits the connection; SELinux confines connectto to the app and
    // system_app domains and every accepted frame is peer-attested below.
    fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o666))
        .map_err(listener_startup_stage("socket-mode"))?;
    let metadata =
        fs::symlink_metadata(&path).map_err(listener_startup_stage("socket-metadata"))?;
    use std::os::unix::fs::MetadataExt;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != app_uid
        || metadata.mode() & 0o777 != 0o666
    {
        return Err(listener_startup_error(
            "socket-authority",
            invalid("daemon socket authority mismatch"),
        ));
    }
    thread::Builder::new()
        .name("daemon-sock-ingress".into())
        .spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let _ = serve_app(&mut stream);
            }
        })
        .map_err(|error| listener_startup_error("ingress-thread", invalid(&error.to_string())))?;
    crate::launcher_page::start_management_relay()
        .map_err(listener_startup_stage("relay-thread"))?;
    Ok(())
}

fn serve_app(stream: &mut UnixStream) -> io::Result<()> {
    serve_app_with_timeout(stream, APP_CONNECTION_TIMEOUT)
}

fn serve_app_with_timeout(stream: &mut UnixStream, timeout: Duration) -> io::Result<()> {
    stream.set_write_timeout(Some(timeout))?;
    let credentials = peer_credentials(stream)?;
    let bytes = read_app_batch(stream, timeout)?;
    let ack = match classify_frame(&bytes)? {
        AppFrame::Rpc {
            request_id,
            operation,
        } => dispatch_socket_rpc(&operation, &request_id, credentials.0, credentials.1)?,
        AppFrame::Batch => {
            let verifier = ProcAppPeer;
            #[cfg(not(test))]
            {
                if !verifier.is_voboost_app(credentials.0, credentials.1) {
                    return Err(invalid("app peer mismatch"));
                }
                crate::owner_client::append_app_batch(&bytes)?
            }
            #[cfg(test)]
            GLOBAL
                .get()
                .ok_or_else(|| invalid("canonical logger is not initialized"))?
                .lock()
                .map_err(|_| invalid("canonical logger lock poisoned"))?
                .accept_app_batch(credentials.0, credentials.1, &verifier, &bytes)?
        }
    };
    stream.write_all(&(ack.len() as u32).to_be_bytes())?;
    stream.write_all(ack.as_bytes())?;
    stream.flush()
}

/// One framed daemon-socket payload: either a canonical app log batch or an
/// RPC request envelope. The exact-field RPC envelope can never parse as a
/// batch (no overlapping required fields), so classification is total.
enum AppFrame {
    Batch,
    Rpc {
        request_id: String,
        operation: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRpc {
    request_id: String,
    operation: String,
}

fn classify_frame(bytes: &[u8]) -> io::Result<AppFrame> {
    match serde_json::from_slice::<WireRpc>(bytes) {
        Ok(wire) => {
            if !valid_request_id(&wire.request_id)
                || wire.operation.is_empty()
                || wire.operation.len() > MAX_RPC_OPERATION_BYTES
                || !wire
                    .operation
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            {
                return Err(invalid("invalid daemon rpc frame"));
            }
            Ok(AppFrame::Rpc {
                request_id: wire.request_id,
                operation: wire.operation,
            })
        }
        Err(_) => Ok(AppFrame::Batch),
    }
}

/// Per-operation peer attestation for daemon-socket RPC. The Settings host
/// proves itself with the fixed system uid plus its exact process name.
pub trait SettingsPeerVerifier {
    fn is_settings_host(&self, uid: u32, pid: u32) -> bool;
}

struct ProcSettingsPeer;
impl SettingsPeerVerifier for ProcSettingsPeer {
    fn is_settings_host(&self, uid: u32, pid: u32) -> bool {
        uid == SETTINGS_PEER_UID
            && pid != 0
            && read_bounded_file(format!("/proc/{pid}/cmdline"), MAX_APP_CMDLINE_BYTES)
                .ok()
                .and_then(|bytes| bytes.split(|b| *b == 0).next().map(|v| v.to_vec()))
                .map(|name| name == SETTINGS_PEER_PROCESS)
                .unwrap_or(false)
    }
}

/// Dispatch one daemon-socket RPC operation. Answers use the fixed envelope
/// `{"requestId","accepted","reason"}` with reasons limited to "busy" and
/// "wrong-peer"; anything else about the frame or operation is a stream
/// error the client must treat as not accepted.
fn dispatch_socket_rpc(
    operation: &str,
    request_id: &str,
    uid: u32,
    pid: u32,
) -> io::Result<String> {
    dispatch_socket_rpc_with_peer(operation, request_id, uid, pid, &ProcSettingsPeer)
}

#[cfg(test)]
#[test]
fn launcher_observation_socket_refuses_foreign_peer_and_bad_nonce() {
    assert!(dispatch_socket_rpc("launcher-page-observe", &"a".repeat(64), 1000, 10).is_err());
    assert!(dispatch_socket_rpc("launcher-page-observe", &"a".repeat(64), 0, 0).is_err());
    assert!(dispatch_socket_rpc("launcher-page-observe", "bad", 0, 10).is_err());
    assert!(dispatch_socket_rpc("launcher-page-eval", &"a".repeat(64), 0, 10).is_err());
}

fn dispatch_socket_rpc_with_peer(
    operation: &str,
    request_id: &str,
    uid: u32,
    pid: u32,
    peer: &dyn SettingsPeerVerifier,
) -> io::Result<String> {
    if operation == "launcher-page-observe" {
        if uid != 0 || pid == 0 || !crate::launcher_page::valid_nonce(request_id) {
            return Err(invalid(
                "launcher observation requires root and strict nonce",
            ));
        }
        return crate::launcher_page::request(request_id).map_err(|error| invalid(&error));
    }
    if operation != "uninstall-request" {
        return Err(invalid("unknown daemon rpc operation"));
    }
    if !peer.is_settings_host(uid, pid) {
        return Ok(format!(
            r#"{{"requestId":"{request_id}","accepted":false,"reason":"wrong-peer"}}"#
        ));
    }
    // The emulator operator may lose one authenticated transport before any
    // durable removal request. Peer authority and all ordinary admission stay intact.
    if crate::emulator_diagnostic::drop_uninstall_transport(uid, pid, request_id) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "emulator uninstall transport loss",
        ));
    }
    match crate::uninstall::handle_settings_request() {
        Ok(()) => Ok(format!(r#"{{"requestId":"{request_id}","accepted":true}}"#)),
        Err(error) if error == "uninstall already requested" => Ok(format!(
            r#"{{"requestId":"{request_id}","accepted":false,"reason":"busy"}}"#
        )),
        Err(error) => {
            crate::log::err(
                "uninstall",
                &format!("request could not be retained: {error}"),
            );
            Ok(format!(
                r#"{{"requestId":"{request_id}","accepted":false,"reason":"unavailable"}}"#
            ))
        }
    }
}

#[cfg(test)]
pub(crate) fn diagnostic_uninstall_test() {
    struct Peer(bool);
    impl SettingsPeerVerifier for Peer {
        fn is_settings_host(&self, _: u32, _: u32) -> bool {
            self.0
        }
    }
    crate::uninstall::reset_settings_request_for_test();
    let pid = std::process::id();
    crate::emulator_diagnostic::with_test_window("uninstall-transport-loss", pid as i32, || {
        assert!(dispatch_socket_rpc_with_peer(
            "uninstall-request",
            "untrusted",
            1000,
            pid,
            &Peer(false)
        )
        .unwrap()
        .contains("wrong-peer"));
        assert!(!crate::uninstall::settings_request_accepted());
        assert_eq!(
            dispatch_socket_rpc_with_peer("uninstall-request", "first", 1000, pid, &Peer(true))
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(!crate::uninstall::settings_request_accepted());
        assert!(dispatch_socket_rpc_with_peer(
            "uninstall-request",
            "retry",
            1000,
            pid,
            &Peer(true)
        )
        .unwrap()
        .contains("\"accepted\":true"));
        assert!(crate::uninstall::settings_request_accepted());
    });
    crate::uninstall::reset_settings_request_for_test();
}

fn read_app_batch(stream: &mut UnixStream, timeout: Duration) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(timeout))?;
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_BATCH_BYTES {
        return Err(invalid("invalid app batch frame"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((credentials.uid, credentials.pid as u32))
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn peer_credentials(_stream: &UnixStream) -> io::Result<(u32, u32)> {
    Err(invalid("peer credentials require Android or Linux"))
}

struct ProcAppPeer;
impl PeerVerifier for ProcAppPeer {
    fn is_voboost_app(&self, uid: u32, pid: u32) -> bool {
        verify_installed_app_process(uid, pid).is_ok()
    }
}

pub(crate) fn installed_app_uid(package: &str) -> io::Result<u32> {
    let bytes = read_bounded_file("/data/system/packages.list", MAX_PACKAGES_LIST_BYTES)?;
    parse_installed_app_uid(&bytes, package)
}

pub(crate) fn verify_installed_app_peer(uid: u32, pid: u32) -> io::Result<()> {
    verify_app_peer(uid, pid, installed_app_uid("ru.voboost")?)
}

fn verify_app_peer(uid: u32, pid: u32, installed_uid: u32) -> io::Result<()> {
    if pid == 0 || !(10000..=19999).contains(&uid) || uid != installed_uid {
        return Err(invalid("installed Voboost app peer credentials differ"));
    }
    Ok(())
}

pub(crate) fn verify_installed_app_process(uid: u32, pid: u32) -> io::Result<()> {
    if uid == 0 || pid == 0 || installed_app_uid("ru.voboost")? != uid {
        return Err(invalid("installed Voboost app peer credentials differ"));
    }
    let cmdline = read_bounded_file(format!("/proc/{pid}/cmdline"), MAX_APP_CMDLINE_BYTES)
        .map_err(|error| {
            invalid(&format!(
                "installed Voboost app peer cmdline unavailable: {error}"
            ))
        })?;
    if cmdline.split(|byte| *byte == 0).next() != Some(b"ru.voboost") {
        return Err(invalid("installed Voboost app peer cmdline differs"));
    }
    Ok(())
}

fn read_bounded_file(path: impl AsRef<std::path::Path>, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("peer identity file exceeds bound"));
    }
    Ok(bytes)
}
fn parse_installed_app_uid(bytes: &[u8], package: &str) -> io::Result<u32> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("packages.list is not UTF-8"))?;
    let mut packages = std::collections::HashMap::<u32, usize>::new();
    let mut selected = None;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let name = fields
            .next()
            .ok_or_else(|| invalid("package name missing"))?;
        let uid = fields
            .next()
            .and_then(|field| field.parse::<u32>().ok())
            .ok_or_else(|| invalid("invalid package uid"))?;
        *packages.entry(uid).or_default() += 1;
        if name == package && selected.replace(uid).is_some() {
            return Err(invalid("duplicate package record"));
        }
    }
    let uid = selected.ok_or_else(|| invalid("installed package uid unavailable"))?;
    if !(10000..=19999).contains(&uid) || packages.get(&uid) != Some(&1) {
        return Err(invalid(
            "installed package requires an exclusive application uid",
        ));
    }
    Ok(uid)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingBatch {
    start_sequence: u64,
    batch: AppBatch,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalRecord {
    pub schema_version: u8,
    pub sequence: u64,
    pub timestamp: String,
    pub source: Source,
    pub level: Level,
    pub component: String,
    pub message: String,
    pub fields: HashMap<String, String>,
}

pub trait PeerVerifier {
    fn is_voboost_app(&self, uid: u32, pid: u32) -> bool;
}

/// Closed export-stage diagnosis. The source is retained locally, never emitted.
#[derive(Debug)]
struct ExportFailure {
    code: &'static str,
    source: io::Error,
}
impl std::fmt::Display for ExportFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for ExportFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
fn export_stage(code: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), ExportFailure { code, source })
}
pub fn export_failure_reason(error: &io::Error) -> &'static str {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ExportFailure>())
        .map(|failure| {
            if failure.code != "segment-read" {
                return failure.code;
            }
            // Only fixed secure-fs diagnostics are admitted. Never expose
            // arbitrary error text, paths, file contents, or record payloads.
            match failure.source.to_string().as_str() {
                "directory entry bound exceeded" => "segment-directory-entry-bound",
                "non-UTF8 directory entry" => "segment-directory-entry-encoding",
                "trusted entry is not a single-link regular file" => "segment-file-kind-or-links",
                "trusted entry has unexpected owner" => "segment-file-owner",
                "trusted entry has unexpected mode" => "segment-file-mode",
                "trusted file exceeds size bound" => "segment-file-size-bound",
                "trusted file size changed while reading" => "segment-file-size-changed",
                "trusted file metadata changed while reading" => "segment-file-metadata-changed",
                "export exceeds bound" => "segment-export-size-bound",
                _ => "segment-read",
            }
        })
        .unwrap_or("unknown")
}
pub fn export_failure_errno(error: &io::Error) -> Option<i32> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<ExportFailure>())
        .and_then(|failure| failure.source.raw_os_error())
        .or_else(|| error.raw_os_error())
}

// Independent retention: debug 128 MiB, info 128 MiB, error 128 MiB.
// Canonical exports merge identical sequences; the worst-case 384 MiB union
// leaves room for context within the widened 400 MiB protocol bound.
const SEVERITY_TIERS: [(&str, usize); 2] = [("info", 16), ("error", 16)];

pub struct CanonicalLog {
    authority: Directory,
    next_sequence: u64,
    accepted_batches: HashSet<String>,
    pending_file: Option<File>,
    append_failed: bool,
    pending_records: Vec<PreparedRecord>,
    pending_record_bytes: usize,
    #[cfg(test)]
    synchronizations: usize,
}

impl CanonicalLog {
    pub fn open(directory: impl Into<PathBuf>) -> io::Result<Self> {
        let directory = directory.into();
        repair_torn_segments(&directory)?;
        let authority = match Directory::open(&directory) {
            Ok(authority) => authority,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = directory
                    .parent()
                    .ok_or_else(|| invalid("log authority has no parent"))?;
                let name = directory
                    .file_name()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| invalid("log authority name is invalid"))?;
                Directory::open(parent)?.create_private_child(name)?
            }
            Err(error) => return Err(error),
        };
        authority.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        prepare_severity_tiers(&authority)?;
        recover_severity_pending(&authority)?;
        let mut records = read_segments(&authority)?;
        // Completed segment names sort sequence-descending (the open-bound
        // suffix), so the concatenation order from read_segments is NOT
        // append order; sequence-sort before scanning so next_sequence is the
        // true maximum and record scan order is canonical.
        records.sort_by_key(|record| record.sequence);
        let next_sequence = match records.last() {
            Some(record) => record
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("log sequence exhausted"))?,
            None => 1,
        };
        let accepted_batches = authority
            .read_trusted("accepted-batches", MAX_BATCH_LEDGER_BYTES, 0o600)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default()
            .lines()
            .filter(|line| valid_batch_id(line))
            .map(str::to_owned)
            .collect();
        let mut result = Self {
            authority,
            next_sequence,
            accepted_batches,
            pending_file: None,
            append_failed: false,
            pending_records: Vec::new(),
            pending_record_bytes: 0,
            #[cfg(test)]
            synchronizations: 0,
        };
        result.recover_pending_batch()?;
        Ok(result)
    }

    pub fn open_for_export(directory: impl Into<PathBuf>) -> io::Result<Self> {
        let directory = directory.into();
        let authority =
            Directory::open(&directory).map_err(|e| export_stage("directory-open", e))?;
        authority
            .validate_owner_mode(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o700,
            )
            .map_err(|e| export_stage("directory-authority", e))?;
        Ok(Self {
            authority,
            next_sequence: 1,
            accepted_batches: HashSet::new(),
            pending_file: None,
            append_failed: false,
            pending_records: Vec::new(),
            pending_record_bytes: 0,
            #[cfg(test)]
            synchronizations: 0,
        })
    }

    pub fn accept_app_batch(
        &mut self,
        uid: u32,
        pid: u32,
        verifier: &dyn PeerVerifier,
        bytes: &[u8],
    ) -> io::Result<String> {
        if !verifier.is_voboost_app(uid, pid) {
            return Err(invalid("app peer mismatch"));
        }
        if bytes.len() > MAX_BATCH_BYTES {
            return Err(invalid("app batch exceeds byte bound"));
        }
        let batch = AppBatch::decode(bytes).map_err(invalid)?;
        if self.accepted_batches.contains(&batch.batch_id) {
            return Ok(batch.batch_id);
        }
        // Reject internal conflicts and every producer record against the
        // canonical bounds BEFORE anything is durably written or the pending
        // intent is staged, so a bound failure cannot strand a half batch.
        let mut encoded = Vec::new();
        for (offset, record) in batch.records.iter().enumerate() {
            validate_producer(record)?;
            let prep = encode_canonical_line(
                Source {
                    kind: "app".into(),
                    id: None,
                },
                self.next_sequence + offset as u64,
                record,
            )?;
            encoded.push(prep);
        }
        // A full ledger refuses admission before any canonical record is
        // written, so no record is stranded when the ledger append would
        // fail deterministically anyway.
        {
            ensure_batch_ledger_slot(&self.authority, 1)?;
        }
        let pending = serde_json::to_vec(&PendingBatch {
            start_sequence: self.next_sequence,
            batch: batch.clone(),
        })
        .map_err(invalid_json)?;
        self.authority
            .write_atomic("accepted-batch.pending", &pending, 0o600)?;
        for prep in encoded {
            self.append_prepared(prep)?;
        }
        self.authority.append_trusted(
            "accepted-batches",
            format!("{}\n", batch.batch_id).as_bytes(),
            MAX_BATCH_LEDGER_BYTES as u64,
            0o600,
        )?;
        self.accepted_batches.insert(batch.batch_id.clone());
        self.authority.unlink("accepted-batch.pending")?;
        self.authority.sync_all()?;
        Ok(batch.batch_id)
    }

    fn recover_pending_batch(&mut self) -> io::Result<()> {
        let bytes = match self.authority.read_trusted(
            "accepted-batch.pending",
            MAX_BATCH_BYTES + 1024,
            0o600,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let pending: PendingBatch = serde_json::from_slice(&bytes).map_err(invalid_json)?;
        if self.accepted_batches.contains(&pending.batch.batch_id) {
            self.authority.unlink("accepted-batch.pending")?;
            self.authority.sync_all()?;
            return Ok(());
        }
        let existing = read_segments(&self.authority)?;
        // Any daemon-owned sequence inside the pending range means the
        // recovery intent is stale (a later daemon restart already moved the
        // sequence past it); the prior prefix is some other writer's data and
        // must not be absorbed into this batch, so the pending file is an
        // unreadable orphan.
        if existing
            .iter()
            .any(|record| record.source.kind != "app" && record.sequence >= pending.start_sequence)
        {
            return Err(invalid(
                "pending app batch conflicts with daemon-owned sequences",
            ));
        }
        // Count a leading prefix as present only when the durable record is
        // byte-identical to what this batch would have encoded, so an
        // unrelated daemon record that merely occupies the same sequence can
        // never be mistaken for batch progress (false ACK).
        let mut present = 0usize;
        for (offset, record) in pending.batch.records.iter().enumerate() {
            let durable = existing
                .iter()
                .find(|record| record.sequence == pending.start_sequence + offset as u64);
            // Match on content identity EXCLUDING the timestamp: a durable
            // prefix written by the previous process carries that process's
            // timestamp, so byte-equality could never hold and every restart
            // would re-append the whole prefix as duplicates.
            let same = match durable {
                Some(durable) => {
                    durable.schema_version == 1
                        && durable.level == record.level
                        && durable.component == record.component
                        && durable.message == redact(&record.message)
                        && durable.fields.len() == record.fields.len()
                        && durable.fields.iter().all(|(key, value)| {
                            record.fields.get(key).map(|v| v.as_str()) == Some(value.as_str())
                        })
                }
                None => false,
            };
            if same {
                present += 1;
            } else {
                break;
            }
        }
        if present < pending.batch.records.len()
            && existing
                .iter()
                .any(|record| record.sequence >= pending.start_sequence + present as u64)
        {
            return Err(invalid(
                "pending app batch sequence range is not contiguous",
            ));
        }
        self.next_sequence = pending.start_sequence + present as u64;
        for record in pending.batch.records.iter().skip(present).cloned() {
            self.append(
                Source {
                    kind: "app".into(),
                    id: None,
                },
                record,
            )?;
        }
        self.authority.append_trusted(
            "accepted-batches",
            format!("{}\n", pending.batch.batch_id).as_bytes(),
            MAX_BATCH_LEDGER_BYTES as u64,
            0o600,
        )?;
        self.accepted_batches.insert(pending.batch.batch_id);
        self.authority.unlink("accepted-batch.pending")?;
        self.authority.sync_all()
    }

    /// Append one record whose canonical line is already durably encoded and
    /// bound-checked; the caller must leave `next_sequence` pointing at it.
    /// The timestamped canonical form comes from `prep`, so an interrupted
    /// batch retries with byte-identical content instead of minting a fresh
    /// timestamp that would leave divergent duplicates after recovery.
    fn append_prepared(&mut self, prep: PreparedRecord) -> io::Result<u64> {
        self.append_prepared_with_durability(prep, true)
    }

    fn append_prepared_with_durability(
        &mut self,
        prep: PreparedRecord,
        durable: bool,
    ) -> io::Result<u64> {
        if !self.pending_records.is_empty() {
            self.flush_pending()?;
        }
        if self.append_failed {
            return Err(invalid(
                "canonical writer requires recovery after append failure",
            ));
        }
        let _snapshot_lock = self.authority.lock_transaction(Duration::from_secs(2))?;
        let sequence = prep.sequence;
        if sequence == u64::MAX {
            return Err(invalid("log sequence exhausted"));
        }
        let record: CanonicalRecord = serde_json::from_slice(&prep.line).map_err(invalid_json)?;
        let retained = record.level != Level::Debug;
        // Persist the exact canonical bytes BEFORE any fanout. Recovery fills
        // missing copies rather than generating fresh timestamps/sequences.
        if retained {
            if let Err(error) = self
                .authority
                .write_atomic("severity.pending", &prep.line, 0o600)
            {
                self.append_failed = true;
                return Err(error);
            }
        }
        let result = (|| {
            self.rotate_for(prep.line.len() as u64)?;
            let file = self.authority.append_trusted_with_durability(
                "segment-active.jsonl",
                &prep.line,
                MAX_SEGMENT_BYTES,
                0o600,
                self.pending_file.as_ref(),
                durable || retained,
            )?;
            self.pending_file = if durable || retained {
                #[cfg(test)]
                {
                    self.synchronizations += 1;
                }
                None
            } else {
                Some(file)
            };
            if retained {
                finish_severity_fanout(&self.authority, &prep.line, &record, false)?;
                self.authority.unlink("severity.pending")?;
                self.authority.sync_all()?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            // A partial fanout may already own this sequence. Never admit a
            // different record until reopen has completed its pending intent.
            self.append_failed = true;
            return Err(error);
        }
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("log sequence exhausted"))?;
        Ok(sequence)
    }

    pub fn append(&mut self, source: Source, record: ProducerRecord) -> io::Result<u64> {
        validate_source(&source)?;
        validate_producer(&record)?;
        let prep = encode_canonical_line(source, self.next_sequence, &record)?;
        self.append_prepared(prep)
    }

    #[cfg(test)]
    fn append_uplink(&mut self, source: Source, record: ProducerRecord) -> io::Result<u64> {
        validate_source(&source)?;
        validate_producer(&record)?;
        let prepared = encode_canonical_line(source, self.next_sequence, &record)?;
        if in_uplink_batch() && (record.level != Level::Debug || !self.pending_records.is_empty()) {
            if self.append_failed {
                return Err(invalid(
                    "canonical writer requires recovery after append failure",
                ));
            }
            if self.pending_records.len() == MAX_BATCH_RECORDS
                || self.pending_record_bytes + prepared.line.len() > MAX_BATCH_BYTES
            {
                self.flush_pending()?;
            }
            let sequence = prepared.sequence;
            self.next_sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid("log sequence exhausted"))?;
            self.pending_record_bytes += prepared.line.len();
            self.pending_records.push(prepared);
            return Ok(sequence);
        }
        self.append_prepared_with_durability(prepared, !in_uplink_batch())
    }

    fn flush_pending(&mut self) -> io::Result<()> {
        if !self.pending_records.is_empty() {
            self.flush_record_group()?;
        }
        if let Some(file) = &self.pending_file {
            self.authority
                .sync_trusted_append("segment-active.jsonl", 0o600, file)?;
            #[cfg(test)]
            {
                self.synchronizations += 1;
            }
            self.pending_file = None;
        }
        Ok(())
    }

    fn flush_record_group(&mut self) -> io::Result<()> {
        if self.append_failed {
            return Err(invalid(
                "canonical writer requires recovery after append failure",
            ));
        }
        let _snapshot_lock = self.authority.lock_transaction(Duration::from_secs(2))?;
        let records = std::mem::take(&mut self.pending_records);
        self.pending_record_bytes = 0;
        let bytes: Vec<u8> = records
            .iter()
            .flat_map(|record| record.line.iter().copied())
            .collect();
        let result = (|| {
            self.authority
                .write_atomic("severity.pending", &bytes, 0o600)?;
            let mut tier_files: [Option<File>; 2] = [None, None];
            for prepared in records {
                self.rotate_for(prepared.line.len() as u64)?;
                self.pending_file = Some(self.authority.append_trusted_with_durability(
                    "segment-active.jsonl",
                    &prepared.line,
                    MAX_SEGMENT_BYTES,
                    0o600,
                    self.pending_file.as_ref(),
                    false,
                )?);
                let record: CanonicalRecord =
                    serde_json::from_slice(&prepared.line).map_err(invalid_json)?;
                if record.level == Level::Debug {
                    continue;
                }
                for (index, (name, maximum)) in SEVERITY_TIERS.into_iter().enumerate() {
                    if name == "error" && record.level != Level::Error {
                        continue;
                    }
                    let tier = open_severity_tier(&self.authority, name)?;
                    tier_files[index] = append_tier_unflushed(
                        &tier,
                        &prepared.line,
                        prepared.sequence,
                        maximum,
                        false,
                        false,
                    )?;
                }
            }
            // One durable group commit, before the outer UplinkLogBatch ends.
            self.flush_pending()?;
            for (index, (name, _)) in SEVERITY_TIERS.into_iter().enumerate() {
                if let Some(file) = &tier_files[index] {
                    let tier = open_severity_tier(&self.authority, name)?;
                    tier.sync_trusted_append("segment-active.jsonl", 0o600, file)?;
                    tier.sync_all()?;
                }
            }
            self.authority.unlink("severity.pending")?;
            self.authority.sync_all()
        })();
        if result.is_err() {
            self.append_failed = true;
        }
        result
    }

    fn rotate_for(&mut self, incoming: u64) -> io::Result<()> {
        let size = match self
            .authority
            .metadata_trusted("segment-active.jsonl", 0o600)
        {
            Ok((_, size)) => size,
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        if size + incoming <= MAX_SEGMENT_BYTES {
            return Ok(());
        }
        if size != 0 {
            self.flush_pending()?;
            self.publish_rotated_segment()?;
            // The publish left the inode linked under BOTH names; drop the
            // active name so the next append starts a fresh single-link file
            // (append_trusted requires nlink == 1).
            self.authority.unlink("segment-active.jsonl")?;
            self.authority.sync_all()?;
        }
        retention_sweep(&self.authority)?;
        Ok(())
    }

    /// Publish the full active segment under a unique completed name spanning
    /// the sequence range it covers, so two rotations inside one clock tick
    /// still get distinct names, and via a no-replace hard link so a colliding
    /// name can never overwrite an existing completed segment.
    fn publish_rotated_segment(&self) -> io::Result<()> {
        let mut stamp = now_millis();
        let mut candidate = segment_name_for(stamp, self.next_sequence);
        while self.authority.entry_exists(&candidate)? {
            let Some(next_stamp) = stamp.checked_add(1) else {
                return Err(invalid("segment timestamps exhausted"));
            };
            stamp = next_stamp;
            candidate = segment_name_for(stamp, self.next_sequence);
        }
        self.authority
            .publish_no_replace("segment-active.jsonl", &candidate)?;
        Ok(())
    }

    pub fn query(&self, request: &Query) -> io::Result<QueryResponse> {
        if request.limit == 0 || request.limit > MAX_QUERY_RECORDS {
            return Err(invalid("invalid query limit"));
        }
        let mut records = read_segments(&self.authority)?;
        // Read order is segment-name lexical, which is timestamp order, not
        // sequence order: with historical names "[1,2]" and "[3,4]", clients
        // paging by sequence must not deliver [3,4] first and then re-deliver
        // them after the older records, so scan in strict sequence order and
        // keep the cursor monotonic with it.
        records.sort_unstable_by_key(|record| record.sequence);
        let mut out = Vec::new();
        let mut bytes = 0;
        let mut cursor = request.after_sequence;
        for record in records {
            if record.sequence <= request.after_sequence || !request.matches(&record) {
                continue;
            }
            let size = serde_json::to_vec(&record).map_err(invalid_json)?.len();
            if out.len() == request.limit || bytes + size > MAX_QUERY_BYTES {
                break;
            }
            bytes += size;
            cursor = record.sequence;
            out.push(record);
        }
        Ok(QueryResponse {
            records: out,
            cursor,
        })
    }

    pub fn export(&self, context: &serde_json::Value) -> io::Result<Vec<u8>> {
        let _snapshot_lock = self
            .authority
            .lock_transaction(Duration::from_secs(2))
            .map_err(|e| export_stage("snapshot-lock", e))?;
        let raw_records =
            read_raw_segments(&self.authority).map_err(|e| export_stage("segment-read", e))?;
        // Validate every complete canonical line in the exact bytes encoded;
        // never publish a torn line or silently omit malformed records.
        if !raw_records.is_empty() && !raw_records.ends_with(b"\n") {
            return Err(export_stage(
                "record-unterminated",
                invalid("unterminated export record"),
            ));
        }
        let mut lines = Vec::new();
        for line in raw_records.split_inclusive(|byte| *byte == b'\n') {
            let record = serde_json::from_slice::<CanonicalRecord>(line)
                .map_err(|e| export_stage("record-json", invalid_json(e)))?;
            lines.push((record.sequence, line));
        }
        // Wall clock can move backwards; sequence is the canonical ordering.
        lines.sort_by_key(|(sequence, _)| *sequence);
        if lines.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(export_stage(
                "sequence-duplicate",
                invalid("duplicate export sequence"),
            ));
        }
        let mut records = lines
            .into_iter()
            .flat_map(|(_, line)| line.iter().copied())
            .collect::<Vec<_>>();
        let mut sessions = crate::log_archive::Snapshot::owner(&self.authority)?;
        drop(_snapshot_lock);
        sessions.qnx(&self.authority)?;
        let sessions = sessions.into_bytes();
        if records.len().saturating_add(sessions.len()) > MAX_EXPORT_BYTES {
            return Err(export_stage(
                "stream-encode",
                invalid("export exceeds bound"),
            ));
        }
        records.extend_from_slice(&sessions);
        // The sorted bytes own their storage; release the snapshot before encoding.
        drop(raw_records);
        let context = serde_json::to_vec(context)
            .map_err(|e| export_stage("context-json", invalid_json(e)))?;
        encode_export(&records, &context).map_err(|e| export_stage("stream-encode", e))
    }
}

#[derive(Default)]
pub struct SubscriptionRegistry {
    next_id: u64,
    entries: HashMap<u64, u64>,
}
impl SubscriptionRegistry {
    pub fn follow(&mut self, sequence: u64) -> u64 {
        self.next_id += 1;
        self.entries.insert(self.next_id, sequence);
        self.next_id
    }
    pub fn stop(&mut self, id: u64) -> bool {
        self.entries.remove(&id).is_some()
    }
}

pub struct Query {
    pub after_sequence: u64,
    pub limit: usize,
    pub levels: Vec<Level>,
    pub kinds: Vec<String>,
    pub agent_ids: Vec<String>,
    pub search: Option<String>,
    pub from_epoch_millis: u64,
    pub to_epoch_millis: u64,
}
impl Query {
    fn matches(&self, record: &CanonicalRecord) -> bool {
        let received = timestamp_epoch_millis(&record.timestamp).unwrap_or(0);
        (self.levels.is_empty() || self.levels.contains(&record.level))
            && (self.kinds.is_empty() || self.kinds.contains(&record.source.kind))
            && (self.agent_ids.is_empty()
                || record
                    .source
                    .id
                    .as_ref()
                    .map(|id| self.agent_ids.contains(id))
                    .unwrap_or(false))
            && self
                .search
                .as_ref()
                .map(|needle| record.message.contains(needle))
                .unwrap_or(true)
            && received >= self.from_epoch_millis
            && received <= self.to_epoch_millis
    }
}
pub struct QueryResponse {
    pub records: Vec<CanonicalRecord>,
    pub cursor: u64,
}

fn validate_source(source: &Source) -> io::Result<()> {
    match (source.kind.as_str(), &source.id) {
        ("app" | "daemon", None) => Ok(()),
        ("agent", Some(id)) if valid_agent_id(id) => Ok(()),
        _ => Err(invalid("invalid bound source")),
    }
}
fn validate_producer(record: &ProducerRecord) -> io::Result<()> {
    if record.component.is_empty()
        || record.component.len() > 64
        || record.fields.len() > 32
        || record.message.len() > 8 * 1024
        || has_control(&record.component)
        || record
            .message
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
        || record.fields.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 64
                || value.len() > 1024
                || has_control(key)
                || has_control(value)
        })
    {
        Err(invalid("invalid producer record"))
    } else {
        Ok(())
    }
}
fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}
fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
fn valid_batch_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}
pub(crate) use crate::log_export::timestamp_epoch_millis;
fn segment_names(directory: &Directory) -> io::Result<Vec<String>> {
    segment_names_with_bound(directory, MAX_LOG_DIRECTORY_ENTRIES)
}
fn segment_names_with_bound(directory: &Directory, maximum: usize) -> io::Result<Vec<String>> {
    Ok(directory
        .entry_names_bounded(maximum)?
        .into_iter()
        .filter(|name| {
            if !name.starts_with("segment-")
                || !name.ends_with(".jsonl")
                || name == "segment-active.jsonl"
            {
                return false;
            }
            let core = &name[8..name.len() - 6];
            // Two accepted shapes: legacy rotation names with a bare 20-digit
            // stamp, and range names carrying the addition open-sequence bound.
            let parts: Vec<&str> = core.split('-').collect();
            let digits = |part: &str| {
                !part.is_empty() && part.len() == 20 && part.bytes().all(|b| b.is_ascii_digit())
            };
            match parts.as_slice() {
                [stamp] => digits(stamp),
                [stamp, bound] => digits(stamp) && digits(bound),
                _ => false,
            }
        })
        .collect())
}
fn all_segment_names(directory: &Directory) -> io::Result<Vec<String>> {
    let mut names = segment_names(directory)?;
    if directory.entry_exists("segment-active.jsonl")? {
        names.push("segment-active.jsonl".to_string())
    }
    names.sort();
    Ok(names)
}
/// One canonical record pre-encoded for a *specific* sequence, with the exact
/// newline-terminated JSONL line that was bound-checked. Recovery and retry
/// reuse this form so the durable bytes never diverge between attempts.
struct PreparedRecord {
    sequence: u64,
    line: Vec<u8>,
}

/// Timestamped canonical form for a producer record at a given sequence.
/// The timestamp is only sampled here, once per record, so a retried append
/// is byte-identical to the original attempt.
fn encode_canonical_record(
    source: Source,
    sequence: u64,
    record: &ProducerRecord,
) -> CanonicalRecord {
    CanonicalRecord {
        schema_version: 1,
        sequence,
        timestamp: timestamp(),
        source,
        level: record.level.clone(),
        component: record.component.clone(),
        message: redact(&record.message),
        fields: record
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), redact(value)))
            .collect(),
    }
}

fn encode_canonical_line(
    source: Source,
    sequence: u64,
    record: &ProducerRecord,
) -> io::Result<PreparedRecord> {
    let canonical = encode_canonical_record(source, sequence, record);
    let mut line = serde_json::to_vec(&canonical).map_err(invalid_json)?;
    line.push(b'\n');
    if line.len() > MAX_RECORD_BYTES {
        return Err(invalid("canonical record exceeds bound"));
    }
    Ok(PreparedRecord { sequence, line })
}

/// Refuse to admit a new app batch when the accepted-batches ledger cannot
/// absorb another line. Doing this before writing any canonical record keeps
/// the failed-batch path side-effect free and non-orphaning.
fn ensure_batch_ledger_slot(directory: &Directory, incoming_lines: usize) -> io::Result<()> {
    match directory.read_trusted("accepted-batches", MAX_BATCH_LEDGER_BYTES, 0o600) {
        Ok(bytes) => {
            let current = String::from_utf8(bytes)
                .map_err(invalid_utf8)?
                .lines()
                .filter(|line| valid_batch_id(line))
                .count();
            if current + incoming_lines >= MAX_ACCEPTED_BATCHES {
                return Err(invalid("accepted batch ledger is exhausted"));
            }
        }
        // A ledger beyond the read bound is definitely full: fail closed
        // instead of treating the unreadable tail as an empty ledger.
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            return Err(error);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

/// A segment whose name encodes both the completion wall-clock stamp and the
/// exclusive sequence bound (`next_sequence` at rotation time). The sequence
/// suffix makes names unique across rotations that share one clock tick.
/// Retention orders canonical record sequences, not these wall-clock names.
fn segment_name_for(stamp: u128, open_sequence_bound: u64) -> String {
    format!("segment-{:020}-{:020}.jsonl", stamp, open_sequence_bound)
}

/// Retain the newest canonical sequences, independently of wall-clock changes.
/// Legacy names lack sequence bounds, so read the bounded trusted records for
/// every completed segment. Validate all candidates before deleting anything.
fn retention_sweep(directory: &Directory) -> io::Result<()> {
    retention_sweep_bound(directory, MAX_SEGMENTS)
}
fn retention_sweep_bound(directory: &Directory, maximum: usize) -> io::Result<()> {
    let names = segment_names(directory)?;
    if names.len() < maximum {
        return Ok(());
    }
    let mut completed = Vec::with_capacity(names.len());
    for name in names {
        let bytes = directory.read_trusted(&name, MAX_SEGMENT_BYTES as usize, 0o600)?;
        let mut last_sequence = 0;
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let record: CanonicalRecord = serde_json::from_slice(line).map_err(invalid_json)?;
            last_sequence = last_sequence.max(record.sequence);
        }
        completed.push((last_sequence, name));
    }
    // Filenames only break equal-sequence ties; a future timestamp cannot
    // outrank a segment containing newer records.
    completed.sort();
    while completed.len() >= maximum {
        directory.unlink(&completed.remove(0).1)?;
        directory.sync_all()?;
    }
    Ok(())
}

/// Truncate torn tails left by a crash during an append: a fully-written
/// last line that is missing only its newline, or a partially-written line
/// after the last newline. Only the active segment and only its final line
/// are touched; mid-segment corruption stays a hard open failure so it is
/// never silently masked.
fn repair_torn_segments(directory: &std::path::Path) -> io::Result<()> {
    let authority = match Directory::open(directory) {
        Ok(authority) => authority,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    authority.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    for (name, _) in SEVERITY_TIERS {
        if authority.entry_exists(name)? {
            repair_torn_segments(&directory.join(name))?;
        }
    }
    let _snapshot_lock = authority.lock_transaction(Duration::from_secs(2))?;
    // A durable link publication precedes removal of the active name. A
    // power cut in that interval leaves exactly these two trusted aliases.
    // Roll back the completed alias before strict single-link tail reads.
    for name in segment_names_with_bound(&authority, MAX_LOG_DIRECTORY_ENTRIES + 1)? {
        if authority.rollback_interrupted_publication(
            "segment-active.jsonl",
            &name,
            MAX_SEGMENT_BYTES,
        )? {
            break;
        }
    }
    // The one publication alias is the only transient extra entry. Restore
    // the ordinary bound before any tail repair; unrelated overflow fails.
    let completed = segment_names(&authority)?;
    repair_torn_tail(&authority, "segment-active.jsonl")?;
    // A crash between publishing a rotated segment and appending to the new
    // active segment can also leave the just-rotated name torn.
    for name in completed {
        repair_torn_tail(&authority, &name)?;
    }
    Ok(())
}

fn repair_torn_tail(directory: &Directory, name: &str) -> io::Result<()> {
    // Segments are bound to MAX_SEGMENT_BYTES; +1 lets us notice content
    // beyond the bound instead of silently repair-truncating it.
    let bound = MAX_SEGMENT_BYTES as usize + 1;
    let bytes = match directory.read_trusted(name, bound, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return Ok(());
    }
    // The last append finished only a prefix of its bytes. Everything up to
    // (not including) the final newline-less fragment is the durable prefix;
    // verify it parses before truncating so interior corruption surfaces as
    // a hard open failure instead of being masked as a torn tail.
    let keep = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .map(|at| at + 1)
        .unwrap_or(0);
    for line in bytes[..keep]
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
    {
        serde_json::from_slice::<CanonicalRecord>(line).map_err(invalid_json)?;
    }
    directory.truncate_trusted(name, keep as u64, 0o600)?;
    Ok(())
}

fn read_raw_local_segments(directory: &Directory) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    for name in all_segment_names(directory)? {
        let bytes = directory.read_trusted(&name, MAX_SEGMENT_BYTES as usize, 0o600)?;
        out.extend_from_slice(&bytes);
        if out.len() > MAX_EXPORT_BYTES {
            return Err(invalid("export exceeds bound"));
        }
    }
    Ok(out)
}
/// Merge tiers by exact canonical bytes. Duplicate sequences inside the
/// original ring remain visible to the existing strict export validation.
fn read_raw_segments(directory: &Directory) -> io::Result<Vec<u8>> {
    let mut out = read_raw_local_segments(directory)?;
    // Index byte ranges instead of copying every retained line into a second
    // 384 MiB payload allocation while exporting on the car.
    let mut seen = HashMap::<u64, (usize, usize)>::new();
    let mut offset = 0;
    for line in out.split_inclusive(|b| *b == b'\n') {
        // Preserve the original export's detailed JSON/torn-tail diagnosis.
        if let Ok(record) = serde_json::from_slice::<CanonicalRecord>(line) {
            seen.insert(record.sequence, (offset, offset + line.len()));
        }
        offset += line.len();
    }
    for (name, _) in SEVERITY_TIERS {
        if !directory.entry_exists(name)? {
            continue;
        }
        let tier = open_severity_tier(directory, name)?;
        let bytes = read_raw_local_segments(&tier)?;
        for line in bytes.split_inclusive(|b| *b == b'\n') {
            let record: CanonicalRecord = serde_json::from_slice(line).map_err(invalid_json)?;
            if (name == "error" && record.level != Level::Error) || record.level == Level::Debug {
                return Err(invalid("record severity violates retention tier"));
            }
            if let Some((start, end)) = seen.get(&record.sequence) {
                if &out[*start..*end] != line {
                    return Err(invalid("divergent canonical sequence across tiers"));
                }
            } else {
                let start = out.len();
                out.extend_from_slice(line);
                seen.insert(record.sequence, (start, out.len()));
                if out.len() > MAX_EXPORT_BYTES {
                    return Err(invalid("export exceeds bound"));
                }
            }
        }
    }
    Ok(out)
}
fn open_severity_tier(directory: &Directory, name: &str) -> io::Result<Directory> {
    let tier = directory.open_child(name)?;
    tier.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    Ok(tier)
}
fn prepare_severity_tiers(directory: &Directory) -> io::Result<()> {
    for (name, _) in SEVERITY_TIERS {
        if directory.entry_exists(name)? {
            open_severity_tier(directory, name)?;
        } else {
            directory.create_private_child(name)?;
        }
    }
    Ok(())
}
fn finish_severity_fanout(
    directory: &Directory,
    line: &[u8],
    record: &CanonicalRecord,
    recovering: bool,
) -> io::Result<()> {
    for (name, maximum) in SEVERITY_TIERS {
        if name == "error" && record.level != Level::Error {
            continue;
        }
        let tier = open_severity_tier(directory, name)?;
        append_tier_exact(&tier, line, record.sequence, maximum, recovering)?;
        tier.sync_all()?;
    }
    Ok(())
}
fn append_tier_exact(
    directory: &Directory,
    line: &[u8],
    sequence: u64,
    maximum: usize,
    recovering: bool,
) -> io::Result<()> {
    append_tier_unflushed(directory, line, sequence, maximum, recovering, true).map(|_| ())
}
fn append_tier_unflushed(
    directory: &Directory,
    line: &[u8],
    sequence: u64,
    maximum: usize,
    recovering: bool,
    durable: bool,
) -> io::Result<Option<File>> {
    // Recovery may encounter an already-written copy. It must match exactly.
    if recovering {
        let existing = read_raw_local_segments(directory)?;
        for previous in existing.split_inclusive(|b| *b == b'\n') {
            let record: CanonicalRecord = serde_json::from_slice(previous).map_err(invalid_json)?;
            if record.sequence == sequence {
                return if previous == line {
                    Ok(None)
                } else {
                    Err(invalid("divergent severity recovery record"))
                };
            }
        }
    }
    let size = match directory.metadata_trusted("segment-active.jsonl", 0o600) {
        Ok((_, size)) => size,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    if size + line.len() as u64 > MAX_SEGMENT_BYTES {
        // A group may rotate before its final sync. Preserve the prior inode
        // before publication and only then begin the next segment.
        let previous =
            directory.open_trusted_readwrite_file("segment-active.jsonl", size, 0o600)?;
        directory.sync_trusted_append("segment-active.jsonl", 0o600, &previous)?;
        let mut stamp = now_millis();
        let mut name = segment_name_for(stamp, sequence);
        while directory.entry_exists(&name)? {
            stamp = stamp
                .checked_add(1)
                .ok_or_else(|| invalid("segment timestamps exhausted"))?;
            name = segment_name_for(stamp, sequence);
        }
        directory.publish_no_replace("segment-active.jsonl", &name)?;
        directory.unlink("segment-active.jsonl")?;
        directory.sync_all()?;
        retention_sweep_bound(directory, maximum)?;
    }
    directory
        .append_trusted_with_durability(
            "segment-active.jsonl",
            line,
            MAX_SEGMENT_BYTES,
            0o600,
            None,
            durable,
        )
        .map(Some)
}
fn recover_severity_pending(directory: &Directory) -> io::Result<()> {
    let bytes = match directory.read_trusted("severity.pending", MAX_BATCH_BYTES, 0o600) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !bytes.ends_with(b"\n") || bytes.is_empty() {
        return Err(invalid("invalid severity recovery record"));
    }
    let lines: Vec<&[u8]> = bytes.split_inclusive(|byte| *byte == b'\n').collect();
    if lines.len() > MAX_BATCH_RECORDS {
        return Err(invalid("severity recovery group exceeds bound"));
    }
    let mut last = None;
    for line in &lines {
        if line.len() > MAX_RECORD_BYTES {
            return Err(invalid("severity recovery record exceeds bound"));
        }
        let record: CanonicalRecord = serde_json::from_slice(line).map_err(invalid_json)?;
        if last.is_some_and(|value: u64| value.checked_add(1) != Some(record.sequence)) {
            return Err(invalid("severity recovery group is not contiguous"));
        }
        last = Some(record.sequence);
    }
    for line in lines {
        let record: CanonicalRecord = serde_json::from_slice(line).map_err(invalid_json)?;
        append_tier_exact(directory, line, record.sequence, MAX_SEGMENTS, true)?;
        if record.level != Level::Debug {
            finish_severity_fanout(directory, line, &record, true)?;
        }
    }
    directory.unlink("severity.pending")?;
    directory.sync_all()
}
fn read_segments(directory: &Directory) -> io::Result<Vec<CanonicalRecord>> {
    let bytes = read_raw_segments(directory)?;
    bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).map_err(invalid_json))
        .collect()
}
fn timestamp() -> String {
    let millis = now_millis();
    let seconds = (millis / 1000) as libc::time_t;
    let mut value = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::gmtime_r(&seconds, value.as_mut_ptr()) }.is_null() {
        return "1970-01-01T00:00:00.000Z".to_string();
    }
    let value = unsafe { value.assume_init() };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.tm_year + 1900,
        value.tm_mon + 1,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        value.tm_sec,
        millis % 1000
    )
}
fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn invalid_json(error: impl std::fmt::Display) -> io::Error {
    invalid(&error.to_string())
}
fn invalid_utf8(error: std::string::FromUtf8Error) -> io::Error {
    invalid(&error.to_string())
}

#[cfg(test)]
pub(crate) fn test_rotate_away_initial_record() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut log = CanonicalLog::open(directory.path()).unwrap();
    let source = Source {
        kind: "daemon".into(),
        id: None,
    };
    let record = ProducerRecord {
        level: Level::Error,
        component: "injector".into(),
        message: "original-native-failure".into(),
        fields: Default::default(),
    };
    log.append(source.clone(), record.clone()).unwrap();
    let mut filler = record;
    filler.message = "x".repeat(7 * 1024);
    for _ in 0..=MAX_SEGMENTS {
        log.rotate_for(MAX_SEGMENT_BYTES).unwrap();
        log.append(source.clone(), filler.clone()).unwrap();
    }
    let bytes = read_raw_segments(&log.authority).unwrap();
    assert!(String::from_utf8_lossy(&bytes).contains("original-native-failure"));
    let debug = read_raw_local_segments(&log.authority).unwrap();
    assert!(!String::from_utf8_lossy(&debug).contains("original-native-failure"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn log(directory: &tempfile::TempDir) -> CanonicalLog {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        CanonicalLog::open(directory.path()).unwrap()
    }
    struct Peer(bool);
    impl PeerVerifier for Peer {
        fn is_voboost_app(&self, _: u32, _: u32) -> bool {
            self.0
        }
    }
    fn record(level: Level, message: &str) -> ProducerRecord {
        ProducerRecord {
            level,
            component: "test".into(),
            message: message.into(),
            fields: HashMap::new(),
        }
    }
    fn daemon_source() -> Source {
        Source {
            kind: "daemon".into(),
            id: None,
        }
    }

    #[test]
    fn severity_host_batch_cost_observation() {
        for level in [Level::Debug, Level::Info, Level::Error] {
            let directory = tempfile::tempdir().unwrap();
            with_test_log(&directory.path().join("logs"), || {
                let started = std::time::Instant::now();
                let batch = begin_uplink_batch();
                for i in 0..64 {
                    append_global(daemon_source(), record(level.clone(), &format!("cost-{i}")))
                        .unwrap();
                }
                drop(batch);
                let root_syncs =
                    TEST_LOG.with(|log| log.borrow().as_ref().unwrap().synchronizations);
                eprintln!("severity-cost level={level:?} records=64 elapsed_us={} root_file_syncs={root_syncs}", started.elapsed().as_micros());
            });
        }
    }

    #[test]
    fn severity_tiers_keep_exact_identity_and_filter_membership() {
        let directory = tempfile::tempdir().unwrap();
        let mut logger = log(&directory);
        for (level, message) in [
            (Level::Debug, "debug"),
            (Level::Info, "info"),
            (Level::Error, "error"),
        ] {
            logger
                .append(daemon_source(), record(level, message))
                .unwrap();
        }
        let root = read_raw_local_segments(&logger.authority).unwrap();
        let info = read_raw_local_segments(&open_severity_tier(&logger.authority, "info").unwrap())
            .unwrap();
        let error =
            read_raw_local_segments(&open_severity_tier(&logger.authority, "error").unwrap())
                .unwrap();
        assert_eq!(
            root.split(|b| *b == b'\n')
                .filter(|v| !v.is_empty())
                .count(),
            3
        );
        assert_eq!(
            info.split(|b| *b == b'\n')
                .filter(|v| !v.is_empty())
                .count(),
            2
        );
        assert_eq!(
            error
                .split(|b| *b == b'\n')
                .filter(|v| !v.is_empty())
                .count(),
            1
        );
        assert!(info.ends_with(&error));
        assert!(root.ends_with(&info));
        assert_eq!(read_segments(&logger.authority).unwrap().len(), 3);
        logger.export(&serde_json::json!({})).unwrap();
    }

    #[test]
    fn debug_rotation_cannot_evict_early_info_or_error() {
        let directory = tempfile::tempdir().unwrap();
        let mut logger = log(&directory);
        logger
            .append(daemon_source(), record(Level::Error, "early-error"))
            .unwrap();
        logger
            .append(daemon_source(), record(Level::Info, "early-info"))
            .unwrap();
        for _ in 0..=MAX_SEGMENTS {
            logger.rotate_for(MAX_SEGMENT_BYTES).unwrap();
            logger
                .append(daemon_source(), record(Level::Debug, "noise"))
                .unwrap();
        }
        let local = read_raw_local_segments(&logger.authority).unwrap();
        assert!(!String::from_utf8_lossy(&local).contains("early-error"));
        let records = read_segments(&logger.authority).unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|r| r.message == "early-error")
                .count(),
            1
        );
        assert_eq!(
            records.iter().filter(|r| r.message == "early-info").count(),
            1
        );
        let stream = logger
            .export(&serde_json::json!({"scope":"product-log-interop"}))
            .unwrap();
        if let Some(path) = std::env::var_os("VOBOOST_TEST_LOG_EXPORT") {
            use std::os::unix::fs::OpenOptionsExt;
            let path = std::path::PathBuf::from(path);
            assert!(path.is_absolute());
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            output.write_all(&stream).unwrap();
            output.sync_all().unwrap();
        }
    }

    #[test]
    fn severity_recovery_completes_each_interrupted_fanout_without_sequence_reuse() {
        for copies in 0..=3 {
            let directory = tempfile::tempdir().unwrap();
            let logger = log(&directory);
            let prepared =
                encode_canonical_line(daemon_source(), 7, &record(Level::Error, "durable-error"))
                    .unwrap();
            logger
                .authority
                .write_atomic("severity.pending", &prepared.line, 0o600)
                .unwrap();
            for name in ["debug", "info", "error"].into_iter().take(copies) {
                if name == "debug" {
                    logger
                        .authority
                        .append_trusted(
                            "segment-active.jsonl",
                            &prepared.line,
                            MAX_SEGMENT_BYTES,
                            0o600,
                        )
                        .unwrap();
                } else {
                    open_severity_tier(&logger.authority, name)
                        .unwrap()
                        .append_trusted(
                            "segment-active.jsonl",
                            &prepared.line,
                            MAX_SEGMENT_BYTES,
                            0o600,
                        )
                        .unwrap();
                }
            }
            drop(logger);
            let mut reopened = CanonicalLog::open(directory.path()).unwrap();
            assert_eq!(reopened.next_sequence, 8);
            assert!(!reopened.authority.entry_exists("severity.pending").unwrap());
            assert_eq!(read_segments(&reopened.authority).unwrap().len(), 1);
            for name in ["info", "error"] {
                assert_eq!(
                    read_raw_local_segments(
                        &open_severity_tier(&reopened.authority, name).unwrap()
                    )
                    .unwrap(),
                    prepared.line
                );
            }
            assert_eq!(
                reopened
                    .append(daemon_source(), record(Level::Debug, "next"))
                    .unwrap(),
                8
            );
        }
    }

    #[test]
    fn severity_retained_sequence_drives_restart_and_divergence_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let logger = log(&directory);
        let prepared =
            encode_canonical_line(daemon_source(), 90, &record(Level::Error, "retained")).unwrap();
        let tier = open_severity_tier(&logger.authority, "error").unwrap();
        tier.append_trusted(
            "segment-active.jsonl",
            &prepared.line,
            MAX_SEGMENT_BYTES,
            0o600,
        )
        .unwrap();
        drop(logger);
        let mut logger = CanonicalLog::open(directory.path()).unwrap();
        assert_eq!(
            logger
                .append(daemon_source(), record(Level::Debug, "next"))
                .unwrap(),
            91
        );
        let divergent =
            encode_canonical_line(daemon_source(), 90, &record(Level::Info, "different")).unwrap();
        open_severity_tier(&logger.authority, "info")
            .unwrap()
            .append_trusted(
                "segment-active.jsonl",
                &divergent.line,
                MAX_SEGMENT_BYTES,
                0o600,
            )
            .unwrap();
        assert!(logger.export(&serde_json::json!({})).is_err());
        drop(logger);
        assert!(CanonicalLog::open(directory.path()).is_err());
    }

    #[test]
    fn severity_mixed_group_crash_restores_exact_missing_copies() {
        for prefix in 0..=3 {
            let directory = tempfile::tempdir().unwrap();
            let logger = log(&directory);
            let prepared: Vec<PreparedRecord> = [Level::Error, Level::Info, Level::Debug]
                .into_iter()
                .enumerate()
                .map(|(index, level)| {
                    encode_canonical_line(
                        daemon_source(),
                        index as u64 + 1,
                        &record(level, &format!("group-{index}")),
                    )
                    .unwrap()
                })
                .collect();
            let bytes: Vec<u8> = prepared
                .iter()
                .flat_map(|record| record.line.iter().copied())
                .collect();
            logger
                .authority
                .write_atomic("severity.pending", &bytes, 0o600)
                .unwrap();
            for row in prepared.iter().take(prefix) {
                logger
                    .authority
                    .append_trusted("segment-active.jsonl", &row.line, MAX_SEGMENT_BYTES, 0o600)
                    .unwrap();
            }
            // The info copy may have progressed ahead of the last error copy.
            let first: CanonicalRecord = serde_json::from_slice(&prepared[0].line).unwrap();
            if prefix != 0 {
                append_tier_exact(
                    &open_severity_tier(&logger.authority, "info").unwrap(),
                    &prepared[0].line,
                    first.sequence,
                    2,
                    false,
                )
                .unwrap();
            }
            drop(logger);
            let reopened = CanonicalLog::open(directory.path()).unwrap();
            assert_eq!(reopened.next_sequence, 4);
            assert_eq!(read_raw_local_segments(&reopened.authority).unwrap(), bytes);
            assert_eq!(read_segments(&reopened.authority).unwrap().len(), 3);
            let info =
                read_raw_local_segments(&open_severity_tier(&reopened.authority, "info").unwrap())
                    .unwrap();
            assert_eq!(
                info,
                [prepared[0].line.clone(), prepared[1].line.clone()].concat()
            );
            let error =
                read_raw_local_segments(&open_severity_tier(&reopened.authority, "error").unwrap())
                    .unwrap();
            assert_eq!(error, prepared[0].line);
            reopened.export(&serde_json::json!({})).unwrap();
        }
    }

    #[test]
    fn severity_uplink_group_is_bounded_and_commits_before_guard_returns() {
        let directory = tempfile::tempdir().unwrap();
        with_test_log(&directory.path().join("logs"), || {
            let batch = begin_uplink_batch();
            for index in 0..80 {
                append_global(
                    daemon_source(),
                    record(Level::Info, &format!("{index}:{}", "x".repeat(8000))),
                )
                .unwrap();
                TEST_LOG.with(|log| {
                    let logger = log.borrow();
                    let logger = logger.as_ref().unwrap();
                    assert!(logger.pending_records.len() <= MAX_BATCH_RECORDS);
                    assert!(logger.pending_record_bytes <= MAX_BATCH_BYTES);
                });
            }
            drop(batch);
            TEST_LOG.with(|log| {
                let logger = log.borrow();
                let logger = logger.as_ref().unwrap();
                assert!(logger.pending_records.is_empty());
                assert!(logger.pending_file.is_none());
                assert!(!logger.authority.entry_exists("severity.pending").unwrap());
                assert_eq!(read_segments(&logger.authority).unwrap().len(), 80);
            });
        });
        let reopened = CanonicalLog::open(directory.path().join("logs")).unwrap();
        assert_eq!(reopened.next_sequence, 81);
    }

    #[test]
    fn severity_pending_app_batch_recovery_and_retry_remain_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let logger = log(&directory);
        let batch = AppBatch {
            schema_version: 1,
            batch_id: "abcdef0123456789abcdef0123456789".into(),
            records: vec![
                record(Level::Error, "app-error"),
                record(Level::Info, "app-info"),
            ],
        };
        let pending = PendingBatch {
            start_sequence: 1,
            batch: batch.clone(),
        };
        logger
            .authority
            .write_atomic(
                "accepted-batch.pending",
                &serde_json::to_vec(&pending).unwrap(),
                0o600,
            )
            .unwrap();
        let prepared = encode_canonical_line(
            Source {
                kind: "app".into(),
                id: None,
            },
            1,
            &batch.records[0],
        )
        .unwrap();
        logger
            .authority
            .write_atomic("severity.pending", &prepared.line, 0o600)
            .unwrap();
        logger
            .authority
            .append_trusted(
                "segment-active.jsonl",
                &prepared.line,
                MAX_SEGMENT_BYTES,
                0o600,
            )
            .unwrap();
        drop(logger);
        let mut reopened = CanonicalLog::open(directory.path()).unwrap();
        assert_eq!(reopened.next_sequence, 3);
        assert_eq!(read_segments(&reopened.authority).unwrap().len(), 2);
        let bytes = serde_json::to_vec(&batch).unwrap();
        reopened
            .accept_app_batch(1000, 5, &Peer(true), &bytes)
            .unwrap();
        assert_eq!(read_segments(&reopened.authority).unwrap().len(), 2);
        assert!(!reopened
            .authority
            .entry_exists("accepted-batch.pending")
            .unwrap());
        reopened.export(&serde_json::json!({})).unwrap();
    }

    #[test]
    fn severity_partial_failure_refuses_further_append_and_recovers_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let mut logger = log(&directory);
        let error_path = directory.path().join("error/segment-active.jsonl");
        std::os::unix::fs::symlink("missing", &error_path).unwrap();
        assert!(logger
            .append(daemon_source(), record(Level::Error, "first-failure"))
            .is_err());
        assert!(logger
            .append(daemon_source(), record(Level::Debug, "must-not-reuse"))
            .is_err());
        fs::remove_file(error_path).unwrap();
        drop(logger);
        let mut reopened = CanonicalLog::open(directory.path()).unwrap();
        let rows = read_segments(&reopened.authority).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message, "first-failure");
        assert_eq!(
            reopened
                .append(daemon_source(), record(Level::Debug, "after-recovery"))
                .unwrap(),
            2
        );
    }

    #[test]
    fn severity_tier_rotation_has_independent_segment_limits() {
        let directory = tempfile::tempdir().unwrap();
        let logger = log(&directory);
        for (name, maximum) in SEVERITY_TIERS {
            let tier = open_severity_tier(&logger.authority, name).unwrap();
            for sequence in 1..=5 {
                let prepared =
                    encode_canonical_line(daemon_source(), sequence, &record(Level::Error, "row"))
                        .unwrap();
                append_tier_exact(&tier, &prepared.line, sequence, maximum, false).unwrap();
                tier.publish_no_replace(
                    "segment-active.jsonl",
                    &segment_name_for(sequence as u128, sequence + 1),
                )
                .unwrap();
                tier.unlink("segment-active.jsonl").unwrap();
                retention_sweep_bound(&tier, maximum).unwrap();
                assert!(segment_names(&tier).unwrap().len() < maximum);
            }
        }
    }

    #[test]
    fn severity_child_symlinks_and_unsafe_modes_are_rejected() {
        for symlink in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let logger = log(&directory);
            fs::remove_dir(directory.path().join("info")).unwrap();
            if symlink {
                std::os::unix::fs::symlink(
                    directory.path().join("error"),
                    directory.path().join("info"),
                )
                .unwrap();
            } else {
                fs::create_dir(directory.path().join("info")).unwrap();
                fs::set_permissions(
                    directory.path().join("info"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
            assert!(logger.export(&serde_json::json!({})).is_err());
            drop(logger);
            assert!(CanonicalLog::open(directory.path()).is_err());
        }
    }

    #[test]
    fn listener_startup_failure_reaches_canonical_sink_before_relay_worker() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let logs = directory.path().join("logs");
        let run = directory.path().join("run");
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        with_test_log(&logs, || {
            // The production first authority check fails before package lookup,
            // socket binding or any management worker can be started.
            let error = start_app_listener(run.join("daemon.sock").to_str().unwrap()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let original = io::Error::from_raw_os_error(13);
            let returned = listener_startup_error("socket-bind", original);
            assert_eq!(returned.raw_os_error(), Some(13));
            let long = io::Error::other(format!("cause\n{}", "x".repeat(500)));
            let returned = listener_startup_error("installed-app-uid", long);
            assert!(
                returned.to_string().contains('\n'),
                "original error stays intact"
            );
        });
        let rows = fs::read_to_string(logs.join("segment-active.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<CanonicalRecord>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 3);
        assert!(rows[0].message.contains("stage=run-authority:"));
        assert!(rows[1]
            .message
            .contains("stage=socket-bind: Permission denied"));
        assert!(rows[2].message.contains("stage=installed-app-uid: cause "));
        for row in rows {
            assert_eq!(row.level, Level::Error);
            assert_eq!(row.component, "runtime-transport");
            assert_eq!(row.source.kind, "daemon");
            assert!(!row.message.contains('\n'));
            assert!(row.message.chars().count() <= 340);
        }
        assert!(!run.join("daemon.sock").exists());
    }

    #[test]
    fn interrupted_rotation_cold_open_preserves_records_and_sequence() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        l.append(daemon_source(), record(Level::Info, "before-cut"))
            .unwrap();
        l.publish_rotated_segment().unwrap();
        drop(l); // Actual publication cut, before active unlink.
        let mut reopened = CanonicalLog::open(d.path()).unwrap();
        assert_eq!(all_records(&reopened).len(), 1);
        reopened
            .append(daemon_source(), record(Level::Info, "after-cut"))
            .unwrap();
        assert_eq!(
            all_records(&reopened)
                .iter()
                .map(|r| r.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        reopened.export(&serde_json::json!({})).unwrap();
        drop(reopened);
        for _ in 0..3 {
            let reopened = CanonicalLog::open(d.path()).unwrap();
            assert_eq!(all_records(&reopened).len(), 2);
        }
    }

    #[test]
    fn interrupted_rotation_rejects_external_third_alias_and_wrong_mode() {
        for third_alias in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let mut l = log(&d);
            l.append(daemon_source(), record(Level::Info, "preserve"))
                .unwrap();
            l.publish_rotated_segment().unwrap();
            if third_alias {
                fs::hard_link(
                    d.path().join("segment-active.jsonl"),
                    d.path().join("external"),
                )
                .unwrap();
            } else {
                fs::set_permissions(
                    d.path().join("segment-active.jsonl"),
                    fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            drop(l);
            assert!(CanonicalLog::open(d.path()).is_err());
            assert!(d.path().join("segment-active.jsonl").exists());
        }
    }

    #[test]
    fn interrupted_rotation_rejects_unrecognized_aliases_without_data_loss() {
        for kind in ["different-inode", "symlink", "bad-name"] {
            let d = tempfile::tempdir().unwrap();
            let mut l = log(&d);
            l.append(daemon_source(), record(Level::Info, "preserve"))
                .unwrap();
            let active = d.path().join("segment-active.jsonl");
            let original = fs::read(&active).unwrap();
            let completed = d.path().join(segment_name_for(1, 2));
            match kind {
                "different-inode" => {
                    fs::hard_link(&active, d.path().join("unknown-alias")).unwrap();
                    fs::write(&completed, b"other").unwrap();
                    fs::set_permissions(&completed, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "symlink" => {
                    fs::hard_link(&active, d.path().join("unknown-alias")).unwrap();
                    std::os::unix::fs::symlink(&active, &completed).unwrap();
                }
                "bad-name" => fs::hard_link(&active, d.path().join("segment-123.jsonl")).unwrap(),
                _ => unreachable!(),
            }
            drop(l);
            assert!(CanonicalLog::open(d.path()).is_err(), "{kind}");
            assert_eq!(fs::read(active).unwrap(), original, "{kind}");
        }
    }

    #[test]
    fn interrupted_rotation_rejects_untrusted_directory_before_mutation() {
        for mode in [0o755, 0o777] {
            let d = tempfile::tempdir().unwrap();
            let mut l = log(&d);
            l.append(daemon_source(), record(Level::Info, "preserve"))
                .unwrap();
            l.publish_rotated_segment().unwrap();
            let before = segment_names(&l.authority).unwrap();
            drop(l);
            fs::set_permissions(d.path(), fs::Permissions::from_mode(mode)).unwrap();
            assert!(CanonicalLog::open(d.path()).is_err());
            assert_eq!(
                segment_names(&Directory::open(d.path()).unwrap()).unwrap(),
                before
            );
            fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(all_records(&CanonicalLog::open(d.path()).unwrap()).len(), 1);
        }
    }

    #[test]
    fn interrupted_rotation_full_inventory_recovers_before_normal_bound() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        l.append(daemon_source(), record(Level::Info, "preserve"))
            .unwrap();
        for i in 0..MAX_SEGMENTS - 1 {
            l.authority
                .write_atomic(&segment_name_for(i as u128, 0), b"", 0o600)
                .unwrap();
        }
        for name in LOG_AUXILIARY_NAMES {
            if !l.authority.entry_exists(name).unwrap() {
                l.authority.write_atomic(name, b"", 0o600).unwrap();
            }
        }
        // Historical writer directories occupy the archive capacity reserved
        // by the same production enumeration bound as legacy segment files.
        for writer in 0..crate::log_archive::MAX_SESSIONS {
            l.authority
                .create_private_child(&format!("{writer:032x}"))
                .unwrap();
        }
        let pending = serde_json::to_vec(&PendingBatch {
            start_sequence: 2,
            batch: AppBatch {
                schema_version: 1,
                batch_id: "abcdef0123456789abcdef0123456789".into(),
                records: vec![record(Level::Info, "pending")],
            },
        })
        .unwrap();
        l.authority
            .write_atomic("accepted-batch.pending", &pending, 0o600)
            .unwrap();
        // Publishing pending consumes its own reserved temporary name.
        l.authority
            .write_atomic(".accepted-batch.pending.tmp", b"interrupted", 0o600)
            .unwrap();
        assert_eq!(
            l.authority
                .entry_names_bounded(MAX_LOG_DIRECTORY_ENTRIES)
                .unwrap()
                .len(),
            MAX_LOG_DIRECTORY_ENTRIES - 2
        );
        l.publish_rotated_segment().unwrap();
        drop(l);
        repair_torn_segments(d.path()).unwrap();
        let dir = Directory::open(d.path()).unwrap();
        assert_eq!(
            dir.entry_names_bounded(MAX_LOG_DIRECTORY_ENTRIES)
                .unwrap()
                .len(),
            MAX_LOG_DIRECTORY_ENTRIES - 2
        );
        assert!(!dir
            .read_trusted("segment-active.jsonl", MAX_SEGMENT_BYTES as usize, 0o600)
            .unwrap()
            .is_empty());
        repair_torn_segments(d.path()).unwrap();
        let reopened = CanonicalLog::open(d.path()).unwrap();
        assert_eq!(all_records(&reopened).len(), 2);
        reopened.export(&serde_json::json!({})).unwrap();
    }

    #[test]
    fn export_segment_subreasons_are_closed_and_payload_free() {
        for (source, expected) in [
            (
                "directory entry bound exceeded",
                "segment-directory-entry-bound",
            ),
            (
                "non-UTF8 directory entry",
                "segment-directory-entry-encoding",
            ),
            (
                "trusted entry is not a single-link regular file",
                "segment-file-kind-or-links",
            ),
            ("trusted entry has unexpected owner", "segment-file-owner"),
            ("trusted entry has unexpected mode", "segment-file-mode"),
            ("trusted file exceeds size bound", "segment-file-size-bound"),
            (
                "trusted file size changed while reading",
                "segment-file-size-changed",
            ),
            (
                "trusted file metadata changed while reading",
                "segment-file-metadata-changed",
            ),
            ("export exceeds bound", "segment-export-size-bound"),
            (
                "private=secret trusted file exceeds size bound",
                "segment-read",
            ),
        ] {
            let error = export_stage("segment-read", invalid(source));
            assert_eq!(export_failure_reason(&error), expected);
            assert!(!error.to_string().contains("secret"));
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn export_segment_subreasons_reproduce_actual_file_boundaries() {
        for (fault, expected) in [
            ("mode", "segment-file-mode"),
            ("links", "segment-file-kind-or-links"),
            ("size", "segment-file-size-bound"),
            ("entries", "segment-directory-entry-bound"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let mut logger = log(&directory);
            logger
                .append(daemon_source(), record(Level::Info, "private=secret"))
                .unwrap();
            let active = directory.path().join("segment-active.jsonl");
            match fault {
                "mode" => fs::set_permissions(&active, fs::Permissions::from_mode(0o644)).unwrap(),
                "links" => fs::hard_link(&active, directory.path().join("other")).unwrap(),
                "size" => File::options()
                    .write(true)
                    .open(&active)
                    .unwrap()
                    .set_len(MAX_SEGMENT_BYTES + 1)
                    .unwrap(),
                "entries" => {
                    for i in 0..MAX_LOG_DIRECTORY_ENTRIES {
                        logger
                            .authority
                            .write_atomic(&format!("aux-{i}"), b"", 0o600)
                            .unwrap();
                    }
                }
                _ => unreachable!(),
            }
            let error = logger.export(&serde_json::json!({})).unwrap_err();
            assert_eq!(export_failure_reason(&error), expected);
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn export_retention_with_sidecars_pending_batch_and_recovery_temps() {
        let d = tempfile::tempdir().unwrap();
        let mut logger = log(&d);
        // Fill the steady retained inventory with genuine canonical records.
        for i in 1..MAX_SEGMENTS {
            logger
                .append(daemon_source(), record(Level::Info, &format!("row-{i}")))
                .unwrap();
            logger
                .authority
                .rename(
                    "segment-active.jsonl",
                    &segment_name_for(i as u128, i as u64 + 1),
                )
                .unwrap();
        }
        logger
            .append(daemon_source(), record(Level::Info, "active"))
            .unwrap();
        for name in ["helper-error.log", "remount-dbg.log", "accepted-batches"] {
            logger.authority.write_atomic(name, b"", 0o600).unwrap();
        }
        let pending = serde_json::to_vec(&PendingBatch {
            start_sequence: MAX_SEGMENTS as u64 + 1,
            batch: AppBatch {
                schema_version: 1,
                batch_id: "abcdef0123456789abcdef0123456789".into(),
                records: vec![record(Level::Info, "pending")],
            },
        })
        .unwrap();
        logger
            .authority
            .write_atomic("accepted-batch.pending", &pending, 0o600)
            .unwrap();
        // 16 canonical + 2 real sidecars + ledger + pending = 20 entries.
        // This valid snapshot failed the old nineteen-entry bound.
        assert_eq!(logger.authority.entry_names_bounded(64).unwrap().len(), 22);
        logger.export(&serde_json::json!({})).unwrap();
        for name in &LOG_AUXILIARY_NAMES[4..] {
            logger
                .authority
                .write_atomic(name, b"interrupted-publication", 0o600)
                .unwrap();
        }
        let snapshot = logger.export(&serde_json::json!({})).unwrap();
        assert!(!snapshot.is_empty());
        assert_eq!(
            read_segments(&logger.authority).unwrap().len(),
            MAX_SEGMENTS
        );
        // Cold reopening recovers the actual pending batch without dropping
        // retained canonical records or allowing sidecars into the stream.
        drop(logger);
        let start = std::sync::Barrier::new(2);
        let logger = thread::scope(|scope| {
            let start_ref = &start;
            let path = d.path();
            let reader = scope.spawn(move || {
                let reader = CanonicalLog::open_for_export(path).unwrap();
                start_ref.wait();
                for _ in 0..16 {
                    reader.export(&serde_json::json!({})).unwrap();
                    thread::yield_now();
                }
            });
            start.wait();
            let logger = CanonicalLog::open(d.path()).unwrap();
            reader.join().unwrap();
            logger
        });
        let records = read_segments(&logger.authority).unwrap();
        assert_eq!(records.len(), MAX_SEGMENTS + 1);
        assert_eq!(records.last().unwrap().message, "pending");
        logger.export(&serde_json::json!({})).unwrap();
        let existing = logger
            .authority
            .entry_names_bounded(MAX_LOG_DIRECTORY_ENTRIES)
            .unwrap()
            .len();
        for index in existing..=MAX_LOG_DIRECTORY_ENTRIES {
            logger
                .authority
                .write_atomic(&format!("unexpected-overflow-{index}"), b"", 0o600)
                .unwrap();
        }
        assert_eq!(
            export_failure_reason(&logger.export(&serde_json::json!({})).unwrap_err()),
            "segment-directory-entry-bound"
        );
    }

    #[test]
    fn export_closed_diagnosis_reproduces_record_failures_without_payload() {
        for (content, expected) in [
            (b"private=secret".to_vec(), "record-unterminated"),
            (b"private=secret\n".to_vec(), "record-json"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let logger = CanonicalLog::open(directory.path().join("logs")).unwrap();
            logger
                .authority
                .write_atomic("segment-active.jsonl", &content, 0o600)
                .unwrap();
            let error = logger.export(&serde_json::json!({})).unwrap_err();
            assert_eq!(export_failure_reason(&error), expected);
            assert!(!error.to_string().contains("secret"));
        }
        let directory = tempfile::tempdir().unwrap();
        let mut logger = CanonicalLog::open(directory.path().join("logs")).unwrap();
        logger
            .append(daemon_source(), record(Level::Info, "private=secret"))
            .unwrap();
        let bytes = logger
            .authority
            .read_trusted("segment-active.jsonl", MAX_SEGMENT_BYTES as usize, 0o600)
            .unwrap();
        logger
            .authority
            .write_atomic(
                "segment-active.jsonl",
                &[bytes.as_slice(), bytes.as_slice()].concat(),
                0o600,
            )
            .unwrap();
        let error = logger.export(&serde_json::json!({})).unwrap_err();
        assert_eq!(export_failure_reason(&error), "sequence-duplicate");
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn export_closed_diagnosis_keeps_errno_and_unknown_is_closed() {
        let error = export_stage("directory-open", io::Error::from_raw_os_error(libc::ENOENT));
        assert_eq!(export_failure_errno(&error), Some(libc::ENOENT));
        assert_eq!(export_failure_reason(&error), "directory-open");
        let unknown = invalid("password=secret");
        assert_eq!(export_failure_reason(&unknown), "unknown");
    }

    #[test]
    fn uplink_batch_syncs_once_and_preserves_order() {
        let directory = tempfile::tempdir().unwrap();
        with_test_log(&directory.path().join("logs"), || {
            let outer = begin_uplink_batch();
            for number in 0..8 {
                let inner = begin_uplink_batch();
                assert_eq!(
                    append_global(
                        daemon_source(),
                        record(Level::Debug, &format!("line-{number}"))
                    )
                    .unwrap(),
                    number + 1
                );
                drop(inner);
            }
            TEST_LOG.with(|log| {
                let log = log.borrow();
                let log = log.as_ref().unwrap();
                assert_eq!(log.synchronizations, 0);
                assert!(log.pending_file.is_some());
                let rows = read_segments(&log.authority).unwrap();
                assert_eq!(rows.len(), 8);
                for (number, row) in rows.iter().enumerate() {
                    assert_eq!(row.sequence, number as u64 + 1);
                    assert_eq!(row.message, format!("line-{number}"));
                    assert_eq!(row.level, Level::Debug);
                }
            });
            drop(outer);
            TEST_LOG.with(|log| {
                let log = log.borrow();
                let log = log.as_ref().unwrap();
                assert_eq!(log.synchronizations, 1);
                assert!(log.pending_file.is_none());
            });
        });
    }

    #[test]
    fn uplink_batch_durable_append_and_rotation_flush_prior_prefix() {
        let directory = tempfile::tempdir().unwrap();
        with_test_log(&directory.path().join("logs"), || {
            TEST_LOG.with(|log| {
                let mut log = log.borrow_mut();
                let log = log.as_mut().unwrap();
                while log
                    .authority
                    .metadata_trusted("segment-active.jsonl", 0o600)
                    .map(|(_, size)| size)
                    .unwrap_or(0)
                    + 7000
                    < MAX_SEGMENT_BYTES
                {
                    log.append(daemon_source(), record(Level::Debug, &"f".repeat(6000)))
                        .unwrap();
                }
                log.synchronizations = 0;
            });
            let batch = begin_uplink_batch();
            append_global(daemon_source(), record(Level::Debug, "prior")).unwrap();
            TEST_LOG.with(|log| {
                let mut log = log.borrow_mut();
                let log = log.as_mut().unwrap();
                log.append(daemon_source(), record(Level::Debug, "durable"))
                    .unwrap();
                assert_eq!(log.synchronizations, 1);
                assert!(log.pending_file.is_none());
            });
            append_global(daemon_source(), record(Level::Debug, "pending")).unwrap();
            append_global(daemon_source(), record(Level::Debug, &"r".repeat(8000))).unwrap();
            TEST_LOG.with(|log| assert_eq!(log.borrow().as_ref().unwrap().synchronizations, 2));
            drop(batch);
            TEST_LOG.with(|log| {
                let log = log.borrow();
                let log = log.as_ref().unwrap();
                assert_eq!(log.synchronizations, 3);
                let mut rows = read_segments(&log.authority).unwrap();
                rows.sort_by_key(|row| row.sequence);
                let end = rows.len();
                assert_eq!(rows[end - 4].message, "prior");
                assert_eq!(rows[end - 3].message, "durable");
                assert_eq!(rows[end - 2].message, "pending");
                assert_eq!(rows[end - 1].message, "r".repeat(8000));
                assert!(rows
                    .windows(2)
                    .all(|pair| pair[1].sequence == pair[0].sequence + 1));
            });
        });
    }

    #[test]
    fn uplink_batch_rejects_replaced_leaf_without_modifying_it() {
        for kind in 0..3 {
            let directory = tempfile::tempdir().unwrap();
            let logs = directory.path().join("logs");
            with_test_log(&logs, || {
                let batch = begin_uplink_batch();
                append_global(daemon_source(), record(Level::Debug, "owned")).unwrap();
                let active = logs.join("segment-active.jsonl");
                fs::rename(&active, logs.join("old-inode")).unwrap();
                let foreign = logs.join("foreign");
                fs::write(&foreign, b"foreign\n").unwrap();
                fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
                match kind {
                    0 => {
                        fs::write(&active, b"foreign\n").unwrap();
                        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
                    }
                    1 => std::os::unix::fs::symlink(&foreign, &active).unwrap(),
                    _ => fs::hard_link(&foreign, &active).unwrap(),
                }
                TEST_LOG.with(|log| {
                    assert!(log.borrow_mut().as_mut().unwrap().flush_pending().is_err())
                });
                assert!(append_global(daemon_source(), record(Level::Debug, "rejected")).is_err());
                assert_eq!(fs::read(&active).unwrap(), b"foreign\n");
                assert_eq!(fs::read(&foreign).unwrap(), b"foreign\n");
                drop(batch);
                TEST_LOG.with(|log| {
                    let log = log.borrow();
                    let log = log.as_ref().unwrap();
                    assert_eq!(log.synchronizations, 0);
                    assert!(log.pending_file.is_some());
                });
            });
        }
    }
    #[test]
    fn spoof_and_replay_are_rejected_or_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        let b=serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"batchId":"0123456789abcdef0123456789abcdef","records":[record(Level::Info,"once")]})).unwrap();
        assert!(l.accept_app_batch(1, 2, &Peer(false), &b).is_err());
        assert_eq!(
            l.accept_app_batch(1, 2, &Peer(true), &b).unwrap(),
            l.accept_app_batch(1, 2, &Peer(true), &b).unwrap()
        );
        assert_eq!(
            l.query(&Query {
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
            .records
            .len(),
            1
        );
    }
    #[test]
    fn query_bounds_filters_and_stop() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        for i in 0..210 {
            l.append(
                Source {
                    kind: "daemon".into(),
                    id: None,
                },
                record(Level::Info, &format!("record-{i}")),
            )
            .unwrap();
        }
        let q = l
            .query(&Query {
                after_sequence: 0,
                limit: 200,
                levels: vec![Level::Info],
                kinds: vec!["daemon".into()],
                agent_ids: vec![],
                search: Some("record".into()),
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap();
        assert_eq!(q.records.len(), 200);
        let mut s = SubscriptionRegistry::default();
        let id = s.follow(q.cursor);
        assert!(s.stop(id));
        assert!(!s.stop(id));
    }
    #[test]
    fn export_snapshot_policy_authorizes_runtime_directory_lock() {
        let policy = include_str!("../../selinux/voboost.te");
        let rule = policy
            .split("allow voboost voboost_data_file:dir {")
            .nth(1)
            .unwrap()
            .split("};")
            .next()
            .unwrap();
        assert!(rule
            .split_whitespace()
            .any(|permission| permission == "lock"));
    }

    #[test]
    fn export_transaction_blocks_real_writer_until_snapshot_released() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = log(&directory);
        let authority = Directory::open(directory.path()).unwrap();
        let guard = authority.lock_transaction(Duration::from_secs(2)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            tx.send(writer.append(daemon_source(), record(Level::Info, "blocked")))
                .unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(30)).is_err());
        drop(guard);
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
        worker.join().unwrap();
    }

    fn validate_complete_export(bytes: &[u8]) {
        assert_eq!(&bytes[..10], MAGIC);
        let header_length = u32::from_be_bytes(bytes[11..15].try_into().unwrap()) as usize;
        let header: serde_json::Value =
            serde_json::from_slice(&bytes[55..55 + header_length]).unwrap();
        let count = header["recordsLength"].as_u64().unwrap() as usize;
        let records = &bytes[55 + header_length..55 + header_length + count];
        assert!(records.is_empty() || records.ends_with(b"\n"));
        for line in records
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            serde_json::from_slice::<CanonicalRecord>(line).unwrap();
        }
    }

    fn validate_contended_export(result: io::Result<Vec<u8>>) {
        match result {
            Ok(bytes) => validate_complete_export(&bytes),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(export_failure_reason(&error), "snapshot-lock");
            }
        }
    }

    #[test]
    fn held_export_lock_times_out_and_recovers_after_release() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = log(&directory);
        writer
            .append(daemon_source(), record(Level::Info, "before"))
            .unwrap();
        let reader = CanonicalLog::open_for_export(directory.path()).unwrap();
        let authority = Directory::open(directory.path()).unwrap();
        let guard = authority.lock_transaction(Duration::from_secs(2)).unwrap();
        let error = reader.export(&serde_json::json!({})).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(export_failure_reason(&error), "snapshot-lock");
        drop(guard);
        validate_complete_export(&reader.export(&serde_json::json!({})).unwrap());
    }

    #[test]
    fn contended_export_rejects_other_errors() {
        for error in [
            export_stage(
                "segment-read",
                io::Error::new(io::ErrorKind::TimedOut, "secret"),
            ),
            export_stage(
                "snapshot-lock",
                io::Error::new(io::ErrorKind::InvalidData, "secret"),
            ),
            io::Error::new(io::ErrorKind::TimedOut, "different timeout"),
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory transaction lock deadline",
            ),
        ] {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                validate_contended_export(Err(error))
            }))
            .is_err());
        }
    }

    #[test]
    fn concurrent_live_exports_remain_complete_during_append_and_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = log(&directory);
        let path = directory.path().to_owned();
        // Scoped threads finish before unwinding can remove the directory.
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                for index in 0..(MAX_SEGMENT_BYTES as usize / 4096 + 1) {
                    writer
                        .append(
                            daemon_source(),
                            record(Level::Info, &format!("{index}:{}", "x".repeat(4096))),
                        )
                        .unwrap();
                }
            });
            for _ in 0..25 {
                let reader = CanonicalLog::open_for_export(&path).unwrap();
                validate_contended_export(reader.export(&serde_json::json!({})));
            }
            worker.join().unwrap();
        });
        let reader = CanonicalLog::open_for_export(&path).unwrap();
        validate_complete_export(&reader.export(&serde_json::json!({})).unwrap());
        assert!(!segment_names(&Directory::open(&path).unwrap())
            .unwrap()
            .is_empty());
    }
    #[test]
    fn diagnostic_retention_and_export_budgets_are_coherent() {
        assert_eq!(MAX_SEGMENTS, 16);
        assert_eq!(MAX_SEGMENT_BYTES, 8 * 1024 * 1024);
        assert_eq!(MAX_SEGMENTS as u64 * MAX_SEGMENT_BYTES, 128 * 1024 * 1024);
        assert_eq!(MAX_EXPORT_BYTES, 400 * 1024 * 1024);
        let retained = (MAX_SEGMENTS
            + SEVERITY_TIERS
                .iter()
                .map(|(_, count)| *count)
                .sum::<usize>()) as u64
            * MAX_SEGMENT_BYTES;
        assert_eq!(retained, 384 * 1024 * 1024);
        for (_, maximum) in SEVERITY_TIERS {
            assert_eq!(maximum, 16);
            assert_eq!(maximum as u64 * MAX_SEGMENT_BYTES, 128 * 1024 * 1024);
        }
        assert!(retained + 8 * 1024 * 1024 <= MAX_EXPORT_BYTES as u64);
        assert_eq!(MAX_BATCH_LEDGER_BYTES, 32 * 1024 * 1024);
        // A formerly rejected payload now fits, with room for runtime context.
        let records = vec![b' '; 32 * 1024 * 1024 + 1];
        let bytes = encode_export(&records, b"{}").unwrap();
        assert_eq!(
            u64::from_be_bytes(bytes[15..23].try_into().unwrap()),
            records.len() as u64 + 2
        );
    }

    #[test]
    fn export_is_bounded_and_has_fixed_magic() {
        let out = encode_export(b"{}\n", br#"{"resident":false}"#).unwrap();
        assert_eq!(&out[..10], b"VBOOSTLOG1");
        assert!(encode_export(&vec![0; MAX_EXPORT_BYTES + 1], b"").is_err());
    }

    #[test]
    fn segment_authority_rejects_links_and_foreign_modes() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("outside", directory.path().join("segment-active.jsonl"))
            .unwrap();
        assert!(CanonicalLog::open(directory.path()).is_err());
        fs::remove_file(directory.path().join("segment-active.jsonl")).unwrap();
        fs::write(directory.path().join("segment-active.jsonl"), b"{}\n").unwrap();
        fs::set_permissions(
            directory.path().join("segment-active.jsonl"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(CanonicalLog::open(directory.path()).is_err());
    }

    #[test]
    fn agent_rpc_is_capability_scoped_and_replay_safe() {
        let directory = tempfile::tempdir().unwrap();
        let mut canonical = log(&directory);
        canonical
            .append(
                Source {
                    kind: "daemon".into(),
                    id: None,
                },
                record(Level::Info, "ready"),
            )
            .unwrap();
        let _ = GLOBAL.set(Mutex::new(canonical));
        let request = r#"{"afterSequence":0,"limit":20,"sources":["daemon"],"agentIds":[],"levels":["info"],"fromEpochMillis":0,"toEpochMillis":18446744073709551615,"text":"ready"}"#;
        let denied = HashSet::new();
        assert!(dispatch_agent_rpc("logs-query", "denied", request, &denied, &denied).is_err());
        let allowed = HashSet::from(["logs".to_string()]);
        let first =
            dispatch_agent_rpc("logs-follow", "request-1", request, &allowed, &allowed).unwrap();
        let replay =
            dispatch_agent_rpc("logs-follow", "request-1", request, &allowed, &allowed).unwrap();
        assert_eq!(first, replay);
        assert!(first.contains("\"records\""));
        assert!(dispatch_agent_rpc("logs-stop", "request-1", "{}", &allowed, &allowed).is_ok());
    }

    #[test]
    fn agent_filter_uses_selected_catalog_not_settings_resident_set() {
        let directory = tempfile::tempdir().unwrap();
        let _ = GLOBAL.set(Mutex::new(log(&directory)));
        let resident = HashSet::from(["logs".to_string(), "settings".to_string()]);
        let selected = HashSet::from([
            "logs".to_string(),
            "settings".to_string(),
            "keyboard-ru".to_string(),
        ]);
        let selected_request = r#"{"afterSequence":0,"limit":20,"sources":["agent"],"agentIds":["keyboard-ru"],"levels":["info"],"fromEpochMillis":0,"toEpochMillis":18446744073709551615,"text":""}"#;
        assert!(dispatch_agent_rpc(
            "logs-query",
            "cross-process",
            selected_request,
            &resident,
            &selected,
        )
        .is_ok());

        let absent_request = selected_request.replace("keyboard-ru", "planned-agent");
        assert!(dispatch_agent_rpc(
            "logs-query",
            "absent",
            &absent_request,
            &resident,
            &selected,
        )
        .is_err());
    }

    #[test]
    fn partial_app_frame_times_out_without_blocking_forever() {
        use std::time::Instant;

        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&[0, 0]).unwrap();
        let started = Instant::now();
        let error = read_app_batch(&mut server, Duration::from_millis(10)).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn app_peer_files_reject_n_plus_one_before_unbounded_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peer");
        fs::write(&path, vec![b'x'; 256]).unwrap();
        assert_eq!(read_bounded_file(&path, 256).unwrap().len(), 256);
        fs::write(&path, vec![b'x'; 257]).unwrap();
        assert!(read_bounded_file(&path, 256).is_err());
    }

    #[test]
    fn existing_app_batch_preserves_producer_context_inside_fields() {
        let d = tempfile::tempdir().unwrap();
        let mut logger = log(&d);
        logger
            .append(daemon_source(), record(Level::Debug, "prior"))
            .unwrap();
        let fields: HashMap<String, String> = [
            ("producerTimestamp", "2026-10-26T09:00:00.000Z"),
            ("event", "log.line"),
            ("outcome", "info"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        let batch = AppBatch {
            schema_version: 1,
            batch_id: "abcdef0123456789abcdef0123456789".into(),
            records: vec![ProducerRecord {
                level: Level::Info,
                component: "application".into(),
                message: "Operation completed".into(),
                fields: fields.clone(),
            }],
        };
        let bytes = serde_json::to_vec(&batch).unwrap();
        let parsed: AppBatch = serde_json::from_slice(&bytes).unwrap();
        validate_producer(&parsed.records[0]).unwrap();
        accept(&mut logger, &bytes).unwrap();
        let rows = all_records(&logger);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].fields, fields);
        assert_eq!(rows[1].sequence, 2);
        assert_eq!(
            rows[1].source,
            Source {
                kind: "app".into(),
                id: None
            }
        );
        assert_eq!(rows[1].schema_version, 1);
        assert_ne!(rows[1].timestamp, rows[1].fields["producerTimestamp"]);
        accept(&mut logger, &bytes).unwrap();
        assert_eq!(all_records(&logger).len(), 2);
    }

    #[test]
    fn app_batches_admit_all_severities_without_losing_first_errors() {
        for levels in [
            vec![Level::Error],
            vec![Level::Debug],
            vec![Level::Error, Level::Info, Level::Debug],
        ] {
            let d = tempfile::tempdir().unwrap();
            let mut logger = log(&d);
            let batch = AppBatch {
                schema_version: 1,
                batch_id: "abcdef0123456789abcdef0123456789".into(),
                records: levels
                    .iter()
                    .cloned()
                    .map(|level| record(level, "retained"))
                    .collect(),
            };
            let bytes = serde_json::to_vec(&batch).unwrap();
            assert!(logger.accept_app_batch(1, 2, &Peer(false), &bytes).is_err());
            assert!(all_records(&logger).is_empty());
            accept(&mut logger, &bytes).unwrap();
            assert_eq!(
                all_records(&logger)
                    .iter()
                    .map(|r| r.level.clone())
                    .collect::<Vec<_>>(),
                levels
            );
            let mut bad = batch.clone();
            bad.schema_version = 2;
            bad.batch_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
            assert!(accept(&mut logger, &serde_json::to_vec(&bad).unwrap()).is_err());
            let mut bad = batch.clone();
            bad.batch_id = "cccccccccccccccccccccccccccccccc".into();
            bad.records[0].message = "x".repeat(8193);
            assert!(accept(&mut logger, &serde_json::to_vec(&bad).unwrap()).is_err());
            assert_eq!(all_records(&logger).len(), levels.len());
        }
    }

    #[test]
    fn agent_event_clock_is_context_and_does_not_replace_sink_timestamp() {
        let d = tempfile::tempdir().unwrap();
        with_test_log(&d.path().join("logs"), || {
            crate::log::agent(
                1700000000123,
                Some("fixture-agent"),
                2,
                "Vehicle settings applied",
                [("producerTimestampMs".into(), "spoofed".into())]
                    .into_iter()
                    .collect(),
            );
            TEST_LOG.with(|log| {
                let rows = all_records(log.borrow().as_ref().unwrap());
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].fields["producerTimestampMs"], "1700000000123");
                assert_eq!(rows[0].fields["producerClock"], "unix");
                assert_eq!(rows[0].sequence, 1);
                assert_eq!(rows[0].source.kind, "agent");
                assert_ne!(rows[0].timestamp, "2023-11-14T22:13:20.123Z");
            });
        });
    }

    fn batch_json(id: &str, records_json: &str) -> Vec<u8> {
        format!("{{\"schemaVersion\":1,\"batchId\":\"{id}\",\"records\":{records_json}}}")
            .into_bytes()
    }
    fn accept(l: &mut CanonicalLog, bytes: &[u8]) -> io::Result<String> {
        l.accept_app_batch(1, 2, &Peer(true), bytes)
    }
    fn all_records(l: &CanonicalLog) -> Vec<CanonicalRecord> {
        l.query(&Query {
            after_sequence: 0,
            limit: MAX_QUERY_RECORDS,
            levels: vec![],
            kinds: vec![],
            agent_ids: vec![],
            search: None,
            from_epoch_millis: 0,
            to_epoch_millis: u64::MAX,
        })
        .unwrap()
        .records
    }
    #[test]
    fn oversize_secondary_record_leaves_no_durable_prefix_and_retry_is_clean() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        let small = record(Level::Info, "small");
        let mut big = record(Level::Info, "big");
        // Message within the producer bound, but 32 max-size fields push the
        // canonical record over the 16 KiB record bound.
        big.fields = (0..32)
            .map(|i| (format!("k{i:03}"), "v".repeat(1024)))
            .collect();
        let big_json = serde_json::to_string(&big).unwrap();
        let good = serde_json::to_vec(&AppBatch {
            schema_version: 1,
            batch_id: "abcdef0123456789abcdef0123456789".into(),
            records: vec![small.clone()],
        })
        .unwrap();
        let tiny_json = serde_json::to_string(&record(Level::Info, "tiny")).unwrap();
        let mixed = batch_json(
            "abcdef0123456789abcdef012345678a",
            &format!("[{big_json},{tiny_json}]"),
        );
        assert!(serde_json::from_slice::<AppBatch>(&mixed).is_ok());
        // The batch as a whole parses and passes producer bounds, but the
        // first record exceeds the canonical record bound after appending
        // schema/sequence/source wrapping.
        assert!(accept(&mut l, &mixed).is_err());
        assert!(all_records(&l).is_empty());
        assert!(!l.authority.entry_exists("accepted-batch.pending").unwrap());
        // A later valid batch still lands intact at the origin sequence.
        accept(&mut l, &good).unwrap();
        let records = all_records(&l);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].message, "small");
        assert_eq!(records[0].sequence, 1);
    }

    #[test]
    fn recovery_does_not_false_ack_when_a_daemon_record_occupies_the_sequence() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        l.append(
            Source {
                kind: "daemon".into(),
                id: None,
            },
            record(Level::Info, "daemon-owned"),
        )
        .unwrap();
        // Pending intent claims sequence 1, but the durable sequence-1
        // record is daemon-owned and byte-different: recovery must fail
        // loudly, never ACK a batch whose records were never written.
        let batch = serde_json::to_vec(&AppBatch {
            schema_version: 1,
            batch_id: "abcdef0123456789abcdef0123456789".into(),
            records: vec![record(Level::Info, "app-first")],
        })
        .unwrap();
        l.authority
            .write_atomic(
                "accepted-batch.pending",
                &serde_json::to_vec(&PendingBatch {
                    start_sequence: 1,
                    batch: serde_json::from_slice(&batch).unwrap(),
                })
                .unwrap(),
                0o600,
            )
            .unwrap();
        drop(l);
        assert!(CanonicalLog::open(d.path()).is_err());
    }

    #[test]
    fn torn_tail_is_repaired_to_valid_prefix_and_interior_corruption_is_hard_error() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = log(&d);
            l.append(
                Source {
                    kind: "daemon".into(),
                    id: None,
                },
                record(Level::Info, "one"),
            )
            .unwrap();
            l.append(
                Source {
                    kind: "daemon".into(),
                    id: None,
                },
                record(Level::Info, "two"),
            )
            .unwrap();
        }
        let segment = d.path().join("segment-active.jsonl");
        let mut bytes = fs::read(&segment).unwrap();
        assert!(bytes.ends_with(b"\n"));
        // Simulate a torn third append: prefix of a JSON line, no newline.
        bytes.extend_from_slice(b"{\"schema\":");
        fs::write(&segment, &bytes).unwrap();
        let opened = CanonicalLog::open(d.path()).unwrap();
        let records = all_records(&opened);
        assert_eq!(records.len(), 2);
        // Corrupting the FIRST line (interior) must stay a hard failure:
        // tearing repair must never mask mid-segment corruption.
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o600)).unwrap();
        let mut torn = fs::read(&segment).unwrap();
        let newline = torn.iter().position(|b| *b == b'\n').unwrap();
        torn[newline] = b' ';
        fs::write(&segment, &torn).unwrap();
        assert!(CanonicalLog::open(d.path()).is_err());
    }

    #[test]
    fn ledger_exhaustion_refuses_admission_before_writing_any_record() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        let mut ledger = String::new();
        for i in 0..MAX_ACCEPTED_BATCHES {
            let mut id = format!("{:032x}", i);
            id.truncate(32);
            ledger.push_str(&id);
            ledger.push('\n');
        }
        l.authority
            .write_atomic("accepted-batches", ledger.as_bytes(), 0o600)
            .unwrap();
        let b = batch_json(
            "abcdef0123456789abcdef0123456789",
            &format!(
                "[{}]",
                serde_json::to_string(&record(Level::Info, "refused")).unwrap()
            ),
        );
        assert!(accept(&mut l, &b).is_err());
        assert!(all_records(&l).is_empty());
        assert!(!l.authority.entry_exists("accepted-batch.pending").unwrap());
    }

    #[test]
    fn retention_ties_are_deterministic_and_malformed_candidates_fail_before_deletion() {
        let d = tempfile::tempdir().unwrap();
        let mut l = log(&d);
        l.append(
            Source {
                kind: "daemon".into(),
                id: None,
            },
            record(Level::Info, "tie"),
        )
        .unwrap();
        let row = all_records(&l).remove(0);
        let mut line = serde_json::to_vec(&row).unwrap();
        line.push(b'\n');
        for i in 0..MAX_SEGMENTS {
            let path = d.path().join(segment_name_for(i as u128, 2));
            fs::write(&path, &line).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        // Unrecognized filenames are outside retention's existing ownership.
        let foreign = d.path().join("segment-malformed.jsonl");
        fs::write(&foreign, b"foreign").unwrap();
        let corrupt = d.path().join(segment_name_for(0, 2));
        fs::write(&corrupt, b"not-json\n").unwrap();
        assert!(retention_sweep(&l.authority).is_err());
        assert_eq!(segment_names(&l.authority).unwrap().len(), MAX_SEGMENTS);
        fs::write(&corrupt, &line).unwrap();
        retention_sweep(&l.authority).unwrap();
        let remaining = segment_names(&l.authority).unwrap();
        assert_eq!(remaining.len(), MAX_SEGMENTS - 1);
        for i in 0..1 {
            assert!(!remaining.contains(&segment_name_for(i, 2)));
        }
        assert_eq!(fs::read(foreign).unwrap(), b"foreign");
    }

    #[test]
    fn retention_ignores_clock_changes_and_preserves_restart_sequence() {
        for legacy in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let mut l = log(&d);
            for i in 0..MAX_SEGMENTS + 2 {
                l.append(
                    Source {
                        kind: "daemon".into(),
                        id: None,
                    },
                    record(Level::Debug, "boot"),
                )
                .unwrap();
                let rows = all_records(&l);
                let row = rows.last().unwrap();
                // Alternate future and rollback clocks across daemon lifetimes.
                let stamp = if i % 2 == 0 { 9_000_000 + i } else { 1_000 + i };
                let name = if legacy {
                    format!("segment-{:020}.jsonl", stamp)
                } else {
                    segment_name_for(stamp as u128, 100_000 - i as u64)
                };
                let mut line = serde_json::to_vec(row).unwrap();
                line.push(b'\n');
                let path = d.path().join(&name);
                fs::write(&path, &line).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                l.authority.unlink("segment-active.jsonl").unwrap();
                retention_sweep(&l.authority).unwrap();
                drop(l);
                l = CanonicalLog::open(d.path()).unwrap();
                assert_eq!(l.next_sequence, i as u64 + 2);
                let mut retained = all_records(&l);
                retained.sort_by_key(|r| r.sequence);
                let expected_start = (i + 2).saturating_sub(MAX_SEGMENTS - 1).max(1) as u64;
                assert_eq!(retained.first().unwrap().sequence, expected_start);
                assert_eq!(retained.last().unwrap().sequence, i as u64 + 1);
                assert!(segment_names(&l.authority).unwrap().len() < MAX_SEGMENTS);
            }
        }
    }

    #[test]
    fn reversed_timestamp_segments_page_in_sequence_order() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut l = log(&d);
            for i in 0..6 {
                l.append(
                    Source {
                        kind: "daemon".into(),
                        id: None,
                    },
                    record(Level::Info, &format!("m{i}")),
                )
                .unwrap();
            }
        }
        // Manually move all records into completed segments whose names run
        // opposite to sequence order: newest-content first lexically.
        let records = {
            let l = CanonicalLog::open(d.path()).unwrap();
            all_records(&l)
        };
        fs::remove_file(d.path().join("segment-active.jsonl")).unwrap();
        for (i, chunk) in records.chunks(2).enumerate() {
            let stamp = 1_000_000_000_000u128 - (i as u128) * 10;
            let name = format!(
                "segment-{:020}-{:020}.jsonl",
                stamp,
                (chunk.last().unwrap().sequence + 1)
            );
            let mut body = Vec::new();
            for r in chunk {
                body.extend_from_slice(&serde_json::to_vec(r).unwrap());
                body.push(b'\n');
            }
            let path = d.path().join(&name);
            fs::write(&path, &body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let opened = CanonicalLog::open(d.path()).unwrap();
        let page1 = opened
            .query(&Query {
                after_sequence: 0,
                limit: 2,
                levels: vec![],
                kinds: vec![],
                agent_ids: vec![],
                search: None,
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap();
        assert_eq!(
            page1.records.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            vec![1, 2]
        );
        let page2 = opened
            .query(&Query {
                after_sequence: page1.cursor,
                limit: 2,
                levels: vec![],
                kinds: vec![],
                agent_ids: vec![],
                search: None,
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap();
        assert_eq!(
            page2.records.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn rotation_never_overwrites_an_existing_completed_segment() {
        let d = tempfile::tempdir().unwrap();
        // Pre-create a completed segment that a later rotation would love to
        // claim: same stamp trick as any fast rotation.
        let foreign_name = format!("segment-{:020}.jsonl", 1710000000000u128);
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // A syntactically valid canonical record so segment scans still parse;
        // the point is whether rotation can REPLACE this file's content.
        let foreign = encode_canonical_record(
            Source {
                kind: "daemon".into(),
                id: None,
            },
            0,
            &record(Level::Info, "foreign"),
        );
        let mut foreign_body = serde_json::to_vec(&foreign).unwrap();
        foreign_body.push(b'\n');
        let stored = foreign_body.clone();
        let foreign_path = d.path().join(&foreign_name);
        fs::write(&foreign_path, &foreign_body).unwrap();
        fs::set_permissions(&foreign_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut l = CanonicalLog::open(d.path()).unwrap();
        l.append(
            Source {
                kind: "daemon".into(),
                id: None,
            },
            record(Level::Info, "rotate-me"),
        )
        .unwrap();
        // Fill the active segment past MAX_SEGMENT_BYTES so rotation fires.
        let mut big = record(Level::Info, "filler");
        big.message = "y".repeat(7 * 1024);
        let mut appended = 0;
        while appended < MAX_SEGMENT_BYTES as usize / big.message.len() + 1 {
            l.append(
                Source {
                    kind: "daemon".into(),
                    id: None,
                },
                big.clone(),
            )
            .unwrap();
            appended += 1;
        }
        assert!(segment_names(&l.authority).unwrap().len() > 1);
        // The pre-existing completed segment must never be replaced by the
        // rotation: its bytes survive byte-for-byte.
        assert_eq!(fs::read(&foreign_path).unwrap(), stored);
    }

    #[test]
    fn pending_batch_recovery_completes_without_duplicate_sequences() {
        let directory = tempfile::tempdir().unwrap();
        let mut canonical = log(&directory);
        let batch = AppBatch {
            schema_version: 1,
            batch_id: "abcdef0123456789abcdef0123456789".into(),
            records: vec![record(Level::Info, "first"), record(Level::Error, "second")],
        };
        canonical
            .authority
            .write_atomic(
                "accepted-batch.pending",
                &serde_json::to_vec(&PendingBatch {
                    start_sequence: 1,
                    batch,
                })
                .unwrap(),
                0o600,
            )
            .unwrap();
        canonical
            .append(
                Source {
                    kind: "app".into(),
                    id: None,
                },
                record(Level::Info, "first"),
            )
            .unwrap();
        drop(canonical);
        let recovered = CanonicalLog::open(directory.path()).unwrap();
        let response = recovered
            .query(&Query {
                after_sequence: 0,
                limit: 20,
                levels: vec![],
                kinds: vec![],
                agent_ids: vec![],
                search: None,
                from_epoch_millis: 0,
                to_epoch_millis: u64::MAX,
            })
            .unwrap();
        assert_eq!(response.records.len(), 2);
        assert_eq!(response.records[0].sequence, 1);
        assert_eq!(response.records[1].sequence, 2);
        assert!(!recovered
            .authority
            .entry_exists("accepted-batch.pending")
            .unwrap());
    }

    #[test]
    fn package_uid_parser_requires_exact_package_field() {
        let bytes = b"ru.voboost.fake 10100 0 /data/user/0/ru.voboost.fake\nru.voboost 10123 0 /data/user/0/ru.voboost\n";
        assert_eq!(parse_installed_app_uid(bytes, "ru.voboost").unwrap(), 10123);
        assert!(parse_installed_app_uid(bytes, "ru.voboost.other").is_err());
        assert!(
            parse_installed_app_uid(b"ru.voboost 10123\nother.app 10123\n", "ru.voboost").is_err()
        );
        assert!(
            parse_installed_app_uid(b"ru.voboost 10123\nru.voboost 10124\n", "ru.voboost").is_err()
        );
    }

    #[test]
    fn app_peer_requires_exclusive_installed_uid_and_live_pid() {
        assert!(verify_app_peer(10123, 42, 10123).is_ok());
        assert!(verify_app_peer(10124, 42, 10123).is_err());
        assert!(verify_app_peer(10123, 0, 10123).is_err());
        assert!(verify_app_peer(0, 42, 0).is_err());
        assert!(verify_app_peer(9999, 42, 9999).is_err());
        assert!(verify_app_peer(20000, 42, 20000).is_err());
    }

    struct SettingsPeer(bool);
    impl SettingsPeerVerifier for SettingsPeer {
        fn is_settings_host(&self, _: u32, _: u32) -> bool {
            self.0
        }
    }

    #[test]
    fn socket_rpc_frame_classification_separates_batches_from_requests() {
        assert!(matches!(
            classify_frame(
                br#"{"schemaVersion":1,"batchId":"0123456789abcdef0123456789abcdef","records":[]}"#
            )
            .unwrap(),
            AppFrame::Batch
        ));
        match classify_frame(br#"{"requestId":"req-1","operation":"uninstall-request"}"#).unwrap() {
            AppFrame::Rpc {
                request_id,
                operation,
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(operation, "uninstall-request");
            }
            AppFrame::Batch => panic!("rpc envelope misclassified as a batch"),
        }
        // A parseable RPC envelope with an invalid request id or operation
        // charset is a frame error, never silently a batch.
        assert!(
            classify_frame(br#"{"requestId":"bad id","operation":"uninstall-request"}"#).is_err()
        );
        assert!(classify_frame(br#"{"requestId":"req-1","operation":"UNINSTALL"}"#).is_err());
        assert!(classify_frame(br#"{"requestId":"req-1","operation":""}"#).is_err());
    }

    #[test]
    fn socket_rpc_uninstall_attests_the_peer_and_stays_busy_idempotent() {
        crate::uninstall::reset_settings_request_for_test();
        let trusted = SettingsPeer(true);
        let untrusted = SettingsPeer(false);
        // A foreign peer never reaches the request, whatever its uid/pid are.
        assert_eq!(
            dispatch_socket_rpc_with_peer("uninstall-request", "req-1", 1000, 4242, &untrusted)
                .unwrap(),
            r#"{"requestId":"req-1","accepted":false,"reason":"wrong-peer"}"#
        );
        assert!(!crate::uninstall::settings_request_accepted());
        // The attested Settings peer is accepted exactly once; the retry
        // while the request is unconsumed is busy, and an unknown operation
        // is a stream error the client reads as not accepted.
        assert_eq!(
            dispatch_socket_rpc_with_peer("uninstall-request", "req-2", 1000, 4242, &trusted)
                .unwrap(),
            r#"{"requestId":"req-2","accepted":true}"#
        );
        assert!(crate::uninstall::settings_request_accepted());
        assert_eq!(
            dispatch_socket_rpc_with_peer("uninstall-request", "req-3", 1000, 4242, &trusted)
                .unwrap(),
            r#"{"requestId":"req-3","accepted":false,"reason":"busy"}"#
        );
        assert!(
            dispatch_socket_rpc_with_peer("logs-query", "req-4", 1000, 4242, &trusted).is_err()
        );
        crate::uninstall::reset_settings_request_for_test();
    }
}
