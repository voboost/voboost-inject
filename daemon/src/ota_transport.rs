//! Descriptor-only app-to-daemon OTA transport.
#![cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]

use std::fs::File;
use std::io;
#[cfg(test)]
use std::io::Read;
#[cfg(any(test, target_os = "android"))]
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[cfg(test)]
use voboost_contract::status::TerminalOutcome;
use voboost_contract::status::{
    ActiveReleaseIdentity, ActiveReleaseResult, CandidateArtifactDescriptor,
    CandidateDescriptorHandoff, DaemonOtaRequest, DaemonOtaResponse, DaemonProposalResult,
    OtaCandidateHandle, TerminalAcknowledgement, MAX_STATUS_BYTES,
};

use crate::{
    canonical_log,
    product_candidate::{Admission, ProductCandidateStore},
    trust, uninstall,
};
use voboost_contract::product_update::ProductUpdateOrigin;

pub const ABSTRACT_SOCKET_NAME: &str = "voboost.ota.v1";
pub const MAX_CHANGED_DESCRIPTORS: usize = 251;
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RECEIVED_FDS: usize = MAX_CHANGED_DESCRIPTORS + 2;
const AUTH_TIMEOUT: Duration = Duration::from_secs(8);
const RESPONSE_TIMEOUT: Duration = Duration::from_millis(10);
const PEER_CACHE_LIFETIME: Duration = Duration::from_secs(2);
const MAX_INGRESS_WORKERS: usize = 4;

struct PreparedRequest {
    stream: UnixStream,
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
    active_release: Option<Result<ActiveReleaseIdentity, String>>,
    authority: CachedPeer,
    deadline: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp(u64, u64, u64, i64, i64, i64, i64, u32, u32, u32);

fn file_stamp(path: &Path) -> io::Result<FileStamp> {
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() || m.nlink() != 1 {
        return Err(invalid("peer authority file is not single-link regular"));
    }
    Ok(metadata_stamp(&m))
}

fn metadata_stamp(m: &std::fs::Metadata) -> FileStamp {
    FileStamp(
        m.dev(),
        m.ino(),
        m.len(),
        m.ctime(),
        m.ctime_nsec(),
        m.mtime(),
        m.mtime_nsec(),
        m.mode(),
        m.uid(),
        m.gid(),
    )
}

#[derive(Clone)]
struct CachedPeer {
    uid: u32,
    expires: Instant,
    files: Vec<(std::path::PathBuf, Option<FileStamp>)>,
}

impl CachedPeer {
    fn valid(&self, uid: u32, now: Instant) -> bool {
        now < self.expires && self.current(uid)
    }

    fn admitted(&self, uid: u32, now: Instant, deadline: Instant) -> bool {
        now < deadline && self.current(uid)
    }

    fn current(&self, uid: u32) -> bool {
        uid == self.uid
            && self
                .files
                .iter()
                .all(|(path, stamp)| authority_stamp(path).is_ok_and(|fresh| &fresh == stamp))
    }
}

fn authority_stamp(path: &Path) -> io::Result<Option<FileStamp>> {
    match file_stamp(path) {
        Ok(stamp) => Ok(Some(stamp)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn pinned_peer_files() -> io::Result<Vec<(std::path::PathBuf, Option<FileStamp>)>> {
    let mut paths = vec![
        Path::new(crate::config::ROOT_ZONE).join("voboost.json"),
        Path::new(crate::config::ROOT_ZONE).join("voboost.json.sig"),
        Path::new(crate::config::ROOT_ZONE).join("operation.json"),
        "/data/system/packages.list".into(),
    ];
    let root = crate::secure_fs::Directory::open(Path::new(crate::config::ROOT_ZONE))?;
    match root.read_trusted("operation.json", 4096, 0o600) {
        Ok(bytes) => {
            let operation = crate::operation_contract::OperationDescriptor::parse(&bytes)
                .map_err(|error| invalid(&error))?;
            if operation.operation == crate::operation_contract::Operation::Update {
                paths.push(Path::new(crate::config::ROOT_ZONE).join(&operation.journal));
                let candidate = Path::new(crate::config::ROOT_ZONE)
                    .join("install")
                    .join(&operation.transaction_id)
                    .join("complete-candidate");
                paths.extend([
                    candidate.join("voboost.json"),
                    candidate.join("voboost.json.sig"),
                ]);
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    paths
        .into_iter()
        .map(|path| authority_stamp(&path).map(|stamp| (path, stamp)))
        .collect()
}

fn prepare_request(
    mut stream: UnixStream,
    cache: &Mutex<Option<CachedPeer>>,
) -> io::Result<PreparedRequest> {
    let deadline = Instant::now() + AUTH_TIMEOUT;
    let (uid, pid) = peer_credentials(&stream)?;
    canonical_log::verify_installed_app_peer(uid, pid)?;
    let cached = cache
        .lock()
        .map_err(|_| invalid("peer cache poisoned"))?
        .clone();
    let mut authority = match cached.filter(|cached| cached.valid(uid, Instant::now())) {
        Some(cached) => cached,
        None => {
            let files = pinned_peer_files()?;
            let (path, metadata) = authenticate_peer_apk(deadline)?;
            let mut verified = CachedPeer {
                uid,
                expires: Instant::now() + PEER_CACHE_LIFETIME,
                files,
            };
            if !verified.valid(uid, Instant::now()) {
                return Err(invalid("pinned APK authority changed while verifying"));
            }
            let path = std::path::PathBuf::from(path);
            verified.files.push((path, Some(metadata_stamp(&metadata))));
            if !verified.valid(uid, Instant::now()) {
                return Err(invalid("verified APK changed before caching"));
            }
            *cache.lock().map_err(|_| invalid("peer cache poisoned"))? = Some(verified.clone());
            verified
        }
    };
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(Duration::from_millis(10)))?;
    let (bytes, descriptors) = receive_frame_until(
        &mut stream,
        deadline.min(Instant::now() + REQUEST_TIMEOUT),
        |_| {},
    )?;
    let active_release = if matches!(
        DaemonOtaRequest::parse(&bytes),
        Ok(DaemonOtaRequest::ActiveRelease)
    ) {
        Some(load_active_release_until(deadline))
    } else {
        None
    };
    // An ingress worker cannot grant authority across an install cutover.
    // Refresh only the lease time, after checking the original file stamps.
    authority.expires = Instant::now() + PEER_CACHE_LIFETIME;
    canonical_log::verify_installed_app_peer(uid, pid)?;
    if !authority.valid(uid, Instant::now()) || Instant::now() >= deadline {
        return Err(invalid("OTA ingress deadline or peer authority changed"));
    }
    Ok(PreparedRequest {
        stream,
        bytes,
        descriptors,
        active_release,
        authority,
        deadline,
    })
}

fn request_authorized(request: &PreparedRequest) -> bool {
    peer_credentials(&request.stream).is_ok_and(|(uid, pid)| {
        canonical_log::verify_installed_app_peer(uid, pid).is_ok()
            && request
                .authority
                .admitted(uid, Instant::now(), request.deadline)
    })
}

pub(crate) struct OtaTransport {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    listener: OwnedFd,
    backend: ProductionBackend,
    ingress: Vec<JoinHandle<io::Result<PreparedRequest>>>,
    peer_cache: Arc<Mutex<Option<CachedPeer>>>,
}

impl OtaTransport {
    pub(crate) fn bind() -> io::Result<Self> {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            Ok(Self {
                listener: bind_abstract_listener()?,
                backend: ProductionBackend::default(),
                ingress: Vec::new(),
                peer_cache: Arc::new(Mutex::new(None)),
            })
        }
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            Err(invalid("abstract OTA socket requires Android or Linux"))
        }
    }

    pub(crate) fn poll_once(&mut self, mutations_allowed: bool) {
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        let _ = mutations_allowed;
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            let mut index = 0;
            while index < self.ingress.len() {
                if !self.ingress[index].is_finished() {
                    index += 1;
                    continue;
                }
                match self.ingress.swap_remove(index).join() {
                    Ok(Ok(mut request)) if request_authorized(&request) => {
                        self.backend.active_release = request.active_release.take();
                        let result = serve_received(
                            &mut request.stream,
                            &mut self.backend,
                            request.bytes,
                            request.descriptors,
                            uninstall::request_present() || uninstall::prepared_marker_valid(),
                            mutations_allowed,
                        );
                        self.backend.active_release = None;
                        if let Err(error) = result {
                            crate::log::err("ota", &format!("OTA request rejected: {error}"));
                        }
                    }
                    Ok(Ok(_)) => {
                        crate::log::err("ota", "OTA peer authority changed before dispatch")
                    }
                    Ok(Err(error)) => {
                        crate::log::err("ota", &format!("OTA ingress rejected: {error}"))
                    }
                    Err(_) => crate::log::err("ota", "OTA ingress worker panicked"),
                }
            }
            if self.ingress.len() >= MAX_INGRESS_WORKERS {
                return;
            }
            let fd = unsafe {
                libc::accept4(
                    self.listener.as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::WouldBlock {
                    crate::log::err("ota", &format!("OTA accept failed: {error}"));
                }
                return;
            }
            let stream = unsafe { UnixStream::from_raw_fd(fd) };
            let cache = Arc::clone(&self.peer_cache);
            match std::thread::Builder::new()
                .name("ota-ingress".into())
                .spawn(move || prepare_request(stream, &cache))
            {
                Ok(worker) => self.ingress.push(worker),
                Err(error) => crate::log::err("ota", &format!("OTA ingress unavailable: {error}")),
            }
        }
    }
}

trait Backend {
    fn active_release(&mut self) -> Result<ActiveReleaseIdentity, String>;
    /// Terminal acknowledgement of a previously proposed OTA transaction,
    /// replayed on every activeRelease so an app that died before its own
    /// record update can still retire the durable PROPOSED/READY state.
    /// Default `None`: test backends and hosts without an operation WAL.
    fn terminal_acknowledgement(&mut self) -> Option<TerminalAcknowledgement> {
        None
    }
    fn propose(
        &mut self,
        candidate: &OtaCandidateHandle,
        handoff: &CandidateDescriptorHandoff,
    ) -> DaemonProposalResult;
}

struct ProductionBackend {
    product_key: [u8; 32],
    candidates: ProductCandidateStore,
    active_release: Option<Result<ActiveReleaseIdentity, String>>,
}

impl Default for ProductionBackend {
    fn default() -> Self {
        Self {
            product_key: trust::release_catalog_public_key(),
            candidates: ProductCandidateStore::production(),
            active_release: None,
        }
    }
}

impl Backend for ProductionBackend {
    fn active_release(&mut self) -> Result<ActiveReleaseIdentity, String> {
        self.active_release
            .take()
            .unwrap_or_else(load_active_release)
    }

    fn terminal_acknowledgement(&mut self) -> Option<TerminalAcknowledgement> {
        crate::product_candidate::terminal_acknowledgement_in(Path::new(crate::config::ROOT_ZONE))
            .ok()
            .flatten()
    }

    fn propose(
        &mut self,
        candidate: &OtaCandidateHandle,
        handoff: &CandidateDescriptorHandoff,
    ) -> DaemonProposalResult {
        if candidate.artifacts.len() > MAX_CHANGED_DESCRIPTORS {
            return rejected("changed artifact descriptor count exceeds transport bound");
        }
        let verified = match handoff.verify_open_descriptors(candidate, &self.product_key) {
            Ok(verified) => verified,
            Err(_) => return rejected("candidate descriptor verification failed"),
        };
        match self
            .candidates
            .admit(candidate, &verified, handoff, &ProductUpdateOrigin::Ota)
        {
            Ok(Admission::Pending) => DaemonProposalResult::Pending,
            Ok(Admission::Accepted) => DaemonProposalResult::Accepted,
            Ok(Admission::InstallApk) => DaemonProposalResult::InstallApk,
            Ok(Admission::RebootRequired) => DaemonProposalResult::Pending,
            Ok(Admission::MetadataOnlyUnavailable) => {
                rejected("metadata-only activation is not available")
            }
            Ok(Admission::TransactionCollision) => {
                rejected("transaction identity is already bound")
            }
            Ok(Admission::UnsupportedActivationClass) => {
                rejected("candidate requires APK, native, init or SELinux activation")
            }
            Ok(Admission::ActivationFailed) => rejected("product activation rolled back"),
            Ok(Admission::ApkIdentityInvalid) => rejected("installed APK identity is invalid"),
            Err(error) => {
                crate::log::err(
                    "ota",
                    &format!("product candidate admission failed: {error}"),
                );
                DaemonProposalResult::Unavailable
            }
        }
    }
}

#[cfg(test)]
fn serve_authenticated(stream: &mut UnixStream, backend: &mut dyn Backend) -> io::Result<()> {
    serve_authenticated_with_removal(
        stream,
        backend,
        uninstall::request_present() || uninstall::prepared_marker_valid(),
    )
}

#[cfg(test)]
fn serve_authenticated_with_removal(
    stream: &mut UnixStream,
    backend: &mut dyn Backend,
    removing: bool,
) -> io::Result<()> {
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    let (bytes, descriptors) = receive_frame(stream)?;
    serve_received(stream, backend, bytes, descriptors, removing, true)
}

fn serve_received(
    stream: &mut UnixStream,
    backend: &mut dyn Backend,
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
    removing: bool,
    mutations_allowed: bool,
) -> io::Result<()> {
    if let Ok(request) = voboost_contract::cluster_pw_live::LocalRequest::parse(&bytes) {
        if !descriptors.is_empty() {
            return Err(invalid("PW proof request carries descriptors"));
        }
        let voboost_contract::cluster_pw_live::LocalRequest::ClusterPwLiveProof {
            request_id,
            challenge,
            ..
        } = request;
        let proof = crate::control_plane::pw_live::proof(
            challenge,
            std::time::Instant::now()
                + std::time::Duration::from_millis(
                    voboost_contract::cluster_pw_live::CHALLENGE_MILLIS,
                ),
            &std::sync::atomic::AtomicBool::new(false),
        )
        .ok()
        .map(hex::encode);
        let response = voboost_contract::cluster_pw_live::LocalResponse::ClusterPwLiveProof {
            protocol_version: 1,
            request_id,
            proof,
        };
        let bytes =
            voboost_contract::domain_core::ascii_json(&response).map_err(|e| invalid(&e))?;
        return write_frame(stream, &bytes);
    }
    if let Ok(request) = voboost_contract::cluster_wire::LocalRequest::parse(&bytes) {
        return serve_cluster(stream, request, descriptors);
    }
    if removing {
        return Err(invalid("OTA is unavailable while removal owns the device"));
    }
    let request = DaemonOtaRequest::parse(&bytes).map_err(|error| invalid(&error))?;
    let response = match request {
        DaemonOtaRequest::ActiveRelease => {
            if !descriptors.is_empty() {
                return Err(invalid("activeRelease carries descriptors"));
            }
            let result = match backend.active_release() {
                Ok(identity) => ActiveReleaseResult::Active {
                    identity,
                    // Replayed terminal outcome lets the app reconcile a
                    // durable PROPOSED/READY record even if the process
                    // died before it observed the daemon result.
                    terminal: backend.terminal_acknowledgement(),
                },
                Err(error) => {
                    crate::log::err("ota", &format!("active release unavailable: {error}"));
                    ActiveReleaseResult::Unavailable
                }
            };
            DaemonOtaResponse::ActiveRelease { result }
        }
        DaemonOtaRequest::Propose { candidate } => {
            if !mutations_allowed {
                let response = DaemonOtaResponse::Propose {
                    result: DaemonProposalResult::Unavailable,
                };
                return write_frame(
                    stream,
                    &response.canonical_bytes().map_err(|e| invalid(&e))?,
                );
            }
            let expected = candidate.artifacts.len().saturating_add(2);
            let result = if expected > MAX_RECEIVED_FDS || descriptors.len() != expected {
                rejected("descriptor count differs from candidate")
            } else {
                let handoff = CandidateDescriptorHandoff {
                    manifest_fd: descriptors[0].as_raw_fd(),
                    signature_fd: descriptors[1].as_raw_fd(),
                    artifacts: descriptors[2..]
                        .iter()
                        .zip(&candidate.artifacts)
                        .map(|(descriptor, identity)| CandidateArtifactDescriptor {
                            fd: descriptor.as_raw_fd(),
                            file: identity.file.clone(),
                            size: identity.size,
                            sha256: identity.sha256.clone(),
                        })
                        .collect(),
                };
                backend.propose(&candidate, &handoff)
            };
            DaemonOtaResponse::Propose { result }
        }
    };
    let bytes = response
        .canonical_bytes()
        .map_err(|error| invalid(&error))?;
    write_frame(stream, &bytes)
}

fn serve_cluster(
    stream: &mut UnixStream,
    request: voboost_contract::cluster_wire::LocalRequest,
    descriptors: Vec<OwnedFd>,
) -> io::Result<()> {
    use voboost_contract::cluster_wire::LocalRequest;
    let handoff = match &request {
        LocalRequest::Take { request_id, .. } => {
            if !descriptors.is_empty() {
                return Err(invalid("Cluster take carries descriptors"));
            }
            crate::cluster_control::take_production(request_id).map_err(|e| invalid(&e))?
        }
        LocalRequest::Result { receipt, .. } => {
            if descriptors.len() != usize::from(receipt.is_some()) {
                return Err(invalid("Cluster receipt descriptor count differs"));
            }
            let file = descriptors.into_iter().next().map(File::from);
            crate::cluster_control::Handoff {
                response: crate::cluster_control::result_production(&request, file.as_ref())
                    .map_err(|e| invalid(&e))?,
                descriptors: Vec::new(),
            }
        }
    };
    let bytes = handoff
        .response
        .canonical_bytes()
        .map_err(|e| invalid(&e))?;
    let descriptors = handoff
        .descriptors
        .iter()
        .map(AsRawFd::as_raw_fd)
        .collect::<Vec<_>>();
    write_frame_descriptors(stream, &bytes, &descriptors)
}
fn write_frame_descriptors(
    stream: &mut UnixStream,
    bytes: &[u8],
    descriptors: &[RawFd],
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES || descriptors.len() > 253 {
        return Err(invalid("Cluster response bounds"));
    }
    if descriptors.is_empty() {
        return write_frame(stream, bytes);
    }
    stream.set_nonblocking(true)?;
    let header = (bytes.len() as u32).to_be_bytes();
    let mut iov = libc::iovec {
        iov_base: header.as_ptr() as *mut libc::c_void,
        iov_len: header.len(),
    };
    let mut control = [0_usize; 132];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) as _ };
    let rights = unsafe { libc::CMSG_FIRSTHDR(&message) };
    unsafe {
        (*rights).cmsg_level = libc::SOL_SOCKET;
        (*rights).cmsg_type = libc::SCM_RIGHTS;
        (*rights).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as _;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(rights).cast::<RawFd>(),
            descriptors.len(),
        );
    }
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let sent = loop {
        let sent = unsafe {
            libc::sendmsg(
                stream.as_raw_fd(),
                &message,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent >= 0 {
            break sent;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            wait_ready(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        } else if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OTA response deadline",
            ));
        }
    };
    if sent == 0 || sent > 4 {
        return Err(invalid("Cluster descriptor header write"));
    }
    write_all_until(stream, &header[sent as usize..], deadline)?;
    write_all_until(stream, bytes, deadline)
}

fn rejected(reason: &str) -> DaemonProposalResult {
    DaemonProposalResult::Rejected {
        reason: reason.to_string(),
    }
}

#[cfg(test)]
fn receive_frame(stream: &mut UnixStream) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    receive_frame_with(stream, |_| {})
}

#[cfg(test)]
fn receive_frame_with(
    stream: &mut UnixStream,
    observe_descriptors: impl FnOnce(&[OwnedFd]),
) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    receive_frame_until(
        stream,
        Instant::now() + REQUEST_TIMEOUT,
        observe_descriptors,
    )
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        wait_readable(stream.as_raw_fd(), deadline)?;
        let received = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if received == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "OTA request disconnected",
            ));
        }
        if received > 0 {
            bytes = &mut bytes[received as usize..];
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted && error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
    }
    Ok(())
}

fn wait_readable(fd: RawFd, deadline: Instant) -> io::Result<()> {
    wait_ready(fd, libc::POLLIN, deadline)
}

fn wait_ready(fd: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OTA frame deadline",
            ));
        }
        let timeout = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn receive_frame_until(
    stream: &mut UnixStream,
    deadline: Instant,
    observe_descriptors: impl FnOnce(&[OwnedFd]),
) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut header = [0_u8; 4];
    let mut control = [0_usize; 132];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    let received = loop {
        wait_readable(stream.as_raw_fd(), deadline)?;
        let received = unsafe {
            libc::recvmsg(
                stream.as_raw_fd(),
                &mut message,
                recvmsg_flags() | libc::MSG_DONTWAIT,
            )
        };
        if received >= 0 {
            break received;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted && error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
    };
    if received <= 0 {
        return Err(if received == 0 {
            io::Error::new(io::ErrorKind::UnexpectedEof, "OTA request disconnected")
        } else {
            io::Error::last_os_error()
        });
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(invalid("OTA descriptor control data truncated"));
    }
    let descriptors = received_descriptors(&message)?;
    observe_descriptors(&descriptors);
    read_exact_until(stream, &mut header[received as usize..], deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_STATUS_BYTES {
        return Err(invalid("OTA request frame length is invalid"));
    }
    let mut bytes = vec![0; length];
    read_exact_until(stream, &mut bytes, deadline)?;
    let mut trailing = [0_u8; 1];
    let peeked = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            trailing.as_mut_ptr().cast(),
            1,
            libc::MSG_DONTWAIT | libc::MSG_PEEK,
        )
    };
    if peeked > 0 {
        return Err(invalid("OTA connection carries more than one request"));
    }
    Ok((bytes, descriptors))
}

fn received_descriptors(message: &libc::msghdr) -> io::Result<Vec<OwnedFd>> {
    let mut result = Vec::new();
    let mut rights_messages = 0;
    let mut current = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !current.is_null() {
        let header = unsafe { &*current };
        if header.cmsg_level != libc::SOL_SOCKET || header.cmsg_type != libc::SCM_RIGHTS {
            return Err(invalid("unexpected OTA ancillary data"));
        }
        rights_messages += 1;
        let header_length = unsafe { libc::CMSG_LEN(0) } as usize;
        if (header.cmsg_len as usize) < header_length {
            return Err(invalid("truncated OTA descriptor message"));
        }
        let bytes = header.cmsg_len as usize - header_length;
        if !bytes.is_multiple_of(std::mem::size_of::<RawFd>()) {
            return Err(invalid("unaligned OTA descriptor message"));
        }
        let count = bytes / std::mem::size_of::<RawFd>();
        let values =
            unsafe { std::slice::from_raw_parts(libc::CMSG_DATA(current).cast::<RawFd>(), count) };
        for fd in values {
            if *fd < 0 {
                return Err(invalid("negative OTA descriptor"));
            }
            result.push(unsafe { OwnedFd::from_raw_fd(*fd) });
        }
        current = unsafe { libc::CMSG_NXTHDR(message, current) };
    }
    if rights_messages > 1 {
        return Err(invalid("multiple OTA descriptor messages"));
    }
    if result.len() > MAX_RECEIVED_FDS {
        return Err(invalid("too many OTA descriptors"));
    }
    for fd in &result {
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(result)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
const fn recvmsg_flags() -> libc::c_int {
    libc::MSG_CMSG_CLOEXEC
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
const fn recvmsg_flags() -> libc::c_int {
    0
}

fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_STATUS_BYTES {
        return Err(invalid("OTA response frame length is invalid"));
    }
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    write_all_until(stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_all_until(stream, bytes, deadline)
}

fn write_all_until(stream: &UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OTA response deadline",
            ));
        }
        let sent = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if sent > 0 {
            bytes = &bytes[sent as usize..];
            continue;
        }
        if sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "OTA response disconnected",
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            wait_ready(stream.as_raw_fd(), libc::POLLOUT, deadline)?;
        } else if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn open_abstract_listener_socket() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn bind_abstract_listener() -> io::Result<OwnedFd> {
    #[cfg(target_os = "android")]
    let listener = {
        const SOCKCREATE: &str = "/proc/thread-self/attr/sockcreate";
        let mut attr = File::options().write(true).open(SOCKCREATE)?;
        let mut reset = File::options().write(true).open(SOCKCREATE)?;
        attr.write_all(b"u:object_r:voboost_ota_socket:s0")?;
        let listener = open_abstract_listener_socket();
        // A newline clears the context. The daemon must not continue if its
        // thread would still apply the OTA label to subsequently created sockets.
        if let Err(error) = reset.write_all(b"\n") {
            crate::log::err(
                "ota",
                &format!("cannot clear OTA socket creation context: {error}"),
            );
            std::process::abort();
        }
        listener?
    };
    #[cfg(target_os = "linux")]
    let listener = open_abstract_listener_socket()?;
    let name = ABSTRACT_SOCKET_NAME.as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if name.len() + 1 > address.sun_path.len() {
        return Err(invalid("OTA abstract socket name exceeds sockaddr_un"));
    }
    for (target, source) in address.sun_path[1..].iter_mut().zip(name) {
        *target = *source as libc::c_char;
    }
    let base = (&address as *const libc::sockaddr_un).cast::<u8>() as usize;
    let path = address.sun_path.as_ptr().cast::<u8>() as usize;
    let length = (path - base + 1 + name.len()) as libc::socklen_t;
    if unsafe {
        libc::bind(
            listener.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(listener.as_raw_fd(), 4) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(listener)
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
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || credentials.pid <= 0
    {
        return Err(invalid("OTA peer credentials unavailable"));
    }
    Ok((credentials.uid, credentials.pid as u32))
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((uid, std::process::id()))
}

fn authenticate_peer_apk(deadline: Instant) -> io::Result<(String, std::fs::Metadata)> {
    let active = crate::installed_product::load_manifest().map_err(|error| invalid(&error))?;
    let active_apk = active
        .artifact("voboost-app.apk")
        .map_err(|error| invalid(&error))?;
    let active_matches = crate::installed_product::verify_installed_apk_identity_until(
        active_apk,
        std::path::Path::new(crate::config::ROOT_ZONE),
        deadline,
    );
    if let Ok(path) = active_matches {
        return Ok(path);
    }
    if let Some(artifact) =
        crate::product_candidate::pending_apk_peer_authority().map_err(|error| invalid(&error))?
    {
        return crate::installed_product::verify_installed_apk_identity_until(
            &artifact,
            Path::new(crate::config::ROOT_ZONE),
            deadline,
        )
        .map_err(|error| invalid(&error));
    }
    Err(invalid(
        "installed APK identity is not an active product authority",
    ))
}

fn load_active_release() -> Result<ActiveReleaseIdentity, String> {
    load_active_release_until(Instant::now() + AUTH_TIMEOUT)
}

fn load_active_release_until(deadline: Instant) -> Result<ActiveReleaseIdentity, String> {
    let check = || {
        if Instant::now() >= deadline {
            Err("active release observation deadline".to_string())
        } else {
            Ok(())
        }
    };
    check()?;
    let manifest = crate::installed_product::load_manifest()?;
    check()?;
    crate::installed_product::verify_native_closure_until(&manifest, deadline)?;
    let package = uninstall::installed_package_authority()?;
    check()?;
    let app = manifest.artifact("voboost-app.apk")?;
    if app.size != package.apk_size
        || app.sha256 != package.apk_sha256
        || app.certificate_sha256.as_deref() != Some(&package.certificate_sha256)
    {
        return Err("active product authority differs from installed APK authority".into());
    }
    let version = semver::Version::parse(&manifest.release_identity)
        .map_err(|_| "active release identity is invalid".to_string())?;
    let channel = if version.pre.is_empty() {
        "stable"
    } else {
        "beta"
    };
    let identity = ActiveReleaseIdentity::from_manifest(channel.to_string(), &manifest)?;
    check()?;
    Ok(identity)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    #[test]
    fn peer_cache_rejects_replacement_expiration_and_pinned_metadata_changes() {
        use super::*;
        let root = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let apk = root.path().join("base.apk");
        let metadata = root.path().join("voboost.json");
        std::fs::write(&apk, b"verified").unwrap();
        std::fs::write(&metadata, b"pinned").unwrap();
        let now = Instant::now();
        let cache = CachedPeer {
            uid: 10001,
            expires: now + PEER_CACHE_LIFETIME,
            files: vec![
                (apk.clone(), authority_stamp(&apk).unwrap()),
                (metadata.clone(), authority_stamp(&metadata).unwrap()),
            ],
        };
        assert!(cache.valid(10001, now));
        assert!(!cache.valid(10002, now));
        assert!(!cache.valid(10001, now + PEER_CACHE_LIFETIME));
        // Cache reuse expires independently from an already authenticated request.
        assert!(cache.current(10001));
        let dispatch = now + PEER_CACHE_LIFETIME;
        assert!(cache.admitted(10001, dispatch, now + AUTH_TIMEOUT));
        assert!(!cache.admitted(10001, now + AUTH_TIMEOUT, now + AUTH_TIMEOUT));
        assert!(!cache.current(10002));
        let old = root.path().join("old.apk");
        std::fs::rename(&apk, &old).unwrap();
        std::fs::write(&apk, b"replaced").unwrap();
        assert!(!cache.valid(10001, now));
        assert!(!cache.current(10001));
        std::fs::remove_file(&apk).unwrap();
        std::fs::rename(&old, &apk).unwrap();
        std::fs::write(&metadata, b"new pinned metadata").unwrap();
        assert!(!cache.valid(10001, now));
    }

    #[test]
    fn trickled_frame_has_one_absolute_deadline() {
        use super::*;
        let (mut server, mut client) = UnixStream::pair().unwrap();
        client.write_all(&4_u32.to_be_bytes()).unwrap();
        let worker = std::thread::spawn(move || {
            for _ in 0..4 {
                if client.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let started = Instant::now();
        assert!(
            receive_frame_until(&mut server, started + Duration::from_millis(50), |_| {}).is_err()
        );
        assert!(started.elapsed() < Duration::from_millis(200));
        drop(server);
        worker.join().unwrap();
    }

    #[test]
    fn response_backpressure_cannot_extend_the_main_loop_deadline() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let small = 1024_i32;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    server.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&small as *const i32).cast(),
                    std::mem::size_of_val(&small) as _,
                )
            },
            0
        );
        server.set_write_timeout(Some(RESPONSE_TIMEOUT)).unwrap();
        client.set_nonblocking(true).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            while !reader_stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = client.read(&mut [0; 256]);
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        started_rx.recv().unwrap();
        let started = Instant::now();
        assert!(write_frame(&mut server, &vec![b'x'; MAX_STATUS_BYTES]).is_err());
        let elapsed = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(server);
        reader.join().unwrap();
        assert!(elapsed < Duration::from_millis(200));
    }

    #[test]
    fn removal_keeps_the_socket_responsive_but_rejects_ota_requests() {
        let (mut server, client) = UnixStream::pair().unwrap();
        send_frame(
            &client,
            &DaemonOtaRequest::ActiveRelease.canonical_bytes().unwrap(),
            &[],
        );
        let mut backend = FixtureBackend {
            active: active(),
            proposals: 0,
        };
        let error = serve_authenticated_with_removal(&mut server, &mut backend, true).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OTA is unavailable while removal owns the device"
        );
        assert_eq!(backend.proposals, 0);
    }
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::io::Seek;
    use std::os::unix::fs::PermissionsExt;

    struct FixtureBackend {
        active: ActiveReleaseIdentity,
        proposals: usize,
    }

    impl Backend for FixtureBackend {
        fn active_release(&mut self) -> Result<ActiveReleaseIdentity, String> {
            Ok(self.active.clone())
        }

        fn propose(
            &mut self,
            candidate: &OtaCandidateHandle,
            handoff: &CandidateDescriptorHandoff,
        ) -> DaemonProposalResult {
            self.proposals += 1;
            let descriptors = std::iter::once(handoff.manifest_fd)
                .chain(std::iter::once(handoff.signature_fd))
                .chain(handoff.artifacts.iter().map(|artifact| artifact.fd));
            let cloexec = descriptors.into_iter().all(|fd| {
                (unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC) == libc::FD_CLOEXEC
            });
            if handoff.validate(candidate).is_ok() && cloexec {
                DaemonProposalResult::Pending
            } else {
                rejected("fixture verification failed")
            }
        }
    }

    fn send_frame(stream: &UnixStream, bytes: &[u8], descriptors: &[RawFd]) {
        let header = (bytes.len() as u32).to_be_bytes();
        let mut iov = libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        };
        let mut control = [0_usize; 132];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !descriptors.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) as _ };
            let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
            unsafe {
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as _;
                std::ptr::copy_nonoverlapping(
                    descriptors.as_ptr(),
                    libc::CMSG_DATA(header).cast::<RawFd>(),
                    descriptors.len(),
                );
            }
        }
        assert_eq!(unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) }, 4);
        (&*stream).write_all(bytes).unwrap();
    }

    fn read_frame(stream: &mut UnixStream) -> DaemonOtaResponse {
        let mut length = [0; 4];
        stream.read_exact(&mut length).unwrap();
        let mut bytes = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut bytes).unwrap();
        DaemonOtaResponse::parse(&bytes).unwrap()
    }

    fn active() -> ActiveReleaseIdentity {
        ActiveReleaseIdentity::parse(include_bytes!(
            "../../test/fixtures/product-release/status/active.json"
        ))
        .unwrap()
    }

    #[test]
    fn socketpair_transfers_exact_ordered_descriptors_and_one_response() {
        let (mut server, client) = UnixStream::pair().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for (index, bytes) in [b"manifest".as_slice(), b"signature", b"artifact"]
            .into_iter()
            .enumerate()
        {
            let mut file = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.path().join(index.to_string()))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.rewind().unwrap();
            files.push(file);
        }
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "b".repeat(64),
            artifacts: vec![voboost_contract::status::CandidateArtifactIdentity {
                file: "voboost-daemon".into(),
                size: 8,
                sha256: "c".repeat(64),
            }],
        };
        let request = DaemonOtaRequest::Propose { candidate };
        let bytes = request.canonical_bytes().unwrap();
        send_frame(
            &client,
            &bytes,
            &files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
        );
        let mut backend = FixtureBackend {
            active: active(),
            proposals: 0,
        };
        serve_authenticated(&mut server, &mut backend).unwrap();
        assert_eq!(
            read_frame(&mut client.try_clone().unwrap()),
            DaemonOtaResponse::Propose {
                result: DaemonProposalResult::Pending
            }
        );
        assert_eq!(backend.proposals, 1);
        let (mut server, client) = UnixStream::pair().unwrap();
        send_frame(
            &client,
            &bytes,
            &files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
        );
        let (bytes, descriptors) = receive_frame(&mut server).unwrap();
        serve_received(&mut server, &mut backend, bytes, descriptors, false, false).unwrap();
        assert_eq!(
            read_frame(&mut client.try_clone().unwrap()),
            DaemonOtaResponse::Propose {
                result: DaemonProposalResult::Unavailable
            }
        );
        assert_eq!(
            backend.proposals, 1,
            "live jobs must fence product admission"
        );
    }

    #[test]
    fn terminal_acknowledgement_travels_the_production_wire() {
        // A terminal acknowledgement from the backend must ride the
        // activeRelease response unchanged: canonical bytes, exact keys and
        // a parse that survives the strict contract round-trip.
        struct TerminalBackend {
            active: ActiveReleaseIdentity,
            terminal: TerminalAcknowledgement,
        }
        impl Backend for TerminalBackend {
            fn active_release(&mut self) -> Result<ActiveReleaseIdentity, String> {
                Ok(self.active.clone())
            }
            fn terminal_acknowledgement(&mut self) -> Option<TerminalAcknowledgement> {
                Some(self.terminal.clone())
            }
            fn propose(
                &mut self,
                _candidate: &OtaCandidateHandle,
                _handoff: &CandidateDescriptorHandoff,
            ) -> DaemonProposalResult {
                DaemonProposalResult::Rejected {
                    reason: "unused".into(),
                }
            }
        }
        let manifest = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let active = ActiveReleaseIdentity::from_manifest("beta".into(), &manifest).unwrap();
        let terminal = TerminalAcknowledgement {
            transaction_id: "0123456789abcdef".into(),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: "a".repeat(64),
            outcome: TerminalOutcome::Complete,
        };
        let response = DaemonOtaResponse::ActiveRelease {
            result: ActiveReleaseResult::Active {
                identity: active.clone(),
                terminal: Some(terminal.clone()),
            },
        };
        let bytes = response.canonical_bytes().unwrap();
        let parsed = DaemonOtaResponse::parse(&bytes).unwrap();
        match parsed {
            DaemonOtaResponse::ActiveRelease {
                result: ActiveReleaseResult::Active { identity, terminal },
            } => {
                assert_eq!(identity, active);
                assert_eq!(terminal.as_ref(), Some(&terminal_original(&terminal)));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        fn terminal_original(value: &Option<TerminalAcknowledgement>) -> TerminalAcknowledgement {
            value.clone().unwrap()
        }

        // The acknowledgement rides the served socket path end-to-end.
        let (mut server, mut client) = UnixStream::pair().unwrap();
        drop(client.set_read_timeout(Some(Duration::from_secs(2))));
        send_frame(
            &client,
            &DaemonOtaRequest::ActiveRelease.canonical_bytes().unwrap(),
            &[],
        );
        let mut backend = TerminalBackend { active, terminal };
        serve_authenticated(&mut server, &mut backend).unwrap();
        match read_frame(&mut client) {
            DaemonOtaResponse::ActiveRelease {
                result: ActiveReleaseResult::Active { terminal, .. },
            } => assert!(terminal.is_some()),
            other => panic!("unexpected served response: {other:?}"),
        }
    }

    #[test]
    fn active_release_uses_zero_descriptors_and_daemon_state() {
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let expected = active();
        send_frame(
            &client,
            &DaemonOtaRequest::ActiveRelease.canonical_bytes().unwrap(),
            &[],
        );
        let mut backend = FixtureBackend {
            active: expected.clone(),
            proposals: 0,
        };
        serve_authenticated(&mut server, &mut backend).unwrap();
        assert_eq!(
            read_frame(&mut client),
            DaemonOtaResponse::ActiveRelease {
                result: ActiveReleaseResult::Active {
                    identity: expected,
                    terminal: None
                }
            }
        );
        assert_eq!(backend.proposals, 0);
    }

    #[test]
    fn missing_extra_and_trailing_descriptors_fail_closed() {
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: "1.0.0-beta2".into(),
            manifest_sha256: "b".repeat(64),
            artifacts: Vec::new(),
        };
        for descriptor_count in [0, 1, 3] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            let files = (0..descriptor_count)
                .map(|_| tempfile::tempfile().unwrap())
                .collect::<Vec<_>>();
            send_frame(
                &client,
                &DaemonOtaRequest::Propose {
                    candidate: candidate.clone(),
                }
                .canonical_bytes()
                .unwrap(),
                &files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
            );
            let mut backend = FixtureBackend {
                active: active(),
                proposals: 0,
            };
            serve_authenticated(&mut server, &mut backend).unwrap();
            assert!(matches!(
                read_frame(&mut client),
                DaemonOtaResponse::Propose {
                    result: DaemonProposalResult::Rejected { .. }
                }
            ));
            assert_eq!(backend.proposals, 0);
        }

        let (mut server, mut client) = UnixStream::pair().unwrap();
        let request = DaemonOtaRequest::ActiveRelease.canonical_bytes().unwrap();
        send_frame(&client, &request, &[]);
        (&client).write_all(b"x").unwrap();
        let mut backend = FixtureBackend {
            active: active(),
            proposals: 0,
        };
        assert!(serve_authenticated(&mut server, &mut backend).is_err());
        drop(server);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn peer_credentials_are_socket_bound_and_uid_mismatch_is_hostile() {
        let (server, _client) = UnixStream::pair().unwrap();
        let (uid, pid) = peer_credentials(&server).unwrap();
        assert_eq!(uid, unsafe { libc::geteuid() });
        assert_eq!(pid, std::process::id());
        assert_ne!(uid.wrapping_add(1), uid);
    }

    #[test]
    fn disconnect_before_frame_is_bounded_and_returns_no_response() {
        let (mut server, client) = UnixStream::pair().unwrap();
        drop(client);
        assert_eq!(
            receive_frame(&mut server).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn disconnect_after_rights_transfer_closes_received_descriptors() {
        let (mut server, client) = UnixStream::pair().unwrap();
        let mut pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let mut read_end = unsafe { File::from_raw_fd(pipe[0]) };
        let write_end = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let declared = (128_u32).to_be_bytes();
        send_header(&client, &declared, &[write_end.as_raw_fd()]);
        drop(write_end);
        drop(client);
        assert_eq!(
            receive_frame(&mut server).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut byte = [0];
        assert_eq!(read_end.read(&mut byte).unwrap(), 0);
    }

    fn send_header(stream: &UnixStream, header: &[u8; 4], descriptors: &[RawFd]) {
        let mut iov = libc::iovec {
            iov_base: header.as_ptr() as *mut libc::c_void,
            iov_len: header.len(),
        };
        let mut control = [0_usize; 132];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) as _ };
        let control_header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        unsafe {
            (*control_header).cmsg_level = libc::SOL_SOCKET;
            (*control_header).cmsg_type = libc::SCM_RIGHTS;
            (*control_header).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as _;
            std::ptr::copy_nonoverlapping(
                descriptors.as_ptr(),
                libc::CMSG_DATA(control_header).cast::<RawFd>(),
                descriptors.len(),
            );
        }
        assert_eq!(unsafe { libc::sendmsg(stream.as_raw_fd(), &message, 0) }, 4);
    }

    #[test]
    fn production_replay_binds_one_transaction_to_one_candidate() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut manifest = voboost_contract::release::Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let body = b"daemon-body";
        let (artifact_file, artifact_size, artifact_sha256) = {
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|artifact| artifact.file == "voboost-daemon")
                .unwrap();
            artifact.size = body.len() as u64;
            artifact.sha256 = hex::encode(Sha256::digest(body));
            (
                artifact.file.clone(),
                artifact.size,
                artifact.sha256.clone(),
            )
        };
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(&manifest_bytes).to_bytes();
        let write = |name: &str, bytes: &[u8]| {
            let mut file = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.path().join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file
        };
        let manifest_file = write("manifest", &manifest_bytes);
        let signature_file = write("signature", &signature);
        let body_file = write("body", body);
        let candidate = OtaCandidateHandle {
            transaction_id: "a".repeat(64),
            release_identity: manifest.release_identity.clone(),
            manifest_sha256: manifest.digest().unwrap(),
            artifacts: vec![voboost_contract::status::CandidateArtifactIdentity {
                file: artifact_file.clone(),
                size: artifact_size,
                sha256: artifact_sha256.clone(),
            }],
        };
        let handoff = CandidateDescriptorHandoff {
            manifest_fd: manifest_file.as_raw_fd(),
            signature_fd: signature_file.as_raw_fd(),
            artifacts: vec![CandidateArtifactDescriptor {
                fd: body_file.as_raw_fd(),
                file: artifact_file,
                size: artifact_size,
                sha256: artifact_sha256,
            }],
        };
        // Simulate a crash immediately after the root recovery transaction
        // directory was made but before its first journal rename.
        let interrupted_recovery = directory
            .path()
            .join("recovery")
            .join(&candidate.transaction_id);
        std::fs::create_dir_all(&interrupted_recovery).unwrap();
        std::fs::set_permissions(
            directory.path().join("recovery"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            &interrupted_recovery,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let mut backend = ProductionBackend {
            product_key: *key.verifying_key().as_bytes(),
            candidates: ProductCandidateStore::at(directory.path()),
            active_release: None,
        };
        assert_eq!(
            backend.propose(&candidate, &handoff),
            DaemonProposalResult::Pending
        );
        let candidate_path = directory
            .path()
            .join("install")
            .join(&candidate.transaction_id)
            .join("candidate");
        let journal_path = directory
            .path()
            .join("recovery")
            .join(&candidate.transaction_id)
            .join("product-proposal.json");
        assert_eq!(
            std::fs::read(candidate_path.join("voboost-daemon")).unwrap(),
            body
        );
        let journal = String::from_utf8(std::fs::read(&journal_path).unwrap()).unwrap();
        assert!(journal.contains("\"phase\":\"pending\""));

        // A crash after the binding WAL but before the last body is copied is
        // resumed from the same retained descriptors, never rebound.
        std::fs::write(
            &journal_path,
            journal.replace("\"phase\":\"pending\"", "\"phase\":\"copying\""),
        )
        .unwrap();
        std::fs::remove_file(candidate_path.join("voboost-daemon")).unwrap();
        drop(backend);
        let mut backend = ProductionBackend {
            product_key: *key.verifying_key().as_bytes(),
            candidates: ProductCandidateStore::at(directory.path()),
            active_release: None,
        };
        assert_eq!(
            backend.propose(&candidate, &handoff),
            DaemonProposalResult::Pending
        );
        assert_eq!(
            std::fs::read(candidate_path.join("voboost-daemon")).unwrap(),
            body
        );
        drop(backend);
        let mut backend = ProductionBackend {
            product_key: *key.verifying_key().as_bytes(),
            candidates: ProductCandidateStore::at(directory.path()),
            active_release: None,
        };
        assert_eq!(
            backend.propose(&candidate, &handoff),
            DaemonProposalResult::Pending
        );
        let metadata = OtaCandidateHandle {
            artifacts: Vec::new(),
            ..candidate
        };
        let metadata_handoff = CandidateDescriptorHandoff {
            manifest_fd: manifest_file.as_raw_fd(),
            signature_fd: signature_file.as_raw_fd(),
            artifacts: Vec::new(),
        };
        assert_eq!(
            backend.propose(&metadata, &metadata_handoff),
            rejected("transaction identity is already bound")
        );
    }
}
