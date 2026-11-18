//! Explicit, boot-bound emulator observer acceptance. This is not generation acknowledgement.
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use crate::{contract::StagingDescriptor, journal::InstallJournal};

const STATE: &str = "install-acceptance.json";
const SOCKET: &str = "accept.sock";
const MAX: usize = 4096;
// Finite upper bound: host readiness 600s + capture 180s + discovery/decision 120s.
// Native guest-monotonic expiry remains immutable; this is never a wait interval.
const LIFETIME: u64 = 900_000;

use voboost_contract::install_acceptance::{bytes, Decision, Receipt, Request, State};

#[derive(Clone, Copy, Default)]
pub(crate) struct Platform {
    pub android: bool,
    pub qemu: bool,
    pub uid: u32,
    pub gid: u32,
    pub enforcing: bool,
}

impl Platform {
    pub(crate) fn admit(self) -> Result<(), String> {
        if self.android && self.qemu && self.uid == 0 && self.gid == 0 {
            Ok(())
        } else {
            Err("install acceptance staging requires root Android QEMU".into())
        }
    }

    pub(crate) fn guard(self) -> Result<(), String> {
        self.admit()?;
        if self.enforcing {
            Ok(())
        } else {
            Err("install acceptance requires root Enforcing Android QEMU".into())
        }
    }
}

fn platform() -> Platform {
    #[cfg(target_os = "android")]
    return Platform {
        android: true,
        qemu: crate::android_property(c"ro.kernel.qemu") == "1",
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        enforcing: matches!(
            std::fs::read("/sys/fs/selinux/enforce").as_deref(),
            Ok(b"1" | b"1\n")
        ),
    };
    #[cfg(not(target_os = "android"))]
    Platform::default()
}

pub fn admit() -> Result<(), String> {
    // ARM staging permits the installer's intentional permissive preparation before reboot1.
    platform().admit()
}

pub fn guard() -> Result<(), String> {
    platform().guard()
}

fn correlate(request: &Request, receipt: &Receipt) -> Result<(), String> {
    request.validate()?;
    if request.schema_version != receipt.schema_version
        || request.transaction_id != receipt.transaction_id
        || request.manifest_sha256 != receipt.manifest_sha256
        || request.attempt_token != receipt.attempt_token
        || request.boot_id != receipt.boot_id
        || request.reboot_count != receipt.reboot_count
    {
        return Err("install acceptance correlation differs".into());
    }
    Ok(())
}

fn deadline(receipt: &Receipt) -> Result<u64, String> {
    let value = receipt
        .expires_monotonic_ms
        .parse::<u64>()
        .map_err(|_| "invalid acceptance deadline")?;
    if value == 0 || value.to_string() != receipt.expires_monotonic_ms {
        return Err("invalid acceptance deadline".into());
    }
    Ok(value)
}

fn transition(receipt: &mut Receipt, request: &Request, now: u64) -> Result<(), String> {
    correlate(request, receipt)?;
    if now >= deadline(receipt)? {
        return Err("install acceptance deadline expired".into());
    }
    match (receipt.state, request.decision) {
        (_, Decision::Status) => (),
        (State::Waiting, Decision::Accept) => receipt.state = State::Accepted,
        (State::Waiting, Decision::Reject) => receipt.state = State::Rejected,
        (State::Accepted, Decision::Accept) | (State::Rejected, Decision::Reject) => (),
        _ => return Err("install acceptance decision is terminal".into()),
    }
    receipt.decision = request.decision;
    Ok(())
}

fn initial(path: &Path, request: &Request, now: u64) -> Result<Receipt, String> {
    if crate::path_entry_exists(path)? {
        let input = crate::read_bounded(path, MAX, 0o600)?;
        let receipt: Receipt = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
        if bytes(&receipt)? != input {
            return Err("noncanonical acceptance state".into());
        }
        correlate(request, &receipt)?;
        deadline(&receipt)?;
        return Ok(receipt);
    }
    let receipt = Receipt {
        schema_version: request.schema_version,
        transaction_id: request.transaction_id.clone(),
        manifest_sha256: request.manifest_sha256.clone(),
        attempt_token: request.attempt_token.clone(),
        boot_id: request.boot_id.clone(),
        reboot_count: 1,
        decision: Decision::Status,
        state: State::Waiting,
        expires_monotonic_ms: now
            .checked_add(LIFETIME)
            .ok_or("acceptance clock overflow")?
            .to_string(),
    };
    crate::write_atomic(path, &bytes(&receipt)?, 0o600)?;
    Ok(receipt)
}

fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| error.to_string())?;
    let mut input = Vec::new();
    // EOF terminates one frame, never an implicit decision.
    stream
        .take(MAX as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|error| format!("acceptance frame: {error}"))?;
    if input.len() > MAX || input.last() != Some(&b'\n') {
        return Err("invalid acceptance frame".into());
    }
    Ok(input)
}

fn socket_identity(path: &Path) -> Result<(u64, u64), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !meta.file_type().is_socket() || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 {
        return Err("unsafe acceptance socket".into());
    }
    #[cfg(target_os = "android")]
    if meta.uid() != 0 || meta.gid() != 0 {
        return Err("foreign acceptance socket owner".into());
    }
    Ok((meta.dev(), meta.ino()))
}

struct SocketOwner {
    path: std::path::PathBuf,
    identity: (u64, u64),
}
impl Drop for SocketOwner {
    fn drop(&mut self) {
        if socket_identity(&self.path).ok() == Some(self.identity) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(target_os = "android")]
fn peer_root(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        ) == 0
            && peer.uid == 0
            && peer.gid == 0
    }
}

#[cfg(not(target_os = "android"))]
fn peer_root(_stream: &UnixStream) -> bool {
    false
}

pub fn wait(
    lease: &crate::OperationLease,
    journal_path: &Path,
    journal: &InstallJournal,
    actions: &mut impl crate::InstallActions,
    uninstall: &impl Fn() -> bool,
) -> Result<(), String> {
    let parent = journal_path
        .parent()
        .ok_or("acceptance recovery parent missing")?;
    let chain = crate::retain_private_directory_chain(&parent.join("frozen"))?;
    let frozen = crate::StagingRoot::open(&parent.join("frozen"))?;
    let staging = StagingDescriptor::parse(&frozen.read("staging.json", MAX)?)?;
    frozen.verify_named_identity()?;
    crate::revalidate_directory_chain(&chain)?;
    let Some(arm) = staging.emulator_acceptance else {
        return Ok(());
    };
    guard()?;
    if staging.transaction_id != journal.transaction_id
        || staging.manifest_sha256 != journal.manifest_sha256
        || journal.phase != crate::InstallPhase::InstallAgents
        || journal.boot_ids.len() != 1
    {
        return Err("install acceptance requires exact intermediate WAL".into());
    }
    let boot = actions.boot_id()?;
    if journal.boot_ids[0] == boot {
        return Err("install acceptance requires boot1".into());
    }
    let request = Request {
        schema_version: 1,
        transaction_id: journal.transaction_id.clone(),
        manifest_sha256: journal.manifest_sha256.clone(),
        attempt_token: arm.attempt_token,
        boot_id: boot.clone(),
        reboot_count: 1,
        decision: Decision::Status,
    };
    let state_path = parent.join(STATE);
    let mut receipt = initial(&state_path, &request, actions.monotonic_ms()?)?;
    let path = parent.join(SOCKET);
    if crate::path_entry_exists(&path)? {
        socket_identity(&path)?;
        std::fs::remove_file(&path).map_err(|error| error.to_string())?;
    }
    let listener =
        UnixListener::bind(&path).map_err(|error| format!("bind acceptance socket: {error}"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let owner = SocketOwner {
        identity: socket_identity(&path)?,
        path,
    };
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    loop {
        guard()?;
        lease.verify_owner()?;
        crate::revalidate_directory_chain(&chain)?;
        if crate::read_bounded(journal_path, crate::MAX_INSTALL_JOURNAL_BYTES, 0o600)?
            != journal.canonical_bytes()?
        {
            return Err("acceptance intermediate WAL changed".into());
        }
        if socket_identity(&owner.path)? != owner.identity {
            return Err("acceptance endpoint identity changed".into());
        }
        if uninstall() {
            return Err("install superseded by an explicit uninstall request".into());
        }
        if actions.boot_id()? != boot || !actions.boot_completed()? {
            return Err("acceptance intermediate boot changed".into());
        }
        if actions.monotonic_ms()? >= deadline(&receipt)? {
            return Err("install acceptance deadline expired".into());
        }
        match receipt.state {
            State::Accepted => return Ok(()),
            State::Rejected => return Err("install acceptance rejected".into()),
            State::Waiting => (),
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if !peer_root(&stream) {
                    return Err("acceptance peer is not root".into());
                }
                let input = frame(&mut stream)?;
                let incoming = Request::parse(&input)?;
                // Recheck all fences after bounded IO, before durable consumption.
                lease.verify_owner()?;
                crate::revalidate_directory_chain(&chain)?;
                if crate::read_bounded(journal_path, crate::MAX_INSTALL_JOURNAL_BYTES, 0o600)?
                    != journal.canonical_bytes()?
                {
                    return Err("acceptance intermediate WAL changed".into());
                }
                if socket_identity(&owner.path)? != owner.identity {
                    return Err("acceptance endpoint identity changed".into());
                }
                if uninstall() || actions.boot_id()? != boot || !actions.boot_completed()? {
                    return Err("acceptance fence changed".into());
                }
                guard()?;
                transition(&mut receipt, &incoming, actions.monotonic_ms()?)?;
                crate::write_atomic(&state_path, &bytes(&receipt)?, 0o600)?;
                stream
                    .set_write_timeout(Some(Duration::from_millis(500)))
                    .map_err(|error| error.to_string())?;
                // A lost response cannot undo a durably accepted exact decision.
                let _ = stream.write_all(&bytes(&receipt)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                actions.pause_boot_poll()
            }
            Err(error) => return Err(format!("acceptance listener: {error}")),
        }
    }
}

pub fn validate_cleanup(path: &Path, transaction: &str, manifest: &str) -> Result<(), String> {
    let input = crate::read_bounded(path, MAX, 0o600)?;
    let receipt: Receipt = serde_json::from_slice(&input).map_err(|error| error.to_string())?;
    let request = Request {
        schema_version: receipt.schema_version,
        transaction_id: transaction.into(),
        manifest_sha256: manifest.into(),
        attempt_token: receipt.attempt_token.clone(),
        boot_id: receipt.boot_id.clone(),
        reboot_count: 1,
        decision: Decision::Status,
    };
    correlate(&request, &receipt)?;
    deadline(&receipt)?;
    if bytes(&receipt)? != input || receipt.state != State::Accepted {
        return Err("install acceptance cleanup requires correlated accepted state".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            manifest_sha256: "2".repeat(64),
            attempt_token: "3".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            reboot_count: 1,
            decision: Decision::Status,
        }
    }
    #[test]
    fn restart_preserves_deadline_and_acceptance_is_correlated_terminal() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STATE);
        let original = request();
        let mut receipt = initial(&path, &original, 100).unwrap();
        assert_eq!(
            initial(&path, &original, 10000)
                .unwrap()
                .expires_monotonic_ms,
            "900100"
        );
        for field in [0, 1, 2, 3, 4] {
            let mut wrong = original.clone();
            wrong.decision = Decision::Accept;
            match field {
                0 => wrong.transaction_id = "4".repeat(64),
                1 => wrong.manifest_sha256 = "4".repeat(64),
                2 => wrong.attempt_token = "4".repeat(64),
                3 => wrong.boot_id = "00000000-0000-0000-0000-000000000002".into(),
                _ => wrong.reboot_count = 2,
            }
            assert!(transition(&mut receipt, &wrong, 101).is_err());
            assert_eq!(receipt.state, State::Waiting);
        }
        let mut accept = original.clone();
        accept.decision = Decision::Accept;
        assert!(transition(&mut receipt, &accept, 900100).is_err());
        assert_eq!(receipt.state, State::Waiting);
        transition(&mut receipt, &accept, 102).unwrap();
        transition(&mut receipt, &accept, 103).unwrap();
        assert_eq!(receipt.state, State::Accepted);
        let mut reject = original;
        reject.decision = Decision::Reject;
        assert!(transition(&mut receipt, &reject, 104).is_err());
    }
    #[test]
    fn rejection_and_restart_never_renew_or_accept() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(STATE);
        let mut request = request();
        let mut receipt = initial(&path, &request, 1).unwrap();
        request.decision = Decision::Reject;
        transition(&mut receipt, &request, 2).unwrap();
        crate::write_atomic(&path, &bytes(&receipt).unwrap(), 0o600).unwrap();
        let mut resumed = initial(&path, &request, 500).unwrap();
        assert_eq!(resumed.state, State::Rejected);
        request.decision = Decision::Accept;
        assert!(transition(&mut resumed, &request, 501).is_err());
        request.boot_id = "00000000-0000-0000-0000-000000000002".into();
        assert!(initial(&path, &request, 502).is_err());
    }
    #[test]
    fn socket_replacement_is_detected_and_foreign_replacement_is_not_unlinked() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(SOCKET);
        let first = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = SocketOwner {
            path: path.clone(),
            identity: socket_identity(&path).unwrap(),
        };
        std::fs::remove_file(&path).unwrap();
        let second = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(socket_identity(&path).unwrap(), owner.identity);
        drop(owner);
        assert!(path.exists());
        drop(first);
        drop(second);
    }

    #[test]
    fn bounded_canonical_frames_and_eof_are_closed() {
        let canonical = bytes(&request()).unwrap();
        assert!(Request::parse(&canonical).is_ok());
        assert!(Request::parse(&[]).is_err());
        assert!(Request::parse(&vec![b'x'; MAX + 1]).is_err());
        let extra = String::from_utf8(canonical)
            .unwrap()
            .replace("{\"schemaVersion\":1,", "{\"extra\":1,\"schemaVersion\":1,");
        assert!(Request::parse(extra.as_bytes()).is_err());
        let (mut reader, writer) = UnixStream::pair().unwrap();
        drop(writer);
        assert!(frame(&mut reader).is_err());
        assert!(guard().is_err());
    }
}
