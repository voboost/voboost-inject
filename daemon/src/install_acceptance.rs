//! Closed emulator management relay; only the resident runtime contacts the installer.
use crate::{config, operation_contract, secure_fs::Directory};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use voboost_contract::install_acceptance::{bytes, Decision, Receipt, Request, State};
const REQUEST: &str = "install-acceptance-request.json";
const RESPONSE: &str = "install-acceptance-response.json";
const MAX: usize = 4096;

fn run_directory() -> Result<Directory, String> {
    run_directory_in(Path::new(config::ROOT_ZONE), 0, 0)
}

fn run_directory_in(path: &Path, uid: u32, gid: u32) -> Result<Directory, String> {
    let root = Directory::open(path).map_err(|error| error.to_string())?;
    root.validate_owner_mode(uid, gid, 0o755)
        .map_err(|error| error.to_string())?;
    let run = root.open_child("run").map_err(|error| error.to_string())?;
    run.validate_owner_mode(uid, gid, config::RUN_DIR_MODE)
        .map_err(|error| error.to_string())?;
    Ok(run)
}
fn guard() -> Result<(), String> {
    if crate::emulator_diagnostic::emulator_guard() {
        Ok(())
    } else {
        Err("acceptance relay requires root Enforcing Android QEMU".into())
    }
}
fn matches(request: &Request, receipt: &Receipt) -> bool {
    request.schema_version == receipt.schema_version
        && request.transaction_id == receipt.transaction_id
        && request.manifest_sha256 == receipt.manifest_sha256
        && request.attempt_token == receipt.attempt_token
        && request.boot_id == receipt.boot_id
        && request.reboot_count == receipt.reboot_count
        && request.decision == receipt.decision
}
pub(crate) fn connect_bounded(path: &Path) -> Result<UnixStream, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let name = path.as_os_str().as_bytes();
    if name.len() >= address.sun_path.len() {
        return Err("acceptance socket path exceeds bound".into());
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(name) {
        *target = *byte as libc::c_char;
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    stream
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.to_string());
        }
        let mut ready = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        if unsafe { libc::poll(&mut ready, 1, 500) } != 1 {
            return Err("acceptance connect deadline expired".into());
        }
        let mut error: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut error as *mut libc::c_int).cast(),
                &mut size,
            )
        } != 0
            || error != 0
        {
            return Err("acceptance connect failed".into());
        }
    }
    stream
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    Ok(stream)
}

fn relay(request: &Request) -> Result<Vec<u8>, String> {
    let outcome = relay_attempt(request);
    // Relay failures used to be silent, which made an unanswered install
    // acceptance undiagnosable. The stage is logged once per REQUEST file;
    // the CLI deletes the file at its own timeout, bounding the record.
    if let Err(stage) = outcome.as_ref() {
        crate::log::err(
            "install_acceptance",
            &format!("acceptance relay stage failed: {stage}"),
        );
    }
    outcome
}

fn relay_attempt(request: &Request) -> Result<Vec<u8>, String> {
    guard()?;
    if crate::uninstall::request_present() {
        return Err("acceptance superseded by uninstall".into());
    }
    if operation_contract::current_boot_id()? != request.boot_id {
        return Err("acceptance relay boot differs".into());
    }
    let active = operation_contract::read_active_in(Path::new(config::ROOT_ZONE))?
        .ok_or("no active install")?;
    if active.operation != operation_contract::Operation::Install
        || active.transaction_id != request.transaction_id
    {
        return Err("acceptance relay transaction differs".into());
    }
    let root = Directory::open(Path::new(config::ROOT_ZONE)).map_err(|error| error.to_string())?;
    let recovery = root
        .open_child("recovery")
        .and_then(|directory| directory.open_child(&request.transaction_id))
        .map_err(|error| error.to_string())?;
    recovery
        .validate_owner_mode(0, 0, 0o700)
        .map_err(|error| error.to_string())?;
    let state = recovery
        .read_trusted("install-acceptance.json", MAX, 0o600)
        .map_err(|error| error.to_string())?;
    let mut receipt: Receipt = serde_json::from_slice(&state).map_err(|error| error.to_string())?;
    let deadline = receipt
        .expires_monotonic_ms
        .parse::<u64>()
        .map_err(|_| "acceptance deadline invalid")?;
    if bytes(&receipt)? != state
        || deadline.to_string() != receipt.expires_monotonic_ms
        || crate::emulator_diagnostic::monotonic_ms().map_err(|error| error.to_string())?
            >= deadline
    {
        return Err("acceptance relay expired or noncanonical".into());
    }
    // Terminal receipt queries cannot create or change installer state.
    if receipt.state != State::Waiting {
        if !((receipt.state == State::Accepted && request.decision == Decision::Accept)
            || (receipt.state == State::Rejected && request.decision == Decision::Reject)
            || request.decision == Decision::Status)
        {
            return Err("acceptance decision is terminal".into());
        }
        receipt.decision = request.decision;
        if !matches(request, &receipt) {
            return Err("acceptance terminal correlation differs".into());
        }
        return bytes(&receipt);
    }
    let path = Path::new(config::ROOT_ZONE)
        .join("recovery")
        .join(&request.transaction_id)
        .join("accept.sock");
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err("acceptance socket authority differs".into());
    }
    let mut stream = connect_bounded(&path)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&bytes(request)?)
        .map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    stream
        .take(MAX as u64 + 1)
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    if output.len() > MAX {
        return Err("oversized acceptance response".into());
    }
    let receipt: Receipt = serde_json::from_slice(&output).map_err(|error| error.to_string())?;
    if !matches(request, &receipt) || bytes(&receipt)? != output {
        return Err("acceptance response correlation differs".into());
    }
    Ok(output)
}

pub(crate) fn poll() {
    if !crate::emulator_diagnostic::emulator_guard() {
        return;
    }
    // No ordinary product path or daemon IO changes without an explicit emulator request.
    let Ok(run) = run_directory() else {
        return;
    };
    if let Ok(output) = run.read_trusted(RESPONSE, MAX, 0o600) {
        let expired = serde_json::from_slice::<Receipt>(&output)
            .ok()
            .and_then(|receipt| receipt.expires_monotonic_ms.parse::<u64>().ok())
            .zip(crate::emulator_diagnostic::monotonic_ms().ok())
            .is_none_or(|(deadline, now)| now >= deadline);
        let foreign_boot = serde_json::from_slice::<Receipt>(&output)
            .ok()
            .zip(operation_contract::current_boot_id().ok())
            .is_none_or(|(receipt, boot)| receipt.boot_id != boot);
        if expired || foreign_boot || crate::uninstall::request_present() {
            let _ = run.unlink(RESPONSE);
        }
    }
    let Ok(input) = run.read_trusted(REQUEST, MAX, 0o600) else {
        return;
    };
    let Ok(request) = Request::parse(&input) else {
        crate::log::err("install_acceptance", "relay request dropped: parse differs");
        let _ = run.unlink(REQUEST);
        return;
    };
    let Ok(output) = relay(&request) else {
        // relay() already logged the refusing stage; drop the request so the
        // bounded CLI timeout and this diagnostic agree on one attempt.
        let _ = run.unlink(REQUEST);
        return;
    };
    if run.read_trusted(REQUEST, MAX, 0o600).ok().as_deref() != Some(input.as_slice()) {
        return;
    }
    if run.write_atomic(RESPONSE, &output, 0o600).is_ok() {
        let _ = run.unlink(REQUEST);
    }
}

pub(crate) fn handle_cli() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("--emulator-install-acceptance") {
        return None;
    }
    let result = (|| {
        guard()?;
        crate::native_binary::verify_current_role(
            crate::native_executable_signature::NativeExecutableRole::Inject,
        )?;
        if args.len() != 2 {
            return Err("invalid closed acceptance arguments".to_string());
        }
        let mut input = args[1].as_bytes().to_vec();
        input.push(b'\n');
        let request = Request::parse(&input)?;
        let run = run_directory()?;
        run.validate_optional_trusted_file(REQUEST, 0o600)
            .map_err(|error| error.to_string())?;
        run.validate_optional_trusted_file(RESPONSE, 0o600)
            .map_err(|error| error.to_string())?;
        if run
            .entry_exists(RESPONSE)
            .map_err(|error| error.to_string())?
        {
            run.unlink(RESPONSE).map_err(|error| error.to_string())?;
        }
        run.write_atomic(REQUEST, &input, 0o600)
            .map_err(|error| error.to_string())?;
        let started = Instant::now();
        loop {
            if let Ok(output) = run.read_trusted(RESPONSE, MAX, 0o600) {
                let receipt: Receipt =
                    serde_json::from_slice(&output).map_err(|error| error.to_string())?;
                if !matches(&request, &receipt) || bytes(&receipt)? != output {
                    return Err("acceptance relay response differs".into());
                }
                run.unlink(RESPONSE).map_err(|error| error.to_string())?;
                std::io::stdout()
                    .write_all(&output)
                    .map_err(|error| error.to_string())?;
                return Ok(());
            }
            if started.elapsed() >= Duration::from_secs(3) {
                if run.read_trusted(REQUEST, MAX, 0o600).ok().as_deref() == Some(input.as_slice()) {
                    let _ = run.unlink(REQUEST);
                }
                return Err("acceptance relay not ready".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    Some(match result {
        Ok(()) => 0,
        Err(error) => {
            crate::log::err(
                "install_acceptance",
                &format!("install acceptance rejected: {error}"),
            );
            73
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn run_directory_accepts_shared_mode_and_rejects_private_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let run = root.path().join("run");
        std::fs::create_dir(&run).unwrap();
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(config::RUN_DIR_MODE))
            .unwrap();
        let metadata = std::fs::metadata(root.path()).unwrap();
        let accepted = run_directory_in(root.path(), metadata.uid(), metadata.gid()).unwrap();
        accepted.write_atomic(REQUEST, b"request", 0o600).unwrap();
        assert_eq!(
            accepted.read_trusted(REQUEST, MAX, 0o600).unwrap(),
            b"request"
        );
        assert_eq!(
            std::fs::metadata(run.join(REQUEST)).unwrap().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(run_directory_in(root.path(), metadata.uid(), metadata.gid()).is_err());
    }

    #[test]
    fn response_identity_includes_every_context_field_and_decision() {
        let request = Request {
            schema_version: 1,
            transaction_id: "1".repeat(64),
            manifest_sha256: "2".repeat(64),
            attempt_token: "3".repeat(64),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            reboot_count: 1,
            decision: Decision::Accept,
        };
        let receipt = Receipt {
            schema_version: 1,
            transaction_id: request.transaction_id.clone(),
            manifest_sha256: request.manifest_sha256.clone(),
            attempt_token: request.attempt_token.clone(),
            boot_id: request.boot_id.clone(),
            reboot_count: 1,
            decision: Decision::Accept,
            state: State::Accepted,
            expires_monotonic_ms: "180001".into(),
        };
        assert!(matches(&request, &receipt));
        for field in 0..7 {
            let mut wrong = receipt.clone();
            match field {
                0 => wrong.schema_version = 2,
                1 => wrong.transaction_id = "4".repeat(64),
                2 => wrong.manifest_sha256 = "4".repeat(64),
                3 => wrong.attempt_token = "4".repeat(64),
                4 => wrong.boot_id = "00000000-0000-0000-0000-000000000002".into(),
                5 => wrong.reboot_count = 2,
                _ => wrong.decision = Decision::Reject,
            }
            assert!(!matches(&request, &wrong));
        }
    }
    #[test]
    fn fixed_socket_transport_connects_and_rejects_missing_and_oversized_paths() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("accept.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut client = connect_bounded(&path).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(b"exact").unwrap();
        let mut data = [0; 5];
        server.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"exact");
        assert!(connect_bounded(&root.path().join("absent")).is_err());
        assert!(connect_bounded(Path::new(&"a".repeat(200))).is_err());
    }
}
