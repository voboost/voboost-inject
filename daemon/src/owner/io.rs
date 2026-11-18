//! Bounded framed exchange on the private owner socket.
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use voboost_contract::runtime_owner::MAX_FRAME_BYTES;
fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "owner exchange deadline"))
}
fn wait(fd: libc::c_int, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let milliseconds = remaining(deadline)?
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if ready > 0 {
            return Ok(());
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
pub(crate) fn connect(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !path.is_absolute() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "owner socket path rejected",
        ));
    }
    address.sun_family = libc::AF_UNIX as _;
    for (target, value) in address.sun_path.iter_mut().zip(bytes) {
        *target = *value as _;
    }
    let length =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    #[cfg(target_vendor = "apple")]
    {
        address.sun_len = length as _;
    }
    remaining(deadline)?;
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(true)?;
    let connected =
        unsafe { libc::connect(fd, &address as *const _ as *const libc::sockaddr, length) };
    if connected != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        ) {
            return Err(error);
        }
        loop {
            let milliseconds = remaining(deadline)?
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut poll, 1, milliseconds) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            if let Some(error) = stream.take_error()? {
                return Err(error);
            }
            stream.peer_addr()?;
            break;
        }
    }
    remaining(deadline)?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}
fn read_exact(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "owner frame ended",
                ))
            }
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream.as_raw_fd(), libc::POLLIN, deadline)?
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
pub(crate) fn read(stream: &mut UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    stream.set_nonblocking(true)?;
    let mut header = [0; 4];
    read_exact(stream, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner frame exceeds bound",
        ));
    }
    let mut bytes = vec![0; length];
    read_exact(stream, &mut bytes, deadline)?;
    Ok(bytes)
}
pub(crate) fn write(stream: &mut UnixStream, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner frame exceeds bound",
        ));
    }
    stream.set_nonblocking(true)?;
    let header = (bytes.len() as u32).to_be_bytes();
    for mut part in [&header[..], bytes] {
        while !part.is_empty() {
            remaining(deadline)?;
            match stream.write(part) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "owner frame write stalled",
                    ))
                }
                Ok(n) => part = &part[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    wait(stream.as_raw_fd(), libc::POLLOUT, deadline)?
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}
pub(crate) fn request<
    O: serde::de::DeserializeOwned + Into<voboost_contract::runtime_owner::Outcome>,
>(
    stream: &mut UnixStream,
    command: voboost_contract::runtime_owner::Command,
    deadline: Instant,
) -> io::Result<voboost_contract::runtime_owner::Outcome> {
    let greeting =
        voboost_contract::runtime_owner::Reply::<O>::decode_as(&read(stream, deadline)?, 0)
            .map_err(io::Error::other)?;
    let request = voboost_contract::runtime_owner::Request {
        schema_version: voboost_contract::runtime_owner::SCHEMA,
        session: greeting.session,
        request_id: 1,
        command,
    };
    request.validate().map_err(io::Error::other)?;
    let bytes = serde_json::to_vec(&request).map_err(io::Error::other)?;
    write(stream, &bytes, deadline)?;
    let reply = voboost_contract::runtime_owner::Reply::<O>::decode_as(
        &read(stream, deadline)?,
        request.request_id,
    )
    .map_err(io::Error::other)?;
    if reply.session != request.session {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime owner session changed",
        ));
    }
    Ok(reply.outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voboost_contract::runtime_owner::{Command, Outcome, Reply, Request, SCHEMA};

    fn greeted_pair() -> (UnixStream, UnixStream) {
        let (client, mut server) = UnixStream::pair().unwrap();
        write(
            &mut server,
            &serde_json::to_vec(&Reply {
                schema_version: SCHEMA,
                session: "a".repeat(32),
                request_id: 0,
                outcome: Outcome::Ready {},
            })
            .unwrap(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        (client, server)
    }

    #[test]
    fn typed_request_rejects_invalid_commands_and_oversized_encoding_before_send() {
        for (command, message) in [
            (
                Command::PublishInjectionStatus { bytes: "".into() },
                "invalid runtime command",
            ),
            (
                Command::ReplaceConfig {
                    expected: None,
                    next: "\0".repeat(voboost_contract::runtime_owner::MAX_CONFIG_BYTES),
                },
                "owner frame exceeds bound",
            ),
        ] {
            let (mut client, mut server) = greeted_pair();
            let error = request::<Outcome>(
                &mut client,
                command,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), message);
            server.set_nonblocking(true).unwrap();
            assert_eq!(
                server.read(&mut [0]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }

    #[test]
    fn typed_request_uses_the_same_wire_contract_and_owner_reply() {
        let (mut client, mut server) = greeted_pair();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(1);
            let request = Request::decode(&read(&mut server, deadline).unwrap()).unwrap();
            assert!(matches!(request.command, Command::ReadConfig {}));
            write(
                &mut server,
                &serde_json::to_vec(&Reply {
                    schema_version: SCHEMA,
                    session: request.session,
                    request_id: request.request_id,
                    outcome: Outcome::Config { bytes: None },
                })
                .unwrap(),
                deadline,
            )
            .unwrap();
        });
        assert!(matches!(
            request::<Outcome>(
                &mut client,
                Command::ReadConfig {},
                Instant::now() + Duration::from_secs(1)
            )
            .unwrap(),
            Outcome::Config { bytes: None }
        ));
        worker.join().unwrap();
    }

    #[test]
    fn connection_uses_fixed_unix_path_and_rejects_expired_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owner.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let mut client = connect(&path, Instant::now() + Duration::from_secs(1)).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        write(
            &mut client,
            b"probe",
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(
            read(&mut server, Instant::now() + Duration::from_secs(1)).unwrap(),
            b"probe"
        );
        assert!(connect(&path, Instant::now()).is_err());
        assert!(connect(
            Path::new("owner.sock"),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
    }
    #[test]
    fn complete_frame_and_truncation_use_actual_socket_pairs() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        write(&mut a, b"exact", Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!(
            read(&mut b, Instant::now() + Duration::from_secs(1)).unwrap(),
            b"exact"
        );
        a.write_all(&10u32.to_be_bytes()).unwrap();
        a.write_all(b"short").unwrap();
        a.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(
            read(&mut b, Instant::now() + Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&10u32.to_be_bytes()).unwrap();
        a.write_all(b"short").unwrap();
        drop(a);
        assert!(read(&mut b, Instant::now() + Duration::from_secs(1)).is_err());
    }
    #[test]
    fn complete_buffered_reply_remains_readable_after_peer_exits() {
        for _ in 0..16 {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            write(
                &mut a,
                b"committed",
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            drop(a);
            assert_eq!(
                read(&mut b, Instant::now() + Duration::from_secs(1)).unwrap(),
                b"committed"
            );
        }
    }
    #[test]
    fn empty_oversized_and_stalled_frames_fail_closed() {
        for length in [0, MAX_FRAME_BYTES as u32 + 1] {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            a.write_all(&length.to_be_bytes()).unwrap();
            assert_eq!(
                read(&mut b, Instant::now() + Duration::from_secs(1))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let (_a, mut b) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(read(&mut b, start + Duration::from_millis(20)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
