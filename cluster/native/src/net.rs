//! Bounded ordinary TCP and protected local socket framing.
use crate::{
    fs::{read_exact, write_all, Fd},
    Result,
};
use alloc::{ffi::CString, vec, vec::Vec};
use voboost_contract_core::MAX_DOCUMENT_BYTES;
pub fn timeout(fd: i32) -> Result<()> {
    let timeout = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&timeout as *const libc::timeval).cast(),
                core::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } != 0
        {
            return Err("socket timeout unavailable".into());
        }
    }
    Ok(())
}
pub fn read_frame(fd: i32) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    read_exact(fd, &mut length)?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > MAX_DOCUMENT_BYTES {
        return Err("native IPC frame size".into());
    }
    let mut b = vec![0; n];
    read_exact(fd, &mut b)?;
    Ok(b)
}
pub fn write_frame(fd: i32, b: &[u8]) -> Result<()> {
    write_all(fd, &voboost_contract_core::wire::frame(b)?)
}
fn unix_address(path: &str) -> Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut a: libc::sockaddr_un = unsafe { core::mem::zeroed() };
    if !voboost_contract_core::safe_path(path) || path.len() >= a.sun_path.len() {
        return Err("protected IPC path bound".into());
    }
    a.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (out, byte) in a.sun_path.iter_mut().zip(path.bytes()) {
        *out = byte as libc::c_char;
    }
    #[cfg(any(target_os = "nto", target_os = "macos"))]
    {
        a.sun_len = core::mem::size_of_val(&a) as u8;
    }
    let size = core::mem::size_of_val(&a) as libc::socklen_t;
    Ok((a, size))
}
pub fn unix_connect(path: &str) -> Result<Fd> {
    unix_connect_optional(path)?.ok_or_else(|| "startup controller unavailable".into())
}
fn connection_failure(error: i32) -> Result<Option<Fd>> {
    match error {
        libc::ENOENT | libc::ECONNREFUSED => Ok(None),
        _ => Err(alloc::format!(
            "startup controller connect failed errno={error}"
        )),
    }
}
pub(crate) fn unix_connect_optional(path: &str) -> Result<Option<Fd>> {
    let fd = Fd(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) });
    if fd.0 < 0 {
        return Err("IPC socket unavailable".into());
    }
    timeout(fd.0)?;
    let (address, length) = unix_address(path)?;
    if unsafe { libc::connect(fd.0, (&address as *const libc::sockaddr_un).cast(), length) } != 0 {
        return connection_failure(crate::fs::errno());
    }
    Ok(Some(fd))
}

pub fn unix_listen(path: &str) -> Result<Fd> {
    let (address, length) = unix_address(path)?;
    let name = CString::new(path).map_err(|_| "IPC path NUL")?;
    let mut s = unsafe { core::mem::zeroed() };
    if unsafe { libc::lstat(name.as_ptr(), &mut s) } == 0 {
        // The protected root excludes untrusted creators. Only an earlier socket can
        // be removed; ordinary files and symlinks are never replaced.
        if s.st_mode & libc::S_IFMT != libc::S_IFSOCK || s.st_uid != unsafe { libc::geteuid() } {
            return Err("IPC endpoint is not owned socket".into());
        }
        if unix_connect(path).is_ok() {
            return Err("startup controller already serving".into());
        }
        if unsafe { libc::unlink(name.as_ptr()) } != 0 {
            return Err("stale IPC socket remove failed".into());
        }
    }
    let fd = Fd(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) });
    if fd.0 < 0
        || unsafe { libc::bind(fd.0, (&address as *const libc::sockaddr_un).cast(), length) } != 0
        || unsafe { libc::chmod(name.as_ptr(), 0o600) } != 0
        || unsafe { libc::listen(fd.0, 1) } != 0
    {
        return Err("protected IPC listener failed".into());
    }
    Ok(fd)
}
#[derive(Debug)]
pub(crate) struct ListenError {
    stage: &'static str,
    errno: Option<i32>,
}

impl ListenError {
    fn syscall(stage: &'static str) -> Self {
        Self {
            stage,
            errno: Some(crate::fs::errno()),
        }
    }

    pub(crate) fn network_unavailable(&self) -> bool {
        matches!(
            self.errno,
            Some(
                libc::EADDRNOTAVAIL
                    | libc::ENETDOWN
                    | libc::ENETUNREACH
                    | libc::ENODEV
                    | libc::ENXIO
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_listener_reports_bind_failure_without_retrying_an_occupied_port() {
        let occupied = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let Err(error) = tcp_listen("127.0.0.1", port) else {
            panic!("the port is already occupied");
        };
        assert_eq!(error.stage, "bind");
        assert_eq!(error.errno, Some(libc::EADDRINUSE));
        assert!(!error.network_unavailable());
    }

    #[test]
    fn tcp_listener_retries_when_the_local_address_is_not_ready() {
        let error = ListenError {
            stage: "bind",
            errno: Some(libc::EADDRNOTAVAIL),
        };
        assert!(error.network_unavailable());
    }
}

impl core::fmt::Display for ListenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.errno {
            Some(errno) => write!(
                f,
                "native TCP listener {} failed (errno {errno})",
                self.stage
            ),
            None => f.write_str(self.stage),
        }
    }
}

pub(crate) fn tcp_listen(address: &str, port: u16) -> core::result::Result<Fd, ListenError> {
    let mut a: libc::sockaddr_in = unsafe { core::mem::zeroed() };
    let octets = address
        .parse::<core::net::Ipv4Addr>()
        .map_err(|_| ListenError {
            stage: "IPv4 literal required",
            errno: None,
        })?
        .octets();
    a.sin_family = libc::AF_INET as libc::sa_family_t;
    a.sin_port = port.to_be();
    a.sin_addr.s_addr = u32::from_ne_bytes(octets);
    #[cfg(any(target_os = "nto", target_os = "macos"))]
    {
        a.sin_len = core::mem::size_of_val(&a) as u8;
    }
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(ListenError::syscall("socket"));
    }
    let fd = Fd(fd);
    let one = 1i32;
    if unsafe {
        libc::setsockopt(
            fd.0,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&one as *const i32).cast(),
            core::mem::size_of_val(&one) as libc::socklen_t,
        )
    } != 0
    {
        return Err(ListenError::syscall("setsockopt(SO_REUSEADDR)"));
    }
    if unsafe {
        libc::bind(
            fd.0,
            (&a as *const libc::sockaddr_in).cast(),
            core::mem::size_of_val(&a) as libc::socklen_t,
        )
    } != 0
    {
        return Err(ListenError::syscall("bind"));
    }
    if unsafe { libc::listen(fd.0, 4) } != 0 {
        return Err(ListenError::syscall("listen"));
    }
    Ok(fd)
}
pub fn listener_ready(listener: i32, timeout_ms: i32) -> Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        if crate::fs::errno() == libc::EINTR {
            return Ok(false);
        }
        return Err("native listener poll failed".into());
    }
    if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err("native listener became unavailable".into());
    }
    Ok(result > 0 && descriptor.revents & libc::POLLIN != 0)
}

pub fn accept(listener: i32) -> Result<Fd> {
    let fd = Fd(unsafe { libc::accept(listener, core::ptr::null_mut(), core::ptr::null_mut()) });
    if fd.0 < 0 {
        return Err("native accept failed".into());
    }
    timeout(fd.0)?;
    Ok(fd)
}

#[cfg(test)]
mod connection_tests {
    use super::*;
    #[test]
    fn idle_listener_tick_does_not_need_a_peer_and_detects_closed_channel() {
        let mut pair = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pair.as_mut_ptr()) }, 0);
        let reader = Fd(pair[0]);
        let writer = Fd(pair[1]);
        assert!(!listener_ready(reader.0, 0).unwrap());
        let byte = 1u8;
        assert_eq!(
            unsafe { libc::write(writer.0, (&byte as *const u8).cast(), 1) },
            1
        );
        assert!(listener_ready(reader.0, 0).unwrap());
        drop(writer);
        assert!(listener_ready(reader.0, 0).is_err());
    }

    #[test]
    fn absent_controller_is_pending_but_access_and_transport_failures_are_errors() {
        for error in [libc::ENOENT, libc::ECONNREFUSED] {
            assert!(connection_failure(error).unwrap().is_none());
        }
        for error in [libc::EACCES, libc::EPERM, libc::EIO, libc::ETIMEDOUT] {
            assert!(connection_failure(error).is_err());
        }
        let directory = tempfile::tempdir().unwrap();
        assert!(
            unix_connect_optional(directory.path().join("absent").to_str().unwrap())
                .unwrap()
                .is_none()
        );
    }
}
