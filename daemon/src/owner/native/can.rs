//! Passive, bounded OEM CAN datagrams. Receiving a frame does not prove ECU freshness.
use std::io;

#[cfg(any(target_os = "android", target_os = "linux", test))]
const CAPACITY: usize = 257;

#[cfg(any(target_os = "android", target_os = "linux", test))]
fn require_device(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    if !std::fs::symlink_metadata(path)?
        .file_type()
        .is_char_device()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OEM CAN character device unavailable",
        ));
    }
    Ok(())
}

// Unsupported host platforms have no native receiver that constructs these variants.
#[cfg_attr(
    not(any(target_os = "android", target_os = "linux", test)),
    expect(dead_code)
)]
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Received {
    Frame(Vec<u8>),
    Unsupported,
    Empty,
}

#[cfg(any(target_os = "android", target_os = "linux", test))]
pub(super) fn validate(
    bytes: &[u8],
    sender_pid: u32,
    sender_groups: u32,
    truncated: bool,
) -> io::Result<Received> {
    if sender_pid != 0 || sender_groups != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid OEM CAN sender",
        ));
    }
    // Kernel multicast also carries service messages outside the short-frame schema.
    // recvmsg consumes that datagram even when its payload exceeds our buffer.
    if truncated
        || bytes.len() < 2
        || bytes.len() > CAPACITY
        || bytes.len() != usize::from(bytes[1]) + 2
    {
        return Ok(Received::Unsupported);
    }
    Ok(Received::Frame(bytes.into()))
}

pub(super) struct Receiver {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    descriptor: std::os::fd::OwnedFd,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    buffer: Vec<u8>,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    receive_buffer_bytes: libc::c_int,
}

impl Receiver {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub(super) fn open() -> io::Result<Self> {
        fn at(stage: &str, error: io::Error) -> io::Error {
            io::Error::new(error.kind(), format!("{stage}: {error}"))
        }

        use std::os::fd::FromRawFd;
        // Protocol21 alone may be a standard Linux crypto endpoint on another kernel.
        require_device(std::path::Path::new("/dev/cis_can"))
            .map_err(|error| at("probe /dev/cis_can", error))?;
        let descriptor = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                21,
            )
        };
        if descriptor < 0 {
            return Err(at(
                "socket(AF_NETLINK, protocol 21)",
                io::Error::last_os_error(),
            ));
        }
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) };
        let requested: libc::c_int = 256 * 1024;
        if unsafe {
            libc::setsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&requested as *const libc::c_int).cast(),
                std::mem::size_of_val(&requested) as _,
            )
        } != 0
        {
            return Err(at("setsockopt(CAN SO_RCVBUF)", io::Error::last_os_error()));
        }
        let mut receive_buffer_bytes: libc::c_int = 0;
        let mut option_bytes = std::mem::size_of_val(&receive_buffer_bytes) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                descriptor,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&mut receive_buffer_bytes as *mut libc::c_int).cast(),
                &mut option_bytes,
            )
        } != 0
        {
            return Err(at("getsockopt(CAN SO_RCVBUF)", io::Error::last_os_error()));
        }
        if option_bytes as usize != std::mem::size_of_val(&receive_buffer_bytes)
            || receive_buffer_bytes <= 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid CAN receive buffer size",
            ));
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        address.nl_pid = unsafe { libc::getpid() } as u32;
        address.nl_groups = 1;
        let status = unsafe {
            libc::bind(
                descriptor,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if status < 0 {
            return Err(at(
                "bind(CAN multicast group 1)",
                io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            descriptor: owned,
            buffer: vec![0; 65536],
            receive_buffer_bytes,
        })
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    pub(super) fn open() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OEM CAN requires Linux netlink",
        ))
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub(super) fn receive(
        &mut self,
        capture: impl FnOnce(super::capture::Datagram),
    ) -> io::Result<Received> {
        use std::os::fd::AsRawFd;
        let bytes = &mut self.buffer;
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        message.msg_namelen = std::mem::size_of_val(&sender) as libc::socklen_t;
        message.msg_iov = &mut vector;
        message.msg_iovlen = 1;
        let received = unsafe {
            libc::recvmsg(
                self.descriptor.as_raw_fd(),
                &mut message,
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(Received::Empty)
            } else {
                Err(error)
            };
        }
        let length =
            usize::try_from(received).map_err(|_| io::Error::other("invalid CAN receive size"))?;
        capture(super::capture::Datagram {
            bytes: bytes[..length.min(bytes.len())].to_vec(),
            reported_bytes: length,
            socket_buffer_bytes: self.receive_buffer_bytes,
            sender_pid: sender.nl_pid,
            sender_groups: sender.nl_groups,
            address_bytes: message.msg_namelen as usize,
            sender_family: sender.nl_family,
            flags: message.msg_flags,
            received_boot_ms: super::clock::Stamp::now().boot_ms,
        });
        if message.msg_namelen as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid OEM CAN sender address",
            ));
        }
        validate(
            &bytes[..length.min(bytes.len())],
            sender.nl_pid,
            sender.nl_groups,
            length > bytes.len() || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0,
        )
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    pub(super) fn receive(
        &mut self,
        capture: impl FnOnce(super::capture::Datagram),
    ) -> io::Result<Received> {
        let _ = capture;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OEM CAN requires Linux netlink",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_device_probe_rejects_missing_regular_and_redirected_nodes() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("node");
        assert!(require_device(&file).is_err());
        std::fs::write(&file, b"not a device").unwrap();
        assert!(require_device(&file).is_err());
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("/dev/null", &file).unwrap();
        assert!(require_device(&file).is_err());
        assert!(require_device(std::path::Path::new("/dev/null")).is_ok());
    }

    #[test]
    fn kernel_service_datagram_is_not_a_receiver_failure() {
        // Captured on A9: kernel/group 1, reported length 7424, prefix 8f 1c.
        let mut captured_prefix = vec![0; CAPACITY];
        captured_prefix[..2].copy_from_slice(&[0x8f, 0x1c]);
        assert!(
            validate(&captured_prefix, 0, 1, true).is_ok(),
            "an unsupported kernel datagram must not close the receiver or erase ACC"
        );
    }

    #[test]
    fn only_kernel_group_one_exact_frames_are_accepted() {
        let frame = [0x71, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            validate(&frame, 0, 1, false).unwrap(),
            Received::Frame(frame.into())
        );
        for (pid, groups, truncated) in [(1, 1, false), (0, 0, false), (0, 3, false)] {
            assert!(validate(&frame, pid, groups, truncated).is_err());
        }
        for length in 0..frame.len() {
            assert_eq!(
                validate(&frame[..length], 0, 1, false).unwrap(),
                Received::Unsupported
            );
        }
        assert_eq!(
            validate(&[0x71, 0, 0], 0, 1, false).unwrap(),
            Received::Unsupported
        );
        assert_eq!(
            validate(&[0; CAPACITY + 1], 0, 1, false).unwrap(),
            Received::Unsupported
        );
        assert_eq!(validate(&frame, 0, 1, true).unwrap(), Received::Unsupported);
        let mut largest = vec![0; CAPACITY];
        largest[1] = 255;
        assert_eq!(
            validate(&largest, 0, 1, false).unwrap(),
            Received::Frame(largest)
        );
    }
}
