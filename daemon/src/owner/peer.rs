//! Authenticate the fixed installed peer, not identity supplied in a frame.
use crate::native_executable_signature::NativeExecutableRole;
#[cfg(any(target_os = "android", target_os = "linux", test))]
use std::fs::{File, Metadata};
use std::io;
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "android", target_os = "linux", test))]
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;

#[cfg(any(target_os = "android", target_os = "linux", test))]
#[path = "peer/cache.rs"]
mod cache;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "owner peer identity rejected",
    )
}
#[cfg(any(target_os = "android", target_os = "linux", test))]
#[derive(Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}
#[cfg(any(target_os = "android", target_os = "linux", test))]
fn stamp(m: &Metadata) -> Stamp {
    Stamp {
        device: m.dev(),
        inode: m.ino(),
        size: m.len(),
        links: m.nlink(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    }
}
pub(crate) fn verify(stream: &UnixStream, role: NativeExecutableRole) -> io::Result<()> {
    verify_roles(stream, &[role]).map(|_| ())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[allow(
    dead_code,
    reason = "Shared peer module: owner binds producer identities; inject uses only signature verification"
)]
pub(crate) fn process_identity(stream: &UnixStream) -> io::Result<(i32, u64)> {
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut peer as *mut _ as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || peer.pid <= 1
    {
        return Err(invalid());
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", peer.pid))
        .map_err(|error| io::Error::new(error.kind(), format!("peer stat: {error}")))?;
    let (_, fields) = stat.rsplit_once(')').ok_or_else(invalid)?;
    let starttime = fields
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(invalid)?;
    Ok((peer.pid, starttime))
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
#[allow(
    dead_code,
    reason = "Shared peer module: owner binds producer identities; inject uses only signature verification"
)]
pub(crate) fn process_identity(_stream: &UnixStream) -> io::Result<(i32, u64)> {
    Err(invalid())
}
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn verify_roles(
    stream: &UnixStream,
    roles: &[NativeExecutableRole],
) -> io::Result<NativeExecutableRole> {
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut peer as *mut _ as *mut libc::c_void,
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || peer.uid != 0
        || peer.gid != 0
        || peer.pid <= 1
    {
        return Err(invalid());
    }
    let path = format!("/proc/{}/exe", peer.pid);
    // On the bounded-su kernel (proved on the free-09-chinese 6.0.3 emulator)
    // the /proc/<pid>/exe link and handle of an adb-spawned CLI peer are denied
    // even to this root owner, exactly like the task hooks in
    // resident_inject_status. The kernel-recorded argv is the documented
    // fallback there; the peer here is bounded to one of the fixed installed
    // executables, so the argv[0] identity selects the stable on-disk path
    // and the signature is verified against that stable file. Opening the
    // exact installed path directly (never through /proc) keeps every other
    // check authoritative: mode, owner, single link and appended signature.
    // Every refusal names its stage so the bounded client log pinpoints it.
    let cmdline_stage = std::cell::Cell::new(None);
    let executable = match std::fs::read_link(&path) {
        Ok(value) => Some(value),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => None,
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("peer exe link: {error}"),
            ))
        }
    };
    let role = roles
        .iter()
        .copied()
        .find(|role| {
            let name = match role {
                NativeExecutableRole::Daemon => "voboost-daemon",
                NativeExecutableRole::Inject => "voboost-inject",
                _ => return false,
            };
            let installed = std::path::Path::new("/data/voboost").join(name);
            match &executable {
                Some(link) => *link == installed,
                None => {
                    // argv[0] identifies the exec'd binary: the CLI peer is
                    // exec'd from the exact stable path, and the signature
                    // check below binds the file.
                    match std::fs::read(format!("/proc/{}/cmdline", peer.pid)) {
                        Ok(cmdline) => {
                            cmdline
                                .split(|byte| *byte == 0)
                                .next()
                                .map(|value| value.to_vec())
                                .as_deref()
                                == Some(installed.as_os_str().as_encoded_bytes())
                        }
                        Err(error) => {
                            cmdline_stage.set(Some(format!("peer cmdline: {error}")));
                            false
                        }
                    }
                }
            }
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                cmdline_stage
                    .take()
                    .unwrap_or_else(|| "owner peer identity rejected".to_string()),
            )
        })?;
    let stable = std::path::Path::new("/data/voboost").join(match role {
        NativeExecutableRole::Daemon => "voboost-daemon",
        // The accepted peer set above is exactly Daemon and Inject; any other
        // role was already rejected by the roles filter.
        NativeExecutableRole::Inject => "voboost-inject",
        _ => return Err(invalid()),
    });
    let file = File::open(&stable)
        .map_err(|error| io::Error::new(error.kind(), format!("peer stable open: {error}")))?;
    let before = file
        .metadata()
        .map_err(|error| io::Error::new(error.kind(), format!("peer stable stat: {error}")))?;
    if !before.is_file()
        || before.uid() != 0
        || before.gid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o700
        || before.len() == 0
        || before.len() > crate::config::MAX_NATIVE_EXECUTABLE_BYTES as u64
    {
        return Err(invalid());
    }
    cache::authenticate(
        role,
        file,
        || std::fs::metadata(&stable),
        |role, bytes| crate::native_binary::verify_appended_signature(role, bytes),
    )?;
    Ok(role)
}
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub(crate) fn verify_roles(
    _stream: &UnixStream,
    _roles: &[NativeExecutableRole],
) -> io::Result<NativeExecutableRole> {
    Err(invalid())
}
