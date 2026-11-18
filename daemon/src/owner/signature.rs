//! The resident authenticates only its native role and the fixed native peer.
use crate::native_executable_signature::NativeExecutableRole;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
include!(concat!(env!("OUT_DIR"), "/owner_pubkey.rs"));

pub(crate) fn verify_appended_signature(role: NativeExecutableRole, bytes: &[u8]) -> bool {
    crate::native_executable_signature::verify(&NATIVE_EXECUTABLE_PUBKEY, role, bytes)
}

pub(crate) fn verify_current_role(role: NativeExecutableRole) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(Path::new("/proc/self/exe"))
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o700
        || before.len() == 0
        || before.len() > crate::config::MAX_NATIVE_EXECUTABLE_BYTES as u64
    {
        return Err("resident executable metadata rejected".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(crate::config::MAX_NATIVE_EXECUTABLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if changed(&before, &file)
        || bytes.len() as u64 != before.len()
        || !verify_appended_signature(role, &bytes)
    {
        return Err("resident executable role signature rejected".into());
    }
    Ok(())
}
fn changed(before: &std::fs::Metadata, file: &File) -> bool {
    let Ok(after) = file.metadata() else {
        return true;
    };
    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.nlink() != after.nlink()
        || before.mode() != after.mode()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}
