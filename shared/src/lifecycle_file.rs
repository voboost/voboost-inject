use std::fs;
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStamp {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl FileStamp {
    pub fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            nlink: metadata.nlink(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }
}

#[derive(Debug)]
pub struct TrustedBytes {
    pub bytes: Vec<u8>,
    pub stamp: FileStamp,
    pub selinux_context: Option<String>,
}
