// secure_fs.rs — descriptor-relative file-boundary primitives.
//
// App-zone inputs are opened without following links and read from one stable
// descriptor. Trusted-zone output is always a fresh daemon-created inode.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::Path;

use sha2::{Digest, Sha256};

const WRITE_BITS: u32 = 0o022;

pub struct Directory {
    file: File,
}

#[derive(Debug, Eq, PartialEq)]
pub struct TrustedSnapshot {
    pub bytes: Vec<u8>,
    stamp: FileStamp,
}

/// Advisory transaction lock on the already validated directory inode.
/// Each acquisition opens the pinned inode through `.` to obtain an independent
/// open-file description, so threads and processes coordinate identically.
pub struct DirectoryTransactionLock(File);
impl Drop for DirectoryTransactionLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Directory {
    pub fn lock_transaction(
        &self,
        deadline: std::time::Duration,
    ) -> io::Result<DirectoryTransactionLock> {
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let start = std::time::Instant::now();
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(DirectoryTransactionLock(file));
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.raw_os_error(),
                Some(libc::EWOULDBLOCK) | Some(libc::EINTR)
            ) {
                return Err(error);
            }
            if start.elapsed() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "directory transaction lock deadline",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    pub fn append_trusted(
        &self,
        name: &str,
        bytes: &[u8],
        maximum_after_write: u64,
        mode: u32,
    ) -> io::Result<u64> {
        self.append_trusted_inner(name, bytes, maximum_after_write, mode, None, true)
            .map(|(size, _)| size)
    }

    pub fn append_trusted_with_durability(
        &self,
        name: &str,
        bytes: &[u8],
        maximum_after_write: u64,
        mode: u32,
        expected: Option<&File>,
        synchronize: bool,
    ) -> io::Result<File> {
        self.append_trusted_inner(
            name,
            bytes,
            maximum_after_write,
            mode,
            expected,
            synchronize,
        )
        .map(|(_, file)| file)
    }

    fn append_trusted_inner(
        &self,
        name: &str,
        bytes: &[u8],
        maximum_after_write: u64,
        mode: u32,
        expected_file: Option<&File>,
        synchronize: bool,
    ) -> io::Result<(u64, File)> {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_APPEND
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let before = file.metadata()?;
        validate_trusted(&before, uid, gid, Some(mode))?;
        if let Some(expected) = expected_file {
            let expected = expected.metadata()?;
            if (before.dev(), before.ino()) != (expected.dev(), expected.ino()) {
                return Err(invalid_data("pending append inode changed"));
            }
        }
        let expected = before
            .len()
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid_data("trusted append size overflow"))?;
        if expected > maximum_after_write {
            return Err(invalid_data("trusted append exceeds size bound"));
        }
        file.write_all(bytes)?;
        if synchronize {
            file.sync_data()?;
        }
        let after = file.metadata()?;
        validate_trusted(&after, uid, gid, Some(mode))?;
        if after.dev() != before.dev() || after.ino() != before.ino() || after.len() != expected {
            return Err(invalid_data("trusted append inode or size changed"));
        }
        Ok((after.len(), file))
    }

    pub fn sync_trusted_append(&self, name: &str, mode: u32, file: &File) -> io::Result<()> {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let before = file.metadata()?;
        validate_trusted(&before, uid, gid, Some(mode))?;
        let named = self.entry_metadata(name)?;
        validate_trusted(&named, uid, gid, Some(mode))?;
        if (named.dev(), named.ino()) != (before.dev(), before.ino()) {
            return Err(invalid_data("pending append name changed"));
        }
        file.sync_data()?;
        let after = file.metadata()?;
        let named_after = self.entry_metadata(name)?;
        validate_trusted(&after, uid, gid, Some(mode))?;
        validate_trusted(&named_after, uid, gid, Some(mode))?;
        if (after.dev(), after.ino(), after.len()) != (before.dev(), before.ino(), before.len())
            || (named_after.dev(), named_after.ino()) != (after.dev(), after.ino())
        {
            return Err(invalid_data("pending append changed during sync"));
        }
        Ok(())
    }

    pub fn metadata_trusted(&self, name: &str, mode: u32) -> io::Result<(u64, u64)> {
        let metadata = self.entry_metadata(name)?;
        validate_trusted(
            &metadata,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            Some(mode),
        )?;
        Ok((metadata.ino(), metadata.len()))
    }
    pub fn entry_names_bounded(&self, maximum: usize) -> io::Result<Vec<String>> {
        unsafe fn errno_location() -> *mut libc::c_int {
            #[cfg(target_os = "macos")]
            {
                libc::__error()
            }
            #[cfg(target_os = "android")]
            {
                libc::__errno()
            }
            #[cfg(not(any(target_os = "macos", target_os = "android")))]
            {
                libc::__errno_location()
            }
        }
        // `dup` shares one open-file-description directory offset with the
        // retained authority. Re-open `.` descriptor-relatively so repeated
        // bounded enumerations always start from a fresh offset.
        let duplicate = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0,
            )
        };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(duplicate) };
            return Err(error);
        }
        let mut names = Vec::new();
        let result = loop {
            unsafe { *errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = unsafe { *errno_location() };
                break if errno == 0 {
                    Ok(names)
                } else {
                    Err(io::Error::from_raw_os_error(errno))
                };
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if names.len() >= maximum {
                break Err(invalid_data("directory entry bound exceeded"));
            }
            let name = match std::str::from_utf8(bytes) {
                Ok(name) => name,
                Err(_) => break Err(invalid_data("non-UTF8 directory entry")),
            };
            names.push(name.to_owned());
        };
        unsafe { libc::closedir(stream) };
        result
    }

    pub fn entry_info_nofollow(&self, name: &str) -> io::Result<(bool, u64)> {
        let name = c_name(OsStr::new(name))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok((
            (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR,
            stat.st_size.max(0) as u64,
        ))
    }

    /// Whether the entry exists and is a regular file (never follows a
    /// symlink). Callers use this to decide if a stale temp entry may be
    /// replaced; every non-regular entry must fail closed instead.
    pub fn entry_is_regular(&self, name: &str) -> io::Result<bool> {
        let name = c_name(OsStr::new(name))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFREG)
    }
    pub fn open(path: &Path) -> io::Result<Self> {
        let path = c_path(path)?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        from_dir_fd(fd)
    }

    pub fn open_child(&self, name: &str) -> io::Result<Self> {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        from_dir_fd(fd)
    }

    /// Open the fixed child directory under the caller-supplied canonical
    /// mode contract, creating it with that exact mode when absent. The
    /// all-`0`700 variant above guards private transaction state; this one
    /// serves fixed directories — such as the root-zone run directory —
    /// whose canonical mode is intentionally broader.
    pub fn open_or_create_child_with_mode(&self, name: &str, mode: u32) -> io::Result<Self> {
        match self.open_child(name) {
            Ok(dir) => {
                let uid = unsafe { libc::geteuid() };
                let gid = unsafe { libc::getegid() };
                dir.validate_owner_mode(uid, gid, mode)?;
                Ok(dir)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name_c = c_name(OsStr::new(name))?;
                let result = unsafe {
                    libc::mkdirat(self.file.as_raw_fd(), name_c.as_ptr(), mode as libc::mode_t)
                };
                if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(io::Error::last_os_error());
                }
                let dir = self.open_child(name)?;
                dir.set_owner(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
                dir.set_mode(mode)?;
                dir.sync_all()?;
                self.sync_all()?;
                Ok(dir)
            }
            Err(error) => Err(error),
        }
    }

    pub fn open_or_create_private_child(&self, name: &str) -> io::Result<Self> {
        match self.open_child(name) {
            Ok(dir) => {
                let uid = unsafe { libc::geteuid() };
                let gid = unsafe { libc::getegid() };
                dir.validate_owner_mode(uid, gid, 0o700)?;
                Ok(dir)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name_c = c_name(OsStr::new(name))?;
                let result = unsafe {
                    libc::mkdirat(
                        self.file.as_raw_fd(),
                        name_c.as_ptr(),
                        0o700 as libc::mode_t,
                    )
                };
                if result != 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                {
                    return Err(io::Error::last_os_error());
                }
                let dir = self.open_child(name)?;
                dir.set_owner(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
                dir.set_mode(0o700)?;
                dir.sync_all()?;
                self.sync_all()?;
                Ok(dir)
            }
            Err(error) => Err(error),
        }
    }

    /// Create a fresh root-owned private child directory. Unlike
    /// `open_or_create_private_child`, an existing name is always an error;
    /// transaction callers therefore cannot accidentally reuse stale state.
    pub fn create_private_child(&self, name: &str) -> io::Result<Self> {
        let name_c = c_name(OsStr::new(name))?;
        let result = unsafe {
            libc::mkdirat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                0o700 as libc::mode_t,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let dir = self.open_child(name)?;
        dir.set_owner(unsafe { libc::geteuid() }, unsafe { libc::getegid() })?;
        dir.set_mode(0o700)?;
        dir.sync_all()?;
        self.sync_all()?;
        Ok(dir)
    }

    pub fn validate_optional_trusted_file(&self, name: &str, mode: u32) -> io::Result<()> {
        self.validate_optional_trusted(name, unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        })?;
        if self.entry_exists(name)? {
            validate_trusted(
                &self.entry_metadata(name)?,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                Some(mode),
            )?;
        }
        Ok(())
    }

    pub fn owner(&self) -> io::Result<(u32, u32)> {
        let meta = self.file.metadata()?;
        Ok((meta.uid(), meta.gid()))
    }

    pub fn set_mode(&self, mode: u32) -> io::Result<()> {
        self.file
            .set_permissions(std::fs::Permissions::from_mode(mode))
    }

    pub fn set_owner(&self, uid: u32, gid: u32) -> io::Result<()> {
        set_owner(&self.file, uid, gid)
    }

    /// Relabel this directory to the given SELinux context. Callers use it
    /// to give a freshly created transaction directory the dedicated type its
    /// consumer expects instead of the label inherited from the parent tree.
    pub fn set_selinux_context(&self, context: &str) -> io::Result<()> {
        set_selinux_context(&self.file, context)
    }

    pub fn validate_owner_mode(&self, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
        let meta = self.file.metadata()?;
        if meta.uid() != uid || meta.gid() != gid {
            return Err(invalid_data("directory has unexpected owner"));
        }
        if meta.permissions().mode() & 0o777 != mode {
            return Err(invalid_data("directory has unexpected mode"));
        }
        Ok(())
    }

    pub fn validate_owner_not_writable(&self, uid: u32, gid: u32) -> io::Result<()> {
        let meta = self.file.metadata()?;
        if meta.uid() != uid || meta.gid() != gid {
            return Err(invalid_data("directory has unexpected owner"));
        }
        if meta.permissions().mode() & WRITE_BITS != 0 {
            return Err(invalid_data("directory is group/world writable"));
        }
        Ok(())
    }

    pub fn read_untrusted(&self, name: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
        let owner = self.owner()?;
        self.read_untrusted_owned_with(name, max_bytes, owner, || {})
    }

    pub fn read_untrusted_owned(
        &self,
        name: &str,
        max_bytes: usize,
        owner: (u32, u32),
    ) -> io::Result<Vec<u8>> {
        self.read_untrusted_owned_with(name, max_bytes, owner, || {})
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn read_untrusted_with<F>(
        &self,
        name: &str,
        max_bytes: usize,
        after_read: F,
    ) -> io::Result<Vec<u8>>
    where
        F: FnOnce(),
    {
        let owner = self.owner()?;
        self.read_untrusted_owned_with(name, max_bytes, owner, after_read)
    }

    fn read_untrusted_owned_with<F>(
        &self,
        name: &str,
        max_bytes: usize,
        owner: (u32, u32),
        after_read: F,
    ) -> io::Result<Vec<u8>>
    where
        F: FnOnce(),
    {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let before = file.metadata()?;
        validate_untrusted(&before, owner.0, owner.1, max_bytes)?;

        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes || bytes.len() as u64 != before.len() {
            return Err(invalid_data("staged file size changed while reading"));
        }

        after_read();
        let after = file.metadata()?;
        if FileStamp::from(&before) != FileStamp::from(&after) {
            return Err(invalid_data("staged file metadata changed while reading"));
        }

        Ok(bytes)
    }

    pub fn create_new(&self, name: &OsStr, mode: u32) -> io::Result<File> {
        let name = c_name(name)?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub fn prepare_trusted(&self, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
        self.prepare_trusted_with_context(name, bytes, mode, None, false)
    }

    pub fn prepare_trusted_labeled(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        expected_selinux_context: &str,
    ) -> io::Result<()> {
        self.prepare_trusted_with_context(name, bytes, mode, Some(expected_selinux_context), false)
    }

    /// Create a fresh inode whose label must be supplied by policy transition.
    /// Never relabel it: a wrong transition fails closed before publication.
    pub fn prepare_trusted_with_existing_label(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        expected: &str,
    ) -> io::Result<()> {
        self.prepare_trusted_with_context(name, bytes, mode, Some(expected), true)
    }

    fn prepare_trusted_with_context(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        expected_selinux_context: Option<&str>,
        verify_only: bool,
    ) -> io::Result<()> {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        match self.entry_metadata(name) {
            Ok(meta) => {
                validate_trusted(&meta, uid, gid, None)?;
                self.unlink(name)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }

        let mut file = self.create_new(OsStr::new(name), 0o600)?;
        let result = (|| {
            file.write_all(bytes)?;
            set_owner(&file, uid, gid)?;
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            if let Some(context) = expected_selinux_context {
                if !verify_only {
                    set_selinux_context(&file, context)?;
                }
            }
            file.sync_all()?;
            validate_trusted(&file.metadata()?, uid, gid, Some(mode))?;
            if let Some(context) = expected_selinux_context {
                validate_selinux_context(&file, context)?;
            }
            file.seek(SeekFrom::Start(0))?;
            let mut offset = 0usize;
            let mut chunk = [0u8; 64 * 1024];
            while offset < bytes.len() {
                let wanted = std::cmp::min(chunk.len(), bytes.len() - offset);
                file.read_exact(&mut chunk[..wanted])?;
                if chunk[..wanted] != bytes[offset..offset + wanted] {
                    return Err(invalid_data("trusted temp differs after write"));
                }
                offset += wanted;
            }
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 {
                return Err(invalid_data("trusted temp has trailing bytes"));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = self.unlink(name);
        }
        result
    }

    pub fn write_atomic(&self, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
        self.write_atomic_with(name, bytes, mode, || Ok(()))
    }

    /// Stream one retained untrusted descriptor into a fresh trusted inode.
    /// At most one 64 KiB body chunk is resident and the source identity is
    /// checked before and after the complete copy.
    pub fn write_atomic_from_descriptor(
        &self,
        name: &str,
        source_fd: i32,
        expected_size: u64,
        expected_sha256: &str,
        mode: u32,
    ) -> io::Result<()> {
        c_name(OsStr::new(name))?;
        let duplicate = unsafe { libc::fcntl(source_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let source = unsafe { File::from_raw_fd(duplicate) };
        let before = source.metadata()?;
        if !before.is_file() || before.nlink() != 1 || before.len() != expected_size {
            return Err(invalid_data("source descriptor identity is unsafe"));
        }
        let source_stamp = FileStamp::from(&before);
        let temp = format!(".{name}.tmp");
        match self.entry_metadata(&temp) {
            Ok(metadata) => {
                validate_trusted(
                    &metadata,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    None,
                )?;
                self.unlink(&temp)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut destination = self.create_new(OsStr::new(&temp), 0o600)?;
        let result = (|| {
            let mut offset = 0_u64;
            let mut chunk = [0_u8; 64 * 1024];
            let mut source_hash = Sha256::new();
            while offset < expected_size {
                let wanted = usize::try_from((expected_size - offset).min(chunk.len() as u64))
                    .map_err(|_| invalid_data("source descriptor chunk size overflows"))?;
                let read = source.read_at(&mut chunk[..wanted], offset)?;
                if read == 0 {
                    return Err(invalid_data("source descriptor ended before declared size"));
                }
                destination.write_all(&chunk[..read])?;
                source_hash.update(&chunk[..read]);
                offset = offset
                    .checked_add(read as u64)
                    .ok_or_else(|| invalid_data("source descriptor offset overflow"))?;
            }
            if source.read_at(&mut chunk[..1], expected_size)? != 0 {
                return Err(invalid_data("source descriptor exceeds declared size"));
            }
            if hex::encode(source_hash.finalize()) != expected_sha256 {
                return Err(invalid_data("source descriptor digest differs"));
            }
            if FileStamp::from(&source.metadata()?) != source_stamp {
                return Err(invalid_data("source descriptor changed during copy"));
            }
            set_owner(&destination, unsafe { libc::geteuid() }, unsafe {
                libc::getegid()
            })?;
            destination.set_permissions(std::fs::Permissions::from_mode(mode))?;
            destination.sync_all()?;
            validate_trusted(
                &destination.metadata()?,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                Some(mode),
            )?;
            verify_file_digest(&destination, expected_size, expected_sha256)?;
            self.rename(&temp, name)?;
            self.sync_all()
        })();
        if result.is_err() {
            let _ = self.unlink(&temp);
        }
        result
    }

    pub fn verify_trusted_digest(
        &self,
        name: &str,
        expected_size: u64,
        expected_sha256: &str,
        mode: u32,
    ) -> io::Result<()> {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let before = file.metadata()?;
        validate_trusted(
            &before,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            Some(mode),
        )?;
        if before.len() != expected_size {
            return Err(invalid_data("trusted file size differs"));
        }
        verify_file_digest(&file, expected_size, expected_sha256)?;
        if FileStamp::from(&file.metadata()?) != FileStamp::from(&before) {
            return Err(invalid_data(
                "trusted file changed during digest verification",
            ));
        }
        Ok(())
    }

    pub fn open_trusted_file(&self, name: &str, expected_size: u64, mode: u32) -> io::Result<File> {
        self.open_trusted_file_with_access(name, expected_size, mode, libc::O_RDONLY)
    }

    /// Open a read-only trusted inode and require its exact policy-assigned label.
    pub fn open_trusted_labeled_file(
        &self,
        name: &str,
        expected_size: u64,
        mode: u32,
        expected_context: &str,
    ) -> io::Result<File> {
        let file = self.open_trusted_file(name, expected_size, mode)?;
        validate_selinux_context(&file, expected_context)?;
        Ok(file)
    }

    /// Open an existing trusted inode without create, truncate or append access.
    pub fn open_trusted_readwrite_file(
        &self,
        name: &str,
        expected_size: u64,
        mode: u32,
    ) -> io::Result<File> {
        self.open_trusted_file_with_access(name, expected_size, mode, libc::O_RDWR)
    }

    fn open_trusted_file_with_access(
        &self,
        name: &str,
        expected_size: u64,
        mode: u32,
        access: i32,
    ) -> io::Result<File> {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        validate_trusted(
            &metadata,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            Some(mode),
        )?;
        if metadata.len() != expected_size {
            return Err(invalid_data("trusted file size differs"));
        }
        Ok(file)
    }

    pub fn write_atomic_with<F>(
        &self,
        name: &str,
        bytes: &[u8],
        mode: u32,
        before_rename: F,
    ) -> io::Result<()>
    where
        F: FnOnce() -> io::Result<()>,
    {
        let temp = format!(".{name}.tmp");
        self.prepare_trusted(&temp, bytes, mode)?;
        if let Err(error) = before_rename() {
            let _ = self.unlink(&temp);
            return Err(error);
        }
        self.rename(&temp, name)?;
        self.sync_all()
    }

    pub fn read_trusted(&self, name: &str, max_bytes: usize, mode: u32) -> io::Result<Vec<u8>> {
        self.read_trusted_with_mode(name, max_bytes, Some(mode))
    }

    /// Read one verified publication and retain the descriptor that supplied
    /// its bytes. Keeping a replaced publication open prevents inode reuse.
    pub fn read_trusted_retained(
        &self,
        name: &str,
        max_bytes: usize,
        mode: u32,
    ) -> io::Result<(Vec<u8>, File)> {
        self.read_trusted_retained_with_mode_and(name, max_bytes, Some(mode), || {})
    }

    pub fn read_trusted_snapshot(
        &self,
        name: &str,
        max_bytes: usize,
        mode: u32,
        expected_selinux_context: &str,
    ) -> io::Result<TrustedSnapshot> {
        self.read_trusted_snapshot_inner(name, max_bytes, mode, Some(expected_selinux_context))
    }

    /// Same owner/mode/link/size identity contract as
    /// [`Self::read_trusted_snapshot`], but the SELinux context only needs to
    /// exist and stay bounded. Explicit uninstall admission uses this degraded
    /// read when a damaged-but-root-owned inventory no longer carries the
    /// compile-time label; deletion authority never depends on the health of
    /// the removed installation.
    pub fn read_trusted_snapshot_any_context(
        &self,
        name: &str,
        max_bytes: usize,
        mode: u32,
    ) -> io::Result<TrustedSnapshot> {
        self.read_trusted_snapshot_inner(name, max_bytes, mode, None)
    }

    fn read_trusted_snapshot_inner(
        &self,
        name: &str,
        max_bytes: usize,
        mode: u32,
        expected_selinux_context: Option<&str>,
    ) -> io::Result<TrustedSnapshot> {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let before = file.metadata()?;
        validate_trusted(&before, uid, gid, Some(mode))?;
        if before.len() as usize > max_bytes {
            return Err(invalid_data("trusted file exceeds size bound"));
        }
        validate_selinux(&file, expected_selinux_context)?;
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut file)
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes || bytes.len() as u64 != before.len() {
            return Err(invalid_data("trusted file size changed while reading"));
        }
        let after = file.metadata()?;
        let before_stamp = FileStamp::from(&before);
        if before_stamp != FileStamp::from(&after) {
            return Err(invalid_data("trusted file metadata changed while reading"));
        }
        validate_selinux(&file, expected_selinux_context)?;
        Ok(TrustedSnapshot {
            bytes,
            stamp: before_stamp,
        })
    }

    pub fn read_trusted_bounded(&self, name: &str, max_bytes: usize) -> io::Result<Vec<u8>> {
        self.read_trusted_with_mode(name, max_bytes, None)
    }

    fn read_trusted_with_mode(
        &self,
        name: &str,
        max_bytes: usize,
        mode: Option<u32>,
    ) -> io::Result<Vec<u8>> {
        self.read_trusted_with_mode_and(name, max_bytes, mode, || {})
    }

    fn read_trusted_with_mode_and<F>(
        &self,
        name: &str,
        max_bytes: usize,
        mode: Option<u32>,
        after_read: F,
    ) -> io::Result<Vec<u8>>
    where
        F: FnOnce(),
    {
        self.read_trusted_retained_with_mode_and(name, max_bytes, mode, after_read)
            .map(|(bytes, _file)| bytes)
    }

    fn read_trusted_retained_with_mode_and<F>(
        &self,
        name: &str,
        max_bytes: usize,
        mode: Option<u32>,
        after_read: F,
    ) -> io::Result<(Vec<u8>, File)>
    where
        F: FnOnce(),
    {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let meta = file.metadata()?;
        validate_trusted(&meta, uid, gid, mode)?;
        if meta.len() as usize > max_bytes {
            return Err(invalid_data("trusted file exceeds size bound"));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        (&mut file)
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes || bytes.len() as u64 != meta.len() {
            return Err(invalid_data("trusted file size changed while reading"));
        }
        after_read();
        let after = file.metadata()?;
        if FileStamp::from(&meta) != FileStamp::from(&after) {
            return Err(invalid_data("trusted file metadata changed while reading"));
        }
        Ok((bytes, file))
    }

    pub fn validate_activation_names(
        &self,
        temp: &str,
        active: &str,
        previous: &str,
        mode: u32,
    ) -> io::Result<()> {
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        validate_trusted(&self.entry_metadata(temp)?, uid, gid, Some(mode))?;
        self.validate_optional_trusted(active, uid, gid)?;
        self.validate_optional_trusted(previous, uid, gid)
    }

    pub fn activate(
        &self,
        temp: &str,
        active: &str,
        previous: &str,
        mode: u32,
    ) -> io::Result<Activation> {
        self.validate_activation_names(temp, active, previous, mode)?;
        let had_previous = self.entry_exists(active)?;
        let activation = Activation {
            dir: self.try_clone()?,
            active: active.to_string(),
            previous: previous.to_string(),
            had_previous,
        };
        if had_previous {
            self.rename(active, previous)?;
        }
        if let Err(e) = self.rename(temp, active) {
            if had_previous {
                let _ = self.rename(previous, active);
            }
            return Err(e);
        }
        if let Err(e) = self.sync_all() {
            let _ = activation.rollback();
            return Err(e);
        }

        Ok(activation)
    }

    pub fn replace(&self, temp: &str, active: &str) -> io::Result<()> {
        self.rename(temp, active)?;
        // Status is transient and its canonical contract makes directory fsync
        // best-effort. Rollback-sensitive activation uses `activate` instead.
        let _ = self.sync_all();
        Ok(())
    }

    /// Atomically give the retained file `existing` the additional name
    /// `published` WITHOUT replacing anything: the link is created with
    /// `linkat` and fails with `EEXIST` (never silently replacing) if the
    /// target name is already taken. `existing` keeps its name, so the
    /// publisher decides when (and whether) to drop it afterwards.
    pub fn publish_no_replace(&self, existing: &str, published: &str) -> io::Result<()> {
        // The existing name must be a trusted regular file; validate up front
        // so the hard link can never pin a symlink or a foreign inode under a
        // second name.
        self.metadata_trusted(existing, 0o600)?;
        let existing = c_name(OsStr::new(existing))?;
        let published = c_name(OsStr::new(published))?;
        let result = unsafe {
            libc::linkat(
                self.file.as_raw_fd(),
                existing.as_ptr(),
                self.file.as_raw_fd(),
                published.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        cvt(result)?;
        self.sync_all()
    }

    /// Roll back only the exact two-name publication pair after interrupted
    /// rotation. Caller holds the directory transaction lock and supplies an
    /// allowlisted completed name. Ordinary trusted reads remain single-link.
    pub fn rollback_interrupted_publication(
        &self,
        active: &str,
        published: &str,
        maximum: u64,
    ) -> io::Result<bool> {
        self.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        let core = published
            .strip_prefix("segment-")
            .and_then(|s| s.strip_suffix(".jsonl"));
        let valid = core.is_some_and(|s| {
            let parts: Vec<_> = s.split('-').collect();
            (parts.len() == 1 || parts.len() == 2)
                && parts
                    .iter()
                    .all(|p| p.len() == 20 && p.bytes().all(|b| b.is_ascii_digit()))
        });
        if active != "segment-active.jsonl" || !valid {
            return Err(invalid_data("invalid interrupted publication names"));
        }
        let open = |name: &str| -> io::Result<File> {
            let name = c_name(OsStr::new(name))?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        };
        let active_file = match open(active) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let a = active_file.metadata()?;
        if a.nlink() == 1 {
            return Ok(false);
        }
        let published_file = open(published)?;
        let b = published_file.metadata()?;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return Ok(false);
        }
        if !a.is_file()
            || a.nlink() != 2
            || a.uid() != unsafe { libc::geteuid() }
            || a.gid() != unsafe { libc::getegid() }
            || a.mode() & 0o7777 != 0o600
            || a.len() > maximum
        {
            return Err(invalid_data("invalid interrupted publication pair"));
        }
        let expected = FileStamp::from(&a);
        if FileStamp::from(&b) != expected
            || FileStamp::from(&open(active)?.metadata()?) != expected
            || FileStamp::from(&open(published)?.metadata()?) != expected
        {
            return Err(invalid_data("interrupted publication pair changed"));
        }
        self.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        self.unlink(published)?;
        self.sync_all()?;
        validate_trusted(
            &active_file.metadata()?,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            Some(0o600),
        )?;
        Ok(true)
    }

    /// Durably truncate a trusted file to a shorter length. The file must be a
    /// regular trusted file with the expected mode; fsync makes the shortened
    /// length recoverable before the caller proceeds.
    pub fn truncate_trusted(&self, name: &str, length: u64, mode: u32) -> io::Result<()> {
        let name = c_name(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let before = file.metadata()?;
        validate_trusted(
            &before,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            Some(mode),
        )?;
        if before.len() < length {
            return Err(invalid_data("trusted truncate would extend the file"));
        }
        file.set_len(length)?;
        file.sync_all()?;
        let after = file.metadata()?;
        validate_trusted(
            &after,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            Some(mode),
        )?;
        if after.dev() != before.dev() || after.ino() != before.ino() || after.len() != length {
            return Err(invalid_data("trusted entry changed during truncation"));
        }
        Ok(())
    }

    pub fn rename(&self, old: &str, new: &str) -> io::Result<()> {
        let old = c_name(OsStr::new(old))?;
        let new = c_name(OsStr::new(new))?;
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                old.as_ptr(),
                self.file.as_raw_fd(),
                new.as_ptr(),
            )
        };
        cvt(result)
    }

    /// Atomically move one entry between two already-open directories on the
    /// same filesystem, then durably publish both directory updates.
    pub fn rename_to(&self, old: &str, destination: &Directory, new: &str) -> io::Result<()> {
        let old = c_name(OsStr::new(old))?;
        let new = c_name(OsStr::new(new))?;
        let result = unsafe {
            libc::renameat(
                self.file.as_raw_fd(),
                old.as_ptr(),
                destination.file.as_raw_fd(),
                new.as_ptr(),
            )
        };
        cvt(result)?;
        destination.sync_all()?;
        self.sync_all()
    }

    /// Exchange two directory entries atomically; there is no rename fallback.
    /// Both retained entries remain present even after a process interruption.
    #[cfg(test)]
    pub fn exchange_to(&self, old: &str, destination: &Directory, new: &str) -> io::Result<()> {
        for directory in [self, destination] {
            directory.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe {
                libc::getegid()
            })?;
        }
        for (directory, name) in [(self, old), (destination, new)] {
            let entry = directory.open_child(name)?;
            entry.validate_owner_not_writable(unsafe { libc::geteuid() }, unsafe {
                libc::getegid()
            })?;
        }
        let old = c_name(OsStr::new(old))?;
        let new = c_name(OsStr::new(new))?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.file.as_raw_fd(),
                old.as_ptr(),
                destination.file.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_EXCHANGE,
            ) as i32
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                self.file.as_raw_fd(),
                old.as_ptr(),
                destination.file.as_raw_fd(),
                new.as_ptr(),
                libc::RENAME_SWAP,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic directory exchange unavailable",
        ));
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        {
            cvt(result)?;
            destination.sync_all()?;
            self.sync_all()
        }
    }

    pub fn unlink(&self, name: &str) -> io::Result<()> {
        let name = c_name(OsStr::new(name))?;
        let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
        cvt(result)
    }

    pub fn remove_child_dir(&self, name: &str) -> io::Result<()> {
        let name = c_name(OsStr::new(name))?;
        let result =
            unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
        cvt(result)
    }

    pub fn entry_exists(&self, name: &str) -> io::Result<bool> {
        match self.entry_metadata(name) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn validate_optional_trusted(&self, name: &str, uid: u32, gid: u32) -> io::Result<()> {
        match self.entry_metadata(name) {
            Ok(meta) => validate_trusted(&meta, uid, gid, None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn entry_metadata(&self, name: &str) -> io::Result<Metadata> {
        let name = c_name(OsStr::new(name))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return metadata_from_stat(stat);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        file.metadata()
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
        })
    }
}

pub struct Activation {
    dir: Directory,
    active: String,
    previous: String,
    had_previous: bool,
}

impl Activation {
    pub fn rollback(&self) -> io::Result<()> {
        if self.had_previous {
            self.dir.rename(&self.previous, &self.active)?;
        } else if self.dir.entry_exists(&self.active)? {
            self.dir.unlink(&self.active)?;
        }
        self.dir.sync_all()
    }

    pub fn discard_previous(&self) -> io::Result<()> {
        if self.had_previous && self.dir.entry_exists(&self.previous)? {
            self.dir.unlink(&self.previous)?;
            self.dir.sync_all()?;
        }
        Ok(())
    }
}

pub fn set_owner(file: &File, uid: u32, gid: u32) -> io::Result<()> {
    let meta = file.metadata()?;
    if meta.uid() == uid && meta.gid() == gid {
        return Ok(());
    }
    let result = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
    cvt(result)
}

fn from_dir_fd(fd: libc::c_int) -> io::Result<Directory> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.file_type().is_dir() {
        return Err(invalid_data("opened object is not a directory"));
    }
    Ok(Directory { file })
}

fn validate_untrusted(meta: &Metadata, uid: u32, gid: u32, max: usize) -> io::Result<()> {
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err(invalid_data(
            "staged input is not a single-link regular file",
        ));
    }
    if meta.uid() != uid || meta.gid() != gid {
        return Err(invalid_data(
            "staged input owner differs from staging directory",
        ));
    }
    if meta.mode() & WRITE_BITS != 0 {
        return Err(invalid_data("staged input is group/world writable"));
    }
    if meta.len() as usize > max {
        return Err(invalid_data("staged input exceeds size bound"));
    }
    Ok(())
}

fn validate_trusted(meta: &Metadata, uid: u32, gid: u32, mode: Option<u32>) -> io::Result<()> {
    if !meta.file_type().is_file() || meta.nlink() != 1 {
        return Err(invalid_data(
            "trusted entry is not a single-link regular file",
        ));
    }
    if meta.uid() != uid || meta.gid() != gid {
        return Err(invalid_data("trusted entry has unexpected owner"));
    }
    if let Some(mode) = mode {
        if meta.permissions().mode() & 0o777 != mode {
            return Err(invalid_data("trusted entry has unexpected mode"));
        }
    } else if meta.mode() & WRITE_BITS != 0 {
        return Err(invalid_data("trusted entry is group/world writable"));
    }
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct FileStamp {
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

fn verify_file_digest(file: &File, expected_size: u64, expected_sha256: &str) -> io::Result<()> {
    let mut offset = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    let mut digest = Sha256::new();
    while offset < expected_size {
        let wanted = usize::try_from((expected_size - offset).min(chunk.len() as u64))
            .map_err(|_| invalid_data("trusted digest chunk size overflows"))?;
        let read = file.read_at(&mut chunk[..wanted], offset)?;
        if read == 0 {
            return Err(invalid_data("trusted file ended before declared size"));
        }
        digest.update(&chunk[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| invalid_data("trusted digest offset overflow"))?;
    }
    if file.read_at(&mut chunk[..1], expected_size)? != 0 {
        return Err(invalid_data("trusted file exceeds declared size"));
    }
    if hex::encode(digest.finalize()) != expected_sha256 {
        return Err(invalid_data("trusted file digest differs"));
    }
    Ok(())
}

/// The exact strict-context mismatch message. Callers that intentionally
/// degrade admission for explicit uninstall match this message only.
pub const SELINUX_CONTEXT_MISMATCH_MESSAGE: &str = "trusted file has unexpected SELinux context";

#[cfg(target_os = "android")]
fn validate_selinux(file: &File, expected: Option<&str>) -> io::Result<()> {
    match expected {
        Some(expected) => validate_selinux_context(file, expected),
        None => validate_selinux_context_bounded(file),
    }
}

#[cfg(not(target_os = "android"))]
fn validate_selinux(_file: &File, _expected: Option<&str>) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "android")]
fn validate_selinux_context_bounded(file: &File) -> io::Result<()> {
    let name = b"security.selinux\0";
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 || size > 256 {
        return Err(invalid_data("trusted file has no bounded SELinux context"));
    }
    Ok(())
}

#[cfg(target_os = "android")]
fn validate_selinux_context(file: &File, expected: &str) -> io::Result<()> {
    let name = b"security.selinux\0";
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 || size > 256 {
        return Err(invalid_data("trusted file has no bounded SELinux context"));
    }
    let mut value = vec![0u8; size as usize];
    let read = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read != size {
        return Err(invalid_data("trusted file SELinux context changed"));
    }
    while value.last() == Some(&0) {
        value.pop();
    }
    if value != expected.as_bytes() {
        return Err(invalid_data(SELINUX_CONTEXT_MISMATCH_MESSAGE));
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn validate_selinux_context(_file: &File, _expected: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(target_os = "android")]
fn set_selinux_context(file: &File, context: &str) -> io::Result<()> {
    let name = b"security.selinux\0";
    let mut value = context.as_bytes().to_vec();
    value.push(0);
    let result = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "android"))]
fn set_selinux_context(_file: &File, _context: &str) -> io::Result<()> {
    Ok(())
}

impl From<&Metadata> for FileStamp {
    fn from(meta: &Metadata) -> Self {
        Self {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            links: meta.nlink(),
            uid: meta.uid(),
            gid: meta.gid(),
            mode: meta.mode(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
        }
    }
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn c_name(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry name must be one path component",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry name contains NUL"))
}

fn cvt(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn metadata_from_stat(_stat: libc::stat) -> io::Result<Metadata> {
    Err(invalid_data(
        "entry cannot be opened without following links",
    ))
}

/// Atomic write of a root-owned private file: O_NOFOLLOW + O_EXCL tmp in the
/// same directory, fixed mode (umask-independent), fsync, rename and mandatory
/// parent fsync. O_EXCL matches the discipline of `prepare_trusted`: a stale
/// temp left by a prior crash cannot be silently overwritten — if one is
/// present it is unlinked and the create is retried once, so a torn temp never
/// substitutes for fresh content.
pub fn write_atomic_private(path: &std::path::Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;
    let dir = Directory::open(parent)?;
    dir.write_atomic(name, bytes, mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;

    #[test]
    fn existing_label_publication_preserves_trusted_readback_and_rejects_links() {
        let root = tempdir().unwrap();
        let dir = Directory::open(root.path()).unwrap();
        let name = ".reply.tmp";
        dir.prepare_trusted_with_existing_label(name, b"result", 0o600, "test-context")
            .unwrap();
        let snapshot = dir
            .read_trusted_snapshot(name, 100, 0o600, "test-context")
            .unwrap();
        assert_eq!(snapshot.bytes, b"result");
        std::fs::remove_file(root.path().join(name)).unwrap();
        std::fs::write(root.path().join("foreign"), b"foreign").unwrap();
        std::os::unix::fs::symlink(root.path().join("foreign"), root.path().join(name)).unwrap();
        assert!(dir
            .prepare_trusted_with_existing_label(name, b"result", 0o600, "test-context")
            .is_err());
        assert_eq!(
            std::fs::read(root.path().join("foreign")).unwrap(),
            b"foreign"
        );
    }

    #[test]
    fn directory_exchange_retains_both_inodes_and_open_descriptors() {
        let root = tempdir().unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let active = directory.create_private_child("active").unwrap();
        let recovery = directory.create_private_child("recovery").unwrap();
        let replacement = recovery.create_private_child("replacement").unwrap();
        active.write_atomic("payload", b"old", 0o600).unwrap();
        replacement.write_atomic("payload", b"new", 0o600).unwrap();
        let old_inode = fs::metadata(root.path().join("active")).unwrap().ino();
        let new_inode = fs::metadata(root.path().join("recovery/replacement"))
            .unwrap()
            .ino();
        directory
            .exchange_to("active", &recovery, "replacement")
            .unwrap();
        assert_eq!(
            fs::metadata(root.path().join("active")).unwrap().ino(),
            new_inode
        );
        assert_eq!(
            fs::metadata(root.path().join("recovery/replacement"))
                .unwrap()
                .ino(),
            old_inode
        );
        assert_eq!(active.read_trusted("payload", 3, 0o600).unwrap(), b"old");
        assert_eq!(
            replacement.read_trusted("payload", 3, 0o600).unwrap(),
            b"new"
        );
        assert_eq!(
            directory
                .open_child("active")
                .unwrap()
                .read_trusted("payload", 3, 0o600)
                .unwrap(),
            b"new"
        );
    }

    #[test]
    fn directory_exchange_rejects_symlinks_and_missing_entries_without_moving() {
        let root = tempdir().unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let active = directory.create_private_child("active").unwrap();
        active.write_atomic("payload", b"old", 0o600).unwrap();
        symlink(root.path().join("active"), root.path().join("alias")).unwrap();
        assert!(directory
            .exchange_to("active", &directory, "alias")
            .is_err());
        assert!(directory
            .exchange_to("active", &directory, "missing")
            .is_err());
        assert_eq!(
            directory
                .open_child("active")
                .unwrap()
                .read_trusted("payload", 3, 0o600)
                .unwrap(),
            b"old"
        );
        assert!(fs::symlink_metadata(root.path().join("alias"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn trusted_readwrite_open_preserves_bytes_and_omits_append() {
        let root = tempdir().unwrap();
        let dir = Directory::open(root.path()).unwrap();
        dir.write_atomic("lease", b"sentinel", 0o600).unwrap();
        let before = fs::metadata(root.path().join("lease")).unwrap();
        let file = dir.open_trusted_readwrite_file("lease", 8, 0o600).unwrap();
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
        assert_eq!(flags & libc::O_APPEND, 0);
        assert_ne!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let readonly = dir.open_trusted_file("lease", 8, 0o600).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(readonly.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
        drop(file);
        assert_eq!(fs::read(root.path().join("lease")).unwrap(), b"sentinel");
        let after = fs::metadata(root.path().join("lease")).unwrap();
        assert_eq!(
            (before.ino(), before.len(), before.mode()),
            (after.ino(), after.len(), after.mode())
        );
        assert!(dir
            .open_trusted_readwrite_file("missing", 0, 0o600)
            .is_err());
        assert!(!root.path().join("missing").exists());
        assert!(dir.open_trusted_readwrite_file("lease", 7, 0o600).is_err());
        assert!(dir.open_trusted_readwrite_file("lease", 8, 0o644).is_err());
        symlink(root.path().join("lease"), root.path().join("alias")).unwrap();
        assert!(dir.open_trusted_readwrite_file("alias", 8, 0o600).is_err());
    }

    #[test]
    fn repeated_directory_enumeration_has_an_independent_offset() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("first"), b"1").unwrap();
        fs::write(root.path().join("second"), b"2").unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let mut first = directory.entry_names_bounded(2).unwrap();
        let mut second = directory.entry_names_bounded(2).unwrap();
        first.sort();
        second.sort();
        assert_eq!(first, vec!["first", "second"]);
        assert_eq!(second, first);
    }

    #[test]
    fn untrusted_read_rejects_symlink_and_hard_link() {
        let root = tempdir().unwrap();
        let dir = Directory::open(root.path()).unwrap();
        fs::write(root.path().join("target"), b"bytes").unwrap();
        symlink(root.path().join("target"), root.path().join("link")).unwrap();
        fs::hard_link(root.path().join("target"), root.path().join("hard")).unwrap();

        assert!(dir.read_untrusted("link", 16).is_err());
        assert!(dir.read_untrusted("hard", 16).is_err());
    }

    #[test]
    fn untrusted_read_detects_descriptor_mutation() {
        let root = tempdir().unwrap();
        let path = root.path().join("input");
        fs::write(&path, b"before").unwrap();
        let dir = Directory::open(root.path()).unwrap();

        let result = dir.read_untrusted_with("input", 16, || {
            fs::write(&path, b"after!").unwrap();
        });

        assert!(result.is_err());
    }

    #[test]
    fn trusted_read_detects_descriptor_mutation() {
        let root = tempdir().unwrap();
        let path = root.path().join("input");
        fs::write(&path, b"before").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let dir = Directory::open(root.path()).unwrap();

        let result = dir.read_trusted_with_mode_and("input", 16, Some(0o600), || {
            fs::write(&path, b"after!").unwrap();
        });

        assert!(result.is_err());
    }

    #[test]
    fn untrusted_read_rejects_owner_and_writable_mode() {
        let root = tempdir().unwrap();
        let path = root.path().join("input");
        fs::write(&path, b"bytes").unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert!(validate_untrusted(&meta, meta.uid().wrapping_add(1), meta.gid(), 16).is_err());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let dir = Directory::open(root.path()).unwrap();
        assert!(dir.read_untrusted("input", 16).is_err());
    }

    #[test]
    fn trusted_prepare_refuses_symlink_temp() {
        let root = tempdir().unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        symlink(&victim, root.path().join("temp")).unwrap();
        let dir = Directory::open(root.path()).unwrap();

        assert!(dir.prepare_trusted("temp", b"new", 0o600).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
    }

    #[test]
    fn trusted_activation_rolls_back_previous_inode() {
        let root = tempdir().unwrap();
        let active = root.path().join("active");
        fs::write(&active, b"old").unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        let dir = Directory::open(root.path()).unwrap();
        dir.prepare_trusted("temp", b"new", 0o600).unwrap();

        let activation = dir.activate("temp", "active", "previous", 0o600).unwrap();
        assert_eq!(fs::read(&active).unwrap(), b"new");
        assert_eq!(fs::read(root.path().join("previous")).unwrap(), b"old");

        activation.rollback().unwrap();
        assert_eq!(fs::read(&active).unwrap(), b"old");
    }

    #[test]
    fn write_atomic_private_replaces_stale_temp_without_truncating() {
        // A stale .<name>.tmp left by a prior crash must not be silently
        // truncated in place (which could leave torn content). It is unlinked
        // and a fresh O_EXCL temp is created, so the final file is atomic.
        let root = tempdir().unwrap();
        let target = root.path().join("state.json");
        let temp = root.path().join(".state.json.tmp");
        fs::write(&temp, b"stale-torn-bytes").unwrap();

        write_atomic_private(&target, b"fresh", 0o600).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"fresh");
        // The stale temp is gone (renamed into place as `target`).
        assert!(!temp.exists());
    }
}
