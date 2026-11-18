use crate::Result;
use alloc::{ffi::CString, format, string::String, vec, vec::Vec};
pub struct Fd(pub i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}
fn c(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| "embedded path NUL".into())
}
fn error(stage: &str) -> String {
    format!("native filesystem {stage} failed")
}
pub(crate) fn errno() -> i32 {
    #[cfg(target_os = "nto")]
    unsafe {
        *libc::__get_errno_ptr()
    }
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error()
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location()
    }
}
pub fn read_exact(fd: i32, mut bytes: &mut [u8]) -> Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len()) };
        if n <= 0 {
            return Err(error("read"));
        }
        bytes = &mut bytes[n as usize..];
    }
    Ok(())
}
pub fn write_all(fd: i32, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n <= 0 {
            return Err(error("write"));
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}
pub fn stat(fd: i32) -> Result<libc::stat> {
    let mut s = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut s) } != 0 {
        return Err(error("fstat"));
    }
    Ok(s)
}
pub fn uid() -> Result<u32> {
    #[cfg(target_os = "nto")]
    {
        u32::try_from(unsafe { libc::geteuid() }).map_err(|_| "negative native UID".into())
    }
    #[cfg(not(target_os = "nto"))]
    {
        Ok(unsafe { libc::geteuid() })
    }
}
fn owner(s: &libc::stat) -> Option<u32> {
    #[cfg(target_os = "nto")]
    {
        u32::try_from(s.st_uid).ok()
    }
    #[cfg(not(target_os = "nto"))]
    {
        Some(s.st_uid)
    }
}
pub fn unchanged(a: &libc::stat, b: &libc::stat) -> bool {
    #[cfg(target_os = "nto")]
    let time = a.st_mtim.tv_sec == b.st_mtim.tv_sec
        && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
        && a.st_ctim.tv_sec == b.st_ctim.tv_sec
        && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
    #[cfg(not(target_os = "nto"))]
    let time = a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec;
    time && a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_size == b.st_size
        && a.st_nlink == b.st_nlink
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
}
pub struct Dir {
    pub fd: Fd,
    pub path: String,
    pub owner: u32,
    private: bool,
    paths: bool,
    probe_write: bool,
    #[cfg(target_os = "nto")]
    oem_var: Option<OemVarMount>,
}
fn identity(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
}
fn lstat(path: &str) -> Result<libc::stat> {
    let mut s = unsafe { core::mem::zeroed() };
    if unsafe { libc::lstat(c(path)?.as_ptr(), &mut s) } != 0 {
        return Err(error("lstat"));
    }
    Ok(s)
}
// OEM /var is group-0 writable. This contract trusts those OEM principals;
// it does not make the parent root-exclusive. Never apply it to arbitrary paths.
#[cfg(any(target_os = "nto", test))]
#[allow(clippy::too_many_arguments)]
fn oem_var_policy(
    path: &str,
    uid: u64,
    gid: u64,
    mode: u32,
    separate: bool,
    qnx6: bool,
    var_ro: bool,
) -> bool {
    path == "/var"
        && uid == 0
        && gid == 0
        && mode == (libc::S_IFDIR as u32 | 0o775)
        && separate
        && qnx6
        && !var_ro
}
#[cfg(target_os = "nto")]
#[derive(Clone, Copy, PartialEq)]
struct OemVarMount {
    dev: u64,
    ino: u64,
    fsid: u64,
    flags: u64,
}
#[cfg(target_os = "nto")]
fn oem_var_mount() -> Result<OemVarMount> {
    let open = |path: &str| -> Result<Fd> {
        let fd = Fd(unsafe {
            libc::open(
                c(path)?.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        });
        if fd.0 < 0 {
            return Err(error("OEM parent open"));
        }
        Ok(fd)
    };
    let root = open("/")?;
    let var = open("/var")?;
    let rs = stat(root.0)?;
    let vs = stat(var.0)?;
    let fs = |fd| -> Result<libc::statvfs> {
        let mut value = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstatvfs(fd, &mut value) } != 0 {
            return Err(error("OEM parent filesystem"));
        }
        Ok(value)
    };
    let rf = fs(root.0)?;
    let vf = fs(var.0)?;
    let kind: Vec<u8> = vf
        .f_basetype
        .iter()
        .take_while(|v| **v != 0)
        .map(|v| *v as u8)
        .collect();
    if !identity(&rs, &lstat("/")?)
        || !identity(&vs, &lstat("/var")?)
        || rs.st_uid != 0
        || rs.st_gid != 0
        || !oem_var_policy(
            "/var",
            vs.st_uid as u64,
            vs.st_gid as u64,
            vs.st_mode as u32,
            rs.st_dev != vs.st_dev && rf.f_fsid != vf.f_fsid,
            kind == b"qnx6",
            vf.f_flag & libc::ST_RDONLY != 0,
        )
    {
        return Err("OEM /var mount contract rejected".into());
    }
    Ok(OemVarMount {
        dev: vs.st_dev as u64,
        ino: vs.st_ino as u64,
        fsid: vf.f_fsid as u64,
        flags: vf.f_flag as u64,
    })
}
fn trusted_oem_parent(path: &str) -> Result<bool> {
    #[cfg(target_os = "nto")]
    if path == "/var" {
        return oem_var_mount().map(|_| true);
    }
    let _ = path;
    Ok(false)
}
/// A root-ancestor directory with group/other write bits may only pass the
/// protected walk when it demonstrably rejects new file creation (read-only
/// filesystem mount). This keeps the check fail-closed: on a real writable
/// root the probe fails and the ancestor stays rejected.
fn writable_probe_ok(path: &str) -> Result<bool> {
    let probe_path = format!("{path}/.voboost-ro-probe");
    let fd = Fd(unsafe {
        libc::open(
            c(&probe_path)?.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            0o600,
        )
    });
    if fd.0 < 0 {
        return match errno() {
            libc::EROFS => Ok(true),
            _ => Ok(false),
        };
    }
    // Directory accepted a new entry: it is writable despite its mode bits.
    drop(fd);
    if unsafe { libc::unlink(c(&probe_path)?.as_ptr()) } != 0 {
        return Err(error("probe unlink"));
    }
    Ok(false)
}

fn readonly_ancestor(fd: i32, path: &str, probe_write: bool) -> Result<bool> {
    if probe_write {
        return writable_probe_ok(path);
    }
    let mut filesystem = unsafe { core::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::fstatvfs(fd, &mut filesystem) } != 0 {
        return Err(error("read-only ancestor filesystem"));
    }
    Ok(filesystem.f_flag & libc::ST_RDONLY != 0)
}

impl Dir {
    pub fn open(path: &str, owner: u32) -> Result<Self> {
        Self::walk(path, owner, true, cfg!(target_os = "nto"), true)
    }
    pub fn parent(path: &str, owner: u32) -> Result<Self> {
        Self::walk(path, owner, false, cfg!(target_os = "nto"), true)
    }
    #[cfg(target_os = "nto")]
    pub(crate) fn observe_parent(path: &str) -> Result<Self> {
        Self::walk(path, 0, false, true, false)
    }
    fn walk(path: &str, owner: u32, private: bool, paths: bool, probe_write: bool) -> Result<Self> {
        if !voboost_contract_core::safe_path(path) {
            return Err("unsafe protected root path".into());
        }
        let mut fd = Fd(unsafe {
            libc::open(
                c("/")?.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        });
        if fd.0 < 0 {
            return Err(error("root open"));
        }
        let mut current = String::from("/");
        for component in path.split('/').skip(1) {
            let parent = stat(fd.0)?;
            if !cfg!(test) && parent.st_uid != 0 {
                return Err("unprotected root ancestor".into());
            }
            if !cfg!(test)
                && parent.st_mode & 0o022 != 0
                && !trusted_oem_parent(&current)?
                && !readonly_ancestor(fd.0, &current, probe_write)?
            {
                return Err("unprotected root ancestor".into());
            }
            if paths && !identity(&parent, &lstat(&current)?) {
                return Err("root ancestor identity changed".into());
            }
            let next_path = if current == "/" {
                format!("/{component}")
            } else {
                format!("{current}/{component}")
            };
            let next = if paths {
                let next = unsafe {
                    libc::open(
                        c(&next_path)?.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if !identity(&parent, &lstat(&current)?) {
                    if next >= 0 {
                        unsafe {
                            libc::close(next);
                        }
                    }
                    return Err("root ancestor changed during open".into());
                }
                next
            } else {
                #[cfg(not(target_os = "nto"))]
                {
                    unsafe {
                        libc::openat(
                            fd.0,
                            c(component)?.as_ptr(),
                            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    }
                }
                #[cfg(target_os = "nto")]
                {
                    return Err("unsupported directory capability backend".into());
                }
            };
            if next < 0 {
                return Err(error("directory open"));
            }
            fd = Fd(next);
            current = next_path;
            let st = stat(fd.0)?;
            if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err("protected path is not directory".into());
            }
            if paths && !identity(&st, &lstat(&current)?) {
                return Err("opened directory identity changed".into());
            }
            if !cfg!(test) && st.st_uid != 0 {
                return Err("unprotected root ancestor".into());
            }
            if !cfg!(test)
                && st.st_mode & 0o022 != 0
                && !trusted_oem_parent(&current)?
                && !readonly_ancestor(fd.0, &current, probe_write)?
            {
                return Err("unprotected root ancestor".into());
            }
        }
        let d = Self {
            fd,
            path: path.into(),
            owner,
            private,
            paths,
            probe_write,
            #[cfg(target_os = "nto")]
            oem_var: if path == "/var" || path.starts_with("/var/") {
                Some(oem_var_mount()?)
            } else {
                None
            },
        };
        d.guard()?;
        Ok(d)
    }
    fn guard(&self) -> Result<()> {
        #[cfg(target_os = "nto")]
        if let Some(expected) = self.oem_var {
            if oem_var_mount()? != expected
                || !self.probe_write && stat(self.fd.0)?.st_dev as u64 != expected.dev
            {
                return Err("retained OEM /var mount changed".into());
            }
        }
        let s = stat(self.fd.0)?;
        if s.st_mode & libc::S_IFMT != libc::S_IFDIR
            || owner(&s) != Some(self.owner)
            || self.private && s.st_mode & 0o777 != 0o700
            || !self.private && s.st_mode & 0o022 != 0 && !trusted_oem_parent(&self.path)?
        {
            return Err("protected parent owner/mode rejected".into());
        }
        if self.paths && !identity(&s, &lstat(&self.path)?) {
            return Err("retained protected parent identity changed".into());
        }
        Ok(())
    }
    fn member(&self, name: &str) -> Result<String> {
        if !voboost_contract_core::basename(name) {
            return Err("unsafe protected member".into());
        }
        Ok(format!("{}/{}", self.path, name))
    }
    fn entry(&self, name: &str) -> Result<Option<libc::stat>> {
        let path = self.member(name)?;
        self.guard()?;
        let mut s = unsafe { core::mem::zeroed() };
        let code = if self.paths {
            unsafe { libc::lstat(c(&path)?.as_ptr(), &mut s) }
        } else {
            #[cfg(not(target_os = "nto"))]
            {
                unsafe {
                    libc::fstatat(
                        self.fd.0,
                        c(name)?.as_ptr(),
                        &mut s,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                }
            }
            #[cfg(target_os = "nto")]
            {
                return Err("unsupported stat capability backend".into());
            }
        };
        let failure = errno();
        self.guard()?;
        if code == 0 {
            Ok(Some(s))
        } else if failure == libc::ENOENT {
            Ok(None)
        } else {
            Err(error("member stat"))
        }
    }
    pub(crate) fn open_file(&self, name: &str, flags: i32, mode: u32) -> Result<Fd> {
        let path = self.member(name)?;
        self.guard()?;
        let number = if self.paths {
            unsafe { libc::open(c(&path)?.as_ptr(), flags, mode) }
        } else {
            #[cfg(not(target_os = "nto"))]
            {
                unsafe { libc::openat(self.fd.0, c(name)?.as_ptr(), flags, mode) }
            }
            #[cfg(target_os = "nto")]
            {
                return Err("unsupported file capability backend".into());
            }
        };
        let fd = Fd(number);
        self.guard()?;
        if fd.0 < 0 {
            return Err(error("file open"));
        }
        if self.paths
            && !identity(
                &stat(fd.0)?,
                &self.entry(name)?.ok_or("opened member disappeared")?,
            )
        {
            return Err("opened protected member identity changed".into());
        }
        Ok(fd)
    }
    fn move_member(&self, old: &str, new: &str) -> Result<()> {
        let from = self.member(old)?;
        let to = self.member(new)?;
        self.guard()?;
        let source = self.entry(old)?.ok_or("rename source absent")?;
        if source.st_mode & libc::S_IFMT == libc::S_IFLNK || owner(&source) != Some(self.owner) {
            return Err("unsafe rename source".into());
        }
        if let Some(destination) = self.entry(new)? {
            if destination.st_mode & libc::S_IFMT == libc::S_IFLNK
                || owner(&destination) != Some(self.owner)
            {
                return Err("unsafe rename destination".into());
            }
        }
        let result = if self.paths {
            unsafe { libc::rename(c(&from)?.as_ptr(), c(&to)?.as_ptr()) }
        } else {
            #[cfg(not(target_os = "nto"))]
            {
                unsafe { libc::renameat(self.fd.0, c(old)?.as_ptr(), self.fd.0, c(new)?.as_ptr()) }
            }
            #[cfg(target_os = "nto")]
            {
                return Err("unsupported rename capability backend".into());
            }
        };
        self.guard()?;
        if result != 0 || !identity(&source, &self.entry(new)?.ok_or("renamed member absent")?) {
            return Err(error("same-parent atomic rename"));
        }
        Ok(())
    }
    fn unlink_file(&self, name: &str) -> Result<()> {
        let path = self.member(name)?;
        self.guard()?;
        let s = self.entry(name)?.ok_or("temporary member absent")?;
        if s.st_mode & libc::S_IFMT != libc::S_IFREG
            || owner(&s) != Some(self.owner)
            || s.st_nlink != 1
        {
            return Err("temporary unlink identity rejected".into());
        }
        let code = if self.paths {
            unsafe { libc::unlink(c(&path)?.as_ptr()) }
        } else {
            #[cfg(not(target_os = "nto"))]
            {
                unsafe { libc::unlinkat(self.fd.0, c(name)?.as_ptr(), 0) }
            }
            #[cfg(target_os = "nto")]
            {
                return Err("unsupported unlink capability backend".into());
            }
        };
        self.guard()?;
        if code != 0 {
            return Err(error("temporary unlink"));
        }
        Ok(())
    }
    pub fn child(&self, name: &str) -> Result<Self> {
        let path = self.member(name)?;
        self.guard()?;
        let code = if self.paths {
            unsafe { libc::mkdir(c(&path)?.as_ptr(), 0o700) }
        } else {
            #[cfg(not(target_os = "nto"))]
            {
                unsafe { libc::mkdirat(self.fd.0, c(name)?.as_ptr(), 0o700) }
            }
            #[cfg(target_os = "nto")]
            {
                return Err("unsupported mkdir capability backend".into());
            }
        };
        let failure = errno();
        self.guard()?;
        if code != 0 && failure != libc::EEXIST {
            return Err(error("protected mkdir"));
        }
        Self::walk(&path, self.owner, true, self.paths, self.probe_write)
    }
    pub(crate) fn existing_child(&self, name: &str) -> Result<Self> {
        let path = self.member(name)?;
        self.guard()?;
        let child = Self::walk(&path, self.owner, true, self.paths, self.probe_write)?;
        self.guard()?;
        Ok(child)
    }
    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.entry(name)?.is_some())
    }
    #[cfg(target_os = "nto")]
    pub(crate) fn observe_names(&self) -> Result<Vec<String>> {
        self.guard()?;
        let before = stat(self.fd.0)?;
        let mut names = directory_names(&self.path)?;
        names.sort_unstable();
        self.guard()?;
        if !unchanged(&before, &stat(self.fd.0)?) {
            return Err("protected parent changed during enumeration".into());
        }
        Ok(names)
    }
    pub fn read(&self, name: &str, max: usize, mode: u32) -> Result<Vec<u8>> {
        let fd = self.open_file(name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0)?;
        let before = stat(fd.0)?;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || owner(&before) != Some(self.owner)
            || before.st_nlink != 1
            || (before.st_mode as u32) & 0o777 != mode
            || before.st_size < 0
            || before.st_size as u64 > max as u64
        {
            return Err("protected file identity rejected".into());
        }
        let mut bytes = vec![0; before.st_size as usize];
        read_exact(fd.0, &mut bytes)?;
        let after = stat(fd.0)?;
        self.guard()?;
        if !unchanged(&before, &after)
            || self.paths
                && !identity(
                    &after,
                    &self.entry(name)?.ok_or("protected member disappeared")?,
                )
        {
            return Err("protected file changed".into());
        }
        Ok(bytes)
    }
    /// Repair only the fixed signed implant executable bit, without replacing bytes.
    pub(crate) fn repair_implant_executable(&self, expected: &[u8]) -> Result<()> {
        let name = "libvoboost-cluster-inject.so";
        self.guard()?;
        let fd = self.open_file(name, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0)?;
        let before = stat(fd.0)?;
        let mode = before.st_mode as u32 & 0o7777;
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || owner(&before) != Some(self.owner)
            || before.st_nlink != 1
            || ![0o600, 0o700].contains(&mode)
            || before.st_size < 0
            || before.st_size as u64 != expected.len() as u64
        {
            return Err("native implant repair identity rejected".into());
        }
        let mut bytes = vec![0; expected.len()];
        read_exact(fd.0, &mut bytes)?;
        self.guard()?;
        if bytes != expected
            || !unchanged(&before, &stat(fd.0)?)
            || !identity(
                &before,
                &self.entry(name)?.ok_or("native implant disappeared")?,
            )
        {
            return Err("native implant repair content or path changed".into());
        }
        if mode == 0o600 && unsafe { libc::fchmod(fd.0, 0o700) } != 0 {
            return Err(error("implant executable repair"));
        }
        if unsafe { libc::fsync(fd.0) } != 0 {
            return Err(error("implant repair sync"));
        }
        let after = stat(fd.0)?;
        self.guard()?;
        if after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || after.st_uid != before.st_uid
            || after.st_gid != before.st_gid
            || after.st_nlink != 1
            || after.st_size != before.st_size
            || after.st_mode as u32 & 0o7777 != 0o700
            || !identity(
                &after,
                &self.entry(name)?.ok_or("native implant disappeared")?,
            )
            || self.read(name, expected.len(), 0o700)? != expected
            || !unchanged(&after, &stat(fd.0)?)
            || !identity(
                &after,
                &self.entry(name)?.ok_or("native implant disappeared")?,
            )
        {
            return Err("native implant executable repair readback rejected".into());
        }
        Ok(())
    }
    /// Move a protected record to an absent name in another directory on this filesystem.
    pub(crate) fn rename_file_to(&self, old: &str, target: &Dir, new: &str) -> Result<()> {
        let from = self.member(old)?;
        let to = target.member(new)?;
        self.guard()?;
        target.guard()?;
        let source = self.entry(old)?.ok_or("migration source absent")?;
        if self.paths != target.paths
            || self.owner != target.owner
            || owner(&source) != Some(self.owner)
            || source.st_nlink != 1
            || source.st_mode & (libc::S_IFMT | 0o777) != (libc::S_IFREG | 0o600)
            || source.st_dev != stat(target.fd.0)?.st_dev
            || target.exists(new)?
        {
            return Err("native install migration authority differs".into());
        }
        let result = if self.paths {
            unsafe { libc::rename(c(&from)?.as_ptr(), c(&to)?.as_ptr()) }
        } else {
            #[cfg(not(target_os = "nto"))]
            {
                unsafe {
                    libc::renameat(self.fd.0, c(old)?.as_ptr(), target.fd.0, c(new)?.as_ptr())
                }
            }
            #[cfg(target_os = "nto")]
            return Err("unsupported migration capability backend".into());
        };
        self.guard()?;
        target.guard()?;
        if result != 0
            || self.exists(old)?
            || !identity(
                &source,
                &target.entry(new)?.ok_or("migration destination absent")?,
            )
        {
            return Err(error("native install record rename"));
        }
        if unsafe { libc::fsync(target.fd.0) } != 0 || unsafe { libc::fsync(self.fd.0) } != 0 {
            return Err(error("native install migration sync"));
        }
        Ok(())
    }
    pub fn rename(&self, old: &str, new: &str) -> Result<()> {
        if self.exists(new)? {
            return Err("immutable directory destination exists".into());
        }
        self.move_member(old, new)?;
        if unsafe { libc::fsync(self.fd.0) } != 0 {
            return Err(error("directory sync"));
        }
        Ok(())
    }
    pub fn write(&self, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
        self.member(name)?;
        let temp = format!(
            ".write-{}",
            crate::nonce().map_err(|failure| format!("atomic file nonce: {failure}"))?
        );
        let fd = self.open_file(
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )?;
        let result = (|| {
            write_all(fd.0, bytes)?;
            if unsafe { libc::fchmod(fd.0, mode as libc::mode_t) } != 0 {
                return Err(format!(
                    "native filesystem atomic file chmod failed errno={}",
                    errno()
                ));
            }
            if unsafe { libc::fsync(fd.0) } != 0 {
                return Err(format!(
                    "native filesystem atomic file sync failed errno={}",
                    errno()
                ));
            }
            self.move_member(&temp, name)?;
            if unsafe { libc::fsync(self.fd.0) } != 0 {
                return Err(format!(
                    "native filesystem atomic directory sync failed errno={}",
                    errno()
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = self.unlink_file(&temp);
        }
        result
    }
}
pub fn read_protected(path: &str, owner: u32, max: usize, mode: u32) -> Result<Vec<u8>> {
    if !voboost_contract_core::safe_path(path) {
        return Err("unsafe protected file path".into());
    }
    let (parent, name) = path.rsplit_once('/').ok_or("protected parent missing")?;
    Dir::open(parent, owner)?.read(name, max, mode)
}

/// QNX procnto RAM objects outlive process exits and disappear on OS reboot.
/// This dedicated API deliberately does not relax regular-file protection.
pub fn boot_identity_path(pair_id: &str) -> Result<String> {
    if !voboost_contract_core::digest(pair_id) {
        return Err("invalid boot identity pairing".into());
    }
    Ok(format!("/dev/shmem/voboost-boot-{pair_id}"))
}
fn boot_identity_name(path: &str, pair_id: &str) -> Result<CString> {
    if path != boot_identity_path(pair_id)? {
        return Err("per-boot identity must use paired procnto RAM object".into());
    }
    c(path
        .strip_prefix("/dev/shmem")
        .ok_or("boot identity namespace")?)
}
fn boot_identity_read_fd(fd: i32, expected_owner: u32) -> Result<String> {
    let before = stat(fd)?;
    // shm_open supplies the kernel capability; QNX advertises S_IFNAM.
    if owner(&before) != Some(expected_owner)
        || before.st_mode & 0o777 != 0o600
        || before.st_size != 65
    {
        return Err("per-boot RAM object owner/mode/size rejected".into());
    }
    let mut bytes = [0u8; 65];
    read_exact(fd, &mut bytes)?;
    if !unchanged(&before, &stat(fd)?) || bytes[64] != b'\n' {
        return Err("per-boot RAM object changed or incomplete".into());
    }
    let value = core::str::from_utf8(&bytes[..64]).map_err(|_| "boot identity UTF8")?;
    if !voboost_contract_core::digest(value) {
        return Err("invalid per-boot RAM token".into());
    }
    Ok(String::from(value))
}
fn boot_identity_initialize_fd(fd: i32, expected_owner: u32) -> Result<String> {
    let before = stat(fd)?;
    if owner(&before) != Some(expected_owner) || before.st_size != 0 {
        return Err("new per-boot RAM object identity rejected".into());
    }
    let value = crate::nonce()?;
    let bytes = format!("{value}\n");
    if unsafe { libc::fchmod(fd, 0o600) } != 0 || unsafe { libc::ftruncate(fd, 65) } != 0 {
        return Err("per-boot RAM object initialization failed".into());
    }
    write_all(fd, bytes.as_bytes())?;
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err("per-boot RAM object readback seek failed".into());
    }
    if boot_identity_read_fd(fd, expected_owner)? != value {
        return Err("per-boot RAM object readback differs".into());
    }
    Ok(value)
}
/// Run synchronously before daemon and OEM startup descendants.
/// Never replace an interrupted or malformed existing object within a boot.
pub fn prepare_boot_identity(path: &str, pair_id: &str, expected_owner: u32) -> Result<()> {
    prepare_ram_identity(&boot_identity_name(path, pair_id)?, expected_owner)
}

pub(crate) fn prepare_supervisor_boot_identity(owner: u32) -> Result<String> {
    let name = c("/voboost-supervisor-boot")?;
    prepare_ram_identity(&name, owner)?;
    read_ram_identity(&name, owner)
}

pub(crate) fn read_supervisor_boot_identity(owner: u32) -> Result<String> {
    read_ram_identity(&c("/voboost-supervisor-boot")?, owner)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub(crate) enum UninstallBoot {
    Supervisor(String),
    KernelTime(u32),
}

impl UninstallBoot {
    pub(crate) fn current(owner: u32) -> Result<Self> {
        prepare_supervisor_boot_identity(owner).map(Self::Supervisor)
    }

    pub(crate) fn read_current(&self, owner: u32) -> Result<Self> {
        match self {
            Self::Supervisor(_) => Self::current(owner),
            Self::KernelTime(_) => kernel_boot_time().map(Self::KernelTime),
        }
    }

    pub(crate) fn valid(&self) -> bool {
        match self {
            Self::Supervisor(token) => voboost_contract_core::digest(token),
            Self::KernelTime(time) => *time != 0,
        }
    }

    pub(crate) fn same_source(&self, other: &Self) -> bool {
        core::mem::discriminant(self) == core::mem::discriminant(other)
    }
}

#[cfg(test)]
impl From<u32> for UninstallBoot {
    fn from(value: u32) -> Self {
        Self::KernelTime(value)
    }
}

fn prepare_ram_identity(name: &core::ffi::CStr, expected_owner: u32) -> Result<()> {
    if !cfg!(test) && expected_owner != 0 {
        return Err("per-boot RAM identity preparation requires root".into());
    }
    let fd = Fd(unsafe {
        libc::shm_open(
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    });
    if fd.0 >= 0 {
        boot_identity_initialize_fd(fd.0, expected_owner)?;
    } else if errno() == libc::EEXIST {
        let existing = Fd(unsafe { libc::shm_open(name.as_ptr(), libc::O_RDONLY, 0) });
        if existing.0 < 0 {
            return Err("existing per-boot RAM object open failed".into());
        }
        boot_identity_read_fd(existing.0, expected_owner)?;
    } else {
        return Err("per-boot RAM object create failed".into());
    }
    Ok(())
}
pub fn read_boot_identity(path: &str, pair_id: &str, expected_owner: u32) -> Result<String> {
    #[cfg(not(target_os = "nto"))]
    if !path.starts_with("/dev/shmem/") {
        // Project-local host fixtures only. Production QNX has no disk fallback.
        let bytes = read_protected(path, expected_owner, 129, 0o600)?;
        let value = core::str::from_utf8(&bytes)
            .map_err(|_| "boot identity UTF8")?
            .strip_suffix('\n')
            .ok_or("boot identity must end LF")?;
        if !voboost_contract_core::printable(value, 128) {
            return Err("verified per-boot identity missing".into());
        }
        return Ok(String::from(value));
    }
    read_ram_identity(&boot_identity_name(path, pair_id)?, expected_owner)
}

fn read_ram_identity(name: &core::ffi::CStr, expected_owner: u32) -> Result<String> {
    let fd = Fd(unsafe { libc::shm_open(name.as_ptr(), libc::O_RDONLY, 0) });
    if fd.0 < 0 {
        return Err("per-boot RAM object is not prepared".into());
    }
    boot_identity_read_fd(fd.0, expected_owner)
}

pub fn path_absent(path: &str) -> Result<bool> {
    let mut value = unsafe { core::mem::zeroed() };
    if unsafe { libc::lstat(c(path)?.as_ptr(), &mut value) } == 0 {
        return Ok(false);
    }
    if errno() == libc::ENOENT {
        Ok(true)
    } else {
        Err(error("absence stat"))
    }
}

// Older QNX kernels expose a shorter qtime record than the current libc type.
// Validate the declared record, but require only the field we actually read.
#[cfg(any(target_os = "nto", test))]
fn kernel_boot_time_offset(
    base: usize,
    header_size: usize,
    total_size: usize,
    descriptor_end: usize,
    entry_offset: usize,
    entry_size: usize,
    boot_offset: usize,
) -> Result<usize> {
    let invalid = || String::from("QNX qtime bounds invalid");
    let field_end = boot_offset
        .checked_add(core::mem::size_of::<u32>())
        .ok_or_else(invalid)?;
    let entry_end = entry_offset.checked_add(entry_size).ok_or_else(invalid)?;
    let field_offset = entry_offset.checked_add(boot_offset).ok_or_else(invalid)?;
    let address = base.checked_add(field_offset).ok_or_else(invalid)?;
    if header_size < descriptor_end
        || header_size > total_size
        || entry_offset < header_size
        || entry_size < field_end
        || entry_end > total_size
        || base.checked_add(total_size).is_none()
        || address % core::mem::align_of::<u32>() != 0
    {
        return Err(invalid());
    }
    Ok(field_offset)
}

/// Independent kernel identity; unlike the managed RAM token this is never
/// generated or rewritten by Voboost.
pub fn kernel_boot_time() -> Result<u32> {
    #[cfg(target_os = "nto")]
    unsafe {
        let page = libc::_syspage_ptr;
        if page.is_null() {
            return Err("QNX syspage missing".into());
        }
        if page as usize % core::mem::align_of::<u16>() != 0 {
            return Err("QNX qtime bounds invalid".into());
        }
        // Read header scalars without constructing a reference to a newer,
        // potentially larger syspage or qtime structure.
        let header_size = usize::from(core::ptr::read_volatile(core::ptr::addr_of!((*page).size)));
        let total_size = usize::from(core::ptr::read_volatile(core::ptr::addr_of!(
            (*page).total_size
        )));
        let descriptor_end = core::mem::offset_of!(libc::syspage_entry, qtime)
            + core::mem::size_of::<libc::syspage_entry_info>();
        if header_size < descriptor_end || header_size > total_size {
            return Err("QNX qtime bounds invalid".into());
        }
        let info = core::ptr::read_volatile(core::ptr::addr_of!((*page).qtime));
        let offset = kernel_boot_time_offset(
            page as usize,
            header_size,
            total_size,
            descriptor_end,
            usize::from(info.entry_off),
            usize::from(info.entry_size),
            core::mem::offset_of!(libc::qtime_entry, boot_time),
        )?;
        let value = core::ptr::read_volatile(page.cast::<u8>().add(offset).cast::<u32>());
        if value == 0 {
            return Err("QNX kernel boot time unknown".into());
        }
        Ok(value)
    }
    #[cfg(not(target_os = "nto"))]
    {
        Err("QNX kernel boot time unavailable on host".into())
    }
}

pub fn boot_identity_absent(path: &str, pair_id: &str) -> Result<bool> {
    let name = boot_identity_name(path, pair_id)?;
    let fd = Fd(unsafe { libc::shm_open(name.as_ptr(), libc::O_RDONLY, 0) });
    if fd.0 >= 0 {
        return Ok(false);
    }
    if errno() == libc::ENOENT {
        Ok(true)
    } else {
        Err("per-boot RAM absence not proven".into())
    }
}

/// Read directory names only; callers validate every child before using it.
pub fn directory_names(path: &str) -> Result<Vec<String>> {
    let directory = unsafe { libc::opendir(c(path)?.as_ptr()) };
    if directory.is_null() {
        return Err(error("directory enumeration"));
    }
    let result = (|| {
        let mut names = Vec::new();
        loop {
            // readdir distinguishes end of stream from failure through errno.
            #[cfg(target_os = "nto")]
            unsafe {
                *libc::__get_errno_ptr() = 0;
            }
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                if errno() != 0 {
                    return Err(error("directory enumeration read"));
                }
                break;
            }
            let name = unsafe { core::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| "directory member UTF8")?;
            if name == "." || name == ".." {
                continue;
            }
            if !voboost_contract_core::basename(name) || names.len() >= 4096 {
                return Err("directory enumeration bound".into());
            }
            names.push(String::from(name));
        }
        Ok(names)
    })();
    unsafe {
        libc::closedir(directory);
    }
    result
}

/// Validate a dedicated protected managed tree in full before any removal.
/// No symlinks, foreign owners, hard links, mount crossings or special files.
pub fn purge_private_tree(root: &Dir) -> Result<()> {
    purge_private_tree_with(root, || Ok(()))
}

/// Dedicated installation cleanup: only its direct disposable log may retain
/// the old shell-created0666 mode. Log contents are never authority.
pub fn purge_installation_tree(root: &Dir) -> Result<()> {
    purge_private_tree_policy(root, true, || Ok(()))
}

fn purge_private_tree_with(root: &Dir, before_remove: impl FnMut() -> Result<()>) -> Result<()> {
    purge_private_tree_policy(root, false, before_remove)
}

fn purge_private_tree_policy(
    root: &Dir,
    allow_service_log: bool,
    mut before_remove: impl FnMut() -> Result<()>,
) -> Result<()> {
    fn collect(
        root: &Dir,
        dev: u64,
        depth: usize,
        entries: &mut Vec<(String, libc::stat)>,
        allow_service_log: bool,
    ) -> Result<()> {
        if depth > 16 {
            return Err("managed tree depth bound".into());
        }
        root.guard()?;
        for name in directory_names(&root.path)? {
            let stat = root.entry(&name)?.ok_or("managed member disappeared")?;
            if stat.st_dev as u64 != dev
                || owner(&stat) != Some(root.owner)
                || (stat.st_mode & 0o077 != 0
                    && !(allow_service_log
                        && depth == 0
                        && name == "service.log"
                        && stat.st_mode & (libc::S_IFMT | 0o7777) == (libc::S_IFREG | 0o666)))
                || entries.len() >= 16384
            {
                return Err("managed purge member authority rejected".into());
            }
            let path = root.member(&name)?;
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => collect(
                    &Dir::open(&path, root.owner)?,
                    dev,
                    depth + 1,
                    entries,
                    allow_service_log,
                )?,
                libc::S_IFREG if stat.st_nlink == 1 => (),
                _ => return Err("managed purge member type rejected".into()),
            }
            entries.push((path, stat));
        }
        root.guard()
    }
    let root_stat = stat(root.fd.0)?;
    let mut entries = Vec::new();
    collect(
        root,
        root_stat.st_dev as u64,
        0,
        &mut entries,
        allow_service_log,
    )?;
    for (path, before) in entries {
        if !(if before.st_mode & libc::S_IFMT == libc::S_IFDIR {
            identity(&before, &lstat(&path)?)
        } else {
            unchanged(&before, &lstat(&path)?)
        }) {
            return Err("managed purge member changed".into());
        }
        before_remove()?;
        let code = if before.st_mode & libc::S_IFMT == libc::S_IFDIR {
            unsafe { libc::rmdir(c(&path)?.as_ptr()) }
        } else {
            unsafe { libc::unlink(c(&path)?.as_ptr()) }
        };
        if code != 0 {
            return Err(error("managed purge"));
        }
    }
    root.guard()?;
    before_remove()?;
    if unsafe { libc::rmdir(c(&root.path)?.as_ptr()) } != 0 {
        return Err(error("managed root purge"));
    }
    unsafe {
        libc::sync();
    }
    let mut absent = unsafe { core::mem::zeroed() };
    if unsafe { libc::lstat(c(&root.path)?.as_ptr(), &mut absent) } == 0 || errno() != libc::ENOENT
    {
        return Err("managed root absence not proven".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    /// Owned canonical temp directory for the managed-purge tests: Dir::open
    /// is fail-closed on ".." components and on symlinked ancestors (the macOS
    /// system TMPDIR lives under symlinked /var), so the guard keeps the
    /// original TempDir owner and removes nothing canonicalized itself.
    struct PurgeTempGuard {
        #[expect(dead_code)]
        dir: tempfile::TempDir,
        canonical: String,
    }
    impl PurgeTempGuard {
        fn new(base: &std::path::Path, mode: u32) -> Self {
            std::fs::create_dir_all(base).unwrap();
            let dir = tempfile::tempdir_in(base).unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let canonical = std::fs::canonicalize(dir.path())
                .unwrap()
                .into_os_string()
                .into_string()
                .unwrap();
            Self { dir, canonical }
        }
        fn path_str(&self) -> &str {
            &self.canonical
        }
    }
    fn temp_path_join(base: &str) -> std::path::PathBuf {
        std::path::Path::new(base).join("managed")
    }
    #[test]
    fn kernel_boot_time_accepts_older_qtime_prefix() {
        assert_eq!(
            kernel_boot_time_offset(0x1000, 64, 96, 36, 64, 32, 28).unwrap(),
            92
        );
        // Alignment applies to the u32 read, not the unused newer u64 tail.
        assert_eq!(
            kernel_boot_time_offset(0x1000, 64, 100, 36, 68, 32, 28).unwrap(),
            96
        );
        assert_eq!(
            kernel_boot_time_offset(0x1000, 64, 184, 36, 64, 120, 28).unwrap(),
            92
        );
    }

    #[test]
    fn kernel_boot_time_rejects_invalid_declared_records() {
        for (header, total, offset, size, boot) in [
            (32, 96, 64, 32, 28),  // Descriptor outside header.
            (100, 96, 64, 32, 28), // Header outside page.
            (64, 96, 32, 32, 28),  // Record overlaps header.
            (64, 96, 64, 31, 28),  // Read extends beyond record.
            (64, 96, 64, 40, 28),  // Unread declared tail outside page.
            (64, 100, 65, 32, 28), // Misaligned actual u32 address.
            (64, usize::MAX, usize::MAX - 8, 32, 28),
            (64, 96, 64, 32, usize::MAX),
        ] {
            assert!(
                kernel_boot_time_offset(0x1000, header, total, 36, offset, size, boot).is_err()
            );
        }
        assert!(kernel_boot_time_offset(usize::MAX - 80, 64, 96, 36, 64, 32, 28).is_err());
    }

    #[test]
    fn retained_identity_rejects_group_changes() {
        let a: libc::stat = unsafe { core::mem::zeroed() };
        let mut b = a;
        b.st_gid = 1;
        assert!(!identity(&a, &b));
        assert!(!unchanged(&a, &b));
    }
    #[test]
    fn oem_var_parent_policy_is_exact_and_fail_closed() {
        let mode = libc::S_IFDIR as u32 | 0o775;
        assert!(oem_var_policy("/var", 0, 0, mode, true, true, false));
        for (path, uid, gid, mode, separate, qnx6, var_ro) in [
            ("/other", 0, 0, mode, true, true, false),
            ("/var/child", 0, 0, mode, true, true, false),
            ("/var", 1, 0, mode, true, true, false),
            ("/var", 0, 1, mode, true, true, false),
            ("/var", 0, 0, mode | 2, true, true, false),
            ("/var", 0, 0, mode, false, true, false),
            ("/var", 0, 0, mode, true, false, false),
            ("/var", 0, 0, mode, true, true, true),
        ] {
            assert!(!oem_var_policy(path, uid, gid, mode, separate, qnx6, var_ro));
        }
    }
    #[test]
    fn interrupted_managed_purge_can_resume_after_each_removal_boundary() {
        for fail_at in 0..4 {
            let temp = PurgeTempGuard::new(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../build/cluster-test-tmp"),
                0o700,
            );
            let temp_path = temp.path_str();
            let path = temp_path_join(temp_path);
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = Dir::open(path.to_str().unwrap(), uid().unwrap()).unwrap();
            root.child("bin")
                .unwrap()
                .write("payload", b"fixture", 0o700)
                .unwrap();
            root.write("authority", b"fixture", 0o600).unwrap();
            let mut boundary = 0;
            assert!(purge_private_tree_with(&root, || {
                if boundary == fail_at {
                    return Err("simulated interrupted removal".into());
                }
                boundary += 1;
                Ok(())
            })
            .is_err());
            assert!(path.exists());
            purge_private_tree(&root).unwrap();
            assert!(path_absent(path.to_str().unwrap()).unwrap());
            assert!(std::path::Path::new(temp_path).exists());
        }
    }
    #[test]
    fn managed_purge_rejects_symlink_before_removing_any_file() {
        let temp = PurgeTempGuard::new(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp"),
            0o700,
        );
        let temp_path = temp.path_str();
        let file = std::path::Path::new(temp_path).join("retained");
        std::fs::write(&file, b"keep").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink("retained", std::path::Path::new(temp_path).join("unsafe")).unwrap();
        let root = Dir::open(temp_path, uid().unwrap()).unwrap();
        assert!(purge_private_tree(&root).is_err());
        assert_eq!(std::fs::read(file).unwrap(), b"keep");
    }
    #[test]
    fn installation_purge_log_exception_is_direct_regular_single_link_only() {
        for scenario in 0..7 {
            let temp = PurgeTempGuard::new(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-tmp"),
                0o700,
            );
            let temp_path = temp.path_str();
            let managed = std::path::Path::new(temp_path).join("managed");
            std::fs::create_dir(&managed).unwrap();
            std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = Dir::open(managed.to_str().unwrap(), uid().unwrap()).unwrap();
            root.write("authority", b"retained", 0o600).unwrap();
            let mut log = managed.join(if scenario == 2 {
                "other.log"
            } else {
                "service.log"
            });
            if scenario == 3 {
                let nested = root.child("nested").unwrap();
                log = std::path::Path::new(&nested.path).join("service.log");
            }
            if scenario == 5 {
                symlink("authority", &log).unwrap();
            } else {
                std::fs::write(&log, b"untrusted log").unwrap();
                std::fs::set_permissions(
                    &log,
                    std::fs::Permissions::from_mode(if scenario == 4 { 0o777 } else { 0o666 }),
                )
                .unwrap();
            }
            if scenario == 6 {
                std::fs::hard_link(&log, std::path::Path::new(temp_path).join("outside-link"))
                    .unwrap();
            }
            let result = if scenario == 1 {
                purge_private_tree(&root)
            } else {
                purge_installation_tree(&root)
            };
            if scenario == 0 {
                result.unwrap();
                assert!(!managed.exists());
            } else {
                assert!(result.is_err(), "scenario {scenario}");
                assert_eq!(
                    std::fs::read(managed.join("authority")).unwrap(),
                    b"retained"
                );
            }
        }
    }

    #[test]
    fn managed_purge_removes_only_validated_private_fixture() {
        let temp = PurgeTempGuard::new(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp"),
            0o700,
        );
        let temp_path = temp.path_str();
        let path = temp_path_join(temp_path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(path.to_str().unwrap(), uid().unwrap()).unwrap();
        let child = root.child("bin").unwrap();
        child.write("payload", b"fixture", 0o700).unwrap();
        root.write("authority", b"fixture", 0o600).unwrap();
        purge_private_tree(&root).unwrap();
        assert!(path_absent(path.to_str().unwrap()).unwrap());
        assert!(std::path::Path::new(temp_path).exists());
    }
    #[test]
    fn boot_ram_token_model_is_stable_until_namespace_reset_and_rejects_corruption() {
        use std::os::fd::AsRawFd;
        let base =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/cluster-test-tmp");
        std::fs::create_dir_all(&base).unwrap();
        let temp = tempfile::tempdir_in(base).unwrap();
        let path = temp.path().join("modeled-ram-object");
        let create = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap()
        };
        let owner = uid().unwrap();
        let first = create();
        let first_id = boot_identity_initialize_fd(first.as_raw_fd(), owner).unwrap();
        drop(first);
        let reader = std::fs::File::open(&path).unwrap();
        assert_eq!(
            boot_identity_read_fd(reader.as_raw_fd(), owner).unwrap(),
            first_id
        );
        drop(reader);
        // Model OS reboot by resetting the RAM namespace, never process restart.
        std::fs::remove_file(&path).unwrap();
        let second = create();
        let second_id = boot_identity_initialize_fd(second.as_raw_fd(), owner).unwrap();
        assert_ne!(first_id, second_id);
        assert!(boot_identity_initialize_fd(second.as_raw_fd(), owner).is_err());
        drop(second);
        std::fs::write(&path, b"incomplete").unwrap();
        let reader = std::fs::File::open(&path).unwrap();
        assert!(boot_identity_read_fd(reader.as_raw_fd(), owner).is_err());
        drop(reader);
        std::fs::write(&path, format!("{}\n", "g".repeat(64))).unwrap();
        let reader = std::fs::File::open(&path).unwrap();
        assert!(boot_identity_read_fd(reader.as_raw_fd(), owner).is_err());
        drop(reader);
        std::fs::write(&path, format!("{}\n", "a".repeat(64))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let reader = std::fs::File::open(&path).unwrap();
        assert!(boot_identity_read_fd(reader.as_raw_fd(), owner).is_err());
        assert!(boot_identity_name("/persistent/boot-id", &"a".repeat(64)).is_err());
        let expected = boot_identity_path(&"a".repeat(64)).unwrap();
        assert!(boot_identity_name(&expected, &"a".repeat(64)).is_ok());
        assert!(boot_identity_name(&expected, &"b".repeat(64)).is_err());
    }
    #[test]
    fn protected_store_rejects_symlink_wrong_mode_and_preserves_atomic_bytes() {
        let t = {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/cluster-test-tmp");
            std::fs::create_dir_all(&path).unwrap();
            tempfile::tempdir_in(path).unwrap()
        };
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = std::fs::canonicalize(t.path()).unwrap();
        let d = Dir::open(canonical.to_str().unwrap(), unsafe { libc::geteuid() }).unwrap();
        d.write("state.json", b"old", 0o600).unwrap();
        d.write("state.json", b"new", 0o600).unwrap();
        assert_eq!(d.read("state.json", 3, 0o600).unwrap(), b"new");
        symlink("state.json", t.path().join("alias")).unwrap();
        assert!(d.read("alias", 3, 0o600).is_err());
        assert!(d.read("state.json", 3, 0o644).is_err());
        assert!(d.read("../state.json", 3, 0o600).is_err());
    }
    #[test]
    fn path_adapter_rejects_replaced_parent_symlinks_and_writable_root() {
        let t = {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/cluster-test-tmp");
            std::fs::create_dir_all(&path).unwrap();
            tempfile::tempdir_in(path).unwrap()
        };
        let base = std::fs::canonicalize(t.path()).unwrap();
        let root = base.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = uid().unwrap();
        let d = Dir::walk(root.to_str().unwrap(), owner, true, true, true).unwrap();
        d.write("state.json", b"verified", 0o600).unwrap();
        let child = d.child("stage").unwrap();
        child.write("module", b"native", 0o600).unwrap();
        d.rename("stage", "generation").unwrap();
        assert_eq!(d.read("state.json", 8, 0o600).unwrap(), b"verified");
        symlink("state.json", root.join("alias")).unwrap();
        assert!(d.read("alias", 8, 0o600).is_err());
        assert!(d.write("alias", b"evil", 0o600).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(d.write("state.json", b"evil", 0o600).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&root, base.join("retained")).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(d.write("state.json", b"evil", 0o600).is_err());
        assert!(!root.join("state.json").exists());
        std::fs::remove_dir(&root).unwrap();
        symlink(base.join("retained"), &root).unwrap();
        assert!(d.read("state.json", 8, 0o600).is_err());
    }
}
