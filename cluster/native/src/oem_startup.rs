//! Structurally probed startup editing with a bounded writable mount transaction.
//! The installer root principal is trusted; no protection against hostile uid0
//! remounting or renaming paths concurrently is claimed.
use crate::Result;
#[cfg(any(target_os = "nto", test))]
use alloc::string::String;

#[cfg(any(target_os = "nto", test))]
trait Edit {
    fn writable(&mut self) -> Result<()>;
    fn verify_writable(&mut self) -> Result<()>;
    fn replace(&mut self) -> Result<()>;
    fn rollback(&mut self) -> Result<()>;
    fn readonly(&mut self) -> Result<()>;
    fn verify_readonly(&mut self) -> Result<()>;
    fn verify_before(&mut self) -> Result<()>;
    fn verify_after(&mut self) -> Result<()>;
}
#[cfg(any(target_os = "nto", test))]
#[derive(Debug)]
enum ExecuteOutcome {
    Applied,
    RolledBack(String),
    RecoveryRequired(String),
}
#[cfg(any(target_os = "nto", test))]
fn restore_ro(edit: &mut impl Edit) -> Result<()> {
    edit.readonly()?;
    edit.verify_readonly()
}
#[cfg(any(target_os = "nto", test))]
fn execute(edit: &mut impl Edit) -> ExecuteOutcome {
    let operation = (|| {
        edit.writable()?;
        edit.verify_writable()?;
        edit.replace()
    })();
    if let Err(error) = operation {
        let rollback = edit.rollback();
        let restoration = restore_ro(edit);
        if rollback.is_ok() && restoration.is_ok() && edit.verify_before().is_ok() {
            return ExecuteOutcome::RolledBack(error);
        }
        return ExecuteOutcome::RecoveryRequired(
            "SetupRequired: OEM rollback/RO verification incomplete; journal retained".into(),
        );
    }
    if restore_ro(edit).is_err() {
        // A failed remount may have changed flags despite its return value.
        // Re-establish and verify RW before attempting exact rollback.
        let rollback = (|| {
            edit.writable()?;
            edit.verify_writable()?;
            edit.rollback()
        })();
        let restoration = restore_ro(edit);
        if restoration.is_err() || rollback.is_err() || edit.verify_before().is_err() {
            return ExecuteOutcome::RecoveryRequired(
                "SetupRequired: OEM rollback/RO verification incomplete; journal retained".into(),
            );
        }
        return ExecuteOutcome::RolledBack(
            "OEM edit rolled back after RO restoration failure".into(),
        );
    }
    match edit.verify_after() {
        Ok(()) => ExecuteOutcome::Applied,
        Err(error) => ExecuteOutcome::RecoveryRequired(error),
    }
}

#[cfg(any(target_os = "nto", test))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MountIdentity {
    flags: u64,
    filesystem_id: u64,
    root_device: String,
    root_inode: u64,
    root_mode: u32,
    root_uid: u32,
    root_gid: u32,
    parent_device: String,
    parent_inode: u64,
    parent_mode: u32,
    parent_uid: u32,
    parent_gid: u32,
}
#[cfg(any(target_os = "nto", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
enum JournalState {
    Prepared,
    Applied,
    RolledBack,
}
#[cfg(any(target_os = "nto", test))]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    transaction_id: String,
    startup_file: String,
    before_sha256: String,
    after_sha256: String,
    mount: MountIdentity,
    state: JournalState,
}
#[cfg(any(target_os = "nto", test))]
fn recover_journal(
    previous: &mut Journal,
    observed: &MountIdentity,
    current_sha256: &str,
    mut persist: impl FnMut(&Journal) -> Result<()>,
) -> Result<()> {
    use voboost_contract_core::digest;
    if previous.schema_version != 2
        || !digest(&previous.transaction_id)
        || previous.startup_file != "/scripts/startup_cluster.sh"
        || !digest(&previous.before_sha256)
        || !digest(&previous.after_sha256)
        || &previous.mount != observed
    {
        return Err("SetupRequired: OEM journal recovery authority/identity differs".into());
    }
    let state = if current_sha256 == previous.after_sha256 {
        JournalState::Applied
    } else if current_sha256 == previous.before_sha256 {
        JournalState::RolledBack
    } else {
        return Err("SetupRequired: OEM journal current startup digest is unknown".into());
    };
    if previous.state != JournalState::Prepared && previous.state != state
        // A no-op restore has the same before and after bytes.
        && previous.before_sha256 != previous.after_sha256
    {
        return Err("SetupRequired: OEM terminal journal contradicts startup bytes".into());
    }
    if previous.state == JournalState::Prepared {
        previous.state = state;
        persist(previous)?;
    }
    Ok(())
}
#[cfg(any(target_os = "nto", test))]
fn finish_journal(
    journal: &mut Journal,
    outcome: ExecuteOutcome,
    mut persist: impl FnMut(&Journal) -> Result<()>,
) -> Result<()> {
    match outcome {
        ExecuteOutcome::Applied => {
            journal.state = JournalState::Applied;
            persist(journal)
        }
        ExecuteOutcome::RolledBack(error) => {
            journal.state = JournalState::RolledBack;
            persist(journal)?;
            Err(error)
        }
        ExecuteOutcome::RecoveryRequired(error) => Err(error),
    }
}

#[cfg(target_os = "nto")]
mod qnx {
    use super::*;
    use crate::fs::{Dir, Fd};
    use alloc::{format, vec::Vec};
    use voboost_contract_core::{ascii_json, hash, parse_canonical};

    // Verified QNX libc API, not a guessed _MOUNT_REMOUNT/ioctl constant:
    // https://qnx.com/developers/docs/7.1/com.qnx.doc.neutrino.lib_ref/topic/m/mount_parse_generic_args.html
    extern "C" {
        fn mount_parse_generic_args(
            options: *mut libc::c_char,
            flags: *mut libc::c_int,
        ) -> *mut libc::c_char;
    }
    struct Native<'a> {
        root_fd: Fd,
        root_stat: libc::stat,
        parent: &'a Dir,
        parent_stat: libc::stat,
        filesystem_id: u64,
        flags: u64,
        before: &'a [u8],
        after: &'a [u8],
        mode: u32,
    }
    fn identity(a: &libc::stat, b: &libc::stat) -> bool {
        a.st_dev == b.st_dev
            && a.st_ino == b.st_ino
            && a.st_mode == b.st_mode
            && a.st_uid == b.st_uid
            && a.st_gid == b.st_gid
    }
    fn filesystem(fd: i32) -> Result<libc::statvfs> {
        let mut value = unsafe { core::mem::zeroed::<libc::statvfs>() };
        if unsafe { libc::fstatvfs(fd, &mut value) } != 0 {
            return Err("SetupRequired: OEM filesystem flags unavailable".into());
        }
        let end = value
            .f_basetype
            .iter()
            .position(|v| *v == 0)
            .ok_or("OEM filesystem type is unterminated")?;
        let name: alloc::vec::Vec<u8> = value.f_basetype[..end].iter().map(|v| *v as u8).collect();
        if name != b"qnx6" {
            return Err("SetupRequired: OEM filesystem is not qnx6".into());
        }
        Ok(value)
    }
    impl Native<'_> {
        fn identities(&self) -> Result<()> {
            let mut path = unsafe { core::mem::zeroed::<libc::stat>() };
            if unsafe { libc::lstat(b"/\0".as_ptr().cast(), &mut path) } != 0
                || !identity(&self.root_stat, &path)
                || !identity(&self.root_stat, &crate::fs::stat(self.root_fd.0)?)
            {
                return Err("SetupRequired: OEM root identity changed".into());
            }
            if unsafe { libc::lstat(b"/scripts\0".as_ptr().cast(), &mut path) } != 0
                || !identity(&self.parent_stat, &path)
                || !identity(&self.parent_stat, &crate::fs::stat(self.parent.fd.0)?)
            {
                return Err("SetupRequired: OEM startup parent identity changed".into());
            }
            for fd in [self.root_fd.0, self.parent.fd.0] {
                if filesystem(fd)?.f_fsid as u64 != self.filesystem_id {
                    return Err("SetupRequired: OEM filesystem identity changed".into());
                }
            }
            Ok(())
        }
        fn flags(&self, readonly: bool) -> u64 {
            if readonly {
                self.flags
            } else {
                self.flags & !(libc::ST_RDONLY as u64)
            }
        }
        fn verify(&self, readonly: bool) -> Result<()> {
            self.identities()?;
            for fd in [self.root_fd.0, self.parent.fd.0] {
                if filesystem(fd)?.f_flag as u64 != self.flags(readonly) {
                    return Err("SetupRequired: OEM mount flags differ".into());
                }
            }
            Ok(())
        }
        fn remount(&self, readonly: bool) -> Result<()> {
            if self.flags & libc::ST_RDONLY as u64 == 0 {
                return self.verify(readonly);
            }
            self.identities()?;
            let requested = self.flags(readonly);
            let mut flags = i32::try_from(requested).map_err(|_| "OEM mount flags exceed ABI")?;
            let mut option = *b"remount\0";
            if !unsafe { mount_parse_generic_args(option.as_mut_ptr().cast(), &mut flags) }
                .is_null()
                || flags < 0
                || (flags as u64 & requested) != requested
                || ((flags as u64) & !requested).count_ones() != 1
            {
                return Err("SetupRequired: OEM libc remount option unavailable".into());
            }
            // QNX-authored standard mount -u implementation sends NULL special
            // and NULL extra options using the string-options protocol (-1):
            // https://raw.githubusercontent.com/vocho/openqnx/master/trunk/utils/m/mount/mount.c
            // lines 283-305, 570-578, 607. This is an update of the existing
            // mounted filesystem, not a new mount or an option replay.
            // Official usage: https://get.qnx.com/developers/docs/7.0.0/com.qnx.doc.neutrino.user_guide/topic/fsystems_Mounting.html
            // fstatvfs _MOUNT_*/ST_* equivalence (seven stored flags):
            // https://www.qnx.com/developers/docs/7.1/com.qnx.doc.neutrino.lib_ref/topic/f/fstatvfs.html
            if unsafe {
                libc::mount(
                    core::ptr::null(),
                    b"/\0".as_ptr().cast(),
                    flags,
                    b"qnx6\0".as_ptr().cast(),
                    core::ptr::null(),
                    -1,
                )
            } != 0
            {
                return Err("SetupRequired: OEM filesystem remount failed".into());
            }
            Ok(())
        }
        fn bytes(&self) -> Result<Vec<u8>> {
            self.identities()?;
            self.parent
                .read("startup_cluster.sh", 1024 * 1024, self.mode)
        }
        fn mount_identity(&self) -> Result<MountIdentity> {
            Ok(MountIdentity {
                flags: self.flags,
                filesystem_id: self.filesystem_id,
                root_device: format!("{}", self.root_stat.st_dev),
                root_inode: self.root_stat.st_ino as u64,
                root_mode: self.root_stat.st_mode as u32,
                root_uid: u32::try_from(self.root_stat.st_uid)
                    .map_err(|_| "OEM root UID invalid")?,
                root_gid: u32::try_from(self.root_stat.st_gid)
                    .map_err(|_| "OEM root GID invalid")?,
                parent_device: format!("{}", self.parent_stat.st_dev),
                parent_inode: self.parent_stat.st_ino as u64,
                parent_mode: self.parent_stat.st_mode as u32,
                parent_uid: u32::try_from(self.parent_stat.st_uid)
                    .map_err(|_| "OEM parent UID invalid")?,
                parent_gid: u32::try_from(self.parent_stat.st_gid)
                    .map_err(|_| "OEM parent GID invalid")?,
            })
        }
    }
    impl Edit for Native<'_> {
        fn writable(&mut self) -> Result<()> {
            self.remount(false)
        }
        fn verify_writable(&mut self) -> Result<()> {
            self.verify(false)
        }
        fn replace(&mut self) -> Result<()> {
            self.verify(false)?;
            if self.bytes()? != self.before {
                return Err("OEM startup changed before commit".into());
            }
            self.parent
                .write("startup_cluster.sh", self.after, self.mode)?;
            if self.bytes()? != self.after {
                return Err("OEM startup commit readback differs".into());
            }
            Ok(())
        }
        fn rollback(&mut self) -> Result<()> {
            self.identities()?;
            let current = self.bytes()?;
            if current == self.before {
                return Ok(());
            }
            self.verify(false)?;
            if current != self.after {
                return Err("OEM startup changed outside transaction".into());
            }
            self.parent
                .write("startup_cluster.sh", self.before, self.mode)?;
            if self.bytes()? != self.before {
                return Err("OEM startup rollback readback differs".into());
            }
            Ok(())
        }
        fn readonly(&mut self) -> Result<()> {
            self.remount(true)
        }
        fn verify_readonly(&mut self) -> Result<()> {
            self.verify(true)
        }
        fn verify_before(&mut self) -> Result<()> {
            self.verify(true)?;
            if self.bytes()? != self.before {
                return Err("OEM rollback final bytes differ".into());
            }
            Ok(())
        }
        fn verify_after(&mut self) -> Result<()> {
            self.verify(true)?;
            if self.bytes()? != self.after {
                return Err("OEM commit final bytes differ".into());
            }
            Ok(())
        }
    }
    pub(super) fn write(
        input: &crate::install::Integration,
        parent: &Dir,
        before: &[u8],
        after: &[u8],
        mode: u32,
        store: &Dir,
    ) -> Result<()> {
        if crate::fs::uid()? != 0
            || input.startup_file != "/scripts/startup_cluster.sh"
            || parent.path != "/scripts"
            || !matches!(
                input.startup_profile,
                Some(crate::install::StartupProfile::Clusterboot)
            )
        {
            return Err("SetupRequired: typed OEM startup authority unavailable".into());
        }
        let original = if voboost_contract_core::hash(before) == input.original_sha256 {
            before
        } else if voboost_contract_core::hash(after) == input.original_sha256 {
            after
        } else {
            return Err("SetupRequired: OEM edit differs from transaction original".into());
        };
        crate::install::probe_clusterboot_startup(original)?;
        let root_fd = Fd(unsafe {
            libc::open(
                b"/\0".as_ptr().cast(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        });
        if root_fd.0 < 0 {
            return Err("OEM root descriptor unavailable".into());
        }
        let root_stat = crate::fs::stat(root_fd.0)?;
        let parent_stat = crate::fs::stat(parent.fd.0)?;
        let fs = filesystem(root_fd.0)?;
        if root_stat.st_uid != 0
            || parent_stat.st_uid != 0
            || root_stat.st_dev != parent_stat.st_dev
            || root_stat.st_gid != 0
            || parent_stat.st_gid != 0
            || root_stat.st_mode & 0o002 != 0
            || parent_stat.st_mode & 0o002 != 0
        {
            return Err("SetupRequired: OEM root or parent authority differs".into());
        }
        // Exact original backup is persistent before any writable mount request.
        let backup = store.read("startup.original", 1024 * 1024, 0o600)?;
        if hash(&backup) != input.original_sha256 {
            return Err("OEM persistent backup differs".into());
        }
        let mut edit = Native {
            root_fd,
            root_stat,
            parent,
            parent_stat,
            filesystem_id: fs.f_fsid as u64,
            flags: fs.f_flag as u64,
            before,
            after,
            mode,
        };
        edit.verify(true)?;
        if edit.bytes()? != before {
            return Err("OEM startup preflight differs".into());
        }
        let mount = edit.mount_identity()?;
        if store.exists("startup-edit.json")? {
            let mut previous: Journal =
                parse_canonical(&store.read("startup-edit.json", 16384, 0o600)?, 16384)?;
            // Current bytes were already admitted by installation proof and the
            // caller's exact before readback. Recover only the same mount,
            // root and parent identities; never blindly retry an unknown state.
            recover_journal(&mut previous, &mount, &hash(before), |journal| {
                store.write("startup-edit.json", &ascii_json(journal)?, 0o600)
            })?;
        }
        let mut journal = Journal {
            schema_version: 2,
            transaction_id: input.transaction_id.clone(),
            startup_file: input.startup_file.clone(),
            before_sha256: hash(before),
            after_sha256: hash(after),
            mount,
            state: JournalState::Prepared,
        };
        store.write("startup-edit.json", &ascii_json(&journal)?, 0o600)?;
        let outcome = if before == after {
            // Official restore after a proven rolled-back install is a no-op.
            // Verify the complete terminal state without opening a RW window.
            match edit.verify_after() {
                Ok(()) => ExecuteOutcome::Applied,
                Err(error) => ExecuteOutcome::RecoveryRequired(error),
            }
        } else {
            execute(&mut edit)
        };
        finish_journal(&mut journal, outcome, |record| {
            store.write("startup-edit.json", &ascii_json(record)?, 0o600)
        })
    }
}
pub fn write(
    input: &crate::install::Integration,
    parent: &crate::fs::Dir,
    before: &[u8],
    after: &[u8],
    mode: u32,
    store: &crate::fs::Dir,
) -> Result<()> {
    #[cfg(target_os = "nto")]
    {
        qnx::write(input, parent, before, after, mode, store)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = (input, parent, before, after, mode, store);
        Err("SetupRequired: typed OEM mount editing is QNX-only".into())
    }
}

#[cfg(test)]
#[path = "../../tests/oem_startup.rs"]
mod tests;
