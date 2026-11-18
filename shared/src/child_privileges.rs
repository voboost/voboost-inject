//! Child-only, fail-closed privilege reduction before exec.
use std::io;

#[cfg(any(target_os = "android", target_os = "linux", test))]
trait CapabilityOps {
    fn no_new_privileges(&mut self) -> io::Result<()>;
    fn clear(&mut self) -> io::Result<()>;
    fn is_clear(&mut self) -> io::Result<bool>;
}
#[cfg(any(target_os = "android", target_os = "linux", test))]
fn drop_with(ops: &mut impl CapabilityOps) -> io::Result<()> {
    ops.no_new_privileges()?;
    ops.clear()?;
    if !ops.is_clear()? {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod native {
    use super::*;
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    pub(super) struct Syscalls;
    fn checked(result: libc::c_long) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
    impl CapabilityOps for Syscalls {
        fn no_new_privileges(&mut self) -> io::Result<()> {
            checked(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } as libc::c_long)
        }
        fn clear(&mut self) -> io::Result<()> {
            let header = Header {
                version: 0x2008_0522,
                pid: 0,
            };
            let zero = [Data::default(); 2];
            checked(unsafe { libc::syscall(libc::SYS_capset, &header, zero.as_ptr()) })
        }
        fn is_clear(&mut self) -> io::Result<bool> {
            let header = Header {
                version: 0x2008_0522,
                pid: 0,
            };
            let mut data = [Data::default(); 2];
            checked(unsafe { libc::syscall(libc::SYS_capget, &header, data.as_mut_ptr()) })?;
            Ok(data
                .iter()
                .all(|slot| slot.effective == 0 && slot.permitted == 0 && slot.inheritable == 0))
        }
    }
}

/// Only raw syscalls and stack locals: suitable for Command::pre_exec.
/// Clearing permitted/inheritable bits also clears their ambient capabilities.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn drop_for_exec() -> io::Result<()> {
    drop_with(&mut native::Syscalls)
}
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub(crate) fn drop_for_exec() -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOTSUP))
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        fail: u8,
        calls: [u8; 3],
        len: usize,
        clear: bool,
    }
    impl Fake {
        fn step(&mut self, step: u8) -> io::Result<()> {
            self.calls[self.len] = step;
            self.len += 1;
            if self.fail == step {
                Err(io::Error::from_raw_os_error(libc::EACCES))
            } else {
                Ok(())
            }
        }
    }
    impl CapabilityOps for Fake {
        fn no_new_privileges(&mut self) -> io::Result<()> {
            self.step(1)
        }
        fn clear(&mut self) -> io::Result<()> {
            self.step(2)
        }
        fn is_clear(&mut self) -> io::Result<bool> {
            self.step(3)?;
            Ok(self.clear)
        }
    }
    #[test]
    fn every_failed_step_prevents_following_steps() {
        for fail in 1..=3 {
            let mut ops = Fake {
                fail,
                calls: [0; 3],
                len: 0,
                clear: true,
            };
            assert!(drop_with(&mut ops).is_err());
            assert_eq!(ops.len, usize::from(fail));
            assert_eq!(&ops.calls[..ops.len], &[1, 2, 3][..ops.len]);
        }
        let mut ops = Fake {
            fail: 0,
            calls: [0; 3],
            len: 0,
            clear: false,
        };
        assert!(drop_with(&mut ops).is_err());
        ops.len = 0;
        ops.clear = true;
        assert!(drop_with(&mut ops).is_ok());
    }
}
