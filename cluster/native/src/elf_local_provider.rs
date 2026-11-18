//! Read-only proof for an already loaded GNU exception owner. Never loads a new
//! owner, patches code, or supplies a replacement unwind implementation.
use super::{checked_mapped_function, function_bytes, local_function, MappedLoad};
use crate::Result;

pub fn prove(
    file: &[u8],
    base: u64,
    anchor: u64,
    loads: &[MappedLoad],
    forbidden: u64,
    mut mapped: impl FnMut(u64, usize) -> Result<alloc::vec::Vec<u8>>,
) -> Result<u64> {
    let symbol = local_function(file, "_Unwind_Resume", "__gxx_personality_v0")?;
    let target = checked_mapped_function(file, symbol, base, anchor, loads, forbidden)?;
    for (relative, length) in [
        (symbol.value, symbol.size),
        (symbol.anchor_value, symbol.anchor_size),
    ] {
        let expected = function_bytes(file, relative, length)?;
        let address = base
            .checked_add(relative)
            .ok_or("mapped bytes address overflow")?;
        if mapped(address, expected.len())?.as_slice() != expected {
            return Err("mapped owner function bytes differ".into());
        }
    }
    Ok(target)
}

#[cfg(any(target_os = "nto", test))]
fn claim(slot: &core::sync::atomic::AtomicUsize, address: usize, forbidden: usize) -> Result<bool> {
    use core::sync::atomic::Ordering;
    if address == 0 || address == forbidden {
        return Err("invalid provider publication".into());
    }
    match slot.compare_exchange(0, address, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(true),
        Err(existing) if existing == address => Ok(false),
        Err(_) => Err("provider changed during preparation".into()),
    }
}
#[cfg(target_os = "nto")]
mod qnx {
    use super::*;
    use alloc::vec::Vec;
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicUsize, Ordering};
    const GNU_PATH: &core::ffi::CStr = c"/usr/lib64/libstdc++.so.6";

    #[no_mangle]
    pub static VBC_I18N_UNWIND_TARGET: AtomicUsize = AtomicUsize::new(0);
    struct Pin(*mut c_void);
    impl Drop for Pin {
        fn drop(&mut self) {
            unsafe {
                libc::dlclose(self.0);
            }
        }
    }
    #[derive(Default)]
    struct Owner {
        base: u64,
        anchor: u64,
        found: bool,
        failed: bool,
        loads: Vec<MappedLoad>,
    }
    unsafe extern "C" fn headers(
        info: *mut libc::dl_phdr_info,
        size: usize,
        data: *mut c_void,
    ) -> i32 {
        if info.is_null() || data.is_null() || size < core::mem::size_of::<libc::dl_phdr_info>() {
            return 0;
        }
        let out = &mut *(data as *mut Owner);
        let view = &*info;
        if view.dlpi_phnum == 0 || view.dlpi_phnum > 128 || view.dlpi_phdr.is_null() {
            return 0;
        }
        let headers = core::slice::from_raw_parts(view.dlpi_phdr, view.dlpi_phnum as usize);
        let owners = headers
            .iter()
            .filter(|p| {
                p.p_type == 1
                    && p.p_flags & 5 == 5
                    && view.dlpi_addr.checked_add(p.p_vaddr).is_some_and(|start| {
                        out.anchor
                            .checked_sub(start)
                            .is_some_and(|offset| offset < p.p_filesz)
                    })
            })
            .count();
        if owners == 0 {
            return 0;
        }
        if owners != 1 || out.found {
            out.failed = true;
            return 1;
        }
        out.found = true;
        out.base = view.dlpi_addr;
        // Capacity is allocated before entering the loader callback.
        for p in headers {
            if p.p_type == 1 {
                out.loads.push(MappedLoad {
                    address: p.p_vaddr,
                    offset: p.p_offset,
                    files: p.p_filesz,
                    memory: p.p_memsz,
                    flags: p.p_flags,
                });
            }
        }
        0
    }
    /// Explicit worker operation; caller must not invoke on the owning UI frame.
    /// Success retains the actual loader reference for process lifetime.
    pub fn prepare(forbidden: usize) -> Result<usize> {
        if let value @ 1.. = VBC_I18N_UNWIND_TARGET.load(Ordering::Acquire) {
            return if value != forbidden {
                Ok(value)
            } else {
                Err("cached provider is forbidden".into())
            };
        }
        let flags = libc::RTLD_NOW | libc::RTLD_NOLOAD;
        let mut handle = unsafe { libc::dlopen(GNU_PATH.as_ptr(), flags) };
        if handle.is_null() {
            handle = unsafe { libc::dlopen(c"libstdc++.so.6".as_ptr(), flags) };
        }
        if handle.is_null() {
            return Err("GNU owner not already loaded".into());
        }
        let pin = Pin(handle);
        let anchor = unsafe { libc::dlsym(handle, b"__gxx_personality_v0\0".as_ptr().cast()) };
        if anchor.is_null() {
            return Err("GNU owner anchor unavailable".into());
        }
        // The fixed OEM name contains '+'. Paths supplied by callers still use
        // the restricted reader. The anchor, headers, and bytes bind this file
        // to the actual mapped owner.
        let file = super::super::read_file(GNU_PATH, 64 * 1024 * 1024)?;
        let mut owner = Owner {
            anchor: anchor as u64,
            loads: Vec::with_capacity(128),
            ..Owner::default()
        };
        unsafe {
            libc::dl_iterate_phdr(Some(headers), (&mut owner as *mut Owner).cast());
        }
        if !owner.found || owner.failed {
            return Err("GNU mapped owner headers unavailable".into());
        }
        let address = prove(
            &file,
            owner.base,
            anchor as u64,
            &owner.loads,
            forbidden as u64,
            |at, len| {
                // prove checked this exact range against the pinned loader's RX
                // file-backed segment before this callback can be reached.
                Ok(unsafe { core::slice::from_raw_parts(at as *const u8, len) }.to_vec())
            },
        )? as usize;
        if claim(&VBC_I18N_UNWIND_TARGET, address, forbidden)? {
            core::mem::forget(pin);
        }
        Ok(address)
    }
}
#[cfg(target_os = "nto")]
pub use qnx::prepare;

/// Explicit admission-worker operation shared by all GNU C++ consumers. It
/// prepares only the original exception provider, never locale/resource probes.
pub fn prepare_shared_exception_provider() -> Result<()> {
    #[cfg(target_os = "nto")]
    return preparation::prepare_sync();
    #[cfg(not(target_os = "nto"))]
    Err("GNU owner proof requires QNX".into())
}

/// Constant-time readonly capability. No worker, loader/file I/O or locale
/// identity preparation runs as a side effect of a module's UI-frame lookup.
#[no_mangle]
pub extern "C" fn vbc_gnu_exception_resume() -> *mut core::ffi::c_void {
    #[cfg(target_os = "nto")]
    {
        if preparation::vbc_i18n_exception_provider_ready() == 1 {
            return qnx::VBC_I18N_UNWIND_TARGET.load(core::sync::atomic::Ordering::Acquire)
                as *mut core::ffi::c_void;
        }
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    #[cfg(not(target_os = "nto"))]
    #[test]
    fn common_resume_capability_has_no_host_or_locale_fallback() {
        assert!(vbc_gnu_exception_resume().is_null());
        assert!(prepare_shared_exception_provider().is_err());
        assert!(vbc_gnu_exception_resume().is_null());
    }
    #[test]
    fn publication_has_one_pin_owner_and_rejects_changed_or_self_target() {
        let slot = std::sync::Arc::new(AtomicUsize::new(0));
        let winners = std::sync::Arc::new(AtomicUsize::new(0));
        let mut threads = alloc::vec::Vec::new();
        for _ in 0..16 {
            let slot = slot.clone();
            let winners = winners.clone();
            threads.push(std::thread::spawn(move || {
                if claim(&slot, 0x1000, 0x2000).unwrap() {
                    winners.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(winners.load(Ordering::SeqCst), 1);
        assert!(claim(&slot, 0x3000, 0x2000).is_err());
        assert!(claim(&slot, 0x1000, 0x1000).is_err());
        assert!(claim(&slot, 0, 0x2000).is_err());
    }
}

#[cfg(all(target_os = "nto", target_arch = "aarch64"))]
core::arch::global_asm!(
    r#"
.section .text.vbc_i18n_unwind,"ax",@progbits
.p2align 2
.global _Unwind_Resume
.hidden _Unwind_Resume
.hidden VBC_I18N_UNWIND_TARGET
.type _Unwind_Resume,@function
_Unwind_Resume:
    adrp x16, VBC_I18N_UNWIND_TARGET
    add x16, x16, :lo12:VBC_I18N_UNWIND_TARGET
    ldar x16, [x16]
    cbz x16, 1f
    br x16
1:
    b abort
.size _Unwind_Resume, .-_Unwind_Resume
"#
);

#[cfg(target_os = "nto")]
mod preparation {
    use core::ffi::c_void;
    use core::sync::atomic::{AtomicU8, Ordering};
    static STATE: AtomicU8 = AtomicU8::new(0);
    extern "C" {
        fn _Unwind_Resume(exception: *mut c_void) -> !;
    }
    fn prepare() -> crate::Result<()> {
        let result = super::qnx::prepare(_Unwind_Resume as *const () as usize);
        if result.is_ok() {
            STATE.store(2, Ordering::Release);
        } else {
            let _ = STATE.compare_exchange(1, 3, Ordering::AcqRel, Ordering::Acquire);
        }
        result.map(|_| ())
    }

    extern "C" fn worker(_: *mut c_void) -> *mut c_void {
        let _ = prepare();
        core::ptr::null_mut()
    }

    pub(super) fn prepare_sync() -> crate::Result<()> {
        if STATE.load(Ordering::Acquire) == 2 {
            return Ok(());
        }
        let _ = STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
        prepare()
    }

    #[no_mangle]
    pub extern "C" fn vbc_i18n_prepare_exception_provider_sync() -> i32 {
        i32::from(prepare_sync().is_ok())
    }
    #[no_mangle]
    pub extern "C" fn vbc_i18n_exception_provider_ready() -> i32 {
        i32::from(STATE.load(Ordering::Acquire) == 2)
    }
    /// Explicit startup request. Observer installation must await ready==1 on
    /// its owning UI thread; this function never installs a hook itself.
    #[no_mangle]
    pub extern "C" fn vbc_i18n_prepare_exception_provider() -> i32 {
        if STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let started = unsafe {
                let mut attributes = core::mem::zeroed();
                if libc::pthread_attr_init(&mut attributes) != 0 {
                    false
                } else {
                    let mut thread = core::mem::zeroed();
                    let ok = libc::pthread_attr_setdetachstate(
                        &mut attributes,
                        libc::PTHREAD_CREATE_DETACHED,
                    ) == 0
                        && libc::pthread_create(
                            &mut thread,
                            &attributes,
                            worker,
                            core::ptr::null_mut(),
                        ) == 0;
                    libc::pthread_attr_destroy(&mut attributes);
                    ok
                }
            };
            if !started {
                let _ = STATE.compare_exchange(1, 3, Ordering::AcqRel, Ordering::Acquire);
            }
        }
        match STATE.load(Ordering::Acquire) {
            2 => 1,
            3 => 0,
            _ => -1,
        }
    }
}
