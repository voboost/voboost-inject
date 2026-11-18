//! Process-lifetime resource ABI proof. Expensive preparation is worker-only;
//! published callbacks do no loader, filesystem, ELF or UI work.
use crate::{
    pw_readback_types::Field,
    resource_content_calls as calls,
    resource_content_types::{self, DestructorEvidence, TypeEvidence},
    Result,
};
use alloc::vec::Vec;

pub struct FileProof {
    types: TypeEvidence,
    functions: Vec<(&'static str, u64)>,
}
impl FileProof {
    pub fn inspect(executable: &[u8], core: &[u8], gnu: &[u8]) -> Result<Self> {
        let types = resource_content_types::inspect(executable)?;
        if types.destructor() == DestructorEvidence::RequiresStructuralCleanup {
            crate::resource_content_cleanup::inspect(core)?;
        }
        let methods = calls::inspect_typed(executable, core, gnu)?;
        let mut functions = Vec::new();
        for name in [
            calls::CONSTRUCTOR,
            calls::CONTAINS,
            calls::FIND,
            calls::DESTROY,
            calls::DATA,
            calls::SIZE,
        ] {
            functions.push((
                name,
                methods.address(name).ok_or("resource ABI method absent")?,
            ));
        }
        Ok(Self { types, functions })
    }
    pub fn relative(&self, name: &str) -> Option<u64> {
        self.functions
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, at)| *at)
    }
    pub fn query(&self, ty: &str, member: &str) -> Option<Field> {
        match (ty, member) {
            ("ResourceID", "$memberOnlyCleanup") => Some(Field {
                kind: 10,
                bytes: 0,
                offset: 0,
                count: 1,
            }),
            // Alignment divides object size. 48-byte/32-byte objects therefore need no
            // more than 16/32 alignment, so 32-aligned storage is sufficient for both.
            ("ResourceID" | "std::__cxx11::string", "$storageAlignment") => Some(Field {
                kind: 11,
                bytes: 32,
                offset: 0,
                count: 1,
            }),
            _ => self.types.query(ty, member),
        }
    }
}

#[cfg(target_os = "nto")]
mod qnx {
    use super::*;
    use crate::elf::{self, LocalFunction, MappedLoad};
    use alloc::{boxed::Box, ffi::CString, string::String};
    use core::{
        ffi::{c_char, c_void, CStr},
        sync::atomic::{AtomicPtr, AtomicU8, Ordering},
    };
    struct Pin(*mut c_void);
    impl Drop for Pin {
        fn drop(&mut self) {
            unsafe {
                libc::dlclose(self.0);
            }
        }
    }
    struct Source {
        file: Vec<u8>,
        base: u64,
        loads: Vec<MappedLoad>,
        owner: u32,
        pin: Pin,
    }
    #[derive(Default)]
    struct Headers {
        base: u64,
        anchor: u64,
        loads: Vec<MappedLoad>,
        found: bool,
        failed: bool,
    }
    unsafe extern "C" fn headers(
        info: *mut libc::dl_phdr_info,
        n: usize,
        data: *mut c_void,
    ) -> i32 {
        if info.is_null() || data.is_null() || n < core::mem::size_of::<libc::dl_phdr_info>() {
            return 0;
        }
        let out = &mut *(data as *mut Headers);
        let view = &*info;
        if view.dlpi_phnum == 0 || view.dlpi_phnum > 128 || view.dlpi_phdr.is_null() {
            return 0;
        }
        let belongs = core::slice::from_raw_parts(view.dlpi_phdr, view.dlpi_phnum as usize)
            .iter()
            .any(|p| {
                p.p_type == 1
                    && p.p_flags & 1 != 0
                    && view
                        .dlpi_addr
                        .checked_add(p.p_vaddr)
                        .is_some_and(|start| out.anchor >= start && out.anchor - start < p.p_memsz)
            });
        if !belongs {
            return 0;
        }
        out.base = view.dlpi_addr;

        if out.found || view.dlpi_phnum == 0 || view.dlpi_phnum > 128 || view.dlpi_phdr.is_null() {
            out.failed = true;
            return 1;
        }
        out.found = true;
        for p in core::slice::from_raw_parts(view.dlpi_phdr, view.dlpi_phnum as usize) {
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
    fn read_file(path: &str) -> Result<Vec<u8>> {
        if !voboost_contract_core::safe_path(path) {
            return Err("resource proof path".into());
        }
        let path = CString::new(path).map_err(|_| "resource proof path NUL")?;
        let fd =
            crate::fs::Fd(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) });
        if fd.0 < 0 {
            return Err("resource proof file unavailable".into());
        }
        let before = crate::fs::stat(fd.0)?;
        if before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_size <= 0
            || before.st_size > 64 * 1024 * 1024
        {
            return Err("resource proof file trust/bound".into());
        }
        let mut bytes = alloc::vec![0;before.st_size as usize];
        crate::fs::read_exact(fd.0, &mut bytes)?;
        if !crate::fs::unchanged(&before, &crate::fs::stat(fd.0)?) {
            return Err("resource proof file changed".into());
        }
        Ok(bytes)
    }
    unsafe fn bounded_string(p: *const c_char) -> Result<String> {
        if p.is_null() {
            return Err("resource owner name absent".into());
        }
        let mut n = 0;
        while n < 4096 && *p.add(n) != 0 {
            n += 1;
        }
        if n == 0 || n == 4096 {
            return Err("resource owner name bound".into());
        }
        CStr::from_ptr(p)
            .to_str()
            .map(alloc::string::ToString::to_string)
            .map_err(|_| "resource owner name UTF8".into())
    }
    impl Source {
        fn load(path: Option<&str>, anchor: &str) -> Result<Self> {
            let path = path
                .map(CString::new)
                .transpose()
                .map_err(|_| "resource provider NUL")?;
            let handle = unsafe {
                libc::dlopen(
                    path.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                    libc::RTLD_NOW | if path.is_some() { libc::RTLD_NOLOAD } else { 0 },
                )
            };
            if handle.is_null() {
                return Err("resource provider not loaded".into());
            }
            let pin = Pin(handle);
            let symbol = CString::new(anchor).map_err(|_| "resource anchor NUL")?;
            let at = unsafe { libc::dlsym(handle, symbol.as_ptr()) };
            if at.is_null() {
                return Err("resource anchor absent".into());
            }
            let mut info: libc::Dl_info = unsafe { core::mem::zeroed() };
            if unsafe { libc::dladdr(at, &mut info) } == 0 {
                return Err("resource mapped owner absent".into());
            }
            let actual = unsafe { bounded_string(info.dli_fname)? };
            let file = read_file(&actual)?;
            let mut h = Headers {
                anchor: at as u64,
                ..Headers::default()
            };
            unsafe {
                libc::dl_iterate_phdr(Some(headers), (&mut h as *mut Headers).cast());
            }
            if !h.found || h.failed || elf::file_loads(&file)? != h.loads {
                return Err("resource mapped PHDR mismatch".into());
            }
            // Bind executable DWARF and library code to actual loaded RX bytes, not only
            // one unchanged anchor. Pinned original mappings cannot be unloaded here.
            let mut remaining = 64 * 1024 * 1024u64;
            for load in &h.loads {
                if load.flags & 1 == 0 {
                    continue;
                }
                if load.flags & 4 == 0 {
                    return Err("resource RX unreadable".into());
                }
                remaining = remaining
                    .checked_sub(load.files)
                    .ok_or("resource RX work budget")?;
                let start = usize::try_from(load.offset).map_err(|_| "resource file offset")?;
                let len = usize::try_from(load.files).map_err(|_| "resource file extent")?;
                let expected = file
                    .get(start..start.checked_add(len).ok_or("resource RX overflow")?)
                    .ok_or("resource RX file range")?;
                let address = h
                    .base
                    .checked_add(load.address)
                    .ok_or("resource RX address")?;
                let mapped = unsafe { core::slice::from_raw_parts(address as *const u8, len) };
                if mapped != expected {
                    return Err("resource actual RX differs".into());
                }
            }
            let source = Self {
                file,
                base: h.base,
                loads: h.loads,
                owner: if path.is_none() {
                    match actual.as_str() {
                        "/usr/bin/gauge" => 1,
                        "/usr/bin/point" => 2,
                        "/usr/bin/light" => 3,
                        _ => return Err("resource executable symbol owner".into()),
                    }
                } else {
                    0
                },
                pin,
            };
            source.bind(anchor)?;
            Ok(source)
        }
        fn bind(&self, name: &str) -> Result<u64> {
            let symbol = CString::new(name).map_err(|_| "resource symbol NUL")?;
            let at = unsafe { libc::dlsym(self.pin.0, symbol.as_ptr()) };
            if at.is_null() {
                return Err("resource original method absent".into());
            }
            let code = crate::pw_readback_types::export_code(&self.file, name)?;
            let function = LocalFunction {
                value: code.address,
                size: code.code.len() as u64,
                anchor_value: code.address,
                anchor_size: code.code.len() as u64,
            };
            elf::checked_mapped_function(&self.file, function, self.base, at as u64, &self.loads, 0)
        }
    }
    struct Prepared {
        proof: FileProof,
        methods: Vec<(&'static str, u64)>,
        pid: u64,
        owner: u32,
        _sources: [Source; 3],
    }
    static PREPARED: AtomicPtr<Prepared> = AtomicPtr::new(core::ptr::null_mut());
    static STATE: AtomicU8 = AtomicU8::new(0);
    fn actual_owner() -> Result<u32> {
        let name = CString::new(alloc::format!("/proc/{}/exefile", unsafe {
            libc::getpid()
        }))
        .unwrap();
        let fd = crate::fs::Fd(unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        });
        if fd.0 < 0 {
            return Err("resource executable observation absent".into());
        }
        let mut buf = [0; 514];
        let n = unsafe { libc::read(fd.0, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 || n as usize == buf.len() {
            return Err("resource executable observation bound".into());
        }
        let value = &buf[..n as usize];
        let value = value.strip_suffix(&[0]).unwrap_or(value);
        let value = value.strip_suffix(b"\n").unwrap_or(value);
        match value {
            b"/usr/bin/gauge" => Ok(1),
            b"/usr/bin/point" => Ok(2),
            b"/usr/bin/light" => Ok(3),
            _ => Err("resource executable owner unsupported".into()),
        }
    }
    fn prepare() -> Result<Prepared> {
        if crate::elf::local_provider::prepare_shared_exception_provider().is_err() {
            return Err("resource GNU provider not ready".into());
        }
        let owner = actual_owner()?;
        let executable = Source::load(None, "_Z20getApplicationScreenv")?;
        let core = Source::load(Some("/lib64/libkzcoreui.so"), calls::CONSTRUCTOR)?;
        let gnu = Source::load(Some("/usr/lib64/libstdc++.so.6"), calls::DESTROY)?;
        if executable.owner != owner {
            return Err("resource executable owner mismatch".into());
        }
        let proof = FileProof::inspect(&executable.file, &core.file, &gnu.file)?;
        let mut methods = Vec::new();
        for (name, relative) in &proof.functions {
            let source = if matches!(*name, calls::CONSTRUCTOR | calls::CONTAINS | calls::FIND) {
                &core
            } else {
                &gnu
            };
            let actual = source.bind(name)?;
            if actual
                != source
                    .base
                    .checked_add(*relative)
                    .ok_or("resource method base overflow")?
            {
                return Err("resource method address mismatch".into());
            }
            methods.push((*name, actual));
        }
        Ok(Prepared {
            proof,
            methods,
            pid: unsafe { libc::getpid() } as u64,
            owner,
            _sources: [executable, core, gnu],
        })
    }
    pub fn prepare_sync() -> i32 {
        if STATE
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            match prepare() {
                Ok(p) => {
                    PREPARED.store(Box::into_raw(Box::new(p)), Ordering::Release);
                    STATE.store(2, Ordering::Release);
                }
                Err(error) => {
                    crate::diagnostic_log::emit("error", "resource-mapping", &error, &[]);
                    STATE.store(3, Ordering::Release)
                }
            }
        }
        if STATE.load(Ordering::Acquire) == 2 {
            1
        } else {
            0
        }
    }
    fn current() -> Option<&'static Prepared> {
        if STATE.load(Ordering::Acquire) != 2 {
            return None;
        }
        let p = unsafe { PREPARED.load(Ordering::Acquire).as_ref() }?;
        if p.pid != unsafe { libc::getpid() } as u64
            || p.owner != crate::locale_identity::vbc_locale_current_owner()
        {
            return None;
        }
        Some(p)
    }
    unsafe fn text<'a>(p: *const c_char) -> Option<&'a str> {
        if p.is_null() {
            return None;
        }
        let mut n = 0;
        while n < 1024 && *p.add(n) != 0 {
            n += 1;
        }
        if n == 1024 {
            return None;
        }
        core::str::from_utf8(core::slice::from_raw_parts(p.cast(), n)).ok()
    }
    extern "C" fn query(ty: *const c_char, member: *const c_char, out: *mut Field) -> i32 {
        if out.is_null() {
            return 0;
        }
        unsafe {
            *out = Field {
                kind: 0,
                bytes: 0,
                offset: 0,
                count: 0,
            };
        }
        let Some(p) = current() else {
            return 0;
        };
        let (Some(ty), Some(member)) = (unsafe { text(ty) }, unsafe { text(member) }) else {
            return 0;
        };
        let Some(field) = p.proof.query(ty, member) else {
            return 0;
        };
        unsafe {
            *out = field;
        }
        1
    }
    extern "C" fn function(name: *const c_char, address: *const c_void) -> i32 {
        let Some(p) = current() else {
            return 0;
        };
        let Some(name) = (unsafe { text(name) }) else {
            return 0;
        };
        i32::from(
            p.methods
                .iter()
                .any(|(n, at)| *n == name && *at == address as u64),
        )
    }
    extern "C" fn is_current() -> i32 {
        i32::from(current().is_some())
    }
    #[repr(C)]
    struct Api {
        abi: u32,
        size: u32,
        query: extern "C" fn(*const c_char, *const c_char, *mut Field) -> i32,
        function: extern "C" fn(*const c_char, *const c_void) -> i32,
        current: extern "C" fn() -> i32,
    }
    static API: Api = Api {
        abi: 1,
        size: core::mem::size_of::<Api>() as u32,
        query,
        function,
        current: is_current,
    };
    #[no_mangle]
    pub extern "C" fn vbc_resource_content_proof_v1() -> *const c_void {
        if current().is_some() {
            (&API as *const Api).cast()
        } else {
            core::ptr::null()
        }
    }
}
#[cfg(target_os = "nto")]
pub use qnx::prepare_sync;
#[cfg(not(target_os = "nto"))]
pub fn prepare_sync() -> i32 {
    0
}
#[cfg(not(target_os = "nto"))]
#[no_mangle]
pub extern "C" fn vbc_resource_content_proof_v1() -> *const core::ffi::c_void {
    core::ptr::null()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_sources_never_publish() {
        assert!(FileProof::inspect(&[], &[], &[]).is_err());
    }
    #[test]
    fn unsupported_host_is_unavailable() {
        assert_eq!(prepare_sync(), 0);
        assert!(vbc_resource_content_proof_v1().is_null());
    }
}
