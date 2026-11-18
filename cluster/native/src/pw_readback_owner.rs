//! Actual getter type proof bound to an already loaded, pinned OEM owner.
//! Offline/opt-in only until the startup hook/admission path is reviewed.
use crate::{
    elf::{self, LocalFunction, MappedLoad},
    pw_readback_types::{self, Family, Field, Proof},
    Result,
};
use alloc::vec::Vec;

pub struct OwnerProof {
    proof: Proof,
    original: u64,
    process: u64,
}
#[derive(Clone, Copy)]
pub struct LoadedGetter {
    pub process: u64,
    pub base: u64,
    pub symbol: u64,
    pub forbidden: u64,
}
impl OwnerProof {
    pub fn inspect(
        file: &[u8],
        family: Family,
        loaded: LoadedGetter,
        mapped_loads: &[MappedLoad],
        mut mapped: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let LoadedGetter {
            process,
            base,
            symbol,
            forbidden,
        } = loaded;
        if process == 0 {
            return Err("PW mapped process absent".into());
        }
        let proof = pw_readback_types::inspect(file, family)?;
        let relative = proof.address();
        let size = proof.code().len() as u64;
        let reference = LocalFunction {
            value: relative,
            size,
            anchor_value: relative,
            anchor_size: size,
        };
        let original =
            elf::checked_mapped_function(file, reference, base, symbol, mapped_loads, forbidden)?;
        if mapped(original, proof.code().len())?.as_slice() != proof.code() {
            return Err("PW actual mapped getter differs from type-proof owner".into());
        }
        Ok(Self {
            proof,
            original,
            process,
        })
    }
    pub fn original(&self) -> u64 {
        self.original
    }
    pub fn query(&self, process: u64, method: &str, ty: &str, member: &str) -> Option<Field> {
        (process == self.process)
            .then(|| self.proof.query(method, ty, member))
            .flatten()
    }
}

#[cfg(target_os = "nto")]
pub mod qnx {
    use super::*;
    use alloc::ffi::CString;
    use core::ffi::{c_char, c_void, CStr};
    struct Pin(*mut c_void);
    impl Drop for Pin {
        fn drop(&mut self) {
            unsafe {
                libc::dlclose(self.0);
            }
        }
    }
    pub struct Pinned {
        proof: OwnerProof,
        _pin: Pin,
    }
    pub(crate) struct PinnedInput {
        pub bytes: Vec<u8>,
        pub loaded: LoadedGetter,
        pub loads: Vec<MappedLoad>,
        _pin: Pin,
    }
    pub(crate) enum OwnerSymbol {
        EngineGetter(Family),
        LightScreen,
    }
    impl PinnedInput {
        pub(crate) fn resolve(&self, name: &str) -> Result<LoadedGetter> {
            if name.is_empty() || name.len() > 1024 {
                return Err("PW original method name bound".into());
            }
            let text = CString::new(name).map_err(|_| "PW original method name NUL")?;
            let symbol = unsafe { libc::dlsym(self._pin.0, text.as_ptr()) };
            if symbol.is_null() {
                return Err("PW original method absent".into());
            }
            Ok(LoadedGetter {
                symbol: symbol as u64,
                ..self.loaded
            })
        }
        pub(crate) fn discard_file(&mut self) {
            self.bytes.clear();
            self.bytes.shrink_to_fit();
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
            out.failed = true;
            return 1;
        }
        let entries = core::slice::from_raw_parts(view.dlpi_phdr, view.dlpi_phnum as usize);
        let matching = entries
            .iter()
            .filter(|p| {
                p.p_type == 1
                    && p.p_flags & 5 == 5
                    && view.dlpi_addr.checked_add(p.p_vaddr).is_some_and(|start| {
                        start <= out.anchor
                            && start
                                .checked_add(p.p_filesz)
                                .is_some_and(|end| out.anchor < end)
                    })
            })
            .count();
        if matching == 0 {
            return 0;
        }
        if matching != 1 || out.found {
            out.failed = true;
            return 1;
        }
        out.base = view.dlpi_addr;
        out.found = true;
        for p in entries {
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
    fn file(path: &str) -> Result<Vec<u8>> {
        if !voboost_contract_core::safe_path(path) {
            return Err("PW owner path rejected".into());
        }
        let name = CString::new(path).map_err(|_| "PW owner path NUL")?;
        // Canonical OEM names can be symlinks. The opened actual regular file
        // must be root-owned/non-writable and correspond to the pinned mapping.
        let fd =
            crate::fs::Fd(unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) });
        if fd.0 < 0 {
            return Err("PW original owner unavailable".into());
        }
        let before = crate::fs::stat(fd.0)?;
        if before.st_uid != 0
            || before.st_mode & 0o022 != 0
            || before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_size <= 0
            || before.st_size as u64 > 64 * 1024 * 1024
        {
            return Err("PW original owner trust/size".into());
        }
        let mut bytes = alloc::vec![0;before.st_size as usize];
        crate::fs::read_exact(fd.0, &mut bytes)?;
        if !crate::fs::unchanged(&before, &crate::fs::stat(fd.0)?) {
            return Err("PW original owner changed".into());
        }
        Ok(bytes)
    }
    /// Worker-only operation. No ELF/file/loader work on a UI frame. The returned
    /// value must outlive every installed wrapper and callback that uses it.
    pub(crate) fn pin_input(which: OwnerSymbol, forbidden: u64) -> Result<PinnedInput> {
        let (path, method) = match which {
            OwnerSymbol::EngineGetter(Family::Buffer) => (
                Some(b"/lib64/libenginecore.so\0".as_slice()),
                b"_ZN12CContextData7getDataEjPvj\0".as_slice(),
            ),
            OwnerSymbol::EngineGetter(Family::Object) => (
                Some(b"/lib64/libenginecore.so\0".as_slice()),
                b"_ZN12CContextData7getDataEjP15CTupMemTemplate\0".as_slice(),
            ),
            OwnerSymbol::LightScreen => (None, b"_Z20getApplicationScreenv\0".as_slice()),
        };
        pin_symbol(path, method, forbidden, None)
    }

    /// Resolve the selected export only after the current pinned mapping has
    /// been bound to the already verified cache input, without an export scan.
    pub(crate) fn pin_cached_lookup(
        path: &str,
        export: &str,
        bytes: Vec<u8>,
    ) -> Result<PinnedInput> {
        let path = CString::new(path).map_err(|_| "PW lookup path NUL")?;
        let mut input = pin_symbol(
            Some(path.as_bytes_with_nul()),
            b"_ZNK5kanzi4Node10isAttachedEv\0",
            0,
            Some(bytes),
        )?;
        let selected = input.resolve(export)?;
        let offset = selected
            .symbol
            .checked_sub(selected.base)
            .ok_or("PW lookup owner differs")?;
        if !input.loads.iter().any(|load| {
            load.flags & 5 == 5
                && offset
                    .checked_sub(load.address)
                    .is_some_and(|within| within < load.files)
        }) {
            return Err("PW lookup export is outside the verified executable mapping".into());
        }
        input.loaded = selected;
        Ok(input)
    }

    fn pin_symbol(
        path: Option<&[u8]>,
        method: &[u8],
        forbidden: u64,
        verified_bytes: Option<Vec<u8>>,
    ) -> Result<PinnedInput> {
        let handle = unsafe {
            libc::dlopen(
                path.map_or(core::ptr::null(), |p| p.as_ptr().cast()),
                libc::RTLD_NOW | if path.is_some() { libc::RTLD_NOLOAD } else { 0 },
            )
        };
        if handle.is_null() {
            return Err("PW OEM engine is not already loaded".into());
        }
        let pin = Pin(handle);
        let symbol = unsafe { libc::dlsym(handle, method.as_ptr().cast()) };
        if symbol.is_null() || symbol as u64 == forbidden {
            return Err("PW original getter absent/self".into());
        }
        let process = unsafe { libc::getpid() } as u64;
        let cached_lookup = verified_bytes.is_some();
        let bytes = match (verified_bytes, path) {
            (Some(bytes), _) => bytes,
            (None, None) => file(&elf::process_path(process)?)?,
            (None, Some(_)) => {
                let mut info: libc::Dl_info = unsafe { core::mem::zeroed() };
                if unsafe { libc::dladdr(symbol, &mut info) } == 0 || info.dli_fname.is_null() {
                    return Err("PW actual getter owner absent".into());
                }
                let mut length = 0usize;
                while length < 4096 && unsafe { *info.dli_fname.add(length) } != 0 {
                    length += 1;
                }
                if length == 0 || length == 4096 {
                    return Err("PW actual owner path bound".into());
                }
                let path = unsafe { CStr::from_ptr(info.dli_fname as *const c_char) }
                    .to_str()
                    .map_err(|_| "PW actual owner path encoding")?;
                file(path)?
            }
        };
        let mut owner = Owner {
            anchor: symbol as u64,
            loads: Vec::with_capacity(128),
            ..Owner::default()
        };
        unsafe {
            libc::dl_iterate_phdr(Some(headers), (&mut owner as *mut Owner).cast());
        }
        if !owner.found || owner.failed {
            return Err("PW pinned owner headers absent".into());
        }
        if elf::file_loads(&bytes)? != owner.loads {
            return Err("PW mapped owner LOAD headers mismatch".into());
        }
        let mut compared = 0u64;
        for p in owner
            .loads
            .iter()
            .filter(|p| p.flags & 5 == 5 || (cached_lookup && p.flags & 6 == 4))
        {
            compared = compared
                .checked_add(p.files)
                .filter(|n| *n <= 64 * 1024 * 1024)
                .ok_or("PW executable comparison budget")?;
            let start = usize::try_from(p.offset).map_err(|_| "PW executable offset")?;
            let length = usize::try_from(p.files).map_err(|_| "PW executable length")?;
            let expected = bytes
                .get(start..start.checked_add(length).ok_or("PW executable range")?)
                .ok_or("PW executable file bounds")?;
            let address = owner
                .base
                .checked_add(p.address)
                .ok_or("PW executable mapped address")?;
            // Actual loader-owned RX file segment, retained by the handle.
            let current = unsafe { core::slice::from_raw_parts(address as *const u8, length) };
            if current != expected {
                return Err("PW actual executable owner bytes mismatch".into());
            }
        }
        if compared == 0 {
            return Err("PW executable owner empty".into());
        }
        let loaded = LoadedGetter {
            process,
            base: owner.base,
            symbol: symbol as u64,
            forbidden,
        };
        Ok(PinnedInput {
            bytes,
            loaded,
            loads: owner.loads,
            _pin: pin,
        })
    }
    pub fn prepare(family: Family, forbidden: u64) -> Result<Pinned> {
        // Explicit admission demand only; shared provider performs no locale probes.
        if crate::elf::local_provider::prepare_shared_exception_provider().is_err() {
            return Err("PW original GNU exception provider unavailable".into());
        }
        let input = pin_input(OwnerSymbol::EngineGetter(family), forbidden)?;
        let proof = OwnerProof::inspect(
            &input.bytes,
            family,
            input.loaded,
            &input.loads,
            |at, len| {
                // checked_mapped_function has proved this exact range is backed by
                // the pinned loader owner's readable executable file segment.
                Ok(unsafe { core::slice::from_raw_parts(at as *const u8, len) }.to_vec())
            },
        )?;
        Ok(Pinned {
            proof,
            _pin: input._pin,
        })
    }
    impl Pinned {
        pub fn original(&self) -> u64 {
            self.proof.original()
        }
        pub fn query(&self, method: &str, ty: &str, member: &str) -> Option<Field> {
            self.proof
                .query(unsafe { libc::getpid() } as u64, method, ty, member)
        }
    }
}
