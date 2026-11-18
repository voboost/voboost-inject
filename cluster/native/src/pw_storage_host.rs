//! Fixed read-only capability for worker-admitted actual light storage types.
#[cfg(target_os = "nto")]
use crate::Result;
use core::ffi::{c_char, c_int, c_void};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Demand {
    NotRequested,
    Waiting,
    Ready,
    Unavailable,
}
#[cfg(any(target_os = "nto", test))]
fn claim(
    inflight: &core::sync::atomic::AtomicBool,
    last: &core::sync::atomic::AtomicU64,
    now: u64,
) -> bool {
    use core::sync::atomic::Ordering;
    if now == 0
        || inflight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return false;
    }
    let previous = last.load(Ordering::Acquire);
    if previous != 0 && (now < previous || now - previous < 10_000) {
        inflight.store(false, Ordering::Release);
        return false;
    }
    last.store(now, Ordering::Release);
    true
}
#[repr(C)]
pub struct Field {
    pub kind: u32,
    pub bytes: u32,
    pub offset: u32,
}
#[repr(C)]
pub struct Host {
    size: u32,
    abi: u32,
    query: unsafe extern "C" fn(*const c_char, *const c_char, *mut Field) -> c_int,
}
#[repr(C)]
pub struct OemField {
    kind: u32,
    bytes: u32,
    offset: u32,
    count: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OemHost {
    size: u32,
    abi: u32,
    family: u32,
    reserved: u32,
    thread: extern "C" fn() -> u64,
    process: extern "C" fn() -> u64,
    bind: unsafe extern "C" fn(*const c_char, u32, *mut *mut c_void) -> c_int,
    getter: extern "C" fn() -> *mut c_void,
    field:
        unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *mut OemField) -> c_int,
}

#[cfg(any(target_os = "nto", test))]
#[derive(Clone, Eq, PartialEq)]
struct LookupRequest {
    generation: [u8; 64],
    descriptor: voboost_contract_core::lookups::Descriptor,
}
#[cfg(any(target_os = "nto", test))]
#[derive(Default)]
struct GenerationBinding {
    current: Option<LookupRequest>,
    revision: u64,
    admitted: Option<u64>,
    failure: Option<alloc::string::String>,
}
#[cfg(any(target_os = "nto", test))]
impl GenerationBinding {
    fn request(&mut self, current: Option<LookupRequest>) {
        if self.current != current {
            self.current = current;
            self.admitted = None;
            self.failure = None;
            self.revision = self.revision.wrapping_add(1);
        }
    }

    fn publish(&mut self, revision: u64) -> bool {
        if self.current.is_none() || self.revision != revision {
            return false;
        }
        self.admitted = Some(revision);
        self.failure = None;
        true
    }

    fn record_failure(&mut self, revision: u64, reason: &str) -> bool {
        if self.current.is_none() || self.revision != revision || self.ready()
            || self.failure.as_deref() == Some(reason)
        {
            return false;
        }
        self.failure = Some(reason.into());
        true
    }

    fn ready(&self) -> bool {
        self.admitted == Some(self.revision)
    }
}

#[cfg(target_os = "nto")]
mod actual {
    use super::*;
    use crate::pw_storage_owner::qnx::Pinned;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
    struct Admitted {
        storage: Pinned,
        lookup: crate::pw_readback_owner::qnx::PinnedInput,
        descriptor: voboost_contract_core::lookups::Descriptor,
    }
    static BINDING: crate::controller::Spin<GenerationBinding> =
        crate::controller::Spin::new(GenerationBinding {
            current: None,
            revision: 0,
            admitted: None,
            failure: None,
        });
    static OWNER: AtomicPtr<Admitted> = AtomicPtr::new(core::ptr::null_mut());
    static INFLIGHT: AtomicBool = AtomicBool::new(false);
    static LAST: AtomicU64 = AtomicU64::new(0);
    extern "C" fn worker(_: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
        let revision = BINDING.with(|binding| binding.revision);
        if let Err(reason) = prepare() {
            let message = reason.chars().filter(|ch| matches!(ch, ' '..='~')).take(128)
                .collect::<alloc::string::String>();
            let message = if message.is_empty() { "PW storage probe unavailable" } else { &message };
            if BINDING.with(|binding| binding.record_failure(revision, message)) {
                crate::diagnostic_log::emit("error", "pw-oem-admission", message, &[]);
            }
        }
        INFLIGHT.store(false, Ordering::Release);
        core::ptr::null_mut()
    }
    pub fn revoke() {
        BINDING.with(|binding| binding.request(None));
    }

    pub fn failure() -> Option<alloc::string::String> {
        BINDING.with(|binding| binding.failure.clone())
    }

    pub fn request(generation: &str) -> Demand {
        // This is called from the authenticated controller command thread, including
        // before every PW lease. A same-generation replacement is observed here.
        let Ok(descriptor) = crate::pw_lookup_cache::read(generation) else {
            revoke();
            return Demand::Unavailable;
        };
        let mut generation_id = [0; 64];
        generation_id.copy_from_slice(generation.as_bytes());
        let request = LookupRequest {
            generation: generation_id,
            descriptor,
        };
        BINDING.with(|binding| binding.request(Some(request)));
        if ready() {
            return Demand::Ready;
        }
        retry()
    }

    pub fn retry() -> Demand {
        if !BINDING.with(|binding| binding.current.is_some() && !binding.ready()) {
            return Demand::NotRequested;
        }
        let Some(now) = crate::engine::monotonic_ms() else {
            return Demand::Unavailable;
        };
        if !claim(&INFLIGHT, &LAST, now) {
            return Demand::Waiting;
        }
        let mut thread = unsafe { core::mem::zeroed() };
        if unsafe {
            libc::pthread_create(
                &mut thread,
                core::ptr::null(),
                worker,
                core::ptr::null_mut(),
            )
        } != 0
        {
            INFLIGHT.store(false, Ordering::Release);
            return Demand::Unavailable;
        }
        unsafe {
            libc::pthread_detach(thread);
        }
        Demand::Waiting
    }
    pub fn ready() -> bool {
        !OWNER.load(Ordering::Acquire).is_null() && BINDING.with(|binding| binding.ready())
    }
    fn prepare() -> Result<()> {
        if ready() {
            return Ok(());
        }
        let (revision, descriptor) = BINDING
            .with(|binding| {
                binding
                    .current
                    .as_ref()
                    .map(|request| (binding.revision, request.descriptor.clone()))
            })
            .ok_or("PW lookup request revoked")?;
        let existing = OWNER.load(Ordering::Acquire);
        if !existing.is_null() {
            if unsafe { (&*existing).descriptor != descriptor } {
                return Err("PW lookup differs from this light process; restart light".into());
            }
            publish_binding(revision, None);
            return Ok(());
        }
        // PW owns this demand; readiness never depends on enabling locale.
        crate::elf::local_provider::prepare_shared_exception_provider()
            .map_err(|reason| alloc::format!("PW GNU exception provider: {reason}"))?;
        let storage = crate::pw_storage_owner::qnx::prepare(0)?;
        // The visual source needs Kanzi storage ownership, not a completed
        // vehicle state-machine cycle. Engine readback remains offline proof.
        let lookup = crate::pw_lookup_cache::admit(&descriptor)?;
        let proof = Box::new(Admitted {
            storage,
            lookup,
            descriptor,
        });
        publish_binding(revision, Some(proof));
        Ok(())
    }

    fn publish_binding(revision: u64, mut prepared: Option<Box<Admitted>>) {
        BINDING.with(|binding| {
            if !binding.publish(revision) {
                return;
            }
            if let Some(proof) = prepared.take() {
                OWNER.store(Box::into_raw(proof), Ordering::Release);
            }
        });
        // Stale preparation drops both pins after releasing the short binding lock.
    }

    unsafe fn text<'a>(p: *const c_char) -> Option<&'a str> {
        if p.is_null() {
            return None;
        }
        for len in 0..=512 {
            if *p.add(len) == 0 {
                return core::str::from_utf8(core::slice::from_raw_parts(p.cast(), len)).ok();
            }
        }
        None
    }
    pub unsafe fn query(ty: *const c_char, path: *const c_char, out: *mut Field) -> c_int {
        if out.is_null() {
            return -1;
        }
        let pointer = OWNER.load(Ordering::Acquire);
        if pointer.is_null() || !ready() {
            return -1;
        }
        let (Some(ty), Some(path)) = (text(ty), text(path)) else {
            return -1;
        };
        let Some(field) = (&*pointer).storage.query(ty, path) else {
            return -1;
        };
        out.write(Field {
            kind: field.kind,
            bytes: field.bytes,
            offset: field.offset,
        });
        0
    }
    pub fn lookup() -> *mut c_void {
        let pointer = OWNER.load(Ordering::Acquire);
        if pointer.is_null() || !ready() {
            return core::ptr::null_mut();
        }
        unsafe { (&*pointer).lookup.loaded.symbol as *mut c_void }
    }
    pub fn family() -> Option<u32> {
        None
    }
    pub unsafe fn bind(name: *const c_char, kind: u32, out: *mut *mut c_void) -> c_int {
        if out.is_null() {
            return -1;
        }
        let _ = (name, kind);
        -1
    }
    pub fn getter() -> *mut c_void {
        core::ptr::null_mut()
    }
    pub unsafe fn field(
        method: *const c_char,
        ty: *const c_char,
        member: *const c_char,
        out: *mut OemField,
    ) -> c_int {
        if out.is_null() {
            return -1;
        }
        let _ = (method, ty, member);
        -1
    }
}
/// Called by the authenticated controller command thread, never by an OEM UI frame.
pub(crate) fn revoke() {
    #[cfg(target_os = "nto")]
    actual::revoke();
}
/// Retry a previously admitted demand on the authenticated controller thread.
pub(crate) fn retry() {
    #[cfg(target_os = "nto")]
    let _ = actual::retry();
}

pub(crate) fn failure() -> Option<alloc::string::String> {
    #[cfg(target_os = "nto")]
    return actual::failure();
    #[cfg(not(target_os = "nto"))]
    None
}

fn request_on_demand(selected_enabled: bool, generation: &str) -> Demand {
    if !selected_enabled {
        revoke();
        return Demand::NotRequested;
    }
    #[cfg(target_os = "nto")]
    {
        actual::request(generation)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = generation;
        Demand::Unavailable
    }
}
pub fn request_consumer(id: &str, enabled: bool, selected: bool, generation: &str) -> Demand {
    request_on_demand(
        id == "vehicle-drive-pedestrian-warning" && enabled && selected,
        generation,
    )
}
unsafe extern "C" fn query(ty: *const c_char, path: *const c_char, out: *mut Field) -> c_int {
    #[cfg(target_os = "nto")]
    {
        actual::query(ty, path, out)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = (ty, path, out);
        -1
    }
}
static HOST: Host = Host {
    size: core::mem::size_of::<Host>() as u32,
    abi: 1,
    query,
};
extern "C" fn thread_identity() -> u64 {
    #[cfg(target_os = "nto")]
    {
        (unsafe { libc::pthread_self() }) as u64
    }
    #[cfg(not(target_os = "nto"))]
    {
        0
    }
}
extern "C" fn process_identity() -> u64 {
    #[cfg(target_os = "nto")]
    {
        (unsafe { libc::getpid() }) as u64
    }
    #[cfg(not(target_os = "nto"))]
    {
        0
    }
}
unsafe extern "C" fn bind(name: *const c_char, kind: u32, out: *mut *mut c_void) -> c_int {
    #[cfg(target_os = "nto")]
    {
        actual::bind(name, kind, out)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = (name, kind, out);
        -1
    }
}
extern "C" fn getter() -> *mut c_void {
    #[cfg(target_os = "nto")]
    {
        actual::getter()
    }
    #[cfg(not(target_os = "nto"))]
    {
        core::ptr::null_mut()
    }
}
unsafe extern "C" fn field(
    method: *const c_char,
    ty: *const c_char,
    member: *const c_char,
    out: *mut OemField,
) -> c_int {
    #[cfg(target_os = "nto")]
    {
        actual::field(method, ty, member, out)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = (method, ty, member, out);
        -1
    }
}
static OEM_A9: OemHost = OemHost {
    size: core::mem::size_of::<OemHost>() as u32,
    abi: 1,
    family: 1,
    reserved: 0,
    thread: thread_identity,
    process: process_identity,
    bind,
    getter,
    field,
};
static OEM_A11: OemHost = OemHost {
    family: 2,
    ..OEM_A9
};
#[no_mangle]
pub extern "C" fn vbc_pw_oem_host_v1() -> *const OemHost {
    #[cfg(target_os = "nto")]
    match actual::family() {
        Some(1) => return &OEM_A9,
        Some(2) => return &OEM_A11,
        _ => {}
    }
    let _ = (&OEM_A9, &OEM_A11);
    core::ptr::null()
}
#[no_mangle]
pub extern "C" fn vbc_pw_lookup_node_shared_boost_v1() -> *mut c_void {
    #[cfg(target_os = "nto")]
    return actual::lookup();
    #[cfg(not(target_os = "nto"))]
    core::ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn vbc_pw_storage_host_v1() -> *const Host {
    #[cfg(target_os = "nto")]
    {
        if actual::ready() {
            return &HOST;
        }
    }
    let _ = &HOST;
    core::ptr::null()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_replacement_or_revocation_rejects_stale_worker_publication() {
        use voboost_contract_core::lookups::Descriptor;
        let request = |revision| LookupRequest {
            generation: [b'a'; 64],
            descriptor: Descriptor::Native {
                library: "/lib64/libkzcoreui.so".into(),
                contract_revision: revision,
                export: "lookup".into(),
                adapter: "fixture".into(),
            },
        };
        let mut binding = GenerationBinding::default();
        binding.request(Some(request(1)));
        let first = binding.revision;
        assert!(binding.record_failure(first, "first probe failed"));
        assert!(!binding.record_failure(first, "first probe failed"));
        binding.request(Some(request(2)));
        assert!(!binding.publish(first));
        assert!(!binding.record_failure(first, "stale probe"));
        assert!(binding.failure.is_none());
        assert!(!binding.ready());
        assert!(binding.record_failure(binding.revision, "current probe failed"));
        assert!(binding.publish(binding.revision));
        assert!(binding.failure.is_none());
        assert!(binding.ready());
        let second = binding.revision;
        binding.request(None);
        binding.request(Some(request(2)));
        assert!(!binding.publish(second));
        assert!(!binding.ready());
    }

    #[test]
    fn host_has_no_fixture_or_file_fallback() {
        assert!(vbc_pw_storage_host_v1().is_null());
        assert!(vbc_pw_oem_host_v1().is_null());
        assert_eq!(request_on_demand(true, ""), Demand::Unavailable);
        assert_eq!(core::mem::size_of::<Field>(), 12);
        assert_eq!(core::mem::size_of::<Host>(), 16);
        assert_eq!(core::mem::size_of::<OemField>(), 16);
        assert_eq!(core::mem::size_of::<OemHost>(), 56);
    }
    #[test]
    fn request_is_scoped_and_retry_survives_a_failed_attempt() {
        use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        assert_eq!(request_on_demand(false, ""), Demand::NotRequested);
        assert_eq!(
            request_consumer("font-cyrillic", true, true, ""),
            Demand::NotRequested
        );
        assert_eq!(
            request_consumer("i18n-ru", true, true, ""),
            Demand::NotRequested
        );
        assert_eq!(
            request_consumer("vehicle-drive-pedestrian-warning", false, true, ""),
            Demand::NotRequested
        );
        assert_eq!(
            request_consumer("vehicle-drive-pedestrian-warning", true, false, ""),
            Demand::NotRequested
        );
        let inflight = AtomicBool::new(false);
        let last = AtomicU64::new(0);
        assert!(!claim(&inflight, &last, 0));
        assert!(claim(&inflight, &last, 100));
        assert!(!claim(&inflight, &last, 10_100));
        inflight.store(false, Ordering::Release);
        assert!(!claim(&inflight, &last, 101));
        assert!(claim(&inflight, &last, 10_100));
    }
}
