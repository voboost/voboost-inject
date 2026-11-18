//! Structural method/RTTI/property admission, prepared off the UI caller.
use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};
const UNPREPARED: u8 = 0;
const PREPARING: u8 = 1;
const ADMITTED: u8 = 2;
const REJECTED: u8 = 3;
struct Identity(AtomicU8);
impl Identity {
    const fn new() -> Self {
        Self(AtomicU8::new(UNPREPARED))
    }
    fn status(&self) -> i32 {
        match self.0.load(Ordering::Acquire) {
            ADMITTED => 1,
            REJECTED => 0,
            _ => -1,
        }
    }
    fn request(&self, start: impl FnOnce() -> bool) -> i32 {
        if self
            .0
            .compare_exchange(UNPREPARED, PREPARING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            && !start()
        {
            self.finish(false);
        }
        self.status()
    }
    fn finish(&self, admitted: bool) {
        self.0.store(
            if admitted { ADMITTED } else { REJECTED },
            Ordering::Release,
        );
    }
}
static IDENTITY: Identity = Identity::new();
static OWNER: AtomicU32 = AtomicU32::new(0);
#[cfg(any(target_os = "nto", test))]
fn owner_for_path(path: &[u8]) -> u32 {
    match path {
        b"/usr/bin/gauge" => 1,
        b"/usr/bin/point" => 2,
        b"/usr/bin/light" => 3,
        _ => 0,
    }
}
fn status_for(identity: &Identity, actual: &AtomicU32, requested: u32) -> i32 {
    if !(1..=3).contains(&requested) {
        return 0;
    }
    let status = identity.status();
    if status == 1 && actual.load(Ordering::Acquire) != requested {
        0
    } else {
        status
    }
}
#[no_mangle]
pub extern "C" fn vbc_locale_current_owner() -> u32 {
    if IDENTITY.status() == 1 {
        OWNER.load(Ordering::Acquire)
    } else {
        0
    }
}
#[no_mangle]
pub extern "C" fn vbc_locale_prepare_current() -> i32 {
    prepare_current()
}
/// Constant-time query: -1 awaits preparation, 0 rejects, 1 admits.
#[no_mangle]
pub extern "C" fn vbc_locale_owner_identity(owner: u32) -> i32 {
    status_for(&IDENTITY, &OWNER, owner)
}
/// Explicit preparation never probes in the caller. Unsupported owners and
/// hosts fail closed; the admitted QNX profile runs once per executable lifetime.
#[no_mangle]
pub extern "C" fn vbc_locale_prepare_identity(owner: u32) -> i32 {
    if !(1..=3).contains(&owner) {
        return 0;
    }
    prepare_current();
    status_for(&IDENTITY, &OWNER, owner)
}
fn prepare_current() -> i32 {
    IDENTITY.request(|| {
        #[cfg(target_os = "nto")]
        {
            spawn(identity_worker, core::ptr::null_mut())
        }
        #[cfg(not(target_os = "nto"))]
        {
            false
        }
    })
}
#[cfg(any(target_os = "nto", test))]
fn spawn(
    entry: extern "C" fn(*mut core::ffi::c_void) -> *mut core::ffi::c_void,
    data: *mut core::ffi::c_void,
) -> bool {
    unsafe {
        let mut attributes = core::mem::zeroed();
        if libc::pthread_attr_init(&mut attributes) != 0 {
            return false;
        }
        let mut thread = core::mem::zeroed();
        let created =
            libc::pthread_attr_setdetachstate(&mut attributes, libc::PTHREAD_CREATE_DETACHED) == 0
                && libc::pthread_create(&mut thread, &attributes, entry, data) == 0;
        libc::pthread_attr_destroy(&mut attributes);
        created
    }
}
#[cfg(target_os = "nto")]
extern "C" fn identity_worker(_: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    let owner = observed_owner();
    let admitted = owner != 0 && verify_profile();
    if admitted {
        OWNER.store(owner, Ordering::Release);
    }
    IDENTITY.finish(admitted);
    core::ptr::null_mut()
}
#[cfg(target_os = "nto")]
fn observed_owner() -> u32 {
    let path = alloc::ffi::CString::new(alloc::format!("/proc/{}/exefile", unsafe {
        libc::getpid()
    }))
    .unwrap();
    let fd = crate::fs::Fd(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    });
    if fd.0 < 0 || !matches!(crate::fs::stat(fd.0),Ok(stat) if stat.st_uid==0) {
        return 0;
    }
    let mut bytes = [0u8; 514];
    let count = unsafe { libc::read(fd.0, bytes.as_mut_ptr().cast(), bytes.len()) };
    if count <= 0 || count as usize == bytes.len() {
        return 0;
    }
    let path = &bytes[..count as usize];
    let path = path.strip_suffix(&[0]).unwrap_or(path);
    let path = path.strip_suffix(b"\n").unwrap_or(path);
    owner_for_path(path)
}
#[cfg(target_os = "nto")]
fn verify_profile() -> bool {
    unsafe extern "C" {
        fn vbc_i18n_prepare_exception_provider_sync() -> i32;
        fn vbc_locale_object_probe_prepare() -> i32;
    }
    // The real provider is pinned before any potentially throwing GNU call.
    // Capabilities are published by the probe before Identity's Release store.
    unsafe {
        let admitted = vbc_i18n_prepare_exception_provider_sync() == 1
            && vbc_locale_object_probe_prepare() == 1;
        if admitted {
            let _ = crate::resource_content_owner::prepare_sync();
        }
        // Missing resource proof leaves only that optional capability unavailable;
        // it must not revoke independent scalar/GNU/font/PW admission.
        admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Barrier, Mutex};
    use std::time::Duration;
    #[test]
    fn host_and_unproven_owners_are_never_admitted() {
        for owner in [0, 4, 9, u32::MAX] {
            assert_eq!(vbc_locale_owner_identity(owner), 0);
            assert_eq!(vbc_locale_prepare_identity(owner), 0);
        }
        assert_eq!(vbc_locale_owner_identity(1), -1);
        assert_eq!(vbc_locale_prepare_identity(1), 0);
        assert_eq!(vbc_locale_owner_identity(1), 0);
    }
    #[test]
    fn actual_process_role_never_aliases_another_owner() {
        let identity = Identity::new();
        identity.finish(true);
        for (path, owner) in [
            (b"/usr/bin/gauge".as_slice(), 1),
            (b"/usr/bin/point".as_slice(), 2),
            (b"/usr/bin/light".as_slice(), 3),
        ] {
            assert_eq!(owner_for_path(path), owner);
            for requested in 0..=5 {
                assert_eq!(
                    status_for(&identity, &AtomicU32::new(owner), requested),
                    if requested == owner { 1 } else { 0 }
                );
            }
        }
        for path in [
            b"/tmp/gauge".as_slice(),
            b"/usr/bin/ignoff",
            b"/usr/bin/gauge-extra",
            b"/usr/bin/gauge    struct Fixture {evil",
        ] {
            assert_eq!(owner_for_path(path), 0);
        }
    }
    struct Fixture {
        identity: Identity,
        started: Barrier,
        release: Barrier,
        creator: Mutex<Option<std::thread::ThreadId>>,
        done: mpsc::Sender<()>,
    }
    extern "C" fn delayed_probe(raw: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
        let fixture = unsafe { Arc::from_raw(raw.cast::<Fixture>()) };
        assert_ne!(
            fixture.creator.lock().unwrap().unwrap(),
            std::thread::current().id()
        );
        fixture.started.wait();
        fixture.release.wait();
        fixture.identity.finish(true);
        fixture.done.send(()).unwrap();
        core::ptr::null_mut()
    }
    #[test]
    fn concurrent_prepare_runs_once_off_caller_and_queries_do_not_wait() {
        let (done, completed) = mpsc::channel();
        let fixture = Arc::new(Fixture {
            identity: Identity::new(),
            started: Barrier::new(2),
            release: Barrier::new(2),
            creator: Mutex::new(None),
            done,
        });
        let mut callers = Vec::new();
        for _ in 0..8 {
            let fixture = fixture.clone();
            callers.push(std::thread::spawn(move || {
                fixture.identity.request(|| {
                    *fixture.creator.lock().unwrap() = Some(std::thread::current().id());
                    let raw = Arc::into_raw(fixture.clone());
                    let created = spawn(delayed_probe, raw.cast_mut().cast());
                    if !created {
                        unsafe {
                            drop(Arc::from_raw(raw));
                        }
                    }
                    created
                })
            }));
        }
        for caller in callers {
            assert_eq!(caller.join().unwrap(), -1);
        }
        fixture.started.wait();
        // The worker is still blocked; UI queries neither join it nor start work.
        for _ in 0..1000 {
            assert_eq!(fixture.identity.status(), -1);
        }
        assert_eq!(fixture.identity.request(|| panic!("duplicate worker")), -1);
        fixture.release.wait();
        completed.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(fixture.identity.status(), 1);
        assert_eq!(fixture.identity.request(|| panic!("cached worker")), 1);
    }
    #[test]
    fn spawn_failure_and_failed_verification_stay_rejected() {
        let failed_spawn = Identity::new();
        assert_eq!(failed_spawn.request(|| false), 0);
        assert_eq!(
            failed_spawn.request(|| panic!("rejected worker retried")),
            0
        );
        let failed_probe = Identity::new();
        assert_eq!(failed_probe.request(|| true), -1);
        failed_probe.finish(false);
        assert_eq!(failed_probe.status(), 0);
        assert_eq!(failed_probe.request(|| panic!("failed profile retried")), 0);
    }
}
