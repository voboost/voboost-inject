//! Signed immutable resource leases prepared off UI; snapshots pin every borrowed view.
use super::{ProcessIdentity, Result, Spin};
use crate::engine::OwnedPackLeaseInputs;
use alloc::{boxed::Box, ffi::CString, format, string::String, vec::Vec};
use core::{
    ffi::{c_char, c_void},
    sync::atomic::{AtomicU64, Ordering},
};
use voboost_contract_core::resource_pack::OwnedPack;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Key {
    storage: String,
    process: ProcessIdentity,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Text {
    data: *const c_char,
    size: usize,
}
impl Text {
    fn new(s: &str) -> Self {
        Self {
            data: s.as_ptr().cast(),
            size: s.len(),
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Entry {
    key: Text,
    value: Text,
}
#[repr(C)]
struct Lease {
    size: u32,
    owner: u32,
    token: u64,
    pack: *const u8,
    pack_size: usize,
    dictionary_uri: Text,
    entries: *const Entry,
    entry_count: usize,
}
#[repr(C)]
struct Api {
    abi: u32,
    size: u32,
    count: extern "C" fn() -> u32,
    snapshot: unsafe extern "C" fn(u32, *mut Lease) -> i32,
    current: extern "C" fn(u64) -> i32,
    retain: extern "C" fn(u64) -> i32,
    release: extern "C" fn(u64),
}
struct Candidate {
    token: u64,
    owner: u32,
    pack: OwnedPack,
    uri: CString,
    entries: Vec<Entry>,
    borrowed: usize,
    pinned: bool,
}
pub(super) struct Prepared {
    key: Option<Key>,
    candidates: Vec<Candidate>,
}
// Pointers refer only to immutable allocations owned by the same Prepared.
// Publication and borrow counters are serialized by STATE; replacement cannot
// release any allocation while a snapshot exists or a load was attempted.
unsafe impl Send for Prepared {}
impl Prepared {
    pub(super) fn empty() -> Box<Self> {
        Box::new(Self {
            key: None,
            candidates: Vec::new(),
        })
    }
    pub(super) fn key(&self) -> Option<&Key> {
        self.key.as_ref()
    }
}
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
pub(super) fn prepare(
    input: OwnedPackLeaseInputs,
    process_name: &str,
    process: &ProcessIdentity,
) -> Result<Box<Prepared>> {
    let owner = match process_name {
        "gauge" => 1,
        "point" => 2,
        "light" => 3,
        _ => return Err("private resource owner unsupported".into()),
    };
    let mut candidates = Vec::new();
    for pack in input
        .packs
        .into_iter()
        .filter(|p| p.ledger().target_process == process_name)
    {
        if candidates.len() == 64 {
            return Err("private resource candidate bound".into());
        }
        let token = NEXT_TOKEN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_add(1)
                    .filter(|v| *v <= voboost_contract_core::MAX_SAFE_INTEGER)
            })
            .map_err(|_| "private resource token exhausted")?;
        let uri = CString::new(format!(
            "kzb://voboost-localization/Locales/{}",
            pack.ledger().locale
        ))
        .map_err(|_| "private resource URI")?;
        let entries = pack
            .ledger()
            .expected_readback
            .iter()
            .map(|(k, v)| Entry {
                key: Text::new(k),
                value: Text::new(v),
            })
            .collect();
        candidates.push(Candidate {
            token,
            owner,
            pack,
            uri,
            entries,
            borrowed: 0,
            pinned: false,
        });
    }
    let key = if candidates.is_empty() {
        None
    } else {
        Some(Key {
            storage: input.storage_id,
            process: process.clone(),
        })
    };
    Ok(Box::new(Prepared { key, candidates }))
}
/// A single bounded slot: revoked snapshots prevent replacement, while any
/// attempted load keeps all backing bytes until actual process destruction.
struct Slot<T> {
    key: Option<Key>,
    payload: Option<Box<T>>,
    live: bool,
    borrowed: usize,
    attempted: bool,
    restart: bool,
}
impl<T> Slot<T> {
    const fn new() -> Self {
        Self {
            key: None,
            payload: None,
            live: false,
            borrowed: 0,
            attempted: false,
            restart: false,
        }
    }
    fn matches(&self, key: Option<&Key>) -> bool {
        !self.restart && self.key.as_ref() == key && (key.is_none() || self.live)
    }
    fn replace(&mut self, key: Option<Key>, payload: Option<Box<T>>) -> Result<()> {
        if self.restart {
            return Err("private-resource-owner-restart-required".into());
        }
        if self.key == key {
            self.live = key.is_some();
            return Ok(());
        }
        if self.attempted {
            self.live = false;
            self.restart = true;
            return Err("private-resource-owner-restart-required".into());
        }
        if self.borrowed != 0 {
            self.live = false;
            return Err("private-resource-snapshot-still-borrowed".into());
        }
        self.key = key;
        self.payload = payload;
        self.live = self.key.is_some();
        Ok(())
    }
    fn borrow(&mut self) -> bool {
        if !self.live || self.restart || self.payload.is_none() || self.borrowed >= 4096 {
            return false;
        }
        self.borrowed += 1;
        true
    }
    fn release(&mut self) {
        if self.borrowed != 0 {
            self.borrowed -= 1
        }
    }
    fn retain(&mut self) -> bool {
        if !self.live || self.restart || self.borrowed == 0 {
            return false;
        }
        self.attempted = true;
        true
    }
    fn revoke(&mut self) {
        self.live = false;
        if self.attempted {
            self.restart = true
        }
    }
}
static STATE: Spin<Slot<Prepared>> = Spin::new(Slot::new());
pub(super) fn matches(key: Option<&Key>) -> bool {
    STATE.with(|s| s.matches(key))
}
/// Called by the OEM UI owner only after the old runtime returned RESTORED.
/// An attempted private load still refuses replacement even if a caller lies.
pub(super) fn publish(next: Box<Prepared>) -> Result<()> {
    STATE.with(|s| {
        let key = next.key.clone();
        let payload = if key.is_some() { Some(next) } else { None };
        s.replace(key, payload)
    })
}
pub(super) fn revoke() {
    STATE.with(Slot::revoke)
}
/// Only the current opaque signed payload can establish this lifetime fact.
pub(super) fn retained_restart_required() -> bool {
    STATE.with(|slot| slot.attempted && slot.restart && slot.payload.is_some())
}

extern "C" fn count() -> u32 {
    STATE.with(|s| {
        if s.live && !s.restart {
            s.payload.as_ref().map_or(0, |p| p.candidates.len() as u32)
        } else {
            0
        }
    })
}
/// # Safety
/// out is a writable Lease-sized caller object. Success strongly pins all
/// returned data until release_snapshot(token), independent of current(token).
unsafe extern "C" fn snapshot(index: u32, out: *mut Lease) -> i32 {
    if out.is_null() || (*out).size as usize != core::mem::size_of::<Lease>() {
        return 0;
    }
    STATE.with(|s| {
        if !s.live
            || s.restart
            || s.payload
                .as_ref()
                .is_none_or(|p| index as usize >= p.candidates.len())
            || !s.borrow()
        {
            return 0;
        }
        let c = &mut s.payload.as_mut().expect("borrowed payload").candidates[index as usize];
        c.borrowed += 1;
        let value = Lease {
            size: core::mem::size_of::<Lease>() as u32,
            owner: c.owner,
            token: c.token,
            pack: c.pack.pack().as_ptr(),
            pack_size: c.pack.pack().len(),
            dictionary_uri: Text {
                data: c.uri.as_ptr(),
                size: c.uri.as_bytes().len(),
            },
            entries: c.entries.as_ptr(),
            entry_count: c.entries.len(),
        };
        out.write(value);
        1
    })
}
extern "C" fn current(token: u64) -> i32 {
    STATE.with(|s| {
        i32::from(
            s.live
                && !s.restart
                && s.payload.as_ref().is_some_and(|p| {
                    p.candidates
                        .iter()
                        .any(|c| c.token == token && (c.borrowed != 0 || c.pinned))
                }),
        )
    })
}
extern "C" fn retain(token: u64) -> i32 {
    STATE.with(|s| {
        let Some(index) = s.payload.as_ref().and_then(|p| {
            p.candidates
                .iter()
                .position(|c| c.token == token && c.borrowed != 0)
        }) else {
            return 0;
        };
        if s.attempted && !s.payload.as_ref().unwrap().candidates[index].pinned {
            return 0;
        }
        if !s.retain() {
            return 0;
        }
        s.payload.as_mut().unwrap().candidates[index].pinned = true;
        1
    })
}
extern "C" fn release(token: u64) {
    STATE.with(|s| {
        if let Some(c) = s.payload.as_mut().and_then(|p| {
            p.candidates
                .iter_mut()
                .find(|c| c.token == token && c.borrowed != 0)
        }) {
            c.borrowed -= 1;
            s.release();
        }
    })
}
static API: Api = Api {
    abi: 1,
    size: core::mem::size_of::<Api>() as u32,
    count,
    snapshot,
    current,
    retain,
    release,
};
unsafe extern "C" fn entry() -> *const Api {
    &API
}
pub(super) unsafe fn resolve(path: *const c_char, symbol: *const c_char) -> Option<*mut c_void> {
    if path.is_null()
        && !symbol.is_null()
        && core::ffi::CStr::from_ptr(symbol).to_bytes() == b"vbc_private_locale_authority_v1"
    {
        Some(entry as *const () as *mut c_void)
    } else {
        None
    }
}
#[cfg(test)]
pub(crate) fn actual_signed_ffi_regression(
    first: OwnedPackLeaseInputs,
    mut replace_authority: impl FnMut() -> OwnedPackLeaseInputs,
) {
    let process = ProcessIdentity {
        pid: unsafe { libc::getpid() } as u64,
        birth_identity: "host-ffi".into(),
        executable_sha256: "a".repeat(64),
        endpoint_epoch: "b".repeat(64),
        lifecycle_generation: 1,
        supervisor: None,
    };
    let expected = first.packs[0].pack().to_vec();
    let expected_values = first.packs[0].ledger().expected_readback.clone();
    let storage = first.storage_id.clone();
    publish(prepare(first, "gauge", &process).unwrap()).unwrap();
    unsafe {
        let name = CString::new("vbc_private_locale_authority_v1").unwrap();
        assert!(resolve(name.as_ptr(), name.as_ptr()).is_none());
        assert!(resolve(core::ptr::null(), core::ptr::null()).is_none());
        let function: unsafe extern "C" fn() -> *const Api =
            core::mem::transmute(resolve(core::ptr::null(), name.as_ptr()).unwrap());
        let api = &*function();
        assert_eq!((api.abi, api.size), (1, 48));
        assert_eq!((api.count)(), 1);
        assert_eq!((api.snapshot)(0, core::ptr::null_mut()), 0);
        let mut lease: Lease = core::mem::zeroed();
        assert_eq!((api.snapshot)(0, &mut lease), 0);
        lease.size = 64;
        assert_eq!((api.snapshot)(1, &mut lease), 0);
        assert_eq!((api.snapshot)(0, &mut lease), 1);
        let check = |lease: &Lease| {
            assert_eq!(
                core::slice::from_raw_parts(lease.pack, lease.pack_size),
                expected
            );
            let uri = core::slice::from_raw_parts(
                lease.dictionary_uri.data.cast::<u8>(),
                lease.dictionary_uri.size,
            );
            assert!(core::str::from_utf8(uri)
                .unwrap()
                .starts_with("kzb://voboost-localization/Locales/voboost-ru-"));
            let entries = core::slice::from_raw_parts(lease.entries, lease.entry_count);
            assert_eq!(entries.len(), expected_values.len());
            for entry in entries {
                let key = core::str::from_utf8(core::slice::from_raw_parts(
                    entry.key.data.cast::<u8>(),
                    entry.key.size,
                ))
                .unwrap();
                let value = core::str::from_utf8(core::slice::from_raw_parts(
                    entry.value.data.cast::<u8>(),
                    entry.value.size,
                ))
                .unwrap();
                assert_eq!(expected_values.get(key).unwrap(), value);
            }
        };
        assert_eq!((api.current)(lease.token), 1);
        let replacement = replace_authority();
        assert_ne!(replacement.storage_id, storage);
        let next = prepare(replacement, "gauge", &process).unwrap();
        assert!(publish(next).unwrap_err().contains("still-borrowed"));
        assert_eq!((api.current)(lease.token), 0);
        check(&lease);
        (api.release)(lease.token.wrapping_add(100));
        check(&lease);
        (api.release)(lease.token);
        (api.release)(lease.token);
        // Revoked, unattempted data may now retire. No pointer is used afterward.
        publish(Prepared::empty()).unwrap();
        assert_eq!((api.count)(), 0);
        assert_eq!((api.current)(lease.token), 0);
        assert_eq!((api.retain)(lease.token), 0);
        publish(prepare(replace_authority(), "gauge", &process).unwrap()).unwrap();
        assert_eq!((api.snapshot)(0, &mut lease), 1);
        assert_eq!((api.retain)(lease.token), 1);
        (api.release)(lease.token);
        assert_eq!((api.current)(lease.token), 1);
        check(&lease);
        revoke();
        assert_eq!((api.current)(lease.token), 0);
        assert!(publish(Prepared::empty())
            .unwrap_err()
            .contains("owner-restart"));
        (api.release)(lease.token);
        check(&lease);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicUsize;
    struct DropProbe(Arc<AtomicUsize>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn key(storage: &str) -> Key {
        Key {
            storage: storage.into(),
            process: ProcessIdentity {
                pid: 10,
                birth_identity: "birth".into(),
                executable_sha256: "a".repeat(64),
                endpoint_epoch: "b".repeat(64),
                lifecycle_generation: 1,
                supervisor: None,
            },
        }
    }
    #[test]
    fn same_catalog_different_storage_requires_replacement() {
        let mut s = Slot::new();
        let n = Arc::new(AtomicUsize::new(0));
        s.replace(Some(key("product-a")), Some(Box::new(DropProbe(n.clone()))))
            .unwrap();
        assert!(s.matches(Some(&key("product-a"))));
        assert!(!s.matches(Some(&key("product-b"))));
        s.replace(Some(key("product-b")), Some(Box::new(DropProbe(n.clone()))))
            .unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn snapshot_pins_all_data_before_current_or_load_attempt() {
        let mut s = Slot::new();
        let old = Arc::new(AtomicUsize::new(0));
        s.replace(Some(key("a")), Some(Box::new(DropProbe(old.clone()))))
            .unwrap();
        assert!(s.borrow());
        assert!(s.replace(Some(key("b")), None).is_err());
        assert_eq!(old.load(Ordering::SeqCst), 0);
        s.release();
        s.replace(Some(key("b")), None).unwrap();
        assert_eq!(old.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn load_attempt_retains_payload_after_snapshot_release_and_reload_required() {
        let mut s = Slot::new();
        let old = Arc::new(AtomicUsize::new(0));
        s.replace(Some(key("a")), Some(Box::new(DropProbe(old.clone()))))
            .unwrap();
        assert!(!s.retain());
        assert!(s.borrow());
        assert!(s.retain());
        s.release();
        s.revoke();
        assert!(s
            .replace(Some(key("b")), None)
            .unwrap_err()
            .contains("owner-restart"));
        assert!(!s.matches(Some(&key("a"))));
        assert_eq!(old.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn process_lifecycle_changes_invalidate_same_storage() {
        let mut s = Slot::new();
        s.replace(Some(key("a")), Some(Box::new(()))).unwrap();
        let mut changed = key("a");
        changed.process.lifecycle_generation = 2;
        assert!(!s.matches(Some(&changed)));
    }
    #[test]
    fn ffi_layout_matches_unpublished_arm64_header() {
        assert_eq!(core::mem::size_of::<Text>(), 16);
        assert_eq!(core::mem::size_of::<Entry>(), 32);
        assert_eq!(core::mem::size_of::<Lease>(), 64);
        assert_eq!(core::mem::size_of::<Api>(), 48);
    }
}
