//! C-layout consumers of the canonical SDK headers exported from cluster/sdk.
use core::ffi::{c_char, c_void};
#[repr(C)]
pub struct KeyValue {
    pub key: *const c_char,
    pub value: *const c_char,
}
#[repr(C)]
pub struct Observation {
    pub size: u32,
    pub id: *const c_char,
    pub state: i32,
    pub reason: *const c_char,
    pub revision: u64,
    pub lifecycle: u64,
}
#[repr(C)]
pub struct Host {
    pub abi: u32,
    pub size: u32,
    pub resolve: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    pub monotonic_ms: unsafe extern "C" fn() -> u64,
    pub log: unsafe extern "C" fn(*const c_char),
    pub compatible: unsafe extern "C" fn(*const c_char, *const c_char) -> i32,
    pub ui_ready: unsafe extern "C" fn() -> i32,
    pub report_user: *mut c_void,
    pub report: unsafe extern "C" fn(*mut c_void, *const Observation),
}
#[repr(C)]
pub struct Module {
    pub size: u32,
    pub id: *const c_char,
    pub domain: *const c_char,
    pub file: *const c_char,
    pub entry: *const c_char,
    pub configuration: *const KeyValue,
    pub configuration_count: u32,
}
#[repr(C)]
pub struct Authorization {
    pub abi: u32,
    pub size: u32,
    pub catalog: *const c_char,
    pub generation: *const c_char,
    pub modules: *const Module,
    pub count: u32,
}
#[repr(C)]
pub struct ModuleDesired {
    pub size: u32,
    pub id: *const c_char,
    pub enabled: u32,
    pub options: *const KeyValue,
    pub count: u32,
}
#[repr(C)]
pub struct Desired {
    pub abi: u32,
    pub size: u32,
    pub generation: *const c_char,
    pub sha256: *const c_char,
    pub revision: u64,
    pub modules: *const ModuleDesired,
    pub count: u32,
}
#[repr(C)]
pub struct Runtime {
    pub abi: u32,
    pub size: u32,
    pub initialize: Option<unsafe extern "C" fn(*const Host, *const Authorization) -> i32>,
    pub apply: Option<unsafe extern "C" fn(*const Desired) -> i32>,
    pub init: Option<
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void),
    >,
    pub update: Option<unsafe extern "C" fn(*mut c_void)>,
    pub data: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, u32)>,
    pub stop: Option<unsafe extern "C" fn() -> i32>,
}
impl Runtime {
    pub fn valid(&self) -> bool {
        self.abi == 2
            && self.size >= core::mem::size_of::<Self>() as u32
            && self.initialize.is_some()
            && self.apply.is_some()
            && self.init.is_some()
            && self.update.is_some()
            && self.data.is_some()
            && self.stop.is_some()
    }
}
