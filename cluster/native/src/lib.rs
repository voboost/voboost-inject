#![cfg_attr(target_os = "nto", no_std)]
#![cfg_attr(target_os = "nto", feature(alloc_error_handler))]
extern crate alloc;
pub mod bootstrap;
pub mod config;
pub mod controller;
mod controller_pw;
mod diagnostic_log;
mod diagnostic_ram;
pub mod elf;
pub mod engine;
pub mod entry;
pub mod fs;
pub mod install;
mod install_layout;
pub mod ipc;
pub mod locale_identity;
pub mod net;
pub mod oem_startup;
mod operation;
mod owner_restart;
pub mod pw_live;
pub mod sdk;
pub mod service;
mod service_ingress;
pub(crate) mod supervisor_config;
pub(crate) mod supervisor_delivery;
pub(crate) mod supervisor_elf;
pub mod tls;
pub type Result<T> = core::result::Result<T, alloc::string::String>;
pub mod roots {
    include!(concat!(env!("OUT_DIR"), "/roots.rs"));
}
pub fn nonce() -> Result<alloc::string::String> {
    let mut bytes = [0u8; 32];
    #[cfg(target_os = "nto")]
    {
        extern "C" {
            fn RAND_bytes(p: *mut u8, n: i32) -> i32;
        }
        if unsafe { RAND_bytes(bytes.as_mut_ptr(), 32) } != 1 {
            return Err("native entropy unavailable".into());
        }
    }
    #[cfg(not(target_os = "nto"))]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(|_| "host entropy unavailable")?;
    }
    Ok(hex::encode(bytes))
}
pub fn key(value: &str) -> Result<[u8; 32]> {
    if !voboost_contract_core::digest(value) {
        return Err("invalid raw32 hex".into());
    }
    hex::decode(value)
        .map_err(|_| "invalid raw32 hex".into())
        .and_then(|v| v.try_into().map_err(|_| "invalid raw32 length".into()))
}
#[cfg(target_os = "nto")]
mod allocation {
    use core::{
        alloc::{GlobalAlloc, Layout},
        ffi::c_void,
    };
    struct Allocator;
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            if l.align() <= 16 {
                libc::malloc(l.size().max(1)).cast()
            } else {
                let mut p: *mut c_void = core::ptr::null_mut();
                if libc::posix_memalign(&mut p, l.align(), l.size().max(1)) != 0 {
                    core::ptr::null_mut()
                } else {
                    p.cast()
                }
            }
        }
        unsafe fn dealloc(&self, p: *mut u8, _: Layout) {
            libc::free(p.cast())
        }
    }
    #[global_allocator]
    static GLOBAL: Allocator = Allocator;
    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        unsafe { libc::abort() }
    }
    #[alloc_error_handler]
    fn oom(_: Layout) -> ! {
        unsafe { libc::abort() }
    }
}

#[cfg(test)]
pub(crate) fn tests_catalog(
    runtime: &[u8],
    agent: &[u8],
) -> voboost_contract_core::agent_catalog::AgentCatalog {
    use voboost_contract_core::{catalog::AGENT_ENTRY_ABI_SHA256, hash};
    serde_json::from_value(serde_json::json!({
 "schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{"schemaVersion":1,"sha256":AGENT_ENTRY_ABI_SHA256},
 "core":{"file":"agent-common.dex","size":1,"sha256":"5".repeat(64)},
 "clusterRuntime":{"file":"libvoboost-runtime-cluster.so","size":runtime.len(),"sha256":hash(runtime)},
 "agents":[{"id":"font-cyrillic","targets":[{"process":"gauge","file":"libagent-font-cyrillic.so","size":agent.len(),"sha256":hash(agent),"platform":"qnx","domain":"cluster","entryAbi":"voboost-agent3-v1","boot":false}],"status":"stable","order":1,"activation":{"type":"checkbox","default":true},"title":{"en":"Font","ru":"Font"},"description":{"en":"Font","ru":"Font"},"applicability":{"chip":[],"vehicle":[],"android":[],"powertrain":[],"market":[]}}]
 })).unwrap()
}

pub mod pw_readback_types;

pub mod resource_content_types;

pub mod resource_content_calls;

pub mod resource_content_cleanup;

pub mod resource_content_owner;

pub mod pw_readback_owner;

pub mod pw_oem_method_owner;

pub mod pw_storage_types;

pub mod pw_storage_owner;

mod pw_lookup_cache;
pub mod pw_storage_host;
