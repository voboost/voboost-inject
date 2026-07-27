// injector.rs — FFI wrapper over libinjector (the ptrace injection rail).
//
// The daemon's sole extern "C" seam to the native layer. Calls vbi_inject
// (defined in injector/injector.h) to inject libimplant.so into a target
// process via ptrace. The daemon never links libimplant.so or any
// LSPlant/Dobby symbol.

use std::ffi::CString;
use std::os::raw::{c_char, c_int};

use crate::config;
use crate::log;

/// vbi_inject return codes (matching injector/injector.h).
pub const INJECT_OK: c_int = 0;
pub const INJECT_DENIED: c_int = -1;
pub const INJECT_TARGET_GONE: c_int = -2;
pub const INJECT_DLOPEN_FAILED: c_int = -3;
pub const INJECT_INIT_FAILED: c_int = -4;
pub const INJECT_BITNESS_FAILED: c_int = -5;

extern "C" {
    fn vbi_inject(
        pid: c_int,
        so_path: *const c_char,
        init_sym: *const c_char,
        config_path: *const c_char,
    ) -> c_int;
}

/// The result of an injection attempt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectResult {
    Ok,
    Denied,
    TargetGone,
    DlopenFailed,
    InitFailed,
    BitnessFailed,
}

impl InjectResult {
    pub fn from_code(code: c_int) -> Self {
        match code {
            INJECT_OK => Self::Ok,
            INJECT_DENIED => Self::Denied,
            INJECT_TARGET_GONE => Self::TargetGone,
            INJECT_DLOPEN_FAILED => Self::DlopenFailed,
            INJECT_INIT_FAILED => Self::InitFailed,
            INJECT_BITNESS_FAILED => Self::BitnessFailed,
            _ => Self::InitFailed,
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::TargetGone => "target-gone",
            Self::DlopenFailed => "dlopen-failed",
            Self::InitFailed => "init-failed",
            Self::BitnessFailed => "bitness-failed",
        }
    }
}

/// Inject libimplant.so into a target process, then call implant_init.
///
/// `abi` selects the per-ABI payload ("arm64-v8a" or "armeabi-v7a").
/// The daemon passes the matching-ABI path based on runtime bitness detection.
/// `config_path` is the channel-B config file path (see control_plane);
/// the injector writes it into the target and passes it to implant_init.
pub fn inject(pid: i32, abi: &str, config_path: &str) -> InjectResult {
    let so_path = config::libimplant_path(abi);

    // Verify the payload file exists before attempting injection.
    if !std::path::Path::new(&so_path).exists() {
        log::err(
            "injector",
            &format!("payload not found for {abi}: {so_path}"),
        );
        return InjectResult::DlopenFailed;
    }

    let c_so = match CString::new(so_path.as_str()) {
        Ok(c) => c,
        Err(_) => return InjectResult::DlopenFailed,
    };
    let c_sym = match CString::new("implant_init") {
        Ok(c) => c,
        Err(_) => return InjectResult::InitFailed,
    };
    let c_cfg = match CString::new(config_path) {
        Ok(c) => c,
        Err(_) => return InjectResult::InitFailed,
    };

    log::info("injector", &format!("injecting pid={pid} abi={abi}"));

    let code = unsafe { vbi_inject(pid, c_so.as_ptr(), c_sym.as_ptr(), c_cfg.as_ptr()) };
    let result = InjectResult::from_code(code);

    if result.is_ok() {
        log::ok("injector", &format!("injected pid={pid}"));
    } else {
        log::err(
            "injector",
            &format!("inject failed pid={pid}: {}", result.label()),
        );
    }

    result
}
