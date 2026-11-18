//! Thin executable build binding for existing startup-service entrypoints.
use alloc::string::String;
use core::ffi::{c_char, CStr};
/// # Safety
/// Called by the owned native CRT with both strings valid for the process lifetime.
#[no_mangle]
pub unsafe extern "C" fn vbc_native_main(
    executable: *const c_char,
    input: *const c_char,
    role: u32,
) -> i32 {
    let result = (|| -> crate::Result<()> {
        if input.is_null() || executable.is_null() {
            return Err(String::from("native input absent"));
        }
        let value = CStr::from_ptr(input)
            .to_str()
            .map_err(|_| "native input UTF8")?;
        let executable = || {
            CStr::from_ptr(executable)
                .to_str()
                .map_err(|_| "native executable path UTF8")
        };
        if role == 5 {
            return crate::bootstrap::prepare_stage(executable()?, value);
        }
        if role == 12 {
            return crate::bootstrap::observe_stock(executable()?, value);
        }
        if role == 1 {
            return crate::bootstrap::install(executable()?, value);
        }
        if role == 6 {
            let root = crate::fs::Dir::open("/var/voboost", crate::fs::uid()?)?;
            let _operation = crate::operation::Lock::existing(&root)?;
            return crate::install::prepare_remove(value);
        }
        if role == 7 {
            return crate::install::finish_remove(value);
        }
        if role == 8 {
            let parent = crate::bootstrap::bootstrap_parent(executable()?, value)?;
            let root = parent.existing_child("voboost")?;
            let _operation = crate::operation::Lock::existing(&root)?;
            return crate::install::finish_install(value);
        }
        if role == 9 || role == 10 || role == 11 {
            if !voboost_contract_core::safe_path(value) {
                return Err("recovery input path rejected".into());
            }
            if role == 11 {
                return crate::install::restore_offline(value);
            }
            let root = if role == 10 || role == 11 {
                Some(crate::fs::Dir::open("/var/voboost", crate::fs::uid()?)?)
            } else {
                None
            };
            let _operation = root
                .as_ref()
                .map(crate::operation::Lock::wait_existing)
                .transpose()?;
            return if role == 10 {
                crate::install::repair_executable_mode(value)
            } else {
                crate::install::observe_recovery(value)
            };
        }
        if !voboost_contract_core::safe_path(value) {
            return Err(String::from("native input path rejected"));
        }
        match role {
            0 => crate::service::run(crate::service::bootfile(value)?),
            4 => crate::supervisor_delivery::prepare(crate::service::bootfile(value)?),
            3 => {
                let input = crate::install::FinalizeInput::parse(&crate::fs::read_protected(
                    value,
                    crate::fs::uid()?,
                    16384,
                    0o600,
                )?)?;
                // A terminal retry after verified root absence cannot open the removed lock.
                let root = if crate::fs::path_absent("/var/voboost")? {
                    None
                } else {
                    Some(crate::fs::Dir::open("/var/voboost", crate::fs::uid()?)?)
                };
                let _operation = root
                    .as_ref()
                    .map(crate::operation::Lock::existing)
                    .transpose()?;
                crate::install::uninstall(input)
            }
            2 => {
                let input = crate::install::Integration::parse(&crate::fs::read_protected(
                    value,
                    crate::fs::uid()?,
                    16384,
                    0o600,
                )?)?;
                let config = crate::service::bootfile(&input.bootfile)?;
                let root = crate::fs::Dir::open(&config.root, crate::fs::uid()?)?;
                let _operation = crate::operation::Lock::existing(&root)?;
                crate::install::restore(input)
            }
            _ => Err(String::from(
                "native executable implementation is unavailable",
            )),
        }
    })();
    match result {
        Ok(()) => 0,
        Err(reason) if role == 0 => {
            crate::diagnostic_log::emit("error", "native-entry", &reason, &[]);
            2
        }
        Err(reason) => {
            emit_failure(role, &reason, |fd, bytes| {
                libc::write(fd, bytes.as_ptr().cast(), bytes.len());
            });
            2
        }
    }
}

/// Pre-pair prepare-stage has only captured stdout over qconn. Paired roles
/// keep stderr; this diagnostic never claims successful completion.
fn emit_failure(role: u32, reason: &str, mut write: impl FnMut(i32, &[u8])) {
    let mut end = reason.len().min(512);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let mut bytes = crate::diagnostic_log::record("error", "native-entry", &reason[..end], &[]);
    bytes.push(b'\n');
    write(if role == 5 { 1 } else { 2 }, &bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_failure_uses_captured_stdout_and_paired_roles_keep_stderr() {
        for role in 0..=12 {
            let mut output = alloc::vec::Vec::new();
            emit_failure(role, "OEM /var mount contract rejected", |fd, bytes| {
                assert_eq!(fd, if role == 5 { 1 } else { 2 });
                output.extend_from_slice(bytes);
            });
            let record: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(record["component"], "native-entry");
            assert_eq!(record["message"], "OEM /var mount contract rejected");
        }
    }

    #[test]
    fn failure_reason_is_bounded_to_existing_installer_contract() {
        let reason = "x".repeat(600);
        let mut output = alloc::vec::Vec::new();
        emit_failure(5, &reason, |fd, bytes| {
            assert_eq!(fd, 1);
            output.extend_from_slice(bytes);
        });
        let record: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(record["message"].as_str().unwrap().len(), 512);
        assert_eq!(output.last(), Some(&b'\n'));
    }
}
