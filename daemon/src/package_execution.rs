//! Serializes APK admission with the canonical startup-mode transaction.
use crate::{config, generation, installed_product, operation_contract, plan};
use std::path::Path;

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn reconcile(
    generation: &generation::VerifiedGeneration,
    startup: plan::Startup,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    let guard = operation_contract::GenerationGuard::acquire_in(Path::new(config::ROOT_ZONE))
        .map_err(|error| error.to_string())?;
    reconcile_guarded(generation, startup, &guard, cancelled)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) fn reconcile_guarded(
    generation: &generation::VerifiedGeneration,
    startup: plan::Startup,
    guard: &operation_contract::GenerationGuard,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(), String> {
    guard.verify_owner()?;
    let current = plan::read_runtime_and_validate(generation);
    if !current.valid || current.startup != startup {
        return Err("APK execution policy canonical mode changed".into());
    }
    if generation::GenerationStore::production()
        .active_id()
        .as_deref()
        != Some(generation.id.as_str())
    {
        return Err("APK execution generation changed".into());
    }
    if verify_receipt(generation, startup).is_ok() {
        guard.verify_owner()?;
        return Ok(());
    }
    let manifest = installed_product::load_manifest()?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.file == "voboost-app.apk")
        .ok_or("signed product lacks APK identity")?;
    if !installed_product::installed_apk_matches_in(artifact, Path::new(config::ROOT_ZONE)) {
        return Err("installed APK differs from signed product identity".into());
    }
    guard.verify_owner()?;
    voboost_shared::package_execution::reconcile_cancellable(
        if startup == plan::Startup::None {
            voboost_shared::package_execution::Admission::Disabled
        } else {
            voboost_shared::package_execution::Admission::Enabled
        },
        cancelled,
    )?;
    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
        return Err("APK admission cancelled before publication".into());
    }
    guard.verify_owner()?;
    let receipt = expected_receipt(generation, startup)?;
    let root = receipt_directory()?;
    root.write_atomic(
        RECEIPT,
        &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
        0o644,
    )
    .map_err(|e| e.to_string())
}

const RECEIPT: &str = "package-execution.json";
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Receipt {
    schema_version: u32,
    generation_id: String,
    manifest_sha256: String,
    boot_id: String,
    startup: plan::Startup,
}
fn expected_receipt(
    generation: &generation::VerifiedGeneration,
    startup: plan::Startup,
) -> Result<Receipt, String> {
    let boot_id =
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| e.to_string())?;
    let boot_id = boot_id.trim();
    if boot_id.len() != 36 || !boot_id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err("invalid kernel boot identity".into());
    }
    Ok(Receipt {
        schema_version: 1,
        generation_id: generation.id.clone(),
        manifest_sha256: installed_product::load_manifest()?.digest()?,
        boot_id: boot_id.into(),
        startup,
    })
}
pub(crate) fn verify_receipt(
    generation: &generation::VerifiedGeneration,
    startup: plan::Startup,
) -> Result<(), String> {
    let root = receipt_directory()?;
    let bytes = root
        .read_trusted(RECEIPT, 4096, 0o644)
        .map_err(|e| e.to_string())?;
    verify_receipt_bytes(&bytes, &expected_receipt(generation, startup)?)
}

fn verify_receipt_bytes(bytes: &[u8], expected: &Receipt) -> Result<(), String> {
    let receipt: Receipt = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if &receipt != expected {
        return Err("APK execution admission receipt stale".into());
    }
    Ok(())
}

fn receipt_directory() -> Result<crate::secure_fs::Directory, String> {
    let root = crate::secure_fs::Directory::open(Path::new(config::ROOT_ZONE))
        .map_err(|e| e.to_string())?;
    let run = root.open_child("run").map_err(|e| e.to_string())?;
    run.validate_owner_mode(0, 0, config::RUN_DIR_MODE)
        .map_err(|e| e.to_string())?;
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Receipt {
        Receipt {
            schema_version: 1,
            generation_id: "generation-a".into(),
            manifest_sha256: "a".repeat(64),
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
            startup: plan::Startup::None,
        }
    }
    #[test]
    fn apk_execution_confirmation_rejects_each_stale_authority() {
        let expected = expected();
        let original = serde_json::to_value(&expected).unwrap();
        assert!(verify_receipt_bytes(&serde_json::to_vec(&original).unwrap(), &expected).is_ok());
        for (key, value) in [
            ("schemaVersion", serde_json::json!(2)),
            ("generationId", serde_json::json!("generation-b")),
            ("manifestSha256", serde_json::json!("b".repeat(64))),
            ("bootId", serde_json::json!("oldboot")),
            ("startup", serde_json::json!("interface")),
            ("foreign", serde_json::json!(true)),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(
                verify_receipt_bytes(&serde_json::to_vec(&changed).unwrap(), &expected).is_err(),
                "{key}"
            );
        }
        assert!(verify_receipt_bytes(b"{}", &expected).is_err());
    }
    #[test]
    fn replaced_generation_guard_cannot_mutate_apk_or_publish_receipt() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let guard = operation_contract::GenerationGuard::acquire_in(root.path()).unwrap();
        std::fs::rename(
            root.path().join("operation.lock"),
            root.path().join("operation.lock.displaced"),
        )
        .unwrap();
        std::fs::write(root.path().join("operation.lock"), b"").unwrap();
        std::fs::set_permissions(
            root.path().join("operation.lock"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let generation = generation::test_support::verified_variant(1);
        let error = reconcile_guarded(
            &generation,
            plan::Startup::None,
            &guard,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error, "operation lock pathname identity changed");
        assert!(!root.path().join("package-execution.json").exists());
    }
    #[test]
    fn package_execution_policy_grants_only_required_service_finds() {
        let policy = include_str!("../../selinux/voboost.te");
        assert!(policy.contains("allow voboost { activity_service jobscheduler_service user_service }:service_manager find;"));
        assert!(!policy.contains("allow su activity_service"));
        assert!(!policy.contains("allow su jobscheduler_service"));
        assert!(!policy.contains("allow voboost domain:process"));
    }
}

#[cfg(target_os = "android")]
fn android_boot_completed() -> bool {
    unsafe extern "C" {
        fn __system_property_get(
            name: *const libc::c_char,
            value: *mut libc::c_char,
        ) -> libc::c_int;
    }
    let mut value = [0 as libc::c_char; 92];
    (unsafe { __system_property_get(c"sys.boot_completed".as_ptr(), value.as_mut_ptr()) == 1 })
        && value[0] == b'1' as libc::c_char
}

type OwnedJob = (
    String,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<Result<(), String>>,
);
#[derive(Default)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) struct Worker {
    active: Option<OwnedJob>,
    retry_after: Option<std::time::Instant>,
}
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
impl Worker {
    #[cfg(target_os = "android")]
    pub(crate) fn poll(
        &mut self,
        generation: &generation::VerifiedGeneration,
        startup: plan::Startup,
    ) -> Result<bool, String> {
        if self.wait_for_boot(startup, android_boot_completed()) {
            return Ok(false);
        }
        let key = format!("{}:{:?}", generation.id, startup);
        let ready = verify_receipt(generation, startup).is_ok();
        let generation = generation.clone();
        self.poll_with(key, ready, move |cancelled| {
            reconcile(&generation, startup, &cancelled)
        })
    }
    fn wait_for_boot(&mut self, startup: plan::Startup, completed: bool) -> bool {
        let waiting = startup != plan::Startup::None && !completed;
        if waiting {
            self.quiesce();
        }
        waiting
    }

    fn poll_with(
        &mut self,
        key: String,
        ready: bool,
        operation: impl FnOnce(std::sync::Arc<std::sync::atomic::AtomicBool>) -> Result<(), String>
            + Send
            + 'static,
    ) -> Result<bool, String> {
        if let Some((owned, cancelled, thread)) = &self.active {
            if owned != &key {
                cancelled.store(true, std::sync::atomic::Ordering::Release);
            }
            if !thread.is_finished() {
                return Ok(false);
            }
            let (owned, _, thread) = self.active.take().unwrap();
            let result = thread
                .join()
                .map_err(|_| "APK execution worker panicked".to_string())?;
            if owned == key {
                if let Err(error) = result {
                    self.retry_after =
                        Some(std::time::Instant::now() + std::time::Duration::from_secs(1));
                    return Err(error);
                }
            }
            return Ok(false); // Require a fresh independently validated receipt next pass.
        }
        if ready {
            return Ok(true);
        }
        if self
            .retry_after
            .is_some_and(|deadline| std::time::Instant::now() < deadline)
        {
            return Ok(false);
        }
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child = cancelled.clone();
        let thread = std::thread::Builder::new()
            .name("apk-execution".into())
            .spawn(move || operation(child))
            .map_err(|e| e.to_string())?;
        self.active = Some((key, cancelled, thread));
        Ok(false)
    }
    pub(crate) fn is_active(&self) -> bool {
        self.active.is_some()
    }
    pub(crate) fn quiesce(&mut self) -> bool {
        if let Some((_, cancelled, thread)) = &self.active {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            if !thread.is_finished() {
                return false;
            }
        }
        if let Some((_, _, thread)) = self.active.take() {
            let _ = thread.join();
        }
        true
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some((_, cancelled, thread)) = self.active.take() {
            cancelled.store(true, std::sync::atomic::Ordering::Release);
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    #[test]
    fn apk_scheduling_waits_for_android_boot_but_disabling_never_waits() {
        let mut worker = Worker::default();
        assert!(worker.wait_for_boot(plan::Startup::Interface, false));
        assert!(!worker.is_active());
        assert!(!worker.wait_for_boot(plan::Startup::Interface, true));
        assert!(!worker.wait_for_boot(plan::Startup::None, false));
    }

    #[test]
    fn held_package_service_does_not_block_vehicle_registration_reads_or_completion() {
        let mut worker = Worker::default();
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        assert!(!worker
            .poll_with("generation-a:interface".into(), false, move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(())
            })
            .unwrap());
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let mut productive_events = Vec::new();
        for event in [
            "register vehicle endpoint",
            "read FEV",
            "read PW",
            "collect native completion",
            "drain vehicle status",
        ] {
            assert!(!worker
                .poll_with("generation-a:interface".into(), false, |_| panic!(
                    "must not start second worker"
                ))
                .unwrap());
            productive_events.push(event);
        }
        assert_eq!(productive_events.len(), 5);
        release_tx.send(()).unwrap();
        // Joining is explicit and happens only after completion/cancellation.
        while !worker.quiesce() {
            std::thread::yield_now();
        }
    }
    #[test]
    fn changed_generation_cancels_old_operation_and_never_confirms_it() {
        let mut worker = Worker::default();
        let (tx, rx) = mpsc::channel();
        assert!(!worker
            .poll_with("old:none".into(), false, move |cancelled| {
                tx.send(()).unwrap();
                while !cancelled.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::yield_now();
                }
                Err("cancelled".into())
            })
            .unwrap());
        rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!worker
            .poll_with("new:interface".into(), false, |_| panic!(
                "old worker still owned"
            ))
            .unwrap());
        while !worker.quiesce() {
            std::thread::yield_now();
        }
        assert!(worker.active.is_none());
    }
    #[test]
    fn denied_package_operation_cannot_confirm_none() {
        let mut worker = Worker::default();
        assert!(!worker
            .poll_with("g:none".into(), false, |_| Err("permission denied".into()))
            .unwrap());
        while !worker.active.as_ref().unwrap().2.is_finished() {
            std::thread::yield_now();
        }
        assert!(worker
            .poll_with("g:none".into(), false, |_| panic!(
                "cannot replay before collect"
            ))
            .is_err());
        assert!(!worker
            .poll_with("g:none".into(), false, |_| panic!(
                "backoff cannot dispatch"
            ))
            .unwrap());
    }
}
