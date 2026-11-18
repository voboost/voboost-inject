//! One resource-only boot barrier for the complete authenticated overlay set.
use super::*;
use std::process::ExitStatus;
use voboost_contract::operation::{self, Operation, OperationLease};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Continuation {
    Continue,
    AwaitBoot,
    RequestReboot,
}

pub(super) fn prepare_before_runtime_remove(
    key: &[u8; 32],
    lease: &OperationLease,
) -> io::Result<Continuation> {
    lease.verify_owner().map_err(io::Error::other)?;
    let active = operation::read_active_in(Path::new("/data/voboost")).map_err(io::Error::other)?;
    if active
        .as_ref()
        .is_none_or(|value| value.operation != Operation::Uninstall)
    {
        return Err(fail("resource pause requires active uninstall"));
    }
    let profiles = open_operation_variants()?;
    if profiles.is_empty() {
        verify_resource_absence(&profiles)?;
        return Ok(Continuation::Continue);
    }
    let batch = none_batch::Lease::open()?;
    let mut locks = Vec::new();
    for (_, _, journal) in &profiles {
        locks.push(journal.lock_transaction(Duration::from_secs(5))?);
    }
    preflight_profiles(&profiles, key, RemovalMode::Resume)?;
    let boot = operation::current_boot_id().map_err(io::Error::other)?;
    let mut members = Vec::new();
    let mut actions = Vec::new();
    for (variant, overlays, journal) in &profiles {
        let receipt: Receipt = serde_json::from_slice(&journal.read_trusted(JOURNAL, 4096, 0o600)?)
            .map_err(io::Error::other)?;
        let authority = read_owned_authority_for(journal, &receipt.generation, key, *variant)?;
        if receipt.generation != authority.manifest_sha256()
            || receipt.overlay_sha256 != authority.artifact().sha256
        {
            return Err(fail("resource pause authority differs"));
        }
        match overlays.read_trusted(variant.file(), MAX_APK, 0o644) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Ok(_) => return Err(fail("owned overlay remains at plural boot barrier")),
            Err(error) => return Err(error),
        }
        actions.push(operation_boot::decide(&receipt, &boot)?);
        members.push((*variant, receipt));
    }
    if actions
        .iter()
        .all(|action| *action == operation_boot::Action::VerifyAbsence)
    {
        drop(locks);
        drop(batch);
        verify_operation_absence(key, lease, Operation::Uninstall)?;
        return Ok(Continuation::Continue);
    }
    if actions.contains(&operation_boot::Action::RequestReboot) {
        let first = &profiles[0];
        let resource = read_owned_authority_for(&first.2, &members[0].1.generation, key, first.0)?;
        none_driver::restore_native(&first.2, &resource)?;
        lease.verify_owner().map_err(io::Error::other)?;
        if operation::current_boot_id().map_err(io::Error::other)? != boot {
            return Err(fail("resource pause boot changed"));
        }
        for ((_, _, journal), (_, receipt)) in profiles.iter().zip(members.iter_mut()) {
            if receipt.removal_boot_id.as_deref() == Some(&boot) {
                receipt.phase = "operation-reboot-attempted".into();
                publish(journal, receipt)?;
            }
        }
    }
    lease.verify_owner().map_err(io::Error::other)?;
    if operation::current_boot_id().map_err(io::Error::other)? != boot {
        return Err(fail("resource pause boot changed"));
    }
    // A crash can leave every receipt attempted without publishing the batch
    // ticket. The first claimant can still request reboot. An existing ticket
    // proves intent only, so same-boot replay must still await a changed boot.
    if batch.claim(&members, &boot)? {
        Ok(Continuation::RequestReboot)
    } else {
        Ok(Continuation::AwaitBoot)
    }
}

/// A nonempty signed collection requires an already registered resume service.
pub(super) fn require_resume_service(key: &[u8; 32]) -> io::Result<()> {
    let profiles = open_operation_variants()?;
    if profiles.is_empty() {
        return verify_resource_absence(&profiles);
    }
    let _batch = none_batch::Lease::open()?;
    let mut locks = Vec::new();
    for (_, _, journal) in &profiles {
        locks.push(journal.lock_transaction(Duration::from_secs(5))?);
    }
    preflight_profiles(&profiles, key, RemovalMode::Operation)?;
    let output = voboost_shared::fixed_process::output(
        "/system/bin/getprop",
        &[RESUME_PROPERTY],
        Duration::from_secs(2),
        128,
    )
    .map_err(|error| io::Error::other(format!("getprop {RESUME_PROPERTY}: {error}")))?;
    validate_resume_service(output.status, &output.stdout, &output.stderr)
}

const RESUME_PROPERTY: &str = "init.svc.voboost-resource-uninstall-resume";

fn validate_resume_service(status: ExitStatus, stdout: &[u8], stderr: &[u8]) -> io::Result<()> {
    if status.success() && stderr.is_empty() && matches!(stdout, b"running\n" | b"stopped\n") {
        return Ok(());
    }
    Err(fail(&format!(
        "resource uninstall requires the registered init resume service; getprop {RESUME_PROPERTY}: {status}, stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn service_preflight_reports_failed_and_empty_property_reads() {
        let ok = ExitStatus::from_raw(0);
        assert!(validate_resume_service(ok, b"running\n", b"").is_ok());
        assert!(validate_resume_service(ok, b"stopped\n", b"").is_ok());

        let empty = validate_resume_service(ok, b"\n", b"")
            .unwrap_err()
            .to_string();
        assert!(empty.contains(RESUME_PROPERTY));
        assert!(empty.contains("exit status: 0"));
        assert!(empty.contains("stdout=\"\\n\""));

        let failure = validate_resume_service(ExitStatus::from_raw(7 << 8), b"", b"denied\n")
            .unwrap_err()
            .to_string();
        assert!(failure.contains("exit status: 7"));
        assert!(failure.contains("stderr=\"denied\\n\""));
    }
}
