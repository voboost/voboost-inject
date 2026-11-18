//! Resource-only boot barrier before uninstall removes its runtime authority.
use super::{fail, valid_resource_boot_id, Receipt};
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    RequestReboot,
    AwaitBoot,
    VerifyAbsence,
}

/// Called only after the shared executor authenticates ownership and recovers
/// an interrupted removal. This decision is not a package-absence proof.
pub(super) fn decide(receipt: &Receipt, current_boot: &str) -> io::Result<Action> {
    if receipt.schema != 1 || !valid_resource_boot_id(current_boot) {
        return Err(fail("resource operation boot input invalid"));
    }
    let removal = receipt
        .removal_boot_id
        .as_deref()
        .filter(|value| valid_resource_boot_id(value))
        .ok_or_else(|| fail("resource operation removal boot missing"))?;
    match receipt.phase.as_str() {
        "operation-awaiting-package-absence" if removal == current_boot => {
            Ok(Action::RequestReboot)
        }
        "operation-reboot-attempted" if removal == current_boot => Ok(Action::AwaitBoot),
        "operation-awaiting-package-absence"
        | "operation-reboot-attempted"
        | "operation-package-absence-confirmed"
            if removal != current_boot =>
        {
            Ok(Action::VerifyAbsence)
        }
        _ => Err(fail("resource operation boot phase not admitted")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    fn receipt(phase: &str) -> Receipt {
        Receipt {
            schema: 1,
            generation: "a".repeat(64),
            overlay_sha256: "b".repeat(64),
            previous_sha256: None,
            phase: phase.into(),
            removal_boot_id: Some(A.into()),
        }
    }
    #[test]
    fn first_request_and_same_boot_replay_are_distinct() {
        let mut r = receipt("operation-awaiting-package-absence");
        assert_eq!(decide(&r, A).unwrap(), Action::RequestReboot);
        r.phase = "operation-reboot-attempted".into();
        assert_eq!(decide(&r, A).unwrap(), Action::AwaitBoot);
        assert_eq!(decide(&r, B).unwrap(), Action::VerifyAbsence);
    }
    #[test]
    fn previous_confirmation_always_requires_new_observation() {
        let r = receipt("operation-package-absence-confirmed");
        assert_eq!(decide(&r, B).unwrap(), Action::VerifyAbsence);
        assert!(decide(&r, A).is_err());
    }
    #[test]
    fn unremoved_or_malformed_receipt_cannot_request_reboot() {
        for phase in ["operation-removing", "prepared", "unknown"] {
            assert!(decide(&receipt(phase), A).is_err());
        }
        let mut r = receipt("operation-awaiting-package-absence");
        r.removal_boot_id = None;
        assert!(decide(&r, A).is_err());
        r.removal_boot_id = Some("00000000-0000-0000-0000-000000000000".into());
        assert!(decide(&r, A).is_err());
    }
}
