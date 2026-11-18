//! Durable two-boot None resource removal; the caller supplies authenticated device IO.
use super::{valid_resource_boot_id, Receipt};
use std::io;

pub trait Io {
    fn fence(&mut self) -> io::Result<()>;
    fn verify_authority(&mut self) -> io::Result<()>;
    fn native_consistency(&mut self) -> io::Result<()>;
    fn disable_overlay(&mut self) -> io::Result<()>;
    fn recover_wal(&mut self) -> io::Result<()>;
    fn present_matching(&mut self) -> io::Result<bool>;
    fn unlink_owned(&mut self) -> io::Result<()>;
    fn packages_absent(&mut self) -> io::Result<bool>;
    fn persist(&mut self, receipt: &Receipt) -> io::Result<()>;
    fn request_reboot(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    NoResource,
    Pending,
    Final,
}

fn fail(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn step(io: &mut dyn Io, receipt: &mut Receipt, phase: &str) -> io::Result<()> {
    let mut next = receipt.clone();
    next.phase = phase.to_string();
    io.persist(&next)?; // durable first; never fake an ack
    *receipt = next;
    Ok(())
}

fn request_once(io: &mut dyn Io, receipt: &mut Receipt) -> io::Result<Outcome> {
    io.fence()?;
    io.verify_authority()?;
    io.native_consistency()?;
    step(io, receipt, "late-none-request-attempted")?; // BEFORE the real request
    io.request_reboot()?;
    Ok(Outcome::Pending)
}

fn disable_and_unlink(io: &mut dyn Io, receipt: &mut Receipt, boot: &str) -> io::Result<()> {
    io.verify_authority()?;
    io.native_consistency()?; // full en-ZH native readback
    io.disable_overlay()?; // OMS disable before any removal
    io.fence()?;
    let mut next = receipt.clone();
    next.removal_boot_id = Some(boot.to_string()); // real boot recorded
    next.phase = "late-none-removing".to_string();
    io.persist(&next)?; // persisted BEFORE unlink
    *receipt = next;
    io.unlink_owned()?; // scoped to the owned file inside the adapter
    step(io, receipt, "late-none-awaiting-package-absence")
}

fn removal_boot(receipt: &Receipt) -> io::Result<&str> {
    let value = receipt.removal_boot_id.as_deref();
    match value {
        Some(value) if valid_resource_boot_id(value) => Ok(value),
        _ => Err(fail("none removal boot missing or malformed")),
    }
}

fn final_proof(io: &mut dyn Io, receipt: &mut Receipt, boot: &str) -> io::Result<Outcome> {
    let removal = removal_boot(receipt)?;
    if removal == boot {
        return Err(fail("none final requires a different boot"));
    }
    io.verify_authority()?;
    io.native_consistency()?;
    if io.present_matching()? {
        return Err(fail("owned resource reappeared before confirmation"));
    }
    if !io.packages_absent()? {
        return Ok(Outcome::Pending); // observer not fresh/absent: no final
    }
    io.fence()?;
    io.verify_authority()?;
    if io.present_matching()? {
        return Err(fail("owned resource reappeared during confirmation"));
    }
    step(io, receipt, "late-none-final")?;
    Ok(Outcome::Final)
}

fn armed(io: &mut dyn Io, receipt: &mut Receipt, boot: &str) -> io::Result<Outcome> {
    io.recover_wal()?; // WAL recovery before presence
    if !io.present_matching()? {
        return Err(fail("armed owned resource missing"));
    }
    disable_and_unlink(io, receipt, boot)?;
    request_once(io, receipt)
}

fn replay_removing(io: &mut dyn Io, receipt: &mut Receipt, boot: &str) -> io::Result<Outcome> {
    io.recover_wal()?;
    if io.present_matching()? {
        // interrupted before unlink: redo disable/unlink, resetting an old boot
        return disable_and_unlink(io, receipt, boot).and_then(|()| request_once(io, receipt));
    }
    if removal_boot(receipt)? == boot {
        request_once(io, receipt) // unlinked this boot: at most one request
    } else {
        final_proof(io, receipt, boot)
    }
}

fn replay_awaiting(io: &mut dyn Io, receipt: &mut Receipt, boot: &str) -> io::Result<Outcome> {
    io.recover_wal()?;
    if io.present_matching()? {
        return Err(fail("owned resource reappeared before confirmation"));
    }
    if removal_boot(receipt)? == boot {
        io.fence()?;
        io.verify_authority()?;
        if receipt.phase == "late-none-awaiting-package-absence" {
            request_once(io, receipt) // crash before request: resume one attempt
        } else {
            Ok(Outcome::Pending) // attempted same boot: never repeat the request
        }
    } else {
        final_proof(io, receipt, boot)
    }
}

pub fn drive(io: &mut impl Io, receipt: &mut Receipt, boot: &str) -> io::Result<Outcome> {
    if receipt.schema != 1 || !valid_resource_boot_id(boot) {
        return Err(fail("none drive schema or boot malformed"));
    }
    match receipt.phase.as_str() {
        "prepared"
        | "awaiting-system-scan"
        | "enabled-owner-readback-confirmed"
        | "oms-enabled-awaiting-owner-readback"
        | "oms-disabled-awaiting-owner-readback"
        | "disabled-owner-readback-confirmed" => armed(io, receipt, boot),
        "late-none-final" => final_proof(io, receipt, boot),
        "late-none-removing" => replay_removing(io, receipt, boot),
        "late-none-awaiting-package-absence" | "late-none-request-attempted" => {
            replay_awaiting(io, receipt, boot)
        }
        _ => Err(fail("none drive phase unknown")),
    }
}

/// Callers with no durable journal have no resource: zero IO calls.
pub fn drive_optional(
    io: &mut impl Io,
    receipt: Option<Receipt>,
    boot: &str,
) -> io::Result<Outcome> {
    match receipt {
        None => Ok(Outcome::NoResource),
        Some(mut value) => drive(io, &mut value, boot),
    }
}

/// Plural removal barrier. IOs are already authenticated, fixed-profile adapters.
/// The caller's durable batch ticket is the sole reboot-attempt authority.
pub(super) fn drive_batch(
    ios: &mut [&mut dyn Io],
    receipts: &mut [Receipt],
    boot: &str,
    native: &mut dyn FnMut() -> io::Result<()>,
    reboot_once: &mut dyn FnMut(&[Receipt], &str) -> io::Result<()>,
) -> io::Result<Outcome> {
    if ios.len() != receipts.len()
        || ios.len() > voboost_shared::owned_overlay::Variant::ALL.len()
        || !valid_resource_boot_id(boot)
    {
        return Err(fail("None batch shape invalid"));
    }
    if ios.is_empty() {
        return Ok(Outcome::NoResource);
    }
    let mut present = Vec::with_capacity(ios.len());
    // Preflight the WHOLE collection before the first unlink or publication.
    for (adapter, receipt) in ios.iter_mut().zip(receipts.iter()) {
        if receipt.schema != 1
            || !matches!(
                receipt.phase.as_str(),
                "prepared"
                    | "awaiting-system-scan"
                    | "enabled-owner-readback-confirmed"
                    | "oms-enabled-awaiting-owner-readback"
                    | "oms-disabled-awaiting-owner-readback"
                    | "disabled-owner-readback-confirmed"
                    | "late-none-removing"
                    | "late-none-awaiting-package-absence"
                    | "late-none-request-attempted"
                    | "late-none-final"
                    | "early-none-awaiting-native-readback"
                    | "early-none-restored-confirmed"
            )
        {
            return Err(fail("None batch phase invalid"));
        }
        adapter.fence()?;
        adapter.verify_authority()?;
        adapter.recover_wal()?;
        let exists = adapter.present_matching()?;
        if !exists
            && !(receipt.phase.starts_with("late-none-")
                || receipt.phase.starts_with("early-none-"))
        {
            return Err(fail("armed batch resource missing"));
        }
        if exists
            && matches!(
                receipt.phase.as_str(),
                "late-none-awaiting-package-absence"
                    | "late-none-request-attempted"
                    | "late-none-final"
            )
        {
            return Err(fail("batch resource reappeared"));
        }
        if receipt.phase.starts_with("late-none-") || receipt.phase.starts_with("early-none-") {
            removal_boot(receipt)?;
        }
        present.push(exists);
    }
    native()?; // one global EN/helper observation for the entire collection
    for ((adapter, receipt), exists) in ios.iter_mut().zip(receipts.iter_mut()).zip(present) {
        if exists {
            adapter.disable_overlay()?;
            adapter.fence()?;
            let mut next = receipt.clone();
            next.removal_boot_id = Some(boot.into());
            next.phase = "late-none-removing".into();
            adapter.persist(&next)?;
            *receipt = next;
            adapter.unlink_owned()?;
        }
        if receipt.phase == "late-none-removing" {
            step(*adapter, receipt, "late-none-awaiting-package-absence")?;
        }
    }
    // Nothing may ask for reboot or final readiness before ALL files are absent.
    for adapter in ios.iter_mut() {
        adapter.fence()?;
        adapter.verify_authority()?;
        if adapter.present_matching()? {
            return Err(fail("batch unlink incomplete"));
        }
    }
    if receipts.iter().any(|r| {
        r.removal_boot_id.as_deref() == Some(boot)
            && !matches!(
                r.phase.as_str(),
                "late-none-final"
                    | "early-none-awaiting-native-readback"
                    | "early-none-restored-confirmed"
            )
    }) {
        for (adapter, receipt) in ios.iter_mut().zip(receipts.iter_mut()) {
            if receipt.removal_boot_id.as_deref() == Some(boot) {
                step(*adapter, receipt, "late-none-request-attempted")?;
            }
        }
        reboot_once(receipts, boot)?;
        return Ok(Outcome::Pending);
    }
    for adapter in ios.iter_mut() {
        if !adapter.packages_absent()? {
            return Ok(Outcome::Pending);
        }
    }
    for (adapter, receipt) in ios.iter_mut().zip(receipts.iter_mut()) {
        adapter.fence()?;
        adapter.verify_authority()?;
        if adapter.present_matching()? {
            return Err(fail("batch resource reappeared at commit"));
        }
        step(*adapter, receipt, "late-none-final")?;
    }
    Ok(Outcome::Final)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestIo {
        calls: Vec<&'static str>,
        present: bool,
        packages_absent: bool,
        fail_persist: bool,
        fail_reboot: bool,
        fail_native: bool,
        fail_authority: bool,
    }
    impl Io for TestIo {
        fn fence(&mut self) -> io::Result<()> {
            self.calls.push("fence");
            Ok(())
        }
        fn verify_authority(&mut self) -> io::Result<()> {
            self.calls.push("auth");
            if self.fail_authority {
                return Err(fail("authority"));
            }
            Ok(())
        }
        fn native_consistency(&mut self) -> io::Result<()> {
            self.calls.push("native");
            if self.fail_native {
                return Err(fail("native"));
            }
            Ok(())
        }
        fn disable_overlay(&mut self) -> io::Result<()> {
            self.calls.push("disable");
            Ok(())
        }
        fn recover_wal(&mut self) -> io::Result<()> {
            self.calls.push("wal");
            Ok(())
        }
        fn present_matching(&mut self) -> io::Result<bool> {
            self.calls.push("present");
            Ok(self.present)
        }
        fn unlink_owned(&mut self) -> io::Result<()> {
            self.calls.push("unlink");
            Ok(())
        }
        fn packages_absent(&mut self) -> io::Result<bool> {
            self.calls.push("packages");
            Ok(self.packages_absent)
        }
        fn persist(&mut self, _: &Receipt) -> io::Result<()> {
            self.calls.push("persist");
            if self.fail_persist {
                Err(fail("persist"))
            } else {
                Ok(())
            }
        }
        fn request_reboot(&mut self) -> io::Result<()> {
            self.calls.push("reboot");
            if self.fail_reboot {
                Err(fail("reboot"))
            } else {
                Ok(())
            }
        }
    }

    const BOOT: &str = "11111111-1111-1111-1111-111111111111";
    const OTHER: &str = "22222222-2222-2222-2222-222222222222";

    fn receipt(phase: &str, boot: Option<&str>) -> Receipt {
        Receipt {
            schema: 1,
            generation: "a".repeat(64),
            overlay_sha256: "b".repeat(64),
            previous_sha256: None,
            phase: phase.to_string(),
            removal_boot_id: boot.map(str::to_string),
        }
    }
    fn pos(hay: &[&str], needle: &str) -> usize {
        hay.iter().position(|c| *c == needle).unwrap()
    }

    #[test]
    fn armed_enabled_rro_full_order() {
        let mut io = TestIo {
            present: true,
            ..Default::default()
        };
        let mut r = receipt("enabled-owner-readback-confirmed", None);
        assert_eq!(drive(&mut io, &mut r, BOOT).unwrap(), Outcome::Pending);
        let c = io.calls;
        assert_eq!(
            &c[..9],
            [
                "wal", "present", "auth", "native", "disable", "fence", "persist", "unlink",
                "persist"
            ]
        );
        assert_eq!(&c[9..], ["fence", "auth", "native", "persist", "reboot"]);
        assert_eq!(c.iter().filter(|x| **x == "reboot").count(), 1);
        assert_eq!(r.phase, "late-none-request-attempted");
        assert_eq!(r.removal_boot_id.as_deref(), Some(BOOT));
        assert_eq!(pos(&c, "persist"), pos(&c, "unlink") - 1); // removing persisted before unlink
        assert_eq!(c[pos(&c, "reboot") - 1], "persist"); // attempted persisted before request
    }

    #[test]
    fn interrupted_removing_retries_unlink() {
        let mut io = TestIo {
            present: true,
            ..Default::default()
        };
        let mut r = receipt("late-none-removing", Some(OTHER)); // old boot: reset to current
        assert_eq!(drive(&mut io, &mut r, BOOT).unwrap(), Outcome::Pending);
        assert!(io.calls.contains(&"disable") && io.calls.contains(&"unlink"));
        assert_eq!(r.removal_boot_id.as_deref(), Some(BOOT));
        assert_eq!(r.phase, "late-none-request-attempted");
    }

    #[test]
    fn failed_reboot_no_repeat_same_boot() {
        let mut io = TestIo {
            present: false,
            fail_reboot: true,
            ..Default::default()
        };
        let mut r = receipt("late-none-awaiting-package-absence", Some(BOOT));
        assert!(drive(&mut io, &mut r, BOOT).is_err());
        assert_eq!(r.phase, "late-none-request-attempted"); // persisted before the failed request
        io.fail_reboot = false;
        let mut io2 = TestIo {
            present: false,
            ..Default::default()
        };
        assert_eq!(drive(&mut io2, &mut r, BOOT).unwrap(), Outcome::Pending);
        assert!(!io2.calls.contains(&"reboot")); // never two requests in one boot
        assert!(!io2.calls.contains(&"unlink"));
    }

    #[test]
    fn fresh_different_boot_final() {
        let mut io = TestIo {
            present: false,
            packages_absent: true,
            ..Default::default()
        };
        let mut r = receipt("late-none-request-attempted", Some(BOOT));
        assert_eq!(drive(&mut io, &mut r, OTHER).unwrap(), Outcome::Final);
        assert!(!io.calls.contains(&"reboot")); // no extra reboot for final
        assert_eq!(r.phase, "late-none-final");
    }

    #[test]
    fn failed_observer_not_final() {
        let mut io = TestIo {
            present: false,
            packages_absent: false,
            ..Default::default()
        };
        let mut r = receipt("late-none-removing", Some(BOOT));
        assert_eq!(drive(&mut io, &mut r, OTHER).unwrap(), Outcome::Pending);
        assert_eq!(r.phase, "late-none-removing"); // unchanged, no fake confirmation
        assert!(!io.calls.contains(&"persist"));
    }

    #[test]
    fn failed_persist_keeps_receipt_and_authority() {
        let mut io = TestIo {
            present: true,
            fail_persist: true,
            ..Default::default()
        };
        let mut r = receipt("oms-enabled-awaiting-owner-readback", None);
        let before = r.clone();
        assert!(drive(&mut io, &mut r, BOOT).is_err());
        assert_eq!(r, before); // nothing assigned without a durable ack
        assert_eq!(io.calls.iter().filter(|x| **x == "auth").count(), 1);
        // Failure leaves the retained authority available for a later retry.
    }

    #[test]
    fn final_replay_requires_fresh_absence() {
        let mut io = TestIo {
            packages_absent: true,
            ..Default::default()
        };
        let mut r = receipt("late-none-final", Some(BOOT));
        assert_eq!(drive(&mut io, &mut r, OTHER).unwrap(), Outcome::Final);
        assert!(!io.calls.contains(&"reboot"));
        assert_eq!(
            io.calls.iter().filter(|call| **call == "present").count(),
            2
        );
        assert_eq!(io.calls.iter().filter(|call| **call == "auth").count(), 2);
    }

    #[test]
    fn failed_native_or_authority_never_unlinks_or_confirms() {
        for authority in [false, true] {
            let mut io = TestIo {
                present: true,
                fail_authority: authority,
                fail_native: !authority,
                ..Default::default()
            };
            let mut r = receipt("enabled-owner-readback-confirmed", None);
            let before = r.clone();
            assert!(drive(&mut io, &mut r, BOOT).is_err());
            assert_eq!(r, before);
            assert!(!io.calls.contains(&"unlink"));
            assert!(!io.calls.contains(&"reboot"));
        }
    }

    #[test]
    fn same_boot_cannot_confirm_even_if_package_absent() {
        let mut io = TestIo {
            packages_absent: true,
            ..Default::default()
        };
        let mut r = receipt("late-none-final", Some(BOOT));
        assert!(drive(&mut io, &mut r, BOOT).is_err());
        assert!(io.calls.is_empty());
    }

    #[test]
    fn no_resource_zero_calls() {
        let mut io = TestIo::default();
        assert_eq!(
            drive_optional(&mut io, None, BOOT).unwrap(),
            Outcome::NoResource
        );
        assert!(io.calls.is_empty());
        assert!(
            drive_optional(&mut io, Some(receipt("late-none-final", Some(BOOT))), BOOT).is_err()
        );
    }
    struct BatchIo {
        present: bool,
        foreign: bool,
        fail_unlink: bool,
        absent: bool,
        writes: usize,
        unlinks: usize,
        final_writes: usize,
        fail_presence: bool,
    }
    impl BatchIo {
        fn armed() -> Self {
            Self {
                present: true,
                foreign: false,
                fail_unlink: false,
                absent: true,
                writes: 0,
                unlinks: 0,
                final_writes: 0,
                fail_presence: false,
            }
        }
    }
    impl Io for BatchIo {
        fn fence(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn verify_authority(&mut self) -> io::Result<()> {
            if self.foreign {
                Err(fail("foreign"))
            } else {
                Ok(())
            }
        }
        fn native_consistency(&mut self) -> io::Result<()> {
            panic!("per-profile native forbidden")
        }
        fn disable_overlay(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn recover_wal(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn present_matching(&mut self) -> io::Result<bool> {
            if self.fail_presence {
                return Err(fail("owned file changed"));
            }
            Ok(self.present)
        }
        fn unlink_owned(&mut self) -> io::Result<()> {
            if self.fail_unlink {
                return Err(fail("unlink"));
            }
            self.present = false;
            self.unlinks += 1;
            Ok(())
        }
        fn packages_absent(&mut self) -> io::Result<bool> {
            Ok(self.absent)
        }
        fn persist(&mut self, receipt: &Receipt) -> io::Result<()> {
            self.writes += 1;
            if receipt.phase == "late-none-final" {
                self.final_writes += 1;
            }
            Ok(())
        }
        fn request_reboot(&mut self) -> io::Result<()> {
            panic!("per-profile reboot forbidden")
        }
    }
    #[test]
    fn plural_unlinks_all_before_one_reboot_and_confirms_all_next_boot() {
        let (mut a, mut b) = (BatchIo::armed(), BatchIo::armed());
        let mut receipts = vec![receipt("prepared", None), receipt("prepared", None)];
        let (mut native, mut reboots) = (0, 0);
        assert_eq!(
            drive_batch(
                &mut [&mut a, &mut b],
                &mut receipts,
                BOOT,
                &mut || {
                    native += 1;
                    Ok(())
                },
                &mut |r, _| {
                    assert!(r.iter().all(|r| r.phase == "late-none-request-attempted"));
                    reboots += 1;
                    Ok(())
                }
            )
            .unwrap(),
            Outcome::Pending
        );
        assert_eq!((native, reboots, a.unlinks, b.unlinks), (1, 1, 1, 1));
        b.absent = false;
        assert_eq!(
            drive_batch(
                &mut [&mut a, &mut b],
                &mut receipts,
                OTHER,
                &mut || Ok(()),
                &mut |_, _| panic!("extra reboot")
            )
            .unwrap(),
            Outcome::Pending
        );
        assert!(receipts.iter().all(|r| r.phase != "late-none-final"));
        b.absent = true;
        assert_eq!(
            drive_batch(
                &mut [&mut a, &mut b],
                &mut receipts,
                OTHER,
                &mut || Ok(()),
                &mut |_, _| panic!("extra reboot")
            )
            .unwrap(),
            Outcome::Final
        );
    }
    #[test]
    fn plural_partial_unlink_failure_resumes_without_early_reboot() {
        let (mut a, mut b) = (BatchIo::armed(), BatchIo::armed());
        b.fail_unlink = true;
        let mut r = vec![receipt("prepared", None), receipt("prepared", None)];
        assert!(drive_batch(
            &mut [&mut a, &mut b],
            &mut r,
            BOOT,
            &mut || Ok(()),
            &mut |_, _| panic!("early reboot")
        )
        .is_err());
        assert!(!a.present && b.present);
        b.fail_unlink = false;
        assert_eq!(
            drive_batch(
                &mut [&mut a, &mut b],
                &mut r,
                BOOT,
                &mut || Ok(()),
                &mut |_, _| Ok(())
            )
            .unwrap(),
            Outcome::Pending
        );
        assert_eq!((a.unlinks, b.unlinks), (1, 1));
    }
    #[test]
    fn plural_foreign_second_profile_prevents_first_profile_mutation() {
        let (mut a, mut b) = (BatchIo::armed(), BatchIo::armed());
        b.foreign = true;
        let mut r = vec![receipt("prepared", None), receipt("prepared", None)];
        assert!(drive_batch(
            &mut [&mut a, &mut b],
            &mut r,
            BOOT,
            &mut || panic!("native before auth"),
            &mut |_, _| panic!("reboot")
        )
        .is_err());
        assert_eq!((a.writes, a.unlinks, b.writes, b.unlinks), (0, 0, 0, 0));
    }

    #[test]
    fn early_prezygote_absence_finishes_without_extra_reboot() {
        let (mut a, mut b) = (BatchIo::armed(), BatchIo::armed());
        a.present = false;
        b.present = false;
        let mut r = vec![
            receipt("early-none-awaiting-native-readback", Some(BOOT)),
            receipt("early-none-awaiting-native-readback", Some(BOOT)),
        ];
        assert_eq!(
            drive_batch(
                &mut [&mut a, &mut b],
                &mut r,
                BOOT,
                &mut || Ok(()),
                &mut |_, _| panic!("ordinary boot reboot")
            )
            .unwrap(),
            Outcome::Final
        );
    }
    #[test]
    fn mixed_old_early_and_new_partial_removal_share_one_reboot_barrier() {
        let (mut a, mut b) = (BatchIo::armed(), BatchIo::armed());
        a.present = false;
        let mut r = vec![
            receipt("early-none-awaiting-native-readback", Some(OTHER)),
            receipt("prepared", None),
        ];
        assert_eq!(
            drive_batch(
                &mut [&mut a, &mut b],
                &mut r,
                BOOT,
                &mut || Ok(()),
                &mut |members, _| {
                    assert_eq!(members[0].phase, "early-none-awaiting-native-readback");
                    assert_eq!(members[1].phase, "late-none-request-attempted");
                    Ok(())
                }
            )
            .unwrap(),
            Outcome::Pending
        );
    }
    #[test]
    fn invalid_second_phase_prevents_any_first_profile_unlink() {
        let (mut a, mut b) = (BatchIo::armed(), BatchIo::armed());
        let mut r = vec![receipt("prepared", None), receipt("corrupt", None)];
        assert!(drive_batch(
            &mut [&mut a, &mut b],
            &mut r,
            BOOT,
            &mut || panic!("native"),
            &mut |_, _| panic!("reboot")
        )
        .is_err());
        assert_eq!((a.unlinks, a.writes), (0, 0));
    }

    #[test]
    fn third_or_fourth_package_presence_prevents_every_final_commit() {
        for failed in [2, 3] {
            let mut profiles: Vec<_> = (0..4).map(|_| BatchIo::armed()).collect();
            for profile in &mut profiles {
                profile.present = false;
            }
            profiles[failed].absent = false;
            let mut receipts = vec![receipt("late-none-request-attempted", Some(BOOT)); 4];
            let mut native = 0;
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    OTHER,
                    &mut || {
                        native += 1;
                        Ok(())
                    },
                    &mut |_, _| panic!("absence failure requested reboot"),
                )
                .unwrap(),
                Outcome::Pending
            );
            drop(ios);
            assert_eq!(native, 1);
            assert!(profiles.iter().all(|p| p.final_writes == 0));
            assert!(receipts.iter().all(|r| r.phase != "late-none-final"));
            profiles[failed].absent = true;
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    OTHER,
                    &mut || Ok(()),
                    &mut |_, _| panic!("extra reboot")
                )
                .unwrap(),
                Outcome::Final
            );
            drop(ios);
            assert!(profiles.iter().all(|p| p.final_writes == 1));
        }
    }

    #[test]
    fn four_profiles_share_native_pass_and_single_reboot_across_replay() {
        let mut profiles: Vec<_> = (0..4).map(|_| BatchIo::armed()).collect();
        let mut receipts = vec![receipt("prepared", None); 4];
        let (mut native, mut reboots) = (0, 0);
        let mut claimed = false;
        for _ in 0..2 {
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    BOOT,
                    &mut || {
                        native += 1;
                        Ok(())
                    },
                    &mut |members, _| {
                        assert_eq!(members.len(), 4);
                        assert!(members
                            .iter()
                            .all(|r| r.phase == "late-none-request-attempted"));
                        if !claimed {
                            claimed = true;
                            reboots += 1;
                        }
                        Ok(())
                    }
                )
                .unwrap(),
                Outcome::Pending
            );
        }
        assert_eq!((native, reboots), (2, 1));
        assert!(profiles
            .iter()
            .all(|p| p.unlinks == 1 && p.final_writes == 0));
    }

    #[test]
    fn four_profile_partial_unlink_resumes_before_one_reboot() {
        let mut profiles: Vec<_> = (0..4).map(|_| BatchIo::armed()).collect();
        profiles[2].fail_unlink = true;
        let mut receipts = vec![receipt("prepared", None); 4];
        let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
        assert!(drive_batch(
            &mut ios,
            &mut receipts,
            BOOT,
            &mut || Ok(()),
            &mut |_, _| panic!("partial unlink reboot")
        )
        .is_err());
        drop(ios);
        assert!(!profiles[0].present && !profiles[1].present);
        assert!(profiles[2].present && profiles[3].present);
        profiles[2].fail_unlink = false;
        let mut reboots = 0;
        let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
        assert_eq!(
            drive_batch(
                &mut ios,
                &mut receipts,
                BOOT,
                &mut || Ok(()),
                &mut |_, _| {
                    reboots += 1;
                    Ok(())
                }
            )
            .unwrap(),
            Outcome::Pending
        );
        drop(ios);
        assert_eq!(reboots, 1);
        assert!(profiles.iter().all(|p| p.unlinks == 1));
    }

    #[test]
    fn empty_plural_collection_has_zero_native_or_reboot_calls() {
        assert_eq!(
            drive_batch(
                &mut [],
                &mut [],
                BOOT,
                &mut || panic!("empty native call"),
                &mut |_, _| panic!("empty reboot call")
            )
            .unwrap(),
            Outcome::NoResource
        );
    }

    #[test]
    fn fifth_or_sixth_file_failure_blocks_entire_six_profile_collection() {
        let count = 6;
        for failed in [4, 5] {
            let mut profiles: Vec<_> = (0..count).map(|_| BatchIo::armed()).collect();
            profiles[failed].fail_presence = true;
            let mut receipts = vec![receipt("prepared", None); count];
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert!(drive_batch(
                &mut ios,
                &mut receipts,
                BOOT,
                &mut || panic!("native before all file proofs"),
                &mut |_, _| panic!("reboot after failed file proof"),
            )
            .is_err());
            drop(ios);
            assert!(profiles
                .iter()
                .all(|p| p.writes == 0 && p.unlinks == 0 && p.final_writes == 0));
        }
    }

    #[test]
    fn fifth_or_sixth_package_presence_blocks_all_six_final_commits() {
        let count = 6;
        for failed in [4, 5] {
            let mut profiles: Vec<_> = (0..count).map(|_| BatchIo::armed()).collect();
            for profile in &mut profiles {
                profile.present = false;
            }
            profiles[failed].absent = false;
            let mut receipts = vec![receipt("late-none-request-attempted", Some(BOOT)); count];
            let mut native = 0;
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    OTHER,
                    &mut || {
                        native += 1;
                        Ok(())
                    },
                    &mut |_, _| panic!("package observer must not request reboot"),
                )
                .unwrap(),
                Outcome::Pending
            );
            drop(ios);
            assert_eq!(native, 1);
            assert!(profiles.iter().all(|p| p.final_writes == 0));
            assert!(receipts.iter().all(|r| r.phase != "late-none-final"));
            profiles[failed].absent = true;
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    OTHER,
                    &mut || Ok(()),
                    &mut |_, _| panic!("extra reboot")
                )
                .unwrap(),
                Outcome::Final
            );
            drop(ios);
            assert!(profiles.iter().all(|p| p.final_writes == 1));
        }
    }

    #[test]
    fn six_profiles_resume_fifth_unlink_with_one_helper_per_pass_and_one_reboot() {
        let count = 6;
        let mut profiles: Vec<_> = (0..count).map(|_| BatchIo::armed()).collect();
        profiles[4].fail_unlink = true;
        let mut receipts = vec![receipt("prepared", None); count];
        let mut native = 0;
        let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
        assert!(drive_batch(
            &mut ios,
            &mut receipts,
            BOOT,
            &mut || {
                native += 1;
                Ok(())
            },
            &mut |_, _| panic!("partial sixth-owner removal reboot")
        )
        .is_err());
        drop(ios);
        assert_eq!(native, 1);
        assert!(profiles[..4].iter().all(|p| !p.present));
        assert!(profiles[4..].iter().all(|p| p.present));
        profiles[4].fail_unlink = false;
        let (mut claimed, mut reboots) = (false, 0);
        for _ in 0..2 {
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    BOOT,
                    &mut || {
                        native += 1;
                        Ok(())
                    },
                    &mut |members, _| {
                        assert_eq!(members.len(), 6);
                        assert!(members
                            .iter()
                            .all(|r| r.phase == "late-none-request-attempted"));
                        if !claimed {
                            claimed = true;
                            reboots += 1;
                        }
                        Ok(())
                    }
                )
                .unwrap(),
                Outcome::Pending
            );
        }
        assert_eq!((native, reboots), (3, 1));
        assert!(profiles
            .iter()
            .all(|p| p.unlinks == 1 && p.final_writes == 0));
    }

    #[test]
    fn last_two_owned_failures_block_every_final_publication() {
        let count = voboost_shared::owned_overlay::Variant::ALL.len();
        assert_eq!(count, 20);
        for failed in [count - 2, count - 1] {
            for file_failure in [true, false] {
                let mut profiles: Vec<_> = (0..count).map(|_| BatchIo::armed()).collect();
                for profile in &mut profiles {
                    profile.present = false;
                }
                profiles[failed].fail_presence = file_failure;
                profiles[failed].absent = false;
                let mut receipts = vec![receipt("late-none-request-attempted", Some(BOOT)); count];
                let mut ios: Vec<&mut dyn Io> =
                    profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
                let result = drive_batch(
                    &mut ios,
                    &mut receipts,
                    OTHER,
                    &mut || Ok(()),
                    &mut |_, _| panic!("failed collection reboot"),
                );
                if file_failure {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), Outcome::Pending);
                }
                drop(ios);
                assert!(profiles.iter().all(|p| p.final_writes == 0));
                assert!(receipts.iter().all(|r| r.phase != "late-none-final"));
            }
        }
    }

    #[test]
    fn all_profiles_share_one_native_pass_and_resume_penultimate_unlink() {
        let count = voboost_shared::owned_overlay::Variant::ALL.len();
        assert_eq!(count, 20);
        let mut profiles: Vec<_> = (0..count).map(|_| BatchIo::armed()).collect();
        profiles[count - 2].fail_unlink = true;
        let mut receipts = vec![receipt("prepared", None); count];
        let mut native = 0;
        let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
        assert!(drive_batch(
            &mut ios,
            &mut receipts,
            BOOT,
            &mut || {
                native += 1;
                Ok(())
            },
            &mut |_, _| panic!("partial reboot")
        )
        .is_err());
        drop(ios);
        assert_eq!(native, 1);
        assert!(profiles[..count - 2].iter().all(|p| !p.present));
        assert!(profiles[count - 2..].iter().all(|p| p.present));
        profiles[count - 2].fail_unlink = false;
        let (mut claimed, mut reboots) = (false, 0);
        for _ in 0..2 {
            let mut ios: Vec<&mut dyn Io> = profiles.iter_mut().map(|p| p as &mut dyn Io).collect();
            assert_eq!(
                drive_batch(
                    &mut ios,
                    &mut receipts,
                    BOOT,
                    &mut || {
                        native += 1;
                        Ok(())
                    },
                    &mut |members, _| {
                        assert_eq!(members.len(), count);
                        assert!(members
                            .iter()
                            .all(|r| r.phase == "late-none-request-attempted"));
                        if !claimed {
                            claimed = true;
                            reboots += 1;
                        }
                        Ok(())
                    }
                )
                .unwrap(),
                Outcome::Pending
            );
        }
        assert_eq!((native, reboots), (3, 1));
        assert!(profiles.iter().all(|p| p.unlinks == 1));
    }
}
