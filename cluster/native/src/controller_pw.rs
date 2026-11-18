//! Volatile UI-process view of a service-authenticated native PW lease.
//! This is a read-only host seam, never an OEM lifecycle/readiness producer.
use crate::{controller::Spin, engine::Authority, Result};
use voboost_contract_core::pw_live::{Actual, Proof, MAX_SOURCE_AGE_MS};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HostLease {
    pub size: u32,
    pub abi: u32,
    pub config_revision: u64,
    pub endpoint_identity: u64,
    pub lifecycle_generation: u64,
    pub document_generation: u64,
    pub observation_sequence: u64,
    pub enabled: u32,
    pub desired_disabled: u32,
    pub actual: u32,
    pub remaining_ms: u32,
}
struct State {
    sample: Option<Proof>,
    deadline: u64,
    admitted_at: u64,
}
static STATE: Spin<State> = Spin::new(State {
    sample: None,
    deadline: 0,
    admitted_at: 0,
});

pub fn revoke() {
    // Keep the last source sequence: clearing authority must not make replay a
    // fresh sample, even after an explicit unknown/disable.
    STATE.with(|s| s.deadline = 0);
}

pub fn admit(a: &Authority, proof: Option<Proof>, deadline: u64, now: u64) -> Result<()> {
    let Some(p) = proof else {
        revoke();
        return Ok(());
    };
    p.validate()?;
    let g = a
        .generation
        .as_ref()
        .ok_or("PW controller generation absent")?;
    let d = a.desired.as_ref().ok_or("PW controller desired absent")?;
    let selected = d
        .agents
        .iter()
        .find(|v| v.id == "vehicle-drive-pedestrian-warning")
        .ok_or("PW controller target absent")?;
    // Reopening Authority intentionally generates a NEW random service epoch;
    // the actual running epoch is retained in this protected startup receipt.
    // Reading it has no heartbeat/persistence side effects.
    let service: crate::service::ServiceRecord =
        voboost_contract_core::parse_canonical(&a.root.read("service.json", 4096, 0o600)?, 4096)?;
    if p.challenge.native_boot != voboost_contract_core::hash(a.boot_id.as_bytes())
        || p.challenge.pair_id != a.config.pair_id
        || p.challenge.generation_id != g.generation_id
        || p.challenge.desired_revision != d.desired_revision
        || p.challenge.desired_sha256 != d.desired_sha256
        || p.desired_disabled != selected.enabled
        || !epoch_matches(&p, &service, &a.boot_id)
        || deadline <= now
        || deadline - now > MAX_SOURCE_AGE_MS
    {
        revoke();
        return Err("PW controller current authority mismatch".into());
    }
    store(p, deadline, now)
}

fn epoch_matches(p: &Proof, service: &crate::service::ServiceRecord, boot: &str) -> bool {
    service.schema_version == 1
        && service.running
        && service.pid > 0
        && service.boot_id == boot
        && service.daemon_epoch == p.challenge.native_epoch
}

fn store(p: Proof, deadline: u64, now: u64) -> Result<()> {
    STATE.with(|s| {
        if let Some(old) = &s.sample {
            let same_source = old.challenge.native_epoch == p.challenge.native_epoch
                && old.endpoint_identity == p.endpoint_identity
                && old.lifecycle_generation == p.lifecycle_generation;
            if same_source && p.observation_sequence <= old.observation_sequence {
                // Exact duplicates retain the earlier absolute deadline. They
                // cannot reinstate an explicitly revoked/expired lease.
                if p == *old {
                    return Ok(());
                }
                s.deadline = 0;
                return Err("PW controller stale/conflicting source".into());
            }
        }
        s.sample = Some(p);
        s.deadline = deadline;
        s.admitted_at = now;
        Ok(())
    })
}

/// # Safety
/// `out` must point to a writable HostLease with an initialized size field.
/// No authority may be published through this function; callers only read it.
#[no_mangle]
pub unsafe extern "C" fn vbc_controller_pw_lease(out: *mut HostLease) -> i32 {
    let Some(out) = out.as_mut() else {
        return -1;
    };
    if out.size < core::mem::size_of::<HostLease>() as u32 || out.abi != 1 {
        return -1;
    }
    let size = out.size;
    *out = HostLease {
        size,
        abi: 1,
        ..HostLease::default()
    };
    let Some(now) = crate::engine::monotonic_ms() else {
        return 0;
    };
    copy_at(out, now, crate::controller::pw_matches_current)
}

fn copy_at(out: &mut HostLease, now: u64, current: impl FnOnce(&Proof) -> bool) -> i32 {
    STATE.with(|s| {
        let Some(p) = &s.sample else {
            return 0;
        };
        if now < s.admitted_at
            || s.deadline <= now
            || s.deadline - now > MAX_SOURCE_AGE_MS
            || !current(p)
        {
            return 0;
        }
        out.config_revision = p.challenge.desired_revision;
        out.endpoint_identity = p.endpoint_identity;
        out.lifecycle_generation = p.lifecycle_generation;
        out.document_generation = p.document_generation;
        out.observation_sequence = p.observation_sequence;
        out.enabled = 1;
        out.desired_disabled = p.desired_disabled as u32;
        out.actual = match p.actual {
            Actual::Unknown => 0,
            Actual::Enabled => 1,
            Actual::Disabled => 2,
        };
        out.remaining_ms = (s.deadline - now) as u32;
        1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use voboost_contract_core::pw_live::Challenge;
    #[test]
    fn duplicate_and_revocation_do_not_extend_lease() {
        assert_eq!(core::mem::size_of::<HostLease>(), 64);
        assert_eq!(core::mem::offset_of!(HostLease, config_revision), 8);
        assert_eq!(core::mem::offset_of!(HostLease, remaining_ms), 60);
        let p = Proof {
            challenge: Challenge {
                schema_version: 1,
                native_boot: "1".repeat(64),
                native_epoch: "2".repeat(64),
                nonce: "3".repeat(64),
                pair_id: "4".repeat(64),
                generation_id: "5".repeat(64),
                desired_revision: 1,
                desired_sha256: "6".repeat(64),
                desired_disabled: true,
            },
            endpoint_identity: 1,
            document_generation: 1,
            lifecycle_generation: 1,
            observation_sequence: 1,
            source_age_ms: 0,
            desired_disabled: true,
            actual: Actual::Disabled,
        };
        let mut service = crate::service::ServiceRecord {
            schema_version: 1,
            pid: 1,
            boot_id: "boot".into(),
            daemon_epoch: p.challenge.native_epoch.clone(),
            generation_id: Some(p.challenge.generation_id.clone()),
            desired_revision: 1,
            desired_sha256: p.challenge.desired_sha256.clone(),
            running: true,
        };
        assert!(epoch_matches(&p, &service, "boot"));
        service.daemon_epoch = "7".repeat(64);
        assert!(!epoch_matches(&p, &service, "boot"));
        service.daemon_epoch = p.challenge.native_epoch.clone();
        service.running = false;
        assert!(!epoch_matches(&p, &service, "boot"));
        service.running = true;
        assert!(!epoch_matches(&p, &service, "other-boot"));
        let mut abi = HostLease {
            size: 64,
            abi: 2,
            ..HostLease::default()
        };
        assert_eq!(unsafe { vbc_controller_pw_lease(&mut abi) }, -1);
        STATE.with(|s| {
            s.sample = None;
            s.deadline = 0;
        });
        store(p.clone(), 500, 100).unwrap();
        store(p.clone(), 800, 100).unwrap();
        assert_eq!(STATE.with(|s| s.deadline), 500);
        revoke();
        store(p.clone(), 900, 100).unwrap();
        assert_eq!(STATE.with(|s| s.deadline), 0);
        let mut conflicting = p.clone();
        conflicting.actual = Actual::Enabled;
        assert!(store(conflicting, 900, 100).is_err());
        let mut fresh = p;
        fresh.observation_sequence = 2;
        store(fresh, 950, 100).unwrap();
        assert_eq!(STATE.with(|s| s.deadline), 950);
        let mut out = HostLease {
            size: 64,
            abi: 1,
            ..HostLease::default()
        };
        assert_eq!(copy_at(&mut out, 949, |_| true), 1);
        assert_eq!(out.remaining_ms, 1);
        assert_eq!(out.actual, 2);
        assert_eq!(copy_at(&mut out, 950, |_| true), 0);
        assert_eq!(copy_at(&mut out, 949, |_| false), 0);
        assert_eq!(copy_at(&mut out, 1, |_| true), 0); // Backwards native clock is unknown.
        assert_eq!(copy_at(&mut out, 950 + MAX_SOURCE_AGE_MS, |_| true), 0);
        revoke();
        assert_eq!(copy_at(&mut out, 949, |_| true), 0);
    }
}
