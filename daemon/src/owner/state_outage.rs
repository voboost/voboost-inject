//! Closed native state-outage accounting for the emulator diagnostic.

// This module accounts only controller calls. Authentication, marker lifetime,
// serialization with the owner loop and receipt publication belong to its caller.
pub(super) const PW: &str = "vehicle-drive-pedestrian-warning";
pub(super) const DISARM: &str = "pedestrian-warning-disarm-pending";
const ARMED: &str = "pedestrian-warning-armed";
const CLEAN_STOP: &str = "pedestrian-warning-clean-stop-pending-reconcile";
const MAX_WINDOW_MS: u64 = 90_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FaultKind {
    Read,
    Write,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Scope {
    pub kind: FaultKind,
    pub token: String,
    pub boot: String,
    pub generation: String,
    pub catalog: String,
    pub owner_session: String,
    pub target_pid: i32,
    pub target_start: u64,
    pub deadline_ms: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Receipt {
    pub reads: u64,
    pub dropped: u64,
    pub writes: u64,
    pub failed_writes: u64,
    pub waits: u64,
    pub recovered_values: u64,
    pub recovered_value: Option<bool>,
    pub released: bool,
    pub stopped: bool,
    pub closed: bool,
}

pub(super) struct Observer {
    scope: Scope,
    receipt: Receipt,
    poisoned: bool,
    last_ms: u64,
    pending_read: Option<String>,
    lease: Option<u64>,
}

fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key(source: &str, key: &str) -> bool {
    source == PW && matches!(key, DISARM | ARMED | CLEAN_STOP)
}

impl Observer {
    pub fn begin(scope: Scope, now: u64) -> Result<Self, ()> {
        let boot = &scope.boot;
        if !hex(&scope.token, 64)
            || !hex(&scope.generation, 64)
            || !hex(&scope.catalog, 64)
            || !hex(&scope.owner_session, 32)
            || boot.len() != 36
            || !boot.bytes().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            || scope.target_pid <= 0
            || scope.target_start == 0
            || now == 0
            || scope
                .deadline_ms
                .checked_sub(now)
                .is_none_or(|delta| delta == 0 || delta > MAX_WINDOW_MS)
        {
            return Err(());
        }
        Ok(Self {
            scope,
            receipt: Receipt::default(),
            poisoned: false,
            last_ms: now,
            pending_read: None,
            lease: None,
        })
    }
    fn live(&mut self, scope: &Scope, now: u64) -> Result<(), ()> {
        if self.poisoned || self.receipt.closed || self.scope != *scope {
            return Err(());
        }
        if now < self.last_ms || now >= self.scope.deadline_ms {
            self.poisoned = true;
            return Err(());
        }
        self.last_ms = now;
        Ok(())
    }
    fn lease(&mut self, revision: u64) -> Result<(), ()> {
        if revision == 0 {
            self.poisoned = true;
            return Err(());
        }
        match self.lease {
            None => self.lease = Some(revision),
            Some(old) if old == revision && self.receipt.stopped => {
                self.poisoned = true;
                return Err(());
            }
            Some(old) if old == revision => (),
            Some(old) if self.receipt.released && self.receipt.stopped && revision > old => {
                self.lease = Some(revision);
                self.receipt.stopped = false;
            }
            _ => {
                self.poisoned = true;
                return Err(());
            }
        }
        Ok(())
    }
    // Returns true only when the exact native controller read must see Unavailable.
    pub fn read(
        &mut self,
        scope: &Scope,
        now: u64,
        revision: u64,
        source: &str,
        name: &str,
    ) -> bool {
        if !key(source, name) || self.live(scope, now).is_err() {
            return false;
        }
        if self.lease(revision).is_err() {
            return false;
        }
        let Some(reads) = self.receipt.reads.checked_add(1) else {
            self.poisoned = true;
            return false;
        };
        self.receipt.reads = reads;
        if self.receipt.released || self.scope.kind != FaultKind::Read {
            if self.receipt.released && self.pending_read.replace(name.to_string()).is_some() {
                self.poisoned = true;
            }
            return false;
        }
        let Some(dropped) = self.receipt.dropped.checked_add(1) else {
            self.poisoned = true;
            return false;
        };
        self.receipt.dropped = dropped;
        true
    }
    pub fn write(
        &mut self,
        scope: &Scope,
        now: u64,
        revision: u64,
        source: &str,
        name: &str,
    ) -> Result<bool, ()> {
        if !key(source, name) {
            return Err(());
        }
        self.live(scope, now)?;
        self.lease(revision)?;
        self.receipt.writes = self.receipt.writes.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
        })?;
        if self.scope.kind == FaultKind::Write && !self.receipt.released {
            self.receipt.failed_writes =
                self.receipt.failed_writes.checked_add(1).ok_or_else(|| {
                    self.poisoned = true;
                })?;
            return Ok(true);
        }
        Ok(false)
    }
    pub fn check_progress(
        &mut self,
        scope: &Scope,
        now: u64,
        revision: u64,
        source: &str,
    ) -> Result<(), ()> {
        if source != PW {
            return Err(());
        }
        self.live(scope, now)?;
        self.lease(revision)
    }
    pub fn wait_state(
        &mut self,
        scope: &Scope,
        now: u64,
        revision: u64,
        source: &str,
    ) -> Result<(), ()> {
        if source != PW {
            return Err(());
        }
        self.live(scope, now)?;
        self.lease(revision)?;
        self.receipt.waits = self.receipt.waits.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
        })?;
        Ok(())
    }
    pub fn stopped_write(
        &mut self,
        scope: &Scope,
        now: u64,
        source: &str,
        name: &str,
    ) -> Result<(), ()> {
        if !key(source, name) {
            return Err(());
        }
        self.live(scope, now)?;
        if self.lease.is_none() || self.receipt.stopped {
            self.poisoned = true;
            return Err(());
        }
        self.receipt.writes = self.receipt.writes.checked_add(1).ok_or_else(|| {
            self.poisoned = true;
        })?;
        Ok(())
    }
    pub fn invalidate(&mut self) {
        self.poisoned = true;
    }
    pub fn lease_revision(&self) -> Option<u64> {
        self.lease
    }
    pub fn released(&self) -> bool {
        self.receipt.released
    }

    pub fn stopped(&mut self, scope: &Scope, now: u64, source: &str) -> Result<(), ()> {
        if source != PW {
            return Err(());
        }
        self.live(scope, now)?;
        if self.lease.is_none() {
            self.poisoned = true;
            return Err(());
        }
        self.receipt.stopped = true;
        Ok(())
    }
    pub fn release(&mut self, scope: &Scope, now: u64) -> Result<(), ()> {
        self.live(scope, now)?;
        if self.receipt.released {
            return Err(());
        }
        self.receipt.released = true;
        Ok(())
    }
    pub fn read_value(
        &mut self,
        scope: &Scope,
        now: u64,
        revision: u64,
        source: &str,
        name: &str,
        value: Option<bool>,
    ) -> Result<(), ()> {
        if !key(source, name) {
            return Err(());
        }
        self.live(scope, now)?;
        self.lease(revision)?;
        if !self.receipt.released || self.pending_read.take().as_deref() != Some(name) {
            self.poisoned = true;
            return Err(());
        }
        let Some(value) = value else {
            return Ok(());
        };
        if name != ARMED {
            return Ok(());
        }
        self.receipt.recovered_value = Some(value);
        self.receipt.recovered_values =
            self.receipt
                .recovered_values
                .checked_add(1)
                .ok_or_else(|| {
                    self.poisoned = true;
                })?;
        Ok(())
    }
    pub fn snapshot(&mut self, scope: &Scope, now: u64) -> Result<Receipt, ()> {
        self.live(scope, now)?;
        Ok(self.receipt.clone())
    }
    pub fn close(&mut self, scope: &Scope, now: u64) -> Result<Receipt, ()> {
        self.live(scope, now)?;
        self.receipt.closed = true;
        Ok(self.receipt.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        Scope {
            kind: FaultKind::Read,
            token: "a".repeat(64),
            boot: "11111111-1111-1111-1111-111111111111".into(),
            generation: "b".repeat(64),
            catalog: "c".repeat(64),
            owner_session: "d".repeat(32),
            target_pid: 41,
            target_start: 514,
            deadline_ms: 1100,
        }
    }

    #[test]
    fn counter_receipts_are_bound_and_terminal_barriers_do_not_replay() {
        let s = scope();
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        assert!(o.read(&s, 101, 7, PW, DISARM));
        assert!(o.read(&s, 102, 7, PW, DISARM));
        o.wait_state(&s, 103, 7, PW).unwrap();
        o.wait_state(&s, 104, 7, PW).unwrap();
        let pending = o.snapshot(&s, 105).unwrap();
        assert_eq!((pending.dropped, pending.waits), (2, 2));
        o.stopped(&s, 106, PW).unwrap();
        let before = o.snapshot(&s, 107).unwrap();
        let after = o.snapshot(&s, 108).unwrap();
        assert!(before.stopped && after.stopped);
        assert_eq!((before.reads, before.writes), (after.reads, after.writes));
        o.release(&s, 109).unwrap();
        assert!(!o.read(&s, 109, 8, PW, ARMED));
        o.read_value(&s, 109, 8, PW, ARMED, Some(false)).unwrap();
        assert_eq!(o.snapshot(&s, 109).unwrap().recovered_values, 1);
        assert!(o.close(&s, 110).unwrap().closed);
        assert!(o.snapshot(&s, 111).is_err());
    }

    #[test]
    fn stopped_old_worker_cannot_manufacture_recovery_before_new_lease() {
        let s = scope();
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        assert!(o.read(&s, 101, 7, PW, DISARM));
        o.stopped(&s, 102, PW).unwrap();
        o.release(&s, 103).unwrap();
        let _ = o.read(&s, 104, 7, PW, ARMED);
        let _ = o.read_value(&s, 105, 7, PW, ARMED, Some(true));
        let _ = o.wait_state(&s, 106, 8, PW);
        assert!(
            o.snapshot(&s, 107).is_err(),
            "old worker must permanently invalidate recovery coverage"
        );
    }

    #[test]
    fn ordinary_stop_cleanup_before_stop_ack_remains_covered() {
        let s = scope();
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        assert!(o.read(&s, 101, 7, PW, DISARM));
        o.stopped_write(&s, 102, PW, CLEAN_STOP).unwrap();
        o.stopped(&s, 103, PW).unwrap();
        assert_eq!(o.snapshot(&s, 104).unwrap().writes, 1);
        o.release(&s, 105).unwrap();
        assert!(!o.read(&s, 106, 8, PW, ARMED));
        o.read_value(&s, 107, 8, PW, ARMED, Some(true)).unwrap();
        assert_eq!(o.snapshot(&s, 108).unwrap().recovered_value, Some(true));
    }

    #[test]
    fn stopped_old_lease_and_late_stop_write_poison_before_release() {
        let s = scope();
        for action in 0..4 {
            let mut o = Observer::begin(s.clone(), 100).unwrap();
            assert!(o.read(&s, 101, 7, PW, DISARM));
            o.stopped(&s, 102, PW).unwrap();
            match action {
                0 => {
                    let _ = o.read(&s, 103, 7, PW, ARMED);
                }
                1 => {
                    let _ = o.write(&s, 103, 7, PW, ARMED);
                }
                2 => {
                    let _ = o.stopped_write(&s, 103, PW, CLEAN_STOP);
                }
                _ => {
                    let _ = o.wait_state(&s, 103, 7, PW);
                }
            }
            assert!(
                o.snapshot(&s, 104).is_err(),
                "post-stop activity must invalidate coverage"
            );
        }
    }

    #[test]
    fn stale_lease_poison_is_not_recovered_by_later_success() {
        let s = scope();
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        assert!(o.read(&s, 101, 7, PW, DISARM));
        assert!(!o.read(&s, 102, 8, PW, DISARM));
        assert!(o.snapshot(&s, 103).is_err());
        assert!(!o.read(&s, 104, 7, PW, DISARM));
        assert!(o.snapshot(&s, 105).is_err());
    }

    #[test]
    fn value_requires_a_matched_actual_read_and_cannot_be_replayed() {
        let s = scope();
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        assert!(o.read(&s, 101, 7, PW, DISARM));
        o.release(&s, 102).unwrap();
        assert!(o.read_value(&s, 103, 7, PW, ARMED, Some(true)).is_err());
        assert!(o.snapshot(&s, 104).is_err());
        let mut other = Observer::begin(s.clone(), 100).unwrap();
        assert!(other.read(&s, 101, 7, PW, DISARM));
        other.release(&s, 102).unwrap();
        assert!(!other.read(&s, 103, 7, PW, ARMED));
        other
            .read_value(&s, 104, 7, PW, ARMED, Some(false))
            .unwrap();
        assert!(other
            .read_value(&s, 105, 7, PW, ARMED, Some(false))
            .is_err());
        assert!(other.snapshot(&s, 106).is_err());
    }

    #[test]
    fn write_failure_is_separate_from_read_and_stops_after_release() {
        let mut s = scope();
        s.kind = FaultKind::Write;
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        assert!(!o.read(&s, 101, 7, PW, ARMED));
        assert!(o.write(&s, 102, 7, PW, ARMED).unwrap());
        assert_eq!(o.snapshot(&s, 103).unwrap().failed_writes, 1);
        o.release(&s, 104).unwrap();
        assert!(!o.write(&s, 105, 7, PW, ARMED).unwrap());
        assert_eq!(o.snapshot(&s, 106).unwrap().failed_writes, 1);
    }

    #[test]
    fn foreign_identity_expiration_overflow_and_wrong_scope_never_admit_coverage() {
        let s = scope();
        let mut o = Observer::begin(s.clone(), 100).unwrap();
        for f in 0..7 {
            let mut bad = s.clone();
            match f {
                0 => bad.token = "e".repeat(64),
                1 => bad.boot = "foreign".into(),
                2 => bad.generation = "e".repeat(64),
                3 => bad.catalog = "e".repeat(64),
                4 => bad.owner_session = "e".repeat(32),
                5 => bad.target_pid += 1,
                _ => bad.target_start += 1,
            }
            assert!(!o.read(&bad, 101, 7, PW, DISARM));
            assert!(o.snapshot(&bad, 101).is_err());
        }
        assert!(!o.read(&s, 101, 7, "foreign", DISARM));
        assert!(!o.read(&s, 101, 7, PW, "foreign"));
        assert!(o.snapshot(&s, 1100).is_err());
        let mut overflow = Observer::begin(s.clone(), 100).unwrap();
        overflow.receipt.reads = u64::MAX;
        assert!(!overflow.read(&s, 101, 7, PW, DISARM));
        assert!(overflow.snapshot(&s, 102).is_err());
        let mut clock = Observer::begin(s.clone(), 100).unwrap();
        assert!(clock.snapshot(&s, 101).is_ok());
        assert!(clock.snapshot(&s, 100).is_err());
        assert!(clock.snapshot(&s, 102).is_err());
    }
}
