//! Bounded observations made only after a validated kernel receive.
use std::collections::VecDeque;
const CAPACITY: usize = 256;

#[derive(Default)]
pub(super) struct Journal {
    records: VecDeque<(u64, u64, String)>,
    // First target frames seen by this process, retained across ring overflow and reconnects.
    first_frames: std::collections::BTreeMap<u8, (u64, u64, u64, String)>,
    seq: u64,
    datagrams: u64,
    epoch: u64,
    dropped: u64,
    discarded: u64,
    unsupported: u64,
    errors: u64,
    active: bool,
    clock_error: bool,
    exhausted: bool,
    caught_up: bool,
    terminal_boot_ms: Option<u64>,
}
impl Journal {
    pub(super) fn next_datagram(&mut self) -> Option<(u64, u64)> {
        match self.datagrams.checked_add(1) {
            Some(sequence) => {
                self.datagrams = sequence;
                Some((sequence, self.epoch))
            }
            None => {
                self.exhausted = true;
                None
            }
        }
    }
    pub(super) fn open(&mut self) {
        match self.epoch.checked_add(1) {
            Some(epoch) => self.epoch = epoch,
            None => self.exhausted = true,
        }
        self.active = true;
        self.clock_error = false;
        self.records.clear();
        self.caught_up = false;
        self.terminal_boot_ms = None;
    }
    pub(super) fn close(&mut self) {
        self.active = false;
        self.caught_up = false;
    }
    pub(super) fn fail(&mut self) {
        match self.errors.checked_add(1) {
            Some(errors) => self.errors = errors,
            None => self.exhausted = true,
        }
        self.close();
    }
    pub(super) fn discard(&mut self) {
        match self.discarded.checked_add(1) {
            Some(discarded) => self.discarded = discarded,
            None => self.exhausted = true,
        }
    }
    pub(super) fn unsupported(&mut self) {
        self.unsupported = self.unsupported.saturating_add(1);
    }
    pub(super) fn clock_unavailable(&mut self) {
        self.clock_error = true;
        self.caught_up = false;
    }
    pub(super) fn polling(&mut self) {
        self.caught_up = false;
    }
    pub(super) fn caught_up(&mut self, time: Option<u64>) {
        self.terminal_boot_ms = time;
        self.caught_up = time.is_some();
        if time.is_none() {
            self.clock_error = true;
        }
    }
    pub(super) fn record(&mut self, frame: &[u8], time: Option<u64>) {
        let Some(time) = time else {
            self.clock_error = true;
            return;
        };
        let Some(seq) = self.seq.checked_add(1) else {
            self.exhausted = true;
            return;
        };
        self.seq = seq;
        if frame.len() == 10 && frame[1] == 8 && matches!(frame[0], 0x6a | 0x73 | 0x9a) {
            self.first_frames
                .entry(frame[0])
                .or_insert_with(|| (seq, self.epoch, time, hex::encode(frame)));
        }
        if self.records.len() == CAPACITY {
            self.records.pop_front();
            match self.dropped.checked_add(1) {
                Some(dropped) => self.dropped = dropped,
                None => self.exhausted = true,
            }
        }
        self.records.push_back((seq, time, hex::encode(frame)));
    }
    pub(super) fn snapshot(&self, cursor: u64, boot: &str, writer: &str) -> serde_json::Value {
        let earliest = self
            .records
            .front()
            .map_or(self.seq.saturating_add(1), |entry| entry.0);
        let records: Vec<_> = self.records.iter().filter(|entry| entry.0 > cursor).map(|(seq, time, frame)| serde_json::json!({"seq":seq.to_string(), "receiveBootMs":time.to_string(), "frameHex":frame})).collect();
        let first_frames: Vec<_> = self.first_frames.values().map(|(seq, epoch, time, frame)| {
    serde_json::json!({"seq":seq.to_string(), "receiverEpoch":epoch.to_string(), "receiveBootMs":time.to_string(), "frameHex":frame})
}).collect();
        serde_json::json!({"schemaVersion":1, "producer":"actual_kernel_rx", "bootId":boot, "writerId":writer, "receiverEpoch":self.epoch.to_string(), "status":if !self.active || self.clock_error || self.exhausted { "unavailable" } else if !self.caught_up { "draining" } else { "active" }, "earliestSeq":earliest.to_string(), "latestSeq":self.seq.to_string(), "nextCursor":self.seq.to_string(), "dropped":self.dropped.to_string(), "discarded":self.discarded.to_string(), "unsupportedDatagrams":self.unsupported.to_string(), "errors":self.errors.to_string(), "hasMore":false, "gap":cursor > self.seq || cursor.saturating_add(1) < earliest, "sampledBootMs":self.terminal_boot_ms.map(|n| n.to_string()), "records":records, "firstTargetFrames":first_frames})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_target_receive_survives_overflow_and_receiver_reopen() {
        let mut j = Journal::default();
        j.open();
        let first = [0x9a, 8, 0, 0, 0, 0, 0, 0, 4, 0];
        j.record(&first, Some(2800));
        for _ in 0..600 {
            j.record(&[0x73, 8, 1, 0, 0, 0, 0, 0, 0, 0], Some(3000));
        }
        j.close();
        j.open();
        j.record(&[0x9a, 8, 0, 0, 0, 0, 0, 0, 16, 0], Some(15000));
        let page = j.snapshot(0, "boot", "writer");
        let initial = page["firstTargetFrames"]
            .as_array()
            .unwrap()
            .iter()
            .find(|frame| frame["frameHex"] == hex::encode(first))
            .unwrap();
        assert_eq!(initial["receiveBootMs"], "2800");
        assert_eq!(initial["receiverEpoch"], "1");
        assert_eq!(initial["seq"], "1");
        assert_eq!(page["firstTargetFrames"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn repeated_frames_and_overflow_are_visible() {
        let mut j = Journal::default();
        j.open();
        j.caught_up(Some(0));
        j.record(&[0x71, 0], Some(1));
        j.record(&[0x71, 0], Some(2));
        assert_eq!(
            j.snapshot(0, "boot", "writer")["records"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        for _ in 0..600 {
            j.record(&[0x71, 0], Some(3));
        }
        assert_eq!(j.snapshot(0, "boot", "writer")["gap"], true);
    }
    #[test]
    fn terminal_requires_empty_queue_and_uses_pre_receive_clock() {
        let mut j = Journal::default();
        j.open();
        assert_eq!(j.snapshot(0, "b", "w")["status"], "draining");
        j.caught_up(Some(41));
        let page = j.snapshot(0, "b", "w");
        assert_eq!(page["status"], "active");
        assert_eq!(page["sampledBootMs"], "41");
        j.polling();
        assert_eq!(j.snapshot(0, "b", "w")["status"], "draining");
        j.caught_up(None);
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");
    }
    #[test]
    fn exhausted_epoch_and_counters_never_restore_coverage() {
        let mut j = Journal {
            epoch: u64::MAX,
            ..Journal::default()
        };
        j.open();
        j.caught_up(Some(1));
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");
        let mut j = Journal::default();
        j.open();
        j.discarded = u64::MAX;
        j.discard();
        j.caught_up(Some(1));
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");
        j.close();
        j.open();
        j.caught_up(Some(2));
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");

        let mut j = Journal::default();
        j.open();
        j.seq = u64::MAX;
        j.record(&[1, 0], Some(1));
        j.close();
        j.open();
        j.caught_up(Some(2));
        assert_eq!(j.snapshot(u64::MAX, "b", "w")["status"], "unavailable");

        let mut j = Journal::default();
        j.open();
        j.errors = u64::MAX;
        j.fail();
        j.open();
        j.caught_up(Some(2));
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");

        let mut j = Journal::default();
        j.open();
        j.dropped = u64::MAX;
        for _ in 0..=CAPACITY {
            j.record(&[1, 0], Some(1));
        }
        j.close();
        j.open();
        j.caught_up(Some(2));
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");
    }
    #[test]
    fn policy_discard_preserves_epoch_and_clock_failure_blocks_coverage() {
        let mut j = Journal::default();
        j.open();
        let epoch = j.epoch;
        j.discard();
        assert_eq!(j.snapshot(0, "b", "w")["discarded"], "1");
        assert_eq!(j.epoch, epoch);
        j.record(&[1, 0], None);
        assert_eq!(j.snapshot(0, "b", "w")["status"], "unavailable");
        j.close();
        j.open();
        assert_eq!(j.epoch, epoch + 1);
    }
}
