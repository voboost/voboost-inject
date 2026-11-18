//! In-memory native contract fixture; never compiled into a product executable.
use super::*;
use std::collections::BTreeMap;

pub struct ContextFixture {
    pub current_lease: Option<Lease>,
    pub now: u64,
    pub epoch: Option<u64>,
    pub intent: Read<bool>,
    pub options: BTreeMap<String, String>,
    pub state: BTreeMap<String, Read<bool>>,
    pub signals: BTreeMap<String, Read<i32>>,
    pub inputs: Read<Vec<u8>>,
    pub early: bool,
    pub ready: bool,
    pub cancel_send: bool,
    pub fail_write: Option<usize>,
    pub writes: Vec<(String, bool)>,
    pub sent: Vec<Command>,
    pub submitted: Vec<Command>,
    pub pending_send: bool,
    pub in_flight: Option<(Lease, Command)>,
    pub waiting_send: Option<Wait>,
}
impl Default for ContextFixture {
    fn default() -> Self {
        Self {
            current_lease: Some(Lease { revision: 1 }),
            now: 0,
            epoch: Some(1),
            intent: Read::Missing,
            options: BTreeMap::new(),
            state: BTreeMap::new(),
            signals: BTreeMap::new(),
            inputs: Read::Unavailable,
            early: true,
            ready: true,
            cancel_send: false,
            fail_write: None,
            writes: Vec::new(),
            sent: Vec::new(),
            submitted: Vec::new(),
            pending_send: false,
            in_flight: None,
            waiting_send: None,
        }
    }
}
impl Context for ContextFixture {
    fn lease(&self) -> Option<Lease> {
        self.current_lease
    }
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn power_epoch(&self) -> Option<u64> {
        self.epoch
    }
    fn intent(&self) -> Read<bool> {
        self.intent.clone()
    }
    fn option(&self, key: &str) -> Option<String> {
        self.options.get(key).cloned()
    }
    fn read_state(&self, key: &str) -> Read<bool> {
        self.state.get(key).cloned().unwrap_or(Read::Missing)
    }
    fn write_state(&mut self, lease: Lease, key: &str, value: bool) -> Result<(), Failure> {
        if self.current_lease != Some(lease) {
            return Err(Failure::Cancelled);
        }
        if self.fail_write == Some(self.writes.len() + 1) {
            return Err(Failure::StateUnavailable);
        }
        self.writes.push((key.into(), value));
        self.state.insert(key.into(), Read::Value(value));
        Ok(())
    }
    fn feedback(&self, key: &str) -> Read<i32> {
        self.signals.get(key).cloned().unwrap_or(Read::Unavailable)
    }
    fn transport_ready(&self) -> bool {
        self.ready
    }
    fn send(&mut self, lease: Lease, command: Command) -> Result<Transmission, Failure> {
        if self.cancel_send {
            self.current_lease = Some(Lease {
                revision: lease.revision + 1,
            });
        }
        if self.current_lease != Some(lease) {
            return Err(Failure::Cancelled);
        }
        if let Some(wait) = self.waiting_send {
            return Ok(Transmission::Waiting(wait));
        }
        if !self.ready {
            return Ok(Transmission::Waiting(Wait::Transport));
        }
        if self.early && !matches!(self.inputs, Read::Value(_)) {
            return Ok(Transmission::Waiting(Wait::Inputs));
        }
        if let Some(operation) = self.in_flight {
            if operation != (lease, command) {
                return Ok(Transmission::Waiting(Wait::Transport));
            }
        } else {
            self.submitted.push(command);
            self.in_flight = Some((lease, command));
        }
        if self.pending_send {
            return Ok(Transmission::Pending);
        }
        self.in_flight = None;
        self.sent.push(command);
        Ok(Transmission::Accepted)
    }
}

impl StopContext for ContextFixture {
    fn write_state(&mut self, key: &str, value: bool) -> Result<(), Failure> {
        let lease = self.current_lease.ok_or(Failure::Cancelled)?;
        Context::write_state(self, lease, key, value)
    }
}
