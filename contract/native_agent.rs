//! In-process native agent contract. Persistence and transport stay with the owner.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read<T> {
    Missing,
    Unavailable,
    Value(T),
}

/// Current source-scoped user-intent revision, issued only to the active controller owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command {
    pub state: &'static str,
    pub value: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    StateUnavailable,
    InvalidValue,
    Cancelled,
    TransportUnavailable,
    ReadbackTimeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    Ownership,
    State,
    Feedback,
    Transport,
    Inputs,
    Mode,
    Reply,
    UserChoice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Idle,
    Waiting(Wait),
    Applied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transmission {
    Waiting(Wait),
    Pending,
    Accepted,
}

pub trait Context {
    /// Missing ownership never authorizes state or CAN mutations.
    fn lease(&self) -> Option<Lease>;
    fn now_ms(&self) -> u64;
    /// Boot activation, observed ACC reset, or proven host suspend followed by fresh ACC2.
    /// Socket reconnect and a plain poll delay alone never create an activation.
    fn power_epoch(&self) -> Option<u64>;
    /// Latest durable explicit choice for this source's restore permission.
    /// Missing permits first-observation seeding; Unavailable never does.
    fn intent(&self) -> Read<bool>;
    fn option(&self, key: &str) -> Option<String>;
    fn read_state(&self, key: &str) -> Read<bool>;
    /// Confirm durable persistence under the same current lease before success.
    fn write_state(&mut self, lease: Lease, key: &str, value: bool) -> Result<(), Failure>;
    /// Only fresh, source-probed samples in the current power epoch may be returned as Value.
    fn feedback(&self, key: &str) -> Read<i32>;
    fn transport_ready(&self) -> bool;
    /// Recheck current ownership, enabled intent, lease revision and input authority at emission.
    /// Waiting does not submit; Pending polls once; Accepted means the selected operation completed.
    /// Only independent post-admission feedback proves application.
    fn send(&mut self, lease: Lease, command: Command) -> Result<Transmission, Failure>;
}

/// State-only cleanup for a controller whose source is explicitly disabled.
pub trait StopContext {
    fn write_state(&mut self, key: &str, value: bool) -> Result<(), Failure>;
}

pub trait Agent {
    /// One source-authenticated Electric click; None means transport is still pending.
    /// Some(true) means accepted transmission, not independent vehicle feedback.
    fn electric_click(
        &mut self,
        _context: &mut dyn Context,
        _id: u64,
    ) -> Result<Option<bool>, Failure> {
        Ok(Some(false))
    }
    /// A user gesture has drained this source; do not restore over its next mode selection.
    fn electric_click_finished(&mut self, _lease: Option<Lease>, _epoch: Option<u64>) {}
    fn step(&mut self, context: &mut dyn Context) -> Result<Progress, Failure>;
    fn stop(&mut self, context: &mut dyn StopContext) -> Result<(), Failure>;
}

#[cfg(test)]
#[path = "native_agent.test.rs"]
pub mod testing;
