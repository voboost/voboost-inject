//! Native codec bindings compiled from agent-owned source metadata.
mod can;
mod capture;
mod clock;
mod compatibility;
mod context;
mod inputs;
mod rx;
mod transmit;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
pub struct Codec {
    pub id: &'static str,
    pub applicability: &'static str,
    pub fields: &'static [&'static str],
    pub pending_journals: &'static [&'static str],
    pub commands: &'static [crate::native_api::Command],
    pub encode: fn(&[u8], crate::native_api::Command) -> Option<[u8; 10]>,
    pub feedback: fn(&[u8]) -> Option<(&'static str, i32)>,
    pub create: fn() -> Box<dyn crate::native_api::Agent>,
}

include!(concat!(env!("OUT_DIR"), "/native_registry.rs"));

/// The Store owns this revocation value; zero denies transmission.
#[derive(Clone)]
pub(super) struct Admission {
    pub lease: crate::native_api::Lease,
    pub fence: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Admission {
    pub(super) fn current(&self) -> bool {
        self.lease.revision != 0
            && self.fence.load(std::sync::atomic::Ordering::Acquire) == self.lease.revision
    }
}

/// Source-scoped persistence and execution admission supplied by the sole owner.
pub(super) trait Host {
    fn admission(&self, source: &str) -> Option<Admission>;
    fn enabled(&self, source: &str) -> bool;
    fn action_allowed(&self, source: &str) -> bool {
        self.enabled(source)
    }
    fn command_transport_ready(&self, source: &str) -> bool;
    fn vehicle_observation(
        &self,
        _source: &str,
    ) -> Option<voboost_contract::runtime_owner::NativeVehicleObservation> {
        None
    }

    fn send_command(
        &mut self,
        source: &str,
        lease: crate::native_api::Lease,
        command: crate::native_api::Command,
    ) -> Result<crate::native_api::Transmission, crate::native_api::Failure>;
    fn withdraw_command(&mut self, source: &str, lease: crate::native_api::Lease, completed: bool);
    fn action_identity(
        &self,
        _source: &str,
    ) -> Option<voboost_contract::runtime_owner::NativeCommandIdentity> {
        None
    }
    fn action_terminal(
        &mut self,
        _identity: &voboost_contract::runtime_owner::NativeCommandIdentity,
    ) -> Option<voboost_contract::runtime_owner::NativeCommandStatus> {
        None
    }

    fn write_stopped_state(
        &mut self,
        source: &str,
        key: &str,
        value: bool,
    ) -> Result<(), crate::native_api::Failure>;
    fn intent(&self, source: &str) -> crate::native_api::Read<bool>;
    fn option(&self, source: &str, key: &str) -> Option<String>;
    fn read_state(&self, source: &str, key: &str) -> crate::native_api::Read<bool>;
    fn read_controller_state(&self, source: &str, key: &str) -> crate::native_api::Read<bool> {
        self.read_state(source, key)
    }
    // Emulator diagnostics may account for the controller call before IO.
    // The production default does not alter state operations.
    fn diagnostic_stale_read(&self, _source: &str, _lease: crate::native_api::Lease, _key: &str) {}
    fn diagnostic_stale_write(
        &mut self,
        _source: &str,
        _lease: crate::native_api::Lease,
        _key: &str,
    ) {
    }
    fn diagnostic_state_read(
        &self,
        _source: &str,
        _lease: crate::native_api::Lease,
        _key: &str,
    ) -> bool {
        false
    }
    fn diagnostic_state_read_complete(
        &self,
        _source: &str,
        _lease: crate::native_api::Lease,
        _key: &str,
        _result: &crate::native_api::Read<bool>,
    ) {
    }
    fn diagnostic_state_write(
        &mut self,
        _source: &str,
        _lease: crate::native_api::Lease,
        _key: &str,
    ) -> bool {
        false
    }
    fn diagnostic_progress(
        &mut self,
        _source: &str,
        _lease: crate::native_api::Lease,
        _result: Result<crate::native_api::Progress, crate::native_api::Failure>,
    ) {
    }
    fn diagnostic_stopped_write(&mut self, _source: &str, _key: &str) {}
    fn diagnostic_stopped(&mut self, _source: &str) {}
    fn write_state(
        &mut self,
        source: &str,
        lease: crate::native_api::Lease,
        key: &str,
        value: bool,
    ) -> Result<(), crate::native_api::Failure>;
    fn write_controller_state(
        &mut self,
        source: &str,
        lease: crate::native_api::Lease,
        key: &str,
        value: bool,
    ) -> Result<(), crate::native_api::Failure> {
        self.write_state(source, lease, key, value)
    }
}

pub enum Event {
    Datagram {
        capture: capture::Datagram,
        sequence: u64,
        epoch: u64,
    },
    InputsUnavailable {
        reason: String,
        expected: bool,
    },
    TransmitterUnavailable {
        reason: String,
        expected: bool,
    },
    CapabilityUnavailable {
        source: &'static str,
        reason: String,
    },
    Controller {
        source: &'static str,
        result: Result<crate::native_api::Progress, crate::native_api::Failure>,
    },
    ReceiverAvailable,
    ReceiverUnavailable(String),
    Sample {
        source: &'static str,
        key: &'static str,
        value: i32,
    },
}

/// A received kernel sample, not an authoritative user choice or fresh ECU acknowledgement.
pub struct Sample {
    pub value: i32,
    pub received_at: clock::Stamp,
}

pub struct Runtime {
    enabled: BTreeSet<&'static str>,
    receiver: Option<can::Receiver>,
    rx: rx::Journal,
    rx_lease_until: Option<u64>,
    samples: BTreeMap<&'static str, BTreeMap<&'static str, Sample>>,
    retry_at: Instant,
    available: bool,
    last_error: Option<String>,
    controllers: BTreeMap<&'static str, Box<dyn crate::native_api::Agent>>,
    electric_action_key: Option<voboost_contract::desired::Input>,
    electric_action_result: Option<voboost_contract::runtime_owner::ElectricClickStatus>,
    electric_action_pending: Option<u64>,
    electric_action_identity: Option<voboost_contract::runtime_owner::NativeCommandIdentity>,
    electric_action_fence: Option<(crate::native_api::Lease, u64)>,
    controller_activations: BTreeMap<&'static str, u64>,
    progress:
        BTreeMap<&'static str, Result<crate::native_api::Progress, crate::native_api::Failure>>,
    sender: Option<transmit::Sender>,
    sender_retry_at: Instant,
    activated: u64,
    power: Option<bool>,
    power_observed: bool,
    wake_pending: bool,
    discard_rx: bool,
    feedback_after_ms: Option<u64>,
    started_at: Instant,
    inputs: Option<inputs::Inputs>,
    inputs_retry_at: Instant,
    inputs_start_error: Option<String>,
    inputs_error: Option<(String, bool)>,
    observed_clock: clock::Stamp,
    compatible: BTreeSet<&'static str>,
    profile: compatibility::Profile,
    probed_powertrain: Option<Option<&'static str>>,
    requested: BTreeSet<&'static str>,
    probe_powertrain: bool,
    capability_errors: BTreeMap<&'static str, String>,
    transmit_error: Option<(String, bool)>,
    late: bool,
}

impl Default for Runtime {
    fn default() -> Self {
        let profile = compatibility::Profile::current();
        Self {
            enabled: BTreeSet::new(),
            receiver: None,
            rx: rx::Journal::default(),
            rx_lease_until: None,
            samples: BTreeMap::new(),
            retry_at: Instant::now(),
            available: false,
            last_error: None,
            controllers: BTreeMap::new(),
            electric_action_key: None,
            electric_action_result: None,
            electric_action_pending: None,
            electric_action_identity: None,
            electric_action_fence: None,
            controller_activations: BTreeMap::new(),
            progress: BTreeMap::new(),
            sender: None,
            sender_retry_at: Instant::now(),
            activated: 0,
            power: None,
            power_observed: false,
            wake_pending: false,
            discard_rx: false,
            feedback_after_ms: None,
            started_at: Instant::now(),
            inputs: None,
            inputs_retry_at: Instant::now(),
            inputs_start_error: None,
            inputs_error: None,
            observed_clock: clock::Stamp::now(),
            compatible: CODECS
                .iter()
                .filter(|codec| profile.permits(codec.applicability))
                .map(|codec| codec.id)
                .collect(),
            profile,
            probed_powertrain: None,
            requested: BTreeSet::new(),
            probe_powertrain: false,
            capability_errors: BTreeMap::new(),
            transmit_error: None,
            late: false,
        }
    }
}

impl Runtime {
    // The stage is process-local and resets when the owner restarts; no file is modified.
    fn enter_late(&mut self) {
        if self.late {
            return;
        }
        self.late = true;
        if let Some(inputs) = self.inputs.as_mut() {
            inputs.finish_bootstrap();
        }
        self.samples.clear();
        self.discard_rx = true;
        if let Some(sender) = self.sender.as_mut() {
            sender.retire();
        }
    }

    pub fn configure(&mut self, enabled: &BTreeSet<String>) {
        let requested = CODECS
            .iter()
            .filter(|codec| enabled.contains(codec.id))
            .map(|codec| codec.id)
            .collect();
        if self.requested != requested {
            self.requested = requested;
            self.probe_powertrain = CODECS.iter().any(|codec| {
                self.requested.contains(codec.id)
                    && self.profile.needs_powertrain_probe(codec.applicability)
            });
        }
        let count = CODECS
            .iter()
            .filter(|codec| enabled.contains(codec.id) && self.compatible.contains(codec.id))
            .count();
        if self.enabled.len() == count && self.enabled.iter().all(|id| enabled.contains(*id)) {
            return;
        }
        self.enabled = CODECS
            .iter()
            .filter(|codec| enabled.contains(codec.id) && self.compatible.contains(codec.id))
            .map(|codec| codec.id)
            .collect();
        self.samples.retain(|id, _| self.enabled.contains(id));
        self.retry_at = Instant::now();
        if self.enabled.is_empty() {
            if !self.wants_receiver(clock::Stamp::now().boot_ms) {
                self.close_receiver();
            }
            self.power_observed = false;
            self.available = false;
            self.last_error = None;
        }
    }
    fn wants_receiver(&self, now: Option<u64>) -> bool {
        !self.enabled.is_empty()
            || now
                .zip(self.rx_lease_until)
                .is_some_and(|(now, until)| now < until)
    }

    fn close_receiver(&mut self) {
        self.receiver = None;
        self.rx.close();
        self.available = false;
    }

    fn observe_rx(&mut self, now: Option<u64>) {
        if !self.wants_receiver(now) {
            self.close_receiver();
        }
        self.rx_lease_until = now.and_then(|time| time.checked_add(15000));
        if self.rx_lease_until.is_none() {
            self.rx.clock_unavailable();
        }
    }

    pub(super) fn touch_rx(&mut self) {
        self.observe_rx(clock::Stamp::now().boot_ms);
    }

    pub(super) fn rx_snapshot(&self, cursor: u64, boot: &str, writer: &str) -> serde_json::Value {
        self.rx.snapshot(cursor, boot, writer)
    }

    pub fn sample(&self, source: &str, key: &str) -> Option<&Sample> {
        self.samples.get(source)?.get(key)
    }

    /// Drain at most 32 datagrams per poll until EAGAIN. Only later telemetry
    /// can satisfy a new PW challenge; buffered pre-challenge frames cannot.
    pub(super) fn begin_pw_readback(&mut self) {
        self.samples.remove("vehicle-drive-pedestrian-warning");
        self.discard_rx = true;
    }

    /// Only passive kernel feedback from the currently powered, compatible source.
    pub(super) fn pw_sample(&self) -> Option<(u64, i32)> {
        self.pw_source_epoch()?;
        if self.discard_rx {
            return None;
        }
        let sample = self.sample("vehicle-drive-pedestrian-warning", "HUM_VSP_FUNCTION_SW")?;
        Some((sample.received_at.boot_ms?, sample.value))
    }

    pub(super) fn pw_source_epoch(&self) -> Option<u64> {
        const SOURCE: &str = "vehicle-drive-pedestrian-warning";
        if !self.available
            || self.power != Some(true)
            || !self.power_observed
            || self.activated == 0
            || !self.compatible.contains(SOURCE)
            || !self.enabled.contains(SOURCE)
        {
            return None;
        }
        Some(self.activated)
    }

    pub fn poll(&mut self) -> Vec<Event> {
        self.observe_time(clock::Stamp::now());
        if let Some(inputs) = self.inputs.as_mut() {
            inputs.poll();
            if let Some(powertrain) = inputs
                .powertrain()
                .filter(|powertrain| Some(*powertrain) != self.probed_powertrain)
            {
                self.probed_powertrain = Some(powertrain);
                self.profile.observe_powertrain(powertrain);
                self.compatible = CODECS
                    .iter()
                    .filter(|codec| self.profile.permits(codec.applicability))
                    .map(|codec| codec.id)
                    .collect();
                self.probe_powertrain = CODECS.iter().any(|codec| {
                    self.requested.contains(codec.id)
                        && self.profile.needs_powertrain_probe(codec.applicability)
                });
                let requested = self
                    .requested
                    .iter()
                    .map(|source| source.to_string())
                    .collect();
                self.configure(&requested);
            }
        }
        let input_error = self
            .inputs
            .as_ref()
            .and_then(inputs::Inputs::error)
            .cloned();
        let changed_input_error = input_error != self.inputs_error;
        self.inputs_error = input_error;
        if self
            .inputs
            .as_ref()
            .is_some_and(|inputs| inputs.service_seen())
        {
            self.enter_late();
        }
        let mut events = Vec::new();
        if changed_input_error {
            if let Some((reason, expected)) = self.inputs_error.as_ref() {
                events.push(Event::InputsUnavailable {
                    reason: reason.clone(),
                    expected: *expected,
                });
            }
        }
        if let Some(sender) = self.sender.as_mut() {
            if sender.poll() {
                self.samples.clear();
                self.discard_rx = true;
            }
        }

        if self
            .sender
            .as_ref()
            .is_some_and(|sender| sender.late_required())
        {
            self.enter_late();
        }
        if let Some(sender) = self.sender.as_ref() {
            if let Some(error) = sender.error() {
                if self.transmit_error.as_ref() != Some(error) {
                    self.transmit_error = Some(error.clone());
                    events.push(Event::TransmitterUnavailable {
                        reason: error.0.clone(),
                        expected: error.1,
                    });
                }
            } else if sender.ready() {
                self.transmit_error = None;
            }
        }
        if !self.wants_receiver(clock::Stamp::now().boot_ms) {
            self.close_receiver();
            return events;
        }
        if self.receiver.is_none() {
            if Instant::now() < self.retry_at {
                return events;
            }
            match can::Receiver::open() {
                Ok(receiver) => {
                    self.receiver = Some(receiver);
                    self.rx.open();
                }
                Err(error) => {
                    self.fail(error, &mut events);
                    return events;
                }
            }
        }
        self.rx.polling();
        let mut reset = false;
        for _ in 0..32 {
            let Some(receiver) = self.receiver.as_mut() else {
                break;
            };
            let terminal = clock::Stamp::now().boot_ms;
            let mut captured = None;
            let received = receiver.receive(|raw| captured = Some(raw));
            if let Some(capture) = captured {
                if let Some((sequence, epoch)) = self.rx.next_datagram() {
                    events.push(Event::Datagram {
                        capture,
                        sequence,
                        epoch,
                    });
                }
            }
            match received {
                Ok(received) => {
                    if self.accept_received(received, &mut events, terminal) {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    if !reset && self.resume_after_queue_reset(&error, &mut events) {
                        reset = true;
                    } else {
                        self.fail(error, &mut events);
                        break;
                    }
                }
            }
        }
        events
    }

    fn accept_received(
        &mut self,
        received: can::Received,
        events: &mut Vec<Event>,
        terminal: Option<u64>,
    ) -> bool {
        match received {
            can::Received::Frame(frame) if self.enabled.is_empty() => {
                self.rx.record(&frame, clock::Stamp::now().boot_ms);
            }
            can::Received::Frame(frame) => self.receive_frame(Some(&frame), events),
            can::Received::Unsupported => self.rx.unsupported(),
            can::Received::Empty => {
                if !self.enabled.is_empty() {
                    self.receive_frame(None, events);
                }
                self.rx.caught_up(terminal);
                return true;
            }
        }
        false
    }

    fn observe_time(&mut self, now: clock::Stamp) {
        if self.observed_clock.interrupted(now) {
            self.rx_lease_until = None;
            self.close_receiver();
            self.retry_at = Instant::now();
            self.samples.clear();
            self.power_observed = false;
            self.wake_pending = true;
            self.discard_rx = true;
            if let Some(inputs) = self.inputs.as_mut() {
                inputs.invalidate();
            }
        }
        self.observed_clock = now;
    }

    fn receive_frame(&mut self, frame: Option<&[u8]>, events: &mut Vec<Event>) {
        self.receive_frame_at(frame, events, clock::Stamp::now().boot_ms);
    }

    fn receive_frame_at(
        &mut self,
        frame: Option<&[u8]>,
        events: &mut Vec<Event>,
        boot_ms: Option<u64>,
    ) {
        if let Some(frame) = frame {
            // The observer captures the raw receive before policy discards its cache.
            self.rx.record(frame, boot_ms);
        }
        match frame {
            Some(frame) if !self.discard_rx => self.record(frame, events),
            Some(frame) => {
                self.rx.discard();
                self.record_power(frame);
            }
            None => self.discard_rx = false,
        }
    }

    fn record_power(&mut self, frame: &[u8]) {
        if frame.len() == 10 && frame[0] == 0x6a && frame[1] == 8 {
            match frame[2] & 7 {
                1 => self.observe_power(false),
                2 => self.observe_power(true),
                _ => {}
            }
        }
    }

    fn observe_power(&mut self, on: bool) {
        if self.power != Some(on) || (on && self.wake_pending) {
            self.discard_rx = true;
            if on {
                self.activated = self.activated.saturating_add(1);
            }
            self.samples.clear();
        }
        if on {
            self.wake_pending = false;
        }
        self.power = Some(on);
        self.power_observed = true;
    }

    fn record(&mut self, frame: &[u8], events: &mut Vec<Event>) {
        self.record_power(frame);
        if !self.available {
            self.available = true;
            self.last_error = None;
            events.push(Event::ReceiverAvailable);
        }
        for codec in CODECS {
            if !self.enabled.contains(codec.id) {
                continue;
            }
            if let Some((key, value)) = (codec.feedback)(frame) {
                let samples = self.samples.entry(codec.id).or_default();
                let changed = samples.get(key).is_none_or(|old| old.value != value);
                samples.insert(
                    key,
                    Sample {
                        value,
                        received_at: clock::Stamp::now(),
                    },
                );
                if changed {
                    events.push(Event::Sample {
                        source: codec.id,
                        key,
                        value,
                    });
                }
            }
        }
    }

    fn resume_after_queue_reset(
        &mut self,
        error: &std::io::Error,
        events: &mut Vec<Event>,
    ) -> bool {
        if error.raw_os_error() != Some(libc::ENETRESET) {
            return false;
        }
        // A queue reset invalidates old samples, but recvmsg can still deliver the
        // following ACC frame on this socket. A reset alone is not a power edge.
        self.invalidate_receiver(error, events);
        self.rx.open();
        self.discard_rx = true;
        true
    }

    fn fail(&mut self, error: std::io::Error, events: &mut Vec<Event>) {
        self.receiver = None;
        self.invalidate_receiver(&error, events);
        self.retry_at = Instant::now() + Duration::from_secs(5);
    }

    fn invalidate_receiver(&mut self, error: &std::io::Error, events: &mut Vec<Event>) {
        self.rx.fail();
        self.power_observed = false;
        self.samples.clear();
        self.available = false;
        let reason = error.to_string();
        if self.last_error.as_ref() != Some(&reason) {
            events.push(Event::ReceiverUnavailable(reason.clone()));
            self.last_error = Some(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn service_datagram_preserves_power_and_subsequent_soc_without_acc_replay() {
        let mut runtime = runtime();
        runtime.enabled.insert("vehicle-drive-forced-ev");
        runtime.rx.open();
        runtime.record_power(&[0x6a, 8, 2, 0, 0, 0, 0, 0, 0, 0]);
        let mut events = Vec::new();
        runtime.accept_received(can::Received::Empty, &mut events, Some(1));
        let epoch = runtime.activated;
        for mode in [3, 4, 2, 3, 4, 2] {
            let mut prefix = vec![0; 257];
            prefix[..2].copy_from_slice(&[0x8f, 0x1c]);
            runtime.accept_received(
                can::validate(&prefix, 0, 1, true).unwrap(),
                &mut events,
                Some(2),
            );
            let frame = vec![0x9a, 8, 0, 0, 0, 0, 0, 0, (mode - 1) << 2, 0];
            runtime.accept_received(
                can::validate(&frame, 0, 1, false).unwrap(),
                &mut events,
                Some(3),
            );
            assert!(runtime.power_observed);
            assert_eq!(runtime.activated, epoch);
            assert_eq!(
                runtime.samples["vehicle-drive-forced-ev"]["IVI_SOC_MODESET"].value,
                i32::from(mode)
            );
        }
        let snapshot = runtime.rx.snapshot(0, "boot", "writer");
        assert_eq!(snapshot["errors"], "0");
        assert_eq!(snapshot["unsupportedDatagrams"], "6");
        assert!(!events
            .iter()
            .any(|event| matches!(event, Event::ReceiverUnavailable(_))));
    }

    #[test]
    fn passive_observation_is_bounded_without_enabling_controllers() {
        let mut runtime = runtime();
        runtime.configure(&BTreeSet::new());
        assert!(!runtime.wants_receiver(Some(1000)));
        runtime.observe_rx(Some(1000));
        assert!(runtime.enabled.is_empty());
        assert!(runtime.wants_receiver(Some(15999)));
        assert!(!runtime.wants_receiver(Some(16000)));
        assert!(!runtime.wants_receiver(None));
        runtime.rx.open();
        runtime.rx.caught_up(Some(1500));
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["status"], "active");
        runtime.observe_rx(Some(16000));
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["status"], "unavailable");
        runtime.rx.open();
        runtime.rx.caught_up(Some(16001));
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["receiverEpoch"], "2");
        runtime.observe_rx(None);
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["status"], "unavailable");
    }
    #[test]
    fn diagnostic_clock_failure_invalidates_even_an_enabled_receiver() {
        let mut runtime = runtime();
        runtime.enabled.insert("fixture");
        runtime.rx.open();
        runtime.rx.caught_up(Some(1));
        runtime.observe_rx(None);
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["status"], "unavailable");
    }
    #[test]
    fn policy_discard_keeps_raw_receive_without_changing_epoch() {
        let mut runtime = runtime();
        runtime.rx.open();
        runtime.rx.caught_up(Some(10));
        runtime.discard_rx = true;
        let mut events = Vec::new();
        runtime.receive_frame_at(Some(&[0x71, 0]), &mut events, Some(11));
        runtime.receive_frame_at(None, &mut events, Some(12));
        let page = runtime.rx_snapshot(0, "boot", "writer");
        assert_eq!(page["receiverEpoch"], "1");
        assert_eq!(page["records"][0]["frameHex"], "7100");
        assert_eq!(page["discarded"], "1");
        assert_eq!(page["gap"], false);
    }
    #[test]
    fn pw_challenge_discards_queued_feedback_until_eagain_then_accepts_new_state() {
        const SOURCE: &str = "vehicle-drive-pedestrian-warning";
        assert!(CODECS.iter().any(|codec| codec.id == SOURCE));
        let mut runtime = runtime();
        runtime.configure(&BTreeSet::from([SOURCE.into()]));
        runtime.power = Some(true);
        runtime.power_observed = true;
        runtime.available = true;
        runtime.samples.insert(
            "vehicle-drive-forced-ev",
            BTreeMap::from([(
                "DRIVING_MODE_SET_FB",
                Sample {
                    value: 3,
                    received_at: clock::Stamp::now(),
                },
            )]),
        );
        let mut events = Vec::new();
        let disabled = [0x71, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        let accepted_command = [0x6a, 8, 0, 0, 0, 0, 0, 0x10, 0x7c, 0];
        runtime.begin_pw_readback();
        assert_eq!(
            runtime
                .sample("vehicle-drive-forced-ev", "DRIVING_MODE_SET_FB")
                .unwrap()
                .value,
            3
        );
        for _ in 0..64 {
            runtime.receive_frame(Some(&disabled), &mut events);
        }
        assert!(runtime.sample(SOURCE, "HUM_VSP_FUNCTION_SW").is_none());
        assert!(runtime.discard_rx);
        runtime.receive_frame(None, &mut events);
        runtime.receive_frame(Some(&accepted_command), &mut events);
        assert!(runtime.sample(SOURCE, "HUM_VSP_FUNCTION_SW").is_none());
        runtime.receive_frame(Some(&disabled), &mut events);
        assert_eq!(
            runtime.sample(SOURCE, "HUM_VSP_FUNCTION_SW").unwrap().value,
            1
        );
        runtime.begin_pw_readback();
        assert!(runtime.sample(SOURCE, "HUM_VSP_FUNCTION_SW").is_none());
        runtime.receive_frame(None, &mut events);
        runtime.receive_frame(Some(&disabled), &mut events);
        let off = [0x6a, 8, 1, 0, 0, 0, 0, 0, 0, 0];
        runtime.receive_frame(Some(&off), &mut events);
        assert!(runtime.sample(SOURCE, "HUM_VSP_FUNCTION_SW").is_none());
        assert!(runtime.discard_rx);
        runtime.receive_frame(Some(&disabled), &mut events);
        assert!(runtime.sample(SOURCE, "HUM_VSP_FUNCTION_SW").is_none());
        runtime.power = Some(true);
        runtime.begin_pw_readback();
        runtime.receive_frame(Some(&off), &mut events);
        assert_eq!(runtime.power, Some(false));
    }
    fn runtime() -> Runtime {
        let mut instance = Runtime::default();
        let properties = BTreeMap::from([
            ("ro.product.board", "sa8155"),
            ("ro.build.version.release", "9"),
            ("ro.build.product", "f0506h"),
            ("persist.sys.qg.powertrain", "hybrid"),
            ("ro.product.locale", "zh-CN"),
        ]);
        let mut profile =
            compatibility::Profile::probe(|key| properties.get(key).map(|value| value.to_string()));
        profile.observe_powertrain(Some("hybrid"));
        instance.compatible = CODECS
            .iter()
            .filter(|codec| profile.permits(codec.applicability))
            .map(|codec| codec.id)
            .collect();
        instance
    }

    #[test]
    fn declared_codecs_have_unique_owners_and_reject_missing_inputs() {
        let mut owners = BTreeSet::new();
        for codec in CODECS {
            assert!(voboost_contract::runtime_owner::valid_source(codec.id));
            assert!(owners.insert(codec.id));
            assert!(!codec.fields.is_empty());
            assert_eq!(
                codec.fields.iter().collect::<BTreeSet<_>>().len(),
                codec.fields.len()
            );
            assert_eq!(
                codec.pending_journals.iter().collect::<BTreeSet<_>>().len(),
                codec.pending_journals.len()
            );
            assert!(codec
                .pending_journals
                .iter()
                .all(|key| voboost_contract::runtime_owner::valid_key(key)));
            assert!(!codec.commands.is_empty());
            for command in codec.commands {
                assert!((codec.encode)(&[], *command).is_none());
            }
            assert!((codec.feedback)(&[]).is_none());
            let mut agent = (codec.create)();
            let mut context = crate::native_api::testing::ContextFixture {
                current_lease: None,
                ..Default::default()
            };
            assert_eq!(
                agent.step(&mut context),
                Ok(crate::native_api::Progress::Waiting(
                    crate::native_api::Wait::Ownership
                ))
            );
            assert!(context.writes.is_empty());
            assert!(context.sent.is_empty());
        }
    }

    #[test]
    fn feedback_fields_keep_independent_values_and_change_events() {
        let soc = [0x9a, 8, 0, 0, 0, 0, 0, 0, 16, 0];
        let mut drive = [0x73, 8, 1, 0, 0, 0, 0, 0, 0, 0];
        let Some(codec) = CODECS
            .iter()
            .find(|codec| (codec.feedback)(&soc) == Some(("IVI_SOC_MODESET", 5)))
        else {
            return;
        };
        let mut runtime = runtime();
        runtime.configure(&BTreeSet::from([codec.id.into()]));
        let mut events = Vec::new();
        runtime.record(&soc, &mut events);
        runtime.record(&drive, &mut events);
        assert_eq!(
            runtime.sample(codec.id, "IVI_SOC_MODESET").unwrap().value,
            5
        );
        assert_eq!(
            runtime
                .sample(codec.id, "DRIVING_MODE_SET_FB")
                .unwrap()
                .value,
            2
        );
        let received = runtime
            .sample(codec.id, "DRIVING_MODE_SET_FB")
            .unwrap()
            .received_at;
        let count = events.len();
        runtime.record(&drive, &mut events);
        assert_eq!(events.len(), count);
        assert!(
            runtime
                .sample(codec.id, "DRIVING_MODE_SET_FB")
                .unwrap()
                .received_at
                >= received
        );
        drive[2] = 2;
        runtime.record(&drive, &mut events);
        assert!(matches!(
            events.last(),
            Some(Event::Sample {
                key: "DRIVING_MODE_SET_FB",
                value: 3,
                ..
            })
        ));
        assert_eq!(
            runtime.sample(codec.id, "IVI_SOC_MODESET").unwrap().value,
            5
        );
        drive[1] = 7;
        runtime.record(&drive, &mut events);
        assert_eq!(
            runtime
                .sample(codec.id, "DRIVING_MODE_SET_FB")
                .unwrap()
                .value,
            3
        );
        runtime.configure(&BTreeSet::new());
        assert!(runtime.sample(codec.id, "IVI_SOC_MODESET").is_none());
        assert!(runtime.sample(codec.id, "DRIVING_MODE_SET_FB").is_none());
    }

    #[test]
    fn receiver_failure_forgets_samples_and_repeated_waits_do_not_repeat_events() {
        let mut runtime = runtime();
        runtime.samples.insert(
            "fixture",
            BTreeMap::from([(
                "signal",
                Sample {
                    value: 1,
                    received_at: clock::Stamp::now(),
                },
            )]),
        );
        let mut events = Vec::new();
        for _ in 0..3 {
            runtime.fail(
                std::io::Error::new(std::io::ErrorKind::Unsupported, "not ready"),
                &mut events,
            );
        }
        assert!(runtime.sample("fixture", "signal").is_none());
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], Event::ReceiverUnavailable(reason) if reason == "not ready"));
    }

    #[test]
    fn disabled_native_parts_drop_their_samples_without_opening_transport() {
        let Some(codec) = CODECS.first() else { return };
        let mut runtime = runtime();
        runtime.configure(&BTreeSet::from([codec.id.to_string()]));
        runtime.samples.insert(
            codec.id,
            BTreeMap::from([(
                "signal",
                Sample {
                    value: 1,
                    received_at: clock::Stamp::now(),
                },
            )]),
        );
        runtime.configure(&BTreeSet::new());
        assert!(runtime.sample(codec.id, "signal").is_none());
        assert!(runtime.enabled.is_empty());
        assert!(runtime.poll().is_empty());
    }
    #[test]
    fn reconnect_requires_new_acc_observation_without_inventing_a_power_boundary() {
        let mut runtime = runtime();
        let mut events = Vec::new();
        let mut acc = [0x6a, 8, 2, 0, 0, 0, 0, 0, 0, 0];
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 1);
        assert!(runtime.power_observed);
        runtime.fail(std::io::Error::other("disconnected"), &mut events);
        assert!(!runtime.power_observed);
        runtime.record(&[0x9a, 8, 0, 0, 0, 0, 0, 0, 16, 0], &mut events);
        assert!(!runtime.power_observed);
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 1);
        assert!(runtime.power_observed);
        acc[2] = 1;
        runtime.record(&acc, &mut events);
        acc[2] = 2;
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 2);
    }
    #[test]
    fn queue_reset_keeps_receiving_acc_but_does_not_imply_a_wake() {
        let mut runtime = runtime();
        let mut events = Vec::new();
        let on = [0x6a, 8, 2, 0, 0, 0, 0, 0, 0, 0];
        let off = [0x6a, 8, 1, 0, 0, 0, 0, 0, 0, 0];
        let reset = std::io::Error::from_raw_os_error(libc::ENETRESET);

        runtime.rx.open();
        runtime.record(&on, &mut events);
        assert_eq!(runtime.activated, 1);
        assert!(!runtime.resume_after_queue_reset(
            &std::io::Error::from_raw_os_error(libc::ENOBUFS),
            &mut events
        ));

        assert!(runtime.resume_after_queue_reset(&reset, &mut events));
        assert!(!runtime.power_observed);
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["receiverEpoch"], "2");
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["errors"], "1");
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["status"], "draining");
        runtime.receive_frame_at(Some(&on), &mut events, Some(10));
        assert!(runtime.power_observed);
        assert_eq!(runtime.activated, 1);

        assert!(runtime.resume_after_queue_reset(&reset, &mut events));
        runtime.receive_frame_at(Some(&off), &mut events, Some(11));
        assert_eq!(runtime.power, Some(false));
        assert_eq!(runtime.activated, 1);
        assert!(runtime.resume_after_queue_reset(&reset, &mut events));
        runtime.receive_frame_at(Some(&on), &mut events, Some(12));
        runtime.receive_frame_at(None, &mut events, Some(12));
        runtime.receive_frame_at(Some(&on), &mut events, Some(13));
        assert!(runtime.power_observed);
        assert_eq!(runtime.power, Some(true));
        assert_eq!(runtime.activated, 2);
    }

    #[test]
    fn observed_suspend_requires_fresh_acc_and_creates_one_wake_activation() {
        let mut runtime = runtime();
        let mut events = Vec::new();
        let acc = [0x6a, 8, 2, 0, 0, 0, 0, 0, 0, 0];
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 1);
        let before = clock::Stamp {
            at: Instant::now(),
            boot_ms: Some(1000),
        };
        runtime.observed_clock = before;
        runtime.observe_rx(Some(1000));
        runtime.rx.open();
        runtime.rx.caught_up(Some(1000));
        runtime.observe_time(clock::Stamp {
            at: before.at + Duration::from_millis(1),
            boot_ms: Some(61001),
        });
        assert!(!runtime.power_observed);
        assert_eq!(runtime.rx_lease_until, None);
        assert_eq!(runtime.rx_snapshot(0, "b", "w")["status"], "unavailable");
        assert_eq!(runtime.activated, 1);
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 2);
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 2);
        let before = runtime.observed_clock;
        runtime.observe_time(clock::Stamp {
            at: before.at + Duration::from_secs(60),
            boot_ms: Some(121001),
        });
        runtime.record(&acc, &mut events);
        assert_eq!(runtime.activated, 2);
    }
}
