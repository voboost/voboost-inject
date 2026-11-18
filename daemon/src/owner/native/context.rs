//! Source-bound policy execution with early native and late OEM transport.
use super::{Admission, Codec, Event, Host, Runtime, CODECS};
use crate::native_api::{Command, Context, Failure, Lease, Progress, Read, Transmission, Wait};
use std::time::{Duration, Instant};

impl Runtime {
    #[cfg(test)]
    pub(crate) fn electric_action_test_pending(&self) -> bool {
        self.electric_action_pending.is_some()
    }

    #[cfg(test)]
    pub(crate) fn electric_action_test_ready(&mut self) {
        self.enabled.insert("vehicle-drive-forced-ev");
        self.compatible.insert("vehicle-drive-forced-ev");
        self.power_observed = true;
        self.power = Some(true);
        self.activated = 1;
        self.late = true;
    }

    pub(crate) fn electric_click_request(
        &mut self,
        host: &mut dyn Host,
        input: voboost_contract::desired::Input,
        poll: bool,
        cancel: bool,
    ) -> voboost_contract::runtime_owner::ElectricClickStatus {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        const SOURCE: &str = "vehicle-drive-forced-ev";
        if !input.bound() {
            return Status::Unknown;
        }
        if self.electric_action_key.as_ref() != Some(&input) {
            if self.electric_action_pending.is_some() {
                return Status::Busy;
            }
            self.electric_action_key = Some(input.clone());
            self.electric_action_result = None;
            // A user gesture may withdraw earlier automatic work, but never claim its result.
            if let Some(identity) = host.action_identity(SOURCE) {
                self.electric_action_pending = Some(input.request_id);
                self.electric_action_identity = Some(identity);
                self.electric_action_result = Some(Status::Draining);
            } else if cancel || poll {
                let status = if cancel {
                    Status::NotSubmitted
                } else {
                    Status::Drained
                };
                self.electric_action_result = Some(status);
                return status;
            }
        } else if let Some(status) = self.electric_action_result {
            if matches!(
                status,
                Status::Accepted | Status::NotSubmitted | Status::Drained
            ) {
                return status;
            }
        }
        if self.electric_action_result == Some(Status::Draining) {
            let identity = self
                .electric_action_identity
                .clone()
                .expect("draining identity");
            let lease = Lease {
                revision: identity.revision,
            };
            host.withdraw_command(SOURCE, lease, false);
            if host.action_terminal(&identity).is_none() {
                return Status::Draining;
            }
            host.withdraw_command(SOURCE, lease, true);
            self.electric_action_pending = None;
            self.electric_action_identity = None;
            self.electric_action_result = Some(Status::Drained);
            self.electric_click_finished(host);
            return Status::Drained;
        }
        if cancel {
            if let Some(identity) = self.electric_action_identity.as_ref() {
                host.withdraw_command(
                    "vehicle-drive-forced-ev",
                    Lease {
                        revision: identity.revision,
                    },
                    false,
                );
            }
        }
        let was_pending = self.electric_action_pending.is_some();
        let status = match self.electric_click(host, input.request_id) {
            Ok(Some(false)) => Status::NotSubmitted,
            Ok(Some(true)) => Status::Accepted,
            Ok(None) => Status::Pending,
            Err(_) if self.electric_action_pending.is_some() => Status::Pending,
            Err(_) => Status::Drained,
        };
        if matches!(status, Status::Accepted | Status::Drained)
            || (was_pending && status == Status::NotSubmitted)
        {
            self.electric_click_finished(host);
        }
        self.electric_action_result = Some(status);
        status
    }

    fn electric_click_finished(&mut self, host: &dyn Host) {
        self.samples.clear();
        self.feedback_after_ms = super::clock::Stamp::now().boot_ms;
        self.discard_rx = true;
        let lease = host
            .admission("vehicle-drive-forced-ev")
            .filter(Admission::current)
            .map(|admission| admission.lease);
        let epoch = (self.activated > 0).then_some(self.activated);
        self.electric_action_fence = lease.zip(epoch);
        if let Some(agent) = self.controllers.get_mut("vehicle-drive-forced-ev") {
            agent.electric_click_finished(lease, epoch);
        }
    }

    /// Execute the closed Electric action under the same admission and transport as controllers.
    pub(crate) fn electric_click(
        &mut self,
        host: &mut dyn Host,
        id: u64,
    ) -> Result<Option<bool>, Failure> {
        const SOURCE: &str = "vehicle-drive-forced-ev";
        if self.electric_action_pending == Some(id) {
            if let Some(identity) = self.electric_action_identity.clone() {
                if !host.action_allowed(SOURCE)
                    || host.admission(SOURCE).is_none_or(|admission| {
                        !admission.current() || admission.lease.revision != identity.revision
                    })
                {
                    host.withdraw_command(
                        SOURCE,
                        Lease {
                            revision: identity.revision,
                        },
                        false,
                    );
                }
                if let Some(status) = host.action_terminal(&identity) {
                    use voboost_contract::runtime_owner::NativeCommandStatus;
                    self.electric_action_pending = None;
                    self.electric_action_identity = None;
                    host.withdraw_command(
                        SOURCE,
                        Lease {
                            revision: identity.revision,
                        },
                        true,
                    );
                    return match status {
                        NativeCommandStatus::Accepted => {
                            self.samples.clear();
                            self.discard_rx = true;
                            Ok(Some(true))
                        }
                        NativeCommandStatus::Cancelled => Ok(Some(false)),
                        NativeCommandStatus::Failed
                        | NativeCommandStatus::Unknown
                        | NativeCommandStatus::Claim => Err(Failure::TransportUnavailable),
                    };
                }
                return Ok(None);
            }
        }
        if self
            .electric_action_pending
            .is_some_and(|pending| pending != id)
        {
            return Ok(None);
        }
        if id == 0
            || !self.late
            || !host.action_allowed(SOURCE)
            || !self.enabled.contains(SOURCE)
            || !self.compatible.contains(SOURCE)
        {
            return Ok(if self.electric_action_pending == Some(id) {
                None
            } else {
                Some(false)
            });
        }
        let Some(admission) = host.admission(SOURCE).filter(Admission::current) else {
            return Ok(if self.electric_action_pending == Some(id) {
                None
            } else {
                Some(false)
            });
        };
        let Some(codec) = CODECS.iter().find(|codec| codec.id == SOURCE) else {
            return Ok(Some(false));
        };
        // Never attach a user request to a command already owned by automatic restore.
        if self.electric_action_pending.is_none() && host.action_identity(SOURCE).is_some() {
            // Existing source work may still execute; no competing OEM fallback is safe yet.
            return Err(Failure::TransportUnavailable);
        }
        let mut agent = self
            .controllers
            .remove(SOURCE)
            .unwrap_or_else(|| (codec.create)());
        let (result, accepted) = {
            let mut context = Source {
                codec,
                admission,
                host,
                samples: self.samples.get(SOURCE),
                feedback_after_ms: self.feedback_after_ms,
                sender: self.sender.as_mut(),
                inputs: self.inputs.as_ref(),
                late: self.late,
                accepted: false,
                epoch: (self.power_observed && self.power == Some(true) && self.activated > 0)
                    .then_some(self.activated),
                now_ms: super::clock::Stamp::now().boot_ms.unwrap_or_else(|| {
                    u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
                }),
            };
            let result = agent.electric_click(&mut context, id);
            (result, context.accepted)
        };
        if accepted {
            self.feedback_after_ms = super::clock::Stamp::now().boot_ms;
            self.samples.clear();
            self.discard_rx = true;
        }
        self.controllers.insert(SOURCE, agent);
        match result {
            Ok(None) => {
                self.electric_action_identity = host.action_identity(SOURCE);
                if self.electric_action_identity.is_some() {
                    self.electric_action_pending = Some(id);
                } else {
                    return Ok(Some(false));
                }
            }
            Ok(Some(_)) => {
                self.electric_action_pending = None;
                self.electric_action_identity = None;
            }
            Err(_) => {}
        }
        result
    }

    pub(crate) fn step(&mut self, host: &mut dyn Host) -> Vec<Event> {
        if self.electric_action_pending.is_some() {
            if let Some(input) = self.electric_action_key.clone() {
                let _ = self.electric_click_request(host, input, true, false);
            }
        }
        let now = Instant::now();
        let mut events = Vec::new();
        if !self.power_observed {
            let acc = self.enabled.iter().find_map(|source| {
                host.vehicle_observation(source)
                    .map(|observed| observed.acc)
            });
            match acc {
                Some(0) => self.observe_power(false),
                Some(2) => self.observe_power(true),
                _ => {}
            }
        }

        if self
            .requested
            .iter()
            .any(|source| host.command_transport_ready(source))
        {
            self.enter_late();
        }
        if self.inputs.is_none()
            && now >= self.inputs_retry_at
            && ((!self.late && !self.enabled.is_empty()) || self.probe_powertrain)
        {
            self.inputs_retry_at = now + Duration::from_secs(1);
            match super::inputs::Inputs::start() {
                Ok(inputs) => {
                    self.inputs = Some(inputs);
                    self.inputs_start_error = None;
                }
                Err(error) => {
                    let reason = format!("Native input worker unavailable: {error}");
                    if self.inputs_start_error.as_ref() != Some(&reason) {
                        for source in &self.requested {
                            events.push(Event::CapabilityUnavailable {
                                source,
                                reason: reason.clone(),
                            });
                        }
                        self.inputs_start_error = Some(reason);
                    }
                }
            }
        }
        if let Some(inputs) = self.inputs.as_mut() {
            inputs.require_powertrain(self.probe_powertrain);
            if self.late {
                inputs.finish_bootstrap();
            }
        }
        if self.sender.is_none()
            && !self.late
            && !self.enabled.is_empty()
            && now >= self.sender_retry_at
        {
            self.sender_retry_at = now + Duration::from_secs(1);
            match super::transmit::Sender::start() {
                Ok(sender) => self.sender = Some(sender),
                Err(error) => {
                    let detail = (
                        format!("Native transmit worker unavailable: {error}"),
                        false,
                    );
                    if self.transmit_error.as_ref() != Some(&detail) {
                        events.push(Event::TransmitterUnavailable {
                            reason: detail.0.clone(),
                            expected: detail.1,
                        });
                        self.transmit_error = Some(detail);
                    }
                }
            }
        }
        if self.sender.as_ref().is_some_and(|sender| sender.terminal()) {
            self.sender = None;
            self.sender_retry_at = now + Duration::from_secs(5);
        }
        for codec in CODECS {
            if !host.enabled(codec.id) {
                if let Some(mut agent) = self.controllers.remove(codec.id) {
                    if let Err(error) = agent.stop(&mut Stopped {
                        source: codec.id,
                        host,
                    }) {
                        self.controllers.insert(codec.id, agent);
                        let result = Err(error);
                        if self.progress.get(codec.id) != Some(&result) {
                            self.progress.insert(codec.id, result);
                            events.push(Event::Controller {
                                source: codec.id,
                                result,
                            });
                        }
                        continue;
                    }
                    host.diagnostic_stopped(codec.id);
                }
                self.progress.remove(codec.id);
                self.controller_activations.remove(codec.id);
                self.capability_errors.remove(codec.id);
                continue;
            }
            if !self.compatible.contains(codec.id) {
                let mut reason = self
                    .profile
                    .reason(codec.applicability)
                    .unwrap_or_else(|| "Native applicability probe is unavailable".into());
                if self.profile.needs_powertrain_probe(codec.applicability) {
                    if let Some(inputs) = self.inputs.as_ref() {
                        if let Some(error) = inputs.powertrain_error() {
                            reason.push_str(": ");
                            reason.push_str(error);
                        } else if inputs.powertrain().is_none() {
                            // The worker has not reported its first profile observation yet.
                            continue;
                        }
                    }
                }
                if self.capability_errors.get(codec.id) != Some(&reason) {
                    self.capability_errors.insert(codec.id, reason.clone());
                    events.push(Event::CapabilityUnavailable {
                        source: codec.id,
                        reason,
                    });
                }
                continue;
            }
            self.capability_errors.remove(codec.id);
            if !self.enabled.contains(codec.id) {
                continue;
            }
            let Some(admission) = host.admission(codec.id).filter(Admission::current) else {
                continue;
            };
            // A user action owns the source transport until its terminal result is drained.
            if codec.id == "vehicle-drive-forced-ev" && self.electric_action_pending.is_some() {
                if !host.action_allowed(codec.id) {
                    if let Some(identity) = self.electric_action_identity.as_ref() {
                        host.withdraw_command(
                            codec.id,
                            Lease {
                                revision: identity.revision,
                            },
                            false,
                        );
                    }
                }
                continue;
            }
            let lease = admission.lease;
            if self.power_observed
                && self.activated > 0
                && self.controller_activations.get(codec.id) != Some(&self.activated)
            {
                host.withdraw_command(codec.id, lease, true);
                if let Some(sender) = self.sender.as_mut() {
                    if !sender.in_flight() {
                        sender.withdraw(codec.id, lease, true);
                    }
                }
                self.controller_activations.insert(codec.id, self.activated);
            }
            let mut agent = self
                .controllers
                .remove(codec.id)
                .unwrap_or_else(|| (codec.create)());
            if codec.id == "vehicle-drive-forced-ev" {
                if let Some((fenced_lease, epoch)) = self.electric_action_fence {
                    if fenced_lease != lease || self.activated != epoch {
                        self.electric_action_fence = None;
                    } else if self.power_observed && self.power == Some(true) {
                        agent.electric_click_finished(Some(lease), Some(epoch));
                        self.electric_action_fence = None;
                    }
                }
            }
            let (mut result, accepted) = {
                let mut context = Source {
                    codec,
                    admission,
                    host,
                    samples: self.samples.get(codec.id),
                    feedback_after_ms: self.feedback_after_ms,
                    sender: self.sender.as_mut(),
                    inputs: self.inputs.as_ref(),
                    late: self.late,
                    accepted: false,
                    epoch: (self.power_observed && self.power == Some(true) && self.activated > 0)
                        .then_some(self.activated),
                    now_ms: super::clock::Stamp::now().boot_ms.unwrap_or_else(|| {
                        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
                    }),
                };
                let result = agent.step(&mut context);
                (result, context.accepted)
            };
            if self
                .sender
                .as_ref()
                .is_some_and(|sender| sender.in_flight() && sender.owns(codec.id, lease))
                && matches!(
                    result,
                    Ok(Progress::Waiting(Wait::Feedback | Wait::Transport))
                )
            {
                result = Ok(Progress::Waiting(Wait::Reply));
            }
            if accepted {
                self.feedback_after_ms = super::clock::Stamp::now().boot_ms;
                self.samples.clear();
                self.discard_rx = true;
            }
            if result != Ok(Progress::Waiting(Wait::Reply)) {
                let completed = matches!(
                    result,
                    Ok(Progress::Applied
                        | Progress::Idle
                        | Progress::Waiting(Wait::Mode | Wait::UserChoice))
                        | Err(Failure::ReadbackTimeout)
                );
                host.withdraw_command(codec.id, lease, completed);
                if let Some(sender) = self.sender.as_mut() {
                    sender.withdraw(codec.id, lease, completed);
                }
            }
            self.controllers.insert(codec.id, agent);
            host.diagnostic_progress(codec.id, lease, result);
            if self.progress.get(codec.id) != Some(&result) {
                self.progress.insert(codec.id, result);
                events.push(Event::Controller {
                    source: codec.id,
                    result,
                });
            }
        }
        events
    }
}

struct Source<'a> {
    codec: &'static Codec,
    admission: Admission,
    host: &'a mut dyn Host,
    samples: Option<&'a std::collections::BTreeMap<&'static str, super::Sample>>,
    feedback_after_ms: Option<u64>,
    sender: Option<&'a mut super::transmit::Sender>,
    inputs: Option<&'a super::inputs::Inputs>,
    epoch: Option<u64>,
    now_ms: u64,
    late: bool,
    accepted: bool,
}
impl Source<'_> {
    fn current(&self, lease: Lease) -> bool {
        self.admission.lease == lease
            && self.admission.current()
            && self
                .host
                .admission(self.codec.id)
                .is_some_and(|current| current.lease == lease && current.current())
    }
    fn blocked(&self) -> bool {
        self.sender.as_ref().is_some_and(|sender| {
            sender.in_flight() && !sender.owns(self.codec.id, self.admission.lease)
        })
    }
}
impl Context for Source<'_> {
    fn lease(&self) -> Option<Lease> {
        self.current(self.admission.lease)
            .then_some(self.admission.lease)
    }
    fn now_ms(&self) -> u64 {
        self.now_ms
    }
    fn power_epoch(&self) -> Option<u64> {
        self.epoch
    }
    fn intent(&self) -> Read<bool> {
        self.host.intent(self.codec.id)
    }
    fn option(&self, key: &str) -> Option<String> {
        self.host.option(self.codec.id, key)
    }
    fn read_state(&self, key: &str) -> Read<bool> {
        if !self.current(self.admission.lease) {
            // Preserve the original read behavior, but a stale lease cannot
            // qualify as an admitted controller read for first-use evidence.
            self.host
                .diagnostic_stale_read(self.codec.id, self.admission.lease, key);
            return self.host.read_state(self.codec.id, key);
        }
        if self
            .host
            .diagnostic_state_read(self.codec.id, self.admission.lease, key)
        {
            return Read::Unavailable;
        }
        let result = self.host.read_controller_state(self.codec.id, key);
        self.host
            .diagnostic_state_read_complete(self.codec.id, self.admission.lease, key, &result);
        result
    }
    fn write_state(&mut self, lease: Lease, key: &str, value: bool) -> Result<(), Failure> {
        if !self.current(lease) {
            self.host.diagnostic_stale_write(self.codec.id, lease, key);
            return Err(Failure::Cancelled);
        }
        if self.host.diagnostic_state_write(self.codec.id, lease, key) {
            return Err(Failure::StateUnavailable);
        }
        self.host
            .write_controller_state(self.codec.id, lease, key, value)
    }
    fn feedback(&self, key: &str) -> Read<i32> {
        if self.epoch.is_none() || self.blocked() {
            return Read::Unavailable;
        }
        self.samples
            .and_then(|samples| samples.get(key))
            .filter(|sample| sample.received_at.fresh(Duration::from_secs(2)))
            .map(|sample| Read::Value(sample.value))
            .unwrap_or_else(|| {
                self.host
                    .vehicle_observation(self.codec.id)
                    .filter(|observed| {
                        observed.state == key
                            && observed.acc == 2
                            && self
                                .feedback_after_ms
                                .is_none_or(|after| observed.sampled_boot_ms > after)
                    })
                    .map_or(Read::Unavailable, |observed| Read::Value(observed.value))
            })
    }
    fn transport_ready(&self) -> bool {
        if self.blocked() {
            return false;
        }
        if self
            .sender
            .as_ref()
            .is_some_and(|sender| sender.owns(self.codec.id, self.admission.lease))
        {
            return true;
        }
        if self.late {
            return self.host.command_transport_ready(self.codec.id);
        }
        self.sender.as_ref().is_some_and(|sender| {
            sender.ready() || sender.owns(self.codec.id, self.admission.lease)
        })
    }
    fn send(&mut self, lease: Lease, command: Command) -> Result<Transmission, Failure> {
        if !self.current(lease) {
            return Err(Failure::Cancelled);
        }
        if !self.codec.commands.contains(&command) {
            return Err(Failure::InvalidValue);
        }
        if let Some(sender) = self.sender.as_mut() {
            if let Some(result) = sender.finish(self.codec.id, lease, command) {
                return result;
            }
            if sender.in_flight() {
                return Ok(if sender.owns(self.codec.id, lease) {
                    Transmission::Pending
                } else {
                    Transmission::Waiting(Wait::Transport)
                });
            }
            if sender.uncertain(self.codec.id, lease) {
                return Err(Failure::TransportUnavailable);
            }
        }
        if self.late {
            let result = self.host.send_command(self.codec.id, lease, command)?;
            self.accepted |= result == Transmission::Accepted;
            return Ok(result);
        }
        let Some(inputs) = self.inputs else {
            return Ok(Transmission::Waiting(Wait::Inputs));
        };
        let Read::Value(fields) = inputs.read(self.codec.fields) else {
            return Ok(Transmission::Waiting(Wait::Inputs));
        };
        let frame = (self.codec.encode)(&fields, command).ok_or(Failure::InvalidValue)?;
        let freshness = super::transmit::Freshness {
            issued: super::clock::Stamp::now(),
            feedback: self.samples.map_or_else(Vec::new, |samples| {
                samples.values().map(|sample| sample.received_at).collect()
            }),
            inputs: Some(inputs.observed()),
        };
        self.sender
            .as_mut()
            .ok_or(Failure::TransportUnavailable)?
            .send(
                self.codec.id,
                self.admission.clone(),
                command,
                frame,
                inputs.fence.clone(),
                freshness,
            )
    }
}

struct Stopped<'a> {
    source: &'static str,
    host: &'a mut dyn Host,
}
impl crate::native_api::StopContext for Stopped<'_> {
    fn write_state(&mut self, key: &str, value: bool) -> Result<(), Failure> {
        self.host.diagnostic_stopped_write(self.source, key);
        self.host.write_stopped_state(self.source, key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    struct Owner {
        source: &'static str,
        enabled: bool,
        admission: Option<Admission>,
        ready: bool,
        result: Transmission,
        sent: Vec<Command>,
        withdrawn: Vec<(Lease, bool)>,
        action_identity: Option<voboost_contract::runtime_owner::NativeCommandIdentity>,
        action_terminal: Option<voboost_contract::runtime_owner::NativeCommandStatus>,
        state: BTreeMap<String, Read<bool>>,
        observation: Option<voboost_contract::runtime_owner::NativeVehicleObservation>,
        diagnostic_drop: bool,
        diagnostic_drop_write: bool,
        diagnostic_reads: std::cell::Cell<u32>,
        qualified_reads: std::cell::Cell<u32>,
        stale_reads: std::cell::Cell<u32>,
        stale_writes: u32,
        diagnostic_writes: u32,
    }
    impl Host for Owner {
        fn admission(&self, source: &str) -> Option<Admission> {
            (source == self.source)
                .then(|| self.admission.clone())
                .flatten()
        }
        fn enabled(&self, source: &str) -> bool {
            self.enabled && source == self.source
        }
        fn vehicle_observation(
            &self,
            source: &str,
        ) -> Option<voboost_contract::runtime_owner::NativeVehicleObservation> {
            (source == self.source)
                .then(|| self.observation.clone())
                .flatten()
        }
        fn command_transport_ready(&self, source: &str) -> bool {
            self.ready && source == self.source
        }
        fn send_command(
            &mut self,
            source: &str,
            lease: Lease,
            command: Command,
        ) -> Result<Transmission, Failure> {
            if !self
                .admission(source)
                .is_some_and(|admission| admission.current() && admission.lease == lease)
            {
                return Err(Failure::Cancelled);
            }
            if !self.ready {
                return Ok(Transmission::Waiting(Wait::Transport));
            }
            if !matches!(self.result, Transmission::Waiting(_)) {
                self.sent.push(command);
            }
            if self.result == Transmission::Pending && self.action_identity.is_none() {
                self.action_identity =
                    Some(voboost_contract::runtime_owner::NativeCommandIdentity {
                        owner_session: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                        boot_id: "11111111-1111-4111-8111-111111111111".into(),
                        source: source.into(),
                        command_id: 1,
                        revision: lease.revision,
                        state: command.state.into(),
                        value: command.value,
                    });
            }
            Ok(self.result)
        }
        fn withdraw_command(&mut self, _: &str, lease: Lease, completed: bool) {
            self.withdrawn.push((lease, completed));
        }
        fn action_identity(
            &self,
            _: &str,
        ) -> Option<voboost_contract::runtime_owner::NativeCommandIdentity> {
            self.action_identity.clone()
        }
        fn action_terminal(
            &mut self,
            _: &voboost_contract::runtime_owner::NativeCommandIdentity,
        ) -> Option<voboost_contract::runtime_owner::NativeCommandStatus> {
            self.action_terminal
        }
        fn intent(&self, _: &str) -> Read<bool> {
            Read::Missing
        }
        fn option(&self, _: &str, _: &str) -> Option<String> {
            None
        }
        fn read_state(&self, _: &str, key: &str) -> Read<bool> {
            self.state.get(key).cloned().unwrap_or(Read::Missing)
        }
        fn read_controller_state(&self, source: &str, key: &str) -> Read<bool> {
            self.qualified_reads.set(self.qualified_reads.get() + 1);
            self.read_state(source, key)
        }
        fn diagnostic_stale_read(&self, _: &str, _: Lease, _: &str) {
            self.stale_reads.set(self.stale_reads.get() + 1);
        }
        fn diagnostic_stale_write(&mut self, _: &str, _: Lease, _: &str) {
            self.stale_writes += 1;
        }
        fn diagnostic_state_read(&self, _: &str, _: Lease, _: &str) -> bool {
            self.diagnostic_reads.set(self.diagnostic_reads.get() + 1);
            self.diagnostic_drop
        }
        fn diagnostic_state_write(&mut self, _: &str, _: Lease, _: &str) -> bool {
            self.diagnostic_writes += 1;
            self.diagnostic_drop_write
        }
        fn write_state(
            &mut self,
            _: &str,
            _: Lease,
            key: &str,
            value: bool,
        ) -> Result<(), Failure> {
            self.state.insert(key.into(), Read::Value(value));
            Ok(())
        }
        fn write_stopped_state(&mut self, _: &str, key: &str, value: bool) -> Result<(), Failure> {
            self.state.insert(key.into(), Read::Value(value));
            Ok(())
        }
    }
    fn codec() -> &'static Codec {
        CODECS
            .iter()
            .find(|codec| {
                codec.commands.contains(&Command {
                    state: "HUM_VSP_FUNCTION_SW",
                    value: 1,
                })
            })
            .expect("generated PW native registry prerequisite missing")
    }
    fn owner(codec: &'static Codec) -> Owner {
        Owner {
            source: codec.id,
            enabled: true,
            ready: true,
            result: Transmission::Accepted,
            admission: Some(Admission {
                lease: Lease { revision: 1 },
                fence: Arc::new(AtomicU64::new(1)),
            }),
            sent: Vec::new(),
            withdrawn: Vec::new(),
            action_identity: None,
            action_terminal: None,
            state: BTreeMap::new(),
            observation: None,
            diagnostic_drop: false,
            diagnostic_drop_write: false,
            diagnostic_reads: std::cell::Cell::new(0),
            qualified_reads: std::cell::Cell::new(0),
            stale_reads: std::cell::Cell::new(0),
            stale_writes: 0,
            diagnostic_writes: 0,
        }
    }
    #[test]
    fn controller_diagnostic_intercepts_before_read_and_observes_writes() {
        let codec = codec();
        let mut owner = owner(codec);
        owner
            .state
            .insert("pedestrian-warning-armed".into(), Read::Value(true));
        owner.diagnostic_drop = true;
        let admission = owner.admission.clone().unwrap();
        let mut context = Source {
            codec,
            admission,
            host: &mut owner,
            samples: None,
            feedback_after_ms: None,
            sender: None,
            inputs: None,
            epoch: None,
            now_ms: 1,
            late: true,
            accepted: false,
        };
        assert_eq!(
            context.read_state("pedestrian-warning-armed"),
            Read::Unavailable
        );
        context
            .write_state(Lease { revision: 1 }, "pedestrian-warning-armed", false)
            .unwrap();
        assert_eq!(owner.diagnostic_reads.get(), 1);
        assert_eq!(owner.diagnostic_writes, 1);
        assert_eq!(owner.state["pedestrian-warning-armed"], Read::Value(false));
    }
    #[test]
    fn diagnostic_write_failure_never_calls_the_state_writer() {
        let codec = codec();
        let mut owner = owner(codec);
        owner
            .state
            .insert("pedestrian-warning-armed".into(), Read::Value(true));
        owner.diagnostic_drop_write = true;
        let admission = owner.admission.clone().unwrap();
        let mut context = Source {
            codec,
            admission,
            host: &mut owner,
            samples: None,
            feedback_after_ms: None,
            sender: None,
            inputs: None,
            epoch: None,
            now_ms: 1,
            late: true,
            accepted: false,
        };
        assert_eq!(
            context.write_state(Lease { revision: 1 }, "pedestrian-warning-armed", false),
            Err(Failure::StateUnavailable)
        );
        assert_eq!(owner.diagnostic_writes, 1);
        assert_eq!(owner.state["pedestrian-warning-armed"], Read::Value(true));
    }

    #[test]
    fn stale_controller_write_is_cancelled_and_invalidates_coverage() {
        let codec = codec();
        let mut owner = owner(codec);
        owner
            .state
            .insert("pedestrian-warning-armed".into(), Read::Value(true));
        let admission = owner.admission.clone().unwrap();
        admission
            .fence
            .store(2, std::sync::atomic::Ordering::Release);
        let mut context = Source {
            codec,
            admission,
            host: &mut owner,
            samples: None,
            feedback_after_ms: None,
            sender: None,
            inputs: None,
            epoch: None,
            now_ms: 1,
            late: true,
            accepted: false,
        };
        assert_eq!(
            context.write_state(Lease { revision: 1 }, "pedestrian-warning-armed", false),
            Err(Failure::Cancelled)
        );
        assert_eq!(owner.state["pedestrian-warning-armed"], Read::Value(true));
        assert_eq!(
            owner.stale_writes, 1,
            "cancelled stale write must invalidate coverage"
        );
    }

    #[test]
    fn stale_controller_lease_never_qualifies_as_first_read() {
        let codec = codec();
        let mut owner = owner(codec);
        owner
            .state
            .insert("pedestrian-warning-armed".into(), Read::Value(true));
        let admission = owner.admission.clone().unwrap();
        admission
            .fence
            .store(2, std::sync::atomic::Ordering::Release);
        let context = Source {
            codec,
            admission,
            host: &mut owner,
            samples: None,
            feedback_after_ms: None,
            sender: None,
            inputs: None,
            epoch: None,
            now_ms: 1,
            late: true,
            accepted: false,
        };
        assert_eq!(
            context.read_state("pedestrian-warning-armed"),
            Read::Value(true)
        );
        assert_eq!(owner.qualified_reads.get(), 0);
        assert_eq!(owner.diagnostic_reads.get(), 0);
        assert_eq!(
            owner.stale_reads.get(),
            1,
            "fallback must invalidate diagnostic coverage"
        );
    }

    #[test]
    fn oem_feedback_must_be_read_after_the_last_accepted_command() {
        let codec = codec();
        for (captured, floor, accepted) in [(100, 100, false), (99, 100, false), (101, 100, true)] {
            let mut owner = owner(codec);
            owner.observation = Some(voboost_contract::runtime_owner::NativeVehicleObservation {
                acc: 2,
                state: codec.commands[0].state.into(),
                value: 2,
                sampled_boot_ms: captured,
            });
            let source = Source {
                codec,
                admission: owner.admission(codec.id).unwrap(),
                host: &mut owner,
                samples: None,
                feedback_after_ms: Some(floor),
                sender: None,
                inputs: None,
                epoch: Some(1),
                now_ms: 200,
                late: true,
                accepted: false,
            };
            assert_eq!(
                source.feedback(codec.commands[0].state),
                if accepted {
                    Read::Value(2)
                } else {
                    Read::Unavailable
                }
            );
        }
    }

    #[test]
    fn current_oem_read_recovers_forced_ev_after_receiver_loss_without_acc_replay() {
        let codec = CODECS
            .iter()
            .find(|codec| codec.id == "vehicle-drive-forced-ev")
            .unwrap();
        let mut host = owner(codec);
        host.state
            .insert("forced-ev-armed".into(), Read::Value(true));
        host.state
            .insert("forced-ev-lifecycle-active".into(), Read::Value(true));
        host.observation = Some(voboost_contract::runtime_owner::NativeVehicleObservation {
            acc: 2,
            state: "IVI_SOC_MODESET".into(),
            value: 2,
            sampled_boot_ms: 100,
        });
        let mut runtime = Runtime::default();
        runtime.electric_action_test_ready();
        runtime.invalidate_receiver(&std::io::ErrorKind::UnexpectedEof.into(), &mut Vec::new());
        assert!(!runtime.power_observed);
        runtime.step(&mut host);
        assert!(runtime.power_observed);
        assert_eq!(
            runtime.activated, 1,
            "recovery must not invent a new activation"
        );
        assert_eq!(host.sent.len(), 1);
        assert_eq!(host.sent[0].value, 5);
    }

    #[test]
    fn electric_request_replay_is_lookup_only_and_endpoint_bound() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        let codec = CODECS
            .iter()
            .find(|codec| codec.id == "vehicle-drive-forced-ev")
            .unwrap();
        let mut host = owner(codec);
        host.state
            .insert("forced-ev-armed".into(), Read::Value(true));
        let mut runtime = Runtime::default();
        runtime.enabled.insert(codec.id);
        runtime.compatible.insert(codec.id);
        runtime.power_observed = true;
        runtime.power = Some(true);
        runtime.activated = 1;
        runtime.late = true;
        let input = voboost_contract::desired::Input {
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            endpoint_epoch: 7,
            request_id: 10,
            injector_pid: 42,
            injector_starttime: 100,
        };
        assert_eq!(
            runtime.electric_click_request(&mut host, input.clone(), false, false),
            Status::Accepted
        );
        assert_eq!(
            runtime.electric_click_request(&mut host, input.clone(), true, false),
            Status::Accepted
        );
        assert_eq!(host.sent.len(), 1);
        let mut foreign = input.clone();
        foreign.endpoint_epoch = 8;
        assert_eq!(
            runtime.electric_click_request(&mut host, foreign, true, false),
            Status::Drained
        );
        assert_eq!(host.sent.len(), 1);
        let mut next = input.clone();
        next.request_id = 11;
        assert_eq!(
            runtime.electric_click_request(&mut host, next, false, false),
            Status::Accepted
        );
        assert_eq!(
            runtime.electric_click_request(&mut host, input, true, false),
            Status::Drained
        );
        assert_eq!(host.sent.len(), 2);
    }

    #[test]
    fn electric_finished_fence_survives_absent_controller_only_for_current_admission() {
        for next in 0..6 {
            let codec = CODECS
                .iter()
                .find(|codec| codec.id == "vehicle-drive-forced-ev")
                .unwrap();
            let mut host = owner(codec);
            host.state
                .insert("forced-ev-armed".into(), Read::Value(true));
            let mut runtime = Runtime::default();
            runtime.electric_action_test_ready();
            if next == 3 {
                host.admission = None;
            }
            if next == 4 {
                runtime.invalidate_receiver(
                    &std::io::ErrorKind::UnexpectedEof.into(),
                    &mut Vec::new(),
                );
            }
            runtime.electric_click_finished(&host);
            assert!(runtime.controllers.is_empty());
            if next == 1 || next == 3 {
                host.admission = Some(Admission {
                    lease: Lease { revision: 2 },
                    fence: Arc::new(AtomicU64::new(2)),
                });
            }
            if next == 2 {
                runtime.record_power(&[0x6a, 8, 1, 0, 0, 0, 0, 0, 0, 0]);
                runtime.record_power(&[0x6a, 8, 2, 0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(runtime.activated, 2);
            }
            if next == 5 {
                runtime.invalidate_receiver(
                    &std::io::ErrorKind::UnexpectedEof.into(),
                    &mut Vec::new(),
                );
                runtime.step(&mut host);
                assert!(runtime.electric_action_fence.is_some());
            }
            if next == 4 || next == 5 {
                runtime.record_power(&[0x6a, 8, 2, 0, 0, 0, 0, 0, 0, 0]);
                assert_eq!(
                    runtime.activated, 1,
                    "receiver reconnect is not a new power activation"
                );
            }
            runtime.samples.entry(codec.id).or_default().insert(
                "IVI_SOC_MODESET",
                super::super::Sample {
                    value: 2,
                    received_at: super::super::clock::Stamp::now(),
                },
            );
            runtime.step(&mut host);
            let fenced = matches!(next, 0 | 4 | 5);
            assert_eq!(host.sent.len(), if fenced { 0 } else { 1 });
            if fenced {
                assert_eq!(
                    runtime.progress.get(codec.id),
                    Some(&Ok(Progress::Waiting(Wait::UserChoice)))
                );
            }
            assert_eq!(host.state.get("forced-ev-armed"), Some(&Read::Value(true)));
        }
    }

    #[test]
    fn electric_click_uses_current_runtime_admission_and_transport() {
        let codec = CODECS
            .iter()
            .find(|codec| codec.id == "vehicle-drive-forced-ev")
            .expect("generated FEV registry prerequisite missing");
        let mut host = owner(codec);
        host.state
            .insert("forced-ev-armed".into(), Read::Value(true));
        let mut runtime = Runtime::default();
        runtime.enabled.insert(codec.id);
        runtime.compatible.insert(codec.id);
        runtime.power_observed = true;
        runtime.power = Some(true);
        runtime.activated = 1;
        runtime.late = true;
        assert_eq!(runtime.electric_click(&mut host, 1), Ok(Some(true)));
        assert_eq!(
            host.sent,
            vec![Command {
                state: "IVI_SOC_MODESET",
                value: 5
            }]
        );
        host.enabled = false;
        assert_eq!(runtime.electric_click(&mut host, 2), Ok(Some(false)));
        assert_eq!(host.sent.len(), 1);
    }

    #[test]
    fn electric_click_disable_cannot_fallback_while_transport_pending() {
        let codec = CODECS
            .iter()
            .find(|codec| codec.id == "vehicle-drive-forced-ev")
            .unwrap();
        let mut host = owner(codec);
        host.state
            .insert("forced-ev-armed".into(), Read::Value(true));
        host.result = Transmission::Pending;
        let mut runtime = Runtime::default();
        runtime.enabled.insert(codec.id);
        runtime.compatible.insert(codec.id);
        runtime.power_observed = true;
        runtime.power = Some(true);
        runtime.activated = 1;
        runtime.late = true;
        assert_eq!(runtime.electric_click(&mut host, 1), Ok(None));
        assert_eq!(runtime.electric_click(&mut host, 1), Ok(None));
        assert_eq!(runtime.electric_click(&mut host, 2), Ok(None));
        assert_eq!(host.sent.len(), 1);
        let before = host.sent.len();
        runtime.step(&mut host);
        assert_eq!(
            host.sent.len(),
            before,
            "automatic restore must not consume the user action"
        );
        host.enabled = false;
        assert_eq!(runtime.electric_click(&mut host, 1), Ok(None));
    }

    #[test]
    fn electric_click_does_not_claim_other_work_or_waiting_as_submitted() {
        let codec = CODECS
            .iter()
            .find(|codec| codec.id == "vehicle-drive-forced-ev")
            .unwrap();
        let mut host = owner(codec);
        host.state
            .insert("forced-ev-armed".into(), Read::Value(true));
        host.result = Transmission::Waiting(Wait::Transport);
        let mut runtime = Runtime::default();
        runtime.enabled.insert(codec.id);
        runtime.compatible.insert(codec.id);
        runtime.power_observed = true;
        runtime.power = Some(true);
        runtime.activated = 1;
        runtime.late = true;
        assert_eq!(runtime.electric_click(&mut host, 1), Ok(Some(false)));
        assert!(host.sent.is_empty());
        host.action_identity = Some(voboost_contract::runtime_owner::NativeCommandIdentity {
            owner_session: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            source: codec.id.into(),
            command_id: 2,
            revision: 1,
            state: "IVI_SOC_MODESET".into(),
            value: 5,
        });
        runtime.controllers.insert(codec.id, (codec.create)());
        assert_eq!(
            runtime.electric_click(&mut host, 2),
            Err(Failure::TransportUnavailable)
        );
        assert!(
            runtime.controllers.contains_key(codec.id),
            "busy action must retain controller state"
        );
        assert!(host.sent.is_empty());
    }

    #[test]
    fn electric_click_drains_exact_terminal_after_disable() {
        use voboost_contract::runtime_owner::NativeCommandStatus;
        for (terminal, expected) in [
            (NativeCommandStatus::Cancelled, Ok(Some(false))),
            (NativeCommandStatus::Accepted, Ok(Some(true))),
            (
                NativeCommandStatus::Unknown,
                Err(Failure::TransportUnavailable),
            ),
        ] {
            let codec = CODECS
                .iter()
                .find(|codec| codec.id == "vehicle-drive-forced-ev")
                .unwrap();
            let mut host = owner(codec);
            host.state
                .insert("forced-ev-armed".into(), Read::Value(true));
            host.result = Transmission::Pending;
            let mut runtime = Runtime::default();
            runtime.enabled.insert(codec.id);
            runtime.compatible.insert(codec.id);
            runtime.power_observed = true;
            runtime.power = Some(true);
            runtime.activated = 1;
            runtime.late = true;
            assert_eq!(runtime.electric_click(&mut host, 1), Ok(None));
            host.enabled = false;
            host.action_terminal = Some(terminal);
            assert_eq!(runtime.electric_click(&mut host, 1), expected);
            assert_eq!(host.sent.len(), 1);
        }
    }

    #[test]
    fn temporary_admission_loss_keeps_a_controller_paused_by_unexplained_feedback() {
        let codec = codec();
        let mut fixture = crate::native_api::testing::ContextFixture::default();
        fixture
            .state
            .insert("pedestrian-warning-armed".into(), Read::Value(true));
        fixture
            .signals
            .insert("HUM_VSP_FUNCTION_SW".into(), Read::Value(1));
        fixture.inputs = Read::Value(vec![0]);
        let mut agent = (codec.create)();
        assert_eq!(agent.step(&mut fixture), Ok(Progress::Applied));
        fixture
            .signals
            .insert("HUM_VSP_FUNCTION_SW".into(), Read::Value(2));
        assert_eq!(
            agent.step(&mut fixture),
            Ok(Progress::Waiting(Wait::UserChoice))
        );
        let mut runtime = Runtime::default();
        runtime.controllers.insert(codec.id, agent);
        runtime.compatible.insert(codec.id);
        runtime.configure(&BTreeSet::new());
        let mut host = owner(codec);
        host.admission = None;
        host.ready = false;
        assert!(runtime.step(&mut host).is_empty());
        let mut retained = runtime
            .controllers
            .remove(codec.id)
            .expect("transient fence discarded the controller");
        assert_eq!(
            retained.step(&mut fixture),
            Ok(Progress::Waiting(Wait::UserChoice))
        );
        assert!(fixture.sent.is_empty());
    }
    #[test]
    fn late_semantic_send_needs_no_bootstrap_storage_and_rejects_undeclared_commands() {
        let codec = codec();
        let mut owner = owner(codec);
        let admission = owner.admission.clone().unwrap();
        let mut context = Source {
            codec,
            admission,
            host: &mut owner,
            samples: None,
            feedback_after_ms: None,
            sender: None,
            inputs: None,
            epoch: Some(1),
            now_ms: 1,
            late: true,
            accepted: false,
        };
        assert_eq!(
            context.send(
                Lease { revision: 1 },
                Command {
                    state: "EPS_MODE_SET",
                    value: 2
                }
            ),
            Err(Failure::InvalidValue)
        );
        assert_eq!(
            context.send(
                Lease { revision: 1 },
                Command {
                    state: "HUM_VSP_FUNCTION_SW",
                    value: 1
                }
            ),
            Ok(Transmission::Accepted)
        );
        assert!(context.accepted);
    }
    #[test]
    fn an_unavailable_late_executor_never_falls_back_to_raw_dispatch() {
        let codec = codec();
        let mut owner = owner(codec);
        owner.ready = false;
        let admission = owner.admission.clone().unwrap();
        let mut context = Source {
            codec,
            admission,
            host: &mut owner,
            samples: None,
            feedback_after_ms: None,
            sender: None,
            inputs: None,
            epoch: Some(1),
            now_ms: 1,
            late: true,
            accepted: false,
        };
        assert_eq!(
            context.send(Lease { revision: 1 }, codec.commands[0]),
            Ok(Transmission::Waiting(Wait::Transport))
        );
        assert!(context.sender.is_none());
        assert!(!context.accepted);
        let mut runtime = Runtime::default();
        runtime.enter_late();
        runtime.configure(&BTreeSet::new());
        runtime.step(&mut owner);
        assert!(runtime.late);
        assert!(runtime.sender.is_none());
    }
    #[test]
    fn accepted_late_operation_invalidates_all_pre_ack_feedback() {
        let codec = codec();
        let mut owner = owner(codec);
        owner
            .state
            .insert("pedestrian-warning-armed".into(), Read::Value(true));
        let mut runtime = Runtime::default();
        runtime.compatible.insert(codec.id);
        runtime.enabled.insert(codec.id);
        runtime.requested.insert(codec.id);
        runtime.late = true;
        runtime.power = Some(true);
        runtime.power_observed = true;
        runtime.activated = 1;
        runtime.samples.insert(
            codec.id,
            BTreeMap::from([(
                "HUM_VSP_FUNCTION_SW",
                super::super::Sample {
                    value: 2,
                    received_at: super::super::clock::Stamp::now(),
                },
            )]),
        );
        let events = runtime.step(&mut owner);
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Controller {
                result: Ok(Progress::Waiting(Wait::Reply)),
                ..
            }
        )));
        assert_eq!(
            owner.sent,
            vec![Command {
                state: "HUM_VSP_FUNCTION_SW",
                value: 1
            }]
        );
        assert!(runtime.samples.is_empty());
        assert!(runtime.discard_rx);
    }
}
