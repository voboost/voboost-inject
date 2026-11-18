//! Source-bound OEM commands; only native controllers may enqueue work.
use super::{invalid, Store};
use crate::native::Host;
use crate::native_api::{Command, Failure, Lease, Transmission, Wait};
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};
use voboost_contract::runtime_owner::{
    NativeCommandEnvelope, NativeCommandIdentity, NativeCommandPhase, NativeCommandStatus,
    NativeTransportReceipt, Outcome, SCHEMA,
};

#[derive(Default)]
pub(super) struct Queue {
    next_id: u64,
    transports: BTreeMap<String, Transport>,
    jobs: BTreeMap<String, Job>,
    observations: BTreeMap<String, VehicleObservation>,
    completed: BTreeMap<String, VecDeque<Completion>>,
}
struct Completion {
    identity: NativeCommandIdentity,
    executor: (i32, u64),
    result: NativeCommandStatus,
}
struct Transport {
    pid: i32,
    epoch: u64,
    available: bool,
    observed: Instant,
}
struct VehicleObservation {
    pid: i32,
    epoch: u64,
    observation: voboost_contract::runtime_owner::NativeVehicleObservation,
    received: Instant,
}
struct Job {
    identity: NativeCommandIdentity,
    phase: NativeCommandPhase,
    executor: Option<(i32, u64)>,
    result: Option<NativeCommandStatus>,
    consumed: bool,
    cancelled: bool,
}
impl Job {
    fn running(&self) -> bool {
        self.phase == NativeCommandPhase::Execute && self.result.is_none()
    }
    fn envelope(&self) -> NativeCommandEnvelope {
        NativeCommandEnvelope {
            schema_version: SCHEMA,
            identity: self.identity.clone(),
            phase: if self.cancelled {
                NativeCommandPhase::Cancelled
            } else {
                self.phase
            },
        }
    }
    fn cancel(&mut self) {
        self.cancelled = true;
        if self.result.is_none() && !self.running() {
            self.phase = NativeCommandPhase::Cancelled;
            self.result = Some(NativeCommandStatus::Cancelled);
            self.consumed = true;
        }
    }
}

impl Store {
    pub(super) fn cancel_source_commands(&mut self, source: &str) {
        if let Some(job) = self.command_queue.jobs.get_mut(source) {
            job.cancel();
        }
    }

    fn reap_commands(&mut self) {
        for job in self.command_queue.jobs.values_mut() {
            if job.running() && job.executor.is_some_and(|(pid, _)| !process_alive(pid)) {
                job.result = Some(NativeCommandStatus::Unknown);
            }
        }
    }

    fn command_current(&self, identity: &NativeCommandIdentity) -> bool {
        identity.owner_session == self.session
            && self.native_boot.as_deref() == Some(&identity.boot_id)
            && self.admission(&identity.source).is_some_and(|admission| {
                admission.current() && admission.lease.revision == identity.revision
            })
    }
    pub(super) fn send_command(
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
        if !crate::native::CODECS
            .iter()
            .any(|codec| codec.id == source && codec.commands.contains(&command))
        {
            return Err(Failure::InvalidValue);
        }
        if let Some(job) = self.command_queue.jobs.get_mut(source) {
            let same = job.identity.revision == lease.revision
                && job.identity.state == command.state
                && job.identity.value == command.value;
            if same {
                match job.result {
                    Some(NativeCommandStatus::Accepted) if !job.consumed => {
                        job.consumed = true;
                        return Ok(Transmission::Accepted);
                    }
                    Some(NativeCommandStatus::Failed | NativeCommandStatus::Unknown)
                        if !job.consumed =>
                    {
                        return Err(Failure::TransportUnavailable)
                    }
                    None => return Ok(Transmission::Pending),
                    _ => {}
                }
            } else if job.running() {
                job.cancelled = true;
                return Ok(Transmission::Waiting(Wait::Reply));
            }
        }
        self.command_queue.jobs.remove(source);
        if !self
            .command_queue
            .transports
            .get(source)
            .is_some_and(|transport| {
                transport.available && transport.observed.elapsed() < Duration::from_secs(1)
            })
        {
            return Ok(Transmission::Waiting(Wait::Transport));
        }
        let boot = self.native_boot.clone().ok_or(Failure::StateUnavailable)?;
        self.command_queue.next_id = self
            .command_queue
            .next_id
            .checked_add(1)
            .filter(|id| *id <= i64::MAX as u64)
            .ok_or(Failure::InvalidValue)?;
        let identity = NativeCommandIdentity {
            owner_session: self.session.clone(),
            boot_id: boot,
            source: source.into(),
            command_id: self.command_queue.next_id,
            revision: lease.revision,
            state: command.state.into(),
            value: command.value,
        };
        self.command_queue.jobs.insert(
            source.into(),
            Job {
                identity: identity.clone(),
                phase: NativeCommandPhase::Offered,
                executor: None,
                result: None,
                consumed: false,
                cancelled: false,
            },
        );
        self.record_command_phase(&identity, "offered");
        Ok(Transmission::Pending)
    }

    pub(super) fn action_identity(&self, source: &str) -> Option<NativeCommandIdentity> {
        // Older revisions may still be executing and must drain before any user fallback.
        self.command_queue
            .jobs
            .get(source)
            .filter(|job| {
                !(job.consumed && job.result.is_some())
                    && job.identity.state == "IVI_SOC_MODESET"
                    && matches!(job.identity.value, 2 | 5)
            })
            .map(|job| job.identity.clone())
    }

    /// Observe the terminal result only for the exact command identity.
    pub(super) fn action_terminal(
        &mut self,
        identity: &NativeCommandIdentity,
    ) -> Option<NativeCommandStatus> {
        self.reap_commands();
        self.command_queue
            .jobs
            .get(&identity.source)
            .filter(|job| job.identity == *identity)
            .and_then(|job| job.result)
            .or_else(|| {
                self.command_queue
                    .completed
                    .get(&identity.source)
                    .and_then(|entries| entries.iter().find(|entry| entry.identity == *identity))
                    .map(|entry| entry.result)
            })
    }

    pub(super) fn withdraw_command(&mut self, source: &str, lease: Lease, completed: bool) {
        if let Some(job) = self.command_queue.jobs.get_mut(source) {
            if job.identity.revision == lease.revision {
                if completed && job.result.is_some() {
                    job.consumed = true;
                }
                if job.result.is_none() {
                    job.cancel();
                }
            }
        }
    }

    pub(super) fn native_command_ready(&self, source: &str) -> bool {
        let Some(admission) = self
            .admission(source)
            .filter(|admission| admission.current())
        else {
            return false;
        };
        if let Some(job) = self.command_queue.jobs.get(source) {
            if job.identity.revision == admission.lease.revision {
                return true;
            }
            if job.running() {
                return false;
            }
        }
        self.command_queue
            .transports
            .get(source)
            .is_some_and(|transport| {
                transport.available && transport.observed.elapsed() < Duration::from_secs(1)
            })
    }

    pub(super) fn register_transport(
        &mut self,
        source: &str,
        pid: i32,
        epoch: u64,
        available: bool,
    ) -> io::Result<Outcome> {
        if pid <= 1 || epoch == 0 || !crate::native::CODECS.iter().any(|codec| codec.id == source) {
            return Err(invalid("native transport authority differs"));
        }
        let mut granted = available;
        if let Some(job) = self.command_queue.jobs.get_mut(source) {
            if job.running() && job.executor != Some((pid, epoch)) && available {
                let old_pid = job
                    .executor
                    .ok_or_else(|| invalid("native executor unavailable"))?
                    .0;
                if old_pid != pid && process_alive(old_pid) {
                    granted = false;
                } else {
                    // Same-process readiness is issued only after the shared component barrier.
                    job.result = Some(NativeCommandStatus::Unknown);
                }
            }
            if !available {
                job.cancel();
            }
        }
        if granted || !available {
            self.command_queue.transports.insert(
                source.into(),
                Transport {
                    pid,
                    epoch,
                    available: granted,
                    observed: Instant::now(),
                },
            );
        }
        Ok(Outcome::NativeTransportRegistered {
            receipt: NativeTransportReceipt {
                owner_session: self.session.clone(),
                boot_id: self
                    .native_boot
                    .clone()
                    .ok_or_else(|| invalid("native boot unavailable"))?,
                source: source.into(),
                pid,
                endpoint_epoch: epoch,
                available: granted,
            },
        })
    }

    pub(super) fn observe_vehicle(
        &mut self,
        source: &str,
        pid: i32,
        epoch: u64,
        observation: voboost_contract::runtime_owner::NativeVehicleObservation,
    ) -> io::Result<Outcome> {
        let now = crate::startup::boot_ms().map_err(io::Error::other)?;
        self.observe_vehicle_at(source, pid, epoch, observation, now)
    }

    fn observe_vehicle_at(
        &mut self,
        source: &str,
        pid: i32,
        epoch: u64,
        observation: voboost_contract::runtime_owner::NativeVehicleObservation,
        now: u64,
    ) -> io::Result<Outcome> {
        if !observation.valid()
            || !now
                .checked_sub(observation.sampled_boot_ms)
                .is_some_and(|age| age <= 2000)
            || !crate::native::CODECS.iter().any(|codec| {
                codec.id == source
                    && codec
                        .commands
                        .iter()
                        .any(|command| command.state == observation.state)
            })
        {
            return Err(invalid("OEM vehicle observation differs or is stale"));
        }
        self.touch_transport(source, pid, epoch)?;
        self.command_queue.observations.insert(
            source.into(),
            VehicleObservation {
                pid,
                epoch,
                observation,
                received: Instant::now(),
            },
        );
        Ok(Outcome::NativeVehicleObserved {
            source: source.into(),
            boot_id: self
                .native_boot
                .clone()
                .ok_or_else(|| invalid("native boot unavailable"))?,
        })
    }

    pub(super) fn vehicle_observation(
        &self,
        source: &str,
    ) -> Option<voboost_contract::runtime_owner::NativeVehicleObservation> {
        self.vehicle_observation_at(source, crate::startup::boot_ms().ok()?)
    }

    fn vehicle_observation_at(
        &self,
        source: &str,
        now: u64,
    ) -> Option<voboost_contract::runtime_owner::NativeVehicleObservation> {
        let observed = self.command_queue.observations.get(source)?;
        let transport = self.command_queue.transports.get(source)?;
        if !transport.available
            || transport.pid != observed.pid
            || transport.epoch != observed.epoch
            || !process_alive(transport.pid)
            || observed.received.elapsed() > Duration::from_secs(2)
            || !now
                .checked_sub(observed.observation.sampled_boot_ms)
                .is_some_and(|age| age <= 2000)
        {
            return None;
        }
        Some(observed.observation.clone())
    }

    pub(super) fn poll_command(
        &mut self,
        source: &str,
        pid: i32,
        epoch: u64,
    ) -> io::Result<Outcome> {
        self.touch_transport(source, pid, epoch)?;
        self.reap_commands();
        let current = self
            .command_queue
            .jobs
            .get(source)
            .is_some_and(|job| self.command_current(&job.identity));
        let executing_other = self
            .command_queue
            .jobs
            .iter()
            .any(|(id, job)| id != source && job.running());
        let command = self.command_queue.jobs.get_mut(source).and_then(|job| {
            if !current {
                job.cancel();
            }
            if job.result.is_some() && !job.cancelled || executing_other {
                return None;
            }
            Some(job.envelope())
        });
        Ok(Outcome::NativeCommand {
            source: source.into(),
            command,
        })
    }

    pub(super) fn report_command(
        &mut self,
        identity: NativeCommandIdentity,
        pid: i32,
        epoch: u64,
        status: NativeCommandStatus,
    ) -> io::Result<Outcome> {
        if status != NativeCommandStatus::Claim {
            if let Some(previous) = self
                .command_queue
                .completed
                .get(&identity.source)
                .and_then(|entries| entries.iter().find(|entry| entry.identity == identity))
            {
                if previous.executor != (pid, epoch) || previous.result != status {
                    return Err(invalid("native historical completion conflicts"));
                }
                return Ok(Outcome::NativeCommandReported {
                    identity,
                    result: status,
                });
            }
        }
        let current = self.command_current(&identity);
        if status == NativeCommandStatus::Claim {
            self.touch_transport(&identity.source, pid, epoch)?;
            self.reap_commands();
            if self
                .command_queue
                .jobs
                .iter()
                .any(|(source, job)| source != &identity.source && job.running())
            {
                return Ok(Outcome::NativeCommand {
                    source: identity.source,
                    command: None,
                });
            }
        }
        let job = self
            .command_queue
            .jobs
            .get_mut(&identity.source)
            .filter(|job| job.identity == identity)
            .ok_or_else(|| invalid("native command identity differs"))?;
        if status == NativeCommandStatus::Claim {
            let was_execute = job.phase == NativeCommandPhase::Execute;
            if !current {
                job.cancel();
            }
            if !job.cancelled && job.result.is_none() {
                if job
                    .executor
                    .is_some_and(|executor| executor != (pid, epoch))
                {
                    return Err(invalid("native command executor differs"));
                }
                job.executor = Some((pid, epoch));
                job.phase = NativeCommandPhase::Execute;
            }
            let outcome = Outcome::NativeCommand {
                source: identity.source.clone(),
                command: Some(job.envelope()),
            };
            let granted = !was_execute && job.phase == NativeCommandPhase::Execute;
            if granted {
                self.record_command_phase(&identity, "execute");
            }
            return Ok(outcome);
        }
        if job.executor != Some((pid, epoch)) {
            return Err(invalid("native completion executor differs"));
        }
        if let Some(previous) = job.result {
            if previous != status {
                return Err(invalid("native completion conflicts"));
            }
        } else {
            job.result = Some(status);
        }
        let history = self
            .command_queue
            .completed
            .entry(identity.source.clone())
            .or_default();
        history.push_back(Completion {
            identity: identity.clone(),
            executor: (pid, epoch),
            result: status,
        });
        while history.len() > 16 {
            history.pop_front();
        }
        self.record_command_phase(
            &identity,
            match status {
                NativeCommandStatus::Accepted => "accepted",
                NativeCommandStatus::Cancelled => "cancelled",
                NativeCommandStatus::Failed => "failed",
                NativeCommandStatus::Unknown => "unknown",
                NativeCommandStatus::Claim => unreachable!("claim returned its own grant"),
            },
        );
        Ok(Outcome::NativeCommandReported {
            identity,
            result: status,
        })
    }

    // Best-effort diagnostic phases, never an ECU application or lossless bus oracle.
    fn record_command_phase(&mut self, identity: &NativeCommandIdentity, phase: &str) {
        let mut fields = std::collections::HashMap::from([
            ("agent".into(), identity.source.clone()),
            ("commandId".into(), identity.command_id.to_string()),
            ("state".into(), identity.state.clone()),
            ("value".into(), identity.value.to_string()),
            ("phase".into(), phase.into()),
        ]);
        if let Ok(time) = crate::startup::boot_ms() {
            fields.insert("observedBootMs".into(), time.to_string());
        }
        let _ = self.write_log(
            voboost_contract::runtime_log::Source::daemon(),
            voboost_contract::runtime_log::Record {
                level: voboost_contract::runtime_log::Level::Debug,
                component: "native".into(),
                message: "native command phase changed".into(),
                fields,
            },
        );
    }

    fn touch_transport(&mut self, source: &str, pid: i32, epoch: u64) -> io::Result<()> {
        let transport = self
            .command_queue
            .transports
            .get_mut(source)
            .filter(|transport| {
                transport.available && transport.pid == pid && transport.epoch == epoch
            })
            .ok_or_else(|| invalid("native transport endpoint differs"))?;
        transport.observed = Instant::now();
        Ok(())
    }
}

fn process_alive(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::CODECS;
    use std::os::unix::fs::PermissionsExt;

    fn endpoint_pid() -> i32 {
        std::process::id() as i32
    }

    struct Executor(std::process::Child);

    impl Executor {
        fn finish(&mut self) -> io::Result<std::process::ExitStatus> {
            drop(self.0.stdin.take());
            self.0.wait()
        }
    }

    impl Drop for Executor {
        fn drop(&mut self) {
            let _ = self.finish();
        }
    }

    fn abandoned_execution(dead: bool, claim_directly: bool) {
        let (_root, mut store, source, lease, command) = fixture();
        let other = CODECS.iter().find(|codec| codec.id != source).unwrap();
        let previous = store.config().unwrap().unwrap();
        let mut next: serde_json::Value = serde_json::from_slice(&previous).unwrap();
        next["agents"][other.id] =
            serde_json::json!({"enabled":true,"options":{"intent":"observe"}});
        store
            .command(super::super::Command::ReplaceConfig {
                expected: Some(String::from_utf8(previous).unwrap()),
                next: next.to_string(),
            })
            .unwrap();
        store
            .register_transport(other.id, endpoint_pid(), 1, true)
            .unwrap();
        let other_lease = store.admission(other.id).unwrap().lease;
        store
            .send_command(other.id, other_lease, other.commands[0])
            .unwrap();
        let other_identity = offered(&mut store, other.id);
        let mut executor = Executor(
            std::process::Command::new("/bin/sh")
                .args(["-c", "read value"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let pid = executor.0.id() as i32;
        store.register_transport(source, pid, 2, true).unwrap();
        store.send_command(source, lease, command).unwrap();
        let identity = match store.poll_command(source, pid, 2).unwrap() {
            Outcome::NativeCommand {
                command: Some(envelope),
                ..
            } => envelope.identity,
            other => panic!("unexpected {other:?}"),
        };
        store
            .report_command(identity, pid, 2, NativeCommandStatus::Claim)
            .unwrap();
        let previous = store.config().unwrap().unwrap();
        let mut next: serde_json::Value = serde_json::from_slice(&previous).unwrap();
        next["agents"][source]["enabled"] = false.into();
        store
            .command(super::super::Command::ReplaceConfig {
                expected: Some(String::from_utf8(previous).unwrap()),
                next: next.to_string(),
            })
            .unwrap();
        assert!(!store.enabled(source));
        store.register_transport(source, pid, 2, false).unwrap();
        if dead {
            executor.finish().unwrap();
        }
        let outcome = if claim_directly {
            store.report_command(
                other_identity,
                endpoint_pid(),
                1,
                NativeCommandStatus::Claim,
            )
        } else {
            store.poll_command(other.id, endpoint_pid(), 1)
        };
        if !dead {
            executor.finish().unwrap();
        }
        assert!(
            matches!(outcome.unwrap(), Outcome::NativeCommand { command, .. }
            if command.is_some() == dead)
        );
        assert_eq!(
            store.command_queue.jobs[source].result,
            dead.then_some(NativeCommandStatus::Unknown)
        );
        if dead && !claim_directly {
            let identity = store.command_queue.jobs[other.id].identity.clone();
            claim(&mut store, &identity);
        }
    }

    #[test]
    fn a_dead_disabled_executor_releases_another_source_without_reregistration() {
        abandoned_execution(true, false);
        abandoned_execution(true, true);
    }

    #[test]
    fn unregistering_a_live_executor_keeps_other_sources_blocked() {
        abandoned_execution(false, false);
        abandoned_execution(false, true);
    }

    fn fixture() -> (tempfile::TempDir, Store, &'static str, Lease, Command) {
        let root = tempfile::Builder::new()
            .prefix(".semantic-owner-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let codec = CODECS
            .first()
            .expect("semantic owner tests require generated registry");
        let config = serde_json::json!({"schemaVersion":2,"startup":"interface","userRevision":0,"fieldRevisions":{},"agents":{
            (codec.id):{"enabled":true,"options":{"intent":"on"}} }});
        super::super::Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", config.to_string().as_bytes(), 0o600)
            .unwrap();
        let mut store = Store::new(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        store
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        let lease = store.admission(codec.id).unwrap().lease;
        store
            .register_transport(codec.id, endpoint_pid(), 1, true)
            .unwrap();
        (root, store, codec.id, lease, codec.commands[0])
    }
    #[test]
    fn current_vehicle_observation_requires_the_live_registered_endpoint_and_fresh_clock() {
        let (_root, mut store, source, _, command) = fixture();
        let now = 10000;
        let observation = voboost_contract::runtime_owner::NativeVehicleObservation {
            acc: 2,
            state: command.state.into(),
            value: 2,
            sampled_boot_ms: now,
        };
        assert!(store
            .observe_vehicle_at(source, endpoint_pid(), 2, observation.clone(), now)
            .is_err());
        assert!(store
            .observe_vehicle_at(source, endpoint_pid(), 1, observation.clone(), now)
            .is_ok());
        assert_eq!(
            store.vehicle_observation_at(source, now),
            Some(observation.clone())
        );
        let mut stale = observation.clone();
        stale.sampled_boot_ms = now.saturating_sub(3000);
        assert!(store
            .observe_vehicle_at(source, endpoint_pid(), 1, stale, now)
            .is_err());
        let mut future = observation.clone();
        future.sampled_boot_ms = now + 60000;
        assert!(store
            .observe_vehicle_at(source, endpoint_pid(), 1, future, now)
            .is_err());
        let mut foreign = observation.clone();
        foreign.state = if command.state == "IVI_SOC_MODESET" {
            "HUM_VSP_FUNCTION_SW".into()
        } else {
            "IVI_SOC_MODESET".into()
        };
        assert!(store
            .observe_vehicle_at(source, endpoint_pid(), 1, foreign, now)
            .is_err());
        store
            .register_transport(source, endpoint_pid(), 1, false)
            .unwrap();
        assert!(store.vehicle_observation_at(source, now).is_none());
        assert!(store
            .observe_vehicle_at(source, endpoint_pid(), 1, observation, now)
            .is_err());
    }

    fn desired_input(request_id: u64) -> voboost_contract::desired::Input {
        voboost_contract::desired::Input {
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            endpoint_epoch: 1,
            request_id,
            injector_pid: 42,
            injector_starttime: 100,
        }
    }

    fn saved_on_fixture() -> (tempfile::TempDir, Store, &'static str, Lease, Command) {
        let (root, mut store, source, _lease, command) = fixture();
        let field = voboost_contract::desired::Field::Option {
            agent: source.into(),
            key: "intent".into(),
        };
        assert!(matches!(
            store
                .save_desired(&field, &"on".into(), &desired_input(7))
                .unwrap(),
            Outcome::DesiredSaved {
                disposition: voboost_contract::desired::Disposition::Saved,
                ..
            }
        ));
        assert_eq!(store.intent(source), crate::native_api::Read::Value(true));
        let lease = store.admission(source).unwrap().lease;
        (root, store, source, lease, command)
    }

    #[test]
    fn scoped_electric_drain_distinguishes_cancelled_and_unknown() {
        let (_root, mut store, source, lease, command) = fixture();
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Pending)
        );
        let identity = offered(&mut store, source);
        assert_eq!(store.action_terminal(&identity), None);
        store.withdraw_command(source, lease, false);
        assert_eq!(
            store.action_terminal(&identity),
            Some(NativeCommandStatus::Cancelled)
        );
        assert_eq!(
            store.action_terminal(&identity),
            Some(NativeCommandStatus::Cancelled)
        );

        let (_root, mut store, source, lease, command) = fixture();
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Pending)
        );
        let identity = offered(&mut store, source);
        claim(&mut store, &identity);
        store.withdraw_command(source, lease, false);
        assert_eq!(store.action_terminal(&identity), None);
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Unknown,
            )
            .unwrap();
        assert_eq!(
            store.action_terminal(&identity),
            Some(NativeCommandStatus::Unknown)
        );
        let mut other = identity;
        other.command_id += 1;
        assert_eq!(store.action_terminal(&other), None);
    }

    #[test]
    fn electric_action_composes_store_runtime_and_queue_on_disable() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        for running in [false, true] {
            let (_root, mut store, source, lease, _) = fixture();
            assert_eq!(source, "vehicle-drive-forced-ev");
            store
                .write_controller_state(source, lease, "forced-ev-armed", true)
                .unwrap();
            let mut runtime = crate::native::Runtime::default();
            runtime.electric_action_test_ready();
            let input = desired_input(20);
            assert_eq!(
                runtime.electric_click_request(&mut store, input.clone(), false, false),
                Status::Pending
            );
            let identity = offered(&mut store, source);
            if running {
                claim(&mut store, &identity);
            }
            store.begin_withdrawal(source);
            if running {
                assert_eq!(
                    runtime.electric_click_request(&mut store, input.clone(), true, false),
                    Status::Pending
                );
                store
                    .report_command(identity, endpoint_pid(), 1, NativeCommandStatus::Unknown)
                    .unwrap();
                assert_eq!(
                    runtime.electric_click_request(&mut store, input, true, false),
                    Status::Drained
                );
            } else {
                assert_eq!(
                    runtime.electric_click_request(&mut store, input.clone(), true, false),
                    Status::NotSubmitted
                );
                assert_eq!(
                    runtime.electric_click_request(&mut store, input, true, false),
                    Status::NotSubmitted
                );
            }
        }
    }

    #[test]
    fn electric_uncertain_terminal_drains_and_allows_a_new_request() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        let (_root, mut store, source, lease, _) = fixture();
        store
            .write_controller_state(source, lease, "forced-ev-armed", true)
            .unwrap();
        let mut runtime = crate::native::Runtime::default();
        runtime.electric_action_test_ready();
        let input = desired_input(40);
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), false, false),
            Status::Pending
        );
        let identity = offered(&mut store, source);
        claim(&mut store, &identity);
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), true, true),
            Status::Pending
        );
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Unknown,
            )
            .unwrap();
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), true, false),
            Status::Drained
        );
        assert_eq!(
            runtime.electric_click_request(&mut store, input, true, false),
            Status::Drained
        );
        assert!(!runtime.electric_action_test_pending());
        assert_eq!(store.command_queue.next_id, identity.command_id);
        assert_eq!(
            runtime.electric_click_request(&mut store, desired_input(41), false, false),
            Status::Pending
        );
        assert_eq!(store.command_queue.next_id, identity.command_id + 1);
    }

    #[test]
    fn electric_gesture_drains_automatic_work_without_claiming_or_replaying_it() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        for terminal in [NativeCommandStatus::Accepted, NativeCommandStatus::Unknown] {
            let (_root, mut store, source, lease, _) = fixture();
            store
                .write_controller_state(source, lease, "forced-ev-armed", true)
                .unwrap();
            assert_eq!(
                store.send_command(
                    source,
                    lease,
                    crate::native_api::Command {
                        state: "IVI_SOC_MODESET",
                        value: 5,
                    }
                ),
                Ok(Transmission::Pending)
            );
            let identity = offered(&mut store, source);
            claim(&mut store, &identity);
            let mut runtime = crate::native::Runtime::default();
            runtime.electric_action_test_ready();
            let input = desired_input(50);
            assert_eq!(
                runtime.electric_click_request(&mut store, input.clone(), false, false),
                Status::Draining
            );
            assert_eq!(
                runtime.electric_click_request(&mut store, input.clone(), true, true),
                Status::Draining
            );
            store
                .report_command(identity.clone(), endpoint_pid(), 1, terminal)
                .unwrap();
            assert_eq!(
                runtime.electric_click_request(&mut store, input, true, false),
                Status::Drained
            );
            assert!(!runtime.electric_action_test_pending());
            assert_eq!(store.command_queue.next_id, identity.command_id);
        }
    }

    #[test]
    fn electric_gesture_drains_executing_work_across_newer_intent_revisions() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        for value in [2, 5] {
            for choice in ["off", "on"] {
                let (_root, mut store, source, lease, _) = fixture();
                store
                    .write_controller_state(source, lease, "forced-ev-armed", true)
                    .unwrap();
                store
                    .send_command(
                        source,
                        lease,
                        Command {
                            state: "IVI_SOC_MODESET",
                            value,
                        },
                    )
                    .unwrap();
                let identity = offered(&mut store, source);
                claim(&mut store, &identity);
                for next_choice in if choice == "on" {
                    vec!["off", "on"]
                } else {
                    vec!["off"]
                } {
                    let previous = store.config().unwrap().unwrap();
                    let mut next: serde_json::Value = serde_json::from_slice(&previous).unwrap();
                    next["agents"][source]["options"]["intent"] = next_choice.into();
                    store
                        .command(super::super::Command::ReplaceConfig {
                            expected: Some(String::from_utf8(previous).unwrap()),
                            next: next.to_string(),
                        })
                        .unwrap();
                }
                assert_ne!(store.admission(source).unwrap().lease, lease);
                let mut runtime = crate::native::Runtime::default();
                runtime.electric_action_test_ready();
                let input = desired_input(60);
                assert_eq!(
                    runtime.electric_click_request(&mut store, input.clone(), false, false),
                    Status::Draining
                );
                assert_eq!(
                    runtime.electric_click_request(&mut store, input.clone(), true, true),
                    Status::Draining
                );
                assert_eq!(store.command_queue.next_id, identity.command_id);
                store
                    .report_command(
                        identity.clone(),
                        endpoint_pid(),
                        1,
                        NativeCommandStatus::Unknown,
                    )
                    .unwrap();
                assert_eq!(
                    runtime.electric_click_request(&mut store, input, true, false),
                    Status::Drained
                );
                assert!(!runtime.electric_action_test_pending());
                assert_eq!(store.command_queue.next_id, identity.command_id);
                let saved: serde_json::Value =
                    serde_json::from_slice(&store.config().unwrap().unwrap()).unwrap();
                assert_eq!(saved["agents"][source]["options"]["intent"], choice);
            }
        }
    }

    #[test]
    fn electric_cancel_drains_queue_without_new_write() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        {
            let (_root, mut store, source, lease, _) = fixture();
            store
                .write_controller_state(source, lease, "forced-ev-armed", true)
                .unwrap();
            let mut runtime = crate::native::Runtime::default();
            runtime.electric_action_test_ready();
            let input = desired_input(24);
            assert_eq!(
                runtime.electric_click_request(&mut store, input.clone(), false, true),
                Status::NotSubmitted
            );
            assert_eq!(
                runtime.electric_click_request(&mut store, input, true, false),
                Status::NotSubmitted
            );
            assert_eq!(store.command_queue.next_id, 0);
        }
        for running in [false, true] {
            let (_root, mut store, source, lease, _) = fixture();
            store
                .write_controller_state(source, lease, "forced-ev-armed", true)
                .unwrap();
            let mut runtime = crate::native::Runtime::default();
            runtime.electric_action_test_ready();
            let input = desired_input(25);
            assert_eq!(
                runtime.electric_click_request(&mut store, input.clone(), false, false),
                Status::Pending
            );
            let identity = offered(&mut store, source);
            if running {
                claim(&mut store, &identity);
            }
            let result = runtime.electric_click_request(&mut store, input.clone(), true, true);
            if running {
                assert_eq!(result, Status::Pending);
                store
                    .report_command(
                        identity.clone(),
                        endpoint_pid(),
                        1,
                        NativeCommandStatus::Unknown,
                    )
                    .unwrap();
                assert_eq!(
                    runtime.electric_click_request(&mut store, input, true, true),
                    Status::Drained
                );
            } else {
                assert_eq!(result, Status::NotSubmitted);
                assert_eq!(
                    runtime.electric_click_request(&mut store, input, true, false),
                    Status::NotSubmitted
                );
            }
            assert_eq!(store.command_queue.next_id, identity.command_id);
            assert_eq!(
                store.read_controller_state(source, "forced-ev-armed"),
                crate::native_api::Read::Value(true)
            );
        }
    }

    #[test]
    fn electric_action_drains_terminal_without_ui_poll() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        let (_root, mut store, source, lease, _) = fixture();
        store
            .write_controller_state(source, lease, "forced-ev-armed", true)
            .unwrap();
        let mut runtime = crate::native::Runtime::default();
        runtime.electric_action_test_ready();
        let input = desired_input(29);
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), false, false),
            Status::Pending
        );
        let identity = offered(&mut store, source);
        claim(&mut store, &identity);
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        runtime.step(&mut store);
        assert!(!runtime.electric_action_test_pending());
        assert_eq!(
            runtime.electric_click_request(&mut store, input, true, false),
            Status::Accepted
        );
        assert_eq!(store.command_queue.next_id, identity.command_id);
    }

    #[test]
    fn electric_action_composes_accepted_command_and_duplicate_lookup() {
        use voboost_contract::runtime_owner::ElectricClickStatus as Status;
        let (_root, mut store, source, lease, _) = fixture();
        assert_eq!(source, "vehicle-drive-forced-ev");
        store
            .write_controller_state(source, lease, "forced-ev-armed", true)
            .unwrap();
        let mut runtime = crate::native::Runtime::default();
        runtime.electric_action_test_ready();
        let input = desired_input(30);
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), false, false),
            Status::Pending
        );
        let identity = offered(&mut store, source);
        claim(&mut store, &identity);
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), true, false),
            Status::Accepted
        );
        assert_eq!(
            runtime.electric_click_request(&mut store, input.clone(), true, false),
            Status::Accepted
        );
        assert_eq!(store.command_queue.next_id, identity.command_id);
        let mut foreign = input;
        foreign.endpoint_epoch += 1;
        assert_eq!(
            runtime.electric_click_request(&mut store, foreign, true, false),
            Status::Drained
        );
        assert_eq!(store.command_queue.next_id, identity.command_id);
        let next = desired_input(31);
        assert_eq!(
            runtime.electric_click_request(&mut store, next, false, false),
            Status::Pending
        );
        assert_eq!(store.command_queue.next_id, identity.command_id + 1);
    }

    #[test]
    fn same_value_saved_on_gets_fresh_lease_without_reusing_old_execution_receipt() {
        let (_root, mut store, source, lease, command) = saved_on_fixture();
        let issued = store.admission(source).unwrap();
        store.send_command(source, lease, command).unwrap();
        let old = offered(&mut store, source);
        claim(&mut store, &old);
        let field = voboost_contract::desired::Field::Option {
            agent: source.into(),
            key: "intent".into(),
        };
        store
            .save_desired(&field, &"on".into(), &desired_input(8))
            .unwrap();
        let next_lease = store.admission(source).unwrap().lease;
        assert_ne!(next_lease, lease);
        assert!(!issued.current());
        assert_eq!(store.intent(source), crate::native_api::Read::Value(true));
        assert_eq!(
            store.send_command(source, next_lease, command),
            Ok(Transmission::Waiting(Wait::Reply))
        );
        store
            .report_command(
                old.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        assert_eq!(
            store.send_command(source, lease, command),
            Err(Failure::Cancelled)
        );
        assert_eq!(
            store.send_command(source, next_lease, command),
            Ok(Transmission::Pending)
        );
        let next = offered(&mut store, source);
        assert_ne!(next.command_id, old.command_id);
        assert_eq!(next.revision, next_lease.revision);
        store
            .save_desired(&field, &"on".into(), &desired_input(8))
            .unwrap();
        assert_eq!(store.admission(source).unwrap().lease, next_lease);
        assert_eq!(store.command_queue.jobs[source].identity, next);
    }

    #[test]
    fn saved_checkbox_off_cancels_real_offered_and_running_native_on() {
        for running in [false, true] {
            let (root, mut store, source, lease, command) = saved_on_fixture();
            let issued = store.admission(source).unwrap();
            assert_eq!(
                store.send_command(source, lease, command),
                Ok(Transmission::Pending)
            );
            let old = offered(&mut store, source);
            if running {
                claim(&mut store, &old);
            }
            let field = voboost_contract::desired::Field::Enabled {
                agent: source.into(),
            };
            assert!(matches!(
                store
                    .save_desired(&field, &false.into(), &desired_input(8))
                    .unwrap(),
                Outcome::DesiredSaved {
                    disposition: voboost_contract::desired::Disposition::Saved,
                    ..
                }
            ));
            let durable = voboost_contract::desired::Config::decode(
                &std::fs::read(root.path().join("agents.json")).unwrap(),
            )
            .unwrap();
            assert!(!durable.agents[source].enabled);
            assert!(!issued.current());
            // Saved OFF revokes both queued and running automation immediately.
            assert!(store.admission(source).is_none());
            assert_eq!(
                store.send_command(source, lease, command),
                Err(Failure::Cancelled)
            );
            if running {
                store
                    .report_command(old, endpoint_pid(), 1, NativeCommandStatus::Accepted)
                    .unwrap();
            } else {
                assert!(matches!(
                    store.report_command(old, endpoint_pid(), 1, NativeCommandStatus::Claim).unwrap(),
                    Outcome::NativeCommand { command: Some(envelope), .. }
                    if envelope.phase == NativeCommandPhase::Cancelled
                ));
            }
            store.refresh_native().unwrap();
            assert!(store.admission(source).is_none());
            assert!(!store.enabled(source));
            // Completing target cleanup cannot restore the cancelled authority.
            store.confirm_withdrawn(source);
            assert!(store.admission(source).is_none());
            assert!(!store.enabled(source));
            assert_eq!(
                store.send_command(source, lease, command),
                Err(Failure::Cancelled)
            );
        }
    }

    #[test]
    fn failed_saved_off_fsync_revokes_actual_running_native_command_before_ack() {
        let (_root, mut store, source, lease, command) = saved_on_fixture();
        let issued = store.admission(source).unwrap();
        store.send_command(source, lease, command).unwrap();
        let old = offered(&mut store, source);
        claim(&mut store, &old);
        let field = voboost_contract::desired::Field::Enabled {
            agent: source.into(),
        };
        assert!(store
            .save_desired_with(&field, &false.into(), &desired_input(8), |_, _| {
                assert!(
                    !issued.current(),
                    "old worker token revoked before persistence"
                );
                Err(io::Error::other("injected fsync failure"))
            })
            .is_err());
        assert!(store.command_queue.jobs[source].cancelled);
        assert!(store.admission(source).is_none());
        store
            .report_command(old, endpoint_pid(), 1, NativeCommandStatus::Accepted)
            .unwrap();
        store.refresh_native().unwrap();
        assert!(store.admission(source).is_none());
        assert_eq!(
            store.send_command(source, lease, command),
            Err(Failure::Cancelled)
        );
    }

    #[test]
    fn saved_intent_off_waits_for_real_old_execution_before_release_and_stale_acceptance_is_inert()
    {
        let (_root, mut store, source, lease, command) = saved_on_fixture();
        let issued = store.admission(source).unwrap();
        store.send_command(source, lease, command).unwrap();
        let old = offered(&mut store, source);
        claim(&mut store, &old);
        let field = voboost_contract::desired::Field::Option {
            agent: source.into(),
            key: "intent".into(),
        };
        store
            .save_desired(&field, &"off".into(), &desired_input(8))
            .unwrap();
        let release = CODECS
            .iter()
            .find(|codec| codec.id == source)
            .unwrap()
            .commands[1];
        let replacement = store
            .admission(source)
            .expect("OFF retains enabled release controller")
            .lease;
        assert_ne!(replacement, lease);
        assert!(!issued.current());
        assert_eq!(store.intent(source), crate::native_api::Read::Value(false));
        assert_eq!(
            store.send_command(source, replacement, release),
            Ok(Transmission::Waiting(Wait::Reply))
        );
        store
            .report_command(
                old.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        assert_eq!(
            store.send_command(source, lease, command),
            Err(Failure::Cancelled)
        );
        assert_eq!(
            store.send_command(source, replacement, release),
            Ok(Transmission::Pending)
        );
        let next = offered(&mut store, source);
        assert_eq!(next.revision, replacement.revision);
        assert_eq!(next.value, release.value);
        store
            .report_command(old, endpoint_pid(), 1, NativeCommandStatus::Accepted)
            .unwrap();
        assert_eq!(store.intent(source), crate::native_api::Read::Value(false));
        assert_eq!(store.admission(source).unwrap().lease, replacement);
        assert_eq!(store.command_queue.jobs[source].identity, next);
    }

    fn offered(store: &mut Store, source: &str) -> NativeCommandIdentity {
        match store.poll_command(source, endpoint_pid(), 1).unwrap() {
            Outcome::NativeCommand {
                command: Some(envelope),
                ..
            } => {
                assert_eq!(envelope.phase, NativeCommandPhase::Offered);
                envelope.identity
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    fn claim(store: &mut Store, identity: &NativeCommandIdentity) {
        match store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Claim,
            )
            .unwrap()
        {
            Outcome::NativeCommand {
                command: Some(envelope),
                ..
            } => assert_eq!(envelope.phase, NativeCommandPhase::Execute),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn only_a_claimed_exact_command_can_report_transport_acceptance() {
        let (_root, mut store, source, lease, command) = fixture();
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Pending)
        );
        let identity = offered(&mut store, source);
        assert!(store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted
            )
            .is_err());
        claim(&mut store, &identity);
        assert!(store
            .report_command(
                identity.clone(),
                endpoint_pid() + 1,
                1,
                NativeCommandStatus::Accepted
            )
            .is_err());
        let mut changed = identity.clone();
        changed.value += 1;
        assert!(store
            .report_command(changed, endpoint_pid(), 1, NativeCommandStatus::Accepted)
            .is_err());
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Accepted)
        );
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        assert!(store
            .report_command(identity, endpoint_pid(), 1, NativeCommandStatus::Unknown)
            .is_err());
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Pending)
        );
    }

    #[test]
    fn waiting_for_feedback_keeps_the_unconsumed_terminal_receipt() {
        let (_root, mut store, source, lease, command) = fixture();
        store.send_command(source, lease, command).unwrap();
        let identity = offered(&mut store, source);
        claim(&mut store, &identity);
        store
            .report_command(identity, endpoint_pid(), 1, NativeCommandStatus::Accepted)
            .unwrap();
        store.withdraw_command(source, lease, false);
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Accepted)
        );
    }

    #[test]
    fn applied_policy_retires_old_acceptance_without_breaking_lost_ack_recovery() {
        let (_root, mut store, source, lease, command) = fixture();
        store.send_command(source, lease, command).unwrap();
        let old = offered(&mut store, source);
        claim(&mut store, &old);
        store
            .report_command(
                old.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Accepted,
            )
            .unwrap();
        store.withdraw_command(source, lease, true);
        assert_eq!(
            store.send_command(source, lease, command),
            Ok(Transmission::Pending)
        );
        assert_ne!(offered(&mut store, source).command_id, old.command_id);
        assert!(matches!(
            store
                .report_command(old, endpoint_pid(), 1, NativeCommandStatus::Accepted)
                .unwrap(),
            Outcome::NativeCommandReported {
                result: NativeCommandStatus::Accepted,
                ..
            }
        ));
    }

    #[test]
    fn an_explicit_new_choice_waits_for_the_old_execution_terminal() {
        let (_root, mut store, source, lease, command) = fixture();
        store.send_command(source, lease, command).unwrap();
        let old = offered(&mut store, source);
        claim(&mut store, &old);
        let previous = store.config().unwrap().unwrap();
        let mut next: serde_json::Value = serde_json::from_slice(&previous).unwrap();
        next["agents"][source]["options"]["intent"] = "off".into();
        store
            .command(super::super::Command::ReplaceConfig {
                expected: Some(String::from_utf8(previous).unwrap()),
                next: next.to_string(),
            })
            .unwrap();
        let replacement = store.admission(source).unwrap().lease;
        assert_ne!(replacement, lease);
        assert_eq!(
            store.send_command(source, replacement, command),
            Ok(Transmission::Waiting(Wait::Reply))
        );
        store
            .report_command(old, endpoint_pid(), 1, NativeCommandStatus::Unknown)
            .unwrap();
        assert_eq!(
            store.send_command(source, replacement, command),
            Ok(Transmission::Pending)
        );
        assert_eq!(offered(&mut store, source).revision, replacement.revision);
    }

    #[test]
    fn unknown_execution_never_replays_on_the_same_active_operation() {
        let (_root, mut store, source, lease, command) = fixture();
        store.send_command(source, lease, command).unwrap();
        let identity = offered(&mut store, source);
        claim(&mut store, &identity);
        store
            .report_command(
                identity.clone(),
                endpoint_pid(),
                1,
                NativeCommandStatus::Unknown,
            )
            .unwrap();
        for _ in 0..3 {
            assert_eq!(
                store.send_command(source, lease, command),
                Err(Failure::TransportUnavailable)
            );
        }
        assert_eq!(store.command_queue.jobs[source].identity, identity);
    }
}
