//! Native controllers borrow persistence from the sole state owner.
use super::{invalid, state, ReadOutcome, Store};
use crate::native::{Admission, Host};
use crate::native_api::{Failure, Lease, Read};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Upper bound on pending UI cleanup acknowledgement; never an automation lease.
pub(super) const WITHDRAWAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(15);

pub(super) struct Slot {
    admission: Admission,
    desired_revision: u64,
    config: serde_json::Value,
    captures: Vec<Option<Vec<u8>>>,
}

impl Store {
    /// Track teardown independently of the already revoked automation authority.
    pub(super) fn begin_withdrawal(&mut self, source: &str) {
        self.revoke_source(source);
        self.cancel_source_commands(source);
        self.withdrawing.insert(
            source.to_string(),
            std::time::Instant::now() + WITHDRAWAL_DEADLINE,
        );
    }

    /// Every target applied removal; the durable OFF was authoritative earlier.
    pub(super) fn confirm_withdrawn(&mut self, source: &str) {
        if self.withdrawing.remove(source).is_none() {
            return;
        }
        self.revoke_source(source);
        self.cancel_source_commands(source);
        let _ = self.refresh_native();
    }

    /// Retire cleanup records when a producer dies before confirming removal.
    pub(crate) fn expire_withdrawals(&mut self) {
        let now = std::time::Instant::now();
        if !self.withdrawing.values().any(|deadline| *deadline <= now) {
            return;
        }
        let expired: Vec<String> = self
            .withdrawing
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(source, _)| source.clone())
            .collect();
        for source in expired {
            self.withdrawing.remove(&source);
            self.revoke_source(&source);
            self.cancel_source_commands(&source);
        }
        let _ = self.refresh_native();
    }

    pub(super) fn revoke_source(&mut self, source: &str) {
        self.native_enabled.remove(source);
        if let Some(slot) = self.native_slots.get(source) {
            slot.admission.fence.store(0, Ordering::Release);
        }
    }

    pub(super) fn revoke_native(&mut self) {
        for slot in self.native_slots.values() {
            slot.admission.fence.store(0, Ordering::Release);
        }

        self.native_enabled.clear();
    }

    pub(super) fn prune_native(&mut self) {
        self.native_slots.retain(|source, slot| {
            let keep = self.native_configured.contains(source);
            if !keep {
                slot.admission.fence.store(0, Ordering::Release);
            }
            keep
        });
    }

    pub(super) fn grant_native(&mut self, config: &serde_json::Value) -> io::Result<()> {
        for codec in crate::native::CODECS {
            if !self.native_enabled.contains(codec.id) {
                continue;
            }
            let next = &config["agents"][codec.id];
            let prefix = format!("agents/{}/", codec.id);
            let desired_revision = config["fieldRevisions"]
                .as_object()
                .into_iter()
                .flat_map(|stamps| stamps.iter())
                .filter(|(path, _)| path.starts_with(&prefix))
                .filter_map(|(_, stamp)| stamp["revision"].as_u64())
                .max()
                .unwrap_or(0);
            let captures: Vec<_> = codec
                .pending_journals
                .iter()
                .map(|key| {
                    let field = voboost_contract::desired::Field::Option {
                        agent: codec.id.into(),
                        key: (*key).into(),
                    };
                    if config["fieldRevisions"].get(field.path()).is_some() {
                        Ok(None)
                    } else {
                        self.journal(codec.id, key)
                    }
                })
                .collect::<io::Result<_>>()?;
            if let Some(slot) = self.native_slots.get_mut(codec.id) {
                let same_choice = slot.config["options"].get("intent")
                    == next["options"].get("intent")
                    && slot.captures == captures
                    && slot.desired_revision == desired_revision;
                if same_choice {
                    if slot.config != *next || !slot.admission.current() {
                        slot.admission.fence.store(0, Ordering::Release);
                        slot.admission.fence =
                            Arc::new(AtomicU64::new(slot.admission.lease.revision));
                        slot.config = next.clone();
                    }
                    continue;
                }
            }
            if let Some(old) = self.native_slots.remove(codec.id) {
                old.admission.fence.store(0, Ordering::Release);
            }
            self.native_revision = self
                .native_revision
                .checked_add(1)
                .ok_or_else(|| invalid("native revision exhausted"))?;
            self.native_slots.insert(
                codec.id.into(),
                Slot {
                    admission: Admission {
                        lease: Lease {
                            revision: self.native_revision,
                        },
                        fence: Arc::new(AtomicU64::new(self.native_revision)),
                    },
                    config: next.clone(),
                    desired_revision,
                    captures,
                },
            );
        }
        Ok(())
    }
}

impl Host for Store {
    fn send_command(
        &mut self,
        source: &str,
        lease: Lease,
        command: crate::native_api::Command,
    ) -> Result<crate::native_api::Transmission, Failure> {
        Store::send_command(self, source, lease, command)
    }

    fn withdraw_command(&mut self, source: &str, lease: Lease, completed: bool) {
        Store::withdraw_command(self, source, lease, completed);
    }

    fn action_identity(
        &self,
        source: &str,
    ) -> Option<voboost_contract::runtime_owner::NativeCommandIdentity> {
        Store::action_identity(self, source)
    }
    fn action_terminal(
        &mut self,
        identity: &voboost_contract::runtime_owner::NativeCommandIdentity,
    ) -> Option<voboost_contract::runtime_owner::NativeCommandStatus> {
        Store::action_terminal(self, identity)
    }
    fn vehicle_observation(
        &self,
        source: &str,
    ) -> Option<voboost_contract::runtime_owner::NativeVehicleObservation> {
        Store::vehicle_observation(self, source)
    }
    fn command_transport_ready(&self, source: &str) -> bool {
        self.native_command_ready(source)
    }

    fn enabled(&self, source: &str) -> bool {
        self.native_configured.contains(source)
    }

    fn action_allowed(&self, source: &str) -> bool {
        self.native_configured.contains(source) && !self.withdrawing.contains_key(source)
    }

    fn admission(&self, source: &str) -> Option<Admission> {
        self.native_slots
            .get(source)
            .filter(|slot| slot.admission.current())
            .map(|slot| slot.admission.clone())
    }

    fn intent(&self, source: &str) -> Read<bool> {
        let Some(slot) = self
            .native_slots
            .get(source)
            .filter(|slot| slot.admission.current())
        else {
            return Read::Unavailable;
        };
        let Some(value) = slot.config["options"].get("intent") else {
            return Read::Missing;
        };
        match value.as_str() {
            Some("on") => Read::Value(true),
            Some("off") => Read::Value(false),
            Some("observe") => Read::Missing,
            _ => Read::Unavailable,
        }
    }

    fn option(&self, source: &str, key: &str) -> Option<String> {
        self.native_slots.get(source)?.config["options"][key]
            .as_str()
            .map(str::to_owned)
    }

    fn read_state(&self, source: &str, key: &str) -> Read<bool> {
        if !crate::native::CODECS.iter().any(|codec| codec.id == source) {
            return Read::Unavailable;
        }
        match state::read(&self.root.join("state"), source, key) {
            ReadOutcome::Value(serde_json::Value::Bool(value)) => Read::Value(value),
            ReadOutcome::Missing => Read::Missing,
            _ => Read::Unavailable,
        }
    }

    fn diagnostic_stale_read(&self, source: &str, _lease: Lease, _key: &str) {
        if let Some(session) = self.outage.borrow_mut().as_mut() {
            session.stale_operation(source);
        }
    }
    fn diagnostic_stale_write(&mut self, source: &str, _lease: Lease, _key: &str) {
        if let Some(session) = self.outage.borrow_mut().as_mut() {
            session.stale_operation(source);
        }
    }
    fn diagnostic_state_read(&self, source: &str, lease: Lease, key: &str) -> bool {
        self.outage
            .borrow_mut()
            .as_mut()
            .is_some_and(|session| session.read(source, lease.revision, key))
    }
    fn diagnostic_state_read_complete(
        &self,
        source: &str,
        lease: Lease,
        key: &str,
        result: &Read<bool>,
    ) {
        if let Some(session) = self.outage.borrow_mut().as_mut() {
            session.read_complete(source, lease.revision, key, result);
        }
    }
    fn diagnostic_state_write(&mut self, source: &str, lease: Lease, key: &str) -> bool {
        self.outage
            .borrow_mut()
            .as_mut()
            .is_some_and(|session| session.write(source, lease.revision, key))
    }
    fn diagnostic_stopped_write(&mut self, source: &str, key: &str) {
        if let Some(session) = self.outage.borrow_mut().as_mut() {
            session.stopped_write(source, key);
        }
    }
    fn diagnostic_progress(
        &mut self,
        source: &str,
        lease: Lease,
        result: Result<crate::native_api::Progress, Failure>,
    ) {
        if let Some(session) = self.outage.borrow_mut().as_mut() {
            session.progress(source, lease.revision, result);
        }
    }
    fn diagnostic_stopped(&mut self, source: &str) {
        if let Some(session) = self.outage.borrow_mut().as_mut() {
            session.stopped(source);
        }
    }

    fn read_controller_state(&self, source: &str, key: &str) -> Read<bool> {
        if !crate::native::CODECS.iter().any(|codec| codec.id == source) {
            return Read::Unavailable;
        }
        match state::read_controller(&self.root.join("state"), source, key) {
            ReadOutcome::Value(serde_json::Value::Bool(value)) => Read::Value(value),
            ReadOutcome::Missing => Read::Missing,
            _ => Read::Unavailable,
        }
    }

    fn write_stopped_state(&mut self, source: &str, key: &str, value: bool) -> Result<(), Failure> {
        if self.enabled(source)
            || self.admission(source).is_some()
            || !crate::native::CODECS.iter().any(|codec| codec.id == source)
        {
            return Err(Failure::Cancelled);
        }
        let key = state::storage_key(source, key).ok_or(Failure::InvalidValue)?;
        state::write(
            &self.root.join("state"),
            &key,
            &state::render_value(&serde_json::Value::Bool(value)),
        )
        .map_err(|_| Failure::StateUnavailable)
    }

    fn write_state(
        &mut self,
        source: &str,
        lease: Lease,
        key: &str,
        value: bool,
    ) -> Result<(), Failure> {
        if !self
            .admission(source)
            .is_some_and(|admission| admission.lease == lease)
        {
            return Err(Failure::Cancelled);
        }
        let key = state::storage_key(source, key).ok_or(Failure::InvalidValue)?;
        state::write(
            &self.root.join("state"),
            &key,
            &state::render_value(&serde_json::Value::Bool(value)),
        )
        .map_err(|_| Failure::StateUnavailable)
    }

    fn write_controller_state(
        &mut self,
        source: &str,
        lease: Lease,
        key: &str,
        value: bool,
    ) -> Result<(), Failure> {
        if !self
            .admission(source)
            .is_some_and(|admission| admission.lease == lease)
        {
            return Err(Failure::Cancelled);
        }
        let key = state::storage_key(source, key).ok_or(Failure::InvalidValue)?;
        state::write_controller(
            &self.root.join("state"),
            &key,
            &state::render_value(&serde_json::Value::Bool(value)),
        )
        .map_err(|_| Failure::StateUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fixture() -> (tempfile::TempDir, Store, &'static str) {
        let root = tempfile::Builder::new()
            .prefix(".native-owner-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let source = crate::native::CODECS
            .first()
            .expect("native owner tests require generated registry")
            .id;
        let config = serde_json::json!({"schemaVersion":2,"startup":"interface","userRevision":0,"fieldRevisions":{},"agents":{
            (source):{"enabled":true,"options":{"intent":"observe"}}
        }});
        super::super::Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", config.to_string().as_bytes(), 0o600)
            .unwrap();
        let mut store = Store::new(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        store
            .initialize_native("11111111-1111-4111-8111-111111111111")
            .unwrap();
        (root, store, source)
    }

    #[test]
    fn disabled_cleanup_can_commit_state_without_acquiring_transmission_authority() {
        let (_root, mut store, source) = fixture();
        assert_eq!(
            store.write_stopped_state(source, "lifecycle", false),
            Err(Failure::Cancelled)
        );
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
        assert!(store.admission(source).is_none());
        store
            .write_stopped_state(source, "lifecycle", false)
            .unwrap();
        assert_eq!(store.read_state(source, "lifecycle"), Read::Value(false));
        assert!(store.admission(source).is_none());
        assert_eq!(
            store.write_stopped_state("unregistered", "lifecycle", false),
            Err(Failure::Cancelled)
        );
    }

    #[test]
    fn controller_state_commits_keep_the_current_intent_lease() {
        let (_root, mut store, source) = fixture();
        let admitted = store.admission(source).unwrap();
        assert_eq!(store.intent(source), Read::Missing);
        store
            .write_state(source, admitted.lease, "armed", true)
            .unwrap();
        assert_eq!(store.read_state(source, "armed"), Read::Value(true));
        assert!(admitted.current());
        store.refresh_native().unwrap();
        assert_eq!(store.admission(source).unwrap().lease, admitted.lease);
        assert!(admitted.current());
        assert_eq!(
            store.write_state(
                source,
                Lease {
                    revision: admitted.lease.revision + 1
                },
                "armed",
                false
            ),
            Err(Failure::Cancelled)
        );
        assert_eq!(store.read_state(source, "armed"), Read::Value(true));
    }

    #[test]
    fn unrelated_configuration_cancels_queued_io_without_creating_a_new_user_choice() {
        let (_root, mut store, source) = fixture();
        let original = store.admission(source).unwrap();
        for same_source in [false, true] {
            let previous = store.config().unwrap().unwrap();
            let mut next: serde_json::Value = serde_json::from_slice(&previous).unwrap();
            if same_source {
                next["agents"][source]["options"]["hide-indicator"] = true.into();
            } else {
                next["agents"]["unrelated"] = serde_json::json!({"enabled":true,"options":{}});
            }
            assert!(matches!(
                store
                    .command(super::super::Command::ReplaceConfig {
                        expected: Some(String::from_utf8(previous).unwrap()),
                        next: next.to_string(),
                    })
                    .unwrap(),
                super::super::Outcome::Written {}
            ));
            assert_eq!(store.admission(source).unwrap().lease, original.lease);
            assert!(store.admission(source).unwrap().current());
        }
        assert!(!original.current());
        let previous = store.config().unwrap().unwrap();
        let mut next: serde_json::Value = serde_json::from_slice(&previous).unwrap();
        next["agents"][source]["options"]["intent"] = "off".into();
        store
            .command(super::super::Command::ReplaceConfig {
                expected: Some(String::from_utf8(previous).unwrap()),
                next: next.to_string(),
            })
            .unwrap();
        assert_ne!(store.admission(source).unwrap().lease, original.lease);
        assert_eq!(store.intent(source), Read::Value(false));
    }

    #[test]
    fn pending_choice_revokes_the_worker_token_without_disabling_the_agent() {
        let (_root, mut store, source) = fixture();
        let admitted = store.admission(source).unwrap();
        store.revoke_source(source);
        assert!(!admitted.current());
        assert!(store.enabled(source));
        assert!(store.admission(source).is_none());
        assert_eq!(store.intent(source), Read::Unavailable);
        assert_eq!(
            store.write_state(source, admitted.lease, "armed", true),
            Err(Failure::Cancelled)
        );
    }

    #[test]
    fn malformed_present_intent_is_never_first_observation_permission() {
        let (_root, mut store, source) = fixture();
        for value in [
            serde_json::json!(false),
            serde_json::Value::Null,
            serde_json::json!(4),
            serde_json::json!({"choice":"off"}),
        ] {
            store.native_slots.get_mut(source).unwrap().config["options"]["intent"] = value;
            assert_eq!(store.intent(source), Read::Unavailable);
        }
        store.native_slots.get_mut(source).unwrap().config["options"] = serde_json::json!({});
        assert_eq!(store.intent(source), Read::Missing);
    }

    #[test]
    fn configuration_read_failure_revokes_every_previously_issued_token() {
        let (root, mut store, source) = fixture();
        let admitted = store.admission(source).unwrap();
        super::super::Directory::open(root.path())
            .unwrap()
            .write_atomic("agents.json", b"invalid", 0o600)
            .unwrap();
        assert!(store.refresh_native().is_err());
        assert!(!admitted.current());
        assert!(store.enabled(source));
        assert!(store.admission(source).is_none());
    }
}
