//! Volatile PW authority belongs to the daemon, independent of Java status and ACKs.
use super::Store;
use crate::native::Host;
use crate::native_api::Read;
use ed25519_dalek::SigningKey;
use std::io;
use voboost_contract::cluster_pw_live::{
    Actual, Challenge, Proof, CHALLENGE_MILLIS, MAX_SOURCE_AGE_MS,
};
use voboost_shared::cluster_mailbox::{Provision, State};

const SOURCE: &str = "vehicle-drive-pedestrian-warning";

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[derive(Default)]
pub(super) struct Live {
    sample: Option<(u64, i32)>,
    ticket: Option<Ticket>,
    drain_requested: bool,
    source_epoch: Option<u64>,
}
struct Ticket {
    challenge: Challenge,
    received_ms: u64,
    revision: u64,
    consumed: bool,
}
impl Ticket {
    fn observation(
        &mut self,
        revision: u64,
        now: u64,
        sample: Option<(u64, i32)>,
        draining: bool,
    ) -> io::Result<Option<(u64, Actual, u64)>> {
        if self.consumed
            || self.revision != revision
            || now
                .checked_sub(self.received_ms)
                .is_none_or(|age| age >= CHALLENGE_MILLIS)
        {
            self.consumed = true;
            return Err(invalid("PW challenge expired or consumed"));
        }
        if draining {
            return Ok(None);
        }
        let Some((observed, value)) = sample else {
            return Ok(None);
        };
        let Some(age) = now
            .checked_sub(observed)
            .filter(|age| *age <= MAX_SOURCE_AGE_MS)
        else {
            return Ok(None);
        };
        if observed <= self.received_ms {
            return Ok(None);
        }
        Ok(Some((
            observed,
            match value {
                1 => Actual::Disabled,
                2 => Actual::Enabled,
                _ => Actual::Unknown,
            },
            age,
        )))
    }
}

fn armed(
    intent: Read<bool>,
    state: Read<bool>,
    disarm: Read<bool>,
    clean_stop: Read<bool>,
) -> bool {
    matches!(intent, Read::Value(true) | Read::Missing)
        && state == Read::Value(true)
        && matches!(disarm, Read::Missing | Read::Value(false))
        && matches!(clean_stop, Read::Missing | Read::Value(false))
}

impl Store {
    pub(crate) fn observe_pw(&mut self, source_epoch: Option<u64>, sample: Option<(u64, i32)>) {
        if self.pw_live.source_epoch != source_epoch {
            if let Some(ticket) = self.pw_live.ticket.as_mut() {
                ticket.consumed = true;
            }
        }
        self.pw_live.source_epoch = source_epoch;
        self.pw_live.sample = sample;
    }

    pub(crate) fn take_pw_drain(&mut self) -> bool {
        std::mem::take(&mut self.pw_live.drain_requested)
    }

    pub(super) fn pw_proof(&mut self, challenge: Challenge) -> io::Result<Option<Vec<u8>>> {
        challenge.validate().map_err(invalid)?;
        self.refresh_native()?;
        let now = crate::startup::boot_ms()?;
        let revision = self
            .admission(SOURCE)
            .ok_or_else(|| invalid("PW owner unavailable"))?
            .lease
            .revision;
        if self.pw_live.source_epoch.is_none() {
            return Err(invalid("PW source epoch unavailable"));
        }
        // OFF and a pending release revoke signing immediately, before readback changes.
        if !armed(
            self.intent(SOURCE),
            self.read_state(SOURCE, "pedestrian-warning-armed"),
            self.read_state(SOURCE, "pedestrian-warning-disarm-pending"),
            self.read_state(SOURCE, "pedestrian-warning-clean-stop-pending-reconcile"),
        ) {
            self.pw_live.ticket = None;
            return Err(invalid("PW policy not armed"));
        }
        let directory = crate::secure_fs::Directory::open(&self.root)?.open_child("cluster")?;
        let state: State = serde_json::from_slice(&directory.read_trusted(
            "mailbox.json",
            voboost_contract::runtime_owner::MAX_CLUSTER_MAILBOX_BYTES,
            0o600,
        )?)
        .map_err(invalid)?;
        state.validate().map_err(invalid)?;
        let provision: Provision =
            serde_json::from_slice(&directory.read_trusted("provision.json", 65536, 0o600)?)
                .map_err(invalid)?;
        provision.validate().map_err(invalid)?;
        let selected = state
            .agents
            .iter()
            .find(|agent| agent.id == SOURCE)
            .ok_or_else(|| invalid("PW visual target absent"))?;
        let configured_intent = self.option(SOURCE, "intent");
        let saved = match self.read_state(SOURCE, "pedestrian-warning-armed") {
            Read::Value(value) => Some(value),
            Read::Missing => None,
            Read::Unavailable => return Err(invalid("PW saved choice unavailable")),
        };
        let current_intent = configured_intent
            .as_deref()
            .map(|intent| voboost_contract::cluster_pw_live::effective_intent(intent, saved));
        if self.native_boot.as_deref() != Some(state.android_boot_id.as_str())
            || self.cluster_epoch != state.android_daemon_epoch
            || !selected.enabled
            || !challenge.desired_disabled
            || selected.options.get("intent").map(String::as_str) != current_intent
            || challenge.pair_id != provision.pair_id
            || challenge.desired_revision != state.desired_revision
            || challenge.desired_sha256 != state.desired_sha256
            || state
                .generation
                .as_ref()
                .map(|receipt| &receipt.generation_id)
                != Some(&challenge.generation_id)
        {
            self.pw_live.ticket = None;
            return Err(invalid("PW current authority differs"));
        }
        if self.pw_live.ticket.is_none() {
            self.pw_live.ticket = Some(Ticket {
                challenge: challenge.clone(),
                received_ms: now,
                revision,
                consumed: false,
            });
            self.pw_live.sample = None;
            self.pw_live.drain_requested = true;
        }
        let ticket = self.pw_live.ticket.as_mut().unwrap();
        if ticket.challenge != challenge {
            if now
                .checked_sub(ticket.received_ms)
                .is_some_and(|age| age < CHALLENGE_MILLIS)
                && !ticket.consumed
            {
                return Err(invalid("PW challenge already pending"));
            }
            *ticket = Ticket {
                challenge: challenge.clone(),
                received_ms: now,
                revision,
                consumed: false,
            };
            self.pw_live.sample = None;
            self.pw_live.drain_requested = true;
        }
        let Some((observed_ms, actual, age)) = ticket.observation(
            revision,
            now,
            self.pw_live.sample,
            self.pw_live.drain_requested,
        )?
        else {
            return Ok(None);
        };
        let seed: [u8; 32] = directory
            .read_trusted("device-signing.seed", 32, 0o600)?
            .try_into()
            .map_err(|_| invalid("PW signing seed size"))?;
        let key = SigningKey::from_bytes(&seed);
        if hex::encode(key.verifying_key().to_bytes()) != provision.android_public_key {
            return Err(invalid("PW signing identity differs"));
        }
        let endpoint = u64::from_str_radix(&self.session[..13], 16)
            .map_err(invalid)?
            .max(1);
        let proof = Proof {
            challenge,
            endpoint_identity: endpoint,
            document_generation: revision,
            lifecycle_generation: revision,
            observation_sequence: observed_ms,
            source_age_ms: age,
            desired_disabled: true,
            actual,
        };
        let signed = proof.sign(&key).map_err(invalid)?;
        ticket.consumed = true;
        Ok(Some(signed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pw_power_source_epoch_loss_or_change_revokes_pending_ticket() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::Builder::new()
            .prefix(".pw-owner-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut owner = Store::new(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        owner.pw_live.source_epoch = Some(1);
        owner.pw_live.ticket = Some(ticket());
        owner.observe_pw(Some(1), Some((1001, 1)));
        assert!(!owner.pw_live.ticket.as_ref().unwrap().consumed);
        owner.observe_pw(None, None);
        assert!(owner.pw_live.ticket.as_ref().unwrap().consumed);
        owner.pw_live.source_epoch = Some(1);
        owner.pw_live.ticket = Some(ticket());
        owner.observe_pw(Some(2), Some((1002, 1)));
        assert!(owner.pw_live.ticket.as_ref().unwrap().consumed);
    }
    fn ticket() -> Ticket {
        Ticket {
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
            received_ms: 1000,
            revision: 7,
            consumed: false,
        }
    }
    #[test]
    fn pw_owner_requires_post_barrier_independent_state_and_bounded_ticket() {
        let mut t = ticket();
        assert!(t.observation(7, 1001, None, false).unwrap().is_none());
        assert!(t
            .observation(7, 1001, Some((999, 1)), false)
            .unwrap()
            .is_none());
        assert!(t
            .observation(7, 1001, Some((1001, 1)), true)
            .unwrap()
            .is_none());
        assert_eq!(
            t.observation(7, 1002, Some((1001, 1)), false).unwrap(),
            Some((1001, Actual::Disabled, 1))
        );
        assert_eq!(
            t.observation(7, 1002, Some((1001, 2)), false).unwrap(),
            Some((1001, Actual::Enabled, 1))
        );
        for (revision, now) in [(8, 1002), (7, 999), (7, 3000)] {
            let mut t = ticket();
            assert!(t
                .observation(revision, now, Some((1001, 1)), false)
                .is_err());
            assert!(t.consumed);
        }
        let mut t = ticket();
        t.consumed = true;
        assert!(t.observation(7, 1002, Some((1001, 1)), false).is_err());
    }
    #[test]
    fn pw_enabled_is_not_intent_and_off_or_release_revokes_before_actual_changes() {
        assert!(armed(
            Read::Missing,
            Read::Value(true),
            Read::Missing,
            Read::Missing
        ));
        assert!(!armed(
            Read::Value(false),
            Read::Value(true),
            Read::Missing,
            Read::Missing
        ));
        assert!(!armed(
            Read::Unavailable,
            Read::Value(true),
            Read::Missing,
            Read::Missing
        ));
        assert!(!armed(
            Read::Value(true),
            Read::Value(false),
            Read::Missing,
            Read::Missing
        ));
        assert!(!armed(
            Read::Value(true),
            Read::Value(true),
            Read::Value(true),
            Read::Missing
        ));
        assert!(!armed(
            Read::Value(true),
            Read::Value(true),
            Read::Missing,
            Read::Value(true)
        ));
    }
}
