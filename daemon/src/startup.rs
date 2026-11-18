//! Retained first startup receipts. The owner supplies attested identities and its own clock.
use serde::{Deserialize, Serialize};

fn decimal<T: std::fmt::Display, S: serde::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}
fn optional_decimal<S: serde::Serializer>(
    value: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

fn parse_decimal<'de, T: std::str::FromStr + std::fmt::Display, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    let text = String::deserialize(deserializer)?;
    let value: T = text
        .parse()
        .map_err(|_| serde::de::Error::custom("invalid decimal"))?;
    if value.to_string() != text {
        return Err(serde::de::Error::custom("noncanonical decimal"));
    }
    Ok(value)
}
fn parse_optional_decimal<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    text.map(|text| {
        let value: u64 = text
            .parse()
            .map_err(|_| serde::de::Error::custom("invalid decimal"))?;
        if value.to_string() != text {
            return Err(serde::de::Error::custom("noncanonical decimal"));
        }
        Ok(value)
    })
    .transpose()
}

pub(crate) const MAX_BYTES: usize = 64 * 1024;
const MAX_TARGETS: usize = 64 * 64;
const MAX_MEMBERS: usize = 64 * 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Identity {
    pub boot_id: String,
    pub daemon_pid: i32,
    #[serde(serialize_with = "decimal", deserialize_with = "parse_decimal")]
    pub daemon_starttime: u64,
    pub manifest_sha256: String,
    pub generation_id: String,
    pub catalog_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Target {
    pub process: String,
    pub pid: i32,
    #[serde(serialize_with = "decimal", deserialize_with = "parse_decimal")]
    pub starttime: u64,
    pub ready_ms: u64,
    pub batch: u64,
    pub priority: u8,
    pub dispatch_ms: Option<u64>,
    pub dispatch_rank: Option<u32>,
    #[serde(
        serialize_with = "optional_decimal",
        deserialize_with = "parse_optional_decimal"
    )]
    pub endpoint_epoch: Option<u64>,
    pub adopted_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Semantic {
    pub name: String,
    pub desired: bool,
    pub actual: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Outcome {
    MatchedNoop,
    WriteVerified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Application {
    pub outcome: Outcome,
    pub contract: String,
    pub intent: String,
    pub semantics: Vec<Semantic>,
    pub android_observed_at_boot_ms: u64,
    pub received_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AgentApplication {
    authority: String,
    document_generation: String,
    lifecycle_generation: String,
    clock_domain: String,
    contract: String,
    intent: String,
    semantics: Vec<Semantic>,
    outcome: Outcome,
    observed_at_boot_ms: u64,
}

pub(crate) fn parse_application(
    details: &serde_json::Value,
    document: i64,
    lifecycle: i64,
    received_ms: u64,
) -> Option<Application> {
    let receipt: AgentApplication =
        serde_json::from_value(details.get("startupApplication")?.clone()).ok()?;
    if receipt.authority != "backend"
        || receipt.clock_domain != "android.elapsedRealtime"
        || receipt.document_generation != document.to_string()
        || receipt.lifecycle_generation != lifecycle.to_string()
        || receipt.observed_at_boot_ms > 9_007_199_254_740_991
        || received_ms > 9_007_199_254_740_991
    {
        return None;
    }
    let application = Application {
        contract: receipt.contract,
        intent: receipt.intent,
        semantics: receipt.semantics,
        outcome: receipt.outcome,
        android_observed_at_boot_ms: receipt.observed_at_boot_ms,
        received_ms,
    };
    if application.contract.is_empty()
        || application.contract.len() > 96
        || application.intent.is_empty()
        || application.intent.len() > 64
        || application.semantics.is_empty()
        || application.semantics.len() > 16
        || application
            .semantics
            .iter()
            .any(|s| s.name.is_empty() || s.name.len() > 96 || s.desired != s.actual)
        || application.semantics.iter().enumerate().any(|(i, s)| {
            application.semantics[..i]
                .iter()
                .any(|other| other.name == s.name)
        })
    {
        return None;
    }
    Some(application)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Member {
    pub id: String,
    pub target: usize,
    #[serde(serialize_with = "decimal", deserialize_with = "parse_decimal")]
    pub document_generation: i64,
    #[serde(serialize_with = "decimal", deserialize_with = "parse_decimal")]
    pub lifecycle_generation: i64,
    pub application: Option<Application>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClockAnchor {
    pub clock_domain: String,
    pub observed_at_boot_ms: u64,
    pub owner_before_ms: u64,
    pub owner_after_ms: u64,
    pub precision_ms: u32,
}

impl ClockAnchor {
    #[cfg(any(target_os = "linux", target_os = "android", test))]
    pub(crate) fn from_sample(observed: Option<u64>, before: u64, after: u64) -> Option<Self> {
        let observed = observed?;
        if observed % 10 != 0
            || before > after
            || observed > 9_007_199_254_740_991
            || after > 9_007_199_254_740_991
        {
            return None;
        }
        Some(Self {
            clock_domain: "linux.bootElapsedRealtime".to_string(),
            observed_at_boot_ms: observed,
            owner_before_ms: before,
            owner_after_ms: after,
            precision_ms: 10,
        })
    }

    pub(crate) fn sample_owner_start(started: std::time::Instant) -> Option<Self> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let before = started.elapsed().as_millis() as u64;
            let boot = crate::agent_state::boot_elapsed_ms();
            let after = started.elapsed().as_millis() as u64;
            Self::from_sample(boot, before, after)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = started;
            None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Milestones {
    #[serde(skip)]
    pub batch_counter: u64,
    #[serde(skip)]
    pub rank_counter: u32,
    pub clock_domain: String,
    pub identity: Identity,
    pub clock_anchor: Option<ClockAnchor>,
    pub complete: bool,
    pub reason: Option<String>,
    pub expected_target_count: usize,
    pub expected_member_count: usize,
    pub targets: Vec<Target>,
    pub members: Vec<Member>,
}

impl Milestones {
    pub(crate) fn new(
        identity: Identity,
        expected_target_count: usize,
        expected_member_count: usize,
    ) -> Self {
        Self {
            batch_counter: 0,
            rank_counter: 0,
            clock_domain: "daemon.monotonicSinceOwnerStart".into(),
            identity,
            clock_anchor: None,
            complete: true,
            reason: None,
            expected_target_count,
            expected_member_count,
            targets: Vec::new(),
            members: Vec::new(),
        }
    }

    pub(crate) fn begin_batch(&mut self) {
        self.batch_counter = self.batch_counter.saturating_add(1);
        self.rank_counter = 0;
    }
    pub(crate) fn target_index(&self, process: &str) -> Option<usize> {
        self.targets.iter().position(|t| t.process == process)
    }
    pub(crate) fn next_rank(&mut self) -> u32 {
        let rank = self.rank_counter;
        self.rank_counter = self.rank_counter.saturating_add(1);
        rank
    }

    /// A new admission replaces the old process identity and its dependent receipts.
    pub(crate) fn ready(&mut self, target: Target) -> Option<usize> {
        if !self.complete
            || target.pid < 2
            || target.starttime == 0
            || target.process.is_empty()
            || target.process.len() > 255
            || target.dispatch_ms.is_some()
            || target.endpoint_epoch.is_some()
            || target.adopted_ms.is_some()
            || target.dispatch_rank.is_some()
        {
            return None;
        }
        if let Some(index) = self
            .targets
            .iter()
            .position(|t| t.process == target.process)
        {
            if self.targets[index].pid == target.pid
                && self.targets[index].starttime == target.starttime
            {
                return Some(index);
            }
            self.targets[index] = target;
            self.members.retain(|m| m.target != index);
            return self.with_budget().then_some(index);
        }
        if self.targets.len() >= MAX_TARGETS {
            self.overflow();
            return None;
        }
        self.targets.push(target);
        let index = self.targets.len() - 1;
        self.with_budget().then_some(index)
    }

    /// Call only after successful spawn, passing the timestamp sampled BEFORE spawn.
    pub(crate) fn dispatched(&mut self, index: usize, before_spawn_ms: u64, rank: u32) -> bool {
        let Some(target) = self.targets.get_mut(index) else {
            return false;
        };
        if !self.complete || before_spawn_ms < target.ready_ms {
            return false;
        }
        if target.dispatch_ms.is_none() {
            target.dispatch_ms = Some(before_spawn_ms);
            target.dispatch_rank = Some(rank);
        }
        self.with_budget()
    }

    pub(crate) fn adopted(
        &mut self,
        index: usize,
        pid: i32,
        starttime: u64,
        epoch: u64,
        now_ms: u64,
    ) -> bool {
        let Some(target) = self.targets.get_mut(index) else {
            return false;
        };
        if !self.complete
            || target.pid != pid
            || target.starttime != starttime
            || epoch == 0
            || !target.dispatch_ms.is_some_and(|time| now_ms >= time)
        {
            return false;
        }
        if target.endpoint_epoch != Some(epoch) {
            target.endpoint_epoch = Some(epoch);
            target.adopted_ms = Some(now_ms);
            self.members.retain(|m| m.target != index);
        }
        self.with_budget()
    }

    pub(crate) fn admit_member(&mut self, mut member: Member) -> bool {
        if !self.complete
            || member.id.is_empty()
            || member.id.len() > 96
            || member.document_generation < 0
            || member.lifecycle_generation < 0
            || member.application.is_some()
            || self.targets.get(member.target).is_none()
        {
            return false;
        }
        if let Some(slot) = self
            .members
            .iter_mut()
            .find(|m| m.id == member.id && m.target == member.target)
        {
            if slot.document_generation == member.document_generation
                && slot.lifecycle_generation == member.lifecycle_generation
            {
                return true;
            }
            member.application = None;
            *slot = member;
        } else {
            if self.members.len() >= MAX_MEMBERS {
                self.overflow();
                return false;
            }
            self.members.push(member);
        }
        self.with_budget()
    }

    /// Receipt authority is checked by the endpoint/document owner before this call.
    pub(crate) fn confirm(
        &mut self,
        member: &Member,
        epoch: u64,
        application: Application,
    ) -> bool {
        let Some(target) = self.targets.get(member.target) else {
            return false;
        };
        if !self.complete
            || target.endpoint_epoch != Some(epoch)
            || !target
                .adopted_ms
                .is_some_and(|time| application.received_ms >= time)
            || application.contract.is_empty()
            || application.contract.len() > 96
            || application.intent.is_empty()
            || application.intent.len() > 64
            || application.semantics.is_empty()
            || application.semantics.len() > 16
            || application
                .semantics
                .iter()
                .any(|s| s.name.is_empty() || s.name.len() > 96 || s.actual != s.desired)
            || application.semantics.iter().enumerate().any(|(i, s)| {
                application.semantics[..i]
                    .iter()
                    .any(|other| other.name == s.name)
            })
        {
            return false;
        }
        let Some(slot) = self.members.iter_mut().find(|m| {
            m.id == member.id
                && m.target == member.target
                && m.document_generation == member.document_generation
                && m.lifecycle_generation == member.lifecycle_generation
        }) else {
            return false;
        };
        if slot.application.is_none() {
            slot.application = Some(application);
        }
        self.with_budget()
    }

    fn overflow(&mut self) {
        self.complete = false;
        self.reason = Some("budget-exceeded".into());
        self.targets.clear();
        self.members.clear();
    }

    fn with_budget(&mut self) -> bool {
        if serde_json::to_vec(self).map_or(true, |bytes| bytes.len() > MAX_BYTES) {
            self.overflow();
        }
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tracker() -> Milestones {
        Milestones::new(
            Identity {
                boot_id: "boot".into(),
                daemon_pid: 2,
                daemon_starttime: 1,
                manifest_sha256: "m".into(),
                generation_id: "g".into(),
                catalog_sha256: "c".into(),
            },
            4096,
            4096,
        )
    }
    fn target(process: &str, pid: i32) -> Target {
        Target {
            process: process.into(),
            pid,
            starttime: 1,
            ready_ms: 5,
            batch: 1,
            priority: 0,
            dispatch_ms: None,
            dispatch_rank: None,
            endpoint_epoch: None,
            adopted_ms: None,
        }
    }
    fn member() -> Member {
        Member {
            id: "vehicle-example".into(),
            target: 0,
            document_generation: 1,
            lifecycle_generation: 1,
            application: None,
        }
    }
    fn application() -> Application {
        Application {
            outcome: Outcome::WriteVerified,
            contract: "selected-contract".into(),
            intent: "user-desired-off".into(),
            semantics: vec![Semantic {
                name: "sound".into(),
                desired: false,
                actual: false,
            }],
            android_observed_at_boot_ms: 900,
            received_ms: 10,
        }
    }
    fn admitted() -> Milestones {
        let mut t = tracker();
        t.ready(target("process", 2));
        assert!(t.dispatched(0, 6, 0));
        assert!(t.adopted(0, 2, 1, 1, 8));
        assert!(t.admit_member(member()));
        t
    }
    #[test]
    fn successful_dispatch_retains_pre_spawn_sample() {
        let mut t = tracker();
        t.ready(target("process", 2));
        assert!(t.targets[0].dispatch_ms.is_none());
        assert!(!t.dispatched(0, 4, 0));
        assert!(t.dispatched(0, 6, 0));
        assert!(t.dispatched(0, 7, 1));
        assert_eq!(t.targets[0].dispatch_ms, Some(6));
        assert_eq!(t.targets[0].dispatch_rank, Some(0));
    }
    #[test]
    fn first_receipt_immutable_and_false_is_valid_desired_state() {
        let mut t = admitted();
        assert!(t.confirm(&member(), 1, application()));
        let mut later = application();
        later.received_ms = 20;
        assert!(t.confirm(&member(), 1, later));
        assert_eq!(t.members[0].application.as_ref().unwrap().received_ms, 10);
    }
    #[test]
    fn stale_endpoint_and_document_and_baseline_do_not_confirm() {
        let mut t = admitted();
        assert!(!t.confirm(&member(), 2, application()));
        let mut m = member();
        m.document_generation = 2;
        assert!(!t.confirm(&m, 1, application()));
        let mut a = application();
        a.semantics[0].actual = true;
        assert!(!t.confirm(&member(), 1, a));
        let mut a = application();
        a.received_ms = 7;
        assert!(!t.confirm(&member(), 1, a));
        assert!(t.members[0].application.is_none());
    }
    #[test]
    fn identity_changes_reset_dependent_evidence() {
        let mut t = admitted();
        t.confirm(&member(), 1, application());
        assert!(t.adopted(0, 2, 1, 2, 11));
        assert!(t.members.is_empty());
        t.admit_member(member());
        t.ready(target("process", 3));
        assert!(t.members.is_empty());
        assert!(t.targets[0].dispatch_ms.is_none());
    }
    #[test]
    fn document_lifecycle_change_resets_first_receipt() {
        let mut t = admitted();
        t.confirm(&member(), 1, application());
        let mut m = member();
        m.document_generation = 2;
        t.admit_member(m.clone());
        assert!(t.members[0].application.is_none());
        assert!(t.confirm(&m, 1, application()));
        m.lifecycle_generation = 2;
        t.admit_member(m);
        assert!(t.members[0].application.is_none());
    }
    #[test]
    fn already_matched_noop_is_explicit() {
        let mut t = admitted();
        let mut a = application();
        a.outcome = Outcome::MatchedNoop;
        assert!(t.confirm(&member(), 1, a));
    }
    #[test]
    fn hostile_max_catalog_cannot_exhaust_wire_budget() {
        let mut t = tracker();
        for i in 0..4096 {
            let name = format!("{:0255}", i);
            t.ready(target(&name, 2));
        }
        assert!(!t.complete);
        assert_eq!(t.reason.as_deref(), Some("budget-exceeded"));
        assert!(t.targets.is_empty());
        assert!(serde_json::to_vec(&t).unwrap().len() < MAX_BYTES);
        assert_eq!(t.expected_target_count, 4096);
        assert_eq!(t.expected_member_count, 4096);
    }
    #[test]
    fn current_catalog_conservative_52_targets_three_vehicle_members_fit() {
        let mut t = tracker();
        for i in 0..52 {
            let name = format!("{:0255}", i);
            let index = t.ready(target(&name, i + 2)).unwrap();
            assert!(t.dispatched(index, 6, i as u32));
            assert!(t.adopted(index, i + 2, 1, 1, 8));
        }
        for i in 0..3 {
            let mut m = member();
            m.id = format!("vehicle-{i}");
            m.target = i;
            assert!(t.admit_member(m.clone()));
            let mut a = application();
            a.intent = "d".repeat(64);
            a.semantics = (0..16)
                .map(|j| Semantic {
                    name: format!("{j:096}"),
                    desired: false,
                    actual: false,
                })
                .collect();
            assert!(t.confirm(&m, 1, a));
        }
        assert!(t.complete);
        assert!(serde_json::to_vec(&t).unwrap().len() < MAX_BYTES);
    }

    #[test]
    fn hostile_member_budget_preserves_expected_inventory_counts() {
        let mut t = admitted();
        for i in 0..4096 {
            let mut m = member();
            m.id = format!("{i:096}");
            t.admit_member(m);
        }
        assert!(!t.complete);
        assert_eq!(t.reason.as_deref(), Some("budget-exceeded"));
        assert_eq!(t.expected_member_count, 4096);
        assert!(t.members.is_empty());
    }
    fn details() -> serde_json::Value {
        serde_json::json!({"startupApplication":{"authority":"backend","documentGeneration":"1","lifecycleGeneration":"1","clockDomain":"android.elapsedRealtime","contract":"selected-contract","intent":"armed","semantics":[{"name":"sound-disabled","desired":true,"actual":true}],"outcome":"matchedNoop","observedAtBootMs":900}})
    }
    #[test]
    fn typed_receipt_rejects_stale_stamp_clock_unknown_fields_and_baseline() {
        let d = details();
        assert!(parse_application(&d, 1, 1, 10).is_some());
        assert!(parse_application(&d, 2, 1, 10).is_none());
        assert!(parse_application(&d, 1, 2, 10).is_none());
        let mut bad = d.clone();
        bad["startupApplication"]["clockDomain"] = "daemon.monotonicSinceOwnerStart".into();
        assert!(parse_application(&bad, 1, 1, 10).is_none());
        let mut bad = d.clone();
        bad["startupApplication"]["baseline"] = true.into();
        assert!(parse_application(&bad, 1, 1, 10).is_none());
        let mut bad = d.clone();
        bad["startupApplication"]["semantics"][0]["actual"] = false.into();
        assert!(parse_application(&bad, 1, 1, 10).is_none());
        let mut bad = d.clone();
        bad["startupApplication"]["documentGeneration"] = 1.into();
        assert!(parse_application(&bad, 1, 1, 10).is_none());
    }
    #[test]
    fn exact_revision_serialization_preserves_large_values() {
        let mut t = admitted();
        t.members[0].document_generation = 1_791_521_183_847_145_209;
        let encoded = serde_json::to_value(&t).unwrap();
        assert_eq!(
            encoded["members"][0]["documentGeneration"],
            "1791521183847145209"
        );
        assert_eq!(encoded["targets"][0]["endpointEpoch"], "1");
    }
    #[test]
    fn owner_boot_anchor_is_separate_bounded_and_never_fabricated() {
        let anchor = ClockAnchor::from_sample(Some(123450), 0, 2).unwrap();
        assert_eq!(anchor.clock_domain, "linux.bootElapsedRealtime");
        assert_eq!(anchor.observed_at_boot_ms, 123450);
        assert_eq!(
            (
                anchor.owner_before_ms,
                anchor.owner_after_ms,
                anchor.precision_ms
            ),
            (0, 2, 10)
        );
        assert!(ClockAnchor::from_sample(None, 0, 2).is_none());
        assert!(ClockAnchor::from_sample(Some(123451), 0, 2).is_none());
        assert!(ClockAnchor::from_sample(Some(123450), 3, 2).is_none());
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert!(ClockAnchor::sample_owner_start(std::time::Instant::now()).is_none());
    }
}
