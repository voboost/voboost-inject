//! Authenticated resource observations; only a root-issued pending probe can yield a proof.
use crate::{agent_log::EndpointContext, status::EndpointBinding};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use voboost_shared::owned_overlay::{Owner, Variant};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProbePhase {
    Preflight,
    Readback,
    Current,
    #[serde(rename = "current-en")]
    CurrentEn,
    #[serde(rename = "current-zh")]
    CurrentZh,
}
impl ProbePhase {
    pub(crate) fn is_current(self) -> bool {
        matches!(self, Self::Current | Self::CurrentEn | Self::CurrentZh)
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Readback => "readback",
            Self::Current => "current",
            Self::CurrentEn => "current-en",
            Self::CurrentZh => "current-zh",
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct ProbeDescriptor {
    pub schema: u32,
    pub phase: ProbePhase,
    pub probe_revision: u64,
    pub profile: String,
    pub target_package: String,
    pub ledger: Value,
}
#[derive(Clone, Debug)]
pub struct ProbeTicket {
    binding: EndpointBinding,
    descriptor: ProbeDescriptor,
    serial: u64,
}
impl ProbeTicket {
    pub(crate) fn descriptor(&self) -> ProbeDescriptor {
        self.descriptor.clone()
    }
}
#[derive(Debug)]
pub struct CompatibilityProof {
    ticket: ProbeTicket,
    observed_binding: EndpointBinding,
}
#[derive(Debug)]
pub struct ResourcesProof {
    ticket: ProbeTicket,
    observed_binding: EndpointBinding,
}
macro_rules! proof_accessors {
    ($kind:ty) => {
        impl $kind {
            pub fn binding(&self) -> &EndpointBinding {
                &self.observed_binding
            }
            pub fn probe_revision(&self) -> u64 {
                self.ticket.descriptor.probe_revision
            }
            pub fn profile(&self) -> &str {
                &self.ticket.descriptor.profile
            }
        }
    };
}
proof_accessors!(CompatibilityProof);
proof_accessors!(ResourcesProof);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Observation {
    schema: u32,
    generation: String,
    document_generation: i64,
    probe_revision: u64,
    profile: String,
    target_package: String,
    phase: ProbePhase,
    checked_resource_count: usize,
    context_kinds: Vec<String>,
    outcome: String,
    observed_readback: BTreeMap<String, String>,
    #[serde(default)]
    reference_readback: Option<BTreeMap<String, String>>,
    #[serde(default)]
    observed_at_boot_ms: Option<u64>,
}
struct Pending {
    ticket: ProbeTicket,
    started: Instant,
    observed: Option<EndpointBinding>,
    observed_at: Option<u64>,
    compatible: bool,
}
#[derive(Default)]
struct State {
    next: u64,
    pending: Vec<Pending>,
    last_started: Option<(EndpointBinding, u64, ProbePhase)>,
    published: Option<Published>,
    current_published: Option<Published>,
}

#[derive(Clone, Debug)]
pub(crate) struct Published {
    pub profile: String,
    pub probe_revision: u64,
    pub binding: EndpointBinding,
    pub observed_at_boot_ms: u64,
    pub phase: ProbePhase,
}

impl Published {
    pub(crate) fn age_ms(&self) -> Option<u64> {
        super::global_locale::boot_ms()?.checked_sub(self.observed_at_boot_ms)
    }
}
pub(crate) fn published(owner: Owner) -> Option<Published> {
    let value = owner_state(owner).lock().ok()?.published.clone()?;
    value
        .age_ms()
        .is_some_and(|age| age <= 30000)
        .then_some(value)
}

pub(crate) fn current_published(owner: Owner) -> Option<Published> {
    let value = owner_state(owner).lock().ok()?.current_published.clone()?;
    value
        .age_ms()
        .is_some_and(|age| age <= 30000)
        .then_some(value)
}

pub(crate) fn clear_current(owner: Owner) {
    if let Ok(mut state) = owner_state(owner).lock() {
        state.current_published = None;
    }
}

fn owner_state(owner: Owner) -> &'static Mutex<State> {
    static STATES: OnceLock<[Mutex<State>; Owner::ALL_RESOURCES.len()]> = OnceLock::new();
    &STATES.get_or_init(|| std::array::from_fn(|_| Mutex::new(State::default())))[owner as usize]
}
#[cfg(test)]
fn state() -> &'static Mutex<State> {
    owner_state(Owner::Setting)
}
fn binding(ctx: &EndpointContext, owner: Owner) -> Option<EndpointBinding> {
    (Owner::from_process(&ctx.process).is_ok()
        && ctx.settings_generation_is_active()
        && ctx.resident_agents.contains(owner.agent())
        && ctx.agents.contains(owner.agent())
        && ctx.selected_agents.contains(owner.agent()))
    .then(|| crate::control_plane::endpoint_binding(ctx))
    .flatten()
}
fn same_endpoint(a: &EndpointBinding, b: &EndpointBinding) -> bool {
    a.target_pid == b.target_pid
        && a.target_starttime == b.target_starttime
        && a.endpoint_epoch == b.endpoint_epoch
        && a.generation_id == b.generation_id
        && a.catalog_sha256 == b.catalog_sha256
}
fn expected(descriptor: &ProbeDescriptor) -> Option<(usize, BTreeMap<String, String>)> {
    if descriptor.schema != 1
        || descriptor.probe_revision == 0
        || descriptor.profile.is_empty()
        || descriptor.profile.len() > 64
        || !descriptor
            .profile
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !descriptor
            .profile
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || Variant::from_profile(&descriptor.profile)
            .ok()?
            .owner()
            .process()
            != descriptor.target_package
    {
        return None;
    }
    if serde_json::to_vec(&descriptor.ledger).ok()?.len() > 1024 * 1024 {
        return None;
    }
    let contract = descriptor.ledger.get("compatibility")?.as_object()?;
    if contract.len() != 3
        || contract.get("schemaVersion")?.as_u64() != Some(1)
        || contract.get("targetPackage")?.as_str()? != descriptor.target_package
    {
        return None;
    }
    let rows = contract.get("resources")?.as_array()?;
    if rows.is_empty() || rows.len() > 10000 {
        return None;
    }
    let mut names = std::collections::BTreeSet::new();
    for row in rows {
        let name = row.get("resource")?.as_str()?;
        let kind = row.get("type")?.as_str()?;
        if !matches!(kind, "string" | "array" | "plurals")
            || !name.starts_with(&format!("{kind}/"))
            || name.len() > 256
            || !names.insert(name)
        {
            return None;
        }
    }
    let english = descriptor.profile.starts_with("en-");
    let field = match (english, descriptor.phase) {
        (true, ProbePhase::Preflight) => "nativeReadback",
        (true, ProbePhase::Current | ProbePhase::CurrentZh) => return None,
        (_, ProbePhase::CurrentEn) => "expectedEnglishReadback",
        _ => "expectedReadback",
    };
    let expected: BTreeMap<String, String> =
        serde_json::from_value(descriptor.ledger.get(field)?.clone()).ok()?;
    if english
        && (descriptor.ledger["scope"].as_str() != Some("english-delta")
            || expected.len() > 64
            || !expected
                .keys()
                .map(String::as_str)
                .eq(names.iter().copied()))
    {
        return None;
    }
    if expected.is_empty()
        || expected.len() > 256
        || expected
            .iter()
            .any(|(key, value)| key.len() > 256 || value.len() > 4096)
    {
        return None;
    }
    Some((rows.len(), expected))
}
pub fn begin_probe(
    ctx: &EndpointContext,
    descriptor: &ProbeDescriptor,
) -> Result<ProbeTicket, String> {
    begin_probes(ctx, std::slice::from_ref(descriptor)).map(|mut tickets| tickets.remove(0))
}
pub fn begin_probes(
    ctx: &EndpointContext,
    descriptors: &[ProbeDescriptor],
) -> Result<Vec<ProbeTicket>, String> {
    let descriptor = descriptors.first().ok_or("i18n probe batch empty")?;
    let owner = Owner::from_profile_process(&descriptor.profile, &ctx.process)?;
    let binding = binding(ctx, owner).ok_or("i18n probe endpoint unavailable")?;
    if descriptors.len() > Owner::CANDIDATE_LIMIT
        || (descriptors.len() > 1 && descriptor.phase != ProbePhase::Preflight)
        || descriptors.iter().any(|d| {
            expected(d).is_none()
                || d.target_package != ctx.process
                || Owner::from_profile_process(&d.profile, &ctx.process).ok() != Some(owner)
                || d.probe_revision != descriptor.probe_revision
                || d.phase != descriptor.phase
        })
        || descriptors.iter().enumerate().any(|(index, d)| {
            descriptors[..index]
                .iter()
                .any(|prior| prior.profile == d.profile)
        })
    {
        return Err("i18n probe batch invalid".into());
    }
    let mut state = owner_state(owner)
        .lock()
        .map_err(|_| "i18n probe lock poisoned")?;
    if state.pending.len() == descriptors.len()
        && state.pending.iter().zip(descriptors).all(|(pending, d)| {
            same_endpoint(&pending.ticket.binding, &binding) && pending.ticket.descriptor == *d
        })
    {
        if state
            .pending
            .iter()
            .any(|p| p.started.elapsed() > Duration::from_secs(30))
        {
            return Err("i18n probe expired".into());
        }
        return Ok(state.pending.iter().map(|p| p.ticket.clone()).collect());
    }
    if let Some((previous, revision, phase)) = &state.last_started {
        if same_endpoint(previous, &binding)
            && (descriptor.probe_revision < *revision
                || (descriptor.probe_revision == *revision
                    && !(*phase == ProbePhase::Preflight
                        && descriptor.phase == ProbePhase::Readback)))
        {
            return Err("i18n probe revision replay".into());
        }
    }
    // A new issued probe revokes any earlier evidence before a new result is known.
    if descriptor.phase.is_current() {
        state.current_published = None;
    } else {
        state.published = None;
        state.current_published = None;
    }
    state.last_started = Some((binding.clone(), descriptor.probe_revision, descriptor.phase));
    state.pending.clear();
    let mut tickets = Vec::new();
    for descriptor in descriptors {
        state.next = state
            .next
            .checked_add(1)
            .ok_or("i18n probe serial exhausted")?;
        let ticket = ProbeTicket {
            binding: binding.clone(),
            descriptor: descriptor.clone(),
            serial: state.next,
        };
        state.pending.push(Pending {
            ticket: ticket.clone(),
            started: Instant::now(),
            observed: None,
            observed_at: None,
            compatible: false,
        });
        tickets.push(ticket);
    }
    Ok(tickets)
}
pub fn forget(endpoint_epoch: u64) {
    for owner in Owner::ALL_RESOURCES {
        if let Ok(mut state) = owner_state(owner).lock() {
            if state
                .last_started
                .as_ref()
                .is_some_and(|(binding, _, _)| binding.endpoint_epoch == endpoint_epoch.to_string())
            {
                state.last_started = None;
            }

            if state
                .published
                .as_ref()
                .is_some_and(|p| p.binding.endpoint_epoch == endpoint_epoch.to_string())
            {
                state.published = None;
            }
            if state
                .current_published
                .as_ref()
                .is_some_and(|p| p.binding.endpoint_epoch == endpoint_epoch.to_string())
            {
                state.current_published = None;
            }
            state
                .pending
                .retain(|p| p.ticket.binding.endpoint_epoch != endpoint_epoch.to_string());
        }
    }
}
#[cfg(test)]
pub fn observe(payload: &str, ctx: &EndpointContext) -> Option<usize> {
    observe_from("i18n-ru", payload, ctx)
}
pub fn observe_from(source: &str, payload: &str, ctx: &EndpointContext) -> Option<usize> {
    if payload.len() > 64 * 1024 {
        return None;
    }
    let observation: Observation = serde_json::from_str(payload).ok()?;
    let owner = Owner::from_profile_process(&observation.profile, &ctx.process).ok()?;
    if owner.agent() != source {
        return None;
    }
    let actual = binding(ctx, owner)?;
    let mut state = owner_state(owner).lock().ok()?;
    let pending = state
        .pending
        .iter_mut()
        .find(|p| p.ticket.descriptor.profile == observation.profile)?;
    let descriptor = &pending.ticket.descriptor;
    let now_boot_ms = super::global_locale::boot_ms()?;
    let observed_boot_ms = if descriptor.phase.is_current() {
        let timestamp = observation.observed_at_boot_ms?;
        if timestamp == 0 || now_boot_ms.checked_sub(timestamp)? > 30000 {
            return None;
        }
        timestamp
    } else {
        if observation.observed_at_boot_ms.is_some() {
            return None;
        }
        now_boot_ms
    };
    let (schema_count, readback) = expected(descriptor)?;
    let count = match descriptor.phase {
        ProbePhase::Preflight => schema_count,
        ProbePhase::Readback
        | ProbePhase::Current
        | ProbePhase::CurrentEn
        | ProbePhase::CurrentZh => readback.len(),
    };
    if pending.started.elapsed() > Duration::from_secs(30)
        || !same_endpoint(&pending.ticket.binding, &actual)
        || observation.schema != 1
        || observation.generation != actual.generation_id
        || Some(observation.document_generation) != ctx.document_generation
        || observation.probe_revision != descriptor.probe_revision
        || observation.profile != descriptor.profile
        || observation.target_package != descriptor.target_package
        || observation.phase != descriptor.phase
        || (observation.outcome != "incompatible" && observation.checked_resource_count != count)
    {
        return None;
    }
    let valid = match descriptor.phase {
        ProbePhase::Preflight => {
            ((observation.outcome == "compatible" && observation.checked_resource_count == count)
                || (observation.outcome == "incompatible"
                    && observation.checked_resource_count <= count))
                && observation.context_kinds == ["en"]
                && observation.reference_readback.is_none()
                && if owner.agent() == "i18n-en" && observation.outcome == "compatible" {
                    observation.observed_readback == readback
                } else {
                    observation.observed_readback.is_empty()
                }
        }
        ProbePhase::Readback | ProbePhase::Current | ProbePhase::CurrentEn => {
            observation.outcome == "applied"
                && observation.context_kinds
                    == [if descriptor.phase == ProbePhase::Readback {
                        owner.locale()
                    } else {
                        descriptor.phase.name()
                    }]
                && observation.reference_readback.is_none()
                && observation.observed_readback == readback
        }
        ProbePhase::CurrentZh => {
            let english: Option<BTreeMap<String, String>> = descriptor
                .ledger
                .get("expectedEnglishReadback")
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let values = &observation.observed_readback;
            let keys_match = values.len() == readback.len() && values.keys().eq(readback.keys());
            let bounded = values.values().all(|v| !v.is_empty() && v.len() <= 4096);
            let han = values.values().any(|v| {
                v.chars().any(
                    |c| matches!(c as u32, 0x3400..=0x4dbf | 0x4e00..=0x9fff | 0x20000..=0x3134f),
                )
            });
            let distinct_ru = values
                .iter()
                .any(|(k, v)| readback.get(k).is_some_and(|r| r != v));
            let distinct_en = english.as_ref().is_some_and(|en| {
                values
                    .iter()
                    .any(|(k, v)| en.get(k).is_some_and(|e| e != v))
            });
            observation.outcome == "applied"
                && observation.context_kinds == ["current-zh"]
                && observation.reference_readback.as_ref() == Some(values)
                && keys_match
                && bounded
                && han
                && distinct_ru
                && distinct_en
        }
    };
    if !valid {
        return None;
    }
    if pending.observed.as_ref() != Some(&actual) || pending.observed_at.is_none() {
        pending.observed_at = Some(observed_boot_ms);
    }
    pending.observed = Some(actual);
    pending.compatible = observation.outcome != "incompatible";
    Some(1)
}
fn take(
    ticket: &ProbeTicket,
    ctx: &EndpointContext,
    phase: ProbePhase,
) -> Option<(EndpointBinding, u64)> {
    let owner = Owner::from_profile_process(&ticket.descriptor.profile, &ctx.process).ok()?;
    let actual = binding(ctx, owner)?;
    if ticket.descriptor.target_package != ctx.process {
        return None;
    }
    let mut state = owner_state(owner).lock().ok()?;
    if state.pending.len() != 1 {
        return None;
    }
    let index = state
        .pending
        .iter()
        .position(|p| p.ticket.serial == ticket.serial)?;
    let pending = &state.pending[index];
    if pending.ticket.serial != ticket.serial
        || pending.ticket.descriptor.phase != phase
        || pending.started.elapsed() > Duration::from_secs(30)
        || !same_endpoint(&ticket.binding, &actual)
        || pending.observed.as_ref() != Some(&actual)
        || !pending.compatible
    {
        return None;
    }
    let removed = state.pending.remove(index);
    Some((removed.observed?, removed.observed_at?))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreflightMismatch {
    NoMatch,
    Ambiguous,
}
impl PreflightMismatch {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoMatch => "no resource variant matches",
            Self::Ambiguous => "resource variant match is ambiguous",
        }
    }
}
/// Wait for every candidate in the same root-issued batch; never select the first ACK.
pub fn take_unique_preflight(
    tickets: &[ProbeTicket],
    ctx: &EndpointContext,
) -> Option<Result<CompatibilityProof, PreflightMismatch>> {
    let owner =
        Owner::from_profile_process(&tickets.first()?.descriptor.profile, &ctx.process).ok()?;
    let actual = binding(ctx, owner)?;
    let mut state = owner_state(owner).lock().ok()?;
    if tickets.is_empty()
        || tickets.len() > 2
        || state.pending.len() != tickets.len()
        || tickets.iter().enumerate().any(|(index, ticket)| {
            tickets[..index].iter().any(|prior| {
                prior.serial == ticket.serial
                    || prior.descriptor.profile == ticket.descriptor.profile
            })
        })
    {
        return None;
    }
    for ticket in tickets {
        if ticket.descriptor.target_package != ctx.process
            || Owner::from_profile_process(&ticket.descriptor.profile, &ctx.process).ok()
                != Some(owner)
        {
            return None;
        }
        let pending = state
            .pending
            .iter()
            .find(|p| p.ticket.serial == ticket.serial)?;
        if pending.ticket.descriptor.phase != ProbePhase::Preflight
            || pending.started.elapsed() > Duration::from_secs(30)
            || !same_endpoint(&ticket.binding, &actual)
            || pending.observed.as_ref() != Some(&actual)
        {
            return None;
        }
    }
    let compatible = state.pending.iter().filter(|p| p.compatible).count();
    if compatible != 1 {
        state.pending.clear();
        return Some(Err(if compatible == 0 {
            PreflightMismatch::NoMatch
        } else {
            PreflightMismatch::Ambiguous
        }));
    }
    let pending = state.pending.iter().find(|p| p.compatible)?;
    let proof = CompatibilityProof {
        ticket: pending.ticket.clone(),
        observed_binding: actual,
    };
    state.pending.clear();
    Some(Ok(proof))
}
pub fn take_preflight(ticket: &ProbeTicket, ctx: &EndpointContext) -> Option<CompatibilityProof> {
    Some(CompatibilityProof {
        ticket: ticket.clone(),
        observed_binding: take(ticket, ctx, ProbePhase::Preflight)?.0,
    })
}
pub fn take_readback(ticket: &ProbeTicket, ctx: &EndpointContext) -> Option<ResourcesProof> {
    let (observed_binding, observed_at) = take(ticket, ctx, ProbePhase::Readback)?;
    let owner = Owner::from_profile_process(&ticket.descriptor.profile, &ctx.process).ok()?;
    owner_state(owner).lock().ok()?.published = Some(Published {
        profile: ticket.descriptor.profile.clone(),
        probe_revision: ticket.descriptor.probe_revision,
        binding: observed_binding.clone(),
        observed_at_boot_ms: observed_at,
        phase: ticket.descriptor.phase,
    });
    Some(ResourcesProof {
        ticket: ticket.clone(),
        observed_binding,
    })
}

pub fn take_current(ticket: &ProbeTicket, ctx: &EndpointContext) -> Option<ResourcesProof> {
    if !ticket.descriptor.phase.is_current() {
        return None;
    }
    let (observed_binding, observed_at) = take(ticket, ctx, ticket.descriptor.phase)?;
    let owner = Owner::from_profile_process(&ticket.descriptor.profile, &ctx.process).ok()?;
    owner_state(owner).lock().ok()?.current_published = Some(Published {
        profile: ticket.descriptor.profile.clone(),
        probe_revision: ticket.descriptor.probe_revision,
        binding: observed_binding.clone(),
        observed_at_boot_ms: observed_at,
        phase: ticket.descriptor.phase,
    });
    Some(ResourcesProof {
        ticket: ticket.clone(),
        observed_binding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    #[test]
    fn current_en_and_zh_require_locale_specific_actual_resources() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ctx = context();
        forget(ctx.endpoint_epoch);
        let mut en = descriptor(ProbePhase::CurrentEn, 910);
        en.ledger["expectedEnglishReadback"] = json!({"a":"Language"});
        let ticket = begin_probe(&ctx, &en).unwrap();
        let mut value = ack(&ctx, &en);
        value["phase"] = json!("current-en");
        value["contextKinds"] = json!(["current-en"]);
        assert!(observe(&value.to_string(), &ctx).is_none());
        value["observedReadback"] = json!({"a":"Language"});
        value.as_object_mut().unwrap().remove("observedAtBootMs");
        assert!(observe(&value.to_string(), &ctx).is_none());
        let now = super::super::global_locale::boot_ms().unwrap();
        value["observedAtBootMs"] = json!(now + 60000);
        assert!(observe(&value.to_string(), &ctx).is_none());
        value["observedAtBootMs"] = json!(now.saturating_sub(30001));
        assert!(observe(&value.to_string(), &ctx).is_none());
        value["observedAtBootMs"] = json!(now);
        assert_eq!(observe(&value.to_string(), &ctx), Some(1));
        assert!(take_current(&ticket, &ctx).is_some());
        let mut zh = descriptor(ProbePhase::CurrentZh, 911);
        zh.ledger["expectedEnglishReadback"] = json!({"a":"Language"});
        let ticket = begin_probe(&ctx, &zh).unwrap();
        let mut value = ack(&ctx, &zh);
        value["phase"] = json!("current-zh");
        value["contextKinds"] = json!(["current-zh"]);
        value["observedReadback"] = json!({"a":"语言"});
        value["referenceReadback"] = json!({"a":"其他"});
        assert!(observe(&value.to_string(), &ctx).is_none());
        value["referenceReadback"] = json!({"a":"语言"});
        assert_eq!(observe(&value.to_string(), &ctx), Some(1));
        assert!(take_current(&ticket, &ctx).is_some());
        forget(ctx.endpoint_epoch);
    }

    #[test]
    fn current_chinese_requires_a_distinct_overlapping_english_witness() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ctx = context();
        forget(ctx.endpoint_epoch);
        for (revision, english, accepted) in [
            (
                912,
                json!({"a": "Language", "en_only": "Menu", "other": "General"}),
                true,
            ),
            (913, json!({"en_only": "Menu", "other": "General"}), false),
            (914, json!({"a": "语言", "en_only": "Menu"}), false),
        ] {
            let mut zh = descriptor(ProbePhase::CurrentZh, revision);
            zh.ledger["expectedReadback"] = json!({"a": "Язык", "b": "Настройки"});
            zh.ledger["expectedEnglishReadback"] = english;
            let ticket = begin_probe(&ctx, &zh).unwrap();
            let mut event = ack(&ctx, &zh);
            event["phase"] = json!("current-zh");
            event["contextKinds"] = json!(["current-zh"]);
            event["checkedResourceCount"] = json!(2);
            event["observedReadback"] = json!({"a": "语言", "b": "设置"});
            event["referenceReadback"] = event["observedReadback"].clone();
            assert_eq!(observe(&event.to_string(), &ctx), accepted.then_some(1));
            assert_eq!(take_current(&ticket, &ctx).is_some(), accepted);
        }
        forget(ctx.endpoint_epoch);
    }

    #[test]
    fn every_current_locale_needs_seven_individual_tickets() {
        let _guard = TEST_LOCK.lock().unwrap();
        for phase in [ProbePhase::CurrentEn, ProbePhase::CurrentZh] {
            let mut contexts = Vec::new();
            for (index, owner) in Owner::ALL.into_iter().enumerate() {
                let mut ctx = context();
                ctx.process = owner.process().into();
                ctx.pid += index as i32;
                ctx.endpoint_epoch += index as u64;
                forget(ctx.endpoint_epoch);
                let variant = Variant::ALL
                    .into_iter()
                    .find(|v| v.owner() == owner)
                    .unwrap();
                let mut d = descriptor(phase, 919);
                d.profile = variant.profile().into();
                d.target_package = ctx.process.clone();
                d.ledger["compatibility"]["targetPackage"] = json!(ctx.process);
                d.ledger["expectedEnglishReadback"] = json!({"a":"Language"});
                let ticket = begin_probe(&ctx, &d).unwrap();
                if index < 6 {
                    let mut event = ack(&ctx, &d);
                    event["phase"] = json!(phase.name());
                    event["contextKinds"] = json!([phase.name()]);
                    if phase == ProbePhase::CurrentEn {
                        event["observedReadback"] = json!({"a":"Language"});
                    } else {
                        event["observedReadback"] = json!({"a":"语言"});
                        event["referenceReadback"] = json!({"a":"语言"});
                    }
                    assert_eq!(observe(&event.to_string(), &ctx), Some(1));
                    assert!(take_current(&ticket, &ctx).is_some());
                } else {
                    assert!(take_current(&ticket, &ctx).is_none());
                    assert!(current_published(owner).is_none());
                }
                contexts.push(ctx);
            }
            for ctx in contexts {
                forget(ctx.endpoint_epoch);
            }
        }
    }

    #[test]
    fn actual_current_readback_cannot_borrow_forced_ru_ack() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ctx = context();
        forget(ctx.endpoint_epoch);
        let d = descriptor(ProbePhase::Current, 902);
        let ticket = begin_probe(&ctx, &d).unwrap();
        let mut forced = ack(&ctx, &d);
        forced["phase"] = json!("current");
        forced["contextKinds"] = json!(["ru"]);
        assert!(observe(&forced.to_string(), &ctx).is_none());
        forced["contextKinds"] = json!(["current"]);
        assert_eq!(observe(&forced.to_string(), &ctx), Some(1));
        assert!(take_current(&ticket, &ctx).is_some());
        assert!(take_current(&ticket, &ctx).is_none());
        forget(ctx.endpoint_epoch);
    }

    #[test]
    fn exported_readback_requires_consumed_ticket_and_revokes_on_endpoint_forget() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ctx = context();
        forget(ctx.endpoint_epoch);
        let d = descriptor(ProbePhase::Readback, 900);
        let ticket = begin_probe(&ctx, &d).unwrap();
        assert!(published(Owner::Setting).is_none());
        assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), Some(1));
        assert!(published(Owner::Setting).is_none());
        take_readback(&ticket, &ctx).unwrap();
        let actual = published(Owner::Setting).unwrap();
        assert_eq!(actual.profile, "setting-a9");
        assert_eq!(actual.probe_revision, 900);
        assert_eq!(actual.binding.target_pid, "4242");
        forget(ctx.endpoint_epoch);
        assert!(published(Owner::Setting).is_none());
    }
    #[test]
    fn all_seven_current_receipts_are_independent_and_missing_owner_stays_absent() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut contexts = Vec::new();
        for (index, owner) in Owner::ALL.into_iter().enumerate() {
            let mut ctx = context();
            ctx.process = owner.process().into();
            ctx.pid += index as i32;
            ctx.endpoint_epoch += index as u64;
            forget(ctx.endpoint_epoch);
            let variant = Variant::ALL
                .into_iter()
                .find(|v| v.owner() == owner)
                .unwrap();
            let mut d = descriptor(ProbePhase::Current, 903);
            d.profile = variant.profile().into();
            d.target_package = owner.process().into();
            d.ledger["compatibility"]["targetPackage"] = json!(owner.process());
            let ticket = begin_probe(&ctx, &d).unwrap();
            if index != 6 {
                let mut event = ack(&ctx, &d);
                event["phase"] = json!("current");
                event["contextKinds"] = json!(["current"]);
                assert_eq!(observe(&event.to_string(), &ctx), Some(1));
                assert!(take_current(&ticket, &ctx).is_some());
                assert!(current_published(owner).is_some());
            } else {
                assert!(take_current(&ticket, &ctx).is_none());
                assert!(current_published(owner).is_none());
            }
            contexts.push(ctx);
        }
        for ctx in contexts {
            forget(ctx.endpoint_epoch);
        }
    }

    #[test]
    fn all_seven_readbacks_require_each_owner_ticket_and_observation() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut contexts = Vec::new();
        for (index, owner) in Owner::ALL.into_iter().enumerate() {
            let mut ctx = context();
            ctx.process = owner.process().into();
            ctx.pid += index as i32;
            ctx.endpoint_epoch += index as u64;
            forget(ctx.endpoint_epoch);
            let variant = Variant::ALL
                .into_iter()
                .find(|v| v.owner() == owner)
                .unwrap();
            let mut d = descriptor(ProbePhase::Readback, 901);
            d.profile = variant.profile().into();
            d.target_package = owner.process().into();
            d.ledger["compatibility"]["targetPackage"] = json!(owner.process());
            let ticket = begin_probe(&ctx, &d).unwrap();
            if index != 6 {
                assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), Some(1));
                assert!(take_readback(&ticket, &ctx).is_some());
                assert!(published(owner).is_some());
            } else {
                assert!(take_readback(&ticket, &ctx).is_none());
                assert!(published(owner).is_none());
            }
            contexts.push(ctx);
        }
        for ctx in contexts {
            forget(ctx.endpoint_epoch);
        }
    }

    #[test]
    fn seven_owner_batches_require_current_complete_unique_results() {
        let _guard = TEST_LOCK.lock().unwrap();
        for vehicle_outcomes in [[false, false], [true, false], [false, true], [true, true]] {
            let contexts: Vec<_> = Owner::ALL
                .into_iter()
                .enumerate()
                .map(|(index, owner)| {
                    let mut ctx = context();
                    ctx.process = owner.process().into();
                    ctx.pid += index as i32;
                    ctx.endpoint_epoch += index as u64;
                    forget(ctx.endpoint_epoch);
                    ctx
                })
                .collect();
            let descriptors: Vec<Vec<_>> = Owner::ALL
                .into_iter()
                .map(|owner| {
                    Variant::ALL
                        .into_iter()
                        .filter(|variant| variant.owner() == owner)
                        .map(|variant| {
                            let mut d = descriptor(ProbePhase::Preflight, 300);
                            d.profile = variant.profile().into();
                            d.target_package = owner.process().into();
                            d.ledger["compatibility"]["targetPackage"] = json!(owner.process());
                            d
                        })
                        .collect()
                })
                .collect();
            let tickets: Vec<_> = contexts
                .iter()
                .zip(&descriptors)
                .map(|(ctx, descriptors)| begin_probes(ctx, descriptors).unwrap())
                .collect();
            for owner in 0..Owner::ALL.len() {
                for other in 0..Owner::ALL.len() {
                    if owner == other {
                        continue;
                    }
                    assert!(begin_probes(&contexts[owner], &descriptors[other]).is_err());
                    assert!(observe(
                        &ack(&contexts[other], &descriptors[other][0]).to_string(),
                        &contexts[owner]
                    )
                    .is_none());
                }
            }
            for candidate in 0..2 {
                for index in 0..Owner::ALL.len() {
                    let compatible = match index {
                        0 => candidate == 0,
                        1 => candidate == 1,
                        _ => vehicle_outcomes[candidate],
                    };
                    let mut payload = ack(&contexts[index], &descriptors[index][candidate]);
                    if !compatible {
                        payload["outcome"] = json!("incompatible");
                        payload["checkedResourceCount"] = json!(0);
                    }
                    assert_eq!(observe(&payload.to_string(), &contexts[index]), Some(1));
                }
                if candidate == 0 {
                    for index in 0..Owner::ALL.len() {
                        assert!(take_unique_preflight(&tickets[index], &contexts[index]).is_none());
                        assert!(take_unique_preflight(
                            &[tickets[index][0].clone(), tickets[index][0].clone()],
                            &contexts[index]
                        )
                        .is_none());
                    }
                    assert!(take_unique_preflight(
                        &[tickets[2][0].clone(), tickets[2][0].clone()],
                        &contexts[2]
                    )
                    .is_none());
                }
            }
            assert!(take_unique_preflight(&tickets[2], &contexts[1]).is_none());
            for index in 0..Owner::ALL.len() {
                let result = take_unique_preflight(&tickets[index], &contexts[index]).unwrap();
                assert_eq!(
                    result.is_ok(),
                    index < 2 || vehicle_outcomes.iter().filter(|value| **value).count() == 1
                );
                assert!(take_unique_preflight(&tickets[index], &contexts[index]).is_none());
                assert!(begin_probes(&contexts[index], &descriptors[index]).is_err());
                forget(contexts[index].endpoint_epoch);
            }
        }
    }
    #[test]
    fn independent_owner_batches_require_current_complete_unique_results() {
        let _guard = TEST_LOCK.lock().unwrap();
        let setting = context();
        let mut launcher = setting.clone();
        launcher.process = Owner::Launcher.process().into();
        launcher.pid += 1;
        launcher.endpoint_epoch += 1;
        for outcomes in [[false, false], [true, false], [false, true], [true, true]] {
            forget(setting.endpoint_epoch);
            forget(launcher.endpoint_epoch);
            let make = |owner: Owner| {
                Variant::ALL
                    .into_iter()
                    .filter(|v| v.owner() == owner)
                    .map(|variant| {
                        let mut d = descriptor(ProbePhase::Preflight, 200);
                        d.profile = variant.profile().into();
                        d.target_package = owner.process().into();
                        d.ledger["compatibility"]["targetPackage"] = json!(owner.process());
                        d
                    })
                    .collect::<Vec<_>>()
            };
            let settings = make(Owner::Setting);
            let launchers = make(Owner::Launcher);
            let a = begin_probes(&setting, &settings).unwrap();
            let b = begin_probes(&launcher, &launchers).unwrap();
            assert!(begin_probes(&launcher, &settings).is_err());
            assert!(observe(&ack(&setting, &settings[0]).to_string(), &launcher).is_none());
            for index in 0..2 {
                assert_eq!(
                    observe(&ack(&setting, &settings[index]).to_string(), &setting),
                    Some(1)
                );
                let mut payload = ack(&launcher, &launchers[index]);
                if !outcomes[index] {
                    payload["outcome"] = json!("incompatible");
                    payload["checkedResourceCount"] = json!(0);
                }
                assert_eq!(observe(&payload.to_string(), &launcher), Some(1));
                if index == 0 {
                    assert!(take_unique_preflight(&b, &launcher).is_none());
                    assert!(
                        take_unique_preflight(&[b[0].clone(), b[0].clone()], &launcher).is_none()
                    );
                }
            }
            // Two Setting matches are ambiguous, without consuming the Launcher result.
            assert!(take_unique_preflight(&a, &setting).unwrap().is_err());
            assert!(take_unique_preflight(&b, &setting).is_none());
            let result = take_unique_preflight(&b, &launcher).unwrap();
            assert_eq!(result.is_ok(), outcomes.iter().filter(|v| **v).count() == 1);
            assert!(take_unique_preflight(&b, &launcher).is_none());
            assert!(begin_probes(&launcher, &launchers).is_err());
        }
        forget(setting.endpoint_epoch);
        forget(launcher.endpoint_epoch);
    }
    fn context() -> EndpointContext {
        EndpointContext {
            pid: 4242,
            process: "com.qinggan.app.setting".into(),
            endpoint_epoch: 4242,
            target_starttime: Some(120),
            document_generation: Some(7),
            log_generation: Some(("a".repeat(64), "b".repeat(64))),
            resident_generation_id: "a".repeat(64),
            resident_catalog_sha256: "b".repeat(64),
            active_generation_id: "a".repeat(64),
            active_catalog_sha256: "b".repeat(64),
            resident_agents: ["i18n-ru".into()].into(),
            agents: ["i18n-ru".into()].into(),
            selected_agents: ["i18n-ru".into()].into(),
            ..Default::default()
        }
    }
    fn descriptor(phase: ProbePhase, revision: u64) -> ProbeDescriptor {
        ProbeDescriptor {
            schema: 1,
            phase,
            probe_revision: revision,
            profile: "setting-a9".into(),
            target_package: "com.qinggan.app.setting".into(),
            ledger: json!({"compatibility":{"schemaVersion":1,"targetPackage":"com.qinggan.app.setting","resources":[{"resource":"string/a","type":"string"},{"resource":"array/b","type":"array"}]},"expectedReadback":{"a":"Русский"}}),
        }
    }
    fn ack(ctx: &EndpointContext, d: &ProbeDescriptor) -> Value {
        let mut value = json!({"schema":1,"generation":ctx.resident_generation_id,"documentGeneration":ctx.document_generation,
            "probeRevision":d.probe_revision,"profile":d.profile,"targetPackage":d.target_package,
            "phase":if d.phase==ProbePhase::Preflight{"preflight"}else{"readback"},
            "checkedResourceCount":if d.phase==ProbePhase::Preflight{2}else{1},
            "contextKinds":[if d.phase==ProbePhase::Preflight{"en"}else{"ru"}],
            "outcome":if d.phase==ProbePhase::Preflight{"compatible"}else{"applied"},
            "observedReadback":if d.phase==ProbePhase::Preflight{json!({})}else{json!({"a":"Русский"})}});
        if d.phase.is_current() {
            value["observedAtBootMs"] = json!(super::super::global_locale::boot_ms().unwrap());
        }
        value
    }
    #[test]
    fn english_and_russian_probes_coexist_and_reject_foreign_source() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut ctx = context();
        ctx.endpoint_epoch = 115712;
        for agents in [
            &mut ctx.resident_agents,
            &mut ctx.agents,
            &mut ctx.selected_agents,
        ] {
            agents.insert("i18n-en".into());
        }
        forget(ctx.endpoint_epoch);
        let ru = descriptor(ProbePhase::Preflight, 1);
        let mut en = ru.clone();
        en.profile = "en-setting-a11".into();
        en.ledger["scope"] = json!("english-delta");
        en.ledger["nativeReadback"] =
            json!({"string/a":"语言","array/b":"[\"Stock wording\",\"中文\"]"});
        en.ledger["expectedReadback"] =
            json!({"string/a":"Language","array/b":"[\"Stock wording\",\"Chinese\"]"});
        en.ledger["expectedEnglishReadback"] = en.ledger["expectedReadback"].clone();
        let ru_ticket = begin_probe(&ctx, &ru).unwrap();
        let en_ticket = begin_probe(&ctx, &en).unwrap();
        assert_eq!(
            observe_from("i18n-ru", &ack(&ctx, &en).to_string(), &ctx),
            None
        );
        assert_eq!(
            observe_from("i18n-en", &ack(&ctx, &ru).to_string(), &ctx),
            None
        );
        let mut english_observation = ack(&ctx, &en);
        for value in [
            json!({}),
            en.ledger["expectedReadback"].clone(),
            json!({"string/a":"语言","array/b":"[\"Different stock wording\",\"中文\"]"}),
        ] {
            english_observation["observedReadback"] = value;
            assert_eq!(
                observe_from("i18n-en", &english_observation.to_string(), &ctx),
                None
            );
        }
        english_observation["observedReadback"] = en.ledger["nativeReadback"].clone();
        assert_eq!(
            observe_from("i18n-en", &english_observation.to_string(), &ctx),
            Some(1)
        );
        assert_eq!(
            observe_from("i18n-ru", &ack(&ctx, &ru).to_string(), &ctx),
            Some(1)
        );
        assert!(take_preflight(&ru_ticket, &ctx).is_some());
        assert!(take_preflight(&en_ticket, &ctx).is_some());
        // EN can be the only resident/selected translation agent.
        for agents in [
            &mut ctx.resident_agents,
            &mut ctx.agents,
            &mut ctx.selected_agents,
        ] {
            agents.remove("i18n-ru");
        }
        en.phase = ProbePhase::Readback;
        let en_ticket = begin_probe(&ctx, &en).unwrap();
        let mut observation = ack(&ctx, &en);
        observation["contextKinds"] = json!(["en"]);
        observation["checkedResourceCount"] = json!(2);
        observation["observedReadback"] = en.ledger["expectedReadback"].clone();
        assert_eq!(
            observe_from("i18n-en", &observation.to_string(), &ctx),
            Some(1)
        );
        assert!(take_readback(&en_ticket, &ctx).is_some());
        assert!(published(Owner::EnSetting).is_some());
        assert!(published(Owner::Setting).is_none());
        assert!(begin_probe(&ctx, &descriptor(ProbePhase::Preflight, 2)).is_err());
        forget(ctx.endpoint_epoch);
    }

    #[test]
    fn current_signed_ledger_shape_uses_compatibility_not_translation_count() {
        let mut descriptor = descriptor(ProbePhase::Preflight, 1);
        descriptor.ledger = serde_json::from_str(include_str!(
            "../../../voboost-agents/src/i18n/ru/setting-a9/completion-ledger.json"
        ))
        .unwrap();
        let (count, readback) = expected(&descriptor).unwrap();
        assert_eq!(count, 1670);
        assert_eq!(readback.len(), 5);
        descriptor.profile = "another-supported-resource-owner".into();
        assert!(expected(&descriptor).is_none());
        descriptor.profile = "setting-a11".into();
        assert!(expected(&descriptor).is_some());
        descriptor.profile = "../setting-a9".into();
        assert!(expected(&descriptor).is_none());
        descriptor.profile = "setting-a11".into();
        descriptor.ledger["compatibility"]["schemaVersion"] = json!(2);
        assert!(expected(&descriptor).is_none());
    }

    #[test]
    fn two_phase_identity_replay_refresh_and_consumption() {
        let _guard = TEST_LOCK.lock().unwrap();
        let mut ctx = context();
        forget(ctx.endpoint_epoch);
        let d = descriptor(ProbePhase::Preflight, 1);
        assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), None);
        let ticket = begin_probe(&ctx, &d).unwrap();
        assert!(take_preflight(&ticket, &ctx).is_none());
        for case in 0..7 {
            let mut bad = ctx.clone();
            match case {
                0 => bad.process = "system_server".into(),
                1 => bad.pid += 1,
                2 => bad.target_starttime = Some(121),
                3 => bad.endpoint_epoch += 1,
                4 => bad.selected_agents.clear(),
                5 => bad.agents.clear(),
                _ => bad.active_catalog_sha256 = "c".repeat(64),
            }
            assert_eq!(
                observe(&ack(&bad, &d).to_string(), &bad),
                None,
                "identity {case}"
            );
            assert!(take_preflight(&ticket, &bad).is_none());
        }

        for (field, value) in [
            ("generation", json!("c".repeat(64))),
            ("documentGeneration", json!(6)),
            ("probeRevision", json!(2)),
            ("profile", json!("wrong")),
            ("checkedResourceCount", json!(1)),
            ("contextKinds", json!(["ru"])),
            ("outcome", json!("applied")),
            ("extra", json!(true)),
        ] {
            let mut bad = ack(&ctx, &d);
            bad[field] = value;
            assert_eq!(observe(&bad.to_string(), &ctx), None, "{field}");
        }
        assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), Some(1));
        let same = begin_probe(&ctx, &d).unwrap();
        assert_eq!(same.serial, ticket.serial);
        assert!(state()
            .lock()
            .unwrap()
            .pending
            .first()
            .unwrap()
            .observed
            .is_some());
        ctx.document_generation = Some(8);
        assert_eq!(begin_probe(&ctx, &d).unwrap().serial, ticket.serial);
        assert!(take_preflight(&ticket, &ctx).is_none());
        assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), Some(1));
        let proof = take_preflight(&ticket, &ctx).unwrap();
        assert_eq!(proof.binding().desired_document_generation, "8");
        assert_eq!(proof.profile(), "setting-a9");
        assert_eq!(proof.probe_revision(), 1);
        assert!(take_preflight(&ticket, &ctx).is_none());
        assert!(begin_probe(&ctx, &d).is_err());
        let d = descriptor(ProbePhase::Readback, 1);
        let ticket = begin_probe(&ctx, &d).unwrap();
        let mut bad = ack(&ctx, &d);
        bad["observedReadback"] = json!({"a":"wrong"});
        assert_eq!(observe(&bad.to_string(), &ctx), None);
        assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), Some(1));
        let mut replaced = ctx.clone();
        replaced.target_starttime = Some(121);
        assert!(take_readback(&ticket, &replaced).is_none());
        let proof = take_readback(&ticket, &ctx).unwrap();
        assert_eq!(proof.probe_revision(), 1);
        assert_eq!(proof.profile(), "setting-a9");
        assert_eq!(proof.binding().target_pid, "4242");
        assert!(begin_probe(&ctx, &d).is_err());
        let d = descriptor(ProbePhase::Preflight, 2);
        let ticket = begin_probe(&ctx, &d).unwrap();
        state().lock().unwrap().pending.first_mut().unwrap().started =
            Instant::now() - Duration::from_secs(31);
        assert_eq!(observe(&ack(&ctx, &d).to_string(), &ctx), None);
        assert!(take_preflight(&ticket, &ctx).is_none());
        forget(ctx.endpoint_epoch);
        assert!(state().lock().unwrap().pending.is_empty());
    }
    #[test]
    fn batch_waits_for_all_and_requires_exactly_one_actual_compatible_candidate() {
        let _guard = TEST_LOCK.lock().unwrap();
        let ctx = context();
        for outcomes in [[false, false], [true, false], [false, true], [true, true]] {
            forget(ctx.endpoint_epoch);
            let first = descriptor(ProbePhase::Preflight, 100);
            let mut second = first.clone();
            second.profile = "setting-a11".into();
            let descriptors = vec![first, second];
            let tickets = begin_probes(&ctx, &descriptors).unwrap();
            assert!(take_preflight(&tickets[0], &ctx).is_none());
            assert!(take_unique_preflight(&tickets[..1], &ctx).is_none());
            for index in 0..2 {
                let mut payload = ack(&ctx, &descriptors[index]);
                if !outcomes[index] {
                    payload["outcome"] = json!("incompatible");
                    payload["checkedResourceCount"] = json!(0);
                }
                assert_eq!(observe(&payload.to_string(), &ctx), Some(1));
                if index == 0 {
                    assert!(take_unique_preflight(&tickets, &ctx).is_none());
                    assert!(
                        take_unique_preflight(&[tickets[0].clone(), tickets[0].clone()], &ctx)
                            .is_none()
                    );
                }
            }
            let result = take_unique_preflight(&tickets, &ctx).unwrap();
            if outcomes.iter().filter(|v| **v).count() == 1 {
                let proof = result.unwrap();
                assert_eq!(
                    proof.profile(),
                    if outcomes[0] {
                        "setting-a9"
                    } else {
                        "setting-a11"
                    }
                );
            } else {
                assert!(result.is_err());
            }
            assert!(take_unique_preflight(&tickets, &ctx).is_none());
        }
        forget(ctx.endpoint_epoch);
        let d = descriptor(ProbePhase::Preflight, 101);
        assert!(begin_probes(&ctx, &[]).is_err());
        assert!(begin_probes(&ctx, &[d.clone(), d.clone()]).is_err());
    }
}
