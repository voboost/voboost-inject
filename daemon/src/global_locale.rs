//! Volatile observation of the real ActivityManager configuration, never user intent.
use crate::agent_log::EndpointContext;
use crate::status::EndpointBinding;
use serde::Deserialize;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub enum GlobalLanguage {
    #[serde(rename = "en")]
    English,
    #[serde(rename = "zh")]
    Chinese,
    #[serde(rename = "ru")]
    Russian,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalLocaleObservation {
    pub language: GlobalLanguage,
    pub observed_at_boot_ms: u64,
    pub binding: EndpointBinding,
    pub process: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    schema: u32,
    generation: String,
    document_generation: i64,
    locale: GlobalLanguage,
    observed_at_boot_ms: u64,
}

struct Cached {
    observation: GlobalLocaleObservation,
    last_seen_boot_ms: u64,
}

fn state() -> &'static Mutex<Option<Cached>> {
    static STATE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

fn binding(ctx: &EndpointContext, language: Option<GlobalLanguage>) -> Option<EndpointBinding> {
    if ctx.process != "com.qinggan.app.setting" || !ctx.settings_generation_is_active() {
        return None;
    }
    let active = ["i18n-ru", "i18n-en"].into_iter().any(|agent| {
        ctx.resident_agents.contains(agent)
            && ctx.agents.contains(agent)
            && ctx.selected_agents.contains(agent)
    });
    let retiring = !ctx.agents.contains("i18n-ru")
        && matches!(
            language,
            Some(GlobalLanguage::English | GlobalLanguage::Chinese)
        )
        && ctx
            .retiring_state
            .as_ref()
            .is_some_and(|token| token.permits_retirement(ctx, "i18n-ru"));
    if !active && !retiring {
        return None;
    }
    crate::control_plane::endpoint_binding(ctx)
}

const MAX_OBSERVATION_AGE_MS: u64 = 30_000;

pub(super) fn boot_ms() -> Option<u64> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(clock, &mut time) } != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return None;
    }
    (time.tv_sec as u64)
        .checked_mul(1000)?
        .checked_add(time.tv_nsec as u64 / 1_000_000)
}

pub fn latest(ctx: &EndpointContext) -> Option<GlobalLocaleObservation> {
    latest_at(ctx, boot_ms()?)
}

fn latest_at(ctx: &EndpointContext, now_boot_ms: u64) -> Option<GlobalLocaleObservation> {
    let value = {
        let state = state().lock().ok()?;
        let cached = state.as_ref()?;
        let age = now_boot_ms.checked_sub(cached.last_seen_boot_ms)?;
        if age > MAX_OBSERVATION_AGE_MS {
            return None;
        }
        let mut value = cached.observation.clone();
        value.observed_at_boot_ms = cached.last_seen_boot_ms;
        value
    };
    // Revocation closes admission, not the readback already admitted before
    // the terminal cleanup S frame. Its exact revision still fences reads.
    let readable = binding(ctx, Some(value.language)).is_some()
        || (ctx.process == "com.qinggan.app.setting"
            && ctx.settings_generation_is_active()
            && !ctx.agents.contains("i18n-ru")
            && matches!(
                value.language,
                GlobalLanguage::English | GlobalLanguage::Chinese
            ));
    if !readable {
        return None;
    }
    let expected = crate::control_plane::endpoint_binding(ctx)?;
    (value.binding == expected && value.process == ctx.process).then_some(value)
}

pub fn forget(endpoint_epoch: u64) {
    if let Ok(mut current) = state().lock() {
        if current.as_ref().is_some_and(|value| {
            value.observation.binding.endpoint_epoch == endpoint_epoch.to_string()
        }) {
            *current = None;
        }
    }
}

#[cfg(test)]
pub fn observe(payload: &str, ctx: &EndpointContext) -> Option<usize> {
    observe_from("i18n-ru", payload, ctx)
}
pub fn observe_from(source: &str, payload: &str, ctx: &EndpointContext) -> Option<usize> {
    let active = matches!(source, "i18n-ru" | "i18n-en")
        && ctx.resident_agents.contains(source)
        && ctx.agents.contains(source)
        && ctx.selected_agents.contains(source);
    let retiring = source == "i18n-ru"
        && ctx
            .retiring_state
            .as_ref()
            .is_some_and(|token| token.permits_retirement(ctx, source));
    if !active && !retiring {
        return None;
    }
    if payload.len() > 512 {
        return None;
    }
    let wire: Wire = serde_json::from_str(payload).ok()?;
    if !active && wire.locale == GlobalLanguage::Russian {
        return None;
    }
    let expected = binding(ctx, Some(wire.locale))?;
    if wire.schema != 1
        || ctx.document_generation != Some(wire.document_generation)
        || wire.generation != expected.generation_id
        || wire.observed_at_boot_ms == 0
    {
        return None;
    }
    let next = GlobalLocaleObservation {
        language: wire.locale,
        observed_at_boot_ms: wire.observed_at_boot_ms,
        binding: expected,
        process: ctx.process.clone(),
    };
    let mut current = state().lock().ok()?;
    if let Some(previous) = current
        .as_mut()
        .filter(|value| value.observation.binding == next.binding)
    {
        if next.observed_at_boot_ms < previous.last_seen_boot_ms
            || (next.observed_at_boot_ms == previous.last_seen_boot_ms
                && next.language != previous.observation.language)
        {
            return None;
        }
        if previous.observation.language == next.language {
            previous.last_seen_boot_ms = next.observed_at_boot_ms;
            return Some(1);
        }
    }
    *current = Some(Cached {
        last_seen_boot_ms: next.observed_at_boot_ms,
        observation: next,
    });
    Some(1)
}

#[cfg(test)]
pub(super) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ctx() -> EndpointContext {
        EndpointContext {
            pid: 42,
            process: "com.qinggan.app.setting".into(),
            endpoint_epoch: 99,
            target_starttime: Some(123),
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
    fn wire(locale: &str, time: u64) -> String {
        format!(
            r#"{{"schema":1,"generation":"{}","documentGeneration":7,"locale":"{locale}","observedAtBootMs":{time}}}"#,
            "a".repeat(64)
        )
    }
    #[test]
    fn english_only_source_observes_system_locale_and_cannot_extend_russian_retirement() {
        let _guard = test_guard();
        let mut english = ctx();
        english.endpoint_epoch = 189;
        english.resident_agents = ["i18n-en".into()].into();
        english.agents = english.resident_agents.clone();
        english.selected_agents = english.resident_agents.clone();
        forget(english.endpoint_epoch);
        assert_eq!(observe_from("i18n-ru", &wire("ru", 10), &english), None);
        assert_eq!(observe_from("i18n-en", &wire("ru", 10), &english), Some(1));
        assert_eq!(
            latest_at(&english, 11).unwrap().language,
            GlobalLanguage::Russian
        );
        english.retiring_state = Some(crate::agent_log::RetiringState {
            process: english.process.clone(),
            binding: crate::control_plane::endpoint_binding(&english).unwrap(),
            sources: ["i18n-ru".into()].into(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(30),
            revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        assert_eq!(observe_from("i18n-ru", &wire("ru", 11), &english), None);
        assert_eq!(observe_from("i18n-ru", &wire("en", 12), &english), Some(1));
        assert_eq!(observe_from("i18n-en", &wire("zh", 13), &english), Some(1));
        forget(english.endpoint_epoch);
    }
    #[test]
    fn validates_closed_schema_and_authenticated_endpoint() {
        let good = ctx();
        assert!(binding(&good, None).is_some());
        for change in 0..11 {
            let mut bad = good.clone();
            match change {
                0 => bad.process = "system_server".into(),
                1 => bad.pid = 0,
                2 => bad.target_starttime = None,
                3 => bad.endpoint_epoch = 0,
                4 => bad.log_generation = None,
                5 => bad.active_generation_id = "c".repeat(64),
                6 => bad.active_catalog_sha256 = "c".repeat(64),
                7 => bad.resident_agents.clear(),
                8 => bad.agents.clear(),
                9 => bad.selected_agents.clear(),
                _ => bad.document_generation = None,
            }
            assert!(binding(&bad, None).is_none(), "case {change}");
            assert_eq!(observe(&wire("ru", 10), &bad), None);
        }
        for invalid in [
            wire("de", 10),
            wire("ru", 0),
            wire("ru", 10).replace("\"schema\":1", "\"schema\":2"),
            wire("ru", 10).replace("\"schema\":1", "\"schema\":1,\"desired\":true"),
            wire("ru", 10).replace(&"a".repeat(64), &"c".repeat(64)),
            wire("ru", 10).replace("\"documentGeneration\":7", "\"documentGeneration\":6"),
            wire("ru", 10).replace("\"documentGeneration\":7,", ""),
        ] {
            assert_eq!(observe(&invalid, &good), None);
        }
    }
    #[test]
    fn retiring_authority_only_admits_non_russian_cleanup() {
        let mut retiring = ctx();
        retiring.agents.clear();
        retiring.selected_agents.clear();
        retiring.resident_agents.clear();
        let token = crate::agent_log::RetiringState {
            process: retiring.process.clone(),
            binding: crate::control_plane::endpoint_binding(&retiring).unwrap(),
            sources: ["i18n-ru".into()].into(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(30),
            revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        retiring.retiring_state = Some(token);
        assert!(binding(&retiring, Some(GlobalLanguage::English)).is_some());
        assert!(binding(&retiring, Some(GlobalLanguage::Chinese)).is_some());
        assert!(binding(&retiring, Some(GlobalLanguage::Russian)).is_none());
        assert!(binding(&retiring, None).is_none());
        let mut bad = retiring.clone();
        bad.pid += 1;
        assert!(binding(&bad, Some(GlobalLanguage::English)).is_none());
        bad = retiring.clone();
        bad.document_generation = Some(8);
        assert!(binding(&bad, Some(GlobalLanguage::English)).is_none());
        bad = retiring.clone();
        bad.retiring_state.as_mut().unwrap().sources.clear();
        assert!(binding(&bad, Some(GlobalLanguage::English)).is_none());
        bad = retiring.clone();
        bad.retiring_state.as_mut().unwrap().expires = std::time::Instant::now();
        assert!(binding(&bad, Some(GlobalLanguage::English)).is_none());
        retiring
            .retiring_state
            .as_ref()
            .unwrap()
            .revoked
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(binding(&retiring, Some(GlobalLanguage::English)).is_none());
    }
    #[test]
    fn changes_only_and_forgets_exact_endpoint() {
        let _guard = test_guard();
        // Publishing tests hold the same observation lock.
        let good = ctx();
        forget(good.endpoint_epoch);
        assert_eq!(observe(&wire("ru", 10), &good), Some(1));
        let first = latest_at(&good, 40).unwrap();
        assert_eq!(first.language, GlobalLanguage::Russian);
        assert_eq!(observe(&wire("ru", 20), &good), Some(1));
        let mut refreshed = first;
        refreshed.observed_at_boot_ms = 20;
        assert_eq!(latest_at(&good, 40), Some(refreshed));
        assert!(latest_at(&good, 30_021).is_none());
        assert!(latest_at(&good, 19).is_none());
        assert!(latest_at(&good, 30_020).is_some());
        assert_eq!(observe(&wire("en", 9), &good), None);
        assert_eq!(observe(&wire("en", 10), &good), None);
        assert_eq!(observe(&wire("en", 19), &good), None);
        assert_eq!(observe(&wire("en", 21), &good), Some(1));
        for change in 0..4 {
            let mut stale = good.clone();
            match change {
                0 => stale.pid += 1,
                1 => stale.target_starttime = Some(124),
                2 => stale.document_generation = Some(8),
                _ => stale.endpoint_epoch += 1,
            }
            assert!(latest_at(&stale, 40).is_none());
        }
        forget(100);
        assert!(latest_at(&good, 40).is_some());
        forget(99);
        assert!(latest_at(&good, 40).is_none());
        let mut retiring = good.clone();
        retiring.agents.clear();
        retiring.selected_agents.clear();
        retiring.resident_agents.clear();
        retiring.retiring_state = Some(crate::agent_log::RetiringState {
            process: retiring.process.clone(),
            binding: crate::control_plane::endpoint_binding(&retiring).unwrap(),
            sources: ["i18n-ru".into()].into(),
            expires: std::time::Instant::now() + std::time::Duration::from_secs(30),
            revoked: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        assert_eq!(observe(&wire("ru", 30), &retiring), None);
        assert_eq!(observe(&wire("en", 30), &retiring), Some(1));
        let admitted = latest_at(&retiring, 40).unwrap();
        retiring
            .retiring_state
            .as_ref()
            .unwrap()
            .revoked
            .store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(latest_at(&retiring, 40), Some(admitted));
        assert_eq!(observe(&wire("zh", 31), &retiring), None);
        retiring.document_generation = Some(8);
        assert!(latest_at(&retiring, 40).is_none());
        forget(99);
    }
}
