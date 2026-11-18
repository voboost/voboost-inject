//! Fail-closed native parser for the single schema-1 JSON line printed by
//! the standalone `I18nRuNoneCleanup` process. serde_json's `from_slice`
//! consumes the whole input (rejecting trailing log text) and the derived
//! `Deserialize` with `deny_unknown_fields` rejects unknown fields, while
//! duplicate keys are rejected by serde's generated map visitor.
use serde::Deserialize;

const MAXIMUM: usize = 8 * 1024;
const MAX_TAGS_CHARS: usize = 512;
const MAX_LOCALES: usize = 16;

/// Primary language of the FIRST locale of the observed list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrimaryLanguage {
    English,
    Chinese,
    Russian,
}

/// Private typed observation; only constructible via [`parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoneCleanupObservation {
    primary: PrimaryLanguage,
    full_tags: String,
    user_id: u32,
    update_requested: bool,
}

impl NoneCleanupObservation {
    /// Primary language of the first observed (== persisted) locale.
    pub fn primary_language(&self) -> PrimaryLanguage {
        self.primary
    }

    /// Full observed locale tag list, verbatim (e.g. "en-US,ru-RU").
    pub fn full_tags(&self) -> &str {
        &self.full_tags
    }

    /// Current Android user id recorded by the cleanup process.
    pub fn user_id(&self) -> u32 {
        self.user_id
    }

    /// True only when the cleanup had to switch ru -> en itself.
    pub fn update_requested(&self) -> bool {
        self.update_requested
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Raw {
    schema: u32,
    status: String,
    update_requested: bool,
    user_id: u32,
    actual_locales: String,
    persisted_locales: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FailureLocales {
    Tags(String),
    Absent(()),
}

impl FailureLocales {
    fn valid(&self) -> bool {
        match self {
            Self::Tags(tags) => validate_tags(tags).is_ok(),
            Self::Absent(()) => true,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawFailure {
    schema: u32,
    status: String,
    #[serde(rename = "updateRequested")]
    _update_requested: bool,
    user_id: i32,
    actual_locales: FailureLocales,
    persisted_locales: FailureLocales,
}

fn failure_status(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() > MAXIMUM {
        return None;
    }
    let raw: RawFailure = serde_json::from_slice(bytes).ok()?;
    if raw.schema != 1
        || raw.user_id < -1
        || !raw.actual_locales.valid()
        || !raw.persisted_locales.valid()
    {
        return None;
    }
    match raw.status.as_str() {
        "invalid-arguments" => Some("invalid-arguments"),
        "process-timeout" => Some("process-timeout"),
        "capability-or-execution-failed" => Some("capability-or-execution-failed"),
        "observation-timeout" => Some("observation-timeout"),
        "unsupported-language" => Some("unsupported-language"),
        _ => None,
    }
}

/// Parse raw stdout of a finished cleanup process; nonzero exit fails closed.
pub fn parse_process(success: bool, bytes: &[u8]) -> Result<NoneCleanupObservation, String> {
    if !success {
        return Err(match failure_status(bytes) {
            Some(status) => format!("none cleanup command failed: {status}"),
            None => "none cleanup command failed".into(),
        });
    }
    parse(bytes)
}

pub fn parse_english_process(
    success: bool,
    bytes: &[u8],
) -> Result<NoneCleanupObservation, String> {
    if !success {
        return parse_process(success, bytes);
    }
    parse_for_owner(bytes, true)
}

/// Fail-closed parse of cleanup stdout against schema 1.
pub fn parse(bytes: &[u8]) -> Result<NoneCleanupObservation, String> {
    parse_for_owner(bytes, false)
}
fn parse_for_owner(bytes: &[u8], english_owner: bool) -> Result<NoneCleanupObservation, String> {
    if bytes.len() > MAXIMUM {
        return Err("none cleanup output exceeds bound".into());
    }
    let raw: Raw =
        serde_json::from_slice(bytes).map_err(|e| format!("malformed none cleanup JSON: {e}"))?;
    if raw.user_id > i32::MAX as u32 {
        return Err("user outside Android integer range".into());
    }
    if raw.schema != 1 {
        return Err("schema is not 1".into());
    }
    if raw.status != "confirmed" {
        return Err("status not confirmed".into());
    }
    validate_tags(&raw.actual_locales)?;
    validate_tags(&raw.persisted_locales)?;
    if raw.actual_locales != raw.persisted_locales {
        return Err("actual and persisted locale lists differ".into());
    }
    let primary = primary_of(&raw.actual_locales)?;
    if english_owner && raw.update_requested {
        return Err("English cleanup must preserve locale".into());
    }
    if !english_owner && primary == PrimaryLanguage::Russian {
        return Err("RU cleanup retained Russian".into());
    }
    if raw.update_requested && primary != PrimaryLanguage::English {
        return Err("RU cleanup update did not confirm English".into());
    }
    Ok(NoneCleanupObservation {
        primary,
        full_tags: raw.actual_locales,
        user_id: raw.user_id,
        update_requested: raw.update_requested,
    })
}

/// Mirrors the producer's `I18nRuNoneCleanup.validTags` bound rules.
fn validate_tags(tags: &str) -> Result<(), String> {
    if tags.is_empty() || tags.len() > MAX_TAGS_CHARS {
        return Err("locale list out of bounds".into());
    }
    let locales: Vec<&str> = tags.split(',').collect();
    if locales.len() > MAX_LOCALES {
        return Err("locale list out of bounds".into());
    }
    for locale in locales {
        let parts: Vec<&str> = locale.split('-').collect();
        if parts[0].len() < 2 || parts[0].len() > 8 {
            return Err("invalid locale tag".into());
        }
        for (index, part) in parts.iter().enumerate() {
            if part.is_empty()
                || part.len() > 8
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphabetic() || (index > 0 && b.is_ascii_digit()))
            {
                return Err("invalid locale tag".into());
            }
        }
    }
    Ok(())
}

/// First locale's primary language; case-sensitive, mirroring the Producer.
fn primary_of(tags: &str) -> Result<PrimaryLanguage, String> {
    let first = tags.split(',').next().unwrap_or("");
    match first.split('-').next().unwrap_or("") {
        "en" => Ok(PrimaryLanguage::English),
        "zh" => Ok(PrimaryLanguage::Chinese),
        "ru" => Ok(PrimaryLanguage::Russian),
        _ => Err("first locale is not en, zh or ru".into()),
    }
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
