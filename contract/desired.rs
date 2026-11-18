//! Typed user actions. Runtime application never manufactures a new action identity.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
pub const MAX_FIELDS: usize = 4096;
pub const MAX_ORIGINS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stamp {
    pub revision: u64,
    pub input: Input,
    pub origins: BTreeMap<String, u64>,
}

impl Stamp {
    pub fn valid(&self, revision: u64) -> bool {
        self.input.bound()
            && self.revision > 0
            && self.revision <= revision
            && self.origins.len() <= MAX_ORIGINS
            && self.origins.get(&self.input.origin()) == Some(&self.input.request_id)
            && self.origins.iter().all(|(origin, request)| {
                let parts: Vec<_> = origin.split(':').collect();
                parts.len() == 3
                    && parts[0].parse::<i32>().is_ok_and(|pid| pid > 1)
                    && parts[1].parse::<u64>().is_ok_and(|start| start > 0)
                    && parts[2].parse::<u64>().is_ok_and(|epoch| {
                        epoch > 0 && epoch <= super::runtime_owner::MAX_NATIVE_ID
                    })
                    && *request > 0
                    && *request <= super::runtime_owner::MAX_NATIVE_ID
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Field {
    Startup,
    Enabled { agent: String },
    Option { agent: String, key: String },
    LauncherItemVisibility { identity: String },
    LauncherAppPreference { identity: String, key: String },
}

impl Field {
    pub fn from_path(path: &str) -> Option<Self> {
        let parts: Vec<_> = path.split('/').collect();
        let field = match parts.as_slice() {
            ["startup"] => Self::Startup,
            ["agents", agent, "enabled"] => Self::Enabled {
                agent: (*agent).into(),
            },
            ["agents", agent, "options", key] => Self::Option {
                agent: (*agent).into(),
                key: (*key).into(),
            },
            ["agents", "launcher", "options", "itemVisibility", identity] => {
                Self::LauncherItemVisibility {
                    identity: (*identity).into(),
                }
            }
            ["agents", "launcher", "options", "appPreferences", identity, key] => {
                Self::LauncherAppPreference {
                    identity: (*identity).into(),
                    key: (*key).into(),
                }
            }
            _ => return None,
        };
        field.valid().then_some(field)
    }
    pub fn valid(&self) -> bool {
        match self {
            Self::Startup => true,
            Self::Enabled { agent } => super::runtime_owner::valid_source(agent),
            Self::Option { agent, key } => {
                super::runtime_owner::valid_source(agent)
                    && super::runtime_owner::valid_key(key)
                    && !(agent == "launcher"
                        && matches!(key.as_str(), "itemVisibility" | "appPreferences"))
            }
            Self::LauncherItemVisibility { identity } => valid_launcher_identity(identity),
            Self::LauncherAppPreference { identity, key } => {
                valid_launcher_identity(identity)
                    && matches!(key.as_str(), "densityDpi" | "displayMode")
            }
        }
    }

    pub fn path(&self) -> String {
        match self {
            Self::Startup => "startup".into(),
            Self::Enabled { agent } => format!("agents/{agent}/enabled"),
            Self::Option { agent, key } => format!("agents/{agent}/options/{key}"),
            Self::LauncherItemVisibility { identity } => {
                format!("agents/launcher/options/itemVisibility/{identity}")
            }
            Self::LauncherAppPreference { identity, key } => {
                format!("agents/launcher/options/appPreferences/{identity}/{key}")
            }
        }
    }

    pub fn accepts(&self, value: &Value) -> bool {
        self.valid()
            && match self {
                Self::Startup => matches!(value.as_str(), Some("none" | "hidden" | "interface")),
                Self::Enabled { .. } => value.is_boolean(),
                Self::Option { .. } => !value.is_null(),
                Self::LauncherItemVisibility { .. } => value.is_boolean(),
                Self::LauncherAppPreference { key, .. } => match key.as_str() {
                    "densityDpi" => value.as_u64().is_some_and(|value| value <= u32::MAX as u64),
                    "displayMode" => value.as_str().is_some_and(|value| value.len() <= 96),
                    _ => false,
                },
            }
    }
}

pub fn valid_launcher_identity(identity: &str) -> bool {
    (3..=192).contains(&identity.len())
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
}

/// Bound by the injector to an authenticated live user-input endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub boot_id: String,
    pub endpoint_epoch: u64,
    pub request_id: u64,
    #[serde(default)]
    pub injector_pid: i32,
    #[serde(default)]
    pub injector_starttime: u64,
}

impl Input {
    pub fn origin(&self) -> String {
        format!(
            "{}:{}:{}",
            self.injector_pid, self.injector_starttime, self.endpoint_epoch
        )
    }

    pub fn bound(&self) -> bool {
        self.valid() && self.injector_pid > 1 && self.injector_starttime > 0
    }
    pub fn valid(&self) -> bool {
        super::operation::canonical_boot_id(&self.boot_id)
            && self.endpoint_epoch > 0
            && self.endpoint_epoch <= super::runtime_owner::MAX_NATIVE_ID
            && self.request_id > 0
            && self.request_id <= super::runtime_owner::MAX_NATIVE_ID
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    Saved,
    Replayed,
    Superseded,
}

use std::io;
pub const CONFIG_SCHEMA: u32 = 2;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    schema_version: u32,
    pub startup: String,
    pub agents: BTreeMap<String, Agent>,
    pub user_revision: u64,
    pub field_revisions: BTreeMap<String, Stamp>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub enabled: bool,
    pub options: BTreeMap<String, Value>,
}

impl Config {
    /// All unstamped values must be exactly the trusted product defaults.
    pub fn verify_defaults(&self, defaults: &[u8]) -> io::Result<()> {
        self.validate()?;
        if serde_json::to_vec(self).map_err(io::Error::other)? != self.reconcile(defaults)? {
            return Err(invalid("published product defaults differ"));
        }
        Ok(())
    }

    pub fn preserves_user_authority(&self, previous: &Self) -> bool {
        self.user_revision == previous.user_revision
            && self.field_revisions == previous.field_revisions
            && previous
                .field_revisions
                .keys()
                .all(|path| self.value_at(path) == previous.value_at(path))
    }

    /// Disables only incompatible enabled choices declared by the trusted catalog.
    /// This derived repair never manufactures user input or changes action stamps.
    pub fn normalize_exclusive(
        &self,
        relations: &BTreeMap<String, Vec<String>>,
    ) -> io::Result<Option<Self>> {
        self.validate()?;
        let enabled = |id: &str| self.agents.get(id).is_some_and(|agent| agent.enabled);
        let revision = |id: &str| {
            self.field_revisions
                .get(&Field::Enabled { agent: id.into() }.path())
                .map(|stamp| stamp.revision)
        };
        let mut neighbors: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        let mut disabled = std::collections::BTreeSet::new();
        for (source, dependencies) in relations {
            if !super::runtime_owner::valid_source(source) {
                return Err(invalid("invalid exclusive source"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for dependency in dependencies {
                if !super::runtime_owner::valid_source(dependency)
                    || dependency == source
                    || !seen.insert(dependency)
                {
                    return Err(invalid("invalid exclusive dependency"));
                }
                if !enabled(source) || !enabled(dependency) {
                    continue;
                }
                neighbors
                    .entry(source.clone())
                    .or_default()
                    .insert(dependency.clone());
                neighbors
                    .entry(dependency.clone())
                    .or_default()
                    .insert(source.clone());
                if revision(source).is_none()
                    || revision(dependency).is_none()
                    || revision(source) == revision(dependency)
                {
                    disabled.insert(source.clone());
                    disabled.insert(dependency.clone());
                }
            }
        }
        let mut ordered: Vec<_> = neighbors.keys().cloned().collect();
        ordered.sort_by(|left, right| revision(right).cmp(&revision(left)).then(left.cmp(right)));
        for source in ordered {
            if disabled.contains(&source) {
                continue;
            }
            if let Some(conflicts) = neighbors.get(&source) {
                disabled.extend(conflicts.iter().cloned());
            }
        }
        if disabled.is_empty() {
            return Ok(None);
        }
        let mut next = self.clone();
        for source in disabled {
            if let Some(agent) = next.agents.get_mut(&source) {
                agent.enabled = false;
            }
        }
        next.validate()?;
        Ok(Some(next))
    }

    /// A derived exception is accepted only as the complete exact catalog normalization.
    pub fn is_exclusive_normalization_of(
        &self,
        previous: &Self,
        relations: &BTreeMap<String, Vec<String>>,
    ) -> bool {
        previous
            .normalize_exclusive(relations)
            .ok()
            .flatten()
            .is_some_and(|expected| {
                match (serde_json::to_vec(&expected), serde_json::to_vec(self)) {
                    (Ok(expected), Ok(current)) => expected == current,
                    _ => false,
                }
            })
    }

    /// A read after publication may contain newer actions, but cannot rewrite an old stamp.
    pub fn advances_user_authority(&self, previous: &Self) -> bool {
        if self.user_revision < previous.user_revision {
            return false;
        }
        for (path, old) in &previous.field_revisions {
            let Some(next) = self.field_revisions.get(path) else {
                return false;
            };
            if next.revision == old.revision {
                if next != old || self.value_at(path) != previous.value_at(path) {
                    return false;
                }
            } else {
                if next.revision <= previous.user_revision {
                    return false;
                }
                if next.input.boot_id == old.input.boot_id
                    && old.origins.iter().any(|(origin, request)| {
                        next.origins.get(origin).is_none_or(|next| next < request)
                    })
                {
                    return false;
                }
            }
        }
        self.field_revisions.iter().all(|(path, stamp)| {
            previous
                .field_revisions
                .get(path)
                .is_some_and(|old| old == stamp)
                || stamp.revision > previous.user_revision
        })
    }
    pub fn initial(bytes: &[u8]) -> io::Result<Vec<u8>> {
        let defaults = Self::decode(bytes)?;
        if defaults.user_revision != 0 || !defaults.field_revisions.is_empty() {
            return Err(invalid("product defaults cannot create user revisions"));
        }
        serde_json::to_vec(&defaults).map_err(io::Error::other)
    }

    pub fn reconcile(&self, defaults: &[u8]) -> io::Result<Vec<u8>> {
        let mut next = Self::decode(&Self::initial(defaults)?)?;
        next.user_revision = self.user_revision;
        next.field_revisions = self.field_revisions.clone();
        for path in self.field_revisions.keys() {
            let field =
                Field::from_path(path).ok_or_else(|| invalid("invalid desired field path"))?;
            let value = self
                .value_at(path)
                .ok_or_else(|| invalid("desired value unavailable"))?;
            next.set_value(&field, value)?;
        }
        let bytes = serde_json::to_vec(&next).map_err(io::Error::other)?;
        Self::decode(&bytes)?;
        Ok(bytes)
    }
    pub fn new(startup: &str, agents: BTreeMap<String, Agent>) -> io::Result<Self> {
        let value = Self {
            schema_version: CONFIG_SCHEMA,
            startup: startup.into(),
            agents,
            user_revision: 0,
            field_revisions: BTreeMap::new(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > crate::runtime_owner::MAX_CONFIG_BYTES {
            return Err(invalid("desired configuration exceeds bound"));
        }
        let strict: crate::strict_json::StrictValue =
            serde_json::from_slice(bytes).map_err(io::Error::other)?;
        strict
            .validate(crate::strict_json::ValueLimits {
                max_depth: 16,
                max_total_nodes: 32768,
                max_object_properties: MAX_FIELDS,
                max_array_items: 1024,
                max_string_bytes: 16384,
            })
            .map_err(invalid)?;
        let value: Self = serde_json::from_value(strict.0).map_err(io::Error::other)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema_version != CONFIG_SCHEMA
            || self.user_revision > crate::runtime_owner::MAX_NATIVE_ID
            || !Field::Startup.accepts(&Value::String(self.startup.clone()))
            || self
                .agents
                .keys()
                .any(|id| !crate::runtime_owner::valid_source(id))
            || self.agents.values().any(|agent| {
                agent
                    .options
                    .keys()
                    .any(|key| !crate::runtime_owner::valid_key(key))
            })
            || self.field_revisions.len() > MAX_FIELDS
            || self
                .field_revisions
                .values()
                .map(|stamp| stamp.revision)
                .max()
                .unwrap_or(0)
                != self.user_revision
        {
            return Err(invalid("invalid desired configuration"));
        }
        for (path, stamp) in &self.field_revisions {
            if !Field::from_path(path).is_some_and(|field| {
                self.value_at(path)
                    .is_some_and(|value| field.accepts(&value))
            }) || !stamp.valid(self.user_revision)
            {
                return Err(invalid("invalid desired field revision"));
            }
        }
        Ok(())
    }

    pub fn value_at(&self, path: &str) -> Option<Value> {
        match Field::from_path(path)? {
            Field::Startup => Some(self.startup.clone().into()),
            Field::Enabled { agent } => Some(self.agents.get(&agent)?.enabled.into()),
            Field::Option { agent, key } => self.agents.get(&agent)?.options.get(&key).cloned(),
            Field::LauncherItemVisibility { identity } => self
                .agents
                .get("launcher")?
                .options
                .get("itemVisibility")?
                .get(&identity)
                .cloned(),
            Field::LauncherAppPreference { identity, key } => self
                .agents
                .get("launcher")?
                .options
                .get("appPreferences")?
                .get(&identity)?
                .get(&key)
                .cloned(),
        }
    }

    pub fn classify(&self, field: &Field, value: &Value, input: &Input) -> io::Result<Disposition> {
        let Some(stamp) = self.field_revisions.get(&field.path()) else {
            return Ok(Disposition::Saved);
        };
        if stamp.input == *input {
            return if self.value_at(&field.path()).as_ref() == Some(value) {
                Ok(Disposition::Replayed)
            } else {
                Err(invalid("desired input identity conflicts"))
            };
        }
        if stamp.input.boot_id == input.boot_id
            && stamp
                .origins
                .get(&input.origin())
                .is_some_and(|last| input.request_id <= *last)
        {
            return Ok(Disposition::Superseded);
        }
        Ok(Disposition::Saved)
    }

    /// The owner derives dependencies from its trusted catalog; they are never client payload.
    pub fn save(
        &mut self,
        boot: &str,
        field: &Field,
        value: &Value,
        input: &Input,
        dependencies: &[String],
    ) -> io::Result<Disposition> {
        if !input.bound() || input.boot_id != boot || !field.accepts(value) {
            return Err(invalid("invalid desired user action"));
        }
        if !dependencies.is_empty() && (!matches!(field, Field::Enabled { .. }) || value != true) {
            return Err(invalid("invalid desired dependencies"));
        }
        let mut changes = vec![(field.clone(), value.clone())];
        for agent in dependencies {
            let dependency = Field::Enabled {
                agent: agent.clone(),
            };
            if !dependency.valid() || changes.iter().any(|(field, _)| field == &dependency) {
                return Err(invalid("invalid desired dependency"));
            }
            changes.push((dependency, false.into()));
        }
        self.save_changes(boot, changes, input)
    }

    pub fn save_launcher(
        &mut self,
        boot: &str,
        changes: Vec<(Field, Value)>,
        input: &Input,
    ) -> io::Result<Disposition> {
        if changes.is_empty() || changes.len() > 512 || changes.iter().any(|(field, _)| !matches!(field,
            Field::LauncherItemVisibility { .. } | Field::LauncherAppPreference { .. }
        ) && !matches!(field, Field::Option { agent, key } if agent == "launcher" && key == "densityDpi")) {
            return Err(invalid("invalid launcher desired action"));
        }
        self.save_changes(boot, changes, input)
    }

    fn save_changes(
        &mut self,
        boot: &str,
        changes: Vec<(Field, Value)>,
        input: &Input,
    ) -> io::Result<Disposition> {
        if !input.bound() || input.boot_id != boot {
            return Err(invalid("invalid desired input authority"));
        }
        let mut paths = std::collections::HashSet::new();
        if changes
            .iter()
            .any(|(field, value)| !field.accepts(value) || !paths.insert(field.path()))
        {
            return Err(invalid("invalid or duplicate desired leaf"));
        }
        let mut replayed = true;
        for (field, value) in &changes {
            match self.classify(field, value, input)? {
                Disposition::Superseded => return Ok(Disposition::Superseded),
                Disposition::Saved => replayed = false,
                Disposition::Replayed => (),
            }
            if self
                .field_revisions
                .get(&field.path())
                .is_some_and(|stamp| {
                    stamp.input.boot_id == input.boot_id
                        && !stamp.origins.contains_key(&input.origin())
                        && stamp.origins.len() >= MAX_ORIGINS
                })
            {
                return Err(invalid("desired field origin bound reached"));
            }
        }
        if replayed {
            return Ok(Disposition::Replayed);
        }
        let revision = self
            .user_revision
            .checked_add(1)
            .filter(|value| *value <= crate::runtime_owner::MAX_NATIVE_ID)
            .ok_or_else(|| invalid("desired revision exhausted"))?;
        let mut next = self.clone();
        for (field, value) in changes {
            next.set_value(&field, value)?;
            let path = field.path();
            let mut origins = next
                .field_revisions
                .get(&path)
                .filter(|stamp| stamp.input.boot_id == boot)
                .map(|stamp| stamp.origins.clone())
                .unwrap_or_default();
            origins.insert(input.origin(), input.request_id);
            next.field_revisions.insert(
                path,
                Stamp {
                    revision,
                    input: input.clone(),
                    origins,
                },
            );
        }
        next.user_revision = revision;
        next.validate()?;
        // Serialization bounds apply to metadata as well as user values.
        Self::decode(&serde_json::to_vec(&next).map_err(io::Error::other)?)?;
        *self = next;
        Ok(Disposition::Saved)
    }

    fn set_value(&mut self, field: &Field, value: Value) -> io::Result<()> {
        match field {
            Field::Startup => {
                self.startup = value
                    .as_str()
                    .ok_or_else(|| invalid("invalid startup"))?
                    .into()
            }
            Field::Enabled { agent } => {
                self.agents
                    .entry(agent.clone())
                    .or_insert_with(empty_agent)
                    .enabled = value.as_bool().ok_or_else(|| invalid("invalid enabled"))?;
            }
            Field::Option { agent, key } => {
                self.agents
                    .entry(agent.clone())
                    .or_insert_with(empty_agent)
                    .options
                    .insert(key.clone(), value);
            }
            Field::LauncherItemVisibility { identity } => {
                let agent = self
                    .agents
                    .entry("launcher".into())
                    .or_insert_with(empty_agent);
                let items = agent
                    .options
                    .entry("itemVisibility".into())
                    .or_insert_with(|| serde_json::json!({}));
                let items = items
                    .as_object_mut()
                    .ok_or_else(|| invalid("launcher visibility desired shape differs"))?;
                if !items.contains_key(identity) && items.len() >= 256 {
                    return Err(invalid("launcher visibility desired map bound reached"));
                }
                items.insert(identity.clone(), value);
            }
            Field::LauncherAppPreference { identity, key } => {
                let agent = self
                    .agents
                    .entry("launcher".into())
                    .or_insert_with(empty_agent);
                agent
                    .options
                    .entry("itemVisibility".into())
                    .or_insert_with(|| serde_json::json!({}));
                let preferences = agent
                    .options
                    .entry("appPreferences".into())
                    .or_insert_with(|| serde_json::json!({}));
                let preferences = preferences
                    .as_object_mut()
                    .ok_or_else(|| invalid("launcher preference desired shape differs"))?;
                if !preferences.contains_key(identity) && preferences.len() >= 256 {
                    return Err(invalid("launcher preference desired map bound reached"));
                }
                let preference = preferences
                    .entry(identity.clone())
                    .or_insert_with(|| serde_json::json!({"densityDpi":0,"displayMode":"fit"}));
                preference
                    .as_object_mut()
                    .ok_or_else(|| invalid("launcher app preference desired shape differs"))?
                    .insert(key.clone(), value);
            }
        }
        Ok(())
    }
}

fn empty_agent() -> Agent {
    Agent {
        enabled: false,
        options: BTreeMap::new(),
    }
}

#[cfg(test)]
mod exclusive_tests {
    use super::*;
    use serde_json::json;

    fn relations() -> BTreeMap<String, Vec<String>> {
        BTreeMap::from([
            ("keyboard-en".into(), vec!["keyboard-ru".into()]),
            ("keyboard-ru".into(), vec!["keyboard-en".into()]),
        ])
    }

    fn stamp(revision: u64) -> Value {
        json!({"revision": revision, "input": {
            "bootId":"11111111-1111-4111-8111-111111111111",
            "endpointEpoch":1,"requestId":revision,"injectorPid":42,"injectorStarttime":100
        },"origins":{"42:100:1":revision}})
    }

    fn config(english: Option<u64>, russian: Option<u64>) -> Config {
        let mut revisions = serde_json::Map::new();
        revisions.insert("startup".into(), stamp(5));
        for (id, revision) in [("keyboard-en", english), ("keyboard-ru", russian)] {
            if let Some(revision) = revision {
                revisions.insert(format!("agents/{id}/enabled"), stamp(revision));
            }
        }
        Config::decode(
            &serde_json::to_vec(&json!({
                "schemaVersion":2,"startup":"interface","userRevision":5,"fieldRevisions":revisions,
                "agents": {
                    "keyboard-en":{"enabled":true,"options":{}},
                    "keyboard-ru":{"enabled":true,"options":{}},
                    "i18n-en":{"enabled":true,"options":{}},
                    "i18n-ru":{"enabled":true,"options":{}},
                    "font-cyrillic":{"enabled":true,"options":{}},
                    "unrelated":{"enabled":false,"options":{"mode":"original"}}
                }
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn latest_known_keyboard_choice_wins_without_changing_action_stamps() {
        for (english, russian, winner) in [(5, 3, "keyboard-en"), (3, 5, "keyboard-ru")] {
            let previous = config(Some(english), Some(russian));
            let next = previous.normalize_exclusive(&relations()).unwrap().unwrap();
            assert_eq!(next.user_revision, 5);
            assert_eq!(next.field_revisions, previous.field_revisions);
            assert!(next.agents[winner].enabled);
            let loser = if winner == "keyboard-en" {
                "keyboard-ru"
            } else {
                "keyboard-en"
            };
            assert!(!next.agents[loser].enabled);
            for id in ["i18n-en", "i18n-ru", "font-cyrillic"] {
                assert!(next.agents[id].enabled);
            }
            assert!(!next.advances_user_authority(&previous));
            assert!(next.is_exclusive_normalization_of(&previous, &relations()));
            assert!(next.normalize_exclusive(&relations()).unwrap().is_none());
        }
    }

    #[test]
    fn ambiguous_or_missing_order_disables_both_without_inventing_input() {
        for revisions in [
            (Some(3), Some(3)),
            (Some(3), None),
            (None, Some(3)),
            (None, None),
        ] {
            let previous = config(revisions.0, revisions.1);
            let next = previous.normalize_exclusive(&relations()).unwrap().unwrap();
            assert!(!next.agents["keyboard-en"].enabled);
            assert!(!next.agents["keyboard-ru"].enabled);
            assert_eq!(next.field_revisions, previous.field_revisions);
            assert!(next.is_exclusive_normalization_of(&previous, &relations()));
        }
    }

    #[test]
    fn derived_exception_rejects_other_fields_on_values_stamps_origins_and_catalogs() {
        let previous = config(Some(5), Some(3));
        let expected = previous.normalize_exclusive(&relations()).unwrap().unwrap();
        let mut variants = Vec::new();
        let mut next = expected.clone();
        next.startup = "hidden".into();
        variants.push(next);
        let mut next = expected.clone();
        next.agents.get_mut("font-cyrillic").unwrap().enabled = false;
        variants.push(next);
        let mut next = expected.clone();
        next.agents.get_mut("unrelated").unwrap().enabled = true;
        variants.push(next);
        let mut next = expected.clone();
        next.agents.get_mut("keyboard-ru").unwrap().enabled = true;
        variants.push(next);
        let mut next = expected.clone();
        next.agents
            .get_mut("unrelated")
            .unwrap()
            .options
            .insert("mode".into(), "changed".into());
        variants.push(next);
        let mut next = expected.clone();
        next.field_revisions
            .get_mut("agents/keyboard-ru/enabled")
            .unwrap()
            .revision = 4;
        variants.push(next);
        let mut next = expected.clone();
        next.field_revisions
            .get_mut("agents/keyboard-ru/enabled")
            .unwrap()
            .origins
            .insert("42:100:1".into(), 4);
        variants.push(next);
        let mut next = expected.clone();
        next.user_revision += 1;
        variants.push(next);
        for next in variants {
            assert!(!next.is_exclusive_normalization_of(&previous, &relations()));
        }
        assert!(!expected.is_exclusive_normalization_of(&previous, &BTreeMap::new()));
        let foreign = BTreeMap::from([("i18n-en".into(), vec!["i18n-ru".into()])]);
        assert!(!expected.is_exclusive_normalization_of(&previous, &foreign));
    }

    #[test]
    fn invalid_relations_and_configuration_fail_without_mutation() {
        let previous = config(Some(5), Some(3));
        for invalid in [
            BTreeMap::from([("keyboard-en".into(), vec!["keyboard-en".into()])]),
            BTreeMap::from([(
                "keyboard-en".into(),
                vec!["keyboard-ru".into(), "keyboard-ru".into()],
            )]),
        ] {
            assert!(previous.normalize_exclusive(&invalid).is_err());
        }
        let mut invalid = previous.clone();
        invalid.user_revision = super::super::runtime_owner::MAX_NATIVE_ID;
        assert!(invalid.normalize_exclusive(&relations()).is_err());
        assert!(previous.agents["keyboard-en"].enabled && previous.agents["keyboard-ru"].enabled);
    }
}
