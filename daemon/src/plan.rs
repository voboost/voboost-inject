//! Canonical daemon-owned `agents.json` reader and runtime projection builder.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::catalog::{Activation, AgentCatalog, AgentStatus};
use crate::generation::VerifiedGeneration;
use crate::selection::VehicleProfile;
use crate::strict_json::{StrictValue, ValueLimits};
use crate::{config, log};

#[derive(Debug, Clone)]
pub struct PlanEntry {
    pub id: String,
    pub enabled: bool,
    pub config: Value,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub valid: bool,
    pub schema_version: u32,
    pub generation_id: String,
    pub catalog_sha256: String,
    pub selection_sha256: String,
    pub startup: Startup,
    /// Persisted selection shown in Settings; runtime startup is boot-scoped.
    pub configured_startup: Option<Startup>,
    pub disable_all: bool,
    /// Uninstall preparation projection: distinguishes the ephemeral
    /// uninstall disable-all document (where the resident settings host must
    /// stop mid-session) from the ordinary startup gate (where a live settings
    /// host survives in-process until the next boot, agent-side contract).
    pub uninstall_cleanup: bool,
    pub log_level: LogLevel,
    pub entries: Vec<PlanEntry>,
    /// Runtime-only fail-closed scope; canonical enable choices stay intact.
    pub(crate) runtime_fences: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Startup {
    None,
    Hidden,
    Interface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Info,
    Debug,
}

impl LogLevel {
    pub fn is_debug(self) -> bool {
        self == Self::Debug
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlanDocument {
    schema_version: u32,
    startup: Startup,
    agents: BTreeMap<String, PlanEntryDocument>,
    user_revision: u64,
    field_revisions: BTreeMap<String, voboost_contract::desired::Stamp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanEntryDocument {
    enabled: bool,
    options: StrictValue,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessDocument<'a> {
    schema_version: u32,
    generation_id: &'a str,
    catalog_sha256: &'a str,
    document_generation: i64,
    runtime_facts: &'a VehicleProfile,
    agents: Vec<ProcessAgent<'a>>,
    /* Uninstall cleanup projection: the ephemeral uninstall disable-all
     * document must stop the resident settings host mid-session, unlike the
     * startup gate which keeps a live host until the process restarts. The
     * agent's parser is strict about the exact root field set, so the field
     * is always serialized (false on every ordinary document). */
    uninstall_cleanup: bool,
    /* Always serialized (explicit null when absent): both desired-document
     * paths emit the same shape and AgentEntry's parser treats null and a
     * missing field identically (optJSONObject). */
    profile: Option<SettingsProjection>,
}

#[derive(Serialize)]
struct ProcessAgent<'a> {
    id: &'a str,
    enabled: bool,
    config: Value,
}

#[derive(Serialize)]
struct SettingsProjection {
    startup: Startup,
    #[serde(rename = "configuredStartup")]
    configured_startup: Startup,
    entries: Vec<SettingsProjectionEntry>,
}

#[derive(Serialize)]
struct SettingsProjectionEntry {
    id: String,
    status: &'static str,
    category: String,
    order: i32,
    applicability: &'static str,
    title: crate::catalog::LocaleMap,
    description: crate::catalog::LocaleMap,
    activation: Value,
    disables: Vec<String>,
    options: Vec<Value>,
    values: Value,
}

pub fn read_and_validate(generation: &VerifiedGeneration) -> Plan {
    read_and_validate_at(generation, std::path::Path::new(&config::plan_file()))
}

fn read_and_validate_at(generation: &VerifiedGeneration, path: &std::path::Path) -> Plan {
    let recovery_error = crate::owned_intent::recover(path).err();
    let mut plan = match read_canonical_bounded(path) {
        Ok(bytes) => validate(generation, &bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let plan = Plan::defaults_for(generation);
            if let Err(error) = persist_canonical(&plan) {
                log::err(
                    "plan",
                    &format!("cannot create default agents.json: {error}"),
                );
            }
            // Defaults are not runtime authority if a user save raced initialization.
            read_canonical_bounded(path)
                .map(|bytes| validate(generation, &bytes))
                .unwrap_or_else(|_| Plan::invalid())
        }
        Err(error) => {
            log::err("plan", &format!("agents.json bounded read failed: {error}"));
            Plan::invalid()
        }
    };
    if let Some(error) = recovery_error {
        log::err(
            "plan",
            &format!("FEV input recovery unavailable; fencing only FEV: {error}"),
        );
        // Preserve the fence even with an independently invalid shared plan;
        // runtime last-valid fallback must never restore old FEV ON authority.
        plan.runtime_fences.insert(
            "vehicle-drive-forced-ev".into(),
            error.chars().take(1024).collect(),
        );
    }
    plan
}

/// Read one canonical root-owned plan through a stable directory descriptor.
/// The size check happens before allocation and the file is opened nofollow.
pub(crate) fn read_canonical_bounded(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    #[cfg(not(test))]
    {
        crate::owner_client::read_config(path)
    }
    #[cfg(test)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("agents.json has no parent"))?;
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| std::io::Error::other("agents.json name is invalid"))?;
        crate::secure_fs::Directory::open(parent)?.read_trusted(name, config::MAX_PLAN_BYTES, 0o600)
    }
}

/// Replace the observed configuration without overwriting a concurrent commit.
pub(crate) fn replace_canonical(
    path: &std::path::Path,
    expected: Option<Vec<u8>>,
    bytes: &[u8],
) -> Result<(), String> {
    #[cfg(not(test))]
    {
        crate::owner_client::replace_config(path, expected, bytes).map_err(|e| e.to_string())
    }
    #[cfg(test)]
    {
        let current = match read_canonical_bounded(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        if current != expected {
            return Err("configuration changed".into());
        }
        crate::secure_fs::write_atomic_private(path, bytes, 0o600).map_err(|e| e.to_string())
    }
}

/// Runtime selection is independent from the next-boot Settings choice.
pub fn read_runtime_and_validate(generation: &VerifiedGeneration) -> Plan {
    apply_runtime_startup(
        read_and_validate(generation),
        crate::startup_session::effective,
    )
}

fn apply_runtime_startup(
    mut plan: Plan,
    effective: impl FnOnce(Startup) -> Result<Startup, String>,
) -> Plan {
    if plan.valid {
        match effective(plan.startup) {
            Ok(effective) => {
                plan.configured_startup = Some(plan.startup);
                plan.startup = effective;
                plan.disable_all = effective == Startup::None;
            }
            Err(error) => {
                log::err("plan", &format!("startup session unavailable: {error}"));
                let mut invalid = Plan::invalid();
                invalid.retain_recovery_fences_from(&plan);
                return invalid;
            }
        }
    }
    plan
}

pub fn validate(generation: &VerifiedGeneration, json_bytes: &[u8]) -> Plan {
    if json_bytes.len() > config::MAX_PLAN_BYTES {
        return Plan::invalid();
    }
    if voboost_contract::desired::Config::decode(json_bytes).is_err() {
        return Plan::invalid();
    }
    let parsed: PlanDocument = match serde_json::from_slice(json_bytes) {
        Ok(parsed) => parsed,
        Err(_) => return Plan::invalid(),
    };
    if parsed.schema_version != 2
        || parsed.agents.len() > voboost_contract::desired::MAX_FIELDS
        || parsed.user_revision > i64::MAX as u64
        || parsed.field_revisions.len() > voboost_contract::desired::MAX_FIELDS
        || parsed.field_revisions.iter().any(|(path, stamp)| {
            voboost_contract::desired::Field::from_path(path).is_none()
                || !stamp.valid(parsed.user_revision)
        })
    {
        return Plan::invalid();
    }

    let installed = generation.installed_agent_ids();
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut runtime_fences = BTreeMap::new();
    let defaults = Plan::defaults_for(generation);
    for (id, entry) in parsed.agents {
        if !seen.insert(id.clone()) {
            return Plan::invalid();
        }
        if !installed.contains(id.as_str()) {
            continue;
        }
        let Some(agent) = generation.catalog.find(&id) else {
            continue;
        };
        if entry
            .options
            .validate(ValueLimits {
                max_depth: 16,
                max_total_nodes: 2048,
                max_object_properties: 256,
                max_array_items: 256,
                max_string_bytes: 16_384,
            })
            .is_err()
            || !entry.options.0.is_object()
        {
            return Plan::invalid();
        }
        let config = if serde_json::to_vec(&entry.options.0)
            .map_or(true, |bytes| bytes.len() > config::MAX_CONFIG_BYTES)
            || !valid_config_slice(agent, &entry.options.0)
        {
            runtime_fences.insert(
                id.clone(),
                "desired options unavailable for this catalog".into(),
            );
            defaults
                .entries
                .iter()
                .find(|entry| entry.id == id)
                .map(|entry| entry.config.clone())
                .unwrap_or_else(|| serde_json::json!({}))
        } else {
            entry.options.0
        };
        entries.push(PlanEntry {
            id,
            enabled: entry.enabled,
            config,
        });
    }

    let enabled = entries
        .iter()
        .filter(|entry| entry.enabled)
        .map(|entry| entry.id.clone())
        .collect::<HashSet<_>>();
    if any_enabled_conflict(
        &enabled,
        generation.catalog.agents.iter().filter_map(|agent| {
            agent
                .disables
                .as_ref()
                .map(|disables| (agent.id.as_str(), disables.as_slice()))
        }),
    ) {
        for agent in &generation.catalog.agents {
            if !enabled.contains(&agent.id) {
                continue;
            }
            for other in agent.disables.as_deref().unwrap_or(&[]) {
                if !enabled.contains(other) {
                    continue;
                }
                let revision = |id: &str| {
                    parsed
                        .field_revisions
                        .get(&format!("agents/{id}/enabled"))
                        .map_or(0, |stamp| stamp.revision)
                };
                let left = revision(&agent.id);
                let right = revision(other);
                if left == 0 && right == 0 {
                    return Plan::invalid();
                }
                if left >= right {
                    runtime_fences.insert(other.clone(), "newer conflicting desired choice".into());
                }
                if right >= left {
                    runtime_fences
                        .insert(agent.id.clone(), "newer conflicting desired choice".into());
                }
            }
        }
    }

    Plan {
        valid: true,
        // Runtime desired snapshots retain their independent schema-one ABI.
        schema_version: 1,
        generation_id: generation.id.clone(),
        catalog_sha256: generation.catalog_sha256.clone(),
        selection_sha256: generation.selection_sha256.clone(),
        startup: parsed.startup,
        configured_startup: None,
        disable_all: parsed.startup == Startup::None,
        uninstall_cleanup: false,
        log_level: LogLevel::Debug,
        entries,
        runtime_fences,
    }
}

/// Migrate canonical intent across a verified catalog change. Existing values
/// are preserved only when the new catalog still accepts their exact option
/// shape; new agents receive signed-catalog defaults and removed agents are
/// dropped. Newly introduced conflict relations are resolved in catalog order
/// in the same atomic full-document replacement.
pub fn migrate_canonical(
    previous_generation: &VerifiedGeneration,
    next_generation: &VerifiedGeneration,
) -> Result<Plan, String> {
    let path = std::path::PathBuf::from(config::plan_file());
    let prepared = prepare_canonical_transition(Some(previous_generation), next_generation, &path)?;
    let publication = publish_prepared_canonical(
        &path,
        next_generation,
        prepared.previous_bytes,
        &prepared.next_bytes,
    )?;
    verify_published_canonical(&path, next_generation, &publication)?;
    Ok(validate(
        next_generation,
        &read_canonical_bounded(&path).map_err(|error| error.to_string())?,
    ))
}

#[derive(Debug, Clone)]
pub struct PreparedCanonicalMigration {
    pub previous_bytes: Option<Vec<u8>>,
    pub next_bytes: Vec<u8>,
}

/// Compute both sides of a generation plan transaction without mutating the
/// canonical file. The generation journal persists these exact bounded bytes
/// before the active pointer can change.
pub fn prepare_canonical_transition(
    previous_generation: Option<&VerifiedGeneration>,
    next_generation: &VerifiedGeneration,
    path: &std::path::Path,
) -> Result<PreparedCanonicalMigration, String> {
    let previous_bytes = match previous_generation {
        Some(_) => Some(
            read_canonical_bounded(path).map_err(|error| format!("read agents.json: {error}"))?,
        ),
        None => None,
    };
    let mut migrated = if let (Some(previous_generation), Some(bytes)) =
        (previous_generation, previous_bytes.as_deref())
    {
        let previous = validate(previous_generation, bytes);
        if !previous.valid {
            return Err("existing agents.json is invalid for the previous generation".to_string());
        }
        migrate_plan(previous, next_generation)
    } else {
        Plan::defaults_for(next_generation)
    };
    migrated.generation_id = next_generation.id.clone();
    migrated.catalog_sha256 = next_generation.catalog_sha256.clone();
    migrated.selection_sha256 = next_generation.selection_sha256.clone();
    let next_bytes = canonical_bytes(&migrated)?;
    if !validate(next_generation, &next_bytes).valid {
        return Err("prepared agents.json is invalid for the next generation".to_string());
    }
    Ok(PreparedCanonicalMigration {
        previous_bytes,
        next_bytes,
    })
}

fn migrate_plan(previous: Plan, next_generation: &VerifiedGeneration) -> Plan {
    if !previous.valid {
        return Plan::invalid();
    }

    let mut migrated = Plan::defaults_for(next_generation);
    migrated.startup = previous.startup;
    migrated.disable_all = migrated.startup == Startup::None;
    migrated.uninstall_cleanup = previous.uninstall_cleanup;
    for entry in &mut migrated.entries {
        let Some(old) = previous.entries.iter().find(|old| old.id == entry.id) else {
            continue;
        };
        let Some(agent) = next_generation.catalog.find(&entry.id) else {
            continue;
        };
        if valid_config_slice(agent, &old.config) {
            entry.config = old.config.clone();
        }
        // A config-activated host follows its activation default and the
        // startup gate, not a checkbox intent persisted by an older plan.
        if !agent.is_executor()
            && matches!(agent.activation.as_ref(), Some(Activation::Checkbox { .. }))
        {
            entry.enabled = old.enabled;
        }
    }
    for agent in &next_generation.catalog.agents {
        if !migrated
            .entries
            .iter()
            .any(|entry| entry.id == agent.id && entry.enabled)
        {
            continue;
        }
        let Some(disables) = &agent.disables else {
            continue;
        };
        for disabled in disables {
            if let Some(entry) = migrated
                .entries
                .iter_mut()
                .find(|entry| entry.id == *disabled)
            {
                entry.enabled = false;
            }
        }
    }
    migrated
}

pub struct PublishedCanonical {
    defaults: Vec<u8>,
    receipt: Vec<u8>,
}

fn accepts_canonical_update(
    current: &voboost_contract::desired::Config,
    previous: &voboost_contract::desired::Config,
    generation: &VerifiedGeneration,
) -> bool {
    if current.advances_user_authority(previous) {
        return true;
    }
    let relations = generation
        .catalog
        .agents
        .iter()
        .filter(|agent| {
            !agent.is_executor() && matches!(agent.activation, Some(Activation::Checkbox { .. }))
        })
        .filter_map(|agent| {
            agent
                .disables
                .as_ref()
                .map(|disables| (agent.id.clone(), disables.clone()))
        })
        .collect();
    current.is_exclusive_normalization_of(previous, &relations)
}

pub fn publish_prepared_canonical(
    path: &std::path::Path,
    generation: &VerifiedGeneration,
    expected: Option<Vec<u8>>,
    bytes: &[u8],
) -> Result<PublishedCanonical, String> {
    if bytes.len() > config::MAX_PLAN_BYTES || !validate(generation, bytes).valid {
        return Err("prepared agents.json failed generation validation".to_string());
    }
    let defaults = canonical_bytes(&validate(generation, bytes))?;
    let receipt = reconcile_canonical(path, &defaults)?;
    let current =
        voboost_contract::desired::Config::decode(&receipt).map_err(|error| error.to_string())?;
    current
        .verify_defaults(&defaults)
        .map_err(|error| error.to_string())?;
    if let Some(expected) = expected {
        let observed = voboost_contract::desired::Config::decode(&expected)
            .map_err(|error| error.to_string())?;
        if !accepts_canonical_update(&current, &observed, generation) {
            return Err("product publication regressed observed user authority".into());
        }
    }
    Ok(PublishedCanonical { defaults, receipt })
}

pub fn verify_published_canonical(
    path: &std::path::Path,
    generation: &VerifiedGeneration,
    publication: &PublishedCanonical,
) -> Result<(), String> {
    let bytes = read_canonical_bounded(path).map_err(|error| error.to_string())?;
    let current =
        voboost_contract::desired::Config::decode(&bytes).map_err(|error| error.to_string())?;
    let receipt = voboost_contract::desired::Config::decode(&publication.receipt)
        .map_err(|error| error.to_string())?;
    current
        .verify_defaults(&publication.defaults)
        .map_err(|error| error.to_string())?;
    if !accepts_canonical_update(&current, &receipt, generation)
        || !validate(generation, &bytes).valid
    {
        return Err("published user authority or effective projection differs".into());
    }
    Ok(())
}

fn reconcile_canonical(path: &std::path::Path, defaults: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(not(test))]
    {
        let _ = path;
        crate::owner_client::reconcile_desired(defaults).map_err(|error| error.to_string())
    }
    #[cfg(test)]
    {
        let observed = match read_canonical_bounded(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.to_string()),
        };
        let previous = observed
            .as_deref()
            .map(voboost_contract::desired::Config::decode)
            .transpose()
            .map_err(|error| error.to_string())?;
        let bytes = match &previous {
            Some(current) => current.reconcile(defaults),
            None => voboost_contract::desired::Config::initial(defaults),
        }
        .map_err(|error| error.to_string())?;
        let next =
            voboost_contract::desired::Config::decode(&bytes).map_err(|error| error.to_string())?;
        next.verify_defaults(defaults)
            .map_err(|error| error.to_string())?;
        if previous
            .as_ref()
            .is_some_and(|previous| !next.preserves_user_authority(previous))
        {
            return Err("product reconciliation changed user authority".into());
        }
        replace_canonical(path, observed, &bytes)?;
        Ok(bytes)
    }
}

pub fn canonical_identity(bytes: &[u8]) -> String {
    crate::trust::sha256_bytes(bytes)
}

fn any_enabled_conflict<'a, I>(enabled: &HashSet<String>, relations: I) -> bool
where
    I: IntoIterator<Item = (&'a str, &'a [String])>,
{
    relations.into_iter().any(|(id, disables)| {
        enabled.contains(id) && disables.iter().any(|disabled| enabled.contains(disabled))
    })
}

fn valid_config_slice(agent: &crate::catalog::CatalogAgent, config: &Value) -> bool {
    if agent.id == "launcher" {
        return crate::launcher_config::valid_options(config);
    }
    let Some(object) = config.as_object() else {
        return false;
    };
    let options = agent.options.as_deref().unwrap_or(&[]);
    if object.len() != options.len() {
        return false;
    }
    options.iter().all(|option| {
        let Some(value) = object.get(&option.key).and_then(Value::as_str) else {
            return false;
        };
        option
            .values
            .iter()
            .any(|candidate| candidate.value == value)
    })
}

impl Plan {
    pub(crate) fn retain_recovery_fences_from(&mut self, invalid: &Self) {
        self.runtime_fences.extend(invalid.runtime_fences.clone());
    }

    /// Build the uninstall cleanup projection without changing canonical user
    /// intent on disk. A crash before prepared publication therefore restarts
    /// from the exact prior plan instead of a durable disable-all replacement.
    pub fn disabled_for_uninstall(&self) -> Self {
        let mut disabled = self.clone();
        disabled.startup = Startup::None;
        disabled.disable_all = true;
        disabled.uninstall_cleanup = true;
        for entry in &mut disabled.entries {
            entry.enabled = false;
        }
        disabled
    }

    fn effective_enabled(&self, entry: &PlanEntry) -> bool {
        !self.runtime_fences.contains_key(&entry.id)
            && self.startup != Startup::None
            && entry.enabled
            && (!is_settings_host(&entry.id) || self.startup == Startup::Interface)
    }

    fn resident_enabled(
        &self,
        entry: &PlanEntry,
        settings_loaded: bool,
        admitted_ids: &[String],
    ) -> bool {
        if self.runtime_fences.contains_key(&entry.id) {
            return false;
        }
        self.effective_enabled(entry)
            || (settings_loaded && !self.uninstall_cleanup && is_settings_host(&entry.id))
            || (self.startup == Startup::None
                && !self.uninstall_cleanup
                && entry.enabled
                && !is_settings_host(&entry.id)
                && admitted_ids.contains(&entry.id))
    }
    fn invalid() -> Self {
        Self {
            valid: false,
            schema_version: 0,
            generation_id: String::new(),
            catalog_sha256: String::new(),
            selection_sha256: String::new(),
            startup: Startup::None,
            configured_startup: None,
            disable_all: true,
            uninstall_cleanup: false,
            log_level: LogLevel::Debug,
            entries: Vec::new(),
            runtime_fences: BTreeMap::new(),
        }
    }

    pub fn valid_empty_for(generation: &VerifiedGeneration) -> Self {
        Self {
            valid: true,
            schema_version: 1,
            generation_id: generation.id.clone(),
            catalog_sha256: generation.catalog_sha256.clone(),
            selection_sha256: generation.selection_sha256.clone(),
            startup: Startup::None,
            configured_startup: None,
            disable_all: false,
            uninstall_cleanup: false,
            log_level: LogLevel::Debug,
            entries: Vec::new(),
            runtime_fences: BTreeMap::new(),
        }
    }

    pub fn defaults_for(generation: &VerifiedGeneration) -> Self {
        let installed = generation.installed_agent_ids();
        let entries = generation
            .catalog
            .agents
            .iter()
            .filter(|agent| installed.contains(agent.id.as_str()))
            // Executors are not plan-gated: no plan entry, they always run in
            // their target processes.
            .filter(|agent| !agent.is_executor())
            .map(|agent| {
                let activation = agent.activation.as_ref().expect("validated catalog");
                let enabled = matches!(activation,
                    Activation::Config { key, value } if key == "voboost-startup" && value == "interface")
                    || matches!(activation, Activation::Checkbox { default: true })
                    // Technical agents are always enabled: like a config agent
                    // whose condition is permanently satisfied. The global
                    // disable-all (startup none) gate still applies.
                    || matches!(activation, Activation::Technical {});
                let config = if agent.id == "launcher" { crate::launcher_config::default_options() } else { Value::Object(
                    agent
                        .options
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .map(|option| (option.key.clone(), Value::String(option.default.clone())))
                        .collect(),
                ) };
                PlanEntry {
                    id: agent.id.clone(),
                    enabled,
                    config,
                }
            })
            .collect();
        Self {
            valid: true,
            schema_version: 1,
            generation_id: generation.id.clone(),
            catalog_sha256: generation.catalog_sha256.clone(),
            selection_sha256: generation.selection_sha256.clone(),
            startup: Startup::Interface,
            configured_startup: None,
            disable_all: false,
            uninstall_cleanup: false,
            log_level: LogLevel::Debug,
            entries,
            runtime_fences: BTreeMap::new(),
        }
    }

    pub fn config_for(&self, id: &str) -> &Value {
        self.entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| &entry.config)
            .unwrap_or(&Value::Null)
    }

    pub fn enabled_ids_for_process(&self, process: &str, catalog: &AgentCatalog) -> Vec<String> {
        self.enabled_ids_for_resident(process, catalog, false)
    }

    pub fn enabled_ids_for_resident(
        &self,
        process: &str,
        catalog: &AgentCatalog,
        settings_loaded: bool,
    ) -> Vec<String> {
        self.enabled_ids_for_admitted(process, catalog, settings_loaded, &[])
    }

    pub fn enabled_ids_for_admitted(
        &self,
        process: &str,
        catalog: &AgentCatalog,
        settings_loaded: bool,
        admitted_ids: &[String],
    ) -> Vec<String> {
        self.entries
            .iter()
            .filter(|entry| {
                self.resident_enabled(entry, settings_loaded, admitted_ids)
                    && catalog.has_target(&entry.id, process)
            })
            .map(|entry| entry.id.clone())
            .collect()
    }

    pub(crate) fn startup_priority(&self, process: &str, catalog: &AgentCatalog) -> u8 {
        let enabled = self.enabled_ids_for_process(process, catalog);
        catalog
            .agents
            .iter()
            .filter(|agent| {
                (agent.is_executor() || enabled.contains(&agent.id))
                    && catalog.has_target(&agent.id, process)
            })
            .map(|agent| {
                agent
                    .startup_priority
                    .unwrap_or(crate::catalog::StartupPriority::Applications) as u8
            })
            .min()
            .unwrap_or(crate::catalog::StartupPriority::Background as u8)
    }

    pub fn desired_agents_for_process(&self, process: &str, catalog: &AgentCatalog) -> Value {
        self.desired_agents_for_admitted(process, catalog, false, &[])
    }

    fn desired_agents_for_admitted(
        &self,
        process: &str,
        catalog: &AgentCatalog,
        settings_loaded: bool,
        admitted_ids: &[String],
    ) -> Value {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let agent = catalog.find(&entry.id)?;
                (self.resident_enabled(entry, settings_loaded, admitted_ids)
                    && agent.targets.iter().any(|target| target.process == process))
                .then_some((entry, agent))
            })
            .collect();
        entries.sort_by_key(|(_, agent)| {
            agent
                .startup_priority
                .unwrap_or(crate::catalog::StartupPriority::Applications)
        });
        Value::Array(
            entries
                .into_iter()
                .map(|(entry, agent)| {
                    serde_json::json!({
                        "id": entry.id,
                        "enabled": true,
                        "config": self.compatible_config_for_process(entry, agent, process),
                    })
                })
                .collect(),
        )
    }

    /// Stable semantic fingerprint of the complete process control surface.
    /// It intentionally omits `documentGeneration`, while retaining the
    /// resident generation identity, the verified immutable runtime facts,
    /// desired agents and the complete Settings projection. Thus any
    /// externally committed startup/checkbox or option change
    /// allocates a new live document for Settings even when the changed agent
    /// runs in another process. Facts are sourced only from the verified
    /// generation selection receipt; agent config is never an authority for
    /// contract selection.
    pub fn desired_semantics_for_process(
        &self,
        process: &str,
        generation: &VerifiedGeneration,
    ) -> Result<String, String> {
        self.desired_semantics_for_resident(process, generation, false)
    }

    pub fn desired_semantics_for_resident(
        &self,
        process: &str,
        generation: &VerifiedGeneration,
        settings_loaded: bool,
    ) -> Result<String, String> {
        self.desired_semantics_for_admitted(process, generation, settings_loaded, &[])
    }

    pub fn desired_semantics_for_admitted(
        &self,
        process: &str,
        generation: &VerifiedGeneration,
        settings_loaded: bool,
        admitted_ids: &[String],
    ) -> Result<String, String> {
        let settings_process = generation
            .catalog
            .agents
            .iter()
            .filter(|agent| is_settings_host(&agent.id))
            .any(|agent| {
                self.entries.iter().any(|entry| {
                    entry.id == agent.id
                        && self.resident_enabled(entry, settings_loaded, admitted_ids)
                }) && agent.targets.iter().any(|target| target.process == process)
            });
        serde_json::to_string(&serde_json::json!({
            "generationId": generation.id,
            "catalogSha256": generation.catalog_sha256,
            "runtimeFacts": generation.selection.receipt.facts,
            "agents": self.desired_agents_for_admitted(process, &generation.catalog, settings_loaded, admitted_ids),
            "profile": settings_process.then(|| self.profile(generation)),
        }))
        .map_err(|error| format!("serialize desired process semantics: {error}"))
    }

    pub fn desired_document_for_process(
        &self,
        process: &str,
        generation: &VerifiedGeneration,
        document_generation: i64,
    ) -> Result<String, String> {
        self.desired_document_for_resident(process, generation, document_generation, false)
    }

    pub fn desired_document_for_resident(
        &self,
        process: &str,
        generation: &VerifiedGeneration,
        document_generation: i64,
        settings_loaded: bool,
    ) -> Result<String, String> {
        self.desired_document_for_admitted(
            process,
            generation,
            document_generation,
            settings_loaded,
            &[],
        )
    }

    pub fn desired_document_for_admitted(
        &self,
        process: &str,
        generation: &VerifiedGeneration,
        document_generation: i64,
        settings_loaded: bool,
        admitted_ids: &[String],
    ) -> Result<String, String> {
        let mut agents: Vec<_> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let agent = generation.catalog.find(&entry.id)?;
                (self.resident_enabled(entry, settings_loaded, admitted_ids)
                    && agent.targets.iter().any(|target| target.process == process))
                .then(|| ProcessAgent {
                    id: &entry.id,
                    enabled: true,
                    config: self.compatible_config_for_process(entry, agent, process),
                })
            })
            .collect();
        agents.sort_by_key(|entry| {
            generation
                .catalog
                .find(entry.id)
                .and_then(|agent| agent.startup_priority)
                .unwrap_or(crate::catalog::StartupPriority::Applications)
        });
        let settings_process = generation
            .catalog
            .agents
            .iter()
            .filter(|agent| is_settings_host(&agent.id))
            .any(|agent| {
                self.entries.iter().any(|entry| {
                    entry.id == agent.id
                        && self.resident_enabled(entry, settings_loaded, admitted_ids)
                }) && agent.targets.iter().any(|target| target.process == process)
            });
        serde_json::to_string(&ProcessDocument {
            schema_version: 1,
            generation_id: &generation.id,
            catalog_sha256: &generation.catalog_sha256,
            document_generation,
            runtime_facts: &generation.selection.receipt.facts,
            agents,
            uninstall_cleanup: self.uninstall_cleanup,
            profile: settings_process.then(|| self.profile(generation)),
        })
        .map_err(|error| format!("serialize desired process document: {error}"))
    }

    fn profile(&self, generation: &VerifiedGeneration) -> SettingsProjection {
        let results: BTreeMap<_, _> = generation
            .selection
            .receipt
            .agents
            .iter()
            .map(|entry| (entry.id.as_str(), entry.result))
            .collect();
        let entries = generation
            .catalog
            .agents
            .iter()
            .filter(|agent| !is_settings_host(&agent.id))
            // Technical agents are never user-visible toggles: no Settings row.
            .filter(|agent| !agent.is_executor())
            .filter(|agent| !matches!(agent.activation.as_ref(), Some(Activation::Technical {})))
            .filter_map(|agent| {
                let applicability = match *results.get(agent.id.as_str())? {
                    crate::selection::ApplicabilityResult::Supported => "supported",
                    crate::selection::ApplicabilityResult::Unknown => "unknown",
                    crate::selection::ApplicabilityResult::Unsupported => return None,
                };
                let plan_entry = self.entries.iter().find(|entry| entry.id == agent.id);
                let mut values = Map::new();
                values.insert(
                    "enabled".to_string(),
                    Value::Bool(plan_entry.is_some_and(|entry| entry.enabled)),
                );
                // UI values contain catalog enum options, never derived runtime configuration.
                for option in agent.options.as_deref().unwrap_or(&[]) {
                    let value = plan_entry
                        .and_then(|entry| entry.config.get(&option.key))
                        .and_then(Value::as_str)
                        .filter(|current| {
                            option
                                .values
                                .iter()
                                .any(|candidate| candidate.value == *current)
                        })
                        .unwrap_or(&option.default);
                    values.insert(option.key.clone(), Value::String(value.to_string()));
                }
                Some(SettingsProjectionEntry {
                    id: agent.id.clone(),
                    status: match agent.status {
                        Some(AgentStatus::Stable) => "stable",
                        _ => "unstable",
                    },
                    category: agent.category.clone().unwrap_or_default(),
                    order: agent.order.unwrap_or(i32::MAX),
                    applicability,
                    title: agent.title.clone().unwrap_or(crate::catalog::LocaleMap {
                        en: String::new(),
                        ru: String::new(),
                        zh: None,
                    }),
                    description: agent
                        .description
                        .clone()
                        .unwrap_or(crate::catalog::LocaleMap {
                            en: String::new(),
                            ru: String::new(),
                            zh: None,
                        }),
                    activation: activation_json(agent.activation.as_ref().unwrap_or(
                        // Executors never reach the Settings projection.
                        &Activation::Technical {},
                    )),
                    disables: agent.disables.clone().unwrap_or_default(),
                    options: agent
                        .options
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .map(|option| {
                            serde_json::json!({
                                "key": option.key,
                                "type": option.option_type,
                                "default": option.default,
                                "values": option.values.iter().map(|value| serde_json::json!({
                                    "value": value.value,
                                    "title": value.title,
                                })).collect::<Vec<_>>()
                            })
                        })
                        .collect(),
                    values: Value::Object(values),
                })
            })
            .collect();
        SettingsProjection {
            startup: self.startup,
            configured_startup: self.configured_startup.unwrap_or(self.startup),
            entries,
        }
    }

    fn compatible_config_for_process(
        &self,
        entry: &PlanEntry,
        agent: &crate::catalog::CatalogAgent,
        process: &str,
    ) -> Value {
        if matches!(agent.id.as_str(), "i18n-ru" | "i18n-en") {
            return resource_config_projection(
                self.effective_enabled(entry),
                crate::i18n_resources::configuration_for_agent_generation(
                    &agent.id,
                    &self.generation_id,
                    &self.catalog_sha256,
                    process,
                ),
                agent.id == "i18n-en" && process == voboost_shared::owned_overlay::OWNER,
            );
        }
        let mut config = self.compatible_config(entry, agent);
        if agent.id == "launcher" && process == "system_server" {
            let russian_enabled = self
                .entries
                .iter()
                .any(|candidate| candidate.id == "i18n-ru" && self.effective_enabled(candidate));
            config
                .as_object_mut()
                .expect("derived launcher configuration is an object")
                .insert("i18nRuEnabled".into(), Value::Bool(russian_enabled));
        }
        config
    }
    fn compatible_config(&self, entry: &PlanEntry, agent: &crate::catalog::CatalogAgent) -> Value {
        if agent.id == "launcher" {
            return crate::launcher_config::derived_with_original_bindings(
                &entry.config,
                entry.enabled,
                &self.generation_id,
                &self.catalog_sha256,
            );
        }
        Value::Object(
            agent
                .options
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|option| {
                    let value = entry
                        .config
                        .get(&option.key)
                        .and_then(Value::as_str)
                        .filter(|current| {
                            option
                                .values
                                .iter()
                                .any(|candidate| candidate.value == *current)
                        })
                        .unwrap_or(&option.default);
                    (option.key.clone(), Value::String(value.to_string()))
                })
                .collect(),
        )
    }
}

fn persist_canonical(plan: &Plan) -> Result<(), String> {
    let bytes = canonical_bytes(plan)?;
    let path = std::path::PathBuf::from(config::plan_file());
    reconcile_canonical(&path, &bytes).map(|_| ())
}

fn canonical_bytes(plan: &Plan) -> Result<Vec<u8>, String> {
    let agents: BTreeMap<_, _> = plan
        .entries
        .iter()
        .map(|entry| {
            (
                entry.id.clone(),
                serde_json::json!({"enabled":entry.enabled,"options":entry.config}),
            )
        })
        .collect();
    let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schemaVersion": 2,
        "userRevision": 0,
        "fieldRevisions": {},
        "startup": plan.configured_startup.unwrap_or(plan.startup),
        "agents": agents,
    }))
    .map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn activation_json(value: &Activation) -> Value {
    match value {
        Activation::Checkbox { default } => {
            serde_json::json!({"type":"checkbox","default":default})
        }
        Activation::Config { key, value } => {
            serde_json::json!({"type":"config","key":key,"value":value})
        }
        // Unreachable in the projection (technical agents are filtered out),
        // kept exhaustive for future callers.
        Activation::Technical {} => {
            serde_json::json!({"type":"technical"})
        }
    }
}

pub(crate) fn is_settings_host(id: &str) -> bool {
    matches!(id, "settings")
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    pub(crate) fn startup_session_unavailable(plan: super::Plan) -> super::Plan {
        super::apply_runtime_startup(plan, |_| Err("owner exchange deadline".into()))
    }

    use super::*;

    pub(crate) fn vehicle_fault_generation() -> VerifiedGeneration {
        let mut generation = settings_generation();
        let prototype = generation.catalog.agents[1].clone();
        generation.catalog.agents.truncate(1);
        for id in [
            "vehicle-drive-forced-ev",
            "vehicle-drive-pedestrian-warning",
            "font-cyrillic",
            "keyboard-en",
            "keyboard-ru-en",
            "launcher-apps",
            "peer-six",
        ] {
            let mut peer = prototype.clone();
            peer.id = id.into();
            peer.targets[0].file = format!("agent-{id}.dex");
            if id == "vehicle-drive-forced-ev" {
                peer.options = Some(vec![serde_json::from_value(serde_json::json!({
                    "key":"intent", "type":"enum", "default":"on",
                    "values":[
                        {"value":"on","title":{"en":"On","ru":"On"}},
                        {"value":"off","title":{"en":"Off","ru":"Off"}}
                    ]
                }))
                .unwrap()]);
                for process in ["com.qinggan.app.launcher", "com.qinggan.app.vehiclesetting"] {
                    let mut target = peer.targets[0].clone();
                    target.process = process.into();
                    peer.targets.push(target);
                }
            }
            generation.catalog.agents.push(peer);
        }
        generation.selection.selected_agent_ids = generation
            .catalog
            .agents
            .iter()
            .map(|agent| agent.id.clone())
            .collect();
        generation
    }

    pub(crate) fn settings_generation() -> VerifiedGeneration {
        let sha = "a".repeat(64);
        let value: serde_json::Value = serde_json::from_str(&format!(
            r#"{{"schemaVersion":2,"supportedAbis":["arm64-v8a"],"agentEntryAbi":{{"schemaVersion":1,"sha256":"{}"}},"core":{{"file":"agent-common.dex","size":1,"sha256":"{sha}"}},"agents":[{{"id":"settings","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.app.setting","file":"agent-settings.dex","size":1,"sha256":"{sha}","entryClass":"ru.voboost.agents.settings.SettingsAgent","boot":false}}],"status":"unstable","category":"interface","order":0,"activation":{{"type":"config","key":"voboost-startup","value":"interface"}},"disables":[],"options":[],"title":{{"en":"Settings","ru":"Settings"}},"description":{{"en":"Settings","ru":"Settings"}},"applicability":{{"chip":["8155"],"vehicle":["free"],"android":[9],"powertrain":["hybrid"],"market":["china"]}}}},{{"id":"forced-ev","targets":[{{"platform":"android","domain":"android","entryAbi":"android-java-v1","process":"com.qinggan.systemservice","file":"agent-forced-ev.dex","size":1,"sha256":"{sha}","entryClass":"ru.voboost.agents.forcedev.ForcedEvAgent","boot":false}}],"status":"unstable","category":"vehicle","order":1,"activation":{{"type":"checkbox","default":false}},"disables":[],"options":[],"title":{{"en":"Forced EV","ru":"Forced EV"}},"description":{{"en":"Forced EV","ru":"Forced EV"}},"applicability":{{"chip":["8155"],"vehicle":["free"],"android":[9],"powertrain":["hybrid"],"market":["china"]}}}}]}}"#,
            crate::catalog::AGENT_ENTRY_ABI_SHA256,
        ))
        .unwrap();
        let typed: AgentCatalog = serde_json::from_value(value).unwrap();
        let mut bytes = serde_json::to_vec(&typed).unwrap();
        bytes.push(b'\n');
        let catalog = AgentCatalog::parse(&bytes).unwrap();
        let facts = crate::selection::VehicleProfileDocument::parse_canonical(
            br#"{"schemaVersion":1,"facts":{"chip":{"value":"8155"},"vehicle":{"value":"free"},"android":{"value":9},"powertrain":{"value":"hybrid"},"market":{"value":"china"}}}"#,
        )
        .unwrap()
        .facts;
        let catalog_sha256 = "b".repeat(64);
        let selection =
            crate::selection::SelectionReceipt::compute(&catalog, &catalog_sha256, &facts).unwrap();
        VerifiedGeneration {
            id: "generation-r1".to_string(),
            catalog_sha256,
            selection_sha256: selection.sha256.clone(),
            directory: std::path::PathBuf::new(),
            catalog,
            selection,
            files: Vec::new(),
        }
    }
}

fn resource_config_projection(
    enabled: bool,
    admission: Option<Value>,
    handler_only: bool,
) -> Value {
    match (enabled, admission) {
        (true, Some(configuration)) => configuration,
        (true, None) if handler_only => serde_json::json!({"handlerOnly": true}),
        _ => serde_json::json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixtures::settings_generation;
    use super::*;

    #[test]
    fn canonical_keyboard_normalization_reaches_only_one_java_agent() {
        let mut generation = settings_generation();
        let prototype = generation.catalog.agents[1].clone();
        generation.catalog.agents.truncate(1);
        for (id, other) in [
            ("keyboard-en", "keyboard-ru"),
            ("keyboard-ru", "keyboard-en"),
        ] {
            let mut agent = prototype.clone();
            agent.id = id.into();
            agent.disables = Some(vec![other.into()]);
            agent.targets[0].process = "com.qinggan.app.qgime".into();
            generation.catalog.agents.push(agent);
        }
        generation.selection.selected_agent_ids = generation
            .catalog
            .agents
            .iter()
            .map(|agent| agent.id.clone())
            .collect();
        let stamp = |revision| {
            serde_json::json!({"revision":revision,"input":{
            "bootId":"11111111-1111-4111-8111-111111111111","endpointEpoch":1,"requestId":revision,"injectorPid":42,"injectorStarttime":100
        },"origins":{"42:100:1":revision}})
        };
        let previous = voboost_contract::desired::Config::decode(&serde_json::to_vec(&serde_json::json!({
            "schemaVersion":2,"startup":"interface","userRevision":5,
            "fieldRevisions":{"agents/keyboard-en/enabled":stamp(5),"agents/keyboard-ru/enabled":stamp(3)},
            "agents":{"keyboard-en":{"enabled":true,"options":{}},"keyboard-ru":{"enabled":true,"options":{}}}
        })).unwrap()).unwrap();
        let relations = BTreeMap::from([
            ("keyboard-en".into(), vec!["keyboard-ru".into()]),
            ("keyboard-ru".into(), vec!["keyboard-en".into()]),
        ]);
        let next = previous.normalize_exclusive(&relations).unwrap().unwrap();
        assert!(accepts_canonical_update(&next, &previous, &generation));
        let plan = validate(&generation, &serde_json::to_vec(&next).unwrap());
        assert!(plan.valid);
        let agents = plan.desired_agents_for_process("com.qinggan.app.qgime", &generation.catalog);
        assert_eq!(agents.as_array().unwrap().len(), 1);
        assert_eq!(agents[0]["id"], "keyboard-en");
        assert_eq!(next.user_revision, previous.user_revision);
        let old_document = serde_json::json!([
            {"id":"keyboard-en","config":{}}, {"id":"keyboard-ru","config":{}}
        ])
        .to_string();
        let old_runtime = crate::runtime::test_support::DesiredDocumentState::new(&old_document, 7);
        assert_eq!(
            crate::runtime::test_support::next_desired_generation(
                Some(&old_runtime),
                &agents.to_string(),
                0
            )
            .unwrap(),
            Some(8)
        );
        let root = tempfile::Builder::new()
            .prefix(".keyboard-normalization-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.path().join("agents.json");
        crate::secure_fs::write_atomic_private(&path, &serde_json::to_vec(&next).unwrap(), 0o600)
            .unwrap();
        let publication = publish_prepared_canonical(
            &path,
            &generation,
            Some(serde_json::to_vec(&previous).unwrap()),
            &serde_json::to_vec(&next).unwrap(),
        )
        .unwrap();
        verify_published_canonical(&path, &generation, &publication).unwrap();
        let mut foreign = generation.clone();
        for agent in &mut foreign.catalog.agents {
            agent.disables = None;
        }
        assert!(!accepts_canonical_update(&next, &previous, &foreign));
    }

    #[test]
    fn i18n_root_admission_is_derived_never_user_config() {
        let observed =
            serde_json::json!({"resourceAdmission":{"generation":"a".repeat(64),"enabled":true}});
        assert_eq!(
            resource_config_projection(true, Some(observed.clone()), false),
            observed.clone()
        );
        assert_eq!(
            resource_config_projection(true, None, false),
            serde_json::json!({})
        );
        assert_eq!(
            resource_config_projection(false, Some(observed), false),
            serde_json::json!({})
        );
    }
    #[test]
    fn english_settings_gets_handler_only_without_resource_admission() {
        let generation = settings_generation();
        let mut english = generation.catalog.agents[1].clone();
        english.id = "i18n-en".into();
        let mut plan = Plan::defaults_for(&generation);
        plan.startup = Startup::Interface;
        let mut entry = plan.entries[0].clone();
        entry.id = english.id.clone();
        entry.enabled = true;
        entry.config = serde_json::json!({"resourceAdmission": {"enabled": true}});
        assert_eq!(
            plan.compatible_config_for_process(
                &entry,
                &english,
                voboost_shared::owned_overlay::OWNER
            ),
            serde_json::json!({"handlerOnly": true})
        );
        assert_eq!(
            plan.compatible_config_for_process(&entry, &english, "com.qinggan.app.launcher"),
            serde_json::json!({})
        );
        entry.enabled = false;
        assert_eq!(
            plan.compatible_config_for_process(
                &entry,
                &english,
                voboost_shared::owned_overlay::OWNER
            ),
            serde_json::json!({})
        );
    }
    #[test]
    fn launcher_window_locale_flag_is_derived_and_changes_desired_semantics() {
        let mut generation = settings_generation();
        let launcher = &mut generation.catalog.agents[1];
        launcher.id = "launcher".into();
        launcher.targets[0].process = "system_server".into();
        let mut language = launcher.clone();
        language.id = "i18n-ru".into();
        language.targets[0].process = "com.qinggan.app.setting".into();
        let mut english = language.clone();
        english.id = "i18n-en".into();
        generation.catalog.agents.push(language);
        generation.catalog.agents.push(english);
        generation.selection.selected_agent_ids = generation
            .catalog
            .agents
            .iter()
            .map(|agent| agent.id.clone())
            .collect();
        let mut plan = Plan::defaults_for(&generation);
        plan.startup = Startup::Interface;
        plan.entries
            .iter_mut()
            .find(|entry| entry.id == "launcher")
            .unwrap()
            .enabled = true;
        let config = |plan: &Plan| {
            let document: Value = serde_json::from_str(
                &plan
                    .desired_document_for_process("system_server", &generation, 1)
                    .unwrap(),
            )
            .unwrap();
            document["agents"][0]["config"].clone()
        };
        let semantics = |plan: &Plan| {
            plan.desired_semantics_for_admitted(
                "system_server",
                &generation,
                false,
                &["launcher".into()],
            )
            .unwrap()
        };
        let baseline = config(&plan);
        assert_eq!(baseline["i18nRuEnabled"], false);
        let disabled = semantics(&plan);
        for (russian, english) in [(false, false), (true, false), (false, true), (true, true)] {
            for entry in &mut plan.entries {
                if entry.id == "i18n-ru" {
                    entry.enabled = russian;
                } else if entry.id == "i18n-en" {
                    entry.enabled = english;
                }
            }
            assert_eq!(config(&plan)["i18nRuEnabled"], russian);
            assert_eq!(semantics(&plan) == disabled, !russian);
        }
        assert!(!canonical_bytes(&plan)
            .unwrap()
            .windows(b"i18nRuEnabled".len())
            .any(|part| part == b"i18nRuEnabled"));
        plan.runtime_fences
            .insert("i18n-ru".into(), "unavailable".into());
        assert_eq!(config(&plan), baseline);
        assert_eq!(semantics(&plan), disabled);
        plan.runtime_fences.clear();
        plan.startup = Startup::Hidden;
        assert_eq!(config(&plan)["i18nRuEnabled"], true);
        let launcher = generation
            .catalog
            .agents
            .iter()
            .find(|agent| agent.id == "launcher")
            .unwrap();
        let entry = plan
            .entries
            .iter()
            .find(|entry| entry.id == "launcher")
            .unwrap();
        assert!(!plan
            .compatible_config_for_process(entry, launcher, "com.qinggan.app.launcher")
            .as_object()
            .unwrap()
            .contains_key("i18nRuEnabled"));
        plan.startup = Startup::None;
        let document: Value = serde_json::from_str(
            &plan
                .desired_document_for_admitted(
                    "system_server",
                    &generation,
                    2,
                    false,
                    &["launcher".into()],
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(document["agents"][0]["config"]["i18nRuEnabled"], false);
        plan.startup = Startup::Interface;
        plan.entries
            .retain(|entry| entry.id != "i18n-ru" && entry.id != "i18n-en");
        assert_eq!(config(&plan), baseline);
    }

    #[test]
    fn wal_fault_fences_fev_without_blocking_six_other_agents_or_settings() {
        use std::os::unix::fs::PermissionsExt;
        let generation = test_fixtures::vehicle_fault_generation();
        let fixture = tempfile::tempdir().unwrap();
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = fixture.path().join("agents.json");
        let mut canonical = Plan::defaults_for(&generation);
        for entry in &mut canonical.entries {
            entry.enabled = true;
        }
        let bytes = canonical_bytes(&canonical).unwrap();
        crate::secure_fs::write_atomic_private(&path, &bytes, 0o600).unwrap();
        let state =
            crate::agent_state::open_state_directory(&fixture.path().join("state"), true).unwrap();
        state
            .write_atomic(
                "vehicle-drive-forced-ev_forced-ev-armed.json",
                b"true",
                0o600,
            )
            .unwrap();
        state
            .write_atomic(
                ".vehicle-drive-forced-ev_intent.journal.json",
                b"{invalid",
                0o600,
            )
            .unwrap();
        let mut fenced = read_and_validate_at(&generation, &path);
        assert!(fenced.valid);
        assert!(!fenced.disable_all);
        assert!(fenced.entries.iter().all(|entry| entry.enabled));
        assert_eq!(fenced.runtime_fences.len(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            state
                .read_trusted("vehicle-drive-forced-ev_forced-ev-armed.json", 16, 0o600)
                .unwrap(),
            b"true"
        );
        let admitted = canonical
            .entries
            .iter()
            .map(|entry| entry.id.clone())
            .collect::<Vec<_>>();
        for startup in [Startup::Interface, Startup::Hidden, Startup::None] {
            fenced.startup = startup;
            for process in generation.catalog.processes() {
                let ids =
                    fenced.enabled_ids_for_admitted(&process, &generation.catalog, true, &admitted);
                assert!(!ids.iter().any(|id| id == "vehicle-drive-forced-ev"));
                let desired: Value = serde_json::from_str(
                    &fenced
                        .desired_document_for_admitted(&process, &generation, 2, true, &admitted)
                        .unwrap(),
                )
                .unwrap();
                assert!(desired["agents"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|agent| agent["id"] != "vehicle-drive-forced-ev"));
            }
        }
        fenced.startup = Startup::Interface;
        let peers =
            fenced.enabled_ids_for_process("com.qinggan.systemservice", &generation.catalog);
        assert_eq!(peers.len(), 6);
        assert_eq!(
            fenced.enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog),
            ["settings"]
        );
        // A valid auxiliary record still has no authority to manufacture OFF.
        state.write_atomic(".vehicle-drive-forced-ev_intent.journal.json",
            br#"{"schemaVersion":1,"bootId":"11111111-1111-4111-8111-111111111111","captureNs":10,"pid":10,"requestId":1,"choice":"off","pending":true}"#, 0o600).unwrap();
        let pending = read_and_validate_at(&generation, &path);
        assert!(pending.valid);
        assert!(pending
            .runtime_fences
            .contains_key("vehicle-drive-forced-ev"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let auxiliary = state
            .read_trusted(".vehicle-drive-forced-ev_intent.journal.json", 4096, 0o600)
            .unwrap();
        // Only an atomic user save clears this ambiguity. Auxiliary bytes remain inert.
        let mut saved = voboost_contract::desired::Config::decode(&bytes).unwrap();
        let boot = "11111111-1111-4111-8111-111111111111";
        saved
            .save(
                boot,
                &voboost_contract::desired::Field::Option {
                    agent: "vehicle-drive-forced-ev".into(),
                    key: "intent".into(),
                },
                &"off".into(),
                &voboost_contract::desired::Input {
                    boot_id: boot.into(),
                    endpoint_epoch: 1,
                    request_id: 2,
                    injector_pid: 42,
                    injector_starttime: 100,
                },
                &[],
            )
            .unwrap();
        let saved = serde_json::to_vec(&saved).unwrap();
        crate::secure_fs::write_atomic_private(&path, &saved, 0o600).unwrap();
        let recovered = read_and_validate_at(&generation, &path);
        assert!(recovered.valid && recovered.runtime_fences.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        assert_eq!(
            state
                .read_trusted(".vehicle-drive-forced-ev_intent.journal.json", 4096, 0o600)
                .unwrap(),
            auxiliary
        );
        assert_eq!(
            recovered.config_for("vehicle-drive-forced-ev")["intent"],
            "off"
        );
        assert!(recovered
            .enabled_ids_for_process("com.qinggan.systemservice", &generation.catalog)
            .contains(&"vehicle-drive-forced-ev".into()));
    }

    #[test]
    fn simultaneous_wal_and_startup_session_failures_preserve_fev_fence() {
        use std::os::unix::fs::PermissionsExt;
        let generation = test_fixtures::vehicle_fault_generation();
        let fixture = tempfile::tempdir().unwrap();
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = fixture.path().join("agents.json");
        let mut prior = Plan::defaults_for(&generation);
        prior
            .entries
            .iter_mut()
            .for_each(|entry| entry.enabled = true);
        crate::secure_fs::write_atomic_private(&path, &canonical_bytes(&prior).unwrap(), 0o600)
            .unwrap();
        let state =
            crate::agent_state::open_state_directory(&fixture.path().join("state"), true).unwrap();
        state
            .write_atomic(
                ".vehicle-drive-forced-ev_intent.journal.json",
                b"{corrupt",
                0o600,
            )
            .unwrap();
        let root = crate::secure_fs::Directory::open(fixture.path()).unwrap();
        let run = root
            .open_or_create_child_with_mode("run", config::RUN_DIR_MODE)
            .unwrap();
        run.write_atomic("startup-session.json", b"{corrupt", 0o600)
            .unwrap();
        let candidate =
            apply_runtime_startup(read_and_validate_at(&generation, &path), |startup| {
                crate::startup_session::effective_at_for_event(fixture.path(), startup)
            });
        assert!(!candidate.valid);
        assert!(candidate
            .runtime_fences
            .contains_key("vehicle-drive-forced-ev"));
        prior.retain_recovery_fences_from(&candidate);
        assert!(!prior
            .enabled_ids_for_process("com.qinggan.systemservice", &generation.catalog)
            .contains(&"vehicle-drive-forced-ev".into()));
        assert_eq!(
            prior
                .enabled_ids_for_process("com.qinggan.systemservice", &generation.catalog)
                .len(),
            6
        );
        assert_eq!(
            prior.enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog),
            ["settings"]
        );
    }

    #[test]
    fn shared_invalid_fallback_cannot_drop_uncertain_fev_recovery_fence() {
        let generation = test_fixtures::vehicle_fault_generation();
        let mut last = Plan::defaults_for(&generation);
        last.entries
            .iter_mut()
            .for_each(|entry| entry.enabled = true);
        let mut invalid = Plan::invalid();
        invalid
            .runtime_fences
            .insert("vehicle-drive-forced-ev".into(), "corrupt input WAL".into());
        last.retain_recovery_fences_from(&invalid);
        assert!(last.valid);
        assert!(!last
            .enabled_ids_for_process("com.qinggan.systemservice", &generation.catalog)
            .contains(&"vehicle-drive-forced-ev".into()));
        last.retain_recovery_fences_from(&Plan::invalid());
        assert!(last.runtime_fences.contains_key("vehicle-drive-forced-ev"));
        assert_eq!(
            last.enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog),
            ["settings"]
        );
    }

    #[test]
    fn none_live_projection_retains_only_admitted_enabled_agents_in_every_process() {
        for (process, peer) in [
            ("com.qinggan.app.setting", "font-cyrillic"),
            ("com.qinggan.app.launcher", "launcher-apps"),
            ("com.pateonavi.naviapp", "font-cyrillic"),
            ("com.qinggan.app.qgime", "keyboard-ru"),
        ] {
            let mut generation = settings_generation();
            generation.catalog.agents[1].targets[0].process = process.into();
            generation.catalog.agents[1].id = peer.into();
            generation.selection = crate::selection::SelectionReceipt::compute(
                &generation.catalog,
                &generation.catalog_sha256,
                &generation.selection.receipt.facts,
            )
            .unwrap();
            let mut plan = Plan::defaults_for(&generation);
            plan.entries[1].enabled = true;
            plan.startup = Startup::None;
            plan.disable_all = true;
            let loaded = process == "com.qinggan.app.setting";
            let ids = vec![peer.to_string()];
            let expected = if loaded { 2 } else { 1 };
            let document: Value = serde_json::from_str(
                &plan
                    .desired_document_for_admitted(process, &generation, 2, loaded, &ids)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(document["agents"].as_array().unwrap().len(), expected);
            assert!(document["agents"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["id"] == peer));
            let semantics: Value = serde_json::from_str(
                &plan
                    .desired_semantics_for_admitted(process, &generation, loaded, &ids)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(semantics["agents"], document["agents"]);
            assert_eq!(
                plan.enabled_ids_for_admitted(process, &generation.catalog, loaded, &ids)
                    .len(),
                expected
            );
            if loaded {
                assert_eq!(document["profile"]["startup"], "none");
            }

            // Enabled but unadmitted peers are never started by NONE.
            assert_eq!(
                plan.enabled_ids_for_admitted(process, &generation.catalog, loaded, &[])
                    .len(),
                if loaded { 1 } else { 0 }
            );
            plan.entries[1].enabled = false;
            assert_eq!(
                plan.enabled_ids_for_admitted(process, &generation.catalog, loaded, &ids)
                    .len(),
                if loaded { 1 } else { 0 }
            );
            plan.entries[1].enabled = true;
            // Cold none and uninstall cleanup have no agents or projection.
            for (live_settings, cleanup) in [(false, false), (true, true)] {
                plan.uninstall_cleanup = cleanup;
                let admitted = if cleanup { ids.as_slice() } else { &[] };
                let absent: Value = serde_json::from_str(
                    &plan
                        .desired_document_for_admitted(
                            process,
                            &generation,
                            3,
                            live_settings,
                            admitted,
                        )
                        .unwrap(),
                )
                .unwrap();
                assert!(absent["agents"].as_array().unwrap().is_empty());
                assert!(absent["profile"].is_null());
            }
        }
    }

    #[test]
    fn shared_process_desired_agents_start_vehicle_before_background_without_reordering_ui() {
        use crate::catalog::StartupPriority;
        let mut generation = settings_generation();
        let process = generation.catalog.agents[0].targets[0].process.clone();
        generation.catalog.agents[0].startup_priority = Some(StartupPriority::Background);
        generation.catalog.agents[1].startup_priority = Some(StartupPriority::Vehicle);
        generation.catalog.agents[1].targets[0].process = process.clone();
        let mut plan = Plan::defaults_for(&generation);
        plan.entries[1].enabled = true;
        let desired = plan.desired_agents_for_process(&process, &generation.catalog);
        assert_eq!(desired[0]["id"], "forced-ev");
        assert_eq!(desired[1]["id"], "settings");
        for document in [
            plan.desired_document_for_process(&process, &generation, 17)
                .unwrap(),
            plan.desired_document_for_resident(&process, &generation, 17, false)
                .unwrap(),
            plan.desired_document_for_admitted(&process, &generation, 17, false, &[])
                .unwrap(),
        ] {
            let serialized: Value = serde_json::from_str(&document).unwrap();
            assert_eq!(serialized["agents"][0]["id"], "forced-ev");
            assert_eq!(serialized["agents"][1]["id"], "settings");
        }
        assert_eq!(plan.entries[0].id, "settings");
        assert_eq!(generation.catalog.agents[0].id, "settings");
        assert_eq!(plan.startup_priority(&process, &generation.catalog), 0);
    }

    #[test]
    fn startup_priority_uses_enabled_catalog_members_and_executor_targets() {
        use crate::catalog::StartupPriority;
        for priority in [
            StartupPriority::Vehicle,
            StartupPriority::Interface,
            StartupPriority::Applications,
            StartupPriority::Background,
        ] {
            let mut generation = settings_generation();
            generation.catalog.agents[1].startup_priority = Some(priority);
            let mut plan = Plan::defaults_for(&generation);
            plan.entries[1].enabled = true;
            let process = generation.catalog.agents[1].targets[0].process.clone();
            assert_eq!(
                plan.startup_priority(&process, &generation.catalog),
                priority as u8
            );
            assert_eq!(plan.startup_priority("absent", &generation.catalog), 3);
            plan.entries[1].enabled = false;
            assert_eq!(plan.startup_priority(&process, &generation.catalog), 3);
            generation.catalog.agents[1].kind = Some("executor".into());
            assert_eq!(
                plan.startup_priority(&process, &generation.catalog),
                priority as u8
            );
            generation.catalog.agents[0].targets[0].process = process.clone();
            generation.catalog.agents[0].startup_priority = Some(StartupPriority::Vehicle);
            plan.entries[0].enabled = true;
            assert_eq!(plan.startup_priority(&process, &generation.catalog), 0);
        }
    }

    #[test]
    fn settings_defaults_to_enabled_and_receives_both_process_documents() {
        let mut generation = settings_generation();
        let mut second = generation.catalog.agents[0].targets[0].clone();
        second.process = "com.qinggan.app.vehiclesetting".into();
        generation.catalog.agents[0].targets.push(second);
        let mut plan = Plan::defaults_for(&generation);
        plan.startup = Startup::Interface;
        for process in ["com.qinggan.app.setting", "com.qinggan.app.vehiclesetting"] {
            let value: Value = serde_json::from_str(
                &plan
                    .desired_document_for_process(process, &generation, 1)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(value["agents"][0]["id"], "settings");
            assert!(value.get("profile").is_some());
        }
        plan.startup = Startup::Hidden;
        assert!(!plan.effective_enabled(&plan.entries[0]));
    }

    #[test]
    fn uninstall_projection_marks_every_document_and_ordinary_plans_do_not() {
        let generation = settings_generation();
        let plan = Plan::defaults_for(&generation);
        let ordinary: Value = serde_json::from_str(
            &plan
                .desired_document_for_process("com.qinggan.app.setting", &generation, 1)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ordinary["uninstallCleanup"], Value::Bool(false));
        let disabled = plan.disabled_for_uninstall();
        assert!(disabled.disable_all && disabled.uninstall_cleanup);
        let document: Value = serde_json::from_str(
            &disabled
                .desired_document_for_process("com.qinggan.app.setting", &generation, 2)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(document["uninstallCleanup"], Value::Bool(true));
        assert!(document["agents"].as_array().unwrap().is_empty());
    }

    #[test]
    fn migration_reactivates_config_host_and_preserves_checkbox_intents() {
        let generation = settings_generation();
        // Previous plan written by the old defect: settings host disabled,
        // checkbox agent explicitly enabled by the user.
        let mut previous = Plan::defaults_for(&generation);
        previous.startup = Startup::Interface;
        previous.entries[0].enabled = false;
        previous.entries[1].enabled = true;

        let migrated = migrate_plan(previous, &generation);
        assert!(migrated.valid);
        assert_eq!(migrated.startup, Startup::Interface);
        assert!(
            migrated.entries
                .iter()
                .find(|entry| entry.id == "settings")
                .unwrap()
                .enabled,
            "config-activated host must follow the activation default, not the stale checkbox value"
        );
        assert!(
            migrated
                .entries
                .iter()
                .find(|entry| entry.id == "forced-ev")
                .unwrap()
                .enabled,
            "user checkbox intent must survive migration"
        );
        assert!(migrated
            .desired_document_for_process("com.qinggan.app.setting", &generation, 1)
            .is_ok());
    }

    #[test]
    fn publication_accepts_a_newer_user_off_without_losing_product_defaults_integrity() {
        use std::os::unix::fs::PermissionsExt;
        let generation = settings_generation();
        let root = tempfile::Builder::new()
            .prefix(".desired-publish-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.path().join("agents.json");
        let mut old = Plan::defaults_for(&generation);
        old.entries[1].enabled = true;
        let defaults = canonical_bytes(&old).unwrap();
        crate::secure_fs::write_atomic_private(&path, &defaults, 0o600).unwrap();
        let prepared = prepare_canonical_transition(Some(&generation), &generation, &path).unwrap();
        let mut current = voboost_contract::desired::Config::decode(&defaults).unwrap();
        let input = voboost_contract::desired::Input {
            boot_id: "11111111-1111-4111-8111-111111111111".into(),
            endpoint_epoch: 1,
            request_id: 8,
            injector_pid: 42,
            injector_starttime: 100,
        };
        current
            .save(
                &input.boot_id,
                &voboost_contract::desired::Field::Enabled {
                    agent: "forced-ev".into(),
                },
                &false.into(),
                &input,
                &[],
            )
            .unwrap();
        crate::secure_fs::write_atomic_private(
            &path,
            &serde_json::to_vec(&current).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(publish_prepared_canonical(
            &path,
            &generation,
            prepared.previous_bytes,
            &prepared.next_bytes
        )
        .is_ok());
        let published =
            voboost_contract::desired::Config::decode(&read_canonical_bounded(&path).unwrap())
                .unwrap();
        assert!(!published.agents["forced-ev"].enabled);
        assert_eq!(published.user_revision, current.user_revision);
        let expected = published.reconcile(&prepared.next_bytes).unwrap();
        assert_eq!(
            serde_json::to_vec(&published).unwrap(),
            expected,
            "all unchosen product defaults must match the trusted proposal"
        );
        let mut wrong_product = published.clone();
        wrong_product.startup = "hidden".into();
        assert_ne!(
            serde_json::to_vec(&wrong_product).unwrap(),
            wrong_product.reconcile(&prepared.next_bytes).unwrap()
        );
    }

    #[test]
    fn prepared_defaults_never_overwrite_a_later_checkbox_off() {
        use std::os::unix::fs::PermissionsExt;
        let generation = settings_generation();
        let root = tempfile::Builder::new()
            .prefix("plan-stale-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.path().join("agents.json");
        let mut plan = Plan::defaults_for(&generation);
        plan.entries[1].enabled = true;
        let stale = canonical_bytes(&plan).unwrap();
        crate::secure_fs::write_atomic_private(&path, &stale, 0o600).unwrap();
        let prepared = prepare_canonical_transition(Some(&generation), &generation, &path).unwrap();
        let mut current = voboost_contract::desired::Config::decode(&stale).unwrap();
        let boot = "11111111-1111-4111-8111-111111111111";
        current
            .save(
                boot,
                &voboost_contract::desired::Field::Enabled {
                    agent: "forced-ev".into(),
                },
                &false.into(),
                &voboost_contract::desired::Input {
                    boot_id: boot.into(),
                    endpoint_epoch: 1,
                    request_id: 9,
                    injector_pid: 42,
                    injector_starttime: 100,
                },
                &[],
            )
            .unwrap();
        let off = serde_json::to_vec(&current).unwrap();
        replace_canonical(&path, Some(stale), &off).unwrap();

        assert!(publish_prepared_canonical(
            &path,
            &generation,
            prepared.previous_bytes,
            &prepared.next_bytes,
        )
        .is_ok());
        assert_eq!(read_canonical_bounded(&path).unwrap(), off);
        let rebooted = read_and_validate_at(&generation, &path);
        assert!(rebooted.valid);
        assert!(
            !rebooted
                .entries
                .iter()
                .find(|entry| entry.id == "forced-ev")
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn unsupported_catalog_agent_has_no_plan_projection_or_injection_desire() {
        let mut generation = settings_generation();
        generation
            .selection
            .selected_agent_ids
            .retain(|id| id == "settings");
        generation.selection.receipt.agents[1].result =
            crate::selection::ApplicabilityResult::Unsupported;
        generation.selection.receipt.agents[1].unknown_reasons = None;

        let plan = Plan::defaults_for(&generation);
        assert_eq!(
            plan.entries
                .iter()
                .map(|entry| entry.id.as_str())
                .collect::<Vec<_>>(),
            vec!["settings"]
        );
        assert!(plan
            .enabled_ids_for_process("com.qinggan.systemservice", &generation.catalog)
            .is_empty());
        let settings_document = plan
            .desired_document_for_process("com.qinggan.app.setting", &generation, 1)
            .unwrap();
        assert!(!settings_document.contains("forced-ev"));
    }

    #[test]
    fn unsupported_settings_has_no_plan_projection_or_process_desire() {
        let mut generation = settings_generation();
        generation.selection.selected_agent_ids.clear();
        for entry in &mut generation.selection.receipt.agents {
            entry.result = crate::selection::ApplicabilityResult::Unsupported;
            entry.unknown_reasons = None;
        }

        let plan = Plan::defaults_for(&generation);
        assert!(plan.entries.is_empty());
        assert!(plan
            .enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog)
            .is_empty());
        let document = plan
            .desired_document_for_process("com.qinggan.app.setting", &generation, 1)
            .unwrap();
        assert!(document.contains(r#""agents":[]"#));
        assert!(document.contains(r#""profile":null"#));
    }

    #[test]
    fn desired_document_schema_one_carries_exact_verified_runtime_facts() {
        let generation = settings_generation();
        let plan = Plan::defaults_for(&generation);

        let document: Value = serde_json::from_str(
            &plan
                .desired_document_for_process("com.qinggan.app.setting", &generation, 7)
                .unwrap(),
        )
        .unwrap();

        assert_eq!(document["schemaVersion"], 1);
        assert_eq!(document["documentGeneration"], 7);
        assert_eq!(
            document["runtimeFacts"],
            serde_json::to_value(&generation.selection.receipt.facts).unwrap()
        );
        assert_eq!(document["runtimeFacts"]["chip"]["value"], "8155");
        assert_eq!(document["runtimeFacts"]["android"]["value"], 9);
        assert!(document.get("facts").is_none());
    }

    #[test]
    fn desired_document_preserves_unknown_runtime_fact_reason() {
        let mut generation = settings_generation();
        generation.selection.receipt.facts.powertrain =
            crate::selection::Fact::Unknown(crate::selection::Unknown {
                unknown: crate::selection::UnknownReason::ProbeUnavailable,
            });
        let plan = Plan::defaults_for(&generation);

        let document: Value = serde_json::from_str(
            &plan
                .desired_document_for_process("com.qinggan.app.setting", &generation, 8)
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            document["runtimeFacts"]["powertrain"]["unknown"],
            "probe-unavailable"
        );
        assert!(document["runtimeFacts"]["powertrain"]
            .get("value")
            .is_none());
    }

    #[test]
    fn canonical_reader_rejects_sparse_oversize_before_reading_body() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("agents.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(config::MAX_PLAN_BYTES as u64 + 1).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_canonical_bounded(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn ephemeral_uninstall_disable_survives_crash_without_losing_canonical_intent() {
        use std::os::unix::fs::PermissionsExt;

        let generation = settings_generation();
        let canonical = br#"{"schemaVersion":2,"userRevision":0,"fieldRevisions":{},"startup":"interface","agents":{"settings":{"enabled":true,"options":{}}}}"#;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("agents.json");
        std::fs::write(&path, canonical).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let prior = validate(&generation, canonical);
        assert!(prior.valid);
        assert_eq!(prior.startup, Startup::Interface);
        assert!(prior.entries.iter().any(|entry| entry.enabled));

        let disabled = prior.disabled_for_uninstall();
        assert!(disabled.valid);
        assert_eq!(disabled.startup, Startup::None);
        assert!(disabled.disable_all);
        assert!(disabled.entries.iter().all(|entry| !entry.enabled));

        // Simulated crash before prepared publication: deriving and projecting
        // the cleanup plan never wrote the canonical file. Restart therefore
        // sees the original enabled intent even if the next prepare fails.
        assert_eq!(std::fs::read(&path).unwrap(), canonical);
        let restarted = validate(&generation, &std::fs::read(&path).unwrap());
        assert_eq!(restarted.startup, Startup::Interface);
        assert!(restarted.entries.iter().any(|entry| entry.enabled));
    }

    #[test]
    fn malformed_and_duplicate_root_plan_are_rejected() {
        assert!(serde_json::from_slice::<PlanDocument>(b"not-json").is_err());
        assert!(serde_json::from_slice::<PlanDocument>(
            br#"{"schemaVersion":1,"schemaVersion":1}"#
        )
        .is_err());
    }

    #[test]
    fn strict_config_rejects_duplicate_nested_keys() {
        let raw = br#"{"enabled":true,"options":{"a":{"b":1,"b":2}}}"#;
        assert!(serde_json::from_slice::<PlanEntryDocument>(raw).is_err());
    }

    #[test]
    fn enabled_conflicts_are_rejected_regardless_of_relation_order() {
        let enabled = HashSet::from(["keyboard-en".to_string(), "keyboard-ru".to_string()]);
        let en_disables = vec!["keyboard-ru".to_string()];
        let none = Vec::<String>::new();
        assert!(any_enabled_conflict(
            &enabled,
            [
                ("keyboard-ru", none.as_slice()),
                ("keyboard-en", en_disables.as_slice()),
            ]
        ));

        let only_en = HashSet::from(["keyboard-en".to_string()]);
        assert!(!any_enabled_conflict(
            &only_en,
            [("keyboard-en", en_disables.as_slice())]
        ));
    }

    #[test]
    fn canonical_intent_follows_system_language_without_an_override() {
        let generation = settings_generation();
        let mut canonical: Value =
            serde_json::from_slice(&canonical_bytes(&Plan::defaults_for(&generation)).unwrap())
                .unwrap();
        canonical.as_object_mut().unwrap().remove("language");
        assert!(validate(&generation, &serde_json::to_vec(&canonical).unwrap()).valid);
        canonical["language"] = "en".into();
        assert!(!validate(&generation, &serde_json::to_vec(&canonical).unwrap()).valid);
        canonical.as_object_mut().unwrap().remove("language");
        canonical["unknown"] = true.into();
        assert!(!validate(&generation, &serde_json::to_vec(&canonical).unwrap()).valid);
    }

    #[test]
    fn settings_semantics_cover_the_complete_resident_catalog_projection() {
        let generation = settings_generation();
        let base = Plan::defaults_for(&generation);
        let process = "com.qinggan.app.setting";
        let base_semantics = base.desired_semantics_for_process(process, &generation);

        assert_eq!(
            base_semantics,
            base.clone()
                .desired_semantics_for_process(process, &generation),
            "an unchanged plan must not allocate a new document generation"
        );

        let mut startup = base.clone();
        startup.startup = Startup::Hidden;
        assert_ne!(
            base_semantics,
            startup.desired_semantics_for_process(process, &generation)
        );

        let mut other_process_checkbox = base.clone();
        other_process_checkbox
            .entries
            .iter_mut()
            .find(|entry| entry.id == "forced-ev")
            .unwrap()
            .enabled = true;
        let changed = other_process_checkbox
            .desired_semantics_for_process(process, &generation)
            .unwrap();
        assert_ne!(base_semantics.as_ref().unwrap(), &changed);
        let parsed: Value = serde_json::from_str(&changed).unwrap();
        assert_eq!(parsed["profile"]["entries"][0]["id"], "forced-ev");
        assert_eq!(parsed["profile"]["entries"][0]["values"]["enabled"], true);
        assert!(parsed.get("documentGeneration").is_none());
    }

    #[test]
    fn technical_agent_is_always_enabled_but_never_a_settings_row() {
        let mut generation = settings_generation();
        let template = generation.catalog.find("forced-ev").unwrap().clone();
        let mut technical = template;
        technical.id = "ui-qinggan".to_string();
        technical.targets[0].process = "com.qinggan.app.setting".to_string();
        technical.targets[0].file = "agent-ui-qinggan.dex".to_string();
        technical.targets[0].entry_class =
            Some("ru.voboost.agents.uiqinggan.UiQingganAgent".to_string());
        technical.order = Some(2);
        technical.activation = Some(Activation::Technical {});
        generation.catalog.agents.push(technical);
        generation
            .selection
            .selected_agent_ids
            .push("ui-qinggan".into());
        generation
            .selection
            .receipt
            .agents
            .push(crate::selection::AgentSelection {
                id: "ui-qinggan".to_string(),
                result: crate::selection::ApplicabilityResult::Supported,
                unknown_reasons: None,
            });

        let plan = Plan::defaults_for(&generation);
        let technical_entry = plan
            .entries
            .iter()
            .find(|entry| entry.id == "ui-qinggan")
            .unwrap();
        assert!(
            technical_entry.enabled,
            "technical activation defaults to enabled like a satisfied config gate"
        );

        // Desired process document carries the agent into its target process.
        let document: Value = serde_json::from_str(
            &plan
                .desired_document_for_process("com.qinggan.app.setting", &generation, 1)
                .unwrap(),
        )
        .unwrap();
        let ids: Vec<&str> = document["agents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|agent| agent["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"ui-qinggan"));
        assert_eq!(
            plan.enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog),
            vec!["settings".to_string(), "ui-qinggan".to_string()]
        );

        // Excluded from the Settings projection: no user row, no toggle.
        let semantics: Value = serde_json::from_str(
            &plan
                .desired_semantics_for_process("com.qinggan.app.setting", &generation)
                .unwrap(),
        )
        .unwrap();
        let rows = semantics["profile"]["entries"].as_array().unwrap();
        assert!(rows
            .iter()
            .all(|row| row["id"].as_str() != Some("ui-qinggan")));

        // Migration ignores stale disabled intent, mirroring config hosts.
        let mut previous = plan.clone();
        previous
            .entries
            .iter_mut()
            .find(|entry| entry.id == "ui-qinggan")
            .unwrap()
            .enabled = false;
        let migrated = migrate_plan(previous, &generation);
        assert!(
            migrated
                .entries
                .iter()
                .find(|entry| entry.id == "ui-qinggan")
                .unwrap()
                .enabled
        );

        // The global disable-all gate (startup none, e.g. uninstall) still
        // suppresses technical agents.
        let mut disabled = plan;
        disabled.startup = Startup::None;
        assert!(
            disabled
                .entries
                .iter()
                .find(|entry| entry.id == "ui-qinggan")
                .unwrap()
                .enabled
        );
        assert!(disabled
            .enabled_ids_for_process("com.qinggan.app.setting", &generation.catalog)
            .is_empty());
    }

    #[test]
    fn profile_values_follow_catalog_options_not_runtime_configuration() {
        for id in ["forced-ev", "launcher", "i18n-ru"] {
            let mut generation = settings_generation();
            let agent = &mut generation.catalog.agents[1];
            agent.id = id.into();
            agent.options = Some(vec![crate::catalog::AgentOption {
                key: "mode".into(),
                option_type: "enum".into(),
                default: "default".into(),
                values: ["default", "selected"]
                    .into_iter()
                    .map(|value| crate::catalog::AgentOptionValue {
                        value: value.into(),
                        title: crate::catalog::LocaleMap {
                            en: value.into(),
                            ru: value.into(),
                            zh: None,
                        },
                    })
                    .collect(),
            }]);
            generation.selection.receipt.agents[1].id = id.into();
            generation.selection.selected_agent_ids[1] = id.into();
            let mut plan = Plan::defaults_for(&generation);
            for (configured, expected) in [("selected", "selected"), ("removed", "default")] {
                let entry = plan
                    .entries
                    .iter_mut()
                    .find(|entry| entry.id == id)
                    .unwrap();
                entry.enabled = true;
                entry.config = serde_json::json!({
                    "mode": configured,
                    "resourceAdmission": {"targetPackage": "com.qinggan.app.setting"},
                    "applications": {"example.app": {"enabled": false}},
                });
                let profile = serde_json::to_value(plan.profile(&generation)).unwrap();
                assert_eq!(
                    profile["entries"][0]["values"],
                    serde_json::json!({"enabled": true, "mode": expected}),
                    "{id}"
                );
            }
            plan.entries.retain(|entry| entry.id != id);
            let profile = serde_json::to_value(plan.profile(&generation)).unwrap();
            assert_eq!(
                profile["entries"][0]["values"],
                serde_json::json!({"enabled": false, "mode": "default"}),
                "{id}"
            );
            generation.catalog.agents[1].options = Some(Vec::new());
            let profile = serde_json::to_value(plan.profile(&generation)).unwrap();
            assert_eq!(
                profile["entries"][0]["values"],
                serde_json::json!({"enabled": false}),
                "{id}"
            );
        }
    }

    #[test]
    fn profile_is_exact_resident_catalog_surface() {
        let mut generation = settings_generation();
        generation.catalog.agents[1].title = Some(crate::catalog::LocaleMap {
            en: "Forced EV".to_string(),
            ru: "Принудительный EV".to_string(),
            zh: None,
        });
        generation.catalog.agents[1].description = Some(crate::catalog::LocaleMap {
            en: "Keep electric mode".to_string(),
            ru: "Сохранять электрический режим".to_string(),
            zh: None,
        });
        generation.catalog.agents[1].disables = Some(vec!["supported-second".to_string()]);
        generation.catalog.agents[1].options = Some(vec![crate::catalog::AgentOption {
            key: "mode".to_string(),
            option_type: "radio".to_string(),
            default: "resident-default".to_string(),
            values: vec![crate::catalog::AgentOptionValue {
                value: "resident-default".to_string(),
                title: crate::catalog::LocaleMap {
                    en: "Resident default".to_string(),
                    ru: "Штатный режим".to_string(),
                    zh: None,
                },
            }],
        }]);
        let template = generation.catalog.find("forced-ev").unwrap().clone();

        let mut supported_second = template.clone();
        supported_second.id = "supported-second".to_string();
        supported_second.targets[0].file = "agent-supported-second.dex".to_string();
        supported_second.targets[0].entry_class =
            Some("ru.voboost.agents.supportedsecond.SupportedSecondAgent".to_string());
        supported_second.status = Some(AgentStatus::Unstable);
        supported_second.order = Some(2);
        generation.catalog.agents.push(supported_second);

        let mut unsupported = template;
        unsupported.id = "unsupported-agent".to_string();
        unsupported.targets[0].file = "agent-unsupported-agent.dex".to_string();
        unsupported.targets[0].entry_class =
            Some("ru.voboost.agents.unsupported.UnsupportedAgent".to_string());
        unsupported.order = Some(3);
        generation.catalog.agents.push(unsupported);

        generation.selection.receipt.agents[1].result =
            crate::selection::ApplicabilityResult::Unknown;
        generation
            .selection
            .receipt
            .agents
            .push(crate::selection::AgentSelection {
                id: "supported-second".to_string(),
                result: crate::selection::ApplicabilityResult::Supported,
                unknown_reasons: None,
            });
        generation
            .selection
            .receipt
            .agents
            .push(crate::selection::AgentSelection {
                id: "unsupported-agent".to_string(),
                result: crate::selection::ApplicabilityResult::Unsupported,
                unknown_reasons: None,
            });

        let mut plan = Plan::defaults_for(&generation);
        // Model an active catalog that removed one resident agent and changed
        // a common option value. The old resident surface remains complete,
        // but removed state is disabled and incompatible config falls back to
        // the signed resident default.
        plan.entries.retain(|entry| entry.id != "supported-second");
        let common = plan
            .entries
            .iter_mut()
            .find(|entry| entry.id == "forced-ev")
            .unwrap();
        common.enabled = true;
        common.config = serde_json::json!({"mode":"active-only"});
        plan.entries.push(PlanEntry {
            id: "absent-agent".to_string(),
            enabled: true,
            config: Value::Object(Map::new()),
        });
        let process = "com.qinggan.app.setting";
        let semantics = plan
            .desired_semantics_for_process(process, &generation)
            .unwrap();
        let value: Value = serde_json::from_str(&semantics).unwrap();
        let rows = value["profile"]["entries"].as_array().unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["forced-ev", "supported-second"],
            "self, absent and unsupported rows are omitted; retained rows keep catalog order"
        );
        assert_eq!(rows[0]["status"], "unstable");
        assert_eq!(rows[0]["applicability"], "unknown");
        assert_eq!(
            rows[0]["title"],
            serde_json::json!({"en":"Forced EV","ru":"Принудительный EV"}),
            "SettingsProjection Java contract requires the complete locale map"
        );
        assert_eq!(
            rows[0]["description"],
            serde_json::json!({
                "en":"Keep electric mode",
                "ru":"Сохранять электрический режим"
            })
        );
        assert_eq!(
            rows[0]["options"][0]["values"][0]["title"],
            serde_json::json!({"en":"Resident default","ru":"Штатный режим"})
        );
        assert_eq!(rows[0]["disables"], serde_json::json!(["supported-second"]));
        assert_eq!(
            rows[0]["values"]["mode"], "resident-default",
            "active-only option values must not leak into an older resident catalog"
        );
        assert_eq!(rows[1]["status"], "unstable");
        assert_eq!(rows[1]["applicability"], "supported");
        assert_eq!(rows[1]["values"]["enabled"], false);
        let resident_runtime =
            plan.desired_agents_for_process("com.qinggan.systemservice", &generation.catalog);
        assert_eq!(resident_runtime[0]["id"], "forced-ev");
        assert_eq!(resident_runtime[0]["config"]["mode"], "resident-default");
        assert_eq!(resident_runtime.as_array().unwrap().len(), 1);

        generation.selection.receipt.agents[1].result =
            crate::selection::ApplicabilityResult::Supported;
        assert_ne!(
            semantics,
            plan.desired_semantics_for_process(process, &generation)
                .unwrap(),
            "applicability changes must allocate a new Settings document"
        );
    }
}
