// plan.rs — inject.json reader and validator.
//
// Ported from Vala plan_reader.vala. The plan is untrusted app-written input.
// Each agent id must be whitelisted by the manifest; config is OPAQUE — the
// daemon never interprets it. Process/sha256 are NEVER read from the plan
// (they come from the manifest). Size bounds are a DoS guard.

use serde::Deserialize;
use serde_json::Value;

use crate::config;
use crate::log;
use crate::manifest::Manifest;

/// A single plan entry (agent id + enabled + opaque config).
#[derive(Debug, Clone)]
pub struct PlanEntry {
    pub id: String,
    pub enabled: bool,
    pub config: String,
}

/// The validated plan.
#[derive(Debug, Default)]
pub struct Plan {
    pub plan_version: i64,
    pub startup: String,
    pub disable_all: bool,
    pub log_level: String,
    pub entries: Vec<PlanEntry>,
    pub rejected_ids: Vec<String>,
}

#[derive(Deserialize)]
struct PlanJson {
    version: Option<i64>,
    startup: Option<String>,
    disabled: Option<bool>,
    log_level: Option<String>,
    agents: Option<Vec<PlanEntryJson>>,
}

#[derive(Deserialize)]
struct PlanEntryJson {
    id: Option<String>,
    enabled: Option<bool>,
    config: Option<Value>,
}

/// Read and validate the plan from inject.json.
pub fn read_and_validate(manifest: &Manifest) -> Plan {
    let path = config::plan_file();

    // Stat fast-path DoS guard.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() as usize > config::MAX_PLAN_BYTES {
            log::err("plan", "inject.json exceeds MAX_PLAN_BYTES (stat)");
            return Plan::default();
        }
    }

    let json_bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => return Plan::default(), // absent file → empty plan
    };

    if json_bytes.len() > config::MAX_PLAN_BYTES {
        log::err("plan", "inject.json exceeds MAX_PLAN_BYTES (read)");
        return Plan::default();
    }

    validate(manifest, &json_bytes)
}

/// Parse and validate plan JSON against the manifest.
pub fn validate(manifest: &Manifest, json_bytes: &[u8]) -> Plan {
    let parsed: PlanJson = match serde_json::from_slice(json_bytes) {
        Ok(p) => p,
        Err(_) => return Plan::default(),
    };

    let mut plan = Plan {
        plan_version: parsed.version.unwrap_or(0),
        startup: parsed.startup.unwrap_or_default(),
        disable_all: parsed.disabled.unwrap_or(false),
        log_level: parsed.log_level.unwrap_or_else(|| "info".to_string()),
        entries: Vec::new(),
        rejected_ids: Vec::new(),
    };

    if let Some(agents) = parsed.agents {
        let mut seen = std::collections::HashSet::new();
        for entry in agents {
            let id = entry.id.unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            if seen.contains(&id) {
                log::err("plan", &format!("rejected duplicate agent id {id}"));
                plan.rejected_ids.push(id);
                continue;
            }
            if manifest.find(&id).is_none() {
                log::err("plan", &format!("rejected unknown agent id {id}"));
                plan.rejected_ids.push(id);
                continue;
            }
            seen.insert(id.clone());
            let enabled = entry.enabled.unwrap_or(false);
            let config = match entry.config {
                Some(v) => {
                    let s = serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string());
                    if s.len() > config::MAX_CONFIG_BYTES {
                        log::err("plan", &format!("rejected oversized config for {id}"));
                        plan.rejected_ids.push(id);
                        continue;
                    }
                    s
                }
                None => "{}".to_string(),
            };
            plan.entries.push(PlanEntry {
                id,
                enabled,
                config,
            });
        }
    }

    plan
}

impl Plan {
    /// Group enabled agents by target process (from the manifest).
    pub fn group_by_process<'a>(
        &'a self,
        manifest: &'a Manifest,
    ) -> std::collections::HashMap<&'a str, Vec<&'a crate::manifest::AgentDef>> {
        let mut map = std::collections::HashMap::new();
        for entry in &self.entries {
            if !entry.enabled {
                continue;
            }
            if let Some(def) = manifest.find(&entry.id) {
                map.entry(def.process.as_str())
                    .or_insert_with(Vec::new)
                    .push(def);
            }
        }
        map
    }

    /// Get the opaque config for an agent id.
    pub fn config_for(&self, id: &str) -> &str {
        for entry in &self.entries {
            if entry.id == id {
                return &entry.config;
            }
        }
        "{}"
    }

    /// Build the per-process channel-B config document.
    ///
    /// One implant is injected per process; it loads every enabled agent that
    /// the manifest maps to that process. The document is
    /// `{"agents":[{"id":..,"config":<opaque>}...]}`, matching the no-agents
    /// teardown shape in control_plane. Each agent's config is embedded as raw
    /// JSON (the daemon never interprets it).
    pub fn config_for_process(&self, process: &str, manifest: &Manifest) -> String {
        let agents: Vec<Value> = self
            .entries
            .iter()
            .filter(|e| e.enabled)
            .filter(|e| manifest.find(&e.id).is_some_and(|d| d.process == process))
            .map(|e| {
                let config: Value =
                    serde_json::from_str(&e.config).unwrap_or_else(|_| serde_json::json!({}));
                serde_json::json!({ "id": e.id, "config": config })
            })
            .collect();
        serde_json::json!({ "agents": agents }).to_string()
    }
}
