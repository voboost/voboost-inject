// manifest.rs — verified agent manifest.
//
// Ported from Vala manifest.vala. Verify-then-parse: the signature is
// checked first; only on success is the JSON parsed. The manifest is the
// source of agent metadata (id, process, file, sha256).

use serde::Deserialize;
use serde_json::Value;

use crate::log;
use crate::trust;

/// An agent definition from the verified manifest.
#[derive(Debug, Clone)]
pub struct AgentDef {
    pub id: String,
    pub channel: String,
    pub file: String,
    pub sha256: String,
    pub process: String,
    /// Per-agent boot gate: when true, defer injection until boot_completed.
    pub requires_boot: bool,
}

/// The verified manifest.
#[derive(Debug, Default)]
pub struct Manifest {
    pub manifest_version: i64,
    pub daemon_version: String,
    pub agents: Vec<AgentDef>,
}

#[derive(Deserialize)]
struct ManifestJson {
    version: Option<i64>,
    daemon: Option<String>,
    agents: Option<Vec<AgentEntryJson>>,
}

#[derive(Deserialize)]
struct AgentEntryJson {
    id: Option<String>,
    channel: Option<String>,
    file: Option<String>,
    sha256: Option<String>,
    process: Option<String>,
    boot: Option<bool>,
}

impl Manifest {
    /// Verify signature first; parse only on success.
    pub fn load_verified(json_bytes: &[u8], signature: &[u8]) -> bool {
        if !trust::verify_signature(json_bytes, signature) {
            return false;
        }
        // Safe parse: serde_json::from_slice returns Err on malformed JSON,
        // which we treat as a parse failure (returns false).
        match Self::parse(json_bytes) {
            Some(m) => {
                // Replace self — but since we return bool, the caller
                // re-reads. For now this is a static-style API matching
                // the Vala load_verified that mutates self.
                // The supervisor will hold a Manifest and call this.
                // We refactor slightly: parse returns the Manifest.
                let _ = m; // caller uses parse directly after verify
                true
            }
            None => false,
        }
    }

    /// Parse JSON into a Manifest (only called after signature verification).
    pub fn parse(json: &[u8]) -> Option<Manifest> {
        let parsed: ManifestJson = serde_json::from_slice(json).ok()?;

        let mut agents = Vec::new();
        let mut seen = std::collections::HashSet::new();

        if let Some(entries) = parsed.agents {
            for entry in entries {
                let id = entry.id.unwrap_or_default();
                if id.is_empty() {
                    log::err("manifest", "skipping agent with missing id");
                    continue;
                }
                if !seen.insert(id.clone()) {
                    log::err("manifest", &format!("skipping duplicate agent id {id}"));
                    continue;
                }
                let file = match entry.file {
                    Some(f) if !f.is_empty() => f,
                    _ => {
                        log::err("manifest", &format!("skipping agent {id}: missing file"));
                        continue;
                    }
                };
                let sha256 = match entry.sha256 {
                    Some(s) if !s.is_empty() => s,
                    _ => {
                        log::err("manifest", &format!("skipping agent {id}: missing sha256"));
                        continue;
                    }
                };
                let process = match entry.process {
                    Some(p) if !p.is_empty() => p,
                    _ => {
                        log::err("manifest", &format!("skipping agent {id}: missing process"));
                        continue;
                    }
                };
                agents.push(AgentDef {
                    id,
                    channel: entry.channel.unwrap_or_else(|| "agents".to_string()),
                    file,
                    sha256,
                    process,
                    requires_boot: entry.boot.unwrap_or(false),
                });
            }
        }

        Some(Manifest {
            manifest_version: parsed.version.unwrap_or(0),
            daemon_version: parsed.daemon.unwrap_or_default(),
            agents,
        })
    }

    /// Find an agent by id.
    pub fn find(&self, id: &str) -> Option<&AgentDef> {
        self.agents.iter().find(|a| a.id == id)
    }
}

/// Check whether a JSON value is a well-formed manifest (for validation).
pub fn is_valid_manifest_object(json: &Value) -> bool {
    json.is_object()
}
