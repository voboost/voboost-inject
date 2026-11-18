//! Only signed active catalog relations may expand a user checkbox action.
use super::{invalid, Store};
use crate::generation_catalog;
use std::io;

impl Store {
    fn catalog_for_desired(&mut self) -> io::Result<voboost_contract::agent_catalog::AgentCatalog> {
        let (generations, id) = generation_catalog::active(&self.root)?;
        if let Some((cached_id, catalog)) = &self.desired_catalog {
            if cached_id == &id {
                return Ok(catalog.clone());
            }
        }
        let catalog = generation_catalog::read(&generations, &id)?;
        self.desired_catalog = Some((id, catalog.clone()));
        Ok(catalog)
    }

    pub(super) fn normalize_desired_catalog(&mut self, bytes: Vec<u8>) -> io::Result<Vec<u8>> {
        let current = voboost_contract::desired::Config::decode(&bytes)?;
        let catalog = match self.catalog_for_desired() {
            Ok(catalog) => catalog,
            Err(_) => return Ok(bytes),
        };
        let relations = catalog
            .agents
            .iter()
            .filter(|agent| {
                agent.kind.as_deref() != Some("executor")
                    && matches!(
                        agent.activation,
                        Some(voboost_contract::agent_catalog::Activation::Checkbox { .. })
                    )
            })
            .filter_map(|agent| {
                agent
                    .disables
                    .as_ref()
                    .map(|disables| (agent.id.clone(), disables.clone()))
            })
            .collect();
        let Some(next) = current.normalize_exclusive(&relations)? else {
            return Ok(bytes);
        };
        let disabled: Vec<_> = current
            .agents
            .iter()
            .filter(|(id, agent)| agent.enabled && !next.agents[*id].enabled)
            .map(|(id, _)| id.as_str())
            .collect();
        let normalized = serde_json::to_vec(&next).map_err(io::Error::other)?;
        if self.config()?.as_deref() != Some(bytes.as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "desired configuration changed during conflict normalization",
            ));
        }
        super::Directory::open(&self.root)?.write_atomic("agents.json", &normalized, 0o600)?;
        let _ = self.write_log(
            voboost_contract::runtime_log::Source::daemon(),
            voboost_contract::runtime_log::Record {
                level: voboost_contract::runtime_log::Level::Error,
                component: "settings".into(),
                message: "Conflicting agent choices were disabled".into(),
                fields: std::collections::HashMap::from([
                    ("reason".into(), "signed-catalog-disables".into()),
                    ("disabledAgents".into(), disabled.join(",")),
                    ("previousRevision".into(), current.user_revision.to_string()),
                    ("revision".into(), next.user_revision.to_string()),
                ]),
            },
        );
        Ok(normalized)
    }

    pub(super) fn desired_dependencies(&mut self, source: &str) -> io::Result<Vec<String>> {
        let catalog = self.catalog_for_desired()?;
        let mut matches = catalog.agents.iter().filter(|agent| agent.id == source);
        let agent = matches
            .next()
            .ok_or_else(|| invalid("checkbox catalog entry unavailable"))?;
        if matches.next().is_some() {
            return Err(invalid("checkbox catalog entry ambiguous"));
        }
        if agent.kind.as_deref() == Some("executor")
            || !matches!(
                agent.activation,
                Some(voboost_contract::agent_catalog::Activation::Checkbox { .. })
            )
        {
            return Err(invalid("agent does not expose a user checkbox"));
        }
        let dependencies = agent.disables.clone().unwrap_or_default();
        if dependencies
            .iter()
            .any(|id| !voboost_contract::runtime_owner::valid_source(id) || id == source)
        {
            return Err(invalid("checkbox dependencies invalid"));
        }
        Ok(dependencies)
    }

    pub(super) fn refresh_desired_catalog_fences(&mut self, config: &serde_json::Value) {
        let Some(agents) = config["agents"].as_object() else {
            return;
        };
        let revision = |source: &str| {
            config["fieldRevisions"][format!("agents/{source}/enabled")]["revision"]
                .as_u64()
                .unwrap_or(0)
        };
        let explicit: Vec<_> = agents
            .iter()
            .filter(|(source, value)| value["enabled"] == true && revision(source) > 0)
            .map(|(source, _)| source.clone())
            .collect();
        self.desired_catalog_fences.clear();
        for source in explicit {
            match self.desired_dependencies(&source) {
                Ok(dependencies) => {
                    for dependency in dependencies {
                        if config["agents"][&dependency]["enabled"] != true {
                            continue;
                        }
                        let blocked = if revision(&source) > revision(&dependency) {
                            dependency
                        } else {
                            source.clone()
                        };
                        self.desired_catalog_fences.insert(blocked.clone());
                        self.revoke_source(&blocked);
                    }
                }
                Err(_) => {
                    self.desired_catalog_fences.insert(source.clone());
                    self.revoke_source(&source);
                }
            }
        }
    }
}
