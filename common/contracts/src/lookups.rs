//! Local generation metadata. These results never authorize code or a target.
use crate::{ascii_json, digest, identifier, parse_canonical, printable, safe_path, Result};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

pub const FILE: &str = "lookups.json";
pub const MAX_BYTES: usize = 65536;

type Components = BTreeMap<String, BTreeMap<String, Descriptor>>;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    schema_version: u32,
    generation: String,
    agents: BTreeMap<String, Components>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Descriptor {
    Native {
        library: String,
        contract_revision: u32,
        export: String,
        adapter: String,
    },
    Java {
        artifact: String,
        file_sha256: String,
        contract_revision: u32,
        class_name: String,
        member: String,
        signature: String,
        adapter: String,
    },
}

impl Descriptor {
    fn valid(&self) -> bool {
        match self {
            Self::Native {
                library,
                contract_revision,
                export,
                adapter,
            } => {
                safe_path(library)
                    && *contract_revision > 0
                    && identifier(export, 512)
                    && identifier(adapter, 96)
            }
            Self::Java {
                artifact,
                file_sha256,
                contract_revision,
                class_name,
                member,
                signature,
                adapter,
            } => {
                identifier(artifact, 128)
                    && digest(file_sha256)
                    && *contract_revision > 0
                    && printable(class_name, 512)
                    && printable(member, 256)
                    && printable(signature, 1024)
                    && identifier(adapter, 96)
            }
        }
    }
}

impl Manifest {
    pub fn new(generation: &str) -> Self {
        Self {
            schema_version: 1,
            generation: generation.into(),
            agents: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, agent: &str, component: &str, lookup: &str, descriptor: Descriptor) {
        self.agents
            .entry(agent.into())
            .or_default()
            .entry(component.into())
            .or_default()
            .insert(lookup.into(), descriptor);
    }

    pub fn get(&self, agent: &str, component: &str, lookup: &str) -> Option<&Descriptor> {
        self.agents.get(agent)?.get(component)?.get(lookup)
    }

    fn validate(&self, generation: &str) -> Result<()> {
        if self.schema_version != 1
            || self.generation != generation
            || !digest(generation)
            || self.agents.len() > 128
            || self.agents.iter().any(|(agent, components)| {
                !identifier(agent, 128)
                    || components.is_empty()
                    || components.len() > 16
                    || components.iter().any(|(component, lookups)| {
                        !identifier(component, 96)
                            || lookups.is_empty()
                            || lookups.len() > 128
                            || lookups
                                .iter()
                                .any(|(id, descriptor)| !identifier(id, 128) || !descriptor.valid())
                    })
            })
        {
            return Err("invalid generation lookup manifest".into());
        }
        Ok(())
    }

    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate(&self.generation)?;
        let bytes = ascii_json(self)?;
        if bytes.len() > MAX_BYTES {
            return Err("generation lookup manifest exceeds bound".into());
        }
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8], generation: &str) -> Result<Self> {
        let manifest: Self = parse_canonical(bytes, MAX_BYTES)?;
        manifest.validate(generation)?;
        Ok(manifest)
    }
}
