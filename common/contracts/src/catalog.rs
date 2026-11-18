//! Authenticated catalog2 types and complete domain closure validation.
use crate::{
    agent_catalog::{
        Activation, AgentOption, AgentStatus, LocaleMap, SettingsTab, StartupPriority,
    },
    ascii_json, basename, digest, identifier, Result, MAX_CLOSURE_BYTES, MAX_FILE_BYTES,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use serde::{Deserialize, Serialize};

pub const NATIVE_ENTRY_ABI_SHA256: &str =
    "a74f7cb36661c32f82ea2da85143b066e5b2abbe0650b88987d1956d2f53b8f4";

pub const AGENT_ENTRY_ABI_SHA256: &str =
    "8be969ce42ac44bf8c47d60405d6e44e989640f07c867d6ba2e30f33b7acbb13";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Domain {
    Cluster,
    Multimedia,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeKind {
    Dex,
    Native,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Android,
    Qnx,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntryAbi {
    pub schema_version: u32,
    pub sha256: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}
impl FileIdentity {
    pub fn validate(&self) -> Result<()> {
        if !basename(&self.file)
            || self.size == 0
            || self.size > MAX_FILE_BYTES
            || !digest(&self.sha256)
        {
            return Err("invalid file identity".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Runtime {
    pub domain: Domain,
    pub kind: RuntimeKind,
    pub os: OperatingSystem,
    pub supported_abis: Vec<String>,
    pub entry_abi: EntryAbi,
    pub files: Vec<FileIdentity>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildIdentity {
    pub path: String,
    pub build_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Target {
    Dex {
        process: String,
        file: String,
        size: u64,
        sha256: String,
        #[serde(rename = "entryClass")]
        entry_class: String,
        boot: bool,
    },
    Native {
        process: String,
        executable: String,
        file: String,
        size: u64,
        sha256: String,
        entry: String,
        abi: u32,
        architecture: String,
        compatibility: Vec<BuildIdentity>,
    },
}
impl Target {
    pub fn process(&self) -> &str {
        match self {
            Self::Dex { process, .. } | Self::Native { process, .. } => process,
        }
    }
    pub fn file(&self) -> FileIdentity {
        match self {
            Self::Dex {
                file, size, sha256, ..
            }
            | Self::Native {
                file, size, sha256, ..
            } => FileIdentity {
                file: file.clone(),
                size: *size,
                sha256: sha256.clone(),
            },
        }
    }
    pub fn entry(&self) -> &str {
        match self {
            Self::Dex { entry_class, .. } => entry_class,
            Self::Native { entry, .. } => entry,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Applicability {
    Android(AndroidApplicability),
    Qnx(QnxApplicability),
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AndroidApplicability {
    pub chip: Vec<String>,
    pub vehicle: Vec<String>,
    pub android: Vec<u8>,
    pub powertrain: Vec<String>,
    pub market: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QnxApplicability {
    pub chip: Vec<String>,
    pub vehicle: Vec<String>,
    pub qnx: Vec<String>,
    pub powertrain: Vec<String>,
    pub market: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Agent {
    pub id: String,
    pub domain: Domain,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_priority: Option<StartupPriority>,
    pub targets: Vec<Target>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_tab: Option<SettingsTab>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation: Option<Activation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disables: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<AgentOption>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<LocaleMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<LocaleMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicability: Option<Applicability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configuration: Option<BTreeMap<String, String>>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub runtimes: Vec<Runtime>,
    pub agents: Vec<Agent>,
}

impl Catalog {
    /// Parses only the canonical target-scoped producer schema; this is a derived view.
    pub fn parse(bytes: &[u8], dex_abi_digest: &str, _native_abi_digest: &str) -> Result<Self> {
        use crate::agent_catalog::{AgentCatalog, TargetAbi, TargetDomain, TargetPlatform};
        if bytes.is_empty() || bytes.len() > 1024 * 1024 || !bytes.is_ascii() {
            return Err("catalog byte envelope is invalid".into());
        }
        let raw: AgentCatalog =
            serde_json::from_slice(bytes).map_err(|e| format!("catalog2 JSON: {e}"))?;
        if ascii_json(&raw)? != bytes
            || raw.schema_version != 2
            || raw.agent_entry_abi.schema_version != 1
            || raw.agent_entry_abi.sha256 != dex_abi_digest
            || !digest(dex_abi_digest)
            || raw.supported_abis.is_empty()
            || raw.supported_abis.iter().collect::<BTreeSet<_>>().len() != raw.supported_abis.len()
            || raw
                .supported_abis
                .iter()
                .any(|a| !matches!(a.as_str(), "arm64-v8a" | "armeabi-v7a"))
            || raw.core.file != "agent-common.dex"
            || raw.agents.is_empty()
            || raw.agents.len() > 64
        {
            return Err("invalid canonical catalog2 envelope".into());
        }
        let has_qnx = raw
            .agents
            .iter()
            .any(|a| a.targets.iter().any(|t| t.platform == TargetPlatform::Qnx));
        if has_qnx && _native_abi_digest != NATIVE_ENTRY_ABI_SHA256 {
            return Err("native SDK2 ABI digest mismatch".into());
        }
        if has_qnx != raw.cluster_runtime.is_some() {
            return Err("cluster runtime and target closure disagree".into());
        }
        let identity = |f: &crate::agent_catalog::CatalogFile| FileIdentity {
            file: f.file.clone(),
            size: f.size,
            sha256: f.sha256.clone(),
        };
        let core = identity(&raw.core);
        core.validate()?;
        let mut runtimes = alloc::vec![Runtime {
            domain: Domain::Multimedia,
            kind: RuntimeKind::Dex,
            os: OperatingSystem::Android,
            supported_abis: raw.supported_abis.clone(),
            entry_abi: EntryAbi {
                schema_version: 1,
                sha256: dex_abi_digest.into()
            },
            files: alloc::vec![core]
        }];
        if let Some(runtime) = &raw.cluster_runtime {
            let file = identity(runtime);
            file.validate()?;
            if file.file != "libvoboost-runtime-cluster.so" {
                return Err("invalid cluster runtime".into());
            }
            runtimes.push(Runtime {
                domain: Domain::Cluster,
                kind: RuntimeKind::Native,
                os: OperatingSystem::Qnx,
                supported_abis: alloc::vec!["aarch64".into()],
                entry_abi: EntryAbi {
                    schema_version: 2,
                    sha256: _native_abi_digest.into(),
                },
                files: alloc::vec![file],
            });
        }
        let mut agents = Vec::new();
        let mut ids = BTreeSet::new();
        for agent in &raw.agents {
            if !identifier(&agent.id, 96)
                || !ids.insert(&agent.id)
                || agent.targets.is_empty()
                || agent.targets.len() > 64
            {
                return Err("invalid agent authority".into());
            }
            let mut tuples = BTreeSet::new();
            for domain in [Domain::Multimedia, Domain::Cluster] {
                let mut targets = Vec::new();
                for target in &agent.targets {
                    let file = FileIdentity {
                        file: target.file.clone(),
                        size: target.size,
                        sha256: target.sha256.clone(),
                    };
                    file.validate()?;
                    let selected = match (target.platform, target.domain, target.entry_abi) {
                        (
                            TargetPlatform::Android,
                            TargetDomain::Android,
                            TargetAbi::AndroidJavaV1,
                        ) => {
                            if !(agent.id == "launcher" && target.process == "system_server")
                                && !valid_android_process(&target.process)
                            {
                                return Err("invalid Android target process".into());
                            }
                            if target.boot
                                || !target.file.starts_with("agent-")
                                || !target.file.ends_with(".dex")
                                || !target
                                    .entry_class
                                    .as_deref()
                                    .map(valid_java_class)
                                    .unwrap_or(false)
                            {
                                return Err("invalid Android target".into());
                            }
                            if domain != Domain::Multimedia {
                                continue;
                            }
                            Target::Dex {
                                process: target.process.clone(),
                                file: target.file.clone(),
                                size: target.size,
                                sha256: target.sha256.clone(),
                                entry_class: target.entry_class.clone().unwrap(),
                                boot: false,
                            }
                        }
                        (
                            TargetPlatform::Qnx,
                            TargetDomain::Cluster,
                            TargetAbi::VoboostAgent3V1,
                        ) => {
                            if target.boot
                                || target.entry_class.is_some()
                                || target.file != format!("libagent-{}.so", agent.id)
                                || !matches!(target.process.as_str(), "gauge" | "point" | "light")
                                || raw.cluster_runtime.is_none()
                            {
                                return Err("invalid QNX target".into());
                            }
                            if domain != Domain::Cluster {
                                continue;
                            }
                            Target::Native {
                                process: target.process.clone(),
                                executable: format!("/usr/bin/{}", target.process),
                                file: target.file.clone(),
                                size: target.size,
                                sha256: target.sha256.clone(),
                                entry: "vbc_native_agent_v3".into(),
                                abi: 3,
                                architecture: "aarch64".into(),
                                compatibility: Vec::new(),
                            }
                        }
                        _ => return Err("cross-domain target tuple".into()),
                    };
                    if !tuples.insert((domain, target.process.clone())) {
                        return Err("duplicate target authority".into());
                    }
                    targets.push(selected);
                }
                if targets.is_empty() {
                    continue;
                }
                let applicability = agent.applicability.as_ref().map(|a| match domain {
                    Domain::Multimedia => Applicability::Android(AndroidApplicability {
                        chip: a.chip.clone(),
                        vehicle: a.vehicle.clone(),
                        android: a.android.clone(),
                        powertrain: a.powertrain.clone(),
                        market: a.market.clone(),
                    }),
                    Domain::Cluster => Applicability::Qnx(QnxApplicability {
                        chip: a.chip.clone(),
                        vehicle: a.vehicle.clone(),
                        qnx: Vec::new(),
                        powertrain: a.powertrain.clone(),
                        market: a.market.clone(),
                    }),
                });
                agents.push(Agent {
                    id: agent.id.clone(),
                    domain,
                    kind: agent.kind.clone(),
                    surfaces: agent.surfaces.clone(),
                    startup_priority: agent.startup_priority,
                    targets,
                    settings_tab: agent.settings_tab.clone(),
                    status: agent.status,
                    category: agent.category.clone(),
                    order: agent.order,
                    activation: agent.activation.clone(),
                    disables: agent.disables.clone(),
                    options: agent.options.clone(),
                    title: agent.title.clone(),
                    description: agent.description.clone(),
                    applicability,
                    configuration: None,
                });
            }
        }
        let catalog = Self {
            schema_version: 2,
            runtimes,
            agents,
        };
        catalog.validate(dex_abi_digest, _native_abi_digest)?;
        Ok(catalog)
    }
    pub fn validate(&self, _dex: &str, _native: &str) -> Result<()> {
        if self.schema_version != 2 {
            return Err("unsupported derived catalog".into());
        }
        for agent in &self.agents {
            if let Some(disables) = &agent.disables {
                for id in disables {
                    if id == &agent.id
                        || !self
                            .agents
                            .iter()
                            .any(|other| other.id == *id && other.domain == agent.domain)
                    {
                        return Err("invalid domain disables relation".into());
                    }
                }
            }
        }
        self.closure(Domain::Cluster)?;
        self.closure(Domain::Multimedia)?;
        Ok(())
    }
    pub fn closure(&self, domain: Domain) -> Result<Vec<FileIdentity>> {
        let mut files = BTreeMap::<String, FileIdentity>::new();
        for file in self
            .runtimes
            .iter()
            .filter(|r| r.domain == domain)
            .flat_map(|r| r.files.iter())
            .cloned()
            .chain(
                self.agents
                    .iter()
                    .filter(|a| a.domain == domain)
                    .flat_map(|a| a.targets.iter().map(Target::file)),
            )
        {
            file.validate()?;
            if let Some(old) = files.insert(file.file.clone(), file.clone()) {
                if old != file {
                    return Err("file authority collision".into());
                }
            }
        }
        let files: Vec<_> = files.into_values().collect();
        let mut total = 0u64;
        for f in &files {
            total = total.checked_add(f.size).ok_or("closure size overflow")?;
        }
        if files.len() > 252 || total > MAX_CLOSURE_BYTES {
            return Err("closure exceeds bounds".into());
        }
        Ok(files)
    }
}
pub fn validate_string_map(map: &BTreeMap<String, String>) -> Result<()> {
    if map.len() > 16
        || map
            .iter()
            .any(|(k, v)| !identifier(k, 64) || !crate::printable(v, 256))
    {
        return Err("invalid bounded configuration map".into());
    }
    Ok(())
}
fn valid_android_process(value: &str) -> bool {
    if value.is_empty() || value.len() > 255 {
        return false;
    }
    let (package, suffix) = value
        .split_once(':')
        .map_or((value, None), |(p, s)| (p, Some(s)));
    package.contains('.')
        && package.split('.').all(valid_process_component)
        && suffix
            .map(|s| !s.contains('.') && valid_process_component(s))
            .unwrap_or(true)
}
fn valid_process_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && (bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}
fn valid_java_class(s: &str) -> bool {
    s.contains('.')
        && s.len() <= 255
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_$".contains(&b))
        })
}
