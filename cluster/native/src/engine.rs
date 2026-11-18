//! Independent native authority and durable state for the startup service.
use crate::{config::Config, fs::Dir, key, Result};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use voboost_contract_core::{
    ascii_json,
    catalog::{Catalog, Domain, FileIdentity, AGENT_ENTRY_ABI_SHA256},
    cluster::{
        AcceptedDesired, DesiredAgent, ObservedAgent, ObservedState, Receipt, ReceiptKind, Request,
        RequestKind,
    },
    generation::{
        closure_digest, select, selection_digest, GenerationIdentity, LocalProfile, SelectedTarget,
    },
    hash, parse_canonical,
    release::{verify_manifest_signature, ArtifactRole, Manifest},
    wire::{NetworkHeader, WireFile, WireRole},
    MAX_SAFE_INTEGER,
};
pub(crate) mod executable {
    use alloc::vec::Vec;
    include!("../../../shared/src/native_executable_signature.rs");
}
#[path = "resource_pack_lease.rs"]
mod resource_pack_lease;
pub use resource_pack_lease::OwnedPackLeaseInputs;

pub struct ProductRoots {
    pub catalog: [u8; 32],
    pub release: [u8; 32],
    pub executable: [u8; 32],
}
impl Default for ProductRoots {
    fn default() -> Self {
        Self {
            catalog: crate::roots::AGENT_CATALOG,
            release: crate::roots::RELEASE_CATALOG,
            executable: crate::roots::NATIVE_EXECUTABLE,
        }
    }
}
pub struct Generation {
    pub storage_id: String,
    pub identity: GenerationIdentity,
    pub generation_id: String,
    pub release_sha256: String,
    pub catalog: Catalog,
    pub selection: Vec<SelectedTarget>,
    pub files: Vec<WireFile>,
    pub request: Request,
}

pub(crate) const PEDESTRIAN_WARNING_AGENT: &str = "vehicle-drive-pedestrian-warning";
pub(crate) const PEDESTRIAN_WARNING_HIDE_ICON: &str = "vehicleDrivePedestrianWarningHideIcon";

impl Generation {
    pub(crate) fn agent_state_for(
        &self,
        executable: &str,
        agents: &[DesiredAgent],
    ) -> Result<Vec<DesiredAgent>> {
        let role = crate::config::owner_role(executable)?;
        Ok(agents
            .iter()
            .filter(|agent| {
                self.selection
                    .iter()
                    .any(|target| target.process == role && target.id == agent.id)
            })
            .cloned()
            .map(|mut state| {
                if state.id == PEDESTRIAN_WARNING_AGENT {
                    let hide = state.options.remove("intent").as_deref() == Some("on");
                    state.options.insert(
                        PEDESTRIAN_WARNING_HIDE_ICON.into(),
                        if hide { "true" } else { "false" }.into(),
                    );
                }
                state
            })
            .collect())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Durable {
    schema_version: u32,
    pair_id: String,
    authority_epoch: String,
    generation: Option<String>,
    desired_envelope: Option<String>,
    observation_revision: u64,
    desired_floor_revision: Option<u64>,
    desired_floor_sha256: Option<String>,
    #[serde(default)]
    desired_floor_locale: Option<voboost_contract_core::cluster::GlobalLocale>,
}
pub(crate) fn monotonic_ms() -> Option<u64> {
    let mut time: libc::timespec = unsafe { core::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
    {
        return None;
    }
    (time.tv_sec as u64)
        .checked_mul(1000)?
        .checked_add(time.tv_nsec as u64 / 1_000_000)
}
pub struct Authority {
    pub config: Config,
    pub root: Dir,
    pub generation: Option<Generation>,
    pub desired: Option<AcceptedDesired>,
    pub live_global_locale: Option<voboost_contract_core::cluster::GlobalLocale>,
    pub live_global_locale_deadline_ms: u64,
    pub live_pw: Option<crate::pw_live::Accepted>,
    pub boot_id: String,
    pub daemon_epoch: String,
    state: Durable,
    signer: SigningKey,
    roots: ProductRoots,
}
pub(crate) fn verify(bytes: &[u8], signature: &[u8], key: &[u8; 32]) -> Result<()> {
    VerifyingKey::from_bytes(key)
        .map_err(|_| "product public key")?
        .verify_strict(
            bytes,
            &Signature::from_slice(signature).map_err(|_| "product signature length")?,
        )
        .map_err(|_| "product signature rejected".into())
}
pub(crate) fn native_footer(
    bytes: &[u8],
    role: executable::NativeExecutableRole,
    key: &[u8; 32],
) -> Result<()> {
    let n = bytes
        .len()
        .checked_sub(80)
        .ok_or("native executable footer missing")?;
    if bytes.get(..4) != Some(b"\x7fELF")
        || &bytes[n..n + 8] != b"VOBOOST\0"
        || u64::from_le_bytes(
            bytes[n + 8..n + 16]
                .try_into()
                .map_err(|_| "native footer length")?,
        ) != n as u64
    {
        return Err("native executable footer rejected".into());
    }
    if !executable::verify(key, role, bytes) {
        return Err("product signature rejected".into());
    }
    Ok(())
}
fn wire_role(role: ArtifactRole) -> Result<WireRole> {
    Ok(match role {
        ArtifactRole::QnxDaemon => WireRole::QnxDaemon,
        ArtifactRole::QnxInit => WireRole::QnxInit,
        ArtifactRole::QnxImplant => WireRole::QnxImplant,
        ArtifactRole::QnxRuntime => WireRole::QnxRuntime,
        ArtifactRole::QnxAgentModule => WireRole::QnxAgentModule,
        ArtifactRole::QnxResourcePack => WireRole::QnxResourcePack,
        ArtifactRole::QnxResourceLedger => WireRole::QnxResourceLedger,
        ArtifactRole::AgentCatalog => WireRole::AgentCatalog,
        ArtifactRole::AgentCatalogSignature => WireRole::AgentCatalogSignature,
        _ => return Err("non-Cluster artifact role".into()),
    })
}

fn blob<'a>(files: &'a BTreeMap<String, Vec<u8>>, name: &str) -> Result<&'a [u8]> {
    files
        .get(name)
        .map(|v| v.as_slice())
        .ok_or_else(|| format!("missing signed native file {name}"))
}
pub fn check_desired(catalog: &Catalog, agents: &[DesiredAgent]) -> Result<()> {
    let mut expected: Vec<_> = catalog
        .agents
        .iter()
        .filter(|a| a.domain == Domain::Cluster)
        .collect();
    expected.sort_by(|a, b| a.id.cmp(&b.id));
    if expected.len() != agents.len() {
        return Err("desired native set incomplete".into());
    }
    for (a, d) in expected.iter().zip(agents) {
        if a.id != d.id {
            return Err("desired names unknown native agent".into());
        }
        if !declares_options(a, d) {
            return Err("desired options not declared by catalog".into());
        }
        if d.enabled
            && a.disables
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|id| agents.iter().any(|r| &r.id == id && r.enabled))
        {
            return Err("desired enables mutually exclusive native agents".into());
        }
    }
    Ok(())
}

pub(crate) fn declares_options(
    agent: &voboost_contract_core::catalog::Agent,
    state: &DesiredAgent,
) -> bool {
    let options = agent.options.as_deref().unwrap_or(&[]);
    options.len() == state.options.len()
        && options.iter().all(|option| {
            state
                .options
                .get(&option.key)
                .is_some_and(|value| option.values.iter().any(|allowed| &allowed.value == value))
        })
}

pub(crate) fn declares_projected_state(
    agent: &voboost_contract_core::catalog::Agent,
    state: &DesiredAgent,
) -> bool {
    if agent.id == PEDESTRIAN_WARNING_AGENT {
        return state.options.len() == 1
            && matches!(
                state
                    .options
                    .get(PEDESTRIAN_WARNING_HIDE_ICON)
                    .map(String::as_str),
                Some("true" | "false")
            );
    }
    declares_options(agent, state)
}
impl Authority {
    pub fn open(config: Config, owner: u32, roots: ProductRoots) -> Result<Self> {
        Self::open_inner(config, owner, roots, true)
    }

    pub(crate) fn open_generation(config: Config, owner: u32, roots: ProductRoots) -> Result<Self> {
        Self::open_inner(config, owner, roots, false)
    }

    fn open_inner(
        config: Config,
        owner: u32,
        roots: ProductRoots,
        load_desired: bool,
    ) -> Result<Self> {
        config.validate()?;
        let root = Dir::open(&config.root, owner)?;
        let seed = root.read("qnx-signing.seed", 32, 0o600)?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| "QNX signing seed must be raw32")?;
        let signer = SigningKey::from_bytes(&seed);
        if signer.verifying_key().to_bytes() != key(&config.qnx_public_key)? {
            return Err("QNX provisioned signer mismatch".into());
        }
        let boot_id =
            crate::fs::read_boot_identity(&config.boot_identity_file, &config.pair_id, owner)?;
        let state = if let Some(bytes) = crate::install_layout::read_current(&root)? {
            let s: Durable = parse_canonical(&bytes, 65536)?;
            if s.schema_version != 1
                || s.pair_id != config.pair_id
                || s.authority_epoch != config.authority_epoch
                || s.observation_revision > MAX_SAFE_INTEGER
                || s.desired_floor_revision
                    .map(|v| v > MAX_SAFE_INTEGER)
                    .unwrap_or(false)
                || s.desired_floor_sha256
                    .as_deref()
                    .map(|v| !voboost_contract_core::digest(v))
                    .unwrap_or(false)
                || s.desired_floor_revision.is_some() != s.desired_floor_sha256.is_some()
            {
                return Err("native durable authority mismatch".into());
            }
            s
        } else {
            Durable {
                schema_version: 1,
                pair_id: config.pair_id.clone(),
                authority_epoch: config.authority_epoch.clone(),
                generation: None,
                desired_envelope: None,
                observation_revision: 0,
                desired_floor_revision: None,
                desired_floor_sha256: None,
                desired_floor_locale: None,
            }
        };
        #[cfg(target_os = "nto")]
        for identity in &config.expected_build_ids {
            if !crate::elf::compatible(&identity.path, &identity.build_id) {
                return Err("local OEM compatibility identity rejected".into());
            }
        }
        let mut a = Self {
            config,
            root,
            generation: None,
            desired: None,
            live_global_locale: None,
            live_global_locale_deadline_ms: 0,
            live_pw: None,
            boot_id,
            daemon_epoch: crate::nonce()?,
            state,
            signer,
            roots,
        };
        if let Some(id) = a.state.generation.clone() {
            if !voboost_contract_core::digest(&id) {
                return Err("invalid durable generation pointer".into());
            }
            let d = a.root.child("generations")?.child(&id)?;
            let signed = d.read("request.vbc", 65536, 0o600)?;
            let request = a.request(&signed)?;
            let files = request
                .files
                .as_ref()
                .ok_or("retained generation files missing")?;
            let mut bytes = BTreeMap::new();
            for f in files {
                bytes.insert(f.file.clone(), d.read(&f.file, f.size as usize, 0o600)?);
            }
            let g = a.verify_generation(request, &bytes)?;
            if g.storage_id != id {
                return Err("retained generation pointer mismatch".into());
            }
            a.generation = Some(g);
        }
        if let Some(envelope) = a.state.desired_envelope.clone().filter(|_| load_desired) {
            let request = a.request(&hex::decode(envelope).map_err(|_| "retained desired hex")?)?;
            let g = a.generation.as_ref().ok_or("desired without generation")?;
            check_desired(
                &g.catalog,
                request.agents.as_deref().ok_or("retained desired set")?,
            )?;
            if request.desired_revision != a.state.desired_floor_revision
                || request.desired_sha256 != a.state.desired_floor_sha256
            {
                return Err("retained desired does not match durable floor".into());
            }
            a.desired = Some(
                AcceptedDesired::admit(
                    None,
                    &request,
                    &a.config.authority_epoch,
                    &g.identity.catalog_sha256,
                    &g.identity.closure_sha256,
                )?
                .0,
            );
        }
        Ok(a)
    }
    pub fn request(&self, envelope: &[u8]) -> Result<Request> {
        Self::verify_paired_request(&self.config, envelope)
    }
    pub(crate) fn verify_paired_request(config: &Config, envelope: &[u8]) -> Result<Request> {
        let request = Request::verify(
            envelope,
            &VerifyingKey::from_bytes(&key(&config.android_public_key)?)
                .map_err(|_| "Android pairing key")?,
        )?;
        if request.pair_id != config.pair_id || request.authority_epoch != config.authority_epoch {
            return Err("request belongs to another paired authority".into());
        }
        Ok(request)
    }
    pub fn verify_generation(
        &self,
        request: Request,
        bytes: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Generation> {
        if request.kind != RequestKind::Generation {
            return Err("not generation authority".into());
        }
        #[cfg(target_os = "nto")]
        for identity in &self.config.expected_build_ids {
            if !crate::elf::compatible(&identity.path, &identity.build_id) {
                return Err("current local OEM compatibility rejected".into());
            }
        }
        let files = request.files.clone().ok_or("generation closure missing")?;
        if files.len() != bytes.len() {
            return Err("generation exact file count mismatch".into());
        }
        for f in &files {
            let b = blob(bytes, &f.file)?;
            if f.size != b.len() as u64 || f.sha256 != hash(b) {
                return Err("generation file digest mismatch".into());
            }
        }
        let manifest_bytes = blob(bytes, "voboost.json")?;
        if request.release_manifest_sha256.as_deref() != Some(hash(manifest_bytes).as_str()) {
            return Err("product request digest mismatch".into());
        }
        let manifest = verify_manifest_signature(
            manifest_bytes,
            blob(bytes, "voboost.json.sig")?,
            &self.roots.release,
        )?;
        if manifest.schema_version != 1 {
            return Err("native generation requires product2".into());
        }
        let catalog_bytes = blob(bytes, "agents.json")?;
        verify(
            catalog_bytes,
            blob(bytes, "agents.json.sig")?,
            &self.roots.catalog,
        )?;
        let catalog = Catalog::parse(
            catalog_bytes,
            AGENT_ENTRY_ABI_SHA256,
            &hash(include_bytes!("../../sdk/include/voboost_cluster_v2.h")),
        )?;
        let catalog_sha = hash(catalog_bytes);
        if request.catalog_sha256 != catalog_sha {
            return Err("catalog request digest mismatch".into());
        }
        let closure = catalog.closure(Domain::Cluster)?;
        if closure_digest(&closure)? != request.closure_sha256 {
            return Err("catalog native closure mismatch".into());
        }
        let mut expected = BTreeMap::new();
        expected.insert(String::from("voboost.json"), WireRole::ReleaseManifest);
        expected.insert(
            String::from("voboost.json.sig"),
            WireRole::ReleaseManifestSignature,
        );
        for a in manifest.artifacts.iter().filter(|a| {
            is_cluster_role(a.role)
                || matches!(
                    a.role,
                    ArtifactRole::AgentCatalog | ArtifactRole::AgentCatalogSignature
                )
        }) {
            let b = blob(bytes, &a.file)?;
            if a.size != b.len() as u64 || a.sha256 != hash(b) {
                return Err("native file differs from signed product".into());
            }
            expected.insert(a.file.clone(), wire_role(a.role)?);
            let role = match a.role {
                ArtifactRole::QnxDaemon => Some(executable::NativeExecutableRole::Daemon),

                _ => None,
            };
            if let Some(role) = role {
                native_footer(b, role, &self.roots.executable)?;
            }
        }
        if expected.len() != files.len()
            || files.iter().any(|f| expected.get(&f.file) != Some(&f.role))
        {
            return Err("native product wire roles incomplete".into());
        }
        for f in &closure {
            let a = manifest.artifact(&f.file)?;
            if !is_cluster_role(a.role) || a.size != f.size || a.sha256 != f.sha256 {
                return Err("catalog/product native closure differs".into());
            }
        }
        for artifact in manifest
            .artifacts
            .iter()
            .filter(|a| a.role == ArtifactRole::QnxResourcePack)
        {
            let ledger = format!(
                "{}.json",
                artifact
                    .file
                    .strip_suffix(".kzb")
                    .ok_or("QNX pack suffix")?
            );
            voboost_contract_core::resource_pack::OwnedPack::verify(
                voboost_contract_core::resource_pack::Inputs {
                    manifest: manifest_bytes,
                    signature: blob(bytes, "voboost.json.sig")?,
                    public_key: &self.roots.release,
                    catalog: catalog_bytes,
                    artifact_file: &artifact.file,
                    pack: blob(bytes, &artifact.file)?,
                    ledger: blob(bytes, &ledger)?,
                },
            )?;
        }
        let p = &self.config.profile;
        let selection = select(
            &catalog,
            &LocalProfile {
                domain: Domain::Cluster,
                os_known: cfg!(target_os = "nto") || cfg!(test),
                architecture: "aarch64",
                os_version: p.qnx_version.as_deref(),
                chip: p.chip.as_deref(),
                vehicle: p.vehicle.as_deref(),
                powertrain: p.powertrain.as_deref(),
                market: p.market.as_deref(),
                native_control_available: true,
                build_ids: &self.config.expected_build_ids,
            },
        )?;
        let identity = GenerationIdentity {
            domain: Domain::Cluster,
            catalog_sha256: catalog_sha,
            selection_sha256: selection_digest(&selection)?,
            closure_sha256: request.closure_sha256.clone(),
        };
        let generation_id = identity.generation_id()?;
        let release_sha256 = hash(manifest_bytes);
        let storage_id = hash(format!("{generation_id}:{release_sha256}").as_bytes());
        Ok(Generation {
            storage_id,
            identity,
            generation_id,
            release_sha256,
            catalog,
            selection,
            files,
            request,
        })
    }
    fn persist(&self) -> Result<()> {
        crate::install_layout::recover_activation(&self.root, self.state.generation.as_deref())?;
        crate::install_layout::write_current(&self.root, &ascii_json(&self.state)?)
    }
    pub fn import(
        &mut self,
        envelope: &[u8],
        header: &NetworkHeader,
        bytes: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Request> {
        self.import_with_lookups(envelope, header, bytes, |directory, generation| {
            #[cfg(target_os = "nto")]
            if generation
                .catalog
                .agents
                .iter()
                .any(|agent| agent.id == crate::pw_lookup_cache::AGENT)
            {
                crate::pw_lookup_cache::prepare(directory, &generation.storage_id)?;
            }
            let _ = (directory, generation);
            Ok(())
        })
    }
    fn import_with_lookups(
        &mut self,
        envelope: &[u8],
        header: &NetworkHeader,
        bytes: &BTreeMap<String, Vec<u8>>,
        prepare_lookups: impl Fn(&Dir, &Generation) -> Result<()>,
    ) -> Result<Request> {
        let request = self.request(envelope)?;
        if header.protocol_version != 1 || header.files.is_empty() {
            return Err("invalid generation transport envelope".into());
        }
        if request.kind != RequestKind::Generation
            || request.files.as_deref() != Some(&header.files[1..])
        {
            return Err("transport differs from signed generation closure".into());
        }
        let generation = self.verify_generation(request.clone(), bytes)?;
        let generations = self.root.child("generations")?;
        if !generations.exists(&generation.storage_id)? {
            let temporary = format!("stage-{}", crate::nonce()?);
            let stage = generations.child(&temporary)?;
            stage.write("request.vbc", envelope, 0o600)?;
            for f in &generation.files {
                stage.write(&f.file, blob(bytes, &f.file)?, 0o600)?;
            }
            prepare_lookups(&stage, &generation)?;
            generations.rename(&temporary, &generation.storage_id)?;
        } else {
            let existing = generations.child(&generation.storage_id)?;
            for f in &generation.files {
                if existing.read(&f.file, f.size as usize, 0o600)? != blob(bytes, &f.file)? {
                    return Err("immutable generation bytes changed".into());
                }
            }
            prepare_lookups(&existing, &generation)?;
        }
        // Commit the next authority before exposing it to local dispatch.
        let mut state = self.state.clone();
        let changed =
            self.generation.as_ref().map(|g| &g.storage_id) != Some(&generation.storage_id);
        if changed {
            state.desired_envelope = None;
        }
        if changed {
            crate::install_layout::begin_activation(
                &self.root,
                self.state.generation.as_deref(),
                &generation.storage_id,
            )?;
        } else {
            crate::install_layout::recover_activation(
                &self.root,
                self.state.generation.as_deref(),
            )?;
        }
        state.generation = Some(generation.storage_id.clone());
        crate::install_layout::write_current(&self.root, &ascii_json(&state)?)?;
        self.state = state;
        self.generation = Some(generation);
        if changed {
            self.desired = None;
            self.live_global_locale = None;
        }
        crate::install_layout::recover_activation(&self.root, self.state.generation.as_deref())?;
        Ok(request)
    }
    pub fn admit_desired(&mut self, envelope: &[u8]) -> Result<Request> {
        let request = self.request(envelope)?;
        let g = self
            .generation
            .as_ref()
            .ok_or("native generation unavailable")?;
        check_desired(
            &g.catalog,
            request
                .agents
                .as_deref()
                .ok_or("desired agent set missing")?,
        )?;
        if let Some(floor) = self.state.desired_floor_revision {
            let revision = request.desired_revision.ok_or("desired revision missing")?;
            if revision < floor
                || revision == floor
                    && (request.desired_sha256 != self.state.desired_floor_sha256
                        || request.global_locale != self.state.desired_floor_locale)
            {
                return Err("native durable desired floor rejected rollback/conflict".into());
            }
        }
        if let (Some(next), Some(old)) = (&request.global_locale, &self.state.desired_floor_locale)
        {
            if !next.follows(old) {
                return Err("durable global locale rollback/conflict".into());
            }
        }
        let actual_observation_changed = request
            .global_locale
            .as_ref()
            .is_some_and(|value| self.state.desired_floor_locale.as_ref() != Some(value));
        let (next, admission) = AcceptedDesired::admit(
            self.desired.as_ref(),
            &request,
            &self.config.authority_epoch,
            &g.identity.catalog_sha256,
            &g.identity.closure_sha256,
        )?;
        let mut state = self.state.clone();
        state.desired_floor_revision = Some(next.desired_revision);
        state.desired_floor_sha256 = Some(next.desired_sha256.clone());
        state.desired_floor_locale = request.global_locale.clone();
        state.desired_envelope = Some(hex::encode(envelope));
        crate::install_layout::recover_activation(&self.root, self.state.generation.as_deref())?;
        crate::install_layout::write_current(&self.root, &ascii_json(&state)?)?;
        self.state = state;
        if request.global_locale.is_none() {
            self.live_global_locale = None;
            self.live_global_locale_deadline_ms = 0;
        } else if admission == voboost_contract_core::cluster::DesiredAdmission::Changed
            && actual_observation_changed
        {
            self.live_global_locale = request.global_locale.clone();
            self.live_global_locale_deadline_ms = monotonic_ms()
                .and_then(|now| now.checked_add(30_000))
                .unwrap_or(0);
        }
        // An idempotent replay after service/OEM restart cannot turn retained
        // history into a fresh observation. Fresh Binder heartbeat bumps intent
        // delivery revision; duplicate retries only preserve already-live proof.
        self.desired = Some(next);
        Ok(request)
    }
    pub fn observation_request(&self, envelope: &[u8]) -> Result<Request> {
        let request = self.request(envelope)?;
        let g = self
            .generation
            .as_ref()
            .ok_or("native generation unavailable")?;
        let d = self.desired.as_ref().ok_or("native desired unavailable")?;
        if request.kind != RequestKind::Observe
            || request.catalog_sha256 != g.identity.catalog_sha256
            || request.closure_sha256 != g.identity.closure_sha256
            || request.desired_revision != Some(d.desired_revision)
            || request.desired_sha256.as_deref() != Some(&d.desired_sha256)
        {
            return Err("observe request stale authority".into());
        }
        Ok(request)
    }
    pub fn receipt(
        &mut self,
        request: &Request,
        observed: Option<Vec<ObservedAgent>>,
    ) -> Result<Vec<u8>> {
        let g = self.generation.as_ref().ok_or("generation missing")?;
        let (revision, digest) = self
            .desired
            .as_ref()
            .map(|d| (d.desired_revision, d.desired_sha256.clone()))
            .unwrap_or((0, voboost_contract_core::cluster::desired_digest(&[])?));
        let expected: BTreeSet<_> = g
            .catalog
            .agents
            .iter()
            .filter(|a| a.domain == Domain::Cluster)
            .flat_map(|a| {
                a.targets
                    .iter()
                    .filter(|t| matches!(t, voboost_contract_core::catalog::Target::Native { .. }))
                    .map(|t| (a.id.clone(), alloc::string::String::from(t.process())))
            })
            .collect();
        let agents = observed.unwrap_or_else(|| {
            expected
                .iter()
                .map(|(id, target_process)| ObservedAgent {
                    id: id.clone(),
                    target_process: target_process.clone(),
                    state: ObservedState::WaitingProcess,
                    reason: String::from("startup-controller-unavailable"),
                    process: None,
                })
                .collect()
        });
        let mut agents = agents;
        agents.sort_by(|a, b| (&a.id, &a.target_process).cmp(&(&b.id, &b.target_process)));
        if agents.len() != expected.len()
            || agents
                .iter()
                .any(|a| !expected.contains(&(a.id.clone(), a.target_process.clone())))
            || agents
                .windows(2)
                .any(|p| p[0].id == p[1].id && p[0].target_process == p[1].target_process)
        {
            return Err("controller observation set differs from catalog".into());
        }
        self.state.observation_revision = self
            .state
            .observation_revision
            .checked_add(1)
            .filter(|v| *v <= MAX_SAFE_INTEGER)
            .ok_or("observation counter exhausted")?;
        let receipt = Receipt {
            schema_version: 1,
            kind: match request.kind {
                RequestKind::Generation => ReceiptKind::Generation,
                RequestKind::Desired => ReceiptKind::Desired,
                RequestKind::Observe => ReceiptKind::Observed,
                RequestKind::Uninstall => return Err("uninstall requires operation report".into()),
            },
            pair_id: self.config.pair_id.clone(),
            domain: Domain::Cluster,
            authority_epoch: self.config.authority_epoch.clone(),
            transaction_id: request.transaction_id.clone(),
            catalog_sha256: g.identity.catalog_sha256.clone(),
            closure_sha256: g.identity.closure_sha256.clone(),
            selection_sha256: g.identity.selection_sha256.clone(),
            generation_id: g.generation_id.clone(),
            desired_revision: revision,
            desired_sha256: digest,
            challenge: request.challenge.clone(),
            daemon_epoch: self.daemon_epoch.clone(),
            boot_id: self.boot_id.clone(),
            observation_revision: self.state.observation_revision,
            agents,
        };
        receipt.correlate(request, Some(&g.generation_id))?;
        let signed = receipt.sign(&self.signer)?;
        self.persist()?;
        Ok(signed)
    }
    pub fn manifest(&self) -> Result<Manifest> {
        let g = self.generation.as_ref().ok_or("generation missing")?;
        Manifest::parse(&self.root.child("generations")?.child(&g.storage_id)?.read(
            "voboost.json",
            4 * 1024 * 1024,
            0o600,
        )?)
    }
    pub fn closure(&self) -> Result<Vec<FileIdentity>> {
        self.generation
            .as_ref()
            .ok_or("generation missing")?
            .catalog
            .closure(Domain::Cluster)
    }
}

fn is_cluster_role(role: ArtifactRole) -> bool {
    matches!(
        role,
        ArtifactRole::QnxDaemon
            | ArtifactRole::QnxInit
            | ArtifactRole::QnxImplant
            | ArtifactRole::QnxRuntime
            | ArtifactRole::QnxAgentModule
            | ArtifactRole::QnxResourcePack
            | ArtifactRole::QnxResourceLedger
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::{Listen, Profile, Tls};
    use ed25519_dalek::Signer;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn native_footer_matches_shared_verifier_with_elf_gate() {
        let key = SigningKey::from_bytes(&[13; 32]);
        let public = key.verifying_key().to_bytes();
        let role = executable::NativeExecutableRole::Daemon;
        let sign = |prefix: &[u8]| {
            let mut signed = prefix.to_vec();
            signed.extend_from_slice(b"VOBOOST\0");
            signed.extend_from_slice(&(prefix.len() as u64).to_le_bytes());
            signed.extend_from_slice(
                &key.sign(&executable::transcript(role, prefix).unwrap())
                    .to_bytes(),
            );
            signed
        };
        let signed = sign(b"\x7fELFfixture");
        let mut corpus = vec![signed.clone(), sign(b"not-ELF")];
        for end in 0..signed.len() {
            corpus.push(signed[..end].to_vec());
        }
        for offset in 0..signed.len() {
            let mut changed = signed.clone();
            changed[offset] ^= 1;
            corpus.push(changed);
        }
        for public_key in [
            public,
            SigningKey::from_bytes(&[14; 32]).verifying_key().to_bytes(),
            [255; 32],
        ] {
            for expected_role in [role, executable::NativeExecutableRole::Inject] {
                for bytes in &corpus {
                    assert_eq!(
                        native_footer(bytes, expected_role, &public_key).is_ok(),
                        bytes.starts_with(b"\x7fELF")
                            && executable::verify(&public_key, expected_role, bytes)
                    );
                }
            }
        }
        assert!(native_footer(&signed, role, &public).is_ok());
    }
    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }
    pub(crate) fn fixture() -> (
        tempfile::TempDir,
        Config,
        ProductRoots,
        BTreeMap<String, Vec<u8>>,
        Request,
        SigningKey,
    ) {
        let temp = {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../build/cluster-test-tmp");
            std::fs::create_dir_all(&path).unwrap();
            tempfile::tempdir_in(path).unwrap()
        };
        let path = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = Dir::open(path.to_str().unwrap(), unsafe { libc::geteuid() }).unwrap();
        let catalog_key = SigningKey::from_bytes(&[11; 32]);
        let release_key = SigningKey::from_bytes(&[12; 32]);
        let exec_key = SigningKey::from_bytes(&[13; 32]);
        let qnx = SigningKey::from_bytes(&[15; 32]);
        let android = SigningKey::from_bytes(&[16; 32]);
        root.write("qnx-signing.seed", &[15; 32], 0o600).unwrap();
        root.write("boot-id", b"verified-test-boot-1\n", 0o600)
            .unwrap();
        let config = Config {
            schema_version: 1,
            root: path.to_str().unwrap().into(),
            pair_id: h('1'),
            authority_epoch: h('2'),
            android_public_key: hex::encode(android.verifying_key().to_bytes()),
            qnx_public_key: hex::encode(qnx.verifying_key().to_bytes()),
            ipc_secret: h('3'),
            boot_identity_file: format!("{}/boot-id", path.display()),
            expected_executable: "/usr/bin/gauge".into(),
            expected_build_ids: vec![voboost_contract_core::catalog::BuildIdentity {
                path: "/usr/bin/gauge".into(),
                build_id: "aabb".into(),
            }],
            profile: Profile {
                chip: None,
                vehicle: None,
                powertrain: None,
                market: None,
                qnx_version: None,
            },
            listen: Listen {
                address: "127.0.0.1".into(),
                port: 39494,
            },
            tls: Tls {
                server_certificate: "/protected/server.pem".into(),
                server_private_key: "/protected/key.pem".into(),
                client_ca: "/protected/ca.pem".into(),
                client_certificate_sha256: h('4'),
            },
        };
        let runtime = b"native-runtime-test".to_vec();
        let agent = b"native-agent-test".to_vec();
        let raw = crate::tests_catalog(&runtime, &agent);
        let catalog_bytes = voboost_contract_core::ascii_json(&raw).unwrap();
        let catalog = Catalog::parse(
            &catalog_bytes,
            AGENT_ENTRY_ABI_SHA256,
            voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256,
        )
        .unwrap();
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("agents.json".into(), catalog_bytes.clone());
        files.insert(
            "agents.json.sig".into(),
            catalog_key.sign(&catalog_bytes).to_bytes().to_vec(),
        );
        files.insert("libvoboost-runtime-cluster.so".into(), runtime);
        files.insert("libagent-font-cyrillic.so".into(), agent);
        {
            let (name, role) = (
                "voboost-cluster-daemon",
                executable::NativeExecutableRole::Daemon,
            );
            let mut bytes = b"\x7fELFtest-native".to_vec();
            let n = bytes.len();
            let signature = exec_key.sign(&executable::transcript(role, &bytes).unwrap());
            bytes.extend_from_slice(b"VOBOOST\0");
            bytes.extend_from_slice(&(n as u64).to_le_bytes());
            bytes.extend_from_slice(&signature.to_bytes());
            files.insert(name.into(), bytes);
        }
        files.insert(
            "voboost-cluster-startup.sh".into(),
            b"# signed startup test\n".to_vec(),
        );
        files.insert(
            "libvoboost-cluster-inject.so".into(),
            b"test implant".to_vec(),
        );
        let mut manifest: Manifest = Manifest::parse(include_bytes!(
            "../../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        for artifact in &mut manifest.artifacts {
            if let Some(bytes) = files.get(&artifact.file) {
                artifact.size = bytes.len() as u64;
                artifact.sha256 = hash(bytes);
            }
        }
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let release_sha = hash(&manifest_bytes);
        files.insert(
            "voboost.json.sig".into(),
            release_key.sign(&manifest_bytes).to_bytes().to_vec(),
        );
        files.insert("voboost.json".into(), manifest_bytes);
        let wire = files
            .iter()
            .map(|(name, bytes)| WireFile {
                file: name.clone(),
                size: bytes.len() as u64,
                sha256: hash(bytes),
                role: if name == "voboost.json" {
                    WireRole::ReleaseManifest
                } else if name == "voboost.json.sig" {
                    WireRole::ReleaseManifestSignature
                } else {
                    wire_role(manifest.artifact(name).unwrap().role).unwrap()
                },
            })
            .collect();
        let request = Request {
            global_locale: None,
            schema_version: 1,
            kind: RequestKind::Generation,
            pair_id: config.pair_id.clone(),
            domain: Domain::Cluster,
            authority_epoch: config.authority_epoch.clone(),
            transaction_id: h('7'),
            catalog_sha256: hash(&catalog_bytes),
            closure_sha256: closure_digest(&catalog.closure(Domain::Cluster).unwrap()).unwrap(),
            challenge: h('8'),
            release_manifest_sha256: Some(release_sha),
            files: Some(wire),
            desired_revision: None,
            desired_sha256: None,
            agents: None,
        };
        (
            temp,
            config,
            ProductRoots {
                catalog: catalog_key.verifying_key().to_bytes(),
                release: release_key.verifying_key().to_bytes(),
                executable: exec_key.verifying_key().to_bytes(),
            },
            files,
            request,
            android,
        )
    }
    fn deliver(
        a: &mut Authority,
        bytes: &BTreeMap<String, Vec<u8>>,
        request: &Request,
        android: &SigningKey,
    ) -> Result<Request> {
        let envelope = request.sign(android)?;
        let mut files = vec![WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: envelope.len() as u64,
            sha256: hash(&envelope),
        }];
        files.extend(request.files.clone().unwrap());
        a.import(
            &envelope,
            &NetworkHeader {
                protocol_version: 1,
                files,
            },
            bytes,
        )
    }
    #[test]
    fn lookup_manifest_is_published_with_verified_generation_and_refreshes_in_place() {
        use voboost_contract_core::lookups::{Descriptor, Manifest as Lookups, FILE, MAX_BYTES};

        let (_temp, config, roots, bytes, request, android) = fixture();
        let owner = unsafe { libc::geteuid() };
        let mut authority = Authority::open(config.clone(), owner, roots).unwrap();
        let envelope = request.sign(&android).unwrap();
        let mut files = vec![WireFile {
            role: WireRole::Request,
            file: "request.vbc".into(),
            size: envelope.len() as u64,
            sha256: hash(&envelope),
        }];
        files.extend(request.files.clone().unwrap());
        let header = NetworkHeader {
            protocol_version: 1,
            files,
        };
        let prepare = |revision| {
            move |directory: &Dir, generation: &Generation| {
                let mut lookups = Lookups::new(&generation.storage_id);
                lookups.insert(
                    "vehicle-drive-pedestrian-warning",
                    "cluster-light",
                    "kanzi-lookup-node",
                    Descriptor::Native {
                        library: "/lib64/libkzcoreui.so".into(),
                        contract_revision: revision,
                        export: "lookup".into(),
                        adapter: "fixture".into(),
                    },
                );
                directory.write(FILE, &lookups.bytes()?, 0o600)
            }
        };
        let rejected = authority.import_with_lookups(&envelope, &header, &bytes, |_, _| {
            Err("prepare interrupted".into())
        });
        assert!(rejected.is_err());
        assert!(authority.generation.is_none());
        assert!(crate::install_layout::read_current(&authority.root)
            .unwrap()
            .is_none());
        authority
            .import_with_lookups(&envelope, &header, &bytes, prepare(1))
            .unwrap();
        let generation = authority.generation.as_ref().unwrap().storage_id.clone();
        let directory = authority
            .root
            .child("generations")
            .unwrap()
            .child(&generation)
            .unwrap();
        let first = directory.read(FILE, MAX_BYTES, 0o600).unwrap();
        assert!(Lookups::parse(&first, &generation).is_ok());
        authority
            .import_with_lookups(&envelope, &header, &bytes, prepare(2))
            .unwrap();
        assert_eq!(
            authority.generation.as_ref().unwrap().storage_id,
            generation
        );
        let next = directory.read(FILE, MAX_BYTES, 0o600).unwrap();
        assert_ne!(next, first);
        assert!(matches!(
            Lookups::parse(&next, &generation).unwrap().get(
                "vehicle-drive-pedestrian-warning",
                "cluster-light",
                "kanzi-lookup-node"
            ),
            Some(Descriptor::Native {
                contract_revision: 2,
                ..
            })
        ));
    }

    #[test]
    fn signed_install_update_and_return_to_previous_generation_share_current() {
        let (_temp, config, roots, bytes, request, android) = fixture();
        let owner = unsafe { libc::geteuid() };
        let mut authority = Authority::open(config.clone(), owner, roots).unwrap();
        deliver(&mut authority, &bytes, &request, &android).unwrap();
        let first = authority.generation.as_ref().unwrap().storage_id.clone();

        let mut next = bytes.clone();
        let script = b"# signed updated startup fixture\n".to_vec();
        let mut manifest = Manifest::parse(&next["voboost.json"]).unwrap();
        let artifact = manifest
            .artifacts
            .iter_mut()
            .find(|entry| entry.file == "voboost-cluster-startup.sh")
            .unwrap();
        artifact.size = script.len() as u64;
        artifact.sha256 = hash(&script);
        next.insert(artifact.file.clone(), script);
        let manifest = manifest.canonical_bytes().unwrap();
        next.insert(
            "voboost.json.sig".into(),
            SigningKey::from_bytes(&[12; 32])
                .sign(&manifest)
                .to_bytes()
                .to_vec(),
        );
        next.insert("voboost.json".into(), manifest.clone());
        let mut update = request.clone();
        update.release_manifest_sha256 = Some(hash(&manifest));
        update.transaction_id = "f".repeat(64);
        for file in update.files.as_mut().unwrap() {
            let bytes = &next[&file.file];
            file.size = bytes.len() as u64;
            file.sha256 = hash(bytes);
        }
        deliver(&mut authority, &next, &update, &android).unwrap();
        let second = authority.generation.as_ref().unwrap().storage_id.clone();
        assert_ne!(first, second);
        let previous = || -> Option<String> {
            let dir = authority.root.child("generations").unwrap();
            parse_canonical(&dir.read("previous", 256, 0o600).unwrap(), 256).unwrap()
        };
        assert_eq!(previous().as_deref(), Some(first.as_str()));

        let mut rollback = request.clone();
        rollback.transaction_id = "e".repeat(64);
        deliver(&mut authority, &bytes, &rollback, &android).unwrap();
        assert_eq!(authority.generation.as_ref().unwrap().storage_id, first);
        let dir = authority.root.child("generations").unwrap();
        let previous: Option<String> =
            parse_canonical(&dir.read("previous", 256, 0o600).unwrap(), 256).unwrap();
        assert_eq!(previous.as_deref(), Some(second.as_str()));
        assert!(!authority.root.exists("authority.json").unwrap());
        let current: Durable = parse_canonical(
            &crate::install_layout::read_current(&authority.root)
                .unwrap()
                .unwrap(),
            65536,
        )
        .unwrap();
        assert_eq!(current.generation.as_deref(), Some(first.as_str()));
    }

    fn desired(a: &Authority, on: bool, revision: u64) -> Request {
        let g = a.generation.as_ref().unwrap();
        let agents = vec![DesiredAgent {
            id: "font-cyrillic".into(),
            enabled: on,
            options: BTreeMap::new(),
        }];
        Request {
            global_locale: None,
            schema_version: 1,
            kind: RequestKind::Desired,
            pair_id: a.config.pair_id.clone(),
            domain: Domain::Cluster,
            authority_epoch: a.config.authority_epoch.clone(),
            transaction_id: h('9'),
            catalog_sha256: g.identity.catalog_sha256.clone(),
            closure_sha256: g.identity.closure_sha256.clone(),
            challenge: h('a'),
            release_manifest_sha256: None,
            files: None,
            desired_revision: Some(revision),
            desired_sha256: Some(voboost_contract_core::cluster::desired_digest(&agents).unwrap()),
            agents: Some(agents),
        }
    }
    #[test]
    #[ignore = "requires actual offline Java-generated gauge input path"]
    fn signed_pack_actual_generation_staging_is_inert_and_immutable() {
        let (_temp, config, roots, mut bytes, mut request, android) = fixture();
        let stem = std::env::var("VOBOOST_QNX_PACK_SAMPLE").expect("actual Java gauge sample stem");
        let pack = std::fs::read(format!("{stem}.kzb")).unwrap();
        let ledger = std::fs::read(format!("{stem}.json")).unwrap();
        let mut raw: voboost_contract_core::agent_catalog::AgentCatalog =
            serde_json::from_slice(&bytes["agents.json"]).unwrap();
        raw.agents[0].id = "i18n-ru".into();
        raw.agents[0].targets[0].file = "libagent-i18n-ru.so".into();
        let catalog_bytes = voboost_contract_core::ascii_json(&raw).unwrap();
        let catalog = Catalog::parse(
            &catalog_bytes,
            AGENT_ENTRY_ABI_SHA256,
            voboost_contract_core::catalog::NATIVE_ENTRY_ABI_SHA256,
        )
        .unwrap();
        bytes.insert(
            "agents.json.sig".into(),
            SigningKey::from_bytes(&[11; 32])
                .sign(&catalog_bytes)
                .to_bytes()
                .to_vec(),
        );
        bytes.insert("agents.json".into(), catalog_bytes.clone());
        bytes.insert(
            "libagent-i18n-ru.so".into(),
            bytes["libagent-font-cyrillic.so"].clone(),
        );
        bytes.insert("qnx-resource-i18n-ru-test-gauge.kzb".into(), pack.clone());
        bytes.insert("qnx-resource-i18n-ru-test-gauge.json".into(), ledger);
        let mut manifest = Manifest::parse(&bytes["voboost.json"]).unwrap();
        for file in [
            "libagent-i18n-ru.so",
            "qnx-resource-i18n-ru-test-gauge.kzb",
            "qnx-resource-i18n-ru-test-gauge.json",
        ] {
            let (role, activation, abi) = voboost_contract_core::release::classify(file).unwrap();
            manifest
                .artifacts
                .push(voboost_contract_core::release::Artifact {
                    role,
                    file: file.into(),
                    size: bytes[file].len() as u64,
                    sha256: hash(&bytes[file]),
                    activation,
                    abi,
                    package_name: None,
                    version_code: None,
                    certificate_sha256: None,
                    resource: None,
                });
        }
        for row in &mut manifest.artifacts {
            if let Some(b) = bytes.get(&row.file) {
                row.size = b.len() as u64;
                row.sha256 = hash(b);
            }
        }
        manifest
            .artifacts
            .sort_by(|a, b| a.role.cmp(&b.role).then(a.file.cmp(&b.file)));
        manifest.validate().unwrap();
        let m = manifest.canonical_bytes().unwrap();
        bytes.insert(
            "voboost.json.sig".into(),
            SigningKey::from_bytes(&[12; 32])
                .sign(&m)
                .to_bytes()
                .to_vec(),
        );
        bytes.insert("voboost.json".into(), m.clone());
        request.catalog_sha256 = hash(&catalog_bytes);
        request.closure_sha256 =
            closure_digest(&catalog.closure(Domain::Cluster).unwrap()).unwrap();
        request.release_manifest_sha256 = Some(hash(&m));
        request.files = Some(
            bytes
                .iter()
                .map(|(name, b)| WireFile {
                    file: name.clone(),
                    size: b.len() as u64,
                    sha256: hash(b),
                    role: match name.as_str() {
                        "voboost.json" => WireRole::ReleaseManifest,
                        "voboost.json.sig" => WireRole::ReleaseManifestSignature,
                        _ => wire_role(manifest.artifact(name).unwrap().role).unwrap(),
                    },
                })
                .collect(),
        );
        let mut authority = Authority::open(config, unsafe { libc::geteuid() }, roots).unwrap();
        deliver(&mut authority, &bytes, &request, &android).unwrap();
        let lease = authority.owned_resource_packs().unwrap();
        assert_eq!(lease.packs.len(), 1);
        assert_eq!(lease.packs[0].pack(), pack);
        let generation = authority.generation.as_ref().unwrap();
        let dir = authority
            .root
            .child("generations")
            .unwrap()
            .child(&generation.storage_id)
            .unwrap();
        assert_eq!(
            dir.read("qnx-resource-i18n-ru-test-gauge.kzb", pack.len(), 0o600)
                .unwrap(),
            pack
        );
        assert!(authority.desired.is_none());
        let mut tampered = bytes.clone();
        tampered
            .get_mut("qnx-resource-i18n-ru-test-gauge.kzb")
            .unwrap()[0] ^= 1;
        assert!(deliver(&mut authority, &tampered, &request, &android).is_err());
        let initial = authority.owned_resource_packs().unwrap();
        let mut replacement_manifest = Manifest::parse(&bytes["voboost.json"]).unwrap();
        replacement_manifest.release_identity = "1.0.1".into();
        let replacement = replacement_manifest.canonical_bytes().unwrap();
        bytes.insert("voboost.json".into(), replacement.clone());
        bytes.insert(
            "voboost.json.sig".into(),
            SigningKey::from_bytes(&[12; 32])
                .sign(&replacement)
                .to_bytes()
                .to_vec(),
        );
        request.transaction_id = "8".repeat(64);
        request.release_manifest_sha256 = Some(hash(&replacement));
        for row in request.files.as_mut().unwrap() {
            row.size = bytes[&row.file].len() as u64;
            row.sha256 = hash(&bytes[&row.file]);
        }
        let mut imported = false;
        crate::controller::actual_signed_pack_ffi_regression(initial, || {
            if !imported {
                deliver(&mut authority, &bytes, &request, &android).unwrap();
                imported = true;
            }
            authority.owned_resource_packs().unwrap()
        });
        let mut off = desired(&authority, false, 2);
        off.agents.as_mut().unwrap()[0].id = "i18n-ru".into();
        off.desired_sha256 = Some(
            voboost_contract_core::cluster::desired_digest(off.agents.as_ref().unwrap()).unwrap(),
        );
        authority
            .admit_desired(&off.sign(&android).unwrap())
            .unwrap();
        crate::controller::actual_retained_disabled_intent_regression(&authority);
        crate::owner_restart::actual_signed_admission_regression(&authority);
    }
    #[test]
    fn locale_lease_only_refreshes_from_new_confirmed_observation() {
        let (_t, config, roots, bytes, request, android) = fixture();
        let mut a = Authority::open(config, unsafe { libc::geteuid() }, roots).unwrap();
        deliver(&mut a, &bytes, &request, &android).unwrap();
        let mut intent = desired(&a, true, 2);
        intent.global_locale = Some(voboost_contract_core::cluster::GlobalLocale {
            locale: 3,
            revision: 10,
            endpoint_identity: 2,
            lifecycle_generation: 3,
            document_generation: 1,
        });
        a.admit_desired(&intent.sign(&android).unwrap()).unwrap();
        a.live_global_locale_deadline_ms = 777;
        // A new desired revision or generation binding alone is not new readback.
        intent.desired_revision = Some(3);
        a.admit_desired(&intent.sign(&android).unwrap()).unwrap();
        assert_eq!(a.live_global_locale_deadline_ms, 777);
        a.desired = None; // same durable floor with newly imported generation
        a.live_global_locale = None;
        a.admit_desired(&intent.sign(&android).unwrap()).unwrap();
        assert!(a.live_global_locale.is_none());
        assert_eq!(a.live_global_locale_deadline_ms, 777);
        intent.desired_revision = Some(4);
        intent.global_locale.as_mut().unwrap().revision = 11;
        a.admit_desired(&intent.sign(&android).unwrap()).unwrap();
        assert!(a.live_global_locale_deadline_ms > 777);
        assert_eq!(a.live_global_locale.as_ref().unwrap().revision, 11);
        a.desired = None;
        intent.desired_revision = Some(5);
        intent.global_locale.as_mut().unwrap().revision = 9;
        assert!(a.admit_desired(&intent.sign(&android).unwrap()).is_err());
    }

    #[test]
    fn observe_receipts_bind_new_nonce_revision_and_native_authority_epoch() {
        let (_temp, config, roots, bytes, generation, android) = fixture();
        let owner = unsafe { libc::geteuid() };
        let mut authority = Authority::open(config.clone(), owner, roots).unwrap();
        let admitted = deliver(&mut authority, &bytes, &generation, &android).unwrap();
        authority.receipt(&admitted, None).unwrap();
        let desired = desired(&authority, true, 2);
        authority
            .admit_desired(&desired.sign(&android).unwrap())
            .unwrap();
        let qnx = VerifyingKey::from_bytes(&key(&config.qnx_public_key).unwrap()).unwrap();
        let mut prior_bytes: Option<Vec<u8>> = None;
        let mut prior_revision = 0;
        let native_epoch = authority.daemon_epoch.clone();
        let native_boot = authority.boot_id.clone();
        let mut last_request = desired.clone();
        for nonce in ['b', 'c', 'd'] {
            let mut request = desired.clone();
            request.kind = RequestKind::Observe;
            request.agents = None;
            request.challenge = h(nonce);
            let accepted = authority
                .observation_request(&request.sign(&android).unwrap())
                .unwrap();
            let produced = authority.receipt(&accepted, None).unwrap();
            let consumed = Receipt::verify(&produced, &qnx).unwrap();
            consumed
                .correlate(&request, Some(&consumed.generation_id))
                .unwrap();
            assert!(consumed.observation_revision > prior_revision);
            assert_eq!(consumed.boot_id, native_boot);
            assert_eq!(consumed.daemon_epoch, native_epoch);
            if let Some(replayed) = &prior_bytes {
                let old = Receipt::verify(replayed, &qnx).unwrap();
                assert!(old.correlate(&request, Some(&old.generation_id)).is_err());
            }
            let mut tampered = produced.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(Receipt::verify(&tampered, &qnx).is_err());
            prior_revision = consumed.observation_revision;
            prior_bytes = Some(produced);
            last_request = request;
        }
        drop(authority);
        let roots = ProductRoots {
            catalog: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
            release: SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
            executable: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
        };
        let mut restarted = Authority::open(config, owner, roots).unwrap();
        assert_ne!(restarted.daemon_epoch, native_epoch);
        last_request.challenge = h('e');
        let accepted = restarted
            .observation_request(&last_request.sign(&android).unwrap())
            .unwrap();
        let produced = restarted.receipt(&accepted, None).unwrap();
        let consumed = Receipt::verify(&produced, &qnx).unwrap();
        consumed
            .correlate(&last_request, Some(&consumed.generation_id))
            .unwrap();
        assert!(consumed.observation_revision > prior_revision);
        assert_eq!(consumed.boot_id, native_boot);
        assert_ne!(consumed.daemon_epoch, native_epoch);
    }

    #[test]
    fn signed_generation_desired_restart_and_tampered_store_fail_closed() {
        let (_t, config, roots, bytes, request, android) = fixture();
        let owner = unsafe { libc::geteuid() };
        let mut a = Authority::open(config.clone(), owner, roots).unwrap();
        let admitted = deliver(&mut a, &bytes, &request, &android).unwrap();
        let receipt = a.receipt(&admitted, None).unwrap();
        let qnx = VerifyingKey::from_bytes(&key(&config.qnx_public_key).unwrap()).unwrap();
        let observed = Receipt::verify(&receipt, &qnx).unwrap();
        observed.correlate(&request, None).unwrap();
        assert!(observed
            .agents
            .iter()
            .all(|r| r.state == ObservedState::WaitingProcess));
        let on = desired(&a, true, 2);
        a.admit_desired(&on.sign(&android).unwrap()).unwrap();
        let wrong = SigningKey::from_bytes(&[17; 32]);
        assert!(a
            .admit_desired(&desired(&a, false, 3).sign(&wrong).unwrap())
            .is_err());
        let mut off = desired(&a, false, 3);
        off.global_locale = Some(voboost_contract_core::cluster::GlobalLocale {
            locale: 3,
            revision: 10,
            endpoint_identity: 2,
            lifecycle_generation: 3,
            document_generation: 1,
        });
        a.admit_desired(&off.sign(&android).unwrap()).unwrap();
        assert_eq!(a.live_global_locale, off.global_locale);
        assert!(a.admit_desired(&on.sign(&android).unwrap()).is_err());
        let old_epoch = a.daemon_epoch.clone();
        let id = a.generation.as_ref().unwrap().storage_id.clone();
        let roots = ProductRoots {
            catalog: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
            release: SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
            executable: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
        };
        let mut reopened = Authority::open(config.clone(), owner, roots).unwrap();
        assert_ne!(reopened.daemon_epoch, old_epoch);
        assert!(reopened.live_global_locale.is_none());
        assert_eq!(
            reopened.desired.as_ref().unwrap().global_locale,
            off.global_locale
        );
        reopened
            .admit_desired(&off.sign(&android).unwrap())
            .unwrap();
        assert!(reopened.live_global_locale.is_none());
        assert!(!reopened.desired.as_ref().unwrap().agents[0].enabled);
        assert!(reopened.admit_desired(&on.sign(&android).unwrap()).is_err());
        reopened
            .root
            .child("generations")
            .unwrap()
            .child(&id)
            .unwrap()
            .write("libagent-font-cyrillic.so", b"tamper", 0o600)
            .unwrap();
        let roots = ProductRoots {
            catalog: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
            release: SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
            executable: SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
        };
        assert!(Authority::open(config, owner, roots).is_err());
    }
    #[test]
    fn generation_rejects_missing_files_wrong_roles_and_modified_bytes() {
        let (_t, config, roots, bytes, request, android) = fixture();
        let mut a = Authority::open(config, unsafe { libc::geteuid() }, roots).unwrap();
        let mut missing = bytes.clone();
        missing.remove("libvoboost-runtime-cluster.so");
        assert!(deliver(&mut a, &missing, &request, &android).is_err());
        let mut altered = bytes.clone();
        altered.get_mut("voboost-cluster-daemon").unwrap()[0] = 0;
        assert!(deliver(&mut a, &altered, &request, &android).is_err());
        let mut role = request.clone();
        role.files
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|f| f.file == "voboost-cluster-daemon")
            .unwrap()
            .role = WireRole::Restore;
        assert!(deliver(&mut a, &bytes, &role, &android).is_err());
        assert!(a.generation.is_none());
        assert!(crate::install_layout::read_current(&a.root)
            .unwrap()
            .is_none());
    }
}
