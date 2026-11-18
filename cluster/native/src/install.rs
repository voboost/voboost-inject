//! Explicit protected startup integration. No guessed OEM paths or process control.
use crate::{
    config::Config,
    engine::{executable::NativeExecutableRole, native_footer, ProductRoots},
    fs::{read_protected, Dir, UninstallBoot},
    Result,
};
#[cfg(target_os = "nto")]
use alloc::string::ToString;
use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use voboost_contract_core::{
    ascii_json,
    catalog::{Catalog, Domain, FileIdentity, AGENT_ENTRY_ABI_SHA256},
    digest,
    domain_operation::{
        AuthenticatedReport, DomainOperationReport, Operation, Outcome, Phase, RootScope,
    },
    hash, parse_canonical,
    release::{
        verify_installed_manifest_for_removal, verify_manifest_signature, verify_restore_authority,
        ArtifactRole, Manifest,
    },
    safe_path,
};
/// Structurally probed OEM launcher integrations. This changes only where the
/// environment is inherited; runtime admission still verifies the actual process.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupProfile {
    Clusterboot,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Integration {
    pub schema_version: u32,
    pub bootfile: String,
    pub source_directory: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provision_directory: Option<String>,
    pub startup_file: String,
    pub original_sha256: String,
    pub anchor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup_profile: Option<StartupProfile>,
    pub scope: RootScope,
    pub root_device_id: String,
    pub transaction_id: String,
    pub challenge: String,
    pub receipt_file: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Installation {
    schema_version: u32,
    bootfile: String,
    startup_file: String,
    original_sha256: String,
    installed_sha256: String,
    startup_mode: u32,
    release_manifest_sha256: String,
    catalog_sha256: String,
    files: Vec<FileIdentity>,
    /// Typed supervisor-config capability receipt; absent means the
    /// installation has no config-delivery capability, never an inferred
    /// default. Exact-byte comparisons only; this introduces no new digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supervisor_config: Option<crate::supervisor_config::SupervisorConfig>,
}
/// Protected installed bytes, not supervisor liveness or delivery permission.
pub(crate) struct ValidatedSupervisorInstallation {
    bootfile: String,
    implant_path: String,
    identity: String,
}
impl ValidatedSupervisorInstallation {
    pub(crate) fn bootfile(&self) -> &str {
        &self.bootfile
    }
    pub(crate) fn implant_path(&self) -> &str {
        &self.implant_path
    }
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }
}
/// Admission accessor for the typed supervisor-config subrecord: reuses the
/// full Installation parse/validation so the enclosing signed-authority
/// checks stay active. Called only under the supervisor operation lock.
#[cfg(any(target_os = "nto", test))]
pub(crate) fn supervisor_config_receipt(
    root: &Dir,
) -> Result<Option<crate::supervisor_config::SupervisorConfig>> {
    let proof: Installation = parse_canonical(&crate::install_layout::read_state(root)?, 65536)?;
    if proof.schema_version != 1 {
        return Err("supervisor installation receipt invalid".into());
    }
    Ok(proof.supervisor_config)
}

/// Persist the new Installation record retaining the FIRST original config
/// state and every existing field except the subrecord. The transaction
/// calls this only after the installed-candidate sidecar is durable.
#[cfg(any(target_os = "nto", test))]
pub(crate) fn persist_supervisor_config_receipt(
    root: &Dir,
    receipt: &crate::supervisor_config::SupervisorConfig,
) -> Result<()> {
    let bytes = crate::install_layout::read_state(root)?;
    let mut proof: Installation = parse_canonical(&bytes, 65536)?;
    if proof.schema_version != 1 {
        return Err("supervisor installation receipt invalid".into());
    }
    // The subrecord written into the protected record is validated, not
    // just constructed: every persisted receipt keeps the exact contract.
    receipt.validate()?;
    // FIRST original absence/mode never changes across updates.
    if let Some(previous) = &proof.supervisor_config {
        if previous.original_absent != receipt.original_absent
            || previous.original_mode != receipt.original_mode
        {
            return Err("SetupRequired: FIRST original config state is immutable".into());
        }
    }
    proof.supervisor_config = Some(receipt.clone());
    let updated = ascii_json(&proof)?;
    crate::install_layout::write_state(root, &updated)
}
/// Remove the typed subrecord when the config transaction restores the FIRST
/// original/absent state: capability evidence must not outlive the config.
#[cfg(any(target_os = "nto", test))]
pub(crate) fn clear_supervisor_config_receipt(root: &Dir) -> Result<()> {
    let bytes = crate::install_layout::read_state(root)?;
    let mut proof: Installation = parse_canonical(&bytes, 65536)?;
    if proof.schema_version != 1 {
        return Err("supervisor installation receipt invalid".into());
    }
    proof.supervisor_config = None;
    let updated = ascii_json(&proof)?;
    crate::install_layout::write_state(root, &updated)
}

pub(crate) fn supervisor_installation(config: &Config) -> Result<ValidatedSupervisorInstallation> {
    let owner = crate::fs::uid()?;
    if !cfg!(test) && owner != 0 {
        return Err("supervisor installation requires root".into());
    }
    config.validate()?;
    let root = Dir::open(&config.root, owner)?;
    let receipt = crate::install_layout::read_state(&root)?;
    let proof: Installation = parse_canonical(&receipt, 65536)?;
    let bootfile = format!("{}/boot.json", config.root);
    if proof.schema_version != 1
        || proof.bootfile != bootfile
        || !safe_path(&proof.startup_file)
        || !digest(&proof.original_sha256)
        || !digest(&proof.installed_sha256)
        || !digest(&proof.release_manifest_sha256)
        || !digest(&proof.catalog_sha256)
    {
        return Err("supervisor installation receipt invalid".into());
    }
    let actual_config = Config::parse(&read_protected(&bootfile, owner, 16384, 0o600)?)?;
    if ascii_json(&actual_config)? != ascii_json(config)? {
        return Err("supervisor installation config changed".into());
    }
    let original = root.read("startup.original", 1024 * 1024, 0o600)?;
    let (_, _, current, mode) = startup(&proof.startup_file, owner)?;
    if hash(&original) != proof.original_sha256
        || hash(&current) != proof.installed_sha256
        || mode != proof.startup_mode
    {
        return Err("supervisor installation startup is not installed".into());
    }
    let matches: Vec<_> = proof
        .files
        .iter()
        .filter(|f| f.file == "libvoboost-cluster-inject.so")
        .collect();
    if matches.len() != 1 {
        return Err("supervisor implant receipt is not unique".into());
    }
    let implant = matches[0];
    if implant.size == 0 || implant.size > 32 * 1024 * 1024 || !digest(&implant.sha256) {
        return Err("supervisor implant receipt invalid".into());
    }
    let bin = Dir::open(&format!("{}/bin", config.root), owner)?;
    let bytes = bin.read(
        &implant.file,
        implant.size as usize,
        installed_artifact_mode(&implant.file),
    )?;
    if bytes.len() as u64 != implant.size
        || hash(&bytes) != implant.sha256
        || crate::install_layout::read_state(&root)? != receipt
    {
        return Err("supervisor implant installation changed".into());
    }
    Ok(ValidatedSupervisorInstallation {
        bootfile,
        implant_path: format!("{}/bin/{}", config.root, implant.file),
        identity: hash(&receipt),
    })
}
/// Read-only bootstrap classification. The protected request is supplied through
/// the pinned helper transport; this is an observation, never a signed operation receipt.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryObservationInput {
    pub schema_version: u32,
    pub transaction_id: String,
    pub challenge: String,
    pub pair_id: String,
    pub authority_epoch: String,
    pub qnx_public_key: String,
    pub release_manifest_sha256: String,
    pub catalog_sha256: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryObservation<'a> {
    schema_version: u32,
    kind: &'static str,
    transaction_id: &'a str,
    challenge: &'a str,
    pair_id: &'a str,
    authority_epoch: &'a str,
    release_manifest_sha256: &'a str,
    catalog_sha256: &'a str,
    state: &'static str,
}

pub fn observe_recovery(path: &str) -> Result<()> {
    recovery(path, false)
}
pub fn repair_executable_mode(path: &str) -> Result<()> {
    recovery(path, true)
}
fn recovery(path: &str, repair: bool) -> Result<()> {
    let owner = crate::fs::uid()?;
    if owner != 0 {
        return Err("native recovery observation requires root".into());
    }
    let name = recovery_observation_input_name(path)?;
    let parent = Dir::parent("/var", owner)?;
    let input: RecoveryObservationInput =
        parse_canonical(&read_recovery_observation_input(&parent, name)?, 4096)?;
    recovery_with_input(input, owner, repair, None)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OfflineRestoreInput {
    observation: RecoveryObservationInput,
    request: String,
}
const RECOVERY_INPUT_MAX: usize = 4096;
const OFFLINE_REQUEST_MAX: usize = 65536;
const OFFLINE_INPUT_MAX: usize = OFFLINE_REQUEST_MAX * 2 + RECOVERY_INPUT_MAX;

fn parse_offline_restore_input(bytes: &[u8]) -> Result<(RecoveryObservationInput, Vec<u8>)> {
    let input: OfflineRestoreInput = parse_canonical(bytes, OFFLINE_INPUT_MAX)?;
    if input.request.len() > OFFLINE_REQUEST_MAX * 2 || !input.request.len().is_multiple_of(2) {
        return Err("offline request envelope invalid".into());
    }
    let envelope = hex::decode(&input.request).map_err(|_| "offline request envelope invalid")?;
    Ok((input.observation, envelope))
}
pub fn restore_offline(path: &str) -> Result<()> {
    let owner = crate::fs::uid()?;
    if owner != 0 {
        return Err("native offline restore requires root".into());
    }
    let name = recovery_observation_input_name(path)?;
    let parent = Dir::parent("/var", owner)?;
    let (observation, envelope) =
        parse_offline_restore_input(&read_recovery_input(&parent, name, OFFLINE_INPUT_MAX)?)?;
    validate_recovery_observation_input(&observation)?;
    let root = Dir::open("/var/voboost", owner)?;
    let service = {
        let _operation = crate::operation::Lock::wait_existing(&root)?;
        // Validate the complete available read-only recovery path before asking
        // a healthy resident to stop. Revalidate after it yields the lock.
        let preflight = recovery_preflight(&observation, owner, false, Some(&envelope))?;
        if root.exists("service.json")? {
            let record: crate::service::ServiceRecord =
                parse_canonical(&root.read("service.json", 8192, 0o600)?, 8192)?;
            if record.running {
                let request = preflight.request.as_ref().ok_or("offline request absent")?;
                let shutdown =
                    offline_shutdown(&preflight.config, &observation, request, &envelope, &record)?;
                publish_offline_shutdown(&root, &preflight.config, &record, &shutdown)?;
            }
            Some(record)
        } else {
            None
        }
    };
    let deadline = crate::engine::monotonic_ms()
        .and_then(|now| now.checked_add(5_000))
        .ok_or("native shutdown handoff clock unavailable")?;
    let _operation = wait_offline_handoff(&root, service.as_ref(), deadline)?;
    recovery_with_input(observation, owner, false, Some(envelope))
}

fn wait_offline_handoff(
    root: &Dir,
    service: Option<&crate::service::ServiceRecord>,
    deadline: u64,
) -> Result<crate::operation::Lock> {
    if service.is_some_and(|record| {
        record.schema_version != 1
            || record.pid == 0
            || record.pid > voboost_contract_core::MAX_SAFE_INTEGER
            || record.boot_id.is_empty()
            || !digest(&record.daemon_epoch)
    }) {
        return Err("native shutdown service identity invalid".into());
    }
    loop {
        let remaining = || {
            crate::engine::monotonic_ms()
                .and_then(|now| deadline.checked_sub(now))
                .filter(|ms| *ms > 0)
                .ok_or_else(|| String::from("native shutdown handoff deadline; authority retained"))
        };
        remaining()?;
        // The resident must reacquire this same lock to record its final stop.
        // Release it before sleeping; an unlocked reconciliation tick is not
        // a handoff, and a disappeared/changed record is not stopped evidence.
        match crate::operation::Lock::existing(root) {
            Ok(guard) => {
                let stopped = if let Some(expected) = service {
                    let mut current: crate::service::ServiceRecord =
                        parse_canonical(&root.read("service.json", 8192, 0o600)?, 8192)?;
                    let running = current.running;
                    current.running = expected.running;
                    if ascii_json(&current)? != ascii_json(expected)? {
                        return Err("native shutdown service changed during handoff".into());
                    }
                    !running
                } else {
                    if root.exists("service.json")? {
                        return Err("native shutdown service appeared during handoff".into());
                    }
                    true
                };
                if stopped {
                    remaining()?;
                    return Ok(guard);
                }
            }
            Err(error) if error == crate::operation::BUSY => (),
            Err(error) => return Err(error),
        }
        let wait = remaining()?.min(100);
        unsafe { libc::usleep((wait * 1000) as _) };
    }
}

fn publish_offline_shutdown(
    root: &Dir,
    config: &Config,
    record: &crate::service::ServiceRecord,
    shutdown: &crate::service::Shutdown,
) -> Result<()> {
    shutdown.verify(config)?;
    let bytes = ascii_json(shutdown)?;
    if root.exists("shutdown.request")? {
        let previous: crate::service::Shutdown = parse_canonical(
            &root.read("shutdown.request", crate::service::SHUTDOWN_MAX, 0o600)?,
            crate::service::SHUTDOWN_MAX,
        )?;
        previous.verify(config)?;
        if previous.signed_request != shutdown.signed_request {
            return Err("offline shutdown belongs to another operation".into());
        }
    }
    // A daemon incarnation is replaceable; its signed transaction is not.
    // Refuse publication if preflight observed a record that has since changed.
    if !record.running
        || record.daemon_epoch != shutdown.daemon_epoch
        || root.read("service.json", 8192, 0o600)? != ascii_json(record)?
    {
        return Err("offline shutdown service changed during preflight".into());
    }
    root.write("shutdown.request", &bytes, 0o600)
}

fn offline_shutdown(
    config: &Config,
    input: &RecoveryObservationInput,
    request: &voboost_contract_core::cluster::Request,
    envelope: &[u8],
    record: &crate::service::ServiceRecord,
) -> Result<crate::service::Shutdown> {
    validate_recovery_observation_input(input)?;
    validate_offline_restore_request(input, request)?;
    if config.root != "/var/voboost"
        || config.pair_id != input.pair_id
        || config.authority_epoch != input.authority_epoch
        || config.qnx_public_key != input.qnx_public_key
        || record.schema_version != 1
        || record.pid == 0
        || record.pid > voboost_contract_core::MAX_SAFE_INTEGER
        || record.boot_id.is_empty()
        || !digest(&record.daemon_epoch)
        || !record.running
    {
        return Err("offline shutdown retained service differs".into());
    }
    let shutdown = crate::service::Shutdown {
        schema_version: 1,
        daemon_epoch: record.daemon_epoch.clone(),
        transaction_id: request.transaction_id.clone(),
        signed_request: hex::encode(envelope),
    };
    if ascii_json(&shutdown.verify(config)?)? != ascii_json(request)? {
        return Err("offline shutdown signed request differs".into());
    }
    Ok(shutdown)
}
fn validate_offline_restore_request(
    input: &RecoveryObservationInput,
    request: &voboost_contract_core::cluster::Request,
) -> Result<()> {
    request.validate()?;
    if request.kind != voboost_contract_core::cluster::RequestKind::Uninstall
        || request.transaction_id != input.transaction_id
        || request.challenge != input.challenge
        || request.pair_id != input.pair_id
        || request.authority_epoch != input.authority_epoch
        || request.release_manifest_sha256.as_deref()
            != Some(input.release_manifest_sha256.as_str())
        || request.catalog_sha256 != input.catalog_sha256
    {
        return Err("offline restore request authority differs".into());
    }
    Ok(())
}
struct RecoveryPreflight {
    root: Dir,
    config: Config,
    verified_files: BTreeMap<String, Vec<u8>>,
    request: Option<voboost_contract_core::cluster::Request>,
    state: &'static str,
}

fn recovery_preflight(
    input: &RecoveryObservationInput,
    owner: u32,
    repair: bool,
    offline: Option<&[u8]>,
) -> Result<RecoveryPreflight> {
    validate_recovery_observation_input(input)?;
    crate::bootstrap::verify_recovery_profile()?;
    let root = Dir::open("/var/voboost", owner)?;
    let config = Config::parse(&root.read("boot.json", 16384, 0o600)?)?;
    if config.root != "/var/voboost"
        || config.expected_executable != "/usr/bin/gauge"
        || config.pair_id != input.pair_id
        || config.authority_epoch != input.authority_epoch
        || config.qnx_public_key != input.qnx_public_key
    {
        return Err("native recovery pairing differs".into());
    }
    let (_, _, current, mode) = startup("/scripts/startup_cluster.sh", owner)?;
    let mut files = BTreeMap::new();
    let mut offline_request = None;
    let state = if crate::install_layout::state_exists(&root)? {
        let proof: Installation =
            parse_canonical(&crate::install_layout::read_state(&root)?, 65536)?;
        let original = root.read("startup.original", 1024 * 1024, 0o600)?;
        validate_recovery_installation(input, &proof, &original, &current, mode)?;
        // Reuse the native signature/footer verification, not a host recreation
        // of trust. Every managed artifact must still match the signed bundle.
        let (manifest, _, verified_files) = bundle(
            &Dir::open("/var/voboost/bin", owner)?,
            &ProductRoots::default(),
            !repair,
        )?;
        if manifest.digest()? != input.release_manifest_sha256
            || manifest.agent_catalog_sha256()? != input.catalog_sha256
        {
            return Err("native recovery signed product differs".into());
        }
        if repair || offline.is_some() {
            if repair && hash(&current) != proof.installed_sha256 {
                return Err("native executable repair requires installed startup".into());
            }
            let identities: Vec<FileIdentity> = verified_files
                .iter()
                .map(|(name, bytes)| FileIdentity {
                    file: name.clone(),
                    size: bytes.len() as u64,
                    sha256: hash(bytes),
                })
                .collect();
            if ascii_json(&identities)? != ascii_json(&proof.files)? {
                return Err("native executable repair installation inventory differs".into());
            }
            if repair && installed_implant(&manifest)? != "libvoboost-cluster-inject.so" {
                return Err("native executable repair artifact role differs".into());
            }
            if let Some(request) = offline {
                let request = crate::engine::Authority::verify_paired_request(&config, request)?;
                validate_offline_restore_request(input, &request)?;
                if hash(&current) == proof.original_sha256
                    && !root.exists("uninstall-intent.json")?
                {
                    return Err("offline restore has no retained uninstall intent".into());
                }
                signing_key(&config)?;
                if root.exists("uninstall-intent.json")? {
                    let intent: UninstallIntent =
                        parse_canonical(&root.read("uninstall-intent.json", 4096, 0o600)?, 4096)?;
                    validate_uninstall_intent(&intent, &request)?;
                }
                offline_request = Some(request);
            }
            files = verified_files;
        }
        if hash(&current) == proof.installed_sha256 {
            "installed-managed"
        } else {
            "restored-managed"
        }
    } else {
        if repair || offline.is_some() {
            return Err("native executable repair requires installed authority".into());
        }
        if root.exists("startup.original")? {
            return Err("native recovery partial startup differs".into());
        }
        probe_clusterboot_startup(&current)?;
        "partial-original"
    };
    Ok(RecoveryPreflight {
        root,
        config,
        verified_files: files,
        request: offline_request,
        state,
    })
}

fn recovery_with_input(
    input: RecoveryObservationInput,
    owner: u32,
    repair: bool,
    offline: Option<Vec<u8>>,
) -> Result<()> {
    let preflight = recovery_preflight(&input, owner, repair, offline.as_deref())?;
    if let Some(request) = preflight.request {
        let boot = crate::fs::prepare_supervisor_boot_identity(owner)?;
        let epoch = crate::nonce()?;
        let report = prepare_uninstall(&preflight.config, &request, &boot, &epoch, || Ok(false))?;
        return crate::fs::write_all(1, &report);
    }
    if repair {
        crate::supervisor_delivery::revoke(&preflight.root)?;
        Dir::open("/var/voboost/bin", owner)?.repair_implant_executable(
            preflight
                .verified_files
                .get("libvoboost-cluster-inject.so")
                .ok_or("native implant absent")?,
        )?;
    }
    crate::fs::write_all(
        1,
        &ascii_json(&RecoveryObservation {
            schema_version: 1,
            kind: "bootstrap-recovery-observation",
            transaction_id: &input.transaction_id,
            challenge: &input.challenge,
            pair_id: &input.pair_id,
            authority_epoch: &input.authority_epoch,
            release_manifest_sha256: &input.release_manifest_sha256,
            catalog_sha256: &input.catalog_sha256,
            state: preflight.state,
        })?,
    )
}

fn recovery_observation_input_name(path: &str) -> Result<&str> {
    let name = path
        .strip_prefix("/var/")
        .ok_or("recovery input parent rejected")?;
    let nonce = name
        .strip_prefix("voboost-observe-")
        .and_then(|name| name.strip_suffix(".json"))
        .ok_or("recovery input basename rejected")?;
    if !digest(nonce) {
        return Err("recovery input nonce rejected".into());
    }
    Ok(name)
}

fn read_recovery_observation_input(parent: &Dir, name: &str) -> Result<Vec<u8>> {
    read_recovery_input(parent, name, RECOVERY_INPUT_MAX)
}
fn read_recovery_input(parent: &Dir, name: &str, max: usize) -> Result<Vec<u8>> {
    // /var is an admitted OEM parent, not a private0700 product directory.
    // Its existing owner/mode checks remain active; the input itself is an
    // exact no-follow root-owned0600 regular file with a bounded read.
    recovery_observation_input_name(&format!("/var/{name}"))?;
    parent.read(name, max, 0o600)
}
fn validate_recovery_observation_input(input: &RecoveryObservationInput) -> Result<()> {
    if input.schema_version != 1
        || ![
            &input.transaction_id,
            &input.challenge,
            &input.pair_id,
            &input.authority_epoch,
            &input.qnx_public_key,
            &input.release_manifest_sha256,
            &input.catalog_sha256,
        ]
        .iter()
        .all(|v| digest(v))
    {
        return Err("native recovery observation authority invalid".into());
    }
    Ok(())
}
fn validate_recovery_installation(
    input: &RecoveryObservationInput,
    proof: &Installation,
    original: &[u8],
    current: &[u8],
    mode: u32,
) -> Result<()> {
    if proof.schema_version != 1
        || proof.bootfile != "/var/voboost/boot.json"
        || proof.startup_file != "/scripts/startup_cluster.sh"
        || !digest(&proof.original_sha256)
        || proof.release_manifest_sha256 != input.release_manifest_sha256
        || proof.catalog_sha256 != input.catalog_sha256
        || hash(original) != proof.original_sha256
        || mode != proof.startup_mode
        || (hash(current) != proof.installed_sha256 && hash(current) != proof.original_sha256)
    {
        return Err("native recovery installation authority differs".into());
    }
    Ok(())
}

impl Integration {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_canonical(bytes, 16384)?;
        if value
            .provision_directory
            .as_deref()
            .is_some_and(|p| !safe_path(p))
            || value.schema_version != 1
            || ![
                &value.bootfile,
                &value.source_directory,
                &value.startup_file,
                &value.receipt_file,
            ]
            .iter()
            .all(|v| safe_path(v))
            || ![
                &value.original_sha256,
                &value.transaction_id,
                &value.challenge,
            ]
            .iter()
            .all(|v| digest(v))
            || !voboost_contract_core::printable(&value.root_device_id, 128)
            || value.anchor.is_empty()
            || value.anchor.len() > 2048
            || !value.anchor.is_ascii()
            || value.anchor.contains('\0')
        {
            return Err("explicit native integration input rejected".into());
        }
        Ok(value)
    }
}
fn source(dir: &Dir, name: &str, max: usize) -> Result<Vec<u8>> {
    dir.read(name, max, 0o600)
        .or_else(|_| dir.read(name, max, 0o700))
}
fn bundle(
    dir: &Dir,
    roots: &ProductRoots,
    removing: bool,
) -> Result<(Manifest, Catalog, BTreeMap<String, Vec<u8>>)> {
    let bytes = source(dir, "voboost.json", 4 * 1024 * 1024)?;
    let signature = source(dir, "voboost.json.sig", 64)?;
    let manifest = if removing {
        verify_installed_manifest_for_removal(&bytes, &signature, &roots.release)?
    } else {
        verify_manifest_signature(&bytes, &signature, &roots.release)?
    };
    if manifest.schema_version != 1 {
        return Err("native setup requires signed product2".into());
    }
    verify_restore_authority(
        &manifest,
        &source(dir, "restore.json", 1024)?,
        &source(dir, "restore.json.sig", 64)?,
        &crate::roots::RESTORE,
    )?;
    let mut files = BTreeMap::new();
    for a in manifest.artifacts.iter().filter(|a| {
        is_cluster_role(a.role)
            || matches!(
                a.role,
                ArtifactRole::AgentCatalog | ArtifactRole::AgentCatalogSignature
            )
    }) {
        let bytes = source(dir, &a.file, a.size as usize)?;
        if bytes.len() as u64 != a.size || hash(&bytes) != a.sha256 {
            return Err("native bootstrap file differs from signed product".into());
        }
        let role = match a.role {
            ArtifactRole::QnxDaemon => Some(NativeExecutableRole::Daemon),

            _ => None,
        };
        if let Some(role) = role {
            native_footer(&bytes, role, &roots.executable)?;
        }
        files.insert(a.file.clone(), bytes);
    }
    let catalog_bytes = files.get("agents.json").ok_or("bootstrap catalog absent")?;
    crate::engine::verify(
        catalog_bytes,
        files
            .get("agents.json.sig")
            .ok_or("bootstrap catalog signature absent")?,
        &roots.catalog,
    )?;
    let catalog = Catalog::parse(
        catalog_bytes,
        AGENT_ENTRY_ABI_SHA256,
        &hash(include_bytes!("../../sdk/include/voboost_cluster_v2.h")),
    )?;
    for f in catalog.closure(Domain::Cluster)? {
        let a = manifest.artifact(&f.file)?;
        if !is_cluster_role(a.role) || a.size != f.size || a.sha256 != f.sha256 {
            return Err("bootstrap catalog/product native closure differs".into());
        }
    }
    // Signed pack bytes are inert; this neither loads a ResourceManager directory
    // nor claims a selected dictionary. Owner/target and actual data-only bytes
    // are checked before any owned-tree or startup mutation.
    for artifact in manifest
        .artifacts
        .iter()
        .filter(|a| !removing && a.role == ArtifactRole::QnxResourcePack)
    {
        let stem = artifact
            .file
            .strip_suffix(".kzb")
            .ok_or("QNX pack suffix")?;
        let ledger_file = format!("{stem}.json");
        voboost_contract_core::resource_pack::OwnedPack::verify(
            voboost_contract_core::resource_pack::Inputs {
                manifest: &bytes,
                signature: &source(dir, "voboost.json.sig", 64)?,
                public_key: &roots.release,
                catalog: catalog_bytes,
                artifact_file: &artifact.file,
                pack: files.get(&artifact.file).ok_or("QNX pack bytes absent")?,
                ledger: files.get(&ledger_file).ok_or("QNX pack ledger absent")?,
            },
        )?;
    }
    files.insert("voboost.json".into(), bytes);
    files.insert(
        "voboost.json.sig".into(),
        source(dir, "voboost.json.sig", 64)?,
    );
    files.insert("restore.json".into(), source(dir, "restore.json", 1024)?);
    files.insert(
        "restore.json.sig".into(),
        source(dir, "restore.json.sig", 64)?,
    );
    Ok((manifest, catalog, files))
}
fn trim_shell_space(mut line: &[u8]) -> &[u8] {
    while line
        .first()
        .is_some_and(|v| matches!(v, b' ' | b'\t' | b'\r'))
    {
        line = &line[1..];
    }
    while line
        .last()
        .is_some_and(|v| matches!(v, b' ' | b'\t' | b'\r'))
    {
        line = &line[..line.len() - 1];
    }
    line
}
fn update_startup_compound_context(line: &[u8], stack: &mut Vec<u8>) -> Result<()> {
    let mut i = 0;
    let mut command_start = true;
    while i < line.len() {
        if matches!(line[i], b' ' | b'\t' | b'\r') {
            i += 1;
            continue;
        }
        let c = line[i];
        if matches!(c, b'(' | b')' | b'{' | b'}' | b';' | b'|' | b'&') {
            match c {
                b'(' => stack.push(b'('),
                b')' if stack.last() == Some(&b'(') => {
                    stack.pop();
                }
                b')' if stack.contains(&b'c') => (), // case-pattern terminator
                b')' => return Err("SetupRequired: startup compound context is unsupported".into()),
                b'{' => stack.push(b'{'),
                b'}' if stack.pop() != Some(b'{') => {
                    return Err("SetupRequired: startup brace context differs".into())
                }
                _ => (),
            }
            command_start = true;
            i += 1;
            continue;
        }
        let start = i;
        while i < line.len()
            && !matches!(
                line[i],
                b' ' | b'\t' | b'\r' | b'(' | b')' | b'{' | b'}' | b';' | b'|' | b'&'
            )
        {
            i += 1;
        }
        let word = &line[start..i];
        if command_start {
            match word {
                b"if" => stack.push(b'i'),
                b"case" => stack.push(b'c'),
                b"for" | b"while" | b"until" | b"select" => stack.push(b'l'),
                b"fi" if stack.pop() != Some(b'i') => {
                    return Err("SetupRequired: startup if context differs".into())
                }
                b"esac" if stack.pop() != Some(b'c') => {
                    return Err("SetupRequired: startup case context differs".into())
                }
                b"done" if stack.pop() != Some(b'l') => {
                    return Err("SetupRequired: startup loop context differs".into())
                }
                b"then" | b"else" | b"do" => {
                    command_start = true;
                    continue;
                }
                _ => (),
            }
        }
        command_start = false;
    }
    Ok(())
}
fn startup_shell_clusterboot_count(original: &[u8]) -> Result<usize> {
    if original.is_empty() || original.len() > 1024 * 1024 || original.contains(&0) {
        return Err("startup structural input bound rejected".into());
    }
    let mut count = 0;
    let mut compound = Vec::new();
    for physical in original.split(|v| *v == b'\n') {
        let line = trim_shell_space(physical);
        let mut quote = 0u8;
        let mut code = Vec::new();
        let mut context = Vec::new();
        let mut i = 0;
        while i < line.len() {
            let c = line[i];
            if c == b'\\' && quote != b'\'' {
                if i + 1 == line.len() {
                    return Err("SetupRequired: continued startup lines are unsupported".into());
                }
                code.push(line[i + 1]);
                context.push(b'x');
                i += 2;
                continue;
            }
            if quote == 0
                && c == b'#'
                && (i == 0
                    || matches!(
                        line[i - 1],
                        b' ' | b'\t' | b';' | b'&' | b'|' | b'(' | b')' | b'{' | b'}'
                    ))
            {
                break;
            }
            if quote == 0 && c == b'<' && line.get(i + 1) == Some(&b'<') {
                return Err("SetupRequired: startup heredoc context is unsupported".into());
            }
            if quote != b'\'' && c == b'$' && line.get(i + 1) == Some(&b'(') {
                return Err("SetupRequired: startup command substitution is unsupported".into());
            }
            if quote == 0 && c == b'$' && line.get(i + 1) == Some(&b'{') {
                let start = i;
                let mut nesting = 1;
                i += 2;
                while i < line.len() && nesting != 0 {
                    if line[i] == b'{' {
                        nesting += 1;
                    } else if line[i] == b'}' {
                        nesting -= 1;
                    }
                    i += 1;
                }
                if nesting != 0 {
                    return Err("SetupRequired: multiline startup parameter is unsupported".into());
                }
                code.extend_from_slice(&line[start..i]);
                context.push(b'x');
                continue;
            }
            if quote == 0 && matches!(c, b'\'' | b'"' | b'`') {
                quote = c;
                context.push(b'x');
            } else if quote == c {
                quote = 0;
                context.push(b'x');
            } else {
                code.push(c);
                context.push(if quote == 0 { c } else { b'x' });
            }
            i += 1;
        }
        if quote != 0 {
            return Err("SetupRequired: multiline startup quote is unsupported".into());
        }
        let occurrences = code
            .windows(b"clusterboot".len())
            .filter(|w| *w == b"clusterboot")
            .count();
        if occurrences != 0 && !compound.is_empty() {
            return Err("SetupRequired: clusterboot anchor must be top-level".into());
        }
        count += occurrences;
        let end = trim_shell_space(&context);
        if end.ends_with(b"&&") || end.ends_with(b"||") || end.ends_with(b"|") {
            return Err("SetupRequired: multiline startup operator is unsupported".into());
        }
        update_startup_compound_context(&context, &mut compound)?;
    }
    if !compound.is_empty() {
        return Err("SetupRequired: startup compound context is incomplete".into());
    }
    Ok(count)
}

fn probe_startup_line(original: &[u8], mut matches: impl FnMut(&[u8]) -> bool) -> Result<usize> {
    if original.is_empty() || original.len() > 1024 * 1024 || original.contains(&0) {
        return Err("startup structural input bound rejected".into());
    }
    let mut offset = 0;
    let mut position = None;
    for line in original.split(|v| *v == b'\n') {
        if matches(trim_shell_space(line)) {
            if position.is_some() {
                return Err("startup command must be a complete unique line".into());
            }
            position = Some(offset);
        }
        offset += line.len() + 1;
    }
    position.ok_or_else(|| "unknown startup command integration; setup required".into())
}
pub(crate) fn probe_clusterboot_startup(original: &[u8]) -> Result<usize> {
    if startup_shell_clusterboot_count(original)? != 1 {
        return Err("SetupRequired: startup clusterboot launch must be unique".into());
    }
    probe_startup_line(original, |line| {
        let mut tokens = line
            .split(|v| matches!(v, b' ' | b'\t'))
            .filter(|v| !v.is_empty());
        tokens.next() == Some(b"clusterboot".as_slice())
            && tokens.next() == Some(b"&".as_slice())
            && tokens.next().is_none()
    })
}
fn startup_position(input: &Integration, config: &Config, original: &[u8]) -> Result<usize> {
    if hash(original) != input.original_sha256 || input.anchor.is_empty() {
        return Err("startup original digest mismatch".into());
    }
    let anchor = trim_shell_space(input.anchor.as_bytes());
    if anchor.contains(&b'\n')
        || anchor.contains(&b'\r')
        || !anchor.is_ascii()
        || input.anchor.contains("LD_PRELOAD=")
    {
        return Err("unknown startup command integration; setup required".into());
    }
    if matches!(input.startup_profile, Some(StartupProfile::Clusterboot)) {
        probe_clusterboot_startup(anchor)?;
        return probe_clusterboot_startup(original);
    }
    let anchor = core::str::from_utf8(anchor).map_err(|_| "startup anchor encoding")?;
    let expected = config.expected_executable.as_str();
    if !(anchor == expected
        || anchor.starts_with(&format!("{expected} "))
        || anchor == format!("exec {expected}")
        || anchor.starts_with(&format!("exec {expected} ")))
    {
        return Err("unknown startup command integration; setup required".into());
    }
    probe_startup_line(original, |line| line == anchor.as_bytes())
}

fn startup(path: &str, owner: u32) -> Result<(Dir, String, Vec<u8>, u32)> {
    let (parent, name) = path.rsplit_once('/').ok_or("startup parent missing")?;
    let dir = Dir::parent(parent, owner)?;
    let file =
        alloc::ffi::CString::new(format!("{parent}/{name}")).map_err(|_| "startup filename")?;
    let mut s = unsafe { core::mem::zeroed() };
    // Pinned QNX libc fstatat(dirfd, ...) is ENOSYS on this firmware; lstat by
    // the same no-follow member path is the equivalent retained backend.
    if unsafe { libc::lstat(file.as_ptr(), &mut s) } != 0 {
        return Err("verified writable startup integration unavailable".into());
    }
    let mode = s.st_mode as u32 & 0o777;
    if mode & 0o022 != 0 {
        return Err("startup integration is writable by another principal".into());
    }
    let bytes = dir.read(name, 1024 * 1024, mode)?;
    Ok((dir, name.into(), bytes, mode))
}
/// Import root-authorized pairing material without generating or rotating keys.
/// Validate every input and collision before committing any destination.
fn provision(config: &Config, source: &str, owner: u32) -> Result<()> {
    let input = Dir::open(source, owner)?;
    let root = Dir::open(&config.root, owner)?;
    let mut material = BTreeMap::new();
    let mut seed = input.read("qnx-signing.seed", 32, 0o600)?;
    let mut raw: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "QNX signing seed raw32")?;
    let signer = SigningKey::from_bytes(&raw);
    raw.fill(0);
    if signer.verifying_key().to_bytes() != crate::key(&config.qnx_public_key)? {
        seed.fill(0);
        return Err("provided signing seed is not the paired QNX authority".into());
    }
    material.insert(String::from("qnx-signing.seed"), seed);
    let result = (|| {
        for path in [
            &config.tls.server_certificate,
            &config.tls.server_private_key,
            &config.tls.client_ca,
        ] {
            let (parent, name) = path
                .rsplit_once('/')
                .ok_or("TLS provision destination parent missing")?;
            if parent != config.root || material.contains_key(name) {
                return Err(
                    "TLS provision destinations must be distinct managed-root members".into(),
                );
            }
            let bytes = input.read(name, 65536, 0o600)?;
            if bytes.is_empty() {
                return Err("empty TLS provisioning material".into());
            }
            material.insert(String::from(name), bytes);
        }
        for (name, bytes) in &material {
            if root.exists(name)? && root.read(name, bytes.len(), 0o600)? != *bytes {
                return Err(
                    "existing QNX provision is immutable; explicit rotation required".into(),
                );
            }
        }
        // Missing members are retryable after interruption; existing files are never replaced.
        for (name, bytes) in &material {
            if !root.exists(name)? {
                root.write(name, bytes, 0o600)?;
            }
            if root.read(name, bytes.len(), 0o600)? != *bytes {
                return Err("QNX provision readback differs".into());
            }
        }
        Ok(())
    })();
    for bytes in material.values_mut() {
        bytes.fill(0);
    }
    result
}
fn signing_key(config: &Config) -> Result<SigningKey> {
    let root = Dir::open(&config.root, crate::fs::uid()?)?;
    let mut seed = root.read("qnx-signing.seed", 32, 0o600)?;
    let mut raw: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "QNX signing seed raw32")?;
    let signer = SigningKey::from_bytes(&raw);
    raw.fill(0);
    seed.fill(0);
    if signer.verifying_key().to_bytes() != crate::key(&config.qnx_public_key)? {
        return Err("native operation signer mismatch".into());
    }
    Ok(signer)
}
fn signed_report(
    config: &Config,
    input: &Integration,
    report: DomainOperationReport,
) -> Result<Vec<u8>> {
    let signer = signing_key(config)?;
    AuthenticatedReport {
        schema_version: 1,
        pair_id: config.pair_id.clone(),
        authority_epoch: config.authority_epoch.clone(),
        challenge: input.challenge.clone(),
        report,
    }
    .sign(&signer)
}
fn output(input: &Integration, bytes: &[u8]) -> Result<()> {
    let (parent, name) = input
        .receipt_file
        .rsplit_once('/')
        .ok_or("receipt parent missing")?;
    Dir::open(parent, crate::fs::uid()?)?.write(name, bytes, 0o600)
}
fn installed_artifact_mode(name: &str) -> u32 {
    match name {
        "voboost-cluster-daemon" | "libvoboost-cluster-inject.so"
        | "voboost-cluster" | "libvoboost-cluster-implant.so" => 0o700,
        _ => 0o600,
    }
}

fn installed_implant(manifest: &Manifest) -> Result<&str> {
    manifest.artifacts.iter()
        .find(|artifact| artifact.role == ArtifactRole::QnxImplant)
        .map(|artifact| artifact.file.as_str())
        .ok_or_else(|| "native executable repair implant role absent".into())
}
#[cfg(any(target_os = "nto", test))]
fn supervisor_parent(config_path: &str, owner: u32) -> Result<Dir> {
    let path = config_path
        .strip_suffix("/boot_cfg.xml")
        .ok_or("supervisor config parent constant")?;
    Dir::parent(path, owner)
}
/// Supervisor-config transaction integration (QNX only). Kept as a sibling
/// module of the install graph; the transaction itself lives in
/// supervisor_config with its own reviewed invariants.
#[cfg(target_os = "nto")]
mod supervisor {
    use super::*;

    /// Install or update the fixed OEM supervisor config under the exclusive
    /// operation lock, with first-original preservation and nonce rotation.
    pub(super) fn install_config(input: &Integration, config: &Config, root: &Dir) -> Result<()> {
        use crate::supervisor_config::{machinery::Writer, Operation, CONFIG_PATH};
        let parent = supervisor_parent(CONFIG_PATH, crate::fs::uid()?)?;
        // Fresh installer entropy; not a digest and never derived from bytes.
        let nonce = crate::nonce()?;
        let operation = Operation {
            transaction_id: input.transaction_id.clone(),
            implant: format!("{}/bin/libvoboost-cluster-inject.so", config.root),
            bootfile: input.bootfile.clone(),
            nonce: nonce.clone(),
            default_candidate: None,
            failpoints: alloc::collections::BTreeSet::new(),
            restore: false,
        };
        // Observe once outside the transaction for candidate composition:
        // the proved emitters are pure functions of these bytes. An update
        // rotates ONLY the nonce in the already-complete own delivery; a
        // first install augments the (foreign or absent) live config.
        let mut writer = crate::supervisor_config::qnx::ConfigFile::open(&parent)?;
        let live = writer.observe()?;
        let candidate = match supervisor_config_receipt(root)? {
            Some(previous) => crate::supervisor_config::emit::rotate_nonce(
                &live.bytes,
                &operation.implant,
                &operation.bootfile,
                &previous.delivery_nonce,
                &nonce,
            )?,
            None => crate::supervisor_config::emit::candidate(
                if live.present {
                    Some(&live.bytes)
                } else {
                    None
                },
                &operation.implant,
                &operation.bootfile,
                &nonce,
            )?,
        };
        drop(writer);
        crate::supervisor_config::qnx::run(
            root,
            &parent,
            &operation,
            &candidate,
            // The candidate was composed from this pre-lock observation; run()
            // reobserves under the lock and refuses any concurrent change.
            Some(&live),
            live.mode.max(0o600),
            true,
        )
    }

    /// Restore the FIRST original config bytes/mode or original absence.
    /// Never overwrites foreign content/mode/presence: a failed restoration
    /// preserves payload, authority and WAL for a later bounded recovery.
    pub(super) fn restore_config(root: &Dir, transaction_id: &str) -> Result<()> {
        use crate::supervisor_config::CONFIG_PATH;
        let parent = supervisor_parent(CONFIG_PATH, crate::fs::uid()?)?;
        let mut writer = crate::supervisor_config::qnx::ConfigFile::open(&parent)?;
        // Standard restore orchestration: lock, bounded WAL recovery, then
        // restore(). The receipt is consulted only after recovery so the F5
        // receipt-less crash window terminates through the waived branch
        // instead of the old pre-lock refusal; see restore_standard().
        crate::supervisor_config::restore_standard(root, &mut writer, transaction_id)
    }

    pub(super) fn require_restored_config(
        root: &Dir,
        transaction_id: &str,
        boot: crate::fs::UninstallBoot,
    ) -> Result<()> {
        let parent = supervisor_parent(crate::supervisor_config::CONFIG_PATH, crate::fs::uid()?)?;
        let mut writer = crate::supervisor_config::qnx::ConfigFile::open(&parent)?;
        crate::supervisor_config::require_uninstall_restored(
            root,
            &mut writer,
            transaction_id,
            boot,
        )
    }
}
pub fn install(input: Integration) -> Result<()> {
    let owner = crate::fs::uid()?;
    if !cfg!(test) && owner != 0 {
        return Err("native bootstrap requires root".into());
    }
    let config = Config::parse(&read_protected(&input.bootfile, owner, 16384, 0o600)?)?;
    if input.receipt_file.starts_with(&format!("{}/", config.root)) {
        return Err("operation receipt must be outside managed root".into());
    }
    let root = Dir::open(&config.root, owner)?;
    if format!("{}", crate::fs::stat(root.fd.0)?.st_dev) != input.root_device_id {
        return Err("explicit root filesystem identity differs".into());
    }
    // Fail before changing the startup hook or its exact backup if provisioning is
    // incomplete. A retry must never replace the original installation authority.
    crate::supervisor_delivery::revoke(&root)?;
    if let Some(source) = &input.provision_directory {
        provision(&config, source, owner)?;
    }
    signing_key(&config)?;
    if crate::install_layout::state_exists(&root)? || root.exists("startup.original")? {
        return Err("native installation already exists; explicit restore required".into());
    }
    let source_dir = Dir::open(&input.source_directory, owner)?;
    let (manifest, _catalog, files) = bundle(&source_dir, &ProductRoots::default(), false)?;
    let (parent, name, original, mode) = startup(&input.startup_file, owner)?;
    let position = startup_position(&input, &config, &original)?;
    let insertion = format!(
        ". {}/bin/voboost-cluster-startup.sh {} {}\n",
        config.root, config.root, input.bootfile
    );
    let mut installed = original[..position].to_vec();
    installed.extend_from_slice(insertion.as_bytes());
    installed.extend_from_slice(&original[position..]);
    let bin = root.child("bin")?;
    let mut installed_files = Vec::new();
    for (name, bytes) in &files {
        let mode = installed_artifact_mode(name);
        bin.write(name, bytes, mode)?;
        if bin.read(name, bytes.len(), mode)? != *bytes {
            return Err("bootstrap copy readback differs".into());
        }
        installed_files.push(FileIdentity {
            file: name.clone(),
            size: bytes.len() as u64,
            sha256: hash(bytes),
        });
    }
    root.write("startup.original", &original, 0o600)?;
    let proof = Installation {
        schema_version: 1,
        bootfile: input.bootfile.clone(),
        startup_file: input.startup_file.clone(),
        original_sha256: hash(&original),
        installed_sha256: hash(&installed),
        startup_mode: mode,
        release_manifest_sha256: manifest.digest()?,
        catalog_sha256: manifest.agent_catalog_sha256()?.into(),
        files: installed_files,
        supervisor_config: None,
    };
    crate::install_layout::write_state(&root, &ascii_json(&proof)?)?;
    if matches!(input.startup_profile, Some(StartupProfile::Clusterboot)) {
        crate::oem_startup::write(&input, &parent, &original, &installed, mode, &root)?;
    } else {
        parent.write(&name, &installed, mode)?;
    }
    if parent.read(&name, installed.len(), mode)? != installed {
        return Err("startup installation readback differs".into());
    }
    // Persistent exact-byte supervisor-config transaction on QNX: the typed
    // receipt subrecord is installed inside the Installation record written
    // above; failures here fail the install without a Ready claim.
    #[cfg(target_os = "nto")]
    if matches!(input.startup_profile, Some(StartupProfile::Clusterboot)) {
        supervisor::install_config(&input, &config, &root)?;
    }
    // An immediate uninstall can run before the next OEM startup. Bind its
    // restoration receipt to this boot using the same paired RAM identity.
    #[cfg(target_os = "nto")]
    crate::fs::prepare_boot_identity(&config.boot_identity_file, &config.pair_id, owner)?;
    // Bootstrap files and startup integration are installed; daemon/generation/current
    // process observations are separate and cannot be invented by this command.
    let report = DomainOperationReport {
        schema_version: 2,
        domain: Domain::Cluster,
        operation: Operation::Install,
        phase: Phase::Install,
        outcome: Outcome::Pending,
        transaction_id: input.transaction_id.clone(),
        release_manifest_sha256: proof.release_manifest_sha256,
        catalog_sha256: proof.catalog_sha256,
        generation_id: None,
        desired_revision: 0,
        desired_sha256: voboost_contract_core::cluster::desired_digest(&[])?,
        boot_id: None,
        daemon_epoch: None,
        installed_evidence: None,
    };
    output(&input, &signed_report(&config, &input, report)?)
}
#[path = "install_retirement.rs"]
mod retirement;
pub fn finish_install(transaction: &str) -> Result<()> {
    retirement::finish(transaction)
}
pub fn restore(input: Integration) -> Result<()> {
    let owner = crate::fs::uid()?;
    if !cfg!(test) && owner != 0 {
        return Err("native restore requires root".into());
    }
    let config = Config::parse(&read_protected(&input.bootfile, owner, 16384, 0o600)?)?;
    if input.receipt_file.starts_with(&format!("{}/", config.root)) {
        return Err("operation receipt must be outside managed root".into());
    }
    let root = Dir::open(&config.root, owner)?;
    if format!("{}", crate::fs::stat(root.fd.0)?.st_dev) != input.root_device_id {
        return Err("explicit root filesystem identity differs".into());
    }
    signing_key(&config)?;
    let proof: Installation = parse_canonical(&crate::install_layout::read_state(&root)?, 65536)?;
    if proof.schema_version != 1
        || proof.startup_file != input.startup_file
        || proof.bootfile != input.bootfile
        || proof.original_sha256 != input.original_sha256
    {
        return Err("restore integration authority mismatch".into());
    }
    let original = root.read("startup.original", 1024 * 1024, 0o600)?;
    if hash(&original) != proof.original_sha256 {
        return Err("exact startup backup digest differs".into());
    }
    let (parent, name, current, mode) = startup(&input.startup_file, owner)?;
    if hash(&current) != proof.installed_sha256 && hash(&current) != proof.original_sha256 {
        return Err("startup changed outside managed transaction".into());
    }
    if mode != proof.startup_mode {
        return Err("startup mode changed outside managed transaction".into());
    }
    crate::supervisor_delivery::revoke(&root)?;
    root.write("restore.lock", &ascii_json(&input.transaction_id)?, 0o600)?;
    // Conditional config restoration runs BEFORE startup teardown, under the
    // same revocation: the FIRST original/absence must be back and verified
    // readonly while the installation receipt is still available.
    #[cfg(target_os = "nto")]
    if matches!(input.startup_profile, Some(StartupProfile::Clusterboot)) {
        supervisor::restore_config(&root, &input.transaction_id)?;
    }
    if matches!(input.startup_profile, Some(StartupProfile::Clusterboot)) {
        crate::oem_startup::write(&input, &parent, &current, &original, mode, &root)?;
    } else {
        parent.write(&name, &original, mode)?;
    }
    if parent.read(&name, original.len(), mode)? != original {
        return Err("startup restore readback differs".into());
    }
    let native = crate::engine::Authority::open(config.clone(), owner, ProductRoots::default());
    let (generation, revision, desired, boot, epoch, outcome) = match native {
        Ok(a) => {
            let _ = crate::service::controller(&a, true);
            (
                a.generation.as_ref().map(|g| g.generation_id.clone()),
                a.desired.as_ref().map(|d| d.desired_revision).unwrap_or(0),
                a.desired
                    .as_ref()
                    .map(|d| d.desired_sha256.clone())
                    .unwrap_or(voboost_contract_core::cluster::desired_digest(&[])?),
                Some(a.boot_id),
                None,
                Outcome::ReloadRequired,
            )
        }
        Err(_) => (
            None,
            0,
            voboost_contract_core::cluster::desired_digest(&[])?,
            None,
            None,
            Outcome::Pending,
        ),
    };
    let report = DomainOperationReport {
        schema_version: 2,
        domain: Domain::Cluster,
        operation: Operation::Restore,
        phase: Phase::Restore,
        outcome,
        transaction_id: input.transaction_id.clone(),
        release_manifest_sha256: proof.release_manifest_sha256,
        catalog_sha256: proof.catalog_sha256,
        generation_id: generation,
        desired_revision: revision,
        desired_sha256: desired,
        boot_id: boot,
        daemon_epoch: epoch,
        installed_evidence: None,
    };
    output(&input, &signed_report(&config, &input, report)?)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UninstallIntent {
    schema_version: u32,
    transaction_id: String,
    challenge: String,
    // Existing intents encode a numeric qtime value under this key.
    #[serde(rename = "kernelBootTime")]
    boot: UninstallBoot,
    ram_token: String,
}

fn validate_uninstall_intent(
    intent: &UninstallIntent,
    request: &voboost_contract_core::cluster::Request,
) -> Result<()> {
    if intent.schema_version != 1
        || intent.transaction_id != request.transaction_id
        || intent.challenge != request.challenge
        || !intent.boot.valid()
        || !digest(&intent.ram_token)
    {
        return Err("native uninstall intent belongs to another request".into());
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FinalizeInput {
    pub schema_version: u32,
    pub bootfile: String,
    pub transaction_id: String,
    pub challenge: String,
    pub receipt_file: String,
}
impl FinalizeInput {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Self = parse_canonical(bytes, 16384)?;
        if value.schema_version != 1
            || !safe_path(&value.bootfile)
            || !safe_path(&value.receipt_file)
            || !digest(&value.transaction_id)
            || !digest(&value.challenge)
        {
            return Err("native finalizer input rejected".into());
        }
        Ok(value)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FinalReceipt {
    input_sha256: String,
    root: String,
    root_device: u64,
    root_inode: u64,
    #[serde(rename = "kernelBootTime")]
    boot: UninstallBoot,
    public_key: String,
    pair_id: String,
    authority_epoch: String,
    product: String,
    envelope: String,
}

/// Prepare only a private data directory; executable delivery stays in the
/// installer verified-product path, never in this privileged operation.
pub fn prepare_remove(transaction: &str) -> Result<()> {
    if !digest(transaction) || crate::fs::uid()? != 0 {
        return Err("native remove preparation authority rejected".into());
    }
    let config = Config::parse(&read_protected("/var/voboost/boot.json", 0, 16384, 0o600)?)?;
    if config.root != "/var/voboost" {
        return Err("native remove root differs".into());
    }
    let root = Dir::open(&config.root, 0)?;
    let intent: UninstallIntent =
        parse_canonical(&root.read("uninstall-intent.json", 4096, 0o600)?, 4096)?;
    if intent.schema_version != 1
        || intent.transaction_id != transaction
        || root.read("restore.lock", 256, 0o600)? != ascii_json(transaction)?
    {
        return Err("native remove preparation transaction differs".into());
    }
    let proof: Installation = parse_canonical(&crate::install_layout::read_state(&root)?, 65536)?;
    let backup = root.read("startup.original", 1024 * 1024, 0o600)?;
    let (_, _, original, mode) = startup("/scripts/startup_cluster.sh", 0)?;
    if proof.schema_version != 1
        || proof.bootfile != format!("{}/boot.json", config.root)
        || proof.startup_file != "/scripts/startup_cluster.sh"
        || !digest(&proof.original_sha256)
        || hash(&backup) != proof.original_sha256
        || hash(&original) != proof.original_sha256
        || mode != proof.startup_mode
    {
        return Err("native remove startup not restored".into());
    }
    let stage = Dir::parent("/var", 0)?.child(&format!("voboost-finalize-{transaction}"))?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Stage {
        schema_version: u32,
        directory: String,
    }
    crate::fs::write_all(
        1,
        &ascii_json(&Stage {
            schema_version: 1,
            directory: stage.path,
        })?,
    )
}

fn final_receipt_directory(input: &FinalizeInput, owner: u32) -> Result<(Dir, String)> {
    let (parent, name) = input
        .receipt_file
        .rsplit_once('/')
        .ok_or("receipt parent missing")?;
    Ok((Dir::open(parent, owner)?, String::from(name)))
}

fn retry_final_receipt(input: &FinalizeInput, owner: u32, emit: bool) -> Result<bool> {
    let (directory, name) = final_receipt_directory(input, owner)?;
    let pending_name = format!("{name}.pending");
    if !directory.exists(&pending_name)? {
        return Ok(false);
    }
    let pending: FinalReceipt =
        parse_canonical(&directory.read(&pending_name, 131072, 0o600)?, 131072)?;
    if pending.input_sha256 != hash(&ascii_json(input)?)
        || !safe_path(&pending.root)
        || input.bootfile != format!("{}/boot.json", pending.root)
    {
        return Err("native final receipt authority differs".into());
    }
    let root_absent = crate::fs::path_absent(&pending.root)?;
    let current_boot = pending.boot.read_current(owner)?;
    let regenerate = receipt_retry_regenerate(&pending.boot, &current_boot, root_absent)?;
    let (_, _, original, _) = startup("/scripts/startup_cluster.sh", owner)?;
    require_no_managed_process(&pending.root)?;
    let bytes = hex::decode(&pending.envelope).map_err(|_| "native final receipt encoding")?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&crate::key(&pending.public_key)?)
        .map_err(|_| "native final receipt key")?;
    let verified = AuthenticatedReport::verify(
        &bytes,
        &key,
        &pending.pair_id,
        &pending.authority_epoch,
        &input.challenge,
        &input.transaction_id,
        &pending.product,
    )?;
    if verified.report.outcome != Outcome::Completed {
        return Err("native final receipt not absence".into());
    }
    let Some(voboost_contract_core::domain_operation::InstalledEvidence::QnxAbsence {
        startup,
        ..
    }) = verified.report.installed_evidence.as_ref()
    else {
        return Err("native final receipt not absence".into());
    };
    if startup.path != "/scripts/startup_cluster.sh"
        || !digest(&startup.original_sha256)
        || startup.original_sha256 != startup.restored_sha256
        || hash(&original) != startup.original_sha256
    {
        return Err("native final receipt startup differs from signed original".into());
    }
    if !crate::fs::boot_identity_absent(
        &crate::fs::boot_identity_path(&pending.pair_id)?,
        &pending.pair_id,
    )? {
        return Err("native final receipt RAM identity returned".into());
    }
    if !crate::diagnostic_ram::absent(&pending.pair_id)? {
        return Err("native final receipt diagnostic RAM returned".into());
    }
    if !root_absent {
        // The public-only durable journal is sufficient to resume a partial
        // purge even when installation authority files were already removed.
        let root = Dir::open(&pending.root, owner)?;
        if retry_root_requires_regeneration(
            regenerate,
            (pending.root_device, pending.root_inode),
            || {
                let stat = crate::fs::stat(root.fd.0)?;
                Ok((stat.st_dev as u64, stat.st_ino as u64))
            },
        )? {
            // Never emit the earlier signed proof on a later boot with root
            // present. Re-enter full original-authority validation and signing.
            return Ok(false);
        }
        crate::fs::purge_installation_tree(&root)?;
    }
    if emit {
        directory.write(&name, &bytes, 0o600)?;
        crate::fs::write_all(1, &bytes)?;
    }
    Ok(true)
}

/// Remove the stage before Android imports the signed final receipt as complete.
pub fn finish_remove(transaction: &str) -> Result<()> {
    if !digest(transaction) || crate::fs::uid()? != 0 {
        return Err("native remove cleanup authority rejected".into());
    }
    let path = format!("/var/voboost-finalize-{transaction}");
    let stage = Dir::open(&path, 0)?;
    let input = FinalizeInput::parse(&stage.read("input.json", 16384, 0o600)?)?;
    if input.transaction_id != transaction
        || input.bootfile != "/var/voboost/boot.json"
        || input.receipt_file != format!("{path}/receipt.bin")
        || !crate::fs::path_absent("/var/voboost")?
        || !retry_final_receipt(&input, 0, false)?
    {
        return Err("native remove cleanup lacks final absence".into());
    }
    crate::fs::purge_private_tree(&stage)?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Finished {
        schema_version: u32,
        transaction_id: String,
        stage_absent: bool,
    }
    crate::fs::write_all(
        1,
        &ascii_json(&Finished {
            schema_version: 1,
            transaction_id: transaction.into(),
            stage_absent: true,
        })?,
    )
}

fn require_new_boot(old: &UninstallBoot, current: &UninstallBoot, ram_absent: bool) -> Result<()> {
    if !old.valid() || !current.valid() || !old.same_source(current) || old == current || !ram_absent {
        return Err(
            "native uninstall requires independent new kernel boot and absent old RAM identity"
                .into(),
        );
    }
    Ok(())
}

fn receipt_retry_regenerate(
    recorded: &UninstallBoot,
    current: &UninstallBoot,
    root_absent: bool,
) -> Result<bool> {
    if !recorded.valid()
        || !current.valid()
        || !recorded.same_source(current)
        || matches!((recorded, current), (UninstallBoot::KernelTime(old), UninstallBoot::KernelTime(now)) if now < old)
    {
        return Err("native final receipt kernel differs".into());
    }
    Ok(current != recorded && !root_absent)
}

fn retry_root_requires_regeneration(
    regenerate: bool,
    recorded: (u64, u64),
    current: impl FnOnce() -> Result<(u64, u64)>,
) -> Result<bool> {
    if regenerate {
        // A new boot returns to full original-authority admission. Physical
        // identity from the prior kernel is only a same-boot purge guard.
        return Ok(true);
    }
    if current()? != recorded {
        return Err("native final receipt root identity changed".into());
    }
    Ok(false)
}

fn require_no_managed_process(root: &str) -> Result<()> {
    let prefix = format!("{root}/");
    if managed_process_exists(|path| path.starts_with(prefix.as_bytes()))? {
        return Err("managed native process still exists".into());
    }
    Ok(())
}

pub(crate) fn managed_process_exists(matches_path: impl Fn(&[u8]) -> bool) -> Result<bool> {
    observe_processes(
        || scan_managed_processes(&matches_path),
        || unsafe { libc::usleep(50_000); },
    )
}

fn observe_processes(
    mut scan: impl FnMut() -> Result<bool>,
    mut wait: impl FnMut(),
) -> Result<bool> {
    for attempt in 0..3 {
        let result = scan();
        if attempt == 2 || result.as_ref().err().map(String::as_str)
            != Some("native uninstall process identity unavailable; retry")
        {
            return result;
        }
        wait();
    }
    unreachable!()
}

fn scan_managed_processes(matches_path: &impl Fn(&[u8]) -> bool) -> Result<bool> {
    #[cfg(target_os = "nto")]
    {
        for pid in crate::fs::directory_names("/proc")? {
            if pid.parse::<u32>().is_err() || pid == unsafe { libc::getpid() }.to_string() {
                continue;
            }
            let path = alloc::ffi::CString::new(format!("/proc/{pid}/exefile"))
                .map_err(|_| "process path")?;
            let fd = crate::fs::Fd(unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            });
            // A disappearing or unreadable process cannot establish absence.
            if fd.0 < 0 {
                return Err("native uninstall process identity unavailable; retry".into());
            }
            let mut buffer = [0u8; 4096];
            let n = unsafe { libc::read(fd.0, buffer.as_mut_ptr().cast(), buffer.len()) };
            if n <= 0 || n as usize == buffer.len() {
                return Err("native uninstall process identity bound".into());
            }
            let path = &buffer[..n as usize];
            let path = path.strip_suffix(&[0]).unwrap_or(path);
            let path = path.strip_suffix(b"\n").unwrap_or(path);
            if path.is_empty() || path.contains(&0) || core::str::from_utf8(path).is_err() {
                return Err("native process pathname invalid".into());
            }
            if matches_path(path) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = matches_path;
        Err("QNX process absence unavailable on host".into())
    }
}

/// One-shot, post-kernel-reboot finalizer. The resident service never calls it.
pub fn uninstall(input: FinalizeInput) -> Result<()> {
    use voboost_contract_core::domain_operation::{
        AbsenceChecks, AbsenceStartup, InstalledEvidence,
    };
    let owner = crate::fs::uid()?;
    if owner != 0 {
        return Err("native uninstall finalization requires root".into());
    }
    if retry_final_receipt(&input, owner, true)? {
        return Ok(());
    }
    let config = Config::parse(&read_protected(&input.bootfile, owner, 16384, 0o600)?)?;
    if input.receipt_file.starts_with(&format!("{}/", config.root)) {
        return Err("final receipt must be outside managed root".into());
    }
    let root = Dir::open(&config.root, owner)?;
    let intent: UninstallIntent =
        parse_canonical(&root.read("uninstall-intent.json", 4096, 0o600)?, 4096)?;
    let proof: Installation = parse_canonical(&crate::install_layout::read_state(&root)?, 65536)?;
    let fence = ascii_json(&input.transaction_id)?;
    if intent.schema_version != 1
        || intent.transaction_id != input.transaction_id
        || intent.challenge != input.challenge
        || !digest(&intent.ram_token)
        || proof.schema_version != 1
        || proof.bootfile != input.bootfile
        || proof.startup_file != "/scripts/startup_cluster.sh"
        || !digest(&proof.original_sha256)
        || root.read("restore.lock", 256, 0o600)? != fence
    {
        return Err("native uninstall finalization authority differs".into());
    }
    let current_boot = intent.boot.read_current(owner)?;
    require_new_boot(
        &intent.boot,
        &current_boot,
        crate::fs::boot_identity_absent(&config.boot_identity_file, &config.pair_id)?,
    )?;
    if !crate::diagnostic_ram::absent(&config.pair_id)? {
        return Err("native uninstall diagnostic RAM object remains after reboot".into());
    }
    let (_, _, startup_bytes, startup_mode) = startup(&proof.startup_file, owner)?;
    if hash(&startup_bytes) != proof.original_sha256 || startup_mode != proof.startup_mode {
        return Err("native uninstall original startup not restored".into());
    }
    #[cfg(target_os = "nto")]
    supervisor::require_restored_config(&root, &input.transaction_id, current_boot.clone())?;
    require_no_managed_process(&config.root)?;
    let signer = signing_key(&config)?;
    // Preflight receipt authority before removing the only native signer.
    let (receipt_parent, _) = input
        .receipt_file
        .rsplit_once('/')
        .ok_or("receipt parent missing")?;
    Dir::open(receipt_parent, owner)?;
    let proof_sha256 = hash(&ascii_json(&(intent, &current_boot))?);
    let bytes = AuthenticatedReport {
        schema_version: 1,
        pair_id: config.pair_id.clone(),
        authority_epoch: config.authority_epoch.clone(),
        challenge: input.challenge.clone(),
        report: DomainOperationReport {
            schema_version: 2,
            domain: Domain::Cluster,
            operation: Operation::Uninstall,
            phase: Phase::Complete,
            outcome: Outcome::Completed,
            transaction_id: input.transaction_id.clone(),
            release_manifest_sha256: proof.release_manifest_sha256.clone(),
            catalog_sha256: proof.catalog_sha256,
            generation_id: None,
            desired_revision: 0,
            desired_sha256: voboost_contract_core::cluster::desired_digest(&[])?,
            boot_id: None,
            daemon_epoch: None,
            installed_evidence: Some(InstalledEvidence::QnxAbsence {
                startup: AbsenceStartup {
                    path: proof.startup_file,
                    original_sha256: proof.original_sha256.clone(),
                    restored_sha256: proof.original_sha256,
                },
                checks: AbsenceChecks {
                    daemon_process_absent: true,
                    autostart_removed: true,
                    native_payload_absent: true,
                    persistent_state_absent: true,
                },
                proof_sha256,
            }),
        },
    }
    .sign(&signer)?;
    let (directory, name) = final_receipt_directory(&input, owner)?;
    let pending_name = format!("{name}.pending");
    let pending = ascii_json(&FinalReceipt {
        input_sha256: hash(&ascii_json(&input)?),
        root: config.root.clone(),
        root_device: crate::fs::stat(root.fd.0)?.st_dev as u64,
        root_inode: crate::fs::stat(root.fd.0)?.st_ino as u64,
        boot: current_boot,
        public_key: config.qnx_public_key,
        pair_id: config.pair_id,
        authority_epoch: config.authority_epoch,
        product: proof.release_manifest_sha256,
        envelope: hex::encode(&bytes),
    })?;
    crate::supervisor_delivery::revoke(&root)?;
    directory.write(&pending_name, &pending, 0o600)?;
    if directory.read(&pending_name, 131072, 0o600)? != pending {
        return Err("native final receipt readback differs".into());
    }
    crate::fs::purge_installation_tree(&root)?;
    directory.write(&name, &bytes, 0o600)?;
    crate::fs::write_all(1, &bytes)
}

/// The authenticated service reuses installed, protected authority; the courier
/// never supplies paths, backup hashes, filesystem IDs or executable commands.
pub fn prepare_service_uninstall(
    authority: &crate::engine::Authority,
    request: &voboost_contract_core::cluster::Request,
) -> Result<Vec<u8>> {
    prepare_uninstall(
        &authority.config,
        request,
        &authority.boot_id,
        &authority.daemon_epoch,
        || crate::service::controller(authority, true).map(|value| value.is_some()),
    )
}

fn prepare_uninstall(
    config: &Config,
    request: &voboost_contract_core::cluster::Request,
    boot_id: &str,
    daemon_epoch: &str,
    stop_resident: impl FnOnce() -> Result<bool>,
) -> Result<Vec<u8>> {
    use voboost_contract_core::domain_operation::{AbsenceStartup, InstalledEvidence};
    let owner = crate::fs::uid()?;
    let root = Dir::open(&config.root, owner)?;
    let proof: Installation = parse_canonical(&crate::install_layout::read_state(&root)?, 65536)?;
    if proof.schema_version != 1
        || request.kind != voboost_contract_core::cluster::RequestKind::Uninstall
        || request.pair_id != config.pair_id
        || request.authority_epoch != config.authority_epoch
        || request.release_manifest_sha256.as_deref()
            != Some(proof.release_manifest_sha256.as_str())
        || request.catalog_sha256 != proof.catalog_sha256
        || proof.startup_file != "/scripts/startup_cluster.sh"
        || !digest(&proof.original_sha256)
        || proof.bootfile != format!("{}/boot.json", config.root)
    {
        return Err("native uninstall installation authority differs".into());
    }
    signing_key(config)?;
    let original = root.read("startup.original", 1024 * 1024, 0o600)?;
    let (parent, name, current, mode) = startup(&proof.startup_file, owner)?;
    if hash(&original) != proof.original_sha256
        || ![&proof.installed_sha256, &proof.original_sha256].contains(&&hash(&current))
        || mode != proof.startup_mode
    {
        return Err("native uninstall exact startup backup differs".into());
    }
    let fence = ascii_json(&request.transaction_id)?;
    let mut intent = if root.exists("uninstall-intent.json")? {
        let intent: UninstallIntent =
            parse_canonical(&root.read("uninstall-intent.json", 4096, 0o600)?, 4096)?;
        validate_uninstall_intent(&intent, request)?;
        intent
    } else {
        UninstallIntent {
            schema_version: 1,
            transaction_id: request.transaction_id.clone(),
            challenge: request.challenge.clone(),
            boot: UninstallBoot::current(owner)?,
            ram_token: boot_id.into(),
        }
    };
    // A renewed preparation of a legacy intent requires another real reboot.
    if matches!(intent.boot, UninstallBoot::KernelTime(_)) {
        intent.boot = UninstallBoot::current(owner)?;
    }
    // Fence future delivery before changing any OEM startup files.
    crate::supervisor_delivery::revoke(&root)?;
    let intent_bytes = ascii_json(&intent)?;
    if !root.exists("uninstall-intent.json")?
        || root.read("uninstall-intent.json", 4096, 0o600)? != intent_bytes
    {
        root.write("uninstall-intent.json", &intent_bytes, 0o600)?;
    }
    root.write("restore.lock", &fence, 0o600)?;
    let input = Integration {
        schema_version: 1,
        bootfile: proof.bootfile.clone(),
        source_directory: config.root.clone(),
        provision_directory: None,
        startup_file: proof.startup_file.clone(),
        original_sha256: proof.original_sha256.clone(),
        anchor: "clusterboot &".into(),
        startup_profile: Some(StartupProfile::Clusterboot),
        scope: RootScope::Persistent,
        root_device_id: format!("{}", crate::fs::stat(root.fd.0)?.st_dev),
        transaction_id: request.transaction_id.clone(),
        challenge: request.challenge.clone(),
        // No output file is used by this network operation.
        receipt_file: format!("{}/unused-report", config.root),
    };
    let (resident_restore, reason) = prepare_restoration(
        || {
            #[cfg(target_os = "nto")]
            supervisor::restore_config(&root, &request.transaction_id)?;
            crate::oem_startup::write(&input, &parent, &current, &original, mode, &root)?;
            if parent.read(&name, original.len(), mode)? != original
                || root.read("restore.lock", 256, 0o600)? != fence
            {
                return Err("native uninstall preparation readback differs".into());
            }
            Ok(())
        },
        stop_resident,
    )?;
    signed_report(
        config,
        &input,
        DomainOperationReport {
            schema_version: 2,
            domain: Domain::Cluster,
            operation: Operation::Uninstall,
            phase: Phase::Uninstall,
            outcome: Outcome::ReloadRequired,
            transaction_id: request.transaction_id.clone(),
            release_manifest_sha256: proof.release_manifest_sha256,
            catalog_sha256: proof.catalog_sha256,
            generation_id: None,
            desired_revision: 0,
            desired_sha256: voboost_contract_core::cluster::desired_digest(&[])?,
            boot_id: Some(boot_id.into()),
            daemon_epoch: Some(daemon_epoch.into()),
            installed_evidence: Some(InstalledEvidence::QnxRestored {
                startup: AbsenceStartup {
                    path: proof.startup_file,
                    original_sha256: proof.original_sha256.clone(),
                    restored_sha256: hash(&original),
                },
                restore_fence_sha256: hash(&fence),
                resident_restore,
                reason,
            }),
        },
    )
}

fn prepare_restoration(
    restore_startup: impl FnOnce() -> Result<()>,
    stop_resident: impl FnOnce() -> Result<bool>,
) -> Result<(
    voboost_contract_core::domain_operation::ResidentRestore,
    String,
)> {
    use voboost_contract_core::domain_operation::ResidentRestore;
    restore_startup()?;
    match stop_resident() {
        Ok(true) => Ok((
            ResidentRestore::Restored,
            "resident effects restored; cluster reboot required".into(),
        )),
        Ok(false) => Ok((
            ResidentRestore::ReloadRequired,
            "resident restoration unconfirmed; cluster reboot required".into(),
        )),
        Err(error) => Ok((
            ResidentRestore::ReloadRequired,
            error
                .chars()
                .take(128)
                .map(|c| {
                    if c.is_ascii_graphic() || c == ' ' {
                        c
                    } else {
                        ' '
                    }
                })
                .collect(),
        )),
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
#[path = "../../tests/installation.rs"]
mod tests;

#[cfg(test)]
mod finalizer_tests {
    use super::*;
    #[test]
    fn finalizer_input_rejects_unsafe_paths_and_missing_correlation() {
        let valid = FinalizeInput {
            schema_version: 1,
            bootfile: "/var/voboost/boot.json".into(),
            transaction_id: "a".repeat(64),
            challenge: "b".repeat(64),
            receipt_file: "/var/voboost-finalize-test/receipt.bin".into(),
        };
        assert!(FinalizeInput::parse(&ascii_json(&valid).unwrap()).is_ok());
        assert!(FinalizeInput::parse(b"{}").is_err());
        let mut invalid = valid;
        invalid.bootfile = "/var/../voboost/boot.json".into();
        assert!(FinalizeInput::parse(&ascii_json(&invalid).unwrap()).is_err());
        invalid.bootfile = "/var/voboost/boot.json".into();
        invalid.challenge.clear();
        assert!(FinalizeInput::parse(&ascii_json(&invalid).unwrap()).is_err());
        assert!(super::prepare_remove("../unsafe").is_err());
        assert!(super::finish_remove("../unsafe").is_err());
    }
    #[test]
    fn finalizer_needs_independent_kernel_change_and_ram_absence() {
        for (old, current, absent) in [(0, 2, true), (1, 0, true), (1, 1, true), (1, 2, false)] {
            assert!(super::require_new_boot(&old.into(), &current.into(), absent).is_err());
        }
        assert!(super::require_new_boot(&1.into(), &2.into(), true).is_ok());
    }

    #[test]
    fn finalizer_uses_supervisor_boot_identity_when_qtime_is_constant() {
        let old = UninstallBoot::Supervisor("a".repeat(64));
        let new = UninstallBoot::Supervisor("b".repeat(64));
        assert!(require_new_boot(&old, &old, true).is_err());
        assert!(require_new_boot(&old, &1.into(), true).is_err());
        assert!(require_new_boot(&old, &new, false).is_err());
        assert!(require_new_boot(&old, &new, true).is_ok());
    }

    #[test]
    fn signed_receipt_retry_crosses_kernel_only_after_root_absence() {
        let receipt_retry_regenerate =
            |old: u32, current: u32, absent| super::receipt_retry_regenerate(&old.into(), &current.into(), absent);
        for root_absent in [false, true] {
            assert!(receipt_retry_regenerate(1, 1, root_absent).is_ok());
            for (recorded, current) in [(0, 0), (0, 2), (1, 0), (2, 1)] {
                assert!(receipt_retry_regenerate(recorded, current, root_absent).is_err());
            }
        }
        assert!(receipt_retry_regenerate(1, 2, true).is_ok());
        assert!(receipt_retry_regenerate(1, 2, false).unwrap());
        assert!(!receipt_retry_regenerate(1, 2, true).unwrap());
        assert!(!receipt_retry_regenerate(1, 1, false).unwrap());
    }

    #[test]
    fn new_kernel_revalidates_original_authority_without_old_inode_guard() {
        let regenerate = receipt_retry_regenerate(&1.into(), &2.into(), false).unwrap();
        assert!(retry_root_requires_regeneration(regenerate, (1, 2), || {
            panic!("fresh authority admission must not consult old physical identity")
        })
        .unwrap());
        let same_boot = receipt_retry_regenerate(&1.into(), &1.into(), false).unwrap();
        assert!(!retry_root_requires_regeneration(same_boot, (1, 2), || Ok((1, 2))).unwrap());
        for changed in [(2, 2), (1, 3)] {
            assert!(retry_root_requires_regeneration(same_boot, (1, 2), || Ok(changed)).is_err());
        }
        assert!(retry_root_requires_regeneration(same_boot, (1, 2), || Err(
            "identity unreadable".into()
        ))
        .is_err());
    }
}
