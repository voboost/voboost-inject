//! Bounded observational preparation of the protected install stage.
//! This neither grants privilege nor claims an installation has completed.
use crate::{
    fs::{Dir, Fd},
    Result,
};
use alloc::{ffi::CString, format, string::String, vec, vec::Vec};
use serde::Serialize;
use voboost_contract_core::{ascii_json, catalog::BuildIdentity, digest, hash};

#[path = "bootstrap_elf.rs"]
mod bootstrap_elf;

#[cfg(test)]
pub(crate) use bootstrap_elf::lookup_fixture;
#[cfg(any(target_os = "nto", test))]
pub(crate) use bootstrap_elf::select_export;

const STARTUP: &str = "/scripts/startup_cluster.sh";
const GAUGE: &str = "/usr/bin/gauge";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stage {
    schema_version: u32,
    transaction_id: String,
    root: String,
    stage_directory: String,
    source_directory: String,
    provision_directory: String,
    bootfile: String,
    integration_file: String,
    receipt_file: String,
    prepare_report_file: String,
    effective_uid: u32,
    root_uid: u32,
    root_mode: u32,
    existing_bootfile: bool,
    existing_installation: bool,
    startup_file: String,
    startup_bytes: u64,
    original_sha256: String,
    anchor: String,
    startup_profile: String,
    root_device_id: String,
    expected_executable: String,
    expected_executable_sha256: String,
    expected_executable_bytes: u64,
    expected_build_ids: Vec<BuildIdentity>,
}

#[cfg(any(target_os = "nto", test))]
const STARTUP_MARKERS: &[&[u8]] = &[b"/var/voboost/", b"voboost-cluster-startup.sh"];

fn protected_file(path: &str, maximum: usize) -> Result<Vec<u8>> {
    protected_input(path, maximum, true)
}

pub(crate) fn protected_input(path: &str, maximum: usize, nofollow: bool) -> Result<Vec<u8>> {
    let name = CString::new(path).map_err(|_| "bootstrap identity path")?;
    let fd = Fd(unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | if nofollow { libc::O_NOFOLLOW } else { 0 },
        )
    });
    read_protected_input(fd, maximum)
}

fn read_protected_input(fd: Fd, maximum: usize) -> Result<Vec<u8>> {
    if fd.0 < 0 {
        return Err("SetupRequired: protected bootstrap input unavailable".into());
    }
    let before = crate::fs::stat(fd.0)?;
    if before.st_uid != 0
        || before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_mode & 0o022 != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > maximum as u64
    {
        return Err(
            "SetupRequired: protected bootstrap input owner/mode/type/length rejected".into(),
        );
    }
    let mut bytes = vec![0; before.st_size as usize];
    crate::fs::read_exact(fd.0, &mut bytes)?;
    if !crate::fs::unchanged(&before, &crate::fs::stat(fd.0)?) {
        return Err("SetupRequired: protected bootstrap input changed while reading".into());
    }
    Ok(bytes)
}

fn directories(parent: &Dir, transaction_id: &str, startup: &[u8], gauge: &[u8]) -> Result<Stage> {
    if !digest(transaction_id) {
        return Err("prepare-stage requires strict transaction hash".into());
    }
    let stage_name = format!("voboost-stage-{transaction_id}");
    if parent.exists(&stage_name)? {
        return Err("SetupRequired: transaction stage already exists".into());
    }
    // Existing persistent roots are admitted only by the same exact protected
    // owner/mode/path guard as newly created roots. No chmod or takeover occurs.
    let root = parent.child("voboost")?;
    let stage = parent.child(&stage_name)?;
    let source = stage.child("source")?;
    let provision = stage.child("provision")?;
    let root_stat = crate::fs::stat(root.fd.0)?;
    #[cfg(target_os = "nto")]
    let root_uid = u32::try_from(root_stat.st_uid).map_err(|_| "bootstrap root UID invalid")?;
    #[cfg(not(target_os = "nto"))]
    let root_uid = root_stat.st_uid;
    Ok(Stage {
        schema_version: 1,
        transaction_id: transaction_id.into(),
        root: root.path.clone(),
        stage_directory: stage.path.clone(),
        source_directory: source.path,
        provision_directory: provision.path,
        bootfile: format!("{}/boot.json", root.path),
        integration_file: format!("{}/integration.json", stage.path),
        receipt_file: format!("{}/receipt.json", stage.path),
        prepare_report_file: format!("{}/prepare.json", stage.path),
        effective_uid: crate::fs::uid()?,
        root_uid,
        root_mode: root_stat.st_mode as u32 & 0o777,
        existing_bootfile: root.exists("boot.json")?,
        existing_installation: crate::install_layout::state_exists(&root)?,
        startup_file: STARTUP.into(),
        startup_bytes: startup.len() as u64,
        original_sha256: hash(startup),
        anchor: "clusterboot &".into(),
        startup_profile: "clusterboot".into(),
        root_device_id: format!("{}", root_stat.st_dev),
        expected_executable: GAUGE.into(),
        expected_executable_sha256: hash(gauge),
        expected_executable_bytes: gauge.len() as u64,
        expected_build_ids: vec![BuildIdentity {
            path: GAUGE.into(),
            build_id: crate::elf::build_id(gauge)?,
        }],
    })
}

/// Probe the executable format rather than a firmware-specific identity.
pub(crate) fn verify_recovery_profile() -> Result<()> {
    let gauge = protected_file(GAUGE, 64 * 1024 * 1024)?;
    bootstrap_elf::probe(&gauge, true, &[])?;
    crate::elf::build_id(&gauge)?;
    Ok(())
}

// Names are the actual interposition/resolve targets in service/preload.cpp.
// These are linkage probes; per-feature runtime objects/ABI still need their
// own capability probes before use.
fn probe_startup_dependencies() -> Result<()> {
    let engine = protected_input("/lib64/libenginecore.so.0", 64 * 1024 * 1024, false)?;
    bootstrap_elf::probe(&engine, false, &[
        "_Z13engnCore_initP22_EngineInitInfo_StructP16_Kanzi_Cb_StructP16CEngnThemeActionNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE",
        "_Z17engnCore_onupdatev",
        "_ZN13CMcudataParse14parseGaugedataEPvS0_j",
    ])?;
    let ui = protected_input("/lib64/libkzcoreui.so", 64 * 1024 * 1024, false)?;
    bootstrap_elf::probe(
        &ui,
        false,
        &[
            "FT_New_Memory_Face",
            "_ZN5kanzi4Node13lookupNodeRawEN5boost17basic_string_viewIcSt11char_traitsIcEEE",
            "_ZNK5kanzi4Node10isAttachedEv",
        ],
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StockObservation<'a> {
    schema_version: u32,
    kind: &'static str,
    challenge: &'a str,
    state: &'static str,
    object: &'static str,
}

fn stock_observation(
    challenge: &str,
    observe: impl FnOnce() -> core::result::Result<Option<&'static str>, &'static str>,
) -> Result<Vec<u8>> {
    if !digest(challenge) {
        return Err("observe-stock requires strict challenge".into());
    }
    let (state, object) = match observe() {
        Ok(None) => ("absent", "known-surfaces"),
        Ok(Some(object)) => ("present", object),
        Err(object) => ("unknown", object),
    };
    ascii_json(&StockObservation {
        schema_version: 1,
        kind: "bootstrap-stock-observation",
        challenge,
        state,
        object,
    })
}

#[cfg(any(target_os = "nto", test))]
fn stock_stage_name(name: &str) -> bool {
    name.strip_prefix("voboost-stage-")
        .or_else(|| name.strip_prefix("voboost-finalize-"))
        .or_else(|| {
            let suffix = name.strip_prefix("voboost-observe-")?;
            Some(suffix.strip_suffix(".json").unwrap_or(suffix))
        })
        .is_some_and(digest)
}

#[cfg(any(target_os = "nto", test))]
fn stock_helper_name(name: &str, own_name: &str) -> bool {
    name != own_name
        && ["voboost-stock-", "voboost-bootstrap-"]
            .iter()
            .any(|prefix| name.strip_prefix(prefix).is_some_and(digest))
}

#[cfg(any(target_os = "nto", test))]
fn stock_process(path: &[u8]) -> bool {
    let Some(path) = core::str::from_utf8(path).ok() else {
        return false;
    };
    if let Some(member) = path.strip_prefix("/var/") {
        let name = member.split('/').next().unwrap_or(member);
        return name == "voboost" || stock_stage_name(name) || stock_helper_name(name, "");
    }
    // Legacy qconn uploads are never read through /tmp. An already running
    // helper with its exact historical path is nevertheless positive evidence.
    ["/tmp/", "/log/tmp/"].iter().any(|prefix| {
        path.strip_prefix(prefix)
            .and_then(|name| name.strip_prefix("voboost-"))
            .is_some_and(|name| digest(name) || name.strip_prefix("stock-").is_some_and(digest))
    })
}

fn helper_name<'a>(path: &'a str, role: &str, nonce: &str) -> Result<&'a str> {
    if !digest(nonce) {
        return Err("native helper requires a strict nonce".into());
    }
    let name = path
        .strip_prefix("/var/")
        .ok_or("native helper outside /var")?;
    if name != format!("voboost-{role}-{nonce}") {
        return Err("native helper role or nonce differs".into());
    }
    Ok(name)
}

#[cfg(target_os = "nto")]
fn helper_file(parent: &Dir, name: &str, path: &str) -> Result<Fd> {
    let pid = u64::try_from(unsafe { libc::getpid() }).map_err(|_| "native helper PID invalid")?;
    if crate::elf::process_path(pid)? != path {
        return Err("running native helper path differs".into());
    }
    let fd = parent.open_file(
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )?;
    let file = crate::fs::stat(fd.0)?;
    if file.st_dev != crate::fs::stat(parent.fd.0)?.st_dev
        || file.st_uid != 0
        || file.st_gid != 0
        || file.st_mode as u32 != (libc::S_IFREG as u32 | 0o700)
        || file.st_nlink != 1
        || file.st_size <= 0
    {
        return Err("native helper file authority rejected".into());
    }
    Ok(fd)
}

fn helper_parent(path: &str, role: &str, nonce: &str) -> Result<Dir> {
    let name = helper_name(path, role, nonce)?;
    #[cfg(target_os = "nto")]
    {
        if crate::fs::uid()? != 0 {
            return Err("SetupRequired: initial QNX bootstrap requires root".into());
        }
        let parent = Dir::observe_parent("/var")?;
        helper_file(&parent, name, path)?;
        Ok(parent)
    }
    #[cfg(not(target_os = "nto"))]
    {
        let _ = name;
        Err("QNX helper authority unavailable on host".into())
    }
}

pub(crate) fn bootstrap_parent(path: &str, transaction: &str) -> Result<Dir> {
    helper_parent(path, "bootstrap", transaction)
}

pub(crate) fn install(path: &str, input: &str) -> Result<()> {
    use crate::install::{Integration, StartupProfile};
    use voboost_contract_core::domain_operation::RootScope;

    let transaction = input
        .strip_prefix("/var/voboost-stage-")
        .and_then(|rest| rest.strip_suffix("/integration.json"))
        .ok_or("native bootstrap integration path rejected")?;
    let parent = bootstrap_parent(path, transaction)?;
    let stage = parent.existing_child(&format!("voboost-stage-{transaction}"))?;
    let integration = Integration::parse(&stage.read("integration.json", 16384, 0o600)?)?;
    if integration.transaction_id != transaction
        || integration.bootfile != "/var/voboost/boot.json"
        || integration.startup_file != STARTUP
        || integration.source_directory != format!("{}/source", stage.path)
        || integration.provision_directory.as_deref()
            != Some(format!("{}/provision", stage.path).as_str())
        || integration.receipt_file != format!("{}/receipt.json", stage.path)
        || !matches!(
            integration.startup_profile,
            Some(StartupProfile::Clusterboot)
        )
        || !matches!(integration.scope, RootScope::Persistent)
    {
        return Err("native bootstrap integration authority differs".into());
    }
    stage.existing_child("source")?;
    stage.existing_child("provision")?;
    let root = parent.existing_child("voboost")?;
    let config = crate::service::bootfile(&integration.bootfile)?;
    if config.root != root.path {
        return Err("native bootstrap product root differs".into());
    }
    let _operation = crate::operation::Lock::initialize(&root)?;
    crate::install::install(integration)
}

#[cfg(any(target_os = "nto", test))]
fn has_marker(bytes: &[u8], markers: &[&[u8]]) -> bool {
    markers
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

#[cfg(target_os = "nto")]
fn stock_file(parent: &Dir, name: &str, maximum: usize) -> Result<Vec<u8>> {
    let fd = parent.open_file(
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )?;
    read_protected_input(fd, maximum)
}

#[cfg(target_os = "nto")]
fn stock_surfaces(
    path: &str,
    challenge: &str,
) -> core::result::Result<Option<&'static str>, &'static str> {
    use crate::supervisor_config::{
        machinery::Writer, qnx::ConfigFile, xml::stock_marker_present, CONFIG_PATH,
    };

    if crate::fs::uid().map_err(|_| "authority")? != 0 {
        return Err("authority");
    }
    let var = Dir::observe_parent("/var").map_err(|_| "authority")?;
    let own_name = helper_name(path, "stock", challenge).map_err(|_| "authority")?;
    let own_file = helper_file(&var, own_name, path).map_err(|_| "authority")?;
    let before = crate::fs::stat(own_file.0).map_err(|_| "authority")?;
    let names = var.observe_names().map_err(|_| "transaction-stage")?;
    if names.iter().any(|name| name == "voboost") {
        return Ok(Some("product-root"));
    }
    if names.iter().any(|name| stock_stage_name(name)) {
        return Ok(Some("transaction-stage"));
    }
    if names.iter().any(|name| stock_helper_name(name, own_name)) {
        return Ok(Some("temporary-helper"));
    }

    let scripts = Dir::observe_parent("/scripts").map_err(|_| "startup")?;
    let startup = stock_file(&scripts, "startup_cluster.sh", 1024 * 1024).map_err(|_| "startup")?;
    if has_marker(&startup, STARTUP_MARKERS) {
        return Ok(Some("startup"));
    }
    if scripts
        .observe_names()
        .map_err(|_| "startup")?
        .iter()
        .any(|name| name.strip_prefix(".write-").is_some_and(digest))
    {
        return Err("startup");
    }
    crate::install::probe_clusterboot_startup(&startup).map_err(|_| "startup")?;

    let (parent, _) = CONFIG_PATH.rsplit_once('/').ok_or("supervisor-config")?;
    let clsboot = Dir::observe_parent(parent).map_err(|_| "supervisor-config")?;
    let config = ConfigFile::open(&clsboot)
        .and_then(|mut file| file.observe())
        .map_err(|_| "supervisor-config")?;
    if config.present && stock_marker_present(&config.bytes).map_err(|_| "supervisor-config")? {
        return Ok(Some("supervisor-config"));
    }
    if clsboot
        .observe_names()
        .map_err(|_| "supervisor-config")?
        .iter()
        .any(|name| name.strip_prefix('.').is_some_and(digest))
    {
        return Err("supervisor-config");
    }

    let bin = Dir::observe_parent("/usr/bin").map_err(|_| "oem-profile")?;
    let gauge = stock_file(&bin, "gauge", 64 * 1024 * 1024).map_err(|_| "oem-profile")?;
    bootstrap_elf::probe(&gauge, true, &[]).map_err(|_| "oem-profile")?;
    crate::elf::build_id(&gauge).map_err(|_| "oem-profile")?;

    if crate::install::managed_process_exists(stock_process).map_err(|_| "managed-process")? {
        return Ok(Some("managed-process"));
    }
    if var.observe_names().map_err(|_| "transaction-stage")? != names {
        return Err("transaction-stage");
    }
    let current = helper_file(&var, own_name, path).map_err(|_| "authority")?;
    let after = crate::fs::stat(current.0).map_err(|_| "authority")?;
    if !crate::fs::unchanged(&before, &after) {
        return Err("authority");
    }
    Ok(None)
}

/// Read-only pre-pair observation of known installation surfaces and processes.
/// Paired restoration and pair-specific RAM require authenticated lifecycle evidence.
pub fn observe_stock(path: &str, challenge: &str) -> Result<()> {
    #[cfg(target_os = "nto")]
    let bytes = stock_observation(challenge, || stock_surfaces(path, challenge))?;
    #[cfg(not(target_os = "nto"))]
    let bytes = stock_observation(challenge, || {
        let _ = path;
        Err("authority")
    })?;
    crate::fs::write_all(1, &bytes)
}

pub fn prepare_stage(path: &str, transaction_id: &str) -> Result<()> {
    // Pin the protected parent before any mutation, then probe the OEM entrypoints.
    let parent = bootstrap_parent(path, transaction_id)?;
    let startup = protected_file(STARTUP, 1024 * 1024)?;
    crate::install::probe_clusterboot_startup(&startup)?;
    let gauge = protected_file(GAUGE, 64 * 1024 * 1024)?;
    bootstrap_elf::probe(&gauge, true, &[])?;
    crate::elf::build_id(&gauge)?;
    probe_startup_dependencies()?;
    let report = directories(&parent, transaction_id, &startup, &gauge)
        .map_err(|error| format!("bootstrap directories: {error}"))?;
    let bytes =
        ascii_json(&report).map_err(|error| format!("bootstrap report encoding: {error}"))?;
    if bytes.len() > 16384 {
        return Err("bootstrap observation exceeds bound".into());
    }
    let stage = parent
        .existing_child(&format!("voboost-stage-{transaction_id}"))
        .map_err(|error| format!("bootstrap stage reopen: {error}"))?;
    stage
        .write("prepare.json", &bytes, 0o600)
        .map_err(|error| format!("bootstrap report publication: {error}"))?;
    if stage
        .read("prepare.json", 16384, 0o600)
        .map_err(|error| format!("bootstrap report readback: {error}"))?
        != bytes
    {
        return Err("bootstrap observation readback differs".into());
    }
    crate::fs::write_all(1, &bytes).map_err(|error| format!("bootstrap report stdout: {error}"))
}

#[cfg(test)]
#[path = "../../tests/bootstrap.rs"]
mod tests;
