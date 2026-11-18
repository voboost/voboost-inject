use crate::contract::InstallDescriptor;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use voboost_shared::uninstall_contract;

const UNINSTALL: &str = "/data/voboost/uninstall";
const ROOT: &str = "/data/voboost";
const ARTIFACTS: &str = "/data/voboost/uninstall/system-artifacts.json";
const BASELINE: &str = "/data/voboost/uninstall/current-baseline.json";
const POLICY_META: &str = "/data/voboost/uninstall/policy.meta.json";
const SYSTEM_STATE: &str = "/data/voboost/uninstall/system-state.json";
const INIT_ARCHIVE: &str = "/data/voboost/uninstall/system/voboost.rc";
const POLICY: &str = "/vendor/etc/selinux/precompiled_sepolicy";
const INIT: &str = "/system/etc/init/voboost.rc";
const MAX_FRESH_STATE_BYTES: usize = 4096;
const MAX_INVENTORY_DOCUMENT_BYTES: usize = 1024 * 1024;
const MAX_POLICY_BYTES: usize = 64 * 1024 * 1024;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn runtime_payload(descriptor: &InstallDescriptor) -> Result<Vec<serde_json::Value>, String> {
    [
        ("libimplant-arm64-v8a.so", "arm64-v8a"),
        ("libimplant-armeabi-v7a.so", "armeabi-v7a"),
    ]
    .into_iter()
    .map(|(path, abi)| {
        let item = descriptor
            .artifacts
            .iter()
            .find(|item| item.file == path)
            .ok_or_else(|| format!("descriptor lacks {path}"))?;
        Ok(serde_json::json!({
            "path": format!("/data/voboost/{path}"),
            "abi": abi,
            "component": "implant",
            "size": item.size,
            "sha256": item.sha256,
            "signatureRole": "runtime",
        }))
    })
    .collect()
}

fn artifact(descriptor: &InstallDescriptor, path: &str) -> Result<serde_json::Value, String> {
    let item = descriptor
        .artifacts
        .iter()
        .find(|item| item.file == path)
        .ok_or_else(|| format!("descriptor lacks {path}"))?;
    let installed_path = Path::new("/data/voboost").join(path);
    crate::runtime::read_descriptor_artifact(
        &installed_path,
        path,
        crate::runtime::live_mode(path),
        descriptor,
    )?;
    let metadata = fs::symlink_metadata(&installed_path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(format!("installed artifact {path} has a foreign identity"));
    }
    Ok(
        serde_json::json!({"path":format!("/data/voboost/{path}"),"size":item.size,"sha256":item.sha256,"signatureRole":role_name(item.role),"uid":metadata.uid(),"gid":metadata.gid(),"mode":format!("{:04o}",metadata.permissions().mode()&0o7777),"context":context(&installed_path)?}),
    )
}

fn role_name(role: voboost_contract::release::ArtifactRole) -> &'static str {
    use voboost_contract::release::ArtifactRole;
    match role {
        ArtifactRole::Daemon | ArtifactRole::QnxDaemon => "daemon",
        ArtifactRole::Inject => "inject",
        ArtifactRole::Install => "install",
        ArtifactRole::Restore => "restore",
        ArtifactRole::Uninstall => "uninstall",
        ArtifactRole::Selinux => "selinux",
        _ => "runtime",
    }
}
#[cfg(any(target_os = "android", target_os = "linux"))]
fn context(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let name = b"security.selinux\0";
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size <= 1 || size > 128 {
        return Err(format!("{} has invalid SELinux context", path.display()));
    }
    let mut bytes = vec![0; size as usize];
    if unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    } != size
    {
        return Err("read SELinux context failed".into());
    }
    if bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8(bytes).map_err(|_| "SELinux context is not UTF-8".into())
}
#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn context(_path: &Path) -> Result<String, String> {
    Err("SELinux context inventory requires Android/Linux".into())
}
fn canonical(value: serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&value).map_err(|e| e.to_string())
}

fn write_protected(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    super::write_atomic_labeled(
        path,
        bytes,
        mode,
        Some(crate::selinux_backend::INVENTORY_CONTEXT),
    )
}

fn label_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.set_permissions(fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    super::set_file_context(&file, crate::selinux_backend::INVENTORY_CONTEXT)?;
    file.sync_all().map_err(|e| e.to_string())
}

pub fn commit(
    staging: &Path,
    recovery: &Path,
    _journal: &super::journal::InstallJournal,
) -> Result<(), String> {
    let fresh_state = crate::fresh::FreshState::parse(&crate::read_bounded(
        &recovery.join("fresh-state.json"),
        MAX_FRESH_STATE_BYTES,
        0o600,
    )?)?;
    let descriptor = InstallDescriptor::parse(&crate::read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_NAME),
        voboost_contract::release::MAX_MANIFEST_BYTES,
        0o600,
    )?)?;
    crate::runtime::verify_committed(staging, &descriptor)?;
    crate::runtime::verify_native_release(&descriptor)?;
    let pristine = crate::read_bounded(
        &recovery.join("precompiled_sepolicy.orig"),
        MAX_POLICY_BYTES,
        0o600,
    )?;
    let baseline_sha256 = digest(&pristine);
    let patched = crate::read_bounded(Path::new(POLICY), MAX_POLICY_BYTES, 0o644)?;
    let rc = crate::runtime::read_descriptor_artifact(
        &staging.join("voboost.rc"),
        "voboost.rc",
        0o600,
        &descriptor,
    )?;
    if rc != crate::read_bounded(Path::new(INIT), rc.len(), 0o644)? {
        return Err("live init service differs before inventory commit".into());
    }
    fs::create_dir_all(format!("{UNINSTALL}/system")).map_err(|e| e.to_string())?;
    fs::create_dir_all(format!("{UNINSTALL}/baselines/{}", baseline_sha256))
        .map_err(|e| e.to_string())?;
    for path in [
        UNINSTALL.to_string(),
        format!("{UNINSTALL}/system"),
        format!("{UNINSTALL}/baselines"),
        format!("{UNINSTALL}/baselines/{baseline_sha256}"),
    ] {
        label_directory(Path::new(&path))?;
    }
    let baseline_path = format!(
        "{UNINSTALL}/baselines/{}/precompiled_sepolicy.orig",
        baseline_sha256
    );
    write_protected(Path::new(&baseline_path), &pristine, 0o600)?;
    write_protected(Path::new(INIT_ARCHIVE), &rc, 0o600)?;
    let payload = runtime_payload(&descriptor)?;
    let qnx = uninstall_contract::QNX_RELAY_PATHS
        .iter()
        .map(|(path, _, _)| {
            let name = path
                .strip_prefix("/data/voboost/")
                .ok_or("QNX inventory path is outside root")?;
            artifact(&descriptor, name)
        })
        .collect::<Result<Vec<_>, String>>()?;
    let find = |path: &str| {
        descriptor
            .artifacts
            .iter()
            .find(|v| v.file == path)
            .ok_or_else(|| format!("{path} absent"))
    };
    let manifest_bytes = crate::read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_NAME),
        voboost_contract::release::MAX_MANIFEST_BYTES,
        0o600,
    )?;
    let manifest_signature = crate::read_bounded(
        &staging.join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
        64,
        0o600,
    )?;
    let restore = find("restore.json")?;
    let restore_sig = find("restore.json.sig")?;
    let apk = find("voboost-app.apk")?;
    let init_meta = fs::metadata(INIT).map_err(|e| e.to_string())?;
    let artifacts = canonical(serde_json::json!({"schemaVersion":1,
        "root":{"path":uninstall_contract::ROOT_ZONE_PATH,"markerPath":uninstall_contract::ROOT_ZONE_MARKER_PATH,"markerSha256":uninstall_contract::ROOT_ZONE_MARKER_SHA256},
        "init":{"path":INIT,"installedSize":rc.len(),"installedSha256":digest(&rc),"archivePath":INIT_ARCHIVE,"uid":init_meta.uid(),"gid":init_meta.gid(),"mode":format!("{:04o}",init_meta.permissions().mode()&0o7777),"context":context(Path::new(INIT))?},
        "policy":{"path":POLICY,"installedSha256":digest(&patched),"currentBaselineSha256":baseline_sha256},
        "native":{"daemon":artifact(&descriptor,"voboost-daemon")?,"inject":artifact(&descriptor,"voboost-inject")?,"installer":artifact(&descriptor,"voboost-install")?,"uninstaller":artifact(&descriptor,"voboost-uninstall")?,"restore":artifact(&descriptor,"voboost-restore")?,"restoreManifest":{"path":"/data/voboost/restore.json","size":restore.size,"sha256":restore.sha256,"signaturePath":"/data/voboost/restore.json.sig","signatureSize":restore_sig.size,"signatureSha256":restore_sig.sha256,"signatureRole":"restore-manifest"},"selinux":artifact(&descriptor,"voboost-selinux")?,"manifest":{"path":"/data/voboost/voboost.json","size":manifest_bytes.len(),"sha256":digest(&manifest_bytes),"signaturePath":"/data/voboost/voboost.json.sig","signatureSize":manifest_signature.len(),"signatureSha256":digest(&manifest_signature),"signatureRole":"release-catalog"},"payload":payload,"qnx":qnx},
        "package":{"name":"ru.voboost","versionCode":descriptor.apk_version_code()?,"apkSize":apk.size,"apkSha256":apk.sha256,"certificateSha256":descriptor.apk_certificate_sha256()?},"appOp":{"package":"ru.voboost","operation":"REQUEST_INSTALL_PACKAGES","installedMode":"allow"}}))?;
    let policy_stat = fs::metadata(POLICY).map_err(|e| e.to_string())?;
    let sidecars = crate::mount_policy_transaction::parse_sidecar_backup(&crate::read_bounded(
        &recovery.join("policy-sidecars.json"),
        16 * 1024,
        0o600,
    )?)?;
    let metadata = canonical(
        serde_json::json!({"schemaVersion":2,"path":POLICY,"size":pristine.len(),"sha256":digest(&pristine),"uid":policy_stat.uid(),"gid":policy_stat.gid(),"mode":format!("{:04o}",policy_stat.permissions().mode()&0o7777),"context":context(Path::new(POLICY))?,"sidecars":sidecars}),
    )?;
    let baseline = canonical(
        serde_json::json!({"schemaVersion":1,"policySha256":digest(&pristine),"backupPath":baseline_path,"metadataPath":POLICY_META}),
    )?;
    let state = canonical(serde_json::json!({"schemaVersion":1,
        "rootPriorState":fresh_state.root_prior_state,
        "initPriorState":fresh_state.init_prior_state,
        "initInstalledSha256":digest(&rc),"policyPriorSha256":digest(&pristine),
        "policyInstalledSha256":digest(&patched),
        "packagePriorState":fresh_state.package_prior_state,
        "packageVersionCode":descriptor.apk_version_code()?,
        "appOpPriorMode":fresh_state.app_op_prior_mode,"appOpInstalledMode":"allow"}))?;
    let documents = [
        (ARTIFACTS, &artifacts),
        (BASELINE, &baseline),
        (POLICY_META, &metadata),
        (SYSTEM_STATE, &state),
        (INIT_ARCHIVE, &rc),
    ];
    for (path, bytes) in &documents[..4] {
        write_protected(Path::new(path), bytes, 0o600)?;
    }
    let claims=documents.iter().map(|(path,bytes)|serde_json::json!({"path":path,"size":bytes.len(),"sha256":digest(bytes)})).collect::<Vec<_>>();
    let committed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        .to_string();
    let inventory = canonical(
        serde_json::json!({"schemaVersion":1,"phase":"committed","version":descriptor.release_identity,"committedAt":committed,"documents":claims}),
    )?;
    let root = voboost_shared::secure_fs::Directory::open(Path::new(ROOT))
        .map_err(|error| error.to_string())?;
    let install = voboost_shared::installed_state::prepare_canonical(&root)
        .map_err(|error| error.to_string())?;
    install
        .write_atomic(
            voboost_contract::domain_core::install_layout::STATE,
            &inventory,
            0o600,
        )
        .map_err(|error| error.to_string())?;
    verify_committed()
}

pub fn verify_committed() -> Result<(), String> {
    let read =
        |path: &str| crate::read_bounded(Path::new(path), MAX_INVENTORY_DOCUMENT_BYTES, 0o600);
    let inventory_path = voboost_shared::installed_state::path(Path::new(ROOT))
        .map_err(|error| error.to_string())?;
    let inventory = crate::read_bounded(&inventory_path, MAX_INVENTORY_DOCUMENT_BYTES, 0o600)?;
    let expected_inventory_context = if inventory_path.ends_with("install/state.json") {
        voboost_shared::uninstall_label_contract::INSTALLED_STATE_CONTEXT
    } else {
        crate::selinux_backend::INVENTORY_CONTEXT
    };
    if context(&inventory_path)? != expected_inventory_context {
        return Err("committed installed state label differs".into());
    }
    let artifacts = read(ARTIFACTS)?;
    let baseline = read(BASELINE)?;
    let metadata = read(POLICY_META)?;
    let state = read(SYSTEM_STATE)?;
    let rc = read(INIT_ARCHIVE)?;
    uninstall_contract::parse_committed_contract(
        &inventory, &artifacts, &baseline, &metadata, &state, &rc,
    )?;
    for path in [ARTIFACTS, BASELINE, POLICY_META, SYSTEM_STATE, INIT_ARCHIVE] {
        if context(Path::new(path))? != crate::selinux_backend::INVENTORY_CONTEXT {
            return Err(format!("committed inventory label differs: {path}"));
        }
    }
    Ok(())
}

pub fn verify_committed_at(root: &Path) -> Result<(), String> {
    let uninstall = root.join("uninstall");
    let read =
        |name| crate::read_bounded(&uninstall.join(name), MAX_INVENTORY_DOCUMENT_BYTES, 0o600);
    uninstall_contract::parse_committed_contract(
        &voboost_shared::installed_state::read(
            &voboost_shared::secure_fs::Directory::open(root).map_err(|error| error.to_string())?,
            MAX_INVENTORY_DOCUMENT_BYTES,
        )
        .map_err(|error| error.to_string())?,
        &read("system-artifacts.json")?,
        &read("current-baseline.json")?,
        &read("policy.meta.json")?,
        &read("system-state.json")?,
        &read("system/voboost.rc")?,
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_payload_records_both_combined_implants_without_lsplant_files() {
        let descriptor = InstallDescriptor::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let payload = runtime_payload(&descriptor).unwrap();
        assert_eq!(payload.len(), 2);
        assert_eq!(payload[0]["abi"], "arm64-v8a");
        assert_eq!(payload[1]["abi"], "armeabi-v7a");
        for item in payload {
            assert_eq!(item["component"], "implant");
            assert_eq!(item["signatureRole"], "runtime");
        }
        for name in ["libimplant-arm64-v8a.so", "libimplant-armeabi-v7a.so"] {
            let mut missing = descriptor.clone();
            missing.artifacts.retain(|item| item.file != name);
            assert!(runtime_payload(&missing).unwrap_err().contains(name));
        }
    }
}
