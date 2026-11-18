//! One product artifact-to-installed-authority mapping.

use std::path::Path;
use std::time::{Duration, Instant};

#[cfg(target_os = "android")]
use std::ffi::CString;
#[cfg(target_os = "android")]
use std::fs::File;
#[cfg(target_os = "android")]
use std::os::fd::FromRawFd;

use voboost_contract::release::{Artifact, ArtifactRole, Manifest};

use crate::{config, secure_fs::Directory, trust};

use voboost_shared::uninstall_contract;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstalledAuthority {
    RootFlat { mode: u32 },
    InstalledApk,
    ActiveGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductIdentity {
    pub(crate) release_identity: String,
    pub(crate) manifest_sha256: String,
}

pub(crate) fn load_identity() -> Result<ProductIdentity, String> {
    let manifest = load_manifest()?;
    Ok(ProductIdentity {
        release_identity: manifest.release_identity.clone(),
        manifest_sha256: manifest.digest()?,
    })
}

pub(crate) fn authority(artifact: &Artifact) -> InstalledAuthority {
    match artifact.role {
        ArtifactRole::App => InstalledAuthority::InstalledApk,
        ArtifactRole::QnxRuntime
        | ArtifactRole::QnxAgentModule
        | ArtifactRole::AgentCatalog
        | ArtifactRole::AgentCatalogSignature
        | ArtifactRole::AgentCommon
        | ArtifactRole::AgentModule
        | ArtifactRole::ResourceApk
        | ArtifactRole::ResourceLedger
        | ArtifactRole::QnxResourcePack
        | ArtifactRole::QnxResourceLedger => InstalledAuthority::ActiveGeneration,
        ArtifactRole::QnxDaemon
        | ArtifactRole::QnxInit
        | ArtifactRole::Daemon
        | ArtifactRole::Inject
        | ArtifactRole::Install
        | ArtifactRole::Restore
        | ArtifactRole::Uninstall
        | ArtifactRole::Selinux => InstalledAuthority::RootFlat { mode: 0o700 },
        ArtifactRole::Init => InstalledAuthority::RootFlat { mode: 0o644 },
        ArtifactRole::QnxImplant
        | ArtifactRole::RestoreAuthorization
        | ArtifactRole::RestoreSignature
        | ArtifactRole::Implant
        | ArtifactRole::Lsplant => InstalledAuthority::RootFlat { mode: 0o644 },
    }
}

pub(crate) fn load_manifest() -> Result<Manifest, String> {
    load_manifest_in(Path::new(config::ROOT_ZONE))
}

pub(crate) fn load_manifest_in(root_path: &Path) -> Result<Manifest, String> {
    let root =
        Directory::open(root_path).map_err(|error| format!("open active product root: {error}"))?;
    let bytes = root
        .read_trusted(
            voboost_contract::release::MANIFEST_NAME,
            voboost_contract::release::MAX_MANIFEST_BYTES,
            0o600,
        )
        .map_err(|error| format!("read active product manifest: {error}"))?;
    let signature = root
        .read_trusted(
            voboost_contract::release::MANIFEST_SIGNATURE_NAME,
            64,
            0o600,
        )
        .map_err(|error| format!("read active product signature: {error}"))?;
    voboost_contract::release::verify_manifest_signature(
        &bytes,
        &signature,
        &trust::release_catalog_public_key(),
    )
}

pub(crate) fn verify_runtime_for_abi(manifest: &Manifest, abi: &str) -> Result<(), String> {
    verify_runtime_for_abi_in(manifest, abi, Path::new(config::ROOT_ZONE))
}

fn verify_runtime_for_abi_in(manifest: &Manifest, abi: &str, root: &Path) -> Result<(), String> {
    let root =
        Directory::open(root).map_err(|error| format!("open installed product root: {error}"))?;
    let suffix = match abi {
        "arm64-v8a" => "arm64-v8a",
        "armeabi-v7a" => "armeabi-v7a",
        _ => return Err(format!("unsupported runtime ABI {abi}")),
    };
    verify_root_flat(
        &root,
        manifest.artifact(&format!("libimplant-{suffix}.so"))?,
    )?;
    Ok(())
}

pub(crate) fn verify_native_closure_until(
    manifest: &Manifest,
    deadline: Instant,
) -> Result<(), String> {
    check_deadline(deadline)?;
    let root = Directory::open(Path::new(config::ROOT_ZONE))
        .map_err(|error| format!("open installed product root: {error}"))?;
    for artifact in &manifest.artifacts {
        check_deadline(deadline)?;
        if matches!(authority(artifact), InstalledAuthority::RootFlat { .. }) {
            verify_root_flat_until(&root, artifact, deadline)?;
        }
    }
    check_deadline(deadline)
}

fn check_deadline(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        Err("installed product observation deadline".into())
    } else {
        Ok(())
    }
}

pub(crate) fn verify_candidate_closure_in(
    manifest: &Manifest,
    require_active_manifest: bool,
    root_path: &Path,
) -> Result<(), String> {
    if require_active_manifest {
        let active = load_manifest_in(root_path)?;
        if active.digest()? != manifest.digest()?
            || active.release_identity != manifest.release_identity
        {
            return Err("active product manifest differs from candidate".into());
        }
    }
    let root = Directory::open(root_path)
        .map_err(|error| format!("open installed product root: {error}"))?;
    let generation = crate::generation::GenerationStore::new(
        root_path,
        root_path
            .join(crate::generation::GENERATIONS_DIR)
            .join(crate::generation::NEXT_DIR),
    )
    .active()
    .map_err(|error| error.to_string())?;
    for artifact in &manifest.artifacts {
        match authority(artifact) {
            InstalledAuthority::RootFlat { .. } => verify_root_flat(&root, artifact)?,
            InstalledAuthority::ActiveGeneration => {
                let installed = generation
                    .files
                    .iter()
                    .find(|file| file.file == artifact.file)
                    .ok_or_else(|| format!("active generation lacks {}", artifact.file))?;
                if installed.size != artifact.size || installed.sha256 != artifact.sha256 {
                    return Err(format!(
                        "active generation identity differs for {}",
                        artifact.file
                    ));
                }
                generation
                    .read_file_exact(&artifact.file)
                    .map_err(|error| error.to_string())?;
            }
            InstalledAuthority::InstalledApk => {
                verify_installed_apk_identity_in(artifact, root_path)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn installed_apk_matches_in(artifact: &Artifact, root_path: &Path) -> bool {
    verify_installed_apk_identity_in(artifact, root_path).is_ok()
}

fn verify_installed_apk_identity_in(artifact: &Artifact, root_path: &Path) -> Result<(), String> {
    verify_installed_apk_identity_until(
        artifact,
        root_path,
        Instant::now() + Duration::from_secs(15),
    )
    .map(|_| ())
}

pub(crate) fn verify_installed_apk_identity_until(
    artifact: &Artifact,
    root_path: &Path,
    deadline: Instant,
) -> Result<(String, std::fs::Metadata), String> {
    if Instant::now() >= deadline {
        return Err("installed APK observation deadline".into());
    }
    if artifact.role != ArtifactRole::App {
        return Err("installed APK observation requires the app artifact".into());
    }
    let expected_version = artifact
        .version_code
        .ok_or_else(|| "candidate APK versionCode is absent".to_string())?;
    let expected_certificate = artifact
        .certificate_sha256
        .as_deref()
        .ok_or_else(|| "candidate APK certificate is absent".to_string())?;
    #[cfg(target_os = "android")]
    {
        let _ = root_path;
        let path = crate::installed_apk::observe_installed_apk_until(
            artifact.size,
            &artifact.sha256,
            deadline,
        )?;
        let path_c = CString::new(path.as_str()).map_err(|_| "installed APK path contains NUL")?;
        let fd = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open installed APK signer authority: {}",
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let before =
            voboost_contract::apk::FileStamp::read(&file).map_err(|error| error.to_string())?;
        let signer = voboost_contract::apk::signer_sha256_v2_v3_until(&file, before, deadline)
            .map_err(|error| error.to_string())?;
        let after =
            voboost_contract::apk::FileStamp::read(&file).map_err(|error| error.to_string())?;
        if before != after || hex::encode(signer) != expected_certificate {
            return Err("installed APK signer identity differs".into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("installed APK observation deadline".into());
        }
        let output = crate::fixed_process::output(
            "/system/bin/dumpsys",
            &["package", "ru.voboost"],
            remaining.min(Duration::from_secs(2)),
            1024 * 1024,
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err("installed APK version query failed".into());
        }
        if parse_package_version_code(&output.stdout)? != expected_version {
            return Err("installed APK versionCode differs".into());
        }
        if crate::installed_apk::observe_installed_apk_until(
            artifact.size,
            &artifact.sha256,
            deadline,
        )? != path
        {
            return Err("installed APK path changed while observing identity".into());
        }
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        let final_stamp =
            voboost_contract::apk::FileStamp::read(&file).map_err(|error| error.to_string())?;
        let reopened = File::open(&path).map_err(|error| error.to_string())?;
        if final_stamp != before
            || voboost_contract::apk::FileStamp::read(&reopened)
                .map_err(|error| error.to_string())?
                != before
        {
            return Err("installed APK file changed while observing identity".into());
        }
        return Ok((path, metadata));
    }
    #[cfg(not(target_os = "android"))]
    {
        let root = Directory::open(root_path).map_err(|error| error.to_string())?;
        root.verify_trusted_digest(
            "voboost-app.apk.host-observed",
            artifact.size,
            &artifact.sha256,
            0o600,
        )
        .map_err(|error| error.to_string())?;
        let bytes = root
            .read_trusted("voboost-app.apk.host-observed.json", 1024, 0o600)
            .map_err(|error| error.to_string())?;
        let observation: HostApkObservation = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse host APK observation: {error}"))?;
        let mut canonical = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
        canonical.push(b'\n');
        if canonical != bytes
            || observation.path != "/data/app/ru.voboost/base.apk"
            || observation.version_code != expected_version
            || observation.certificate_sha256 != expected_certificate
        {
            return Err("host APK observation differs".into());
        }
        let path = root_path.join("voboost-app.apk.host-observed");
        Ok((
            path.to_string_lossy().into_owned(),
            std::fs::metadata(path).map_err(|error| error.to_string())?,
        ))
    }
}

#[cfg(any(target_os = "android", test))]
use voboost_shared::installed_apk::parse_package_version_code;

// The runtime observation reader exists only on host builds (Android verifies
// the installed APK through its own authority above); the struct stays
// available to the unified test module so host-observation fixtures compile
// for the android test target too.
#[cfg(any(not(target_os = "android"), test))]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HostApkObservation {
    pub(crate) path: String,
    pub(crate) version_code: u64,
    pub(crate) certificate_sha256: String,
}

pub(crate) fn installed_package_authority_in(
    root_path: &Path,
) -> Result<uninstall_contract::PackageArtifact, String> {
    let root = Directory::open(root_path).map_err(|error| error.to_string())?;
    let uninstall = root
        .open_child("uninstall")
        .map_err(|error| error.to_string())?;
    let read = |name: &str, maximum| {
        uninstall
            .read_trusted(name, maximum, 0o600)
            .map_err(|error| error.to_string())
    };
    let inventory = voboost_shared::installed_state::read(&root, 64 * 1024)
        .map_err(|error| error.to_string())?;
    let artifacts = read("system-artifacts.json", 1024 * 1024)?;
    let baseline = read("current-baseline.json", 1024 * 1024)?;
    let policy = read("policy.meta.json", 1024 * 1024)?;
    let state = read("system-state.json", 1024 * 1024)?;
    let system = uninstall
        .open_child("system")
        .map_err(|error| error.to_string())?;
    let rc = system
        .read_trusted("voboost.rc", 1024 * 1024, 0o600)
        .map_err(|error| error.to_string())?;
    Ok(uninstall_contract::parse_committed_contract(
        &inventory, &artifacts, &baseline, &policy, &state, &rc,
    )?
    .artifacts
    .package)
}

fn verify_root_flat(root: &Directory, artifact: &Artifact) -> Result<(), String> {
    verify_root_flat_until(root, artifact, Instant::now() + Duration::from_secs(15))
}

fn verify_root_flat_until(
    root: &Directory,
    artifact: &Artifact,
    deadline: Instant,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    check_deadline(deadline)?;
    let InstalledAuthority::RootFlat { mode } = authority(artifact) else {
        return Err(format!("{} is not a root-flat artifact", artifact.file));
    };
    let mut file = root
        .open_trusted_file(&artifact.file, artifact.size, mode)
        .map_err(|error| format!("read installed {}: {error}", artifact.file))?;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let before = file.metadata().map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        check_deadline(deadline)?;
        let read = file.read(&mut chunk).map_err(|error| error.to_string())?;
        check_deadline(deadline)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or("native artifact size overflow")?;
        if total > artifact.size {
            return Err("native artifact exceeds declared size".into());
        }
        digest.update(&chunk[..read]);
    }
    if stamp(&before) != stamp(&file.metadata().map_err(|error| error.to_string())?)
        || total != artifact.size
        || hex::encode(digest.finalize()) != artifact.sha256
    {
        return Err(format!("installed {} identity differs", artifact.file));
    }
    check_deadline(deadline)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_closure_rejects_an_expired_deadline_before_opening_payloads() {
        let manifest = Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        assert_eq!(
            verify_native_closure_until(&manifest, Instant::now()).unwrap_err(),
            "installed product observation deadline"
        );
    }
    use sha2::{Digest, Sha256};
    use std::fs::{self, hard_link};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use voboost_contract::release::{Abi, Activation, ArtifactRole};

    fn artifact(file: &str) -> Artifact {
        let (role, activation, abi) = voboost_contract::release::classify(file).unwrap();
        Artifact {
            role,
            file: file.to_string(),
            size: 1,
            sha256: "a".repeat(64),
            activation,
            package_name: (role == ArtifactRole::App).then(|| "ru.voboost".to_string()),
            version_code: (role == ArtifactRole::App).then_some(1),
            certificate_sha256: (role == ArtifactRole::App).then(|| "b".repeat(64)),
            abi,
            resource: None,
        }
    }

    #[test]
    fn every_product_role_has_one_flat_apk_or_generation_authority() {
        for (file, expected) in [
            ("voboost-app.apk", InstalledAuthority::InstalledApk),
            (
                "voboost-daemon",
                InstalledAuthority::RootFlat { mode: 0o700 },
            ),
            (
                "voboost-inject",
                InstalledAuthority::RootFlat { mode: 0o700 },
            ),
            ("voboost.rc", InstalledAuthority::RootFlat { mode: 0o644 }),
            ("restore.json", InstalledAuthority::RootFlat { mode: 0o644 }),
            (
                "libimplant-arm64-v8a.so",
                InstalledAuthority::RootFlat { mode: 0o644 },
            ),
            ("agents.json", InstalledAuthority::ActiveGeneration),
            ("agent-common.dex", InstalledAuthority::ActiveGeneration),
            ("agent-settings.dex", InstalledAuthority::ActiveGeneration),
            (
                "resource-i18n-ru-setting-a9.apk",
                InstalledAuthority::ActiveGeneration,
            ),
            (
                "resource-i18n-ru-setting-a9.json",
                InstalledAuthority::ActiveGeneration,
            ),
        ] {
            assert_eq!(authority(&artifact(file)), expected, "{file}");
        }
    }

    #[test]
    fn active_product_loader_rejects_sparse_oversize_and_links_before_parse() {
        use std::fs::OpenOptions;

        let directory = tempfile::tempdir().unwrap();
        let manifest = directory
            .path()
            .join(voboost_contract::release::MANIFEST_NAME);
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&manifest)
            .unwrap();
        file.set_len(voboost_contract::release::MAX_MANIFEST_BYTES as u64 + 1)
            .unwrap();
        fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            directory
                .path()
                .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
            [0u8; 64],
        )
        .unwrap();
        fs::set_permissions(
            directory
                .path()
                .join(voboost_contract::release::MANIFEST_SIGNATURE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(load_manifest_in(directory.path()).is_err());

        fs::remove_file(&manifest).unwrap();
        let victim = directory.path().join("victim");
        fs::write(&victim, b"{}").unwrap();
        symlink(&victim, &manifest).unwrap();
        assert!(load_manifest_in(directory.path()).is_err());
    }

    #[test]
    fn package_dump_version_code_is_unique_positive_and_exact() {
        assert_eq!(
            parse_package_version_code(b"Packages:\n  versionCode=42 minSdk=28\n").unwrap(),
            42
        );
        for hostile in [
            b"versionCode=0\n".as_slice(),
            b"versionCode=-1\n".as_slice(),
            b"versionCode=1x\n".as_slice(),
            b"versionCode=1\nversionCode=2\n".as_slice(),
            b"no version\n".as_slice(),
            b"versionCode=1\xff\n".as_slice(),
        ] {
            assert!(parse_package_version_code(hostile).is_err());
        }
    }

    #[test]
    fn runtime_uses_exact_flat_abi_qualified_basenames() {
        let manifest = Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        for abi in [Abi::Arm64V8a, Abi::ArmeabiV7a] {
            let suffix = match abi {
                Abi::Arm64V8a => "arm64-v8a",
                Abi::ArmeabiV7a => "armeabi-v7a",
                Abi::QnxAarch64 => panic!("Android runtime fixture cannot select QNX"),
            };
            let item = manifest
                .artifact(&format!("libimplant-{suffix}.so"))
                .unwrap();
            assert_eq!(item.activation, Activation::NativeRuntime);
            assert_eq!(item.abi, Some(abi));
            assert_eq!(
                authority(item),
                InstalledAuthority::RootFlat { mode: 0o644 }
            );
        }
        assert!(manifest
            .artifact("payload/arm64-v8a/libimplant.so")
            .is_err());
    }

    #[test]
    fn runtime_rejects_missing_mode_hash_symlink_hardlink_and_abi_substitution() {
        let mut manifest = Manifest::parse(include_bytes!(
            "../../test/fixtures/product-release/voboost/valid/minimal.json"
        ))
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let implant = b"arm64-implant";
        {
            let (name, bytes) = ("libimplant-arm64-v8a.so", implant.as_slice());
            let artifact = manifest
                .artifacts
                .iter_mut()
                .find(|v| v.file == name)
                .unwrap();
            artifact.size = bytes.len() as u64;
            artifact.sha256 = hex::encode(Sha256::digest(bytes));
            fs::write(root.path().join(name), bytes).unwrap();
            fs::set_permissions(root.path().join(name), fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(verify_runtime_for_abi_in(&manifest, "arm64-v8a", root.path()).is_ok());

        let implant_path = root.path().join("libimplant-arm64-v8a.so");
        fs::set_permissions(&implant_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify_runtime_for_abi_in(&manifest, "arm64-v8a", root.path()).is_err());
        fs::set_permissions(&implant_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&implant_path, b"wrong-identity").unwrap();
        assert!(verify_runtime_for_abi_in(&manifest, "arm64-v8a", root.path()).is_err());
        fs::remove_file(&implant_path).unwrap();
        let unrelated = root.path().join("unrelated.so");
        fs::write(&unrelated, implant).unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o644)).unwrap();
        symlink("unrelated.so", &implant_path).unwrap();
        assert!(verify_runtime_for_abi_in(&manifest, "arm64-v8a", root.path()).is_err());
        fs::remove_file(&implant_path).unwrap();
        hard_link(&unrelated, &implant_path).unwrap();
        assert!(verify_runtime_for_abi_in(&manifest, "arm64-v8a", root.path()).is_err());
        fs::remove_file(&implant_path).unwrap();
        assert!(verify_runtime_for_abi_in(&manifest, "arm64-v8a", root.path()).is_err());
        assert!(verify_runtime_for_abi_in(&manifest, "arm64", root.path()).is_err());
    }

    #[test]
    fn runtime_and_active_status_use_product_authority_not_component_manifest() {
        let runtime = include_str!("runtime.rs");
        assert!(runtime.contains("installed_product::load_manifest()"));
        assert!(runtime.contains("installed_product::verify_runtime_for_abi"));
        assert!(!runtime.contains("ReleaseManifest::load()"));
        assert!(!runtime.contains("verify_payload_for_abi"));

        let transport = include_str!("ota_transport.rs");
        let active = transport
            .split("fn load_active_release()")
            .nth(1)
            .unwrap()
            .split("fn invalid(")
            .next()
            .unwrap();
        assert!(active.contains("installed_product::load_manifest()"));
        assert!(active.contains("installed_product::verify_native_closure"));
        assert!(!active.contains("voboost-inject.json"));
    }
}
