use sha2::{Digest, Sha256};
use std::fs;
use voboost_contract::install::StagingDescriptor;
use voboost_contract::release::{
    Abi, Activation, Artifact, ArtifactRole, Compatibility, Manifest, RestoreDocument,
};

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = &args[1];
    let release_identity = "1.0.0-beta1";

    // Build the manifest in canonical role/name order.
    let mut artifacts: Vec<Artifact> = Vec::new();

    // app
    let apk = fs::read(format!("{dir}/voboost-app.apk")).unwrap();
    artifacts.push(Artifact {
        role: ArtifactRole::App,
        file: "voboost-app.apk".into(),
        size: apk.len() as u64,
        sha256: sha256_bytes(&apk),
        activation: Activation::PackageInstaller,
        package_name: Some("ru.voboost".into()),
        version_code: Some(1000006),
        certificate_sha256: Some(
            "58656561bf0ef123899a66e821f7a01367a0e02829969389d2a355bad4851c7d".into(),
        ),
        abi: None,
        resource: None,
    });

    // Signed native executables.
    for (role, file, activation) in [
        (
            ArtifactRole::Daemon,
            "voboost-daemon",
            Activation::NativeRuntime,
        ),
        (
            ArtifactRole::Inject,
            "voboost-inject",
            Activation::NativeRuntime,
        ),
        (
            ArtifactRole::Install,
            "voboost-install",
            Activation::NativeRuntime,
        ),
        (
            ArtifactRole::Restore,
            "voboost-restore",
            Activation::RestoreAuthority,
        ),
        (
            ArtifactRole::Uninstall,
            "voboost-uninstall",
            Activation::RestoreAuthority,
        ),
        (
            ArtifactRole::Selinux,
            "voboost-selinux",
            Activation::NativeRuntime,
        ),
    ] {
        let bytes = fs::read(format!("{dir}/{file}")).unwrap();
        artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            activation,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: None,
            resource: None,
        });
    }

    // init
    let rc = fs::read(format!("{dir}/voboost.rc")).unwrap();
    artifacts.push(Artifact {
        role: ArtifactRole::Init,
        file: "voboost.rc".into(),
        size: rc.len() as u64,
        sha256: sha256_bytes(&rc),
        activation: Activation::Init,
        package_name: None,
        version_code: None,
        certificate_sha256: None,
        abi: None,
        resource: None,
    });

    // restore.json + sig (restore-authorization, restore-signature)
    for (role, file) in [
        (ArtifactRole::RestoreAuthorization, "restore.json"),
        (ArtifactRole::RestoreSignature, "restore.json.sig"),
    ] {
        let bytes = fs::read(format!("{dir}/{file}")).unwrap();
        artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            activation: Activation::RestoreAuthority,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: None,
            resource: None,
        });
    }

    // One combined implant per ABI.
    for (role, file, abi) in [
        (
            ArtifactRole::Implant,
            "libimplant-arm64-v8a.so",
            Abi::Arm64V8a,
        ),
        (
            ArtifactRole::Implant,
            "libimplant-armeabi-v7a.so",
            Abi::ArmeabiV7a,
        ),
    ] {
        let bytes = fs::read(format!("{dir}/{file}")).unwrap();
        artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            activation: Activation::NativeRuntime,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: Some(abi),
            resource: None,
        });
    }

    // agent-catalog + sig
    for (role, file) in [
        (ArtifactRole::AgentCatalog, "agents.json"),
        (ArtifactRole::AgentCatalogSignature, "agents.json.sig"),
    ] {
        let bytes = fs::read(format!("{dir}/{file}")).unwrap();
        artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            activation: Activation::AgentGeneration,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: None,
            resource: None,
        });
    }

    // agent-common + agent-modules
    for (role, file) in [
        (ArtifactRole::AgentCommon, "agent-common.dex"),
        (ArtifactRole::AgentModule, "agent-settings.dex"),
        (
            ArtifactRole::AgentModule,
            "agent-ui-qinggan-com-qinggan-app-setting.dex",
        ),
        (
            ArtifactRole::AgentModule,
            "agent-ui-qinggan-com-qinggan-app-vehiclesetting.dex",
        ),
    ] {
        let bytes = fs::read(format!("{dir}/{file}")).unwrap();
        artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            activation: Activation::AgentGeneration,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi: None,
            resource: None,
        });
    }

    for file in [
        "voboost-cluster-daemon",
        "voboost-cluster-startup.sh",
        "libvoboost-cluster-inject.so",
        "libvoboost-runtime-cluster.so",
        "libagent-font-cyrillic.so",
    ] {
        let bytes = fs::read(format!("{dir}/{file}")).unwrap();
        let (role, activation, abi) = voboost_contract::release::classify(file).unwrap();
        artifacts.push(Artifact {
            role,
            file: file.into(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
            activation,
            package_name: None,
            version_code: None,
            certificate_sha256: None,
            abi,
            resource: None,
        });
    }
    let manifest = Manifest {
        schema_version: 1,
        release_identity: release_identity.into(),
        compatibility: Compatibility {
            installer_protocol: 1,
            operation_protocol: 1,
            app_daemon_protocol: 1,
            agent_catalog_schema: 2,
            agent_entry_abi: 1,
            implant_abi: 1,
        },
        artifacts,
    };

    // Validate and serialize canonically.
    manifest.validate().unwrap();
    let canonical = manifest.canonical_bytes().unwrap();
    let manifest_sha256 = manifest.digest().unwrap();
    fs::write(format!("{dir}/voboost.json"), &canonical).unwrap();
    println!(
        "wrote voboost.json ({} bytes), digest={manifest_sha256}",
        canonical.len()
    );

    // restore.json. sourceDefinitionSha256 is the sha256 of the manifest's
    // canonical bytes with the restore/recovery artifacts removed (a stable
    // "source definition" that does not depend on restore.json itself).
    let source_artifacts: Vec<&Artifact> = manifest
        .artifacts
        .iter()
        .filter(|artifact| {
            !matches!(
                artifact.role,
                ArtifactRole::RestoreAuthorization | ArtifactRole::RestoreSignature
            )
        })
        .collect();
    let source_definition_sha256 = sha256_bytes(&serde_json::to_vec(&source_artifacts).unwrap());
    let restorable_closure_sha256 =
        voboost_contract::release::restorable_closure_sha256(&manifest).unwrap();
    let restore = RestoreDocument {
        schema_version: 1,
        release_identity: release_identity.into(),
        source_definition_sha256,
        restorable_closure_sha256,
    };
    let mut restore_canonical = serde_json::to_vec(&restore).unwrap();
    restore_canonical.push(b'\n');
    fs::write(format!("{dir}/restore.json"), &restore_canonical).unwrap();
    println!(
        "wrote restore.json, sourceDefinitionSha256={}, restorableClosureSha256={}",
        restore.source_definition_sha256, restore.restorable_closure_sha256
    );

    // staging.json
    let transaction_id =
        sha256_bytes(format!("voboost-offline-update-v1:{manifest_sha256}").as_bytes());
    let staging = StagingDescriptor {
        schema_version: 1,
        transaction_id: transaction_id.clone(),
        release_identity: release_identity.into(),
        manifest_sha256: manifest_sha256.clone(),
        emulator_acceptance: None,
    };
    let staging_bytes = staging.canonical_bytes().unwrap();
    fs::write(format!("{dir}/staging.json"), &staging_bytes).unwrap();
    println!(
        "wrote staging.json, transactionId={transaction_id}, manifestSha256={manifest_sha256}"
    );
}
