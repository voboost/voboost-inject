use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("daemon crate must be inside the workspace")
        .to_path_buf()
}

#[test]
fn first_party_crates_use_the_workspace_mit_license() {
    let root = workspace_root();
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(&root)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("valid cargo metadata JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata packages array");

    let package_names = packages
        .iter()
        .map(|package| package["name"].as_str().expect("package name"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        package_names,
        BTreeSet::from([
            "voboost-cluster-native",
            "voboost-contract",
            "voboost-contract-core",
            "voboost-daemon",
            "voboost-install",
            "voboost-qconn",
            "voboost-restore",
            "voboost-shared",
            "voboost-uninstall",
        ]),
        "closed first-party workspace inventory differs"
    );
    for package in packages {
        let name = package["name"].as_str().expect("package name");
        assert_eq!(
            package["license"].as_str(),
            Some("MIT"),
            "{name} must declare SPDX MIT"
        );
        assert!(
            package["license_file"].is_null(),
            "{name} must not retain the former custom license-file declaration"
        );
    }
}
