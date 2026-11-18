use std::{env, fs, path::PathBuf};

#[path = "../build_support/strict_ed25519_spki.rs"]
mod build_key;
#[path = "../build_support/host_role_keys.rs"]
mod host_role_keys;

fn main() {
    let android = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "android";
    host_role_keys::assert_distinct();
    let read = |name: &str, host: [u8; 32]| {
        println!("cargo:rerun-if-env-changed={name}");
        let path = if android {
            PathBuf::from(
                env::var(name).unwrap_or_else(|_| panic!("Android build requires {name}")),
            )
        } else {
            return host;
        };
        println!("cargo:rerun-if-changed={}", path.display());
        build_key::extract_ed25519_pubkey_from_pem(&fs::read(path).expect("read public key"))
            .expect("parse Ed25519 public key")
    };
    let executable = read(
        "VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM",
        host_role_keys::NATIVE_EXECUTABLE,
    );
    let authorization = read("VOBOOST_RESTORE_PUBLIC_KEY_PEM", host_role_keys::RESTORE);
    let release_catalog = read(
        "VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM",
        host_role_keys::RELEASE_CATALOG,
    );
    let agent_catalog = read(
        "VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM",
        host_role_keys::AGENT_CATALOG,
    );
    let roles = [agent_catalog, release_catalog, executable, authorization];
    for (index, role) in roles.iter().enumerate() {
        assert!(
            !roles[..index].contains(role),
            "product role keys must be distinct"
        );
    }
    let source = format!(
        "pub static NATIVE_EXECUTABLE_PUBKEY: [u8; 32] = {executable:?};\n\
         pub static RESTORE_PUBLIC_KEY: [u8; 32] = {authorization:?};\n\
         pub static RELEASE_CATALOG_PUBLIC_KEY: [u8; 32] = {release_catalog:?};\n\
         pub static AGENT_CATALOG_PUBLIC_KEY: [u8; 32] = {agent_catalog:?};\n"
    );
    fs::write(
        PathBuf::from(env::var("OUT_DIR").unwrap()).join("embedded_keys.rs"),
        source,
    )
    .expect("write embedded restore keys");
}
