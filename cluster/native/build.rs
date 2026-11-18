use std::{env, fs, path::PathBuf};
#[path = "../../build_support/host_role_keys.rs"]
mod fixtures;
#[path = "../../build_support/strict_ed25519_spki.rs"]
mod spki;
fn main() {
    fixtures::assert_distinct();
    let target = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let roles = [
        "AGENT_CATALOG",
        "RELEASE_CATALOG",
        "NATIVE_EXECUTABLE",
        "RESTORE",
    ];
    let host = [
        fixtures::AGENT_CATALOG,
        fixtures::RELEASE_CATALOG,
        fixtures::NATIVE_EXECUTABLE,
        fixtures::RESTORE,
    ];
    let mut keys = Vec::new();
    for (index, role) in roles.iter().enumerate() {
        let variable = format!("VOBOOST_{role}_PUBLIC_KEY_PEM");
        println!("cargo:rerun-if-env-changed={variable}");
        let key = if target == "nto" {
            let path = env::var(&variable)
                .unwrap_or_else(|_| panic!("QNX production build requires {variable}"));
            println!("cargo:rerun-if-changed={path}");
            spki::extract_ed25519_pubkey_from_pem(
                &fs::read(path).expect("public role root unreadable"),
            )
            .expect("invalid explicit public root")
        } else {
            host[index]
        };
        assert!(!keys.contains(&key), "product role roots must differ");
        keys.push(key);
    }
    let mut source = String::new();
    for (role, key) in roles.iter().zip(keys) {
        source.push_str(&format!("pub const {role}: [u8;32] = {key:?};\n"));
    }
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("roots.rs"),
        source,
    )
    .unwrap();
}
