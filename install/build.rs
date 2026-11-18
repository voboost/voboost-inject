use anyhow::{Context, Result};
use std::{env, fs, path::Path};

#[path = "../build_support/host_role_keys.rs"]
mod host_role_keys;
#[path = "../build_support/strict_ed25519_spki.rs"]
mod strict_ed25519_spki;

fn key(environment: &str, host: [u8; 32]) -> Result<[u8; 32]> {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return Ok(host);
    }
    let path = env::var(environment).with_context(|| format!("{environment} is required"))?;
    let bytes = fs::read(Path::new(&path)).with_context(|| format!("read {environment}"))?;
    strict_ed25519_spki::extract_ed25519_pubkey_from_pem(&bytes).map_err(anyhow::Error::msg)
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed=VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM");
    println!("cargo:rerun-if-env-changed=VOBOOST_RESTORE_PUBLIC_KEY_PEM");
    for name in [
        "VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM",
        "VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    host_role_keys::assert_distinct();
    let executable = key(
        "VOBOOST_NATIVE_EXECUTABLE_PUBLIC_KEY_PEM",
        host_role_keys::NATIVE_EXECUTABLE,
    )?;
    let authorization = key("VOBOOST_RESTORE_PUBLIC_KEY_PEM", host_role_keys::RESTORE)?;
    let release_catalog = key(
        "VOBOOST_RELEASE_CATALOG_PUBLIC_KEY_PEM",
        host_role_keys::RELEASE_CATALOG,
    )?;
    let agent_catalog = key(
        "VOBOOST_AGENT_CATALOG_PUBLIC_KEY_PEM",
        host_role_keys::AGENT_CATALOG,
    )?;
    let output = format!(
        "pub static NATIVE_EXECUTABLE_PUBLIC_KEY: [u8; 32] = {:?};\n\
         pub static RESTORE_PUBLIC_KEY: [u8; 32] = {:?};\n",
        executable, authorization
    );
    let output = format!(
        "{output}\
pub static RELEASE_CATALOG_PUBLIC_KEY: [u8; 32] = {release_catalog:?};\n\
pub static AGENT_CATALOG_PUBLIC_KEY: [u8; 32] = {agent_catalog:?};\n"
    );
    fs::write(
        Path::new(&env::var("OUT_DIR")?).join("install_role_keys.rs"),
        output,
    )?;
    Ok(())
}
