use std::{env, fs, path::PathBuf};

#[path = "../build_support/strict_ed25519_spki.rs"]
mod build_key;
#[path = "../build_support/host_role_keys.rs"]
mod host_role_keys;
#[path = "../build_support/strict_hex32.rs"]
mod strict_hex32;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
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
    println!("cargo:rerun-if-env-changed=VOBOOST_ANDROID_CERT_SHA256");
    let certificate = if android {
        strict_hex32::parse_lower_hex32(
            &env::var("VOBOOST_ANDROID_CERT_SHA256")
                .expect("Android build requires VOBOOST_ANDROID_CERT_SHA256"),
        )
        .expect("APK certificate SHA-256 is not canonical lowercase hex")
    } else {
        [0xaa; 32]
    };
    let certificate_hex = certificate
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let source = format!(
        "pub const NATIVE_EXECUTABLE_PUBKEY: [u8; 32] = {executable:?};\n\
         pub const RESTORE_PUBLIC_KEY: [u8; 32] = {authorization:?};\n\
         pub const RELEASE_CATALOG_PUBLIC_KEY: [u8; 32] = {release_catalog:?};\n\
         pub const ANDROID_PACKAGE_CERT_SHA256: [u8; 32] = {certificate:?};\n\
         #[used]\n#[cfg_attr(target_os = \"android\", link_section = \".rodata.voboost_android_cert\")]\n\
         pub static ANDROID_PACKAGE_CERT_MARKER: [u8; 92] = *b\"VOBOOST-ANDROID-CERT-SHA256:{certificate_hex}\";\n"
    );
    fs::write(out_dir.join("embedded_pubkey.rs"), source).expect("write embedded uninstall keys");
}
