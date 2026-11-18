//! Android package authority and package-owned artifact removal.

use super::*;
use voboost_shared::installed_apk::canonical_base_apk_path;

const PACKAGE: &str = "ru.voboost";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackagePathQuery<'a> {
    Absent,
    Present(&'a str),
}

fn classify_package_path_output<'a>(
    success: bool,
    stdout: &'a [u8],
    stderr: &[u8],
) -> Result<PackagePathQuery<'a>, String> {
    let stdout =
        std::str::from_utf8(stdout).map_err(|_| "pm path stdout is not UTF-8".to_string())?;
    let stderr =
        std::str::from_utf8(stderr).map_err(|_| "pm path stderr is not UTF-8".to_string())?;
    if success && stdout.is_empty() && stderr.is_empty() {
        return Ok(PackagePathQuery::Absent);
    }
    let not_found = "Error: package ru.voboost was not found\n";
    if !success
        && ((stdout == not_found && stderr.is_empty())
            || (stderr == not_found && stdout.is_empty()))
    {
        return Ok(PackagePathQuery::Absent);
    }
    if !success || !stderr.is_empty() {
        return Err("pm path failed or emitted unexpected diagnostics".to_string());
    }
    // The canonical acceptance invariant lives in one place:
    // shared/installed_apk.rs (also used by install observe/fresh probing).
    // It accepts the exact `pm path` stdout — one "package:" line — and
    // enforces the single-line, /data/app, base.apk and length rails itself.
    let path = canonical_base_apk_path(stdout)?;
    Ok(PackagePathQuery::Present(path))
}

pub(super) fn installed_apk_signer(path: &Path) -> Result<([u8; 32], FileStamp), String> {
    installed_apk_signer_with(path, || Ok(()))
}

pub(super) fn installed_apk_signer_with<BeforeRestat>(
    path: &Path,
    before_restat: BeforeRestat,
) -> Result<([u8; 32], FileStamp), String>
where
    BeforeRestat: FnOnce() -> Result<(), String>,
{
    let file = open_regular_nofollow(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("stat installed APK: {error}"))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err("installed APK must be a single-link regular file".to_string());
    }
    let before = FileStamp::from(&metadata);
    if before.len < 32 || before.len > 1024 * 1024 * 1024 {
        return Err("installed APK size is outside the accepted bound".to_string());
    }
    let identity_stamp = voboost_contract::apk::FileStamp {
        dev: before.dev,
        ino: before.ino,
        size: before.len,
        ctime: before.ctime,
        ctime_nsec: before.ctime_nsec,
    };
    let certificate = voboost_contract::apk::signer_sha256_v2_v3(&file, identity_stamp)
        .map_err(|error| format!("verify installed APK v2/v3 signer: {error}"))?;
    before_restat()?;
    let after = FileStamp::from(
        &file
            .metadata()
            .map_err(|error| format!("restat installed APK: {error}"))?,
    );
    if before != after {
        return Err("installed APK changed during signer verification".to_string());
    }
    Ok((certificate, before))
}

fn bound_installed_package_path() -> Result<Option<String>, String> {
    let output = fixed_process::output(
        "/system/bin/pm",
        &["path", "--user", "0", PACKAGE],
        Duration::from_secs(10),
        4096,
    );
    match output {
        Ok(output) => {
            super::diag(&format!(
                "pm path exit={} stdout={:?} stderr={:?}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
            match classify_package_path_output(
                output.status.success(),
                &output.stdout,
                &output.stderr,
            )? {
                PackagePathQuery::Absent => Ok(None),
                PackagePathQuery::Present(path) => Ok(Some(path.to_string())),
            }
        }
        Err(error) => {
            super::diag(&format!("pm path spawn failed: {error}"));
            Err(format!("pm path spawn failed: {error}"))
        }
    }
    .or_else(|pm_error| {
        // The pm probe rides the servicemanager binder dialogue, which is
        // unavailable in the voboost_uninstall domain on this OEM policy
        // ("cmd: Can't find service: package"). The package authority check
        // only needs the installed base APK's path — the same filesystem
        // scan the install observes use delivers it without the package
        // service, and the identity verification below rules out lookalikes.
        voboost_shared::installed_apk::scan_base_apk_path()
            .map(|path| {
                super::diag(&format!("pm probe unavailable, scan resolved: {path}"));
                Some(path)
            })
            .map_err(|scan_error| {
                super::diag(&format!("scan failed: {scan_error}"));
                format!("{pm_error}; scan: {scan_error}")
            })
    })
}

#[derive(Debug, Eq, PartialEq)]
struct PackageAuthorityObservation {
    path: String,
    stamp: FileStamp,
    version_code: u64,
}

pub(super) fn parse_package_version_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<u64, String> {
    if !success || !stderr.is_empty() {
        return Err("Package Manager version inventory failed".to_string());
    }
    let output = std::str::from_utf8(stdout)
        .map_err(|_| "Package Manager version inventory is not UTF-8".to_string())?;
    // `pm list packages <FILTER>` matches package names by substring, so the
    // product's own translation packages (`ru.voboost.translation.*`) are
    // reported next to the product package. Only an exact package-name record
    // is this inventory's subject; a second exact record is genuinely
    // ambiguous, while every other record must still be a canonical listing
    // line so an unexpected response cannot pass as a version.
    let exact = format!("package:{PACKAGE} versionCode:");
    let mut value = None;
    for line in output.lines() {
        if let Some(candidate) = line.strip_prefix(&exact) {
            if value.is_some() {
                return Err("Package Manager version inventory is ambiguous".to_string());
            }
            value = Some(candidate);
            continue;
        }
        if !canonical_listing_line(line) {
            return Err("Package Manager version inventory is ambiguous".to_string());
        }
    }
    let value =
        value.ok_or_else(|| "Package Manager version inventory is ambiguous".to_string())?;
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("Package Manager versionCode is non-canonical".to_string());
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or_else(|| {
            "Package Manager versionCode is outside Android's signed-long bound".to_string()
        })
}

/// A canonical Android package name as it appears in a `pm list packages`
/// record.
fn canonical_package_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_')
        })
}

/// One `pm list packages --show-versioncode` record for a package other than
/// the product package. Substring filtering makes those records expected, but
/// each one still has to be a canonical listing line; anything else fails
/// closed instead of being read as the product version.
fn canonical_listing_line(line: &str) -> bool {
    line.strip_prefix("package:")
        .and_then(|record| record.split_once(" versionCode:"))
        .is_some_and(|(name, value)| {
            canonical_package_name(name)
                && !value.is_empty()
                && value.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn installed_package_version_code() -> Result<u64, String> {
    let output = fixed_process::output(
        "/system/bin/pm",
        &[
            "list",
            "packages",
            "--show-versioncode",
            "--user",
            "0",
            PACKAGE,
        ],
        Duration::from_secs(10),
        4096,
    );
    let result = match &output {
        Ok(output) => {
            super::diag(&format!(
                "pm versionCode exit={} stdout={:?} stderr={:?}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
            parse_package_version_output(output.status.success(), &output.stdout, &output.stderr)
        }
        Err(error) => {
            super::diag(&format!("pm versionCode spawn failed: {error}"));
            Err(format!("run /system/bin/pm: {error}"))
        }
    };
    result
}

fn verify_package_authority() -> Result<Option<PackageAuthorityObservation>, String> {
    let Some(path) = bound_installed_package_path()? else {
        return Ok(None);
    };
    let (certificate, stamp) = installed_apk_signer(Path::new(&path))?;
    let marker = std::str::from_utf8(&ANDROID_PACKAGE_CERT_MARKER)
        .map_err(|_| "embedded Android certificate marker is not UTF-8".to_string())?;
    let authority = marker
        .strip_prefix("VOBOOST-ANDROID-CERT-SHA256:")
        .ok_or_else(|| "embedded Android certificate marker prefix is invalid".to_string())?;
    let mut expected = [0u8; 32];
    if authority.len() != 64
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("embedded Android certificate marker is non-canonical".to_string());
    }
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&authority[index * 2..index * 2 + 2], 16)
            .map_err(|_| "embedded Android certificate marker is invalid".to_string())?;
    }
    if expected != ANDROID_PACKAGE_CERT_SHA256 {
        return Err("embedded Android certificate authorities disagree".to_string());
    }
    if certificate != expected {
        return Err(
            "installed ru.voboost signer is outside the embedded Android certificate authority"
                .to_string(),
        );
    }
    Ok(Some(PackageAuthorityObservation {
        path,
        stamp,
        version_code: installed_package_version_code()?,
    }))
}

fn package_registered_globally() -> Result<bool, String> {
    let output = fixed_process::output(
        "/system/bin/pm",
        &["list", "packages", PACKAGE],
        Duration::from_secs(10),
        4096,
    );
    let output = match output {
        Ok(output) => {
            super::diag(&format!(
                "pm global exit={} stdout={:?} stderr={:?}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
            output
        }
        Err(error) => {
            super::diag(&format!("pm global spawn failed: {error}"));
            return Err(format!("run /system/bin/pm: {error}"));
        }
    };
    parse_package_registration_output(output.status.success(), &output.stdout, &output.stderr)
}

/// Prove whether the product package is registered globally.
///
/// `pm list packages <FILTER>` matches package names by substring, so the
/// product's own translation packages are reported next to the product
/// record. Only an exact product record proves registration; a duplicate or a
/// record that is not a canonical package name still fails closed.
pub(super) fn parse_package_registration_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<bool, String> {
    if !success || !stderr.is_empty() {
        return Err("global Package Manager inventory failed".to_string());
    }
    let text = std::str::from_utf8(stdout)
        .map_err(|_| "global Package Manager inventory is not UTF-8".to_string())?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err("global Package Manager inventory is incomplete".to_string());
    }
    let mut registered = false;
    for line in text.lines() {
        let Some(name) = line.strip_prefix("package:") else {
            return Err("global Package Manager inventory is ambiguous".to_string());
        };
        if !canonical_package_name(name) {
            return Err("global Package Manager inventory is ambiguous".to_string());
        }
        if name != PACKAGE {
            continue;
        }
        if registered {
            return Err("global Package Manager inventory contains duplicate package".to_string());
        }
        registered = true;
    }
    Ok(registered)
}

pub(super) fn package_uninstall_args(version_code: u64) -> [String; 4] {
    [
        "uninstall".to_string(),
        "--versionCode".to_string(),
        version_code.to_string(),
        PACKAGE.to_string(),
    ]
}

pub(super) fn uninstall_package() -> Result<(), String> {
    let Some(first) = verify_package_authority()? else {
        return if package_registered_globally()? {
            Err(
                "ru.voboost is registered outside the committed Android user 0 authority"
                    .to_string(),
            )
        } else {
            Ok(())
        };
    };
    let Some(current) = verify_package_authority()? else {
        return Err("bound package disappeared immediately before uninstall".to_string());
    };
    if first != current {
        return Err("bound package changed immediately before uninstall".to_string());
    }
    let arguments = package_uninstall_args(current.version_code);
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let status =
        fixed_process::output("/system/bin/pm", &arguments, Duration::from_secs(120), 4096)?.status;
    if package_registered_globally()? {
        return Err(if status.success() {
            "pm uninstall reported success but the package remains installed".to_string()
        } else {
            "pm uninstall failed and the package remains installed".to_string()
        });
    }
    Ok(())
}

pub(super) fn remove_owned_restore_manifest_pair(inventory: &Inventory) -> Result<(), String> {
    let expected = &inventory.artifacts.native.restore_manifest;
    let descriptor_path = Path::new(RESTORE_MANIFEST_PATH);
    let signature_path = Path::new(RESTORE_MANIFEST_SIGNATURE_PATH);
    let descriptor = if path_entry_exists(descriptor_path)? {
        let trusted = read_regular_nofollow(descriptor_path, expected.size)?;
        require_root_file(trusted.stamp, 0o644, "restore authorization")?;
        require_trusted_context_any(
            &trusted,
            &[STOCK_DATA_CONTEXT, DATA_CONTEXT],
            "restore authorization",
        )?;
        if trusted.bytes.len() as u64 != expected.size
            || sha256_hex(&trusted.bytes) != expected.sha256
        {
            return Err("restore authorization differs from inventory".to_string());
        }
        Some(trusted.bytes)
    } else {
        None
    };
    let signature = if path_entry_exists(signature_path)? {
        let trusted = read_regular_nofollow(signature_path, expected.signature_size)?;
        require_root_file(trusted.stamp, 0o644, "restore authorization signature")?;
        require_trusted_context_any(
            &trusted,
            &[STOCK_DATA_CONTEXT, DATA_CONTEXT],
            "restore authorization signature",
        )?;
        if trusted.bytes.len() as u64 != expected.signature_size
            || sha256_hex(&trusted.bytes) != expected.signature_sha256
        {
            return Err("restore authorization signature differs from inventory".to_string());
        }
        Some(trusted.bytes)
    } else {
        None
    };
    if let (Some(descriptor), Some(signature)) = (&descriptor, &signature) {
        if !restore_pair_signature_valid(
            descriptor,
            signature,
            &expected.signature_role,
            &RESTORE_PUBLIC_KEY,
        ) {
            return Err("restore authorization pair has an invalid role signature".to_string());
        }
        parse_restore_document(descriptor)?;
    }
    remove_restore_pair(descriptor.is_some(), signature.is_some(), |signature| {
        let path = if signature {
            signature_path
        } else {
            descriptor_path
        };
        fs::remove_file(path)
            .map_err(|error| format!("remove restore authorization member: {error}"))?;
        fsync_parent(path)
    })
}

fn remove_restore_pair(
    descriptor: bool,
    signature: bool,
    mut remove: impl FnMut(bool) -> Result<(), String>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (present, is_signature) in [(descriptor, false), (signature, true)] {
        if present {
            if let Err(error) = remove(is_signature) {
                errors.push(format!(
                    "{}: {error}",
                    if is_signature {
                        "signature"
                    } else {
                        "descriptor"
                    }
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn restore_pair_signature_valid(
    descriptor: &[u8],
    signature: &[u8],
    role: &str,
    public_key: &[u8; 32],
) -> bool {
    role == "restore-manifest" && detached_signature_valid(descriptor, signature, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn restore_pair_removal_attempts_both_members_and_preserves_each_failure() {
        for present in 0u8..4 {
            for failures in 0u8..4 {
                let mut calls = Vec::new();
                let result = remove_restore_pair(present & 1 != 0, present & 2 != 0, |signature| {
                    let bit = if signature { 2 } else { 1 };
                    calls.push(bit);
                    if failures & bit != 0 {
                        Err(format!("failure-{bit}"))
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(
                    calls,
                    [1u8, 2]
                        .into_iter()
                        .filter(|bit| present & bit != 0)
                        .collect::<Vec<_>>()
                );
                assert_eq!(result.is_ok(), present & failures == 0);
                if let Err(error) = result {
                    for bit in [1u8, 2] {
                        assert_eq!(
                            error.contains(&format!("failure-{bit}")),
                            present & failures & bit != 0
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn restore_pair_uses_the_shared_raw_canonical_document_signature() {
        let key = SigningKey::from_bytes(&[91; 32]);
        let document = b"{\"schemaVersion\":1,\"releaseIdentity\":\"1.0.0-beta1\"}\n";
        let signature = key.sign(document).to_bytes();
        assert!(restore_pair_signature_valid(
            document,
            &signature,
            "restore-manifest",
            key.verifying_key().as_bytes(),
        ));

        let legacy = [
            b"voboost-install-authorization-v1\0restore\0".as_slice(),
            document,
        ]
        .concat();
        let legacy_signature = key.sign(&legacy).to_bytes();
        assert!(!restore_pair_signature_valid(
            document,
            &legacy_signature,
            "restore-manifest",
            key.verifying_key().as_bytes(),
        ));
        assert!(!restore_pair_signature_valid(
            document,
            &signature,
            "native-manifest",
            key.verifying_key().as_bytes(),
        ));
    }
}
