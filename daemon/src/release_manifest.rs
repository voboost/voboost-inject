// release_manifest.rs — the signed release manifest that covers the multi-file
// native payload (release-manifest spec).
//
// Ported from Vala ota.vala verify_release_manifest and extended for the ptrace
// native payload: the manifest now covers the daemon ELF *and* every per-ABI
// runtime payload file (libimplant.so, liblsplant.so), each carrying an `abi`
// field. The daemon treats the release manifest — not a directory of files
// trusted by name — as the authoritative sha256 source for the payload it
// injects. Fail-closed: the whole manifest is rejected on one bad entry, a
// bound violation, a missing field, an invalid channel, a per-ABI payload
// entry missing its abi, or a one-ABI deployment gap.

use serde::Deserialize;

use crate::config;
use crate::log;
use crate::trust;

/// Byte-size bound (mirrors the daemon plan's MAX_PLAN_BYTES).
pub const MAX_RELEASE_MANIFEST_BYTES: usize = 1_048_576; // 1 MiB
/// Entry-count bound. Accommodates the native payload (≈2 files × 2 ABIs) plus
/// the daemon ELF and any agents/app entries, while rejecting pathological
/// lists.
pub const MAX_RELEASE_ENTRIES: usize = 4096;

/// The per-ABI runtime native payload files. Each must be listed for BOTH ABIs.
/// Build-time-only artifacts are excluded: libdobby.a is linked statically into
/// libimplant.so at build time and liblsplt.so is unused (not in DT_NEEDED of
/// liblsplant.so, not dlopened by the implant). Carrying them would bloat the
/// per-file OTA payloads for no runtime effect (incremental-delta spec).
pub const PAYLOAD_FILES: [&str; 2] = ["libimplant.so", "liblsplant.so"];
/// The ABIs the daemon carries.
pub const REQUIRED_ABIS: [&str; 2] = ["arm64-v8a", "armeabi-v7a"];

const CHANNELS: [&str; 3] = ["agents", "inject", "app"];

/// One verified release-manifest entry.
#[derive(Debug, Clone)]
pub struct ReleaseFile {
    pub path: String,
    pub channel: String,
    pub sha256: String,
    pub size: i64,
    pub version: String,
    /// Set for per-ABI native payload entries; None for single-ABI entries
    /// (the daemon ELF, agent dex).
    pub abi: Option<String>,
}

/// A verified release manifest.
#[derive(Debug, Default)]
pub struct ReleaseManifest {
    pub version: String,
    pub channel: String,
    pub files: Vec<ReleaseFile>,
}

#[derive(Deserialize)]
struct RawManifest {
    version: Option<String>,
    channel: Option<String>,
    files: Option<Vec<RawFile>>,
}

#[derive(Deserialize)]
struct RawFile {
    path: Option<String>,
    channel: Option<String>,
    sha256: Option<String>,
    // A non-integer `size` (float/string) fails deserialization and rejects the
    // whole manifest — matching the Vala int64 type check.
    size: Option<i64>,
    version: Option<String>,
    abi: Option<String>,
}

/// The basename (last path component) of a manifest path.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// True if the path's basename is a per-ABI native payload file.
fn is_payload_file(path: &str) -> bool {
    PAYLOAD_FILES.contains(&basename(path))
}

impl ReleaseManifest {
    /// Parse and structurally validate a release manifest (no signature check).
    pub fn parse(json_bytes: &[u8]) -> Option<ReleaseManifest> {
        if json_bytes.len() > MAX_RELEASE_MANIFEST_BYTES {
            log::err("release", "release-manifest exceeds size bound");
            return None;
        }
        let raw: RawManifest = serde_json::from_slice(json_bytes).ok()?;
        let files = raw.files?;
        if files.len() > MAX_RELEASE_ENTRIES {
            log::err("release", "release-manifest exceeds entry bound");
            return None;
        }

        let mut rm = ReleaseManifest {
            version: raw.version.unwrap_or_default(),
            channel: raw.channel.unwrap_or_default(),
            files: Vec::with_capacity(files.len()),
        };

        for f in files {
            let path = f.path.unwrap_or_default();
            let channel = f.channel.unwrap_or_default();
            let sha256 = f.sha256.unwrap_or_default();
            let version = f.version.unwrap_or_default();
            let size = f.size?;

            if path.is_empty()
                || sha256.is_empty()
                || version.is_empty()
                || !CHANNELS.contains(&channel.as_str())
            {
                return None;
            }

            // Per-ABI payload entries must carry a valid abi; single-ABI
            // entries (the daemon ELF, agent dex) omit it. A stray abi with an
            // unknown value is rejected wherever it appears.
            if is_payload_file(&path) {
                match f.abi.as_deref() {
                    Some(abi) if REQUIRED_ABIS.contains(&abi) => {}
                    _ => {
                        log::err("release", "per-ABI payload entry missing/invalid abi");
                        return None;
                    }
                }
            } else if let Some(abi) = f.abi.as_deref() {
                if !REQUIRED_ABIS.contains(&abi) {
                    return None;
                }
            }

            rm.files.push(ReleaseFile {
                path,
                channel,
                sha256,
                size,
                version,
                abi: f.abi,
            });
        }

        if !rm.abi_coverage_complete() {
            log::err("release", "release-manifest payload has a one-ABI gap");
            return None;
        }

        Some(rm)
    }

    /// Verify the detached ed25519 signature against EMBEDDED_PUBKEY, then parse.
    pub fn verify_and_parse(json_bytes: &[u8], sig: &[u8]) -> Option<ReleaseManifest> {
        if json_bytes.len() > MAX_RELEASE_MANIFEST_BYTES {
            log::err("release", "release-manifest exceeds size bound");
            return None;
        }
        if !trust::verify_signature(json_bytes, sig) {
            log::err("release", "release-manifest signature rejected");
            return None;
        }
        Self::parse(json_bytes)
    }

    /// Load + verify the on-device release manifest (root zone). None if absent
    /// or rejected.
    pub fn load() -> Option<ReleaseManifest> {
        let json = std::fs::read(config::release_manifest_file()).ok()?;
        let sig = std::fs::read(config::release_manifest_sig_file()).ok()?;
        Self::verify_and_parse(&json, &sig)
    }

    /// True when every payload file present for one ABI is present for both
    /// (no one-ABI deployment gap).
    fn abi_coverage_complete(&self) -> bool {
        for name in PAYLOAD_FILES {
            let mut seen_arm64 = false;
            let mut seen_armv7 = false;
            for f in &self.files {
                if f.channel != "inject" || basename(&f.path) != name {
                    continue;
                }
                match f.abi.as_deref() {
                    Some("arm64-v8a") => seen_arm64 = true,
                    Some("armeabi-v7a") => seen_armv7 = true,
                    _ => {}
                }
            }
            if seen_arm64 != seen_armv7 {
                return false;
            }
        }
        true
    }

    /// The expected sha256 for a per-ABI payload file (by basename + abi), used
    /// by trust-verification before injecting. Only inject-channel entries
    /// satisfy the lookup (defense-in-depth).
    pub fn payload_sha256(&self, name: &str, abi: &str) -> Option<&str> {
        self.files
            .iter()
            .find(|f| {
                f.channel == "inject" && f.abi.as_deref() == Some(abi) && basename(&f.path) == name
            })
            .map(|f| f.sha256.as_str())
    }
}

/// Outcome of verifying an ABI's native payload against the release manifest.
#[derive(Debug, Clone, PartialEq)]
pub enum PayloadVerify {
    /// Every payload file for the ABI matches its manifest sha256.
    Ok,
    /// A required payload file is not listed for this ABI in the manifest.
    MissingFromManifest(String),
    /// A payload file's on-disk sha256 differs from the manifest value.
    HashMismatch(String),
}

/// Verify the on-disk native payload files for `abi` against the verified
/// release manifest (trust-verification: "Native payload verification via the
/// release manifest"). Returns the first failure or `Ok` when every required
/// payload file matches. Device-only in practice — the payload files live in
/// `PAYLOAD_DIR` on the device, not the build host.
pub fn verify_payload_for_abi(rm: &ReleaseManifest, abi: &str) -> PayloadVerify {
    verify_payload_paths(rm, abi, |name| {
        format!("{}/{abi}/{name}", config::PAYLOAD_DIR)
    })
}

/// Pure core of payload verification: walk every payload file for `abi`,
/// resolve its on-disk path via `path_for`, and compare its sha256 to the
/// manifest value. Separated from `verify_payload_for_abi` so it can be unit
/// tested with temporary files instead of `PAYLOAD_DIR`.
fn verify_payload_paths<F: Fn(&str) -> String>(
    rm: &ReleaseManifest,
    abi: &str,
    path_for: F,
) -> PayloadVerify {
    for name in PAYLOAD_FILES {
        match rm.payload_sha256(name, abi) {
            None => return PayloadVerify::MissingFromManifest(name.into()),
            Some(expected) => {
                if !trust::verify_payload(&path_for(name), expected) {
                    return PayloadVerify::HashMismatch(name.into());
                }
            }
        }
    }
    PayloadVerify::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    // A well-formed inject manifest: daemon ELF (single-ABI) + all runtime
    // payload files (libimplant.so + liblsplant.so) for both ABIs.
    fn valid_manifest() -> String {
        let mut entries = vec![String::from(
            r#"{"path":"voboost-inject","channel":"inject","sha256":"aa","size":10,"version":"1"}"#,
        )];
        for abi in REQUIRED_ABIS {
            for name in PAYLOAD_FILES {
                entries.push(format!(
                    r#"{{"path":"payload/{abi}/{name}",
                       "channel":"inject","sha256":"bb",
                       "size":20,"version":"1","abi":"{abi}"}}"#
                ));
            }
        }
        format!(
            r#"{{"version":"1","channel":"inject","files":[{}]}}"#,
            entries.join(",")
        )
    }

    #[test]
    fn valid_full_payload_manifest_parses() {
        let rm = ReleaseManifest::parse(valid_manifest().as_bytes()).unwrap();
        assert_eq!(rm.files.len(), 5); // daemon ELF + 2 payload files × 2 ABIs
        assert_eq!(rm.payload_sha256("libimplant.so", "arm64-v8a"), Some("bb"));
        assert_eq!(rm.payload_sha256("libimplant.so", "x86"), None);
    }

    #[test]
    fn per_abi_payload_missing_abi_rejected() {
        let json = r#"{"version":"1","channel":"inject","files":[
            {"path":"payload/arm64-v8a/libimplant.so","channel":"inject",
             "sha256":"bb","size":20,"version":"1"}
        ]}"#;
        assert!(ReleaseManifest::parse(json.as_bytes()).is_none());
    }

    #[test]
    fn entry_missing_required_field_rejected() {
        // sha256 missing.
        let json = r#"{"version":"1","channel":"inject","files":[
            {"path":"voboost-inject","channel":"inject","size":10,"version":"1"}
        ]}"#;
        assert!(ReleaseManifest::parse(json.as_bytes()).is_none());
    }

    #[test]
    fn invalid_channel_rejected() {
        let json = r#"{"version":"1","channel":"inject","files":[
            {"path":"voboost-inject","channel":"bogus","sha256":"aa","size":10,"version":"1"}
        ]}"#;
        assert!(ReleaseManifest::parse(json.as_bytes()).is_none());
    }

    #[test]
    fn one_abi_gap_rejected() {
        // libimplant.so listed for arm64 only.
        let json = r#"{"version":"1","channel":"inject","files":[
            {"path":"payload/arm64-v8a/libimplant.so","channel":"inject",
             "sha256":"bb","size":20,"version":"1","abi":"arm64-v8a"}
        ]}"#;
        assert!(ReleaseManifest::parse(json.as_bytes()).is_none());
    }

    #[test]
    fn non_integer_size_rejected() {
        let json = r#"{"version":"1","channel":"inject","files":[
            {"path":"voboost-inject","channel":"inject","sha256":"aa","size":"10","version":"1"}
        ]}"#;
        assert!(ReleaseManifest::parse(json.as_bytes()).is_none());
    }

    #[test]
    fn entry_count_bound_rejected() {
        let mut entries = Vec::new();
        for i in 0..(MAX_RELEASE_ENTRIES + 1) {
            entries.push(format!(
                r#"{{"path":"f{i}","channel":"agents","sha256":"aa","size":1,"version":"1"}}"#
            ));
        }
        let json = format!(r#"{{"version":"1","files":[{}]}}"#, entries.join(","));
        assert!(ReleaseManifest::parse(json.as_bytes()).is_none());
    }

    #[test]
    fn byte_size_bound_rejected() {
        let big = vec![b' '; MAX_RELEASE_MANIFEST_BYTES + 1];
        assert!(ReleaseManifest::parse(&big).is_none());
    }

    #[test]
    fn bad_signature_rejected() {
        let json = valid_manifest();
        let bogus_sig = [0u8; 64];
        assert!(ReleaseManifest::verify_and_parse(json.as_bytes(), &bogus_sig).is_none());
    }

    #[test]
    fn agents_only_manifest_has_no_gap() {
        // No payload files at all → coverage trivially complete.
        let json = r#"{"version":"1","channel":"agents","files":[
            {"path":"agent.dex","channel":"agents","sha256":"aa","size":10,"version":"1"}
        ]}"#;
        assert!(ReleaseManifest::parse(json.as_bytes()).is_some());
    }

    // --- Payload verification against the release manifest (trust-verification) ---

    #[test]
    fn payload_verify_ok_when_hashes_match() {
        // Build manifest sha values from the same files we then verify.
        let dir = tempfile::tempdir().unwrap();
        let abi = "arm64-v8a";
        let prefix = dir.path().to_str().unwrap().to_string();
        let mut entries = Vec::new();
        for name in PAYLOAD_FILES {
            let p = format!("{prefix}/{name}");
            std::fs::write(&p, b"payload-bytes").unwrap();
            let sha = trust::sha256_file(&p).unwrap();
            entries.push(format!(
                r#"{{"path":"payload/{abi}/{name}","channel":"inject",
                       "sha256":"{sha}","size":13,"version":"1","abi":"{abi}"}}"#
            ));
        }
        let other = "armeabi-v7a";
        for name in PAYLOAD_FILES {
            entries.push(format!(
                r#"{{"path":"payload/{other}/{name}","channel":"inject",
                       "sha256":"ff","size":13,"version":"1","abi":"{other}"}}"#
            ));
        }
        let json = format!(
            r#"{{"version":"1","channel":"inject","files":[{}]}}"#,
            entries.join(",")
        );
        let rm = ReleaseManifest::parse(json.as_bytes()).unwrap();
        assert_eq!(
            verify_payload_paths(&rm, abi, |n| format!("{prefix}/{n}")),
            PayloadVerify::Ok
        );
    }

    #[test]
    fn payload_verify_hash_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let abi = "arm64-v8a";
        let prefix = dir.path().to_str().unwrap().to_string();
        let mut entries = Vec::new();
        for name in PAYLOAD_FILES {
            let p = format!("{prefix}/{name}");
            std::fs::write(&p, b"payload-bytes").unwrap();
            // Wrong sha → mismatch.
            entries.push(format!(
                r#"{{"path":"payload/{abi}/{name}","channel":"inject",
                       "sha256":"00","size":13,"version":"1","abi":"{abi}"}}"#
            ));
        }
        let other = "armeabi-v7a";
        for name in PAYLOAD_FILES {
            entries.push(format!(
                r#"{{"path":"payload/{other}/{name}","channel":"inject",
                       "sha256":"ff","size":13,"version":"1","abi":"{other}"}}"#
            ));
        }
        let json = format!(
            r#"{{"version":"1","channel":"inject","files":[{}]}}"#,
            entries.join(",")
        );
        let rm = ReleaseManifest::parse(json.as_bytes()).unwrap();
        assert_eq!(
            verify_payload_paths(&rm, abi, |n| format!("{prefix}/{n}")),
            PayloadVerify::HashMismatch("libimplant.so".into())
        );
    }

    #[test]
    fn payload_verify_missing_from_manifest_rejected() {
        // Manifest lists only the other ABI → lookup for this ABI is None.
        let dir = tempfile::tempdir().unwrap();
        let abi = "arm64-v8a";
        let prefix = dir.path().to_str().unwrap().to_string();
        let mut entries = Vec::new();
        for name in PAYLOAD_FILES {
            let p = format!("{prefix}/{name}");
            std::fs::write(&p, b"payload-bytes").unwrap();
        }
        // Only arm64 listed; verify asks for armeabi-v7a → MissingFromManifest.
        for name in PAYLOAD_FILES {
            let sha = trust::sha256_file(&format!("{prefix}/{name}")).unwrap();
            entries.push(format!(
                r#"{{"path":"payload/{abi}/{name}","channel":"inject",
                       "sha256":"{sha}","size":13,"version":"1","abi":"{abi}"}}"#
            ));
        }
        let json = format!(
            r#"{{"version":"1","channel":"inject","files":[{}]}}"#,
            entries.join(",")
        );
        // Parse as-is: one-ABI gap → None. Inject a sibling ABI entry with a
        // bogus sha so coverage passes, then verify the *absent* ABI.
        let rm = ReleaseManifest::parse(json.as_bytes());
        assert!(rm.is_none()); // one-ABI gap rejected at parse time

        // Build a complete manifest covering both ABIs, then verify an ABI that
        // has no payload entries at all (simulate missing file).
        let mut entries2 = entries.clone();
        let other = "armeabi-v7a";
        for name in PAYLOAD_FILES {
            entries2.push(format!(
                r#"{{"path":"payload/{other}/{name}","channel":"inject",
                       "sha256":"ff","size":13,"version":"1","abi":"{other}"}}"#
            ));
        }
        let json2 = format!(
            r#"{{"version":"1","channel":"inject","files":[{}]}}"#,
            entries2.join(",")
        );
        let rm2 = ReleaseManifest::parse(json2.as_bytes()).unwrap();
        // Verifying a bogus ABI never listed → MissingFromManifest.
        assert_eq!(
            verify_payload_paths(&rm2, "x86", |_| String::from("/nonexistent")),
            PayloadVerify::MissingFromManifest("libimplant.so".into())
        );
    }
}
