use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

const PACKAGE_ABSENT_ERROR: &[u8] = b"Error: package ru.voboost was not found\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageProbe {
    Absent,
    Present,
}

fn classify_package_probe(
    success: bool,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<PackageProbe, String> {
    // AOSP API 28's `pm path` reports an absent package as status 1 with no
    // output. Other platform revisions emit the exact diagnostic below on
    // stderr. Admit only those two complete tuples; every other failure stays
    // ambiguous rather than being converted into absence.
    if !success
        && exit_code == Some(1)
        && stdout.is_empty()
        && (stderr.is_empty() || stderr == PACKAGE_ABSENT_ERROR)
    {
        return Ok(PackageProbe::Absent);
    }
    if success && exit_code == Some(0) && stderr.is_empty() {
        let text = std::str::from_utf8(stdout)
            .map_err(|_| "fresh package stdout is not UTF-8".to_string())?;
        if text.ends_with('\n') && crate::installed_apk::canonical_base_apk_path(text).is_ok() {
            return Ok(PackageProbe::Present);
        }
    }
    Err("fresh package observation is ambiguous".into())
}

#[cfg(target_os = "android")]
fn run_package_probe() -> Result<crate::fixed_process::BoundedOutput, String> {
    crate::fixed_process::output(
        "/system/bin/pm",
        &["path", "ru.voboost"],
        Duration::from_secs(5),
        4096,
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshState {
    pub schema_version: u32,
    pub root_prior_state: String,
    pub init_prior_state: String,
    pub package_prior_state: String,
    pub app_op_prior_mode: String,
}

impl FreshState {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("parse fresh install state: {error}"))?;
        if value.canonical_bytes()? != bytes
            || value.schema_version != 1
            || value.root_prior_state != "absent"
            || value.init_prior_state != "absent"
            || value.package_prior_state != "absent"
            || value.app_op_prior_mode != "absent"
        {
            return Err("fresh install state is not canonical absence".into());
        }
        Ok(value)
    }
}

#[derive(Default)]
struct Observed {
    foreign_root: bool,
    init_exists: bool,
    package_exists: bool,
    app_op_exists: bool,
    package_data_exists: bool,
}

fn require(observed: &Observed) -> Result<FreshState, String> {
    if observed.foreign_root {
        return Err("fresh install root contains foreign or partial product state".into());
    }
    if observed.init_exists {
        return Err("fresh install init hook already exists".into());
    }
    if observed.package_exists {
        return Err("fresh install package already exists".into());
    }
    if observed.app_op_exists {
        return Err("fresh install AppOp state already exists".into());
    }
    if observed.package_data_exists {
        return Err("fresh install package data already exists".into());
    }
    Ok(FreshState {
        schema_version: 1,
        root_prior_state: "absent".into(),
        init_prior_state: "absent".into(),
        package_prior_state: "absent".into(),
        app_op_prior_mode: "absent".into(),
    })
}

#[cfg(target_os = "android")]
pub fn observe_and_require(staging: &Path) -> Result<FreshState, String> {
    let root = staging
        .parent()
        .and_then(Path::parent)
        .ok_or("install staging is outside product root")?;
    let transaction = staging
        .file_name()
        .ok_or("install staging has no transaction")?;
    let allowed = BTreeSet::from([
        std::ffi::OsString::from("install"),
        std::ffi::OsString::from("operation.lock"),
        std::ffi::OsString::from("voboost-install"),
    ]);
    let foreign_root = fs::read_dir(root)
        .map_err(|e| format!("observe product root: {e}"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|e| e.to_string())?
        .difference(&allowed)
        .next()
        .is_some()
        || fs::read_dir(root.join("install"))
            .map_err(|e| e.to_string())?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|e| e.to_string())?
            != BTreeSet::from([transaction.to_os_string()]);

    let package = run_package_probe()?;
    if classify_package_probe(
        package.status.success(),
        package.status.code(),
        &package.stdout,
        &package.stderr,
    )? == PackageProbe::Present
    {
        return require(&Observed {
            package_exists: true,
            ..Observed::default()
        });
    }
    let app_op = crate::fixed_process::output(
        "/system/bin/appops",
        &["get", "ru.voboost", "REQUEST_INSTALL_PACKAGES"],
        Duration::from_secs(10),
        4096,
    )?;
    let app_op_text = std::str::from_utf8(&app_op.stdout)
        .map_err(|_| "fresh AppOp output is not UTF-8")?
        .trim();
    let app_op_error = std::str::from_utf8(&app_op.stderr)
        .map_err(|_| "fresh AppOp error is not UTF-8")?
        .trim();
    let app_op_absent =
        (app_op.status.success() && app_op_text == "No operations." && app_op_error.is_empty())
            || (!app_op.status.success()
                && app_op_text.is_empty()
                && app_op_error == "Error: No UID for ru.voboost in user 0");
    if !app_op_absent {
        return Err("fresh AppOp absence is ambiguous".into());
    }
    require(&Observed {
        foreign_root,
        init_exists: Path::new("/system/etc/init/voboost.rc").exists(),
        package_exists: false,
        app_op_exists: false,
        package_data_exists: ["/data/user/0/ru.voboost", "/data/data/ru.voboost"]
            .iter()
            .any(|path| Path::new(path).exists()),
    })
}

#[cfg(not(target_os = "android"))]
pub fn observe_and_require(_staging: &Path) -> Result<FreshState, String> {
    Err("fresh install observation requires Android".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fresh_collision_fails_before_mutation() {
        for observed in [
            Observed {
                foreign_root: true,
                ..Observed::default()
            },
            Observed {
                init_exists: true,
                ..Observed::default()
            },
            Observed {
                package_exists: true,
                ..Observed::default()
            },
            Observed {
                app_op_exists: true,
                ..Observed::default()
            },
            Observed {
                package_data_exists: true,
                ..Observed::default()
            },
        ] {
            let mutations = std::cell::Cell::new(0);
            assert!(require(&observed).is_err());
            assert_eq!(mutations.get(), 0);
        }
        let facts = require(&Observed::default()).unwrap();
        assert_eq!(
            FreshState::parse(&facts.canonical_bytes().unwrap()).unwrap(),
            facts
        );
    }

    #[test]
    fn package_probe_accepts_only_documented_absence_or_canonical_presence() {
        assert_eq!(
            classify_package_probe(false, Some(1), b"", b"").unwrap(),
            PackageProbe::Absent
        );
        assert_eq!(
            classify_package_probe(false, Some(1), b"", PACKAGE_ABSENT_ERROR).unwrap(),
            PackageProbe::Absent
        );
        assert_eq!(
            classify_package_probe(
                true,
                Some(0),
                b"package:/data/app/ru.voboost/base.apk\n",
                b""
            )
            .unwrap(),
            PackageProbe::Present
        );

        for result in [
            classify_package_probe(false, Some(2), b"", PACKAGE_ABSENT_ERROR),
            classify_package_probe(false, Some(2), b"", b""),
            classify_package_probe(false, Some(1), b"unexpected\n", b""),
            classify_package_probe(false, Some(1), b"", b"unexpected\n"),
            classify_package_probe(true, Some(0), b"", b""),
            classify_package_probe(true, Some(0), b"garbage\n", b""),
            classify_package_probe(true, Some(0), b"package:/base.apk\n", PACKAGE_ABSENT_ERROR),
            classify_package_probe(false, None, b"", PACKAGE_ABSENT_ERROR),
        ] {
            assert!(result.is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn package_probe_command_preserves_api28_silent_absence_tuple() {
        let silent = crate::fixed_process::output(
            "/bin/sh",
            &["-c", "exit 1"],
            Duration::from_secs(1),
            4096,
        )
        .unwrap();
        assert_eq!(silent.status.code(), Some(1));
        assert!(silent.stdout.is_empty());
        assert!(silent.stderr.is_empty());
        assert_eq!(
            classify_package_probe(
                silent.status.success(),
                silent.status.code(),
                &silent.stdout,
                &silent.stderr,
            )
            .unwrap(),
            PackageProbe::Absent
        );

        assert!(crate::fixed_process::output(
            "/bin/sh",
            &["-c", "sleep 1"],
            Duration::from_millis(10),
            4096,
        )
        .unwrap_err()
        .contains("timed out"));
    }
}
