//! Read-only preflight of the Android registrations for all owned profiles.
use super::*;
use voboost_shared::fixed_process;
use voboost_shared::owned_overlay::parse_list_for;

pub(super) fn preflight(owned: &[Variant]) -> io::Result<()> {
    let pm = fixed_process::output(
        "/system/bin/cmd",
        &[
            "package",
            "list",
            "packages",
            "-u",
            "-f",
            "--user",
            "0",
            "ru.voboost.translation",
        ],
        Duration::from_secs(5),
        64 * 1024,
    )
    .map_err(io::Error::other)?;
    if !pm.status.success() || !pm.stderr.is_empty() {
        return Err(fail("PackageManager resource code path query failed"));
    }
    validate(owned, &pm.stdout, &overlay_list()?, overlay_dump)
}

fn overlay_dump() -> io::Result<Vec<u8>> {
    let output = fixed_process::output(
        "/system/bin/dumpsys",
        &["overlay"],
        Duration::from_secs(5),
        128 * 1024,
    )
    .map_err(io::Error::other)?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(fail("OverlayManager resource code path query failed"));
    }
    Ok(output.stdout)
}

fn validate(
    owned: &[Variant],
    pm: &[u8],
    oms: &[u8],
    dump: impl FnOnce() -> io::Result<Vec<u8>>,
) -> io::Result<()> {
    let pm = complete_text(pm, "PackageManager")?;
    let mut packages = Vec::new();
    for line in pm.lines() {
        let (path, package) = line
            .strip_prefix("package:")
            .and_then(|line| line.rsplit_once('='))
            .filter(|(path, package)| path.starts_with('/') && !package.is_empty())
            .ok_or_else(|| fail("PackageManager resource code path record malformed"))?;
        let Ok(variant) = Variant::from_package(package) else {
            continue;
        };
        if !owned.contains(&variant)
            || path != expected_path(variant)
            || packages.contains(&variant)
        {
            return Err(registration_error("PackageManager", variant));
        }
        packages.push(variant);
    }

    let records = overlay_list_records(oms)?;
    let mut overlays = Vec::new();
    for variant in Variant::ALL {
        if !records.contains(&variant.package()) {
            continue;
        }
        if !packages.contains(&variant) {
            return Err(registration_error("OverlayManager", variant));
        }
        parse_list_for(oms, variant)
            .map_err(|error| fail(&format!("OverlayManager {}: {error}", variant.package())))?;
        overlays.push(variant);
    }
    if !overlays.is_empty() {
        let dump = dump()?;
        for variant in overlays {
            validate_overlay_path(&dump, variant)?;
        }
    }
    Ok(())
}

pub(super) fn verify_overlay_path(variant: Variant) -> io::Result<()> {
    validate_overlay_path(&overlay_dump()?, variant)
}

fn validate_overlay_path(dump: &[u8], variant: Variant) -> io::Result<()> {
    let header = format!("{}:0 {{", variant.package());
    let expected_path = expected_path(variant);
    let dump = complete_text(dump, "OverlayManager")?;
    let mut lines = dump.lines().map(str::trim);
    if !lines.by_ref().any(|line| line == header) {
        return Err(registration_error("OverlayManager", variant));
    }
    let mut package = None;
    let mut user = None;
    let mut target = None;
    let mut path = None;
    let mut closed = false;
    for line in lines.by_ref() {
        if line == "}" {
            closed = true;
            break;
        }
        if line.ends_with('{') {
            break;
        }
        let field = [
            ("mPackageName", &mut package),
            ("mUserId", &mut user),
            ("mTargetPackageName", &mut target),
            ("mBaseCodePath", &mut path),
        ];
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().trim_end_matches('.');
            for (expected, member) in field {
                if name == expected && member.replace(value.trim()).is_some() {
                    return Err(registration_error("OverlayManager", variant));
                }
            }
        }
    }
    if !closed
        || package != Some(variant.package())
        || user != Some("0")
        || target != Some(variant.owner().process())
        || path != Some(expected_path.as_str())
        || lines.any(|line| line == header)
    {
        return Err(registration_error("OverlayManager", variant));
    }
    Ok(())
}

fn complete_text<'a>(bytes: &'a [u8], manager: &str) -> io::Result<&'a str> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|text| text.is_empty() || text.ends_with('\n'))
        .ok_or_else(|| {
            fail(&format!(
                "{manager} returned incomplete resource registration records"
            ))
        })
}

fn expected_path(variant: Variant) -> String {
    format!("/vendor/overlay/{}", variant.file())
}

fn registration_error(manager: &str, variant: Variant) -> io::Error {
    fail(&format!(
        "{manager} {}: registration is not bound to authenticated {}",
        variant.package(),
        expected_path(variant)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm(variant: Variant, path: &str) -> String {
        format!("package:{path}={}\n", variant.package())
    }

    fn oms(variant: Variant) -> String {
        format!("{}\n[ ] {}\n", variant.owner().process(), variant.package())
    }

    fn dump(variant: Variant, path: &str) -> Vec<u8> {
        format!(
            "Settings\n  {}:0 {{\n    mPackageName.......: {}\n    mUserId............: 0\n    mTargetPackageName.: {}\n    mBaseCodePath......: {path}\n    mState.............: STATE_DISABLED\n  }}\n",
            variant.package(),
            variant.package(),
            variant.owner().process(),
        )
        .into_bytes()
    }

    #[test]
    fn disabled_overlay_requires_its_own_oms_and_pm_paths() {
        let variant = Variant::SettingA9;
        let path = expected_path(variant);
        let pm = pm(variant, &path);
        let oms = oms(variant);
        assert!(validate(&[variant], pm.as_bytes(), oms.as_bytes(), || {
            Ok(dump(variant, &path))
        })
        .is_ok());
        assert!(validate(&[variant], pm.as_bytes(), oms.as_bytes(), || {
            Ok(dump(variant, "/data/app/foreign/base.apk"))
        })
        .unwrap_err()
        .to_string()
        .contains("OverlayManager"));
        assert!(validate(&[variant], b"", oms.as_bytes(), || {
            panic!("OMS registration without PM must stop preflight")
        })
        .is_err());
    }

    #[test]
    fn package_manager_only_registration_requires_authenticated_path() {
        let variant = Variant::SettingA9;
        let exact = pm(variant, &expected_path(variant));
        assert!(validate(&[variant], exact.as_bytes(), b"", || {
            panic!("no OMS registration requires no OMS dump")
        })
        .is_ok());
        let foreign = pm(variant, "/data/app/foreign/base.apk");
        for (authorized, registration) in [(&[variant][..], foreign), (&[][..], exact)] {
            assert!(validate(authorized, registration.as_bytes(), b"", || {
                panic!("PM collision must stop preflight")
            })
            .unwrap_err()
            .to_string()
            .contains("PackageManager"));
        }
    }

    #[test]
    fn later_variant_collision_blocks_the_whole_preflight() {
        let first = Variant::SettingA9;
        let later = Variant::SettingA11;
        let pm = format!(
            "{}{}",
            pm(first, &expected_path(first)),
            pm(later, &expected_path(later))
        );
        let oms = format!("{}{}", oms(first), oms(later));
        let dumps = [
            dump(first, &expected_path(first)),
            dump(later, "/data/app/foreign/base.apk"),
        ]
        .concat();
        assert!(
            validate(&[first, later], pm.as_bytes(), oms.as_bytes(), || Ok(dumps))
                .unwrap_err()
                .to_string()
                .contains(later.package())
        );
    }
}
