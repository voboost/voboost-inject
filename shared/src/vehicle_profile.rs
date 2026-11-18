//! VehicleProfileResolver — root probes for the five profile axes and the
//! write-once root-owned `vehicle.json` (vehicle schema 1).
//!
//! Installation and explicit diagnostics persist root-owned hardware facts atomically.
//! Normal startup only reads this document; missing or invalid facts stay unavailable.
//!
//! Defaults are forbidden: any axis whose probe is not found or ambiguous is
//! persisted as `unknown` with a machine-readable reason. Never a guess.

use std::path::Path;

use anyhow::{Context, Result};

use crate::secure_fs::Directory;
use anyhow::ensure;
use serde::{Deserialize, Serialize};

pub const VEHICLE_PROFILE_SCHEMA_VERSION: u32 = 1;
pub const MAX_VEHICLE_PROFILE_BYTES: usize = 4096;
const VEHICLE_PROFILE_FILE: &str = "vehicle.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VehicleProfileDocument {
    pub schema_version: u32,
    pub facts: VehicleProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VehicleProfile {
    pub chip: Fact<Chip>,
    pub vehicle: Fact<Vehicle>,
    pub android: Fact<AndroidVersion>,
    pub powertrain: Fact<Powertrain>,
    pub market: Fact<Market>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Fact<T> {
    Known(Known<T>),
    Unknown(Unknown),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Known<T> {
    pub value: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unknown {
    pub unknown: UnknownReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnknownReason {
    ProbeUnavailable,
    PermissionDenied,
    UnrecognizedValue,
    ConflictingSources,
    MalformedOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Chip {
    #[serde(rename = "8155")]
    Qualcomm8155,
    #[serde(rename = "nxp")]
    Nxp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Vehicle {
    Free,
    Dreamer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidVersion {
    Nine,
    Eleven,
}

impl Serialize for AndroidVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for AndroidVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            9 => Ok(Self::Nine),
            11 => Ok(Self::Eleven),
            _ => Err(serde::de::Error::custom("unsupported Android version")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Powertrain {
    Ev,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Market {
    China,
    Global,
}

impl Chip {
    pub fn as_str(self) -> String {
        match self {
            Self::Qualcomm8155 => "8155",
            Self::Nxp => "nxp",
        }
        .to_string()
    }
}

impl Vehicle {
    pub fn as_str(self) -> String {
        match self {
            Self::Free => "free",
            Self::Dreamer => "dreamer",
        }
        .to_string()
    }
}

impl AndroidVersion {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Nine => 9,
            Self::Eleven => 11,
        }
    }
}

impl Powertrain {
    pub fn as_str(self) -> String {
        match self {
            Self::Ev => "ev",
            Self::Hybrid => "hybrid",
        }
        .to_string()
    }
}

impl Market {
    pub fn as_str(self) -> String {
        match self {
            Self::China => "china",
            Self::Global => "global",
        }
        .to_string()
    }
}

impl VehicleProfileDocument {
    pub fn parse_canonical(exact_bytes: &[u8]) -> Result<Self> {
        ensure!(
            exact_bytes.len() <= MAX_VEHICLE_PROFILE_BYTES,
            "vehicle profile exceed byte bound"
        );
        let document: Self = serde_json::from_slice(exact_bytes)
            .context("vehicle profile are not exact schema 1 JSON")?;
        ensure!(
            document.schema_version == VEHICLE_PROFILE_SCHEMA_VERSION,
            "unsupported facts schema"
        );
        let canonical =
            serde_json::to_vec(&document).context("serialize canonical vehicle profile")?;
        ensure!(
            canonical == exact_bytes,
            "vehicle profile are not canonical compact JSON"
        );
        Ok(document)
    }
}

/// The app-readable mode of the persisted profile (root-owned).
pub const VEHICLE_PROFILE_MODE: u32 = 0o644;

/// How each axis is probed. `getprop` output for missing props is an empty
/// string, so `None` models "source not found" while `Some` carries the raw
/// value (trimmed).
pub trait PropSource {
    fn prop(&self, name: &str) -> Option<String>;
}

/// Production source: read the fixed Android property API directly. The
/// property service is available before the daemon starts at post-fs-data.
pub struct Getprop;

impl PropSource for Getprop {
    fn prop(&self, name: &str) -> Option<String> {
        android_property(name)
    }
}

#[cfg(target_os = "android")]
fn android_property(name: &str) -> Option<String> {
    use std::ffi::{CStr, CString};
    const PROPERTY_VALUE_MAX: usize = 92;
    unsafe extern "C" {
        fn __system_property_get(
            name: *const libc::c_char,
            value: *mut libc::c_char,
        ) -> libc::c_int;
    }
    let name = CString::new(name).ok()?;
    let mut value = [0 as libc::c_char; PROPERTY_VALUE_MAX];
    let length = unsafe { __system_property_get(name.as_ptr(), value.as_mut_ptr()) };
    if length <= 0 || length as usize >= value.len() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(value.as_ptr()) }.to_str().ok()?;
    (value.len() == length as usize)
        .then(|| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(not(target_os = "android"))]
fn android_property(_name: &str) -> Option<String> {
    None
}

/// In-memory source for tests.
#[cfg(test)]
pub struct MapSource(pub std::collections::HashMap<String, String>);

#[cfg(test)]
impl PropSource for MapSource {
    fn prop(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}

// Probe candidate names. `ro.board.platform` and
// `ro.build.version.release` are AOSP-standard. OEM product and locale
// properties provide static vehicle facts, never live vehicle state.
const CHIP_PROPS: [&str; 3] = ["ro.product.board", "ro.board.platform", "ro.hardware"];
const ANDROID_PROP: &str = "ro.build.version.release";
const VEHICLE_PROPS: [&str; 3] = [
    "ro.build.product_3rdparty",
    "ro.build.product",
    "ro.product.device",
];
const POWERTRAIN_PROPS: [&str; 1] = ["persist.sys.qg.powertrain"];
const MARKET_PROPS: [&str; 1] = ["ro.product.locale"];

/// Resolve the full profile from root-readable sources.
pub fn resolve(source: &dyn PropSource) -> VehicleProfile {
    VehicleProfile {
        chip: resolve_chip(source),
        vehicle: resolve_vehicle(source),
        android: resolve_android(source),
        powertrain: resolve_powertrain(source),
        market: resolve_market(source),
    }
}

/// Blanket helpers: map an unknown axis reason onto any `Fact<T>`.
fn unavailable<T>() -> Fact<T> {
    unknown_fact(UnknownReason::ProbeUnavailable)
}

fn unknown_fact<T>(reason: UnknownReason) -> Fact<T> {
    Fact::Unknown(Unknown { unknown: reason })
}

/// All present props among `names` (for conflict detection).
fn all_present(source: &dyn PropSource, names: &[&str]) -> Vec<String> {
    names.iter().filter_map(|name| source.prop(name)).collect()
}

fn normalized_property(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn resolve_chip(source: &dyn PropSource) -> Fact<Chip> {
    const TOKENS_8155: [&str; 3] = ["sa8155", "msmnile", "msmnile_gvmq"];
    const TOKENS_NXP: [&str; 2] = ["imx8", "nxp"];
    let found = all_present(source, &CHIP_PROPS);
    if found.is_empty() {
        return unavailable();
    }
    let mut resolved = None;
    for raw in found {
        let value = normalized_property(&raw);
        // Sources are examined in declared priority order. Unknown noise may
        // fall through to a later definitive source, while two recognized
        // but contradictory identities fail closed.
        let mapped = if TOKENS_8155.contains(&value.as_str()) {
            Some(Chip::Qualcomm8155)
        } else if TOKENS_NXP.contains(&value.as_str()) {
            Some(Chip::Nxp)
        } else {
            None
        };
        if mapped.is_none()
            && TOKENS_8155
                .iter()
                .chain(TOKENS_NXP.iter())
                .any(|token| value.contains(token))
        {
            // An authority token embedded in a longer value (prefix, suffix
            // or infix) is a smuggling attempt, not noise: fail closed even
            // when a higher-priority source already resolved.
            return unknown_fact(UnrecognizedValue);
        }
        match (mapped, resolved) {
            (None, Some(_)) => continue, // unknown source doesn't override a known one
            (None, None) => {}
            (Some(mapped), Some(previous)) if previous != mapped => {
                return unknown_fact(ConflictingSources);
            }
            (Some(mapped), _) => resolved = Some(mapped),
        }
    }
    resolved
        .map(|value| Fact::Known(Known { value }))
        .unwrap_or_else(|| unknown_fact(UnrecognizedValue))
}

fn resolve_vehicle(source: &dyn PropSource) -> Fact<Vehicle> {
    let found = all_present(source, &VEHICLE_PROPS);
    if found.is_empty() {
        return unavailable();
    }
    // Exact Voyah product codes supported by the profile schema:
    //   Free:    f0506h (A9), f0501h (NXP), f6802h/f6805h/f6811 (A11)
    //   Dreamer: f0505h (A9), f6804h (A11)
    // ro.build.product on A11 is the generic "msmnile_gvmq" for both, so the
    // 3rdparty product code (f68xx) is the only A11 differentiator and is
    // probed first.
    let mut resolved: Option<Vehicle> = None;
    for raw in &found {
        let value = normalized_property(raw);
        let mapped = if matches!(
            value.as_str(),
            "f0506h" | "f0501h" | "f6802h" | "f6805h" | "f6811"
        ) {
            Some(Vehicle::Free)
        } else if matches!(value.as_str(), "f0505h" | "f6804h") {
            Some(Vehicle::Dreamer)
        } else {
            None
        };
        match (mapped, resolved, value.as_str()) {
            // The exact documented generic A11 product carries no vehicle
            // identity and cannot override a recognized 3rd-party authority.
            (None, _, "msmnile_gvmq") => {}
            (None, Some(_), _) => return unknown_fact(UnrecognizedValue),
            (None, None, _) => {}
            (Some(mapped), Some(previous), _) if previous != mapped => {
                return unknown_fact(ConflictingSources);
            }
            (Some(mapped), _, _) => resolved = Some(mapped),
        }
    }
    match resolved {
        Some(value) => Fact::Known(Known { value }),
        None => unknown_fact(UnrecognizedValue),
    }
}

fn resolve_android(source: &dyn PropSource) -> Fact<AndroidVersion> {
    let Some(raw) = source.prop(ANDROID_PROP) else {
        return unavailable();
    };
    let major = raw
        .trim()
        .split('.')
        .next()
        .and_then(|part| part.parse::<u8>().ok());
    match major {
        Some(9) => Fact::Known(Known {
            value: AndroidVersion::Nine,
        }),
        Some(11) => Fact::Known(Known {
            value: AndroidVersion::Eleven,
        }),
        Some(_) => unknown_fact(UnrecognizedValue),
        None => unknown_fact(MalformedOutput),
    }
}

fn resolve_powertrain(source: &dyn PropSource) -> Fact<Powertrain> {
    let found = all_present(source, &POWERTRAIN_PROPS);
    if found.is_empty() {
        return unavailable();
    }
    let mut resolved: Option<Powertrain> = None;
    for raw in &found {
        let value = raw.to_ascii_lowercase();
        let mapped = if value == "ev" || value == "electric" {
            Some(Powertrain::Ev)
        } else if value == "hybrid" || value == "reev" {
            Some(Powertrain::Hybrid)
        } else {
            None
        };
        match (mapped, resolved) {
            (None, _) => return unknown_fact(UnrecognizedValue),
            (Some(mapped), Some(previous)) if previous != mapped => {
                return unknown_fact(ConflictingSources);
            }
            (Some(mapped), _) => resolved = Some(mapped),
        }
    }
    match resolved {
        Some(value) => Fact::Known(Known { value }),
        None => unavailable(),
    }
}

fn resolve_market(source: &dyn PropSource) -> Fact<Market> {
    let found = all_present(source, &MARKET_PROPS);
    if found.is_empty() {
        return unavailable();
    }
    // Only exact supported locale values identify a market. Wi-Fi country and
    // `en-US` are not vehicle-market authority and remain excluded.
    let mut resolved: Option<Market> = None;
    for raw in &found {
        let value = normalized_property(raw);
        let mapped = match value.as_str() {
            "zh-cn" => Some(Market::China),
            "ru-ru" | "ar-sa" => Some(Market::Global),
            _ => None,
        };
        match (mapped, resolved) {
            (None, _) => return unknown_fact(UnrecognizedValue),
            (Some(mapped), Some(previous)) if previous != mapped => {
                return unknown_fact(ConflictingSources);
            }
            (Some(mapped), _) => resolved = Some(mapped),
        }
    }
    match resolved {
        Some(value) => Fact::Known(Known { value }),
        None => unavailable(),
    }
}

use UnknownReason::{ConflictingSources, MalformedOutput, UnrecognizedValue};

/// Serialize the profile document to canonical compact JSON (schema 1).
pub fn canonical_bytes(profile: &VehicleProfile) -> Result<Vec<u8>> {
    serde_json::to_vec(&VehicleProfileDocument {
        schema_version: VEHICLE_PROFILE_SCHEMA_VERSION,
        facts: profile.clone(),
    })
    .context("serialize vehicle profile")
}

fn publish_profile(dir: &Directory, bytes: &[u8]) -> Result<()> {
    publish_profile_with(dir, bytes, || Ok(()))
}

fn publish_profile_with<F>(dir: &Directory, bytes: &[u8], before_rename: F) -> Result<()>
where
    F: FnOnce() -> std::io::Result<()>,
{
    dir.write_atomic_with(
        VEHICLE_PROFILE_FILE,
        bytes,
        VEHICLE_PROFILE_MODE,
        before_rename,
    )
    .context("publish vehicle.json atomically")
}

/// Read the installed profile without any hardware probe or automatic repair.
pub fn ensure_vehicle_profile(root_zone: &Path) -> Result<VehicleProfileDocument> {
    let dir = Directory::open(root_zone).context("open root zone for cached profile")?;
    let bytes = dir
        .read_trusted(
            VEHICLE_PROFILE_FILE,
            MAX_VEHICLE_PROFILE_BYTES,
            VEHICLE_PROFILE_MODE,
        )
        .context("read installed vehicle.json")?;
    VehicleProfileDocument::parse_canonical(&bytes)
}

/// The audited operator diagnostic (`--recompute-profile`): intentionally
/// rewrite `vehicle.json` from fresh root probes. The recompute is logged to
/// the daemon log; the operator confirmation is running the command itself.
pub fn recompute_vehicle_profile(root_zone: &Path) -> Result<VehicleProfileDocument> {
    recompute_with(root_zone, &Getprop, || {
        crate::powertrain::probe().ok().flatten()
    })
}

fn recompute_with(
    root_zone: &Path,
    source: &dyn PropSource,
    probe: impl FnOnce() -> Option<&'static str>,
) -> Result<VehicleProfileDocument> {
    let dir = Directory::open(root_zone).context("open root zone for profile recompute")?;
    let mut profile = resolve(source);
    profile.powertrain = hardware_powertrain(&profile.powertrain, probe());
    let bytes = canonical_bytes(&profile)?;
    publish_profile(&dir, &bytes).context("rewrite vehicle.json")?;
    VehicleProfileDocument::parse_canonical(&bytes)
}

fn hardware_powertrain(property: &Fact<Powertrain>, hardware: Option<&str>) -> Fact<Powertrain> {
    let value = match hardware {
        Some("ev") => Powertrain::Ev,
        Some("hybrid") => Powertrain::Hybrid,
        _ => return unavailable(),
    };
    if matches!(property, Fact::Known(Known { value: property }) if *property != value) {
        return unknown_fact(ConflictingSources);
    }
    Fact::Known(Known { value })
}

/// Static hardware facts are reusable only while all current identity axes agree.
pub fn cached_powertrain(root_zone: &Path) -> Result<Option<&'static str>> {
    cached_powertrain_with(root_zone, &Getprop)
}

pub fn cached_powertrain_with(
    root_zone: &Path,
    source: &dyn PropSource,
) -> Result<Option<&'static str>> {
    let saved = ensure_vehicle_profile(root_zone)?.facts;
    let current = resolve(source);
    ensure!(
        saved.chip == current.chip
            && matches!(current.chip, Fact::Known(_))
            && saved.vehicle == current.vehicle
            && matches!(current.vehicle, Fact::Known(_))
            && saved.android == current.android
            && matches!(current.android, Fact::Known(_))
            && saved.market == current.market
            && matches!(current.market, Fact::Known(_)),
        "installed vehicle identity differs from current probes"
    );
    if let Fact::Known(Known { value }) = current.powertrain {
        ensure!(
            saved.powertrain == Fact::Known(Known { value }),
            "installed powertrain conflicts with property"
        );
    }
    Ok(match saved.powertrain {
        Fact::Known(Known {
            value: Powertrain::Hybrid,
        }) => Some("hybrid"),
        Fact::Known(Known {
            value: Powertrain::Ev,
        }) => Some("ev"),
        Fact::Unknown(_) => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn source(pairs: &[(&str, &str)]) -> MapSource {
        MapSource(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        )
    }

    fn identity() -> MapSource {
        source(&[
            ("ro.board.platform", "sa8155"),
            ("ro.build.product", "f0506h"),
            ("ro.build.version.release", "9"),
            ("ro.product.locale", "zh-CN"),
        ])
    }

    #[test]
    fn install_then_repeated_boots_use_cached_hybrid_without_nv_reads() {
        let root = tempdir().unwrap();
        let reads = std::cell::Cell::new(0);
        recompute_with(root.path(), &identity(), || {
            reads.set(reads.get() + 1);
            Some("hybrid")
        })
        .unwrap();
        for _ in 0..3 {
            assert_eq!(
                cached_powertrain_with(root.path(), &identity()).unwrap(),
                Some("hybrid")
            );
            ensure_vehicle_profile(root.path()).unwrap();
        }
        assert_eq!(reads.get(), 1, "only installation may run the NV probe");
        // Explicit refresh changes the fact; ordinary reads never repair it.
        recompute_with(root.path(), &identity(), || {
            reads.set(reads.get() + 1);
            Some("ev")
        })
        .unwrap();
        assert_eq!(
            cached_powertrain_with(root.path(), &identity()).unwrap(),
            Some("ev")
        );
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn missing_corrupt_symlink_bad_mode_and_copied_profile_fail_closed() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        let profile = root.path().join("vehicle.json");
        assert!(cached_powertrain_with(root.path(), &identity()).is_err());
        assert!(!profile.exists(), "normal boot must not create a profile");
        recompute_with(root.path(), &identity(), || Some("hybrid")).unwrap();
        let bytes = fs::read(&profile).unwrap();
        for hostile in [b"{".as_slice(), b"{}", b"null"] {
            fs::write(&profile, hostile).unwrap();
            assert!(cached_powertrain_with(root.path(), &identity()).is_err());
        }
        fs::write(&profile, &bytes).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(cached_powertrain_with(root.path(), &identity()).is_err());
        fs::set_permissions(&profile, fs::Permissions::from_mode(VEHICLE_PROFILE_MODE)).unwrap();
        for (key, value) in [
            ("ro.board.platform", "nxp"),
            ("ro.build.product", "f0505h"),
            ("ro.build.version.release", "11"),
            ("ro.product.locale", "ru-RU"),
            ("persist.sys.qg.powertrain", "ev"),
        ] {
            let mut other = identity();
            other.0.insert(key.into(), value.into());
            assert!(
                cached_powertrain_with(root.path(), &other).is_err(),
                "{key}"
            );
        }
        fs::rename(&profile, root.path().join("copied.json")).unwrap();
        symlink(root.path().join("copied.json"), &profile).unwrap();
        assert!(cached_powertrain_with(root.path(), &identity()).is_err());
    }

    #[test]
    fn unknown_and_contradictory_installation_never_default_to_hybrid() {
        let root = tempdir().unwrap();
        recompute_with(root.path(), &identity(), || None).unwrap();
        assert_eq!(
            cached_powertrain_with(root.path(), &identity()).unwrap(),
            None
        );
        let mut contradictory = identity();
        contradictory
            .0
            .insert("persist.sys.qg.powertrain".into(), "ev".into());
        let saved = recompute_with(root.path(), &contradictory, || Some("hybrid")).unwrap();
        assert!(matches!(saved.facts.powertrain, Fact::Unknown(_)));
        assert!(cached_powertrain_with(root.path(), &contradictory).is_err());
    }

    #[test]
    fn unknown_probes_never_default() {
        let profile = resolve(&source(&[]));
        let Fact::Unknown(_) = profile.chip else {
            panic!("chip");
        };
        let Fact::Unknown(_) = profile.vehicle else {
            panic!("vehicle");
        };
        let Fact::Unknown(_) = profile.android else {
            panic!("android");
        };
        let Fact::Unknown(_) = profile.powertrain else {
            panic!("powertrain");
        };
        let Fact::Unknown(_) = profile.market else {
            panic!("market");
        };
        // Canonical output must equal the canonical contract fixture shape.
        let bytes = canonical_bytes(&profile).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"schemaVersion\":1,\"facts\":{\"chip\":{\"unknown\":\"probe-unavailable\"},\
             \"vehicle\":{\"unknown\":\"probe-unavailable\"},\
             \"android\":{\"unknown\":\"probe-unavailable\"},\
             \"powertrain\":{\"unknown\":\"probe-unavailable\"},\
             \"market\":{\"unknown\":\"probe-unavailable\"}}}"
        );
    }

    #[test]
    fn known_probes_map_to_catalog_vocabulary() {
        let profile = resolve(&source(&[
            ("ro.product.board", "sa8155"),
            ("ro.build.version.release", "9"),
            ("ro.build.product", "f0506h"),
            ("ro.product.locale", "zh-CN"),
        ]));
        assert!(matches!(
            profile.chip,
            Fact::Known(Known {
                value: Chip::Qualcomm8155
            })
        ));
        assert!(matches!(
            profile.android,
            Fact::Known(Known {
                value: AndroidVersion::Nine
            })
        ));
        assert!(matches!(
            profile.vehicle,
            Fact::Known(Known {
                value: Vehicle::Free
            })
        ));
        // Powertrain is live vehicle state, not a build property, so this axis
        // remains unavailable without its separate runtime probe.
        assert!(matches!(profile.powertrain, Fact::Unknown(_)));
        assert!(matches!(
            profile.market,
            Fact::Known(Known {
                value: Market::China
            })
        ));
    }

    #[test]
    fn chip_falls_back_to_hardware_and_maps_nxp() {
        let profile = resolve(&source(&[("ro.hardware", "nxp")]));
        assert!(matches!(
            profile.chip,
            Fact::Known(Known { value: Chip::Nxp })
        ));
    }

    #[test]
    fn chip_maps_msmnile_codename_to_8155() {
        // `msmnile` is the supported platform code for the 8155 profile.
        let profile = resolve(&source(&[("ro.board.platform", "msmnile")]));
        assert!(matches!(
            profile.chip,
            Fact::Known(Known {
                value: Chip::Qualcomm8155
            })
        ));
    }

    #[test]
    fn chip_exact_allowlists_accept_case_and_surrounding_whitespace() {
        for value in [" SA8155 ", "MsMnIlE", " msmnile_GVMQ "] {
            let profile = resolve(&source(&[("ro.board.platform", value)]));
            assert!(matches!(
                profile.chip,
                Fact::Known(Known {
                    value: Chip::Qualcomm8155
                })
            ));
        }
        for value in [" IMX8 ", "NxP"] {
            let profile = resolve(&source(&[("ro.board.platform", value)]));
            assert!(matches!(
                profile.chip,
                Fact::Known(Known { value: Chip::Nxp })
            ));
        }
    }

    #[test]
    fn chip_exact_allowlists_reject_prefix_suffix_and_embedded_values() {
        for authority in ["sa8155", "msmnile", "msmnile_gvmq", "imx8", "nxp"] {
            for hostile in [
                format!("prefix-{authority}"),
                format!("{authority}-suffix"),
                format!("prefix-{authority}-suffix"),
            ] {
                let profile = resolve(&source(&[("ro.board.platform", &hostile)]));
                assert!(matches!(
                    profile.chip,
                    Fact::Unknown(Unknown {
                        unknown: UnrecognizedValue
                    })
                ));
            }
        }
        let malformed_lower_authority = resolve(&source(&[
            ("ro.product.board", "sa8155"),
            ("ro.board.platform", "msmnile-suffix"),
        ]));
        assert!(matches!(
            malformed_lower_authority.chip,
            Fact::Unknown(Unknown {
                unknown: UnrecognizedValue
            })
        ));
    }

    #[test]
    fn chip_falls_through_unknown_noise_and_rejects_recognized_conflict() {
        let fallback = resolve(&source(&[
            ("ro.product.board", "generic-board"),
            ("ro.board.platform", "msmnile"),
        ]));
        assert!(matches!(
            fallback.chip,
            Fact::Known(Known {
                value: Chip::Qualcomm8155
            })
        ));

        let conflict = resolve(&source(&[
            ("ro.product.board", "sa8155"),
            ("ro.board.platform", "imx8"),
        ]));
        assert!(matches!(
            conflict.chip,
            Fact::Unknown(Unknown {
                unknown: ConflictingSources
            })
        ));
    }

    #[test]
    fn chip_maps_imx8_to_nxp() {
        // `imx8` is the supported platform code for the NXP profile.
        let profile = resolve(&source(&[("ro.board.platform", "imx8")]));
        assert!(matches!(
            profile.chip,
            Fact::Known(Known { value: Chip::Nxp })
        ));
    }

    #[test]
    fn vehicle_maps_a11_3rdparty_codes() {
        // A11 Free = f6802h, A11 Dreamer = f6804h (ro.build.product_3rdparty).
        let free = resolve(&source(&[("ro.build.product_3rdparty", "f6802h")]));
        assert!(matches!(
            free.vehicle,
            Fact::Known(Known {
                value: Vehicle::Free
            })
        ));
        let dreamer = resolve(&source(&[("ro.build.product_3rdparty", "f6804h")]));
        assert!(matches!(
            dreamer.vehicle,
            Fact::Known(Known {
                value: Vehicle::Dreamer
            })
        ));
    }

    #[test]
    fn vehicle_exact_allowlists_accept_case_and_surrounding_whitespace() {
        for (code, expected) in [
            (" F0506H ", Vehicle::Free),
            ("f0501H", Vehicle::Free),
            (" F6802h", Vehicle::Free),
            ("f6805H ", Vehicle::Free),
            (" F6811 ", Vehicle::Free),
            (" F0505H ", Vehicle::Dreamer),
            ("f6804H", Vehicle::Dreamer),
        ] {
            let profile = resolve(&source(&[("ro.build.product_3rdparty", code)]));
            assert!(matches!(
                profile.vehicle,
                Fact::Known(Known { value }) if value == expected
            ));
        }
    }

    #[test]
    fn vehicle_exact_allowlists_reject_prefix_suffix_and_embedded_values() {
        for authority in [
            "f0506h", "f0501h", "f6802h", "f6805h", "f6811", "f0505h", "f6804h",
        ] {
            for hostile in [
                format!("prefix-{authority}"),
                format!("{authority}-suffix"),
                format!("prefix-{authority}-suffix"),
            ] {
                let profile = resolve(&source(&[("ro.build.product_3rdparty", &hostile)]));
                assert!(matches!(
                    profile.vehicle,
                    Fact::Unknown(Unknown {
                        unknown: UnrecognizedValue
                    })
                ));
            }
        }
    }

    #[test]
    fn vehicle_a11_authority_ignores_documented_generic_product() {
        for (code, expected) in [("f6802h", Vehicle::Free), ("f6804h", Vehicle::Dreamer)] {
            let profile = resolve(&source(&[
                ("ro.build.product_3rdparty", code),
                ("ro.build.product", "msmnile_gvmq"),
            ]));
            assert!(matches!(
                profile.vehicle,
                Fact::Known(Known { value }) if value == expected
            ));
        }
    }

    #[test]
    fn vehicle_ignores_only_exact_normalized_generic_product() {
        for generic in ["msmnile_gvmq", " MSMNILE_GVMQ "] {
            let profile = resolve(&source(&[
                ("ro.build.product_3rdparty", "f6802h"),
                ("ro.build.product", generic),
            ]));
            assert!(matches!(
                profile.vehicle,
                Fact::Known(Known {
                    value: Vehicle::Free
                })
            ));
        }
        for hostile in [
            "prefix-msmnile_gvmq",
            "msmnile_gvmq-suffix",
            "prefix-msmnile_gvmq-suffix",
        ] {
            let profile = resolve(&source(&[("ro.build.product", hostile)]));
            assert!(matches!(
                profile.vehicle,
                Fact::Unknown(Unknown {
                    unknown: UnrecognizedValue
                })
            ));

            let profile = resolve(&source(&[
                ("ro.build.product_3rdparty", "f6802h"),
                ("ro.build.product", hostile),
            ]));
            assert!(matches!(
                profile.vehicle,
                Fact::Unknown(Unknown {
                    unknown: UnrecognizedValue
                })
            ));
        }
    }

    #[test]
    fn vehicle_rejects_conflicting_recognized_identities() {
        let profile = resolve(&source(&[
            ("ro.build.product_3rdparty", "f6802h"),
            ("ro.product.device", "f6804h"),
        ]));
        assert!(matches!(
            profile.vehicle,
            Fact::Unknown(Unknown {
                unknown: ConflictingSources
            })
        ));
    }

    #[test]
    fn market_exact_allowlist_accepts_case_and_surrounding_whitespace() {
        for (locale, expected) in [
            (" ZH-cn ", Market::China),
            (" Ru-RU", Market::Global),
            ("AR-sa ", Market::Global),
        ] {
            let profile = resolve(&source(&[("ro.product.locale", locale)]));
            assert!(matches!(
                profile.market,
                Fact::Known(Known { value }) if value == expected
            ));
        }
    }

    #[test]
    fn market_exact_allowlist_rejects_prefix_suffix_embedded_and_unreliable_locale() {
        for locale in [
            "prefix-zh-CN",
            "zh-CN-suffix",
            "prefix-ru-RU-suffix",
            "brutal",
            "not-russian",
            "xx-CN-evil",
            "en-US",
            "zh_CN",
            "zh",
            "CN",
        ] {
            let profile = resolve(&source(&[("ro.product.locale", locale)]));
            assert!(matches!(
                profile.market,
                Fact::Unknown(Unknown {
                    unknown: UnrecognizedValue
                })
            ));
        }
    }

    #[test]
    fn unrecognized_values_report_reason() {
        let profile = resolve(&source(&[
            ("ro.board.platform", "tegra"),
            ("ro.build.version.release", "13"),
        ]));
        assert!(matches!(
            profile.chip,
            Fact::Unknown(Unknown {
                unknown: UnknownReason::UnrecognizedValue
            })
        ));
        assert!(matches!(
            profile.android,
            Fact::Unknown(Unknown {
                unknown: UnknownReason::UnrecognizedValue
            })
        ));
    }

    #[test]
    fn malformed_android_release_is_reported() {
        let profile = resolve(&source(&[("ro.build.version.release", "nine")]));
        assert!(matches!(
            profile.android,
            Fact::Unknown(Unknown {
                unknown: UnknownReason::MalformedOutput
            })
        ));
    }

    #[test]
    fn conflicting_sources_report_conflict() {
        let profile = resolve(&source(&[
            ("ro.build.product", "f0506h"),
            ("ro.product.device", "f0505h"),
        ]));
        assert!(matches!(
            profile.vehicle,
            Fact::Unknown(Unknown {
                unknown: UnknownReason::ConflictingSources
            })
        ));
    }

    #[test]
    fn ensure_writes_once_and_never_rewrites() {
        let root = tempdir().unwrap();
        // First call resolves (on a host: all probes unavailable) and writes.
        recompute_vehicle_profile(root.path()).unwrap();
        // An operator/manual profile on disk must win over fresh probes.
        let manual =
            canonical_bytes(&resolve(&source(&[("ro.board.platform", "sa8155")]))).unwrap();
        fs::write(root.path().join("vehicle.json"), &manual).unwrap();
        fs::set_permissions(
            root.path().join("vehicle.json"),
            fs::Permissions::from_mode(VEHICLE_PROFILE_MODE),
        )
        .unwrap();
        let second = ensure_vehicle_profile(root.path()).unwrap();
        assert!(matches!(
            second.facts.chip,
            Fact::Known(Known {
                value: Chip::Qualcomm8155
            })
        ));
        assert_eq!(
            fs::read(root.path().join("vehicle.json")).unwrap(),
            manual,
            "existing vehicle.json must never be rewritten"
        );
        let mode = fs::metadata(root.path().join("vehicle.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, VEHICLE_PROFILE_MODE);
    }

    #[test]
    fn recompute_rewrites() {
        let root = tempdir().unwrap();
        // A manual known profile on disk.
        let manual =
            canonical_bytes(&resolve(&source(&[("ro.board.platform", "sa8155")]))).unwrap();
        fs::write(root.path().join("vehicle.json"), &manual).unwrap();
        fs::set_permissions(
            root.path().join("vehicle.json"),
            fs::Permissions::from_mode(VEHICLE_PROFILE_MODE),
        )
        .unwrap();
        // The diagnostic recompute intentionally rewrites from fresh probes
        // (on a host those are all unavailable, so the content changes).
        let recomputed = recompute_vehicle_profile(root.path()).unwrap();
        let after = fs::read(root.path().join("vehicle.json")).unwrap();
        assert_eq!(after, canonical_bytes(&recomputed.facts).unwrap());
        assert_ne!(after, manual);
    }

    #[test]
    fn failed_atomic_profile_publication_preserves_old_file() {
        let empty_root = tempdir().unwrap();
        let empty_dir = Directory::open(empty_root.path()).unwrap();
        let candidate =
            canonical_bytes(&resolve(&source(&[("ro.board.platform", "imx8")]))).unwrap();
        assert!(publish_profile_with(&empty_dir, &candidate, || {
            Err(std::io::Error::other("simulated initial interruption"))
        })
        .is_err());
        assert!(!empty_root.path().join("vehicle.json").exists());
        assert!(!empty_root.path().join(".vehicle.json.tmp").exists());

        let root = tempdir().unwrap();
        let old = canonical_bytes(&resolve(&source(&[("ro.board.platform", "sa8155")]))).unwrap();
        let new = canonical_bytes(&resolve(&source(&[("ro.board.platform", "imx8")]))).unwrap();
        let dir = Directory::open(root.path()).unwrap();
        publish_profile(&dir, &old).unwrap();

        let error = publish_profile_with(&dir, &new, || {
            Err(std::io::Error::other("simulated interruption"))
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("publish vehicle.json atomically"));
        assert_eq!(fs::read(root.path().join("vehicle.json")).unwrap(), old);
        assert!(!root.path().join(".vehicle.json.tmp").exists());
    }

    #[test]
    fn atomic_profile_publication_keeps_exact_mode_and_single_link() {
        use std::os::unix::fs::MetadataExt;

        let root = tempdir().unwrap();
        let bytes = canonical_bytes(&resolve(&source(&[("ro.board.platform", "sa8155")]))).unwrap();
        let dir = Directory::open(root.path()).unwrap();
        publish_profile(&dir, &bytes).unwrap();
        let metadata = fs::metadata(root.path().join("vehicle.json")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, VEHICLE_PROFILE_MODE);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.gid(), unsafe { libc::getegid() });
    }

    #[test]
    fn production_property_probe_has_no_external_process() {
        let source = include_str!("vehicle_profile.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("Command::new"));
        assert!(!production.contains("/system/bin/getprop"));
        assert!(production.contains("__system_property_get"));
    }
}
