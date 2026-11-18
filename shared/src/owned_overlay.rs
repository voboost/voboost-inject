//! Native read-only observation of the bounded product-owned resource overlays.
use crate::fixed_process;
use std::time::Duration;
pub const OWNER: &str = "com.qinggan.app.setting";
pub const PACKAGE: &str = "ru.voboost.translation.setting";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Owner {
    Setting,
    Launcher,
    VehicleSetting,
    SettingNetwork,
    SystemUi,
    BluetoothPhone,
    Media,
    EnSetting,
    EnLauncher,
    EnSystemUi,
    EnMedia,
}
impl Owner {
    pub const CANDIDATE_LIMIT: usize = 2;
    pub const ALL: [Self; 7] = [
        Self::Setting,
        Self::Launcher,
        Self::VehicleSetting,
        Self::SettingNetwork,
        Self::SystemUi,
        Self::BluetoothPhone,
        Self::Media,
    ];
    pub const ALL_RESOURCES: [Self; 11] = [
        Self::Setting,
        Self::Launcher,
        Self::VehicleSetting,
        Self::SettingNetwork,
        Self::SystemUi,
        Self::BluetoothPhone,
        Self::Media,
        Self::EnSetting,
        Self::EnLauncher,
        Self::EnSystemUi,
        Self::EnMedia,
    ];
    pub fn agent(self) -> &'static str {
        if Self::ALL.contains(&self) {
            "i18n-ru"
        } else {
            "i18n-en"
        }
    }
    pub fn locale(self) -> &'static str {
        if Self::ALL.contains(&self) {
            "ru"
        } else {
            "en"
        }
    }
    pub fn from_agent_process(agent: &str, process: &str) -> Result<Self, String> {
        Self::ALL_RESOURCES
            .into_iter()
            .find(|o| o.agent() == agent && o.process() == process)
            .ok_or_else(|| "unknown resource agent/process".into())
    }
    pub fn from_profile_process(profile: &str, process: &str) -> Result<Self, String> {
        Self::from_agent_process(
            if profile.starts_with("en-") {
                "i18n-en"
            } else {
                "i18n-ru"
            },
            process,
        )
    }
    pub fn process(self) -> &'static str {
        match self {
            Self::Setting | Self::EnSetting => OWNER,
            Self::Launcher | Self::EnLauncher => "com.qinggan.app.launcher",
            Self::VehicleSetting => "com.qinggan.app.vehiclesetting",
            Self::SettingNetwork => "com.qinggan.app.settingnewwork",
            Self::SystemUi | Self::EnSystemUi => "com.qinggan.systemui",
            Self::BluetoothPhone => "com.qinggan.bluetoothphone",
            Self::Media | Self::EnMedia => "com.qinggan.media",
        }
    }
    pub fn from_process(process: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|owner| owner.process() == process)
            .ok_or_else(|| "unknown resource owner process".into())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Variant {
    SettingA9,
    SettingA11,
    LauncherA9,
    LauncherA11,
    VehicleSettingA9,
    VehicleSettingA11,
    SettingNetworkA9,
    SettingNetworkA11,
    SystemUiA9,
    SystemUiA11,
    BluetoothPhoneA9,
    BluetoothPhoneA11,
    MediaA9,
    MediaA11,
    EnSettingA11,
    EnLauncherA9,
    EnLauncherA11,
    EnSystemUiA9,
    EnMediaA9,
    EnMediaA11,
}
impl Variant {
    pub const ALL: [Self; 20] = [
        Self::SettingA9,
        Self::SettingA11,
        Self::LauncherA9,
        Self::LauncherA11,
        Self::VehicleSettingA9,
        Self::VehicleSettingA11,
        Self::SettingNetworkA9,
        Self::SettingNetworkA11,
        Self::SystemUiA9,
        Self::SystemUiA11,
        Self::BluetoothPhoneA9,
        Self::BluetoothPhoneA11,
        Self::MediaA9,
        Self::MediaA11,
        Self::EnSettingA11,
        Self::EnLauncherA9,
        Self::EnLauncherA11,
        Self::EnSystemUiA9,
        Self::EnMediaA9,
        Self::EnMediaA11,
    ];
    pub fn owner(self) -> Owner {
        match self {
            Self::SettingA9 | Self::SettingA11 => Owner::Setting,
            Self::LauncherA9 | Self::LauncherA11 => Owner::Launcher,
            Self::VehicleSettingA9 | Self::VehicleSettingA11 => Owner::VehicleSetting,
            Self::SettingNetworkA9 | Self::SettingNetworkA11 => Owner::SettingNetwork,
            Self::SystemUiA9 | Self::SystemUiA11 => Owner::SystemUi,
            Self::BluetoothPhoneA9 | Self::BluetoothPhoneA11 => Owner::BluetoothPhone,
            Self::MediaA9 | Self::MediaA11 => Owner::Media,
            Self::EnSettingA11 => Owner::EnSetting,
            Self::EnLauncherA9 | Self::EnLauncherA11 => Owner::EnLauncher,
            Self::EnSystemUiA9 => Owner::EnSystemUi,
            Self::EnMediaA9 | Self::EnMediaA11 => Owner::EnMedia,
        }
    }
    pub fn profile(self) -> &'static str {
        match self {
            Self::SettingA9 => "setting-a9",
            Self::SettingA11 => "setting-a11",
            Self::LauncherA9 => "launcher-a9",
            Self::LauncherA11 => "launcher-a11",
            Self::VehicleSettingA9 => "vehiclesetting-a9",
            Self::VehicleSettingA11 => "vehiclesetting-a11",
            Self::SettingNetworkA9 => "settingnetwork-a9",
            Self::SettingNetworkA11 => "settingnetwork-a11",
            Self::SystemUiA9 => "systemui-a9",
            Self::SystemUiA11 => "systemui-a11",
            Self::BluetoothPhoneA9 => "bluetoothphone-a9",
            Self::BluetoothPhoneA11 => "bluetoothphone-a11",
            Self::MediaA9 => "media-a9",
            Self::MediaA11 => "media-a11",
            Self::EnSettingA11 => "en-setting-a11",
            Self::EnLauncherA9 => "en-launcher-a9",
            Self::EnLauncherA11 => "en-launcher-a11",
            Self::EnSystemUiA9 => "en-systemui-a9",
            Self::EnMediaA9 => "en-media-a9",
            Self::EnMediaA11 => "en-media-a11",
        }
    }
    pub fn package(self) -> &'static str {
        match self {
            Self::SettingA9 => PACKAGE,
            Self::SettingA11 => "ru.voboost.translation.setting.a11",
            Self::LauncherA9 => "ru.voboost.translation.launcher",
            Self::LauncherA11 => "ru.voboost.translation.launcher.a11",
            Self::VehicleSettingA9 => "ru.voboost.translation.vehiclesetting",
            Self::VehicleSettingA11 => "ru.voboost.translation.vehiclesetting.a11",
            Self::SettingNetworkA9 => "ru.voboost.translation.settingnetwork",
            Self::SettingNetworkA11 => "ru.voboost.translation.settingnetwork.a11",
            Self::SystemUiA9 => "ru.voboost.translation.systemui",
            Self::SystemUiA11 => "ru.voboost.translation.systemui.a11",
            Self::BluetoothPhoneA9 => "ru.voboost.translation.bluetoothphone",
            Self::BluetoothPhoneA11 => "ru.voboost.translation.bluetoothphone.a11",
            Self::MediaA9 => "ru.voboost.translation.media",
            Self::MediaA11 => "ru.voboost.translation.media.a11",
            Self::EnSettingA11 => "ru.voboost.translation.setting.a11.en",
            Self::EnLauncherA9 => "ru.voboost.translation.launcher.en",
            Self::EnLauncherA11 => "ru.voboost.translation.launcher.a11.en",
            Self::EnSystemUiA9 => "ru.voboost.translation.systemui.en",
            Self::EnMediaA9 => "ru.voboost.translation.media.en",
            Self::EnMediaA11 => "ru.voboost.translation.media.a11.en",
        }
    }
    pub fn file(self) -> &'static str {
        match self {
            Self::SettingA9 => "voboost-setting-ru.apk",
            Self::SettingA11 => "voboost-setting-ru-a11.apk",
            Self::LauncherA9 => "voboost-launcher-ru.apk",
            Self::LauncherA11 => "voboost-launcher-ru-a11.apk",
            Self::VehicleSettingA9 => "voboost-vehiclesetting-ru.apk",
            Self::VehicleSettingA11 => "voboost-vehiclesetting-ru-a11.apk",
            Self::SettingNetworkA9 => "voboost-settingnetwork-ru.apk",
            Self::SettingNetworkA11 => "voboost-settingnetwork-ru-a11.apk",
            Self::SystemUiA9 => "voboost-systemui-ru.apk",
            Self::SystemUiA11 => "voboost-systemui-ru-a11.apk",
            Self::BluetoothPhoneA9 => "voboost-bluetoothphone-ru.apk",
            Self::BluetoothPhoneA11 => "voboost-bluetoothphone-ru-a11.apk",
            Self::MediaA9 => "voboost-media-ru.apk",
            Self::MediaA11 => "voboost-media-ru-a11.apk",
            Self::EnSettingA11 => "voboost-setting-en-a11.apk",
            Self::EnLauncherA9 => "voboost-launcher-en.apk",
            Self::EnLauncherA11 => "voboost-launcher-en-a11.apk",
            Self::EnSystemUiA9 => "voboost-systemui-en.apk",
            Self::EnMediaA9 => "voboost-media-en.apk",
            Self::EnMediaA11 => "voboost-media-en-a11.apk",
        }
    }
    pub fn staged(self) -> &'static str {
        match self {
            Self::SettingA9 => ".voboost-setting-ru.apk.staged",
            Self::SettingA11 => ".voboost-setting-ru-a11.apk.staged",
            Self::LauncherA9 => ".voboost-launcher-ru.apk.staged",
            Self::LauncherA11 => ".voboost-launcher-ru-a11.apk.staged",
            Self::VehicleSettingA9 => ".voboost-vehiclesetting-ru.apk.staged",
            Self::VehicleSettingA11 => ".voboost-vehiclesetting-ru-a11.apk.staged",
            Self::SettingNetworkA9 => ".voboost-settingnetwork-ru.apk.staged",
            Self::SettingNetworkA11 => ".voboost-settingnetwork-ru-a11.apk.staged",
            Self::SystemUiA9 => ".voboost-systemui-ru.apk.staged",
            Self::SystemUiA11 => ".voboost-systemui-ru-a11.apk.staged",
            Self::BluetoothPhoneA9 => ".voboost-bluetoothphone-ru.apk.staged",
            Self::BluetoothPhoneA11 => ".voboost-bluetoothphone-ru-a11.apk.staged",
            Self::MediaA9 => ".voboost-media-ru.apk.staged",
            Self::MediaA11 => ".voboost-media-ru-a11.apk.staged",
            Self::EnSettingA11 => ".voboost-setting-en-a11.apk.staged",
            Self::EnLauncherA9 => ".voboost-launcher-en.apk.staged",
            Self::EnLauncherA11 => ".voboost-launcher-en-a11.apk.staged",
            Self::EnSystemUiA9 => ".voboost-systemui-en.apk.staged",
            Self::EnMediaA9 => ".voboost-media-en.apk.staged",
            Self::EnMediaA11 => ".voboost-media-en-a11.apk.staged",
        }
    }
    pub fn from_artifact_file(file: &str) -> Result<Self, String> {
        let (agent, base) = if let Some(base) = file.strip_prefix("resource-i18n-ru-") {
            ("i18n-ru", base)
        } else if let Some(base) = file.strip_prefix("resource-i18n-en-") {
            ("i18n-en", base)
        } else {
            return Err("owned resource filename invalid".into());
        };
        let base = base
            .strip_suffix(".apk")
            .ok_or("owned resource suffix invalid")?;
        let profile = if agent == "i18n-en" {
            format!("en-{base}")
        } else {
            base.into()
        };
        let variant = Self::from_profile(&profile)?;
        if variant.owner().agent() != agent {
            return Err("resource agent/profile differs".into());
        }
        Ok(variant)
    }
    pub fn from_profile(profile: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|v| v.profile() == profile)
            .ok_or_else(|| "unknown owned overlay profile".into())
    }
    pub fn from_package(package: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|v| v.package() == package)
            .ok_or_else(|| "unknown owned overlay package".into())
    }
}
const MAX_OUTPUT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayState {
    Enabled,
    Disabled,
    /// Native `---`: not enabled, but no precise target/idmap state is proven.
    NotEnabledUnclassified,
}

/// Parse the native Android9 `cmd overlay list --user 0` owner group.
/// No substring matching: similarly named packages and another target cannot admit ours.
pub fn parse_list(bytes: &[u8]) -> Result<OverlayState, String> {
    parse_list_for(bytes, Variant::SettingA9)
}
pub fn parse_list_for(bytes: &[u8], variant: Variant) -> Result<OverlayState, String> {
    if bytes.len() > MAX_OUTPUT {
        return Err("overlay list exceeds bound".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "overlay list is not UTF-8")?;
    let mut owner = None;
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('[') && !line.starts_with("---") {
            owner = Some(line);
            continue;
        }
        let (marker, package) = if let Some(rest) = line.strip_prefix("[x] ") {
            ("enabled", rest)
        } else if let Some(rest) = line.strip_prefix("[ ] ") {
            ("disabled", rest)
        } else if let Some(rest) = line.strip_prefix("--- ") {
            ("missing", rest)
        } else {
            return Err("unknown overlay list marker".into());
        };
        if package != variant.package() {
            continue;
        }
        if owner != Some(variant.owner().process()) {
            return Err("owned overlay has unexpected target".into());
        }
        if found.is_some() {
            return Err("duplicate owned overlay list entry".into());
        }
        found = Some(match marker {
            "enabled" => OverlayState::Enabled,
            "disabled" => OverlayState::Disabled,
            _ => OverlayState::NotEnabledUnclassified,
        });
    }
    found.ok_or_else(|| "owned overlay is not system-scanned".into())
}

pub fn observe() -> Result<OverlayState, String> {
    observe_for(Variant::SettingA9)
}
pub fn observe_for(variant: Variant) -> Result<OverlayState, String> {
    let output = fixed_process::output(
        "/system/bin/cmd",
        &["overlay", "list", "--user", "0"],
        Duration::from_secs(5),
        MAX_OUTPUT,
    )?;
    if !output.status.success() {
        return Err("overlay list command failed".into());
    }
    parse_list_for(&output.stdout, variant)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn english_variants_have_disjoint_identity_and_same_android_target() {
        for russian in Variant::ALL
            .into_iter()
            .filter(|v| v.owner().agent() == "i18n-ru")
        {
            let Ok(english) = Variant::from_profile(&format!("en-{}", russian.profile())) else {
                continue;
            };
            assert_eq!(english.owner().process(), russian.owner().process());
            assert_eq!(english.owner().agent(), "i18n-en");
            assert_eq!(english.package(), format!("{}.en", russian.package()));
            assert_ne!(english.file(), russian.file());
            assert_ne!(english.staged(), russian.staged());
            assert_eq!(
                Variant::from_artifact_file(&format!("resource-i18n-en-{}.apk", russian.profile()))
                    .unwrap(),
                english
            );
            assert_eq!(
                Variant::from_artifact_file(&format!("resource-i18n-ru-{}.apk", russian.profile()))
                    .unwrap(),
                russian
            );
            assert!(Variant::from_artifact_file(&format!(
                "resource-i18n-ru-en-{}.apk",
                russian.profile()
            ))
            .is_err());
            let both = format!(
                "{}\n[x] {}\n[ ] {}\n",
                russian.owner().process(),
                russian.package(),
                english.package()
            );
            assert_eq!(
                parse_list_for(both.as_bytes(), russian).unwrap(),
                OverlayState::Enabled
            );
            assert_eq!(
                parse_list_for(both.as_bytes(), english).unwrap(),
                OverlayState::Disabled
            );
        }
    }
    #[test]
    fn only_six_nonempty_english_delta_profiles_have_owned_paths() {
        let profiles = Variant::ALL
            .into_iter()
            .filter(|variant| variant.owner().agent() == "i18n-en")
            .map(Variant::profile)
            .collect::<Vec<_>>();
        assert_eq!(
            profiles,
            [
                "en-setting-a11",
                "en-launcher-a9",
                "en-launcher-a11",
                "en-systemui-a9",
                "en-media-a9",
                "en-media-a11"
            ]
        );
        assert!(Variant::from_artifact_file("resource-i18n-en-setting-a9.apk").is_err());
        assert!(Variant::from_artifact_file("resource-i18n-en-systemui-a11.apk").is_err());
    }
    #[test]
    fn exact_variants_require_their_own_target() {
        for variant in Variant::ALL {
            assert_eq!(Variant::from_profile(variant.profile()).unwrap(), variant);
            assert_eq!(Variant::from_package(variant.package()).unwrap(), variant);
            let own = format!("{}\n[x] {}\n", variant.owner().process(), variant.package());
            assert_eq!(
                parse_list_for(own.as_bytes(), variant).unwrap(),
                OverlayState::Enabled
            );
            let foreign = Owner::ALL
                .into_iter()
                .find(|owner| owner.process() != variant.owner().process())
                .unwrap();
            let wrong = format!("{}\n[x] {}\n", foreign.process(), variant.package());
            assert!(parse_list_for(wrong.as_bytes(), variant).is_err());
            assert!(Variant::from_package(&format!("{}.foreign", variant.package())).is_err());
        }
        assert!(Owner::from_process("com.qinggan.app.launcher.other").is_err());
        assert!(Variant::from_profile("launcher-a12").is_err());
    }
    #[test]
    fn closed_seven_owner_tuple_inventory_is_exact_and_collision_free() {
        let expected = [
            (Owner::Setting, "com.qinggan.app.setting", "setting"),
            (Owner::Launcher, "com.qinggan.app.launcher", "launcher"),
            (
                Owner::VehicleSetting,
                "com.qinggan.app.vehiclesetting",
                "vehiclesetting",
            ),
            (
                Owner::SettingNetwork,
                "com.qinggan.app.settingnewwork",
                "settingnetwork",
            ),
            (Owner::SystemUi, "com.qinggan.systemui", "systemui"),
            (
                Owner::BluetoothPhone,
                "com.qinggan.bluetoothphone",
                "bluetoothphone",
            ),
            (Owner::Media, "com.qinggan.media", "media"),
        ];
        assert_eq!(Owner::ALL.len(), expected.len());
        assert_eq!(Variant::ALL.len(), 20);
        let mut profiles = std::collections::BTreeSet::new();
        let mut packages = std::collections::BTreeSet::new();
        let mut files = std::collections::BTreeSet::new();
        for (owner, process, slug) in expected {
            assert_eq!(owner.process(), process);
            assert_eq!(Owner::from_process(process).unwrap(), owner);
            let pair: Vec<_> = Variant::ALL
                .into_iter()
                .filter(|v| v.owner() == owner)
                .collect();
            assert_eq!(pair.len(), Owner::CANDIDATE_LIMIT);
            for (index, variant) in pair.into_iter().enumerate() {
                let (profile_suffix, package_suffix, file_suffix) = if index == 0 {
                    ("a9", "", "")
                } else {
                    ("a11", ".a11", "-a11")
                };
                assert_eq!(variant.profile(), format!("{slug}-{profile_suffix}"));
                assert_eq!(
                    variant.package(),
                    format!("ru.voboost.translation.{slug}{package_suffix}")
                );
                assert_eq!(
                    variant.file(),
                    format!("voboost-{slug}-ru{file_suffix}.apk")
                );
                assert_eq!(variant.staged(), format!(".{}.staged", variant.file()));
                assert!(profiles.insert(variant.profile()));
                assert!(packages.insert(variant.package()));
                assert!(files.insert(variant.file()));
            }
        }
        assert!(Owner::from_process("com.qinggan.app.settingnetwork").is_err());
        assert!(Owner::from_process("com.qinggan.app.media").is_err());
    }
    #[test]
    fn distinct_owned_packages_are_observed_independently() {
        let raw=b"com.qinggan.app.setting\n[x] ru.voboost.translation.setting\n[ ] ru.voboost.translation.setting.a11\n";
        assert_eq!(
            parse_list_for(raw, Variant::SettingA9).unwrap(),
            OverlayState::Enabled
        );
        assert_eq!(
            parse_list_for(raw, Variant::SettingA11).unwrap(),
            OverlayState::Disabled
        );
        assert!(Variant::from_package("ru.voboost.translation.setting.fake").is_err());
        assert!(Variant::from_profile("../setting-a11").is_err());
        assert_ne!(Variant::SettingA9.file(), Variant::SettingA11.file());
    }
    #[test]
    fn duplicate_or_wrong_target_a11_cannot_admit_a9_or_a11() {
        let duplicate=b"com.qinggan.app.setting\n[x] ru.voboost.translation.setting.a11\n[ ] ru.voboost.translation.setting.a11\n";
        assert!(parse_list_for(duplicate, Variant::SettingA11).is_err());
        let foreign = b"another.target\n[x] ru.voboost.translation.setting.a11\n";
        assert!(parse_list_for(foreign, Variant::SettingA11).is_err());
        assert!(parse_list_for(foreign, Variant::SettingA9).is_err());
    }
}
