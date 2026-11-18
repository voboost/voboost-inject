use crate::{key, Result};
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use voboost_contract_core::{catalog::BuildIdentity, digest, parse_canonical, safe_path};
pub(crate) fn owner_role(executable: &str) -> Result<&'static str> {
    match executable {
        "/usr/bin/gauge" => Ok("gauge"),
        "/usr/bin/point" => Ok("point"),
        "/usr/bin/light" => Ok("light"),
        _ => Err("native controller owner unsupported".into()),
    }
}
pub(crate) fn owner_socket(root: &str, executable: &str) -> Result<String> {
    Ok(alloc::format!(
        "{root}/run/implant-{}.sock",
        owner_role(executable)?
    ))
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub chip: Option<String>,
    pub vehicle: Option<String>,
    pub powertrain: Option<String>,
    pub market: Option<String>,
    pub qnx_version: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tls {
    pub server_certificate: String,
    pub server_private_key: String,
    pub client_ca: String,
    pub client_certificate_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Listen {
    pub address: String,
    pub port: u16,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub root: String,
    pub pair_id: String,
    pub authority_epoch: String,
    pub android_public_key: String,
    pub qnx_public_key: String,
    pub ipc_secret: String,
    pub boot_identity_file: String,
    pub expected_executable: String,
    pub expected_build_ids: Vec<BuildIdentity>,
    pub profile: Profile,
    pub listen: Listen,
    pub tls: Tls,
}
impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let v: Self = parse_canonical(bytes, 16384)?;
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !safe_path(&self.root)
            || self.root.len() + 17 > 103
            || !safe_path(&self.expected_executable)
            || !safe_path(&self.boot_identity_file)
            || self.listen.port == 0
            || self.listen.address.split('.').count() != 4
            || self
                .listen
                .address
                .split('.')
                .any(|x| x.parse::<u8>().is_err())
            || ![
                &self.pair_id,
                &self.authority_epoch,
                &self.android_public_key,
                &self.qnx_public_key,
                &self.ipc_secret,
                &self.tls.client_certificate_sha256,
            ]
            .iter()
            .all(|s| digest(s))
            || self.android_public_key == self.qnx_public_key
            || self.expected_build_ids.is_empty()
            || self.expected_build_ids.len() > 8
        {
            return Err("invalid explicit native configuration".into());
        }
        #[cfg(target_os = "nto")]
        if self.boot_identity_file != crate::fs::boot_identity_path(&self.pair_id)? {
            return Err("QNX boot identity must use paired procnto RAM namespace".into());
        }
        for path in [
            &self.tls.server_certificate,
            &self.tls.server_private_key,
            &self.tls.client_ca,
        ] {
            if !safe_path(path) {
                return Err("unsafe TLS path".into());
            }
        }
        for axis in [
            &self.profile.chip,
            &self.profile.vehicle,
            &self.profile.powertrain,
            &self.profile.market,
            &self.profile.qnx_version,
        ]
        .into_iter()
        .flatten()
        {
            if !voboost_contract_core::identifier(axis, 64)
                && !axis.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
            {
                return Err("invalid local applicability profile".into());
            }
            if axis.is_empty() || axis.len() > 64 {
                return Err("local applicability bound".into());
            }
        }
        let mut prior = "";
        let mut executable = false;
        for b in &self.expected_build_ids {
            if !safe_path(&b.path)
                || b.path.as_str() <= prior
                || b.build_id.is_empty()
                || b.build_id.len() > 128
                || b.build_id.len() % 2 != 0
                || !b
                    .build_id
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
            {
                return Err("invalid native compatibility profile".into());
            }
            prior = &b.path;
            executable |= b.path == self.expected_executable;
        }
        if !executable {
            return Err("expected executable build identity missing".into());
        }
        for role in [
            crate::roots::AGENT_CATALOG,
            crate::roots::RELEASE_CATALOG,
            crate::roots::NATIVE_EXECUTABLE,
            crate::roots::RESTORE,
        ] {
            if [
                key(&self.android_public_key)?,
                key(&self.qnx_public_key)?,
                key(&self.ipc_secret)?,
            ]
            .contains(&role)
            {
                return Err("device/IPC and product authorities collide".into());
            }
        }
        if self.ipc_secret == self.android_public_key || self.ipc_secret == self.qnx_public_key {
            return Err("IPC authority must be separate".into());
        }
        Ok(())
    }
}
