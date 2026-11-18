//! OS-independent domain selection and immutable generation identity.
use crate::{
    ascii_json,
    catalog::{Applicability, Catalog, Domain, FileIdentity, Target},
    digest, hash, Result,
};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTarget {
    pub id: String,
    pub process: String,
    pub file: String,
    pub entry: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationIdentity {
    pub domain: Domain,
    pub catalog_sha256: String,
    pub selection_sha256: String,
    pub closure_sha256: String,
}
impl GenerationIdentity {
    pub fn generation_id(&self) -> Result<String> {
        if ![
            &self.catalog_sha256,
            &self.selection_sha256,
            &self.closure_sha256,
        ]
        .iter()
        .all(|s| digest(s))
        {
            return Err("invalid generation digest".into());
        }
        let mut transcript = b"VOBOOST_DOMAIN_GENERATION_V1\0".to_vec();
        transcript.extend_from_slice(&ascii_json(self)?);
        Ok(hash(&transcript))
    }
}
pub fn closure_digest(files: &[FileIdentity]) -> Result<String> {
    let mut prior = "";
    for f in files {
        f.validate()?;
        if f.file.as_str() <= prior {
            return Err("closure is not unique/sorted".into());
        }
        prior = &f.file;
    }
    Ok(hash(&ascii_json(files)?))
}
pub fn selection_digest(rows: &[SelectedTarget]) -> Result<String> {
    let mut prior = None;
    for r in rows {
        let key = (r.id.as_str(), r.process.as_str());
        if prior.map(|p| key <= p).unwrap_or(false) {
            return Err("selection is not unique/sorted".into());
        }
        prior = Some(key);
    }
    Ok(hash(&ascii_json(rows)?))
}
/// Captured by an OS backend, never supplied by the courier or desired request.
pub struct LocalProfile<'a> {
    pub domain: Domain,
    pub os_known: bool,
    pub architecture: &'a str,
    pub os_version: Option<&'a str>,
    pub chip: Option<&'a str>,
    pub vehicle: Option<&'a str>,
    pub powertrain: Option<&'a str>,
    pub market: Option<&'a str>,
    pub native_control_available: bool,
    pub build_ids: &'a [crate::catalog::BuildIdentity],
}
fn axis(values: &[String], local: Option<&str>) -> bool {
    values.is_empty()
        || local
            .map(|v| values.iter().any(|s| s == v))
            .unwrap_or(false)
}
pub fn select(catalog: &Catalog, profile: &LocalProfile<'_>) -> Result<Vec<SelectedTarget>> {
    if !profile.os_known {
        return Err("local OS identity is unknown".into());
    }
    let mut rows = Vec::new();
    for a in catalog.agents.iter().filter(|a| a.domain == profile.domain) {
        let applicable = match &a.applicability {
            Some(Applicability::Qnx(p)) => {
                profile.domain == Domain::Cluster
                    && profile.architecture == "aarch64"
                    && profile.native_control_available
                    && !profile.build_ids.is_empty()
                    && axis(&p.chip, profile.chip)
                    && axis(&p.vehicle, profile.vehicle)
                    && axis(&p.qnx, profile.os_version)
                    && axis(&p.powertrain, profile.powertrain)
                    && axis(&p.market, profile.market)
            }
            Some(Applicability::Android(p)) => {
                profile.domain == Domain::Multimedia
                    && matches!(profile.architecture, "arm64-v8a" | "armeabi-v7a")
                    && axis(&p.chip, profile.chip)
                    && axis(&p.vehicle, profile.vehicle)
                    && axis(&p.powertrain, profile.powertrain)
                    && axis(&p.market, profile.market)
                    && (p.android.is_empty()
                        || profile
                            .os_version
                            .and_then(|s| s.parse::<u8>().ok())
                            .map(|v| p.android.contains(&v))
                            .unwrap_or(false))
            }
            None => a.kind.as_deref() == Some("executor") && profile.domain == Domain::Multimedia,
        };
        if !applicable {
            continue;
        }
        for t in &a.targets {
            if let Target::Native { compatibility, .. } = t {
                if !compatibility
                    .iter()
                    .all(|wanted| profile.build_ids.iter().any(|found| found == wanted))
                {
                    continue;
                }
            }
            rows.push(SelectedTarget {
                id: a.id.clone(),
                process: t.process().into(),
                file: t.file().file,
                entry: t.entry().into(),
            });
        }
    }
    rows.sort_by(|a, b| (&a.id, &a.process).cmp(&(&b.id, &b.process)));
    let mut unique = BTreeSet::new();
    if rows.iter().any(|r| !unique.insert((&r.id, &r.process))) {
        return Err("duplicate selected authority".into());
    }
    Ok(rows)
}
