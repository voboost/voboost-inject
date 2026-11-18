//! Signed inert QNX localization data. Ownership never proves engine applicability.
use crate::{
    catalog::{Catalog, Domain, Target, AGENT_ENTRY_ABI_SHA256, NATIVE_ENTRY_ABI_SHA256},
    release::{self, ArtifactRole, Manifest},
    Result,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

pub const MAX_PACK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LEDGER_BYTES: usize = 1024 * 1024;
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ledger {
    pub schema_version: u32,
    pub owner: String,
    pub target_process: String,
    pub format: String,
    pub locale: String,
    pub compatibility_schema: u32,
    pub resources: Vec<Resource>,
    pub expected_readback: BTreeMap<String, String>,
    pub engine_admission: String,
    pub english_keys: usize,
    pub retained_russian: usize,
    pub english_fallback: usize,
    pub translated: usize,
    pub han_fallback: usize,
    pub stock_russian_covers_english: bool,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub key: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub source: String,
    pub format: Vec<String>,
}
pub struct Inputs<'a> {
    pub manifest: &'a [u8],
    pub signature: &'a [u8],
    pub public_key: &'a [u8; 32],
    pub catalog: &'a [u8],
    pub artifact_file: &'a str,
    pub pack: &'a [u8],
    pub ledger: &'a [u8],
}
/// Exact signed bytes admitted only for inert delivery and owned cleanup.
#[derive(Debug)]
pub struct OwnedPack {
    file: String,
    ledger_file: String,
    pack: Vec<u8>,
    ledger_bytes: Vec<u8>,
    ledger: Ledger,
}
impl OwnedPack {
    pub fn verify(input: Inputs<'_>) -> Result<Self> {
        if input.pack.is_empty()
            || input.pack.len() > MAX_PACK_BYTES
            || input.ledger.is_empty()
            || input.ledger.len() > MAX_LEDGER_BYTES
            || input.catalog.len() > 1024 * 1024
        {
            return Err("QNX pack byte bound".into());
        }
        let manifest =
            release::verify_manifest_signature(input.manifest, input.signature, input.public_key)?;
        let artifact = manifest.artifact(input.artifact_file)?;
        if artifact.role != ArtifactRole::QnxResourcePack {
            return Err("QNX pack role required".into());
        }
        check(&manifest, input.artifact_file, input.pack)?;
        check(&manifest, "agents.json", input.catalog)?;
        let ledger_file = format!(
            "{}.json",
            input
                .artifact_file
                .strip_suffix(".kzb")
                .ok_or("QNX pack suffix")?
        );
        if manifest.artifact(&ledger_file)?.role != ArtifactRole::QnxResourceLedger {
            return Err("QNX ledger role required".into());
        }
        check(&manifest, &ledger_file, input.ledger)?;
        let ledger = inspect(input.pack, input.ledger)?;
        let catalog = Catalog::parse(
            input.catalog,
            AGENT_ENTRY_ABI_SHA256,
            NATIVE_ENTRY_ABI_SHA256,
        )?;
        if catalog.agents.iter().filter(|a| a.id==ledger.owner && a.domain==Domain::Cluster && a.kind.is_none() && a.targets.iter().any(|t| matches!(t,Target::Native { process, .. } if process==&ledger.target_process))).count()!=1 { return Err("QNX pack owner target absent or ambiguous".into()); }
        for target in catalog
            .agents
            .iter()
            .filter(|a| a.id == ledger.owner && a.domain == Domain::Cluster)
            .flat_map(|a| &a.targets)
            .filter(|t| t.process() == ledger.target_process)
        {
            let file = target.file();
            let declared = manifest.artifact(&file.file)?;
            if declared.role != ArtifactRole::QnxAgentModule
                || declared.size != file.size
                || declared.sha256 != file.sha256
            {
                return Err("QNX pack owner module differs from signed product".into());
            }
        }
        Ok(Self {
            file: input.artifact_file.into(),
            ledger_file,
            pack: input.pack.into(),
            ledger_bytes: input.ledger.into(),
            ledger,
        })
    }
    pub fn file(&self) -> &str {
        &self.file
    }
    pub fn ledger_file(&self) -> &str {
        &self.ledger_file
    }
    pub fn pack(&self) -> &[u8] {
        &self.pack
    }
    pub fn ledger_bytes(&self) -> &[u8] {
        &self.ledger_bytes
    }
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }
}
fn check(manifest: &Manifest, name: &str, bytes: &[u8]) -> Result<()> {
    let a = manifest.artifact(name)?;
    if a.size != bytes.len() as u64 || a.sha256 != crate::hash(bytes) {
        return Err("QNX resource differs from signed bytes".into());
    }
    Ok(())
}
/// Bounded parser accepts only the indexed or closed-metadata inline inert producer format.
/// No OEM scene/resource code or stock language slot is admitted.
pub fn inspect(pack: &[u8], bytes: &[u8]) -> Result<Ledger> {
    if pack.is_empty()
        || pack.len() > MAX_PACK_BYTES
        || bytes.is_empty()
        || bytes.len() > MAX_LEDGER_BYTES
    {
        return Err("QNX resource input bound".into());
    }
    let value: serde_json::Value = release::parse_canonical(bytes, "QNX localization ledger")?;
    let ledger: Ledger = serde_json::from_value(value).map_err(|e| format!("QNX ledger: {e}"))?;
    let process = &ledger.target_process;
    if ledger.schema_version != 1
        || ledger.compatibility_schema != 1
        || ledger.owner != "i18n-ru"
        || !matches!(ledger.format.as_str(), "KZBF-v3-indexed" | "KZBF-v3-inline")
        || ledger.engine_admission != "unverified"
        || process.is_empty()
        || process.len() > 48
        || !process
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        || ledger.locale != format!("voboost-ru-{process}")
    {
        return Err("QNX localization identity rejected".into());
    }
    if ledger.resources.is_empty()
        || ledger.resources.len() > 8192
        || ledger.expected_readback.len() != ledger.resources.len()
    {
        return Err("QNX resource inventory bound".into());
    }
    let mut seen = BTreeSet::new();
    let mut counts = [0usize; 3];
    for row in &ledger.resources {
        if row.key.is_empty()
            || row.key.len() > 4096
            || row.key.contains('\0')
            || row.kind != "string"
            || !seen.insert(row.key.as_str())
            || !ledger.expected_readback.contains_key(&row.key)
            || row.format.len() > 256
            || row
                .format
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || !s.starts_with('%'))
        {
            return Err("QNX resource row rejected".into());
        }
        if formats(&ledger.expected_readback[&row.key]) != row.format {
            return Err("QNX actual placeholder readback differs".into());
        }
        counts[match row.source.as_str() {
            "ru" => 0,
            "en" => 1,
            "translation" => 2,
            _ => return Err("QNX resource source rejected".into()),
        }] += 1;
    }
    if counts
        != [
            ledger.retained_russian,
            ledger.english_fallback,
            ledger.translated,
        ]
        || ledger.english_keys == 0
        || ledger.english_keys > ledger.resources.len()
        || ledger.han_fallback > ledger.english_fallback
    {
        return Err("QNX coverage accounting differs".into());
    }
    let version = pack.get(4..8).ok_or("QNX pack version absent")?;
    if (ledger.format == "KZBF-v3-indexed" && version != 3u32.to_le_bytes())
        || (ledger.format == "KZBF-v3-inline" && version != 0x30003u32.to_le_bytes())
    {
        return Err("QNX ledger and pack serialization differ".into());
    }
    let actual = decode(pack, &ledger.locale)?;
    if actual != ledger.expected_readback {
        return Err("QNX pack actual string readback differs".into());
    }
    Ok(ledger)
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("QNX span overflow")?;
        let b = self.bytes.get(self.at..end).ok_or("QNX truncated span")?;
        self.at = end;
        Ok(b)
    }
    fn word(&mut self) -> Result<usize> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| "QNX word")?) as usize)
    }
    fn text(&mut self) -> Result<String> {
        let tail = &self.bytes[self.at..];
        let n = tail
            .iter()
            .position(|b| *b == 0)
            .ok_or("QNX missing string terminator")?;
        if n > 1024 * 1024 {
            return Err("QNX text bound".into());
        }
        let s = core::str::from_utf8(self.take(n)?)
            .map_err(|_| "QNX invalid UTF8")?
            .to_string();
        self.take(1)?;
        Ok(s)
    }
}
// Raw3 uses indexed strings; raw0x30003 uses NUL pairs. Both require inert metadata.
// This admits only our seven-resource inert envelope, not arbitrary OEM data.
fn decode_data_pack(bytes: &[u8], locale: &str, indexed: bool) -> Result<BTreeMap<String, String>> {
    let mut r = Reader { bytes, at: 0 };
    if r.take(4)? != b"KZBF" || r.word()? != if indexed { 3 } else { 0x30003 } {
        return Err("QNX data KZBF version".into());
    }
    let n = r.word()?;
    if n > 1024 || r.take(n)? != b"voboost-localization" || r.word()? != 7 {
        return Err("QNX data data-only header".into());
    }
    let names = [
        "/$message_types",
        "/$metaclass_dictionary",
        "/$plugins",
        "/$property_dictionary",
        "/$property_types",
        "/$strings",
    ];
    for name in names {
        if r.text()? != name {
            return Err("QNX data metadata namespace".into());
        }
    }
    if r.text()? != format!("/Locales/{locale}") || r.word()? != 7 {
        return Err("QNX data locale namespace".into());
    }
    let mut spans = [(0usize, 0usize); 7];
    for (i, span) in spans.iter_mut().enumerate() {
        let class = if i == 6 { 0 } else { u32::MAX as usize };
        if r.word()? != i || r.word()? != class {
            return Err("QNX data metaclass index".into());
        }
        let off = r.word()?;
        let len = r.word()?;
        if r.word()? != 0 || r.word()? != len {
            return Err("QNX data compression rejected".into());
        }
        *span = (off, len);
    }
    let mut strings = Vec::new();
    let mut used = BTreeSet::new();
    let mut result = BTreeMap::new();
    let mut decoded_bytes = 0usize;
    for (i, (off, len)) in spans.into_iter().enumerate() {
        let aligned = r.at.checked_add(3).ok_or("QNX data alignment overflow")? & !3;
        if off != aligned || r.take(aligned - r.at)?.iter().any(|b| *b != 0) {
            return Err("QNX data resource offset or padding".into());
        }
        let mut payload = Reader {
            bytes: r.take(len)?,
            at: 0,
        };
        match i {
            1 => {
                if payload.word()? != 1 || payload.text()? != "Kanzi.ResourceDictionary" {
                    return Err("QNX data metaclass dictionary rejected".into());
                }
            }
            5 if indexed => {
                let count = payload.word()?;
                if count == 0 || count > 32768 {
                    return Err("QNX data string pool count".into());
                }
                for _ in 0..count {
                    strings.push(payload.text()?);
                }
            }
            6 => {
                if payload.take(16)?.iter().any(|b| *b != 0) {
                    return Err("QNX data locale header".into());
                }
                let count = payload.word()?;
                if count == 0 || count > 8192 {
                    return Err("QNX data entry count".into());
                }
                for _ in 0..count {
                    let (key, value) = if indexed {
                        let k = payload.word()?;
                        let v = payload.word()?;
                        let key = strings.get(k).ok_or("QNX data key index")?.clone();
                        let value = strings.get(v).ok_or("QNX data value index")?.clone();
                        used.insert(k);
                        used.insert(v);
                        (key, value)
                    } else {
                        (payload.text()?, payload.text()?)
                    };
                    decoded_bytes = decoded_bytes
                        .checked_add(key.len())
                        .and_then(|n| n.checked_add(value.len()))
                        .ok_or("QNX data decoded overflow")?;
                    if decoded_bytes > MAX_LEDGER_BYTES
                        || key.is_empty()
                        || key.len() > 4096
                        || result.insert(key, value).is_some()
                    {
                        return Err("QNX data key or decoded bound".into());
                    }
                }
            }
            _ => {
                if payload.word()? != 0 {
                    return Err("QNX data executable metadata rejected".into());
                }
            }
        }
        if payload.at != payload.bytes.len() {
            return Err("QNX data resource trailing bytes".into());
        }
    }
    if indexed && used.len() != strings.len() {
        return Err("QNX data unowned string pool entries".into());
    }
    if r.at != bytes.len() {
        return Err("QNX data container trailing bytes".into());
    }
    Ok(result)
}

fn decode(bytes: &[u8], locale: &str) -> Result<BTreeMap<String, String>> {
    match bytes.get(4..8) {
        Some(version) if version == 3u32.to_le_bytes() => decode_data_pack(bytes, locale, true),
        Some(version) if version == 0x30003u32.to_le_bytes() => {
            decode_data_pack(bytes, locale, false)
        }
        _ => Err("QNX data-only KZBF version".into()),
    }
}

fn formats(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let mut at = 0;
    let mut result = Vec::new();
    while at < b.len() {
        if b[at] != b'%' {
            at += 1;
            continue;
        }
        let start = at;
        at += 1;
        if b.get(at) == Some(&b'%') {
            at += 1;
            continue;
        }
        let mut end = at;
        if b.get(end).is_some_and(|v| matches!(v, b'1'..=b'9')) {
            while b.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
        }
        let positional = end > at && b.get(end) == Some(&b'$');
        let mut scan = if positional { end + 1 } else { at };
        while b.get(scan).is_some_and(|v| b"-+ #0".contains(v)) {
            scan += 1;
        }
        while b.get(scan).is_some_and(u8::is_ascii_digit) {
            scan += 1;
        }
        if b.get(scan) == Some(&b'.') {
            let dot = scan;
            scan += 1;
            let digits = scan;
            while b.get(scan).is_some_and(u8::is_ascii_digit) {
                scan += 1;
            }
            if scan == digits {
                scan = dot;
            }
        }
        if b.get(scan).is_some_and(|v| b"sdiufFeEgGxXoc".contains(v)) {
            at = scan + 1;
            result.push(text[start..at].into());
        } else if end > start + 1 {
            at = end;
            result.push(text[start..at].into());
        }
    }
    result.sort();
    result
}
#[cfg(test)]
#[path = "resource_pack_tests.rs"]
mod tests;
