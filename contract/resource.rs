//! Authenticated resource APK capability for the fixed-path root executor.
//! Product signatures authorize our bytes; actual compatibility is a separate Android Resources probe.
use crate::release::{self, Artifact, ArtifactRole, ResourceMetadata};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Exact signed inputs sufficient to prove ownership, not permission to enable an overlay.
pub struct SignedResourceInputs<'a> {
    pub manifest_bytes: &'a [u8],
    pub manifest_signature: &'a [u8],
    pub product_public_key: &'a [u8; 32],
    pub artifact_file: &'a str,
    pub catalog_bytes: &'a [u8],
    pub apk_bytes: &'a [u8],
    pub ledger_bytes: &'a [u8],
}

/// Sealed signed-delivery ownership for inert staging and exact-owned cleanup.
/// It never establishes compatibility or authorizes enabling an overlay.
#[derive(Debug)]
pub struct OwnedResourceArtifact {
    artifact: Artifact,
    apk: Vec<u8>,
    ledger: Vec<u8>,
    manifest_bytes: Vec<u8>,
    manifest_signature: Vec<u8>,
    catalog_bytes: Vec<u8>,
    verification_key: [u8; 32],
    manifest_sha256: String,
    catalog_sha256: String,
}
impl OwnedResourceArtifact {
    pub fn verify(input: SignedResourceInputs<'_>) -> Result<Self, String> {
        if input.manifest_bytes.len() > release::MAX_MANIFEST_BYTES
            || input.catalog_bytes.len() > 1024 * 1024
            || input.apk_bytes.len() > 16 * 1024 * 1024
            || input.ledger_bytes.len() > 1024 * 1024
        {
            return Err("resource admission byte bound".into());
        }
        let manifest = release::verify_manifest_signature(
            input.manifest_bytes,
            input.manifest_signature,
            input.product_public_key,
        )?;
        let artifact = manifest.artifact(input.artifact_file)?;
        if artifact.role != ArtifactRole::ResourceApk {
            return Err("resource role required".into());
        }
        let descriptor = artifact
            .resource
            .as_ref()
            .ok_or("resource descriptor absent")?;
        check_bytes(artifact, input.apk_bytes)?;
        check_bytes(manifest.artifact("agents.json")?, input.catalog_bytes)?;
        let catalog = crate::agent_catalog::AgentCatalog::parse(input.catalog_bytes)?;
        if catalog
            .agents
            .iter()
            .filter(|agent| agent.id == descriptor.owner)
            .count()
            != 1
        {
            return Err("resource owner absent or ambiguous in authenticated catalog".into());
        }
        let ledger = manifest.artifact(&descriptor.coverage_ledger.file)?;
        check_bytes(ledger, input.ledger_bytes)?;
        if ledger.role != ArtifactRole::ResourceLedger
            || ledger.size != descriptor.coverage_ledger.size
            || ledger.sha256 != descriptor.coverage_ledger.sha256
        {
            return Err("resource ledger descriptor differs".into());
        }
        voboost_contract_core::resource_apk::InspectedResourceApk::inspect(
            input.apk_bytes,
            &descriptor.overlay_package,
            &descriptor.target_package,
            artifact
                .version_code
                .ok_or("resource version absent")?
                .try_into()
                .map_err(|_| "resource APK version overflow")?,
        )?;
        let signer = voboost_contract_core::apk_signer::signer_sha256_v2_v3_bytes(input.apk_bytes)?;
        if artifact.certificate_sha256.as_deref() != Some(hex::encode(signer).as_str()) {
            return Err("resource APK certificate differs".into());
        }
        verify_ledger(descriptor, input.ledger_bytes)?;
        Ok(Self {
            artifact: artifact.clone(),
            apk: input.apk_bytes.to_vec(),
            ledger: input.ledger_bytes.to_vec(),
            manifest_bytes: input.manifest_bytes.to_vec(),
            manifest_signature: input.manifest_signature.to_vec(),
            catalog_bytes: input.catalog_bytes.to_vec(),
            verification_key: *input.product_public_key,
            manifest_sha256: hex::encode(Sha256::digest(input.manifest_bytes)),
            catalog_sha256: hex::encode(Sha256::digest(input.catalog_bytes)),
        })
    }
    /// Public product key that authenticated this exact ownership authority.
    pub fn verification_key(&self) -> &[u8; 32] {
        &self.verification_key
    }
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    pub fn manifest_signature(&self) -> &[u8] {
        &self.manifest_signature
    }
    pub fn catalog_bytes(&self) -> &[u8] {
        &self.catalog_bytes
    }
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
    pub fn descriptor(&self) -> &ResourceMetadata {
        self.artifact
            .resource
            .as_ref()
            .expect("verified resource descriptor")
    }
    pub fn apk_bytes(&self) -> &[u8] {
        &self.apk
    }
    pub fn ledger_bytes(&self) -> &[u8] {
        &self.ledger
    }
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
    pub fn catalog_sha256(&self) -> &str {
        &self.catalog_sha256
    }
}
fn check_bytes(artifact: &Artifact, bytes: &[u8]) -> Result<(), String> {
    if artifact.size != bytes.len() as u64 || artifact.sha256 != hex::encode(Sha256::digest(bytes))
    {
        return Err("resource authenticated artifact bytes differ".into());
    }
    Ok(())
}
fn verify_ledger(descriptor: &ResourceMetadata, bytes: &[u8]) -> Result<(), String> {
    let ledger: Value = release::parse_canonical(bytes, "resource ledger")?;
    let scope = ledger.get("scope").and_then(Value::as_str);
    let valid_scope = if descriptor.owner == "i18n-en" {
        scope == Some("english-delta")
    } else {
        matches!(scope, Some("admission-subset" | "complete-ui-owner"))
    };
    if ledger.get("schema").and_then(Value::as_u64) != Some(1)
        || ledger.get("targetPackage").and_then(Value::as_str) != Some(&descriptor.target_package)
        || descriptor.compatibility_schema != 1
        || ledger.get("overlayPackage").and_then(Value::as_str) != Some(&descriptor.overlay_package)
        || !valid_scope
    {
        return Err("resource ledger identity differs".into());
    }
    let rows = ledger
        .get("resources")
        .and_then(Value::as_array)
        .ok_or("resource ledger rows absent")?;
    if rows.is_empty() || rows.len() > 32768 {
        return Err("resource ledger row bound".into());
    }
    let mut names = BTreeSet::new();
    for row in rows {
        let name = row
            .get("resource")
            .and_then(Value::as_str)
            .ok_or("resource ledger name absent")?;
        let Some((kind, key)) = name.split_once('/') else {
            return Err("resource ledger name malformed".into());
        };
        if !matches!(kind, "string" | "array" | "plurals")
            || key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
            || !matches!(key.as_bytes()[0],b'a'..=b'z'|b'A'..=b'Z'|b'_')
            || !names.insert(name)
            || !matches!(row.get("source").and_then(Value::as_str), Some("ru" | "en"))
            || (descriptor.owner == "i18n-en"
                && row.get("source").and_then(Value::as_str) != Some("en"))
        {
            return Err("resource ledger invalid or duplicate row".into());
        }
    }
    if descriptor.owner == "i18n-en" {
        validate_english_delta(&ledger, &names)?;
    }
    voboost_contract_core::resource_compatibility::validate(
        &ledger["compatibility"],
        &descriptor.target_package,
        &names,
    )?;
    // Scope is input coverage metadata, never runtime readiness or proof of complete translation.
    Ok(())
}

fn validate_english_delta(ledger: &Value, names: &BTreeSet<&str>) -> Result<(), String> {
    let native = ledger["nativeReadback"]
        .as_object()
        .ok_or("English native baseline absent")?;
    let expected = ledger["expectedReadback"]
        .as_object()
        .ok_or("English delta readback absent")?;
    if names.len() > 64
        || native.len() != names.len()
        || expected.len() != names.len()
        || ledger["expectedEnglishReadback"].as_object() != Some(expected)
    {
        return Err("English delta key sets differ".into());
    }
    for name in names {
        let kind = name.split_once('/').ok_or("English delta key malformed")?.0;
        let read = |map: &serde_json::Map<String, Value>| {
            let value = map
                .get(*name)
                .and_then(Value::as_str)
                .ok_or("English delta value absent")?;
            delta_leaves(kind, value)
        };
        let before = read(native)?;
        let after = read(expected)?;
        if before.len() != after.len()
            || before == after
            || before.iter().zip(&after).any(|(before, after)| {
                before != after
                    && (!contains_han(before) || contains_han(after) || after.trim().is_empty())
            })
        {
            return Err("English delta changes a non-Han leaf or lacks a correction".into());
        }
    }
    Ok(())
}

fn delta_leaves(kind: &str, value: &str) -> Result<Vec<String>, String> {
    if value.len() > 4096 {
        return Err("English delta value exceeds bound".into());
    }
    match kind {
        "string" => Ok(vec![value.into()]),
        "array" => {
            serde_json::from_str(value).map_err(|_| "English array readback malformed".into())
        }
        "plurals" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Plurals {
                one: String,
                other: String,
            }
            let value: Plurals =
                serde_json::from_str(value).map_err(|_| "English plural readback malformed")?;
            Ok(vec![value.one, value.other])
        }
        _ => Err("English delta key type unsupported".into()),
    }
}

fn contains_han(value: &str) -> bool {
    value.chars().any(|c| matches!(c as u32, 0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xf900..=0xfaff | 0x20000..=0x323af))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn descriptor() -> ResourceMetadata {
        ResourceMetadata {
            owner: "i18n-ru".into(),
            locale: "ru".into(),
            target_package: "com.qinggan.app.setting".into(),
            compatibility_schema: 1,
            overlay_package: "ru.voboost.translation.setting".into(),
            coverage_ledger: release::ResourceFile {
                file: "resource-i18n-ru-setting.json".into(),
                size: 1,
                sha256: "b".repeat(64),
            },
        }
    }
    fn ledger() -> Value {
        json!({"schema":1,"targetPackage":"com.qinggan.app.setting","compatibility":{"schemaVersion":1,"targetPackage":"com.qinggan.app.setting","resources":[{"resource":"string/title","type":"string","format":[]}]},"overlayPackage":"ru.voboost.translation.setting","scope":"admission-subset","resources":[{"resource":"string/title","source":"ru"}]})
    }
    fn encoded(value: Value) -> Vec<u8> {
        let mut b = serde_json::to_vec(&value).unwrap();
        b.push(b'\n');
        b
    }
    #[test]
    fn english_owner_admits_english_only_rows_and_matching_english_readback() {
        let mut descriptor = descriptor();
        descriptor.owner = "i18n-en".into();
        descriptor.locale = "en".into();
        let mut ledger = ledger();
        ledger["scope"] = json!("english-delta");
        ledger["resources"][0]["source"] = json!("en");
        ledger["nativeReadback"] = json!({"string/title":"语言"});
        ledger["expectedReadback"] = json!({"string/title":"Language"});
        ledger["expectedEnglishReadback"] = ledger["expectedReadback"].clone();
        verify_ledger(&descriptor, &encoded(ledger.clone())).unwrap();
        let mut wrong = ledger.clone();
        wrong["resources"][0]["source"] = json!("ru");
        assert!(verify_ledger(&descriptor, &encoded(wrong)).is_err());
        ledger["expectedReadback"] = json!({"string/title":"Язык"});
        assert!(verify_ledger(&descriptor, &encoded(ledger)).is_err());
    }
    #[test]
    fn delta_preserves_native_english_leaves_in_typed_values() {
        let names = ["array/options", "plurals/items", "string/title"]
            .into_iter()
            .collect();
        let mut delta = json!({
            "nativeReadback":{"array/options":"[\"Stock wording\",\"中文\"]","plurals/items":"{\"one\":\"One item\",\"other\":\"%d 项\"}","string/title":"语言"},
            "expectedReadback":{"array/options":"[\"Stock wording\",\"Chinese\"]","plurals/items":"{\"one\":\"One item\",\"other\":\"%d items\"}","string/title":"Language"}
        });
        delta["expectedEnglishReadback"] = delta["expectedReadback"].clone();
        assert!(validate_english_delta(&delta, &names).is_ok());
        for (key, replacement) in [
            ("array/options", r#"["New wording","Chinese"]"#),
            (
                "plurals/items",
                r#"{"one":"New wording","other":"%d items"}"#,
            ),
        ] {
            let mut wrong = delta.clone();
            wrong["expectedReadback"][key] = json!(replacement);
            wrong["expectedEnglishReadback"] = wrong["expectedReadback"].clone();
            assert!(validate_english_delta(&wrong, &names).is_err());
        }
        delta["nativeReadback"]["string/title"] = json!("Stock wording");
        assert!(validate_english_delta(&delta, &names).is_err());
    }
    #[test]
    fn accepts_subset_without_runtime_readiness_claim() {
        verify_ledger(&descriptor(), &encoded(ledger())).unwrap();
    }
    #[test]
    fn rejects_ledger_target_substitution() {
        let mut l = ledger();
        l["targetPackage"] = json!("another.target");
        assert!(verify_ledger(&descriptor(), &encoded(l)).is_err());
    }
    #[test]
    fn rejects_duplicate_resource_rows() {
        let mut l = ledger();
        l["resources"]
            .as_array_mut()
            .unwrap()
            .push(json!({"resource":"string/title","source":"en"}));
        assert!(verify_ledger(&descriptor(), &encoded(l)).is_err());
    }
    #[test]
    fn rejects_non_english_fallback() {
        let mut l = ledger();
        l["resources"][0]["source"] = json!("zh");
        assert!(verify_ledger(&descriptor(), &encoded(l)).is_err());
    }
    #[test]
    fn rejects_duplicate_json_keys() {
        assert!(verify_ledger(&descriptor(), b"{\"schema\":1,\"schema\":1}\n").is_err());
    }
}
