use crate::release;
use serde_json::{json, Value};
const H: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn fixture() -> Value {
    let mut v: Value = serde_json::from_slice(include_bytes!(
        "../test/fixtures/product-release/voboost/valid/minimal.json"
    ))
    .unwrap();
    let a = v["artifacts"].as_array_mut().unwrap();
    a.push(json!({"role":"resource-apk","file":"resource-i18n-ru-setting-a9.apk","size":128,"sha256":H,"activation":"agent-generation","packageName":"ru.voboost.translation.setting","versionCode":1,"certificateSha256":H,"resource":{"owner":"i18n-ru","locale":"ru","targetPackage":"com.qinggan.app.setting","compatibilitySchema":1,"overlayPackage":"ru.voboost.translation.setting","coverageLedger":{"file":"resource-i18n-ru-setting-a9.json","size":64,"sha256":H}}}));
    a.push(json!({"role":"resource-ledger","file":"resource-i18n-ru-setting-a9.json","size":64,"sha256":H,"activation":"agent-generation"}));
    v
}
fn validate(v: Value) -> Result<(), String> {
    let m: release::Manifest = serde_json::from_value(v).map_err(|e| e.to_string())?;
    m.validate()
}
fn resource(v: &mut Value) -> &mut Value {
    v["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|a| a["role"] == "resource-apk")
        .unwrap()
}
#[test]
fn valid_graph() {
    validate(fixture()).unwrap();
}
#[test]
fn missing_ledger() {
    let mut v = fixture();
    v["artifacts"].as_array_mut().unwrap().pop();
    assert!(validate(v).unwrap_err().contains("ledger absent"));
}
#[test]
fn wrong_ledger_hash() {
    let mut v = fixture();
    resource(&mut v)["resource"]["coverageLedger"]["sha256"] = json!("0".repeat(64));
    assert!(validate(v).is_err());
}
#[test]
fn wrong_ledger_size() {
    let mut v = fixture();
    resource(&mut v)["resource"]["coverageLedger"]["size"] = json!(99);
    assert!(validate(v).is_err());
}
#[test]
fn unlisted_ledger() {
    let mut v = fixture();
    resource(&mut v)["resource"]["coverageLedger"]["file"] = json!("resource-i18n-ru-other.json");
    assert!(validate(v).is_err());
}
#[test]
fn absent_descriptor() {
    let mut v = fixture();
    resource(&mut v).as_object_mut().unwrap().remove("resource");
    assert!(validate(v).is_err());
}
#[test]
fn foreign_owner() {
    let mut v = fixture();
    resource(&mut v)["resource"]["owner"] = json!("launcher");
    assert!(validate(v).is_err());
}
#[test]
fn foreign_target_identity() {
    let mut v = fixture();
    resource(&mut v)["resource"]["targetPackage"] = json!("ru.voboost.translation.setting");
    assert!(validate(v).is_err());
}
#[test]
fn unsupported_resource_probe_schema() {
    let mut v = fixture();
    resource(&mut v)["resource"]["compatibilitySchema"] = json!(2);
    assert!(validate(v).is_err());
}
#[test]
fn wrong_package_or_signer() {
    for field in ["packageName", "certificateSha256"] {
        let mut v = fixture();
        resource(&mut v)[field] = json!("bad");
        assert!(validate(v).is_err());
    }
}
#[test]
fn descriptor_on_foreign_role() {
    let mut v = fixture();
    let r = resource(&mut v)["resource"].clone();
    v["artifacts"][0]["resource"] = r;
    assert!(validate(v).is_err());
}
#[test]
fn orphan_ledger() {
    let mut v = fixture();
    v["artifacts"]
        .as_array_mut()
        .unwrap()
        .retain(|a| a["role"] != "resource-apk");
    assert!(validate(v).unwrap_err().contains("exactly one"));
}
#[test]
fn no_package_installer_activation() {
    let mut v = fixture();
    resource(&mut v)["activation"] = json!("package-installer");
    assert!(validate(v).is_err());
}
#[test]
fn multiple_resources_allowed() {
    let mut v = fixture();
    let mut apk = resource(&mut v).clone();
    apk["file"] = json!("resource-i18n-ru-vehicle-a9.apk");
    apk["packageName"] = json!("ru.voboost.translation.vehicle");
    apk["resource"]["overlayPackage"] = json!("ru.voboost.translation.vehicle");
    apk["resource"]["targetPackage"] = json!("com.qinggan.app.vehiclesetting");
    apk["resource"]["coverageLedger"]["file"] = json!("resource-i18n-ru-vehicle-a9.json");
    let a = v["artifacts"].as_array_mut().unwrap();
    a.insert(a.len() - 1, apk);
    a.push(json!({"role":"resource-ledger","file":"resource-i18n-ru-vehicle-a9.json","size":64,"sha256":H,"activation":"agent-generation"}));
    validate(v).unwrap();
}

#[test]
fn duplicate_overlay_rejected() {
    let mut v = fixture();
    let mut a = resource(&mut v).clone();
    a["file"] = json!("resource-i18n-ru-vehicle.apk");
    v["artifacts"].as_array_mut().unwrap().insert(18, a);
    assert!(validate(v).is_err());
}

#[test]
fn distinct_probe_profiles_same_package_accepted() {
    let mut v = fixture();
    let mut a = resource(&mut v).clone();
    a["file"] = json!("resource-i18n-ru-setting-a11.apk");
    a["packageName"] = json!("ru.voboost.translation.setting.a11");
    a["resource"]["overlayPackage"] = json!("ru.voboost.translation.setting.a11");

    a["resource"]["coverageLedger"]["file"] = json!("resource-i18n-ru-setting-a11.json");
    let items = v["artifacts"].as_array_mut().unwrap();
    let pos = items
        .iter()
        .position(|a| a["role"] == "resource-apk")
        .unwrap();
    items.insert(pos, a);
    let l = json!({"role":"resource-ledger","file":"resource-i18n-ru-setting-a11.json","size":64,"sha256":H,"activation":"agent-generation"});
    let pos = items
        .iter()
        .position(|a| a["role"] == "resource-ledger")
        .unwrap();
    items.insert(pos, l);
    validate(v).unwrap();
}

#[test]
fn english_resources_coexist_with_russian_and_bind_filename_owner_locale() {
    let mut value = fixture();
    let mut english = resource(&mut value).clone();
    english["file"] = json!("resource-i18n-en-setting-a11.apk");
    english["packageName"] = json!("ru.voboost.translation.setting.a11.en");
    english["resource"]["owner"] = json!("i18n-en");
    english["resource"]["locale"] = json!("en");
    english["resource"]["overlayPackage"] = json!("ru.voboost.translation.setting.a11.en");
    english["resource"]["coverageLedger"]["file"] = json!("resource-i18n-en-setting-a11.json");
    let mut ledger = value["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role"] == "resource-ledger")
        .unwrap()
        .clone();
    ledger["file"] = json!("resource-i18n-en-setting-a11.json");
    let rows = value["artifacts"].as_array_mut().unwrap();
    rows.push(english);
    rows.push(ledger);
    rows.sort_by_key(|a| {
        (
            if a["role"] == "resource-apk" {
                100
            } else if a["role"] == "resource-ledger" {
                101
            } else {
                0
            },
            a["file"].as_str().unwrap().to_string(),
        )
    });
    // Preserve the original canonical order of non-resource roles.
    let base = fixture();
    let prefix = base["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["role"] != "resource-apk" && a["role"] != "resource-ledger")
        .cloned()
        .collect::<Vec<_>>();
    let resources = rows
        .iter()
        .filter(|a| a["role"] == "resource-apk" || a["role"] == "resource-ledger")
        .cloned()
        .collect::<Vec<_>>();
    value["artifacts"] = json!(prefix.into_iter().chain(resources).collect::<Vec<_>>());
    validate(value.clone()).unwrap();
    for (field, wrong) in [("owner", "i18n-ru"), ("locale", "ru")] {
        let mut bad = value.clone();
        let english = bad["artifacts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|a| a["file"] == "resource-i18n-en-setting-a11.apk")
            .unwrap();
        english["resource"][field] = json!(wrong);
        assert!(validate(bad).is_err());
    }
}
