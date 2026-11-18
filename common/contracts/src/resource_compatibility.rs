//! Signed resource contract shape validation, never firmware or APK identity matching.
//! Actual Android Resources probes must independently satisfy this contract before enabling.
use crate::Result;
use alloc::{collections::BTreeSet, format, string::ToString};
use serde_json::Value;
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}

pub fn validate(value: &Value, target: &str, expected: &BTreeSet<&str>) -> Result<()> {
    let object = value
        .as_object()
        .ok_or("resource compatibility object absent")?;
    require(
        object.len() == 3
            && value["schemaVersion"].as_u64() == Some(1)
            && value["targetPackage"].as_str() == Some(target),
        "resource compatibility schema or target differs",
    )?;
    let rows = value["resources"]
        .as_array()
        .ok_or("resource compatibility rows absent")?;
    require(
        !rows.is_empty() && rows.len() <= 8192,
        "resource compatibility row bound",
    )?;
    let mut names = BTreeSet::new();
    for row in rows {
        let object = row.as_object().ok_or("resource probe object required")?;
        require(
            object.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "resource" | "type" | "format" | "formatted" | "items"
                )
            }),
            "unknown resource probe field",
        )?;
        let name = row["resource"]
            .as_str()
            .ok_or("resource probe name absent")?;
        let kind = row["type"].as_str().ok_or("resource probe type absent")?;
        let suffix = name
            .strip_prefix(&format!("{kind}/"))
            .ok_or("resource probe type/name differs")?;
        require(
            !suffix.is_empty()
                && matches!(suffix.as_bytes()[0],b'a'..=b'z'|b'A'..=b'Z'|b'_')
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
                && names.insert(name),
            "invalid or duplicate resource probe name",
        )?;
        match kind {
            "string" => {
                require(row.get("items").is_none(), "string probe cannot have items")?;
                validate_format(row)?;
            }
            "array" | "plurals" => {
                require(
                    row.get("format").is_none() && row.get("formatted").is_none(),
                    "container formatting belongs to items",
                )?;
                let items = row["items"]
                    .as_array()
                    .ok_or("resource item probes absent")?;
                require(items.len() <= 4096, "resource item probe bound")?;
                let mut quantities = BTreeSet::new();
                for item in items {
                    let object = item
                        .as_object()
                        .ok_or("resource item probe object required")?;
                    require(
                        object.keys().all(|key| {
                            matches!(key.as_str(), "format" | "formatted")
                                || (kind == "plurals" && key == "quantity")
                        }),
                        "unknown resource item probe field",
                    )?;
                    if kind == "plurals" {
                        let q = item["quantity"]
                            .as_str()
                            .ok_or("plural probe quantity absent")?;
                        require(
                            matches!(q, "zero" | "one" | "two" | "few" | "many" | "other")
                                && quantities.insert(q),
                            "invalid or duplicate plural quantity",
                        )?;
                    }
                    validate_format(item)?;
                }
                if kind == "plurals" {
                    require(quantities.contains("other"), "plural probe requires other")?;
                }
            }
            _ => return Err("unsupported resource probe type".into()),
        }
    }
    require(
        &names == expected,
        "resource probes differ from coverage set",
    )
}
fn validate_format(value: &Value) -> Result<()> {
    require(
        value.get("formatted").is_none() || value["formatted"] == false,
        "formatted override must be false",
    )?;
    let args = value["format"]
        .as_array()
        .ok_or("resource format probe absent")?;
    require(args.len() <= 256, "resource format probe bound")?;
    let mut previous: Option<(u16, &str)> = None;
    for arg in args {
        let text = arg
            .as_str()
            .ok_or("resource format argument must be string")?;
        let (index, kind) = text
            .split_once(':')
            .ok_or("resource format syntax invalid")?;
        let index_value = index
            .parse::<u16>()
            .map_err(|_| "resource format index invalid")?;
        require(
            index_value > 0
                && index_value.to_string() == index
                && ((kind.len() == 1 && kind.as_bytes()[0].is_ascii_alphabetic())
                    || (kind.len() == 2
                        && matches!(kind.as_bytes()[0], b't' | b'T')
                        && kind.as_bytes()[1].is_ascii_alphabetic())),
            "resource format signature invalid",
        )?;
        let current = (index_value, kind);
        require(
            previous.is_none_or(|previous| previous <= current),
            "resource format signatures not numerically sorted",
        )?;
        previous = Some(current);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        json!({"schemaVersion":1,"targetPackage":"com.qinggan.app.setting","resources":[{"resource":"string/title","type":"string","format":["2:s","10:d"]}]})
    }
    fn check(v: &Value) -> Result<()> {
        validate(
            v,
            "com.qinggan.app.setting",
            &BTreeSet::from(["string/title"]),
        )
    }
    #[test]
    fn numeric_formats_accept_ten_after_two() {
        check(&fixture()).unwrap();
    }
    #[test]
    fn rejects_lexical_format_order() {
        let mut v = fixture();
        v["resources"][0]["format"] = json!(["10:d", "2:s"]);
        assert!(check(&v).is_err());
    }
    #[test]
    fn rejects_unknown_schema_target_or_members() {
        for n in 0..3 {
            let mut v = fixture();
            match n {
                0 => v["schemaVersion"] = json!(2),
                1 => v["targetPackage"] = json!("other.owner"),
                _ => v["fingerprint"] = json!("not-a-capability"),
            };
            assert!(check(&v).is_err());
        }
    }
    #[test]
    fn rejects_partial_or_duplicate_probe_set() {
        let mut v = fixture();
        v["resources"] = json!([]);
        assert!(check(&v).is_err());
        let mut v = fixture();
        let duplicate = v["resources"][0].clone();
        v["resources"].as_array_mut().unwrap().push(duplicate);
        assert!(check(&v).is_err());
    }
    #[test]
    fn rejects_wrong_type_and_noncanonical_format_index() {
        let mut v = fixture();
        v["resources"][0]["type"] = json!("array");
        assert!(check(&v).is_err());
        let mut v = fixture();
        v["resources"][0]["format"] = json!(["01:s"]);
        assert!(check(&v).is_err());
    }
    #[test]
    fn arrays_and_plurals_are_structurally_checked() {
        let v = json!({"schemaVersion":1,"targetPackage":"owner.target","resources":[{"resource":"array/items","type":"array","items":[{"format":[]}]},{"resource":"plurals/count","type":"plurals","items":[{"quantity":"other","format":["1:d"]}]}]});
        let names = BTreeSet::from(["array/items", "plurals/count"]);
        validate(&v, "owner.target", &names).unwrap();
        let mut broken = v;
        broken["resources"][1]["items"] = json!([]);
        assert!(validate(&broken, "owner.target", &names).is_err());
    }
}
