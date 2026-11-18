use super::*;
use alloc::vec;
use serde_json::json;
fn word(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u32).to_le_bytes());
}
fn text(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    out.push(0);
}
fn fixture() -> (Vec<u8>, Vec<u8>) {
    let out = indexed_pack_fixture();
    let mut ledger=serde_json::to_vec(&json!({"schemaVersion":1,"owner":"i18n-ru","targetProcess":"gauge","format":"KZBF-v3-indexed","locale":"voboost-ru-gauge","compatibilitySchema":1,"resources":[{"key":"title","type":"string","source":"en","format":["%1"]}],"expectedReadback":{"title":"res-text:///Value %1"},"engineAdmission":"unverified","englishKeys":1,"retainedRussian":0,"englishFallback":1,"translated":0,"hanFallback":0,"stockRussianCoversEnglish":false})).unwrap();
    ledger.push(b'\n');
    (out, ledger)
}
#[test]
fn data_only_exact_readback() {
    let (p, l) = fixture();
    assert_eq!(
        inspect(&p, &l).unwrap().expected_readback["title"],
        "res-text:///Value %1"
    );
}
#[test]
fn every_truncation_rejected() {
    let (p, l) = fixture();
    for n in 0..p.len() {
        assert!(inspect(&p[..n], &l).is_err(), "prefix {n}");
    }
}
#[test]
fn nonlocalization_and_trailing_payload_rejected() {
    let (p, l) = fixture();
    for i in [0, 4, 8, 12, 32, 36, 50, 80] {
        let mut q = p.clone();
        q[i] ^= 1;
        assert!(inspect(&q, &l).is_err(), "offset {i}");
    }
    let mut q = p;
    q.push(0);
    assert!(inspect(&q, &l).is_err());
}
#[test]
fn unknown_or_forged_readiness_rejected() {
    let (p, l) = fixture();
    for (field, value) in [
        ("engineAdmission", json!("ready")),
        ("firmwareSha256", json!("foreign")),
        ("locale", json!("english")),
        ("owner", json!("font-cyrillic")),
        ("englishFallback", json!(0)),
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
        v[field] = value;
        let mut b = serde_json::to_vec(&v).unwrap();
        b.push(b'\n');
        assert!(inspect(&p, &b).is_err(), "field {field}");
    }
}
#[test]
fn ledger_must_match_actual_text_and_format() {
    let (p, l) = fixture();
    for n in 0..3 {
        let mut v: serde_json::Value = serde_json::from_slice(&l).unwrap();
        match n {
            0 => v["expectedReadback"]["title"] = json!("other"),
            1 => v["resources"][0]["format"] = json!([]),
            _ => v["resources"][0]["type"] = json!("scene"),
        };
        let mut b = serde_json::to_vec(&v).unwrap();
        b.push(b'\n');
        assert!(inspect(&p, &b).is_err());
    }
}
#[test]
fn no_ledger_duplicate_keys_or_whitespace_normalization() {
    let (p, l) = fixture();
    let mut duplicate = b"{\"owner\":\"i18n-ru\",".to_vec();
    duplicate.extend_from_slice(&l[1..]);
    assert!(inspect(&p, &duplicate).is_err());
    let mut spaced = b" ".to_vec();
    spaced.extend_from_slice(&l);
    assert!(inspect(&p, &spaced).is_err());
}
#[test]
fn format_signatures_follow_actual_printf_and_qt_values() {
    assert_eq!(
        formats("x %% %2$s %1 %03d %3.2f"),
        vec!["%03d", "%1", "%2$s", "%3.2f"]
    );
}
#[test]
fn canonical_pair_has_no_stock_path_or_execution_activation() {
    use crate::release::{classify, Abi, Activation};
    for (suffix, role) in [
        ("kzb", ArtifactRole::QnxResourcePack),
        ("json", ArtifactRole::QnxResourceLedger),
    ] {
        assert_eq!(
            classify(&format!("qnx-resource-i18n-ru-stock-gauge.{suffix}")).unwrap(),
            (role, Activation::AgentGeneration, Some(Abi::QnxAarch64))
        );
    }
    for s in [
        "../qnx-resource-i18n-ru-gauge.kzb",
        "qnx-resource-i18n-ru--gauge.kzb",
        "qnx-resource-i18n-ru-Gauge.kzb",
        "qnx-resource-i18n-ru-gauge.so",
    ] {
        assert!(classify(s).is_err());
    }
}
#[test]
#[ignore = "requires actual offline Java-generated input path"]
fn actual_java_generated_pack_readback() {
    let base = std::env::var("VOBOOST_QNX_PACK_SAMPLE").expect("set actual generated pack stem");
    let pack = std::fs::read(format!("{base}.kzb")).unwrap();
    let ledger = std::fs::read(format!("{base}.json")).unwrap();
    let inspected = inspect(&pack, &ledger).unwrap();
    assert_eq!(inspected.resources.len(), inspected.expected_readback.len());
    assert_eq!(inspected.engine_admission, "unverified");
}
#[test]
fn transport_rejects_orphans_wrong_roles_and_foreign_paths() {
    use crate::wire::{validate_files, WireFile, WireRole};
    let p = WireFile {
        role: WireRole::QnxResourcePack,
        file: "qnx-resource-i18n-ru-stock-gauge.kzb".into(),
        size: 32,
        sha256: crate::hash(b"pack"),
    };
    let l = WireFile {
        role: WireRole::QnxResourceLedger,
        file: "qnx-resource-i18n-ru-stock-gauge.json".into(),
        size: 32,
        sha256: crate::hash(b"ledger"),
    };
    assert!(validate_files(&[p.clone(), l.clone()], false).is_ok());
    assert!(validate_files(core::slice::from_ref(&p), false).is_err());
    for n in 0..4 {
        let mut a = p.clone();
        let mut b = l.clone();
        match n {
            0 => a.role = WireRole::QnxAgentModule,
            1 => a.file = "/usr/share/theme/common/english.kzb".into(),
            2 => b.file = "qnx-resource-i18n-ru-stock-point.json".into(),
            _ => b.size = 1024 * 1024 + 1,
        };
        assert!(validate_files(&[a, b], false).is_err());
    }
    assert!(serde_json::from_str::<WireRole>("\"qnx-resource-executable\"").is_err());
}
#[test]
fn repeated_pool_value_cannot_amplify_decoded_memory() {
    let mut pool = Vec::new();
    word(&mut pool, 3);
    text(&mut pool, "a");
    text(&mut pool, "b");
    text(&mut pool, &"v".repeat(600_000));
    let mut table = vec![0; 16];
    word(&mut table, 2);
    for n in [0, 2, 1, 2] {
        word(&mut table, n);
    }
    assert!(
        decode(&envelope_fixture(true, pool, table), "voboost-ru-gauge")
            .unwrap_err()
            .contains("decoded bound")
    );
}

fn inline_fixture() -> (Vec<u8>, Vec<u8>) {
    let (_, ledger) = fixture();
    let mut value: serde_json::Value = serde_json::from_slice(&ledger).unwrap();
    value["format"] = json!("KZBF-v3-inline");
    let mut ledger = serde_json::to_vec(&value).unwrap();
    ledger.push(b'\n');
    let names = [
        "/$message_types",
        "/$metaclass_dictionary",
        "/$plugins",
        "/$property_dictionary",
        "/$property_types",
        "/$strings",
        "/Locales/voboost-ru-gauge",
    ];
    let mut payloads = vec![vec![0; 4]; 7];
    payloads[1].clear();
    word(&mut payloads[1], 1);
    text(&mut payloads[1], "Kanzi.ResourceDictionary");
    payloads[6] = vec![0; 16];
    word(&mut payloads[6], 1);
    text(&mut payloads[6], "title");
    text(&mut payloads[6], "res-text:///Value %1");
    let mut out = b"KZBF".to_vec();
    word(&mut out, 0x30003);
    word(&mut out, 20);
    out.extend_from_slice(b"voboost-localization");
    word(&mut out, 7);
    for name in names {
        text(&mut out, name);
    }
    word(&mut out, 7);
    let mut at = (out.len() + 7 * 24 + 3) & !3;
    for (i, blob) in payloads.iter().enumerate() {
        for n in [
            i,
            if i == 6 { 0 } else { u32::MAX as usize },
            at,
            blob.len(),
            0,
            blob.len(),
        ] {
            word(&mut out, n);
        }
        at = (at + blob.len() + 3) & !3;
    }
    for blob in payloads {
        out.resize((out.len() + 3) & !3, 0);
        out.extend_from_slice(&blob);
    }
    (out, ledger)
}
#[test]
fn inline_closed_metadata_exact_readback() {
    let (pack, ledger) = inline_fixture();
    assert_eq!(
        inspect(&pack, &ledger).unwrap().expected_readback["title"],
        "res-text:///Value %1"
    );
}

fn inline_records(pack: &[u8]) -> usize {
    let marker = b"/Locales/voboost-ru-gauge\0";
    pack.windows(marker.len())
        .position(|p| p == marker)
        .unwrap()
        + marker.len()
        + 4
}
fn read_word(pack: &[u8], at: usize) -> usize {
    u32::from_le_bytes(pack[at..at + 4].try_into().unwrap()) as usize
}
fn put_word(pack: &mut [u8], at: usize, value: usize) {
    pack[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
#[test]
fn inline_every_truncation_and_serialization_mismatch_rejected() {
    let (pack, ledger) = inline_fixture();
    for n in 0..pack.len() {
        assert!(inspect(&pack[..n], &ledger).is_err(), "prefix {n}");
    }
    let mut row: serde_json::Value = serde_json::from_slice(&ledger).unwrap();
    row["format"] = json!("KZBF-v3-indexed");
    let mut wrong = serde_json::to_vec(&row).unwrap();
    wrong.push(b'\n');
    assert!(inspect(&pack, &wrong).is_err());
    let (old, old_ledger) = fixture();
    assert!(inspect(&old, &old_ledger).is_ok());
    assert!(inspect(&old, &ledger).is_err());
    let mut alias = old;
    put_word(&mut alias, 4, 0x30003);
    assert!(
        inspect(&alias, &ledger).is_err(),
        "header alias without required metadata is unsafe"
    );
}
#[test]
fn inline_rejects_metadata_classes_compression_spans_and_extra_data() {
    let (pack, ledger) = inline_fixture();
    let records = inline_records(&pack);
    for (at, value) in [
        (records, 1),
        (records + 4, 0),
        (records + 16, 1),
        (records + 8, read_word(&pack, records + 8) + 4),
        (records + 20, 8),
        (records + 6 * 24 + 4, 1),
    ] {
        let mut bad = pack.clone();
        put_word(&mut bad, at, value);
        assert!(inspect(&bad, &ledger).is_err(), "record offset {at}");
    }
    for i in [0, 2, 3, 4, 5] {
        let mut bad = pack.clone();
        let off = read_word(&bad, records + i * 24 + 8);
        put_word(&mut bad, off, 1);
        assert!(inspect(&bad, &ledger).is_err(), "metadata {i}");
    }
    let dict = read_word(&pack, records + 24 + 8);
    let mut bad = pack.clone();
    put_word(&mut bad, dict, 2);
    assert!(inspect(&bad, &ledger).is_err());
    let mut bad = pack.clone();
    bad[dict + 4] = b'X';
    assert!(inspect(&bad, &ledger).is_err());
    let locale = read_word(&pack, records + 6 * 24 + 8);
    for (at, value) in [(locale, 1), (locale + 16, 0), (locale + 16, 8193)] {
        let mut bad = pack.clone();
        put_word(&mut bad, at, value);
        assert!(inspect(&bad, &ledger).is_err());
    }
    let mut bad = pack.clone();
    bad[locale + 20] = 0xff;
    assert!(inspect(&bad, &ledger).is_err());
    let mut bad = pack.clone();
    bad[locale + 20] = 0;
    assert!(inspect(&bad, &ledger).is_err());
    let mut bad = pack.clone();
    bad.push(0);
    assert!(inspect(&bad, &ledger).is_err());
    let mut duplicate = pack.clone();
    duplicate.extend_from_slice(&pack[locale + 20..]);
    put_word(&mut duplicate, locale + 16, 2);
    let length = duplicate.len() - locale;
    put_word(&mut duplicate, records + 6 * 24 + 12, length);
    put_word(&mut duplicate, records + 6 * 24 + 20, length);
    assert!(
        decode(&duplicate, "voboost-ru-gauge").is_err(),
        "duplicate inline key"
    );
}

#[test]
fn inline_keys_and_decoded_values_remain_bounded() {
    let (pack, _) = inline_fixture();
    let records = inline_records(&pack);
    let locale = read_word(&pack, records + 6 * 24 + 8);
    for (key, value) in [
        ("k".repeat(4097), "v".into()),
        ("k".into(), "v".repeat(MAX_LEDGER_BYTES)),
    ] {
        let mut bad = pack[..locale + 16].to_vec();
        word(&mut bad, 1);
        text(&mut bad, &key);
        text(&mut bad, &value);
        let size = bad.len() - locale;
        put_word(&mut bad, records + 6 * 24 + 12, size);
        put_word(&mut bad, records + 6 * 24 + 20, size);
        assert!(decode(&bad, "voboost-ru-gauge").is_err());
    }
}

fn envelope_fixture(indexed: bool, pool: Vec<u8>, table: Vec<u8>) -> Vec<u8> {
    let names = [
        "/$message_types",
        "/$metaclass_dictionary",
        "/$plugins",
        "/$property_dictionary",
        "/$property_types",
        "/$strings",
        "/Locales/voboost-ru-gauge",
    ];
    let mut payloads = vec![vec![0; 4]; 7];
    payloads[1].clear();
    word(&mut payloads[1], 1);
    text(&mut payloads[1], "Kanzi.ResourceDictionary");
    payloads[5] = pool;
    payloads[6] = table;
    let mut out = b"KZBF".to_vec();
    word(&mut out, if indexed { 3 } else { 0x30003 });
    word(&mut out, 20);
    out.extend_from_slice(b"voboost-localization");
    word(&mut out, 7);
    for name in names {
        text(&mut out, name);
    }
    word(&mut out, 7);
    let mut at = (out.len() + 7 * 24 + 3) & !3;
    for (i, blob) in payloads.iter().enumerate() {
        for n in [
            i,
            if i == 6 { 0 } else { u32::MAX as usize },
            at,
            blob.len(),
            0,
            blob.len(),
        ] {
            word(&mut out, n);
        }
        at = (at + blob.len() + 3) & !3;
    }
    for blob in payloads {
        out.resize((out.len() + 3) & !3, 0);
        out.extend_from_slice(&blob);
    }
    out
}
fn indexed_pack_fixture() -> Vec<u8> {
    let mut pool = Vec::new();
    word(&mut pool, 2);
    text(&mut pool, "title");
    text(&mut pool, "res-text:///Value %1");
    let mut table = vec![0; 16];
    word(&mut table, 1);
    word(&mut table, 0);
    word(&mut table, 1);
    envelope_fixture(true, pool, table)
}

fn legacy_two_resource_fixture() -> Vec<u8> {
    let mut out = b"KZBF".to_vec();
    word(&mut out, 3);
    word(&mut out, 20);
    out.extend_from_slice(b"voboost-localization");
    word(&mut out, 2);
    text(&mut out, "/$strings");
    text(&mut out, "/Locales/voboost-ru-gauge");
    word(&mut out, 2);
    let first = (out.len() + 48 + 3) & !3;
    let mut pool = Vec::new();
    word(&mut pool, 2);
    text(&mut pool, "title");
    text(&mut pool, "res-text:///Value %1");
    let second = (first + pool.len() + 3) & !3;
    for (i, off, len) in [(0, first, pool.len()), (1, second, 28)] {
        for n in [i, 0, off, len, 0, len] {
            word(&mut out, n)
        }
    }
    out.resize(first, 0);
    out.extend_from_slice(&pool);
    out.resize(second + 16, 0);
    word(&mut out, 1);
    word(&mut out, 0);
    word(&mut out, 1);
    out
}
#[test]
fn indexed_missing_mandatory_metadata_is_rejected() {
    let (_, ledger) = fixture();
    assert!(inspect(&legacy_two_resource_fixture(), &ledger).is_err());
}

#[test]
fn indexed_closed_metadata_rejects_bad_indices_and_unowned_pool() {
    let (pack, ledger) = fixture();
    let records = inline_records(&pack);
    let locale = read_word(&pack, records + 6 * 24 + 8);
    for at in [locale + 20, locale + 24] {
        let mut bad = pack.clone();
        put_word(&mut bad, at, 2);
        assert!(inspect(&bad, &ledger).is_err());
    }
    let mut bad = pack.clone();
    put_word(&mut bad, records + 4, 0);
    assert!(inspect(&bad, &ledger).is_err());
    let mut bad = pack.clone();
    put_word(&mut bad, records + 6 * 24 + 4, 1);
    assert!(inspect(&bad, &ledger).is_err());
    let mut pool = Vec::new();
    word(&mut pool, 3);
    text(&mut pool, "title");
    text(&mut pool, "res-text:///Value %1");
    text(&mut pool, "unowned");
    let mut table = vec![0; 16];
    word(&mut table, 1);
    word(&mut table, 0);
    word(&mut table, 1);
    let unused = envelope_fixture(true, pool, table);
    assert!(decode(&unused, "voboost-ru-gauge")
        .unwrap_err()
        .contains("unowned string pool"));
}
