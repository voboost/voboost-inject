//! Byte-derived resource APK identity. The caller separately authenticates the product,
//! APK signing certificate, catalog owner, ledger, and exact installed target digest.
//! Overlay build must store AndroidManifest.xml (ZIP method 0), avoiding a runtime inflater.
extern crate alloc;
use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};
const ANDROID: &str = "http://schemas.android.com/apk/res/android";
const NONE: u32 = u32::MAX;
const MAX_APK: usize = 16 * 1024 * 1024;
const MAX_MANIFEST: usize = 256 * 1024;
type Result<T> = core::result::Result<T, &'static str>;
fn check(ok: bool, why: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}
fn bytes(b: &[u8], p: usize, n: usize) -> Result<&[u8]> {
    b.get(p..p.checked_add(n).ok_or("offset overflow")?)
        .ok_or("truncated binary")
}
fn u16at(b: &[u8], p: usize) -> Result<usize> {
    Ok(u16::from_le_bytes(bytes(b, p, 2)?.try_into().unwrap()) as usize)
}
fn u32at(b: &[u8], p: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(b, p, 4)?.try_into().unwrap()))
}
fn text(b: &[u8]) -> Result<&str> {
    core::str::from_utf8(b).map_err(|_| "invalid UTF-8")
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or("offset overflow")
}
#[derive(Debug, PartialEq, Eq)]
pub struct InspectedResourceApk {
    package: String,
    target: String,
    version: u32,
}
impl InspectedResourceApk {
    pub fn package(&self) -> &str {
        &self.package
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn inspect(blob: &[u8], package: &str, target: &str, version: u32) -> Result<Self> {
        check(
            version > 0 && version <= 2_100_000_000,
            "expected version invalid",
        )?;
        let xml = zip_manifest(blob)?;
        let nodes = parse_axml(xml)?;
        let mut root = None;
        let mut app = None;
        let mut overlay = None;
        for (path, name, attrs) in &nodes {
            match (path.as_slice(), name.as_str()) {
                ([], "manifest") if root.is_none() => root = Some(attrs),
                ([parent], "application") if parent == "manifest" && app.is_none() => {
                    app = Some(attrs)
                }
                ([parent], "overlay") if parent == "manifest" && overlay.is_none() => {
                    overlay = Some(attrs)
                }
                ([parent], "uses-sdk") if parent == "manifest" => {}
                _ => return Err("resource manifest component or duplicate"),
            }
        }
        let root = root.ok_or("manifest missing")?;
        let app = app.ok_or("application missing")?;
        let overlay = overlay.ok_or("overlay missing")?;
        check(
            attr_string(root, "", "package")? == package,
            "overlay package mismatch",
        )?;
        check(
            attr_number(root, ANDROID, "versionCode")? == version,
            "overlay version mismatch",
        )?;
        check(
            !attr_bool(app, ANDROID, "hasCode")?,
            "resource hasCode must be explicit false",
        )?;
        check(
            attr_string(overlay, ANDROID, "targetPackage")? == target,
            "overlay target mismatch",
        )?;
        check(
            !attr_bool(overlay, ANDROID, "isStatic")?,
            "overlay must be dynamic",
        )?;
        Ok(Self {
            package: package.into(),
            target: target.into(),
            version,
        })
    }
}
fn zip_manifest(b: &[u8]) -> Result<&[u8]> {
    check(b.len() >= 22 && b.len() <= MAX_APK, "APK byte bound")?;
    // APK Signing Block precedes the central directory; it is verified elsewhere.
    // EOCD comments are unnecessary for owned resource APKs and are rejected.
    let e = b.len() - 22;
    check(
        u32at(b, e)? == 0x06054b50 && u16at(b, e + 20)? == 0,
        "ZIP end record",
    )?;
    check(
        u16at(b, e + 4)? == 0 && u16at(b, e + 6)? == 0,
        "multi-disk ZIP",
    )?;
    let count = u16at(b, e + 10)?;
    check(
        count > 0 && count <= 1024 && u16at(b, e + 8)? == count,
        "ZIP entry count",
    )?;
    let mut p = u32at(b, e + 16)? as usize;
    check(
        add(p, u32at(b, e + 12)? as usize)? == e,
        "ZIP central bounds",
    )?;
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    let mut manifest = None;
    let mut resources = false;
    let mut regions = Vec::new();
    for _ in 0..count {
        check(u32at(b, p)? == 0x02014b50, "ZIP central record")?;
        let flags = u16at(b, p + 8)?;
        let method = u16at(b, p + 10)?;
        let compressed = u32at(b, p + 20)? as usize;
        let size = u32at(b, p + 24)? as usize;
        let name_len = u16at(b, p + 28)?;
        let extra = u16at(b, p + 30)?;
        let comment = u16at(b, p + 32)?;
        let local = u32at(b, p + 42)? as usize;
        let name_bytes = bytes(b, p + 46, name_len)?;
        let name = text(name_bytes)?;
        check(
            !name.is_empty()
                && !name.starts_with('/')
                && !name.contains('\\')
                && name
                    .trim_end_matches('/')
                    .split('/')
                    .all(|s| !s.is_empty() && s != "." && s != ".."),
            "ZIP unsafe path",
        )?;
        check(names.insert(name), "ZIP duplicate entry")?;
        check(
            flags & (1 | 8 | 0x40 | 0x2000) == 0 && (method == 0 || method == 8),
            "ZIP unsupported flags or compression",
        )?;
        check(
            u16at(b, p + 34)? == 0 && size <= MAX_APK && compressed <= MAX_APK,
            "ZIP entry bounds",
        )?;
        total = add(total, size)?;
        check(total <= MAX_APK, "ZIP expanded byte bound")?;
        let lower = name.to_ascii_lowercase();
        check(
            ![".dex", ".so", ".jar", ".class"]
                .iter()
                .any(|suffix| lower.ends_with(suffix))
                && !name.starts_with("lib/")
                && !name.starts_with("assets/"),
            "resource APK executable entry",
        )?;
        check(
            u32at(b, local)? == 0x04034b50
                && u16at(b, local + 6)? == flags
                && u16at(b, local + 8)? == method
                && u32at(b, local + 14)? == u32at(b, p + 16)?
                && u32at(b, local + 18)? as usize == compressed
                && u32at(b, local + 22)? as usize == size,
            "ZIP local/central mismatch",
        )?;
        let ln = u16at(b, local + 26)?;
        let le = u16at(b, local + 28)?;
        check(
            bytes(b, local + 30, ln)? == name_bytes,
            "ZIP local filename mismatch",
        )?;
        let start = add(add(local + 30, ln)?, le)?;
        let end = add(start, compressed)?;
        check(
            end <= u32at(b, e + 16)? as usize,
            "ZIP local payload overlaps directory",
        )?;
        regions.push((local, end));
        if name == "AndroidManifest.xml" {
            check(
                method == 0 && size == compressed && size <= MAX_MANIFEST,
                "manifest must be stored and bounded",
            )?;
            manifest = Some(bytes(b, start, size)?);
        }
        if name == "resources.arsc" {
            check(size > 0, "empty resource table")?;
            resources = true;
        }
        p = add(add(add(p + 46, name_len)?, extra)?, comment)?;
        check(p <= e, "central record bounds")?;
    }
    check(p == e && resources, "resource APK central inventory")?;
    regions.sort_unstable();
    check(
        regions.windows(2).all(|r| r[0].1 <= r[1].0),
        "overlapping ZIP entries",
    )?;
    manifest.ok_or("manifest missing")
}
#[derive(Debug)]
enum Value {
    String(String),
    Number(u32),
    Boolean(bool),
}
type Attrs = BTreeMap<(String, String), Value>;
type Node = (Vec<String>, String, Attrs);
fn attr_string<'a>(attrs: &'a Attrs, ns: &str, key: &str) -> Result<&'a str> {
    match attrs.get(&(ns.into(), key.into())) {
        Some(Value::String(v)) => Ok(v),
        _ => Err("string attribute missing or wrong type"),
    }
}
fn attr_number(attrs: &Attrs, ns: &str, key: &str) -> Result<u32> {
    match attrs.get(&(ns.into(), key.into())) {
        Some(Value::Number(v)) => Ok(*v),
        _ => Err("number attribute missing or wrong type"),
    }
}
fn attr_bool(attrs: &Attrs, ns: &str, key: &str) -> Result<bool> {
    match attrs.get(&(ns.into(), key.into())) {
        Some(Value::Boolean(v)) => Ok(*v),
        _ => Err("boolean attribute missing or wrong type"),
    }
}
fn string(strings: &[String], i: u32) -> Result<&str> {
    strings
        .get(i as usize)
        .map(String::as_str)
        .ok_or("AXML string index")
}
fn length(b: &[u8], p: &mut usize, utf8: bool) -> Result<usize> {
    let (first, high, shift, step) = if utf8 {
        (bytes(b, *p, 1)?[0] as usize, 0x80, 8, 1)
    } else {
        (u16at(b, *p)?, 0x8000, 16, 2)
    };
    *p = add(*p, step)?;
    if first & high == 0 {
        return Ok(first);
    }
    let second = if utf8 {
        bytes(b, *p, 1)?[0] as usize
    } else {
        u16at(b, *p)?
    };
    *p = add(*p, step)?;
    Ok(((first & (high - 1)) << shift) | second)
}
fn charge(total: &mut usize, count: usize) -> Result<()> {
    *total = add(*total, count)?;
    check(*total <= MAX_MANIFEST * 2, "AXML decoded allocation bound")
}
fn parse_axml(b: &[u8]) -> Result<Vec<Node>> {
    check(
        b.len() >= 8
            && b.len() <= MAX_MANIFEST
            && u16at(b, 0)? == 3
            && u16at(b, 2)? == 8
            && u32at(b, 4)? as usize == b.len(),
        "AXML root envelope",
    )?;
    let mut decoded_bytes = 0usize;
    let mut p = 8;
    let mut strings = None;
    let mut resources: Option<Vec<u32>> = None;
    let mut stack: Vec<String> = Vec::new();
    let mut nodes = Vec::new();
    while p < b.len() {
        let kind = u16at(b, p)?;
        let head = u16at(b, p + 2)?;
        let size = u32at(b, p + 4)? as usize;
        check(head >= 8 && size >= head, "AXML chunk header")?;
        let chunk = bytes(b, p, size)?;
        match kind {
            1 => {
                check(
                    strings.is_none() && head >= 28,
                    "AXML string pool singleton",
                )?;
                let count = u32at(chunk, 8)? as usize;
                let flags = u32at(chunk, 16)?;
                let start = u32at(chunk, 20)? as usize;
                check(
                    count <= 8192
                        && u32at(chunk, 12)? == 0
                        && u32at(chunk, 24)? == 0
                        && flags & !0x101 == 0
                        && add(head, count * 4)? <= start
                        && start <= size,
                    "AXML string pool bounds",
                )?;
                let mut parsed = Vec::new();
                for i in 0..count {
                    let mut q = add(start, u32at(chunk, head + i * 4)? as usize)?;
                    let chars = length(chunk, &mut q, flags & 0x100 != 0)?;
                    let value = if flags & 0x100 != 0 {
                        let n = length(chunk, &mut q, true)?;
                        check(bytes(chunk, add(q, n)?, 1)? == [0], "AXML UTF8 terminator")?;
                        let s = text(bytes(chunk, q, n)?)?;
                        check(s.encode_utf16().count() == chars, "AXML UTF8 count")?;
                        s.to_owned()
                    } else {
                        check(
                            bytes(chunk, add(q, chars * 2)?, 2)? == [0, 0],
                            "AXML UTF16 terminator",
                        )?;
                        let v = bytes(chunk, q, chars * 2)?
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|x| u16::from_le_bytes(*x))
                            .collect::<Vec<_>>();
                        String::from_utf16(&v).map_err(|_| "AXML invalid UTF16")?
                    };
                    charge(&mut decoded_bytes, value.len())?;
                    parsed.push(value);
                }
                strings = Some(parsed);
            }
            0x102 => {
                check(
                    head == 16 && size >= 36 && u32at(chunk, 16)? == NONE,
                    "AXML start node",
                )?;
                let pool = strings.as_deref().ok_or("AXML missing strings")?;
                let name = string(pool, u32at(chunk, 20)?)?;
                charge(&mut decoded_bytes, name.len() * 2)?;
                let name = name.to_owned();
                let offset = u16at(chunk, 24)?;
                let stride = u16at(chunk, 26)?;
                let count = u16at(chunk, 28)?;
                check(
                    offset >= 20
                        && stride == 20
                        && count <= 128
                        && add(16 + offset, count * stride)? <= size,
                    "AXML attributes bounds",
                )?;
                let mut attrs = BTreeMap::new();
                let mut attribute_ids = BTreeSet::new();
                for i in 0..count {
                    let a = 16 + offset + i * stride;
                    let ns = u32at(chunk, a)?;
                    let ns = if ns == NONE { "" } else { string(pool, ns)? };
                    let name_index = u32at(chunk, a + 4)?;
                    let attr_name = string(pool, name_index)?;
                    let resource_id = resources
                        .as_ref()
                        .and_then(|r| r.get(name_index as usize))
                        .copied()
                        .unwrap_or(0);
                    if resource_id != 0 {
                        check(
                            attribute_ids.insert(resource_id),
                            "AXML duplicate resource attribute ID",
                        )?;
                    }
                    let reserved_name = match resource_id {
                        0x0101000c => Some("hasCode"),
                        0x0101021b => Some("versionCode"),
                        0x01010021 => Some("targetPackage"),
                        0x0101055a => Some("isStatic"),
                        0x01010576 => return Err("APK versionCodeMajor is unsupported"),
                        _ => None,
                    };
                    if let Some(expected) = reserved_name {
                        check(
                            ns == ANDROID && attr_name == expected,
                            "AXML reserved resource ID alias",
                        )?;
                    }
                    check(
                        !(ns == ANDROID && attr_name == "versionCodeMajor"),
                        "APK versionCodeMajor is unsupported",
                    )?;
                    charge(&mut decoded_bytes, ns.len() + attr_name.len())?;
                    if ns == ANDROID {
                        let expected = match attr_name {
                            "hasCode" => Some(0x0101000c),
                            "versionCode" => Some(0x0101021b),
                            "targetPackage" => Some(0x01010021),
                            "isStatic" => Some(0x0101055a),
                            _ => None,
                        };
                        if let Some(expected) = expected {
                            check(
                                resources
                                    .as_ref()
                                    .and_then(|r| r.get(name_index as usize))
                                    .copied()
                                    == Some(expected),
                                "AXML framework attribute resource ID mismatch",
                            )?;
                        }
                    }
                    let key = (ns.to_owned(), attr_name.to_owned());
                    check(
                        u16at(chunk, a + 12)? == 8 && bytes(chunk, a + 14, 1)? == [0],
                        "AXML attribute header",
                    )?;
                    let raw = u32at(chunk, a + 8)?;
                    let value = u32at(chunk, a + 16)?;
                    let value = match bytes(chunk, a + 15, 1)?[0] {
                        3 => {
                            let value = string(pool, value)?;
                            if raw != NONE {
                                check(string(pool, raw)? == value, "AXML conflicting string")?;
                            }
                            charge(&mut decoded_bytes, value.len())?;
                            Value::String(value.into())
                        }
                        0x10 => Value::Number(value),
                        0x12 => {
                            check(
                                value == 0 || value == u32::MAX || value == 1,
                                "AXML boolean encoding",
                            )?;
                            Value::Boolean(value != 0)
                        }
                        _ => return Err("AXML unsupported attribute type"),
                    };
                    check(
                        attrs.insert(key, value).is_none(),
                        "AXML duplicate attribute",
                    )?;
                }
                check(stack.len() < 8 && nodes.len() < 64, "AXML node bounds")?;
                charge(&mut decoded_bytes, stack.iter().map(String::len).sum())?;
                nodes.push((stack.clone(), name.clone(), attrs));
                stack.push(name);
            }
            0x103 => {
                check(head == 16 && size == 24, "AXML end node")?;
                let pool = strings.as_deref().ok_or("AXML missing strings")?;
                check(
                    stack.pop().as_deref() == Some(string(pool, u32at(chunk, 20)?)?),
                    "AXML mismatched end",
                )?;
            }
            0x180 => {
                check(
                    head == 8
                        && resources.is_none()
                        && (size - 8).is_multiple_of(4)
                        && (size - 8) / 4 <= 8192,
                    "AXML resource map",
                )?;
                resources = Some(
                    (8..size)
                        .step_by(4)
                        .map(|i| u32at(chunk, i))
                        .collect::<Result<Vec<_>>>()?,
                );
            }
            0x100 | 0x101 => {}
            _ => return Err("AXML unsupported chunk"),
        }
        p = add(p, size)?;
    }
    check(
        stack.is_empty() && !nodes.is_empty(),
        "AXML incomplete tree",
    )?;
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    fn w16(out: &mut Vec<u8>, v: usize) {
        out.extend_from_slice(&(v as u16).to_le_bytes());
    }
    fn w32(out: &mut Vec<u8>, v: u32) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn chunk(kind: usize, head: usize, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        w16(&mut out, kind);
        w16(&mut out, head);
        w32(&mut out, (body.len() + 8) as u32);
        out.extend_from_slice(body);
        out
    }
    fn xml(has_code: bool) -> Vec<u8> {
        let strings = [
            "manifest",
            "application",
            "overlay",
            "package",
            "ru.voboost.translation.setting",
            ANDROID,
            "versionCode",
            "hasCode",
            "targetPackage",
            "com.qinggan.app.setting",
            "isStatic",
        ];
        let mut offsets = Vec::new();
        let mut encoded = Vec::new();
        for text in strings {
            offsets.push(encoded.len() as u32);
            encoded.push(text.len() as u8);
            encoded.push(text.len() as u8);
            encoded.extend_from_slice(text.as_bytes());
            encoded.push(0);
        }
        while !encoded.len().is_multiple_of(4) {
            encoded.push(0);
        }
        let mut pool = Vec::new();
        for v in [
            strings.len() as u32,
            0,
            0x100,
            28 + strings.len() as u32 * 4,
            0,
        ] {
            w32(&mut pool, v);
        }
        for offset in offsets {
            w32(&mut pool, offset);
        }
        pool.extend_from_slice(&encoded);
        let mut body = chunk(1, 28, &pool);
        let mut map = Vec::new();
        for id in [
            0, 0, 0, 0, 0, 0, 0x0101021b, 0x0101000c, 0x01010021, 0, 0x0101055a,
        ] {
            w32(&mut map, id);
        }
        body.extend_from_slice(&chunk(0x180, 8, &map));
        fn tag(name: u32, attrs: &[(u32, u32, u8, u32)]) -> Vec<u8> {
            let mut b = Vec::new();
            for v in [1, NONE, NONE, name] {
                w32(&mut b, v);
            }
            for v in [20, 20, attrs.len(), 0, 0, 0] {
                w16(&mut b, v);
            }
            for (ns, key, kind, value) in attrs {
                for v in [*ns, *key, NONE] {
                    w32(&mut b, v);
                }
                w16(&mut b, 8);
                b.push(0);
                b.push(*kind);
                w32(&mut b, *value);
            }
            chunk(0x102, 16, &b)
        }
        fn end(name: u32) -> Vec<u8> {
            let mut b = Vec::new();
            for v in [1, NONE, NONE, name] {
                w32(&mut b, v);
            }
            chunk(0x103, 16, &b)
        }
        body.extend_from_slice(&tag(0, &[(NONE, 3, 3, 4), (5, 6, 0x10, 1)]));
        body.extend_from_slice(&tag(2, &[(5, 8, 3, 9), (5, 10, 0x12, 0)]));
        body.extend_from_slice(&end(2));
        body.extend_from_slice(&tag(1, &[(5, 7, 0x12, u32::from(has_code))]));
        body.extend_from_slice(&end(1));
        body.extend_from_slice(&end(0));
        chunk(3, 8, &body)
    }
    fn crc32(b: &[u8]) -> u32 {
        let mut c = !0u32;
        for byte in b {
            c ^= *byte as u32;
            for _ in 0..8 {
                c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
            }
        }
        !c
    }
    fn zip(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let start = out.len() as u32;
            let crc = crc32(data);
            let len = data.len() as u32;
            w32(&mut out, 0x04034b50);
            for v in [20, 0, 0, 0, 0] {
                w16(&mut out, v);
            }
            for v in [crc, len, len] {
                w32(&mut out, v);
            }
            w16(&mut out, name.len());
            w16(&mut out, 0);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            w32(&mut central, 0x02014b50);
            for v in [20, 20, 0, 0, 0, 0] {
                w16(&mut central, v);
            }
            for v in [crc, len, len] {
                w32(&mut central, v);
            }
            for v in [name.len(), 0, 0, 0, 0] {
                w16(&mut central, v);
            }
            w32(&mut central, 0);
            w32(&mut central, start);
            central.extend_from_slice(name.as_bytes());
        }
        let offset = out.len() as u32;
        let size = central.len() as u32;
        out.extend_from_slice(&central);
        w32(&mut out, 0x06054b50);
        for v in [0, 0, entries.len(), entries.len()] {
            w16(&mut out, v);
        }
        w32(&mut out, size);
        w32(&mut out, offset);
        w16(&mut out, 0);
        out
    }
    fn fixture() -> Vec<u8> {
        zip(&[
            ("AndroidManifest.xml", xml(false)),
            ("resources.arsc", vec![1]),
        ])
    }
    fn inspect(b: &[u8]) -> Result<InspectedResourceApk> {
        InspectedResourceApk::inspect(
            b,
            "ru.voboost.translation.setting",
            "com.qinggan.app.setting",
            1,
        )
    }
    #[test]
    fn accepts_byte_derived_identity() {
        let r = inspect(&fixture()).unwrap();
        assert_eq!(r.package(), "ru.voboost.translation.setting");
        assert_eq!(r.target(), "com.qinggan.app.setting");
        assert_eq!(r.version(), 1);
    }
    #[test]
    fn rejects_explicit_code() {
        assert!(inspect(&zip(&[
            ("AndroidManifest.xml", xml(true)),
            ("resources.arsc", vec![1])
        ]))
        .is_err());
    }
    #[test]
    fn rejects_executable_entry() {
        for name in ["classes.dex", "res/a.DEX", "lib/a.so", "assets/x"] {
            assert!(
                inspect(&zip(&[
                    ("AndroidManifest.xml", xml(false)),
                    ("resources.arsc", vec![1]),
                    (name, vec![1])
                ]))
                .is_err(),
                "{name}"
            );
        }
    }
    #[test]
    fn rejects_duplicate_or_traversal() {
        for name in ["resources.arsc", "../x"] {
            assert!(inspect(&zip(&[
                ("AndroidManifest.xml", xml(false)),
                ("resources.arsc", vec![1]),
                (name, vec![1])
            ]))
            .is_err());
        }
    }
    #[test]
    fn rejects_wrong_expected_identity() {
        let b = fixture();
        assert!(
            InspectedResourceApk::inspect(&b, "other.package", "com.qinggan.app.setting", 1)
                .is_err()
        );
        assert!(InspectedResourceApk::inspect(
            &b,
            "ru.voboost.translation.setting",
            "other.target",
            1
        )
        .is_err());
        assert!(InspectedResourceApk::inspect(
            &b,
            "ru.voboost.translation.setting",
            "com.qinggan.app.setting",
            2
        )
        .is_err());
    }
    #[test]
    fn all_truncations_reject() {
        let b = fixture();
        for n in 0..b.len() {
            assert!(inspect(&b[..n]).is_err(), "{n}");
        }
    }
    #[test]
    fn one_byte_mutations_do_not_panic() {
        let b = fixture();
        for i in 0..b.len() {
            let mut changed = b.clone();
            changed[i] ^= 0xff;
            let _ = inspect(&changed);
        }
    }
    #[test]
    fn rejects_framework_resource_id_spoof() {
        let mut b = xml(false);
        let marker = 0x0101000cu32.to_le_bytes();
        let p = b.windows(4).position(|x| x == marker).unwrap();
        b[p] ^= 1;
        assert!(inspect(&zip(&[
            ("AndroidManifest.xml", b),
            ("resources.arsc", vec![1])
        ]))
        .is_err());
    }
    #[test]
    fn bounded_random_inputs_do_not_panic() {
        for n in 0..200 {
            let b = format!("not-an-apk-{n}").into_bytes();
            assert!(inspect(&b).is_err());
        }
    }
    fn add_attribute(
        mut b: Vec<u8>,
        element: u32,
        name: u32,
        resource_id: u32,
        value: u32,
    ) -> Vec<u8> {
        let pool_size = u32at(&b, 12).unwrap() as usize;
        let map = 8 + pool_size;
        b[map + 8 + name as usize * 4..map + 12 + name as usize * 4]
            .copy_from_slice(&resource_id.to_le_bytes());
        let mut p = map + u32at(&b, map + 4).unwrap() as usize;
        loop {
            if u16at(&b, p).unwrap() == 0x102 && u32at(&b, p + 20).unwrap() == element {
                break;
            }
            p += u32at(&b, p + 4).unwrap() as usize;
        }
        let oldsize = u32at(&b, p + 4).unwrap() as usize;
        let count = u16at(&b, p + 28).unwrap();
        let mut attr = Vec::new();
        for v in [5, name, NONE] {
            w32(&mut attr, v);
        }
        w16(&mut attr, 8);
        attr.push(0);
        attr.push(0x12);
        w32(&mut attr, value);
        b.splice(p + oldsize..p + oldsize, attr);
        b[p + 4..p + 8].copy_from_slice(&((oldsize + 20) as u32).to_le_bytes());
        b[p + 28..p + 30].copy_from_slice(&((count + 1) as u16).to_le_bytes());
        let len = b.len() as u32;
        b[4..8].copy_from_slice(&len.to_le_bytes());
        b
    }
    #[test]
    fn rejects_unknown_alias_of_reserved_id() {
        let b = add_attribute(xml(false), 1, 4, 0x01010021, 1);
        assert_eq!(
            parse_axml(&b).unwrap_err(),
            "AXML reserved resource ID alias"
        );
    }
    #[test]
    fn rejects_version_code_major_id_alias() {
        let b = add_attribute(xml(false), 0, 4, 0x01010576, 1);
        assert_eq!(
            parse_axml(&b).unwrap_err(),
            "APK versionCodeMajor is unsupported"
        );
    }
    #[test]
    fn bounds_aliased_string_allocations() {
        let count = 32;
        let n = 30000;
        let mut pool = Vec::new();
        for v in [count, 0, 0x100, 28 + count * 4, 0] {
            w32(&mut pool, v);
        }
        for _ in 0..count {
            w32(&mut pool, 0);
        }
        for _ in 0..2 {
            pool.push(0x80 | ((n >> 8) as u8));
            pool.push(n as u8);
        }
        pool.extend_from_slice(&vec![b'a'; n]);
        pool.push(0);
        while !pool.len().is_multiple_of(4) {
            pool.push(0);
        }
        let b = chunk(3, 8, &chunk(1, 28, &pool));
        assert_eq!(parse_axml(&b).unwrap_err(), "AXML decoded allocation bound");
    }
}
