//! Offline OEM configuration emission from the supplied ELF's proven DWARF/data.
use crate::{
    pw_readback_types::{inspect_type, AbiType, TypeProof},
    supervisor_elf::DataReader,
    Result,
};
use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
#[derive(Clone, Copy)]
enum Kind {
    Text,
    Vector,
    Signed,
    Unsigned,
    Enum,
}
const EXEC: [(&str, Kind); 12] = [
    ("m_args", Kind::Vector),
    ("m_envs", Kind::Vector),
    ("m_notify", Kind::Enum),
    ("m_readyFile", Kind::Text),
    ("m_desc", Kind::Text),
    ("m_depCnt", Kind::Signed),
    ("m_deplist", Kind::Text),
    ("m_restart_par", Kind::Signed),
    ("m_bootdeps", Kind::Vector),
    ("m_startupfailed_action", Kind::Enum),
    ("m_checkpath", Kind::Text),
    ("m_monitorfailed_action", Kind::Enum),
];
const MKDIR: [(&str, Kind); 8] = [
    ("m_path", Kind::Text),
    ("m_mode", Kind::Unsigned),
    ("m_option", Kind::Signed),
    ("m_notify", Kind::Enum),
    ("m_readyFile", Kind::Text),
    ("m_desc", Kind::Text),
    ("m_depCnt", Kind::Signed),
    ("m_deplist", Kind::Text),
];
struct Schema {
    bytes: u64,
    offsets: BTreeMap<String, u64>,
}
fn character(t: &AbiType) -> bool {
    matches!(t, AbiType::Signed(1) | AbiType::Unsigned(1))
}
fn text_type(t: &AbiType) -> bool {
    matches!(t,AbiType::Pointer(x) if character(x))
}
fn vector_type(t: &AbiType) -> bool {
    matches!(t,AbiType::Pointer(x) if text_type(x))
}
fn schema(proof: TypeProof, expected: &[(&str, Kind)], bytes: u64) -> Result<Schema> {
    if proof.bytes != bytes || proof.bases != 0 || proof.members.len() != expected.len() {
        return Err("supervisor default record shape".into());
    }
    let mut offsets = BTreeMap::new();
    let mut extents = Vec::new();
    for member in proof.members {
        let kind = expected
            .iter()
            .find(|(name, _)| *name == member.name)
            .map(|v| v.1)
            .ok_or("supervisor unexpected record field")?;
        let (valid, width) = match kind {
            Kind::Text => (text_type(&member.ty), 8),
            Kind::Vector => (vector_type(&member.ty), 8),
            Kind::Signed => (matches!(member.ty, AbiType::Signed(4)), 4),
            Kind::Unsigned => (matches!(member.ty, AbiType::Unsigned(4)), 4),
            Kind::Enum => (
                matches!(
                    member.ty,
                    AbiType::Named {
                        tag: 4,
                        bytes: 4,
                        ..
                    }
                ),
                4,
            ),
        };
        let end = member
            .offset
            .checked_add(width)
            .ok_or("supervisor field overflow")?;
        if !valid
            || member.offset % width != 0
            || end > bytes
            || extents.iter().any(|&(a, b)| member.offset < b && end > a)
            || offsets.insert(member.name, member.offset).is_some()
        {
            return Err("supervisor default field type or extent".into());
        }
        extents.push((member.offset, end));
    }
    Ok(Schema { bytes, offsets })
}
#[derive(Debug, PartialEq, Eq)]
struct Row {
    vectors: BTreeMap<String, Vec<String>>,
    texts: BTreeMap<String, Option<String>>,
    numbers: BTreeMap<String, i64>,
    null_vectors: BTreeMap<String, bool>,
}
fn vector(reader: &DataReader<'_>, address: u64) -> Result<Vec<String>> {
    let mut values = Vec::new();
    if address == 0 {
        return Ok(values);
    }
    for i in 0..=64 {
        let p = reader.pointer(
            address
                .checked_add(i * 8)
                .ok_or("supervisor vector overflow")?,
        )?;
        if p == 0 {
            return Ok(values);
        }
        if i == 64 {
            return Err("supervisor vector count bound".into());
        }
        values.push(reader.string(p, 99)?);
    }
    Err("supervisor unterminated vector".into())
}
fn table_count(bytes: u64, stride: u64) -> Result<u64> {
    if bytes == 0 || stride == 0 || !bytes.is_multiple_of(stride) || bytes / stride > 128 {
        return Err("supervisor default table count".into());
    }
    Ok(bytes / stride)
}
fn rows(
    reader: &DataReader<'_>,
    symbol: &str,
    shape: &Schema,
    fields: &[(&str, Kind)],
) -> Result<Vec<Row>> {
    let object = reader.object(symbol)?;
    let count = table_count(object.bytes, shape.bytes)?;
    let mut result = Vec::new();
    for i in 0..count {
        let base = object
            .address
            .checked_add(i * shape.bytes)
            .ok_or("supervisor row address")?;
        let mut row = Row {
            vectors: BTreeMap::new(),
            texts: BTreeMap::new(),
            numbers: BTreeMap::new(),
            null_vectors: BTreeMap::new(),
        };
        for &(name, kind) in fields {
            let at = base
                .checked_add(
                    *shape
                        .offsets
                        .get(name)
                        .ok_or("supervisor missing schema offset")?,
                )
                .ok_or("supervisor field address")?;
            match kind {
                Kind::Vector => {
                    let pointer = reader.pointer(at)?;
                    row.vectors
                        .insert(name.to_string(), vector(reader, pointer)?);
                    row.null_vectors.insert(name.to_string(), pointer == 0);
                }
                Kind::Text => {
                    let pointer = reader.pointer(at)?;
                    row.texts.insert(
                        name.to_string(),
                        if pointer == 0 {
                            None
                        } else {
                            Some(reader.string(pointer, 99)?)
                        },
                    );
                }
                Kind::Signed | Kind::Enum | Kind::Unsigned => {
                    let value = u32::from_le_bytes(
                        reader
                            .bytes(at, 4)?
                            .try_into()
                            .map_err(|_| "supervisor integer width")?,
                    );
                    row.numbers.insert(
                        name.to_string(),
                        if matches!(kind, Kind::Unsigned) {
                            value as i64
                        } else {
                            value as i32 as i64
                        },
                    );
                }
            }
        }
        result.push(row);
    }
    Ok(result)
}
fn inspect(file: &[u8]) -> Result<(Vec<Row>, Vec<Row>)> {
    let exec = schema(inspect_type(file, "tp_action_exec_t")?, &EXEC, 96)?;
    let mkdir = schema(inspect_type(file, "tp_action_mkdir_t")?, &MKDIR, 56)?;
    let reader = DataReader::open(file)?;
    for category in ["mount_actions", "insmod_actions", "touch_actions"] {
        if reader.object(category)?.bytes != 0 {
            return Err("supervisor nonempty unsupported action category".into());
        }
    }
    let exec = rows(&reader, "exec_actionsTbl", &exec, &EXEC)?;
    let mkdir = rows(&reader, "mkdir_actions", &mkdir, &MKDIR)?;
    if exec
        .iter()
        .any(|r| r.vectors.get("m_args").is_none_or(|v| v.is_empty()))
    {
        return Err("supervisor executable argv absent".into());
    }
    Ok((exec, mkdir))
}
fn escape(output: &mut String, value: &str) -> Result<()> {
    for c in value.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            '\t' | '\n' | '\r' => output.push(c),
            c if c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}' => output.push(c),
            _ => return Err("supervisor XML character unsupported".into()),
        }
    }
    Ok(())
}
fn text(out: &mut String, name: &str, value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    out.push('<');
    out.push_str(name);
    out.push('>');
    escape(out, value)?;
    out.push_str("</");
    out.push_str(name);
    out.push('>');
    Ok(())
}
fn array(out: &mut String, name: &str, item: &str, values: &[String], is_null: bool) -> Result<()> {
    if is_null && !values.is_empty() {
        return Err("NULL supervisor vector has entries".into());
    }
    let count = if values.is_empty() && !is_null {
        1
    } else {
        values.len()
    };
    out.push_str(&format!("<{name} nums=\"{count}\">"));
    for value in values {
        text(out, item, Some(value))?;
    }
    out.push_str("<exp/></");
    out.push_str(name);
    out.push('>');
    Ok(())
}
fn emit_row(out: &mut String, row: &Row, fields: &[(&str, Kind)], mkdir: bool) -> Result<()> {
    for &(name, kind) in fields {
        match kind {
            Kind::Vector => array(
                out,
                name,
                match name {
                    "m_args" => "arg",
                    "m_envs" => "env",
                    _ => "ref",
                },
                row.vectors.get(name).ok_or("supervisor vector missing")?,
                *row.null_vectors
                    .get(name)
                    .ok_or("supervisor vector NULL evidence missing")?,
            )?,
            Kind::Text => text(
                out,
                if mkdir && name == "m_readyFile" {
                    "m_readyfile"
                } else {
                    name
                },
                row.texts
                    .get(name)
                    .ok_or("supervisor text missing")?
                    .as_deref(),
            )?,
            _ => {
                let number = row.numbers.get(name).ok_or("supervisor number missing")?;
                let value = if mkdir && name == "m_mode" {
                    format!("0{number:o}")
                } else {
                    number.to_string()
                };
                text(out, name, Some(&value))?;
            }
        }
    }
    Ok(())
}
/// Builds staging bytes only. Does not execute OEM tools or write any filesystem.
pub(crate) fn emit(file: &[u8]) -> Result<Vec<u8>> {
    let (exec, mkdir) = inspect(file)?;
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<clsboot_root>");
    out.push_str(&format!("<action_execs nums=\"{}\">", exec.len()));
    for row in &exec {
        out.push_str("<action_exec>");
        emit_row(&mut out, row, &EXEC, false)?;
        out.push_str("</action_exec>");
    }
    out.push_str("</action_execs><action_mounts nums=\"0\"/>");
    out.push_str(&format!("<action_mkdirs nums=\"{}\">", mkdir.len()));
    for row in &mkdir {
        out.push_str("<action_mkdir>");
        emit_row(&mut out, row, &MKDIR, true)?;
        out.push_str("</action_mkdir>");
    }
    out.push_str(
        "</action_mkdirs><action_insmods nums=\"0\"/><action_touchs nums=\"0\"/></clsboot_root>\n",
    );
    if out.len() > 262144 {
        return Err("supervisor XML output bound".into());
    }
    Ok(out.into_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pw_readback_types::Member;
    use alloc::boxed::Box;
    fn shape() -> TypeProof {
        TypeProof {
            name: "tp_action_exec_t".to_string(),
            bytes: 96,
            bases: 0,
            implicit_destructor: false,
            members: EXEC
                .iter()
                .map(|&(name, kind)| {
                    let offset = match name {
                        "m_args" => 0,
                        "m_envs" => 8,
                        "m_notify" => 16,
                        "m_readyFile" => 24,
                        "m_desc" => 32,
                        "m_depCnt" => 40,
                        "m_deplist" => 48,
                        "m_restart_par" => 56,
                        "m_bootdeps" => 64,
                        "m_startupfailed_action" => 72,
                        "m_checkpath" => 80,
                        _ => 88,
                    };
                    let charptr = AbiType::Pointer(Box::new(AbiType::Signed(1)));
                    let ty = match kind {
                        Kind::Text => charptr,
                        Kind::Vector => AbiType::Pointer(Box::new(charptr)),
                        Kind::Signed => AbiType::Signed(4),
                        Kind::Unsigned => AbiType::Unsigned(4),
                        Kind::Enum => AbiType::Named {
                            tag: 4,
                            name: String::new(),
                            bytes: 4,
                        },
                    };
                    Member {
                        name: name.to_string(),
                        offset,
                        ty,
                    }
                })
                .collect(),
        }
    }
    #[test]
    fn proven_schema_requires_every_field() {
        assert!(schema(shape(), &EXEC, 96).is_ok());
        for choice in 0..5 {
            let mut s = shape();
            match choice {
                0 => s.members.pop().map(|_| ()).unwrap(),
                1 => s.bases = 1,
                2 => s.members[1].ty = AbiType::Unsigned(8),
                3 => s.members[1].offset = 0,
                _ => s.bytes = 88,
            };
            assert!(schema(s, &EXEC, 96).is_err());
        }
    }
    #[test]
    fn escaping_and_array_sentinel() {
        let mut out = String::new();
        array(&mut out, "m_envs", "env", &["A=<&>\"'".to_string()], false).unwrap();
        assert_eq!(
            out,
            "<m_envs nums=\"1\"><env>A=&lt;&amp;&gt;&quot;&apos;</env><exp/></m_envs>"
        );
        assert!(escape(&mut out, "\0").is_err());
    }
    #[test]
    fn malformed_table_counts() {
        for bytes in [0, 95, 97, 96 * 129] {
            assert!(table_count(bytes, 96).is_err());
        }
        assert_eq!(table_count(96 * 26, 96).unwrap(), 26);
        assert_eq!(table_count(96 * 28, 96).unwrap(), 28);
    }
    #[test]
    fn malformed_elf_cannot_emit() {
        assert!(emit(&[]).is_err());
        assert!(emit(b"not ELF").is_err());
    }
    #[test]
    #[ignore = "requires actual retained supervisor ELFs"]
    fn actual_four_tables() {
        let keys = [
            "VOBOOST_A9_CLUSTERBOOT",
            "VOBOOST_A9_SYSMGR",
            "VOBOOST_A11_CLUSTERBOOT",
            "VOBOOST_A11_SYSMGR",
        ];
        let mut previous = None;
        for (i, key) in keys.iter().enumerate() {
            let file = std::fs::read(std::env::var(key).unwrap()).unwrap();
            let (exec, mkdir) = inspect(&file).unwrap();
            assert_eq!(exec.len(), if i < 2 { 26 } else { 28 });
            assert_eq!(mkdir.len(), 9);
            let output = emit(&file).unwrap();
            assert!(core::str::from_utf8(&output)
                .unwrap()
                .contains("<m_readyfile>"));
            if i % 2 == 1 {
                assert_eq!(previous.as_ref().unwrap(), &exec);
            }
            previous = Some(exec);
        }
    }
}

#[cfg(test)]
mod normalized_tests {
    use super::*;
    #[test]
    #[ignore = "requires retained actual ELFs and independently extracted normalized JSON"]
    fn actual_normalized_json_fields() {
        let path = std::env::var("VOBOOST_SUPERVISOR_DEFAULT_TABLES_JSON").unwrap();
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for (i, key) in [
            "VOBOOST_A9_CLUSTERBOOT",
            "VOBOOST_A9_SYSMGR",
            "VOBOOST_A11_CLUSTERBOOT",
            "VOBOOST_A11_SYSMGR",
        ]
        .iter()
        .enumerate()
        {
            let file = std::fs::read(std::env::var(key).unwrap()).unwrap();
            let (exec, mkdir) = inspect(&file).unwrap();
            let table = &expected["tables"][i];
            for (rows, category) in [(&exec, "exec_actions"), (&mkdir, "mkdir_actions")] {
                let wanted = table[category].as_array().unwrap();
                assert_eq!(rows.len(), wanted.len());
                for (row, json) in rows.iter().zip(wanted) {
                    for (name, value) in &row.vectors {
                        assert_eq!(serde_json::to_value(value).unwrap(), json[name]);
                    }
                    for (name, value) in &row.texts {
                        assert_eq!(serde_json::to_value(value).unwrap(), json[name]);
                    }
                    for (name, value) in &row.numbers {
                        assert_eq!(serde_json::to_value(value).unwrap(), json[name]);
                    }
                    if category == "exec_actions" {
                        assert_eq!(
                            serde_json::to_value(&row.null_vectors).unwrap(),
                            json["null_array_pointers"]
                        );
                        assert_eq!(json["argc"], row.vectors["m_args"].len());
                        assert_eq!(json["envc"], row.vectors["m_envs"].len());
                        assert_eq!(json["bootdeps_count"], row.vectors["m_bootdeps"].len());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod null_preservation_tests {
    use super::*;
    #[test]
    fn omitted_null_scalar_differs_from_present_empty() {
        let mut absent = String::new();
        text(&mut absent, "m_checkpath", None).unwrap();
        assert_eq!(absent, "");
        let mut present = String::new();
        text(&mut present, "m_checkpath", Some("")).unwrap();
        assert_eq!(present, "<m_checkpath></m_checkpath>");
    }
    #[test]
    fn empty_environment_preserves_null_pointer_distinction() {
        let mut nonnull = String::new();
        array(&mut nonnull, "m_envs", "env", &[], false).unwrap();
        assert_eq!(nonnull, "<m_envs nums=\"1\"><exp/></m_envs>");
        let mut null = String::new();
        array(&mut null, "m_envs", "env", &[], true).unwrap();
        assert_eq!(null, "<m_envs nums=\"0\"><exp/></m_envs>");
    }
    #[test]
    fn nonempty_vector_count_and_null_consistency() {
        let mut out = String::new();
        array(
            &mut out,
            "m_envs",
            "env",
            &["A=1".to_string(), "A=2".to_string()],
            false,
        )
        .unwrap();
        assert_eq!(
            out,
            "<m_envs nums=\"2\"><env>A=1</env><env>A=2</env><exp/></m_envs>"
        );
        assert!(array(
            &mut String::new(),
            "m_envs",
            "env",
            &["A=1".to_string()],
            true
        )
        .is_err());
    }
}
