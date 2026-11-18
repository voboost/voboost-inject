//! Bounded, byte-preserving edits to the OEM supervisor configuration.
use crate::Result;
use alloc::{format, string::String, vec::Vec};

const MAX_XML: usize = 1024 * 1024;
const MAX_NODES: usize = 8192;
const MAX_ITEMS: usize = 256;
#[derive(Debug)]
struct Node {
    name: String,
    start: usize,
    content: usize,
    end_content: usize,
    end: usize,
    parent: Option<usize>,
    nums: Option<usize>,
    nums_range: Option<(usize, usize)>,
    empty: bool,
}
#[derive(Clone, Copy)]
enum Entities {
    Named,
    NamedAndNumeric,
}

fn numeric_entity(value: &str) -> Option<char> {
    let number = if let Some(hex) = value.strip_prefix("#x") {
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()?
    } else {
        let decimal = value.strip_prefix('#')?;
        if !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        decimal.parse().ok()?
    };
    char::from_u32(number).filter(|&c| !matches!(c, '\u{fffe}' | '\u{ffff}'))
}

fn decode(raw: &[u8], entities: Entities) -> Result<String> {
    let raw = core::str::from_utf8(raw).map_err(|_| "XML is not UTF-8")?;
    let mut out = String::new();
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let end = rest.find(';').ok_or("unterminated XML entity")?;
        out.push(match &rest[..end] {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            value if matches!(entities, Entities::NamedAndNumeric) => {
                numeric_entity(value).ok_or("unsupported XML entity")?
            }
            _ => return Err("unsupported XML entity".into()),
        });
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    if out
        .chars()
        .any(|c| c == '\0' || (c.is_control() && !matches!(c, '\t' | '\r' | '\n')))
    {
        return Err("invalid XML character".into());
    }
    Ok(out)
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
fn name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b':' | b'.')
}
fn name_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b':')
}

fn stock_declaration(mut text: &str) -> Result<()> {
    // XML 1.0 declaration with UTF-8 input and an optional standalone flag.
    for name in ["version", "encoding", "standalone"] {
        if name != "version" && !text.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
            break;
        }
        let Some(rest) = text.trim_start().strip_prefix(name) else {
            if name == "version" {
                return Err("XML declaration version absent".into());
            }
            continue;
        };
        let value = rest
            .trim_start()
            .strip_prefix('=')
            .ok_or("XML declaration equals")?;
        let mut chars = value.trim_start().chars();
        let quote = chars
            .next()
            .filter(|c| matches!(c, '\'' | '"'))
            .ok_or("XML declaration quote")?;
        let (value, rest) = chars
            .as_str()
            .split_once(quote)
            .ok_or("XML declaration value")?;
        let valid = match name {
            "version" => value == "1.0",
            "encoding" => value.eq_ignore_ascii_case("utf-8"),
            _ => matches!(value, "yes" | "no"),
        };
        if !valid {
            return Err("unsupported XML declaration value".into());
        }
        text = rest;
    }
    if !text.trim().is_empty() {
        return Err("unrecognized XML declaration".into());
    }
    Ok(())
}

fn parse(xml: &[u8], entities: Entities) -> Result<Vec<Node>> {
    if xml.is_empty() || xml.len() > MAX_XML {
        return Err("XML size bound".into());
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut p = 0;
    while p < xml.len() {
        if xml[p] != b'<' {
            let end = xml[p..]
                .iter()
                .position(|&c| c == b'<')
                .map_or(xml.len(), |n| p + n);
            let raw = &xml[p..end];
            let text = decode(raw, entities)?;
            if matches!(entities, Entities::NamedAndNumeric)
                && (raw.windows(3).any(|part| part == b"]]>")
                    || stack.is_empty() && !raw.iter().all(u8::is_ascii_whitespace))
            {
                return Err("invalid XML text".into());
            }
            if stack.is_empty() && !text.trim().is_empty() {
                return Err("text outside XML root".into());
            }
            p = end;
            continue;
        }
        if xml[p..].starts_with(b"<!--") {
            let n = xml[p + 4..]
                .windows(3)
                .position(|s| s == b"-->")
                .ok_or("unterminated comment")?;
            let comment = &xml[p + 4..p + 4 + n];
            if comment.windows(2).any(|s| s == b"--")
                || matches!(entities, Entities::NamedAndNumeric) && comment.ends_with(b"-")
            {
                return Err("invalid comment".into());
            }
            p += 4 + n + 3;
            continue;
        }
        if xml[p..].starts_with(b"<?xml ") && p == 0 {
            let n = xml[p..]
                .windows(2)
                .position(|s| s == b"?>")
                .ok_or("XML declaration")?;
            if matches!(entities, Entities::NamedAndNumeric) {
                let declaration =
                    core::str::from_utf8(&xml[6..n]).map_err(|_| "XML declaration encoding")?;
                stock_declaration(declaration)?;
            }
            p += n + 2;
            continue;
        }
        let start = p;
        p += 1;
        let closing = xml.get(p) == Some(&b'/');
        if closing {
            p += 1;
        }
        let ns = p;
        while p < xml.len() && name_byte(xml[p]) {
            p += 1;
        }
        if ns == p || matches!(entities, Entities::NamedAndNumeric) && !name_start(xml[ns]) {
            return Err("unsupported XML construct".into());
        }
        let name = core::str::from_utf8(&xml[ns..p]).map_err(|_| "XML name")?;
        if closing {
            while xml.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            if xml.get(p) != Some(&b'>') {
                return Err("XML closing tag".into());
            }
            p += 1;
            let id = stack.pop().ok_or("unbalanced XML")?;
            if nodes[id].name != name {
                return Err("mismatched XML tag".into());
            }
            nodes[id].end_content = start;
            nodes[id].end = p;
            continue;
        }
        let mut nums = None;
        let mut nums_range = None;
        let mut attrs: Vec<String> = Vec::new();
        loop {
            let before_space = p;
            while xml.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            if matches!(xml.get(p), Some(b'>') | Some(b'/')) {
                break;
            }
            if matches!(entities, Entities::NamedAndNumeric)
                && (p == before_space || !xml.get(p).is_some_and(|&byte| name_start(byte)))
            {
                return Err("invalid XML attribute name or separator".into());
            }
            let a = p;
            while p < xml.len() && name_byte(xml[p]) {
                p += 1;
            }
            if a == p {
                return Err("XML attribute".into());
            }
            let key = core::str::from_utf8(&xml[a..p]).map_err(|_| "attribute name")?;
            if attrs.iter().any(|v| v == key) {
                return Err("duplicate XML attribute".into());
            }
            if attrs.len() >= 32 {
                return Err("XML attribute bound".into());
            }
            attrs.push(key.into());
            while xml.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            if xml.get(p) != Some(&b'=') {
                return Err("XML attribute equals".into());
            }
            p += 1;
            while xml.get(p).is_some_and(u8::is_ascii_whitespace) {
                p += 1;
            }
            let quote = *xml.get(p).ok_or("attribute quote")?;
            if !matches!(quote, b'\'' | b'"') {
                return Err("XML quote".into());
            }
            p += 1;
            let v = p;
            while p < xml.len() && xml[p] != quote {
                if xml[p] == b'<' {
                    return Err("invalid attribute".into());
                }
                p += 1;
            }
            if p == xml.len() {
                return Err("unterminated attribute".into());
            }
            let val = decode(&xml[v..p], entities)?;
            p += 1;
            if key == "nums" {
                if val.is_empty() || !val.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid nums".into());
                }
                nums = Some(val.parse::<usize>().map_err(|_| "nums overflow")?);
                nums_range = Some((v, p - 1));
            }
        }
        let empty = xml.get(p) == Some(&b'/');
        if empty {
            p += 1;
        }
        if xml.get(p) != Some(&b'>') {
            return Err("XML opening tag".into());
        }
        p += 1;
        if nodes.len() >= MAX_NODES || stack.len() >= 16 {
            return Err("XML structural bound".into());
        }
        let id = nodes.len();
        nodes.push(Node {
            name: name.into(),
            start,
            content: p,
            end_content: p,
            end: p,
            parent: stack.last().copied(),
            nums,
            nums_range,
            empty,
        });
        if !empty {
            stack.push(id);
        }
    }
    if !stack.is_empty()
        || nodes.iter().filter(|n| n.parent.is_none()).count() != 1
        || nodes[0].name != "clsboot_root"
    {
        return Err("XML root or balance".into());
    }
    Ok(nodes)
}
fn children(nodes: &[Node], parent: usize) -> Vec<usize> {
    nodes
        .iter()
        .enumerate()
        .filter_map(|(i, n)| (n.parent == Some(parent)).then_some(i))
        .collect()
}
fn validate_gap(mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        if bytes[0].is_ascii_whitespace() {
            bytes = &bytes[1..];
            continue;
        }
        if bytes.starts_with(b"<!--") {
            let end = bytes
                .windows(3)
                .position(|s| s == b"-->")
                .ok_or("list comment")?;
            bytes = &bytes[end + 3..];
            continue;
        }
        return Err("unexpected OEM list text".into());
    }
    Ok(())
}
fn values(
    xml: &[u8],
    nodes: &[Node],
    parent: usize,
    tag: &str,
    entities: Entities,
) -> Result<Vec<String>> {
    let mut ids = children(nodes, parent);
    let mut previous = nodes[parent].content;
    for &id in &ids {
        // Comments and formatting are preserved; arbitrary list text is not an OEM entry.
        let gap = &xml[previous..nodes[id].start];
        validate_gap(gap)?;
        previous = nodes[id].end;
    }
    validate_gap(&xml[previous..nodes[parent].end_content])?;
    let mut has_sentinel = false;
    if let Some(&last) = ids.last() {
        if nodes[last].name == "exp" {
            let sentinel = &nodes[last];
            if nodes.iter().any(|n| n.parent == Some(last))
                || sentinel.nums.is_some()
                || !xml[sentinel.content..sentinel.end_content]
                    .iter()
                    .all(u8::is_ascii_whitespace)
            {
                return Err("invalid OEM sentinel".into());
            }
            ids.pop();
            has_sentinel = true;
        }
    }
    // Actual A9/A11 OEM parser treats nums as allocation capacity. A sole exp
    // with nums=1 allocates a non-NULL vector whose first element is NULL;
    // nums=0 instead leaves the pointer NULL and changes execve inheritance.
    let nonnull_empty = ids.is_empty() && has_sentinel && nodes[parent].nums == Some(1);
    if (!nonnull_empty && nodes[parent].nums != Some(ids.len())) || ids.len() > MAX_ITEMS {
        return Err("OEM list count".into());
    }
    ids.into_iter()
        .map(|i| {
            let n = &nodes[i];
            if n.name != tag || nodes.iter().any(|c| c.parent == Some(i)) {
                return Err("OEM list child".into());
            }
            if xml[n.content..n.end_content].contains(&b'<') {
                return Err("markup inside OEM string".into());
            }
            let v = decode(&xml[n.content..n.end_content], entities)?;
            if v.len() > 99 || v.contains('\0') {
                return Err("OEM string bound".into());
            }
            Ok(v)
        })
        .collect()
}

fn action_lists(
    xml: &[u8],
    nodes: &[Node],
    id: usize,
    entities: Entities,
) -> Result<(Vec<String>, Vec<String>, usize)> {
    let parent = nodes[id].parent.ok_or("action parent")?;
    if nodes[parent].name != "action_execs" || nodes[parent].parent != Some(0) {
        return Err("action schema".into());
    }
    let kids = children(nodes, id);
    let args: Vec<_> = kids
        .iter()
        .copied()
        .filter(|&i| nodes[i].name == "m_args")
        .collect();
    let envs: Vec<_> = kids
        .iter()
        .copied()
        .filter(|&i| nodes[i].name == "m_envs")
        .collect();
    if args.len() != 1 || envs.len() != 1 {
        return Err("ambiguous action lists".into());
    }
    let argv = values(xml, nodes, args[0], "arg", entities)?;
    if argv.is_empty() {
        return Err("empty argv".into());
    }
    Ok((argv, values(xml, nodes, envs[0], "env", entities)?, envs[0]))
}

fn is_target(path: &str) -> bool {
    matches!(path, "/usr/bin/gauge" | "/usr/bin/point" | "/usr/bin/light")
}

/// Inspect parsed OEM argument and environment values without rewriting the file.
pub(crate) fn stock_marker_present(xml: &[u8]) -> Result<bool> {
    let text = core::str::from_utf8(xml).map_err(|_| "XML is not UTF-8")?;
    if text.chars().any(|c| {
        (c.is_control() && !matches!(c, '\t' | '\r' | '\n')) || matches!(c, '\u{fffe}' | '\u{ffff}')
    }) {
        return Err("invalid XML character".into());
    }
    let nodes = parse(xml, Entities::NamedAndNumeric)?;
    let mut seen: Vec<String> = Vec::new();
    let mut marked = false;
    for (id, _) in nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.name == "action_exec")
    {
        let (argv, env, _) = action_lists(xml, &nodes, id, Entities::NamedAndNumeric)?;
        let first = &argv[0];
        if is_target(first) {
            if seen.contains(first) {
                return Err("duplicate target action".into());
            }
            seen.push(first.clone());
        }
        marked |= argv.iter().chain(env.iter()).any(|value| {
            value.starts_with("VOBOOST_CLUSTER_BOOTFILE=")
                || value.starts_with("VOBOOST_CLUSTER_SUPERVISOR=")
                || value.contains("libvoboost-cluster-inject.so")
                || value.contains("/var/voboost/")
        });
    }
    if seen.len() != 3 {
        return Err("all three OEM target actions are required".into());
    }
    Ok(marked)
}

/// Preserve every byte outside the target environment lists. Never generate defaults.
pub(crate) fn augment(xml: &[u8], implant: &str, bootfile: &str, nonce: &str) -> Result<Vec<u8>> {
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid supervisor delivery nonce".into());
    }
    if !implant.starts_with('/')
        || !bootfile.starts_with('/')
        || implant.contains([':', '\n', '\r', '\0'])
        || bootfile.contains(['\n', '\r', '\0'])
    {
        return Err("invalid delivery path".into());
    }
    let nodes = parse(xml, Entities::Named)?;
    let mut edits = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (id, _) in nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.name == "action_exec")
    {
        let (argv, env, env_id) = action_lists(xml, &nodes, id, Entities::Named)?;
        let first = &argv[0];
        if !is_target(first) {
            continue;
        }
        if seen.contains(first) {
            return Err("duplicate target action".into());
        }
        seen.push(first.clone());
        let env_ids = children(&nodes, env_id);
        let insertion = env_ids
            .last()
            .filter(|&&id| nodes[id].name == "exp")
            .map_or(nodes[env_id].end_content, |&id| nodes[id].start);
        let mut preload_index = None;
        let mut boot_index = None;
        let mut stamp_index = None;
        for (index, value) in env.iter().enumerate() {
            if let Some(existing) = value.strip_prefix("VOBOOST_CLUSTER_BOOTFILE=") {
                if boot_index.replace(index).is_some() || existing != bootfile {
                    return Err("conflicting delivery bootfile".into());
                }
            }
            if let Some(existing) = value.strip_prefix("VOBOOST_CLUSTER_SUPERVISOR=") {
                if stamp_index.replace(index).is_some() || existing != nonce {
                    return Err("conflicting delivery nonce".into());
                }
            }
            if value.starts_with("LD_PRELOAD=") && preload_index.replace(index).is_some() {
                return Err("duplicate LD_PRELOAD".into());
            }
        }
        let preload = if let Some(index) = preload_index {
            let old = &env[index]["LD_PRELOAD=".len()..];
            let present = old
                .split([':', ' ', '\t'])
                .filter(|item| *item == implant)
                .count();
            if present > 1 {
                return Err("duplicate implant preload".into());
            }
            if present == 1 {
                env[index].clone()
            } else if old.is_empty() {
                format!("LD_PRELOAD={implant}")
            } else {
                format!("LD_PRELOAD={old}:{implant}")
            }
        } else {
            format!("LD_PRELOAD={implant}")
        };
        let boot = format!("VOBOOST_CLUSTER_BOOTFILE={bootfile}");
        let stamp = format!("VOBOOST_CLUSTER_SUPERVISOR={nonce}");
        let count = env.len()
            + usize::from(boot_index.is_none())
            + usize::from(preload_index.is_none())
            + usize::from(stamp_index.is_none());
        if preload.len() > 99 || boot.len() > 99 || stamp.len() > 99 || count > MAX_ITEMS {
            return Err("delivery environment bound".into());
        }
        let n = &nodes[env_id];
        if preload_index.is_some_and(|index| env[index] == preload)
            && boot_index.is_some()
            && stamp_index.is_some()
        {
            continue;
        }
        let (digits_start, digits_end) = n.nums_range.ok_or("missing environment count")?;
        let mut replacement = Vec::new();
        replacement.extend_from_slice(&xml[n.start..digits_start]);
        replacement.extend_from_slice(format!("{count}").as_bytes());
        let opening_end = if n.empty { n.content - 2 } else { n.content };
        replacement.extend_from_slice(&xml[digits_end..opening_end]);
        if n.empty {
            replacement.push(b'>');
        }
        if let Some(index) = preload_index {
            let old = &nodes[env_ids[index]];
            replacement.extend_from_slice(&xml[n.content..old.start]);
            if env[index] == preload {
                replacement.extend_from_slice(&xml[old.start..old.end]);
            } else {
                replacement
                    .extend_from_slice(format!("<env>{}</env>", escape(&preload)).as_bytes());
            }
            replacement.extend_from_slice(&xml[old.end..insertion]);
        } else {
            replacement.extend_from_slice(&xml[n.content..insertion]);
            replacement.extend_from_slice(format!("<env>{}</env>", escape(&preload)).as_bytes());
        }
        if boot_index.is_none() {
            replacement.extend_from_slice(format!("<env>{}</env>", escape(&boot)).as_bytes());
        }
        if stamp_index.is_none() {
            replacement.extend_from_slice(format!("<env>{}</env>", escape(&stamp)).as_bytes());
        }
        replacement.extend_from_slice(&xml[insertion..n.end_content]);
        if n.empty {
            replacement.extend_from_slice(b"</m_envs>");
        } else {
            replacement.extend_from_slice(&xml[n.end_content..n.end]);
        }
        edits.push((n.start, n.end, replacement));
    }
    if seen.len() != 3 {
        return Err("all three OEM target actions are required".into());
    }
    edits.sort_by_key(|e| e.0);
    let mut out = Vec::new();
    let mut p = 0;
    for (start, end, replacement) in edits {
        out.extend_from_slice(&xml[p..start]);
        out.extend_from_slice(&replacement);
        p = end;
    }
    out.extend_from_slice(&xml[p..]);
    if out.len() > MAX_XML {
        return Err("augmented XML bound".into());
    }
    parse(&out, Entities::Named)?;
    Ok(out)
}

/// Rotate only the nonce in an already complete, exact delivery configuration.
/// The installation receipt retains the first original configuration separately.
pub(crate) fn rotate_nonce(
    xml: &[u8],
    implant: &str,
    bootfile: &str,
    old_nonce: &str,
    new_nonce: &str,
) -> Result<Vec<u8>> {
    if augment(xml, implant, bootfile, old_nonce)? != xml {
        return Err("incomplete previous supervisor delivery".into());
    }
    // Validate the replacement independently even when old and new are equal.
    if new_nonce.len() != 64
        || !new_nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid replacement supervisor nonce".into());
    }
    let nodes = parse(xml, Entities::Named)?;
    let expected = format!("VOBOOST_CLUSTER_SUPERVISOR={old_nonce}");
    let replacement = format!("VOBOOST_CLUSTER_SUPERVISOR={new_nonce}");
    let mut spans = Vec::new();
    for (id, _) in nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.name == "action_exec")
    {
        let fields = children(&nodes, id);
        let args = fields
            .iter()
            .copied()
            .find(|&i| nodes[i].name == "m_args")
            .ok_or("missing rotation argv")?;
        let argv = values(xml, &nodes, args, "arg", Entities::Named)?;
        if !argv.first().is_some_and(|v| {
            matches!(
                v.as_str(),
                "/usr/bin/gauge" | "/usr/bin/point" | "/usr/bin/light"
            )
        }) {
            continue;
        }
        let envs = fields
            .iter()
            .copied()
            .find(|&i| nodes[i].name == "m_envs")
            .ok_or("missing rotation env")?;
        for env in children(&nodes, envs) {
            let entry = &nodes[env];
            if entry.name == "env"
                && decode(&xml[entry.content..entry.end_content], Entities::Named)? == expected
            {
                spans.push((entry.content, entry.end_content));
            }
        }
    }
    if spans.len() != 3 {
        return Err("incomplete rotation nonce set".into());
    }
    let mut out = Vec::new();
    let mut previous = 0;
    for (start, end) in spans {
        out.extend_from_slice(&xml[previous..start]);
        out.extend_from_slice(replacement.as_bytes());
        previous = end;
    }
    out.extend_from_slice(&xml[previous..]);
    if augment(&out, implant, bootfile, new_nonce)? != out {
        return Err("rotated delivery validation failed".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fn augment(xml: &[u8], implant: &str, bootfile: &str) -> Result<Vec<u8>> {
        super::augment(xml, implant, bootfile, NONCE)
    }
    fn fixture(env: &str, count: usize) -> String {
        let mut xml =
            String::from("<?xml version=\"1.0\"?><clsboot_root><!--keep--><action_execs>");
        for owner in ["gauge", "point", "light"] {
            xml.push_str(&format!("<action_exec><m_name>x</m_name><m_args nums=\"1\"><arg>/usr/bin/{owner}</arg></m_args><m_envs nums=\"{count}\">{env}</m_envs><tail q=\"yes\"/></action_exec>"));
        }
        xml.push_str("</action_execs></clsboot_root>");
        xml
    }
    #[test]
    fn stock_decodes_numeric_xml_entities_without_changing_augment_admission() {
        let input = fixture("<env>A=a&amp;b</env>", 1);
        assert!(!stock_marker_present(input.as_bytes()).unwrap());
        let encoded = fixture("<env>&#86;OBOOST_CLUSTER_SUPERVISOR&#x3d;owned</env>", 1);
        assert!(stock_marker_present(encoded.as_bytes()).unwrap());
        assert!(augment(encoded.as_bytes(), "/v/i.so", "/v/boot").is_err());
    }

    #[test]
    fn stock_requires_valid_nonempty_oem_config() {
        for malformed in ["", "<clsboot_root/>", "<clsboot_root>"] {
            assert!(stock_marker_present(malformed.as_bytes()).is_err());
        }
        let valid = fixture("<env>OTHER=clean</env>", 1);
        for malformed in [
            valid.replace("version=", "unknown="),
            valid.replace("<tail q=", "<tail q='a'x="),
            valid.replace("<tail q=", "<9tail q="),
            valid.replace("<!--keep-->", "<!--keep--->"),
            valid.replace("OTHER=clean", "OTHER=]]>"),
        ] {
            assert!(
                stock_marker_present(malformed.as_bytes()).is_err(),
                "{malformed}"
            );
        }
        let invalid_entity = fixture("<env>O=&#x110000;</env>", 1);
        assert!(stock_marker_present(invalid_entity.as_bytes()).is_err());
        let malformed_count = fixture("<env>VOBOOST_CLUSTER_SUPERVISOR=owned</env>", 0);
        assert!(stock_marker_present(malformed_count.as_bytes()).is_err());
    }

    #[test]
    fn preserves_outside_lists_and_existing_values() {
        let input = fixture("<env>A=a&amp;b</env>", 1);
        let out = augment(input.as_bytes(), "/v/i.so", "/v/boot").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("<!--keep-->"));
        assert!(text.contains("<env>A=a&amp;b</env><env>LD_PRELOAD=/v/i.so</env>"));
        assert!(text.contains("<tail q=\"yes\"/>"));
        assert!(text.contains("nums=\"4\""));
    }
    #[test]
    fn rejects_unsafe_documents() {
        for s in [
            "<!DOCTYPE clsboot_root><clsboot_root/>",
            "<clsboot_root>&evil;</clsboot_root>",
            "<clsboot_root><x></clsboot_root>",
        ] {
            assert!(augment(s.as_bytes(), "/v/i", "/v/b").is_err());
        }
    }
    #[test]
    fn rejects_counts_and_existing_controls() {
        assert!(augment(fixture("", 1).as_bytes(), "/v/i", "/v/b").is_err());
        assert!(augment(
            fixture("<env>LD_PRELOAD=/old</env><env>LD_PRELOAD=/other</env>", 2).as_bytes(),
            "/v/i",
            "/v/b"
        )
        .is_err());
    }
    #[test]
    fn rejects_long_paths() {
        assert!(augment(
            fixture("", 0).as_bytes(),
            &format!("/{}", "x".repeat(100)),
            "/v/b"
        )
        .is_err());
    }
    #[test]
    fn preserves_existing_preload_and_formatting() {
        let source = fixture(
            "\n<!--stable--> <env>OTHER=a&amp;b</env>\n<env>LD_PRELOAD=/o.so</env>\n",
            2,
        );
        let out = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(
            "\n<!--stable--> <env>OTHER=a&amp;b</env>\n<env>LD_PRELOAD=/o.so:/v/i</env>\n"
        ));
        assert!(text.contains("<m_envs nums=\"4\">"));
    }
    #[test]
    fn rejects_missing_or_duplicate_targets() {
        let source = fixture("", 0);
        assert!(augment(
            source
                .replace("/usr/bin/light", "/usr/bin/other")
                .as_bytes(),
            "/v/i",
            "/v/b"
        )
        .is_err());
        assert!(augment(
            source
                .replace("/usr/bin/light", "/usr/bin/gauge")
                .as_bytes(),
            "/v/i",
            "/v/b"
        )
        .is_err());
    }
    #[test]
    fn accepts_empty_lists_and_escapes_paths() {
        let source = fixture("", 0).replace("<m_envs nums=\"0\"></m_envs>", "<m_envs nums=\"0\"/>");
        let out = augment(source.as_bytes(), "/v/i&x", "/v/b").unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("LD_PRELOAD=/v/i&amp;x"));
    }
    #[test]
    fn rejects_garbage_list_text_and_nested_entries() {
        for env in [
            "garbage<env>x</env>",
            "<env><nested/></env>",
            "<env>a<!--b-->c</env>",
        ] {
            assert!(augment(fixture(env, 1).as_bytes(), "/v/i", "/v/b").is_err());
        }
    }
    #[test]
    fn is_byte_idempotent_and_rejects_boot_conflict() {
        let source = fixture("<env>X=1</env>", 1);
        let once = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        assert_eq!(augment(&once, "/v/i", "/v/b").unwrap(), once);
        assert!(augment(&once, "/v/i", "/other").is_err());
    }
    #[test]
    fn preserves_unrelated_actions_and_unknown_fields() {
        let source = fixture("", 0);
        let extra="<action_exec><m_args nums=\"1\"><arg>/usr/bin/other</arg></m_args><m_envs nums=\"1\"><env>LD_PRELOAD=/o</env></m_envs><unfamiliar a=\"1\">opaque</unfamiliar></action_exec>";
        let source = source.replace("</action_execs>", &format!("{extra}</action_execs>"));
        let out = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        assert!(String::from_utf8(out).unwrap().contains(extra));
    }
    #[test]
    fn retains_list_attributes_quotes_and_comments() {
        let source = fixture("\n<!-- env -->\n", 0)
            .replace("<m_envs nums=\"0\">", "<m_envs opaque='keep' nums = '00' >");
        let out = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("<m_envs opaque='keep' nums = '3' >\n<!-- env -->\n"));
    }
    #[test]
    fn oem_sentinel_precedes_neither_new_env_nor_count() {
        let source = fixture("<env>OEM=value</env>\n<!-- before sentinel --><exp/>\n", 1)
            .replace(
                "<arg>/usr/bin/gauge</arg>",
                "<arg>/usr/bin/gauge</arg><exp/>",
            )
            .replace(
                "<arg>/usr/bin/point</arg>",
                "<arg>/usr/bin/point</arg><exp/>",
            )
            .replace(
                "<arg>/usr/bin/light</arg>",
                "<arg>/usr/bin/light</arg><exp/>",
            );
        let out = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        let text = core::str::from_utf8(&out).unwrap();
        assert!(text.contains("<env>OEM=value</env>\n<!-- before sentinel --><env>LD_PRELOAD=/v/i</env><env>VOBOOST_CLUSTER_BOOTFILE=/v/b</env><env>VOBOOST_CLUSTER_SUPERVISOR=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</env><exp/>\n"));
        assert_eq!(augment(&out, "/v/i", "/v/b").unwrap(), out);
    }
    #[test]
    fn rejects_sentinel_before_entries_or_nonempty_sentinel() {
        for env in [
            "<exp/><env>X=1</env>",
            "<env>X=1</env><exp>bad</exp>",
            "<env>X=1</env><exp/><exp/>",
        ] {
            assert!(augment(fixture(env, 1).as_bytes(), "/v/i", "/v/b").is_err());
        }
    }
    #[test]
    fn validates_stamp_shape_conflicts_and_duplicates() {
        let source = fixture("", 0);
        for invalid in [
            "",
            "ABCDEF",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeG",
        ] {
            assert!(super::augment(source.as_bytes(), "/v/i", "/v/b", invalid).is_err());
        }
        let once = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        assert!(super::augment(&once, "/v/i", "/v/b", &"a".repeat(64)).is_err());
        let dup=fixture(&format!("<env>VOBOOST_CLUSTER_SUPERVISOR={NONCE}</env><env>VOBOOST_CLUSTER_SUPERVISOR={NONCE}</env>"),2);
        assert!(augment(dup.as_bytes(), "/v/i", "/v/b").is_err());
    }
    #[test]
    fn rotates_only_owned_nonce_bytes() {
        let source = fixture("<env>OEM=value</env> <!-- keep --> <exp/>", 1);
        let original = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        let next = "a".repeat(64);
        let rotated = rotate_nonce(&original, "/v/i", "/v/b", NONCE, &next).unwrap();
        assert_eq!(
            rotated,
            String::from_utf8(original.clone())
                .unwrap()
                .replace(NONCE, &next)
                .as_bytes()
        );
        assert_eq!(
            rotate_nonce(&rotated, "/v/i", "/v/b", &next, &next).unwrap(),
            rotated
        );
        assert!(rotate_nonce(&original, "/v/i", "/v/b", &next, NONCE).is_err());
        assert!(rotate_nonce(source.as_bytes(), "/v/i", "/v/b", NONCE, &next).is_err());
        assert!(rotate_nonce(&original, "/v/other", "/v/b", NONCE, &next).is_err());
        assert!(rotate_nonce(&original, "/v/i", "/v/other", NONCE, &next).is_err());
    }
    #[test]
    fn preserves_oem_nonnull_empty_environment_encoding() {
        let extra="<action_exec><m_args nums='1'><arg>/usr/bin/other</arg><exp/></m_args><m_envs nums='1'><!-- capacity preserves nonnull --><exp/></m_envs></action_exec>";
        let source =
            fixture("<exp/>", 0).replace("</action_execs>", &format!("{extra}</action_execs>"));
        let out = augment(source.as_bytes(), "/v/i", "/v/b").unwrap();
        assert!(core::str::from_utf8(&out).unwrap().contains(extra));
        for env in [
            "<m_envs nums='2'><exp/></m_envs>",
            "<m_envs nums='1'></m_envs>",
            "<m_envs nums='1'><exp>bad</exp></m_envs>",
        ] {
            assert!(augment(
                source
                    .replace(
                        "<m_envs nums='1'><!-- capacity preserves nonnull --><exp/></m_envs>",
                        env
                    )
                    .as_bytes(),
                "/v/i",
                "/v/b"
            )
            .is_err());
        }
    }
}
