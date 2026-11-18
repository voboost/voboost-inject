//! Observe ActivityManager's current Configuration, not persistent properties or this process locale.
use std::time::Duration;

const MAXIMUM: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    English,
    Chinese,
    Russian,
}

pub fn observe() -> Result<Language, String> {
    let out = crate::fixed_process::output(
        "/system/bin/cmd",
        &["activity", "get-config", "--proto"],
        Duration::from_secs(5),
        MAXIMUM,
    )?;
    if !out.status.success() {
        return Err("framework locale command failed".into());
    }
    parse(&out.stdout)
}

fn varint(bytes: &mut &[u8]) -> Result<u64, String> {
    let mut value = 0u64;
    for i in 0..10 {
        let (&byte, rest) = bytes.split_first().ok_or("truncated locale protobuf")?;
        *bytes = rest;
        if i == 9 && byte > 1 {
            return Err("locale protobuf varint overflow".into());
        }
        value |= u64::from(byte & 127) << (7 * i);
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err("locale protobuf varint overflow".into())
}
type ProtoField<'a> = (u64, Option<&'a [u8]>);

fn fields(mut bytes: &[u8]) -> Result<Vec<ProtoField<'_>>, String> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let key = varint(&mut bytes)?;
        let number = key >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return Err("invalid locale protobuf field".into());
        }
        let length = match key & 7 {
            0 => {
                varint(&mut bytes)?;
                result.push((number, None));
                continue;
            }
            1 => 8,
            2 => usize::try_from(varint(&mut bytes)?).map_err(|_| "locale field too large")?,
            5 => 4,
            _ => return Err("unsupported locale protobuf wire type".into()),
        };
        if length > bytes.len() {
            return Err("truncated locale protobuf field".into());
        }
        let (value, rest) = bytes.split_at(length);
        bytes = rest;
        result.push((number, if key & 7 == 2 { Some(value) } else { None }));
    }
    Ok(result)
}
fn one<'a>(fields: &[ProtoField<'a>], number: u64) -> Result<Option<&'a [u8]>, String> {
    let mut found = None;
    for (n, value) in fields {
        if *n == number {
            if found.is_some() {
                return Err("duplicate singular locale field".into());
            }
            found = Some(value.ok_or("wrong locale protobuf wire type")?);
        }
    }
    Ok(found)
}
fn syntax(tag: &str) -> Result<(), String> {
    let mut subtags = tag.split('-');
    let first = subtags.next().ok_or("missing language")?;
    if !(2..=8).contains(&first.len())
        || !first.bytes().all(|b| b.is_ascii_alphabetic())
        || subtags
            .any(|s| s.is_empty() || s.len() > 8 || !s.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return Err("invalid framework locale tag".into());
    }
    Ok(())
}
fn language(tag: &str) -> Result<Language, String> {
    syntax(tag)?;
    match tag.split('-').next().unwrap_or("") {
        "en" => Ok(Language::English),
        "zh" => Ok(Language::Chinese),
        "ru" => Ok(Language::Russian),
        _ => Err("unsupported framework language".into()),
    }
}
/// AOSP 9: resources(1).configuration(1).locales(4).language(1).
/// AOSP 11: same wrapper, configuration.locale_list(20), comma-separated BCP47.
/// Order is significant: only the first framework locale selects the language.
pub fn parse(bytes: &[u8]) -> Result<Language, String> {
    if bytes.len() > MAXIMUM {
        return Err("framework locale output exceeds bound".into());
    }
    let outer = fields(bytes)?;
    let resources = fields(one(&outer, 1)?.ok_or("missing resources configuration")?)?;
    let config = fields(one(&resources, 1)?.ok_or("missing framework configuration")?)?;
    let tags = one(&config, 20)?;
    let mut old = None;
    for (n, value) in &config {
        if *n == 4 {
            let locale = fields(value.ok_or("wrong locale wire type")?)?;
            let raw = one(&locale, 1)?.ok_or("missing locale language")?;
            let text = std::str::from_utf8(raw).map_err(|_| "invalid locale UTF-8")?;
            if old.is_none() {
                old = Some(language(text)?);
            } else {
                syntax(text)?;
            }
        }
    }
    let modern = if let Some(raw) = tags {
        let text = std::str::from_utf8(raw).map_err(|_| "invalid locale UTF-8")?;
        let mut entries = text.split(',');
        let primary = language(entries.next().ok_or("empty framework locale list")?)?;
        for secondary in entries {
            syntax(secondary)?;
        }
        Some(primary)
    } else {
        None
    };
    match (old, modern) {
        (Some(a), Some(b)) if a != b => Err("conflicting framework locale encodings".into()),
        (_, Some(b)) => Ok(b),
        (Some(a), None) => Ok(a),
        _ => Err("missing framework locale".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn field(n: u8, b: &[u8]) -> Vec<u8> {
        let key = u16::from(n) << 3 | 2;
        let mut v = if key < 128 {
            vec![key as u8]
        } else {
            vec![(key as u8 & 127) | 128, (key >> 7) as u8]
        };
        v.push(b.len() as u8);
        v.extend(b);
        v
    }
    fn config(b: &[u8]) -> Vec<u8> {
        field(1, &field(1, b))
    }
    fn old(s: &str) -> Vec<u8> {
        field(4, &field(1, s.as_bytes()))
    }
    #[test]
    fn android9() {
        assert_eq!(parse(&config(&old("ru"))).unwrap(), Language::Russian);
    }
    #[test]
    fn android11() {
        assert_eq!(
            parse(&config(&field(20, b"en-US,ru-RU"))).unwrap(),
            Language::English
        );
    }
    #[test]
    fn order() {
        let mut b = old("zh");
        b.extend(old("ru"));
        assert_eq!(parse(&config(&b)).unwrap(), Language::Chinese);
    }
    #[test]
    fn unknown_never_defaults() {
        assert!(parse(&config(&old("de"))).is_err());
    }
    #[test]
    fn duplicates() {
        let mut b = field(20, b"en");
        b.extend(field(20, b"en"));
        assert!(parse(&config(&b)).is_err());
    }
    #[test]
    fn conflicting() {
        let mut b = old("ru");
        b.extend(field(20, b"en"));
        assert!(parse(&config(&b)).is_err());
    }
    #[test]
    fn missing() {
        assert!(parse(&config(&[])).is_err());
    }
    #[test]
    fn truncation() {
        let b = config(&old("ru"));
        for n in 0..b.len() {
            assert!(parse(&b[..n]).is_err());
        }
    }
    #[test]
    fn malformed() {
        for b in [vec![0], vec![0x0b], vec![0xff; 11], vec![10, 255, 255, 255]] {
            assert!(parse(&b).is_err());
        }
    }
    #[test]
    fn invalid_tags() {
        for s in ["", "ru-", "en,,ru", "RU", "ru_RU"] {
            assert!(parse(&config(&field(20, s.as_bytes()))).is_err());
        }
    }
    #[test]
    fn field_order() {
        let mut b = field(20, b"ru-RU");
        b.extend([8, 1]);
        assert_eq!(parse(&config(&b)).unwrap(), Language::Russian);
    }
    #[test]
    fn bounded() {
        assert!(parse(&vec![0; MAXIMUM + 1]).is_err());
    }
    #[test]
    fn secondary_language_does_not_select_primary() {
        for tags in ["en-US,de-DE", "en-US,ru-RU", "en-US,fr-FR"] {
            assert_eq!(
                parse(&config(&field(20, tags.as_bytes()))).unwrap(),
                Language::English
            );
        }
        assert!(parse(&config(&field(20, b"de-DE,en-US"))).is_err());
        let mut old_pair = old("en");
        old_pair.extend(old("de"));
        assert_eq!(parse(&config(&old_pair)).unwrap(), Language::English);
        let mut conflict = old("en");
        conflict.extend(field(20, b"zh-CN,de-DE"));
        assert!(parse(&config(&conflict)).is_err());
    }
}
