//! One bounded `/proc/<pid>/maps` snapshot per reconciliation attempt.
//!
//! All injected/foreign/bitness classifiers consume the same validated,
//! immutable document. Paths are matched as exact map-entry pathnames or
//! narrowly defined basenames; arbitrary whole-document substrings are never
//! process identity or coexistence evidence.

use std::fs;
use std::io::{self, Read};
use std::ops::Range;
use std::path::Path;

use crate::config;

/// Generous Android 9 procfs bounds. Classification never uses a truncated
/// prefix or an incomplete logical line.
pub const MAX_PROC_MAPS_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PROC_MAPS_LINES: usize = 65_536;

#[derive(Debug)]
pub struct ProcMapsSnapshot {
    contents: String,
    entries: Vec<MapEntry>,
}

#[derive(Debug)]
struct MapEntry {
    path: Option<Range<usize>>,
}

impl ProcMapsSnapshot {
    pub fn read(pid: i32) -> io::Result<Self> {
        let maps_path = format!("/proc/{pid}/maps");
        let file = fs::File::open(maps_path)?;
        Self::from_reader(file)
    }

    fn from_reader<R: Read>(reader: R) -> io::Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take(MAX_PROC_MAPS_BYTES.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_PROC_MAPS_BYTES {
            return Err(invalid_maps("proc maps exceeds byte bound"));
        }
        let contents =
            String::from_utf8(bytes).map_err(|_| invalid_maps("proc maps is not UTF-8"))?;
        ensure_complete_document(&contents)?;

        let mut entries = Vec::new();
        let mut document_offset = 0usize;
        for complete_line in contents.split_inclusive('\n') {
            if entries.len() >= MAX_PROC_MAPS_LINES {
                return Err(invalid_maps("proc maps exceeds line bound"));
            }
            let line = complete_line
                .strip_suffix('\n')
                .ok_or_else(|| invalid_maps("proc maps has an incomplete line"))?;
            let path = parse_map_line(line)?
                .map(|relative| document_offset + relative.start..document_offset + relative.end);
            entries.push(MapEntry { path });
            document_offset += complete_line.len();
        }

        Ok(Self { contents, entries })
    }

    pub(crate) fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter_map(|entry| entry.path.as_ref())
            .map(|range| &self.contents[range.clone()])
    }

    pub fn contains_exact_path(&self, expected: &str) -> bool {
        self.paths().any(|path| path == expected)
    }

    /// Exact current or kernel-deleted canonical Voboost implant pathname.
    pub fn is_injected(&self) -> bool {
        self.paths().any(is_canonical_implant_path)
    }

    /// Known coexistence markers matched only at complete path-token bounds.
    pub fn has_foreign_footprint(&self) -> bool {
        self.paths().any(is_foreign_path)
    }

    /// Combine exact executable basename and exact canonical map evidence.
    /// Conflicting 32/64 evidence or complete absence of evidence is unknown.
    pub fn detect_bitness_for_exe(&self, executable: Option<&Path>) -> Option<&'static str> {
        let mut evidence = BitnessEvidence::default();
        if let Some(executable) = executable {
            evidence.add(executable_bitness(executable));
        }
        for path in self.paths() {
            evidence.add(map_bitness(path));
        }
        evidence.finish()
    }
}

pub fn detect_bitness(pid: i32, snapshot: &ProcMapsSnapshot) -> Option<&'static str> {
    let exe_path = format!("/proc/{pid}/exe");
    let executable = fs::read_link(exe_path).ok();
    snapshot.detect_bitness_for_exe(executable.as_deref())
}

fn ensure_complete_document(contents: &str) -> io::Result<()> {
    if contents.is_empty() || !contents.ends_with('\n') {
        return Err(invalid_maps("proc maps is empty or truncated"));
    }
    Ok(())
}

fn parse_map_line(line: &str) -> io::Result<Option<Range<usize>>> {
    if line.is_empty() || line.bytes().any(|byte| byte == b'\r') {
        return Err(invalid_maps("proc maps contains an invalid line"));
    }
    let mut cursor = 0usize;
    let address = take_field(line, &mut cursor)?;
    let permissions = take_field(line, &mut cursor)?;
    let offset = take_field(line, &mut cursor)?;
    let device = take_field(line, &mut cursor)?;
    let inode = take_field(line, &mut cursor)?;

    validate_address(&line[address])?;
    validate_permissions(&line[permissions])?;
    parse_hex(&line[offset])?;
    validate_device(&line[device])?;
    line[inode]
        .parse::<u64>()
        .map_err(|_| invalid_maps("proc maps inode is invalid"))?;

    skip_horizontal_space(line, &mut cursor);
    if cursor == line.len() {
        Ok(None)
    } else {
        Ok(Some(cursor..line.len()))
    }
}

fn take_field(line: &str, cursor: &mut usize) -> io::Result<Range<usize>> {
    skip_horizontal_space(line, cursor);
    let start = *cursor;
    while *cursor < line.len() && !is_horizontal_space(line.as_bytes()[*cursor]) {
        *cursor += 1;
    }
    if start == *cursor {
        return Err(invalid_maps("proc maps field is missing"));
    }
    Ok(start..*cursor)
}

fn skip_horizontal_space(line: &str, cursor: &mut usize) {
    while *cursor < line.len() && is_horizontal_space(line.as_bytes()[*cursor]) {
        *cursor += 1;
    }
}

fn is_horizontal_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn validate_address(value: &str) -> io::Result<()> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| invalid_maps("proc maps address range is missing"))?;
    if end.contains('-') {
        return Err(invalid_maps("proc maps address range is ambiguous"));
    }
    let start = parse_hex(start)?;
    let end = parse_hex(end)?;
    if start >= end {
        return Err(invalid_maps("proc maps address range is reversed"));
    }
    Ok(())
}

fn validate_permissions(value: &str) -> io::Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() != 4
        || !matches!(bytes[0], b'r' | b'-')
        || !matches!(bytes[1], b'w' | b'-')
        || !matches!(bytes[2], b'x' | b'-')
        || !matches!(bytes[3], b'p' | b's')
    {
        return Err(invalid_maps("proc maps permissions are invalid"));
    }
    Ok(())
}

fn validate_device(value: &str) -> io::Result<()> {
    let (major, minor) = value
        .split_once(':')
        .ok_or_else(|| invalid_maps("proc maps device is missing"))?;
    if minor.contains(':') {
        return Err(invalid_maps("proc maps device is ambiguous"));
    }
    parse_hex(major)?;
    parse_hex(minor)?;
    Ok(())
}

fn parse_hex(value: &str) -> io::Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_maps("proc maps hexadecimal field is invalid"));
    }
    u64::from_str_radix(value, 16)
        .map_err(|_| invalid_maps("proc maps hexadecimal field overflows"))
}

fn is_canonical_implant_path(path: &str) -> bool {
    let current = path.strip_suffix(" (deleted)").unwrap_or(path);
    matches!(
        current,
        config::IMPLANT_PATH_ARM64 | config::IMPLANT_PATH_ARM32
    )
}

fn is_foreign_path(path: &str) -> bool {
    let current = path.strip_suffix(" (deleted)").unwrap_or(path);
    if matches!(current, "[anon:gum-js-loop]" | "/memfd:gum-js-loop") {
        return true;
    }
    let basename = current.rsplit('/').next().unwrap_or(current);
    let basename = basename.strip_prefix("memfd:").unwrap_or(basename);
    matches!(
        basename,
        "libxposed.so" | "libxposed_art.so" | "libxposed_dex2oat.so" | "libshadowhook.so"
    )
}

#[derive(Default)]
struct BitnessEvidence {
    has_32: bool,
    has_64: bool,
}

impl BitnessEvidence {
    fn add(&mut self, evidence: Option<&'static str>) {
        match evidence {
            Some("armeabi-v7a") => self.has_32 = true,
            Some("arm64-v8a") => self.has_64 = true,
            _ => {}
        }
    }

    fn finish(self) -> Option<&'static str> {
        match (self.has_32, self.has_64) {
            (true, false) => Some("armeabi-v7a"),
            (false, true) => Some("arm64-v8a"),
            _ => None,
        }
    }
}

fn executable_bitness(executable: &Path) -> Option<&'static str> {
    match executable.file_name()?.to_str()? {
        "app_process32" | "app_process32_real" => Some("armeabi-v7a"),
        "app_process64" | "app_process64_real" => Some("arm64-v8a"),
        _ => None,
    }
}

fn map_bitness(path: &str) -> Option<&'static str> {
    match path {
        "/system/bin/linker" | "/system/lib/libc.so" => Some("armeabi-v7a"),
        "/system/bin/linker64" | "/system/lib64/libc.so" => Some("arm64-v8a"),
        _ => None,
    }
}

fn invalid_maps(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(path: &str) -> String {
        format!("1000-2000 r-xp 00000000 00:00 0 {path}\n")
    }

    fn snapshot(document: impl AsRef<[u8]>) -> ProcMapsSnapshot {
        ProcMapsSnapshot::from_reader(document.as_ref()).unwrap()
    }

    #[test]
    fn one_snapshot_drives_exact_injected_foreign_and_bitness_classifiers() {
        let document = format!(
            "{}{}{}",
            line(config::IMPLANT_PATH_ARM64),
            line("/memfd:libxposed_art.so (deleted)"),
            line("/system/bin/linker64")
        );
        let snapshot = snapshot(document);

        assert!(snapshot.is_injected());
        assert!(snapshot.has_foreign_footprint());
        assert_eq!(
            snapshot.detect_bitness_for_exe(Some(Path::new("/system/bin/app_process64"))),
            Some("arm64-v8a")
        );
    }

    #[test]
    fn implant_path_rejects_prefix_suffix_and_accepts_exact_deleted_inode() {
        for path in [
            "/data/voboost/payload/arm64-v8a/fake-libimplant.so",
            "/data/voboost/payload/arm64-v8a/libimplant.so.unexpected",
            "/data/local/tmp/libimplant.so",
        ] {
            assert!(!snapshot(line(path)).is_injected(), "path={path}");
        }
        assert!(snapshot(line(&format!("{} (deleted)", config::IMPLANT_PATH_ARM32))).is_injected());
    }

    #[test]
    fn foreign_markers_require_exact_basename_or_path_token() {
        for path in [
            "/data/local/tmp/fake-libxposed_art.so",
            "/data/local/tmp/libshadowhook.so.backup",
            "[anon:not-gum-js-loop]",
        ] {
            assert!(!snapshot(line(path)).has_foreign_footprint(), "path={path}");
        }
        assert!(snapshot(line("/data/local/tmp/libxposed_art.so")).has_foreign_footprint());
    }

    #[test]
    fn bitness_uses_exact_evidence_and_rejects_conflicts_or_substrings() {
        let ambiguous = snapshot(format!(
            "{}{}",
            line("/system/bin/linker"),
            line("/system/bin/linker64")
        ));
        assert_eq!(ambiguous.detect_bitness_for_exe(None), None);
        assert_eq!(
            ambiguous.detect_bitness_for_exe(Some(Path::new("/system/bin/app_process64"))),
            None
        );
        let map64 = snapshot(line("/system/lib64/libc.so"));
        assert_eq!(
            map64.detect_bitness_for_exe(Some(Path::new("/system/bin/app_process32"))),
            None
        );

        let false_64 = snapshot(line("/data/local/tmp/lib64/fake.so"));
        assert_eq!(false_64.detect_bitness_for_exe(None), None);
        assert_eq!(
            false_64.detect_bitness_for_exe(Some(Path::new("/system/bin/not-app_process64"))),
            None
        );

        let exact_32 = snapshot(line("/system/lib/libc.so"));
        assert_eq!(exact_32.detect_bitness_for_exe(None), Some("armeabi-v7a"));
    }

    #[test]
    fn snapshot_rejects_over_cap_incomplete_malformed_and_invalid_utf8_documents() {
        let oversized = vec![b'x'; MAX_PROC_MAPS_BYTES + 1];
        assert_eq!(
            ProcMapsSnapshot::from_reader(&oversized[..])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        let too_many_lines = line("").repeat(MAX_PROC_MAPS_LINES + 1);
        assert_eq!(
            ProcMapsSnapshot::from_reader(too_many_lines.as_bytes())
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(ProcMapsSnapshot::from_reader(
            &b"1000-2000 r-xp 0 00:00 0 /system/bin/linker64"[..]
        )
        .is_err());
        assert!(ProcMapsSnapshot::from_reader(
            &b"reversed-fields r-xp 0 00:00 0 /system/bin/linker64\n"[..]
        )
        .is_err());
        assert_eq!(
            ProcMapsSnapshot::from_reader(&[0xff, 0xfe][..])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
}
