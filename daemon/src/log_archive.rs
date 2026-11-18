//! Read-only export of resident logging sessions and committed app batches.
use crate::secure_fs::Directory;
use std::{collections::BTreeMap, io};
use voboost_contract::runtime_log::{Event, Level, MAX_RECORD_BYTES};

pub(crate) const MAX_SESSIONS: usize = 1024;
const MAX_BATCHES: usize = voboost_contract::runtime_log::MAX_BATCH_RECEIPTS;
const MAX_SEGMENT: usize = 8 * 1024 * 1024;
pub(crate) const QNX_BATCHES: &str = "qnx-batches";
pub(crate) const MAX_QNX_BATCHES: usize = 4096;
pub(crate) const MAX_QNX_SEGMENT: usize = 65536;

pub(crate) struct Snapshot {
    records: BTreeMap<(String, u64), Vec<u8>>,
    total: usize,
}

impl Snapshot {
    pub(crate) fn owner(root: &Directory) -> io::Result<Self> {
        let mut snapshot = Self {
            records: BTreeMap::new(),
            total: 0,
        };
        for name in root.entry_names_bounded(MAX_SESSIONS + 64)? {
            if !identity(&name) {
                continue;
            }
            let session = private_child(root, &name)?;
            for file in session.entry_names_bounded(3 * 1024)? {
                let Some(tier) = segment_tier(&file) else {
                    continue;
                };
                let bytes = session.read_trusted(&file, MAX_SEGMENT, 0o600)?;
                merge(
                    &bytes,
                    Some(&name),
                    tier,
                    &mut snapshot.records,
                    &mut snapshot.total,
                )?;
            }
        }
        snapshot.batches(root, "batches", MAX_BATCHES, MAX_SEGMENT)?;
        Ok(snapshot)
    }

    pub(crate) fn qnx(&mut self, root: &Directory) -> io::Result<()> {
        self.batches(root, QNX_BATCHES, MAX_QNX_BATCHES, MAX_QNX_SEGMENT)
    }

    fn batches(
        &mut self,
        root: &Directory,
        name: &str,
        maximum: usize,
        max_segment: usize,
    ) -> io::Result<()> {
        match root.open_child(name) {
            Ok(batches) => {
                batches.validate_owner_mode(
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                    0o700,
                )?;
                // The owner transaction has already been released before
                // reading QNX, so this snapshot cannot delay the owner loop.
                let _qnx_snapshot = if name == QNX_BATCHES {
                    Some(batches.lock_transaction(std::time::Duration::from_secs(2))?)
                } else {
                    None
                };
                for id in batches.entry_names_bounded(maximum)? {
                    if !identity(&id) {
                        return Err(invalid("invalid batch archive identity"));
                    }
                    let batch = private_child(&batches, &id)?;
                    match batch.read_trusted("committed", 32, 0o600) {
                        Ok(marker) if marker == id.as_bytes() => (),
                        Ok(_) => return Err(invalid("invalid batch archive commit")),
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    }
                    for (tier, file) in ["debug.jsonl", "info.jsonl", "error.jsonl"]
                        .into_iter()
                        .enumerate()
                    {
                        match batch.read_trusted(
                            &format!(
                                "retired-{}",
                                voboost_contract::runtime_log::TIER_NAMES[tier]
                            ),
                            7,
                            0o600,
                        ) {
                            Ok(marker) if marker == b"retired" => continue,
                            Ok(_) => return Err(invalid("invalid archive retirement marker")),
                            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                            Err(error) => return Err(error),
                        }
                        let bytes = batch.read_trusted(file, max_segment, 0o600)?;
                        merge(&bytes, None, tier, &mut self.records, &mut self.total)?;
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        Ok(())
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.total);
        for line in self.records.into_values() {
            out.extend_from_slice(&line);
        }
        out
    }
}

#[cfg(test)]
pub(crate) fn read(root: &Directory) -> io::Result<Vec<u8>> {
    let mut snapshot = Snapshot::owner(root)?;
    snapshot.qnx(root)?;
    Ok(snapshot.into_bytes())
}

fn private_child(parent: &Directory, name: &str) -> io::Result<Directory> {
    let directory = parent.open_child(name)?;
    directory.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    Ok(directory)
}
fn identity(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn segment_tier(name: &str) -> Option<usize> {
    ["debug-", "info-", "error-"]
        .iter()
        .enumerate()
        .find_map(|(tier, prefix)| {
            let number = name.strip_prefix(prefix)?.strip_suffix(".jsonl")?;
            (number.len() == 20 && number.bytes().all(|b| b.is_ascii_digit())).then_some(tier)
        })
}
fn merge(
    bytes: &[u8],
    writer: Option<&str>,
    tier: usize,
    records: &mut BTreeMap<(String, u64), Vec<u8>>,
    total: &mut usize,
) -> io::Result<()> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(invalid("unterminated session record"));
    }
    let mut previous: Option<(String, u64)> = None;
    for line in bytes.split_inclusive(|&b| b == b'\n') {
        if line.len() > MAX_RECORD_BYTES {
            return Err(invalid("session record exceeds bound"));
        }
        let event: Event =
            serde_json::from_slice(line).map_err(|_| invalid("invalid session record"))?;
        let boot = event.boot_id.as_bytes();
        if event.schema_version != 2
            || !identity(&event.writer_id)
            || event.sequence == 0
            || writer.is_some_and(|id| id != event.writer_id)
            || boot.len() != 36
            || !boot.iter().enumerate().all(|(i, b)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    *b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(b)
                }
            })
            || !event.source.valid()
            || crate::log_export::timestamp_epoch_millis(&event.timestamp).is_none()
            || (tier == 1 && event.level == Level::Debug)
            || (tier == 2 && event.level != Level::Error)
        {
            return Err(invalid("session record identity or tier mismatch"));
        }
        let key = (event.writer_id, event.sequence);
        if previous.as_ref().is_some_and(|old| old >= &key) {
            return Err(invalid("session segment ordering mismatch"));
        }
        previous = Some(key.clone());
        match records.get(&key) {
            Some(existing) if existing == line => (),
            Some(_) => return Err(invalid("divergent session record identity")),
            None => {
                *total = total
                    .checked_add(line.len())
                    .ok_or_else(|| invalid("archive length overflow"))?;
                if *total > crate::log_export::MAX_EXPORT_BYTES {
                    return Err(invalid("archive exceeds bound"));
                }
                records.insert(key, line.into());
            }
        }
    }
    Ok(())
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    const WRITER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn event(sequence: u64) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"bootId":"11111111-1111-4111-8111-111111111111","writerId":WRITER,"sequence":sequence,"timestamp":"2026-10-29T08:00:00.000Z","level":"error","source":{"kind":"app"},"component":"test","message":"event","fields":{}})).unwrap();
        bytes.push(b'\n');
        bytes
    }
    #[test]
    fn export_merges_tiers_and_excludes_uncommitted_batches_without_writes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let directory = Directory::open(root.path()).unwrap();
        let session = directory.create_private_child(WRITER).unwrap();
        session
            .write_atomic("debug-00000000000000000000.jsonl", &event(1), 0o600)
            .unwrap();
        session
            .write_atomic("error-00000000000000000000.jsonl", &event(1), 0o600)
            .unwrap();
        let batches = directory.create_private_child("batches").unwrap();
        let id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let batch = batches.create_private_child(id).unwrap();
        for name in ["debug.jsonl", "info.jsonl", "error.jsonl"] {
            batch.write_atomic(name, &event(2), 0o600).unwrap();
        }
        assert_eq!(read(&directory).unwrap(), event(1));
        batch
            .write_atomic("committed", id.as_bytes(), 0o600)
            .unwrap();
        assert_eq!(read(&directory).unwrap(), [event(1), event(2)].concat());
        let encoded = crate::log_export::encode(&read(&directory).unwrap(), b"{}").unwrap();
        assert_eq!(&encoded[..10], b"VBOOSTLOG1");
        let header_size = u32::from_be_bytes(encoded[11..15].try_into().unwrap()) as usize;
        let header: serde_json::Value =
            serde_json::from_slice(&encoded[55..55 + header_size]).unwrap();
        let length = header["recordsLength"].as_u64().unwrap() as usize;
        assert_eq!(
            &encoded[55 + header_size..55 + header_size + length],
            [event(1), event(2)].concat()
        );
        assert_eq!(batch.entry_names_bounded(8).unwrap().len(), 4);
        batch
            .write_atomic("retired-debug", b"retired", 0o600)
            .unwrap();
        batch.unlink("debug.jsonl").unwrap();
        assert_eq!(read(&directory).unwrap(), [event(1), event(2)].concat());
        for tier in ["info", "error"] {
            batch
                .write_atomic(&format!("retired-{tier}"), b"retired", 0o600)
                .unwrap();
            batch.unlink(&format!("{tier}.jsonl")).unwrap();
        }
        assert_eq!(read(&directory).unwrap(), event(1));
    }
    #[test]
    fn invalid_calendar_and_non_ascii_timestamp_are_rejected_without_panicking() {
        for timestamp in [
            "2026-02-30T08:00:00.000Z",
            "2026-10-29T25:00:00.000Z",
            "éé-10-29T08:00:00.000Z",
        ] {
            let mut row: serde_json::Value = serde_json::from_slice(&event(1)).unwrap();
            row["timestamp"] = timestamp.into();
            let mut bytes = serde_json::to_vec(&row).unwrap();
            bytes.push(b'\n');
            assert!(merge(&bytes, Some(WRITER), 0, &mut BTreeMap::new(), &mut 0).is_err());
        }
    }
    #[test]
    fn divergent_tier_or_wrong_writer_is_not_silently_exported() {
        let mut records = BTreeMap::new();
        let mut total = 0;
        merge(&event(1), Some(WRITER), 0, &mut records, &mut total).unwrap();
        let changed = String::from_utf8(event(1))
            .unwrap()
            .replace("event", "different");
        assert!(merge(
            changed.as_bytes(),
            Some(WRITER),
            2,
            &mut records,
            &mut total
        )
        .is_err());
        assert!(merge(
            &event(1),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            0,
            &mut records,
            &mut total
        )
        .is_err());
        assert!(merge(b"{", None, 0, &mut records, &mut total).is_err());
    }
}
