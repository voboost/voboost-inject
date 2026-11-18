//! One write-only logging session. Archive readers are separate consumers.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};
mod batch;
pub(super) mod qnx;
mod retention;
use voboost_shared::secure_fs::Directory;

const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_SEGMENT_BYTES: u64 = 8 * 1024 * 1024;
const RETRY_MIN: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(5);

pub(super) use voboost_contract::runtime_log::{Level, Source};

pub(super) use voboost_contract::runtime_log::Event;

pub(super) struct Log {
    root: std::path::PathBuf,
    directory: Directory,
    boot_id: String,
    writer_id: String,
    next_sequence: u64,
    segments: [u64; 3],
    bytes: [u64; 3],
    files: [Option<File>; 3],
    failed: bool,
    retry_at: Option<Instant>,
    retry_delay: Duration,
    receipt_inventory: Option<(u64, usize)>,
}

impl Log {
    pub(super) fn session(&self) -> Option<(&str, &str, u64)> {
        (!self.failed).then_some((&self.boot_id, &self.writer_id, self.next_sequence - 1))
    }
    pub(super) fn writer_id(&self) -> &str {
        &self.writer_id
    }
    pub(super) fn append_record(
        &mut self,
        source: Source,
        record: voboost_contract::runtime_log::Record,
    ) -> io::Result<u64> {
        if !source.valid() || !record.valid() {
            return Err(invalid("invalid bound producer record"));
        }
        self.append(
            record.level,
            source,
            &record.component,
            &record.message,
            record.fields.into_iter().collect(),
        )
    }
    pub(super) fn create(root: &Path, boot_id: &str, writer_id: &str) -> io::Result<Self> {
        if !valid_boot(boot_id) || !valid_writer(writer_id) {
            return Err(invalid("invalid logging session identity"));
        }
        let parent = Directory::open(root)?;
        parent.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        let directory = parent.create_private_child(writer_id)?;
        Ok(Self {
            root: root.into(),
            directory,
            boot_id: boot_id.into(),
            writer_id: writer_id.into(),
            next_sequence: 1,
            segments: [0; 3],
            bytes: [0; 3],
            files: [None, None, None],
            failed: false,
            retry_at: None,
            retry_delay: RETRY_MIN,
            receipt_inventory: None,
        })
    }

    /// Commit one bounded diagnostic group without syncing between its records.
    pub(super) fn append_debug_records(
        &mut self,
        records: Vec<voboost_contract::runtime_log::Record>,
    ) -> io::Result<u64> {
        if records.is_empty()
            || records.len() > 128
            || records
                .iter()
                .any(|r| !r.valid() || r.level != Level::Debug)
        {
            return Err(invalid("invalid debug record group"));
        }
        let root = Directory::open(&self.root)?;
        root.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        let _snapshot = root.lock_transaction(Duration::from_secs(2))?;
        self.recover()?;
        let next = self
            .next_sequence
            .checked_add(records.len() as u64)
            .ok_or_else(|| invalid("session sequence exhausted"))?;
        let mut bytes = Vec::new();
        for (offset, record) in records.into_iter().enumerate() {
            let event = Event {
                schema_version: 2,
                boot_id: self.boot_id.clone(),
                writer_id: self.writer_id.clone(),
                sequence: self.next_sequence + offset as u64,
                timestamp: voboost_shared::diagnostic_log::timestamp(),
                level: Level::Debug,
                source: Source::daemon(),
                component: record.component,
                message: voboost_contract::runtime_log::redact(&record.message),
                fields: record
                    .fields
                    .into_iter()
                    .map(|(k, v)| (k, voboost_contract::runtime_log::redact(&v)))
                    .collect(),
            };
            let encoded = serde_json::to_vec(&event).map_err(io::Error::other)?;
            if encoded.len() + 1 > MAX_RECORD_BYTES || bytes.len() + encoded.len() + 1 > 256 * 1024
            {
                return Err(invalid("debug record group exceeds bound"));
            }
            bytes.extend(encoded);
            bytes.push(b'\n');
        }
        self.next_sequence = next;
        let result = (|| {
            if self.bytes[0] + bytes.len() as u64 > MAX_SEGMENT_BYTES {
                self.segments[0] = self.segments[0]
                    .checked_add(1)
                    .ok_or_else(|| invalid("log segment exhausted"))?;
                self.bytes[0] = 0;
                self.files[0] = None;
            }
            let name = format!("debug-{:020}.jsonl", self.segments[0]);
            if self.files[0].is_none() {
                self.files[0] = Some(self.directory.create_new(OsStr::new(&name), 0o600)?);
            }
            let file = self.files[0].as_mut().expect("created session file");
            self.directory.sync_trusted_append(&name, 0o600, file)?;
            if file.metadata()?.len() != self.bytes[0] {
                return Err(invalid("session file length changed"));
            }
            file.write_all(&bytes)?;
            self.directory.sync_trusted_append(&name, 0o600, file)?;
            self.bytes[0] += bytes.len() as u64;
            self.directory.sync_all()
        })();
        if result.is_err() {
            self.fail();
        } else {
            self.retry_delay = RETRY_MIN;
        }
        result.map(|()| next - 1)
    }

    pub(super) fn append(
        &mut self,
        level: Level,
        source: Source,
        component: &str,
        message: &str,
        fields: BTreeMap<String, String>,
    ) -> io::Result<u64> {
        self.append_with(level, source, component, message, fields, |file, bytes| {
            file.write_all(bytes)
        })
    }

    fn append_with(
        &mut self,
        level: Level,
        source: Source,
        component: &str,
        message: &str,
        fields: BTreeMap<String, String>,
        mut write: impl FnMut(&mut File, &[u8]) -> io::Result<()>,
    ) -> io::Result<u64> {
        let root = Directory::open(&self.root)?;
        root.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        let _snapshot = root.lock_transaction(std::time::Duration::from_secs(2))?;
        self.recover()?;
        if !source.valid()
            || component.is_empty()
            || component.len() > 96
            || fields.len() > 32
            || component.chars().any(char::is_control)
        {
            return Err(invalid("invalid logging record context"));
        }
        let context_bytes = source
            .kind
            .len()
            .checked_add(source.id.as_ref().map_or(0, String::len))
            .and_then(|n| n.checked_add(component.len()))
            .and_then(|n| n.checked_add(message.len()))
            .and_then(|n| {
                fields.iter().try_fold(n, |n, (key, value)| {
                    n.checked_add(key.len())?.checked_add(value.len())
                })
            });
        if context_bytes.is_none_or(|n| n > MAX_RECORD_BYTES) {
            return Err(invalid("logging record exceeds bound"));
        }
        let sequence = self.next_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or_else(|| invalid("session sequence exhausted"))?;
        let event = Event {
            schema_version: 2,
            boot_id: self.boot_id.clone(),
            writer_id: self.writer_id.clone(),
            sequence,
            timestamp: voboost_shared::diagnostic_log::timestamp(),
            level,
            source,
            component: component.into(),
            message: voboost_contract::runtime_log::redact(message),
            fields: fields
                .into_iter()
                .map(|(key, value)| (key, voboost_contract::runtime_log::redact(&value)))
                .collect(),
        };
        let mut bytes = serde_json::to_vec(&event).map_err(|_| invalid("log encoding failed"))?;
        bytes.push(b'\n');
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("logging record exceeds bound"));
        }
        // A consumed sequence is never reused after a partial fanout.
        self.next_sequence = next;
        // Error retention is written first, then info, then the complete debug stream.
        let tiers: &[usize] = match event.level {
            Level::Debug => &[0],
            Level::Info => &[1, 0],
            Level::Error => &[2, 1, 0],
        };
        let result = (|| {
            for &tier in tiers {
                if self.bytes[tier] + bytes.len() as u64 > MAX_SEGMENT_BYTES {
                    self.segments[tier] = self.segments[tier]
                        .checked_add(1)
                        .ok_or_else(|| invalid("log segment exhausted"))?;
                    self.bytes[tier] = 0;
                    self.files[tier] = None;
                }
                let prefix = ["debug", "info", "error"][tier];
                let name = format!("{prefix}-{:020}.jsonl", self.segments[tier]);
                if self.files[tier].is_none() {
                    self.files[tier] = Some(self.directory.create_new(OsStr::new(&name), 0o600)?);
                }
                let file = self.files[tier].as_mut().expect("created session file");
                self.directory.sync_trusted_append(&name, 0o600, file)?;
                if file.metadata()?.len() != self.bytes[tier] {
                    return Err(invalid("session file length changed"));
                }
                write(file, &bytes)?;
                self.directory.sync_trusted_append(&name, 0o600, file)?;
                self.bytes[tier] += bytes.len() as u64;
            }
            self.directory.sync_all()
        })();
        if result.is_err() {
            self.fail();
        } else {
            self.retry_delay = RETRY_MIN;
        }
        result.map(|()| sequence)
    }

    fn fail(&mut self) {
        self.failed = true;
        self.files = [None, None, None];
        self.retry_at = Some(Instant::now() + self.retry_delay);
        self.retry_delay = (self.retry_delay * 2).min(RETRY_MAX);
    }

    fn recover(&mut self) -> io::Result<()> {
        if !self.failed {
            return Ok(());
        }
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "logging recovery backoff",
            ));
        }
        // Never reopen a file whose last append or sync was ambiguous. A new
        // identity makes its sequences independent from the retired writer.
        let replacement = (|| {
            let mut random = [0; 16];
            std::io::Read::read_exact(&mut File::open("/dev/urandom")?, &mut random)?;
            Self::create(&self.root, &self.boot_id, &hex::encode(random))
        })();
        match replacement {
            Ok(mut replacement) => {
                replacement.retry_delay = self.retry_delay;
                *self = replacement;
                Ok(())
            }
            Err(error) => {
                self.retry_delay = (self.retry_delay * 2).min(RETRY_MAX);
                self.retry_at = Some(Instant::now() + self.retry_delay);
                Err(error)
            }
        }
    }
}

fn valid_writer(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn append(log: &mut Log, level: Level) -> u64 {
        log.append(level, Source::daemon(), "test", "event", BTreeMap::new())
            .unwrap()
    }
    #[test]
    fn startup_ignores_corrupt_archive_and_does_not_recover_its_checkpoint() {
        let root = root();
        fs::write(
            root.path().join("segment-active.jsonl"),
            b"{torn previous event",
        )
        .unwrap();
        fs::write(root.path().join("sequence.json"), b"not json").unwrap();
        fs::write(
            root.path().join("accepted-batches"),
            b"unreadable historic index",
        )
        .unwrap();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        assert_eq!(append(&mut log, Level::Info), 1);
        assert_eq!(
            fs::read(root.path().join("segment-active.jsonl")).unwrap(),
            b"{torn previous event"
        );
        assert_eq!(
            fs::read(root.path().join("sequence.json")).unwrap(),
            b"not json"
        );
        assert_eq!(
            fs::read(root.path().join("accepted-batches")).unwrap(),
            b"unreadable historic index"
        );
    }
    #[test]
    fn restart_within_same_boot_has_distinct_event_ids_without_old_counter() {
        let root = root();
        let mut first = Log::create(root.path(), BOOT, A).unwrap();
        assert_eq!(append(&mut first, Level::Debug), 1);
        drop(first);
        let mut second = Log::create(root.path(), BOOT, B).unwrap();
        assert_eq!(append(&mut second, Level::Debug), 1);
        let read = |writer| -> Event {
            serde_json::from_slice(
                &fs::read(
                    root.path()
                        .join(writer)
                        .join("debug-00000000000000000000.jsonl"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let a = read(A);
        let b = read(B);
        assert_eq!(a.boot_id, b.boot_id);
        assert_ne!((a.writer_id, a.sequence), (b.writer_id, b.sequence));
    }
    #[test]
    fn session_collision_and_symlink_do_not_change_existing_bytes() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Info);
        let active = root.path().join(A).join("debug-00000000000000000000.jsonl");
        let before = fs::read(&active).unwrap();
        assert!(Log::create(root.path(), BOOT, A).is_err());
        std::os::unix::fs::symlink(root.path().join(A), root.path().join(B)).unwrap();
        assert!(Log::create(root.path(), BOOT, B).is_err());
        assert_eq!(fs::read(active).unwrap(), before);
    }
    #[test]
    fn grouped_debug_recovery_uses_the_replacement_writer_identity() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Debug);
        log.fail();
        log.retry_at = None;
        let record = voboost_contract::runtime_log::Record {
            level: Level::Debug,
            component: "native-can".into(),
            message: "CAN datagram received".into(),
            fields: Default::default(),
        };
        assert_eq!(log.append_debug_records(vec![record]).unwrap(), 1);
        assert_ne!(log.writer_id(), A);
        let bytes = fs::read(
            root.path()
                .join(log.writer_id())
                .join("debug-00000000000000000000.jsonl"),
        )
        .unwrap();
        let event: Event = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(event.writer_id, log.writer_id());
        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn grouped_debug_records_keep_canonical_sequence_and_reject_partial_invalid_input() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Info);
        let record = voboost_contract::runtime_log::Record {
            level: Level::Debug,
            component: "native-can".into(),
            message: "CAN datagram received".into(),
            fields: Default::default(),
        };
        assert_eq!(
            log.append_debug_records(vec![record.clone(), record.clone()])
                .unwrap(),
            3
        );
        let path = root.path().join(A).join("debug-00000000000000000000.jsonl");
        let before = fs::read(&path).unwrap();
        let events: Vec<Event> = before
            .split(|b| *b == b'\n')
            .filter(|b| !b.is_empty())
            .map(|b| serde_json::from_slice(b).unwrap())
            .collect();
        assert_eq!(
            events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        let mut invalid = record.clone();
        invalid.level = Level::Error;
        assert!(log.append_debug_records(vec![record, invalid]).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(append(&mut log, Level::Error), 4);
    }

    #[test]
    fn severity_copies_have_exact_identity_and_private_permissions() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        for level in [Level::Debug, Level::Info, Level::Error] {
            append(&mut log, level);
        }
        let lines = |name| -> Vec<Vec<u8>> {
            fs::read(
                root.path()
                    .join(A)
                    .join(format!("{name}-00000000000000000000.jsonl")),
            )
            .unwrap()
            .split_inclusive(|&b| b == b'\n')
            .map(Vec::from)
            .collect()
        };
        let debug = lines("debug");
        let info = lines("info");
        let error = lines("error");
        assert_eq!((debug.len(), info.len(), error.len()), (3, 2, 1));
        assert_eq!(debug[1], info[0]);
        assert_eq!(debug[2], info[1]);
        assert_eq!(debug[2], error[0]);
        let row: serde_json::Value = serde_json::from_slice(&error[0]).unwrap();
        assert_eq!(row["source"], serde_json::json!({"kind":"daemon"}));
        let timestamp = row["timestamp"].as_str().unwrap();
        assert_eq!(timestamp.len(), 24);
        assert!(timestamp.ends_with('Z'));
        assert!(row.get("receivedAtUnixMs").is_none());
        for tier in ["debug", "info", "error"] {
            let path = root
                .path()
                .join(A)
                .join(format!("{tier}-00000000000000000000.jsonl"));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn invalid_record_does_not_consume_sequence_or_create_files() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        assert!(log
            .append(
                Level::Info,
                Source::daemon(),
                "test",
                &"x".repeat(MAX_RECORD_BYTES),
                BTreeMap::new()
            )
            .is_err());
        assert_eq!(fs::read_dir(root.path().join(A)).unwrap().count(), 0);
        assert_eq!(append(&mut log, Level::Debug), 1);
    }
    #[test]
    fn partial_write_failure_never_reuses_sequence_or_writes_later_records() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        let debug = root.path().join(A).join("debug-00000000000000000000.jsonl");
        fs::create_dir(&debug).unwrap();
        assert!(log
            .append(
                Level::Error,
                Source::daemon(),
                "test",
                "before failure",
                BTreeMap::new()
            )
            .is_err());
        let error = root.path().join(A).join("error-00000000000000000000.jsonl");
        let original = fs::read(&error).unwrap();
        let row: Event = serde_json::from_slice(&original).unwrap();
        assert_eq!(row.sequence, 1);
        assert!(log
            .append(
                Level::Error,
                Source::daemon(),
                "test",
                "later",
                BTreeMap::new()
            )
            .is_err());
        assert_eq!(fs::read(error).unwrap(), original);
        assert_eq!(log.next_sequence, 2);
    }
    #[test]
    fn write_failure_rolls_over_after_backoff_without_touching_the_old_tail() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Error);
        let debug = root.path().join(A).join("debug-00000000000000000000.jsonl");
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(&debug)
            .unwrap()
            .write_all(b"{torn")
            .unwrap();
        assert!(log
            .append(
                Level::Error,
                Source::daemon(),
                "test",
                "failed",
                BTreeMap::new()
            )
            .is_err());
        let before = fs::read(&debug).unwrap();
        assert!(log
            .append(
                Level::Info,
                Source::daemon(),
                "test",
                "backoff",
                BTreeMap::new()
            )
            .is_err());
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(append(&mut log, Level::Error), 1);
        assert_ne!(log.writer_id(), A);
        assert_eq!(fs::read(debug).unwrap(), before);
        for tier in ["debug", "info", "error"] {
            let event: Event = serde_json::from_slice(
                &fs::read(
                    root.path()
                        .join(log.writer_id())
                        .join(format!("{tier}-00000000000000000000.jsonl")),
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(event.writer_id, log.writer_id());
            assert_eq!(event.level, Level::Error);
        }
    }
    #[test]
    fn enospc_and_eio_retire_partial_files_before_a_new_writer_recovers() {
        for errno in [libc::ENOSPC, libc::EIO] {
            let root = root();
            let mut log = Log::create(root.path(), BOOT, A).unwrap();
            let error = log
                .append_with(
                    Level::Info,
                    Source::daemon(),
                    "test",
                    "torn",
                    BTreeMap::new(),
                    |file, bytes| {
                        file.write_all(&bytes[..13])?;
                        Err(io::Error::from_raw_os_error(errno))
                    },
                )
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(errno));
            assert!(log.session().is_none());
            let path = root.path().join(A).join("info-00000000000000000000.jsonl");
            let before = fs::read(&path).unwrap();
            assert_eq!(before.len(), 13);
            log.retry_at = Some(Instant::now());
            assert_eq!(append(&mut log, Level::Info), 1);
            assert_ne!(log.writer_id(), A);
            assert_eq!(fs::read(path).unwrap(), before);
        }
    }
    #[test]
    fn debug_rotation_does_not_rotate_rare_info_or_error_streams() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Error);
        log.bytes[0] = MAX_SEGMENT_BYTES;
        append(&mut log, Level::Debug);
        append(&mut log, Level::Error);
        for tier in ["info", "error"] {
            let bytes = fs::read(
                root.path()
                    .join(A)
                    .join(format!("{tier}-00000000000000000000.jsonl")),
            )
            .unwrap();
            assert_eq!(
                bytes
                    .split(|&b| b == b'\n')
                    .filter(|line| !line.is_empty())
                    .count(),
                2
            );
        }
    }
    #[test]
    fn rotation_uses_only_current_sizes_and_keeps_session_sequence() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Debug);
        log.bytes[0] = MAX_SEGMENT_BYTES;
        assert_eq!(append(&mut log, Level::Debug), 2);
        assert_eq!(log.segments, [1, 0, 0]);
        let row: Event = serde_json::from_slice(
            &fs::read(root.path().join(A).join("debug-00000000000000000001.jsonl")).unwrap(),
        )
        .unwrap();
        assert_eq!(row.sequence, 2);
        assert_eq!(row.writer_id, A);
    }
    #[test]
    fn replaced_regular_file_is_rejected_before_appending_to_either_inode() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        append(&mut log, Level::Debug);
        let active = root.path().join(A).join("debug-00000000000000000000.jsonl");
        let retired = root.path().join(A).join("retired");
        let before = fs::read(&active).unwrap();
        fs::rename(&active, &retired).unwrap();
        fs::write(&active, b"foreign").unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(log
            .append(
                Level::Debug,
                Source::daemon(),
                "test",
                "later",
                BTreeMap::new()
            )
            .is_err());
        assert_eq!(fs::read(active).unwrap(), b"foreign");
        assert_eq!(fs::read(retired).unwrap(), before);
    }
    #[test]
    fn unexpected_leaf_collision_never_appends_to_existing_file() {
        let root = root();
        let mut log = Log::create(root.path(), BOOT, A).unwrap();
        let active = root.path().join(A).join("debug-00000000000000000000.jsonl");
        fs::write(&active, b"foreign").unwrap();
        fs::set_permissions(&active, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(log
            .append(
                Level::Debug,
                Source::daemon(),
                "test",
                "later",
                BTreeMap::new()
            )
            .is_err());
        assert_eq!(fs::read(active).unwrap(), b"foreign");
    }
}
