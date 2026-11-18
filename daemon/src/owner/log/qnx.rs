//! A single recoverable intent links immutable tier files to the QNX cursor.
use super::*;
use std::{path::PathBuf, sync::Mutex, time::Duration};
use voboost_contract::cluster_log::{self, Ack, Batch};

pub(super) use crate::log_archive::{MAX_QNX_BATCHES as MAX_BATCHES, QNX_BATCHES as BATCHES};
pub(super) const MAX_SEGMENT: u64 = crate::log_archive::MAX_QNX_SEGMENT as u64;
pub(super) const KEEP_BATCHES: usize = MAX_BATCHES - 512;
pub(super) const TIER_BYTES: u64 = 16 * 1024 * 1024;
const PENDING: &str = "qnx-pending.json";
const DELIVERY: &str = "qnx-delivery.json";
const MAX_PENDING: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Status {
    Connected,
    Unavailable,
    Unpaired,
}

/// Static categories deliberately exclude peer text, paths and credentials.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Failure {
    Configuration,
    Transport,
    Timeout,
    Protocol,
    Storage,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delivery {
    schema_version: u8,
    boot_id: String,
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure_category: Option<Failure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_success_at: Option<String>,
}

impl Delivery {
    fn ack(&self) -> io::Result<Option<Ack>> {
        if self.schema_version != 1 || !valid_boot(&self.boot_id) {
            return Err(invalid("invalid QNX delivery record"));
        }
        match (&self.source_session, self.sequence) {
            (None, None) => Ok(None),
            (Some(source_session), Some(sequence)) => {
                let ack = Ack {
                    source_session: source_session.clone(),
                    sequence,
                };
                ack.validate().map_err(io::Error::other)?;
                Ok(Some(ack))
            }
            _ => Err(invalid("invalid QNX delivery position")),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    id: String,
    ack: Ack,
    events: Vec<Event>,
}

fn read<T: serde::de::DeserializeOwned>(
    directory: &Directory,
    name: &str,
    max_bytes: usize,
) -> io::Result<Option<T>> {
    match directory.read_trusted(name, max_bytes, 0o600) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_pending(root: &Directory) -> io::Result<Option<Pending>> {
    let value: Option<Pending> = read(root, PENDING, MAX_PENDING)?;
    if let Some(pending) = &value {
        pending.ack.validate().map_err(io::Error::other)?;
        let Some(first) = pending.events.first() else {
            return Err(invalid("empty QNX log intent"));
        };
        if !valid_writer(&pending.id)
            || !valid_boot(&first.boot_id)
            || !valid_writer(&first.writer_id)
            || first.sequence == 0
            || pending.events.len() > cluster_log::MAX_EVENTS + 2
            || pending.events.iter().enumerate().any(|(offset, event)| {
                event.schema_version != 2
                    || event.boot_id != first.boot_id
                    || event.writer_id != first.writer_id
                    || Some(event.sequence) != first.sequence.checked_add(offset as u64)
                    || event.source.kind != "qnx"
                    || event.source.id.as_ref() != Some(&pending.ack.source_session)
            })
        {
            return Err(invalid("invalid QNX log intent"));
        }
    }
    Ok(value)
}

pub(super) fn pending_id(root: &Directory) -> io::Result<Option<String>> {
    Ok(read_pending(root)?.map(|pending| pending.id))
}

pub(crate) struct Journal {
    root: PathBuf,
    boot_id: String,
    batch_count: Option<usize>,
    last_success_at: Option<String>,
}

impl Journal {
    pub(crate) fn new(root: &Path, boot_id: &str) -> Self {
        Self {
            root: root.into(),
            boot_id: boot_id.into(),
            batch_count: None,
            last_success_at: None,
        }
    }

    pub(crate) fn maintain(&mut self) -> io::Result<usize> {
        self.maintain_with_limit(TIER_BYTES)
    }

    fn maintain_with_limit(&mut self, limit: u64) -> io::Result<usize> {
        self.batch_count = None;
        super::retention::maintain_qnx(&self.directory()?, limit)
    }

    fn directory(&self) -> io::Result<Directory> {
        let root = Directory::open(&self.root)?;
        root.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        Ok(root)
    }

    pub(crate) fn position(&self) -> io::Result<Option<Ack>> {
        let root = self.directory()?;
        let batches = root.open_or_create_private_child(BATCHES)?;
        let _snapshot = batches.lock_transaction(Duration::ZERO)?;
        self.finish_pending(&root, &batches, Directory::sync_all)?;
        delivery_position(&root)
    }

    pub(crate) fn set_status(&mut self, status: Status) -> io::Result<()> {
        self.set_health(status, None)
    }

    pub(crate) fn set_failure(&mut self, failure: Failure) -> io::Result<()> {
        self.set_health(Status::Unavailable, Some(failure))
    }

    fn set_health(&mut self, status: Status, failure: Option<Failure>) -> io::Result<()> {
        if status == Status::Connected {
            self.last_success_at = Some(voboost_shared::diagnostic_log::timestamp());
        }
        let root = self.directory()?;
        let previous: Option<Delivery> = read(&root, DELIVERY, 512)?;
        if previous.as_ref().is_some_and(|previous| {
            previous.boot_id == self.boot_id
                && previous.status == status
                && previous.failure_category == failure
        }) {
            return Ok(());
        }
        let ack = previous.as_ref().map(Delivery::ack).transpose()?.flatten();
        self.save_delivery(
            &root,
            status,
            ack.as_ref(),
            failure,
            self.last_success_at.as_deref(),
        )
    }

    fn save_qnx_delivery(
        &self,
        root: &Directory,
        status: Status,
        ack: Option<&Ack>,
    ) -> io::Result<()> {
        self.save_delivery(root, status, ack, None, None)
    }

    fn save_delivery(
        &self,
        root: &Directory,
        status: Status,
        ack: Option<&Ack>,
        failure_category: Option<Failure>,
        success_at: Option<&str>,
    ) -> io::Result<()> {
        let previous: Option<Delivery> = read(root, DELIVERY, 512)?;
        let last_success_at = if status == Status::Connected {
            Some(
                success_at
                    .map(str::to_owned)
                    .unwrap_or_else(voboost_shared::diagnostic_log::timestamp),
            )
        } else {
            self.last_success_at
                .clone()
                .max(previous.and_then(|value| value.last_success_at))
        };
        let delivery = Delivery {
            schema_version: 1,
            boot_id: self.boot_id.clone(),
            status,
            source_session: ack.map(|ack| ack.source_session.clone()),
            sequence: ack.map(|ack| ack.sequence),
            failure_category,
            last_success_at,
        };
        let bytes = serde_json::to_vec(&delivery).map_err(io::Error::other)?;
        root.write_atomic(DELIVERY, &bytes, 0o600)
    }

    fn finish_pending(
        &self,
        root: &Directory,
        batches: &Directory,
        sync_cursor: impl FnOnce(&Directory) -> io::Result<()>,
    ) -> io::Result<()> {
        let Some(pending) = read_pending(root)? else {
            return Ok(());
        };
        if !delivery_position(root)?.is_some_and(|ack| ack == pending.ack) {
            let directory = batches.open_or_create_private_child(&pending.id)?;
            batch::publish(&directory, &pending.id, &pending.events)?;
            batches.sync_all()?;
            root.sync_all()?;
            self.save_qnx_delivery(root, Status::Connected, Some(&pending.ack))?;
        }
        // write_atomic may have renamed the cursor before its directory
        // sync returned an error. Keep the intent until that sync succeeds.
        sync_cursor(root)?;
        root.unlink(PENDING)?;
        root.sync_all()
    }

    pub(crate) fn append(&mut self, logger: &Mutex<Log>, incoming: &Batch) -> io::Result<()> {
        incoming.validate().map_err(io::Error::other)?;
        let root = self.directory()?;
        let batches = root.open_or_create_private_child(BATCHES)?;
        let _snapshot = batches.lock_transaction(Duration::ZERO)?;
        self.finish_pending(&root, &batches, Directory::sync_all)?;
        let previous = delivery_position(&root)?;
        if previous.as_ref().is_some_and(|ack| ack.matches(incoming)) {
            return Ok(());
        }
        let same = previous
            .as_ref()
            .filter(|ack| ack.source_session == incoming.source_session);
        let expected = same.map_or(Some(1), |ack| ack.sequence.checked_add(1));
        if expected != Some(incoming.sequence) {
            return Err(invalid("unexpected QNX log position"));
        }
        let count = match self.batch_count {
            Some(count) => count,
            None => batches.entry_names_bounded(MAX_BATCHES)?.len(),
        };
        self.batch_count = Some(count);
        if count >= MAX_BATCHES {
            return Err(invalid("QNX log batch capacity reached"));
        }
        let mut random = [0; 16];
        std::io::Read::read_exact(&mut File::open("/dev/urandom")?, &mut random)?;
        let id = hex::encode(random);
        if batches.entry_exists(&id)? {
            return Err(invalid("QNX log batch identity collision"));
        }
        let ack = Ack {
            source_session: incoming.source_session.clone(),
            sequence: incoming.sequence,
        };
        let events = logger
            .lock()
            .map_err(|_| invalid("logging lock poisoned"))?
            .qnx_events(incoming, previous.as_ref().filter(|_| same.is_none()))?;
        let encoded = serde_json::to_vec(&Pending { id, ack, events }).map_err(io::Error::other)?;
        if encoded.len() > MAX_PENDING {
            return Err(invalid("QNX log intent exceeds bound"));
        }
        // Reserve the canonical sequences even if the intent write is ambiguous.
        // A later attempt recovers a published intent or leaves a harmless gap.
        self.batch_count = None;
        root.write_atomic(PENDING, &encoded, 0o600)?;
        self.batch_count = Some(count + 1);
        self.finish_pending(&root, &batches, Directory::sync_all)
    }
}

impl Log {
    fn qnx_events(&mut self, incoming: &Batch, previous: Option<&Ack>) -> io::Result<Vec<Event>> {
        self.recover()?;
        let mut events = Vec::with_capacity(incoming.events.len() + 2);
        let mut sequence = self.next_sequence;
        let timestamp = voboost_shared::diagnostic_log::timestamp();
        let source = Source::qnx(incoming.source_session.clone());
        let mut push = |level, component, message, mut fields: BTreeMap<String, String>| {
            fields.insert("qnxBatchSequence".into(), incoming.sequence.to_string());
            events.push(Event {
                schema_version: 2,
                boot_id: self.boot_id.clone(),
                writer_id: self.writer_id.clone(),
                sequence,
                timestamp: timestamp.clone(),
                level,
                source: source.clone(),
                component,
                message,
                fields,
            });
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| invalid("session sequence exhausted"))?;
            Ok::<(), io::Error>(())
        };
        if let Some(previous) = previous {
            push(
                Level::Info,
                "cluster-log".into(),
                "QNX log source session changed".into(),
                BTreeMap::from([(
                    "previousSourceSession".into(),
                    previous.source_session.clone(),
                )]),
            )?;
        }
        if incoming.dropped > 0 {
            push(
                Level::Info,
                "cluster-log".into(),
                "QNX log queue dropped events".into(),
                BTreeMap::from([("dropped".into(), incoming.dropped.to_string())]),
            )?;
        }
        use voboost_contract::runtime_log::redact;
        for event in &incoming.events {
            let level = match event.level {
                cluster_log::Level::Debug => Level::Debug,
                cluster_log::Level::Info => Level::Info,
                cluster_log::Level::Error => Level::Error,
            };
            let mut fields: BTreeMap<_, _> = event
                .fields
                .iter()
                .map(|(name, value)| (format!("qnx.{name}"), redact(value)))
                .collect();
            fields.insert("qnxTimestamp".into(), event.timestamp.clone());
            fields.insert("qnxSource".into(), event.source.clone());
            push(
                level,
                redact(&event.component),
                redact(&event.message),
                fields,
            )?;
        }
        let tiers = batch::segments(&events)?;
        if tiers[0].len() as u64 > MAX_SEGMENT {
            return Err(invalid("QNX log segment exceeds bound"));
        }
        self.next_sequence = sequence;
        Ok(events)
    }
}

fn delivery_position(root: &Directory) -> io::Result<Option<Ack>> {
    read::<Delivery>(root, DELIVERY, 512)?
        .as_ref()
        .map(Delivery::ack)
        .transpose()
        .map(Option::flatten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const WRITER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RESTART: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const BATCH_ID: &str = "cccccccccccccccccccccccccccccccc";

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn incoming(session: &str, sequence: u64, dropped: u64) -> Batch {
        Batch {
            source_session: session.into(),
            sequence,
            dropped,
            events: vec![cluster_log::Event {
                level: cluster_log::Level::Error,
                source: "cluster".into(),
                component: "service".into(),
                timestamp: "2026-11-09T12:00:00.000Z".into(),
                message: "token=private".into(),
                fields: BTreeMap::from([("details".into(), "password=private".into())]),
            }],
        }
    }

    fn export(journal: &Journal) -> Vec<Event> {
        crate::log_archive::read(&journal.directory().unwrap())
            .unwrap()
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }

    #[test]
    fn delivery_health_keeps_last_success_and_suppresses_repeated_failures() {
        let root = root();
        let mut journal = Journal::new(root.path(), BOOT);
        journal.set_status(Status::Connected).unwrap();
        let path = root.path().join(DELIVERY);
        let connected: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(connected["lastSuccessAt"].as_str().is_some());
        journal.set_failure(Failure::Timeout).unwrap();
        let first = fs::read(&path).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        for _ in 0..20 {
            journal.set_failure(Failure::Timeout).unwrap();
        }
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        assert_eq!(fs::read(&path).unwrap(), first);
        let failed: serde_json::Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(failed["failureCategory"], "timeout");
        assert_eq!(failed["lastSuccessAt"], connected["lastSuccessAt"]);
        let mut restarted = Journal::new(root.path(), BOOT);
        restarted.set_failure(Failure::Storage).unwrap();
        let failed: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(failed["lastSuccessAt"], connected["lastSuccessAt"]);
        assert_eq!(failed["failureCategory"], "storage");
        restarted.set_status(Status::Connected).unwrap();
        let recovered: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(recovered.get("failureCategory").is_none());
        assert_eq!(recovered["status"], "connected");
    }

    #[test]
    fn qnx_batch_can_replace_a_failed_writer_without_reusing_its_identity() {
        let root = root();
        let mut journal = Journal::new(root.path(), BOOT);
        let mut logger = Log::create(root.path(), BOOT, WRITER).unwrap();
        logger.fail();
        logger.retry_at = Some(Instant::now());
        let logger = Mutex::new(logger);
        journal.append(&logger, &incoming("qnx-a", 1, 0)).unwrap();
        let event = export(&journal).pop().unwrap();
        assert_ne!(event.writer_id, WRITER);
        assert_eq!(event.writer_id, logger.lock().unwrap().writer_id());
        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn restart_finishes_committed_tiers_before_ack_without_allocating_another_sequence() {
        let root = root();
        let journal = Journal::new(root.path(), BOOT);
        let first = Mutex::new(Log::create(root.path(), BOOT, WRITER).unwrap());
        let batch = incoming("qnx-a", 1, 0);
        let ack = Ack {
            source_session: batch.source_session.clone(),
            sequence: batch.sequence,
        };
        let intent = Pending {
            id: BATCH_ID.into(),
            ack: ack.clone(),
            events: first.lock().unwrap().qnx_events(&batch, None).unwrap(),
        };
        let directory = journal.directory().unwrap();
        directory
            .write_atomic(PENDING, &serde_json::to_vec(&intent).unwrap(), 0o600)
            .unwrap();
        let batches = directory.open_or_create_private_child(BATCHES).unwrap();
        let tier_files = batches.create_private_child(BATCH_ID).unwrap();
        batch::publish(&tier_files, BATCH_ID, &intent.events).unwrap();
        assert_eq!(delivery_position(&directory).unwrap(), None);
        drop(first);

        let mut journal = Journal::new(root.path(), BOOT);
        let restarted = Mutex::new(Log::create(root.path(), BOOT, RESTART).unwrap());
        assert_eq!(journal.position().unwrap(), Some(ack));
        assert!(!directory.entry_exists(PENDING).unwrap());
        journal.append(&restarted, &batch).unwrap();
        assert_eq!(restarted.lock().unwrap().next_sequence, 1);
        let events = export(&journal);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], intent.events[0]);
        assert_eq!(events[0].writer_id, WRITER);
        assert_eq!(events[0].message, "token=[REDACTED]");
        assert_eq!(events[0].fields["qnx.details"], "password=[REDACTED]");
    }

    #[test]
    fn failed_tier_publication_preserves_previous_cursor_and_retries_partial_write() {
        let root = root();
        let mut journal = Journal::new(root.path(), BOOT);
        let log = Mutex::new(Log::create(root.path(), BOOT, WRITER).unwrap());
        let first = incoming("qnx-a", 1, 0);
        journal.append(&log, &first).unwrap();
        let second = incoming("qnx-a", 2, 0);
        let intent = Pending {
            id: BATCH_ID.into(),
            ack: Ack {
                source_session: second.source_session.clone(),
                sequence: second.sequence,
            },
            events: log.lock().unwrap().qnx_events(&second, None).unwrap(),
        };
        let directory = journal.directory().unwrap();
        directory
            .write_atomic(PENDING, &serde_json::to_vec(&intent).unwrap(), 0o600)
            .unwrap();
        let tier_files = directory
            .open_child(BATCHES)
            .unwrap()
            .create_private_child(BATCH_ID)
            .unwrap();
        tier_files
            .write_atomic(
                "debug.jsonl",
                &batch::segments(&intent.events).unwrap()[0],
                0o600,
            )
            .unwrap();
        fs::create_dir(root.path().join(BATCHES).join(BATCH_ID).join("info.jsonl")).unwrap();
        assert!(journal.position().is_err());
        assert!(delivery_position(&directory)
            .unwrap()
            .unwrap()
            .matches(&first));
        assert_eq!(export(&journal).len(), 1);

        fs::remove_dir(root.path().join(BATCHES).join(BATCH_ID).join("info.jsonl")).unwrap();
        drop(log);
        let mut journal = Journal::new(root.path(), BOOT);
        let restarted = Mutex::new(Log::create(root.path(), BOOT, RESTART).unwrap());
        assert!(journal.position().unwrap().unwrap().matches(&second));
        journal.append(&restarted, &second).unwrap();
        assert_eq!(export(&journal).len(), 2);
    }

    #[test]
    fn source_restart_and_loss_keep_provenance_and_reject_skipped_positions() {
        let root = root();
        let mut journal = Journal::new(root.path(), BOOT);
        let log = Mutex::new(Log::create(root.path(), BOOT, WRITER).unwrap());
        assert!(journal.append(&log, &incoming("qnx-a", 2, 0)).is_err());
        journal.append(&log, &incoming("qnx-a", 1, 0)).unwrap();
        assert!(journal.append(&log, &incoming("qnx-a", 3, 0)).is_err());
        assert!(journal.append(&log, &incoming("qnx-b", 2, 0)).is_err());
        let mut loss = incoming("qnx-b", 1, 5);
        loss.events.clear();
        journal.append(&log, &loss).unwrap();
        journal.append(&log, &loss).unwrap();
        journal.set_status(Status::Unavailable).unwrap();

        let events = export(&journal);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].source, Source::qnx("qnx-a".into()));
        assert_eq!(events[1].source, Source::qnx("qnx-b".into()));
        assert_eq!(events[1].fields["previousSourceSession"], "qnx-a");
        assert_eq!(events[2].fields["dropped"], "5");
        let health: Delivery = read(&journal.directory().unwrap(), DELIVERY, 512)
            .unwrap()
            .unwrap();
        assert_eq!(health.status, Status::Unavailable);
        assert!(health.ack().unwrap().unwrap().matches(&loss));
    }

    #[test]
    fn fully_retired_qnx_batch_keeps_retry_cursor_without_retaining_intent() {
        let root = root();
        let mut journal = Journal::new(root.path(), BOOT);
        let first = Mutex::new(Log::create(root.path(), BOOT, WRITER).unwrap());
        let batch = incoming("qnx-a", 1, 0);
        journal.append(&first, &batch).unwrap();
        assert_eq!(journal.maintain_with_limit(0).unwrap(), 3);
        let batches = journal.directory().unwrap().open_child(BATCHES).unwrap();
        assert!(batches.entry_names_bounded(MAX_BATCHES).unwrap().is_empty());
        drop(first);

        let mut journal = Journal::new(root.path(), BOOT);
        let restarted = Mutex::new(Log::create(root.path(), BOOT, RESTART).unwrap());
        assert!(journal.position().unwrap().unwrap().matches(&batch));
        journal.append(&restarted, &batch).unwrap();
        assert!(export(&journal).is_empty());
        assert_eq!(restarted.lock().unwrap().next_sequence, 1);
    }

    #[test]
    fn visible_cursor_without_successful_sync_cannot_retire_recovery_intent() {
        let root = root();
        let journal = Journal::new(root.path(), BOOT);
        let mut log = Log::create(root.path(), BOOT, WRITER).unwrap();
        let batch = incoming("qnx-a", 1, 0);
        let ack = Ack {
            source_session: batch.source_session.clone(),
            sequence: batch.sequence,
        };
        let intent = Pending {
            id: BATCH_ID.into(),
            ack: ack.clone(),
            events: log.qnx_events(&batch, None).unwrap(),
        };
        let directory = journal.directory().unwrap();
        directory
            .write_atomic(PENDING, &serde_json::to_vec(&intent).unwrap(), 0o600)
            .unwrap();
        let batches = directory.open_or_create_private_child(BATCHES).unwrap();
        let tier_files = batches.create_private_child(BATCH_ID).unwrap();
        batch::publish(&tier_files, BATCH_ID, &intent.events).unwrap();
        journal
            .save_qnx_delivery(&directory, Status::Connected, Some(&ack))
            .unwrap();

        // Model a readable rename whose directory fsync reports failure.
        assert!(journal
            .finish_pending(&directory, &batches, |_| Err(io::Error::other(
                "injected fsync failure"
            )))
            .is_err());
        assert!(directory.entry_exists(PENDING).unwrap());
        assert_eq!(journal.position().unwrap(), Some(ack));
        assert!(!directory.entry_exists(PENDING).unwrap());
    }

    #[test]
    fn qnx_and_owner_file_transactions_do_not_share_a_lock() {
        let root = root();
        let mut journal = Journal::new(root.path(), BOOT);
        let logger = Mutex::new(Log::create(root.path(), BOOT, WRITER).unwrap());
        let directory = journal.directory().unwrap();
        let owner_lock = directory.lock_transaction(Duration::ZERO).unwrap();
        journal.append(&logger, &incoming("qnx-a", 1, 0)).unwrap();
        drop(owner_lock);

        let batches = directory.open_child(BATCHES).unwrap();
        let _qnx_lock = batches.lock_transaction(Duration::ZERO).unwrap();
        logger
            .lock()
            .unwrap()
            .append(
                Level::Info,
                Source::daemon(),
                "owner",
                "control diagnostic",
                BTreeMap::new(),
            )
            .unwrap();
        assert!(journal.position().is_err());
    }
}
