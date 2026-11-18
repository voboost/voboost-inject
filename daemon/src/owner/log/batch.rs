//! Immutable batch segments with an on-demand, per-identity recovery receipt.
use super::*;
use voboost_contract::runtime_log::{
    AppBatch, MAX_BATCH_BYTES, MAX_BATCH_RECEIPTS, MAX_BATCH_RECEIPT_BYTES, MAX_BATCH_RECORDS,
    TIER_NAMES,
};

const MAX_RECEIPT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    schema_version: u8,
    batch: AppBatch,
    events: Vec<Event>,
}

impl Log {
    pub(crate) fn append_app_batch(&mut self, bytes: &[u8]) -> io::Result<String> {
        let batch = AppBatch::decode(bytes).map_err(invalid)?;
        let parent = Directory::open(&self.root)?;
        parent.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        let _snapshot = parent.lock_transaction(std::time::Duration::from_secs(2))?;
        let batches = parent.open_or_create_private_child("batches")?;
        let directory = match batches.open_child(&batch.batch_id) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.load_receipt_inventory(&batches)?;
                let (bytes, count) = self.receipt_inventory.expect("loaded inventory");
                if count >= MAX_BATCH_RECEIPTS || bytes >= MAX_BATCH_RECEIPT_BYTES {
                    return Err(invalid("app log receipt capacity reached"));
                }
                let directory = batches.create_private_child(&batch.batch_id)?;
                self.receipt_inventory = Some((bytes, count + 1));
                directory
            }
            Err(error) => return Err(error),
        };
        directory.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        // Only the requested identity is read. Cold startup never scans receipts.
        let receipt = match directory.read_trusted("intent.json", MAX_RECEIPT_BYTES, 0o600) {
            Ok(bytes) => {
                let receipt: Receipt =
                    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid batch receipt"))?;
                validate(&receipt, &batch)?;
                receipt
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.recover()?;
                let next = self
                    .next_sequence
                    .checked_add(batch.records.len() as u64)
                    .ok_or_else(|| invalid("session sequence exhausted"))?;
                let timestamp = voboost_shared::diagnostic_log::timestamp();
                let events = batch
                    .records
                    .iter()
                    .enumerate()
                    .map(|(offset, record)| Event {
                        schema_version: 2,
                        boot_id: self.boot_id.clone(),
                        writer_id: self.writer_id.clone(),
                        sequence: self.next_sequence + offset as u64,
                        timestamp: timestamp.clone(),
                        level: record.level.clone(),
                        source: Source {
                            kind: "app".into(),
                            id: None,
                        },
                        component: record.component.clone(),
                        message: record.message.clone(),
                        fields: record.fields.clone().into_iter().collect(),
                    })
                    .collect();
                let receipt = Receipt {
                    schema_version: 1,
                    batch: batch.clone(),
                    events,
                };
                // Check all encodings before reserving a sequence or staging any bytes.
                segments(&receipt.events)?;
                let encoded = serde_json::to_vec(&receipt).map_err(io::Error::other)?;
                if encoded.len() > MAX_RECEIPT_BYTES {
                    return Err(invalid("batch receipt exceeds bound"));
                }
                self.load_receipt_inventory(&batches)?;
                let (used, count) = self.receipt_inventory.expect("loaded inventory");
                let reserved = used
                    .checked_add(encoded.len() as u64)
                    .filter(|bytes| *bytes <= MAX_BATCH_RECEIPT_BYTES)
                    .ok_or_else(|| invalid("app log receipt capacity reached"))?;
                self.receipt_inventory = Some((reserved, count));
                self.next_sequence = next;
                if let Err(error) = directory.write_atomic("intent.json", &encoded, 0o600) {
                    self.fail();
                    return Err(error);
                }
                receipt
            }
            Err(error) => return Err(error),
        };
        publish(&directory, &batch.batch_id, &receipt.events)?;
        directory.sync_all()?;
        batches.sync_all()?;
        parent.sync_all()?;
        self.retry_delay = RETRY_MIN;
        Ok(batch.batch_id)
    }

    fn load_receipt_inventory(&mut self, batches: &Directory) -> io::Result<()> {
        if self.receipt_inventory.is_some() {
            return Ok(());
        }
        let names = batches.entry_names_bounded(MAX_BATCH_RECEIPTS)?;
        let mut total = 0u64;
        for name in &names {
            if !valid_writer(name) {
                return Err(invalid("invalid batch receipt identity"));
            }
            let directory = batches.open_child(name)?;
            directory.validate_owner_mode(
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
                0o700,
            )?;
            match directory.metadata_trusted("intent.json", 0o600) {
                Ok((_, bytes)) if bytes <= MAX_RECEIPT_BYTES as u64 => {
                    total = total
                        .checked_add(bytes)
                        .ok_or_else(|| invalid("receipt size overflow"))?;
                }
                Ok(_) => return Err(invalid("receipt exceeds bound")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
        }
        self.receipt_inventory = Some((total, names.len()));
        Ok(())
    }
}

fn validate(receipt: &Receipt, expected: &AppBatch) -> io::Result<()> {
    let value = serde_json::to_vec(&receipt.batch).map_err(io::Error::other)?;
    let normalized = AppBatch::decode(&value).map_err(invalid)?;
    if receipt.schema_version != 1
        || value.len() > MAX_BATCH_BYTES
        || serde_json::to_value(&normalized).map_err(io::Error::other)?
            != serde_json::to_value(expected).map_err(io::Error::other)?
        || receipt.events.len() != expected.records.len()
    {
        return Err(invalid("batch identity reused with different contents"));
    }
    let first = receipt
        .events
        .first()
        .ok_or_else(|| invalid("empty batch receipt"))?;
    for (offset, (event, record)) in receipt.events.iter().zip(&expected.records).enumerate() {
        if event.schema_version != 2
            || !valid_boot(&event.boot_id)
            || !valid_writer(&event.writer_id)
            || event.boot_id != first.boot_id
            || event.writer_id != first.writer_id
            || first.sequence == 0
            || first.sequence.checked_add(offset as u64) != Some(event.sequence)
            || event.timestamp != first.timestamp
            || event.timestamp.len() != 24
            || event.source
                != (Source {
                    kind: "app".into(),
                    id: None,
                })
            || event.level != record.level
            || event.component != record.component
            || event.message != record.message
            || event.fields != record.fields.clone().into_iter().collect()
        {
            return Err(invalid("batch receipt event mismatch"));
        }
    }
    Ok(())
}

pub(super) fn publish(directory: &Directory, id: &str, events: &[Event]) -> io::Result<()> {
    let tiers = segments(events)?;
    for (tier, expected) in TIER_NAMES.into_iter().zip(tiers) {
        let retired = format!("retired-{tier}");
        match directory.read_trusted(&retired, 7, 0o600) {
            Ok(marker) if marker == b"retired" => {
                if directory.read_trusted("committed", 32, 0o600)? != id.as_bytes() {
                    return Err(invalid("uncommitted batch cannot be retired"));
                }
                continue;
            }
            Ok(_) => return Err(invalid("invalid batch retirement marker")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
        let name = format!("{tier}.jsonl");
        match directory.read_trusted(&name, MAX_BATCH_RECORDS * MAX_RECORD_BYTES, 0o600) {
            Ok(actual) if actual == expected => (),
            Ok(_) => return Err(invalid("batch segment differs from receipt")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                directory.write_atomic(&name, &expected, 0o600)?;
            }
            Err(error) => return Err(error),
        }
    }
    match directory.read_trusted("committed", 32, 0o600) {
        Ok(bytes) if bytes == id.as_bytes() => (),
        Ok(_) => return Err(invalid("batch commit differs from receipt")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            directory.write_atomic("committed", id.as_bytes(), 0o600)?;
        }
        Err(error) => return Err(error),
    }
    directory.sync_all()
}

pub(super) fn segments(events: &[Event]) -> io::Result<[Vec<u8>; 3]> {
    let mut tiers: [Vec<u8>; 3] = Default::default();
    for event in events {
        let mut bytes = serde_json::to_vec(event).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("batch event exceeds bound"));
        }
        tiers[0].extend_from_slice(&bytes);
        if matches!(event.level, Level::Info | Level::Error) {
            tiers[1].extend_from_slice(&bytes);
        }
        if event.level == Level::Error {
            tiers[2].extend_from_slice(&bytes);
        }
    }
    Ok(tiers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const ID: &str = "cccccccccccccccccccccccccccccccc";
    fn payload(message: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"batchId":ID,"records":[{"level":"error","component":"app","message":message,"fields":{}}]})).unwrap()
    }
    #[test]
    fn retry_after_restart_recovers_missing_tier_without_reassigning_identity() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut first = Log::create(root.path(), BOOT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        first.append_app_batch(&payload("event")).unwrap();
        let next = first.next_sequence;
        first.append_app_batch(&payload("event")).unwrap();
        assert_eq!(first.next_sequence, next);
        let directory = root.path().join("batches").join(ID);
        let original = fs::read(directory.join("debug.jsonl")).unwrap();
        fs::remove_file(directory.join("error.jsonl")).unwrap();
        fs::remove_file(directory.join("committed")).unwrap();
        let mut replacement =
            Log::create(root.path(), BOOT, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        replacement.append_app_batch(&payload("event")).unwrap();
        assert_eq!(fs::read(directory.join("error.jsonl")).unwrap(), original);
        assert_eq!(replacement.next_sequence, 1);
        assert!(replacement.append_app_batch(&payload("different")).is_err());
        assert_eq!(fs::read(directory.join("debug.jsonl")).unwrap(), original);
    }
    #[test]
    fn full_receipt_budget_rejects_new_identity_but_keeps_existing_retry() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut log = Log::create(root.path(), BOOT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        log.append_app_batch(&payload("event")).unwrap();
        log.receipt_inventory = Some((MAX_BATCH_RECEIPT_BYTES, MAX_BATCH_RECEIPTS));
        assert_eq!(log.append_app_batch(&payload("event")).unwrap(), ID);
        let next_id = "dddddddddddddddddddddddddddddddd";
        let new = String::from_utf8(payload("event"))
            .unwrap()
            .replace(ID, next_id);
        assert!(log.append_app_batch(new.as_bytes()).is_err());
        assert!(!root.path().join("batches").join(next_id).exists());
    }
    #[test]
    fn committed_retirement_prevents_replay_from_recreating_a_segment() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut log = Log::create(root.path(), BOOT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        log.append_app_batch(&payload("event")).unwrap();
        let directory = Directory::open(&root.path().join("batches").join(ID)).unwrap();
        directory
            .write_atomic("retired-debug", b"retired", 0o600)
            .unwrap();
        directory.unlink("debug.jsonl").unwrap();
        log.append_app_batch(&payload("event")).unwrap();
        assert!(!directory.entry_exists("debug.jsonl").unwrap());
        directory.unlink("committed").unwrap();
        assert!(log.append_app_batch(&payload("event")).is_err());
    }
    #[test]
    fn invalid_batch_never_creates_receipts_or_reserves_sequence() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut log = Log::create(root.path(), BOOT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        assert!(log.append_app_batch(b"{}").is_err());
        assert!(!root.path().join("batches").exists());
        assert_eq!(log.next_sequence, 1);
    }
    #[test]
    fn new_app_batch_can_replace_a_failed_writer_after_backoff() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut log = Log::create(root.path(), BOOT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        log.fail();
        log.retry_at = Some(Instant::now());
        assert_eq!(log.append_app_batch(&payload("event")).unwrap(), ID);
        assert_ne!(log.writer_id(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let event: Event = serde_json::from_slice(
            &fs::read(root.path().join("batches").join(ID).join("error.jsonl")).unwrap(),
        )
        .unwrap();
        assert_eq!(event.writer_id, log.writer_id());
        assert_eq!(event.sequence, 1);
    }
    #[test]
    fn foreign_segment_is_never_overwritten_or_acknowledged() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut log = Log::create(root.path(), BOOT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let directory = root.path().join("batches").join(ID);
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(
            root.path().join("batches"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(directory.join("debug.jsonl"), b"foreign").unwrap();
        fs::set_permissions(
            directory.join("debug.jsonl"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(log.append_app_batch(&payload("event")).is_err());
        assert_eq!(fs::read(directory.join("debug.jsonl")).unwrap(), b"foreign");
        assert!(!directory.join("committed").exists());
    }
}
