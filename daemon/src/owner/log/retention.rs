//! Deferred metadata-only retention of resident writer segments.
use super::*;
use std::time::{Duration, SystemTime};
use voboost_contract::runtime_log::{MAX_BATCH_RECEIPTS, TIER_NAMES};

const TIER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SESSIONS: usize = 1024;
const MAX_FILES: usize = 32768;

struct Candidate {
    session: String,
    name: String,
    tier: usize,
    inode: u64,
    bytes: u64,
    modified: SystemTime,
    protected: bool,
    batch_dir: Option<&'static str>,
    retired: bool,
}

impl Log {
    pub(crate) fn maintain(&self) -> io::Result<usize> {
        let root = Directory::open(&self.root)?;
        let reserve = if root.entry_exists(qnx::BATCHES)? {
            qnx::TIER_BYTES
        } else {
            0
        };
        self.maintain_with_limit(TIER_BYTES - reserve)
    }

    fn maintain_with_limit(&self, limit: u64) -> io::Result<usize> {
        let root = Directory::open(&self.root)?;
        private(&root)?;
        let _snapshot = root.lock_transaction(Duration::from_secs(2))?;
        maintain(&root, Some(self), limit)
    }
}

pub(super) fn maintain_qnx(root: &Directory, limit: u64) -> io::Result<usize> {
    let batches = match root.open_child(qnx::BATCHES) {
        Ok(batches) => batches,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    private(&batches)?;
    let _snapshot = batches.lock_transaction(Duration::ZERO)?;
    maintain(root, None, limit)
}

fn maintain(root: &Directory, log: Option<&Log>, limit: u64) -> io::Result<usize> {
    let mut candidates = Vec::new();
    let mut totals = [0u64; 3];
    let mut sessions = Vec::new();
    if let Some(log) = log {
        for session in root.entry_names_bounded(MAX_SESSIONS + 64)? {
            if !valid_writer(&session) {
                continue;
            }
            let directory = root.open_child(&session)?;
            private(&directory)?;
            for name in directory.entry_names_bounded(MAX_FILES)? {
                let Some((tier, segment)) = segment(&name) else {
                    continue;
                };
                if candidates.len() >= MAX_FILES {
                    return Err(invalid("retention file bound exceeded"));
                }
                let (inode, bytes) = directory.metadata_trusted(&name, 0o600)?;
                if bytes > MAX_SEGMENT_BYTES {
                    return Err(invalid("retention segment exceeds bound"));
                }
                let file = directory.open_trusted_file(&name, bytes, 0o600)?;
                let modified = file.metadata()?.modified()?;
                totals[tier] = totals[tier]
                    .checked_add(bytes)
                    .ok_or_else(|| invalid("retention size overflow"))?;
                candidates.push(Candidate {
                    batch_dir: None,
                    retired: false,
                    protected: session == log.writer_id && segment == log.segments[tier],
                    session: session.clone(),
                    name,
                    tier,
                    inode,
                    bytes,
                    modified,
                });
            }
            sessions.push(session);
        }
    }
    let mut qnx_sessions = Vec::new();
    let mut qnx_cleanup = Vec::new();
    let (batch_dir, batch_limit, segment_limit, pending) = if log.is_some() {
        ("batches", MAX_BATCH_RECEIPTS, MAX_SEGMENT_BYTES, None)
    } else {
        (
            qnx::BATCHES,
            qnx::MAX_BATCHES,
            qnx::MAX_SEGMENT,
            qnx::pending_id(root)?,
        )
    };
    let candidate_limit = if log.is_some() {
        MAX_FILES
    } else {
        qnx::MAX_BATCHES * TIER_NAMES.len()
    };
    match root.open_child(batch_dir) {
        Ok(batches) => {
            private(&batches)?;
            for id in batches.entry_names_bounded(batch_limit)? {
                if !valid_writer(&id) {
                    return Err(invalid("invalid retention batch identity"));
                }
                let directory = batches.open_child(&id)?;
                private(&directory)?;
                let from_qnx = batch_dir == qnx::BATCHES;
                let pending = from_qnx && pending.as_ref() == Some(&id);
                match directory.read_trusted("committed", 32, 0o600) {
                    Ok(marker) if marker == id.as_bytes() => (),
                    Ok(_) => return Err(invalid("invalid retention batch commit")),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // A fully retired QNX batch may have lost its commit
                        // marker in an interrupted directory cleanup.
                        if from_qnx && !pending {
                            qnx_cleanup.push(id);
                        }
                        continue;
                    }
                    Err(error) => return Err(error),
                }
                if from_qnx && !pending {
                    let committed = directory.open_trusted_file("committed", 32, 0o600)?;
                    qnx_sessions.push((committed.metadata()?.modified()?, id.clone()));
                    qnx_cleanup.push(id.clone());
                }
                for (tier, prefix) in TIER_NAMES.into_iter().enumerate() {
                    let retired =
                        match directory.read_trusted(&format!("retired-{prefix}"), 7, 0o600) {
                            Ok(marker) if marker == b"retired" => true,
                            Ok(_) => return Err(invalid("invalid retention marker")),
                            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                            Err(error) => return Err(error),
                        };
                    let name = format!("{prefix}.jsonl");
                    let (inode, bytes) = match directory.metadata_trusted(&name, 0o600) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == io::ErrorKind::NotFound && retired => {
                            continue
                        }
                        Err(error) => return Err(error),
                    };
                    if candidates.len() >= candidate_limit || bytes > segment_limit {
                        return Err(invalid("retention batch bound exceeded"));
                    }
                    let modified = directory
                        .open_trusted_file(&name, bytes, 0o600)?
                        .metadata()?
                        .modified()?;
                    totals[tier] = totals[tier]
                        .checked_add(bytes)
                        .ok_or_else(|| invalid("retention size overflow"))?;
                    candidates.push(Candidate {
                        session: id.clone(),
                        name,
                        tier,
                        inode,
                        bytes,
                        modified,
                        protected: pending,
                        batch_dir: Some(batch_dir),
                        retired,
                    });
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    qnx_sessions.sort_unstable();
    let retire_count = qnx_sessions.len().saturating_sub(qnx::KEEP_BATCHES);
    let retire_qnx: std::collections::BTreeSet<_> = qnx_sessions
        .into_iter()
        .take(retire_count)
        .map(|(_, id)| id)
        .collect();
    // Validate the full bounded inventory before the first deletion.
    candidates.sort_by(|a, b| {
        (&a.modified, &a.session, &a.name).cmp(&(&b.modified, &b.session, &b.name))
    });
    let mut removed = 0;
    for item in candidates {
        let retire_batch =
            item.batch_dir == Some(qnx::BATCHES) && retire_qnx.contains(&item.session);
        if item.protected || !item.retired && !retire_batch && totals[item.tier] <= limit {
            continue;
        }
        let directory = if let Some(batch_dir) = item.batch_dir {
            root.open_child(batch_dir)?.open_child(&item.session)?
        } else {
            root.open_child(&item.session)?
        };
        private(&directory)?;
        if directory.metadata_trusted(&item.name, 0o600)? != (item.inode, item.bytes) {
            return Err(invalid("retention candidate changed"));
        }
        if item.batch_dir.is_some() && !item.retired {
            directory.write_atomic(
                &format!("retired-{}", TIER_NAMES[item.tier]),
                b"retired",
                0o600,
            )?;
        }
        directory.unlink(&item.name)?;
        directory.sync_all()?;
        totals[item.tier] -= item.bytes;
        removed += 1;
    }
    if !qnx_cleanup.is_empty() {
        let batches = root.open_child(qnx::BATCHES)?;
        for id in qnx_cleanup {
            let directory = batches.open_child(&id)?;
            let entries = directory.entry_names_bounded(8)?;
            if entries.iter().all(|entry| {
                matches!(
                    entry.as_str(),
                    "committed" | "retired-debug" | "retired-info" | "retired-error"
                )
            }) {
                // Remove the commit marker first. Any cut during this
                // cleanup is picked up as an uncommitted directory.
                if entries.iter().any(|name| name == "committed") {
                    directory.unlink("committed")?;
                    directory.sync_all()?;
                }
                for entry in entries.into_iter().filter(|name| name != "committed") {
                    directory.unlink(&entry)?;
                }
                directory.sync_all()?;
                batches.remove_child_dir(&id)?;
            }
        }
        batches.sync_all()?;
    }
    for session in sessions {
        if log.is_some_and(|log| session == log.writer_id) {
            continue;
        }
        let directory = root.open_child(&session)?;
        private(&directory)?;
        if directory.entry_names_bounded(MAX_FILES)?.is_empty() {
            root.remove_child_dir(&session)?;
        }
    }
    root.sync_all()?;
    Ok(removed)
}

fn private(directory: &Directory) -> io::Result<()> {
    directory.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )
}

fn segment(name: &str) -> Option<(usize, u64)> {
    ["debug-", "info-", "error-"]
        .iter()
        .enumerate()
        .find_map(|(tier, prefix)| {
            let number = name.strip_prefix(prefix)?.strip_suffix(".jsonl")?;
            if number.len() != 20 || !number.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            Some((tier, number.parse().ok()?))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    #[test]
    #[ignore = "cross-component fixture consumed by the root log pipeline gate"]
    fn rotated_owner_logs_feed_the_installer_archive() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let logs = root.path().join("logs");
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o700)).unwrap();
        let mut current = Log::create(&logs, BOOT, A).unwrap();
        for (level, message) in [(Level::Error, "early-error"), (Level::Info, "early-info")] {
            current
                .append(level, Source::daemon(), "test", message, BTreeMap::new())
                .unwrap();
        }
        let flood = "x".repeat(12 * 1024);
        for _ in 0..(MAX_SEGMENT_BYTES as usize / flood.len() + 2) {
            current
                .append(
                    Level::Debug,
                    Source::daemon(),
                    "test",
                    &flood,
                    BTreeMap::new(),
                )
                .unwrap();
        }
        current
            .append(
                Level::Debug,
                Source::daemon(),
                "test",
                "noise",
                BTreeMap::new(),
            )
            .unwrap();
        assert!(
            current.segments[0] > 0,
            "actual bytes must rotate the debug stream"
        );
        // Exercise the same retention algorithm with a bounded host-test budget.
        assert_eq!(current.maintain_with_limit(MAX_SEGMENT_BYTES).unwrap(), 1);
        assert!(!logs
            .join(A)
            .join("debug-00000000000000000000.jsonl")
            .exists());
        for tier in ["info", "error"] {
            assert!(logs
                .join(A)
                .join(format!("{tier}-00000000000000000000.jsonl"))
                .exists());
        }
        let mut stream = Vec::new();
        crate::logs::write(root.path(), &mut stream).unwrap();
        let path = std::path::PathBuf::from(
            std::env::var_os("VOBOOST_TEST_LOG_EXPORT").expect("root log export path required"),
        );
        assert!(path.is_absolute());
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        output.write_all(&stream).unwrap();
        output.sync_all().unwrap();
    }

    #[test]
    fn committed_batch_uses_same_tier_budget_and_replay_does_not_resurrect_it() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut current = Log::create(root.path(), BOOT, B).unwrap();
        let id = "cccccccccccccccccccccccccccccccc";
        let payload = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"batchId":id,"records":[{"level":"error","component":"app","message":"x".repeat(1024),"fields":{}}]})).unwrap();
        current.append_app_batch(&payload).unwrap();
        current
            .append(
                Level::Debug,
                Source::daemon(),
                "test",
                "active",
                BTreeMap::new(),
            )
            .unwrap();
        let active = root.path().join(B).join("debug-00000000000000000000.jsonl");
        let limit = fs::metadata(active).unwrap().len();
        assert_eq!(current.maintain_with_limit(limit).unwrap(), 3);
        let batch = root.path().join("batches").join(id);
        for tier in TIER_NAMES {
            assert!(!batch.join(format!("{tier}.jsonl")).exists());
            assert_eq!(
                fs::read(batch.join(format!("retired-{tier}"))).unwrap(),
                b"retired"
            );
        }
        current.append_app_batch(&payload).unwrap();
        assert!(!batch.join("debug.jsonl").exists());
    }
    #[test]
    fn debug_pressure_preserves_rare_error_and_active_files() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut old = Log::create(root.path(), BOOT, A).unwrap();
        old.append(
            Level::Error,
            Source::daemon(),
            "test",
            "event",
            BTreeMap::new(),
        )
        .unwrap();
        drop(old);
        let mut current = Log::create(root.path(), BOOT, B).unwrap();
        current
            .append(
                Level::Debug,
                Source::daemon(),
                "test",
                "event",
                BTreeMap::new(),
            )
            .unwrap();
        let active = root.path().join(B).join("debug-00000000000000000000.jsonl");
        let before = fs::read(&active).unwrap();
        assert_eq!(
            current
                .maintain_with_limit(before.len() as u64 + 1)
                .unwrap(),
            1
        );
        assert!(!root
            .path()
            .join(A)
            .join("debug-00000000000000000000.jsonl")
            .exists());
        for tier in ["info", "error"] {
            assert!(root
                .path()
                .join(A)
                .join(format!("{tier}-00000000000000000000.jsonl"))
                .exists());
        }
        assert_eq!(fs::read(&active).unwrap(), before);
        current
            .append(
                Level::Debug,
                Source::daemon(),
                "test",
                "after retention",
                BTreeMap::new(),
            )
            .unwrap();
    }
    #[test]
    fn invalid_candidate_prevents_deletion_of_any_segment() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut old = Log::create(root.path(), BOOT, A).unwrap();
        old.append(
            Level::Debug,
            Source::daemon(),
            "test",
            "event",
            BTreeMap::new(),
        )
        .unwrap();
        let directory = root.path().join(A);
        std::os::unix::fs::symlink(
            directory.join("debug-00000000000000000000.jsonl"),
            directory.join("error-00000000000000000000.jsonl"),
        )
        .unwrap();
        let current = Log::create(root.path(), BOOT, B).unwrap();
        assert!(current.maintain_with_limit(0).is_err());
        assert!(directory.join("debug-00000000000000000000.jsonl").exists());
    }
}
