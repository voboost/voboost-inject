//! Bounded first-read witness, active only after the signed installer arms T2.
use super::{log, state};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use voboost_shared::secure_fs::Directory;

const ARM: &str = "initial-seeding-arm.json";
const RECEIPT: &str = "initial-seeding.json";
const KEYS: [(&str, &str); 2] = [
    ("vehicle-drive-forced-ev", "forced-ev-armed"),
    (
        "vehicle-drive-pedestrian-warning",
        "pedestrian-warning-armed",
    ),
];
static CAPTURE: OnceLock<Mutex<Capture>> = OnceLock::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Arm {
    schema_version: u32,
    transaction_id: String,
    candidate: String,
    prior_boot: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallJournal {
    schema_version: u32,
    transaction_id: String,
    manifest_sha256: String,
    phase: String,
    boot_ids: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Operation {
    key: String,
    operation: &'static str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<bool>,
    sequence: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt {
    schema_version: u32,
    boot_id: String,
    writer_id: String,
    transaction_id: String,
    candidate: String,
    initial_writer_floor: u64,
    install_state: &'static str,
    capture_state: &'static str,
    operations: Vec<Operation>,
}
struct Capture {
    root: PathBuf,
    logger: Arc<Mutex<log::Log>>,
    receipt: Receipt,
    disabled: bool,
}

fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn require_absent(root: &Path) -> io::Result<()> {
    for (source, key) in KEYS {
        if !matches!(
            state::read_unobserved(&root.join("state"), source, key),
            state::ReadOutcome::Missing
        ) {
            return Err(invalid("initial state absence unavailable"));
        }
    }
    Ok(())
}

/// Invalidate every bounded install arm before serving state after an initialization error.
pub(super) fn disarm(root: &Path) -> io::Result<()> {
    let recovery_path = root.join("recovery");
    let entries = match std::fs::read_dir(&recovery_path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let entries: Vec<_> = entries.collect::<io::Result<_>>()?;
    if entries.len() > 256 {
        return Err(invalid("recovery inventory exceeds bound"));
    }
    let recovery = Directory::open(&recovery_path)?;
    recovery.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid("recovery name invalid"));
        };
        if !hex(name, 64) {
            continue;
        }
        let transaction = recovery.open_child(name)?;
        transaction.validate_owner_mode(
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            0o700,
        )?;
        match transaction.unlink(ARM) {
            Ok(()) => transaction.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn emulator_enforcing() -> bool {
    #[cfg(target_os = "android")]
    {
        unsafe extern "C" {
            fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> i32;
        }
        let mut value = [0 as libc::c_char; 92];
        (unsafe { __system_property_get(c"ro.kernel.qemu".as_ptr(), value.as_mut_ptr()) }) == 1
            && value[0] == b'1' as libc::c_char
            && matches!(
                std::fs::read("/sys/fs/selinux/enforce").as_deref(),
                Ok(b"1" | b"1\n")
            )
            && unsafe { libc::geteuid() == 0 && libc::getegid() == 0 }
    }
    #[cfg(not(target_os = "android"))]
    {
        false
    }
}

/// Called once before the owner exposes its socket or initializes native controllers.
pub(super) fn initialize(
    root: &Path,
    boot_id: &str,
    writer: &str,
    logger: Arc<Mutex<log::Log>>,
) -> io::Result<()> {
    initialize_platform(root, boot_id, writer, logger, emulator_enforcing())
}
fn initialize_platform(
    root: &Path,
    boot_id: &str,
    writer: &str,
    logger: Arc<Mutex<log::Log>>,
    emulator: bool,
) -> io::Result<()> {
    if !emulator {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "emulator capture unavailable",
        ));
    }
    let directory = Directory::open(root)?;
    directory.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o755,
    )?;
    let descriptor_bytes = directory.read_trusted("operation.json", 4096, 0o600)?;
    let descriptor = voboost_contract::operation::OperationDescriptor::parse(&descriptor_bytes)
        .map_err(|_| invalid("install operation unavailable"))?;
    if descriptor.operation != voboost_contract::operation::Operation::Install {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no install arm"));
    }
    let recovery = directory.open_child("recovery")?;
    recovery.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    let transaction = recovery.open_child(&descriptor.transaction_id)?;
    transaction.validate_owner_mode(
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        0o700,
    )?;
    let bytes = transaction.read_trusted(ARM, 4096, 0o600)?;
    let arm: Arm = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if arm.schema_version != 1
        || !hex(&arm.transaction_id, 64)
        || !hex(&arm.candidate, 64)
        || !boot(&arm.prior_boot)
        || !boot(boot_id)
        || !hex(writer, 32)
        || descriptor.transaction_id != arm.transaction_id
    {
        return Err(invalid("initial seeding arm scope differs"));
    }
    if arm.prior_boot == boot_id {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "waiting for second boot",
        ));
    }
    if descriptor.phase != "install-reboot-second"
        || descriptor.outcome != "reboot-required"
        || descriptor.boot_id != arm.prior_boot
        || descriptor.reboot_count != 2
    {
        return Err(invalid("install reboot authority differs"));
    }
    let journal = transaction.read_trusted("install-journal.json", 65536, 0o600)?;
    let journal: InstallJournal = serde_json::from_slice(&journal).map_err(io::Error::other)?;
    if journal.schema_version != 1
        || journal.transaction_id != arm.transaction_id
        || journal.manifest_sha256 != arm.candidate
        || journal.phase != "install-reboot-second"
        || journal.boot_ids.len() != 2
        || journal.boot_ids[1] != arm.prior_boot
        || journal.boot_ids[0] == arm.prior_boot
        || !boot(&journal.boot_ids[0])
    {
        return Err(invalid("install journal scope differs"));
    }
    // O_EXCL is a durable first-owner fence. Even a later failure leaves an
    // invalid placeholder, preventing a restarted owner from claiming first read.
    let mut file = directory.create_new(std::ffi::OsStr::new(RECEIPT), 0o600)?;
    file.write_all(b"{}\n")?;
    file.sync_all()?;
    directory.sync_all()?;
    require_absent(root)?;
    let floor = {
        let guard = logger
            .lock()
            .map_err(|_| invalid("logging lock poisoned"))?;
        let (actual_boot, actual_writer, floor) = guard
            .session()
            .ok_or_else(|| invalid("logger unavailable"))?;
        if actual_boot != boot_id || actual_writer != writer {
            return Err(invalid("logger scope differs"));
        }
        floor
    };
    let receipt = Receipt {
        schema_version: 1,
        boot_id: boot_id.into(),
        writer_id: writer.into(),
        transaction_id: arm.transaction_id,
        candidate: arm.candidate,
        initial_writer_floor: floor,
        install_state: "unseeded",
        capture_state: "pending",
        operations: Vec::new(),
    };
    let mut bytes = serde_json::to_vec(&receipt).map_err(io::Error::other)?;
    bytes.push(b'\n');
    directory.write_atomic(RECEIPT, &bytes, 0o600)?;
    CAPTURE
        .set(Mutex::new(Capture {
            root: root.into(),
            logger,
            receipt,
            disabled: false,
        }))
        .map_err(|_| invalid("capture already initialized"))
}

fn selected(root: &Path, source: &str, key: &str) -> bool {
    root == Path::new("/data/voboost/state") && KEYS.contains(&(source, key))
}

pub(super) fn read(
    root: &Path,
    source: &str,
    key: &str,
    controller: bool,
    f: impl FnOnce() -> state::ReadOutcome,
) -> state::ReadOutcome {
    if !selected(root, source, key) {
        return f();
    }
    let Some(capture) = CAPTURE.get() else {
        return f();
    };
    let Ok(mut capture) = capture.lock() else {
        return f();
    };
    let outcome = f();
    if !controller {
        capture.other(source, key, false);
        return outcome;
    }
    let observation = match &outcome {
        state::ReadOutcome::Missing => Some(None),
        state::ReadOutcome::Value(Value::Bool(v)) => Some(Some(*v)),
        _ => None,
    };
    capture.observe(source, key, "read", observation);
    outcome
}

pub(super) fn write(
    root: &Path,
    storage_key: &str,
    bytes: &[u8],
    controller: bool,
    f: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let pair = KEYS
        .into_iter()
        .find(|(source, key)| state::storage_key(source, key).as_deref() == Some(storage_key));
    if root != Path::new("/data/voboost/state") || pair.is_none() {
        return f();
    }
    let Some(capture) = CAPTURE.get() else {
        return f();
    };
    let Ok(mut capture) = capture.lock() else {
        return f();
    };
    let result = f();
    let (source, key) = pair.unwrap();
    if !controller {
        capture.other(source, key, true);
        return result;
    }
    let value = serde_json::from_slice::<bool>(bytes).ok();
    let observation = if result.is_ok()
        && value.is_some()
        && matches!(state::read_unobserved(root, source, key), state::ReadOutcome::Value(Value::Bool(v)) if Some(v) == value)
    {
        Some(value)
    } else {
        None
    };
    capture.observe(source, key, "write-readback", observation);
    result
}

impl Capture {
    fn other(&mut self, source: &str, key: &str, write: bool) {
        if self.disabled || self.receipt.capture_state == "complete" {
            return;
        }
        let name = format!("{source}/{key}");
        let prior = self
            .receipt
            .operations
            .iter()
            .filter(|operation| operation.key == name)
            .count();
        // Later observers cannot invalidate an already retained first read;
        // another writer is safe only after the controller's first commit.
        if prior < if write { 2 } else { 1 } {
            self.disabled = true;
        }
    }

    fn observe(
        &mut self,
        source: &str,
        key: &str,
        operation: &'static str,
        observation: Option<Option<bool>>,
    ) {
        if self.disabled || self.receipt.capture_state == "complete" {
            return;
        }
        let name = format!("{source}/{key}");
        let prior: Vec<_> = self
            .receipt
            .operations
            .iter()
            .filter(|item| item.key == name)
            .collect();
        let valid = match (operation, observation) {
            ("read", Some(None)) => prior.is_empty(),
            ("write-readback", Some(Some(_))) => prior.len() == 1 && prior[0].operation == "read",
            _ => false,
        };
        if !valid {
            self.disabled = true;
            return;
        }
        let value = observation.flatten();
        let outcome = if value.is_some() { "value" } else { "missing" };
        let mut fields = HashMap::from([
            ("key".into(), name.clone()),
            ("operation".into(), operation.into()),
            ("outcome".into(), outcome.into()),
        ]);
        if let Some(value) = value {
            fields.insert("value".into(), value.to_string());
        }
        let sequence = self.logger.lock().ok().and_then(|mut logger| {
            logger
                .append_record(
                    log::Source::daemon(),
                    voboost_contract::runtime_log::Record {
                        level: log::Level::Info,
                        component: "initial-seeding".into(),
                        message: "initial-state-operation".into(),
                        fields,
                    },
                )
                .ok()
        });
        let Some(sequence) = sequence else {
            self.disabled = true;
            return;
        };
        self.receipt.operations.push(Operation {
            key: name,
            operation,
            outcome,
            value,
            sequence,
        });
        if self.receipt.operations.len() == 4 {
            self.receipt.capture_state = "complete";
        }
        let result = (|| -> io::Result<()> {
            let directory = Directory::open(&self.root)?;
            let mut bytes = serde_json::to_vec(&self.receipt).map_err(io::Error::other)?;
            bytes.push(b'\n');
            directory.write_atomic(RECEIPT, &bytes, 0o600)
        })();
        if result.is_err() {
            self.disabled = true;
            return;
        }
        if self.receipt.capture_state == "complete" {
            let fields = HashMap::from([
                ("transactionId".into(), self.receipt.transaction_id.clone()),
                ("candidate".into(), self.receipt.candidate.clone()),
                ("lastSequence".into(), sequence.to_string()),
            ]);
            let sealed = self.logger.lock().ok().and_then(|mut logger| {
                logger
                    .append_record(
                        log::Source::daemon(),
                        voboost_contract::runtime_log::Record {
                            level: log::Level::Info,
                            component: "initial-seeding".into(),
                            message: "initial-state-capture-sealed".into(),
                            fields,
                        },
                    )
                    .ok()
            });
            if sealed.is_none() {
                self.disabled = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const BOOT: &str = "11111111-1111-4111-8111-111111111111";
    const WRITER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fixture() -> (tempfile::TempDir, Capture) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let logs = root.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700)).unwrap();
        let logger = log::Log::create(&logs, BOOT, WRITER).unwrap();
        let capture = Capture {
            root: root.path().into(),
            logger: Arc::new(Mutex::new(logger)),
            receipt: Receipt {
                schema_version: 1,
                boot_id: BOOT.into(),
                writer_id: WRITER.into(),
                transaction_id: "b".repeat(64),
                candidate: "c".repeat(64),
                initial_writer_floor: 0,
                install_state: "unseeded",
                capture_state: "pending",
                operations: vec![],
            },
            disabled: false,
        };
        (root, capture)
    }

    #[test]
    fn complete_requires_two_first_absent_reads_and_matching_readbacks() {
        let (_root, mut capture) = fixture();
        let (a, b) = (KEYS[0], KEYS[1]);
        capture.observe(a.0, a.1, "read", Some(None));
        capture.observe(a.0, a.1, "write-readback", Some(Some(false)));
        capture.observe(b.0, b.1, "read", Some(None));
        assert_eq!(capture.receipt.capture_state, "pending");
        capture.observe(b.0, b.1, "write-readback", Some(Some(true)));
        assert_eq!(capture.receipt.capture_state, "complete");
        assert_eq!(
            capture
                .receipt
                .operations
                .iter()
                .map(|x| x.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        let saved: Value =
            serde_json::from_slice(&std::fs::read(capture.root.join(RECEIPT)).unwrap()).unwrap();
        assert_eq!(saved["captureState"], "complete");
        assert_eq!(saved["writerId"], WRITER);
        let logger = capture.logger.lock().unwrap();
        assert_eq!(logger.session().unwrap().2, 5);
        let rows = std::fs::read_to_string(
            capture
                .root
                .join("logs")
                .join(WRITER)
                .join("info-00000000000000000000.jsonl"),
        )
        .unwrap();
        let seal: Value = serde_json::from_str(rows.lines().last().unwrap()).unwrap();
        assert_eq!(seal["message"], "initial-state-capture-sealed");
        assert_eq!(seal["fields"]["lastSequence"], "4");
    }

    #[test]
    fn earlier_duplicate_value_error_or_write_never_recovers() {
        for mode in 0..4 {
            let (_root, mut capture) = fixture();
            let (source, key) = KEYS[0];
            match mode {
                0 => {
                    capture.observe(source, key, "read", Some(None));
                    capture.observe(source, key, "read", Some(None));
                }
                1 => capture.observe(source, key, "read", Some(Some(false))),
                2 => capture.observe(source, key, "read", None),
                _ => capture.observe(source, key, "write-readback", Some(Some(false))),
            }
            assert!(capture.disabled);
            capture.observe(source, key, "read", Some(None));
            assert_ne!(capture.receipt.capture_state, "complete");
        }
    }
    #[test]
    fn logging_failure_after_read_cannot_publish_complete() {
        let (_root, mut capture) = fixture();
        let (source, key) = KEYS[0];
        capture.observe(source, key, "read", Some(None));
        std::fs::remove_dir_all(capture.root.join("logs")).unwrap();
        capture.observe(source, key, "write-readback", Some(Some(false)));
        assert!(capture.disabled);
        let saved: Value =
            serde_json::from_slice(&std::fs::read(capture.root.join(RECEIPT)).unwrap()).unwrap();
        assert_eq!(saved["captureState"], "pending");
        assert_eq!(saved["operations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn other_origin_preceding_controller_never_becomes_first_read() {
        let (_root, capture) = fixture();
        assert!(CAPTURE.set(Mutex::new(capture)).is_ok());
        let path = Path::new("/data/voboost/state");
        let (source, key) = KEYS[0];
        assert!(matches!(
            read(path, source, key, false, || state::ReadOutcome::Missing),
            state::ReadOutcome::Missing
        ));
        assert!(matches!(
            read(path, source, key, true, || state::ReadOutcome::Missing),
            state::ReadOutcome::Missing
        ));
        let capture = CAPTURE.get().unwrap().lock().unwrap();
        assert!(capture.disabled);
        assert!(capture.receipt.operations.is_empty());
        assert_eq!(capture.receipt.capture_state, "pending");
    }

    #[test]
    fn seeded_or_invalid_state_never_establishes_t2_absence() {
        let (root, _capture) = fixture();
        assert!(require_absent(root.path()).is_ok());
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = state.join("vehicle-drive-forced-ev_forced-ev-armed.json");
        std::fs::write(&path, b"false\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(require_absent(root.path()).is_err());
        std::fs::write(&path, b"not-json\n").unwrap();
        assert!(require_absent(root.path()).is_err());
    }

    fn trusted_write(path: &Path, value: &impl Serialize) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn armed_fixture() -> (tempfile::TempDir, Arc<Mutex<log::Log>>) {
        let (root, capture) = fixture();
        let recovery = root.path().join("recovery");
        std::fs::create_dir(&recovery).unwrap();
        std::fs::set_permissions(&recovery, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transaction = recovery.join("b".repeat(64));
        std::fs::create_dir(&transaction).unwrap();
        std::fs::set_permissions(&transaction, std::fs::Permissions::from_mode(0o700)).unwrap();
        let prior = "22222222-2222-4222-8222-222222222222";
        trusted_write(
            &transaction.join(ARM),
            &serde_json::json!({"schemaVersion":1,
            "transactionId":"b".repeat(64),"candidate":"c".repeat(64),"priorBoot":prior}),
        );
        trusted_write(
            &transaction.join("install-journal.json"),
            &serde_json::json!({"schemaVersion":1,
            "transactionId":"b".repeat(64),"manifestSha256":"c".repeat(64),
            "phase":"install-reboot-second","bootIds":["33333333-3333-4333-8333-333333333333",prior]}),
        );
        let mut descriptor = voboost_contract::operation::OperationDescriptor::new(
            voboost_contract::operation::Operation::Install,
            "b".repeat(64),
            format!("recovery/{}/install-journal.json", "b".repeat(64)),
            prior.into(),
        )
        .unwrap();
        descriptor.phase = "install-reboot-second".into();
        descriptor.outcome = "reboot-required".into();
        descriptor.reboot_count = 2;
        trusted_write(&root.path().join("operation.json"), &descriptor);
        (root, capture.logger)
    }
    #[test]
    fn wrong_boot_writer_candidate_and_seeded_state_fail_closed() {
        let (root, logger) = armed_fixture();
        assert!(initialize(
            root.path(),
            "22222222-2222-4222-8222-222222222222",
            WRITER,
            logger.clone()
        )
        .is_err());
        assert!(initialize_platform(root.path(), BOOT, "d", logger.clone(), true).is_err());
        let journal = root
            .path()
            .join("recovery")
            .join("b".repeat(64))
            .join("install-journal.json");
        trusted_write(
            &journal,
            &serde_json::json!({"schemaVersion":1,"transactionId":"b".repeat(64),
            "manifestSha256":"d".repeat(64),"phase":"install-reboot-second",
            "bootIds":["33333333-3333-4333-8333-333333333333","22222222-2222-4222-8222-222222222222"]}),
        );
        assert!(initialize_platform(root.path(), BOOT, WRITER, logger, true).is_err());
        let (root, logger) = armed_fixture();
        let state = root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            state.join("vehicle-drive-forced-ev_forced-ev-armed.json"),
            b"false\n",
        )
        .unwrap();
        std::fs::set_permissions(
            state.join("vehicle-drive-forced-ev_forced-ev-armed.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(initialize_platform(root.path(), BOOT, WRITER, logger, true).is_err());
        let receipt: Value =
            serde_json::from_slice(&std::fs::read(root.path().join(RECEIPT)).unwrap()).unwrap();
        assert!(receipt.get("captureState").is_none());
    }

    #[test]
    fn later_diagnostic_read_is_allowed_but_an_early_foreign_write_is_not() {
        let (_root, mut capture) = fixture();
        let (source, key) = KEYS[0];
        capture.observe(source, key, "read", Some(None));
        capture.other(source, key, false);
        assert!(!capture.disabled);
        capture.other(source, key, true);
        assert!(capture.disabled);
    }

    #[test]
    fn well_formed_wrong_writer_leaves_only_invalid_placeholder() {
        let (root, logger) = armed_fixture();
        assert!(initialize_platform(root.path(), BOOT, &"d".repeat(32), logger, true).is_err());
        let receipt: Value =
            serde_json::from_slice(&std::fs::read(root.path().join(RECEIPT)).unwrap()).unwrap();
        assert!(receipt.get("captureState").is_none());
    }
    #[test]
    fn foreign_transaction_and_late_capture_cannot_publish() {
        let (root, logger) = armed_fixture();
        let arm = root.path().join("recovery").join("b".repeat(64)).join(ARM);
        trusted_write(
            &arm,
            &serde_json::json!({"schemaVersion":1,"transactionId":"e".repeat(64),
            "candidate":"c".repeat(64),"priorBoot":"22222222-2222-4222-8222-222222222222"}),
        );
        assert!(initialize_platform(root.path(), BOOT, WRITER, logger, true).is_err());
        assert!(!root.path().join(RECEIPT).exists());
        let (root, logger) = armed_fixture();
        let mut descriptor = voboost_contract::operation::OperationDescriptor::new(
            voboost_contract::operation::Operation::Install,
            "b".repeat(64),
            format!("recovery/{}/install-journal.json", "b".repeat(64)),
            "22222222-2222-4222-8222-222222222222".into(),
        )
        .unwrap();
        descriptor.phase = "install-runtime-verify".into();
        descriptor.outcome = "running".into();
        descriptor.reboot_count = 2;
        trusted_write(&root.path().join("operation.json"), &descriptor);
        assert!(initialize_platform(root.path(), BOOT, WRITER, logger, true).is_err());
        assert!(!root.path().join(RECEIPT).exists());
    }
    #[test]
    fn non_emulator_never_starts_capture() {
        let (root, logger) = armed_fixture();
        assert!(initialize_platform(root.path(), BOOT, WRITER, logger, false).is_err());
        assert!(!root.path().join(RECEIPT).exists());
    }
}
