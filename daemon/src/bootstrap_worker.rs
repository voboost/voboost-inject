//! Closed staged/commit identity; a commit is not a worker-ready receipt.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub const FRAME_SIZE: usize = 160;

pub fn new_binding(pid: i32, starttime: u64, envelope: &[u8]) -> Option<Binding> {
    use std::io::Read;
    if envelope.len() < 24 || envelope.get(..8)? != crate::bootstrap_pipe::MAGIC {
        return None;
    }
    let length = u32::from_le_bytes(envelope.get(8..12)?.try_into().ok()?) as usize;
    if length == 0 || length > crate::bootstrap_pipe::MAX_MANIFEST {
        return None;
    }
    let manifest: serde_json::Value =
        serde_json::from_slice(envelope.get(24..24 + length)?).ok()?;
    let mut binding = Binding {
        pid: u32::try_from(pid).ok()?,
        starttime,
        nonce: [0; 16],
        generation: manifest
            .get("generationId")?
            .as_str()?
            .as_bytes()
            .try_into()
            .ok()?,
        catalog: manifest
            .get("catalogSha256")?
            .as_str()?
            .as_bytes()
            .try_into()
            .ok()?,
    };
    std::fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut binding.nonce)
        .ok()?;
    binding.valid().then_some(binding)
}
#[derive(Debug, Clone)]
pub struct DetachedStaged {
    pid: u32,
    starttime: u64,
}
impl DetachedStaged {
    // The caller supplies the actually waited helper status, not a timeout.
    #[cfg(any(target_os = "android", test))]
    pub fn after_helper_exit(
        code: i32,
        status: std::process::ExitStatus,
        pid: i32,
        starttime: u64,
    ) -> Option<Self> {
        (code == -10 && status.success() && pid > 0 && starttime > 0).then_some(Self {
            pid: pid as u32,
            starttime,
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ready,
    Deferred,
    Failed,
}
struct Expected {
    binding: Binding,
    epoch: Option<u64>,
    outcome: Option<Outcome>,
    terminal: bool,
    ready: bool,
    started: std::time::Instant,
}
static EXPECTED: OnceLock<Mutex<HashMap<i32, Expected>>> = OnceLock::new();
fn expected() -> &'static Mutex<HashMap<i32, Expected>> {
    EXPECTED.get_or_init(|| Mutex::new(HashMap::new()))
}
pub fn register(binding: Binding) {
    expected().lock().unwrap().insert(
        binding.pid as i32,
        Expected {
            binding,
            epoch: None,
            outcome: None,
            terminal: false,
            ready: false,
            started: std::time::Instant::now(),
        },
    );
}
pub fn ready_allowed(pid: i32, epoch: u64) -> bool {
    expected()
        .lock()
        .unwrap()
        .get(&pid)
        .is_none_or(|value| value.epoch == Some(epoch) && value.ready)
}
pub fn has_binding(pid: i32, starttime: u64) -> bool {
    expected()
        .lock()
        .unwrap()
        .get(&pid)
        .is_some_and(|value| value.binding.starttime == starttime)
}
pub fn bind_endpoint(pid: i32, epoch: u64) {
    if let Some(value) = expected().lock().unwrap().get_mut(&pid) {
        value.epoch = Some(epoch);
    }
}
pub fn forget(pid: i32) {
    expected().lock().unwrap().remove(&pid);
}
pub fn take_outcome(pid: i32, starttime: u64) -> Option<Outcome> {
    let mut values = expected().lock().unwrap();
    let value = values.get_mut(&pid)?;
    if value.binding.starttime != starttime {
        return None;
    }
    // Preserve the existing helper observation budget without forcibly
    // unwinding managed work. The caller closes only its transport endpoints.
    if !value.terminal && value.started.elapsed() >= std::time::Duration::from_secs(20) {
        value.terminal = true;
        value.outcome = Some(Outcome::Failed);
    }
    value.outcome.take()
}
pub fn observe(record: &str, pid: i32, epoch: u64) -> bool {
    let fields: Vec<_> = record.split('|').collect();
    if fields.len() != 6 {
        return false;
    }
    let mut values = expected().lock().unwrap();
    let Some(value) = values.get_mut(&pid) else {
        return false;
    };
    if value.terminal {
        return false;
    }
    let nonce = value
        .binding
        .nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if value.epoch != Some(epoch)
        || fields[0] != nonce
        || fields[1].parse::<u32>().ok() != Some(value.binding.pid)
        || fields[2].parse::<u64>().ok() != Some(value.binding.starttime)
        || fields[3].as_bytes() != value.binding.generation
        || fields[4].as_bytes() != value.binding.catalog
    {
        return false;
    }
    value.outcome = match fields[5] {
        "ready" => Some(Outcome::Ready),
        "deferred" => Some(Outcome::Deferred),
        "failed" => Some(Outcome::Failed),
        _ => return false,
    };
    value.terminal = true;
    value.ready = value.outcome == Some(Outcome::Ready);
    true
}
static RECEIPTS: OnceLock<Mutex<HashMap<i32, DetachedStaged>>> = OnceLock::new();
#[cfg(any(target_os = "android", test))]
pub fn record_receipt(pid: i32, proof: DetachedStaged) {
    RECEIPTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
        .insert(pid, proof);
}
pub fn take_receipt(pid: i32) -> Option<DetachedStaged> {
    RECEIPTS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
        .remove(&pid)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub pid: u32,
    pub starttime: u64,
    pub nonce: [u8; 16],
    pub generation: [u8; 64],
    pub catalog: [u8; 64],
}
impl Binding {
    pub fn valid(&self) -> bool {
        self.pid > 0
            && self.pid <= i32::MAX as u32
            && self.starttime > 0
            && self.nonce.iter().any(|byte| *byte != 0)
            && self
                .generation
                .iter()
                .chain(&self.catalog)
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    }
    pub fn frame(&self, commit: bool) -> [u8; FRAME_SIZE] {
        let mut frame = [0; FRAME_SIZE];
        frame[..4].copy_from_slice(if commit { b"WKSC" } else { b"WKSS" });
        frame[4..8].copy_from_slice(&self.pid.to_le_bytes());
        frame[8..16].copy_from_slice(&self.starttime.to_le_bytes());
        frame[16..32].copy_from_slice(&self.nonce);
        frame[32..96].copy_from_slice(&self.generation);
        frame[96..].copy_from_slice(&self.catalog);
        frame
    }
    pub fn commit_after_detach(
        &self,
        proof: &DetachedStaged,
        writer_complete: bool,
        current: &Self,
    ) -> Option<[u8; FRAME_SIZE]> {
        (proof.pid == self.pid
            && proof.starttime == self.starttime
            && writer_complete
            && self.valid()
            && self == current)
            .then(|| self.frame(true))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            pid: 42,
            starttime: 123,
            nonce: [1; 16],
            generation: [b'a'; 64],
            catalog: [b'b'; 64],
        }
    }
    #[test]
    fn commit_requires_staged_detach_writer_and_exact_identity() {
        let expected = binding();
        use std::os::unix::process::ExitStatusExt;
        let exited = std::process::ExitStatus::from_raw(0);
        let proof = DetachedStaged::after_helper_exit(-10, exited, 42, 123).unwrap();
        assert!(DetachedStaged::after_helper_exit(-8, exited, 42, 123).is_none());
        assert!(DetachedStaged::after_helper_exit(
            -10,
            std::process::ExitStatus::from_raw(256),
            42,
            123
        )
        .is_none());
        assert!(expected
            .commit_after_detach(&proof, true, &expected)
            .is_some());
        assert!(expected
            .commit_after_detach(&proof, false, &expected)
            .is_none());
        for field in 0..5 {
            let mut current = expected.clone();
            match field {
                0 => current.pid += 1,
                1 => current.starttime += 1,
                2 => current.nonce[0] ^= 1,
                3 => current.generation[0] = b'c',
                _ => current.catalog[0] = b'c',
            }
            assert!(expected
                .commit_after_detach(&proof, true, &current)
                .is_none());
        }
    }
    #[test]
    fn terminal_identity_epoch_replay_and_status_barrier() {
        let mut value = binding();
        value.pid = 17301;
        register(value.clone());
        assert!(!ready_allowed(17301, 11));
        bind_endpoint(17301, 11);
        let nonce = "01".repeat(16);
        let record = format!(
            "{nonce}|17301|123|{}|{}|ready",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(!observe(&record, 17301, 12));
        assert!(!observe(&record.replace("|123|", "|124|"), 17301, 11));
        assert!(!ready_allowed(17301, 11));
        assert!(observe(&record, 17301, 11));
        assert_eq!(take_outcome(17301, 123), Some(Outcome::Ready));
        assert!(ready_allowed(17301, 11));
        assert!(!observe(&record, 17301, 11));
        forget(17301);
    }
    #[test]
    fn observation_deadline_rejects_late_ready_without_managed_unwind() {
        let mut value = binding();
        value.pid = 17302;
        register(value);
        bind_endpoint(17302, 22);
        expected().lock().unwrap().get_mut(&17302).unwrap().started -=
            std::time::Duration::from_secs(21);
        assert_eq!(take_outcome(17302, 123), Some(Outcome::Failed));
        let record = format!(
            "{}|17302|123|{}|{}|ready",
            "01".repeat(16),
            "a".repeat(64),
            "b".repeat(64)
        );
        assert!(!observe(&record, 17302, 22));
        assert!(!ready_allowed(17302, 22));
        forget(17302);
    }
    #[test]
    fn receipt_is_once_and_frame_matches_native_golden() {
        use std::os::unix::process::ExitStatusExt;
        let proof = DetachedStaged::after_helper_exit(
            -10,
            std::process::ExitStatus::from_raw(0),
            17303,
            123,
        )
        .unwrap();
        record_receipt(17303, proof);
        assert!(take_receipt(17303).is_some());
        assert!(take_receipt(17303).is_none());
        let frame = binding().frame(true);
        assert_eq!(&frame[..4], b"WKSC");
        assert_eq!(&frame[4..8], &42u32.to_le_bytes());
        assert_eq!(&frame[8..16], &123u64.to_le_bytes());
        if let Ok(path) = std::env::var("VOBOOST_WORKER_GOLDEN") {
            std::fs::write(path, frame).unwrap();
        }
    }
    #[test]
    fn envelope_authority_and_unique_attempt_binding() {
        let manifest = serde_json::to_vec(
            &serde_json::json!({"generationId":"a".repeat(64),"catalogSha256":"b".repeat(64)}),
        )
        .unwrap();
        let files = [crate::bootstrap_pipe::File {
            name: "core.dex",
            size: 1,
        }];
        let envelope = crate::bootstrap_pipe::build(&manifest, &files, |_| Ok(vec![1])).unwrap();
        let first = new_binding(42, 123, &envelope).unwrap();
        let next = new_binding(42, 123, &envelope).unwrap();
        assert_ne!(first.nonce, next.nonce);
        assert!(new_binding(42, 123, &envelope[..23]).is_none());
        assert!(new_binding(-1, 123, &envelope).is_none());
        assert!(new_binding(42, 0, &envelope).is_none());
    }
}
