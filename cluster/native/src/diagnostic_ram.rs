//! Bounded per-boot handoff shared by the daemon and the loaded OEM owners.
use crate::{fs::Fd, Result};
use alloc::{ffi::CString, format, string::String, vec::Vec};
use core::{
    cell::UnsafeCell,
    ffi::CStr,
    mem::size_of,
    ptr,
    sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering},
};
use voboost_contract_core::cluster_log::{
    Ack, Batch, Event, Level, Response, MAX_COMPONENT_BYTES, MAX_EVENTS, MAX_FIELDS,
    MAX_FIELD_KEY_BYTES, MAX_FIELD_VALUE_BYTES, MAX_MESSAGE_BYTES,
};

const CAPACITY: usize = 64;
const MAP_BYTES: usize = 128 * 1024;
const _: () = assert!(size_of::<Mailbox>() <= MAP_BYTES);
const VERSION: u32 = 1;
const CLAIMED: u32 = 1 << 31;
static ACTIVE: AtomicPtr<Mailbox> = AtomicPtr::new(ptr::null_mut());

#[derive(Clone, Copy)]
#[repr(C)]
struct Text<const N: usize> {
    length: u16,
    bytes: [u8; N],
}

impl<const N: usize> Text<N> {
    fn new(bytes: &[u8]) -> Self {
        let mut length = bytes.len().min(N);
        let mut text = Self {
            length: 0,
            bytes: [0; N],
        };
        if let Err(error) = core::str::from_utf8(&bytes[..length]) {
            // Preserve complete UTF-8 at the truncation boundary. Malformed
            // input from the C ABI is repaired when the daemon reads it.
            if error.error_len().is_none() {
                length = error.valid_up_to();
            }
        }
        text.bytes[..length].copy_from_slice(&bytes[..length]);
        text.length = length as u16;
        text
    }

    fn log_text(&self) -> String {
        let mut escaped = String::new();
        for ch in self.string().chars() {
            if ch.is_control() && !matches!(ch, '\n' | '\t') {
                let value = format!("\\u{:04x}", ch as u32);
                if escaped.len() + value.len() > N {
                    break;
                }
                escaped.push_str(&value);
            } else {
                if escaped.len() + ch.len_utf8() > N {
                    break;
                }
                escaped.push(ch);
            }
        }
        escaped
    }

    fn string(&self) -> String {
        let mut value =
            String::from_utf8_lossy(&self.bytes[..usize::from(self.length).min(N)]).into_owned();
        let mut end = value.len().min(N);
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
        value
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Field {
    key: Text<MAX_FIELD_KEY_BYTES>,
    value: Text<MAX_FIELD_VALUE_BYTES>,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Record {
    seconds: i64,
    millis: i64,
    pid: u32,
    preload: u8,
    component: Text<MAX_COMPONENT_BYTES>,
    message: Text<MAX_MESSAGE_BYTES>,
    fields: [Field; MAX_FIELDS],
}

impl Record {
    fn event(&self, priority: u32) -> Event {
        Event {
            timestamp: crate::diagnostic_log::timestamp(self.seconds, self.millis),
            level: match priority {
                1 => Level::Debug,
                2 => Level::Info,
                _ => Level::Error,
            },
            source: format!(
                "{}:{}",
                if self.preload != 0 {
                    "preload"
                } else {
                    "native"
                },
                self.pid
            ),
            component: self.component.string(),
            message: self.message.log_text(),
            fields: self
                .fields
                .iter()
                .filter(|field| field.key.length != 0)
                .map(|field| (field.key.string(), field.value.log_text()))
                .collect(),
        }
    }
}

#[repr(C)]
struct Slot {
    // The upper half is the publication ticket. The lower half is zero for
    // vacant, 1..=3 for published priority, 4..=6 for awaiting ACK, 7 for a
    // discarded unconfirmed record, or CLAIMED | pid while copying.
    state: AtomicU64,
    record: UnsafeCell<Record>,
}

// A producer or the consumer accesses the record only with an exclusive CAS
// claim. The releasing store publishes the complete copy to other processes.
unsafe impl Sync for Slot {}

#[repr(C)]
struct Mailbox {
    version: AtomicU32,
    ticket: AtomicU32,
    dropped: AtomicU64,
    slots: [Slot; CAPACITY],
    // Appended to the version-one layout's zero-filled reserved mapping so
    // existing producers keep the same field offsets. Only the daemon writes it.
    confirmed_dropped: AtomicU64,
}

impl Mailbox {
    fn push(&self, priority: u32, record: &Record) {
        let ticket = self.ticket.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let claim = (u64::from(ticket) << 32) | u64::from(CLAIMED | record.pid);
        let mut victims = [(0, 0, 0, 0); CAPACITY];
        let mut count = 0;
        // Vary the initial slot so simultaneous publishers rarely collide.
        for offset in 0..CAPACITY {
            let index = (ticket as usize % CAPACITY + offset) % CAPACITY;
            let slot = &self.slots[index];
            let state = slot.state.load(Ordering::Acquire);
            if state == 0 {
                if Self::publish(slot, state, claim, priority, record) {
                    return;
                }
                continue;
            }
            let rank = state as u32;
            if rank <= priority {
                let age = ticket.wrapping_sub((state >> 32) as u32) as i32;
                victims[count] = (rank, age, index, state);
                count += 1;
            }
        }
        // Try every eligible candidate from the snapshot. A producer that
        // loses a CAS on the oldest debug can still replace the next debug.
        // The stack array and bounded scan keep this off the allocator.
        victims[..count].sort_unstable_by_key(|&(rank, age, _, _)| (rank, core::cmp::Reverse(age)));
        for &(_, _, index, state) in &victims[..count] {
            if Self::publish(&self.slots[index], state, claim, priority, record) {
                break;
            }
        }
        // Either the incoming record or the overwritten record was lost.
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn publish(slot: &Slot, state: u64, claim: u64, priority: u32, record: &Record) -> bool {
        if slot
            .state
            .compare_exchange(state, claim, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        unsafe { slot.record.get().write(*record) };
        slot.state.store(
            (claim & !u64::from(u32::MAX)) | u64::from(priority),
            Ordering::Release,
        );
        true
    }

    fn recover_pending(&self) {
        for slot in &self.slots {
            let state = slot.state.load(Ordering::Acquire);
            if (4..=6).contains(&(state as u32)) {
                // Keep the loss marker until a peer ACKs its dropped count.
                // Clearing it and incrementing a separate counter has a crash gap.
                let _ = slot.state.compare_exchange(
                    state,
                    (state & !u64::from(u32::MAX)) | 7,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }
    }

    fn acknowledge(&self, dropped: u64) {
        self.confirmed_dropped.store(dropped, Ordering::Relaxed);
        for slot in &self.slots {
            let state = slot.state.load(Ordering::Acquire);
            if (4..=7).contains(&(state as u32)) {
                let _ = slot
                    .state
                    .compare_exchange(state, 0, Ordering::AcqRel, Ordering::Relaxed);
            }
        }
    }

    fn drain(&self) -> (Vec<Event>, u64, u64) {
        let pid = unsafe { libc::getpid() } as u32;
        let newest = self.ticket.load(Ordering::Relaxed);
        let mut ready = Vec::with_capacity(CAPACITY);
        for slot in &self.slots {
            let state = slot.state.load(Ordering::Acquire);
            let rank = state as u32;
            if (1..=3).contains(&rank) {
                ready.push((
                    newest.wrapping_sub((state >> 32) as u32) as i32,
                    slot,
                    state,
                ));
            } else if rank & CLAIMED != 0
                && rank != (CLAIMED | pid)
                && unsafe { libc::kill((rank & !CLAIMED) as libc::pid_t, 0) } == -1
                && crate::fs::errno() == libc::ESRCH
            {
                // A killed publisher may leave a partial copy. Never read it.
                let _ = slot.state.compare_exchange(
                    state,
                    (state & !u64::from(u32::MAX)) | 7,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }
        ready.sort_unstable_by_key(|&(age, _, _)| core::cmp::Reverse(age));
        let mut events = Vec::with_capacity(MAX_EVENTS);
        for (_, slot, state) in ready {
            let claim = (state & !u64::from(u32::MAX)) | u64::from(CLAIMED | pid);
            if slot
                .state
                .compare_exchange(state, claim, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                continue;
            }
            let record = unsafe { *slot.record.get() };
            let event = record.event(state as u32);
            if event.validate().is_ok() {
                events.push(event);
                slot.state.store(state + 3, Ordering::Release);
            } else {
                slot.state
                    .store((state & !u64::from(u32::MAX)) | 7, Ordering::Release);
            }
            if events.len() == MAX_EVENTS {
                break;
            }
        }
        let total_dropped = self.dropped.load(Ordering::Relaxed);
        let lost = self
            .slots
            .iter()
            .filter(|slot| slot.state.load(Ordering::Acquire) as u32 == 7)
            .count() as u64;
        let dropped = total_dropped
            .saturating_sub(self.confirmed_dropped.load(Ordering::Relaxed))
            .saturating_add(lost);
        (
            events,
            dropped.min(voboost_contract_core::MAX_SAFE_INTEGER),
            total_dropped,
        )
    }
}

fn name(pair: &str) -> Result<CString> {
    if !voboost_contract_core::digest(pair) {
        return Err("invalid diagnostic RAM pairing".into());
    }
    CString::new(format!("/voboost-log-{pair}")).map_err(|_| "invalid diagnostic RAM name".into())
}

fn map(name: &CStr, owner: u32, prepare: bool) -> Result<*mut Mailbox> {
    let fd = Fd(unsafe {
        if prepare {
            let created = libc::shm_open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            );
            if created >= 0 {
                #[cfg(target_os = "nto")]
                if libc::fchmod(created, 0o600) != 0 {
                    let _fd = Fd(created);
                    return Err("diagnostic RAM mode initialization failed".into());
                }
                created
            } else if crate::fs::errno() == libc::EEXIST {
                libc::shm_open(name.as_ptr(), libc::O_RDWR, 0)
            } else {
                return Err("diagnostic RAM creation failed".into());
            }
        } else {
            libc::shm_open(name.as_ptr(), libc::O_RDWR, 0)
        }
    });
    let stat = crate::fs::stat(fd.0)?;
    if stat.st_uid as u32 != owner || stat.st_mode & 0o777 != 0o600 {
        return Err("diagnostic RAM ownership or mode rejected".into());
    }
    if prepare && stat.st_size == 0 {
        // Preparation is serialized by the protected operation lock. A
        // process interrupted immediately after creation may leave size zero.
        if unsafe { libc::ftruncate(fd.0, MAP_BYTES as libc::off_t) } != 0 {
            return Err("diagnostic RAM initialization failed".into());
        }
    } else if stat.st_size != MAP_BYTES as libc::off_t {
        return Err("diagnostic RAM size rejected".into());
    }
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            MAP_BYTES,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.0,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err("diagnostic RAM mapping failed".into());
    }
    let mailbox = mapping.cast::<Mailbox>();
    // A new POSIX shared-memory object is zero-filled by ftruncate. Every
    // member of Mailbox accepts zero, and the version publishes initialization.
    let version = unsafe { &(*mailbox).version };
    match version.load(Ordering::Acquire) {
        VERSION => {}
        0 if prepare => version.store(VERSION, Ordering::Release),
        _ => {
            unmap(mailbox);
            return Err("diagnostic RAM layout version rejected".into());
        }
    }
    Ok(mailbox)
}

fn unmap(mailbox: *mut Mailbox) {
    unsafe { libc::munmap(mailbox.cast(), MAP_BYTES) };
}

pub(crate) fn prepare(pair: &str, owner: u32) -> Result<()> {
    unmap(map(&name(pair)?, owner, true)?);
    Ok(())
}

pub(crate) fn attach(pair: &str, owner: u32) -> Result<()> {
    let mailbox = map(&name(pair)?, owner, false)?;
    if ACTIVE
        .compare_exchange(
            ptr::null_mut(),
            mailbox,
            Ordering::Release,
            Ordering::Relaxed,
        )
        .is_err()
    {
        unmap(mailbox);
    }
    Ok(())
}

pub(crate) fn absent(pair: &str) -> Result<bool> {
    let name = name(pair)?;
    let fd = Fd(unsafe { libc::shm_open(name.as_ptr(), libc::O_RDONLY, 0) });
    if fd.0 >= 0 {
        Ok(false)
    } else if crate::fs::errno() == libc::ENOENT {
        Ok(true)
    } else {
        Err("diagnostic RAM absence not proven".into())
    }
}

pub(crate) fn emit(
    preload: bool,
    level: &str,
    component: &str,
    message: &[u8],
    fields: &[(&str, &str)],
) {
    let Some(mailbox) = (unsafe { ACTIVE.load(Ordering::Acquire).as_ref() }) else {
        return;
    };
    let (seconds, millis) = crate::diagnostic_log::realtime();
    let mut bounded_fields = [Field {
        key: Text::new(&[]),
        value: Text::new(&[]),
    }; MAX_FIELDS];
    for (out, &(key, value)) in bounded_fields.iter_mut().zip(fields) {
        *out = Field {
            key: Text::new(key.as_bytes()),
            value: Text::new(value.as_bytes()),
        };
    }
    mailbox.push(
        match level {
            "debug" => 1,
            "info" => 2,
            _ => 3,
        },
        &Record {
            seconds,
            millis,
            pid: unsafe { libc::getpid() } as u32,
            preload: u8::from(preload),
            component: Text::new(component.as_bytes()),
            message: Text::new(message),
            fields: bounded_fields,
        },
    );
}

#[derive(Default)]
pub(crate) struct Delivery {
    sequence: u64,
    pending: Option<(Batch, Vec<u8>, u64)>,
}

impl Delivery {
    pub(crate) fn exchange(
        &mut self,
        session: &str,
        ack: Option<&Ack>,
        stream: &crate::tls::Stream,
    ) -> Result<()> {
        let deadline = crate::engine::monotonic_ms()
            .ok_or("diagnostic monotonic clock unavailable")?
            .checked_add(100)
            .ok_or("diagnostic deadline overflow")?;
        let mailbox = unsafe { ACTIVE.load(Ordering::Acquire).as_ref() }
            .ok_or("diagnostic RAM unavailable")?;
        match self.reply(session, ack, mailbox)? {
            Some(batch) => stream.write_frame_before(batch, deadline),
            None => stream.write_frame_before(&Response::Idle.encode()?, deadline),
        }
    }

    fn reply(
        &mut self,
        session: &str,
        ack: Option<&Ack>,
        mailbox: &Mailbox,
    ) -> Result<Option<&[u8]>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|(batch, _, _)| ack.is_some_and(|ack| ack.matches(batch)))
        {
            mailbox.acknowledge(self.pending.as_ref().expect("matching pending batch").2);
            self.pending = None;
        }
        if self.pending.is_none() {
            mailbox.recover_pending();
            let sequence = self
                .sequence
                .checked_add(1)
                .filter(|sequence| *sequence <= voboost_contract_core::MAX_SAFE_INTEGER)
                .ok_or("diagnostic sequence overflow")?;
            let (events, dropped, total_dropped) = mailbox.drain();
            if events.is_empty() && dropped == 0 {
                return Ok(None);
            }
            let batch = Batch {
                source_session: session.into(),
                sequence,
                dropped,
                events,
            };
            let bytes = Response::Batch(batch.clone()).encode()?;
            self.sequence = sequence;
            self.pending = Some((batch, bytes, total_dropped));
        }
        Ok(self.pending.as_ref().map(|(_, bytes, _)| bytes.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Shared {
        name: CString,
        mapping: *mut Mailbox,
    }

    impl Shared {
        fn new() -> Self {
            // Darwin's POSIX shared memory names have a shorter limit than QNX.
            let name =
                CString::new(format!("/vbc-log-{}", &crate::nonce().unwrap()[..16])).unwrap();
            let mapping = map(&name, crate::fs::uid().unwrap(), true).unwrap_or_else(|error| {
                unsafe { libc::shm_unlink(name.as_ptr()) };
                panic!("{error}");
            });
            Self { name, mapping }
        }

        fn mailbox(&self) -> &Mailbox {
            unsafe { &*self.mapping }
        }
    }

    impl Drop for Shared {
        fn drop(&mut self) {
            unmap(self.mapping);
            unsafe { libc::shm_unlink(self.name.as_ptr()) };
        }
    }

    fn record(message: &str) -> Record {
        Record {
            seconds: 1709251200,
            millis: 123,
            pid: unsafe { libc::getpid() } as u32,
            preload: 0,
            component: Text::new(b"fixture"),
            message: Text::new(message.as_bytes()),
            fields: [Field {
                key: Text::new(b"reason"),
                value: Text::new(b"test"),
            }; MAX_FIELDS],
        }
    }

    #[test]
    fn preload_can_publish_before_daemon_and_controls_are_safe() {
        const CHILD: &str = "VOBOOST_QNX_TEST_LOG_MAILBOX";
        if let Ok(name) = std::env::var(CHILD) {
            let name = CString::new(name).unwrap();
            let mapping = map(&name, crate::fs::uid().unwrap(), false).unwrap();
            ACTIVE.store(mapping, Ordering::Release);
            let bytes = b"bad:\x01\xff\n";
            let long = format!("{}\u{20ac}", "x".repeat(MAX_MESSAGE_BYTES - 1));
            unsafe {
                crate::diagnostic_log::vbc_preload_diagnostic(1, bytes.as_ptr(), bytes.len());
                crate::diagnostic_log::vbc_preload_diagnostic(0, long.as_ptr(), long.len());
                crate::diagnostic_log::vbc_preload_diagnostic(1, ptr::null(), usize::MAX);
            }
            return;
        }

        let shared = Shared::new();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "diagnostic_ram::tests::preload_can_publish_before_daemon_and_controls_are_safe",
                "--nocapture",
            ])
            .env(CHILD, shared.name.to_str().unwrap())
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(child.wait_with_output().unwrap().status.success());
        let (events, dropped, _) = shared.mailbox().drain();
        assert_eq!(events.len(), 2);
        assert_eq!(dropped, 0);
        assert_eq!(events[0].source, format!("preload:{pid}"));
        assert_eq!(events[0].component, "preload");
        assert_eq!(events[0].level, Level::Error);
        assert_eq!(events[0].message, "bad:\\u0001\u{fffd}\n");
        assert_eq!(events[1].level, Level::Debug);
        assert_eq!(events[1].message, "x".repeat(MAX_MESSAGE_BYTES - 1));
    }

    #[test]
    fn interrupted_initialization_can_be_prepared_again() {
        let shared = Shared::new();
        shared.mailbox().version.store(0, Ordering::Release);
        let owner = crate::fs::uid().unwrap();
        assert!(map(&shared.name, owner, false).is_err());
        unmap(map(&shared.name, owner, true).unwrap());
        unmap(map(&shared.name, owner, false).unwrap());
    }

    #[test]
    fn eviction_drops_oldest_debug_then_oldest_info_and_accounts_for_losses() {
        let shared = Shared::new();
        let mailbox = shared.mailbox();
        mailbox.push(1, &record("debug-old"));
        mailbox.push(1, &record("debug-new"));
        mailbox.push(2, &record("info-old"));
        mailbox.push(2, &record("info-new"));
        for _ in 4..CAPACITY {
            mailbox.push(3, &record("existing-error"));
        }
        mailbox.push(3, &record("new-error-1"));
        mailbox.push(3, &record("new-error-2"));
        mailbox.push(3, &record("new-error-3"));
        mailbox.push(1, &record("discarded-debug"));

        let mut messages = Vec::new();
        let mut total_dropped = 0;
        for _ in 0..=CAPACITY / MAX_EVENTS {
            let (events, dropped, total) = mailbox.drain();
            messages.extend(events.into_iter().map(|event| event.message));
            total_dropped += dropped;
            mailbox.acknowledge(total);
        }
        assert_eq!(total_dropped, 4);
        assert_eq!(messages.len(), CAPACITY);
        assert_eq!(messages[0], "info-new");
        assert_eq!(
            messages[CAPACITY - 3..],
            ["new-error-1", "new-error-2", "new-error-3"]
        );
    }

    #[test]
    fn concurrent_errors_replace_debug_in_a_full_mailbox() {
        const WRITERS: usize = 16;
        let shared = Shared::new();
        let mailbox = shared.mailbox();
        for _ in 0..CAPACITY {
            mailbox.push(1, &record("debug"));
        }
        let barrier = std::sync::Barrier::new(WRITERS);
        std::thread::scope(|threads| {
            for _ in 0..WRITERS {
                threads.spawn(|| {
                    barrier.wait();
                    mailbox.push(3, &record("error"));
                });
            }
        });
        let mut errors = 0;
        let mut total_dropped = 0;
        for _ in 0..=CAPACITY / MAX_EVENTS {
            let (events, dropped, total) = mailbox.drain();
            errors += events
                .iter()
                .filter(|event| event.level == Level::Error)
                .count();
            total_dropped += dropped;
            mailbox.acknowledge(total);
        }
        assert_eq!(errors, WRITERS);
        assert_eq!(total_dropped, WRITERS as u64);
    }

    #[test]
    fn daemon_restart_accounts_for_unacknowledged_events_and_loss() {
        let shared = Shared::new();
        let mailbox = shared.mailbox();
        mailbox.push(3, &record("unacknowledged"));
        mailbox.dropped.store(2, Ordering::Relaxed);
        let mut first = Delivery::default();
        let bytes = first
            .reply("session-one", None, mailbox)
            .unwrap()
            .unwrap()
            .to_vec();
        assert!(
            matches!(Response::parse(&bytes).unwrap(), Response::Batch(Batch { dropped: 2, events, .. }) if events.len() == 1)
        );
        drop(first);
        let mut restarted = Delivery::default();
        let bytes = restarted
            .reply("session-two", None, mailbox)
            .unwrap()
            .unwrap();
        assert!(
            matches!(Response::parse(bytes).unwrap(), Response::Batch(Batch { sequence: 1, dropped: 3, events, .. }) if events.is_empty())
        );
    }

    #[test]
    fn unconfirmed_losses_survive_repeated_restarts_and_clear_only_after_ack() {
        let shared = Shared::new();
        let mailbox = shared.mailbox();
        mailbox.push(3, &record("pending"));
        Delivery::default().reply("first", None, mailbox).unwrap();
        for session in ["second", "third"] {
            let mut delivery = Delivery::default();
            let bytes = delivery.reply(session, None, mailbox).unwrap().unwrap();
            assert!(
                matches!(Response::parse(bytes).unwrap(), Response::Batch(Batch { dropped: 1, events, .. }) if events.is_empty())
            );
        }
        let mut delivery = Delivery::default();
        delivery.reply("fourth", None, mailbox).unwrap();
        let ack = Ack {
            source_session: "fourth".into(),
            sequence: 1,
        };
        assert!(delivery
            .reply("fourth", Some(&ack), mailbox)
            .unwrap()
            .is_none());
        let mut restarted = Delivery::default();
        assert!(restarted.reply("fifth", None, mailbox).unwrap().is_none());
        mailbox.push(3, &record("next"));
        let bytes = restarted.reply("fifth", None, mailbox).unwrap().unwrap();
        assert!(
            matches!(Response::parse(bytes).unwrap(), Response::Batch(Batch { dropped: 0, events, .. }) if events[0].message == "next")
        );
    }

    #[test]
    fn ack_cannot_erase_overflow_after_its_batch_was_prepared() {
        let shared = Shared::new();
        let mailbox = shared.mailbox();
        for _ in 0..CAPACITY {
            mailbox.push(1, &record("debug"));
        }
        let mut delivery = Delivery::default();
        delivery.reply("source", None, mailbox).unwrap();
        for _ in 0..12 {
            mailbox.push(3, &record("error"));
        }
        let ack = Ack {
            source_session: "source".into(),
            sequence: 1,
        };
        let bytes = delivery
            .reply("source", Some(&ack), mailbox)
            .unwrap()
            .unwrap();
        assert!(matches!(
            Response::parse(bytes).unwrap(),
            Response::Batch(Batch {
                sequence: 2,
                dropped: 12,
                ..
            })
        ));
    }

    #[test]
    fn a_lost_or_stale_ack_repeats_identical_bytes_and_an_exact_ack_advances() {
        let shared = Shared::new();
        let mailbox = shared.mailbox();
        mailbox.push(3, &record("first"));
        let mut delivery = Delivery::default();
        let first = delivery
            .reply("session-one", None, mailbox)
            .unwrap()
            .unwrap()
            .to_vec();
        assert!(matches!(Response::parse(&first).unwrap(),
            Response::Batch(Batch { sequence: 1, dropped: 0, events, .. })
                if events[0].message == "first" && events[0].fields["reason"] == "test"
        ));
        mailbox.push(2, &record("second"));
        for ack in [
            None,
            Some(Ack {
                source_session: "stale-session".into(),
                sequence: 1,
            }),
        ] {
            assert_eq!(
                delivery
                    .reply("session-one", ack.as_ref(), mailbox)
                    .unwrap()
                    .unwrap(),
                first
            );
        }
        let mut ack = Ack {
            source_session: "session-one".into(),
            sequence: 1,
        };
        let second = delivery
            .reply("session-one", Some(&ack), mailbox)
            .unwrap()
            .unwrap();
        assert!(
            matches!(Response::parse(second).unwrap(), Response::Batch(Batch { sequence: 2, events, .. }) if events[0].message == "second")
        );
        ack.sequence = 2;
        assert!(delivery
            .reply("session-one", Some(&ack), mailbox)
            .unwrap()
            .is_none());

        let mut restarted = Delivery::default();
        mailbox.dropped.store(3, Ordering::Relaxed);
        let bytes = restarted
            .reply("session-two", Some(&ack), mailbox)
            .unwrap()
            .unwrap();
        assert!(
            matches!(Response::parse(bytes).unwrap(), Response::Batch(Batch { source_session, sequence: 1, dropped: 3, events })
            if source_session == "session-two" && events.is_empty())
        );
    }
}
