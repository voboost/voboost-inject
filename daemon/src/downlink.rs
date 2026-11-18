//! Serialized, bounded, resumable downlink queues (docs/developer/contracts).
//!
//! `R` replies, ordinary `D` snapshots and correlated `A` acknowledgements
//! share one byte stream per resident.
//! A non-blocking write larger than `PIPE_BUF` may be short, so each endpoint
//! keeps the unfinished frame and its offset across daemon poll passes. Later
//! frames cannot overtake it. Queue admission is all-or-nothing and bounded;
//! a hard error poisons the endpoint so no frame is ever appended after torn
//! bytes on that stream.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

/// Bounded independently per resident endpoint.
const MAX_QUEUED_BYTES: usize = 256 * 1024;
const MAX_FLUSH_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct EndpointQueue {
    frames: VecDeque<PendingFrame>,
    remaining_bytes: usize,
    poisoned: bool,
}

struct PendingFrame {
    bytes: Vec<u8>,
    offset: usize,
}

fn endpoints() -> &'static Mutex<HashMap<i32, EndpointQueue>> {
    static ENDPOINTS: OnceLock<Mutex<HashMap<i32, EndpointQueue>>> = OnceLock::new();
    ENDPOINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Admit one complete frame and opportunistically flush it. `true` means the
/// full frame is either delivered or durably queued in daemon memory. `false`
/// means nothing from this frame was written (capacity/argument rejection), or
/// the endpoint hit a hard error and is now poisoned.
pub fn enqueue_frame(fd: i32, frame: &[u8]) -> bool {
    enqueue_frames(fd, &[frame])
}

/// Atomically admit an ordered group of complete frames. Either every frame
/// is queued in the supplied order or none is. This is used for correlated
/// Settings mutation delivery: the runtime `D` and UI `A` must not split at
/// queue admission under backpressure.
pub fn enqueue_frames(fd: i32, frames: &[&[u8]]) -> bool {
    if fd < 0 || frames.is_empty() || frames.iter().any(|frame| frame.is_empty()) {
        return false;
    }
    let Some(total) = frames
        .iter()
        .try_fold(0usize, |total, frame| total.checked_add(frame.len()))
    else {
        return false;
    };
    let mut all = endpoints()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let std::collections::hash_map::Entry::Vacant(entry) = all.entry(fd) {
        if !set_nonblocking(fd) {
            return false;
        }
        entry.insert(EndpointQueue::default());
    }
    let Some(queue) = all.get_mut(&fd) else {
        // Entry insertion above is local and synchronous, but keep this
        // capability boundary fail-closed if that invariant ever changes.
        return false;
    };
    if total > MAX_QUEUED_BYTES {
        poison(queue);
        return false;
    }
    if queue.poisoned {
        return false;
    }
    if queue
        .remaining_bytes
        .checked_add(total)
        .is_none_or(|bytes| bytes > MAX_QUEUED_BYTES)
    {
        poison(queue);
        return false;
    }
    queue.remaining_bytes += total;
    for frame in frames {
        queue.frames.push_back(PendingFrame {
            bytes: frame.to_vec(),
            offset: 0,
        });
    }
    flush_locked(fd, queue)
}

/// Resume queued writes for one endpoint. Returns false only for a hard-error
/// poisoned endpoint; EAGAIN with a retained offset remains healthy.
pub fn flush(fd: i32) -> bool {
    let mut all = endpoints()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(queue) = all.get_mut(&fd) else {
        return true;
    };
    flush_locked(fd, queue)
}

/// True only when an endpoint is healthy and has no retained frame bytes.
/// Uninstall cleanup uses this before accepting a runtime status acknowledgement.
pub fn is_drained(fd: i32) -> bool {
    let all = endpoints()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    all.get(&fd)
        .is_none_or(|queue| !queue.poisoned && queue.frames.is_empty())
}

/// Drop daemon queue state before the tracker closes an fd. Required because a
/// later pipe may reuse the same numeric descriptor.
pub fn forget_fd(fd: i32) {
    if let Ok(mut all) = endpoints().lock() {
        all.remove(&fd);
    }
}

fn set_nonblocking(fd: i32) -> bool {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
}

fn flush_locked(fd: i32, queue: &mut EndpointQueue) -> bool {
    if queue.poisoned {
        return false;
    }
    let mut written_this_call = 0usize;
    loop {
        if written_this_call >= MAX_FLUSH_BYTES {
            return true;
        }
        let Some(frame) = queue.frames.front_mut() else {
            return true;
        };
        let remaining = &frame.bytes[frame.offset..];
        let limit = remaining.len().min(MAX_FLUSH_BYTES - written_this_call);
        let count = unsafe { libc::write(fd, remaining.as_ptr().cast(), limit) };
        if count > 0 {
            let count = count as usize;
            written_this_call += count;
            frame.offset += count;
            queue.remaining_bytes -= count;
            if frame.offset == frame.bytes.len() {
                queue.frames.pop_front();
            }
            continue;
        }
        if count == 0 {
            poison(queue);
            return false;
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => return true,
            _ => {
                poison(queue);
                return false;
            }
        }
    }
}

fn poison(queue: &mut EndpointQueue) {
    queue.poisoned = true;
    queue.frames.clear();
    queue.remaining_bytes = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe() -> [i32; 2] {
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        fds
    }

    fn close(fd: i32) {
        forget_fd(fd);
        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn full_frame_is_delivered_and_readable() {
        let fds = pipe();
        let frame = b"R|41|ok|value\n";
        assert!(enqueue_frame(fds[1], frame));
        let mut buffer = [0u8; 64];
        let count = unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) };
        assert_eq!(&buffer[..count as usize], frame);
        close(fds[0]);
        close(fds[1]);
    }

    #[test]
    fn queued_frames_preserve_order_across_backpressure() {
        let fds = pipe();
        assert!(set_nonblocking(fds[1]));
        assert!(set_nonblocking(fds[0]));

        let filler = [b'x'; 4096];
        let mut filler_bytes = 0usize;
        loop {
            let count = unsafe { libc::write(fds[1], filler.as_ptr().cast(), filler.len()) };
            if count <= 0 {
                break;
            }
            filler_bytes += count as usize;
        }
        let first = [b'a'; 32 * 1024];
        let second = b"D|second\n";
        assert!(enqueue_frame(fds[1], &first));
        assert!(enqueue_frame(fds[1], second));

        let wanted = filler_bytes + first.len() + second.len();
        let mut received = Vec::with_capacity(wanted);
        let mut chunk = [0u8; 8192];
        for _ in 0..1024 {
            loop {
                let count = unsafe { libc::read(fds[0], chunk.as_mut_ptr().cast(), chunk.len()) };
                if count <= 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..count as usize]);
            }
            assert!(flush(fds[1]));
            if received.len() == wanted {
                break;
            }
        }
        assert_eq!(received.len(), wanted);
        assert!(received[..filler_bytes].iter().all(|byte| *byte == b'x'));
        assert_eq!(&received[filler_bytes..filler_bytes + first.len()], &first);
        assert_eq!(&received[filler_bytes + first.len()..], second);
        close(fds[0]);
        close(fds[1]);
    }

    #[test]
    fn drain_state_stays_false_until_backpressured_frame_is_fully_written() {
        let fds = pipe();
        assert!(set_nonblocking(fds[1]));
        assert!(set_nonblocking(fds[0]));
        let filler = [b'x'; 4096];
        loop {
            if unsafe { libc::write(fds[1], filler.as_ptr().cast(), filler.len()) } <= 0 {
                break;
            }
        }
        assert!(enqueue_frame(fds[1], &[b'd'; 32 * 1024]));
        assert!(!is_drained(fds[1]));
        let mut buffer = [0u8; 8192];
        for _ in 0..128 {
            loop {
                if unsafe { libc::read(fds[0], buffer.as_mut_ptr().cast(), buffer.len()) } <= 0 {
                    break;
                }
            }
            assert!(flush(fds[1]));
            if is_drained(fds[1]) {
                break;
            }
        }
        assert!(is_drained(fds[1]));
        close(fds[0]);
        close(fds[1]);
    }

    #[test]
    fn large_desired_frame_precedes_reply_without_byte_loss() {
        let fds = pipe();
        assert!(set_nonblocking(fds[0]));
        let mut desired = Vec::with_capacity(60 * 1024);
        desired.extend_from_slice(b"D|");
        desired.extend(std::iter::repeat_n(b'x', 56 * 1024));
        desired.push(b'\n');
        let reply = b"R|41|ok|value\n";
        assert!(enqueue_frame(fds[1], &desired));
        assert!(enqueue_frame(fds[1], reply));

        let wanted = desired.len() + reply.len();
        let mut received = Vec::with_capacity(wanted);
        let mut chunk = [0u8; 4096];
        for _ in 0..1024 {
            loop {
                let count = unsafe { libc::read(fds[0], chunk.as_mut_ptr().cast(), chunk.len()) };
                if count <= 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..count as usize]);
            }
            assert!(flush(fds[1]));
            if received.len() == wanted {
                break;
            }
        }
        assert_eq!(&received[..desired.len()], &desired);
        assert_eq!(&received[desired.len()..], reply);
        close(fds[0]);
        close(fds[1]);
    }

    #[test]
    fn capacity_rejects_whole_frame_and_hard_error_poisons_endpoint() {
        let fds = pipe();
        assert!(!enqueue_frame(fds[1], &vec![b'z'; MAX_QUEUED_BYTES + 1]));
        assert!(!enqueue_frame(fds[1], b"R|after-overflow|ok|x\n"));
        close(fds[0]);
        assert!(!enqueue_frame(fds[1], b"R|1|ok|x\n"));
        assert!(!enqueue_frame(fds[1], b"D|later\n"));
        close(fds[1]);
    }

    #[test]
    fn invalid_fd_and_empty_frame_fail_closed() {
        assert!(!enqueue_frame(-1, b"x"));
        let fds = pipe();
        assert!(!enqueue_frame(fds[1], b""));
        close(fds[0]);
        close(fds[1]);
    }

    #[test]
    fn epipe_on_closed_read_end_poisons_without_panicking() {
        // When the implant dies, the read end of the reply pipe is gone and
        // write() returns EPIPE. The daemon must poison that endpoint and
        // keep running — it must not panic or abort the poll loop.
        let mut fds = pipe();
        // Other downlink tests share the process-wide queue map and run in
        // parallel. Keep this error-path descriptor outside the allocator's
        // low-FD churn so a just-closed test descriptor cannot leave an ABA
        // observation in this assertion.
        let isolated = unsafe { libc::fcntl(fds[1], libc::F_DUPFD_CLOEXEC, 10_000) };
        assert!(isolated >= 10_000);
        close(fds[1]);
        fds[1] = isolated;
        close(fds[0]); // close the read end first → next write gets EPIPE
                       // The frame is accepted into the queue; flush_locked then hits EPIPE
                       // (or EAGAIN before the close propagates) and poisons the endpoint.
        let _ = enqueue_frame(fds[1], b"R|1|ok|x\n");
        // A second enqueue on a poisoned endpoint must return false and not panic.
        assert!(!enqueue_frame(fds[1], b"R|2|ok|y\n"));
        close(fds[1]);
    }
}
