//! Bounded ingress on the existing listener. A peer that stalls before its
//! first authenticated frame cannot occupy the authority/reconciliation loop.
use crate::{controller::Spin, fs::Fd, tls, Result};
use alloc::{boxed::Box, collections::VecDeque, string::String, sync::Arc, vec::Vec};
use core::{
    ffi::c_void,
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
use voboost_contract_core::cluster_log::Request;

const MAX_CONNECTIONS: usize = 4;
const INGRESS_TIMEOUT_MS: u64 = 2_000;
const RECONCILE_INTERVAL_MS: u64 = 500;
const WORKER_CHECK_MS: u64 = 25;
type Connection = (tls::Stream, Vec<u8>);

pub(crate) struct Ingress {
    state: Arc<State>,
}

struct State {
    tls: Arc<tls::Server>,
    source_session: String,
    diagnostics: Spin<crate::diagnostic_ram::Delivery>,
    ready: Spin<VecDeque<Result<Connection>>>,
    connections: AtomicUsize,
}

impl Ingress {
    pub(crate) fn new(tls: Arc<tls::Server>, source_session: String) -> Self {
        Self {
            state: Arc::new(State {
                tls,
                source_session,
                diagnostics: Spin::new(crate::diagnostic_ram::Delivery::default()),
                ready: Spin::new(VecDeque::with_capacity(MAX_CONNECTIONS)),
                connections: AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) fn next(&self, listener: i32) -> Option<Result<Connection>> {
        let deadline = crate::engine::monotonic_ms()?.checked_add(RECONCILE_INTERVAL_MS)?;
        loop {
            if let Some(Some(ready)) = self.state.ready.take(VecDeque::pop_front) {
                self.state.connections.fetch_sub(1, Ordering::AcqRel);
                return Some(ready);
            }
            let remaining = deadline.checked_sub(crate::engine::monotonic_ms()?)?;
            if remaining == 0 {
                return None;
            }
            let connections = self.state.connections.load(Ordering::Acquire);
            let mut ready = libc::pollfd {
                fd: if connections < MAX_CONNECTIONS {
                    listener
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            };
            let wait = if connections == 0 {
                remaining
            } else {
                remaining.min(WORKER_CHECK_MS)
            };
            if unsafe { libc::poll(&mut ready, 1, wait as i32) } > 0
                && ready.revents & libc::POLLIN != 0
            {
                if let Err(reason) = crate::net::accept(listener).and_then(|fd| self.start(fd)) {
                    return Some(Err(reason));
                }
            }
        }
    }

    fn start(&self, fd: Fd) -> Result<()> {
        let deadline = crate::engine::monotonic_ms()
            .and_then(|now| now.checked_add(INGRESS_TIMEOUT_MS))
            .ok_or("TLS ingress clock unavailable")?;
        self.state.connections.fetch_add(1, Ordering::AcqRel);
        let job = Box::into_raw(Box::new(Job {
            state: self.state.clone(),
            fd,
            deadline,
        }));
        let mut thread = unsafe { core::mem::zeroed() };
        if unsafe { libc::pthread_create(&mut thread, ptr::null(), worker, job.cast()) } != 0 {
            drop(unsafe { Box::from_raw(job) });
            self.state.connections.fetch_sub(1, Ordering::AcqRel);
            return Err("TLS ingress worker unavailable".into());
        }
        unsafe { libc::pthread_detach(thread) };
        Ok(())
    }
}

struct Job {
    state: Arc<State>,
    fd: Fd,
    deadline: u64,
}

extern "C" fn worker(value: *mut c_void) -> *mut c_void {
    let Job {
        state,
        fd,
        deadline,
    } = *unsafe { Box::from_raw(value.cast::<Job>()) };
    let accepted = state.tls.accept_first_frame(fd, deadline);
    if let Ok((stream, bytes)) = &accepted {
        if let Ok(pull) = Request::parse(bytes) {
            // There is one in-flight log batch. Concurrent pulls retry later
            // while other ingress workers remain free to serve control/PW.
            let _ = state.diagnostics.take(|delivery| {
                delivery.exchange(&state.source_session, pull.ack.as_ref(), stream)
            });
            drop(accepted);
            state.connections.fetch_sub(1, Ordering::AcqRel);
            return ptr::null_mut();
        }
    }
    state.ready.with(|ready| ready.push_back(accepted));
    ptr::null_mut()
}
