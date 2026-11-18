//! Owned blocking workers; the synchronous daemon remains the only control writer.

use std::collections::BTreeMap;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct Job<C, R> {
    context: C,
    worker: JoinHandle<(R, Instant)>,
    dispatched: Instant,
}

pub(crate) struct CompletionTiming {
    pub(crate) worker_elapsed: Option<Duration>,
    pub(crate) collection_delay: Option<Duration>,
}

pub(crate) struct Jobs<C, R> {
    active: BTreeMap<i32, Job<C, R>>,
    closed: bool,
}

impl<C, R> Default for Jobs<C, R> {
    fn default() -> Self {
        Self {
            active: BTreeMap::new(),
            closed: false,
        }
    }
}

impl<C, R: Send + 'static> Jobs<C, R> {
    pub(crate) fn contains(&self, pid: i32) -> bool {
        self.active.contains_key(&pid)
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
    pub(crate) fn contexts(&self) -> impl Iterator<Item = &C> {
        self.active.values().map(|job| &job.context)
    }
    pub(crate) fn admissions_open(&self) -> bool {
        !self.closed
    }
    pub(crate) fn reopen(&mut self) {
        if !self.closed {
            return;
        }
        assert!(self.active.is_empty());
        self.closed = false;
    }
    pub(crate) fn close(&mut self) {
        self.closed = true;
    }

    pub(crate) fn dispatch(
        &mut self,
        pid: i32,
        context: C,
        operation: impl FnOnce() -> R + Send + 'static,
    ) -> Result<(), (C, String)> {
        if self.closed || pid <= 0 || self.contains(pid) {
            return Err((
                context,
                "injection admission closed or PID already owned".into(),
            ));
        }
        let dispatched = Instant::now();
        match std::thread::Builder::new()
            .name(format!("inject-{pid}"))
            .spawn(move || {
                let result = operation();
                (result, Instant::now())
            }) {
            Ok(worker) => {
                self.active.insert(
                    pid,
                    Job {
                        context,
                        worker,
                        dispatched,
                    },
                );
                Ok(())
            }
            Err(error) => Err((context, format!("start injection worker: {error}"))),
        }
    }

    pub(crate) fn collect(&mut self) -> Vec<(C, Result<R, String>, CompletionTiming)> {
        let finished = self
            .active
            .iter()
            .filter_map(|(&pid, job)| job.worker.is_finished().then_some(pid))
            .collect::<Vec<_>>();
        finished
            .into_iter()
            .map(|pid| {
                let job = self.active.remove(&pid).unwrap();
                let collected = Instant::now();
                let (result, timing) = match job.worker.join() {
                    Ok((result, finished)) => (
                        Ok(result),
                        CompletionTiming {
                            worker_elapsed: Some(finished.duration_since(job.dispatched)),
                            collection_delay: Some(collected.saturating_duration_since(finished)),
                        },
                    ),
                    Err(_) => (
                        Err("injection worker panicked".into()),
                        CompletionTiming {
                            worker_elapsed: None,
                            collection_delay: None,
                        },
                    ),
                };
                (job.context, result, timing)
            })
            .collect()
    }
}

impl<C, R> Drop for Jobs<C, R> {
    fn drop(&mut self) {
        // Production terminal paths drain with endpoint service before this
        // fallback. Never detach a thread that may still own a ptrace helper.
        for (_, job) in std::mem::take(&mut self.active) {
            let _ = job.worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reopening_an_open_queue_preserves_a_running_job() {
        let mut jobs = super::Jobs::default();
        let (release, wait) = std::sync::mpsc::channel();
        jobs.dispatch(73, (), move || wait.recv().unwrap()).unwrap();
        jobs.reopen();
        assert!(jobs.admissions_open());
        assert!(jobs.contains(73));
        release.send(()).unwrap();
        assert_eq!(collect_all(&mut jobs).len(), 1);
    }
    use super::*;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn collect_all<C, R: Send + 'static>(
        jobs: &mut Jobs<C, R>,
    ) -> Vec<(C, Result<R, String>, CompletionTiming)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut results = Vec::new();
        while !jobs.is_empty() {
            results.extend(jobs.collect());
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        results
    }

    #[test]
    fn finished_worker_timing_excludes_delayed_collection_and_panic_releases_pid() {
        let mut jobs = Jobs::default();
        jobs.dispatch(1, (), || 42).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !jobs.active[&1].worker.is_finished() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        let before_delay = Instant::now();
        let dispatched = jobs.active[&1].dispatched;
        std::thread::sleep(Duration::from_millis(25));
        let (_, result, timing) = jobs.collect().pop().unwrap();
        assert_eq!(result.unwrap(), 42);
        assert!(timing.collection_delay.unwrap() >= Duration::from_millis(25));
        assert!(timing.worker_elapsed.unwrap() <= before_delay.duration_since(dispatched));
        jobs.dispatch(1, (), || panic!("fixture panic")).unwrap();
        let (_, result, timing) = collect_all(&mut jobs).pop().unwrap();
        assert_eq!(result.unwrap_err(), "injection worker panicked");
        assert!(timing.worker_elapsed.is_none());
        assert!(timing.collection_delay.is_none());
        jobs.dispatch(1, (), || 7).unwrap();
        assert_eq!(collect_all(&mut jobs).pop().unwrap().1.unwrap(), 7);
    }

    #[test]
    fn distinct_targets_overlap_and_owner_services_while_blocked() {
        use std::io::{Read, Write};
        let mut jobs = Jobs::default();
        let (started_tx, started_rx) = mpsc::channel();
        let mut releases = Vec::new();
        for pid in 1..=4 {
            let (release_tx, release_rx) = mpsc::channel();
            releases.push(release_tx);
            let started_tx = started_tx.clone();
            jobs.dispatch(pid, pid, move || {
                started_tx.send(pid).unwrap();
                release_rx.recv().unwrap();
                pid
            })
            .unwrap();
        }
        let mut started = (0..4)
            .map(|_| started_rx.recv_timeout(Duration::from_secs(3)).unwrap())
            .collect::<Vec<_>>();
        started.sort();
        assert_eq!(started, [1, 2, 3, 4]);
        assert!(jobs.collect().is_empty());
        let (mut owner, mut endpoint) = std::os::unix::net::UnixStream::pair().unwrap();
        owner.set_nonblocking(true).unwrap();
        endpoint.write_all(b"state-request").unwrap();
        let mut request = [0; 13];
        owner.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"state-request");
        owner.write_all(b"state-reply").unwrap();
        let mut reply = [0; 11];
        endpoint.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"state-reply");
        assert_eq!(jobs.contexts().count(), 4);
        for release in releases {
            release.send(()).unwrap();
        }
        assert_eq!(collect_all(&mut jobs).len(), 4);
    }

    #[test]
    fn same_pid_is_excluded_until_join_even_after_worker_finishes() {
        let mut jobs = Jobs::default();
        let (release_tx, release_rx) = mpsc::channel();
        jobs.dispatch(1, 100_u64, move || release_rx.recv().unwrap())
            .unwrap();
        assert!(jobs.dispatch(1, 200, || ()).is_err());
        jobs.dispatch(2, 200, || ()).unwrap();
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !jobs.active[&1].worker.is_finished() {
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(jobs.dispatch(1, 200, || ()).is_err());
        assert_eq!(collect_all(&mut jobs).len(), 2);
        jobs.dispatch(1, 200, || ()).unwrap();
        assert_eq!(collect_all(&mut jobs).len(), 1);
    }

    #[test]
    fn freeze_rejects_admission_and_drains_before_owner_drop() {
        let mut jobs = Jobs::default();
        let (release_tx, release_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        jobs.dispatch(1, (), move || {
            release_rx.recv().unwrap();
            finished_tx.send(()).unwrap();
        })
        .unwrap();
        jobs.close();
        assert!(jobs.dispatch(2, (), || ()).is_err());
        assert!(jobs.collect().is_empty());
        release_tx.send(()).unwrap();
        assert_eq!(collect_all(&mut jobs).len(), 1);
        finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        drop(jobs);
    }
}
