//! Fixed action dispatch for one synchronous daemon poll pass.

pub(crate) trait PollActions {
    fn record_deaths(&mut self);
    fn drain_agent_logs(&mut self);
    fn prepare_injection(&mut self);
    fn dispatch_injections(&mut self);
    fn collect_injections(&mut self);
    fn aggregate_agent_status(&mut self);
    fn push_live_config(&mut self);
    fn enforce_live_acks(&mut self);
    fn push_confirmed_snapshots(&mut self);
    fn flush_downlinks(&mut self);
    fn persist_status(&mut self);
}

pub(crate) fn run_poll_pass_with_startup_confirmation(
    actions: &mut impl PollActions,
    startup_changed: bool,
) {
    // Confirm a newly admitted mode before productive work can block its first
    // publication. Ordinary passes keep their single final status write.
    if startup_changed {
        actions.persist_status();
    }
    run_poll_pass(actions);
}

pub(crate) fn run_poll_pass(actions: &mut impl PollActions) {
    actions.record_deaths();
    actions.drain_agent_logs();
    actions.prepare_injection();
    actions.dispatch_injections();
    actions.collect_injections();
    actions.aggregate_agent_status();
    actions.push_live_config();
    actions.enforce_live_acks();
    actions.push_confirmed_snapshots();
    actions.flush_downlinks();
    actions.persist_status();
}

/// Pending work wins ties; all ready process jobs share one priority ordering.
pub(crate) fn run_mixed_startup_batch<T>(
    fresh: &[T],
    retries: &[T],
    mut priority: impl FnMut(&T) -> u8,
    mut step: impl FnMut(bool, TargetBatchStep<'_, T>),
) {
    let mut ordered = retries
        .iter()
        .map(|target| (true, target))
        .chain(fresh.iter().map(|target| (false, target)))
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(_, target)| priority(target));
    step(false, TargetBatchStep::ServiceTrackedPipes);
    for (retry, target) in ordered {
        step(retry, TargetBatchStep::Inject(target));
        step(false, TargetBatchStep::ServiceTrackedPipes);
    }
}

/// Rank only ready catalog members; no absent target can block this batch.
pub(crate) fn run_startup_batch<T>(
    targets: &[T],
    mut priority: impl FnMut(&T) -> u8,
    mut step: impl FnMut(TargetBatchStep<'_, T>),
) {
    let mut ordered: Vec<_> = targets.iter().collect();
    ordered.sort_by_key(|target| priority(target));
    run_target_batch(&ordered, |event| match event {
        TargetBatchStep::ServiceTrackedPipes => step(TargetBatchStep::ServiceTrackedPipes),
        TargetBatchStep::Inject(target) => step(TargetBatchStep::Inject(target)),
    });
}

/// Keep state requests from tracked endpoints out of the next injection's blocking window.
pub(crate) enum TargetBatchStep<'a, T> {
    ServiceTrackedPipes,
    Inject(&'a T),
}

pub(crate) fn run_target_batch<T>(targets: &[T], mut step: impl FnMut(TargetBatchStep<'_, T>)) {
    step(TargetBatchStep::ServiceTrackedPipes);
    for target in targets {
        step(TargetBatchStep::Inject(target));
        // Includes skips/failures returned by the target callback and the last target.
        step(TargetBatchStep::ServiceTrackedPipes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_batch_prioritizes_ready_targets_without_starving_peers() {
        for (input, expected) in [
            (
                vec![(3, 0), (2, 1), (0, 2), (1, 3), (0, 4), (3, 5)],
                vec![2, 4, 3, 1, 0, 5],
            ),
            (vec![(3, 0), (1, 1), (2, 2), (3, 3)], vec![1, 2, 0, 3]),
        ] {
            let mut observed = Vec::new();
            let mut services = 0;
            run_startup_batch(
                &input,
                |target| target.0,
                |event| match event {
                    TargetBatchStep::ServiceTrackedPipes => services += 1,
                    TargetBatchStep::Inject(target) => {
                        assert_eq!(services, observed.len() + 1);
                        observed.push(target.1);
                    }
                },
            );
            assert_eq!(observed, expected);
            assert_eq!(services, input.len() + 1);
        }
    }

    #[test]
    fn mixed_startup_batch_admits_retries_by_priority_without_waiting() {
        let fresh = [
            (3, "background"),
            (0, "vehicle"),
            (1, "interface"),
            (2, "application"),
        ];
        let retries = [(2, "retry-app"), (0, "retry-vehicle")];
        let mut dispatched = Vec::new();
        let mut services = 0;
        run_mixed_startup_batch(
            &fresh,
            &retries,
            |target| target.0,
            |retry, step| match step {
                TargetBatchStep::ServiceTrackedPipes => services += 1,
                TargetBatchStep::Inject(target) => dispatched.push((retry, target.1)),
            },
        );
        assert_eq!(
            dispatched,
            [
                (true, "retry-vehicle"),
                (false, "vehicle"),
                (false, "interface"),
                (true, "retry-app"),
                (false, "application"),
                (false, "background")
            ]
        );
        assert_eq!(services, 7);
    }

    #[derive(Default)]
    struct Recorder(Vec<&'static str>);

    impl PollActions for Recorder {
        fn record_deaths(&mut self) {
            self.0.push("record-deaths");
        }
        fn drain_agent_logs(&mut self) {
            self.0.push("drain-agent-logs");
        }
        fn prepare_injection(&mut self) {
            self.0.push("prepare-injection");
        }
        fn dispatch_injections(&mut self) {
            self.0.push("dispatch-injections");
        }
        fn collect_injections(&mut self) {
            self.0.push("collect-injections");
        }
        fn aggregate_agent_status(&mut self) {
            self.0.push("aggregate-agent-status");
        }
        fn push_live_config(&mut self) {
            self.0.push("push-live-config");
        }
        fn enforce_live_acks(&mut self) {
            self.0.push("enforce-live-acks");
        }
        fn push_confirmed_snapshots(&mut self) {
            self.0.push("push-confirmed-snapshots");
        }
        fn flush_downlinks(&mut self) {
            self.0.push("flush-downlinks");
        }
        fn persist_status(&mut self) {
            self.0.push("persist-status");
        }
    }

    #[test]
    fn scheduler_invokes_each_action_in_productive_pass_order() {
        let mut recorder = Recorder::default();
        run_poll_pass(&mut recorder);
        assert_eq!(
            recorder.0,
            [
                "record-deaths",
                "drain-agent-logs",
                "prepare-injection",
                "dispatch-injections",
                "collect-injections",
                "aggregate-agent-status",
                "push-live-config",
                "enforce-live-acks",
                "push-confirmed-snapshots",
                "flush-downlinks",
                "persist-status",
            ]
        );
    }
    #[test]
    fn target_batch_replies_before_late_blocking_target_and_after_last_target() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (request_tx, request_rx) = mpsc::channel();
        let (reply_tx, reply_rx) = mpsc::channel();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let (received_tx, received_rx) = mpsc::channel();
        let client = std::thread::spawn(move || {
            start_rx.recv().unwrap();
            request_tx.send("R|1|owned-agent|armed").unwrap();
            waiting_tx.send(()).unwrap();
            let reply = reply_rx.recv_timeout(Duration::from_millis(100));
            received_tx.send(reply).unwrap();
        });
        let mut last_request = None;
        let mut replies = Vec::new();
        let mut final_reply = None;
        run_target_batch(&[0, 1], |step| match step {
            TargetBatchStep::ServiceTrackedPipes => {
                // A minimal state endpoint with distinct drain and flush stages.
                if request_rx.try_recv().is_ok() {
                    replies.push("R|1|missing|");
                }
                if let Some(request) = last_request.take() {
                    replies.push(request);
                }
                for reply in replies.drain(..) {
                    if reply == "R|2|missing|" {
                        final_reply = Some(reply);
                    } else {
                        reply_tx.send(reply).unwrap();
                    }
                }
            }
            TargetBatchStep::Inject(0) => {
                start_tx.send(()).unwrap();
                waiting_rx.recv().unwrap();
            }
            TargetBatchStep::Inject(1) => {
                // The next synchronous target blocks longer than the RPC budget.
                std::thread::sleep(Duration::from_millis(150));
                assert_eq!(received_rx.recv().unwrap().unwrap(), "R|1|missing|");
                last_request = Some("R|2|missing|");
            }
            TargetBatchStep::Inject(_) => unreachable!(),
        });
        assert_eq!(final_reply, Some("R|2|missing|"));
        client.join().unwrap();
        assert!(
            last_request.is_none(),
            "the last tracked endpoint was not serviced"
        );
    }

    #[test]
    fn target_batch_services_early_return_and_empty_batch() {
        let mut events = Vec::new();
        run_target_batch(&[0, 1], |step| match step {
            TargetBatchStep::ServiceTrackedPipes => events.push("service"),
            TargetBatchStep::Inject(target) => {
                if *target == 0 {
                    events.push("skip");
                    return;
                }
                events.push("track");
            }
        });
        assert_eq!(events, ["service", "skip", "service", "track", "service"]);
        let mut services = 0;
        run_target_batch::<i32>(&[], |step| {
            if let TargetBatchStep::ServiceTrackedPipes = step {
                services += 1;
            }
        });
        assert_eq!(services, 1);
    }
    #[test]
    fn retry_batch_services_removed_and_retained_entries() {
        let mut retries = std::collections::HashMap::from([(0, false), (1, true)]);
        let mut pending_reply = None;
        let mut delivered = Vec::new();
        let mut events = Vec::new();
        run_target_batch(&[0, 1], |step| match step {
            TargetBatchStep::ServiceTrackedPipes => {
                events.push("service");
                if let Some(reply) = pending_reply.take() {
                    delivered.push(reply);
                }
            }
            TargetBatchStep::Inject(process) => {
                let retain = retries.remove(process).unwrap();
                if *process == 0 {
                    events.push("remove");
                    pending_reply = Some("first-reply");
                    return;
                }
                assert_eq!(delivered, ["first-reply"]);
                events.push("retry");
                pending_reply = Some("last-reply");
                if retain {
                    retries.insert(*process, retain);
                }
            }
        });
        assert_eq!(events, ["service", "remove", "service", "retry", "service"]);
        assert_eq!(delivered, ["first-reply", "last-reply"]);
        assert_eq!(retries, std::collections::HashMap::from([(1, true)]));
    }
    #[test]
    fn startup_confirmation_is_published_before_blocked_productive_work() {
        use std::sync::mpsc;
        use std::time::Duration;
        struct BlockedPass {
            published: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            writes: usize,
        }
        impl PollActions for BlockedPass {
            fn record_deaths(&mut self) {}
            fn drain_agent_logs(&mut self) {}
            fn prepare_injection(&mut self) {
                self.release.recv().unwrap();
            }
            fn dispatch_injections(&mut self) {}
            fn collect_injections(&mut self) {}
            fn aggregate_agent_status(&mut self) {}
            fn push_live_config(&mut self) {}
            fn enforce_live_acks(&mut self) {}
            fn push_confirmed_snapshots(&mut self) {}
            fn flush_downlinks(&mut self) {}
            fn persist_status(&mut self) {
                self.writes += 1;
                self.published.send(()).unwrap();
            }
        }
        let (published, publication) = mpsc::channel();
        let (release, blocked) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            let mut pass = BlockedPass {
                published,
                release: blocked,
                writes: 0,
            };
            run_poll_pass_with_startup_confirmation(&mut pass, true);
            pass.writes
        });
        let early_publication = publication.recv_timeout(Duration::from_millis(100));
        release.send(()).unwrap();
        let writes = owner.join().unwrap();
        assert!(
            early_publication.is_ok(),
            "mode confirmation was blocked by productive work"
        );
        assert_eq!(writes, 2);
    }
    #[test]
    fn startup_confirmation_ordinary_pass_keeps_one_final_status_write() {
        let mut recorder = Recorder::default();
        run_poll_pass_with_startup_confirmation(&mut recorder, false);
        assert_eq!(recorder.0.first(), Some(&"record-deaths"));
        assert_eq!(recorder.0.last(), Some(&"persist-status"));
        assert_eq!(
            recorder
                .0
                .iter()
                .filter(|entry| **entry == "persist-status")
                .count(),
            1
        );
        let mut changed = Recorder::default();
        run_poll_pass_with_startup_confirmation(&mut changed, true);
        assert_eq!(changed.0.first(), Some(&"persist-status"));
        assert_eq!(
            changed
                .0
                .iter()
                .filter(|entry| **entry == "persist-status")
                .count(),
            2
        );
    }
}
