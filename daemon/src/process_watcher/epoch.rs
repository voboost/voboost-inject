//! Actual system clock samples identify endpoints across injection-host restarts.
use std::io;

const MAX_READS: usize = 128;
pub(super) const MAX_EPOCH: u64 = i64::MAX as u64;

/// Serial injection hosts share a kernel clock and hold the single-instance lock.
/// The first sample fences the previous host, including clocks with coarse ticks.
/// Issue only observed values above that floor: reserving future values with a
/// counter would allow the next host to collide with an outstanding registration.
pub(super) struct Epochs {
    last: Option<u64>,
}

impl Epochs {
    pub(super) const fn new() -> Self {
        Self { last: None }
    }

    pub(super) fn next(
        &mut self,
        mut read: impl FnMut() -> io::Result<u64>,
        mut wait: impl FnMut(),
    ) -> io::Result<u64> {
        let floor = match self.last {
            Some(last) => last,
            None => {
                let floor = checked(read()?)?;
                self.last = Some(floor);
                floor
            }
        };
        for _ in 0..MAX_READS {
            let now = checked(read()?)?;
            if now < floor {
                return Err(invalid("endpoint clock regressed"));
            }
            if now > floor {
                self.last = Some(now);
                return Ok(now);
            }
            wait();
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "endpoint clock did not advance",
        ))
    }
}

pub(super) fn clock_value(seconds: i128, nanos: i128) -> io::Result<u64> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err(invalid("invalid endpoint clock"));
    }
    let value = u64::try_from(seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(nanos as u64))
        .ok_or_else(|| invalid("endpoint clock overflow"))?;
    checked(value)
}

fn checked(value: u64) -> io::Result<u64> {
    if value == 0 || value > MAX_EPOCH {
        Err(invalid("endpoint epoch exceeds Java integer domain"))
    } else {
        Ok(value)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn samples(values: &[u64]) -> impl FnMut() -> io::Result<u64> {
        let mut values: VecDeque<_> = values.iter().copied().collect();
        move || Ok(values.pop_front().expect("unexpected clock read"))
    }

    #[test]
    fn restarted_allocator_waits_past_its_floor_even_on_the_same_coarse_tick() {
        let mut old = Epochs::new();
        let previous = old.next(samples(&[100, 100, 101]), || {}).unwrap();
        let mut restarted = Epochs::new();
        let fresh = restarted
            .next(samples(&[101, 101, 101, 102]), || {})
            .unwrap();
        assert!(fresh > previous);
        assert_eq!(fresh, 102);
    }

    #[test]
    fn allocations_use_observed_values_without_reserving_future_clock_units() {
        let mut epochs = Epochs::new();
        assert_eq!(epochs.next(samples(&[100, 101]), || {}).unwrap(), 101);
        assert_eq!(epochs.next(samples(&[101, 101, 103]), || {}).unwrap(), 103);
        assert_eq!(epochs.next(samples(&[107]), || {}).unwrap(), 107);
    }

    #[test]
    fn clock_regression_and_errors_never_return_or_replace_an_epoch() {
        let mut epochs = Epochs::new();
        assert_eq!(epochs.next(samples(&[100, 101]), || {}).unwrap(), 101);
        assert_eq!(
            epochs.next(samples(&[100]), || {}).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            epochs
                .next(
                    || Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                    || {}
                )
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(epochs.next(samples(&[102]), || {}).unwrap(), 102);
    }

    #[test]
    fn a_stalled_clock_has_a_finite_read_budget() {
        let mut epochs = Epochs::new();
        let mut reads = 0;
        let mut waits = 0;
        let error = epochs
            .next(
                || {
                    reads += 1;
                    Ok(100)
                },
                || waits += 1,
            )
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(reads, MAX_READS + 1);
        assert_eq!(waits, MAX_READS);
    }

    #[test]
    fn invalid_clock_components_and_java_overflow_fail_closed() {
        for (seconds, nanos) in [
            (-1, 0),
            (0, -1),
            (0, 1_000_000_000),
            (0, 0),
            (i128::MAX, 0),
            (i64::MAX as i128, 0),
        ] {
            assert!(clock_value(seconds, nanos).is_err());
        }
        assert_eq!(clock_value(1, 7).unwrap(), 1_000_000_007);
        let mut epochs = Epochs::new();
        assert_eq!(
            epochs
                .next(samples(&[MAX_EPOCH - 1, MAX_EPOCH]), || {})
                .unwrap(),
            MAX_EPOCH
        );
        assert!(epochs.next(samples(&[MAX_EPOCH + 1]), || {}).is_err());
    }
}
