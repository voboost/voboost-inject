//! Bounded forwarding to the authenticated native owner, the only PW proof issuer.
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use voboost_contract::cluster_pw_live::{Challenge, CHALLENGE_MILLIS};

pub fn proof(challenge: Challenge, deadline: Instant, cancel: &AtomicBool) -> io::Result<Vec<u8>> {
    request(
        challenge,
        deadline,
        cancel,
        crate::owner_client::cluster_pw_proof,
    )
}
fn request(
    challenge: Challenge,
    deadline: Instant,
    cancel: &AtomicBool,
    mut read: impl FnMut(Challenge, Instant) -> io::Result<Option<Vec<u8>>>,
) -> io::Result<Vec<u8>> {
    challenge.validate().map_err(io::Error::other)?;
    let deadline = deadline.min(Instant::now() + Duration::from_millis(CHALLENGE_MILLIS));
    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "PW proof cancelled",
            ));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "PW proof expired"));
        }
        if let Some(proof) = read(challenge.clone(), deadline)? {
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PW proof revoked or expired",
                ));
            }
            return Ok(proof);
        }
        std::thread::sleep(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn challenge() -> Challenge {
        Challenge {
            schema_version: 1,
            native_boot: "1".repeat(64),
            native_epoch: "2".repeat(64),
            nonce: "3".repeat(64),
            pair_id: "4".repeat(64),
            generation_id: "5".repeat(64),
            desired_revision: 1,
            desired_sha256: "6".repeat(64),
            desired_disabled: true,
        }
    }
    #[test]
    fn pending_owner_is_polled_with_the_same_one_use_challenge() {
        let original = challenge();
        let mut attempts = 0;
        let result = request(
            original.clone(),
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
            |current, _| {
                assert_eq!(current, original);
                attempts += 1;
                Ok((attempts == 3).then(|| b"signed-owner-proof".to_vec()))
            },
        )
        .unwrap();
        assert_eq!(result, b"signed-owner-proof");
        assert_eq!(attempts, 3);
    }
    #[test]
    fn revoked_expired_or_rejected_requests_never_return_a_proof() {
        assert_eq!(
            request(
                challenge(),
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true),
                |_, _| panic!("cancelled request must not dispatch")
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            request(
                challenge(),
                Instant::now(),
                &AtomicBool::new(false),
                |_, _| panic!("expired request must not dispatch")
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        let mut attempts = 0;
        assert_eq!(
            request(
                challenge(),
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(false),
                |_, _| {
                    attempts += 1;
                    Err(io::ErrorKind::PermissionDenied.into())
                }
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(attempts, 1);
        let cancel = AtomicBool::new(false);
        assert!(request(
            challenge(),
            Instant::now() + Duration::from_secs(1),
            &cancel,
            |_, _| {
                cancel.store(true, Ordering::Release);
                Ok(Some(vec![1]))
            }
        )
        .is_err());
        assert!(request(
            challenge(),
            Instant::now() + Duration::from_millis(1),
            &AtomicBool::new(false),
            |_, _| {
                std::thread::sleep(Duration::from_millis(2));
                Ok(Some(vec![1]))
            }
        )
        .is_err());
    }
}
