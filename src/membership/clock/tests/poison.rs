//! Actual trusted callback unwind must fence every owner sharing the sampler.
use super::*;

struct PanickingClock(AtomicBool);
impl clbs::Clock for PanickingClock {
    fn now(&self) -> clbs::Result<i64> {
        assert!(
            !self.0.load(Ordering::SeqCst),
            "synthetic trusted clock failure"
        );
        Ok(now())
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn a_panicking_trusted_clock_poisons_the_same_membership_clone_and_legal_owner() {
    let (_dir, db) = temporary().await;
    let membership = crate::Membership::new(
        &db,
        crate::LibsqlStorage::new(&db, "clock-unwind").unwrap(),
        config(),
        Verify,
        PanickingClock(AtomicBool::new(false)),
    )
    .unwrap();
    let mut device = Resident::default();
    let login = register(&membership, &mut device).await;
    let clone = membership.clone();
    membership.clock.0.store(true, Ordering::SeqCst);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| clbs::Clock::now(
            membership.clock.as_ref()
        )))
        .is_err()
    );
    membership.clock.0.store(false, Ordering::SeqCst);
    assert!(matches!(
        membership.begin_self_ban_status(now() + 60).await,
        Err(crate::Error::Unavailable)
    ));
    assert!(matches!(
        clone.passkey_certificate(&login.authentication).await,
        Err(crate::Error::Unavailable)
    ));
    assert!(matches!(
        membership.legal.check_action(SUBJECT, "membership").await,
        Err(clbs::Error::Clock)
    ));
}
