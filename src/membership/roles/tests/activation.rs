use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

#[derive(Clone)]
struct MeasuredClock {
    time: Arc<AtomicI64>,
    calls: Arc<AtomicUsize>,
    advance_at: Arc<AtomicUsize>,
}
impl clbs::Clock for MeasuredClock {
    fn now(&self) -> clbs::Result<i64> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= self.advance_at.load(Ordering::SeqCst) {
            self.time.store(common::now() + 10, Ordering::SeqCst);
        }
        Ok(self.time.load(Ordering::SeqCst))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_legal_activation_during_current_reads_withholds_the_operation() {
    let (_directory, db) = common::temporary().await;
    let clock = MeasuredClock {
        time: Arc::new(AtomicI64::new(common::now())),
        calls: Arc::new(AtomicUsize::new(0)),
        advance_at: Arc::new(AtomicUsize::new(usize::MAX)),
    };
    let owner = Membership::new(
        &db,
        crate::LibsqlStorage::new(&db, "a").unwrap(),
        common::config(),
        common::Verify,
        clock.clone(),
    )
    .unwrap();
    let auth = first(&owner).await;
    let mut lease = owner.role(&auth).await.unwrap();
    let order = clbs::Order {
        community: "a".into(),
        id: "scheduled-role-restriction".into(),
        subject: common::SUBJECT.into(),
        reference: "explicit signature fixture".into(),
        entered_by: "fixture-operator".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
        },
        scope: clbs::Scope::Actions([common::config().membership_action].into()),
        period: clbs::Period {
            starts_at: common::now() + 10,
            ends_at: None,
        },
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    owner
        .legal
        .record_legal(&clbs::SignedOrder { order, proof })
        .await
        .unwrap();
    // Earlier proof/role preparation may cross a second. The final barrier
    // reads the actual current owners afresh instead of requiring that earlier
    // context's second forever; the signed restriction is not yet effective.
    clock.time.store(common::now() + 5, Ordering::SeqCst);
    owner
        .with_current_role(&mut lease, |observed| {
            assert_eq!(observed, common::now() as u64 + 5);
            Ok(())
        })
        .await
        .unwrap();
    // Measure the ORIGINAL actual owner read, including its real CLBS reads,
    // rather than guessing how many clock calls a cryptographic fixture takes.
    clock.calls.store(0, Ordering::SeqCst);
    owner.check_role(&mut lease).await.unwrap();
    let final_read = clock.calls.load(Ordering::SeqCst);
    assert!(final_read > 1);
    clock.calls.store(0, Ordering::SeqCst);
    clock.advance_at.store(final_read, Ordering::SeqCst);
    let mut called = false;
    let result = owner
        .with_current_role(&mut lease, |_| {
            called = true;
            Ok(())
        })
        .await;
    assert!(matches!(result, Err(Error::Transition | Error::Restricted)));
    assert!(!called);
    assert!(!lease.is_current(common::now() as u64 + 10));
    assert!(matches!(
        owner
            .legal
            .check_action(common::SUBJECT, "membership")
            .await,
        Ok(clbs::State::Red(_))
    ));
}
