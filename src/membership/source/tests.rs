//! Genuine SDK and legal reads under the original retained member lease.
use super::*;
use crate::test_common as common;
use cplc::MembershipSource as _;
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    future::{Future, poll_fn},
    sync::atomic::{AtomicI64, AtomicUsize, Ordering},
    task::Poll,
};

const ACCOUNT: &str = "community.account";

async fn admitted<C: clbs::Clock + 'static>(
    owner: &Membership<crate::LibsqlStorage, common::Verify, C>,
) -> Authentication {
    let mut device = common::register(owner, common::USER, common::SUBJECT).await;
    let auth = common::login(owner, &mut device, common::USER)
        .await
        .authentication;
    owner
        .reserve_handle(&auth, common::HANDLE, &[])
        .await
        .unwrap();
    owner
        .admit_test(
            &auth,
            &common::policy("a"),
            &[common::test_gate("a", common::SUBJECT)],
            common::lease(),
        )
        .await
        .unwrap();
    auth
}

fn restriction(id: &str, starts_at: i64) -> clbs::SignedOrder {
    let order = clbs::Order {
        community: "a".into(),
        id: id.into(),
        subject: common::SUBJECT.into(),
        reference: "explicit signature fixture".into(),
        entered_by: "fixture-operator".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
        },
        scope: clbs::Scope::Actions([ACCOUNT.to_owned()].into()),
        period: clbs::Period {
            starts_at,
            ends_at: None,
        },
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    clbs::SignedOrder { order, proof }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readonly_current_source_succeeds_while_original_database_writer_is_held() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = admitted(&owner).await;
    let (original, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    let writer = db.community("a").unwrap().tx().await.unwrap();
    let current = tokio::time::timeout(
        Duration::from_secs(5),
        owner.check_source(&mut lease, &auth, ACCOUNT, common::now() as u64),
    )
    .await
    .expect("current source reads must not acquire a second writer")
    .unwrap();
    assert_eq!(current.community, original.community);
    assert_eq!(current.member, original.member);
    assert_eq!(current.state, crbk::MembershipState::Admitted);
    assert_eq!(current.authorized_devices, original.authorized_devices);
    assert_eq!(current.lease_end, original.lease_end);
    assert!(lease.valid);
    writer.rollback().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_sdk_revocation_invalidates_the_exact_retained_source() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = admitted(&owner).await;
    let (_, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    let keys = owner.passkeys.clone();
    let user = auth.member();
    let credential = auth.credential_id().clone();
    tokio::task::spawn_blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await,
        Err(Error::Passkey)
    ));
    assert!(!lease.valid);
    assert!(matches!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await,
        Err(Error::Identity)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_legal_writer_restricts_account_without_restricting_membership() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock.clone());
    let auth = admitted(&owner).await;
    let (_, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    let independent = common::facade(&db, "a", clock);
    independent
        .legal
        .record_legal(&restriction("account-only", common::now()))
        .await
        .unwrap();
    owner
        .check_source(
            &mut lease,
            &auth,
            &common::config().membership_action,
            common::now() as u64,
        )
        .await
        .unwrap();
    assert!(matches!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await,
        Err(Error::Restricted)
    ));
    assert!(!lease.valid);
    assert!(matches!(
        owner.legal.check_action(common::SUBJECT, ACCOUNT).await,
        Ok(clbs::State::Red(_))
    ));
}

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
            self.time.store(common::now() + 1, Ordering::SeqCst);
        }
        Ok(self.time.load(Ordering::SeqCst))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_account_restriction_crossing_the_final_read_withholds_facts() {
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
    let auth = admitted(&owner).await;
    let (_, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    owner
        .legal
        .record_legal(&restriction("scheduled-account", common::now() + 1))
        .await
        .unwrap();
    // Calibrate the SAME successful owner read with the real stored order.
    // Advance at its final sample, after the earlier legal read was Green.
    clock.calls.store(0, Ordering::SeqCst);
    owner
        .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
        .await
        .unwrap();
    let final_read = clock.calls.load(Ordering::SeqCst);
    assert!(final_read > 1);
    clock.calls.store(0, Ordering::SeqCst);
    clock.advance_at.store(final_read, Ordering::SeqCst);
    assert!(matches!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await,
        Err(Error::Transition | Error::Restricted)
    ));
    assert!(!lease.valid);
    assert!(matches!(
        owner.legal.check_action(common::SUBJECT, ACCOUNT).await,
        Ok(clbs::State::Red(_))
    ));
}

async fn single_connection() -> (tempfile::TempDir, crlt::Db, common::Facade, Authentication) {
    let (directory, setup) = common::temporary().await;
    let owner = common::facade(&setup, "a", common::Clock::new());
    let auth = admitted(&owner).await;
    drop(owner);
    drop(setup);
    let mut config = crlt::Config::new(
        format!("file://{}", directory.path().join("members.db").display()),
        "",
    );
    config.max_connections = 1;
    config.timeout = Duration::from_millis(250);
    config.busy_timeout = Duration::from_millis(100);
    let db = crlt::Db::open(config).await.unwrap();
    db.migrate(&common::migrations()).await.unwrap();
    let owner = common::facade(&db, "a", common::Clock::new());
    (directory, db, owner, auth)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pool_one_refuses_current_read_under_actual_writer_and_poisons_lease() {
    let (_directory, db, owner, auth) = single_connection().await;
    let (_, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    let writer = db.community("a").unwrap().tx().await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        owner.check_source(&mut lease, &auth, ACCOUNT, common::now() as u64),
    )
    .await
    .expect("exhausted actual pool must give bounded refusal");
    assert!(matches!(result, Err(Error::Unavailable)));
    assert!(!lease.valid);
    writer.rollback().await.unwrap();
    assert!(matches!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await,
        Err(Error::Identity)
    ));
    drop(lease);
    assert!(
        owner
            .membership(common::SUBJECT, common::now() as u64)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_while_real_pool_read_waits_cannot_revive_original_lease() {
    let (_directory, db, owner, auth) = single_connection().await;
    let (_, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    let writer = db.community("a").unwrap().tx().await.unwrap();
    let mut pending =
        Box::pin(owner.check_source(&mut lease, &auth, ACCOUNT, common::now() as u64));
    poll_fn(|context| match pending.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("the actual occupied pool must prevent current read"),
    })
    .await;
    drop(pending);
    assert!(!lease.valid);
    writer.rollback().await.unwrap();
    assert!(matches!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await,
        Err(Error::Identity)
    ));
    drop(lease);
    assert!(
        owner
            .membership(common::SUBJECT, common::now() as u64)
            .await
            .is_ok()
    );
}
