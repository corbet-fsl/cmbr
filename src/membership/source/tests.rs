//! Genuine SDK and legal reads under the original retained member lease.
use super::*;
use crate::test_common as common;
use crate::test_common::TestApi as _;
use cplc::MembershipSource as _;
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    future::{Future, poll_fn},
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

fn restriction(id: &str) -> clbs::SignedOrder {
    let order = clbs::Order {
        community: "a".into(),
        id: id.into(),
        subject: common::SUBJECT.into(),
        reference: "explicit signature fixture".into(),
        entered_by: "fixture-operator".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
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
async fn independent_legal_writer_blocks_the_member_for_every_action() {
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
        .record_legal(&restriction("blocked"))
        .await
        .unwrap();
    // A block is total: the membership action is refused exactly like the account action.
    assert!(matches!(
        owner
            .check_source(
                &mut lease,
                &auth,
                &common::config().membership_action,
                common::now() as u64,
            )
            .await,
        Err(Error::Restricted)
    ));
    assert!(!lease.valid);
    assert!(matches!(
        owner.legal.check(common::SUBJECT).await,
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

/// A real Ed25519 public key: the device registry refuses anything else.
fn device(byte: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[byte; 32])
        .verifying_key()
        .to_bytes()
}

/// JOIN by device key (no community passkey) and the session that key signs in with.
async fn device_joined(owner: &common::Facade, key: [u8; 32]) -> Authentication {
    let joined = owner
        .join_with_device_key(common::USER, common::SUBJECT, key, [9; 32])
        .await
        .unwrap();
    let auth = Authentication::from_device_key("a".into(), joined.user(), key);
    owner
        .reserve_handle(&auth, common::HANDLE, &[])
        .await
        .unwrap();
    auth
}

async fn admit(owner: &common::Facade, auth: &Authentication) -> Result<cnrl::Record> {
    owner
        .admit_test(
            auth,
            &common::policy("a"),
            &[common::test_gate("a", common::SUBJECT)],
            common::lease(),
        )
        .await
}

async fn set_registry_state(db: &crlt::Db, key: [u8; 32], state: &str) {
    db.community("a")
        .unwrap()
        .execute(
            "UPDATE cvld_device_registry SET state = ?1 WHERE device_key = ?2",
            crlt::params![state, key.to_vec()],
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_key_member_is_admitted_and_is_a_credential_source() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let key = device(7);
    let auth = device_joined(&owner, key).await;
    let admitted = admit(&owner, &auth).await.unwrap();
    assert_eq!(admitted.state(), State::Admitted);
    // No community passkey: the active device key alone makes her a credential source.
    assert!(owner.credentials(common::USER).await.unwrap().is_empty());
    let (source, mut lease) = owner
        .membership(common::SUBJECT, common::now() as u64)
        .await
        .unwrap();
    assert_eq!(source.state, crbk::MembershipState::Admitted);
    assert_eq!(source.authorized_devices, vec![key]);
    // Revoking the key in the registry ends the retained source and every new one.
    set_registry_state(&db, key, "revoked").await;
    assert!(
        owner
            .check_source(&mut lease, &auth, ACCOUNT, common::now() as u64)
            .await
            .is_err()
    );
    assert!(!lease.valid);
    // The lease holds the member lock; release it before asking again.
    drop(lease);
    assert!(
        owner
            .membership(common::SUBJECT, common::now() as u64)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_inactive_or_foreign_device_key_is_never_admitted() {
    for state in ["revoked", "pending"] {
        let (_directory, db) = common::temporary().await;
        let owner = common::facade(&db, "a", common::Clock::new());
        let key = device(7);
        let auth = device_joined(&owner, key).await;
        set_registry_state(&db, key, state).await;
        assert!(matches!(admit(&owner, &auth).await, Err(_)), "{state}");
        assert_ne!(
            owner.enrolment_state(common::USER).await.unwrap().state(),
            State::Admitted,
            "{state}"
        );
        assert!(
            owner
                .membership(common::SUBJECT, common::now() as u64)
                .await
                .is_err()
        );
    }
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = device_joined(&owner, device(7)).await;
    // A key never registered for her, or the right key for another community, is refused.
    let unknown = Authentication::from_device_key("a".into(), auth.member(), device(8));
    assert!(admit(&owner, &unknown).await.is_err());
    let foreign = Authentication::from_device_key("b".into(), auth.member(), device(7));
    assert!(admit(&owner, &foreign).await.is_err());
    assert_ne!(
        owner.enrolment_state(common::USER).await.unwrap().state(),
        State::Admitted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_passkey_member_without_a_live_passkey_is_still_no_source() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = admitted(&owner).await;
    owner
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
    assert!(
        owner
            .membership(common::SUBJECT, common::now() as u64)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_crossing_a_second_boundary_reads_its_start_instant() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock.clone());
    let key = device(7);
    let auth = device_joined(&owner, key).await;
    admit(&owner, &auth).await.unwrap();
    // The request captured `start`; its source read runs after the clock has
    // ticked into the next second. The read is evaluated at `start` and
    // returns the same facts as a read inside that second.
    let start = common::now();
    let (inside, lease) = owner
        .membership(common::SUBJECT, start as u64)
        .await
        .unwrap();
    drop(lease);
    // An instant the clock has not reached yet is never accepted.
    assert!(matches!(
        owner.membership(common::SUBJECT, (start + 1) as u64).await,
        Err(cplc::Error::Invalid(_))
    ));
    clock.set(start + 1);
    let (crossed, mut lease) = owner
        .membership(common::SUBJECT, start as u64)
        .await
        .unwrap();
    assert_eq!(lease.checked_at, start as u64);
    assert_eq!(crossed.state, inside.state);
    assert_eq!(crossed.lease_end, inside.lease_end);
    assert_eq!(crossed.probation_until, inside.probation_until);
    assert_eq!(crossed.authorized_devices, vec![key]);
    // The retained lease is still rechecked against the live commit sample.
    owner
        .check_source(&mut lease, &auth, ACCOUNT, (start + 1) as u64)
        .await
        .unwrap();
}
