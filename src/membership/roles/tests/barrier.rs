use super::*;
use crate::test_common::TestApi as _;
use std::future::{Future, poll_fn};
use std::task::Poll;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_sdk_writer_cannot_revoke_inside_the_same_database_role_barrier() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = first(&owner).await;
    let mut lease = owner.role(&auth).await.unwrap();
    let keys = owner.passkeys.clone();
    let user = auth.member();
    let credential = auth.credential_id().clone();
    owner
        .with_current_role(&mut lease, |observed| {
            assert_eq!(observed, common::now() as u64);
            // The ACTUAL SDK tries its ordinary atomic revocation on another
            // thread/pooled connection. SQLite's configured busy timeout must
            // refuse this writer while the original Immediate barrier is held.
            let writer_keys = keys.clone();
            let writer_credential = credential.clone();
            let result = std::thread::spawn(move || writer_keys.revoke(user, &writer_credential))
                .join()
                .unwrap();
            assert_eq!(result, Err(ckyh::Error::Storage));
            Ok(())
        })
        .await
        .unwrap();
    assert!(lease.is_current(common::now() as u64));
    tokio::task::spawn_blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Passkey));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_real_barrier_acquisition_cannot_reuse_the_old_role_observation() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = first(&owner).await;
    let mut lease = owner.role(&auth).await.unwrap();
    let writer = db.community("a").unwrap().tx().await.unwrap();
    let mut called = false;
    let mut pending = Box::pin(owner.with_current_role(&mut lease, |_| {
        called = true;
        Ok(())
    }));
    poll_fn(|context| match pending.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("the real competing writer must prevent release"),
    })
    .await;
    drop(pending);
    assert!(!called);
    assert!(!lease.is_current(common::now() as u64));
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Identity));
    writer.rollback().await.unwrap();
    drop(lease);
    // A fresh owner read still sees the actual unrevoked credential/role. It
    // never rehabilitates the cancelled opaque observation.
    assert!(
        owner
            .role(&auth)
            .await
            .unwrap()
            .is_current(common::now() as u64)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_connection_pool_refuses_role_release_and_poisons_the_observation() {
    let (directory, setup) = common::temporary().await;
    let setup_owner = common::facade(&setup, "a", common::Clock::new());
    let _ = first(&setup_owner).await;
    // Genuine admission needs the ordinary pool before the intentionally
    // exhausted owner is opened. This does not fabricate a Register row.
    let mut device = common::register(&setup_owner, Uuid::from_u128(2), &"02".repeat(48)).await;
    let auth = common::login(&setup_owner, &mut device, Uuid::from_u128(2))
        .await
        .authentication;
    setup_owner
        .reserve_handle(&auth, "second_member", &[])
        .await
        .unwrap();
    setup_owner
        .admit_test(
            &auth,
            &common::policy("a"),
            &[common::test_gate("a", &"02".repeat(48))],
            common::lease(),
        )
        .await
        .unwrap();
    drop(setup_owner);
    drop(setup);
    let mut config = crlt::Config::new(
        format!("file://{}", directory.path().join("members.db").display()),
        "",
    );
    config.max_connections = 1;
    config.timeout = Duration::from_millis(250);
    config.busy_timeout = Duration::from_millis(100);
    let db = crlt::Db::open(config).await.unwrap();
    // Load the ORIGINAL schema ledger through the ordinary migration owner.
    db.migrate(&common::migrations()).await.unwrap();
    let owner = common::facade(&db, "a", common::Clock::new());
    let mut lease = owner.role(&auth).await.unwrap();
    let mut called = false;
    assert_eq!(
        owner
            .with_current_role(&mut lease, |_| {
                called = true;
                Ok(())
            })
            .await,
        Err(Error::Unavailable)
    );
    assert!(!called);
    assert!(!lease.is_current(common::now() as u64));
}
