//! Real SDK and legal owner checks after the original role write is staged.
use super::*;
use crate::test_common as common;
use crate::test_common::TestApi as _;

async fn root(owner: &common::Facade) -> Authentication {
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
    let row = owner.enrol_store.load(common::USER).await.unwrap().unwrap();
    // Explicit trusted fixture initialization through the original Register;
    // this does not qualify a production first-Root bootstrap.
    owner
        .register
        .set_role(&row.member_id(), crgs::Role::Root)
        .await
        .unwrap();
    auth
}

fn writer<'a>(
    owner: &'a common::Facade,
    auth: &'a Authentication,
) -> RoleWriter<'a, crate::LibsqlStorage, common::Verify, common::Clock> {
    RoleWriter::new(
        owner,
        auth,
        auth.member(),
        crgs::Role::Root,
        Window {
            floor: common::now() as u64,
            begun_at: common::now() as u64,
            until: common::now() as u64 + 60,
            started: Instant::now(),
            session: None,
        },
    )
}

async fn unchanged(owner: &common::Facade, before: &crgs::Member) {
    assert_eq!(
        owner.register.member(&before.id).await.unwrap(),
        Some(before.clone())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staged_role_change_refuses_actual_revoked_actor_without_durable_role_change() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = root(&owner).await;
    let row = owner
        .enrol_store
        .load(auth.member())
        .await
        .unwrap()
        .unwrap();
    let before = owner
        .register
        .member(&row.member_id())
        .await
        .unwrap()
        .unwrap();
    let mut guard = writer(&owner, &auth);
    let keys = owner.passkeys.clone();
    let original = auth.clone();
    tokio::task::spawn_blocking(move || keys.revoke(original.member(), original.credential_id()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        owner
            .register
            .set_role_checked(&before.id, crgs::Role::Admin, &mut guard)
            .await,
        Err(crgs::Error::Storage)
    );
    unchanged(&owner, &before).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_root_can_change_role_through_the_same_writer_guard() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = root(&owner).await;
    let row = owner
        .enrol_store
        .load(auth.member())
        .await
        .unwrap()
        .unwrap();
    let before = owner
        .register
        .member(&row.member_id())
        .await
        .unwrap()
        .unwrap();
    let mut guard = writer(&owner, &auth);
    let actual = owner
        .register
        .set_role_checked(&before.id, crgs::Role::Admin, &mut guard)
        .await
        .unwrap();
    let mut expected = before;
    expected.role = crgs::Role::Admin;
    assert_eq!(actual, expected);
    assert_eq!(
        owner.register.member(&expected.id).await.unwrap(),
        Some(expected)
    );
}
