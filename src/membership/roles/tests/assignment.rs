use super::*;

const SECOND: Uuid = Uuid::from_u128(2);
fn second_subject() -> String {
    "02".repeat(48)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_root_admin_member_assignment_rights_use_real_register_roles() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock);
    let root = first(&owner).await;
    let target = admitted(
        &owner,
        SECOND,
        &second_subject(),
        "second_member",
        common::lease(),
    )
    .await;
    seed_original_root(&owner, &root).await;
    let now = common::now() as u64;
    owner
        .set_member_role(&root, &second_subject(), crgs::Role::Admin, now, now + 60)
        .await
        .unwrap();
    let lease = owner.role(&target).await.unwrap();
    assert_eq!(lease.role(), crgs::Role::Admin);
    drop(lease);
    assert_eq!(
        owner
            .set_role(&target, common::USER, crgs::Role::Member)
            .await,
        Err(Error::Policy)
    );
    assert_eq!(
        owner.set_role(&target, SECOND, crgs::Role::Root).await,
        Err(Error::Policy)
    );
    owner
        .set_role(&root, SECOND, crgs::Role::Root)
        .await
        .unwrap();
    let lease = owner.role(&target).await.unwrap();
    assert_eq!(lease.role(), crgs::Role::Root);
    drop(lease);
    owner
        .set_role(&target, SECOND, crgs::Role::Member)
        .await
        .unwrap();
    let lease = owner.role(&target).await.unwrap();
    assert_eq!(lease.role(), crgs::Role::Member);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_member_cannot_trigger_expired_target_lifecycle_maintenance() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock.clone());
    let actor = first(&owner).await;
    admitted(
        &owner,
        SECOND,
        &second_subject(),
        "second_member",
        crgs::YearMonth::new(2026, 9).unwrap(),
    )
    .await;
    let before = owner.enrol_store.load(SECOND).await.unwrap().unwrap();
    let register_before = owner
        .register
        .member(&before.member_id())
        .await
        .unwrap()
        .unwrap();
    clock.set(
        "2026-10-01T00:00:00Z"
            .parse::<DateTime<Utc>>()
            .unwrap()
            .timestamp(),
    );
    assert_eq!(
        owner.set_role(&actor, SECOND, crgs::Role::Admin).await,
        Err(Error::Policy)
    );
    let after = owner.enrol_store.load(SECOND).await.unwrap().unwrap();
    assert_eq!(
        serde_json::to_value(&before).unwrap(),
        serde_json::to_value(&after).unwrap()
    );
    let register_after = owner
        .register
        .member(&after.member_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(register_before, register_after);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_original_role_writer_rechecks_real_membership_expiry() {
    use std::{future::Future, task::Poll};
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock.clone());
    let root = first(&owner).await;
    admitted(
        &owner,
        SECOND,
        &second_subject(),
        "second_member",
        common::lease(),
    )
    .await;
    seed_original_root(&owner, &root).await;
    let held = owner.role(&root).await.unwrap();
    let deadline = held.valid_until();
    let mut assigning = Box::pin(owner.set_role(&root, SECOND, crgs::Role::Admin));
    std::future::poll_fn(|cx| {
        // This genuine UUID-ordered write is blocked by the actual role guard;
        // set_role reaches that lock before any queued owner read or mutation.
        assert!(matches!(assigning.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    clock.set(deadline.try_into().unwrap());
    drop(held);
    assert_eq!(assigning.await, Err(Error::Transition));
    let row = owner.enrol_store.load(SECOND).await.unwrap().unwrap();
    assert_eq!(
        owner
            .register
            .member(&row.member_id())
            .await
            .unwrap()
            .unwrap()
            .role,
        crgs::Role::Member
    );
}
