use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_role_lease_retains_owner_latest_floor_and_original_deadline() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock.clone());
    let auth = first(&owner).await;
    let until = common::now() as u64 + 60;
    let mut lease = owner.role_until(&auth, until).await.unwrap();
    assert_eq!(lease.community(), "a");
    assert_eq!(lease.member(), common::SUBJECT);
    assert_eq!(lease.role(), crgs::Role::Member);
    assert_eq!(lease.valid_until(), until);
    assert!(lease.is_current(common::now() as u64));
    assert!(!lease.is_current(until));
    let foreign = common::facade(&db, "a", clock.clone());
    assert_eq!(foreign.check_role(&mut lease).await, Err(Error::Identity));
    clock.set(common::now() + 20);
    assert_eq!(
        owner.clone().check_role(&mut lease).await.unwrap(),
        common::now() as u64 + 20
    );
    assert!(!lease.is_current(common::now() as u64 + 15));
    clock.set(common::now() + 15);
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Unavailable));
    assert!(!lease.is_current(common::now() as u64 + 20));
    clock.set(common::now() + 21);
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Identity));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_wall_clock_cannot_renew_the_original_owned_role_lifetime() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock);
    let auth = first(&owner).await;
    let mut lease = owner
        .role_until(&auth, common::now() as u64 + 60)
        .await
        .unwrap();
    // Advance only the original Instant fixture. Role, key, membership and
    // legal authority still come from their genuine owners and are unchanged.
    lease.started = Instant::now().checked_sub(lease.lifetime).unwrap();
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Transition));
    assert!(!lease.is_current(common::now() as u64));
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Identity));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_sdk_revocation_cannot_survive_a_held_role_lease() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock);
    let auth = first(&owner).await;
    let mut lease = owner.role(&auth).await.unwrap();
    let keys = owner.passkeys.clone();
    let user = auth.member();
    let credential = auth.credential_id().clone();
    tokio::task::spawn_blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Passkey));
    assert!(!lease.is_current(common::now() as u64));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_legal_commit_and_role_change_invalidate_separate_leases() {
    let (_directory, db) = common::temporary().await;
    let clock = common::Clock::new();
    let owner = common::facade(&db, "a", clock);
    let auth = first(&owner).await;
    let mut lease = owner.role(&auth).await.unwrap();
    seed_original_root(&owner, &auth).await;
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Transition));
    assert!(!lease.is_current(common::now() as u64));
    drop(lease);
    let mut lease = owner.role(&auth).await.unwrap();
    assert_eq!(lease.role(), crgs::Role::Root);
    let signed = common::ban("a");
    owner.legal.self_ban(&signed).await.unwrap();
    assert_eq!(owner.check_role(&mut lease).await, Err(Error::Restricted));
    assert!(!lease.is_current(common::now() as u64));
}
