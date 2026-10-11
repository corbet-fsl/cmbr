//! Actual first-key metadata and owner changes while a sealed read is retained.
use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn zero_bind_and_expired_or_negative_host_time_leave_the_real_winner_unset() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let membership = facade(&db, "creation-invalid-bounds", clock.clone());
    let mut device = register_original(&membership, Some([1; 32])).await;
    let login = authenticate(&membership, &mut device).await;
    for (seed, publication) in [([0; 32], [2; 32]), ([1; 32], [0; 32])] {
        assert!(matches!(
            membership
                .bind_initial_publication(&login.authentication, seed, publication, now() + 60)
                .await,
            Err(Error::InvalidInput)
        ));
    }
    assert!(matches!(
        membership
            .initial_creation(&login.authentication, now())
            .await,
        Err(Error::InvalidInput)
    ));
    clock.set(-1);
    assert!(matches!(
        membership
            .initial_creation(&login.authentication, now() + 60)
            .await,
        Err(Error::Unavailable)
    ));
    clock.set(now());
    let membership = facade(&db, "creation-invalid-bounds", clock.clone());
    let mut original = membership
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    assert_eq!(original.publication(), None);
    assert_eq!(original.observed_at(), now());
    clock.set(now() + 5);
    assert_eq!(
        membership
            .check_initial_creation(&mut original)
            .await
            .unwrap(),
        now() + 5
    );
    assert_eq!(original.observed_at(), now() + 5);
    assert!(!original.is_current(now() + 4));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_actual_same_key_publication_commit_invalidates_an_older_sealed_read() {
    let (_dir, db) = temporary().await;
    let membership = facade(&db, "creation-changed-winner", Clock::new());
    let mut device = register_original(&membership, Some([1; 32])).await;
    let login = authenticate(&membership, &mut device).await;
    let mut original = membership
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    assert_eq!(original.publication(), None);
    // The original SDK owns this durable CAS. Its same authenticated key may
    // complete through a different owner process while this RAM lease is held.
    let keys = membership.passkeys.clone();
    let authentication = login.authentication.clone();
    let winner = tokio::task::spawn_blocking(move || {
        keys.bind_initial_publication(&authentication, [1; 32], [2; 32])
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(winner.publication(), Some([2; 32]));
    assert_eq!(
        membership.check_initial_creation(&mut original).await,
        Err(Error::Busy)
    );
    assert!(!original.is_current(now()));
    assert_eq!(
        membership.check_initial_creation(&mut original).await,
        Err(Error::Identity)
    );
    drop(original);
    let fresh = authenticate(&membership, &mut device).await;
    let stored = membership
        .initial_creation(&fresh.authentication, now() + 60)
        .await
        .unwrap();
    assert_eq!(stored.seed(), [1; 32]);
    assert_eq!(stored.publication(), Some([2; 32]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_real_permanent_legal_commit_and_lifecycle_sync_poison_the_retained_creation_read() {
    let (_dir, db) = temporary().await;
    let community = "creation-durable-termination";
    let membership = facade(&db, community, Clock::new());
    let mut device = register_original(&membership, Some([1; 32])).await;
    let login = authenticate(&membership, &mut device).await;
    let mut original = membership
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    // Use the original verified legal owner and original lifecycle sync, as an
    // external durable owner can. No synthetic enrolment row is installed.
    membership.legal.self_ban(&ban(community)).await.unwrap();
    assert_eq!(
        membership.sync(USER, now()).await.unwrap().state(),
        cnrl::State::Released
    );
    assert_eq!(
        membership.check_initial_creation(&mut original).await,
        Err(Error::Transition)
    );
    assert!(!original.is_current(now()));
    assert_eq!(
        membership.check_initial_creation(&mut original).await,
        Err(Error::Identity)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_committed_self_ban_refuses_a_new_creation_read_before_sdk_access() {
    let (_dir, db) = temporary().await;
    let community = "creation-new-terminal-read";
    let membership = facade(&db, community, Clock::new());
    let mut device = register_original(&membership, Some([1; 32])).await;
    let login = authenticate(&membership, &mut device).await;
    membership
        .self_ban(&login.authentication, &ban(community))
        .await
        .unwrap();
    assert!(matches!(
        membership
            .initial_creation(&login.authentication, now() + 60)
            .await,
        Err(Error::Transition)
    ));
    let keys = membership.passkeys.clone();
    let auth = login.authentication.clone();
    let stored = tokio::task::spawn_blocking(move || keys.initial_creation(&auth))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.seed(), [1; 32]);
    assert_eq!(stored.publication(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_actual_handle_reservation_deadline_bounds_every_creation_lease_check() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let membership = facade(&db, "creation-reservation-bound", clock.clone());
    let mut device = register_original(&membership, Some([1; 32])).await;
    let login = authenticate(&membership, &mut device).await;
    membership
        .reserve_handle(&login.authentication, HANDLE, &[])
        .await
        .unwrap();
    let row = membership.enrol.view(USER, now()).await.unwrap();
    assert_eq!(row.state(), cnrl::State::HandleReserved);
    let deadline = row.expires_at().unwrap();
    assert!(deadline > now());
    // Original handle retention is measured in caller-configured days. Choose
    // a host bound just beyond that actual deadline, without inventing policy.
    let host_deadline = deadline.checked_add(1).unwrap();
    let mut original = membership
        .initial_creation(&login.authentication, host_deadline)
        .await
        .unwrap();
    assert_eq!(
        membership
            .check_initial_creation(&mut original)
            .await
            .unwrap(),
        now()
    );
    assert!(!original.is_current(deadline));
    clock.set(deadline);
    assert_eq!(
        membership.check_initial_creation(&mut original).await,
        Err(Error::Identity)
    );
    assert!(!original.is_current(deadline));
}
