//! Original confirmation timing begins before waiting for the member lease.
use super::*;
use std::{future::Future, task::Poll};

#[tokio::test(flavor = "multi_thread")]
async fn time_spent_waiting_for_the_actual_member_owner_cannot_renew_confirmation() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let community = "confirmation-queued-expiry";
    let membership = facade(&db, community, clock.clone());
    let (_, login) = pending(&membership, community).await;
    let before = membership
        .credentials(USER)
        .await
        .unwrap()
        .pop()
        .unwrap()
        .counter();
    let guard = crate::storage::member_lock(community, USER).await;
    let mut beginning = Box::pin(membership.begin_self_ban_confirmation(
        &login.authentication,
        order(community),
        now() + 1,
    ));
    std::future::poll_fn(|cx| {
        // This real owner lock prevents issuance after the original clock read.
        assert!(matches!(beginning.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    clock.set(now() + 1);
    drop(guard);
    assert!(matches!(beginning.await, Err(Error::InvalidInput)));
    assert_eq!(
        membership
            .credentials(USER)
            .await
            .unwrap()
            .pop()
            .unwrap()
            .counter(),
        before
    );
}
