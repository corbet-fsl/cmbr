use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_creation_id_cannot_take_the_pending_admin_seat() {
    let fixture = Fixture::new().await;
    let original = fixture.first_invitation();
    fixture.initialize(&original).await;
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), "another-root")
            .await,
        Err(Error::Identity)
    );
    fixture.assert_pending().await;
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &original)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    // A different id never replaces the committed original winner.
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), "another-root")
            .await,
        Err(Error::Identity)
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_for_a_non_text_creator_or_a_past_expiry_cannot_initialize() {
    let fixture = Fixture::new().await;
    let now = common::now() as u64;
    assert!(
        fixture
            .owner
            .initialize_community_creation("first-root", &[0xff, 0xfe], now + 600)
            .await
            .is_err()
    );
    assert!(
        fixture
            .owner
            .initialize_community_creation("first-root", common::SUBJECT.as_bytes(), now)
            .await
            .is_err()
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Uninitialized
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_expiry_never_becomes_a_later_admin() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    fixture.clock.set(common::now() + 600);
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Transition)
    );
    fixture.assert_pending().await;
}
