use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_real_signed_receipt_recipient_or_target_cannot_redeem_pending_root() {
    let fixture = Fixture::new().await;
    let original = fixture.first_invitation();
    fixture.initialize(&original).await;
    let until = common::now() as u64 + 600;
    let alternate_receipt =
        fixture.invitation("another-root", COMMUNITY, common::SUBJECT.as_bytes(), until);
    let wrong_recipient = fixture.invitation(
        "original-first-root",
        COMMUNITY,
        b"another-real-recipient",
        until,
    );
    let wrong_target = fixture.invitation(
        "original-first-root",
        "other-community",
        common::SUBJECT.as_bytes(),
        until,
    );
    for bytes in [&alternate_receipt, &wrong_recipient, &wrong_target] {
        assert!(
            fixture
                .owner
                .admit_first_root(fixture.request(), bytes)
                .await
                .is_err()
        );
        fixture.assert_pending().await;
    }
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        fixture
            .owner
            .admit_first_root(fixture.request(), &corrupt)
            .await,
        Err(Error::Policy)
    );
    fixture.assert_pending().await;
    assert_eq!(
        fixture
            .owner
            .admit_first_root(fixture.request(), &original)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    // A different genuine receipt never replaces the committed original winner.
    assert_eq!(
        fixture
            .owner
            .admit_first_root(fixture.request(), &alternate_receipt)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_invitation_for_another_member_or_community_cannot_initialize() {
    let fixture = Fixture::new().await;
    let until = common::now() as u64 + 600;
    for (community, member) in [
        (COMMUNITY, b"another-recipient".as_slice()),
        ("other-community", common::SUBJECT.as_bytes()),
    ] {
        let bytes = fixture.invitation("first-root", community, member, until);
        let verified = cvch::role::verify(
            &bytes,
            fixture.policy.key_ring().unwrap(),
            &cvch::role::Context {
                community,
                member,
                purpose: cvch::role::Purpose::BootstrapRoot,
                now: common::now() as u64,
            },
        )
        .unwrap();
        assert_eq!(
            fixture
                .owner
                .initialize_community_creation(&verified, common::SUBJECT.as_bytes())
                .await,
            Err(Error::Identity)
        );
        assert_eq!(
            fixture.owner.community_phase().await.unwrap(),
            CommunityPhase::Uninitialized
        );
        assert!(
            fixture
                .owner
                .register
                .member(&root_id())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_invitation_exclusive_expiry_never_becomes_a_later_root() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    fixture.clock.set(common::now() + 600);
    assert_eq!(
        fixture
            .owner
            .admit_first_root(fixture.request(), &invitation)
            .await,
        Err(Error::Policy)
    );
    fixture.assert_pending().await;
}
