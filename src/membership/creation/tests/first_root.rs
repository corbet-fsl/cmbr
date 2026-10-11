use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_first_root_commits_phase_receipt_lifecycle_and_probation_together() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    fixture.assert_pending().await;
    let admitted = fixture
        .owner
        .admit_first_root(fixture.request(), &invitation)
        .await
        .unwrap();
    assert_eq!(admitted.state(), State::Admitted);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
    let root = fixture
        .owner
        .register
        .member(&root_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(root.role, crgs::Role::Root);
    assert_eq!(root.lease_end, common::lease());
    assert!(root.handle.is_some());
    let probation = fixture
        .owner
        .storage
        .probation(common::SUBJECT)
        .await
        .unwrap();
    let settings = crbk::MembershipSettings::from_snapshot(fixture.snapshot.settings()).unwrap();
    assert_eq!(
        probation,
        Some(Some(
            cplc::day(common::now() as u64) + u64::from(settings.probation_days) * cplc::DAY
        ))
    );
    let claim = cgts::Claim::new(
        "cvch",
        cvch::receipt_id("original-first-root").as_bytes().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        cgts::Storage::commit(&fixture.owner.gate_claims, None, Some(&claim)).await,
        Err(cgts::Error::Refused)
    ));

    // Same receipt, member, policy and ORIGINAL lease is an exact read-only retry.
    let retry = fixture
        .owner
        .admit_first_root(fixture.request(), &invitation)
        .await
        .unwrap();
    assert_eq!(retry, admitted);
    assert_eq!(
        fixture.owner.register.member(&root_id()).await.unwrap(),
        Some(root.clone())
    );
    assert_eq!(
        fixture
            .owner
            .storage
            .probation(common::SUBJECT)
            .await
            .unwrap(),
        probation
    );
    let mut changed = fixture.request();
    changed.lease = crgs::YearMonth::new(2027, 8).unwrap();
    assert_eq!(
        fixture.owner.admit_first_root(changed, &invitation).await,
        Err(Error::Transition)
    );
    assert_eq!(
        fixture.owner.register.member(&root_id()).await.unwrap(),
        Some(root)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_actual_configured_gate_rolls_back_every_first_root_effect() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let empty = common::checked(&fixture.snapshot, common::SUBJECT, &[], common::now()).await;
    let mut request = fixture.request();
    request.gates = &empty;
    assert_eq!(
        fixture.owner.admit_first_root(request, &invitation).await,
        Err(Error::Policy)
    );
    fixture.assert_pending().await;
    // The receipt remains genuinely usable after the refused transaction.
    assert_eq!(
        fixture
            .owner
            .admit_first_root(fixture.request(), &invitation)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_phase_and_absence_cannot_admit_an_ordinary_member() {
    let fixture = Fixture::new().await;
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Uninitialized
    );
    assert_eq!(
        fixture.owner.admit_current(fixture.request()).await,
        Err(Error::Transition)
    );
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    assert_eq!(
        fixture.owner.admit_current(fixture.request()).await,
        Err(Error::Transition)
    );
    fixture.assert_pending().await;
}
