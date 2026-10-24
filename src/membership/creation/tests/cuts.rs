use super::*;
use ed25519_dalek::{Signer as _, SigningKey};
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_sdk_and_policy_writers_are_excluded_at_staged_root_final_cut() {
    use crbk::Storage as _;
    let mut fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let keys = fixture.owner.passkeys.clone();
    let user = fixture.authentication.member();
    let credential = fixture.authentication.credential_id().clone();
    let rules = crbk::LibsqlStore::new(fixture.db.clone());
    let retained = rules
        .load(COMMUNITY, crbk::Selection::Latest)
        .await
        .unwrap()
        .unwrap();
    let revision = retained.revision;
    let mut change = retained.change;
    change.policy_epoch += 1;
    fixture.session.at_final_cut = Some(Box::new(move || {
        let keys = keys.clone();
        let credential = credential.clone();
        assert_eq!(
            std::thread::spawn(move || keys.revoke(user, &credential))
                .join()
                .unwrap(),
            Err(ckyh::Error::Storage)
        );
        let rules = rules.clone();
        let change = change.clone();
        let write = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(rules.append(COMMUNITY, Some(revision), change))
        })
        .join()
        .unwrap();
        assert!(matches!(write, Err(crbk::Error::Storage)));
    }));
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    assert!(fixture.session.calls.load(Ordering::SeqCst) >= 3);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
    assert_eq!(
        fixture.policy.epoch(common::now() as u64).await.unwrap(),
        fixture.snapshot.settings().policy_epoch
    );
    // The actual SDK writer becomes usable immediately after the owned cut.
    let keys = fixture.owner.passkeys.clone();
    let credential = fixture.authentication.credential_id().clone();
    super::super::blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Passkey)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crossed_session_end_at_final_staged_cut_rolls_back() {
    let mut fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let clock = fixture.clock.clone();
    let end = fixture.session.until as i64;
    fixture.session.at_final_cut = Some(Box::new(move || clock.set(end)));
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(fixture.session.calls.load(Ordering::SeqCst), 3);
    fixture.assert_pending().await;
}

/// Commit authorities evaluate at the observed time: a live second passing during
/// the staged admission, with no scheduled boundary in between, commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_later_second_at_final_staged_cut_commits() {
    let mut fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let clock = fixture.clock.clone();
    fixture.session.at_final_cut = Some(Box::new(move || clock.set(common::now() + 1)));
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_original_session_after_await_rolls_back_staged_first_root() {
    let mut fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    // The original session owner invalidates THIS instance at its third live
    // check, after the real transaction has staged all admission effects.
    fixture.session.remove_at = 3;
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Identity)
    );
    assert_eq!(fixture.session.calls.load(Ordering::SeqCst), 3);
    fixture.assert_pending().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_loss_after_actual_commit_is_uncertain_and_never_claims_rollback() {
    let mut fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    fixture.session.remove_at = 4;
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Unavailable)
    );
    assert_eq!(fixture.session.calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
    assert_eq!(
        fixture
            .owner
            .enrol
            .view(common::USER, fixture.owner.now().unwrap())
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
    assert_eq!(
        fixture
            .owner
            .register
            .member(&root_id())
            .await
            .unwrap()
            .unwrap()
            .role,
        crgs::Role::Admin
    );
    assert!(
        fixture
            .owner
            .storage
            .probation(common::SUBJECT)
            .await
            .unwrap()
            .is_some()
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_real_writer_wait_never_spends_or_admits_and_allows_exact_retry() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let writer = fixture.db.community(COMMUNITY).unwrap().tx().await.unwrap();
    let mut operation = Box::pin(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation),
    );
    poll_fn(|context| match operation.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        // A local SQLite file waits for the competing writer inside the first poll (busy timeout of the fixture), so
        // the wait ends either still pending (cancelled by the drop below) or as the busy refusal; what must never
        // happen is an admission. Which one occurs depends on scheduling, so both are accepted.
        Poll::Ready(Err(crate::Error::Unavailable)) => Poll::Ready(()),
        Poll::Ready(other) => {
            panic!("the actual competing writer must prevent admission: {other:?}")
        }
    })
    .await;
    drop(operation);
    writer.rollback().await.unwrap();
    fixture.assert_pending().await;
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await
            .unwrap()
            .state(),
        State::Admitted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_sdk_revocation_refuses_first_root_without_spending_the_invitation() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let keys = fixture.owner.passkeys.clone();
    let user = fixture.authentication.member();
    let credential = fixture.authentication.credential_id().clone();
    super::super::blocking(move || keys.revoke(user, &credential))
        .await
        .unwrap();
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Passkey)
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Creating
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
    assert!(
        fixture
            .owner
            .storage
            .probation(common::SUBJECT)
            .await
            .unwrap()
            .is_none()
    );
    let claim = cgts::Claim::new(
        "cvch",
        cvch::receipt_id("original-first-root").as_bytes().to_vec(),
    )
    .unwrap();
    cgts::Storage::commit(&fixture.owner.gate_claims, None, Some(&claim))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_current_legal_order_prevents_root_and_preserves_creation() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let order = clbs::Order {
        community: COMMUNITY.into(),
        id: "first-root-legal-refusal".into(),
        subject: common::SUBJECT.into(),
        reference: "original signature fixture".into(),
        entered_by: "fixture-operator".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
        },
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    fixture
        .owner
        .legal
        .record_legal(&clbs::SignedOrder { order, proof })
        .await
        .unwrap();
    assert_eq!(
        fixture
            .owner
            .admit_first_admin(fixture.request(), &invitation)
            .await,
        Err(Error::Restricted)
    );
    fixture.assert_pending().await;
}
