//! Original false Policy decisions join lifecycle and revocation in one writer.
use super::*;
use std::sync::atomic::Ordering;

async fn admitted(fixture: &Fixture) -> Record {
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let row = fixture
        .owner
        .admit_first_root(fixture.request(), &invitation)
        .await
        .unwrap();
    assert_eq!(row.state(), State::Admitted);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
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
        crgs::Role::Root
    );
    assert!(fixture.owner.revocations(10).await.unwrap().is_empty());
    // Reset only the fixture's measurement; the real session, its expiry and
    // the Membership owner's original observed-clock floor remain unchanged.
    fixture.session.calls.store(0, Ordering::SeqCst);
    row
}

async fn empty(fixture: &Fixture) -> cgts::CheckedGates {
    common::checked(&fixture.snapshot, common::SUBJECT, &[], common::now()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_negative_decision_lapses_admission_and_signals_once_in_same_writer() {
    let fixture = Fixture::new().await;
    let original = admitted(&fixture).await;
    let register = fixture.owner.register.member(&root_id()).await.unwrap();
    let probation = fixture
        .owner
        .storage
        .probation(common::SUBJECT)
        .await
        .unwrap();
    let gates = empty(&fixture).await;
    let mut request = fixture.request();
    request.gates = &gates;
    let lapsed = fixture.owner.lapse_current(request).await.unwrap();
    assert_eq!(lapsed.state(), State::Lapsed);
    assert_ne!(lapsed, original);
    assert_eq!(fixture.session.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture
            .owner
            .enrol
            .view(common::USER, fixture.owner.now().unwrap())
            .await
            .unwrap(),
        lapsed
    );
    assert_eq!(
        fixture.owner.register.member(&root_id()).await.unwrap(),
        register
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
    let events = fixture.owner.revocations(10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].member, common::SUBJECT);
    assert_eq!(events[0].generation, 1);
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
    let mut retry = fixture.request();
    retry.gates = &gates;
    assert_eq!(fixture.owner.lapse_current(retry).await.unwrap(), lapsed);
    assert_eq!(fixture.owner.revocations(10).await.unwrap(), events);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_original_session_refusal_rolls_back_lapse_and_revocation_together() {
    let mut fixture = Fixture::new().await;
    let original = admitted(&fixture).await;
    let gates = empty(&fixture).await;
    fixture.session.remove_at = 2;
    let mut request = fixture.request();
    request.gates = &gates;
    assert_eq!(
        fixture.owner.lapse_current(request).await,
        Err(Error::Identity)
    );
    assert_eq!(fixture.session.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .owner
            .enrol
            .view(common::USER, fixture.owner.now().unwrap())
            .await
            .unwrap(),
        original
    );
    assert!(fixture.owner.revocations(10).await.unwrap().is_empty());
    assert!(
        !fixture
            .owner
            .storage
            .revocation_pending(common::SUBJECT)
            .await
            .unwrap()
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_session_loss_withholds_result_but_retains_committed_lapse_and_notice() {
    let mut fixture = Fixture::new().await;
    admitted(&fixture).await;
    let gates = empty(&fixture).await;
    fixture.session.remove_at = 3;
    let mut request = fixture.request();
    request.gates = &gates;
    assert_eq!(
        fixture.owner.lapse_current(request).await,
        Err(Error::Unavailable)
    );
    assert_eq!(fixture.session.calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture
            .owner
            .enrol
            .view(common::USER, fixture.owner.now().unwrap())
            .await
            .unwrap()
            .state(),
        State::Lapsed
    );
    let events = fixture.owner.revocations(10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].member, common::SUBJECT);
    assert!(
        fixture
            .owner
            .storage
            .revocation_pending(common::SUBJECT)
            .await
            .unwrap()
    );
    assert_eq!(
        fixture.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negative_decision_never_activates_creating_or_grants_a_root() {
    let fixture = Fixture::new().await;
    let invitation = fixture.first_invitation();
    fixture.initialize(&invitation).await;
    let gates = empty(&fixture).await;
    let mut request = fixture.request();
    request.gates = &gates;
    let row = fixture.owner.lapse_current(request).await.unwrap();
    // Original CNrl records gate progress for a reserved, never-admitted row.
    assert_eq!(row.state(), State::GatesInProgress);
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
    assert!(fixture.owner.revocations(10).await.unwrap().is_empty());
    // Its genuine unspent original entitlement still permits full admission,
    // independently recomputed through the same SQL Policy and checked gates.
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
async fn positive_decision_cannot_use_lapse_endpoint_to_change_membership() {
    let fixture = Fixture::new().await;
    let original = admitted(&fixture).await;
    assert_eq!(
        fixture.owner.lapse_current(fixture.request()).await,
        Err(Error::Policy)
    );
    assert_eq!(
        fixture
            .owner
            .enrol
            .view(common::USER, fixture.owner.now().unwrap())
            .await
            .unwrap(),
        original
    );
    assert!(fixture.owner.revocations(10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_checked_gate_context_cannot_be_rebound_to_a_different_verification_time() {
    let fixture = Fixture::new().await;
    let original = admitted(&fixture).await;
    let gates = empty(&fixture).await;
    for (checked_at, error) in [
        (common::now() as u64 + 1, Error::Identity),
        (common::now() as u64 - 1, Error::Policy),
    ] {
        let mut request = fixture.request();
        request.gates = &gates;
        request.checked_at = checked_at;
        assert_eq!(fixture.owner.lapse_current(request).await, Err(error));
    }
    assert_eq!(
        fixture
            .owner
            .enrol
            .view(common::USER, fixture.owner.now().unwrap())
            .await
            .unwrap(),
        original,
    );
    assert!(fixture.owner.revocations(10).await.unwrap().is_empty());
}
