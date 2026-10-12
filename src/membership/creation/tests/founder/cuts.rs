use super::*;
use std::sync::atomic::Ordering;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_session_loss_before_commit_rolls_back_every_founder_effect() {
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    let original = f.row().await;
    f.session.remove_at = 3;
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await,
        Err(Error::Identity)
    );
    assert_eq!(f.session.calls.load(Ordering::SeqCst), 3);
    f.assert_unadmitted(&original).await;
    assert_eq!(
        f.base.owner.community_phase().await.unwrap(),
        CommunityPhase::Active
    );
    f.session = Session::new(&f.authentication);
    f.base
        .owner
        .admit_founder_admin(f.request(), &invitation)
        .await
        .unwrap();
    f.assert_admitted().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postcommit_session_loss_reports_uncertainty_and_retains_exact_effect() {
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    f.session.remove_at = 4;
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await,
        Err(Error::Unavailable)
    );
    assert_eq!(f.session.calls.load(Ordering::SeqCst), 4);
    let admitted = f.assert_admitted().await;
    let effect = f.effect().await.unwrap();
    f.session = Session::new(&f.authentication);
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await
            .unwrap(),
        admitted
    );
    assert!(f.effect().await.as_ref() == Some(&effect));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_sdk_revocation_refuses_new_founder_and_exact_effect_retry() {
    for committed in [false, true] {
        let mut f = Founder::new(true).await;
        let invitation = f.original().await;
        if committed {
            f.base
                .owner
                .admit_founder_admin(f.request(), &invitation)
                .await
                .unwrap();
        }
        let original = f.row().await;
        let effect = f.effect().await;
        let member = f.base.owner.register.member(&f.member()).await.unwrap();
        let keys = f.base.owner.passkeys.clone();
        let user = f.authentication.member();
        let credential = f.authentication.credential_id().clone();
        super::super::super::blocking(move || keys.revoke(user, &credential))
            .await
            .unwrap();
        assert_eq!(
            f.base
                .owner
                .admit_founder_admin(f.request(), &invitation)
                .await,
            Err(Error::Passkey)
        );
        assert_eq!(f.row().await, original);
        assert_eq!(
            f.base.owner.register.member(&f.member()).await.unwrap(),
            member
        );
        assert!(f.effect().await == effect);
        if !committed {
            f.assert_unadmitted(&original).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_clock_change_at_staged_final_cut_rolls_back_founder() {
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    let original = f.row().await;
    let clock = f.base.clock.clone();
    f.session.at_final_cut = Some(Box::new(move || clock.set(common::now() + 1)));
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(f.session.calls.load(Ordering::SeqCst), 3);
    f.assert_unadmitted(&original).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_legal_order_and_original_gate_timestamp_cannot_be_bypassed() {
    use ed25519_dalek::{Signer as _, SigningKey};
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    let original = f.row().await;
    let mut changed = f.request();
    changed.checked_at += 1;
    assert_eq!(
        f.base.owner.admit_founder_admin(changed, &invitation).await,
        Err(Error::Identity)
    );
    f.assert_unadmitted(&original).await;
    let order = clbs::Order {
        community: COMMUNITY.into(),
        id: "founder-current-legal-refusal".into(),
        subject: f.subject.clone(),
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
    f.base
        .owner
        .legal
        .record_legal(&clbs::SignedOrder { order, proof })
        .await
        .unwrap();
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await,
        Err(Error::Restricted)
    );
    f.assert_unadmitted(&original).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_actual_writer_wait_preserves_receipt_and_allows_genuine_retry() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    let original = f.row().await;
    let writer = f.base.db.community(COMMUNITY).unwrap().tx().await.unwrap();
    let mut operation = Box::pin(f.base.owner.admit_founder_admin(f.request(), &invitation));
    poll_fn(|context| match operation.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(_) => panic!("the genuine independent writer must prevent admission"),
    })
    .await;
    drop(operation);
    writer.rollback().await.unwrap();
    f.assert_unadmitted(&original).await;
    f.base
        .owner
        .admit_founder_admin(f.request(), &invitation)
        .await
        .unwrap();
    f.assert_admitted().await;
}
