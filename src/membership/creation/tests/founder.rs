//! Genuine SDK/SQL/Policy composition at the original external-gate boundary.
//! The joining Admin has a distinct identity from the already admitted Root.
use super::*;

mod cuts;
mod fixture;
use fixture::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn founder_commits_exact_effect_and_readonly_retry_never_renews() {
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    let root = f.base.owner.register.member(&root_id()).await.unwrap();
    let admitted = f
        .base
        .owner
        .admit_founder_admin(f.request(), &invitation)
        .await
        .unwrap();
    assert_eq!(f.assert_admitted().await, admitted);
    let effect = f.effect().await.unwrap();
    let probation = f.base.owner.storage.probation(&f.subject).await.unwrap();
    let member = f.base.owner.register.member(&f.member()).await.unwrap();
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await
            .unwrap(),
        admitted
    );
    assert!(f.effect().await.as_ref() == Some(&effect));
    assert_eq!(
        f.base.owner.storage.probation(&f.subject).await.unwrap(),
        probation
    );
    assert_eq!(
        f.base.owner.register.member(&f.member()).await.unwrap(),
        member
    );
    assert_eq!(
        f.base.owner.register.member(&root_id()).await.unwrap(),
        root
    );
    let mut changed = f.request();
    changed.lease = crgs::YearMonth::new(2027, 8).unwrap();
    assert_eq!(
        f.base.owner.admit_founder_admin(changed, &invitation).await,
        Err(Error::Transition)
    );
    let subject = f.subject.clone();
    let replacement = f
        .invitation(
            "different-founder-receipt",
            subject.as_bytes(),
            common::now() as u64 + 600,
        )
        .await;
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &replacement)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(f.assert_admitted().await, admitted);
    assert!(f.effect().await.as_ref() == Some(&effect));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn genuine_invitation_does_not_promote_an_existing_ordinary_member() {
    let mut f = Founder::new(true).await;
    let invitation = f.original().await;
    let original = f.base.owner.admit_current(f.request()).await.unwrap();
    let member = f
        .base
        .owner
        .register
        .member(&f.member())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.role, crgs::Role::Member);
    assert_eq!(
        f.base
            .owner
            .admit_founder_admin(f.request(), &invitation)
            .await,
        Err(Error::Transition)
    );
    assert_eq!(f.row().await, original);
    assert_eq!(
        f.base.owner.register.member(&f.member()).await.unwrap(),
        Some(member)
    );
    assert!(f.effect().await.is_none());
    assert!(!f.claim_present().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn founder_cannot_activate_creating_or_skip_the_actual_configured_gate() {
    let mut creating = Founder::new(false).await;
    let invitation = creating.original().await;
    let original = creating.row().await;
    assert_eq!(
        creating
            .base
            .owner
            .admit_founder_admin(creating.request(), &invitation)
            .await,
        Err(Error::Transition)
    );
    creating.assert_unadmitted(&original).await;
    assert_eq!(
        creating.base.owner.community_phase().await.unwrap(),
        CommunityPhase::Creating
    );
    let mut active = Founder::new(true).await;
    let invitation = active.original().await;
    let original = active.row().await;
    let empty = common::checked(&active.base.snapshot, &active.subject, &[], common::now()).await;
    let mut request = active.request();
    request.gates = &empty;
    assert_eq!(
        active
            .base
            .owner
            .admit_founder_admin(request, &invitation)
            .await,
        Err(Error::Policy)
    );
    active.assert_unadmitted(&original).await;
    active
        .base
        .owner
        .admit_founder_admin(active.request(), &invitation)
        .await
        .unwrap();
    active.assert_admitted().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_wrong_recipient_wrong_purpose_and_damaged_bytes_have_no_effect() {
    let mut f = Founder::new(true).await;
    let original = f.row().await;
    let invitation = f.original().await;
    let wrong = f
        .invitation(
            INVITATION_ID,
            common::SUBJECT.as_bytes(),
            common::now() as u64 + 600,
        )
        .await;
    let root_purpose = f.base.first_invitation();
    let mut damaged = invitation.clone();
    *damaged.last_mut().unwrap() ^= 1;
    for bytes in [&wrong, &root_purpose, &damaged] {
        assert_eq!(
            f.base.owner.admit_founder_admin(f.request(), bytes).await,
            Err(Error::Policy)
        );
        f.assert_unadmitted(&original).await;
    }
    // A real Policy owner itself refuses a cross-community issuance request.
    let binding = cvch::member_binding(&cvch::receipt_id(INVITATION_ID), f.subject.as_bytes());
    assert!(
        f.base
            .policy
            .issue_role_invitation(&cvch::role::Invitation {
                id: INVITATION_ID,
                community: "other-community",
                member_binding: &binding,
                purpose: cvch::role::Purpose::FounderAdmin,
                issued_at: cplc::day(common::now() as u64),
                valid_until: common::now() as u64 + 600,
            })
            .await
            .is_err()
    );
    // Independently signed external negative exercises the consuming target
    // check too, with the original fixture key already pinned by SQL Policy.
    let mut signer = cplc::csgn::Signer::new(
        COMMUNITY,
        cplc::csgn::SecretKey::from_seed(&mut [18; 32]),
        cplc::day(common::now() as u64),
        30 * cplc::DAY,
    )
    .unwrap();
    let fields = cvch::role::Invitation {
        id: INVITATION_ID,
        community: "other-community",
        member_binding: &binding,
        purpose: cvch::role::Purpose::FounderAdmin,
        issued_at: cplc::day(common::now() as u64),
        valid_until: common::now() as u64 + 600,
    };
    let bytes = signer
        .sign(
            cplc::csgn::Kind::Credential,
            &cvch::role::issuance_bytes(&fields).unwrap(),
            fields.issued_at,
            fields.valid_until,
        )
        .unwrap();
    assert_eq!(
        f.base.owner.admit_founder_admin(f.request(), &bytes).await,
        Err(Error::Policy)
    );
    f.assert_unadmitted(&original).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_expiry_refuses_first_use_and_committed_retry_without_renewal() {
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
        let member = f.base.owner.register.member(&f.member()).await.unwrap();
        let effect = f.effect().await;
        f.base.clock.set(common::now() + 600);
        assert_eq!(
            f.base
                .owner
                .admit_founder_admin(f.request(), &invitation)
                .await,
            Err(Error::Policy)
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
