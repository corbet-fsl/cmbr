//! Original registered passkeys and member leases; no supplied descriptor.
use super::*;
use crate::test_common as common;
use common::*;
mod boundaries;

#[tokio::test(flavor = "multi_thread")]
async fn authenticated_certificate_keeps_the_original_member_and_exact_key() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let member = facade(&db, "certificate-owner", clock.clone());
    let (_, login) = pending(&member, "certificate-owner").await;
    let mut prepared = member
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    assert_eq!(prepared.certificate().community(), "certificate-owner");
    assert_eq!(prepared.certificate().member(), SUBJECT);
    assert_eq!(
        prepared.certificate().credential_id(),
        login.authentication.credential_id().as_ref()
    );
    assert_eq!(
        member.check_certificate(&mut prepared).await.unwrap(),
        now() as u64
    );
    assert_eq!(
        member
            .clone()
            .check_certificate(&mut prepared)
            .await
            .unwrap(),
        now() as u64
    );
    let foreign = facade(&db, "foreign-certificate-owner", clock.clone());
    assert_eq!(
        foreign.check_certificate(&mut prepared).await,
        Err(Error::Identity)
    );
    assert_eq!(
        member.check_certificate(&mut prepared).await,
        Err(Error::Identity)
    );
    drop(prepared);
    let mut prepared = member
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    clock.set(now() - 1);
    assert_eq!(
        member.check_certificate(&mut prepared).await,
        Err(Error::Unavailable)
    );
    drop(prepared);
    clock.set(now());
    // A poisoned owner never recovers automatically; the next independent
    // expiry scenario starts a fresh facade over the same genuine stored key.
    let member = facade(&db, "certificate-owner", clock.clone());
    let mut prepared = member
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    clock.set(prepared.enrolment.expires_at().unwrap());
    assert!(member.check_certificate(&mut prepared).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_lease_blocks_revocation_and_revoked_keys_cannot_renew() {
    let (_dir, db) = temporary().await;
    let member = facade(&db, "certificate-revocation", Clock::new());
    let (_, login) = pending(&member, "certificate-revocation").await;
    let mut prepared = member
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    let credential = login.authentication.credential_id().clone();
    let mut revoke = Box::pin(member.revoke_passkey(&login.authentication, credential.clone()));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), revoke.as_mut())
            .await
            .is_err()
    );
    member.check_certificate(&mut prepared).await.unwrap();
    drop(prepared);
    revoke.await.unwrap();
    assert!(matches!(
        member.passkey_certificate(&login.authentication).await,
        Err(Error::Passkey)
    ));
    let event = member.revocations(10).await.unwrap().pop().unwrap();
    assert_eq!(
        member.revoked_passkeys(&event).await.unwrap(),
        vec![credential.as_ref().to_vec()]
    );
    let foreign = facade(&db, "foreign-revocation", Clock::new());
    assert!(foreign.revoked_passkeys(&event).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_later_certificate_check_cannot_regress_to_a_time_after_initial_preparation() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let member = facade(&db, "certificate-clock-floor", clock.clone());
    let (_, login) = pending(&member, "certificate-clock-floor").await;
    let mut prepared = member
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    clock.set(now() + 20);
    assert_eq!(
        member.check_certificate(&mut prepared).await.unwrap(),
        (now() + 20) as u64
    );
    clock.set(now() + 10);
    assert_eq!(
        member.check_certificate(&mut prepared).await,
        Err(Error::Identity)
    );
    clock.set(now() + 30);
    assert_eq!(
        member.check_certificate(&mut prepared).await,
        Err(Error::Identity)
    );
}
