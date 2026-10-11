//! Actual current-key and post-await certificate boundaries.
use super::*;
use crate::LibsqlStorage;

#[tokio::test(flavor = "multi_thread")]
async fn original_public_key_view_does_not_survive_an_actual_sdk_revocation() {
    let (_dir, db) = temporary().await;
    let membership = facade(&db, "certificate-sdk-revocation", Clock::new());
    let (_, login) = pending(&membership, "certificate-sdk-revocation").await;
    let mut prepared = membership
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    assert_eq!(
        prepared.passkey().credential_id(),
        login.authentication.credential_id()
    );
    assert_eq!(prepared.passkey().member(), USER);
    let keys = membership.passkeys.clone();
    let credential = login.authentication.credential_id().clone();
    tokio::task::spawn_blocking(move || keys.revoke(USER, &credential))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        membership.check_certificate(&mut prepared).await,
        Err(Error::Passkey)
    );
    assert_eq!(
        membership.check_certificate(&mut prepared).await,
        Err(Error::Identity)
    );
}

#[derive(Clone)]
struct CompletionClock {
    observations: Arc<std::sync::atomic::AtomicUsize>,
    deadline: Arc<std::sync::atomic::AtomicI64>,
}
impl clbs::Clock for CompletionClock {
    fn now(&self) -> clbs::Result<i64> {
        use std::sync::atomic::Ordering;
        let deadline = self.deadline.load(Ordering::SeqCst);
        if deadline == 0 {
            return Ok(now());
        }
        Ok(if self.observations.fetch_add(1, Ordering::SeqCst) == 0 {
            now()
        } else {
            deadline
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn real_certificate_completion_refuses_the_original_row_deadline_reached_during_awaits() {
    use std::sync::atomic::Ordering;
    let (_dir, db) = temporary().await;
    let clock = CompletionClock {
        observations: Arc::default(),
        deadline: Arc::default(),
    };
    let membership = Membership::new(
        &db,
        LibsqlStorage::new(&db, "certificate-completion-expiry").unwrap(),
        config(),
        Verify,
        clock.clone(),
    )
    .unwrap();
    let mut device = common::resident::Resident::default();
    let (challenge, pending) = membership.begin_registration(USER, SUBJECT).await.unwrap();
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    common::resident::strip_prf(&mut response);
    membership
        .finish_registration(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    let (challenge, pending) = membership.begin_discoverable_login().await.unwrap();
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
        .await;
    common::resident::strip_prf(&mut response);
    let login = membership
        .finish_login(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    let mut prepared = membership
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    clock
        .deadline
        .store(prepared.enrolment.expires_at().unwrap(), Ordering::SeqCst);
    assert_eq!(
        membership.check_certificate(&mut prepared).await,
        Err(Error::Transition)
    );
    assert!(clock.observations.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        membership.check_certificate(&mut prepared).await,
        Err(Error::Identity)
    );
}
