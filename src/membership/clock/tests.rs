//! Real UV and signed legal expiry across the shared observation boundary.
use super::*;
use crate::test_common::{
    self as common,
    resident::{Resident, strip_prf},
    *,
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[test]
fn invalid_times_and_rollback_poison_the_same_shared_clock_without_replacing_its_floor() {
    use clbs::Clock as _;
    for invalid in [-1, i64::MAX] {
        let source = common::Clock::new();
        let clock = Arc::new(ObservedClock::new(source.clone()));
        assert_eq!(clock.now().unwrap(), now());
        source.set(invalid);
        assert_eq!(clock.now(), Err(clbs::Error::Clock));
        source.set(now() + 1);
        assert_eq!(clock.clone().now(), Err(clbs::Error::Clock));
        assert_eq!(clock.floor.load(Ordering::SeqCst), now());
    }
    let source = common::Clock::new();
    source.set(0);
    let clock = Arc::new(ObservedClock::new(source.clone()));
    assert_eq!(clock.now().unwrap(), 0);
    source.set(20);
    assert_eq!(clock.now().unwrap(), 20);
    source.set(15);
    assert_eq!(clock.now(), Err(clbs::Error::Clock));
    source.set(21);
    assert_eq!(clock.clone().now(), Err(clbs::Error::Clock));
}

struct SequenceClock(Mutex<VecDeque<i64>>);
impl clbs::Clock for SequenceClock {
    fn now(&self) -> clbs::Result<i64> {
        Ok(self.0.lock().unwrap().pop_front().unwrap_or_else(now))
    }
}

async fn register<C: clbs::Clock + 'static>(
    membership: &crate::Membership<crate::LibsqlStorage, Verify, C>,
    device: &mut Resident,
) -> crate::Login {
    let (challenge, pending) = membership.begin_registration(USER, SUBJECT).await.unwrap();
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut response);
    membership
        .finish_registration(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    let (challenge, pending) = membership.begin_discoverable_login().await.unwrap();
    // The resident fixture injects then strips PRF. This upstream optional
    // field may be absent; an empty map preserves its exact challenge and UV.
    let mut options = serde_json::to_value(challenge).unwrap();
    if options["publicKey"]["extensions"].is_null() {
        options["publicKey"]["extensions"] = serde_json::json!({});
    }
    let mut response = device.ceremony(options, false, ORIGIN).await;
    strip_prf(&mut response);
    membership
        .finish_login(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_legal_expiry_at_twenty_cannot_authorize_certificate_completion_back_at_fifteen() {
    let (_dir, db) = temporary().await;
    let community = "shared-legal-floor";
    let membership = crate::Membership::new(
        &db,
        crate::LibsqlStorage::new(&db, community).unwrap(),
        config(),
        Verify,
        SequenceClock(Mutex::default()),
    )
    .unwrap();
    let mut device = Resident::default();
    let login = register(&membership, &mut device).await;
    let mut prepared = membership
        .passkey_certificate(&login.authentication)
        .await
        .unwrap();
    let order = clbs::Order {
        community: community.into(),
        id: "temporary-signed-order".into(),
        subject: SUBJECT.into(),
        reference: "explicit signature fixture".into(),
        entered_by: "fixture-operator".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
        },
        scope: clbs::Scope::Actions([config().membership_action].into()),
        period: clbs::Period {
            starts_at: now(),
            ends_at: Some(now() + 20),
        },
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    membership
        .legal
        .record_legal(&clbs::SignedOrder { order, proof })
        .await
        .unwrap();
    *membership.clock.0.lock().unwrap() = [now(), now() + 20, now() + 15].into();
    assert_eq!(
        membership.check_certificate(&mut prepared).await,
        Err(crate::Error::Unavailable)
    );
    assert!(membership.clock.0.lock().unwrap().is_empty());
    assert_eq!(
        membership.check_certificate(&mut prepared).await,
        Err(crate::Error::Identity)
    );
    assert!(matches!(
        membership.legal.check_action(SUBJECT, "membership").await,
        Err(clbs::Error::Clock)
    ));
}

struct CryptoClock {
    observer: Mutex<Option<(Arc<ckyh::Passkeys<ckyh::LibsqlStore>>, u32)>>,
    first_after_crypto: AtomicBool,
}
impl clbs::Clock for CryptoClock {
    fn now(&self) -> clbs::Result<i64> {
        let observer = self.observer.lock().unwrap().clone();
        let Some((keys, before)) = observer else {
            return Ok(now());
        };
        let counter = std::thread::spawn(move || keys.list(USER).unwrap().pop().unwrap().counter())
            .join()
            .unwrap();
        if counter <= before {
            return Ok(now());
        }
        Ok(now()
            + if self.first_after_crypto.swap(false, Ordering::SeqCst) {
                20
            } else {
                15
            })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_successful_uv_then_in_window_rollback_withholds_confirmation_and_poisons_the_facade()
 {
    let (_dir, db) = temporary().await;
    let community = "shared-confirmation-floor";
    let membership = crate::Membership::new(
        &db,
        crate::LibsqlStorage::new(&db, community).unwrap(),
        config(),
        Verify,
        CryptoClock {
            observer: Mutex::default(),
            first_after_crypto: AtomicBool::new(true),
        },
    )
    .unwrap();
    let mut device = Resident::default();
    let login = register(&membership, &mut device).await;
    let (challenge, pending) = membership
        .begin_self_ban_confirmation(&login.authentication, ban(community).order, now() + 60)
        .await
        .unwrap();
    // The resident fixture injects then strips PRF. This upstream optional
    // field may be absent; an empty map preserves its exact challenge and UV.
    let mut options = serde_json::to_value(challenge).unwrap();
    if options["publicKey"]["extensions"].is_null() {
        options["publicKey"]["extensions"] = serde_json::json!({});
    }
    let mut response = device.ceremony(options, false, ORIGIN).await;
    strip_prf(&mut response);
    let before = membership
        .credentials(USER)
        .await
        .unwrap()
        .pop()
        .unwrap()
        .counter();
    *membership.clock.observer.lock().unwrap() = Some((membership.passkeys.clone(), before));
    assert!(matches!(
        membership
            .finish_self_ban_confirmation(
                &login.authentication,
                pending,
                serde_json::from_value(response).unwrap()
            )
            .await,
        Err(crate::Error::Unavailable)
    ));
    assert!(
        membership
            .credentials(USER)
            .await
            .unwrap()
            .pop()
            .unwrap()
            .counter()
            > before
    );
    assert!(matches!(
        membership
            .begin_self_ban_confirmation(&login.authentication, ban(community).order, now() + 60)
            .await,
        Err(crate::Error::Unavailable)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmed_uv_retains_its_latest_floor_and_exclusive_original_deadline() {
    let (_dir, db) = temporary().await;
    let clock = common::Clock::new();
    let community = "shared-returned-floor";
    let membership = facade(&db, community, clock.clone());
    let mut device = Resident::default();
    let login = register(&membership, &mut device).await;
    let (challenge, pending) = membership
        .begin_self_ban_confirmation(&login.authentication, ban(community).order, now() + 60)
        .await
        .unwrap();
    // The resident fixture injects then strips PRF. This upstream optional
    // field may be absent; an empty map preserves its exact challenge and UV.
    let mut options = serde_json::to_value(challenge).unwrap();
    if options["publicKey"]["extensions"].is_null() {
        options["publicKey"]["extensions"] = serde_json::json!({});
    }
    let mut response = device.ceremony(options, false, ORIGIN).await;
    strip_prf(&mut response);
    clock.set(now() + 20);
    let confirmed = membership
        .finish_self_ban_confirmation(
            &login.authentication,
            pending,
            serde_json::from_value(response).unwrap(),
        )
        .await
        .unwrap();
    assert!(!confirmed.is_current(now() + 15));
    assert!(confirmed.is_current(now() + 20));
    assert_eq!(confirmed.expires_at(), now() + 60);
}
