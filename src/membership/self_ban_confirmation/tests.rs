use super::*;

mod queue;
use crate::test_common as common;
use common::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

fn order(community: &str) -> clbs::Order {
    ban(community).order
}
fn assertion(
    device: &mut SoftToken,
    challenge: ckyh::RequestChallengeResponse,
) -> ckyh::PublicKeyCredential {
    device
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap()
        .into()
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_fresh_dedicated_uv_ceremony_confirms_the_exact_immutable_order() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "self-ban", Clock::new());
    let (mut device, login) = pending(&m, "self-ban").await;
    let expected = order("self-ban");
    let expires = now() + 60;
    let (challenge, state) = m
        .begin_self_ban_confirmation(&login.authentication, expected.clone(), expires)
        .await
        .unwrap();
    let response = assertion(&mut device, challenge);
    let copied: ckyh::PublicKeyCredential =
        serde_json::from_value(serde_json::to_value(&response).unwrap()).unwrap();
    let confirmed = m
        .finish_self_ban_confirmation(&login.authentication, state, response)
        .await
        .unwrap();
    assert_eq!(confirmed.order(), &expected);
    assert_eq!(confirmed.member(), USER);
    assert_eq!(
        confirmed.credential_id(),
        login.authentication.credential_id()
    );
    assert_eq!(confirmed.expires_at(), expires);
    assert!(confirmed.is_current(now()));
    assert!(!confirmed.is_current(now() - 1));
    assert!(!confirmed.is_current(expires));
    // An already signed assertion cannot answer another dedicated challenge.
    let (_, another) = m
        .begin_self_ban_confirmation(&login.authentication, expected, expires)
        .await
        .unwrap();
    assert!(matches!(
        m.finish_self_ban_confirmation(&login.authentication, another, copied)
            .await,
        Err(Error::Passkey)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_login_assertion_cannot_complete_a_self_ban_challenge() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "self-ban-login", Clock::new());
    let (mut device, login) = pending(&m, "self-ban-login").await;
    let (login_challenge, login_state) = m
        .begin_login(USER, login.authentication.credential_id().clone())
        .await
        .unwrap();
    let (_, confirmation) = m
        .begin_self_ban_confirmation(&login.authentication, order("self-ban-login"), now() + 60)
        .await
        .unwrap();
    let response = assertion(&mut device, login_challenge);
    let copied = serde_json::from_value(serde_json::to_value(&response).unwrap()).unwrap();
    m.finish_login(login_state, response).await.unwrap();
    assert!(matches!(
        m.finish_self_ban_confirmation(&login.authentication, confirmation, copied)
            .await,
        Err(Error::Passkey)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_subject_community_actor_kind_period_and_deadline_cannot_begin_confirmation() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "self-ban-input", Clock::new());
    let (_, login) = pending(&m, "self-ban-input").await;
    let expected = order("self-ban-input");
    let mut invalid = Vec::new();
    let mut value = expected.clone();
    value.community = "other".into();
    invalid.push(value);
    let mut value = expected.clone();
    value.subject = "other".into();
    value.entered_by = "other".into();
    invalid.push(value);
    let mut value = expected.clone();
    value.entered_by = "root".into();
    invalid.push(value);
    let mut value = expected.clone();
    value.kind = clbs::OrderKind::Legal {
        authority: "court".into(),
    };
    invalid.push(value);
    let mut value = expected.clone();
    value.reference.clear();
    invalid.push(value);
    for value in invalid {
        assert!(
            m.begin_self_ban_confirmation(&login.authentication, value, now() + 60)
                .await
                .is_err()
        );
    }
    for expires in [now() - 1, now(), now() + 301, i64::MAX] {
        assert!(matches!(
            m.begin_self_ban_confirmation(&login.authentication, expected.clone(), expires)
                .await,
            Err(Error::InvalidInput)
        ));
    }
    assert!(
        m.begin_self_ban_confirmation(&login.authentication, expected, now() + 300)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn confirmation_cannot_move_to_another_member_or_passkey_instance() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "self-ban-instance", clock.clone());
    let (mut device, first) = pending(&m, "self-ban-instance").await;
    let another_user = Uuid::from_u128(2);
    let mut other_device = register(&m, another_user, "other-subject").await;
    let second = login(&m, &mut other_device, another_user).await;
    let (challenge, state) = m
        .begin_self_ban_confirmation(
            &first.authentication,
            order("self-ban-instance"),
            now() + 60,
        )
        .await
        .unwrap();
    assert!(matches!(
        m.finish_self_ban_confirmation(
            &second.authentication,
            state,
            assertion(&mut device, challenge)
        )
        .await,
        Err(Error::Identity)
    ));
    let (challenge, state) = m
        .begin_self_ban_confirmation(
            &first.authentication,
            order("self-ban-instance"),
            now() + 60,
        )
        .await
        .unwrap();
    let reopened = facade(&db, "self-ban-instance", clock);
    assert!(matches!(
        reopened
            .finish_self_ban_confirmation(
                &first.authentication,
                state,
                assertion(&mut device, challenge)
            )
            .await,
        Err(Error::Passkey)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_authority_and_wall_clock_or_monotonic_expiry_cannot_confirm() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "self-ban-expiry", clock.clone());
    let (mut device, login) = pending(&m, "self-ban-expiry").await;
    let (challenge, state) = m
        .begin_self_ban_confirmation(&login.authentication, order("self-ban-expiry"), now() + 1)
        .await
        .unwrap();
    clock.set(now() + 1);
    assert!(matches!(
        m.finish_self_ban_confirmation(
            &login.authentication,
            state,
            assertion(&mut device, challenge)
        )
        .await,
        Err(Error::InvalidInput)
    ));
    clock.set(now());
    let m = facade(&db, "self-ban-expiry", clock.clone());
    let (challenge, mut state) = m
        .begin_self_ban_confirmation(&login.authentication, order("self-ban-expiry"), now() + 60)
        .await
        .unwrap();
    state.started = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
    assert!(matches!(
        m.finish_self_ban_confirmation(
            &login.authentication,
            state,
            assertion(&mut device, challenge)
        )
        .await,
        Err(Error::InvalidInput)
    ));
    let (challenge, state) = m
        .begin_self_ban_confirmation(&login.authentication, order("self-ban-expiry"), now() + 60)
        .await
        .unwrap();
    m.revoke_passkey(
        &login.authentication,
        login.authentication.credential_id().clone(),
    )
    .await
    .unwrap();
    assert!(matches!(
        m.finish_self_ban_confirmation(
            &login.authentication,
            state,
            assertion(&mut device, challenge)
        )
        .await,
        Err(Error::Passkey)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn another_equal_standing_passkey_cannot_take_over_an_existing_confirmation() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "self-ban-key", Clock::new());
    let (mut original, first) = pending(&m, "self-ban-key").await;
    let mut another = SoftToken::new(true).unwrap().0;
    let (mut challenge, registration) = m
        .begin_additional_registration(&first.authentication)
        .await
        .unwrap();
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response = another
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    m.finish_additional_registration(&first.authentication, registration, response.into())
        .await
        .unwrap();
    let second = login(&m, &mut another, USER).await;
    let (challenge, confirmation) = m
        .begin_self_ban_confirmation(&first.authentication, order("self-ban-key"), now() + 60)
        .await
        .unwrap();
    assert!(matches!(
        m.finish_self_ban_confirmation(
            &second.authentication,
            confirmation,
            assertion(&mut original, challenge)
        )
        .await,
        Err(Error::Identity)
    ));
    // The second equal-standing passkey can start and complete its own intent.
    let (challenge, confirmation) = m
        .begin_self_ban_confirmation(&second.authentication, order("self-ban-key"), now() + 60)
        .await
        .unwrap();
    assert!(
        m.finish_self_ban_confirmation(
            &second.authentication,
            confirmation,
            assertion(&mut another, challenge)
        )
        .await
        .is_ok()
    );
}

struct CrossingClock {
    remaining: std::sync::atomic::AtomicUsize,
}
impl clbs::Clock for CrossingClock {
    fn now(&self) -> clbs::Result<i64> {
        use std::sync::atomic::Ordering;
        match self
            .remaining
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                value.checked_sub(1)
            }) {
            Ok(_) => Ok(now()),
            Err(_) => Ok(now() + 60),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn expiry_after_real_awaited_webauthn_verification_withholds_confirmation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_dir, db) = temporary().await;
    let m = cmbr::Membership::new(
        &db,
        cmbr::LibsqlStorage::new(&db, "self-ban-crossing").unwrap(),
        config(),
        Verify,
        CrossingClock {
            remaining: AtomicUsize::new(usize::MAX),
        },
    )
    .unwrap();
    let mut device = SoftToken::new(true).unwrap().0;
    let (mut options, registration) = m.begin_registration(USER, SUBJECT).await.unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response = device
        .perform_register(
            ckyh::Url::parse(ORIGIN).unwrap(),
            options.public_key,
            300_000,
        )
        .unwrap();
    m.finish_registration(registration, response.into())
        .await
        .unwrap();
    let credential = m
        .credentials(USER)
        .await
        .unwrap()
        .pop()
        .unwrap()
        .credential_id()
        .clone();
    let (challenge, login) = m.begin_login(USER, credential).await.unwrap();
    let auth = m
        .finish_login(login, assertion(&mut device, challenge))
        .await
        .unwrap()
        .authentication;
    let (challenge, confirmation) = m
        .begin_self_ban_confirmation(&auth, order("self-ban-crossing"), now() + 60)
        .await
        .unwrap();
    let response = assertion(&mut device, challenge);
    let before = m.credentials(USER).await.unwrap().pop().unwrap().counter();
    // The first two clock reads precede the awaited WebAuthn verification;
    // the next read crosses the exclusive confirmation deadline.
    m.clock.remaining.store(2, Ordering::SeqCst);
    assert!(matches!(
        m.finish_self_ban_confirmation(&auth, confirmation, response)
            .await,
        Err(Error::InvalidInput)
    ));
    let after = m.credentials(USER).await.unwrap().pop().unwrap().counter();
    assert!(
        after > before,
        "the actual upstream verification committed its counter before expiry was refused"
    );
}
