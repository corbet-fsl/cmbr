//! Actual resident UV and original immutable first-key provenance.
use super::*;
use crate::test_common as common;
use common::{
    resident::{Resident, strip_prf},
    *,
};

mod boundaries;
mod post_commit;

async fn register_original(m: &Facade, seed: Option<[u8; 32]>) -> Resident {
    let mut device = Resident::default();
    let (challenge, pending) = match seed {
        Some(seed) => m
            .begin_initial_registration(USER, SUBJECT, seed)
            .await
            .unwrap(),
        None => m.begin_registration(USER, SUBJECT).await.unwrap(),
    };
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut response);
    // Discard original committed finish response, as after a lost HTTP reply.
    m.finish_registration(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    device
}
async fn authenticate(m: &Facade, device: &mut Resident) -> Login {
    let (challenge, pending) = m.begin_discoverable_login().await.unwrap();
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
        .await;
    strip_prf(&mut response);
    m.finish_login(pending, serde_json::from_value(response).unwrap())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn genuine_original_seed_and_winning_publication_survive_lost_replies_and_reopen() {
    let (dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "creation-owner", clock.clone());
    let mut device = register_original(&m, Some([1; 32])).await;
    let login = authenticate(&m, &mut device).await;
    let original = m
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    assert_eq!(original.seed(), [1; 32]);
    assert_eq!(original.publication(), None);
    assert!(original.is_current(now()));
    drop(original);
    // Durable publication commit, but discard response and all facade instances.
    m.bind_initial_publication(&login.authentication, [1; 32], [2; 32], now() + 60)
        .await
        .unwrap();
    drop(m);
    drop(db);
    let reopened = open(
        &format!("file://{}", dir.path().join("members.db").display()),
        "",
    )
    .await;
    let restored = facade(&reopened, "creation-owner", clock.clone());
    let fresh = authenticate(&restored, &mut device).await;
    let mut winner = restored
        .initial_creation(&fresh.authentication, now() + 60)
        .await
        .unwrap();
    assert_eq!(winner.seed(), [1; 32]);
    assert_eq!(winner.publication(), Some([2; 32]));
    assert_eq!(
        restored
            .clone()
            .check_initial_creation(&mut winner)
            .await
            .unwrap(),
        now()
    );
    drop(winner);
    assert_eq!(
        restored
            .bind_initial_publication(&fresh.authentication, [1; 32], [2; 32], now() + 60)
            .await
            .unwrap()
            .publication(),
        Some([2; 32])
    );
    assert!(
        restored
            .bind_initial_publication(&fresh.authentication, [1; 32], [3; 32], now() + 60)
            .await
            .is_err()
    );
    assert!(
        restored
            .bind_initial_publication(&fresh.authentication, [3; 32], [2; 32], now() + 60)
            .await
            .is_err()
    );
    assert_eq!(
        restored
            .initial_creation(&fresh.authentication, now() + 60)
            .await
            .unwrap()
            .publication(),
        Some([2; 32])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn additional_keys_and_legacy_rows_cannot_read_or_create_genesis() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "creation-additional", Clock::new());
    let mut original = register_original(&m, Some([1; 32])).await;
    let login = authenticate(&m, &mut original).await;
    let (challenge, pending) = m
        .begin_additional_registration(&login.authentication)
        .await
        .unwrap();
    let mut additional = Resident::default();
    let mut response = additional
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut response);
    m.finish_additional_registration(
        &login.authentication,
        pending,
        serde_json::from_value(response).unwrap(),
    )
    .await
    .unwrap();
    let other = authenticate(&m, &mut additional).await;
    assert_eq!(other.authentication.member(), login.authentication.member());
    assert_ne!(
        other.authentication.credential_id(),
        login.authentication.credential_id()
    );
    assert!(
        m.initial_creation(&other.authentication, now() + 60)
            .await
            .is_err()
    );
    assert!(
        m.bind_initial_publication(&other.authentication, [1; 32], [2; 32], now() + 60)
            .await
            .is_err()
    );
    assert_eq!(
        m.initial_creation(&login.authentication, now() + 60)
            .await
            .unwrap()
            .publication(),
        None
    );
    let legacy = facade(&db, "creation-legacy", Clock::new());
    let mut legacy_device = register_original(&legacy, None).await;
    let legacy_login = authenticate(&legacy, &mut legacy_device).await;
    assert!(
        legacy
            .initial_creation(&legacy_login.authentication, now() + 60)
            .await
            .is_err()
    );
    assert!(
        legacy
            .bind_initial_publication(&legacy_login.authentication, [1; 32], [2; 32], now() + 60)
            .await
            .is_err()
    );
    assert!(
        m.begin_initial_registration(USER, SUBJECT, [3; 32])
            .await
            .is_err()
    );
    assert!(
        m.begin_initial_registration(USER, SUBJECT, [0; 32])
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn original_lease_floor_deadline_and_current_key_guard_immutable_retries() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "creation-bounds", clock.clone());
    let mut device = register_original(&m, Some([1; 32])).await;
    let login = authenticate(&m, &mut device).await;
    let mut state = m
        .bind_initial_publication(&login.authentication, [1; 32], [2; 32], now() + 60)
        .await
        .unwrap();
    assert!(!state.is_current(now() - 1));
    assert!(!state.is_current(now() + 60));
    let foreign_instance = facade(&db, "creation-bounds", clock.clone());
    assert_eq!(
        foreign_instance.check_initial_creation(&mut state).await,
        Err(Error::Identity)
    );
    assert_eq!(
        m.check_initial_creation(&mut state).await,
        Err(Error::Identity)
    );
    assert!(!state.is_current(now()));
    drop(state);
    let mut state = m
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    clock.set(now() + 5);
    assert_eq!(
        m.check_initial_creation(&mut state).await.unwrap(),
        now() + 5
    );
    clock.set(now() + 4);
    assert_eq!(
        m.check_initial_creation(&mut state).await,
        Err(Error::Identity)
    );
    drop(state);
    clock.set(now());
    let mut state = m
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    state.timing.started = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
    assert!(!state.is_current(now()));
    assert_eq!(
        m.check_initial_creation(&mut state).await,
        Err(Error::Identity)
    );
    drop(state);
    let mut state = m
        .initial_creation(&login.authentication, now() + 60)
        .await
        .unwrap();
    let credential = login.authentication.credential_id().clone();
    let mut removal = Box::pin(m.revoke_passkey(&login.authentication, credential));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), removal.as_mut())
            .await
            .is_err()
    );
    m.check_initial_creation(&mut state).await.unwrap();
    drop(state);
    removal.await.unwrap();
    assert!(
        m.bind_initial_publication(&login.authentication, [1; 32], [2; 32], now() + 60)
            .await
            .is_err()
    );
    assert!(
        m.initial_creation(&login.authentication, now() + 60)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn retained_row_expiry_also_shortens_the_original_monotonic_lifetime() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "creation-row-deadline", clock.clone());
    let mut device = register_original(&m, Some([1; 32])).await;
    let original = authenticate(&m, &mut device).await;
    let row_deadline = original.enrolment.expires_at().unwrap();
    clock.set(row_deadline - 10);
    let fresh = authenticate(&m, &mut device).await;
    let mut state = m
        .initial_creation(&fresh.authentication, row_deadline + 50)
        .await
        .unwrap();
    assert_eq!(state.timing.lifetime, Duration::from_secs(10));
    assert!(state.is_current(row_deadline - 10));
    // Wall time stays at its genuine final observation. The retained row's
    // shorter original interval must still expire without a wall advance.
    state.timing.started = Instant::now().checked_sub(Duration::from_secs(11)).unwrap();
    assert!(!state.is_current(row_deadline - 10));
    assert_eq!(
        m.check_initial_creation(&mut state).await,
        Err(Error::Identity)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_or_terminal_original_membership_refuses_equal_publication_retry() {
    for terminal in [false, true] {
        let (_dir, db) = temporary().await;
        let clock = Clock::new();
        let m = facade(&db, "creation-terminal", clock.clone());
        let mut device = register_original(&m, Some([1; 32])).await;
        let login = authenticate(&m, &mut device).await;
        m.bind_initial_publication(&login.authentication, [1; 32], [2; 32], now() + 60)
            .await
            .unwrap();
        if terminal {
            m.self_ban(&login.authentication, &ban("creation-terminal"))
                .await
                .unwrap();
        } else {
            clock.set(login.enrolment.expires_at().unwrap());
        }
        assert!(
            m.bind_initial_publication(
                &login.authentication,
                [1; 32],
                [2; 32],
                clock.0.load(std::sync::atomic::Ordering::SeqCst) + 60
            )
            .await
            .is_err()
        );
    }
}
