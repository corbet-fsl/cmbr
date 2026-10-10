use super::*;
#[path = "../../../tests/common/mod.rs"]
mod common;
use common::{
    resident::{Resident, strip_prf},
    *,
};

async fn register_resident(m: &Facade) -> Resident {
    let mut device = Resident::default();
    let (challenge, registration) = m.begin_registration(USER, SUBJECT).await.unwrap();
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut response);
    m.finish_registration(registration, serde_json::from_value(response).unwrap())
        .await
        .unwrap();
    device
}
async fn response(
    device: &mut Resident,
    challenge: ckyh::RequestChallengeResponse,
) -> ckyh::PublicKeyCredential {
    let mut response = device
        .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
        .await;
    strip_prf(&mut response);
    serde_json::from_value(response).unwrap()
}
async fn authenticate(m: &Facade, device: &mut Resident) -> cmbr::Login {
    let (challenge, state) = m.begin_discoverable_login().await.unwrap();
    m.finish_login(state, response(device, challenge).await)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn fresh_original_uv_reads_only_committed_receipt_even_after_terminal_state_and_clock_rollback()
 {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "status", clock.clone());
    let mut device = register_resident(&m).await;
    let login = authenticate(&m, &mut device).await;
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    assert!(
        !m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await
            .unwrap()
            .self_banned
    );
    m.self_ban(&login.authentication, &ban("status"))
        .await
        .unwrap();
    assert!(m.resume(&login.authentication).await.is_err());
    clock.set(now() - 1);
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    assert!(
        m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await
            .unwrap()
            .self_banned
    );
    clock.set(now());
    let (challenge, pending) = m.begin_discoverable_login().await.unwrap();
    assert!(
        m.finish_login(pending, response(&mut device, challenge).await)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn login_assertion_replay_and_foreign_instance_cannot_answer_receipt_ceremony() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "status-purpose", Clock::new());
    let mut device = register_resident(&m).await;
    let (challenge, login) = m.begin_discoverable_login().await.unwrap();
    let (_, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    let credential = response(&mut device, challenge).await;
    let copy = serde_json::from_value(serde_json::to_value(&credential).unwrap()).unwrap();
    m.finish_login(login, credential).await.unwrap();
    assert!(matches!(
        m.finish_self_ban_status(pending, copy).await,
        Err(Error::Passkey)
    ));
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    let credential = response(&mut device, challenge).await;
    let copy = serde_json::from_value(serde_json::to_value(&credential).unwrap()).unwrap();
    assert!(
        !m.finish_self_ban_status(pending, credential)
            .await
            .unwrap()
            .self_banned
    );
    let (_, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    assert!(matches!(
        m.finish_self_ban_status(pending, copy).await,
        Err(Error::Passkey)
    ));
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    let reopened = facade(&db, "status-purpose", Clock::new());
    assert!(matches!(
        reopened
            .finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await,
        Err(Error::Passkey)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn revoked_original_key_and_wall_or_monotonic_deadline_refuse_receipt_read() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "status-expiry", clock.clone());
    let mut device = register_resident(&m).await;
    let login = authenticate(&m, &mut device).await;
    for expires in [now(), now() + 301, i64::MAX] {
        assert!(matches!(
            m.begin_self_ban_status(expires).await,
            Err(Error::InvalidInput)
        ));
    }
    let (challenge, pending) = m.begin_self_ban_status(now() + 1).await.unwrap();
    clock.set(now() + 1);
    assert!(matches!(
        m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await,
        Err(Error::Passkey)
    ));
    clock.set(now());
    let (challenge, mut pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    pending.started = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
    assert!(matches!(
        m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await,
        Err(Error::Passkey)
    ));
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    m.revoke_passkey(
        &login.authentication,
        login.authentication.credential_id().clone(),
    )
    .await
    .unwrap();
    assert!(matches!(
        m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await,
        Err(Error::Passkey)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_original_enrolment_and_unavailable_storage_never_become_false() {
    let (_dir, db) = temporary().await;
    let m = facade(&db, "status-original", Clock::new());
    let mut device = register_resident(&m).await;
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    db.community("status-original")
        .unwrap()
        .execute(
            "DELETE FROM cnrl_enrolments WHERE user_id = ?1",
            [USER.to_string()],
        )
        .await
        .unwrap();
    assert!(matches!(
        m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await,
        Err(Error::Unavailable)
    ));
    let m = facade(&db, "status-storage", Clock::new());
    let mut device = register_resident(&m).await;
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    let login = authenticate(&m, &mut device).await;
    m.self_ban(&login.authentication, &ban("status-storage"))
        .await
        .unwrap();
    db.community("status-storage")
        .unwrap()
        .execute(
            "UPDATE clbs_orders SET reference = ?1 WHERE id = ?2",
            ["", "confirmed-self-ban"],
        )
        .await
        .unwrap();
    assert!(
        m.finish_self_ban_status(pending, response(&mut device, challenge).await)
            .await
            .is_err()
    );
}

struct CrossingClock(std::sync::atomic::AtomicUsize);
impl clbs::Clock for CrossingClock {
    fn now(&self) -> clbs::Result<i64> {
        use std::sync::atomic::Ordering;
        Ok(
            if self
                .0
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                now()
            } else {
                now() + 60
            },
        )
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn deadline_crossed_after_real_crypto_commit_withholds_receipt() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (_dir, db) = temporary().await;
    let m = cmbr::Membership::new(
        &db,
        cmbr::LibsqlStorage::new(&db, "status-crossing").unwrap(),
        config(),
        Verify,
        CrossingClock(AtomicUsize::new(usize::MAX)),
    )
    .unwrap();
    let mut device = Resident::default();
    let (challenge, pending) = m.begin_registration(USER, SUBJECT).await.unwrap();
    let mut credential = device
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut credential);
    m.finish_registration(pending, serde_json::from_value(credential).unwrap())
        .await
        .unwrap();
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    let credential = response(&mut device, challenge).await;
    let before = m.credentials(USER).await.unwrap().pop().unwrap().counter();
    m.clock.0.store(1, Ordering::SeqCst);
    assert!(matches!(
        m.finish_self_ban_status(pending, credential).await,
        Err(Error::Passkey)
    ));
    assert!(m.credentials(USER).await.unwrap().pop().unwrap().counter() > before);
}

struct SequenceClock(std::sync::Mutex<std::collections::VecDeque<i64>>);
impl clbs::Clock for SequenceClock {
    fn now(&self) -> clbs::Result<i64> {
        Ok(self.0.lock().unwrap().pop_front().unwrap_or_else(now))
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn observed_in_window_rollback_while_waiting_for_member_lease_refuses_after_genuine_uv() {
    let (_dir, db) = temporary().await;
    let m = cmbr::Membership::new(
        &db,
        cmbr::LibsqlStorage::new(&db, "status-floor").unwrap(),
        config(),
        Verify,
        SequenceClock(std::sync::Mutex::default()),
    )
    .unwrap();
    let mut device = Resident::default();
    let (challenge, pending) = m.begin_registration(USER, SUBJECT).await.unwrap();
    let mut credential = device
        .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
        .await;
    strip_prf(&mut credential);
    m.finish_registration(pending, serde_json::from_value(credential).unwrap())
        .await
        .unwrap();
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    let credential = response(&mut device, challenge).await;
    let before = m.credentials(USER).await.unwrap().pop().unwrap().counter();
    let lease = crate::storage::member_lock("status-floor", USER).await;
    *m.clock.0.lock().unwrap() = [now(), now() + 10, now() + 5].into();
    let finish = m.finish_self_ban_status(pending, credential);
    tokio::pin!(finish);
    // Poll the real finish until it is awaiting the held member lease. The
    // original upstream crypto must already have committed its counter, and
    // the post-crypto clock sample must have consumed the second sequence value.
    let wait = async {
        loop {
            if m.credentials(USER).await.unwrap().pop().unwrap().counter() > before
                && m.clock.0.lock().unwrap().len() == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        result = &mut finish => panic!("finish must wait for the original member lease: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(5), wait) => result.unwrap(),
    }
    drop(lease);
    assert!(matches!(finish.await, Err(Error::Passkey)));
    assert!(m.clock.0.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn original_pending_and_finished_output_timing_cannot_be_extended_by_the_host() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let m = facade(&db, "status-output", clock.clone());
    let mut device = register_resident(&m).await;
    let (challenge, pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    assert_eq!(pending.observed_at(), now());
    assert!(pending.is_current(now()));
    assert!(!pending.is_current(now() - 1));
    assert!(!pending.is_current(now() + 60));
    clock.set(now() + 10);
    let mut finished = m
        .finish_self_ban_status(pending, response(&mut device, challenge).await)
        .await
        .unwrap();
    assert_eq!(finished.observed_at(), now() + 10);
    assert!(finished.is_current(now() + 10));
    assert!(!finished.is_current(now() + 5));
    assert!(!finished.is_current(now() + 60));
    // The result retains the actual original Instant; a host cannot replace it
    // with a new deadline merely because the leaf has returned its boolean.
    finished.started = Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
    assert!(!finished.is_current(now() + 10));
    let (_, mut pending) = m.begin_self_ban_status(now() + 60).await.unwrap();
    pending.started = Instant::now().checked_sub(Duration::from_secs(51)).unwrap();
    assert!(!pending.is_current(now() + 10));
}
