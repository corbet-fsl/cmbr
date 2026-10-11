//! Trigger only after a real committed Keyhole winner, never by call counts.
use super::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy)]
enum AfterCommit {
    Expire,
    Revoke,
}
#[derive(Clone)]
struct CommitClock {
    base: Clock,
    db: crlt::Db,
    runtime: tokio::runtime::Handle,
    authentication: Arc<Mutex<Option<Authentication>>>,
    armed: Arc<AtomicBool>,
    observed_winner: Arc<AtomicBool>,
    action: AfterCommit,
}
impl CommitClock {
    fn keys(&self) -> ckyh::Passkeys<ckyh::LibsqlStore> {
        let configured = config();
        ckyh::Passkeys::new(
            ckyh::LibsqlStore::new(&self.db, "creation-postcommit", self.runtime.clone()).unwrap(),
            "creation-postcommit",
            &configured.rp_id,
            &configured.origins,
        )
        .unwrap()
    }
}
impl clbs::Clock for CommitClock {
    fn now(&self) -> clbs::Result<i64> {
        let current = clbs::Clock::now(&self.base)?;
        if !self.armed.load(Ordering::SeqCst) {
            return Ok(current);
        }
        let authentication = self.authentication.lock().unwrap().clone().unwrap();
        // LibsqlStore is synchronous: query on its supported ordinary thread,
        // while the real multithread runtime continues its actual database I/O.
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let keys = self.keys();
                    let state = keys.initial_creation(&authentication).unwrap();
                    if state.publication() != Some([2; 32]) {
                        return Ok(current);
                    }
                    assert_eq!(state.seed(), [1; 32]);
                    self.armed.store(false, Ordering::SeqCst);
                    self.observed_winner.store(true, Ordering::SeqCst);
                    match self.action {
                        AfterCommit::Expire => Ok(current + 60),
                        AfterCommit::Revoke => {
                            keys.revoke(authentication.member(), authentication.credential_id())
                                .unwrap();
                            Ok(current)
                        }
                    }
                })
                .join()
                .unwrap()
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postcommit_expiry_or_real_key_revocation_is_uncertain_and_never_erases_the_winner() {
    for action in [AfterCommit::Expire, AfterCommit::Revoke] {
        let (_dir, db) = temporary().await;
        let clock = CommitClock {
            base: Clock::new(),
            db: db.clone(),
            runtime: tokio::runtime::Handle::current(),
            authentication: Arc::new(Mutex::new(None)),
            armed: Arc::new(AtomicBool::new(false)),
            observed_winner: Arc::new(AtomicBool::new(false)),
            action,
        };
        let member = Membership::new(
            &db,
            crate::LibsqlStorage::new(&db, "creation-postcommit").unwrap(),
            config(),
            Verify,
            clock.clone(),
        )
        .unwrap();
        let mut device = Resident::default();
        let (challenge, pending) = member
            .begin_initial_registration(USER, SUBJECT, [1; 32])
            .await
            .unwrap();
        let mut response = device
            .ceremony(serde_json::to_value(challenge).unwrap(), true, ORIGIN)
            .await;
        strip_prf(&mut response);
        member
            .finish_registration(pending, serde_json::from_value(response).unwrap())
            .await
            .unwrap();
        let (challenge, pending) = member.begin_discoverable_login().await.unwrap();
        let mut response = device
            .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
            .await;
        strip_prf(&mut response);
        let login = member
            .finish_login(pending, serde_json::from_value(response).unwrap())
            .await
            .unwrap();
        *clock.authentication.lock().unwrap() = Some(login.authentication.clone());
        clock.armed.store(true, Ordering::SeqCst);
        assert!(matches!(
            member
                .bind_initial_publication(&login.authentication, [1; 32], [2; 32], now() + 60)
                .await,
            Err(Error::Unavailable)
        ));
        assert!(clock.observed_winner.load(Ordering::SeqCst));
        match action {
            AfterCommit::Expire => {
                clock.base.set(now() + 61);
                let (challenge, pending) = member.begin_discoverable_login().await.unwrap();
                let mut response = device
                    .ceremony(serde_json::to_value(challenge).unwrap(), false, ORIGIN)
                    .await;
                strip_prf(&mut response);
                let fresh = member
                    .finish_login(pending, serde_json::from_value(response).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    member
                        .initial_creation(&fresh.authentication, now() + 120)
                        .await
                        .unwrap()
                        .publication(),
                    Some([2; 32])
                );
            }
            AfterCommit::Revoke => {
                let observed = tokio::task::spawn_blocking(move || {
                    let keys = clock.keys();
                    assert!(matches!(
                        keys.initial_creation(&login.authentication),
                        Err(ckyh::Error::Revoked)
                    ));
                    keys.list(USER).unwrap()
                })
                .await
                .unwrap();
                assert_eq!(observed.len(), 1);
                assert!(observed[0].is_revoked());
                let retained = serde_json::to_value(&observed[0]).unwrap();
                assert_eq!(
                    retained["initial_creation"]["publication"],
                    serde_json::to_value([2u8; 32]).unwrap()
                );
            }
        }
    }
}
