use super::*;
use std::{
    future::{Future, poll_fn},
    sync::Mutex,
    task::Poll,
    time::Duration,
};
use tokio::sync::oneshot;
use webauthn_authenticator_rs::AuthenticatorBackend;

struct Pause {
    reached: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

// All state comes from the real database. Only the first completed signal's
// return is delayed, before Membership starts the synchronous Keyhole write.
struct PausedSignal {
    inner: crate::LibsqlStorage,
    pause: Mutex<Option<Pause>>,
}

impl Storage for PausedSignal {
    fn community(&self) -> &str {
        self.inner.community()
    }
    async fn set_device_keys(
        &self,
        member: &str,
        credential: &[u8],
        keys: &[[u8; 32]],
    ) -> crate::Result<()> {
        self.inner.set_device_keys(member, credential, keys).await
    }
    async fn set_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        key: [u8; 32],
        expires: u64,
    ) -> crate::Result<()> {
        self.inner
            .set_pending_device(member, credential, key, expires)
            .await
    }
    async fn approve_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        approver: &[u8],
    ) -> crate::Result<()> {
        self.inner
            .approve_pending_device(member, credential, approver)
            .await
    }
    async fn add_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
    ) -> crate::Result<bool> {
        self.inner.add_device_key(member, key, pending_until).await
    }
    async fn pending_device_key_until(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> crate::Result<Option<i64>> {
        self.inner.pending_device_key_until(member, key).await
    }
    async fn remove_expired_pending_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        now: i64,
    ) -> crate::Result<bool> {
        self.inner
            .remove_expired_pending_device_key(member, key, now)
            .await
    }
    async fn set_device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
        from: crate::DeviceKeyState,
        to: crate::DeviceKeyState,
    ) -> crate::Result<bool> {
        self.inner.set_device_key_state(member, key, from, to).await
    }
    async fn clear_pending_device(&self, member: &str, credential: &[u8]) -> crate::Result<()> {
        self.inner.clear_pending_device(member, credential).await
    }
    async fn pending_devices(&self, member: &str) -> crate::Result<Vec<crate::PendingDeviceKey>> {
        self.inner.pending_devices(member).await
    }
    async fn device_keys(&self, member: &str) -> crate::Result<Vec<crate::DeviceKeyBinding>> {
        self.inner.device_keys(member).await
    }
    async fn probation(&self, member: &str) -> crate::Result<Option<Option<u64>>> {
        self.inner.probation(member).await
    }
    async fn initialize_probation(&self, member: &str, until: u64) -> crate::Result<()> {
        self.inner.initialize_probation(member, until).await
    }
    async fn clear_passed_probation(&self, member: &str, now: u64) -> crate::Result<()> {
        self.inner.clear_passed_probation(member, now).await
    }
    async fn prune_probation(&self, now: u64, limit: usize) -> crate::Result<()> {
        self.inner.prune_probation(now, limit).await
    }
    async fn revocation_pending(&self, member: &str) -> crate::Result<bool> {
        self.inner.revocation_pending(member).await
    }
    async fn signal_revocation(&self, member: &str) -> crate::Result<()> {
        self.inner.signal_revocation(member).await?;
        let pause = { self.pause.lock().unwrap().take() };
        if let Some(pause) = pause {
            pause.reached.send(()).map_err(|_| Error::Unavailable)?;
            pause.release.await.map_err(|_| Error::Unavailable)?;
        }
        Ok(())
    }
    async fn revocations(&self, limit: usize) -> crate::Result<Vec<crate::Revocation>> {
        self.inner.revocations(limit).await
    }
    async fn acknowledge(&self, event: &crate::Revocation) -> crate::Result<()> {
        self.inner.acknowledge(event).await
    }
    async fn device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> crate::Result<Option<crate::DeviceKeyState>> {
        self.inner.device_key_state(member, key).await
    }
    async fn active_device_keys(&self, member: &str) -> crate::Result<Vec<[u8; 32]>> {
        self.inner.active_device_keys(member).await
    }
    async fn bind_first_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        seed: [u8; 32],
    ) -> crate::Result<bool> {
        self.inner.bind_first_device_key(member, key, seed).await
    }
    async fn device_initial_creation(
        &self,
        member: &str,
        key: [u8; 32],
        bind: Option<([u8; 32], [u8; 32])>,
    ) -> crate::Result<Option<crate::DeviceInitialCreation>> {
        self.inner.device_initial_creation(member, key, bind).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_caller_keeps_projection_behind_the_durable_revocation() {
    let (_dir, db) = temporary().await;
    let community = "cancelled-revocation";
    let clock = Clock::new();
    let original = facade(&db, community, clock.clone());
    let mut authenticator = register(&original, USER, SUBJECT).await;
    let credential = original
        .credentials(USER)
        .await
        .unwrap()
        .pop()
        .unwrap()
        .credential_id()
        .clone();
    drop(original);
    let (reached, arrived) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let m = crate::Membership::new(
        &db,
        PausedSignal {
            inner: crate::LibsqlStorage::new(&db, community).unwrap(),
            pause: Mutex::new(Some(Pause {
                reached,
                release: released,
            })),
        },
        config(),
        Verify,
        clock,
    )
    .unwrap();
    let (challenge, pending) = m.begin_login(USER, credential.clone()).await.unwrap();
    let response = authenticator
        .perform_auth(
            ckyh::Url::parse(ORIGIN).unwrap(),
            challenge.public_key,
            300_000,
        )
        .unwrap();
    let login = m.finish_login(pending, response.into()).await.unwrap();
    assert!(m.revocations(10).await.unwrap().is_empty());

    let mut removal = Box::pin(m.revoke_passkey(&login.authentication, credential.clone()));
    // The timeout is only a deadlock fence. The oneshot establishes the
    // exact durable-signal boundary; elapsed time never establishes progress.
    tokio::select! {
        result = removal.as_mut() => panic!("revocation bypassed signal barrier: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(30), arrived) => {
            result.expect("durable signal was not reached").unwrap();
        }
    }
    let events = m.revocations(10).await.unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.member, SUBJECT);
    let keys = m.credentials(USER).await.unwrap();
    assert_eq!(keys.len(), 1);
    assert!(!keys[0].is_revoked());
    drop(removal);

    // Probe the exact mutex independently: a Pending database read in the
    // projection alone would not prove that the cancelled caller kept it.
    let mut lock = Box::pin(crate::storage::member_lock(community, USER));
    poll_fn(|cx| {
        assert!(lock.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(lock);
    let mut projection = Box::pin(m.revoked_passkeys(event));
    poll_fn(|cx| {
        assert!(projection.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let projected = tokio::time::timeout(Duration::from_secs(30), projection)
        .await
        .expect("projection did not resume after releasing the real mutation")
        .unwrap();
    assert_eq!(projected, vec![credential.as_ref().to_vec()]);
    assert!(m.credentials(USER).await.unwrap()[0].is_revoked());
    assert_eq!(
        m.enrolment_state(USER).await.unwrap().state(),
        State::Released
    );

    // Losing the final key signals again before releasing the same guard.
    // This checks the actual outbox compare-and-acknowledge operation; the
    // signed Policy publication protocol is exercised by the HTTP fixture.
    let latest = m.revocations(10).await.unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].member, event.member);
    assert_eq!(latest[0].generation, event.generation + 1);
    m.acknowledge_revocation(event).await.unwrap();
    assert_eq!(m.revocations(10).await.unwrap(), latest);
    m.acknowledge_revocation(&latest[0]).await.unwrap();
    assert!(m.revocations(10).await.unwrap().is_empty());
}
