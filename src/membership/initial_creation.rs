//! Original first-passkey commitments, never replacement genesis authority.
use super::*;
use std::time::{Duration, Instant};

/// A sealed original-credential read under the member mutation lease. Retain
/// this through host awaits, then recheck this SAME instance before output.
/// Drop it before starting another read/bind for this member.
pub struct InitialCreationState {
    instance: Arc<()>,
    authentication: Authentication,
    subject: String,
    seed: [u8; 32],
    publication: Option<[u8; 32]>,
    timing: Timing,
    valid: bool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}
struct Timing {
    begun_at: i64,
    observed: i64,
    expires_at: i64,
    started: Instant,
    lifetime: Duration,
}
impl Timing {
    fn new(now: i64, expires_at: i64, started: Instant) -> Result<Self> {
        let seconds = expires_at
            .checked_sub(now)
            .filter(|seconds| *seconds > 0 && now >= 0)
            .ok_or(Error::InvalidInput)?;
        let lifetime = Duration::from_secs(seconds as u64);
        started.checked_add(lifetime).ok_or(Error::InvalidInput)?;
        Ok(Self {
            begun_at: now,
            observed: now,
            expires_at,
            started,
            lifetime,
        })
    }
    fn bound(&mut self, expires_at: i64) -> Result<()> {
        let seconds = expires_at
            .checked_sub(self.begun_at)
            .filter(|seconds| *seconds > 0)
            .ok_or(Error::Identity)?;
        self.expires_at = self.expires_at.min(expires_at);
        // The original Instant and starting wall sample remain fixed. A
        // shorter owner deadline also shortens its monotonic lifetime.
        self.lifetime = self.lifetime.min(Duration::from_secs(seconds as u64));
        Ok(())
    }
    fn current(&self, now: i64) -> bool {
        now >= self.observed && now < self.expires_at && self.started.elapsed() < self.lifetime
    }
    fn advance(&mut self, now: i64) -> Result<()> {
        if !self.current(now) {
            return Err(Error::Identity);
        }
        self.observed = now;
        Ok(())
    }
}
impl InitialCreationState {
    /// Only the opaque caller-domain commitment stored with original enrolment.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
    /// The exact immutable winner, if binding has occurred. Never a capability.
    pub fn publication(&self) -> Option<[u8; 32]> {
        self.publication
    }
    /// Latest trusted observation retained across leaf/host awaits.
    pub fn observed_at(&self) -> i64 {
        self.timing.observed
    }
    /// Sample the host's live clock FIRST, then synchronously check immediately
    /// before projection. This never renews the supplied original expiry.
    pub fn is_current(&self, trusted_now: i64) -> bool {
        self.valid && self.timing.current(trusted_now)
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// The caller supplies a nonzero opaque creation commitment before the
    /// ORIGINAL first WebAuthn ceremony. Legacy or additional keys cannot add it.
    pub async fn begin_initial_registration(
        &self,
        user: Uuid,
        pseudonym: &str,
        seed: [u8; 32],
    ) -> Result<(ckyh::CreationChallengeResponse, PendingRegistration)> {
        if seed == [0; 32] {
            return Err(Error::InvalidInput);
        }
        self.initial_registration(user, pseudonym, Some(seed)).await
    }

    /// The host passes the SAME original session/ceremony exclusive expiry;
    /// the library also bounds it by the original enrolment deadline. No new
    /// session or arbitrary key selector can be produced from this metadata.
    pub async fn initial_creation(
        &self,
        auth: &Authentication,
        expires_at: i64,
    ) -> Result<InitialCreationState> {
        self.creation_state(auth, None, expires_at).await
    }

    /// Store one caller-owned opaque publication intent atomically on the exact
    /// authenticated first key. Equal retry succeeds; different winner refuses.
    pub async fn bind_initial_publication(
        &self,
        auth: &Authentication,
        expected_seed: [u8; 32],
        publication: [u8; 32],
        expires_at: i64,
    ) -> Result<InitialCreationState> {
        if expected_seed == [0; 32] || publication == [0; 32] {
            return Err(Error::InvalidInput);
        }
        self.creation_state(auth, Some((expected_seed, publication)), expires_at)
            .await
    }

    async fn creation_state(
        &self,
        auth: &Authentication,
        bind: Option<([u8; 32], [u8; 32])>,
        expires_at: i64,
    ) -> Result<InitialCreationState> {
        let started = Instant::now();
        let mut timing = Timing::new(self.now()?, expires_at, started)?;
        let guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        timing.advance(self.now()?)?;
        self.member_identity(auth).await?;
        timing.advance(self.now()?)?;
        let row = self.enrol.view(auth.member(), timing.observed).await?;
        self.check_record(&row)?;
        timing.advance(self.now()?)?;
        if row.state().is_terminal() {
            return Err(Error::Transition);
        }
        if let Some(deadline) = row.expires_at() {
            timing.bound(deadline)?;
            timing.advance(self.now()?)?;
        }
        self.unrestricted(row.subject()).await?;
        timing.advance(self.now()?)?;
        let (seed, publication) = self.initial_commitment(auth, bind).await?;
        let completion = async {
            timing.advance(self.now()?)?;
            let mut result = InitialCreationState {
                instance: self.instance.clone(),
                authentication: auth.clone(),
                subject: row.subject().to_owned(),
                seed,
                publication,
                timing,
                valid: true,
                _guard: guard,
            };
            self.check_initial_creation(&mut result).await?;
            Ok(result)
        }
        .await;
        // A successful durable bind precedes every completion check above.
        // Withholding an expired/revoked result must not suggest no winner was
        // installed. Reconcile through actual current authority, never reset.
        if bind.is_some() {
            completion.map_err(|_| Error::Unavailable)
        } else {
            completion
        }
    }

    /// Recheck original key/lifecycle/legal authority after host awaits. A
    /// cancelled or failed check poisons THIS sealed result; it cannot be revived.
    /// A changed winner also refuses instead of silently substituting metadata.
    pub async fn check_initial_creation(&self, state: &mut InitialCreationState) -> Result<i64> {
        if !state.valid {
            return Err(Error::Identity);
        }
        state.valid = false;
        if !Arc::ptr_eq(&self.instance, &state.instance) {
            return Err(Error::Identity);
        }
        state.timing.advance(self.now()?)?;
        self.member_identity(&state.authentication).await?;
        state.timing.advance(self.now()?)?;
        let row = self
            .enrol
            .view(state.authentication.member(), state.timing.observed)
            .await?;
        self.check_record(&row)?;
        state.timing.advance(self.now()?)?;
        if row.subject() != state.subject || row.state().is_terminal() {
            return Err(Error::Transition);
        }
        if let Some(deadline) = row.expires_at() {
            state.timing.bound(deadline)?;
            state.timing.advance(self.now()?)?;
        }
        self.unrestricted(row.subject()).await?;
        state.timing.advance(self.now()?)?;
        // This LAST atomic read rechecks both exact current key and winner.
        let current = self.initial_commitment(&state.authentication, None).await?;
        state.timing.advance(self.now()?)?;
        if current != (state.seed, state.publication) {
            return Err(Error::Busy);
        }
        state.valid = true;
        Ok(state.timing.observed)
    }

    /// The commitment of the authenticating credential, after an optional atomic bind: the
    /// original passkey's ckyh record, or, for a device-key member, the first device key's
    /// registry row (stored at the stamped join). Additional keys of either kind hold none.
    async fn initial_commitment(
        &self,
        auth: &Authentication,
        bind: Option<([u8; 32], [u8; 32])>,
    ) -> Result<([u8; 32], Option<[u8; 32]>)> {
        match auth.origin() {
            ckyh::Origin::Passkey => {
                let keys = self.passkeys.clone();
                let authentication = auth.clone();
                let state = blocking(move || match bind {
                    None => keys.initial_creation(&authentication),
                    Some((seed, publication)) => {
                        keys.bind_initial_publication(&authentication, seed, publication)
                    }
                })
                .await?;
                Ok((state.seed(), state.publication()))
            }
            ckyh::Origin::DeviceKey => {
                if auth.community() != self.storage.community() {
                    return Err(Error::Identity);
                }
                let key = auth.device_key().ok_or(Error::Identity)?;
                let held = self
                    .storage
                    .device_initial_creation(&auth.member().to_string(), key, bind)
                    .await?
                    .ok_or(Error::Passkey)?;
                Ok((held.seed, held.publication))
            }
        }
    }
}

#[cfg(test)]
mod tests;
