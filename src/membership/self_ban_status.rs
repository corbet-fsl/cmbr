//! Fresh original passkey ownership permits only reading one's terminal receipt.
use super::{Error, Membership, Result, Storage, blocking};
use cnrl::Storage as _;
use std::time::{Duration, Instant};

/// A dedicated discoverable receipt ceremony. No login/session state can be
/// substituted; retain this single-use value only in bounded server RAM.
pub struct PendingSelfBanStatus {
    pending: ckyh::PendingDiscoverableAuthentication,
    started: Instant,
    lifetime: Duration,
    not_before: i64,
    expires_at: i64,
}

/// Only the presence of the owner's immutable permanent self-ban record.
/// `false` never means admitted, eligible or permitted to return. This carries
/// no identity, Authentication, session, credential or recovery authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfBanStatus {
    /// Whether the original subject has a recorded permanent self-ban.
    pub self_banned: bool,
    observed_at: i64,
    expires_at: i64,
    started: Instant,
    lifetime: Duration,
}

impl PendingSelfBanStatus {
    /// Latest trusted observation retained after beginning the ceremony.
    pub fn observed_at(&self) -> i64 {
        self.not_before
    }
    /// Sample the host's live clock first, then retain the original exclusive
    /// wall deadline, observed floor and monotonic lifetime at output release.
    pub fn is_current(&self, trusted_now: i64) -> bool {
        trusted_now >= self.not_before
            && trusted_now < self.expires_at
            && self.started.elapsed() < self.lifetime
    }
    fn current(&self, now: i64) -> Result<()> {
        if self.is_current(now) {
            Ok(())
        } else {
            Err(Error::Passkey)
        }
    }
}

impl SelfBanStatus {
    /// Final trusted leaf clock observation. This is only an output guard;
    /// never use the receipt as membership or recovery authority.
    pub fn observed_at(&self) -> i64 {
        self.observed_at
    }
    /// Sample the host clock before calling this immediately prior to output.
    /// Original ceremony timing survives the awaited leaf/host boundary.
    pub fn is_current(&self, trusted_now: i64) -> bool {
        trusted_now >= self.observed_at
            && trusted_now < self.expires_at
            && self.started.elapsed() < self.lifetime
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Begin a fresh, purpose-specific discoverable UV receipt read, without a
    /// user/subject lookup or a bearer. The host supplies an exclusive deadline
    /// of at most 300 seconds and retains bounded, single-use ceremony state.
    pub async fn begin_self_ban_status(
        &self,
        expires_at: i64,
    ) -> Result<(ckyh::RequestChallengeResponse, PendingSelfBanStatus)> {
        let now = self.now()?;
        let seconds = expires_at
            .checked_sub(now)
            .filter(|seconds| (1..=300).contains(seconds))
            .ok_or(Error::InvalidInput)?;
        let started = Instant::now();
        let keys = self.passkeys.clone();
        let (challenge, pending) =
            blocking(move || keys.start_discoverable_authentication()).await?;
        let mut state = PendingSelfBanStatus {
            pending,
            started,
            lifetime: Duration::from_secs(seconds as u64),
            not_before: now,
            expires_at,
        };
        let observed = self.now()?;
        state.current(observed)?;
        state.not_before = observed;
        Ok((challenge, state))
    }

    /// Consume only this dedicated original Keyhole challenge. A terminal row
    /// can disclose its own immutable receipt when a still-enrolled key proves
    /// fresh ownership; it never receives renewed standing or a login result.
    /// Recheck current key ownership and deadlines after every awaited read.
    pub async fn finish_self_ban_status(
        &self,
        state: PendingSelfBanStatus,
        response: ckyh::PublicKeyCredential,
    ) -> Result<SelfBanStatus> {
        let mut observed = self.now()?;
        state.current(observed)?;
        let mut current = || {
            let now = self.now()?;
            if now < observed
                || now >= state.expires_at
                || state.started.elapsed() >= state.lifetime
            {
                Err(Error::Passkey)
            } else {
                observed = now;
                Ok(())
            }
        };
        let keys = self.passkeys.clone();
        let authentication =
            blocking(move || keys.finish_discoverable_authentication(state.pending, &response))
                .await?;
        current()?;
        let _guard =
            crate::storage::member_lock(self.storage.community(), authentication.member()).await;
        current()?;
        self.identity(&authentication).await?;
        current()?;
        let row = self
            .enrol_store
            .load(authentication.member())
            .await?
            .ok_or(Error::Unavailable)?;
        self.check_record(&row)?;
        if row.user() != authentication.member() {
            return Err(Error::Identity);
        }
        current()?;
        let recorded = self.legal.self_ban_record(row.subject()).await?;
        current()?;
        self.identity(&authentication).await?;
        current()?;
        Ok(SelfBanStatus {
            self_banned: recorded.is_some(),
            observed_at: observed,
            expires_at: state.expires_at,
            started: state.started,
            lifetime: state.lifetime,
        })
    }
}

#[cfg(test)]
mod tests;
