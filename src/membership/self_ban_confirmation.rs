//! Fresh WebAuthn confirmation of one immutable community self-ban intent.
use super::{Authentication, Error, Membership, Result, Storage, Uuid, blocking};
use std::time::{Duration, Instant};

const MAX_CONFIRMATION_SECONDS: i64 = 300;

/// Single-use server state for an explicit, permanent self-ban confirmation.
/// Keep it in the initiating live session; never serialize it or return it.
pub struct PendingSelfBanConfirmation {
    order: clbs::Order,
    authorizer: Authentication,
    not_before: i64,
    expires_at: i64,
    started: Instant,
    lifetime: Duration,
    pending: ckyh::PendingAuthentication,
}

/// Sealed evidence of a fresh UV ceremony for one exact self-ban order.
/// A normal login cannot construct this capability. The host must check its
/// originating session again, then consume it once through its clbs verifier.
/// No authority survives the exclusive wall-clock or monotonic deadline.
///
/// ```compile_fail
/// fn from_login(authentication: cmbr::Authentication) -> cmbr::ConfirmedSelfBan {
///     cmbr::ConfirmedSelfBan { authentication }
/// }
/// ```
pub struct ConfirmedSelfBan {
    order: clbs::Order,
    authorizer: Authentication,
    not_before: i64,
    expires_at: i64,
    started: Instant,
    lifetime: Duration,
}

impl ConfirmedSelfBan {
    /// Complete immutable metadata selected before the passkey challenge.
    pub fn order(&self) -> &clbs::Order {
        &self.order
    }
    /// Opaque community-local membership that confirmed the order.
    pub fn member(&self) -> Uuid {
        self.authorizer.member()
    }
    /// Exact enrolled credential of the initiating and confirming authentication.
    pub fn credential_id(&self) -> &ckyh::CredentialID {
        self.authorizer.credential_id()
    }
    /// Exclusive caller-supplied session/pending deadline.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    /// Check freshness using a trusted live clock, never a client timestamp.
    /// Time before the ceremony is refused; the monotonic limit prevents an
    /// in-window backward step or stalled wall clock from extending its life.
    pub fn is_current(&self, now: i64) -> bool {
        current(
            self.not_before,
            self.expires_at,
            self.started,
            self.lifetime,
            now,
        )
    }
}

fn current(
    not_before: i64,
    expires_at: i64,
    started: Instant,
    lifetime: Duration,
    now: i64,
) -> bool {
    not_before <= now && now < expires_at && started.elapsed() < lifetime
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Start fresh UV confirmation after the host presented an explicit warning.
    /// The order is immutable server state, bound to this member and exact key.
    /// `expires_at` must be the earlier of session/pending expiry and 300 seconds.
    /// A login challenge/result cannot substitute for this dedicated ceremony.
    pub async fn begin_self_ban_confirmation(
        &self,
        auth: &Authentication,
        order: clbs::Order,
        expires_at: i64,
    ) -> Result<(ckyh::RequestChallengeResponse, PendingSelfBanConfirmation)> {
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        let now = self.now()?;
        order.validate()?;
        let row = self.authenticated(auth, now).await?;
        if order.community != self.storage.community()
            || order.subject != row.subject()
            || order.entered_by != row.subject()
        {
            return Err(Error::Identity);
        }
        if order.kind != clbs::OrderKind::SelfBan
            || order.period.starts_at > now
            || expires_at <= now
            || expires_at
                .checked_sub(now)
                .is_none_or(|seconds| seconds > MAX_CONFIRMATION_SECONDS)
        {
            return Err(Error::InvalidInput);
        }
        let started = Instant::now();
        let lifetime = Duration::from_secs((expires_at - now) as u64);
        let keys = self.passkeys.clone();
        let user = auth.member();
        let credential = auth.credential_id().clone();
        let (challenge, pending) =
            blocking(move || keys.start_authentication_for(user, &credential)).await?;
        self.authenticated(auth, self.now()?).await?;
        if !current(now, expires_at, started, lifetime, self.now()?) {
            return Err(Error::InvalidInput);
        }
        Ok((
            challenge,
            PendingSelfBanConfirmation {
                order,
                authorizer: auth.clone(),
                not_before: now,
                expires_at,
                started,
                lifetime,
                pending,
            },
        ))
    }

    /// Consume the dedicated ceremony with the same live session/key authority.
    /// UV, RP/origin, challenge, counter and revoked-key checks remain in ckyh.
    /// Recheck membership and legal standing after awaited verification.
    pub async fn finish_self_ban_confirmation(
        &self,
        auth: &Authentication,
        state: PendingSelfBanConfirmation,
        response: ckyh::PublicKeyCredential,
    ) -> Result<ConfirmedSelfBan> {
        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        if auth.community() != state.authorizer.community()
            || auth.member() != state.authorizer.member()
            || auth.credential_id() != state.authorizer.credential_id()
        {
            return Err(Error::Identity);
        }
        let check = |now| {
            current(
                state.not_before,
                state.expires_at,
                state.started,
                state.lifetime,
                now,
            )
        };
        if !check(self.now()?) {
            return Err(Error::InvalidInput);
        }
        self.authenticated(auth, self.now()?).await?;
        let keys = self.passkeys.clone();
        let authentication =
            blocking(move || keys.finish_authentication(state.pending, &response)).await?;
        if authentication.community() != auth.community()
            || authentication.member() != auth.member()
            || authentication.credential_id() != auth.credential_id()
        {
            return Err(Error::Identity);
        }
        let row = self.authenticated(&authentication, self.now()?).await?;
        if row.subject() != state.order.subject {
            return Err(Error::Identity);
        }
        if !check(self.now()?) {
            return Err(Error::InvalidInput);
        }
        Ok(ConfirmedSelfBan {
            order: state.order,
            authorizer: authentication,
            not_before: state.not_before,
            expires_at: state.expires_at,
            started: state.started,
            lifetime: state.lifetime,
        })
    }
}

#[cfg(test)]
mod tests;
