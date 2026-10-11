//! Current recipient and external producer at the original creation writer.
use super::*;
use std::future::Future;
use std::time::{Duration, Instant};

/// Exact original invitation and independently authenticated target session.
/// The trusted producer must retain the actual current target Policy and its
/// signing authority; a previously verified invitation alone is insufficient.
pub struct CreationRequest<'a> {
    /// Original verified BootstrapRoot invitation, never a role assertion.
    pub invitation: &'a cvch::role::Verified,
    /// Actual current target passkey authentication.
    pub authentication: &'a Authentication,
    /// Exact target session, invalidated on removal or replacement.
    pub session: &'a dyn RoleSession,
}

/// Immutable data for the final producer check, not creation authority.
pub struct CreationContext<'a> {
    community: &'a str,
    member: &'a [u8],
    pending: &'a Pending,
}
impl CreationContext<'_> {
    /// Actual target community from the membership owner.
    pub fn community(&self) -> &str {
        self.community
    }
    /// Actual passport-derived recipient from the original enrolment row.
    pub fn member(&self) -> &[u8] {
        self.member
    }
    /// Original immutable invitation receipt.
    pub fn receipt(&self) -> &str {
        self.pending.receipt()
    }
    /// Original immutable recipient commitment.
    pub fn binding(&self) -> &str {
        self.pending.binding()
    }
    /// Original exclusive entitlement expiry; retry cannot extend it.
    pub fn expires_at(&self) -> u64 {
        self.pending.expires()
    }
}

/// Retained authorization of the actual external creation producer.
///
/// The host holds any separate producer credential database guard THROUGH this
/// target transaction and its acknowledged result. `check` must validate the
/// exact context against genuine current producer/session and target Policy
/// authority, including the original invitation under its current issuer ring.
/// `release` is the synchronous final same-second cut. Neither default accepts.
pub trait CreationGuard: Send {
    /// Recheck genuine producer and issuer authority under the target writer.
    fn check(
        &mut self,
        _context: &CreationContext<'_>,
        _observed: u64,
    ) -> impl Future<Output = Result<()>> + Send {
        async { Err(Error::Unavailable) }
    }
    /// Final synchronous producer cut, before commit and after acknowledgment.
    fn release(&mut self, _context: &CreationContext<'_>, _observed: u64) -> Result<()> {
        Err(Error::Unavailable)
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Initialize only after the current recipient and retained external
    /// producer pass the final writer cut. Public creation hosts must use this
    /// checked path; the existing initializer remains a trusted lower primitive.
    /// Failure after a possible commit is unavailable and requires reconciliation.
    pub async fn initialize_community_creation_checked(
        &self,
        request: CreationRequest<'_>,
        producer: &mut impl CreationGuard,
    ) -> Result<CommunityPhase> {
        let started = Instant::now();
        let begun = self.now()? as u64;
        let auth = request.authentication;
        let session = request.session;
        let _member = crate::storage::member_lock(self.community(), auth.member()).await;
        let tx = self.authority_scope.tx().await?;
        let observed = self.now()? as u64;
        let (tx, row) = self
            .enrol
            .get_in_transaction(tx, auth.member(), observed as i64)
            .await?;
        self.check_record(&row)?;
        if row.state().is_terminal() || row.state() == State::Started {
            return Err(Error::Transition);
        }
        let member = row.member_id();
        let pending = self.creation_invitation(request.invitation, member.as_bytes())?;
        let row_until = row
            .expires_at()
            .map(u64::try_from)
            .transpose()
            .map_err(|_| Error::Transition)?
            .unwrap_or(u64::MAX);
        let until = pending.expires().min(session.valid_until()).min(row_until);
        let lifetime = Duration::from_secs(until.checked_sub(begun).ok_or(Error::Transition)?);
        started.checked_add(lifetime).ok_or(Error::Transition)?;
        let cut = || -> Result<()> {
            session.check(auth, observed)?;
            self.creation_cut(observed, until)?;
            if started.elapsed() >= lifetime {
                return Err(Error::Transition);
            }
            Ok(())
        };
        cut()?;
        let tx = self.register.ensure_empty_in_transaction(tx).await?;
        let (tx, _) = self.creation().initialize(tx, &pending).await?;
        let context = CreationContext {
            community: self.community(),
            member: member.as_bytes(),
            pending: &pending,
        };
        producer.check(&context, observed).await?;
        self.identity(auth).await?;
        self.unrestricted(row.subject()).await?;
        cut()?;
        producer.release(&context, observed)?;
        cut()?;
        tx.commit().await?;
        (|| {
            cut()?;
            producer.release(&context, observed)?;
            cut()
        })()
        .map_err(|_| Error::Unavailable)?;
        Ok(CommunityPhase::Creating)
    }
}
