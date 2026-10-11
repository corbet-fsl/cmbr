//! Explicit community creation and authority-preserving legacy adoption.
use super::*;
use crate::storage::creation::{Creation, Pending, State as Phase};
mod admission;
mod lapse;
pub use admission::AdmissionRequest;

/// Coarse trusted-host view. A phase does not authorize admission or a role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommunityPhase {
    /// No creation or explicitly verified legacy adoption has been recorded.
    Uninitialized,
    /// An exact original first-Root entitlement awaits genuine full admission.
    Creating,
    /// The original first Root and entitlement were committed atomically.
    Active,
    /// An explicit migration retained an already admitted original Root.
    LegacyActive,
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Observe private creation state through the actual scoped owner. This
    /// trusted service method is not a public membership or identity listing.
    pub async fn community_phase(&self) -> Result<CommunityPhase> {
        let tx = self.authority_scope.tx().await?;
        let (tx, phase) = self.creation().read(tx).await?;
        tx.rollback().await?;
        Ok(match phase {
            None => CommunityPhase::Uninitialized,
            Some(Phase::Creating(_)) => CommunityPhase::Creating,
            Some(Phase::Active { .. }) => CommunityPhase::Active,
            Some(Phase::LegacyActive { .. }) => CommunityPhase::LegacyActive,
        })
    }

    /// Record the original verified BootstrapRoot invitation for an explicitly
    /// provisioned new community. The trusted creation host authenticates the
    /// intended passport-derived member and the authorized current issuer before
    /// obtaining `invitation`; this method cannot sign or fabricate entitlement.
    /// It creates no member, role or spent receipt. Any retained Register member
    /// prevents initialization, including a released member's coarse row.
    pub async fn initialize_community_creation(
        &self,
        invitation: &cvch::role::Verified,
        member: &[u8],
    ) -> Result<CommunityPhase> {
        let pending = self.creation_invitation(invitation, member)?;
        let tx = self.authority_scope.tx().await?;
        let observed = self.creation_time(pending.expires())?;
        let tx = self.register.ensure_empty_in_transaction(tx).await?;
        let (tx, _) = self.creation().initialize(tx, &pending).await?;
        self.creation_cut(observed, pending.expires())?;
        tx.commit().await?;
        // A lost/late commit reply is uncertain, never an unspent/unchanged claim.
        self.creation_cut(observed, pending.expires())
            .map_err(|_| Error::Unavailable)?;
        Ok(CommunityPhase::Creating)
    }

    /// Explicit migration for an existing genuine Root, never inferred from a
    /// populated database. Retains current SDK/legal/session authority and reads
    /// original Admitted lifecycle plus the exact Register Root in ONE writer.
    /// No invitation, role, membership or admission event is synthesized.
    pub async fn adopt_legacy_community_creation(
        &self,
        auth: &Authentication,
        session: Arc<dyn RoleSession>,
    ) -> Result<CommunityPhase> {
        let mut lease = self.role_until(auth, session.valid_until()).await?;
        if lease.role() != crgs::Role::Root {
            return Err(Error::Policy);
        }
        let tx = self.authority_scope.tx().await?;
        let observed = self.creation_time(lease.valid_until())?;
        session.check(auth, observed)?;
        let (tx, row) = self
            .enrol
            .get_in_transaction(tx, auth.member(), observed as i64)
            .await?;
        self.check_record(&row)?;
        if row.state() != State::Admitted || row.subject() != lease.member() {
            return Err(Error::Transition);
        }
        let (tx, member) = self
            .register
            .member_in_transaction(tx, &row.member_id())
            .await?;
        let member = member.ok_or(Error::Transition)?;
        if member.id != row.member_id()
            || member.role != crgs::Role::Root
            || member.handle.is_none()
            || roles::lease_deadline(member.lease_end)? <= observed
        {
            return Err(Error::Transition);
        }
        let (tx, _) = self.creation().adopt_legacy(tx, &member.id).await?;
        if self.check_role(&mut lease).await? != observed
            || lease.role() != crgs::Role::Root
            || !lease.is_current(observed)
        {
            return Err(Error::Transition);
        }
        session.check(auth, observed)?;
        self.creation_cut(observed, lease.valid_until())?;
        tx.commit().await?;
        let released = (|| {
            session.check(auth, observed)?;
            if !lease.is_current(observed) {
                return Err(Error::Transition);
            }
            self.creation_cut(observed, lease.valid_until())
        })();
        released.map_err(|_| Error::Unavailable)?;
        Ok(CommunityPhase::LegacyActive)
    }

    fn creation(&self) -> Creation {
        Creation::new(self.authority_scope.clone())
    }

    fn creation_invitation(
        &self,
        invitation: &cvch::role::Verified,
        member: &[u8],
    ) -> Result<Pending> {
        crate::text(std::str::from_utf8(member).map_err(|_| Error::Identity)?)?;
        if invitation.community() != self.community()
            || invitation.purpose() != cvch::role::Purpose::BootstrapRoot
            || cvch::member_binding(invitation.receipt(), member) != invitation.binding()
        {
            return Err(Error::Identity);
        }
        self.creation_time(invitation.valid_until())?;
        Pending::new(
            invitation.receipt(),
            invitation.binding(),
            invitation.valid_until(),
        )
    }

    fn creation_time(&self, until: u64) -> Result<u64> {
        let now = self.now()? as u64;
        if now >= until {
            return Err(Error::Transition);
        }
        Ok(now)
    }

    fn creation_cut(&self, observed: u64, until: u64) -> Result<()> {
        if self.creation_time(until)? != observed {
            return Err(Error::Transition);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
