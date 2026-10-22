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
    /// The creator's exact commitment awaits genuine full admission as first admin.
    Creating,
    /// The first admin and creation record were committed atomically.
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

    /// Record the creation of an explicitly provisioned new community for its
    /// creator. The trusted global creation host authenticates the creator and
    /// spends the creation token BEFORE calling this; membership only fixes the
    /// exact creator commitment so that no other member can take the first
    /// admin seat. It creates no member, role or spent receipt. Any retained
    /// Register member prevents initialization.
    pub async fn initialize_community_creation(
        &self,
        id: &str,
        creator: &[u8],
        valid_until: u64,
    ) -> Result<CommunityPhase> {
        let pending = self.creation_pending(id, creator, valid_until)?;
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

    /// Whether this authenticated member is the recorded creator of a community
    /// that is still being created. It decides only whether the creator's verified
    /// global passport may stand in for the voucher step (L1352); first-admin
    /// admission still matches the exact commitment in its own writer.
    pub async fn is_recorded_creator(&self, auth: &Authentication) -> Result<bool> {
        let row = self.authenticated_member(auth, self.now()?).await?;
        self.recorded_creator(&row).await
    }

    pub(super) async fn recorded_creator(&self, row: &Record) -> Result<bool> {
        let tx = self.authority_scope.tx().await?;
        let (tx, phase) = self.creation().read(tx).await?;
        tx.rollback().await?;
        Ok(match phase {
            Some(Phase::Creating(current)) => {
                let receipt = current.receipt();
                Pending::new(
                    receipt,
                    &cvch::member_binding(receipt, row.member_id().as_bytes()),
                    current.expires(),
                )? == current
            }
            _ => false,
        })
    }

    fn creation(&self) -> Creation {
        Creation::new(self.authority_scope.clone())
    }

    fn creation_pending(&self, id: &str, creator: &[u8], valid_until: u64) -> Result<Pending> {
        crate::text(std::str::from_utf8(creator).map_err(|_| Error::Identity)?)?;
        self.creation_time(valid_until)?;
        let receipt = cvch::receipt_id(id);
        Pending::new(
            &receipt,
            &cvch::member_binding(&receipt, creator),
            valid_until,
        )
    }

    fn creation_time(&self, until: u64) -> Result<u64> {
        let now = self.now()? as u64;
        if now >= until {
            return Err(Error::Transition);
        }
        Ok(now)
    }

    /// A commit cut evaluates at `observed` (decided 2026-10-18: commit authorities
    /// evaluate at the observed time). It refuses only a live clock before
    /// `observed` or a crossed scheduled boundary (`until`, the earliest of the
    /// claim, session, snapshot and registration ends); a plain later second commits.
    fn creation_cut(&self, observed: u64, until: u64) -> Result<()> {
        if self.creation_time(until)? < observed {
            return Err(Error::Transition);
        }
        Ok(())
    }
}

/// The gate a founder's verified global passport stands in for.
const FOUNDER_VOUCHER_GATE: &str = "cvch";

/// Lobby decision for the recorded creator of a new community (Julian, L1352):
/// a founder is not gated by the new community's voucher gate, because her
/// verified global passport, presented at admission, proves she was admitted
/// somewhere on the platform (cgts `FoundingVoucher`). Exactly the community-level voucher requirement that lacks a
/// proof counts as passed, once per group (a group never lists one gate and
/// level twice). A disabled voucher gate stays missing, and every other
/// requirement, the legal veto included, is untouched.
pub(super) fn founder_decision(mut decision: crbk::Decision) -> crbk::Decision {
    decision.missing.retain_mut(|missing| match missing {
        crbk::Missing::Gates {
            needed,
            alternatives,
        } => {
            let before = alternatives.len();
            alternatives.retain(|alternative| {
                alternative.requirement.gate != FOUNDER_VOUCHER_GATE
                    || alternative.requirement.level != crbk::GateLevel::Community
                    || alternative.reason != crbk::GateFailure::ProofRequired
            });
            *needed = needed.saturating_sub(before - alternatives.len());
            *needed > 0
        }
        _ => true,
    });
    decision.allowed = decision.missing.is_empty();
    decision
}

#[cfg(test)]
mod tests;
