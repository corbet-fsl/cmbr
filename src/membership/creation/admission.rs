//! Complete role-entitled and ordinary admission share one original writer.
use super::*;
use crate::storage::role_redemptions::{Redemption, RoleRedemptions};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Entitlement<'a> {
    Ordinary,
    FirstRoot(&'a [u8]),
    FounderAdmin(&'a [u8]),
}
impl<'a> Entitlement<'a> {
    fn invitation(self) -> Option<(&'a [u8], cvch::role::Purpose)> {
        match self {
            Self::Ordinary => None,
            Self::FirstRoot(bytes) => Some((bytes, cvch::role::Purpose::BootstrapRoot)),
            Self::FounderAdmin(bytes) => Some((bytes, cvch::role::Purpose::FounderAdmin)),
        }
    }
    fn role(self) -> crgs::Role {
        match self {
            Self::Ordinary => crgs::Role::Member,
            Self::FirstRoot(_) => crgs::Role::Root,
            Self::FounderAdmin(_) => crgs::Role::Admin,
        }
    }
}

/// Original verified gate inputs and independently owned live host session.
/// This trusted composition value has no deserializer or admission verdict.
pub struct AdmissionRequest<'a, R, P, K> {
    /// Actual original community passkey authentication.
    pub authentication: &'a Authentication,
    /// The actual Policy owner, retained through the complete transaction.
    pub policy: &'a cplc::Policy<R, P, K>,
    /// Original authenticated settings used to check the gate receipts.
    pub snapshot: &'a cplc::VerifiedSnapshot,
    /// Exact verified receipt collection, never reconstructed at a later time.
    pub gates: &'a cgts::CheckedGates,
    /// Original verification time of those receipts.
    pub checked_at: u64,
    /// Explicit coarse lease, bounded by current membership settings.
    pub lease: crgs::YearMonth,
    /// Exact original host session, invalidated on removal or replacement.
    pub session: &'a dyn RoleSession,
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Admit or renew only an explicitly active community. The original gate
    /// timestamp is preserved while every current owner is checked under the
    /// final writer. The actual session capability is never inferred from a key.
    ///
    /// ```compile_fail
    /// fn raw(snapshot: crbk::Snapshot, results: Vec<crbk::GateResult>) {
    ///     let _: &cplc::VerifiedSnapshot = &snapshot;
    ///     let _: &cgts::CheckedGates = &results;
    /// }
    /// ```
    pub async fn admit_current<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
    ) -> Result<Record> {
        self.admit_creation_current(request, Entitlement::Ordinary)
            .await
    }

    /// Redeem only the exact initialized BootstrapRoot entitlement, together
    /// with genuine full configured admission. Receipt, Root, lifecycle, phase
    /// and probation are one effect; cancellation rolls back the owned writer.
    /// An exact active retry is read-only and cannot extend the original lease.
    pub async fn admit_first_root<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
        invitation: &[u8],
    ) -> Result<Record> {
        self.admit_creation_current(request, Entitlement::FirstRoot(invitation))
            .await
    }

    /// Redeem the original FounderAdmin invitation only while joining an active
    /// community through full current admission. Existing members cannot be
    /// promoted by this path. An exact retained effect retry is read-only.
    pub async fn admit_founder_admin<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
        invitation: &[u8],
    ) -> Result<Record> {
        self.admit_creation_current(request, Entitlement::FounderAdmin(invitation))
            .await
    }

    async fn admit_creation_current<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
        entitlement: Entitlement<'_>,
    ) -> Result<Record> {
        let auth = request.authentication;
        let policy = request.policy;
        let snapshot = request.snapshot;
        let checked_at = request.checked_at;
        let lease = request.lease;
        let session = request.session;
        let started = Instant::now();
        let begun = self.now()? as u64;
        let _guard = crate::storage::member_lock(self.community(), auth.member()).await;
        if snapshot.settings().community != self.community() || begun < checked_at {
            return Err(Error::Identity);
        }
        let tx = self.authority_scope.tx().await?;
        let observed = self.now()? as u64;
        let (tx, original) = self
            .enrol
            .get_in_transaction(tx, auth.member(), observed as i64)
            .await?;
        self.check_record(&original)?;
        if original.state().is_terminal() {
            return Err(Error::Transition);
        }
        // Reverify the original COSE under THIS actual retained target Policy,
        // not a previously cached Verified invitation or a caller-selected ring.
        let verified = entitlement
            .invitation()
            .map(|(bytes, purpose)| {
                let ring = policy.key_ring().map_err(|_| Error::Policy)?;
                cvch::role::verify(
                    bytes,
                    ring,
                    &cvch::role::Context {
                        community: self.community(),
                        member: original.member_id().as_bytes(),
                        purpose,
                        now: observed,
                    },
                )
                .map_err(|_| Error::Policy)
            })
            .transpose()?;
        let pending = verified
            .as_ref()
            .map(|value| {
                if cvch::member_binding(value.receipt(), original.member_id().as_bytes())
                    != value.binding()
                {
                    return Err(Error::Identity);
                }
                Pending::new(value.receipt(), value.binding(), value.valid_until())
            })
            .transpose()?;
        let until = snapshot
            .valid_until()
            .min(session.valid_until())
            .min(original.expires_at().map_or(u64::MAX, |value| value as u64))
            .min(pending.as_ref().map_or(u64::MAX, Pending::expires));
        let lifetime = Duration::from_secs(until.checked_sub(begun).ok_or(Error::Transition)?);
        let cut = || -> Result<()> {
            session.check(auth, observed)?;
            self.creation_cut(observed, until)?;
            if started.elapsed() >= lifetime {
                return Err(Error::Transition);
            }
            Ok(())
        };
        cut()?;
        let (tx, phase) = self.creation().read(tx).await?;
        let redemptions = RoleRedemptions::new(self.authority_scope.clone());
        let (tx, redemption) = if matches!(entitlement, Entitlement::FounderAdmin(_)) {
            let pending = pending.as_ref().ok_or(Error::Transition)?;
            redemptions.read(tx, pending.receipt()).await?
        } else {
            (tx, None)
        };
        let retry = match (entitlement, &pending, &phase) {
            (
                Entitlement::Ordinary,
                None,
                Some(Phase::Active { .. } | Phase::LegacyActive { .. }),
            ) => false,
            (Entitlement::FirstRoot(_), Some(expected), Some(Phase::Creating(current)))
                if expected == current =>
            {
                false
            }
            (Entitlement::FirstRoot(_), Some(expected), Some(Phase::Active { pending, root }))
                if expected == pending && root == &original.member_id() =>
            {
                true
            }
            (
                Entitlement::FounderAdmin(_),
                Some(pending),
                Some(Phase::Active { .. } | Phase::LegacyActive { .. }),
            ) => {
                if let Some(effect) = redemption {
                    let expected = Redemption::new(
                        pending.receipt(),
                        pending.binding(),
                        pending.expires(),
                        original.member_id(),
                        lease,
                        original.revision(),
                    )?;
                    if effect != expected {
                        return Err(Error::Transition);
                    }
                    true
                } else {
                    false
                }
            }
            _ => return Err(Error::Transition),
        };
        let current = date(observed as i64)?;
        let last = current
            .checked_add_months(chrono::Months::new(self.lease_months))
            .ok_or(Error::InvalidInput)?;
        if lease < crgs::YearMonth::new(current.year() as u16, current.month() as u8)?
            || lease > crgs::YearMonth::new(last.year() as u16, last.month() as u8)?
        {
            return Err(Error::InvalidInput);
        }
        let decision = self
            .admission_decision(&request, &original, observed)
            .await?;
        cut()?;
        let (tx, existing) = self
            .register
            .member_in_transaction(tx, &original.member_id())
            .await?;
        if retry {
            let existing = existing.ok_or(Error::Transition)?;
            if original.state() != State::Admitted
                || existing.role != entitlement.role()
                || existing.handle.is_none()
                || existing.lease_end != lease
                || roles::lease_deadline(existing.lease_end)? <= observed
            {
                return Err(Error::Transition);
            }
            // The same actual receipt/effect was already committed. Releasing
            // this read-only transaction must not claim, admit or renew again.
            cut()?;
            tx.rollback().await?;
            cut()?;
            return Ok(original);
        }
        if pending.is_some() && existing.is_some() {
            return Err(Error::Transition);
        }
        let (tx, row) = self
            .enrol
            .apply_in_transaction(
                tx,
                &original,
                Event::PolicyEvaluated(&decision),
                observed as i64,
            )
            .await?;
        if row.state().is_terminal() {
            return Err(Error::Transition);
        }
        let (tx, member) = if existing.is_some() {
            self.register
                .extend_lease_in_transaction(tx, &row.member_id(), lease, current)
                .await?
        } else {
            let handle = self
                .current_handle(&original)
                .await?
                .ok_or(Error::Transition)?;
            self.register
                .admit_in_transaction(
                    tx,
                    crgs::Admission {
                        id: row.member_id(),
                        handle,
                        role: entitlement.role(),
                        lease_end: lease,
                    },
                    current,
                )
                .await?
        };
        if member.handle.is_none() {
            return Err(Error::Transition);
        }
        let (mut tx, row) = self
            .enrol
            .apply_in_transaction(
                tx,
                &row,
                Event::AdmissionRecorded {
                    member: &member,
                    decision: &decision,
                },
                observed as i64,
            )
            .await?;
        if row.state() != State::Admitted {
            return Err(Error::Transition);
        }
        if let Some(pending) = pending {
            let claim = cgts::Claim::new("cvch", pending.receipt().as_bytes().to_vec())
                .map_err(|_| Error::InvalidInput)?;
            tx = self
                .gate_claims
                .claim_in_transaction(tx, &claim)
                .await
                .map_err(|_| Error::Transition)?;
            if matches!(entitlement, Entitlement::FirstRoot(_)) {
                (tx, _) = self.creation().activate(tx, &pending, &member.id).await?;
            } else {
                let effect = Redemption::new(
                    pending.receipt(),
                    pending.binding(),
                    pending.expires(),
                    member.id.clone(),
                    member.lease_end,
                    row.revision(),
                )?;
                tx = redemptions.insert(tx, &effect).await?;
            }
        }
        let durations = crbk::MembershipSettings::from_snapshot(snapshot.settings())
            .map_err(|_| Error::Policy)?;
        let probation_until = cplc::day(observed)
            .checked_add(u64::from(durations.probation_days) * cplc::DAY)
            .ok_or(Error::InvalidInput)?;
        tx = self
            .storage
            .admit_probation_in_transaction(tx, row.subject(), probation_until, observed)
            .await?;
        // The original writer excludes independent SDK/legal/Policy changes.
        // Scheduled authority still requires these actual reads in ONE second.
        self.admission_decision(&request, &original, observed)
            .await?;
        cut()?;
        tx.commit().await?;
        cut().map_err(|_| Error::Unavailable)?;
        Ok(row)
    }

    async fn admission_decision<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: &AdmissionRequest<'_, R, P, K>,
        row: &Record,
        observed: u64,
    ) -> Result<crbk::Decision> {
        self.identity(request.authentication).await?;
        self.unrestricted(row.subject()).await?;
        let decision = request
            .policy
            .may_current(
                request.snapshot,
                crbk::Subject {
                    id: row.subject(),
                    membership: row.state().membership(),
                },
                &self.action,
                request.gates,
                request.checked_at,
                observed,
            )
            .await
            .map_err(|_| Error::Policy)?;
        if !decision.allowed {
            return Err(Error::Policy);
        }
        Ok(decision)
    }
}
