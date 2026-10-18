//! Complete role-entitled and ordinary admission share one original writer.
use super::*;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Entitlement<'a> {
    Ordinary,
    /// Creation id of the community whose creator takes the first admin seat.
    FirstAdmin(&'a str),
}
impl Entitlement<'_> {
    /// The first seat of the Root board community itself is a Root seat: the
    /// board has no higher authority to promote its first member. Every other
    /// community's creator becomes its first admin.
    fn role(self, community: &str) -> crgs::Role {
        match self {
            Self::Ordinary => crgs::Role::Member,
            Self::FirstAdmin(_) if community == "root" => crgs::Role::Root,
            Self::FirstAdmin(_) => crgs::Role::Admin,
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

    /// Admit the recorded creator as first admin, together with genuine full
    /// configured admission. Commitment, admin, lifecycle and phase are one
    /// effect; cancellation rolls back the owned writer. An exact active retry
    /// is read-only and cannot extend the original lease.
    pub async fn admit_first_admin<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
        id: &str,
    ) -> Result<Record> {
        self.admit_creation_current(request, Entitlement::FirstAdmin(id))
            .await
    }

    async fn admit_creation_current<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
        entitlement: Entitlement<'_>,
    ) -> Result<Record> {
        let auth = request.authentication;
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
        let recorded = self.creation().read(tx).await?;
        let (tx, phase) = recorded;
        let pending = match (entitlement, &phase) {
            (Entitlement::Ordinary, _) => None,
            (
                Entitlement::FirstAdmin(id),
                Some(
                    Phase::Creating(current)
                    | Phase::Active {
                        pending: current, ..
                    },
                ),
            ) => {
                let receipt = cvch::receipt_id(id);
                let expected = Pending::new(
                    &receipt,
                    &cvch::member_binding(&receipt, original.member_id().as_bytes()),
                    current.expires(),
                )?;
                if &expected != current {
                    return Err(Error::Identity);
                }
                Some(expected)
            }
            _ => return Err(Error::Transition),
        };
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
        let retry = match (entitlement, &pending, &phase) {
            (
                Entitlement::Ordinary,
                None,
                Some(Phase::Active { .. } | Phase::LegacyActive { .. }),
            ) => false,
            (Entitlement::FirstAdmin(_), Some(_), Some(Phase::Creating(_))) => false,
            (Entitlement::FirstAdmin(_), Some(_), Some(Phase::Active { root, .. })) => {
                if root != &original.member_id() {
                    return Err(Error::Transition);
                }
                true
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
                || existing.role != entitlement.role(self.community())
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
                        role: entitlement.role(self.community()),
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
            (tx, _) = self.creation().activate(tx, &pending, &member.id).await?;
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
        self.member_identity(request.authentication).await?;
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
