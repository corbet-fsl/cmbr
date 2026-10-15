//! Original membership source with retained identity and read-only revalidation.
use super::*;
use std::time::{Duration, Instant};

/// Opaque owner lease retained across native work and caller cancellation.
/// It contains no cloned authority verdict; use the same Membership to recheck
/// all current facts at the actual transaction's logical decision.
pub struct SourceLease {
    instance: Arc<()>,
    community: String,
    member: String,
    user: Uuid,
    checked_at: u64,
    valid_until: u64,
    started: Instant,
    lifetime: Duration,
    valid: bool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

#[cfg(test)]
mod tests;

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Read every current owner under the already held member lease. The caller
    /// also holds the SAME database's existing writer transaction; this method
    /// acquires no writer, repeats no member lock and performs no cleanup writes.
    /// `action` is the independently selected operation, not a wire value.
    /// `observed` is the native owner's live commit sample. Every read and the
    /// final sample must remain in that exact second, preserving scheduled law.
    /// Refusal/cancellation invalidates this lease; no old success is retained.
    pub async fn check_source(
        &self,
        lease: &mut SourceLease,
        auth: &Authentication,
        _action: &str,
        observed: u64,
    ) -> Result<cplc::MembershipFacts> {
        if !lease.valid
            || !Arc::ptr_eq(&self.instance, &lease.instance)
            || lease.community != self.community()
            || lease.user != auth.member()
        {
            return Err(Error::Identity);
        }
        lease.valid = false;
        let current = || -> Result<()> {
            let now = u64::try_from(self.now()?).map_err(|_| Error::InvalidInput)?;
            if now != observed
                || now < lease.checked_at
                || now >= lease.valid_until
                || lease.started.elapsed() >= lease.lifetime
            {
                return Err(Error::Transition);
            }
            Ok(())
        };
        current()?;
        let row = self
            .authenticated_member(
                auth,
                i64::try_from(observed).map_err(|_| Error::InvalidInput)?,
            )
            .await?;
        current()?;
        if row.subject() != lease.member
            || row.state() != State::Admitted
            || self.storage.revocation_pending(row.subject()).await?
        {
            return Err(Error::Transition);
        }
        current()?;
        let registered = self
            .register
            .member(&row.member_id())
            .await?
            .ok_or(Error::Transition)?;
        current()?;
        if registered.handle.is_none() {
            return Err(Error::Transition);
        }
        let start = chrono::NaiveDate::from_ymd_opt(
            registered.lease_end.year().into(),
            registered.lease_end.month().into(),
            1,
        )
        .ok_or(Error::InvalidInput)?;
        let end = start
            .checked_add_months(chrono::Months::new(1))
            .ok_or(Error::InvalidInput)?;
        let lease_end = u64::try_from(
            end.and_hms_opt(0, 0, 0)
                .ok_or(Error::InvalidInput)?
                .and_utc()
                .timestamp(),
        )
        .map_err(|_| Error::InvalidInput)?;
        if lease_end < lease.valid_until {
            return Err(Error::Transition);
        }
        // Same public projection as clear_passed_probation, without a nested
        // write while the native ledger already owns the database writer.
        let probation_until = self
            .storage
            .probation(row.subject())
            .await?
            .ok_or(Error::Transition)?
            .filter(|until| *until > observed);
        current()?;
        let authorized_devices = self.live_device_keys(&row).await?;
        current()?;
        self.member_identity(auth).await?;
        current()?;
        self.unrestricted(row.subject()).await?;
        current()?;
        match self.legal.check(row.subject()).await? {
            clbs::State::Green => {}
            clbs::State::Red(_) => return Err(Error::Restricted),
        }
        current()?;
        lease.checked_at = observed;
        lease.valid = true;
        Ok(cplc::MembershipFacts {
            community: lease.community.clone(),
            member: lease.member.clone(),
            state: row.state().membership(),
            probation_until,
            lease_end: lease.valid_until,
            authorized_devices,
        })
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    cplc::MembershipSource for Membership<S, L, C>
{
    type Lease = SourceLease;
    async fn membership(
        &self,
        member: &str,
        now: u64,
    ) -> cplc::Result<(cplc::MembershipFacts, Self::Lease)> {
        let read: Result<_> = async {
            let started = Instant::now();
            let now_i64 = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
            if self.now()? != now_i64 {
                return Err(Error::InvalidInput);
            }
            let row = self
                .enrol_store
                .load_subject(member)
                .await?
                .ok_or(Error::Transition)?;
            let guard = crate::storage::member_lock(self.storage.community(), row.user()).await;
            let row = self.enrol.view(row.user(), now_i64).await?;
            self.unrestricted(row.subject()).await?;
            if row.subject() != member
                || row.state() != State::Admitted
                || !self
                    .credentials(row.user())
                    .await?
                    .iter()
                    .any(|key| !key.is_revoked())
            {
                return Err(Error::Transition);
            }
            if self.storage.revocation_pending(member).await? {
                return Err(Error::Restricted);
            }
            self.storage.clear_passed_probation(member, now).await?;
            let probation_until = self
                .storage
                .probation(member)
                .await?
                .ok_or(Error::Transition)?;
            let registered = self
                .register
                .member(&row.member_id())
                .await?
                .ok_or(Error::Transition)?;
            if registered.handle.is_none() {
                return Err(Error::Transition);
            }
            let start = chrono::NaiveDate::from_ymd_opt(
                registered.lease_end.year().into(),
                registered.lease_end.month().into(),
                1,
            )
            .ok_or(Error::InvalidInput)?;
            let end = start
                .checked_add_months(chrono::Months::new(1))
                .ok_or(Error::InvalidInput)?;
            let lease_end = end
                .and_hms_opt(0, 0, 0)
                .ok_or(Error::InvalidInput)?
                .and_utc()
                .timestamp();
            let lease_end = u64::try_from(lease_end).map_err(|_| Error::InvalidInput)?;
            let lifetime = Duration::from_secs(
                lease_end
                    .checked_sub(now)
                    .filter(|seconds| *seconds > 0)
                    .ok_or(Error::Transition)?,
            );
            Ok((
                cplc::MembershipFacts {
                    community: self.storage.community().into(),
                    member: member.into(),
                    state: row.state().membership(),
                    probation_until,
                    lease_end,
                    authorized_devices: self.live_device_keys(&row).await?,
                },
                SourceLease {
                    instance: self.instance.clone(),
                    community: self.community().into(),
                    member: member.into(),
                    user: row.user(),
                    checked_at: now,
                    valid_until: lease_end,
                    started,
                    lifetime,
                    valid: true,
                    _guard: guard,
                },
            ))
        }
        .await;
        read.map_err(|_| cplc::Error::Invalid("membership source unavailable"))
    }
}
