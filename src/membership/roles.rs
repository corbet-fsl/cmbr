//! Current original register roles held under the member's serialization lease.
use super::*;
use std::time::{Duration, Instant};

mod action;
mod assign;
mod current;
mod session;
pub use session::RoleSession;

#[cfg(test)]
mod tests;

/// Original current source-community role, never a transferable credential.
/// Keep this opaque value alive through the authorized operation and ask the
/// SAME Membership owner to recheck it after every external await.
pub struct RoleLease {
    instance: Arc<()>,
    authentication: Authentication,
    community: String,
    member: String,
    role: crgs::Role,
    checked_at: u64,
    valid_until: u64,
    started: Instant,
    lifetime: Duration,
    valid: bool,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl RoleLease {
    /// Exact original source community.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Original passport-derived source-community pseudonym.
    pub fn member(&self) -> &str {
        &self.member
    }
    /// Latest actual owner clock observation; callers cannot reset this floor.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Current role read from the original register, never a submitted assertion.
    pub fn role(&self) -> crgs::Role {
        self.role
    }
    /// Exclusive original membership and optional host-session deadline.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    /// Check timing at a synchronous release boundary using a trusted clock.
    /// This does not replace the owner's awaited current-key/legal recheck.
    pub fn is_current(&self, trusted_now: u64) -> bool {
        self.valid && self.timing_current(trusted_now)
    }

    fn timing_current(&self, trusted_now: u64) -> bool {
        self.checked_at <= trusted_now
            && trusted_now < self.valid_until
            && self.started.elapsed() < self.lifetime
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Read original current garden authority under the member serialization
    /// lease. Acquire any outer Policy lock before calling this owner.
    pub async fn role(&self, auth: &Authentication) -> Result<RoleLease> {
        self.role_until(auth, u64::MAX).await
    }

    /// Read the same role, additionally bounded by the host's ORIGINAL current
    /// session expiry. No fixed lifetime or role policy is invented here.
    pub async fn role_until(&self, auth: &Authentication, until: u64) -> Result<RoleLease> {
        let started = Instant::now();
        let begun_at = self.role_time(0, until)?;
        let guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        let mut observed = self.role_time(begun_at, until)?;
        let row = self.authenticated(auth, observed as i64).await?;
        observed = self.role_time(observed, until)?;
        let member = self.active_register_member(&row, observed as i64).await?;
        observed = self.role_time(observed, until)?;
        let valid_until = until.min(lease_deadline(member.lease_end)?);
        let seconds = valid_until
            .checked_sub(begun_at)
            .filter(|seconds| *seconds > 0)
            .ok_or(Error::Transition)?;
        let mut lease = RoleLease {
            instance: self.instance.clone(),
            authentication: auth.clone(),
            community: self.community().into(),
            member: row.subject().into(),
            role: member.role,
            checked_at: observed,
            valid_until,
            started,
            lifetime: Duration::from_secs(seconds),
            valid: true,
            _guard: guard,
        };
        self.check_role(&mut lease).await?;
        Ok(lease)
    }

    /// Recheck this SAME opaque lease without reacquiring its held member lock.
    /// Actual SDK revocation and legal changes are read through their owners.
    /// Cancellation or refusal permanently invalidates this particular lease.
    pub async fn check_role(&self, lease: &mut RoleLease) -> Result<u64> {
        if !Arc::ptr_eq(&self.instance, &lease.instance)
            || lease.community != self.community()
            || !lease.valid
        {
            return Err(Error::Identity);
        }
        // Refusal as well as cancellation cannot preserve an old success seal.
        lease.valid = false;
        let mut observed = self.role_time(lease.checked_at, lease.valid_until)?;
        if !lease.timing_current(observed) {
            return Err(Error::Transition);
        }
        let row = self
            .authenticated(&lease.authentication, observed as i64)
            .await?;
        observed = self.role_time(observed, lease.valid_until)?;
        let member = self.active_register_member(&row, observed as i64).await?;
        observed = self.role_time(observed, lease.valid_until)?;
        if row.subject() != lease.member
            || member.role != lease.role
            || lease_deadline(member.lease_end)? < lease.valid_until
        {
            return Err(Error::Transition);
        }
        self.identity(&lease.authentication).await?;
        observed = self.role_time(observed, lease.valid_until)?;
        self.unrestricted(row.subject()).await?;
        observed = self.role_time(observed, lease.valid_until)?;
        if lease.started.elapsed() >= lease.lifetime {
            return Err(Error::Transition);
        }
        lease.checked_at = observed;
        lease.valid = true;
        Ok(observed)
    }

    fn role_time(&self, floor: u64, until: u64) -> Result<u64> {
        let now = u64::try_from(self.now()?).map_err(|_| Error::InvalidInput)?;
        if now < floor || now >= until {
            return Err(Error::Transition);
        }
        Ok(now)
    }

    async fn active_register_member(&self, row: &Record, now: i64) -> Result<crgs::Member> {
        self.check_record(row)?;
        if row.state() != State::Admitted {
            return Err(Error::Transition);
        }
        let member = self
            .register
            .member(&row.member_id())
            .await?
            .ok_or(Error::Transition)?;
        let today = date(now)?;
        let month = crgs::YearMonth::new(today.year() as u16, today.month() as u8)?;
        if member.handle.is_none() || member.lease_end < month {
            return Err(Error::Transition);
        }
        Ok(member)
    }
}

pub(super) fn lease_deadline(month: crgs::YearMonth) -> Result<u64> {
    let start = chrono::NaiveDate::from_ymd_opt(month.year().into(), month.month().into(), 1)
        .ok_or(Error::InvalidInput)?;
    let end = start
        .checked_add_months(chrono::Months::new(1))
        .ok_or(Error::InvalidInput)?;
    end.and_hms_opt(0, 0, 0)
        .ok_or(Error::InvalidInput)?
        .and_utc()
        .timestamp()
        .try_into()
        .map_err(|_| Error::InvalidInput)
}
