//! Final role authority while independent writes to the SAME database are fenced.
use super::*;

struct Recheck<'a> {
    lease: &'a mut RoleLease,
    complete: bool,
}

impl Drop for Recheck<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.lease.valid = false;
        }
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Run a synchronous authorized operation under the actual membership DB's
    /// Immediate writer barrier. `lease` must already retain THIS member guard;
    /// acquire Policy owners before it and consume any root nonce BEFORE this
    /// call, since the root/source scopes may share a physical database.
    ///
    /// Key, legal, lifecycle and role reads still use their original owners on
    /// a second pooled connection. An exhausted/single-connection pool refuses
    /// at its configured deadline. The operation cannot await or start another
    /// writer. No read verdict or role assertion is supplied by the caller.
    ///
    /// Acknowledged read-only rollback precedes returning the result. Failed or
    /// cancelled cleanup/time checks withhold it; an already consumed nonce is
    /// never restored. Samples bracket cleanup, not physical wallclock latency.
    pub async fn with_current_role<T>(
        &self,
        lease: &mut RoleLease,
        operation: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        self.with_role_barrier(lease, None, operation).await
    }

    /// Apply the same writer-held role/key/legal barrier to an exact operation
    /// selected by the trusted host. Membership restrictions still apply too.
    pub async fn with_current_role_action<T>(
        &self,
        lease: &mut RoleLease,
        action: &str,
        operation: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        self.with_role_barrier(lease, Some(action), operation).await
    }

    async fn with_role_barrier<T>(
        &self,
        lease: &mut RoleLease,
        action: Option<&str>,
        operation: impl FnOnce(u64) -> Result<T>,
    ) -> Result<T> {
        if !Arc::ptr_eq(&self.instance, &lease.instance) || !lease.valid {
            return Err(Error::Identity);
        }
        let mut recheck = Recheck {
            lease,
            complete: false,
        };
        // Every cancellation point, including acquisition/cleanup, poisons the
        // old observation. Only this complete owner operation restores it.
        recheck.lease.valid = false;
        let transaction = self.authority_scope.tx().await?;
        // Bracket the actual reads as well as signing: a scheduled legal order
        // may activate while its database read is awaiting completion.
        let started = self.role_time(recheck.lease.checked_at, recheck.lease.valid_until)?;
        recheck.lease.valid = true;
        let observed = match action {
            Some(action) => self.check_role_action(recheck.lease, action).await?,
            None => self.check_role(recheck.lease).await?,
        };
        if observed != started {
            return Err(Error::Transition);
        }
        self.role_release_cut(recheck.lease, observed)?;
        let result = operation(observed)?;
        self.role_release_cut(recheck.lease, observed)?;
        transaction.rollback().await?;
        self.role_release_cut(recheck.lease, observed)?;
        recheck.complete = true;
        Ok(result)
    }

    fn role_release_cut(&self, lease: &RoleLease, observed: u64) -> Result<()> {
        // Existing legal orders can become effective solely as time advances.
        // Like the native-pin cut, a changed second requires fresh owner reads;
        // never reuse an earlier all-clear merely because writers are blocked.
        if self.role_time(observed, lease.valid_until)? != observed || !lease.is_current(observed) {
            return Err(Error::Transition);
        }
        Ok(())
    }
}
