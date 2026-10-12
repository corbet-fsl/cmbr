//! Actual current actor/target authority under the original Register writer.
use super::*;

#[cfg(test)]
mod tests;

pub(super) struct RoleWriter<'a, S, L, C> {
    owner: &'a Membership<S, L, C>,
    auth: &'a Authentication,
    target: Uuid,
    actor_role: crgs::Role,
    window: Window,
    cut: Option<u64>,
}
impl<'a, S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    RoleWriter<'a, S, L, C>
{
    pub(super) fn new(
        owner: &'a Membership<S, L, C>,
        auth: &'a Authentication,
        target: Uuid,
        actor_role: crgs::Role,
        window: Window,
    ) -> Self {
        Self {
            owner,
            auth,
            target,
            actor_role,
            window,
            cut: None,
        }
    }
    pub(super) fn check_session(&self, observed: u64) -> Result<()> {
        if let Some(session) = &self.window.session {
            session.check(self.auth, observed)?;
        }
        Ok(())
    }
    fn observe(&self, floor: u64) -> Result<u64> {
        let now = self.owner.role_time(floor, self.window.until)?;
        self.check_session(now)?;
        if self.owner.role_time(now, self.window.until)? != now {
            return Err(Error::Transition);
        }
        let duration = Duration::from_secs(
            self.window
                .until
                .checked_sub(self.window.begun_at)
                .ok_or(Error::Transition)?,
        );
        if self.window.started.elapsed() >= duration {
            return Err(Error::Transition);
        }
        Ok(now)
    }
    async fn current(&mut self, before: &crgs::Member, requested: crgs::Role) -> Result<()> {
        self.cut = None;
        let begun = self.observe(self.window.floor)?;
        let actor_row = self.owner.authenticated(self.auth, begun as i64).await?;
        let actor = self
            .owner
            .active_register_member(&actor_row, begun as i64)
            .await?;
        let target_row = self.owner.enrol.view(self.target, begun as i64).await?;
        self.owner.check_record(&target_row)?;
        let target = self
            .owner
            .active_register_member(&target_row, begun as i64)
            .await?;
        if before != &target || actor.role != self.actor_role {
            return Err(Error::Transition);
        }
        match actor.role {
            crgs::Role::Root => {}
            crgs::Role::Admin
                if before.role != crgs::Role::Root && requested != crgs::Role::Root => {}
            _ => return Err(Error::Policy),
        }
        // Read actual credentials without running lifecycle maintenance under
        // this writer. The original target cannot become a keyless new role.
        if !self
            .owner
            .credentials(self.target)
            .await?
            .iter()
            .any(|key| !key.is_revoked())
        {
            return Err(Error::Transition);
        }
        for subject in [actor_row.subject(), target_row.subject()] {
            self.owner.unrestricted(subject).await?;
            match self
                .owner
                .legal
                .check(subject)
                .await?
            {
                clbs::State::Green => {}
                clbs::State::Red(_) => return Err(Error::Restricted),
            }
        }
        self.window.until = self
            .window
            .until
            .min(lease_deadline(actor.lease_end)?)
            .min(lease_deadline(before.lease_end)?);
        let observed = self.observe(begun)?;
        if observed != begun {
            return Err(Error::Transition);
        }
        self.cut = Some(observed);
        Ok(())
    }
}
impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    crgs::RoleCommitGuard for RoleWriter<'_, S, L, C>
{
    async fn check(&mut self, before: &crgs::Member, requested: crgs::Role) -> crgs::Result<()> {
        self.current(before, requested)
            .await
            .map_err(|_| crgs::Error::Storage)
    }
    fn release(&mut self) -> crgs::Result<()> {
        let cut = self.cut.ok_or(crgs::Error::Storage)?;
        if self.observe(cut).map_err(|_| crgs::Error::Storage)? != cut {
            return Err(crgs::Error::Storage);
        }
        Ok(())
    }
}
