//! Trusted operation-specific legal restrictions on the same original role lease.
use super::*;

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Recheck THIS retained role and an operation selected by the trusted host.
    /// This does not acquire another member guard or writer. The action is never
    /// a member assertion; current legal state is read through the original Gate.
    pub async fn check_role_action(&self, lease: &mut RoleLease, action: &str) -> Result<u64> {
        let floor = self.check_role(lease).await?;
        lease.valid = false;
        match self.legal.check_action(&lease.member, action).await? {
            clbs::State::Green => {}
            clbs::State::Red(_) => return Err(Error::Restricted),
        }
        let observed = self.role_time(floor, lease.valid_until)?;
        if lease.started.elapsed() >= lease.lifetime {
            return Err(Error::Transition);
        }
        lease.checked_at = observed;
        lease.valid = true;
        Ok(observed)
    }
}
