//! Original caller session retained by a completing role mutation.
use crate::{Authentication, Result};

/// Read-only capability supplied by the actual session owner, not wire input.
/// It must invalidate on removal/replacement and use the original live clock.
/// Queued/completing work retains it after HTTP cancellation; no mutex re-lock
/// or new session/deadline can restore this particular authority.
pub trait RoleSession: Send + Sync {
    /// Exclusive original host session deadline; never extended by a command.
    fn valid_until(&self) -> u64;
    /// Check exact original session liveness at a trusted owner observation.
    fn check(&self, authentication: &Authentication, observed: u64) -> Result<()>;
}
