//! Original role-assignment rights and UUID-ordered actor/target ownership.
use super::*;

struct Window {
    floor: u64,
    begun_at: u64,
    until: u64,
    started: Instant,
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Assign the ORIGINAL register role through a current garden actor.
    /// Admins may assign/remove Admins; only Roots may assign/remove Roots.
    pub async fn set_role(
        &self,
        auth: &Authentication,
        target: Uuid,
        role: crgs::Role,
    ) -> Result<()> {
        let started = Instant::now();
        let observed = self.role_time(0, u64::MAX)?;
        self.assign_role(
            auth,
            target,
            role,
            Window {
                floor: observed,
                begun_at: observed,
                until: u64::MAX,
                started,
            },
        )
        .await
    }

    /// Resolve a public community pseudonym through the original enrolment
    /// index. The trusted host supplies its ORIGINAL checked time/session end.
    /// A member request cannot supply a UUID or extend that authority window.
    pub async fn set_member_role(
        &self,
        auth: &Authentication,
        member: &str,
        role: crgs::Role,
        checked_at: u64,
        valid_until: u64,
    ) -> Result<()> {
        crate::text(member)?;
        if checked_at >= valid_until || i64::try_from(valid_until).is_err() {
            return Err(Error::InvalidInput);
        }
        let started = Instant::now();
        let begun_at = self.role_time(checked_at, valid_until)?;
        let mut observed = begun_at;
        self.identity(auth).await?;
        observed = self.role_time(observed, valid_until)?;
        let row = self
            .enrol_store
            .load_subject(member)
            .await?
            .ok_or(Error::Transition)?;
        self.check_record(&row)?;
        observed = self.role_time(observed, valid_until)?;
        self.assign_role(
            auth,
            row.user(),
            role,
            Window {
                floor: observed,
                begun_at,
                until: valid_until,
                started,
            },
        )
        .await
    }

    async fn assign_role(
        &self,
        auth: &Authentication,
        target: Uuid,
        role: crgs::Role,
        window: Window,
    ) -> Result<()> {
        let actor = auth.member();
        let first = actor.min(target);
        let second = actor.max(target);
        let first_guard = crate::storage::member_lock(self.storage.community(), first).await;
        let second_guard = if first == second {
            None
        } else {
            Some(crate::storage::member_lock(self.storage.community(), second).await)
        };
        let owner = self.clone();
        let authentication = auth.clone();
        // The genuine mutation and BOTH leases survive awaiting cancellation.
        completing(async move {
            let _guards = (first_guard, second_guard);
            let Window {
                floor,
                begun_at,
                until,
                started,
            } = window;
            let mut observed = owner.role_time(floor, until)?;
            let actor_row = owner
                .authenticated(&authentication, observed as i64)
                .await?;
            observed = owner.role_time(observed, until)?;
            let actor_member = owner
                .active_register_member(&actor_row, observed as i64)
                .await?;
            observed = owner.role_time(observed, until)?;
            // Preserve the original followup: an ordinary Member cannot cause
            // another member's lifecycle maintenance or role mutation.
            if actor_member.role == crgs::Role::Member {
                return Err(Error::Policy);
            }
            let target_row = owner.live(target, observed as i64).await?;
            observed = owner.role_time(observed, until)?;
            let target_member = owner
                .active_register_member(&target_row, observed as i64)
                .await?;
            observed = owner.role_time(observed, until)?;
            match actor_member.role {
                crgs::Role::Root => {}
                crgs::Role::Admin
                    if target_member.role != crgs::Role::Root && role != crgs::Role::Root => {}
                _ => return Err(Error::Policy),
            }
            let deadline = until
                .min(lease_deadline(actor_member.lease_end)?)
                .min(lease_deadline(target_member.lease_end)?);
            let lifetime =
                Duration::from_secs(deadline.checked_sub(begun_at).ok_or(Error::Transition)?);
            owner.identity(&authentication).await?;
            observed = owner.role_time(observed, deadline)?;
            owner.unrestricted(actor_row.subject()).await?;
            observed = owner.role_time(observed, deadline)?;
            owner.unrestricted(target_row.subject()).await?;
            owner.role_time(observed, deadline)?;
            if started.elapsed() >= lifetime {
                return Err(Error::Transition);
            }
            // Once the original write is attempted, no failed tail establishes
            // that it did not commit. There is no role history or new role table.
            owner
                .register
                .set_role(&target_row.member_id(), role)
                .await
                .map_err(|_| Error::Unavailable)?;
            let completed = async {
                observed = owner.role_time(observed, deadline)?;
                owner.identity(&authentication).await?;
                observed = owner.role_time(observed, deadline)?;
                owner.unrestricted(actor_row.subject()).await?;
                observed = owner.role_time(observed, deadline)?;
                owner.unrestricted(target_row.subject()).await?;
                owner.role_time(observed, deadline)?;
                if started.elapsed() >= lifetime {
                    return Err(Error::Transition);
                }
                Ok(())
            }
            .await;
            completed.map_err(|_| Error::Unavailable)
        })
        .await
    }
}
