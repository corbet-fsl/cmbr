//! An explicit refused admission retains the same current authority as a grant.
use super::*;
use std::time::{Duration, Instant};

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Record the original negative Policy decision and its revocation notice
    /// in one writer. This does not grant admission or activate a community.
    /// The supplied gate verification timestamp and session are never renewed.
    pub async fn lapse_current<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
        &self,
        request: AdmissionRequest<'_, R, P, K>,
    ) -> Result<Record> {
        let started = Instant::now();
        let begun = self.now()? as u64;
        let auth = request.authentication;
        let _guard = crate::storage::member_lock(self.community(), auth.member()).await;
        if request.snapshot.settings().community != self.community() || begun < request.checked_at {
            return Err(Error::Identity);
        }
        let mut tx = self.authority_scope.tx().await?;
        let observed = self.now()? as u64;
        let original;
        (tx, original) = self
            .enrol
            .get_in_transaction(tx, auth.member(), observed as i64)
            .await?;
        self.check_record(&original)?;
        if original.state().is_terminal() {
            return Err(Error::Transition);
        }
        let until = request
            .snapshot
            .valid_until()
            .min(request.session.valid_until())
            .min(original.expires_at().map_or(u64::MAX, |value| value as u64));
        let lifetime = Duration::from_secs(until.checked_sub(begun).ok_or(Error::Transition)?);
        let cut = || {
            request.session.check(auth, observed)?;
            self.creation_cut(observed, until)?;
            if started.elapsed() >= lifetime {
                return Err(Error::Transition);
            }
            Ok(())
        };
        cut()?;
        let decision = self.lapse_decision(&request, &original, observed).await?;
        if original.state() == State::Admitted {
            self.storage
                .signal_revocation_transaction(&mut tx, original.subject())
                .await?;
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
        self.lapse_decision(&request, &original, observed).await?;
        cut()?;
        tx.commit().await?;
        cut().map_err(|_| Error::Unavailable)?;
        Ok(row)
    }

    async fn lapse_decision<R: crbk::Storage, P: cplc::Storage, K: cplc::csgn::Store>(
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
        if decision.allowed {
            return Err(Error::Policy);
        }
        Ok(decision)
    }
}
