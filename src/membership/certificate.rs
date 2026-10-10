//! Original authenticated-passkey certificate owner under a member mutation lease.
use super::*;

#[cfg(test)]
mod tests;

/// Genuine registration and certificate preparation under the original member lock.
/// Keeping this owner alive serializes removal through durable certificate signing.
pub struct RegisteredPasskey {
    instance: Arc<()>,
    enrolment: Record,
    passkey: ckyh::StoredPasskey,
    certificate: ckyh::certificate::RegistrationCertificate,
    observed_at: Option<u64>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}
impl RegisteredPasskey {
    /// Original committed public credential row; its UUID is server routing only.
    pub fn passkey(&self) -> &ckyh::StoredPasskey {
        &self.passkey
    }
    /// Keyhole-only preparation bound to the actual enrolled pseudonym.
    pub fn certificate(&self) -> &ckyh::certificate::RegistrationCertificate {
        &self.certificate
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Read the retained revoked credential IDs after the signalled mutation
    /// releases its member lock. Policy must durably union these into its public
    /// revocations before publishing and acknowledging the outbox generation.
    pub async fn revoked_passkeys(&self, event: &crate::Revocation) -> Result<Vec<Vec<u8>>> {
        crate::text(&event.member)?;
        let row = self
            .enrol_store
            .load_subject(&event.member)
            .await?
            .ok_or(Error::Transition)?;
        self.check_record(&row)?;
        let _guard = crate::storage::member_lock(self.storage.community(), row.user()).await;
        Ok(self
            .credentials(row.user())
            .await?
            .into_iter()
            .filter(|key| key.is_revoked())
            .map(|key| key.credential_id().as_ref().to_vec())
            .collect())
    }
    /// Renew only the passkey that authenticated this live session. This also
    /// reconciles a lost first/additional-registration certificate response.
    pub async fn passkey_certificate(&self, auth: &Authentication) -> Result<RegisteredPasskey> {
        let now = self.now()?;
        let guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;
        let row = self.authenticated(auth, now).await?;
        let receipt = self
            .credentials(auth.member())
            .await?
            .into_iter()
            .find(|key| key.credential_id() == auth.credential_id() && !key.is_revoked())
            .ok_or(Error::Passkey)?;
        self.prepare_certificate(row, receipt, guard, now).await
    }

    async fn prepare_certificate(
        &self,
        row: Record,
        passkey: ckyh::StoredPasskey,
        guard: tokio::sync::OwnedMutexGuard<()>,
        observed_at: i64,
    ) -> Result<RegisteredPasskey> {
        let keys = self.passkeys.clone();
        let user = row.user();
        let credential = passkey.credential_id().clone();
        let pseudonym = row.subject().to_owned();
        let certificate =
            blocking(move || keys.registration_certificate(user, &credential, &pseudonym)).await?;
        let mut prepared = RegisteredPasskey {
            instance: self.instance.clone(),
            enrolment: row,
            passkey,
            certificate,
            observed_at: Some(u64::try_from(observed_at).map_err(|_| Error::InvalidInput)?),
            _guard: guard,
        };
        self.check_certificate(&mut prepared).await?;
        Ok(prepared)
    }

    /// Recheck the original clock/lifecycle after signing awaits, while the same
    /// mutation lease is held. Returns the checked completion time so the signer
    /// owner can refuse a certificate that expired during an await. Signature
    /// persistence alone is not live membership.
    pub async fn check_certificate(&self, prepared: &mut RegisteredPasskey) -> Result<u64> {
        // Cancellation or refusal consumes this lease's check state. A later
        // caller cannot revive it or forget a previous completion-time floor.
        let floor = prepared.observed_at.take().ok_or(Error::Identity)?;
        let now = self.now()?;
        if !Arc::ptr_eq(&self.instance, &prepared.instance)
            || now < 0
            || (now as u64) < floor
            || prepared.enrolment.community() != self.storage.community()
        {
            return Err(Error::Identity);
        }
        let row = self.enrol.view(prepared.enrolment.user(), now).await?;
        if row.subject() != prepared.certificate.member() || row.state().is_terminal() {
            return Err(Error::Transition);
        }
        self.unrestricted(row.subject()).await?;
        if self
            .credentials(row.user())
            .await?
            .iter()
            .any(|key| key.credential_id() == prepared.passkey.credential_id() && !key.is_revoked())
        {
            let completed = self.now()?;
            if completed < now || row.expires_at().is_some_and(|end| completed >= end) {
                return Err(Error::Transition);
            }
            prepared.observed_at = Some(completed as u64);
            Ok(completed as u64)
        } else {
            Err(Error::Passkey)
        }
    }
}
