//! Exact pending field authority retained across the native accounting worker.
use super::*;

/// Transient owner lease, never a wire input or proof verdict. Its exact pending
/// change is selected by Membership; native verification cannot change it.
pub struct PendingPinChange {
    instance: Arc<()>,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    user: Uuid,
    credential: Vec<u8>,
    community: String,
    member: String,
    field: String,
    expected: Pin,
    replacement: cpns::Fingerprint,
    until: i64,
}
impl PendingPinChange {
    fn change(&self) -> cpns::server::Change<'_> {
        cpns::server::Change {
            community: &self.community,
            member: &self.member,
            field: &self.field,
            expected: self.expected,
            replacement: self.replacement,
        }
    }
    /// Original receipt bytes remain untrusted; the actual configured account
    /// worker must return the sealed native capability with this retained lease.
    pub fn native_request(&self, evidence: &[u8]) -> Result<cgts::pins::PinChangeRequest> {
        cgts::pins::PinChangeRequest::new(&self.change(), evidence).map_err(|_| Error::Pin)
    }
}

impl<S: Storage + 'static, L: clbs::Verifier + 'static, C: clbs::Clock + 'static>
    Membership<S, L, C>
{
    /// Retain the original member lock and exact active passkey through native
    /// completed-spend verification. `until` is the trusted exclusive session
    /// and policy bound, never the historical receipt/request deadline.
    pub async fn prepare_pin_change(
        &self,
        auth: &Authentication,
        field: &str,
        expected: Pin,
        replacement: &crate::PinV2,
        until: u64,
    ) -> Result<PendingPinChange> {
        let until = i64::try_from(until).map_err(|_| Error::InvalidInput)?;
        if self.now()? >= until {
            return Err(Error::Unavailable);
        }
        let guard = crate::storage::member_lock(self.community(), auth.member()).await;
        let row = self.authenticated(auth, self.now()?).await?;
        let replacement = replacement.checked(self.community(), row.subject(), field)?;
        let until = row.expires_at().map_or(until, |expires| until.min(expires));
        if self.now()? >= until {
            return Err(Error::Unavailable);
        }
        let pending = PendingPinChange {
            instance: self.instance.clone(),
            _guard: guard,
            user: auth.member(),
            credential: auth.credential_id().as_ref().to_vec(),
            community: self.community().into(),
            member: row.subject().into(),
            field: field.into(),
            expected,
            replacement,
            until,
        };
        pending.change().next_pin().map_err(|_| Error::Pin)?;
        Ok(pending)
    }

    /// Check genuine current key/lifecycle/legal owners under the pin writer
    /// lock, then consume the exact sealed native capability by revision CAS.
    /// Separate pooled reads require another connection; absence refuses.
    pub async fn finish_pin_change(
        &self,
        auth: &Authentication,
        pending: PendingPinChange,
        spent: &cgts::pins::SpentChange,
    ) -> Result<Pin> {
        if !Arc::ptr_eq(&self.instance, &pending.instance)
            || auth.member() != pending.user
            || auth.credential_id().as_ref() != pending.credential.as_slice()
            || auth.community() != pending.community
        {
            return Err(Error::Identity);
        }
        let checked_at = std::sync::atomic::AtomicI64::new(0);
        let cut = || {
            let now = self.now().map_err(|_| cpns::server::Error::TokenRejected)?;
            let checked = checked_at.load(std::sync::atomic::Ordering::Acquire);
            // Legal orders and lifecycle views depend on time. A changed
            // observation requires a fresh owner read, even with writers
            // excluded; do not reuse an earlier green result at the final cut.
            if now >= pending.until || (checked != 0 && now != checked) {
                return Err(cpns::server::Error::TokenRejected);
            }
            Ok(())
        };
        let result = self
            .pins
            .change_current(
                pending.change(),
                spent,
                || async {
                    cut()?;
                    let now = self.now().map_err(|_| cpns::server::Error::TokenRejected)?;
                    let row = self
                        .authenticated(auth, now)
                        .await
                        .map_err(|_| cpns::server::Error::TokenRejected)?;
                    if row.subject() != pending.member {
                        return Err(cpns::server::Error::TokenRejected);
                    }
                    checked_at.store(now, std::sync::atomic::Ordering::Release);
                    cut()?;
                    Ok(())
                },
                cut,
            )
            .await;
        drop(pending);
        Ok(result?)
    }
}
