//! Host-owned verified order append and membership notice share one transaction.
use crate::Storage;
use clbs::{Append, Counts, Record, Result, Revocation, Store};
use std::sync::Arc;

pub(crate) struct LegalStore<S> {
    legal: cgts::legal_storage::LibsqlStore,
    membership: Arc<S>,
}
impl<S: Storage> LegalStore<S> {
    pub(crate) fn new(db: &crlt::Db, membership: Arc<S>) -> Result<Self> {
        Ok(Self {
            legal: cgts::legal_storage::LibsqlStore::new(db, membership.community())?,
            membership,
        })
    }
}
impl<S: Storage + 'static> Store for LegalStore<S> {
    fn community(&self) -> &str {
        self.legal.community()
    }
    async fn append(&self, record: &Record) -> Result<Append> {
        let membership = self.membership.clone();
        let subject = record.order().subject.clone();
        self.legal
            .append_with(record, move |transaction| {
                Box::pin(async move {
                    membership
                        .signal_revocation_transaction(transaction, &subject)
                        .await
                        .map_err(|_| clbs::Error::Storage)
                })
            })
            .await
    }
    async fn record(&self, id: &str) -> Result<Option<Record>> {
        self.legal.record(id).await
    }
    async fn self_ban_record(&self, subject: &str) -> Result<Option<Record>> {
        self.legal.self_ban_record(subject).await
    }
    async fn orders(&self, subject: &str) -> Result<Vec<Record>> {
        self.legal.orders(subject).await
    }
    async fn revocations(&self) -> Result<Vec<Revocation>> {
        self.legal.revocations().await
    }
    async fn counts(&self) -> Result<Counts> {
        self.legal.counts().await
    }
}

#[cfg(test)]
mod tests;
