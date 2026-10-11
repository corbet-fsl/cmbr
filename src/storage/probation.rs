//! Original initialize-once and expiry clear staged in the admission writer.
use super::*;

pub(super) async fn admit(
    store: &LibsqlStorage,
    mut tx: crlt::Transaction,
    member: &str,
    until: u64,
    now: u64,
) -> Result<crlt::Transaction> {
    if !tx.belongs_to(&store.scope) {
        return Err(Error::Identity);
    }
    crate::text(member)?;
    deadline(until)?;
    let now = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
    if tx.query(PROBATION, [member]).await?.is_empty() {
        tx.execute(
            "INSERT INTO cmbr_probation (subject, probation_until) VALUES (?1, ?2)",
            params![member, until as i64],
        )
        .await?;
    }
    tx.execute("UPDATE cmbr_probation SET probation_until = NULL WHERE subject = ?1 AND probation_until <= ?2", params![member, now]).await?;
    Ok(tx)
}

#[cfg(test)]
#[path = "probation/tests.rs"]
mod tests;
