//! Minimal FounderAdmin effect reconciliation inside the original caller writer.
//! Stored data is neither a role voucher nor current membership authority.
use crate::{Error, Result};
use crlt::{Community, Row, Transaction, params};

/// Append separately to the complete application migration history. Creating
/// this table grants no founder, role or community-creation authority.
pub const ROLE_REDEMPTION_SCHEMA: &str = "CREATE TABLE cmbr_role_redemption (
    community_id TEXT NOT NULL,
    receipt TEXT NOT NULL CHECK (length(receipt) = 64 AND NOT (receipt GLOB '*[^0-9a-f]*')),
    binding TEXT NOT NULL CHECK (length(binding) = 64 AND NOT (binding GLOB '*[^0-9a-f]*')),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    member TEXT NOT NULL CHECK (length(member) BETWEEN 1 AND 1024),
    lease_year INTEGER NOT NULL CHECK (lease_year BETWEEN 1 AND 9999),
    lease_month INTEGER NOT NULL CHECK (lease_month BETWEEN 1 AND 12),
    admitted_revision INTEGER NOT NULL CHECK (admitted_revision > 0),
    PRIMARY KEY (community_id, receipt),
    UNIQUE (community_id, member)
) WITHOUT ROWID;";

/// Original verified receipt and exact admitted effect; no signature/session log.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Redemption {
    receipt: String,
    binding: String,
    expires: u64,
    member: crgs::MemberId,
    lease: crgs::YearMonth,
    admitted_revision: u64,
}
impl Redemption {
    pub(crate) fn new(
        receipt: &str,
        binding: &str,
        expires: u64,
        member: crgs::MemberId,
        lease: crgs::YearMonth,
        admitted_revision: u64,
    ) -> Result<Self> {
        hex(receipt)?;
        hex(binding)?;
        member_text(&member)?;
        if expires == 0
            || expires > i64::MAX as u64
            || admitted_revision == 0
            || admitted_revision > i64::MAX as u64
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            receipt: receipt.into(),
            binding: binding.into(),
            expires,
            member,
            lease,
            admitted_revision,
        })
    }
    pub(crate) fn receipt(&self) -> &str {
        &self.receipt
    }
    pub(crate) fn binding(&self) -> &str {
        &self.binding
    }
    pub(crate) fn expires(&self) -> u64 {
        self.expires
    }
    pub(crate) fn member(&self) -> &crgs::MemberId {
        &self.member
    }
    pub(crate) fn lease(&self) -> crgs::YearMonth {
        self.lease
    }
    pub(crate) fn admitted_revision(&self) -> u64 {
        self.admitted_revision
    }
}

pub(crate) struct RoleRedemptions {
    scope: Community,
}
impl RoleRedemptions {
    pub(crate) fn new(scope: Community) -> Self {
        Self { scope }
    }

    /// Return this exact writer only on success. Errors/cancellation drop all
    /// previously staged owners; this method neither starts nor commits a writer.
    pub(crate) async fn read(
        &self,
        mut tx: Transaction,
        receipt: &str,
    ) -> Result<(Transaction, Option<Redemption>)> {
        if !tx.belongs_to(&self.scope) {
            return Err(Error::Identity);
        }
        hex(receipt)?;
        let rows = tx.query(
            "SELECT receipt,binding,expires_at,member,lease_year,lease_month,admitted_revision FROM cmbr_role_redemption WHERE receipt = ?1",
            params![receipt],
        ).await?;
        let value = match rows.as_slice() {
            [] => None,
            [row] => Some(decode(row)?),
            _ => return Err(Error::Unavailable),
        };
        Ok((tx, value))
    }

    /// Stage one immutable original FounderAdmin effect. Only the upper owner
    /// authorizes it and joins the genuine voucher claim and Register admission.
    /// An identical tuple is a read-only retry, never a second role effect.
    pub(crate) async fn insert(&self, tx: Transaction, value: &Redemption) -> Result<Transaction> {
        let (mut tx, previous) = self.read(tx, value.receipt()).await?;
        if let Some(previous) = previous {
            return if previous == *value {
                Ok(tx)
            } else {
                Err(Error::Busy)
            };
        }
        let member = member_text(value.member())?;
        if !tx
            .query(
                "SELECT receipt FROM cmbr_role_redemption WHERE member = ?1",
                params![member],
            )
            .await?
            .is_empty()
        {
            return Err(Error::Transition);
        }
        let written = tx.execute(
            "INSERT INTO cmbr_role_redemption (receipt,binding,expires_at,member,lease_year,lease_month,admitted_revision) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![value.receipt(), value.binding(), value.expires() as i64, member,
                i64::from(value.lease().year()), i64::from(value.lease().month()),
                value.admitted_revision() as i64],
        ).await?;
        if written != 1 {
            return Err(Error::Unavailable);
        }
        let (tx, stored) = self.read(tx, value.receipt()).await?;
        if stored.as_ref() != Some(value) {
            return Err(Error::Unavailable);
        }
        Ok(tx)
    }
}
fn hex(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}
fn member_text(member: &crgs::MemberId) -> Result<&str> {
    let value = std::str::from_utf8(member.as_bytes()).map_err(|_| Error::InvalidInput)?;
    crate::text(value)?;
    Ok(value)
}
fn decode(row: &Row) -> Result<Redemption> {
    let lease = crgs::YearMonth::new(
        u16::try_from(row.get_i64(4)?).map_err(|_| Error::Unavailable)?,
        u8::try_from(row.get_i64(5)?).map_err(|_| Error::Unavailable)?,
    )
    .map_err(|_| Error::Unavailable)?;
    Redemption::new(
        row.get_str(0)?,
        row.get_str(1)?,
        u64::try_from(row.get_i64(2)?).map_err(|_| Error::Unavailable)?,
        crgs::MemberId::new(row.get_str(3)?.as_bytes()).map_err(|_| Error::Unavailable)?,
        lease,
        u64::try_from(row.get_i64(6)?).map_err(|_| Error::Unavailable)?,
    )
    .map_err(|_| Error::Unavailable)
}

#[cfg(test)]
mod tests;
