//! Private first-Root lifecycle facts, staged in the existing caller writer.
use crate::{Error, Result};
use crlt::{Community, Row, Transaction, Value, params};

/// Append separately to the host's existing migration history. The schema
/// creates no phase row: absence cannot authorize creation or ordinary admission.
pub const CREATION_SCHEMA: &str = "CREATE TABLE cmbr_creation (
    community_id TEXT NOT NULL,
    singleton INTEGER NOT NULL CHECK (singleton = 1),
    phase TEXT NOT NULL CHECK (phase IN ('creating', 'active', 'legacy_active')),
    receipt TEXT, binding TEXT, expires_at INTEGER, first_root BLOB,
    PRIMARY KEY (community_id, singleton),
    CHECK (
        (phase IN ('creating', 'active')
            AND typeof(receipt) = 'text' AND length(receipt) = 64
            AND NOT (receipt GLOB '*[^0-9a-f]*')
            AND typeof(binding) = 'text' AND length(binding) = 64
            AND NOT (binding GLOB '*[^0-9a-f]*')
            AND typeof(expires_at) = 'integer' AND expires_at > 0
            AND ((phase = 'creating' AND first_root IS NULL)
                OR (phase = 'active' AND typeof(first_root) = 'blob'
                    AND length(first_root) BETWEEN 1 AND 1024)))
        OR (phase = 'legacy_active'
            AND receipt IS NULL AND binding IS NULL AND expires_at IS NULL
            AND typeof(first_root) = 'blob'
            AND length(first_root) BETWEEN 1 AND 1024)
    )
) WITHOUT ROWID;";

/// Stored original verified invitation fields; not a transferable capability.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Pending {
    receipt: String,
    binding: String,
    expires: u64,
}

impl Pending {
    pub(crate) fn new(receipt: &str, binding: &str, expires: u64) -> Result<Self> {
        hex(receipt)?;
        hex(binding)?;
        if expires == 0 || expires > i64::MAX as u64 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            receipt: receipt.into(),
            binding: binding.into(),
            expires,
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
}

/// Current private durable phase, never admission or role authority by itself.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum State {
    Creating(Pending),
    Active {
        pending: Pending,
        root: crgs::MemberId,
    },
    LegacyActive {
        root: crgs::MemberId,
    },
}

pub(crate) struct Creation {
    scope: Community,
}

impl Creation {
    pub(crate) fn new(scope: Community) -> Self {
        Self { scope }
    }

    /// Preserve absence. Missing schema/data errors never create an active row.
    pub(crate) async fn read(&self, mut tx: Transaction) -> Result<(Transaction, Option<State>)> {
        let state = self.current(&mut tx).await?;
        Ok((tx, state))
    }

    /// The membership owner supplies actual verified original fields and first
    /// proves the original Register empty in THIS writer. This method neither
    /// verifies a voucher nor claims its receipt nor creates a Root member.
    pub(crate) async fn initialize(
        &self,
        mut tx: Transaction,
        pending: &Pending,
    ) -> Result<(Transaction, State)> {
        match self.current(&mut tx).await? {
            None => {
                tx.execute(
                    "INSERT INTO cmbr_creation (singleton, phase, receipt, binding, expires_at, first_root) VALUES (1, 'creating', ?1, ?2, ?3, NULL)",
                    params![pending.receipt.clone(), pending.binding.clone(), pending.expires as i64],
                ).await?;
            }
            Some(State::Creating(current)) if current == *pending => {}
            Some(State::Creating(_)) => return Err(Error::Busy),
            Some(_) => return Err(Error::Transition),
        }
        Ok((tx, State::Creating(pending.clone())))
    }

    /// The upper owner joins actual Root admission, original lifecycle and
    /// verified receipt claim to THIS writer. Exact Active retries still require
    /// those actual owner rows to be checked and must not claim the receipt twice.
    pub(crate) async fn activate(
        &self,
        mut tx: Transaction,
        pending: &Pending,
        root: &crgs::MemberId,
    ) -> Result<(Transaction, State)> {
        member(root)?;
        let next = State::Active {
            pending: pending.clone(),
            root: root.clone(),
        };
        match self.current(&mut tx).await? {
            Some(State::Creating(current)) if current == *pending => {
                if tx.execute("UPDATE cmbr_creation SET phase = 'active', first_root = ?1 WHERE singleton = 1", params![root.as_bytes().to_vec()]).await? != 1 {
                    return Err(Error::Unavailable);
                }
            }
            Some(current) if current == next => {}
            None | Some(State::LegacyActive { .. }) => return Err(Error::Transition),
            Some(_) => return Err(Error::Busy),
        }
        Ok((tx, next))
    }

    /// Explicit trusted migration only. The caller must prove an actual current
    /// original Register Root and matching Admitted CNrl record under THIS writer.
    /// No voucher, receipt, Root row or membership is synthesized by adoption.
    pub(crate) async fn adopt_legacy(
        &self,
        mut tx: Transaction,
        root: &crgs::MemberId,
    ) -> Result<(Transaction, State)> {
        member(root)?;
        let next = State::LegacyActive { root: root.clone() };
        match self.current(&mut tx).await? {
            None => {
                tx.execute(
                    "INSERT INTO cmbr_creation (singleton, phase, receipt, binding, expires_at, first_root) VALUES (1, 'legacy_active', NULL, NULL, NULL, ?1)",
                    params![root.as_bytes().to_vec()],
                ).await?;
            }
            Some(current) if current == next => {}
            Some(State::LegacyActive { .. }) => return Err(Error::Busy),
            Some(_) => return Err(Error::Transition),
        }
        Ok((tx, next))
    }

    async fn current(&self, tx: &mut Transaction) -> Result<Option<State>> {
        if !tx.belongs_to(&self.scope) {
            return Err(Error::Identity);
        }
        let rows = tx.query("SELECT phase, receipt, binding, expires_at, first_root FROM cmbr_creation WHERE singleton = 1", crlt::params![]).await?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => decode(row).map(Some),
            _ => Err(Error::Unavailable),
        }
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

fn member(root: &crgs::MemberId) -> Result<()> {
    crate::text(std::str::from_utf8(root.as_bytes()).map_err(|_| Error::InvalidInput)?)
}

fn null(row: &Row, index: usize) -> Result<()> {
    if matches!(row.get_value(index)?, Value::Null) {
        Ok(())
    } else {
        Err(Error::Unavailable)
    }
}

fn root(row: &Row) -> Result<crgs::MemberId> {
    let Value::Blob(bytes) = row.get_value(4)? else {
        return Err(Error::Unavailable);
    };
    let root = crgs::MemberId::new(bytes.clone()).map_err(|_| Error::Unavailable)?;
    member(&root).map_err(|_| Error::Unavailable)?;
    Ok(root)
}

fn decode(row: &Row) -> Result<State> {
    match row.get_str(0)? {
        "creating" | "active" => {
            let expiry = u64::try_from(row.get_i64(3)?).map_err(|_| Error::Unavailable)?;
            let pending = Pending::new(row.get_str(1)?, row.get_str(2)?, expiry)
                .map_err(|_| Error::Unavailable)?;
            if row.get_str(0)? == "creating" {
                null(row, 4)?;
                Ok(State::Creating(pending))
            } else {
                Ok(State::Active {
                    pending,
                    root: root(row)?,
                })
            }
        }
        "legacy_active" => {
            for index in 1..=3 {
                null(row, index)?;
            }
            Ok(State::LegacyActive { root: root(row)? })
        }
        _ => Err(Error::Unavailable),
    }
}

#[cfg(test)]
#[path = "creation/tests.rs"]
mod tests;
