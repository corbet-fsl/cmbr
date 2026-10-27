use crate::{Error, Result};
pub(crate) mod creation;
mod probation;
use crlt::{Community, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{Arc, Mutex as StdMutex, OnceLock, Weak},
};
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Append through the service's migration history. No durable lock is stored.
pub const SCHEMA: &str = "CREATE TABLE cmbr_probation (
    community_id TEXT NOT NULL, subject TEXT NOT NULL,
    probation_until INTEGER CHECK (probation_until >= 0 AND probation_until % 86400 = 0),
    PRIMARY KEY (community_id, subject)
) WITHOUT ROWID;
CREATE INDEX cmbr_probation_expiry ON cmbr_probation (community_id, probation_until, subject);
CREATE TABLE cmbr_revocations (
    community_id TEXT NOT NULL, subject TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 0),
    pending INTEGER NOT NULL DEFAULT 1 CHECK (pending IN (0,1)),
    PRIMARY KEY (community_id, subject)
) WITHOUT ROWID;
CREATE INDEX cmbr_revocation_pending ON cmbr_revocations (community_id, pending, subject);";

/// Append after the service's existing migration history, never insert into it.
pub const DEVICE_KEYS_SCHEMA: &str = "CREATE TABLE cmbr_device_keys (
    community_id TEXT NOT NULL, subject TEXT NOT NULL,
    credential BLOB NOT NULL CHECK (length(credential) BETWEEN 1 AND 1024),
    signing_key BLOB NOT NULL CHECK (length(signing_key) = 32),
    PRIMARY KEY (community_id, subject, credential, signing_key)
) WITHOUT ROWID;";

/// Per-community registry of a member's device keys (pending, active, revoked): the credential
/// of the one-confirmation model. Appended after `DEVICE_PENDING_SCHEMA`; the table name is the
/// one of its first migration and stays.
pub const DEVICE_REGISTRY_SCHEMA: &str = "CREATE TABLE cvld_device_registry (
    community_id TEXT NOT NULL,
    member TEXT NOT NULL CHECK (length(member) BETWEEN 1 AND 64),
    device_key BLOB NOT NULL CHECK (length(device_key) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending','active','revoked')),
    initial_seed BLOB CHECK (initial_seed IS NULL OR length(initial_seed) = 32),
    initial_publication BLOB CHECK (
        initial_publication IS NULL OR (initial_seed IS NOT NULL AND length(initial_publication) = 32)
    ),
    PRIMARY KEY (community_id, member, device_key)
) WITHOUT ROWID;";

/// Pairing expiry of a PENDING device key: the instant (seconds) after which a key that
/// the pairing approved at `device_add` but that was never activated is dead. Appended after
/// `DEVICE_REGISTRY_SCHEMA`; a PENDING row without it (NULL) counts as already expired.
pub const DEVICE_PAIRING_SCHEMA: &str =
    "ALTER TABLE cvld_device_registry ADD COLUMN pending_until INTEGER
    CHECK (pending_until IS NULL OR pending_until > 0);";

/// Capability class of every registry row. Appended after `DEVICE_PAIRING_SCHEMA`; every row
/// that existed before is a full device.
pub const DEVICE_CLASS_SCHEMA: &str =
    "ALTER TABLE cvld_device_registry ADD COLUMN class TEXT NOT NULL
    DEFAULT 'full' CHECK (class IN ('full','delegated'));";

/// What a registry device key may do. A `Delegated` key (decided 2026-10-27, D1) opens
/// community sessions only: it never authorizes another device, never opens an admin session
/// and never acts for the wallet, account signing, stamps or account proofs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKeyClass {
    /// Every device-key capability of the one-confirmation model.
    Full,
    /// Community sessions only.
    Delegated,
}

/// The opaque initial creation commitment held by a device-key member's first device key,
/// and the one publication bound to it, if any. Never a root, signing or use capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceInitialCreation {
    /// Commitment stored at join (nonzero).
    pub seed: [u8; 32],
    /// The immutable publication winner, once bound (nonzero).
    pub publication: Option<[u8; 32]>,
}

/// State of one registered device key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKeyState {
    /// Announced, grants nothing yet.
    Pending,
    /// Opens sessions and counts as a live credential.
    Active,
    /// Permanently withdrawn.
    Revoked,
}

/// Append after `DEVICE_KEYS_SCHEMA`. One pending device key per passkey, granting nothing
/// until confirmed and dropped once `expires` has passed.
pub const DEVICE_PENDING_SCHEMA: &str = "CREATE TABLE cmbr_device_pending (
    community_id TEXT NOT NULL, subject TEXT NOT NULL,
    credential BLOB NOT NULL CHECK (length(credential) BETWEEN 1 AND 1024),
    signing_key BLOB NOT NULL CHECK (length(signing_key) = 32),
    expires INTEGER NOT NULL CHECK (expires > 0),
    approver BLOB CHECK (approver IS NULL OR length(approver) BETWEEN 1 AND 1024),
    PRIMARY KEY (community_id, subject, credential)
) WITHOUT ROWID;";

/// A device key authorized for pairing but not yet covered by a published lineage.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingDeviceKey {
    /// Community-local credential ID that authorized the key.
    pub credential: Vec<u8>,
    /// Public Ed25519 signing key.
    pub key: [u8; 32],
    /// Unix second after which this pending key no longer exists.
    pub expires: u64,
    /// Another live passkey of the member that approved this key (the existing device).
    pub approver: Option<Vec<u8>>,
}

/// Public signing key linked to the exact passkey that authorized it.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceKeyBinding {
    /// Community-local credential ID; never an authentication capability itself.
    pub credential: Vec<u8>,
    /// Public Ed25519 signing key. No root or private material is persisted.
    pub key: [u8; 32],
}

/// Durable request to advance cplc's epoch before further credential issuance.
/// Epoch advancement invalidates all credentials that could contain a removed key.
#[derive(Clone, PartialEq, Eq)]
pub struct Revocation {
    /// Community pseudonym whose authentication or eligibility changed.
    pub member: String,
    /// Compare-and-delete token; a newer revocation cannot be acknowledged away.
    pub generation: u64,
}
impl std::fmt::Debug for Revocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revocation").finish_non_exhaustive()
    }
}

/// Coarse membership facts and a durable revocation outbox, never mutual exclusion.
pub trait Storage: Send + Sync {
    /// Service-selected community capability.
    fn community(&self) -> &str;
    /// Replace one passkey's bounded key set after membership authorization.
    /// The caller must signal revocation before removing any previous binding.
    fn set_device_keys(
        &self,
        member: &str,
        credential: &[u8],
        keys: &[[u8; 32]],
    ) -> impl Future<Output = Result<()>> + Send;
    /// Read stored bindings; membership must filter currently revoked passkeys.
    fn device_keys(
        &self,
        member: &str,
    ) -> impl Future<Output = Result<Vec<DeviceKeyBinding>>> + Send;
    /// Replace this passkey's single pending device key. A pending key is never live.
    fn set_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        key: [u8; 32],
        expires: u64,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Record the approving passkey on this passkey's pending key.
    fn approve_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        approver: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;
    /// Remove this passkey's pending device key, if any.
    fn clear_pending_device(
        &self,
        member: &str,
        credential: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;
    /// Read stored pending keys (expired ones included; callers compare `expires`).
    fn pending_devices(
        &self,
        member: &str,
    ) -> impl Future<Output = Result<Vec<PendingDeviceKey>>> + Send;
    /// None means never initialized; Some(None) means probation has ended.
    fn probation(&self, member: &str) -> impl Future<Output = Result<Option<Option<u64>>>> + Send;
    /// Initialize once after admission. Existing probation never restarts or slides.
    fn initialize_probation(
        &self,
        member: &str,
        until: u64,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Join original initialize-once and passed-probation clearing to the exact
    /// admission writer. Unsupported storage refuses rather than acknowledging
    /// a membership whose required facts committed independently.
    fn admit_probation_in_transaction(
        &self,
        _transaction: crlt::Transaction,
        _member: &str,
        _until: u64,
        _now: u64,
    ) -> impl Future<Output = Result<crlt::Transaction>> + Send {
        std::future::ready(Err(Error::Unavailable))
    }
    /// Delete a passed probation end while retaining the initialized member row.
    fn clear_passed_probation(
        &self,
        member: &str,
        now: u64,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Delete a bounded batch of passed probation deadlines through an expiry index.
    fn prune_probation(&self, now: u64, limit: usize) -> impl Future<Output = Result<()>> + Send;
    /// Whether this member still requires a cplc revocation update.
    fn revocation_pending(&self, member: &str) -> impl Future<Output = Result<bool>> + Send;
    /// Mark a security change before its leaf mutation. Conservative invalidation
    /// after a refused mutation is safe; losing a committed revocation is not.
    fn signal_revocation(&self, member: &str) -> impl Future<Output = Result<()>> + Send;
    /// Queue a notice inside the trusted legal adapter's same-community
    /// transaction. A store that cannot join that transaction must refuse;
    /// independently writing memory or another database is not atomic.
    /// This default keeps unsupported caller stores explicitly unavailable.
    fn signal_revocation_transaction(
        &self,
        _transaction: &mut crlt::Transaction,
        _member: &str,
    ) -> impl Future<Output = Result<()>> + Send {
        std::future::ready(Err(Error::Unavailable))
    }
    /// Bounded pending outbox, in deterministic pseudonym order.
    fn revocations(&self, limit: usize) -> impl Future<Output = Result<Vec<Revocation>>> + Send;
    /// Clear only after cplc durably advanced its epoch and published fresh trust.
    fn acknowledge(&self, event: &Revocation) -> impl Future<Output = Result<()>> + Send;
    /// The registered state of this member's device key; `None` when unknown.
    fn device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> impl Future<Output = Result<Option<DeviceKeyState>>> + Send;
    /// Every ACTIVE device key of this member, in key order.
    fn active_device_keys(
        &self,
        member: &str,
    ) -> impl Future<Output = Result<Vec<[u8; 32]>>> + Send;
    /// Make `key` the member's first device key, ACTIVE, holding the member's opaque initial
    /// creation commitment `seed` (nonzero). Returns false and changes nothing when the member
    /// already has any registered key (another key, or this one in any state).
    fn bind_first_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        seed: [u8; 32],
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Register `key` as a PENDING device key of a member that already has a registered key
    /// (stamped pairing). Returns false and changes nothing when the key is already
    /// registered in any state (an equal retry is then recognised by `device_key_state`).
    /// The new PENDING row lives until `pending_until` (seconds, positive).
    fn add_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Like `add_device_key`, with the PENDING row in class `Delegated`. A store without
    /// capability classes refuses.
    fn add_delegated_device_key(
        &self,
        _member: &str,
        _key: [u8; 32],
        _pending_until: i64,
    ) -> impl Future<Output = Result<bool>> + Send {
        std::future::ready(Err(Error::Unavailable))
    }
    /// The capability class of this member's registered device key; `None` when unknown.
    /// A store without capability classes refuses.
    fn device_key_class(
        &self,
        _member: &str,
        _key: [u8; 32],
    ) -> impl Future<Output = Result<Option<DeviceKeyClass>>> + Send {
        std::future::ready(Err(Error::Unavailable))
    }
    /// The instant a PENDING key of this member expires; `None` when the key is not PENDING.
    /// A legacy PENDING row that carries no expiry reports 0 (long expired).
    fn pending_device_key_until(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> impl Future<Output = Result<Option<i64>>> + Send;
    /// Delete a PENDING key whose expiry is at or before `now`. Returns false and changes
    /// nothing for a live PENDING key, an active or revoked key, or an unknown key.
    fn remove_expired_pending_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        now: i64,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// Move a registered key from `from` to `to` (pending to active, pending or active to
    /// revoked; never out of revoked). Returns false and changes nothing when the key is not
    /// currently in `from`.
    fn set_device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
        from: DeviceKeyState,
        to: DeviceKeyState,
    ) -> impl Future<Output = Result<bool>> + Send;
    /// The initial creation commitment and publication held by this member's ACTIVE device
    /// key; `None` when the key holds none. With `bind = (seed, publication)` the publication
    /// is set atomically first: an equal retry agrees, a different seed or winner refuses.
    fn device_initial_creation(
        &self,
        member: &str,
        key: [u8; 32],
        bind: Option<([u8; 32], [u8; 32])>,
    ) -> impl Future<Output = Result<Option<DeviceInitialCreation>>> + Send;
}
pub(crate) fn device_input(member: &str, credential: &[u8], keys: &[[u8; 32]]) -> Result<()> {
    crate::text(member)?;
    if credential.is_empty()
        || credential.len() > 1024
        || keys.len() > 64
        || keys.iter().collect::<BTreeSet<_>>().len() != keys.len()
    {
        return Err(Error::InvalidInput);
    }
    for key in keys {
        let public =
            ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| Error::InvalidInput)?;
        if public.is_weak() {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}
fn registry_input(member: &str, key: &[u8; 32]) -> Result<()> {
    crate::text(member)?;
    if member.len() > 64 {
        return Err(Error::InvalidInput);
    }
    let public = ed25519_dalek::VerifyingKey::from_bytes(key).map_err(|_| Error::InvalidInput)?;
    if public.is_weak() {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn pending_until_input(pending_until: i64) -> Result<()> {
    if pending_until <= 0 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn seed_input(seed: &[u8; 32]) -> Result<()> {
    if *seed == [0; 32] {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
/// Apply one optional publication bind to a held commitment: an equal retry agrees, a
/// different seed or an existing different winner refuses and changes nothing.
fn bind_initial(
    mut current: DeviceInitialCreation,
    bind: Option<([u8; 32], [u8; 32])>,
) -> Result<DeviceInitialCreation> {
    if let Some((seed, publication)) = bind {
        if current.seed != seed
            || current
                .publication
                .is_some_and(|prior| prior != publication)
        {
            return Err(Error::Transition);
        }
        current.publication = Some(publication);
    }
    Ok(current)
}
fn bind_input(bind: &Option<([u8; 32], [u8; 32])>) -> Result<()> {
    if let Some((seed, publication)) = bind {
        seed_input(seed)?;
        seed_input(publication)?;
    }
    Ok(())
}
fn state_text(state: DeviceKeyState) -> &'static str {
    match state {
        DeviceKeyState::Pending => "pending",
        DeviceKeyState::Active => "active",
        DeviceKeyState::Revoked => "revoked",
    }
}

fn transition_allowed(from: DeviceKeyState, to: DeviceKeyState) -> bool {
    matches!(
        (from, to),
        (DeviceKeyState::Pending, DeviceKeyState::Active)
            | (DeviceKeyState::Pending, DeviceKeyState::Revoked)
            | (DeviceKeyState::Active, DeviceKeyState::Revoked)
    )
}

fn registry_state(text: &str) -> Result<DeviceKeyState> {
    match text {
        "pending" => Ok(DeviceKeyState::Pending),
        "active" => Ok(DeviceKeyState::Active),
        "revoked" => Ok(DeviceKeyState::Revoked),
        _ => Err(Error::Unavailable),
    }
}
fn deadline(until: u64) -> Result<()> {
    if until > i64::MAX as u64 || !until.is_multiple_of(86400) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
fn limit(value: usize) -> Result<i64> {
    if (1..=1000).contains(&value) {
        Ok(value as i64)
    } else {
        Err(Error::InvalidInput)
    }
}
/// Key, expiry and approving passkey of one pending device key.
type PendingEntry = ([u8; 32], u64, Option<Vec<u8>>);
#[derive(Default)]
struct MemoryState {
    probation: BTreeMap<String, Option<u64>>,
    devices: BTreeMap<(String, Vec<u8>), BTreeSet<[u8; 32]>>,
    pending: BTreeMap<(String, Vec<u8>), PendingEntry>,
    revocations: BTreeMap<String, (u64, bool)>,
    registry: BTreeMap<String, BTreeMap<[u8; 32], DeviceKeyState>>,
    /// Expiry of every PENDING registry key (seconds); absent for keys in any other state.
    pending_until: BTreeMap<(String, [u8; 32]), i64>,
    initial: BTreeMap<(String, [u8; 32]), DeviceInitialCreation>,
    /// Registry keys of class `Delegated`; every other registered key is `Full`.
    delegated: BTreeSet<(String, [u8; 32])>,
}
/// Real in-memory storage. Clones share state; no timestamps of activity exist.
#[derive(Clone)]
pub struct MemoryStorage {
    community: String,
    state: Arc<Mutex<MemoryState>>,
}
impl MemoryStorage {
    /// Create an isolated community store.
    pub fn new(community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        crate::text(&community)?;
        Ok(Self {
            community,
            state: Arc::default(),
        })
    }
}
impl MemoryStorage {
    async fn add_classed(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
        class: DeviceKeyClass,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        pending_until_input(pending_until)?;
        let mut state = self.state.lock().await;
        let keys = state.registry.entry(member.to_owned()).or_default();
        if keys.is_empty() || keys.contains_key(&key) {
            return Ok(false);
        }
        keys.insert(key, DeviceKeyState::Pending);
        state
            .pending_until
            .insert((member.to_owned(), key), pending_until);
        if class == DeviceKeyClass::Delegated {
            state.delegated.insert((member.to_owned(), key));
        } else {
            state.delegated.remove(&(member.to_owned(), key));
        }
        Ok(true)
    }
}
impl Storage for MemoryStorage {
    fn community(&self) -> &str {
        &self.community
    }
    async fn set_device_keys(
        &self,
        member: &str,
        credential: &[u8],
        keys: &[[u8; 32]],
    ) -> Result<()> {
        device_input(member, credential, keys)?;
        let mut state = self.state.lock().await;
        state.devices.insert(
            (member.into(), credential.into()),
            keys.iter().copied().collect(),
        );
        Ok(())
    }
    async fn set_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        key: [u8; 32],
        expires: u64,
    ) -> Result<()> {
        device_input(member, credential, &[key])?;
        i64::try_from(expires).map_err(|_| Error::InvalidInput)?;
        self.state
            .lock()
            .await
            .pending
            .insert((member.into(), credential.into()), (key, expires, None));
        Ok(())
    }
    async fn approve_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        approver: &[u8],
    ) -> Result<()> {
        device_input(member, credential, &[])?;
        device_input(member, approver, &[])?;
        match self
            .state
            .lock()
            .await
            .pending
            .get_mut(&(member.to_owned(), credential.to_vec()))
        {
            Some(entry) => {
                entry.2 = Some(approver.to_vec());
                Ok(())
            }
            None => Err(Error::Identity),
        }
    }
    async fn clear_pending_device(&self, member: &str, credential: &[u8]) -> Result<()> {
        device_input(member, credential, &[])?;
        self.state
            .lock()
            .await
            .pending
            .remove(&(member.to_owned(), credential.to_vec()));
        Ok(())
    }
    async fn pending_devices(&self, member: &str) -> Result<Vec<PendingDeviceKey>> {
        crate::text(member)?;
        Ok(self
            .state
            .lock()
            .await
            .pending
            .iter()
            .filter(|((subject, _), _)| subject == member)
            .map(
                |((_, credential), (key, expires, approver))| PendingDeviceKey {
                    credential: credential.clone(),
                    key: *key,
                    expires: *expires,
                    approver: approver.clone(),
                },
            )
            .collect())
    }
    async fn device_keys(&self, member: &str) -> Result<Vec<DeviceKeyBinding>> {
        crate::text(member)?;
        let state = self.state.lock().await;
        let result: Vec<_> = state
            .devices
            .iter()
            .filter(|((subject, _), _)| subject == member)
            .flat_map(|((_, credential), keys)| {
                keys.iter().map(|key| DeviceKeyBinding {
                    credential: credential.clone(),
                    key: *key,
                })
            })
            .collect();
        if result.len() > 1024 {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }
    async fn probation(&self, member: &str) -> Result<Option<Option<u64>>> {
        crate::text(member)?;
        Ok(self.state.lock().await.probation.get(member).copied())
    }
    async fn initialize_probation(&self, member: &str, until: u64) -> Result<()> {
        crate::text(member)?;
        deadline(until)?;
        self.state
            .lock()
            .await
            .probation
            .entry(member.into())
            .or_insert(Some(until));
        Ok(())
    }
    async fn clear_passed_probation(&self, member: &str, now: u64) -> Result<()> {
        crate::text(member)?;
        i64::try_from(now).map_err(|_| Error::InvalidInput)?;
        if let Some(end) = self.state.lock().await.probation.get_mut(member)
            && end.is_some_and(|end| end <= now)
        {
            *end = None;
        }
        Ok(())
    }
    async fn prune_probation(&self, now: u64, count: usize) -> Result<()> {
        i64::try_from(now).map_err(|_| Error::InvalidInput)?;
        limit(count)?;
        let mut state = self.state.lock().await;
        for end in state
            .probation
            .values_mut()
            .filter(|end| end.is_some_and(|until| until <= now))
            .take(count)
        {
            *end = None;
        }
        Ok(())
    }
    async fn revocation_pending(&self, member: &str) -> Result<bool> {
        crate::text(member)?;
        Ok(self
            .state
            .lock()
            .await
            .revocations
            .get(member)
            .is_some_and(|(_, pending)| *pending))
    }
    async fn signal_revocation(&self, member: &str) -> Result<()> {
        crate::text(member)?;
        let mut state = self.state.lock().await;
        let value = state.revocations.entry(member.into()).or_default();
        value.0 = value
            .0
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or(Error::Unavailable)?;
        value.1 = true;
        Ok(())
    }
    async fn revocations(&self, count: usize) -> Result<Vec<Revocation>> {
        limit(count)?;
        Ok(self
            .state
            .lock()
            .await
            .revocations
            .iter()
            .filter(|(_, (_, pending))| *pending)
            .take(count)
            .map(|(member, generation)| Revocation {
                member: member.clone(),
                generation: generation.0,
            })
            .collect())
    }
    async fn acknowledge(&self, event: &Revocation) -> Result<()> {
        crate::text(&event.member)?;
        i64::try_from(event.generation).map_err(|_| Error::InvalidInput)?;
        let mut state = self.state.lock().await;
        if let Some(value) = state.revocations.get_mut(&event.member)
            && value.0 == event.generation
        {
            value.1 = false;
        }
        Ok(())
    }
    async fn device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> Result<Option<DeviceKeyState>> {
        registry_input(member, &key)?;
        let state = self.state.lock().await;
        Ok(state
            .registry
            .get(member)
            .and_then(|keys| keys.get(&key))
            .copied())
    }
    async fn active_device_keys(&self, member: &str) -> Result<Vec<[u8; 32]>> {
        crate::text(member)?;
        let state = self.state.lock().await;
        Ok(state
            .registry
            .get(member)
            .map(|keys| {
                keys.iter()
                    .filter(|(_, state)| **state == DeviceKeyState::Active)
                    .map(|(key, _)| *key)
                    .collect()
            })
            .unwrap_or_default())
    }
    async fn bind_first_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        seed: [u8; 32],
    ) -> Result<bool> {
        registry_input(member, &key)?;
        seed_input(&seed)?;
        let mut state = self.state.lock().await;
        let keys = state.registry.entry(member.to_owned()).or_default();
        if !keys.is_empty() {
            return Ok(false);
        }
        keys.insert(key, DeviceKeyState::Active);
        state.initial.insert(
            (member.to_owned(), key),
            DeviceInitialCreation {
                seed,
                publication: None,
            },
        );
        Ok(true)
    }
    async fn add_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
    ) -> Result<bool> {
        self.add_classed(member, key, pending_until, DeviceKeyClass::Full)
            .await
    }
    async fn add_delegated_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
    ) -> Result<bool> {
        self.add_classed(member, key, pending_until, DeviceKeyClass::Delegated)
            .await
    }
    async fn device_key_class(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> Result<Option<DeviceKeyClass>> {
        registry_input(member, &key)?;
        let state = self.state.lock().await;
        let known = state
            .registry
            .get(member)
            .is_some_and(|keys| keys.contains_key(&key));
        Ok(known.then(|| {
            if state.delegated.contains(&(member.to_owned(), key)) {
                DeviceKeyClass::Delegated
            } else {
                DeviceKeyClass::Full
            }
        }))
    }
    async fn pending_device_key_until(&self, member: &str, key: [u8; 32]) -> Result<Option<i64>> {
        registry_input(member, &key)?;
        let state = self.state.lock().await;
        let pending = state
            .registry
            .get(member)
            .and_then(|keys| keys.get(&key))
            .is_some_and(|current| *current == DeviceKeyState::Pending);
        Ok(pending.then(|| {
            state
                .pending_until
                .get(&(member.to_owned(), key))
                .copied()
                .unwrap_or(0)
        }))
    }
    async fn remove_expired_pending_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        now: i64,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        let mut state = self.state.lock().await;
        let pending = state
            .registry
            .get(member)
            .and_then(|keys| keys.get(&key))
            .is_some_and(|current| *current == DeviceKeyState::Pending);
        let until = state
            .pending_until
            .get(&(member.to_owned(), key))
            .copied()
            .unwrap_or(0);
        if !pending || until > now {
            return Ok(false);
        }
        if let Some(keys) = state.registry.get_mut(member) {
            keys.remove(&key);
        }
        state.pending_until.remove(&(member.to_owned(), key));
        Ok(true)
    }
    async fn set_device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
        from: DeviceKeyState,
        to: DeviceKeyState,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        if !transition_allowed(from, to) {
            return Err(Error::InvalidInput);
        }
        let mut state = self.state.lock().await;
        let moved = match state
            .registry
            .get_mut(member)
            .and_then(|keys| keys.get_mut(&key))
        {
            Some(current) if *current == from => {
                *current = to;
                true
            }
            _ => false,
        };
        if moved && from == DeviceKeyState::Pending {
            state.pending_until.remove(&(member.to_owned(), key));
        }
        Ok(moved)
    }
    async fn device_initial_creation(
        &self,
        member: &str,
        key: [u8; 32],
        bind: Option<([u8; 32], [u8; 32])>,
    ) -> Result<Option<DeviceInitialCreation>> {
        registry_input(member, &key)?;
        bind_input(&bind)?;
        let mut state = self.state.lock().await;
        let active = state.registry.get(member).and_then(|keys| keys.get(&key))
            == Some(&DeviceKeyState::Active);
        let index = (member.to_owned(), key);
        let Some(current) = state.initial.get(&index).copied().filter(|_| active) else {
            return Ok(None);
        };
        let next = bind_initial(current, bind)?;
        state.initial.insert(index, next);
        Ok(Some(next))
    }
}
/// Persistent membership facts using the one service-owned crlt pool.
#[derive(Clone)]
pub struct LibsqlStorage {
    community: String,
    scope: Community,
}
impl LibsqlStorage {
    /// Bind an already migrated community database.
    pub fn new(db: &crlt::Db, community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        crate::text(&community)?;
        Ok(Self {
            scope: db.community(community.clone())?,
            community,
        })
    }
}
const PROBATION: &str = "SELECT probation_until FROM cmbr_probation WHERE subject = ?1";
fn probation(rows: &[crlt::Row]) -> Result<Option<Option<u64>>> {
    rows.first()
        .map(|row| match row.get_value(0)? {
            crlt::Value::Null => Ok(None),
            crlt::Value::Integer(value) if *value >= 0 && value % 86400 == 0 => {
                Ok(Some(*value as u64))
            }
            _ => Err(Error::Unavailable),
        })
        .transpose()
}
impl Storage for LibsqlStorage {
    fn community(&self) -> &str {
        &self.community
    }
    async fn set_device_keys(
        &self,
        member: &str,
        credential: &[u8],
        keys: &[[u8; 32]],
    ) -> Result<()> {
        device_input(member, credential, keys)?;
        let mut tx = self.scope.tx().await?;
        tx.execute(
            "DELETE FROM cmbr_device_keys WHERE subject = ?1 AND credential = ?2",
            params![member, credential],
        )
        .await?;
        for key in keys {
            tx.execute("INSERT INTO cmbr_device_keys (subject, credential, signing_key) VALUES (?1, ?2, ?3)", params![member, credential, key.as_slice()]).await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn set_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        key: [u8; 32],
        expires: u64,
    ) -> Result<()> {
        device_input(member, credential, &[key])?;
        let expires = i64::try_from(expires).map_err(|_| Error::InvalidInput)?;
        let mut tx = self.scope.tx().await?;
        tx.execute(
            "DELETE FROM cmbr_device_pending WHERE subject = ?1 AND credential = ?2",
            params![member, credential],
        )
        .await?;
        tx.execute(
            "INSERT INTO cmbr_device_pending (subject, credential, signing_key, expires) VALUES (?1, ?2, ?3, ?4)",
            params![member, credential, key.as_slice(), expires],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn approve_pending_device(
        &self,
        member: &str,
        credential: &[u8],
        approver: &[u8],
    ) -> Result<()> {
        device_input(member, credential, &[])?;
        device_input(member, approver, &[])?;
        let mut tx = self.scope.tx().await?;
        let changed = tx
            .execute(
                "UPDATE cmbr_device_pending SET approver = ?3 WHERE subject = ?1 AND credential = ?2",
                params![member, credential, approver],
            )
            .await?;
        if changed == 0 {
            return Err(Error::Identity);
        }
        tx.commit().await?;
        Ok(())
    }
    async fn clear_pending_device(&self, member: &str, credential: &[u8]) -> Result<()> {
        device_input(member, credential, &[])?;
        let mut tx = self.scope.tx().await?;
        tx.execute(
            "DELETE FROM cmbr_device_pending WHERE subject = ?1 AND credential = ?2",
            params![member, credential],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    async fn pending_devices(&self, member: &str) -> Result<Vec<PendingDeviceKey>> {
        crate::text(member)?;
        let rows = self.scope.query("SELECT credential, signing_key, expires, approver FROM cmbr_device_pending WHERE subject = ?1 ORDER BY credential LIMIT 1025", [member]).await?;
        if rows.len() > 1024 {
            return Err(Error::Unavailable);
        }
        rows.iter()
            .map(|row| {
                let crlt::Value::Blob(credential) = row.get_value(0)? else {
                    return Err(Error::Unavailable);
                };
                let crlt::Value::Blob(key) = row.get_value(1)? else {
                    return Err(Error::Unavailable);
                };
                let crlt::Value::Integer(expires) = row.get_value(2)? else {
                    return Err(Error::Unavailable);
                };
                let approver = match row.get_value(3)? {
                    crlt::Value::Blob(approver) => Some(approver.clone()),
                    crlt::Value::Null => None,
                    _ => return Err(Error::Unavailable),
                };
                let key: [u8; 32] = key.as_slice().try_into().map_err(|_| Error::Unavailable)?;
                device_input(member, credential, &[key]).map_err(|_| Error::Unavailable)?;
                Ok(PendingDeviceKey {
                    approver,
                    credential: credential.clone(),
                    key,
                    expires: u64::try_from(*expires).map_err(|_| Error::Unavailable)?,
                })
            })
            .collect()
    }
    async fn device_keys(&self, member: &str) -> Result<Vec<DeviceKeyBinding>> {
        crate::text(member)?;
        let rows = self.scope.query("SELECT credential, signing_key FROM cmbr_device_keys WHERE subject = ?1 ORDER BY credential, signing_key LIMIT 1025", [member]).await?;
        if rows.len() > 1024 {
            return Err(Error::Unavailable);
        }
        rows.iter()
            .map(|row| {
                let crlt::Value::Blob(credential) = row.get_value(0)? else {
                    return Err(Error::Unavailable);
                };
                let crlt::Value::Blob(key) = row.get_value(1)? else {
                    return Err(Error::Unavailable);
                };
                let key: [u8; 32] = key.as_slice().try_into().map_err(|_| Error::Unavailable)?;
                device_input(member, credential, &[key]).map_err(|_| Error::Unavailable)?;
                Ok(DeviceKeyBinding {
                    credential: credential.clone(),
                    key,
                })
            })
            .collect()
    }
    async fn probation(&self, member: &str) -> Result<Option<Option<u64>>> {
        crate::text(member)?;
        probation(&self.scope.query(PROBATION, [member]).await?)
    }
    async fn initialize_probation(&self, member: &str, until: u64) -> Result<()> {
        crate::text(member)?;
        deadline(until)?;
        let mut tx = self.scope.tx().await?;
        if tx.query(PROBATION, [member]).await?.is_empty() {
            tx.execute(
                "INSERT INTO cmbr_probation (subject, probation_until) VALUES (?1, ?2)",
                params![member, until as i64],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn admit_probation_in_transaction(
        &self,
        transaction: crlt::Transaction,
        member: &str,
        until: u64,
        now: u64,
    ) -> Result<crlt::Transaction> {
        probation::admit(self, transaction, member, until, now).await
    }
    async fn clear_passed_probation(&self, member: &str, now: u64) -> Result<()> {
        crate::text(member)?;
        let now = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
        self.scope.execute("UPDATE cmbr_probation SET probation_until = NULL WHERE subject = ?1 AND probation_until <= ?2", params![member, now]).await?;
        Ok(())
    }
    async fn prune_probation(&self, now: u64, count: usize) -> Result<()> {
        let at = i64::try_from(now).map_err(|_| Error::InvalidInput)?;
        let rows = self.scope.query("SELECT subject FROM cmbr_probation WHERE probation_until <= ?1 ORDER BY probation_until, subject LIMIT ?2", params![at, limit(count)?]).await?;
        for row in rows {
            self.clear_passed_probation(row.get_str(0)?, now).await?;
        }
        Ok(())
    }
    async fn revocation_pending(&self, member: &str) -> Result<bool> {
        crate::text(member)?;
        Ok(self
            .scope
            .query(
                "SELECT pending FROM cmbr_revocations WHERE subject = ?1",
                [member],
            )
            .await?
            .first()
            .map(|row| row.get_i64(0))
            .transpose()?
            .is_some_and(|pending| pending == 1))
    }
    async fn signal_revocation(&self, member: &str) -> Result<()> {
        crate::text(member)?;
        let mut tx = self.scope.tx().await?;
        signal_revocation_tx(&mut tx, member).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn signal_revocation_transaction(
        &self,
        transaction: &mut crlt::Transaction,
        member: &str,
    ) -> Result<()> {
        if !transaction.belongs_to(&self.scope) {
            return Err(Error::Identity);
        }
        signal_revocation_tx(transaction, member).await
    }
    async fn revocations(&self, count: usize) -> Result<Vec<Revocation>> {
        self.scope
            .query(
                "SELECT subject, generation FROM cmbr_revocations WHERE pending = 1 ORDER BY subject LIMIT ?1",
                [limit(count)?],
            )
            .await?
            .iter()
            .map(|row| {
                let generation = row.get_i64(1)?;
                if generation <= 0 {
                    return Err(Error::Unavailable);
                }
                Ok(Revocation {
                    member: row.get_str(0)?.into(),
                    generation: generation as u64,
                })
            })
            .collect()
    }
    async fn acknowledge(&self, event: &Revocation) -> Result<()> {
        crate::text(&event.member)?;
        let generation = i64::try_from(event.generation).map_err(|_| Error::InvalidInput)?;
        self.scope
            .execute(
                "UPDATE cmbr_revocations SET pending = 0 WHERE subject = ?1 AND generation = ?2",
                params![event.member.as_str(), generation],
            )
            .await?;
        Ok(())
    }
    async fn device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> Result<Option<DeviceKeyState>> {
        registry_input(member, &key)?;
        let rows = self
            .scope
            .query(
                "SELECT state FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
                params![member, key.to_vec()],
            )
            .await?;
        rows.first()
            .map(|row| registry_state(row.get_str(0)?))
            .transpose()
    }
    async fn active_device_keys(&self, member: &str) -> Result<Vec<[u8; 32]>> {
        crate::text(member)?;
        let rows = self
            .scope
            .query(
                "SELECT device_key FROM cvld_device_registry WHERE member = ?1 AND state = 'active' ORDER BY device_key",
                params![member],
            )
            .await?;
        rows.iter()
            .map(|row| match row.get_value(0)? {
                crlt::Value::Blob(bytes) => {
                    bytes.as_slice().try_into().map_err(|_| Error::Unavailable)
                }
                _ => Err(Error::Unavailable),
            })
            .collect()
    }
    async fn bind_first_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        seed: [u8; 32],
    ) -> Result<bool> {
        registry_input(member, &key)?;
        seed_input(&seed)?;
        let mut tx = self.scope.tx().await?;
        let rows = tx
            .query(
                "SELECT 1 FROM cvld_device_registry WHERE member = ?1 LIMIT 1",
                params![member],
            )
            .await?;
        if !rows.is_empty() {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO cvld_device_registry (member, device_key, state, initial_seed) VALUES (?1, ?2, 'active', ?3)",
            params![member, key.to_vec(), seed.to_vec()],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn add_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        pending_until_input(pending_until)?;
        let mut tx = self.scope.tx().await?;
        let known = tx
            .query(
                "SELECT 1 FROM cvld_device_registry WHERE member = ?1 LIMIT 1",
                params![member],
            )
            .await?;
        let same = tx
            .query(
                "SELECT 1 FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
                params![member, key.to_vec()],
            )
            .await?;
        if known.is_empty() || !same.is_empty() {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO cvld_device_registry (member, device_key, state, pending_until) VALUES (?1, ?2, 'pending', ?3)",
            params![member, key.to_vec(), pending_until],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn add_delegated_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        pending_until: i64,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        pending_until_input(pending_until)?;
        let mut tx = self.scope.tx().await?;
        let known = tx
            .query(
                "SELECT 1 FROM cvld_device_registry WHERE member = ?1 LIMIT 1",
                params![member],
            )
            .await?;
        let same = tx
            .query(
                "SELECT 1 FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
                params![member, key.to_vec()],
            )
            .await?;
        if known.is_empty() || !same.is_empty() {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO cvld_device_registry (member, device_key, state, pending_until, class) VALUES (?1, ?2, 'pending', ?3, 'delegated')",
            params![member, key.to_vec(), pending_until],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn device_key_class(
        &self,
        member: &str,
        key: [u8; 32],
    ) -> Result<Option<DeviceKeyClass>> {
        registry_input(member, &key)?;
        let rows = self
            .scope
            .query(
                "SELECT class FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2",
                params![member, key.to_vec()],
            )
            .await?;
        rows.first()
            .map(|row| match row.get_str(0)? {
                "full" => Ok(DeviceKeyClass::Full),
                "delegated" => Ok(DeviceKeyClass::Delegated),
                _ => Err(Error::Unavailable),
            })
            .transpose()
    }
    async fn pending_device_key_until(&self, member: &str, key: [u8; 32]) -> Result<Option<i64>> {
        registry_input(member, &key)?;
        let rows = self
            .scope
            .query(
                "SELECT COALESCE(pending_until, 0) FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2 AND state = 'pending'",
                params![member, key.to_vec()],
            )
            .await?;
        rows.first()
            .map(|row| match row.get_value(0)? {
                crlt::Value::Integer(until) => Ok(*until),
                _ => Err(Error::Unavailable),
            })
            .transpose()
    }
    async fn remove_expired_pending_device_key(
        &self,
        member: &str,
        key: [u8; 32],
        now: i64,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        let mut tx = self.scope.tx().await?;
        let removed = tx
            .execute(
                "DELETE FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2 AND state = 'pending' AND COALESCE(pending_until, 0) <= ?3",
                params![member, key.to_vec(), now],
            )
            .await?;
        tx.commit().await?;
        Ok(removed > 0)
    }
    async fn set_device_key_state(
        &self,
        member: &str,
        key: [u8; 32],
        from: DeviceKeyState,
        to: DeviceKeyState,
    ) -> Result<bool> {
        registry_input(member, &key)?;
        if !transition_allowed(from, to) {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.scope.tx().await?;
        let changed = tx
            .execute(
                "UPDATE cvld_device_registry SET state = ?4, pending_until = NULL WHERE member = ?1 AND device_key = ?2 AND state = ?3",
                params![member, key.to_vec(), state_text(from), state_text(to)],
            )
            .await?;
        tx.commit().await?;
        Ok(changed > 0)
    }
    async fn device_initial_creation(
        &self,
        member: &str,
        key: [u8; 32],
        bind: Option<([u8; 32], [u8; 32])>,
    ) -> Result<Option<DeviceInitialCreation>> {
        registry_input(member, &key)?;
        bind_input(&bind)?;
        let mut tx = self.scope.tx().await?;
        let rows = tx
            .query(
                "SELECT initial_seed, initial_publication FROM cvld_device_registry WHERE member = ?1 AND device_key = ?2 AND state = 'active' AND initial_seed IS NOT NULL",
                params![member, key.to_vec()],
            )
            .await?;
        let Some(row) = rows.first() else {
            tx.rollback().await?;
            return Ok(None);
        };
        let current = DeviceInitialCreation {
            seed: blob32(row.get_value(0)?)?,
            publication: match row.get_value(1)? {
                crlt::Value::Null => None,
                value => Some(blob32(value)?),
            },
        };
        if current.seed == [0; 32] || current.publication == Some([0; 32]) {
            tx.rollback().await?;
            return Err(Error::Unavailable);
        }
        let next = match bind_initial(current, bind) {
            Ok(next) => next,
            Err(error) => {
                tx.rollback().await?;
                return Err(error);
            }
        };
        if next.publication != current.publication {
            tx.execute(
                "UPDATE cvld_device_registry SET initial_publication = ?3 WHERE member = ?1 AND device_key = ?2 AND initial_publication IS NULL",
                params![
                    member,
                    key.to_vec(),
                    next.publication.ok_or(Error::Unavailable)?.to_vec()
                ],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(next))
    }
}

fn blob32(value: &crlt::Value) -> Result<[u8; 32]> {
    match value {
        crlt::Value::Blob(bytes) => bytes.as_slice().try_into().map_err(|_| Error::Unavailable),
        _ => Err(Error::Unavailable),
    }
}

async fn signal_revocation_tx(transaction: &mut crlt::Transaction, member: &str) -> Result<()> {
    crate::text(member)?;
    let rows = transaction
        .query(
            "SELECT generation FROM cmbr_revocations WHERE subject = ?1",
            [member],
        )
        .await?;
    if let Some(row) = rows.first() {
        let next = row.get_i64(0)?.checked_add(1).ok_or(Error::Unavailable)?;
        transaction
            .execute(
                "UPDATE cmbr_revocations SET generation = ?1, pending = 1 WHERE subject = ?2",
                params![next, member],
            )
            .await?;
    } else {
        transaction
            .execute(
                "INSERT INTO cmbr_revocations (subject, generation) VALUES (?1, 1)",
                [member],
            )
            .await?;
    }
    Ok(())
}

// A process-local per-member queue; no guard survives cancellation/error/process
// exit and no database Busy marker exists. Service writers share this registry.
// Leaf row revisions and unique constraints still fence stale/competing writes.
type MemberLocks = BTreeMap<(String, ckyh::Uuid), Weak<Mutex<()>>>;
static LOCKS: OnceLock<StdMutex<MemberLocks>> = OnceLock::new();
pub(crate) async fn member_lock(community: &str, user: ckyh::Uuid) -> OwnedMutexGuard<()> {
    let lock = {
        let mut locks = LOCKS
            .get_or_init(StdMutex::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, weak| weak.strong_count() > 0);
        let weak = locks.entry((community.into(), user)).or_default();
        match weak.upgrade() {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(Mutex::new(()));
                *weak = Arc::downgrade(&lock);
                lock
            }
        }
    };
    lock.lock_owned().await
}

#[cfg(test)]
mod tests;
