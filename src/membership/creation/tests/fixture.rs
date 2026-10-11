use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) const COMMUNITY: &str = "creation-owner";
pub(super) type SqlPolicy =
    cplc::Policy<crbk::LibsqlStore, cplc::LibsqlStore, cplc::csgn::LibsqlStore>;

pub(super) struct Session {
    authentication: Authentication,
    until: u64,
    pub live: AtomicBool,
    pub calls: AtomicUsize,
    pub remove_at: usize,
    pub at_final_cut: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Session {
    fn new(auth: &Authentication) -> Self {
        Self {
            authentication: auth.clone(),
            until: common::now() as u64 + 3600,
            live: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            remove_at: usize::MAX,
            at_final_cut: None,
        }
    }
}

impl RoleSession for Session {
    fn valid_until(&self) -> u64 {
        self.until
    }
    fn check(&self, auth: &Authentication, observed: u64) -> Result<()> {
        let count = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if count == 3
            && let Some(check) = &self.at_final_cut
        {
            check();
        }
        if count >= self.remove_at {
            self.live.store(false, Ordering::SeqCst);
        }
        if !self.live.load(Ordering::SeqCst)
            || observed >= self.until
            || auth.member() != self.authentication.member()
            || auth.credential_id() != self.authentication.credential_id()
        {
            return Err(Error::Identity);
        }
        Ok(())
    }
}

pub(super) struct Fixture {
    pub _directory: tempfile::TempDir,
    pub db: crlt::Db,
    pub owner: common::Facade,
    pub clock: common::Clock,
    pub authentication: Authentication,
    pub policy: SqlPolicy,
    pub snapshot: cplc::VerifiedSnapshot,
    pub gates: cgts::CheckedGates,
    pub session: Session,
}

impl Fixture {
    pub async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crlt::Config::new(
            format!("file://{}", directory.path().join("creation.db").display()),
            "",
        );
        config.max_connections = 8;
        config.busy_timeout = std::time::Duration::from_millis(100);
        let db = crlt::Db::open(config).await.unwrap();
        let mut schemas = crate::SCHEMAS.to_vec();
        schemas.extend([
            ("cmbr-device-keys", crate::DEVICE_KEYS_SCHEMA),
            ("cgts", cgts::SCHEMA),
            ("creation", crate::storage::creation::CREATION_SCHEMA),
            ("rulebook", crbk::SCHEMA),
            ("signing", cplc::csgn::SCHEMA),
            ("policy", cplc::SCHEMA),
        ]);
        let migrations: Vec<_> = schemas
            .iter()
            .enumerate()
            .map(|(index, (name, ddl))| crlt::Migration::new(index as u32 + 1, name, ddl))
            .collect();
        db.migrate(&migrations).await.unwrap();
        let clock = common::Clock::new();
        let owner = common::facade(&db, COMMUNITY, clock.clone());
        let mut token = common::register(&owner, common::USER, common::SUBJECT).await;
        let authentication = common::login(&owner, &mut token, common::USER)
            .await
            .authentication;
        owner
            .reserve_handle(&authentication, common::HANDLE, &[])
            .await
            .unwrap();
        let mut policy = sql_policy(&db).await;
        let snapshot = policy
            .verified_settings(common::now() as u64)
            .await
            .unwrap();
        let gates = common::checked(
            &snapshot,
            common::SUBJECT,
            &[common::test_gate(COMMUNITY, common::SUBJECT)],
            common::now(),
        )
        .await;
        let session = Session::new(&authentication);
        Self {
            _directory: directory,
            db,
            owner,
            clock,
            authentication,
            policy,
            snapshot,
            gates,
            session,
        }
    }

    pub fn request(
        &self,
    ) -> AdmissionRequest<'_, crbk::LibsqlStore, cplc::LibsqlStore, cplc::csgn::LibsqlStore> {
        AdmissionRequest {
            authentication: &self.authentication,
            policy: &self.policy,
            snapshot: &self.snapshot,
            gates: &self.gates,
            checked_at: common::now() as u64,
            lease: common::lease(),
            session: &self.session,
        }
    }

    pub fn invitation(&self, id: &str, community: &str, member: &[u8], until: u64) -> Vec<u8> {
        // The original role codec is exercised with the ACTUAL target Policy's
        // configured public key. This separate test-owned signer issues only
        // fixture invitations, not production issuance authority or a Root row.
        let mut signer = cplc::csgn::Signer::new(
            COMMUNITY,
            cplc::csgn::SecretKey::from_seed(&mut [18; 32]),
            cplc::day(common::now() as u64),
            30 * cplc::DAY,
        )
        .unwrap();
        assert_eq!(
            signer.key_ring().active().unwrap().public_key(),
            self.policy
                .key_ring()
                .unwrap()
                .active()
                .unwrap()
                .public_key(),
        );
        let binding = cvch::member_binding(&cvch::receipt_id(id), member);
        let fields = cvch::role::Invitation {
            id,
            community,
            member_binding: &binding,
            purpose: cvch::role::Purpose::BootstrapRoot,
            issued_at: common::now() as u64,
            valid_until: until,
        };
        signer
            .sign(
                cplc::csgn::Kind::Credential,
                &cvch::role::issuance_bytes(&fields).unwrap(),
                fields.issued_at,
                fields.valid_until,
            )
            .unwrap()
    }

    pub fn first_invitation(&self) -> Vec<u8> {
        self.invitation(
            "original-first-root",
            COMMUNITY,
            common::SUBJECT.as_bytes(),
            common::now() as u64 + 600,
        )
    }

    pub async fn initialize(&self, bytes: &[u8]) {
        let verified = cvch::role::verify(
            bytes,
            self.policy.key_ring().unwrap(),
            &cvch::role::Context {
                community: COMMUNITY,
                member: common::SUBJECT.as_bytes(),
                purpose: cvch::role::Purpose::BootstrapRoot,
                now: common::now() as u64,
            },
        )
        .unwrap();
        assert_eq!(
            self.owner
                .initialize_community_creation(&verified, common::SUBJECT.as_bytes())
                .await
                .unwrap(),
            CommunityPhase::Creating,
        );
    }

    pub async fn assert_pending(&self) {
        assert_eq!(
            self.owner.community_phase().await.unwrap(),
            CommunityPhase::Creating
        );
        assert_eq!(
            self.owner
                .enrol
                .view(common::USER, self.owner.now().unwrap())
                .await
                .unwrap()
                .state(),
            State::HandleReserved,
        );
        assert!(
            self.owner
                .register
                .member(&root_id())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            self.owner
                .storage
                .probation(common::SUBJECT)
                .await
                .unwrap()
                .is_none()
        );
        let rows = self
            .db
            .community(COMMUNITY)
            .unwrap()
            .query("SELECT marker FROM cgts_spent WHERE domain = ?1", ["cvch"])
            .await
            .unwrap();
        assert!(rows.is_empty());
    }
}

pub(super) fn root_id() -> crgs::MemberId {
    crgs::MemberId::new(common::SUBJECT.as_bytes()).unwrap()
}

async fn sql_policy(db: &crlt::Db) -> SqlPolicy {
    let raw = common::policy(COMMUNITY);
    let mut book = crbk::Rulebook::default();
    for (key, value) in &raw.content {
        book.define(
            key,
            crbk::Setting {
                value_type: if key == &crbk::action_key("membership") {
                    crbk::SettingType::Policy
                } else {
                    crbk::SettingType::Boolean
                },
                nullable: false,
                default: value.clone(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    }
    crbk::define_membership_settings(&mut book).unwrap();
    let signer = cplc::csgn::PersistentSigner::create(
        cplc::csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        cplc::csgn::SecretKey::from_seed(&mut [18; 32]),
        cplc::day(common::now() as u64),
        30 * cplc::DAY,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        crbk::LibsqlStore::new(db.clone()),
        cplc::LibsqlStore::new(db, COMMUNITY).unwrap(),
        signer,
        cplc::Config {
            credential_action: "membership".into(),
            snapshot_validity: cplc::DAY,
        },
    )
    .await
    .unwrap();
    policy
        .schedule_rules(
            None,
            crbk::Change {
                rulebook: book,
                announced_at: common::now(),
                effective_at: common::now(),
                notice_seconds: 0,
                policy_epoch: 1,
            },
        )
        .await
        .unwrap();
    policy
}
