//! Real SQL owner composition. Private phase facts are not full configured-gate
//! admission authority; that remains the membership owner's responsibility.
use super::*;
use crate::test_common as common;
use cnrl::Storage as _;

const COMMUNITY: &str = "a";

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    db: crlt::Db,
    creation: Creation,
    register: crgs::Register<crgs::LibsqlStorage>,
    claims: cgts::LibsqlStore,
}

async fn open(path: &std::path::Path) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    let mut history: Vec<_> = crate::SCHEMAS
        .iter()
        .enumerate()
        .map(|(index, (name, sql))| crlt::Migration::new(index as u32 + 1, *name, *sql))
        .collect();
    history.push(crlt::Migration::new(
        history.len() as u32 + 1,
        "cmbr-device-keys",
        crate::DEVICE_KEYS_SCHEMA,
    ));
    history.push(crlt::Migration::new(
        history.len() as u32 + 1,
        "creation",
        CREATION_SCHEMA,
    ));
    history.push(crlt::Migration::new(
        history.len() as u32 + 1,
        "cgts",
        cgts::SCHEMA,
    ));
    db.migrate(&history).await.unwrap();
    db
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("creation.db");
        let db = open(&path).await;
        Self {
            creation: Creation::new(db.community(COMMUNITY).unwrap()),
            register: crgs::Register::new(
                crgs::LibsqlStorage::new(db.community(COMMUNITY).unwrap()),
                crgs::ReleasePeriod::months(1),
            ),
            claims: cgts::LibsqlStore::new(&db, COMMUNITY).unwrap(),
            _directory: directory,
            path,
            db,
        }
    }
    async fn tx(&self) -> Transaction {
        self.db.community(COMMUNITY).unwrap().tx().await.unwrap()
    }
    async fn state(&self) -> Option<State> {
        let (tx, state) = self.creation.read(self.tx().await).await.unwrap();
        tx.rollback().await.unwrap();
        state
    }
    async fn reserve(&self) {
        self.register
            .reserve_handle(
                crgs::Reservation {
                    member_id: root_id(),
                    handle: common::handle(),
                    expires_at: common::date(common::now() + 3600),
                },
                common::date(common::now()),
            )
            .await
            .unwrap();
    }
    async fn root(&self, tx: Transaction) -> (Transaction, crgs::Member) {
        self.register
            .admit_in_transaction(
                tx,
                crgs::Admission {
                    id: root_id(),
                    handle: common::handle(),
                    role: crgs::Role::Root,
                    lease_end: common::lease(),
                },
                common::date(common::now()),
            )
            .await
            .unwrap()
    }
}

fn root_id() -> crgs::MemberId {
    crgs::MemberId::new(common::SUBJECT.as_bytes()).unwrap()
}

fn invitation(id: &str) -> (Pending, cgts::Claim) {
    let now = common::now() as u64;
    let mut signer = cplc::csgn::Signer::new(
        "root",
        cplc::csgn::SecretKey::from_seed(&mut [7; 32]),
        now - 1,
        now + 7200,
    )
    .unwrap();
    let binding = cvch::member_binding(&cvch::receipt_id(id), root_id().as_bytes());
    let fields = cvch::role::Invitation {
        id,
        community: COMMUNITY,
        member_binding: &binding,
        purpose: cvch::role::Purpose::BootstrapRoot,
        issued_at: now,
        valid_until: now + 3600,
    };
    let cose = signer
        .sign(
            cplc::csgn::Kind::Credential,
            &cvch::role::issuance_bytes(&fields).unwrap(),
            fields.issued_at,
            fields.valid_until,
        )
        .unwrap();
    let verified = cvch::role::verify(
        &cose,
        signer.key_ring(),
        &cvch::role::Context {
            community: COMMUNITY,
            member: root_id().as_bytes(),
            purpose: cvch::role::Purpose::BootstrapRoot,
            now,
        },
    )
    .unwrap();
    let pending = Pending::new(
        verified.receipt(),
        verified.binding(),
        verified.valid_until(),
    )
    .unwrap();
    let claim = cgts::Claim::new("cvch", verified.receipt().as_bytes().to_vec()).unwrap();
    (pending, claim)
}

#[tokio::test]
async fn absent_phase_never_activates_and_initialization_retry_cannot_slide() {
    let fixture = Fixture::new().await;
    let (pending, _) = invitation("first-root");
    assert!(fixture.state().await.is_none());
    assert!(matches!(
        fixture
            .creation
            .activate(fixture.tx().await, &pending, &root_id())
            .await,
        Err(Error::Transition)
    ));
    let tx = fixture
        .register
        .ensure_empty_in_transaction(fixture.tx().await)
        .await
        .unwrap();
    let (tx, state) = fixture.creation.initialize(tx, &pending).await.unwrap();
    assert!(state == State::Creating(pending.clone()));
    tx.commit().await.unwrap();
    let (tx, _) = fixture
        .creation
        .initialize(fixture.tx().await, &pending)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let later = Pending::new(pending.receipt(), pending.binding(), pending.expires() + 1).unwrap();
    let (different, _) = invitation("different-root");
    for changed in [later, different] {
        assert!(matches!(
            fixture
                .creation
                .initialize(fixture.tx().await, &changed)
                .await,
            Err(Error::Busy)
        ));
    }
    assert!(fixture.state().await == Some(State::Creating(pending)));
}

#[tokio::test]
async fn actual_root_receipt_and_active_phase_commit_once_and_retry_exactly() {
    let fixture = Fixture::new().await;
    let (pending, claim) = invitation("first-root");
    fixture.reserve().await;
    let tx = fixture
        .register
        .ensure_empty_in_transaction(fixture.tx().await)
        .await
        .unwrap();
    let (tx, _) = fixture.creation.initialize(tx, &pending).await.unwrap();
    let (tx, root) = fixture.root(tx).await;
    let tx = fixture
        .claims
        .claim_in_transaction(tx, &claim)
        .await
        .unwrap();
    let (tx, active) = fixture
        .creation
        .activate(tx, &pending, &root.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        fixture.register.member(&root.id).await.unwrap(),
        Some(root.clone())
    );
    assert_eq!(root.role, crgs::Role::Root);
    assert!(fixture.state().await == Some(active.clone()));
    assert!(matches!(
        fixture
            .claims
            .claim_in_transaction(fixture.tx().await, &claim)
            .await,
        Err(cgts::Error::Refused)
    ));
    let (tx, retry) = fixture
        .creation
        .activate(fixture.tx().await, &pending, &root.id)
        .await
        .unwrap();
    assert!(retry == active);
    tx.commit().await.unwrap();
    let wrong = crgs::MemberId::new(b"different-root".to_vec()).unwrap();
    assert!(matches!(
        fixture
            .creation
            .activate(fixture.tx().await, &pending, &wrong)
            .await,
        Err(Error::Busy)
    ));
    assert!(fixture.state().await == Some(active));
    assert!(matches!(
        fixture
            .creation
            .initialize(fixture.tx().await, &pending)
            .await,
        Err(Error::Transition)
    ));
    assert!(matches!(
        fixture
            .creation
            .adopt_legacy(fixture.tx().await, &root.id)
            .await,
        Err(Error::Transition)
    ));
}

#[tokio::test]
async fn refusal_and_cancel_drop_actual_root_and_receipt_staging_together() {
    let fixture = Fixture::new().await;
    let (pending, claim) = invitation("first-root");
    let (changed, _) = invitation("changed");
    fixture.reserve().await;
    let (tx, _) = fixture
        .creation
        .initialize(fixture.tx().await, &pending)
        .await
        .unwrap();
    let (tx, root) = fixture.root(tx).await;
    let tx = fixture
        .claims
        .claim_in_transaction(tx, &claim)
        .await
        .unwrap();
    assert!(matches!(
        fixture.creation.activate(tx, &changed, &root.id).await,
        Err(Error::Busy)
    ));
    assert!(fixture.state().await.is_none());
    assert!(fixture.register.member(&root.id).await.unwrap().is_none());
    let tx = fixture
        .claims
        .claim_in_transaction(fixture.tx().await, &claim)
        .await
        .unwrap();
    tx.rollback().await.unwrap();

    let (tx, _) = fixture
        .creation
        .initialize(fixture.tx().await, &pending)
        .await
        .unwrap();
    let (tx, root) = fixture.root(tx).await;
    let tx = fixture
        .claims
        .claim_in_transaction(tx, &claim)
        .await
        .unwrap();
    let future = fixture.creation.activate(tx, &pending, &root.id);
    drop(future);
    assert!(fixture.state().await.is_none());
    assert!(fixture.register.member(&root.id).await.unwrap().is_none());
    let tx = fixture
        .claims
        .claim_in_transaction(fixture.tx().await, &claim)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn scope_reopen_and_missing_schema_refuse_without_partial_phase() {
    let fixture = Fixture::new().await;
    let (pending, _) = invitation("first-root");
    let foreign = Creation::new(fixture.db.community("other").unwrap());
    let (tx, _) = fixture
        .creation
        .initialize(fixture.tx().await, &pending)
        .await
        .unwrap();
    assert!(matches!(foreign.read(tx).await, Err(Error::Identity)));
    assert!(fixture.state().await.is_none());
    let reopened = open(&fixture.path).await;
    let other_handle = Creation::new(reopened.community(COMMUNITY).unwrap());
    let (tx, _) = fixture
        .creation
        .initialize(fixture.tx().await, &pending)
        .await
        .unwrap();
    assert!(matches!(other_handle.read(tx).await, Err(Error::Identity)));
    assert!(fixture.state().await.is_none());
    let (tx, _) = fixture
        .creation
        .initialize(fixture.tx().await, &pending)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let (tx, durable) = other_handle
        .read(reopened.community(COMMUNITY).unwrap().tx().await.unwrap())
        .await
        .unwrap();
    assert!(durable == Some(State::Creating(pending)));
    tx.rollback().await.unwrap();
    let missing = crlt::Db::open(crlt::Config::new(
        format!(
            "file://{}",
            fixture._directory.path().join("missing.db").display()
        ),
        "",
    ))
    .await
    .unwrap();
    let scope = missing.community(COMMUNITY).unwrap();
    assert!(matches!(
        Creation::new(scope.clone())
            .read(scope.tx().await.unwrap())
            .await,
        Err(Error::Unavailable)
    ));
}

#[tokio::test]
async fn explicit_legacy_adoption_keeps_actual_root_and_admitted_proof_without_receipt() {
    let fixture = Fixture::new().await;
    let facade = common::facade(&fixture.db, COMMUNITY, common::Clock::new());
    let mut device = common::register(&facade, common::USER, common::SUBJECT).await;
    let login = common::login(&facade, &mut device, common::USER).await;
    facade
        .reserve_handle(&login.authentication, common::HANDLE, &[])
        .await
        .unwrap();
    let held = facade.resume(&login.authentication).await.unwrap();
    let action = common::config().membership_action;
    let enrol = cnrl::Enrol::new(
        cnrl::LibsqlStorage::new(&fixture.db, COMMUNITY).unwrap(),
        cnrl::Config::new(2, &action).unwrap(),
    );
    // This explicitly empty original Rulebook test policy exercises historical
    // owner storage only; it is not a configured production admission assertion.
    let mut settings = common::policy(COMMUNITY);
    settings.content.insert(
        crbk::action_key(&action),
        serde_json::to_value(crbk::ActionPolicy::default()).unwrap(),
    );
    let decision = settings
        .may(
            crbk::Subject {
                id: held.subject(),
                membership: held.state().membership(),
            },
            &action,
            &[] as &[crbk::GateResult],
            common::now(),
        )
        .unwrap();
    assert!(decision.allowed);
    let (tx, gates) = enrol
        .apply_in_transaction(
            fixture.tx().await,
            &held,
            cnrl::Event::PolicyEvaluated(&decision),
            common::now(),
        )
        .await
        .unwrap();
    let (tx, root) = fixture.root(tx).await;
    let (tx, admitted) = enrol
        .apply_in_transaction(
            tx,
            &gates,
            cnrl::Event::AdmissionRecorded {
                member: &root,
                decision: &decision,
            },
            common::now(),
        )
        .await
        .unwrap();
    assert_eq!(admitted.state(), cnrl::State::Admitted);
    tx.commit().await.unwrap();
    assert!(fixture.state().await.is_none());
    let (tx, stored_root) = fixture
        .register
        .member_in_transaction(fixture.tx().await, &root.id)
        .await
        .unwrap();
    let stored_root = stored_root.unwrap();
    let (tx, row) = enrol
        .get_in_transaction(tx, common::USER, common::now())
        .await
        .unwrap();
    assert_eq!(stored_root.role, crgs::Role::Root);
    assert_eq!(row.state(), cnrl::State::Admitted);
    assert_eq!(row.member_id(), stored_root.id);
    let (tx, legacy) = fixture
        .creation
        .adopt_legacy(tx, &stored_root.id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(
        legacy
            == State::LegacyActive {
                root: root.id.clone()
            }
    );
    let rows = fixture
        .db
        .community(COMMUNITY)
        .unwrap()
        .query(
            "SELECT receipt, binding, expires_at FROM cmbr_creation WHERE singleton = 1",
            crlt::params![],
        )
        .await
        .unwrap();
    for index in 0..=2 {
        assert!(matches!(rows[0].get_value(index).unwrap(), Value::Null));
    }
    let (tx, same) = fixture
        .creation
        .adopt_legacy(fixture.tx().await, &root.id)
        .await
        .unwrap();
    assert!(same == legacy);
    tx.commit().await.unwrap();
    let wrong = crgs::MemberId::new(b"other".to_vec()).unwrap();
    assert!(matches!(
        fixture
            .creation
            .adopt_legacy(fixture.tx().await, &wrong)
            .await,
        Err(Error::Busy)
    ));
    let (pending, _) = invitation("new-creation");
    assert!(matches!(
        fixture
            .creation
            .initialize(fixture.tx().await, &pending)
            .await,
        Err(Error::Transition)
    ));
    assert!(matches!(
        fixture
            .creation
            .activate(fixture.tx().await, &pending, &root.id)
            .await,
        Err(Error::Transition)
    ));
    assert_eq!(
        cnrl::LibsqlStorage::new(&fixture.db, COMMUNITY)
            .unwrap()
            .load(common::USER)
            .await
            .unwrap(),
        Some(admitted)
    );
}
