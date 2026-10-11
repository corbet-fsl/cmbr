//! Genuine SQL/Register effects only; this is not a full founder admission test.
use super::*;
use crate::test_common as common;

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    db: crlt::Db,
    store: RoleRedemptions,
    register: crgs::Register<crgs::LibsqlStorage>,
}
async fn open(path: &std::path::Path) -> crlt::Db {
    open_schema(path, ROLE_REDEMPTION_SCHEMA).await
}
async fn open_schema(path: &std::path::Path, schema: &str) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    let mut history: Vec<_> = crate::SCHEMAS
        .iter()
        .enumerate()
        .map(|(i, (name, sql))| crlt::Migration::new(i as u32 + 1, *name, *sql))
        .collect();
    history.push(crlt::Migration::new(
        history.len() as u32 + 1,
        "role-redemptions",
        schema,
    ));
    db.migrate(&history).await.unwrap();
    db
}
impl Fixture {
    async fn new() -> Self {
        Self::with_schema(ROLE_REDEMPTION_SCHEMA).await
    }
    async fn with_schema(schema: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("founder.db");
        let db = open_schema(&path, schema).await;
        let scope = db.community("alpha").unwrap();
        Self {
            store: RoleRedemptions::new(scope.clone()),
            register: crgs::Register::new(
                crgs::LibsqlStorage::new(scope),
                crgs::ReleasePeriod::months(1),
            ),
            db,
            path,
            _dir: dir,
        }
    }
    async fn tx(&self) -> Transaction {
        self.db.community("alpha").unwrap().tx().await.unwrap()
    }
    async fn row(&self, receipt: &str) -> Option<Redemption> {
        let (tx, value) = self.store.read(self.tx().await, receipt).await.unwrap();
        tx.rollback().await.unwrap();
        value
    }
    async fn staged_admin(&self) -> (Transaction, crgs::Member) {
        self.register
            .reserve_handle(
                crgs::Reservation {
                    member_id: member(),
                    handle: common::handle(),
                    expires_at: common::date(common::now() + 3600),
                },
                common::date(common::now()),
            )
            .await
            .unwrap();
        self.register
            .admit_in_transaction(
                self.tx().await,
                crgs::Admission {
                    id: member(),
                    handle: common::handle(),
                    role: crgs::Role::Admin,
                    lease_end: lease(),
                },
                common::date(common::now()),
            )
            .await
            .unwrap()
    }
}
fn member() -> crgs::MemberId {
    crgs::MemberId::new(b"founder-alpha".to_vec()).unwrap()
}
fn lease() -> crgs::YearMonth {
    crgs::YearMonth::new(2099, 12).unwrap()
}
fn record() -> Redemption {
    Redemption::new(&"a".repeat(64), &"b".repeat(64), 2000, member(), lease(), 1).unwrap()
}

#[tokio::test]
async fn genuine_admin_and_exact_effect_share_one_commit_and_reopen() {
    let f = Fixture::new().await;
    let value = record();
    let (tx, admitted) = f.staged_admin().await;
    assert_eq!(admitted.role, crgs::Role::Admin);
    let tx = f.store.insert(tx, &value).await.unwrap();
    tx.commit().await.unwrap();
    assert!(f.row(value.receipt()).await.as_ref() == Some(&value));
    assert_eq!(
        f.register.member(&member()).await.unwrap().unwrap().role,
        crgs::Role::Admin
    );
    // Exact retry reads the complete original tuple without staging an effect.
    let tx = f.store.insert(f.tx().await, &value).await.unwrap();
    tx.rollback().await.unwrap();
    let reopened = open(&f.path).await;
    let store = RoleRedemptions::new(reopened.community("alpha").unwrap());
    let (tx, row) = store
        .read(
            reopened.community("alpha").unwrap().tx().await.unwrap(),
            value.receipt(),
        )
        .await
        .unwrap();
    assert!(row.as_ref() == Some(&value));
    tx.rollback().await.unwrap();
    for (sql, parameter) in [
        (
            "SELECT receipt FROM cmbr_role_redemption WHERE receipt = ?1",
            value.receipt(),
        ),
        (
            "SELECT receipt FROM cmbr_role_redemption WHERE member = ?1",
            "founder-alpha",
        ),
    ] {
        reopened
            .community("alpha")
            .unwrap()
            .explain(sql, params![parameter])
            .await
            .unwrap()
            .assert_indexed()
            .unwrap();
    }
}

#[tokio::test]
async fn dropped_writer_rolls_back_both_genuine_admin_and_receipt() {
    let f = Fixture::new().await;
    let value = record();
    let (tx, _) = f.staged_admin().await;
    let tx = f.store.insert(tx, &value).await.unwrap();
    drop(tx);
    assert!(f.row(value.receipt()).await.is_none());
    assert!(f.register.member(&member()).await.unwrap().is_none());
}

#[tokio::test]
async fn exact_tuple_mismatch_rolls_back_prior_original_register_staging() {
    let f = Fixture::new().await;
    let value = record();
    f.store
        .insert(f.tx().await, &value)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let mut mismatches = vec![];
    let mut changed = value.clone();
    changed.binding = "c".repeat(64);
    mismatches.push(changed);
    let mut changed = value.clone();
    changed.expires += 1;
    mismatches.push(changed);
    let mut changed = value.clone();
    changed.member = crgs::MemberId::new(b"other").unwrap();
    mismatches.push(changed);
    let mut changed = value.clone();
    changed.lease = crgs::YearMonth::new(2099, 11).unwrap();
    mismatches.push(changed);
    let mut changed = value.clone();
    changed.admitted_revision += 1;
    mismatches.push(changed);
    for changed in mismatches {
        let (tx, _) = f.staged_admin().await;
        assert!(matches!(
            f.store.insert(tx, &changed).await,
            Err(Error::Busy)
        ));
        assert!(f.register.member(&member()).await.unwrap().is_none());
        assert!(f.row(value.receipt()).await.as_ref() == Some(&value));
    }
}

#[tokio::test]
async fn second_receipt_for_same_member_is_not_a_second_founder_effect() {
    let f = Fixture::new().await;
    let value = record();
    f.store
        .insert(f.tx().await, &value)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let mut other = value.clone();
    other.receipt = "d".repeat(64);
    let (tx, _) = f.staged_admin().await;
    assert!(matches!(
        f.store.insert(tx, &other).await,
        Err(Error::Transition)
    ));
    assert!(f.register.member(&member()).await.unwrap().is_none());
    assert!(f.row(other.receipt()).await.is_none());
    assert!(f.row(value.receipt()).await.as_ref() == Some(&value));
}

#[tokio::test]
async fn foreign_scope_or_same_file_different_pool_refuses_and_rolls_back() {
    let f = Fixture::new().await;
    let value = record();
    let other = RoleRedemptions::new(f.db.community("other").unwrap());
    let (tx, _) = f.staged_admin().await;
    assert!(matches!(
        other.insert(tx, &value).await,
        Err(Error::Identity)
    ));
    assert!(f.register.member(&member()).await.unwrap().is_none());
    let reopened = open(&f.path).await;
    let other_pool = RoleRedemptions::new(reopened.community("alpha").unwrap());
    let (tx, _) = f.staged_admin().await;
    assert!(matches!(
        other_pool.read(tx, value.receipt()).await,
        Err(Error::Identity)
    ));
    assert!(f.register.member(&member()).await.unwrap().is_none());
    assert!(f.row(value.receipt()).await.is_none());
}

#[test]
fn malformed_data_is_not_a_redemption_record() {
    for (receipt, binding) in [
        ("A".repeat(64), "b".repeat(64)),
        ("a".repeat(63), "b".repeat(64)),
        ("a".repeat(64), "x".repeat(64)),
    ] {
        assert!(Redemption::new(&receipt, &binding, 2000, member(), lease(), 1).is_err());
    }
    for bound in [0, i64::MAX as u64 + 1] {
        assert!(
            Redemption::new(
                &"a".repeat(64),
                &"b".repeat(64),
                bound,
                member(),
                lease(),
                1
            )
            .is_err()
        );
        assert!(
            Redemption::new(
                &"a".repeat(64),
                &"b".repeat(64),
                2000,
                member(),
                lease(),
                bound
            )
            .is_err()
        );
    }
    for bytes in [vec![0xff], vec![0], b"  ".to_vec(), vec![b'a'; 1025]] {
        assert!(
            Redemption::new(
                &"a".repeat(64),
                &"b".repeat(64),
                2000,
                crgs::MemberId::new(bytes).unwrap(),
                lease(),
                1
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn actual_failed_sql_write_cannot_acknowledge_a_redemption() {
    // A stricter application-owned table is a real SQLite persistence failure,
    // not a mock transaction or a synthesized refusal/acceptance capability.
    let schema =
        ROLE_REDEMPTION_SCHEMA.replace("expires_at > 0", "expires_at > 0 AND expires_at <= 1000");
    let f = Fixture::with_schema(&schema).await;
    let (tx, _) = f.staged_admin().await;
    assert!(matches!(
        f.store.insert(tx, &record()).await,
        Err(Error::Unavailable)
    ));
    assert!(f.register.member(&member()).await.unwrap().is_none());
    assert!(f.row(record().receipt()).await.is_none());
}

#[tokio::test]
async fn malformed_stored_member_refuses_and_drops_prior_admin_staging() {
    let f = Fixture::new().await;
    let value = record();
    f.store
        .insert(f.tx().await, &value)
        .await
        .unwrap()
        .commit()
        .await
        .unwrap();
    let mut tx = f.tx().await;
    tx.execute(
        "UPDATE cmbr_role_redemption SET member = ?1 WHERE receipt = ?2",
        params!["\u{1}", value.receipt()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (tx, _) = f.staged_admin().await;
    assert!(matches!(
        f.store.read(tx, value.receipt()).await,
        Err(Error::Unavailable)
    ));
    assert!(f.register.member(&member()).await.unwrap().is_none());
}
