use super::*;

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    db: crlt::Db,
    store: LibsqlStorage,
}

async fn open(path: &std::path::Path) -> crlt::Db {
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    db.migrate(&[crlt::Migration::new(1, "cmbr", SCHEMA)])
        .await
        .unwrap();
    db
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("probation.db");
        let db = open(&path).await;
        let store = LibsqlStorage::new(&db, "a").unwrap();
        Self {
            _directory: directory,
            path,
            db,
            store,
        }
    }
    async fn tx(&self) -> crlt::Transaction {
        self.db.community("a").unwrap().tx().await.unwrap()
    }
}

#[tokio::test]
async fn original_init_clear_and_exact_retries_never_restart_probation() {
    let fixture = Fixture::new().await;
    let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        fixture.store.probation("member").await.unwrap(),
        Some(Some(172800))
    );
    let tx = admit(&fixture.store, fixture.tx().await, "member", 259200, 86400)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        fixture.store.probation("member").await.unwrap(),
        Some(Some(172800))
    );
    let tx = admit(&fixture.store, fixture.tx().await, "member", 259200, 172800)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(fixture.store.probation("member").await.unwrap(), Some(None));
    let tx = admit(&fixture.store, fixture.tx().await, "member", 345600, 259200)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(fixture.store.probation("member").await.unwrap(), Some(None));
    let reopened = open(&fixture.path).await;
    assert_eq!(
        LibsqlStorage::new(&reopened, "a")
            .unwrap()
            .probation("member")
            .await
            .unwrap(),
        Some(None)
    );
}

#[tokio::test]
async fn dropped_refused_and_abandoned_operations_rollback_prior_staging() {
    let fixture = Fixture::new().await;
    let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
        .await
        .unwrap();
    drop(tx);
    assert_eq!(fixture.store.probation("member").await.unwrap(), None);
    for (until, now) in [(1, 86400), (u64::MAX, 86400), (172800, u64::MAX)] {
        let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
            .await
            .unwrap();
        assert!(matches!(
            admit(&fixture.store, tx, "other", until, now).await,
            Err(Error::InvalidInput)
        ));
        assert_eq!(fixture.store.probation("member").await.unwrap(), None);
        assert_eq!(fixture.store.probation("other").await.unwrap(), None);
    }
    let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
        .await
        .unwrap();
    let future = admit(&fixture.store, tx, "other", 259200, 86400);
    drop(future);
    assert_eq!(fixture.store.probation("member").await.unwrap(), None);
    assert_eq!(fixture.store.probation("other").await.unwrap(), None);
}

#[tokio::test]
async fn unsupported_and_foreign_scope_or_reopened_owner_never_commit() {
    let fixture = Fixture::new().await;
    let other = LibsqlStorage::new(&fixture.db, "other").unwrap();
    let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
        .await
        .unwrap();
    assert!(matches!(
        admit(&other, tx, "member", 172800, 86400).await,
        Err(Error::Identity)
    ));
    assert_eq!(fixture.store.probation("member").await.unwrap(), None);
    let reopened = open(&fixture.path).await;
    let foreign = LibsqlStorage::new(&reopened, "a").unwrap();
    let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
        .await
        .unwrap();
    assert!(matches!(
        admit(&foreign, tx, "member", 172800, 86400).await,
        Err(Error::Identity)
    ));
    assert_eq!(fixture.store.probation("member").await.unwrap(), None);
    let tx = admit(&fixture.store, fixture.tx().await, "member", 172800, 86400)
        .await
        .unwrap();
    assert!(matches!(
        MemoryStorage::new("a")
            .unwrap()
            .admit_probation_in_transaction(tx, "member", 172800, 86400)
            .await,
        Err(Error::Unavailable)
    ));
    assert_eq!(fixture.store.probation("member").await.unwrap(), None);
}
