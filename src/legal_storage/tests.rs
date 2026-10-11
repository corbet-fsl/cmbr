use super::*;
use crate::test_common as common;
use crate::{Error, LibsqlStorage, MemoryStorage};
use common::*;
mod views;

#[tokio::test(flavor = "multi_thread")]
async fn invalid_self_ban_proof_never_records_an_order_or_emits_a_revocation() {
    let (_directory, db) = temporary().await;
    let membership = facade(&db, "invalid-ban", Clock::new());
    let (_, login) = pending(&membership, "invalid-ban").await;
    let mut signed = ban("invalid-ban");
    signed.proof = vec![0; 64];
    assert_eq!(
        membership.self_ban(&login.authentication, &signed).await,
        Err(Error::Restricted)
    );
    assert!(membership.revocations(10).await.unwrap().is_empty());
    let store = cgts::legal_storage::LibsqlStore::new(&db, "invalid-ban").unwrap();
    assert_eq!(store.record(&signed.order.id).await.unwrap(), None);
    assert!(membership.resume(&login.authentication).await.is_ok());
}

#[tokio::test]
async fn verified_append_and_outbox_survive_lost_response_and_canonical_retry_without_another_notice()
 {
    let (directory, db) = temporary().await;
    let storage = Arc::new(LibsqlStorage::new(&db, "atomic-ban").unwrap());
    let gate = clbs::Gate::new(
        LegalStore::new(&db, storage.clone()).unwrap(),
        Verify,
        Clock::new(),
    );
    // The caller loses the result before advancing membership or publishing.
    // The durable record and matching outbox must be sufficient after reopening.
    gate.self_ban(&ban("atomic-ban")).await.unwrap();
    let before = storage.revocations(10).await.unwrap().remove(0);
    drop(gate);
    drop(storage);
    drop(db);
    let db = open(
        &format!("file://{}", directory.path().join("members.db").display()),
        "",
    )
    .await;
    let storage = Arc::new(LibsqlStorage::new(&db, "atomic-ban").unwrap());
    let gate = clbs::Gate::new(
        LegalStore::new(&db, storage.clone()).unwrap(),
        Verify,
        Clock::new(),
    );
    let record = gate.record("confirmed-self-ban").await.unwrap().unwrap();
    assert_eq!(record.order(), &ban("atomic-ban").order);
    let after = storage.revocations(10).await.unwrap().remove(0);
    assert_eq!(after.generation, before.generation);
    assert_eq!(
        gate.self_ban(&ban("atomic-ban")).await.unwrap(),
        clbs::Append::Unchanged
    );
    assert_eq!(
        storage.revocations(10).await.unwrap().remove(0).generation,
        before.generation
    );
    storage.acknowledge(&after).await.unwrap();
    assert_eq!(
        gate.self_ban(&ban("atomic-ban")).await.unwrap(),
        clbs::Append::Unchanged
    );
    assert!(storage.revocations(10).await.unwrap().is_empty());
    assert!(matches!(
        gate.check_action(SUBJECT, "arbitrary-action")
            .await
            .unwrap(),
        clbs::State::Red(_)
    ));
}

#[tokio::test]
async fn notice_generation_failure_rolls_back_the_verified_order_without_erasing_existing_notice() {
    let (_directory, db) = temporary().await;
    let storage = Arc::new(LibsqlStorage::new(&db, "notice-overflow").unwrap());
    storage.signal_revocation(SUBJECT).await.unwrap();
    db.community("notice-overflow")
        .unwrap()
        .execute(
            "UPDATE cmbr_revocations SET generation = ?1 WHERE subject = ?2",
            crlt::params![i64::MAX, SUBJECT],
        )
        .await
        .unwrap();
    let gate = clbs::Gate::new(
        LegalStore::new(&db, storage.clone()).unwrap(),
        Verify,
        Clock::new(),
    );
    assert_eq!(
        gate.self_ban(&ban("notice-overflow")).await,
        Err(clbs::Error::Storage)
    );
    assert_eq!(gate.record("confirmed-self-ban").await.unwrap(), None);
    assert_eq!(
        storage.revocations(10).await.unwrap().remove(0).generation,
        i64::MAX as u64
    );
    assert!(matches!(
        gate.check_action(SUBJECT, "arbitrary-action")
            .await
            .unwrap(),
        clbs::State::Green
    ));
}

#[tokio::test]
async fn a_caller_store_without_transaction_support_refuses_atomic_legal_mutation() {
    let (_directory, db) = temporary().await;
    let storage = Arc::new(MemoryStorage::new("no-atomic-port").unwrap());
    let gate = clbs::Gate::new(
        LegalStore::new(&db, storage.clone()).unwrap(),
        Verify,
        Clock::new(),
    );
    assert_eq!(
        gate.self_ban(&ban("no-atomic-port")).await,
        Err(clbs::Error::Storage)
    );
    assert_eq!(gate.record("confirmed-self-ban").await.unwrap(), None);
    assert!(storage.revocations(10).await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn membership_retry_after_permanent_termination_does_not_emit_another_notice() {
    let (_directory, db) = temporary().await;
    let membership = facade(&db, "membership-retry", Clock::new());
    let (_, login) = pending(&membership, "membership-retry").await;
    let signed = ban("membership-retry");
    assert_eq!(
        membership
            .self_ban(&login.authentication, &signed)
            .await
            .unwrap()
            .state(),
        cmbr::State::Released
    );
    let before = membership
        .revocations(10)
        .await
        .unwrap()
        .remove(0)
        .generation;
    assert_eq!(
        membership
            .self_ban(&login.authentication, &signed)
            .await
            .unwrap()
            .state(),
        cmbr::State::Released
    );
    assert_eq!(
        membership
            .revocations(10)
            .await
            .unwrap()
            .remove(0)
            .generation,
        before
    );
}

#[tokio::test]
async fn a_caller_storage_from_another_database_cannot_hide_the_atomic_notice() {
    let (_first_directory, first) = temporary().await;
    let (_second_directory, second) = temporary().await;
    let storage = Arc::new(LibsqlStorage::new(&second, "mismatched-db").unwrap());
    let gate = clbs::Gate::new(
        LegalStore::new(&first, storage.clone()).unwrap(),
        Verify,
        Clock::new(),
    );
    assert_eq!(
        gate.self_ban(&ban("mismatched-db")).await,
        Err(clbs::Error::Storage)
    );
    assert_eq!(gate.record("confirmed-self-ban").await.unwrap(), None);
    assert!(storage.revocations(10).await.unwrap().is_empty());
    assert!(
        LibsqlStorage::new(&first, "mismatched-db")
            .unwrap()
            .revocations(10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn transaction_notice_refuses_foreign_scope_and_accepts_the_exact_database_clone() {
    let (_directory, db) = temporary().await;
    let storage = LibsqlStorage::new(&db, "owner").unwrap();
    let mut foreign = db.community("other").unwrap().tx().await.unwrap();
    assert_eq!(
        storage
            .signal_revocation_transaction(&mut foreign, SUBJECT)
            .await,
        Err(Error::Identity)
    );
    foreign.rollback().await.unwrap();
    assert!(storage.revocations(10).await.unwrap().is_empty());
    let mut own = db.clone().community("owner").unwrap().tx().await.unwrap();
    storage
        .signal_revocation_transaction(&mut own, SUBJECT)
        .await
        .unwrap();
    own.commit().await.unwrap();
    assert_eq!(storage.revocations(10).await.unwrap().len(), 1);
}
