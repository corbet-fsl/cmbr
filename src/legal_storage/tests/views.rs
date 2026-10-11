//! Signed owner records and their scoped snapshots, without an admission bypass.
use super::*;

#[tokio::test]
async fn legal_views_preserve_exact_active_records_counts_and_community_isolation() {
    let (_directory, db) = temporary().await;
    let storage = Arc::new(LibsqlStorage::new(&db, "legal-views").unwrap());
    let owner = LegalStore::new(&db, storage).unwrap();
    assert!(owner.active(SUBJECT, now()).await.unwrap().is_empty());
    assert!(owner.revocations(now()).await.unwrap().is_empty());
    assert_eq!(owner.counts(now()).await.unwrap(), Counts::default());
    let gate = clbs::Gate::new(owner, Verify, Clock::new());
    let signed = ban("legal-views");
    gate.self_ban(&signed).await.unwrap();
    assert_eq!(
        gate.counts().await.unwrap(),
        Counts {
            legal_orders: 0,
            self_bans: 1,
            active_legal_orders: 0,
            active_self_bans: 1
        }
    );
    let revoked = gate.revocations().await.unwrap();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].order_id, signed.order.id);
    assert_eq!(revoked[0].subject, SUBJECT);
    assert_eq!(revoked[0].community, "legal-views");
    assert_eq!(revoked[0].scope, signed.order.scope);
    assert_eq!(revoked[0].period, signed.order.period);
    let owner = LegalStore::new(
        &db,
        Arc::new(LibsqlStorage::new(&db, "legal-views").unwrap()),
    )
    .unwrap();
    assert_eq!(
        owner.active(SUBJECT, now()).await.unwrap()[0].order(),
        &signed.order
    );
    assert!(
        owner
            .active("other-member", now())
            .await
            .unwrap()
            .is_empty()
    );
    let foreign = LegalStore::new(
        &db,
        Arc::new(LibsqlStorage::new(&db, "other-community").unwrap()),
    )
    .unwrap();
    assert!(foreign.active(SUBJECT, now()).await.unwrap().is_empty());
    assert!(foreign.revocations(now()).await.unwrap().is_empty());
    assert_eq!(foreign.counts(now()).await.unwrap(), Counts::default());
}
