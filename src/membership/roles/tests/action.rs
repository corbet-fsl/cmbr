use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_operation_specific_legal_order_refuses_and_poisons_original_role_observation() {
    let (_directory, db) = common::temporary().await;
    let owner = common::facade(&db, "a", common::Clock::new());
    let auth = first(&owner).await;
    let mut lease = owner.role(&auth).await.unwrap();
    owner
        .check_role_action(&mut lease, "schema_set")
        .await
        .unwrap();
    let order = clbs::Order {
        community: "a".into(),
        id: "actual-schema-restriction".into(),
        subject: common::SUBJECT.into(),
        reference: "explicit real signature fixture".into(),
        entered_by: "fixture-operator".into(),
        kind: clbs::OrderKind::Legal {
            authority: "fixture-signature-authority".into(),
        },
        scope: clbs::Scope::Actions(["schema_set".into()].into()),
        period: clbs::Period {
            starts_at: common::now(),
            ends_at: None,
        },
    };
    let proof = SigningKey::from_bytes(&[7; 32])
        .sign(&order.signing_payload().unwrap())
        .to_bytes()
        .to_vec();
    owner
        .legal
        .record_legal(&clbs::SignedOrder { order, proof })
        .await
        .unwrap();
    // The configured membership action remains unrestricted. Checking only it
    // would incorrectly retain the earlier operation authorization.
    owner.check_role(&mut lease).await.unwrap();
    assert!(matches!(
        owner.check_role_action(&mut lease, "schema_set").await,
        Err(Error::Restricted)
    ));
    assert!(!lease.is_current(common::now() as u64));
    drop(lease);
    let mut fresh = owner.role(&auth).await.unwrap();
    owner
        .check_role_action(&mut fresh, "setting_set")
        .await
        .unwrap();
}
