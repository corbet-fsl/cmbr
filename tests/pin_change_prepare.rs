//! Genuine passkey authority and the original member queue, before native proof.
mod common;
use common::*;
use std::time::Duration;

fn pin(field: &str, salt: u8) -> cmbr::PinV2 {
    cmbr::PinV2::seal(
        &cpns::FingerprintContext {
            community: "garden",
            member: SUBJECT,
            field,
        },
        b"fixture-value",
        &cpns::Salt::from_bytes(vec![salt; 32]).unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_change_retains_actual_member_queue_and_exclusive_session_bound() {
    let (_dir, db) = temporary().await;
    let clock = Clock::new();
    let facade = facade(&db, "garden", clock.clone());
    let (mut device, first) = pending(&facade, "garden").await;
    let second = login(&facade, &mut device, USER).await;
    let expected = facade
        .pin(&first.authentication, "age", &pin("age", 1))
        .await
        .unwrap();
    let until = now() as u64 + 10;
    let held = facade
        .prepare_pin_change(
            &first.authentication,
            "age",
            expected,
            &pin("age", 2),
            until,
        )
        .await
        .unwrap();
    let writer = facade.clone();
    let mut queued = tokio::spawn(async move {
        writer
            .pin(&second.authentication, "other", &pin("other", 3))
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut queued)
            .await
            .is_err()
    );
    drop(held);
    queued.await.unwrap().unwrap();
    clock.set(until as i64);
    assert!(matches!(
        facade
            .prepare_pin_change(
                &first.authentication,
                "age",
                expected,
                &pin("age", 2),
                until
            )
            .await,
        Err(cmbr::Error::Unavailable)
    ));
    assert_eq!(
        facade.get_pin(&first.authentication, "age").await.unwrap(),
        Some(expected)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_change_rejects_device_context_and_revision_without_touching_pin() {
    let (_dir, db) = temporary().await;
    let facade = facade(&db, "garden", Clock::new());
    let (_, login) = pending(&facade, "garden").await;
    let expected = facade
        .pin(&login.authentication, "age", &pin("age", 1))
        .await
        .unwrap();
    assert!(
        facade
            .prepare_pin_change(
                &login.authentication,
                "age",
                expected,
                &pin("other", 2),
                now() as u64 + 10
            )
            .await
            .is_err()
    );
    assert!(
        facade
            .prepare_pin_change(
                &login.authentication,
                "age",
                cmbr::Pin {
                    revision: u64::MAX,
                    ..expected
                },
                &pin("age", 2),
                now() as u64 + 10
            )
            .await
            .is_err()
    );
    assert_eq!(
        facade.get_pin(&login.authentication, "age").await.unwrap(),
        Some(expected)
    );
}
