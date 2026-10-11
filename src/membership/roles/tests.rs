//! Genuine SDK, original register and durable legal authority scenarios.
use super::*;
use crate::test_common as common;
use cnrl::Storage as _;

mod activation;
mod assignment;
mod barrier;
mod lease;

async fn admitted<C: clbs::Clock + 'static>(
    owner: &Membership<crate::LibsqlStorage, common::Verify, C>,
    user: Uuid,
    subject: &str,
    handle: &str,
    until: crgs::YearMonth,
) -> Authentication {
    let mut device = common::register(owner, user, subject).await;
    let login = common::login(owner, &mut device, user).await;
    owner
        .reserve_handle(&login.authentication, handle, &[])
        .await
        .unwrap();
    owner
        .admit_test(
            &login.authentication,
            &common::policy("a"),
            &[common::test_gate("a", subject)],
            until,
        )
        .await
        .unwrap();
    login.authentication
}

async fn first<C: clbs::Clock + 'static>(
    owner: &Membership<crate::LibsqlStorage, common::Verify, C>,
) -> Authentication {
    admitted(
        owner,
        common::USER,
        common::SUBJECT,
        common::HANDLE,
        common::lease(),
    )
    .await
}

async fn seed_original_root(owner: &common::Facade, auth: &Authentication) {
    // The trusted fixture initializer uses the ACTUAL register writer. This
    // is not a production bootstrap claim or a fabricated role lease.
    let row = owner
        .enrol_store
        .load(auth.member())
        .await
        .unwrap()
        .unwrap();
    let original = owner
        .register
        .set_role(&row.member_id(), crgs::Role::Root)
        .await
        .unwrap();
    assert_eq!(original.role, crgs::Role::Root);
}
