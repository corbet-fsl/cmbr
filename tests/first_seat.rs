//! The first seat of a community comes from the caller's entitlement, never from the community name.
mod common;
use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn a_community_named_root_has_an_ordinary_first_admin() {
    let (_dir, db) = temporary().await;
    let facade = facade(&db, "root", Clock::new());
    assert_eq!(facade.community(), "root");
    // `ensure_first_seat` asserts the stored role of the first member.
    ensure_first_seat(&facade, crgs::Role::Admin).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_board_first_seat_is_root_under_any_community_name() {
    let (_dir, db) = temporary().await;
    let facade = facade(&db, "adminboard", Clock::new());
    assert_eq!(facade.community(), "adminboard");
    ensure_first_seat(&facade, crgs::Role::Root).await.unwrap();
}
