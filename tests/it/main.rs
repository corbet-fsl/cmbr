//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/unit` stays put (the library compiles it via `#[path]`).
#[path = "../common/mod.rs"]
mod common;
mod discoverable;
mod first_seat;
mod membership;
mod pin_change_prepare;
mod pins_v2;
mod roles;
mod turso;
