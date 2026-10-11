//! Actual WebAuthn, signed Policy and SQLite admission-owner composition.
//!
//! `common::checked` is the original external development-provider seam. These
//! tests qualify the membership writer, not a complete Global passport host.
use super::*;
use crate::test_common as common;

mod checked;
mod cuts;
mod first_root;
mod fixture;
mod founder;
mod lapse;
mod refusals;
use fixture::*;
