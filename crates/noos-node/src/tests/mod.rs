//! noos-node test battery (node-v1.md §10).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

mod util;

mod e2e;
mod import_matrix;
mod mempool_tests;
mod retention;
mod safety;
mod sync_tests;
