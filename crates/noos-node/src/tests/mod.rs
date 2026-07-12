//! noos-node test battery (node-v1.md §10).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

mod util;

mod claims;
mod contract_exec;
mod devnet_finality;
mod e2e;
mod import_matrix;
mod mempool_tests;
mod network_e2e;
mod retention;
mod rpc_supervisor;
mod safety;
mod security_import;
mod sync_tests;
