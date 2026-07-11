//! Deterministic conformance-vector generator for noos-lumen.
//!
//! Writes `protocol/vectors/lumen/{lumen-tx-v1,lumen-ids-v1,lumen-smt-v1}.json`
//! relative to the workspace root (two levels up from this crate). The case
//! content is built by `noos_lumen::vector_gen`, which the crate's tests
//! re-derive and verify — generator and implementation cannot drift.

// One-shot CLI writer: failing fast on IO errors is the correct behavior.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use noos_lumen::vector_gen;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("vectors")
        .join("lumen");
    std::fs::create_dir_all(&root).expect("create protocol/vectors/lumen");

    for (file, vectors) in [
        ("lumen-tx-v1.json", vector_gen::tx_vectors()),
        ("lumen-ids-v1.json", vector_gen::id_vectors()),
        ("lumen-smt-v1.json", vector_gen::smt_vectors()),
    ] {
        let path = root.join(file);
        std::fs::write(&path, vector_gen::to_json(&vectors)).expect("write vector file");
        println!("wrote {} ({} cases)", path.display(), vectors.cases.len());
    }
}
