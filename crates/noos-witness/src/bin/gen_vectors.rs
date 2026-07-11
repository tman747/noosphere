//! Writes `protocol/vectors/witness/*.json` from the shared deterministic
//! generator (`noos_witness::vector_gen`). The crate tests verify the
//! on-disk bytes match this output exactly, so regeneration is always safe.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("vectors")
        .join("witness");
    std::fs::create_dir_all(&dir).expect("create vectors dir");
    for (name, file) in noos_witness::vector_gen::files() {
        let path = dir.join(name);
        let json = noos_witness::vector_gen::render_json(&file);
        std::fs::write(&path, json.as_bytes()).expect("write vector file");
        println!("wrote {} ({} cases)", path.display(), file.cases.len());
    }
}
