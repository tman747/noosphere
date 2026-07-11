//! Deterministic conformance-vector generator for noos-grain.
//!
//! Writes `protocol/vectors/grain/*.json` relative to the workspace root
//! (two levels up from this crate), or to the directory given as the first
//! argument. Zero dependencies: JSON is emitted by hand from fully
//! controlled ASCII content (`noos_grain::vectors`). The same case table is
//! executed by the crate tests, so the emitted expectations are exactly the
//! tested ones.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let out_dir: PathBuf = match std::env::args().nth(1) {
        Some(d) => PathBuf::from(d),
        None => {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest.join("../../protocol/vectors/grain")
        }
    };
    if let Err(err) = std::fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {err}", out_dir.display());
        return ExitCode::FAILURE;
    }

    let files: [(&str, String); 3] = [
        ("grain-eval-v1.json", noos_grain::vectors::eval_json()),
        (
            "grain-noun-bytes-v1.json",
            noos_grain::vectors::decode_json(),
        ),
        (
            "grain-hint-erasure-v1.json",
            noos_grain::vectors::hint_json(),
        ),
    ];
    for (name, content) in files {
        let path = out_dir.join(name);
        if let Err(err) = std::fs::write(&path, content.as_bytes()) {
            eprintln!("cannot write {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {} ({} bytes)", path.display(), content.len());
    }
    ExitCode::SUCCESS
}
