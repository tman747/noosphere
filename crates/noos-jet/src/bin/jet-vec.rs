//! Deterministic golden-vector generator for noos-jet.
//!
//! Writes `protocol/vectors/jet/*.json` relative to the workspace root
//! (two levels up from this crate), or to the directory given as the first
//! argument. JSON is emitted by hand from fully controlled ASCII content
//! (`noos_jet::vectors`); the same tables are executed by the crate tests,
//! which also byte-compare the committed files against fresh emission.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let out_dir: PathBuf = match std::env::args().nth(1) {
        Some(d) => PathBuf::from(d),
        None => {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest.join("../../protocol/vectors/jet")
        }
    };
    if let Err(err) = std::fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {err}", out_dir.display());
        return ExitCode::FAILURE;
    }

    for (name, content) in noos_jet::vectors::vector_files() {
        let path = out_dir.join(name);
        if let Err(err) = std::fs::write(&path, content.as_bytes()) {
            eprintln!("cannot write {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {} ({} bytes)", path.display(), content.len());
    }
    ExitCode::SUCCESS
}
