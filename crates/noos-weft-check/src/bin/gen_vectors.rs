//! Deterministic conformance-vector generator for noos-weft-check.
//!
//! Writes `protocol/vectors/weft/*.json` relative to the workspace root
//! (two levels up from this crate), or to the directory given as the first
//! argument. JSON is emitted by hand from fully controlled ASCII content
//! (`noos_weft_check::vectors`). The same case tables are executed by the
//! crate tests, so the emitted expectations are exactly the tested ones.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let out_dir: PathBuf = match std::env::args().nth(1) {
        Some(d) => PathBuf::from(d),
        None => {
            let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest.join("../../protocol/vectors/weft")
        }
    };
    if let Err(err) = std::fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {err}", out_dir.display());
        return ExitCode::FAILURE;
    }

    let files: [(&str, String); 3] = [
        (
            "weft-profile-v0.json",
            noos_weft_check::vectors::profile_json(),
        ),
        ("weft-cost-v0.json", noos_weft_check::vectors::cost_json()),
        ("weft-refs-v0.json", noos_weft_check::vectors::refs_json()),
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
