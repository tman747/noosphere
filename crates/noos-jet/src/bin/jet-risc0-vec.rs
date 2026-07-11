use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let path = std::env::args().nth(1).map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../protocol/vectors/jet/jet-risc0-proof-v1.json")
        },
        PathBuf::from,
    );
    let content = noos_jet::vectors::risc0_json();
    if let Some(parent) = path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            eprintln!("cannot create {}: {error}", parent.display());
            return ExitCode::FAILURE;
        }
    }
    if let Err(error) = std::fs::write(&path, content.as_bytes()) {
        eprintln!("cannot write {}: {error}", path.display());
        return ExitCode::FAILURE;
    }
    println!("wrote {} ({} bytes)", path.display(), content.len());
    ExitCode::SUCCESS
}
