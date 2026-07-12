use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: risc0-method-id <combined-method-binary>");
        return ExitCode::FAILURE;
    };
    let blob = match fs::read(&path) {
        Ok(blob) => blob,
        Err(error) => {
            eprintln!("cannot read method artifact: {error}");
            return ExitCode::FAILURE;
        }
    };
    let digest = match risc0_binfmt::compute_image_id(&blob) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("cannot compute RISC Zero method id: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "{}",
        digest
            .as_words()
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    ExitCode::SUCCESS
}
