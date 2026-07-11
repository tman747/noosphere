#![forbid(unsafe_code)]
use std::{
    env, fs,
    io::{self, BufRead, Read},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}
fn emit(source: &str, json: bool) -> Result<(), u8> {
    match noos_weft_compile::compile(source) {
        Ok(c) => {
            let out = if json {
                serde_json::to_string(&c)
            } else {
                serde_json::to_string_pretty(&c)
            }
            .map_err(|e| {
                eprintln!("E-EMIT-001: {e}");
                2
            })?;
            println!("{out}");
            Ok(())
        }
        Err(ds) => {
            for d in ds {
                eprintln!("{d}")
            }
            Err(1)
        }
    }
}
fn run() -> Result<(), u8> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version") {
        println!("weftc {} grain-v1", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args.iter().any(|a| a == "--ndjson") {
        for line in io::stdin().lock().lines() {
            let line = line.map_err(|e| {
                eprintln!("E-IO-001: {e}");
                2
            })?;
            emit(&line, true)?
        }
        return Ok(());
    }
    let json = args.iter().any(|a| a == "--json");
    let path = args.iter().find(|a| !a.starts_with('-'));
    let mut source = String::new();
    if let Some(path) = path {
        source = fs::read_to_string(path).map_err(|e| {
            eprintln!("E-IO-001: {e}");
            2
        })?
    } else {
        io::stdin().read_to_string(&mut source).map_err(|e| {
            eprintln!("E-IO-001: {e}");
            2
        })?;
    }
    emit(&source, json)
}
