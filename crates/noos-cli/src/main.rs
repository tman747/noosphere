use std::io::Read as _;
use zeroize::Zeroize as _;

fn inject_stdin_seed(args: &mut Vec<String>) -> Result<(), String> {
    if args.iter().any(|argument| argument == "--seed") {
        return Err("raw seed command-line arguments are forbidden; use --seed-stdin".into());
    }
    let positions = args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == "--seed-stdin").then_some(index))
        .collect::<Vec<_>>();
    if positions.len() > 1 {
        return Err("--seed-stdin may appear only once".into());
    }
    let Some(index) = positions.first().copied() else {
        return Ok(());
    };
    let mut seed = String::new();
    std::io::stdin()
        .take(257)
        .read_to_string(&mut seed)
        .map_err(|error| format!("cannot read seed from stdin: {error}"))?;
    if seed.len() > 256 {
        seed.zeroize();
        return Err("seed stdin is unbounded".into());
    }
    let trimmed = seed.trim().to_owned();
    seed.zeroize();
    args[index] = "--seed".into();
    args.insert(index.saturating_add(1), trimmed);
    Ok(())
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = inject_stdin_seed(&mut args) {
        args.zeroize();
        eprintln!("{error}");
        std::process::exit(2);
    }
    let result = noos_cli::run(&args);
    args.zeroize();
    match result {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
