fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match noos_cli::run(&args) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
