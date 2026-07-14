use noos_mind_gateway::service::{config::RuntimeConfig, GatewayService};
use std::{env, path::PathBuf, process::ExitCode};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("noos-mind-gateway: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let Some(flag) = arguments.next() else {
        return Err("usage: noos-mind-gateway --config <path>".into());
    };
    let Some(path) = arguments.next() else {
        return Err("usage: noos-mind-gateway --config <path>".into());
    };
    if flag != "--config" || arguments.next().is_some() {
        return Err("usage: noos-mind-gateway --config <path>".into());
    }
    let config = RuntimeConfig::load(&PathBuf::from(path))?;
    let listen = config.listen;
    let model = config.model.model.clone();
    let service = GatewayService::new(config)?;
    println!(
        "WWM TEST-ONLY gateway listening on http://{listen}/query.html using local model {model}"
    );
    println!("No WWM production control or chain-write path is enabled.");
    service.run().await?;
    Ok(())
}
