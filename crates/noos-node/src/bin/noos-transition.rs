//! Differential admission endpoint. This intentionally contains no transition
//! model: every object is sent through the production NodeCore mempool path.
use noos_node::{
    consensus::{NodeConfig, NodeCore},
    genesis::{DevnetParams, GenesisSpec},
    metrics::Metrics,
    store_port::InProcStore,
};
use std::{
    io::{self, BufRead},
    path::Path,
    sync::Arc,
};
fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    };
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .map_err(|_| ())
                .and_then(|p| u8::from_str_radix(p, 16).map_err(|_| ()))
        })
        .collect()
}
fn boot() -> Result<(NodeCore<InProcStore>, [u8; 32]), String> {
    let params = DevnetParams::load(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/genesis/devnet-parameters.toml"),
    )
    .map_err(|e| e.to_string())?;
    let spec = GenesisSpec::devnet(params, 1_760_000_000_000);
    let built = spec.build().map_err(|e| e.to_string())?;
    let chain_id = built.chain_id;
    let mut dir = std::env::temp_dir();
    dir.push(format!("noos-differential-node-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port =
        InProcStore::open(dir, &built.chain_id, &built.genesis_hash).map_err(|e| e.to_string())?;
    let core = NodeCore::boot(
        NodeConfig::default(),
        &spec,
        built,
        port,
        Arc::new(Metrics::default()),
    )
    .map_err(|e| e.to_string())?;
    Ok((core, chain_id))
}
fn main() {
    let (mut core, chain_id) = match boot() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("node boot: {e}");
            std::process::exit(2)
        }
    };
    println!(
        "READY:{}",
        chain_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    for line in io::stdin().lock().lines() {
        let Ok(line) = line else {
            std::process::exit(2)
        };
        let f: Vec<&str> = line.trim().split(',').collect();
        if f.len() != 12 {
            println!("MALFORMED");
            continue;
        }
        let (Ok(tx), Ok(wit)) = (unhex(f[1]), unhex(f[2])) else {
            println!("MALFORMED");
            continue;
        };
        let source = f[0].parse::<u64>().unwrap_or(0);
        match core.submit_tx(&tx, &wit, source) {
            Ok(id) => println!(
                "ADMITTED:{}",
                id.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            Err(e) => println!("REJECTED:{e:?}"),
        }
    }
}
