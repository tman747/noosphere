use noos_indexer::ingest::LineProtocolSource;
use noos_indexer::{router, router_with_operator, Identity, Indexer};

fn bounded_env(name: &str, default: u64, minimum: u64, maximum: u64) -> std::io::Result<u64> {
    let value = match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|_| std::io::Error::other(format!("{name} must be an integer")))?,
        Err(std::env::VarError::NotPresent) => default,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(std::io::Error::other(format!("{name} must be UTF-8")));
        }
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(std::io::Error::other(format!(
            "{name} must be between {minimum} and {maximum}"
        )));
    }
    Ok(value)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["--version"] {
        println!(
            "noos-indexer {} source_revision={}",
            noos_indexer::RELEASE_VERSION,
            noos_indexer::SOURCE_REVISION
        );
        return Ok(());
    }
    if !arguments.is_empty() {
        return Err(std::io::Error::other(
            "noos-indexer accepts only --version; runtime configuration uses NOOS_* environment variables",
        ));
    }
    let root = std::env::var_os("NOOS_INDEXER_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("./noos-index"));
    let chain_id = std::env::var("NOOS_CHAIN_ID")
        .map_err(|_| std::io::Error::other("NOOS_CHAIN_ID is required"))?;
    let genesis_hash = std::env::var("NOOS_GENESIS_HASH")
        .map_err(|_| std::io::Error::other("NOOS_GENESIS_HASH is required"))?;
    let identity = Identity {
        chain_id,
        genesis_hash,
        api_version: "v1".into(),
    };
    let indexer =
        Indexer::open(root, identity.clone(), identity.clone()).map_err(std::io::Error::other)?;

    // Live ingestion and public transaction forwarding share the same
    // authenticated noosd line-protocol client when both settings exist.
    let operator_source = match (
        std::env::var("NOOS_NODE_RPC"),
        std::env::var("NOOS_NODE_TOKEN"),
    ) {
        (Ok(node), Ok(token)) if !node.is_empty() && !token.is_empty() => {
            Some(LineProtocolSource::new(node, token))
        }
        _ => None,
    };
    let sync_batch_size = bounded_env("NOOS_INDEXER_SYNC_BATCH_SIZE", 128, 1, 512)?;
    let sync_interval_ms = bounded_env("NOOS_INDEXER_SYNC_INTERVAL_MS", 250, 50, 10_000)?;
    if let Some(mut source) = operator_source.clone() {
        let ingest_indexer = indexer.clone();
        let ingest_identity = identity.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_millis(sync_interval_ms));
            loop {
                ticker.tick().await;
                // Short blocking localhost round-trips; acceptable in this
                // dedicated operator task.
                if let Err(error) = ingest_indexer
                    .sync_from_node(&ingest_identity, &mut source, sync_batch_size)
                    .await
                {
                    eprintln!("ingest: {error}");
                }
            }
        });
    }

    let address = std::env::var("NOOS_INDEXER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(address).await?;
    let app = match operator_source {
        Some(source) => router_with_operator(indexer, source),
        None => router(indexer),
    };
    axum::serve(listener, app).await
}
