use noos_indexer::ingest::LineProtocolSource;
use noos_indexer::{router, Identity, Indexer};

#[tokio::main]
async fn main() -> std::io::Result<()> {
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

    // Live ingestion from a local noosd operator RPC, when configured.
    if let (Ok(node), Ok(token)) = (
        std::env::var("NOOS_NODE_RPC"),
        std::env::var("NOOS_NODE_TOKEN"),
    ) {
        let ingest_indexer = indexer.clone();
        tokio::spawn(async move {
            let mut source = LineProtocolSource::new(node, token);
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                ticker.tick().await;
                // Short blocking localhost round-trips; acceptable in this
                // dedicated operator task.
                if let Err(error) = ingest_indexer
                    .sync_from_node(&identity, &mut source, 1024)
                    .await
                {
                    eprintln!("ingest: {error}");
                }
            }
        });
    }

    let address = std::env::var("NOOS_INDEXER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router(indexer)).await
}
