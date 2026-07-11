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
    let indexer = Indexer::open(root, identity.clone(), identity).map_err(std::io::Error::other)?;
    let address = std::env::var("NOOS_INDEXER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, router(indexer)).await
}
