#!/usr/bin/env bash
set -euo pipefail

: "${CREDENTIALS_DIRECTORY:?systemd credential directory is required}"
: "${NOOS_CHAIN_ID:?NOOS_CHAIN_ID is required}"
: "${NOOS_GENESIS_HASH:?NOOS_GENESIS_HASH is required}"
: "${NOOS_NODE_RPC:?NOOS_NODE_RPC is required}"
: "${NOOS_INDEXER_LISTEN:?NOOS_INDEXER_LISTEN is required}"
: "${NOOS_INDEXER_ROOT:?NOOS_INDEXER_ROOT is required}"

RPC_TOKEN_FILE="${CREDENTIALS_DIRECTORY}/rpc-token"
[[ -f "${RPC_TOKEN_FILE}" ]] || { echo "missing systemd rpc-token credential" >&2; exit 1; }
IFS= read -r RPC_TOKEN < "${RPC_TOKEN_FILE}"
[[ "${RPC_TOKEN}" =~ ^[A-Za-z0-9_-]{32,256}$ ]] || { echo "invalid rpc-token credential" >&2; exit 1; }

export NOOS_NODE_TOKEN="${RPC_TOKEN}"
exec /opt/mindchain-wwm/bin/noos-indexer
