#!/usr/bin/env bash
set -euo pipefail

: "${NODE_ROLE:?NODE_ROLE is required}"
: "${WITNESS_INDEX:?WITNESS_INDEX is required}"
: "${P2P_LISTEN:?P2P_LISTEN is required}"
: "${BOOTSTRAP_REGISTRY:?BOOTSTRAP_REGISTRY is required}"
: "${BOOTSTRAP_PUBLIC_KEY_FILE:?BOOTSTRAP_PUBLIC_KEY_FILE is required}"
RPC_LISTEN="${RPC_LISTEN:-127.0.0.1:29652}"
RPC_TOKEN_FILE="${RPC_TOKEN_FILE:-/etc/mindchain-wwm/rpc-token}"
DATA_DIR="${DATA_DIR:-/var/lib/mindchain-wwm}"
PRODUCE_INTERVAL_MS="${PRODUCE_INTERVAL_MS:-6000}"
PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT="${PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT:-0}"
[[ "${NODE_ROLE}" =~ ^(validator|producer-witness|witness)$ ]] || { echo "invalid node role" >&2; exit 1; }
[[ "${WITNESS_INDEX}" =~ ^[0-3]$ ]] || { echo "invalid witness index" >&2; exit 1; }
[[ "${P2P_LISTEN}" =~ ^/ip4/0\.0\.0\.0/udp/[0-9]{4,5}/quic-v1$ ]] || { echo "invalid P2P listen multiaddr" >&2; exit 1; }
[[ "${RPC_LISTEN}" =~ ^127\.0\.0\.1:[0-9]{4,5}$ ]] || { echo "invalid loopback RPC listen address" >&2; exit 1; }
[[ "${RPC_TOKEN_FILE}" =~ ^/etc/mindchain-wwm/[a-zA-Z0-9._-]+$ ]] || { echo "invalid RPC token path" >&2; exit 1; }
[[ "${DATA_DIR}" =~ ^/var/lib/mindchain-wwm(-witness-[0-3])?$ ]] || { echo "invalid node data path" >&2; exit 1; }
[[ "${PRODUCE_INTERVAL_MS}" =~ ^[1-9][0-9]{2,5}$ ]] || { echo "invalid production interval" >&2; exit 1; }
[[ "${PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT}" =~ ^(0|[1-9][0-9]*)$ ]] || { echo "invalid public-testnet refund activation height" >&2; exit 1; }
[[ "${BOOTSTRAP_REGISTRY}" == "/etc/mindchain-wwm/bootstrap-registry.json" ]] || { echo "invalid bootstrap registry path" >&2; exit 1; }
[[ "${BOOTSTRAP_PUBLIC_KEY_FILE}" == "/etc/mindchain-wwm/bootstrap-registry.public" ]] || { echo "invalid bootstrap public key path" >&2; exit 1; }
[[ -f "${BOOTSTRAP_REGISTRY}" && ! -L "${BOOTSTRAP_REGISTRY}" ]] || { echo "bootstrap registry is missing or symbolic" >&2; exit 1; }
[[ -f "${BOOTSTRAP_PUBLIC_KEY_FILE}" && ! -L "${BOOTSTRAP_PUBLIC_KEY_FILE}" ]] || { echo "bootstrap public key is missing or symbolic" >&2; exit 1; }
BOOTSTRAP_PUBLIC_KEY="$(tr -d '\r\n' < "${BOOTSTRAP_PUBLIC_KEY_FILE}")"
[[ "${BOOTSTRAP_PUBLIC_KEY}" =~ ^[0-9a-f]{64}$ ]] || { echo "bootstrap public key is malformed" >&2; exit 1; }

arguments=(
  --params /opt/mindchain-wwm/protocol/genesis/devnet-parameters.toml
  --devnet-witness-fixture
  --devnet-bonsai-fixture
  --public-testnet-genesis-v1
  --devnet-governance-account 17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce
  --rpc "${RPC_LISTEN}"
  --rpc-token-file "${RPC_TOKEN_FILE}"
  --p2p-listen "${P2P_LISTEN}"
  --bootstrap-registry "${BOOTSTRAP_REGISTRY}"
  --bootstrap-public-key "${BOOTSTRAP_PUBLIC_KEY}"
  --data-dir "${DATA_DIR}"
)
if [[ "${PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT}" != "0" ]]; then
  arguments+=(--public-testnet-refund-activation-height "${PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT}")
fi
throughput_arguments=(
  --mempool-max-transactions 65536
  --mempool-max-bytes 67108864
  --mempool-per-source-pending 65536
  --mempool-per-account-pending 65536
  --template-byte-budget 983040
  --template-max-transactions 16384
)
if [[ "${NODE_ROLE}" == "validator" ]]; then
  arguments+=(--validator --produce-interval-ms "${PRODUCE_INTERVAL_MS}" "${throughput_arguments[@]}")
elif [[ "${NODE_ROLE}" == "producer-witness" ]]; then
  arguments+=(--devnet-producer --devnet-witness "${WITNESS_INDEX}" --produce-interval-ms "${PRODUCE_INTERVAL_MS}" "${throughput_arguments[@]}")
else
  arguments+=(--devnet-witness "${WITNESS_INDEX}")
fi
exec /opt/mindchain-wwm/bin/noosd "${arguments[@]}"
