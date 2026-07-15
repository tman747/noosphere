#!/usr/bin/env bash
set -euo pipefail

: "${NODE_ROLE:?NODE_ROLE is required}"
: "${WITNESS_INDEX:?WITNESS_INDEX is required}"
: "${P2P_LISTEN:?P2P_LISTEN is required}"
BOOTSTRAP_PEER="${BOOTSTRAP_PEER:-}"
[[ "${NODE_ROLE}" =~ ^(validator|witness)$ ]] || { echo "invalid node role" >&2; exit 1; }
[[ "${WITNESS_INDEX}" =~ ^[0-3]$ ]] || { echo "invalid witness index" >&2; exit 1; }
[[ "${P2P_LISTEN}" =~ ^/ip4/0\.0\.0\.0/udp/[0-9]{4,5}/quic-v1$ ]] || { echo "invalid P2P listen multiaddr" >&2; exit 1; }
if [[ -n "${BOOTSTRAP_PEER}" && ! "${BOOTSTRAP_PEER}" =~ ^/ip4/([0-9]{1,3}\.){3}[0-9]{1,3}/udp/[0-9]{4,5}/quic-v1$ ]]; then
  echo "invalid bootstrap peer multiaddr" >&2
  exit 1
fi

arguments=(
  --params /opt/mindchain-wwm/protocol/genesis/devnet-parameters.toml
  --devnet-witness-fixture
  --devnet-bonsai-fixture
  --devnet-governance-account 17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce
  --rpc 127.0.0.1:29652
  --rpc-token-file /etc/mindchain-wwm/rpc-token
  --p2p-listen "${P2P_LISTEN}"
  --data-dir /var/lib/mindchain-wwm
)
if [[ "${NODE_ROLE}" == "validator" ]]; then
  arguments+=(--validator --produce-interval-ms 1000)
else
  arguments+=(--devnet-witness "${WITNESS_INDEX}")
fi
if [[ -n "${BOOTSTRAP_PEER}" ]]; then
  arguments+=(--peer "${BOOTSTRAP_PEER}")
fi
exec /opt/mindchain-wwm/bin/noosd "${arguments[@]}"
