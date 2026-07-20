#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 && "$#" -ne 5 ]]; then
  echo "usage: $0 <public-api-hostname> <noos-indexer-sha256> [<node-rpc> <rpc-token-file> <node-service>]" >&2
  exit 1
fi
[[ "$(id -u)" -eq 0 ]] || { echo "installer must run as root" >&2; exit 1; }

PUBLIC_HOST="$1"
EXPECTED_SHA="$2"
if [[ ! "${PUBLIC_HOST}" =~ ^[a-z0-9.-]+\.mindchain\.network$ &&
      "${PUBLIC_HOST}" != "mindchain-seed-3.eastus.cloudapp.azure.com" ]]; then
  echo "public hostname is not an approved MindChain edge" >&2
  exit 1
fi
[[ "${EXPECTED_SHA}" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid binary sha256" >&2; exit 1; }
NODE_RPC="${3:-127.0.0.1:29652}"
RPC_TOKEN_FILE="${4:-/etc/mindchain-wwm/rpc-token}"
NODE_SERVICE="${5:-mindchain-wwm-seed.service}"
if [[ ! "${NODE_RPC}" =~ ^127\.0\.0\.1:([0-9]{2,5})$ ]]; then
  echo "indexer node RPC must be a loopback TCP endpoint" >&2
  exit 1
fi
RPC_PORT="${BASH_REMATCH[1]}"
(( RPC_PORT >= 1 && RPC_PORT <= 65535 )) || { echo "indexer node RPC port is invalid" >&2; exit 1; }
if [[ ! "${RPC_TOKEN_FILE}" =~ ^/etc/mindchain-wwm/rpc-token(-witness-[0-9]+)?$ ||
      ! -f "${RPC_TOKEN_FILE}" ]]; then
  echo "indexer RPC token file is not an installed MindChain credential" >&2
  exit 1
fi
if [[ "${NODE_SERVICE}" != "mindchain-wwm-seed.service" &&
      ! "${NODE_SERVICE}" =~ ^mindchain-wwm-witness@[0-9]+\.service$ ]]; then
  echo "indexer node service is not an installed MindChain validator unit" >&2
  exit 1
fi

BINARY_SOURCE=/tmp/noos-indexer.new
[[ -f "${BINARY_SOURCE}" ]] || { echo "missing ${BINARY_SOURCE}" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "${BINARY_SOURCE}" | cut -d' ' -f1)"
[[ "${ACTUAL_SHA}" == "${EXPECTED_SHA}" ]] || { echo "indexer sha256 mismatch" >&2; exit 1; }
for file in \
  /tmp/mindchain-public-indexer-launcher.sh \
  /tmp/mindchain-public-indexer.service \
  /tmp/mindchain-public-indexer.Caddyfile \
  /tmp/caddy-mindchain-public-api.conf; do
  [[ -f "${file}" ]] || { echo "missing deployment file: ${file}" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq caddy

install -d -o root -g mindchain-wwm -m 0750 /etc/mindchain-wwm
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-wwm-indexer
install -o root -g root -m 0755 "${BINARY_SOURCE}" /opt/mindchain-wwm/bin/noos-indexer
install -o root -g root -m 0755 /tmp/mindchain-public-indexer-launcher.sh /opt/mindchain-wwm/bin/mindchain-public-indexer-launcher.sh
install -o root -g root -m 0644 /tmp/mindchain-public-indexer.service /etc/systemd/system/mindchain-public-indexer.service
install -d -o root -g root -m 0755 /etc/systemd/system/mindchain-public-indexer.service.d
cat > /etc/systemd/system/mindchain-public-indexer.service.d/10-node-source.conf <<CONF
[Unit]
Wants=${NODE_SERVICE}
After=${NODE_SERVICE}

[Service]
LoadCredential=
LoadCredential=rpc-token:${RPC_TOKEN_FILE}
CONF
chmod 0644 /etc/systemd/system/mindchain-public-indexer.service.d/10-node-source.conf
install -d -o root -g root -m 0755 /etc/systemd/system/caddy.service.d
install -o root -g root -m 0644 /tmp/caddy-mindchain-public-api.conf /etc/systemd/system/caddy.service.d/mindchain-public-api.conf
install -o root -g caddy -m 0640 /tmp/mindchain-public-indexer.Caddyfile /etc/caddy/Caddyfile

cat > /etc/mindchain-wwm/indexer.env <<ENV
NOOS_CHAIN_ID=0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b
NOOS_GENESIS_HASH=8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e
NOOS_NODE_RPC=${NODE_RPC}
NOOS_INDEXER_LISTEN=127.0.0.1:29670
NOOS_INDEXER_ROOT=/var/lib/mindchain-wwm-indexer
NOOS_INDEXER_SYNC_BATCH_SIZE=256
NOOS_INDEXER_SYNC_INTERVAL_MS=100
ENV
chown root:mindchain-wwm /etc/mindchain-wwm/indexer.env
chmod 0640 /etc/mindchain-wwm/indexer.env
printf 'MINDCHAIN_PUBLIC_API_HOST=%s\n' "${PUBLIC_HOST}" > /etc/mindchain-wwm/public-api.env
chown root:caddy /etc/mindchain-wwm/public-api.env
chmod 0640 /etc/mindchain-wwm/public-api.env

MINDCHAIN_PUBLIC_API_HOST="${PUBLIC_HOST}" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl daemon-reload
systemctl enable mindchain-public-indexer.service caddy.service
systemctl reset-failed mindchain-public-indexer.service caddy.service
systemctl restart mindchain-public-indexer.service
systemctl restart caddy.service
systemctl is-active --quiet mindchain-public-indexer.service
systemctl is-active --quiet caddy.service
