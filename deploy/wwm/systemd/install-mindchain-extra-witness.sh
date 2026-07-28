#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "installer must run as root" >&2; exit 1; }
[[ "$#" -ge 4 && "$#" -le 5 ]] || { echo "usage: $0 <witness-index> <p2p-port> <bootstrap-registry-path> <bootstrap-public-key-path> [public-testnet-refund-activation-height]" >&2; exit 1; }
WITNESS_INDEX="$1"
P2P_PORT="$2"
BOOTSTRAP_REGISTRY_SOURCE="$3"
BOOTSTRAP_PUBLIC_KEY_SOURCE="$4"
PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT="${5:-0}"
[[ "${WITNESS_INDEX}" =~ ^[0-3]$ ]] || { echo "invalid witness index" >&2; exit 1; }
[[ "${P2P_PORT}" =~ ^[0-9]{4,5}$ ]] || { echo "invalid p2p port" >&2; exit 1; }
[[ "${PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT}" =~ ^(0|[1-9][0-9]*)$ ]] || { echo "public-testnet refund activation height is invalid" >&2; exit 1; }
[[ -f "${BOOTSTRAP_REGISTRY_SOURCE}" && ! -L "${BOOTSTRAP_REGISTRY_SOURCE}" ]] || { echo "bootstrap registry source is missing or symbolic" >&2; exit 1; }
[[ -f "${BOOTSTRAP_PUBLIC_KEY_SOURCE}" && ! -L "${BOOTSTRAP_PUBLIC_KEY_SOURCE}" ]] || { echo "bootstrap public key source is missing or symbolic" >&2; exit 1; }
BOOTSTRAP_PUBLIC_KEY="$(tr -d '\r\n' < "${BOOTSTRAP_PUBLIC_KEY_SOURCE}")"
[[ "${BOOTSTRAP_PUBLIC_KEY}" =~ ^[0-9a-f]{64}$ ]] || { echo "bootstrap public key is malformed" >&2; exit 1; }
DATA_DIR="/var/lib/mindchain-wwm-witness-${WITNESS_INDEX}"
TOKEN_FILE="/etc/mindchain-wwm/rpc-token-witness-${WITNESS_INDEX}"
ENV_FILE="/etc/mindchain-wwm/witness-${WITNESS_INDEX}.env"
RPC_PORT="$((29650 + WITNESS_INDEX))"

install -d -o mindchain-wwm -g mindchain-wwm -m 0700 "${DATA_DIR}"
install -o root -g root -m 0755 /tmp/mindchain-wwm-seed-launcher.sh /opt/mindchain-wwm/bin/mindchain-wwm-seed-launcher.sh
install -o root -g root -m 0644 /tmp/mindchain-wwm-witness@.service /etc/systemd/system/mindchain-wwm-witness@.service
install -o root -g root -m 0644 "${BOOTSTRAP_REGISTRY_SOURCE}" /etc/mindchain-wwm/bootstrap-registry.json
install -o root -g root -m 0644 "${BOOTSTRAP_PUBLIC_KEY_SOURCE}" /etc/mindchain-wwm/bootstrap-registry.public
if [[ ! -f "${TOKEN_FILE}" ]]; then
  umask 0077
  dd if=/dev/urandom bs=48 count=1 status=none | base64 | tr -d '\n=' | tr '+/' '-_' > "${TOKEN_FILE}.tmp"
  printf '\n' >> "${TOKEN_FILE}.tmp"
  mv "${TOKEN_FILE}.tmp" "${TOKEN_FILE}"
fi
chown root:mindchain-wwm "${TOKEN_FILE}"
chmod 0640 "${TOKEN_FILE}"
cat > "${ENV_FILE}" <<ENV
NODE_ROLE=witness
WITNESS_INDEX=${WITNESS_INDEX}
P2P_LISTEN=/ip4/0.0.0.0/udp/${P2P_PORT}/quic-v1
BOOTSTRAP_REGISTRY=/etc/mindchain-wwm/bootstrap-registry.json
BOOTSTRAP_PUBLIC_KEY_FILE=/etc/mindchain-wwm/bootstrap-registry.public
RPC_LISTEN=127.0.0.1:${RPC_PORT}
RPC_TOKEN_FILE=${TOKEN_FILE}
DATA_DIR=${DATA_DIR}
PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT=${PUBLIC_TESTNET_REFUND_ACTIVATION_HEIGHT}
ENV
chown root:mindchain-wwm "${ENV_FILE}"
chmod 0640 "${ENV_FILE}"

systemd-analyze verify /etc/systemd/system/mindchain-wwm-witness@.service
systemctl daemon-reload
systemctl enable "mindchain-wwm-witness@${WITNESS_INDEX}.service"
systemctl reset-failed "mindchain-wwm-witness@${WITNESS_INDEX}.service"
systemctl restart "mindchain-wwm-witness@${WITNESS_INDEX}.service"
systemctl is-active --quiet "mindchain-wwm-witness@${WITNESS_INDEX}.service"
