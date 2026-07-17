#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "installer must run as root" >&2; exit 1; }
[[ "$#" -eq 3 ]] || { echo "usage: $0 <witness-index> <p2p-port> <comma-separated-bootstrap-peers>" >&2; exit 1; }
WITNESS_INDEX="$1"
P2P_PORT="$2"
BOOTSTRAP_PEERS="$3"
[[ "${WITNESS_INDEX}" =~ ^[0-3]$ ]] || { echo "invalid witness index" >&2; exit 1; }
[[ "${P2P_PORT}" =~ ^[0-9]{4,5}$ ]] || { echo "invalid p2p port" >&2; exit 1; }
IFS=',' read -r -a bootstrap_peers <<< "${BOOTSTRAP_PEERS}"
(( ${#bootstrap_peers[@]} <= 8 )) || { echo "too many bootstrap peers" >&2; exit 1; }
for peer in "${bootstrap_peers[@]}"; do
  [[ "${peer}" =~ ^/ip4/([0-9]{1,3}\.){3}[0-9]{1,3}/udp/[0-9]{4,5}/quic-v1$ ]] || {
    echo "invalid bootstrap peer"
    exit 1
  }
done
DATA_DIR="/var/lib/mindchain-wwm-witness-${WITNESS_INDEX}"
TOKEN_FILE="/etc/mindchain-wwm/rpc-token-witness-${WITNESS_INDEX}"
ENV_FILE="/etc/mindchain-wwm/witness-${WITNESS_INDEX}.env"
RPC_PORT="$((29650 + WITNESS_INDEX))"

install -d -o mindchain-wwm -g mindchain-wwm -m 0700 "${DATA_DIR}"
install -o root -g root -m 0755 /tmp/mindchain-wwm-seed-launcher.sh /opt/mindchain-wwm/bin/mindchain-wwm-seed-launcher.sh
install -o root -g root -m 0644 /tmp/mindchain-wwm-witness@.service /etc/systemd/system/mindchain-wwm-witness@.service
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
BOOTSTRAP_PEERS=${BOOTSTRAP_PEERS}
RPC_LISTEN=127.0.0.1:${RPC_PORT}
RPC_TOKEN_FILE=${TOKEN_FILE}
DATA_DIR=${DATA_DIR}
ENV
chown root:mindchain-wwm "${ENV_FILE}"
chmod 0640 "${ENV_FILE}"

systemd-analyze verify /etc/systemd/system/mindchain-wwm-witness@.service
systemctl daemon-reload
systemctl enable "mindchain-wwm-witness@${WITNESS_INDEX}.service"
systemctl reset-failed "mindchain-wwm-witness@${WITNESS_INDEX}.service"
systemctl restart "mindchain-wwm-witness@${WITNESS_INDEX}.service"
systemctl is-active --quiet "mindchain-wwm-witness@${WITNESS_INDEX}.service"
