#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <public-api-hostname> <validator-set: 0|1|2,3>" >&2
  exit 1
fi
[[ "$(id -u)" -eq 0 ]] || { echo "installer must run as root" >&2; exit 1; }

PUBLIC_HOST="$1"
VALIDATOR_SET="$2"
case "${PUBLIC_HOST}:${VALIDATOR_SET}" in
  wwm-seed.mindchain.network:0|wwm-seed-2.mindchain.network:1|mindchain-seed-3.eastus.cloudapp.azure.com:2,3) ;;
  *) echo "public hostname and validator set do not match the approved testnet topology" >&2; exit 1 ;;
esac

for file in \
  /tmp/network_dashboard.py \
  /tmp/index.html \
  /tmp/app.js \
  /tmp/styles.css \
  /tmp/favicon.svg \
  /tmp/public-testnet.json \
  /tmp/mindchain-network-dashboard.service \
  /tmp/mindchain-public-indexer.Caddyfile; do
  [[ -f "${file}" ]] || { echo "missing deployment file: ${file}" >&2; exit 1; }
done
[[ -f /etc/mindchain-wwm/rpc-token ]] || { echo "primary RPC token is missing" >&2; exit 1; }
if [[ "${VALIDATOR_SET}" == "2,3" ]]; then
  [[ -f /etc/mindchain-wwm/rpc-token-witness-3 ]] || { echo "witness 3 RPC token is missing" >&2; exit 1; }
fi

install -d -o root -g root -m 0755 /opt/mindchain-wwm/dashboard/app
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-network-dashboard
install -o root -g root -m 0755 /tmp/network_dashboard.py /opt/mindchain-wwm/dashboard/network_dashboard.py
install -o root -g root -m 0644 /tmp/index.html /opt/mindchain-wwm/dashboard/app/index.html
install -o root -g root -m 0644 /tmp/app.js /opt/mindchain-wwm/dashboard/app/app.js
install -o root -g root -m 0644 /tmp/styles.css /opt/mindchain-wwm/dashboard/app/styles.css
install -o root -g root -m 0644 /tmp/favicon.svg /opt/mindchain-wwm/dashboard/app/favicon.svg
install -o root -g root -m 0644 /tmp/public-testnet.json /opt/mindchain-wwm/dashboard/public-testnet.json
install -o root -g root -m 0644 /tmp/mindchain-network-dashboard.service /etc/systemd/system/mindchain-network-dashboard.service
install -o root -g caddy -m 0640 /tmp/mindchain-public-indexer.Caddyfile /etc/caddy/Caddyfile

case "${VALIDATOR_SET}" in
  0)
    VALIDATORS='[{"witness_index":0,"rpc":"http://127.0.0.1:29652","token_file":"/etc/mindchain-wwm/rpc-token"}]'
    ;;
  1)
    VALIDATORS='[{"witness_index":1,"rpc":"http://127.0.0.1:29652","token_file":"/etc/mindchain-wwm/rpc-token"}]'
    ;;
  2,3)
    VALIDATORS='[{"witness_index":2,"rpc":"http://127.0.0.1:29652","token_file":"/etc/mindchain-wwm/rpc-token"},{"witness_index":3,"rpc":"http://127.0.0.1:29653","token_file":"/etc/mindchain-wwm/rpc-token-witness-3"}]'
    ;;
esac
printf '{"schema":"noos/network-dashboard-validator-config/v1","public_base_url":"https://%s","validators":%s}\n' \
  "${PUBLIC_HOST}" "${VALIDATORS}" > /etc/mindchain-wwm/network-dashboard-validators.json
chown root:mindchain-wwm /etc/mindchain-wwm/network-dashboard-validators.json
chmod 0640 /etc/mindchain-wwm/network-dashboard-validators.json

python3 -m py_compile /opt/mindchain-wwm/dashboard/network_dashboard.py
MINDCHAIN_PUBLIC_API_HOST="${PUBLIC_HOST}" caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl daemon-reload
systemctl enable mindchain-network-dashboard.service caddy.service
systemctl reset-failed mindchain-network-dashboard.service caddy.service
systemctl restart mindchain-network-dashboard.service
systemctl restart caddy.service
systemctl is-active --quiet mindchain-network-dashboard.service
systemctl is-active --quiet caddy.service
READY=0
for _ in $(seq 1 15); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:29911/api/health >/dev/null; then
    READY=1
    break
  fi
  sleep 1
done
[[ "${READY}" -eq 1 ]] || { echo "dashboard failed readiness" >&2; exit 1; }
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:29911/validator-status.json >/dev/null
