#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "installer must run as root" >&2
  exit 1
fi
if [[ "$#" -ne 8 ]]; then
  echo "usage: $0 <role:validator|producer-witness|witness> <witness-index:0..3> <p2p-port> <bootstrap-registry-path> <bootstrap-public-key-path> <binary-path> <binary-sha256> <parameters-path>" >&2
  exit 1
fi

NODE_ROLE="$1"
WITNESS_INDEX="$2"
P2P_PORT="$3"
BOOTSTRAP_REGISTRY_SOURCE="$4"
BOOTSTRAP_PUBLIC_KEY_SOURCE="$5"
BINARY_SOURCE="$6"
EXPECTED_SHA256="$7"
PARAMS_SOURCE="$8"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

[[ "${NODE_ROLE}" =~ ^(validator|producer-witness|witness)$ ]] || { echo "invalid node role" >&2; exit 1; }
[[ "${WITNESS_INDEX}" =~ ^[0-3]$ ]] || { echo "witness index must be 0..3" >&2; exit 1; }
[[ "${P2P_PORT}" =~ ^[0-9]{4,5}$ ]] || { echo "P2P port is invalid" >&2; exit 1; }
(( P2P_PORT >= 1024 && P2P_PORT <= 65535 )) || { echo "P2P port is outside 1024..65535" >&2; exit 1; }
[[ "${EXPECTED_SHA256}" =~ ^[0-9a-f]{64}$ ]] || { echo "binary SHA-256 is invalid" >&2; exit 1; }
[[ -f "${BINARY_SOURCE}" && ! -L "${BINARY_SOURCE}" ]] || { echo "binary source is missing or symbolic" >&2; exit 1; }
[[ -f "${PARAMS_SOURCE}" && ! -L "${PARAMS_SOURCE}" ]] || { echo "genesis parameters source is missing or symbolic" >&2; exit 1; }
[[ -f "${BOOTSTRAP_REGISTRY_SOURCE}" && ! -L "${BOOTSTRAP_REGISTRY_SOURCE}" ]] || { echo "bootstrap registry source is missing or symbolic" >&2; exit 1; }
[[ -f "${BOOTSTRAP_PUBLIC_KEY_SOURCE}" && ! -L "${BOOTSTRAP_PUBLIC_KEY_SOURCE}" ]] || { echo "bootstrap public key source is missing or symbolic" >&2; exit 1; }
BOOTSTRAP_PUBLIC_KEY="$(tr -d '\r\n' < "${BOOTSTRAP_PUBLIC_KEY_SOURCE}")"
[[ "${BOOTSTRAP_PUBLIC_KEY}" =~ ^[0-9a-f]{64}$ ]] || { echo "bootstrap public key is malformed" >&2; exit 1; }

ACTUAL_SHA256="$(sha256sum "${BINARY_SOURCE}" | cut -d' ' -f1)"
[[ "${ACTUAL_SHA256}" == "${EXPECTED_SHA256}" ]] || { echo "binary SHA-256 mismatch" >&2; exit 1; }

if ! getent group mindchain-wwm >/dev/null; then
  groupadd --system mindchain-wwm
fi
if ! getent passwd mindchain-wwm >/dev/null; then
  useradd --system --gid mindchain-wwm --home-dir /var/lib/mindchain-wwm --shell /usr/sbin/nologin mindchain-wwm
fi

install -d -o root -g root -m 0755 /opt/mindchain-wwm/bin
install -d -o root -g root -m 0755 /opt/mindchain-wwm/protocol/genesis
install -d -o root -g mindchain-wwm -m 0750 /etc/mindchain-wwm
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-wwm
install -o root -g root -m 0755 "${BINARY_SOURCE}" /opt/mindchain-wwm/bin/noosd
install -o root -g root -m 0755 "${SCRIPT_DIR}/mindchain-wwm-seed-launcher.sh" /opt/mindchain-wwm/bin/mindchain-wwm-seed-launcher.sh
install -o root -g root -m 0755 "${SCRIPT_DIR}/mindchain-wwm-external-probe.py" /opt/mindchain-wwm/bin/mindchain-wwm-external-probe.py
install -o root -g root -m 0755 "${SCRIPT_DIR}/create-mindchain-seed-snapshot.sh" /opt/mindchain-wwm/bin/create-mindchain-seed-snapshot.sh
install -o root -g root -m 0755 "${SCRIPT_DIR}/restore-mindchain-seed-snapshot.sh" /opt/mindchain-wwm/bin/restore-mindchain-seed-snapshot.sh
install -o root -g root -m 0644 "${PARAMS_SOURCE}" /opt/mindchain-wwm/protocol/genesis/devnet-parameters.toml
install -o root -g root -m 0644 "${SCRIPT_DIR}/mindchain-wwm-seed.service" /etc/systemd/system/mindchain-wwm-seed.service
install -o root -g root -m 0644 "${BOOTSTRAP_REGISTRY_SOURCE}" /etc/mindchain-wwm/bootstrap-registry.json
install -o root -g root -m 0644 "${BOOTSTRAP_PUBLIC_KEY_SOURCE}" /etc/mindchain-wwm/bootstrap-registry.public
install -o root -g root -m 0644 "${SCRIPT_DIR}/mindchain-wwm-external-probe.service" /etc/systemd/system/mindchain-wwm-external-probe.service
install -o root -g root -m 0644 "${SCRIPT_DIR}/mindchain-wwm-external-probe.timer" /etc/systemd/system/mindchain-wwm-external-probe.timer

if [[ ! -f /etc/mindchain-wwm/rpc-token ]]; then
  umask 0077
  dd if=/dev/urandom bs=48 count=1 status=none | base64 | tr -d '\n=' | tr '+/' '-_' > /etc/mindchain-wwm/rpc-token.tmp
  printf '\n' >> /etc/mindchain-wwm/rpc-token.tmp
  mv /etc/mindchain-wwm/rpc-token.tmp /etc/mindchain-wwm/rpc-token
fi
TOKEN_LENGTH="$(tr -d '\r\n' < /etc/mindchain-wwm/rpc-token | wc -c)"
(( TOKEN_LENGTH >= 32 )) || { echo "RPC token file is invalid" >&2; exit 1; }
chown root:mindchain-wwm /etc/mindchain-wwm/rpc-token
chmod 0640 /etc/mindchain-wwm/rpc-token

NODE_ENV_TMP="$(mktemp /etc/mindchain-wwm/node.env.XXXXXX)"
printf 'NODE_ROLE=%s\nWITNESS_INDEX=%s\nP2P_LISTEN=/ip4/0.0.0.0/udp/%s/quic-v1\nBOOTSTRAP_REGISTRY=/etc/mindchain-wwm/bootstrap-registry.json\nBOOTSTRAP_PUBLIC_KEY_FILE=/etc/mindchain-wwm/bootstrap-registry.public\nPRODUCE_INTERVAL_MS=6000\n' \
  "${NODE_ROLE}" "${WITNESS_INDEX}" "${P2P_PORT}" > "${NODE_ENV_TMP}"
chown root:mindchain-wwm "${NODE_ENV_TMP}"
chmod 0640 "${NODE_ENV_TMP}"
mv "${NODE_ENV_TMP}" /etc/mindchain-wwm/node.env

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow "${P2P_PORT}/udp" comment 'MindChain WWM QUIC'
fi

systemd-analyze verify \
  /etc/systemd/system/mindchain-wwm-seed.service \
  /etc/systemd/system/mindchain-wwm-external-probe.service \
  /etc/systemd/system/mindchain-wwm-external-probe.timer
systemctl daemon-reload
systemctl enable mindchain-wwm-seed.service mindchain-wwm-external-probe.timer
systemctl reset-failed mindchain-wwm-seed.service
systemctl restart mindchain-wwm-seed.service
systemctl start mindchain-wwm-external-probe.timer
systemctl is-active --quiet mindchain-wwm-seed.service

printf 'installed role=%s witness=%s p2p_port=%s binary_sha256=%s\n' "${NODE_ROLE}" "${WITNESS_INDEX}" "${P2P_PORT}" "${ACTUAL_SHA256}"
