#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "snapshot must run as root" >&2; exit 1; }
SOURCE=/var/lib/mindchain-wwm
OUTPUT=/tmp/mindchain-seed-state.tgz
[[ -d "${SOURCE}/live" && -d "${SOURCE}/wal" ]] || { echo "live validator state is missing" >&2; exit 1; }

restart_services() {
  systemctl start mindchain-wwm-seed.service
  systemctl start mindchain-public-indexer.service
}
trap restart_services EXIT

systemctl stop mindchain-public-indexer.service
systemctl stop mindchain-wwm-seed.service
rm -f "${OUTPUT}.tmp"
tar \
  --exclude='./p2p-key' \
  --exclude='./engine-logs' \
  --exclude='./continuous-learning' \
  -C "${SOURCE}" \
  -czf "${OUTPUT}.tmp" .
mv "${OUTPUT}.tmp" "${OUTPUT}"
chmod 0600 "${OUTPUT}"
sha256sum "${OUTPUT}"
