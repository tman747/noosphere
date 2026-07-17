#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 <service> <data-dir> <with-indexer:yes|no> <snapshot-sha256>" >&2
  exit 1
fi
[[ "$(id -u)" -eq 0 ]] || { echo "restore must run as root" >&2; exit 1; }
SERVICE="$1"
DATA_DIR="$2"
WITH_INDEXER="$3"
EXPECTED_SHA="$4"
SNAPSHOT=/tmp/mindchain-seed-state.tgz
[[ "${SERVICE}" =~ ^mindchain-wwm-(seed|witness@[0-3])\.service$ ]] || { echo "invalid service" >&2; exit 1; }
[[ "${DATA_DIR}" =~ ^/var/lib/mindchain-wwm(-witness-[0-3])?$ ]] || { echo "invalid data directory" >&2; exit 1; }
[[ "${WITH_INDEXER}" =~ ^(yes|no)$ ]] || { echo "invalid indexer flag" >&2; exit 1; }
[[ "${EXPECTED_SHA}" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid snapshot sha256" >&2; exit 1; }
[[ -f "${SNAPSHOT}" ]] || { echo "snapshot is missing" >&2; exit 1; }
ACTUAL_SHA="$(sha256sum "${SNAPSHOT}" | cut -d' ' -f1)"
[[ "${ACTUAL_SHA}" == "${EXPECTED_SHA}" ]] || { echo "snapshot sha256 mismatch" >&2; exit 1; }

tar -tzf "${SNAPSHOT}" >/dev/null
if [[ "${WITH_INDEXER}" == yes ]]; then
  systemctl stop mindchain-public-indexer.service
fi
systemctl stop "${SERVICE}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="${DATA_DIR}.pre-sync-${STAMP}"
[[ ! -e "${BACKUP}" ]] || { echo "backup destination already exists" >&2; exit 1; }
mv "${DATA_DIR}" "${BACKUP}"
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 "${DATA_DIR}"
tar -xzf "${SNAPSHOT}" -C "${DATA_DIR}"
if [[ -f "${BACKUP}/p2p-key" ]]; then
  install -o mindchain-wwm -g mindchain-wwm -m 0600 "${BACKUP}/p2p-key" "${DATA_DIR}/p2p-key"
fi
chown -R mindchain-wwm:mindchain-wwm "${DATA_DIR}"
chmod 0700 "${DATA_DIR}"

if [[ "${WITH_INDEXER}" == yes ]]; then
  INDEXER=/var/lib/mindchain-wwm-indexer
  mv "${INDEXER}" "${INDEXER}.pre-sync-${STAMP}"
  install -d -o mindchain-wwm -g mindchain-wwm -m 0700 "${INDEXER}"
fi
systemctl start "${SERVICE}"
systemctl is-active --quiet "${SERVICE}"
if [[ "${WITH_INDEXER}" == yes ]]; then
  systemctl start mindchain-public-indexer.service
  systemctl is-active --quiet mindchain-public-indexer.service
fi
