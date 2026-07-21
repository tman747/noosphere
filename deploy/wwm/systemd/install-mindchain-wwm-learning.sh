#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "installer must run as root" >&2
  exit 1
fi
if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <bundle-root> <manifest-sha256>" >&2
  exit 1
fi

BUNDLE_ROOT="$(cd -- "$1" && pwd -P)"
EXPECTED_MANIFEST_SHA256="$2"
MANIFEST_SOURCE="${BUNDLE_ROOT}/deploy/wwm/continuous-learning-manifest.testnet.json"
[[ "${EXPECTED_MANIFEST_SHA256}" =~ ^[0-9a-f]{64}$ ]] || { echo "manifest SHA-256 is invalid" >&2; exit 1; }
[[ -f "${MANIFEST_SOURCE}" && ! -L "${MANIFEST_SOURCE}" ]] || { echo "deployment manifest is missing or symbolic" >&2; exit 1; }
ACTUAL_MANIFEST_SHA256="$(sha256sum "${MANIFEST_SOURCE}" | cut -d' ' -f1)"
[[ "${ACTUAL_MANIFEST_SHA256}" == "${EXPECTED_MANIFEST_SHA256}" ]] || { echo "deployment manifest SHA-256 mismatch" >&2; exit 1; }

python3 -B - "${BUNDLE_ROOT}" "${MANIFEST_SOURCE}" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest = json.loads(Path(sys.argv[2]).read_bytes())
expected = {
    "tools/operations/wwm_continuous_learning.py",
    "tools/operations/wwm_model_improvement.py",
    "protocol/schemas/wwm-v2.md",
    "deploy/wwm/continuous-learning.testnet.json",
    "deploy/wwm/model-improvement.json",
    "deploy/wwm/licenses/Bonsai-27B/LICENSE.txt",
    "deploy/wwm/licenses/Bonsai-27B/NOTICE.txt",
    "deploy/wwm/systemd/mindchain-wwm-learning.service",
    "deploy/wwm/systemd/mindchain-wwm-seed2-rpc-tunnel.service",
    "deploy/wwm/systemd/install-mindchain-wwm-learning.sh",
}
if manifest.get("schema") != "noos/wwm-continuous-learning-deployment-manifest/v1":
    raise SystemExit("unsupported deployment manifest schema")
if manifest.get("environment") != "testnet" or manifest.get("production") is not False:
    raise SystemExit("deployment manifest must remain explicitly non-production")
if manifest.get("execution_enabled") is not False or manifest.get("promotion_effect") != "NONE":
    raise SystemExit("deployment manifest must remain monitoring-only and non-promoting")
files = manifest.get("files")
if not isinstance(files, dict) or set(files) != expected:
    raise SystemExit("deployment manifest does not contain the exact file set")
for relative, expected_sha in files.items():
    if not isinstance(expected_sha, str) or re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None:
        raise SystemExit(f"invalid SHA-256 for {relative}")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise SystemExit(f"manifest path escapes bundle root: {relative}") from error
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"manifest file is missing or symbolic: {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected_sha:
        raise SystemExit(f"manifest file SHA-256 mismatch: {relative}")
PY

python3 -B -c 'import cryptography' >/dev/null 2>&1 || {
  echo "Python cryptography package is required" >&2
  exit 1
}
[[ -f /etc/mindchain-wwm/rpc-token && ! -L /etc/mindchain-wwm/rpc-token ]] || {
  echo "the local node RPC token must exist before installing continual learning" >&2
  exit 1
}
for required_secret in seed-2-rpc-token seed-2-tunnel-key seed-2-known-hosts; do
  [[ -f "/etc/mindchain-wwm/${required_secret}" && ! -L "/etc/mindchain-wwm/${required_secret}" ]] || {
    echo "pre-provisioned ${required_secret} is required" >&2
    exit 1
  }
done

if ! getent group mindchain-wwm >/dev/null; then
  groupadd --system mindchain-wwm
fi
if ! getent passwd mindchain-wwm >/dev/null; then
  useradd --system --gid mindchain-wwm --home-dir /var/lib/mindchain-wwm --shell /usr/sbin/nologin mindchain-wwm
fi

install -d -o root -g root -m 0755 /opt/mindchain-wwm/tools/operations
install -d -o root -g root -m 0755 /opt/mindchain-wwm/protocol/schemas
install -d -o root -g root -m 0755 /opt/mindchain-wwm/deploy/wwm/licenses/Bonsai-27B
install -d -o root -g mindchain-wwm -m 0750 /etc/mindchain-wwm
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-wwm/continuous-learning
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-wwm/continuous-learning/requests
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-wwm/continuous-learning/evidence
install -d -o mindchain-wwm -g mindchain-wwm -m 0700 /var/lib/mindchain-wwm/continuous-learning/state

install -o root -g root -m 0755 "${BUNDLE_ROOT}/tools/operations/wwm_continuous_learning.py" /opt/mindchain-wwm/tools/operations/wwm_continuous_learning.py
install -o root -g root -m 0644 "${BUNDLE_ROOT}/tools/operations/wwm_model_improvement.py" /opt/mindchain-wwm/tools/operations/wwm_model_improvement.py
install -o root -g root -m 0644 "${BUNDLE_ROOT}/deploy/wwm/model-improvement.json" /opt/mindchain-wwm/deploy/wwm/model-improvement.json
install -o root -g root -m 0644 "${BUNDLE_ROOT}/deploy/wwm/licenses/Bonsai-27B/LICENSE.txt" /opt/mindchain-wwm/deploy/wwm/licenses/Bonsai-27B/LICENSE.txt
install -o root -g root -m 0644 "${BUNDLE_ROOT}/deploy/wwm/licenses/Bonsai-27B/NOTICE.txt" /opt/mindchain-wwm/deploy/wwm/licenses/Bonsai-27B/NOTICE.txt
install -o root -g root -m 0644 "${BUNDLE_ROOT}/protocol/schemas/wwm-v2.md" /opt/mindchain-wwm/protocol/schemas/wwm-v2.md
install -o root -g root -m 0644 "${MANIFEST_SOURCE}" /opt/mindchain-wwm/deploy/wwm/continuous-learning-manifest.testnet.json
install -o root -g mindchain-wwm -m 0640 "${BUNDLE_ROOT}/deploy/wwm/continuous-learning.testnet.json" /etc/mindchain-wwm/continuous-learning.json
install -o root -g root -m 0644 "${BUNDLE_ROOT}/deploy/wwm/systemd/mindchain-wwm-learning.service" /etc/systemd/system/mindchain-wwm-learning.service
install -o root -g root -m 0644 "${BUNDLE_ROOT}/deploy/wwm/systemd/mindchain-wwm-seed2-rpc-tunnel.service" /etc/systemd/system/mindchain-wwm-seed2-rpc-tunnel.service
install -o root -g root -m 0755 "${BUNDLE_ROOT}/deploy/wwm/systemd/install-mindchain-wwm-learning.sh" /opt/mindchain-wwm/deploy/wwm/install-mindchain-wwm-learning.sh

PYTHONDONTWRITEBYTECODE=1 python3 -B - /opt/mindchain-wwm/tools/operations /etc/mindchain-wwm/continuous-learning.json <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import wwm_continuous_learning as learning

config = learning.load_config(Path(sys.argv[2]))
if config.production or config.execution_enabled or not config.monitoring_enabled:
    raise SystemExit("installed continuous-learning config is not monitoring-only")
PY

systemd-analyze verify \
  /etc/systemd/system/mindchain-wwm-seed2-rpc-tunnel.service \
  /etc/systemd/system/mindchain-wwm-learning.service
systemctl daemon-reload
systemctl enable mindchain-wwm-seed2-rpc-tunnel.service mindchain-wwm-learning.service
systemctl reset-failed mindchain-wwm-seed2-rpc-tunnel.service mindchain-wwm-learning.service
systemctl restart mindchain-wwm-seed2-rpc-tunnel.service
systemctl is-active --quiet mindchain-wwm-seed2-rpc-tunnel.service
systemctl restart mindchain-wwm-learning.service
HEALTHY=0
for _attempt in {1..45}; do
  if python3 -B - <<'PY'
import json
import urllib.error
import urllib.request

try:
    with urllib.request.urlopen("http://127.0.0.1:29790/healthz", timeout=2) as response:
        payload = json.loads(response.read())
except (OSError, ValueError, urllib.error.URLError):
    raise SystemExit(1)
if response.status != 200 or payload != {"healthy": True}:
    raise SystemExit(1)
PY
  then
    HEALTHY=1
    break
  fi
  sleep 2
done
[[ "${HEALTHY}" -eq 1 ]] || {
  systemctl --no-pager --full status mindchain-wwm-learning.service >&2 || true
  echo "continual-learning service did not become healthy" >&2
  exit 1
}
systemctl is-active --quiet mindchain-wwm-learning.service

printf 'installed manifest_sha256=%s mode=monitoring-only promotion_effect=NONE\n' "${ACTUAL_MANIFEST_SHA256}"
