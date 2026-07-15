from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
TOKEN_PATH = Path("/etc/mindchain-wwm/rpc-token")
CHAIN_ID = "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b"
GENESIS_HASH = "8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e"
PUBLIC_URLS = (
    "https://wwm.mindchain.network/",
    "https://wwm-rpc.mindchain.network/healthz",
    "https://wwm-artifacts.mindchain.network/healthz",
    "https://wwm-status.mindchain.network/status.json",
)


def probe(url: str, token: str | None = None, validator: object | None = None) -> dict[str, object]:
    headers = {"Accept": "application/json", "User-Agent": "mindchain-wwm-azure-probe/1"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise RuntimeError("response_too_large")
            if response.status != 200:
                raise RuntimeError("unexpected_status")
            detail: dict[str, object] = {}
            if validator is not None:
                document = json.loads(body)
                if not isinstance(document, dict):
                    raise RuntimeError("invalid_json_object")
                detail = validator(document)
            return {
                "url": url,
                "ok": True,
                "status": response.status,
                "bytes": len(body),
                "latency_ms": round((time.monotonic() - started) * 1000),
                **detail,
            }
    except Exception as error:
        code = error.code if isinstance(error, urllib.error.HTTPError) else str(error)
        return {"url": url, "ok": False, "error": str(code)[:64], "latency_ms": round((time.monotonic() - started) * 1000)}


def validate_chain(document: dict[str, object]) -> dict[str, object]:
    if document.get("chain_id") != CHAIN_ID or document.get("genesis_hash") != GENESIS_HASH:
        raise RuntimeError("wrong_chain_identity")
    head = document.get("unsafe_head") if isinstance(document.get("unsafe_head"), dict) else {}
    finalized = document.get("finalized") if isinstance(document.get("finalized"), dict) else {}
    return {"chain_id": CHAIN_ID, "genesis_hash": GENESIS_HASH, "unsafe_height": head.get("height"), "finalized_epoch": finalized.get("epoch")}


def validate_public(document: dict[str, object]) -> dict[str, object]:
    if document.get("production") is not False:
        raise RuntimeError("public_endpoint_not_fail_closed")
    return {"production": False}


def main() -> int:
    token = TOKEN_PATH.read_text(encoding="ascii").strip()
    if len(token) < 32 or any(character.isspace() for character in token):
        raise RuntimeError("invalid_rpc_token_file")
    checks = [
        probe(PUBLIC_URLS[0]),
        probe(PUBLIC_URLS[1], validator=validate_public),
        probe(PUBLIC_URLS[2], validator=validate_public),
        probe(PUBLIC_URLS[3], validator=validate_public),
        probe("http://127.0.0.1:29652/status", token, validate_chain),
    ]
    report = {
        "schema": "noos/wwm-external-uptime-probe/v1",
        "environment": "public-testnet",
        "production": False,
        "promotion_effect": "NONE",
        "observed_at": int(time.time()),
        "status": "ok" if all(check["ok"] for check in checks) else "degraded",
        "checks": checks,
    }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
