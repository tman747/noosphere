#!/usr/bin/env python3
"""Fail-closed readiness probe for the complete local MindChain service stack."""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def http_json(url: str, token: str | None = None, timeout: float = 8.0) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError(f"{url} returned non-object JSON")
    return value


def nested_int(value: dict[str, Any], *path: str) -> int:
    current: Any = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ValueError(f"missing {'.'.join(path)}")
        current = current[key]
    if isinstance(current, bool):
        raise ValueError(f"invalid {'.'.join(path)}")
    return int(current)


def inspect_stack(
    operator: dict[str, Any],
    indexer: dict[str, Any],
    mindscan: dict[str, Any],
    compute: dict[str, Any],
    dashboard: dict[str, Any],
    *,
    maximum_head_lag: int,
) -> dict[str, Any]:
    errors: list[str] = []
    identities = {
        (value.get("chain_id"), value.get("genesis_hash"))
        for value in (operator, indexer, mindscan)
    }
    if len(identities) != 1 or any(not chain or not genesis for chain, genesis in identities):
        errors.append("identity_mismatch")
    if indexer.get("ready") is not True or indexer.get("readiness") != "ready":
        errors.append("indexer_not_ready")
    if compute.get("ok") is not True or compute.get("operator_head") is not True:
        errors.append("compute_not_ready")
    if dashboard.get("ok") is not True or dashboard.get("schema") != "noos/network-dashboard-health/v1":
        errors.append("dashboard_not_ready")
    operator_height = nested_int(operator, "unsafe_head", "height")
    indexer_height = nested_int(indexer, "unsafe_head", "height")
    mindscan_height = nested_int(mindscan, "unsafe_head", "height")
    if operator_height < indexer_height or operator_height - indexer_height > maximum_head_lag:
        errors.append("indexer_head_lag")
    if mindscan_height != indexer_height:
        errors.append("mindscan_index_mismatch")
    finalized = nested_int(indexer, "finalized", "height")
    justified = nested_int(indexer, "justified", "height")
    if not 0 <= finalized <= justified <= indexer_height:
        errors.append("invalid_finality_order")
    chain_id, genesis_hash = next(iter(identities)) if len(identities) == 1 else (None, None)
    return {
        "ok": not errors,
        "schema": "noos/network-readiness/v1",
        "errors": errors,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "operator_height": str(operator_height),
        "indexer_height": str(indexer_height),
        "mindscan_height": str(mindscan_height),
        "finalized_height": str(finalized),
        "justified_height": str(justified),
    }


def load_token(path: Path) -> str:
    value = json.loads(path.read_text(encoding="utf-8"))
    token = value.get("rpc_token") if isinstance(value, dict) else None
    if not isinstance(token, str) or not token:
        raise ValueError("operator secret does not contain rpc_token")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator", default="http://127.0.0.1:21632")
    parser.add_argument("--operator-secret", type=Path, required=True)
    parser.add_argument("--indexer", default="http://127.0.0.1:21080")
    parser.add_argument("--mindscan", default="http://127.0.0.1:18130")
    parser.add_argument("--compute", default="http://127.0.0.1:18110")
    parser.add_argument("--dashboard", default="http://127.0.0.1:18120")
    parser.add_argument("--maximum-head-lag", type=int, default=8)
    parser.add_argument("--advance-seconds", type=float, default=2.0)
    args = parser.parse_args()
    token = load_token(args.operator_secret)
    try:
        operator = http_json(args.operator.rstrip("/") + "/status", token)
        indexer = http_json(args.indexer.rstrip("/") + "/api/status")
        mindscan = http_json(args.mindscan.rstrip("/") + "/api/status")
        compute = http_json(args.compute.rstrip("/") + "/api/health")
        dashboard = http_json(args.dashboard.rstrip("/") + "/api/health")
        result = inspect_stack(
            operator,
            indexer,
            mindscan,
            compute,
            dashboard,
            maximum_head_lag=args.maximum_head_lag,
        )
        if args.advance_seconds > 0:
            first_height = nested_int(operator, "unsafe_head", "height")
            time.sleep(args.advance_seconds)
            later = http_json(args.operator.rstrip("/") + "/status", token)
            later_height = nested_int(later, "unsafe_head", "height")
            result["later_operator_height"] = str(later_height)
            if later_height <= first_height:
                result["errors"].append("producer_not_advancing")
                result["ok"] = False
    except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as error:
        result = {
            "ok": False,
            "schema": "noos/network-readiness/v1",
            "errors": ["probe_failed"],
            "detail": str(error),
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
