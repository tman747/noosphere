from __future__ import annotations

import argparse
import base64
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
USER_AGENT = "mindchain-wwm-public-alert-probe/1"


class ProbeError(RuntimeError):
    pass


def load_deployment(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if resolved.stat().st_size > MAX_BYTES:
        raise ProbeError("deployment manifest exceeds byte bound")
    try:
        document = json.loads(resolved.read_bytes())
    except (OSError, ValueError) as error:
        raise ProbeError("deployment manifest is invalid") from error
    if not isinstance(document, dict):
        raise ProbeError("deployment manifest must be an object")
    if (
        document.get("schema") != "noos/wwm-public-testnet/v1"
        or document.get("environment") != "public-testnet"
        or document.get("production") is not False
        or document.get("production_capable") is not False
        or document.get("promotion_effect") != "NONE"
    ):
        raise ProbeError("deployment manifest is not fail-closed public testnet")
    return document


def request_bytes(url: str, accept: str) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": accept,
            "Cache-Control": "no-cache",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        response = urllib.request.urlopen(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise ProbeError("public response exceeds byte bound")
        return int(response.status), body


def request_json(url: str) -> tuple[int, dict[str, object]]:
    status, raw = request_bytes(url, "application/json")
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise ProbeError("public endpoint returned malformed JSON") from error
    if not isinstance(document, dict):
        raise ProbeError("public endpoint JSON must be an object")
    return status, document


def require_public_testnet(document: dict[str, object], *, production_authorized: bool = False) -> None:
    if document.get("production") is not False or document.get("promotion_effect") != "NONE":
        raise ProbeError("public endpoint is not fail-closed")
    if production_authorized and document.get("production_authorized") is not False:
        raise ProbeError("public endpoint claims production authorization")


def validate_gateway(
    status: int,
    document: dict[str, object],
    chain_id: str,
    genesis_hash: str,
) -> dict[str, object]:
    require_public_testnet(document)
    head = document.get("unsafe_head") if isinstance(document.get("unsafe_head"), dict) else {}
    finalized = document.get("finalized") if isinstance(document.get("finalized"), dict) else {}
    if (
        status != 200
        or document.get("status") != "ok"
        or document.get("chain_id") != chain_id
        or document.get("genesis_hash") != genesis_hash
        or not isinstance(head.get("height"), int)
        or not isinstance(finalized.get("epoch"), int)
    ):
        raise ProbeError("gateway health or chain identity is invalid")
    return {"unsafe_height": head["height"], "finalized_epoch": finalized["epoch"]}


def validate_artifacts(status: int, document: dict[str, object]) -> dict[str, object]:
    require_public_testnet(document)
    count = document.get("share_count")
    if status != 200 or document.get("production_custody") is not False or not isinstance(count, int) or count < 9:
        raise ProbeError("artifact host is unavailable or production-promoting")
    return {"share_count": count, "share_bytes": document.get("share_bytes")}


def validate_monitor(status: int, document: dict[str, object], signer_key_id: str) -> dict[str, object]:
    require_public_testnet(document, production_authorized=True)
    checks = document.get("checks") if isinstance(document.get("checks"), list) else []
    try:
        public_key = base64.b64decode(str(document["public_key_base64"]), validate=True)
        signature = base64.b64decode(str(document["signature_base64"]), validate=True)
    except (KeyError, ValueError) as error:
        raise ProbeError("monitor signature envelope encoding is invalid") from error
    if (
        status != 200
        or document.get("status") != "ok"
        or document.get("signer_key_id") != signer_key_id
        or not HEX32.fullmatch(str(document.get("sample_id", "")))
        or not HEX40.fullmatch(str(document.get("source_revision", "")))
        or len(public_key) != 32
        or len(signature) != 64
        or not checks
        or any(not isinstance(check, dict) or check.get("ok") is not True for check in checks)
    ):
        raise ProbeError("signed monitor sample is unavailable or degraded")
    return {
        "observed_at_utc": document.get("observed_at_utc"),
        "source_revision": document["source_revision"],
        "sample_id": document["sample_id"],
    }


def run_check(name: str, function: Callable[[], dict[str, object]]) -> dict[str, object]:
    started = time.monotonic()
    try:
        detail = function()
        return {"name": name, "ok": True, "latency_ms": round((time.monotonic() - started) * 1000), "detail": detail}
    except Exception as error:
        message = str(error) if isinstance(error, ProbeError) else type(error).__name__
        return {
            "name": name,
            "ok": False,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "detail": {"error": message[:160]},
        }


def collect(deployment: dict[str, object]) -> dict[str, object]:
    chain = deployment.get("chain_binding")
    endpoints = deployment.get("public_endpoints")
    seeds = deployment.get("public_seeds")
    monitoring = deployment.get("monitoring")
    if not isinstance(chain, dict) or not isinstance(endpoints, dict) or not isinstance(seeds, list) or not isinstance(monitoring, dict):
        raise ProbeError("deployment lacks chain, endpoint, seed, or monitoring bindings")
    chain_id = str(chain.get("chain_id", ""))
    genesis_hash = str(chain.get("genesis_hash", ""))
    signer_key_id = str(monitoring.get("signer_key_id", ""))
    if not HEX32.fullmatch(chain_id) or not HEX32.fullmatch(genesis_hash) or not HEX32.fullmatch(signer_key_id):
        raise ProbeError("deployment has invalid cryptographic bindings")

    def exact_origin(key: str) -> str:
        value = endpoints.get(key)
        parsed = urlsplit(value) if isinstance(value, str) else None
        if parsed is None or parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
            raise ProbeError(f"{key} endpoint is not an exact HTTPS origin")
        return value.rstrip("/")

    site = exact_origin("site")
    rpc = exact_origin("read_gateway")
    artifacts = exact_origin("artifacts")
    status_origin = exact_origin("status")

    checks: list[dict[str, object]] = []

    def site_probe() -> dict[str, object]:
        status, body = request_bytes(site + "/", "text/html")
        if status != 200 or b"MindChain" not in body:
            raise ProbeError("public site is unavailable or invalid")
        return {"status": status, "bytes": len(body)}

    checks.append(run_check("site", site_probe))
    checks.append(run_check("gateway", lambda: validate_gateway(*request_json(rpc + "/healthz"), chain_id, genesis_hash)))
    checks.append(run_check("artifacts", lambda: validate_artifacts(*request_json(artifacts + "/healthz"))))
    checks.append(run_check("monitor", lambda: validate_monitor(*request_json(status_origin + "/healthz"), signer_key_id)))

    for index, seed in enumerate(seeds, start=1):
        if not isinstance(seed, dict):
            raise ProbeError("seed record must be an object")
        hostname = str(seed.get("hostname", ""))
        expected_ip = str(seed.get("ipv4", ""))

        def dns_probe(hostname: str = hostname, expected_ip: str = expected_ip) -> dict[str, object]:
            addresses = sorted({row[4][0] for row in socket.getaddrinfo(hostname, None, socket.AF_INET)})
            if addresses != [expected_ip]:
                raise ProbeError("seed DNS answer differs from the pinned IPv4 address")
            return {"hostname": hostname, "addresses": addresses}

        def rpc_closed(expected_ip: str = expected_ip) -> dict[str, object]:
            try:
                with socket.create_connection((expected_ip, 29652), timeout=3):
                    raise ProbeError("seed operator RPC is publicly reachable")
            except ProbeError:
                raise
            except OSError:
                return {"public_ip": expected_ip, "port": 29652, "closed": True}

        checks.append(run_check(f"seed_{index}_dns", dns_probe))
        checks.append(run_check(f"seed_{index}_rpc_closed", rpc_closed))

    return {
        "schema": "noos/wwm-public-remote-probe/v1",
        "environment": "public-testnet",
        "production": False,
        "production_authorized": False,
        "promotion_effect": "NONE",
        "observed_at": int(time.time()),
        "status": "ok" if all(check["ok"] for check in checks) else "degraded",
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="External fail-closed alert probe for the WWM public testnet")
    parser.add_argument("--deployment", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = collect(load_deployment(args.deployment))
    except (ProbeError, OSError, ValueError) as error:
        report = {
            "schema": "noos/wwm-public-remote-probe/v1",
            "environment": "public-testnet",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "status": "degraded",
            "error": str(error)[:160],
        }
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if report.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
