#!/usr/bin/env python3
"""Run the loopback-only WWM test gateway against a declared test-network node."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ACK_ENV = "NOOS_WWM_TEST_ONLY_ACK"
ACK_VALUE = "I_UNDERSTAND_WWM_IS_TEST_ONLY"
GATEWAY_SEED_ENV = "NOOS_WWM_TEST_GATEWAY_SEED"
CREDENTIAL_KEY_ENV = "NOOS_WWM_TEST_CREDENTIAL_KEY"
STATE_BEARER_ENV = "NOOS_WWM_STATE_BEARER"


def canonical_hash(label: str, *parts: str) -> str:
    digest = hashlib.sha256()
    digest.update(label.encode("utf-8"))
    for part in parts:
        digest.update(b"\x00")
        digest.update(part.encode("utf-8"))
    value = digest.hexdigest()
    if value == "0" * 64:
        raise RuntimeError("unexpected zero identity")
    return value


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def require_hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
        or value == "0" * 64
    ):
        raise RuntimeError(f"{field} must be a nonzero lowercase 32-byte hash")
    return value


def load_or_create_secret(path: Path) -> str:
    if path.exists():
        value = path.read_text(encoding="ascii").strip()
        return require_hash(value, str(path))
    value = secrets.token_hex(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, f"{value}\n".encode("ascii"))
    finally:
        os.close(descriptor)
    return value


def model_digest(base_url: str, model: str, supplied: str | None) -> str:
    if supplied is not None:
        return require_hash(supplied, "--model-digest")
    normalized = base_url.rstrip("/")
    if normalized.endswith("/v1"):
        normalized = normalized[:-3]
    try:
        with urllib.request.urlopen(f"{normalized}/api/tags", timeout=5) as response:
            payload = json.loads(response.read(2 * 1024 * 1024))
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise RuntimeError(
            "cannot derive the model artifact digest; supply --model-digest for a non-Ollama backend"
        ) from error
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        raise RuntimeError("model backend returned no model inventory")
    for entry in models:
        if isinstance(entry, dict) and entry.get("name") == model:
            return require_hash(entry.get("digest"), "model digest")
    raise RuntimeError(f"model {model!r} is not installed in the local backend")


def bearer_token(path: Path | None) -> str | None:
    if path is None:
        return None
    document = read_json(path)
    value = document.get("rpc_token")
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"{path} has no nonempty rpc_token")
    return value


def build_config(arguments: argparse.Namespace) -> tuple[Path, dict[str, str]]:
    if arguments.model_api != "OLLAMA" and arguments.model_num_gpu is not None:
        raise RuntimeError("--model-num-gpu is only valid with --model-api OLLAMA")
    profile = read_json(arguments.profile)
    if profile.get("test_network") is not True:
        raise RuntimeError("the WWM test gateway refuses a profile not marked test_network=true")
    chain_id = require_hash(profile.get("chain_id"), "profile chain_id")
    genesis_hash = require_hash(profile.get("genesis_hash"), "profile genesis_hash")
    digest = model_digest(arguments.model_base_url, arguments.model, arguments.model_digest)

    runtime_dir = arguments.runtime_dir.resolve()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    gateway_seed = load_or_create_secret(runtime_dir / "gateway.seed")
    credential_key = load_or_create_secret(runtime_dir / "credential.key")
    token = bearer_token(arguments.operator_secret)

    identity_parts = (chain_id, genesis_hash, arguments.model, digest)
    capsule_id = canonical_hash("NOOS/WWM/TEST-CAPSULE/V1", *identity_parts)
    query_policy_id = canonical_hash("NOOS/WWM/TEST-QUERY-POLICY/V1", chain_id)
    snapshot_id = canonical_hash("NOOS/WWM/TEST-SNAPSHOT/V1", chain_id, digest)
    fee_schedule_id = canonical_hash("NOOS/WWM/TEST-FEE/V1", chain_id)
    endpoint_id = canonical_hash("NOOS/WWM/TEST-ENDPOINT/V1", arguments.state_url)
    control_cluster = canonical_hash("NOOS/WWM/TEST-CONTROL/V1", arguments.state_url)
    sponsor_id = canonical_hash("NOOS/WWM/TEST-SPONSOR/V1", chain_id)

    document: dict[str, Any] = {
        "schema": "noos/wwm-test-gateway/v1",
        "activation_scope": "TEST_ONLY",
        "listen": arguments.listen,
        "site_dir": str((Path(__file__).resolve().parents[2] / "site").resolve()),
        "data_path": str(runtime_dir / "gateway.sqlite3"),
        "gateway_seed_env": GATEWAY_SEED_ENV,
        "credential_key_env": CREDENTIAL_KEY_ENV,
        "expected_chain_id": chain_id,
        "expected_genesis_hash": genesis_hash,
        "pin_mode": "TEST_SINGLE_NODE",
        "state_endpoints": [
            {
                "url": arguments.state_url,
                "endpoint_id": endpoint_id,
                "control_cluster": control_cluster,
                "bearer_token_env": STATE_BEARER_ENV if token is not None else None,
            }
        ],
        "activation": {
            "capsule_id": capsule_id,
            "query_policy_id": query_policy_id,
            "knowledge_snapshot_id": snapshot_id,
            "executor_registry_epoch": 1,
        },
        "fee_schedule": {
            "schedule_id": fee_schedule_id,
            "base_micro_noos": 10,
            "input_token_micro_noos": 1,
            "retrieval_token_micro_noos": 1,
            "output_token_micro_noos": 2,
            "anchored_surcharge_micro_noos": 0,
            "assured_surcharge_micro_noos": 0,
        },
        "rate_policy": {
            "window_blocks": 256,
            "maximum_requests": 100,
            "maximum_output_tokens": 100_000,
        },
        "sponsor": {
            "sponsor_id": sponsor_id,
            "remaining_micro_noos": 100_000_000,
            "per_job_cap_micro_noos": 100_000,
            "allowed_capsule_only": True,
            "expires_height": 4_294_967_295,
        },
        "model": {
            "api": arguments.model_api,
            "base_url": arguments.model_base_url,
            "model": arguments.model,
            "api_key_env": arguments.model_api_key_env,
            "system_prompt": (
                "You are the test-only World Wide Mind model bound to a MindChain test-network "
                "state pin. Answer directly and concisely. Never imply that execution finality "
                "proves factual truth, and never describe this test profile as production."
            ),
            "timeout_ms": arguments.model_timeout_ms,
            "num_gpu": (
                arguments.model_num_gpu
                if arguments.model_num_gpu is not None
                else (0 if arguments.model_api == "OLLAMA" else None)
            ),
        },
        "quote_lifetime_blocks": 64,
        "maximum_prompt_bytes": 48_000,
        "maximum_pending_jobs": 64,
    }
    config_path = runtime_dir / "wwm-test-gateway.json"
    temporary = config_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, config_path)

    environment = os.environ.copy()
    environment[ACK_ENV] = ACK_VALUE
    environment[GATEWAY_SEED_ENV] = gateway_seed
    environment[CREDENTIAL_KEY_ENV] = credential_key
    if token is not None:
        environment[STATE_BEARER_ENV] = token
    return config_path, environment


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--state-url", required=True)
    parser.add_argument("--operator-secret", type=Path)
    parser.add_argument("--runtime-dir", type=Path, default=Path("C:/tmp/noosphere-wwm-test-gateway"))
    parser.add_argument("--listen", default="127.0.0.1:18787")
    parser.add_argument("--model-api", choices=("OLLAMA", "OPEN_AI"), default="OLLAMA")
    parser.add_argument("--model-base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen2.5:0.5b")
    parser.add_argument("--model-digest")
    parser.add_argument("--model-api-key-env")
    parser.add_argument("--model-timeout-ms", type=int, default=120_000)
    parser.add_argument(
        "--model-num-gpu",
        type=int,
        default=None,
        help="Ollama GPU layers; OLLAMA defaults to CPU because the local AMD path produced corrupt tokens",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        config_path, environment = build_config(arguments)
    except RuntimeError as error:
        print(f"run_wwm_test_gateway: {error}", file=sys.stderr)
        return 2
    repository = Path(__file__).resolve().parents[2]
    command = [
        "cargo",
        "run",
        "--locked",
        "-p",
        "noos-mind-gateway",
        "--bin",
        "noos-mind-gateway",
        "--",
        "--config",
        str(config_path),
    ]
    print(f"Starting WWM test gateway from {config_path}")
    print(f"Open http://{arguments.listen}/query.html")
    print("This process is test-only and does not submit WWM receipts to the chain.")
    try:
        completed = subprocess.run(command, cwd=repository, env=environment, check=False)
    except KeyboardInterrupt:
        return 130
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
