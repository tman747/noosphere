#!/usr/bin/env python3
"""Verify finalized Bonsai registration, exact local bytes, then run one inference."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

BONSAI_NAME = "Bonsai-27B-Q1_0.gguf"
BONSAI_BYTES = 3_803_452_480
BONSAI_SHA256 = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
BONSAI_MANIFEST_ROOT = "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7"
BONSAI_RUNTIME_ROOT = "690d9bbd8d44631fb971e0b0677e10c8d0bb1e08a743bb720eeaab728e30ba27"
BONSAI_BUILD_ROOT = "72b5b1514a6fdf64a275d9ae660cda4db3cb2ce64e37a7ca7e97899729dc3b05"
PRISM_RUNTIME_COMMIT = "62061f91088281e65071cc38c5f69ee95c39f14e"
RUNTIME_EXE_SHA256 = "d09e9f62e2bfc20af43f47dac8adddae47de25ae7678702f109faaa03dfe8a56"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class TestError(RuntimeError):
    pass


def require_loopback(url: str, label: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise TestError(f"{label} must be an explicit loopback HTTP URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise TestError(f"{label} must not contain credentials or a fragment")


def read_bounded(response: Any) -> bytes:
    length = response.headers.get("Content-Length")
    if length is not None and int(length) > MAX_RESPONSE_BYTES:
        raise TestError("HTTP response exceeds the 4 MiB bound")
    body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise TestError("HTTP response exceeds the 4 MiB bound")
    return body


def request_json(
    url: str,
    *,
    bearer: str | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 180.0,
) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    data = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        method = "POST"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = read_bounded(response)
    except urllib.error.HTTPError as error:
        detail = read_bounded(error).decode("utf-8", errors="replace")
        raise TestError(f"HTTP {error.code} from {url}: {detail}") from error
    except (OSError, urllib.error.URLError) as error:
        raise TestError(f"cannot reach {url}: {error}") from error
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TestError(f"non-JSON response from {url}") from error
    if not isinstance(value, dict):
        raise TestError(f"JSON response from {url} is not an object")
    return value


def sha256_file(path: Path, expected_bytes: int | None = None) -> str:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise TestError(f"cannot inspect {path}: {error}") from error
    if expected_bytes is not None and size != expected_bytes:
        raise TestError(f"{path} has {size} bytes; expected {expected_bytes}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise TestError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def require_hash32(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise TestError(f"{label} is not a 32-byte lowercase hex value")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise TestError(f"{label} is not hexadecimal") from error
    if len(decoded) != 32 or value != value.lower():
        raise TestError(f"{label} is not canonical lowercase hex")
    return value


def verify_resolution(value: dict[str, Any]) -> dict[str, Any]:
    if value.get("schema") != "noos/finalized-model-resolution/v1":
        raise TestError("wrong model-resolution schema")
    if value.get("registration_state") != "ACTIVE_TESTNET":
        raise TestError("Bonsai is not active in Testnet control state")
    if value.get("production_effect") != "NONE":
        raise TestError("local test unexpectedly claims production effect")
    if value.get("trust_scope") != "LOCAL_FULL_NODE_FINALIZED_STATE":
        raise TestError("unexpected resolution trust scope")
    if value.get("proofs_verified") is not True or value.get("proof_count") != 17:
        raise TestError("the full 17-leaf finalized proof graph was not verified")
    if value.get("weights_on_chain") is not False:
        raise TestError("model weights must remain outside consensus state")
    if value.get("control_mode") != "TESTNET" or value.get("selector") != "bonsai-q1":
        raise TestError("wrong control mode or serving alias")
    chain_id = require_hash32(value.get("chain_id"), "chain_id")
    genesis_hash = require_hash32(value.get("genesis_hash"), "genesis_hash")
    finalized_hash = require_hash32(value.get("finalized_hash"), "finalized_hash")
    objects_root = require_hash32(value.get("objects_root"), "objects_root")
    height = value.get("finalized_height")
    if not isinstance(height, int) or height < 0 or height % 256 != 0:
        raise TestError("finalized height is not a checkpoint height")
    try:
        canonical = bytes.fromhex(value["canonical_resolution_body_hex"])
        finality = bytes.fromhex(value["finality_evidence_hex"])
    except (KeyError, TypeError, ValueError) as error:
        raise TestError("canonical resolution or finality evidence is malformed") from error
    if not canonical or len(canonical) > 262_144 or not finality:
        raise TestError("canonical resolution/finality evidence violates bounds")

    active = value.get("active")
    if not isinstance(active, dict):
        raise TestError("active model summary is missing")
    exact = {
        "model_name": BONSAI_NAME,
        "artifact_bytes": BONSAI_BYTES,
        "artifact_sha256": BONSAI_SHA256,
        "manifest_root": BONSAI_MANIFEST_ROOT,
        "runtime_root": BONSAI_RUNTIME_ROOT,
        "build_root": BONSAI_BUILD_ROOT,
    }
    for field, expected in exact.items():
        if active.get(field) != expected:
            raise TestError(f"registered {field} differs from the exact Bonsai fixture")
    for field in (
        "capsule_id",
        "artifact_id",
        "payload_root",
        "availability_policy_id",
        "availability_certificate_id",
        "tokenizer_root",
        "template_root",
        "execution_profile_id",
        "query_policy_id",
        "authorized_config_id",
    ):
        require_hash32(active.get(field), f"active.{field}")
    if active.get("codec_profile_id") != 1 or active.get("stripe_count") != 454:
        raise TestError("registered artifact codec geometry differs from RS(8,4) Bonsai geometry")
    if active.get("availability_claim") != "TESTNET_FIXTURE_ONLY":
        raise TestError("local availability evidence was mislabeled")
    return {
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "finalized_height": height,
        "finalized_hash": finalized_hash,
        "objects_root": objects_root,
        "capsule_id": active["capsule_id"],
        "artifact_id": active["artifact_id"],
        "manifest_root": active["manifest_root"],
        "execution_profile_id": active["execution_profile_id"],
        "query_policy_id": active["query_policy_id"],
        "canonical_resolution_bytes": len(canonical),
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    require_loopback(args.node_url, "--node-url")
    require_loopback(args.inference_url, "--inference-url")
    if not args.node_token:
        raise TestError("--node-token must not be empty")
    prompt = args.prompt.strip()
    prompt_bytes = prompt.encode("utf-8")
    if not prompt_bytes or len(prompt_bytes) > 16_384:
        raise TestError("--prompt must contain 1..16384 UTF-8 bytes")
    if not 1 <= args.max_tokens <= 512:
        raise TestError("--max-tokens must be in 1..512")

    resolution_url = args.node_url.rstrip("/") + "/model-resolution/bonsai-q1"
    resolution = request_json(resolution_url, bearer=args.node_token, timeout=30)
    chain = verify_resolution(resolution)

    artifact_path = Path(args.artifact)
    runtime_path = Path(args.runtime)
    artifact_sha256 = sha256_file(artifact_path, BONSAI_BYTES)
    if artifact_sha256 != BONSAI_SHA256:
        raise TestError("local GGUF SHA-256 differs from the finalized artifact identity")
    runtime_sha256 = sha256_file(runtime_path)
    if runtime_sha256 != RUNTIME_EXE_SHA256:
        raise TestError("local llama-cli executable differs from the pinned build identity")

    inference = request_json(
        args.inference_url,
        payload={
            "model": BONSAI_NAME,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "top_p": 1,
            "max_tokens": args.max_tokens,
            "seed": 42,
            "stream": False,
        },
        timeout=args.timeout,
    )
    try:
        choice = inference["choices"][0]
        message = choice["message"]
        content = message["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise TestError("inference server returned no assistant message") from error
    if not isinstance(content, str) or not content.strip():
        raise TestError("inference server returned an empty assistant message")

    return {
        "schema": "noos/bonsai-mindchain-local-result/v1",
        "claim": "LOCAL_CHAIN_RESOLVED_INFERENCE",
        "chain_registration": chain,
        "local_runtime": {
            "model_name": BONSAI_NAME,
            "artifact_path": str(artifact_path.resolve()),
            "artifact_bytes": BONSAI_BYTES,
            "artifact_sha256": artifact_sha256,
            "runtime_path": str(runtime_path.resolve()),
            "runtime_sha256": runtime_sha256,
            "runtime_commit": PRISM_RUNTIME_COMMIT,
            "remote_route_used": False,
        },
        "request": {
            "prompt_commitment": hashlib.sha256(prompt_bytes).hexdigest(),
            "maximum_output_tokens": args.max_tokens,
            "temperature": 0,
            "seed": 42,
        },
        "response": {
            "content": content,
            "finish_reason": choice.get("finish_reason"),
            "usage": inference.get("usage"),
        },
        "chain_settlement_claimed": False,
        "production_claimed": False,
        "disclosure": (
            "The finalized chain proves the Bonsai descriptor/capsule/policy/control graph. "
            "Inference ran against the exact locally hashed 3.8 GB GGUF with the pinned Prism runtime. "
            "Fixture custody, production operation, assured inference, and chain settlement are not claimed."
        ),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prompt", default="Introduce yourself in one concise sentence.")
    parser.add_argument("--max-tokens", type=int, default=64)
    parser.add_argument("--node-url", default="http://127.0.0.1:8632")
    parser.add_argument("--node-token", default="bonsai-local-devnet")
    parser.add_argument(
        "--inference-url",
        default="http://127.0.0.1:18768/v1/chat/completions",
    )
    parser.add_argument(
        "--artifact",
        default="D:/noosphere-artifacts/bonsai/Bonsai-27B-Q1_0.gguf",
    )
    parser.add_argument(
        "--runtime",
        default="D:/noosphere-artifacts/runtime/hip-run/llama-cli.exe",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        result = run(parse_args(argv))
    except TestError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
