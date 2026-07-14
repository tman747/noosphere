#!/usr/bin/env python3
"""Submit one real prompt through the loopback WWM test gateway and verify its receipt."""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import json
import secrets
import sys
import urllib.error
import urllib.request
from typing import Any

MAX_RESPONSE_BYTES = 2 * 1024 * 1024


def request_json(
    opener: urllib.request.OpenerDirector,
    url: str,
    body: dict[str, Any] | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/json",
            **({"Content-Type": "application/json"} if data is not None else {}),
        },
        method="POST" if data is not None else "GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        detail = error.read(64 * 1024).decode("utf-8", errors="replace")
        raise RuntimeError(f"{url} returned HTTP {error.code}: {detail}") from error
    except OSError as error:
        raise RuntimeError(f"{url} failed: {error}") from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise RuntimeError(f"{url} exceeded the response-size bound")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{url} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{url} did not return a JSON object")
    return value


def read_events(
    opener: urllib.request.OpenerDirector,
    url: str,
    timeout: int,
) -> list[tuple[str, dict[str, Any]]]:
    request = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
    events: list[tuple[str, dict[str, Any]]] = []
    event_name = "message"
    data_lines: list[str] = []
    consumed = 0
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        detail = error.read(64 * 1024).decode("utf-8", errors="replace")
        raise RuntimeError(f"stream returned HTTP {error.code}: {detail}") from error
    try:
        for raw_line in response:
            consumed += len(raw_line)
            if consumed > MAX_RESPONSE_BYTES:
                raise RuntimeError("event stream exceeded the response-size bound")
            line = raw_line.decode("utf-8", errors="strict").rstrip("\r\n")
            if line.startswith(":"):
                continue
            if not line:
                if data_lines:
                    try:
                        payload = json.loads("\n".join(data_lines))
                    except json.JSONDecodeError as error:
                        raise RuntimeError("event stream contained malformed JSON") from error
                    if not isinstance(payload, dict):
                        raise RuntimeError("event payload was not a JSON object")
                    events.append((event_name, payload))
                    if event_name in {"receipt", "gateway-error"}:
                        break
                event_name = "message"
                data_lines = []
            elif line.startswith("event:"):
                event_name = line.removeprefix("event:").strip()
            elif line.startswith("data:"):
                data_lines.append(line.removeprefix("data:").lstrip())
    finally:
        response.close()
    return events


def require_hash(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value.lower() != value
        or any(character not in "0123456789abcdef" for character in value)
        or value == "0" * 64
    ):
        raise RuntimeError(f"{field} is not a canonical nonzero hash")
    return value


def run(origin: str, prompt: str, output_tokens: int, timeout: int) -> dict[str, Any]:
    if not prompt.strip():
        raise RuntimeError("prompt must be nonempty")
    if not 1 <= output_tokens <= 4096:
        raise RuntimeError("output token bound must be in [1,4096]")
    origin = origin.rstrip("/")
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))

    state = request_json(opener, f"{origin}/api/wwm/v1/state")
    if state.get("enabled") is not True or state.get("test_only") is not True:
        raise RuntimeError(f"gateway is not enabled in disclosed test-only mode: {state}")
    pin = state.get("pin")
    if not isinstance(pin, dict):
        raise RuntimeError("state response has no pin")
    pin_id = require_hash(pin.get("pin_id"), "pin_id")
    chain_id = require_hash(pin.get("chain_id"), "chain_id")
    genesis_hash = require_hash(pin.get("genesis_hash"), "genesis_hash")
    capsule_id = require_hash(pin.get("capsule_id"), "capsule_id")

    prompt_bytes = prompt.encode("utf-8")
    prompt_commitment = hashlib.sha256(prompt_bytes).hexdigest()
    client_nonce = secrets.token_hex(32)
    input_tokens = max(1, (len(prompt) + 3) // 4)
    quote = request_json(
        opener,
        f"{origin}/api/wwm/v1/quotes",
        {
            "pin_id": pin_id,
            "prompt_commitment": prompt_commitment,
            "client_nonce": client_nonce,
            "compute_profile": "P0_OPEN",
            "requested_finality": "SOFT",
            "input_tokens": input_tokens,
            "maximum_output_tokens": output_tokens,
            "sponsor_requested": True,
        },
    )
    quote_id = require_hash(quote.get("quote_id"), "quote_id")
    if quote.get("pin_id") != pin_id or quote.get("capsule_id") != capsule_id:
        raise RuntimeError("quote changed the pinned state or model capsule")
    require_hash(quote.get("gateway_key"), "gateway_key")
    signature = quote.get("signature")
    if not isinstance(signature, str) or len(signature) != 128:
        raise RuntimeError("quote has no canonical Ed25519 signature")

    job = request_json(
        opener,
        f"{origin}/api/wwm/v1/jobs",
        {
            "quote_id": quote_id,
            "prompt": prompt,
            "prompt_commitment": prompt_commitment,
            "client_nonce": client_nonce,
        },
    )
    job_id = require_hash(job.get("job_id"), "job_id")
    stream_url = job.get("stream_url")
    if not isinstance(stream_url, str) or not stream_url.startswith("/api/wwm/v1/"):
        raise RuntimeError("job returned an invalid same-origin stream path")

    events = read_events(opener, f"{origin}{stream_url}", timeout)
    gateway_error = next((payload for name, payload in events if name == "gateway-error"), None)
    if gateway_error is not None:
        raise RuntimeError(f"gateway execution failed: {gateway_error}")
    answer = "".join(
        payload.get("token", "")
        for name, payload in events
        if name == "token" and isinstance(payload.get("token"), str)
    )
    if not answer.strip():
        raise RuntimeError("model stream returned no answer")
    receipt = next((payload for name, payload in events if name == "receipt"), None)
    if receipt is None:
        raise RuntimeError("model stream returned no receipt")
    receipt_id = require_hash(receipt.get("receipt_id"), "receipt_id")
    if (
        receipt.get("job_id") != job_id
        or receipt.get("quote_id") != quote_id
        or receipt.get("capsule_id") != capsule_id
        or receipt.get("pin_id") != pin_id
        or receipt.get("actual_finality") != "SOFT"
        or receipt.get("test_only") is not True
        or receipt.get("on_chain_receipt") is not False
        or receipt.get("chain_anchor_status") != "PINNED_FINALIZED_STATE_ONLY"
    ):
        raise RuntimeError("receipt did not preserve the test job and chain-pin contract")
    require_hash(receipt.get("token_history_root"), "token_history_root")
    require_hash(receipt.get("settlement_id"), "settlement_id")
    receipt_signature = receipt.get("signature")
    if not isinstance(receipt_signature, str) or len(receipt_signature) != 128:
        raise RuntimeError("receipt has no canonical Ed25519 signature")

    stored = request_json(opener, f"{origin}/api/wwm/v1/jobs/{job_id}/receipt")
    if stored.get("receipt_id") != receipt_id:
        raise RuntimeError("persisted receipt differs from the streamed receipt")
    return {
        "verdict": "PASS_TEST_ONLY",
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "pin_id": pin_id,
        "capsule_id": capsule_id,
        "quote_id": quote_id,
        "job_id": job_id,
        "receipt_id": receipt_id,
        "actual_finality": "SOFT",
        "on_chain_receipt": False,
        "answer": answer,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="http://127.0.0.1:18787")
    parser.add_argument(
        "--prompt",
        default="Explain MindChain finality in two short sentences and label this response test-only.",
    )
    parser.add_argument("--output-tokens", type=int, default=128)
    parser.add_argument("--timeout", type=int, default=180)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        result = run(arguments.origin, arguments.prompt, arguments.output_tokens, arguments.timeout)
    except RuntimeError as error:
        print(f"wwm_gateway_smoke: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
