#!/usr/bin/env python3
"""Measure signed-transfer throughput against a live MindChain network.

This is an observed end-to-end benchmark: canonical build, local Ed25519 sign,
public submission, block execution, indexer ingestion, and settlement. It does
not extrapolate to untested hardware or WAN deployments.
"""
from __future__ import annotations

import argparse
import hashlib
from collections import Counter
import json
import statistics
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wallet_transfer import USER_AGENT, action, balance, cargo_binary, checked_status, cli_json, derive, load_profile, read_seed  # noqa: E402

ZERO_ASSET = "00" * 32


def post(base: str, envelope: dict, retry_seconds: float = 120) -> dict:
    deadline = time.monotonic() + retry_seconds
    body = json.dumps(envelope, separators=(",", ":")).encode()
    while True:
        request = urllib.request.Request(
            base.rstrip("/") + "/api/v1/transactions",
            method="POST",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            if exc.code in {409, 429, 503} and time.monotonic() < deadline:
                time.sleep(0.1)
                continue
            raise RuntimeError(f"submission HTTP {exc.code}: {detail}") from exc

def tx_record(base: str, txid: str) -> dict | None:
    root = base.rstrip("/")
    try:
        transaction_request = urllib.request.Request(
            root + f"/api/v1/transactions/{txid}",
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(transaction_request, timeout=5) as response:
            value = json.load(response)
        return value if isinstance(value, dict) else None
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    try:
        receipt_request = urllib.request.Request(
            root + f"/api/v1/receipts/{txid}",
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(receipt_request, timeout=5) as response:
            receipt = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    state = receipt.get("state") if isinstance(receipt, dict) else None
    if not isinstance(state, dict) or "status_code" not in state:
        return None
    return {
        "txid": txid,
        "state": "INCLUDED" if int(state["status_code"]) == 0 else "REJECTED",
        "inclusion": {"height": int(state["settled_height"])},
        "receipt": receipt.get("receipt"),
    }


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * q))]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--seed-file")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--account", type=int, default=0)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--slot-seconds", type=float, default=6.0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.count <= 10_000:
        raise SystemExit("count must be between 1 and 10000")
    profile = load_profile(args.profile)
    seed = read_seed(args.seed_file)
    exe = cargo_binary("noos-cli")
    sender = str(derive(exe, seed, args.account, args.index)["verifying_key"])
    status = checked_status(profile)
    start_height = int(status["unsafe_head"]["height"])
    available_record = balance(profile, sender, ZERO_ASSET)
    available = int(available_record.get("unsafe_amount", available_record.get("balance", "0")))
    if available < args.count * 2000:
        raise SystemExit(f"benchmark account has insufficient fee headroom: {available}")

    submitted: dict[str, float] = {}
    submission_started = time.perf_counter()
    for index in range(args.count):
        recipient = hashlib.sha256(b"NOOS/TPS/RECIPIENT/V1" + index.to_bytes(8, "little") + time.time_ns().to_bytes(8, "little")).hexdigest()
        live = checked_status(profile)
        spec = {
            "chain_id": profile["chain_id"], "format_version": 1,
            "expiry_height": int(live["unsafe_head"]["height"]) + 1000,
            "fee_payer": sender, "fee_authorization": None,
            "resource_limits": {"bytes": 4096, "grain_steps": 0, "proof_units": 0,
                                 "blob_bytes": 0, "state_reads": 64, "state_writes": 64},
            "note_inputs": [], "account_inputs": [sender], "object_access_list": [],
            "actions": [action(3, sender, ZERO_ASSET, 1), action(2, recipient, ZERO_ASSET, 1)],
            "outputs": [], "evidence_refs": [], "lock_reveals": [],
        }
        built = cli_json(exe, "tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
        signed = cli_json(exe, "tx", "sign", "--tx", str(built["tx"]), "--seed", seed,
            "--account", str(args.account), "--index", str(args.index),
            "--chain-id", str(profile["chain_id"]), "--genesis-hash", str(profile["genesis_hash"]), "--scope", "0")
        accepted = post(str(profile["api_base_url"]), {"tx": built["tx"], "witnesses": signed["witnesses"]})
        if accepted.get("txid") != built["txid"]:
            raise SystemExit("submission txid mismatch")
        submitted[str(built["txid"])] = time.perf_counter()
    submission_finished = time.perf_counter()

    pending = set(submitted)
    records: dict[str, dict] = {}
    deadline = time.monotonic() + args.timeout
    while pending and time.monotonic() < deadline:
        for txid in list(pending):
            record = tx_record(str(profile["api_base_url"]), txid)
            if record and record.get("state") in {"INCLUDED", "JUSTIFIED", "FINALIZED"}:
                record["observed_at"] = time.perf_counter()
                records[txid] = record
                pending.remove(txid)
            elif record and record.get("state") in {"REJECTED", "REVERTED"}:
                raise SystemExit(f"benchmark transaction failed: {txid}: {record}")
        if pending:
            time.sleep(0.1)
    if pending:
        raise SystemExit(f"{len(pending)} transactions did not settle before timeout")

    completed = max(record["observed_at"] for record in records.values())
    latencies = [records[txid]["observed_at"] - submitted[txid] for txid in submitted]
    heights = []
    for record in records.values():
        inclusion = record.get("inclusion")
        if isinstance(inclusion, dict) and "height" in inclusion:
            heights.append(int(inclusion["height"]))
    block_counts = Counter(heights)
    blocks_used = len(block_counts)
    duration = completed - submission_started
    report = {
        "schema": "noos/tps-benchmark/v1",
        "chain_id": profile["chain_id"], "genesis_hash": profile["genesis_hash"],
        "account": sender, "transaction_count": args.count,
        "start_height": start_height, "end_height": max(heights) if heights else None,
        "submission_seconds": submission_finished - submission_started,
        "settlement_seconds": duration,
        "observed_end_to_end_tps": args.count / duration,
        "configured_slot_seconds": args.slot_seconds,
        "slot_normalized_tps": (
            args.count / (blocks_used * args.slot_seconds) if blocks_used else None
        ),
        "transactions_by_height": {
            str(height): count for height, count in sorted(block_counts.items())
        },
        "settlement_latency_seconds": {"min": min(latencies), "median": statistics.median(latencies),
                                        "p95": percentile(latencies, .95), "max": max(latencies)},
        "blocks_used": blocks_used or None,
        "transactions_per_observed_block": args.count / blocks_used if blocks_used else None,
        "environment": {"note": "local measured result; no production/WAN extrapolation"},
        "completed_unix_ms": int(time.time() * 1000),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
