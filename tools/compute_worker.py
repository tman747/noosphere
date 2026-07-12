#!/usr/bin/env python3
"""MindChain compute worker for the deterministic MIX32 rental workload.

The worker keeps its seed local, registers capabilities on chain, claims one
open shard at a time, computes it with a bounded thread pool, commits the result
root on chain, and asks the requester gateway to verify/accept delivery.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import platform
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wallet_transfer import (  # noqa: E402
    api_json, cargo_binary, checked_status, cli_json, derive, load_profile, read_seed,
)


def transaction_spec(profile: dict, signer: str, height: int, action: dict) -> dict:
    return {
        "chain_id": profile["chain_id"], "format_version": 1,
        "expiry_height": height + 1000, "fee_payer": signer,
        "fee_authorization": None,
        "resource_limits": {"bytes": 8192, "grain_steps": 0, "proof_units": 0,
                             "blob_bytes": 0, "state_reads": 128, "state_writes": 128},
        "note_inputs": [], "account_inputs": [signer], "object_access_list": [],
        "actions": [action], "outputs": [], "evidence_refs": [], "lock_reveals": [],
    }


def live_status(profile: dict) -> dict:
    node = profile.get("_operator_node")
    token = profile.get("_operator_token")
    if not isinstance(node, str) or not isinstance(token, str):
        return checked_status(profile)
    origin = node if node.startswith(("http://", "https://")) else f"http://{node}"
    request = urllib.request.Request(
        origin.rstrip("/") + "/status",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("operator status returned malformed JSON")
    if value.get("chain_id") != profile["chain_id"] or value.get("genesis_hash") != profile["genesis_hash"]:
        raise RuntimeError("operator status returned the wrong protocol identity")
    return value


def settlement_record(profile: dict, txid: str) -> dict | None:
    try:
        return api_json(str(profile["api_base_url"]), f"/api/v1/transactions/{txid}")
    except SystemExit as error:
        if "HTTP Error 404" not in str(error):
            raise
    try:
        receipt = api_json(str(profile["api_base_url"]), f"/api/v1/receipts/{txid}")
    except SystemExit as error:
        if "HTTP Error 404" in str(error):
            return None
        raise
    state = receipt.get("state") if isinstance(receipt, dict) else None
    if not isinstance(state, dict) or "status_code" not in state:
        return None
    return {
        "state": "INCLUDED" if int(state["status_code"]) == 0 else "REJECTED",
        "receipt": receipt,
    }


def submit_action(profile: dict, seed: str, account: int, index: int, action: dict, wait: float = 90) -> dict:
    exe = cargo_binary("noos-cli")
    signer = str(derive(exe, seed, account, index)["verifying_key"])
    status = live_status(profile)
    spec = transaction_spec(profile, signer, int(status["unsafe_head"]["height"]), action)
    built = cli_json(exe, "tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
    signed = cli_json(exe, "tx", "sign", "--tx", str(built["tx"]), "--seed", seed,
                      "--account", str(account), "--index", str(index),
                      "--chain-id", str(profile["chain_id"]),
                      "--genesis-hash", str(profile["genesis_hash"]), "--scope", "0")
    checked_status(profile)
    accepted = api_json(str(profile["api_base_url"]), "/api/v1/transactions",
                        body={"tx": built["tx"], "witnesses": signed["witnesses"]})
    txid = str(built["txid"])
    if accepted.get("txid") != txid:
        raise RuntimeError("transaction submission returned a mismatched txid")
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        record = settlement_record(profile, txid)
        if record is None:
            time.sleep(0.25)
            continue
        if record.get("state") in {"INCLUDED", "JUSTIFIED", "FINALIZED"}:
            return {"txid": txid, "built": built, "state": record["state"]}
        if record.get("state") in {"REJECTED", "REVERTED"}:
            raise RuntimeError(f"transaction failed: {record}")
        time.sleep(0.5)
    raise RuntimeError(f"transaction did not settle: {txid}")


def mix_one(seed: int, global_index: int, rounds: int) -> int:
    value = (seed ^ global_index ^ 0x9E3779B9) & 0xFFFFFFFF
    for _ in range(rounds):
        value ^= (value << 13) & 0xFFFFFFFF
        value ^= value >> 17
        value ^= (value << 5) & 0xFFFFFFFF
        value = (value * 0x85EBCA6B + 0xC2B2AE35) & 0xFFFFFFFF
    return value


def compute_root(seed: int, start: int, units: int, rounds: int, threads: int) -> str:
    if not 1 <= units <= 1_000_000 or not 1 <= rounds <= 1_048_576:
        raise ValueError("workload bounds exceeded")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        values = pool.map(lambda item: mix_one(seed, item, rounds), range(start, start + units), chunksize=64)
        digest = hashlib.sha256(b"NOOS/COMPUTE/MIX32/RESULT/V1")
        for value in values:
            digest.update(value.to_bytes(4, "little"))
    return digest.hexdigest()


def get_payload(market: str, job_id: str) -> dict:
    with urllib.request.urlopen(f"{market.rstrip('/')}/api/payload/{job_id}", timeout=10) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise RuntimeError("market returned malformed payload")
    return value


def validate_payload(job: dict, payload: dict, max_operations: int) -> tuple[int, int, int, int]:
    """Bind coordinator bytes to the claimed on-chain job and local meter."""
    if job.get("workload_kind") != 0:
        raise ValueError("unregistered workload kind")
    if set(payload) != {"seed", "start", "units", "rounds"}:
        raise ValueError("MIX32 payload fields mismatch")
    if any(type(payload[name]) is not int for name in payload):
        raise ValueError("MIX32 payload fields must be integers")
    seed, start, units, rounds = (
        payload["seed"], payload["start"], payload["units"], payload["rounds"]
    )
    if not 0 <= seed <= 0xFFFFFFFF or not 0 <= start <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("MIX32 seed or start is out of range")
    if not 1 <= units <= 1_000_000 or not 1 <= rounds <= 1_048_576:
        raise ValueError("MIX32 workload bounds exceeded")
    operations = units * rounds
    if max_operations < 1 or operations > max_operations:
        raise ValueError("MIX32 deterministic operation budget exceeded")
    if units != int(job.get("units", "0")) or rounds != int(job.get("unit_size", "0")):
        raise ValueError("MIX32 payload differs from the on-chain meter")
    commitment = hashlib.sha256(
        b"NOOS/COMPUTE/MIX32/INPUT/V1"
        + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if commitment != job.get("input_root"):
        raise ValueError("MIX32 payload commitment mismatch")
    return seed, start, units, rounds


def notify_result(market: str, job_id: str, result_root: str) -> dict:
    request = urllib.request.Request(
        f"{market.rstrip('/')}/api/result", method="POST",
        data=json.dumps({"job_id": job_id, "result_root": result_root}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response)


def register(args: argparse.Namespace, profile: dict, seed: str, worker: str) -> dict:
    endpoint = hashlib.sha256(args.market.rstrip("/").encode()).hexdigest()
    action = {
        "type": "register_compute_worker", "worker": worker,
        "capabilities": 1, "cpu_threads": args.threads,
        "memory_mb": args.memory_mb, "gpu_memory_mb": 0,
        "price_per_unit": str(args.price_per_unit), "endpoint_commitment": endpoint,
    }
    return submit_action(profile, seed, args.account, args.index, action)


def run_worker(args: argparse.Namespace, profile: dict, seed: str, worker: str) -> None:
    print(json.dumps({"worker": worker, "platform": platform.platform(), "threads": args.threads,
                      "market": args.market}, indent=2), flush=True)
    while True:
        try:
            jobs = api_json(str(profile["api_base_url"]), "/api/v1/jobs").get("items", [])
            candidates = [job for job in jobs if job.get("state") == 0 and job.get("workload_kind") == 0
                          and int(job.get("max_price_per_unit", "0")) >= args.price_per_unit]
            if not candidates:
                time.sleep(args.poll)
                continue
            job = min(candidates, key=lambda item: item["job_id"])
            job_id = str(job["job_id"])
            try:
                submit_action(profile, seed, args.account, args.index,
                              {"type": "claim_compute_job", "worker": worker, "job_id": job_id})
            except RuntimeError:
                time.sleep(0.5)
                continue
            payload = get_payload(args.market, job_id)
            workload_seed, start, units, rounds = validate_payload(
                job, payload, args.max_operations
            )
            started = time.perf_counter()
            result_root = compute_root(workload_seed, start, units, rounds, args.threads)
            elapsed = time.perf_counter() - started
            submit_action(profile, seed, args.account, args.index, {
                "type": "submit_compute_result", "worker": worker, "job_id": job_id,
                "result_root": result_root, "completed_units": int(payload["units"]),
            })
            accepted = notify_result(args.market, job_id, result_root)
            print(json.dumps({"job_id": job_id, "units": payload["units"], "seconds": elapsed,
                              "units_per_second": int(payload["units"]) / elapsed,
                              "result_root": result_root, "settlement": accepted}, indent=2), flush=True)
        except (OSError, urllib.error.URLError, RuntimeError, ValueError) as exc:
            print(f"worker error: {exc}", file=sys.stderr, flush=True)
            time.sleep(args.poll)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--market", required=True)
    parser.add_argument("--seed-file")
    parser.add_argument("--account", type=int, default=0)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--threads", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument("--memory-mb", type=int, default=4096)
    parser.add_argument("--price-per-unit", type=int, default=1)
    parser.add_argument("--max-operations", type=int, default=100_000_000)
    parser.add_argument("--poll", type=float, default=2)
    parser.add_argument("command", choices=("register", "run", "register-and-run"))
    args = parser.parse_args()
    profile = load_profile(args.profile)
    seed = read_seed(args.seed_file)
    exe = cargo_binary("noos-cli")
    worker = str(derive(exe, seed, args.account, args.index)["verifying_key"])
    if args.command in {"register", "register-and-run"}:
        print(json.dumps(register(args, profile, seed, worker), indent=2), flush=True)
    if args.command in {"run", "register-and-run"}:
        run_worker(args, profile, seed, worker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
