#!/usr/bin/env python3
"""MindChain compute worker for the deterministic MIX32 rental workload.

The worker keeps its seed local, registers policy-bound capabilities on chain,
claims one open shard at a time, executes the registry-bound workload in a
zero-capability resource-limited child, commits the result root on chain, and
asks the requester gateway to verify and accept delivery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compute_workload_registry import (  # noqa: E402
    VerifiedRegistry,
    WorkloadSpec,
    load_registry,
    read_public_key,
    validate_payload as validate_registered_payload,
)
from wallet_transfer import api_json, cargo_binary, checked_status, cli_json, load_profile  # noqa: E402
from worker_payout_identity import (  # noqa: E402
    WorkerIdentity,
    open_identity,
    read_password,
)
from worker_sandbox import (  # noqa: E402
    JobNetworkBudget,
    SandboxPolicy,
    execute_mix32,
    load_policy,
    mix32_root,
    probe_host,
)

WORKER_ACTIONS = frozenset(
    {
        "register_compute_worker",
        "claim_compute_job",
        "submit_compute_result",
    }
)
REQUESTER_ACTIONS = frozenset(
    {
        "open_compute_job",
        "accept_compute_result",
        "cancel_compute_job",
        "challenge_compute_result",
    }
)
PERMISSIONLESS_ACTIONS = frozenset({"finalize_compute_result", "expire_compute_job"})
DISPUTE_ACTIONS = frozenset({"challenge_compute_result", "finalize_compute_result"})

def require_local_action_actor(action: dict, signer: str) -> None:
    action_type = action.get("type")
    if action_type in WORKER_ACTIONS:
        actor = action.get("worker")
    elif action_type in REQUESTER_ACTIONS:
        actor = action.get("requester")
    elif action_type in PERMISSIONLESS_ACTIONS:
        actor = signer
    else:
        raise RuntimeError("unsupported compute action for local signing")
    if actor != signer:
        raise RuntimeError("compute action differs from the local payout identity")


def transaction_spec(profile: dict, signer: str, height: int, action: dict) -> dict:
    grain_steps = 1_000_000 if action.get("type") in DISPUTE_ACTIONS else 0
    return {
        "chain_id": profile["chain_id"], "format_version": 1,
        "expiry_height": height + 1000, "fee_payer": signer,
        "fee_authorization": None,
        "resource_limits": {"bytes": 8192, "grain_steps": grain_steps, "proof_units": 0,
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


def submit_action(
    profile: dict,
    identity: WorkerIdentity,
    action: dict,
    wait: float = 90,
) -> dict:
    signer = identity.payout_account
    require_local_action_actor(action, signer)
    exe = cargo_binary("noos-cli")
    status = live_status(profile)
    spec = transaction_spec(profile, signer, int(status["unsafe_head"]["height"]), action)
    built = cli_json(exe, "tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
    signed = cli_json(
        exe,
        "tx",
        "sign",
        "--tx",
        str(built["tx"]),
        "--seed-stdin",
        "--account",
        str(identity.account),
        "--index",
        str(identity.index),
        "--chain-id",
        str(profile["chain_id"]),
        "--genesis-hash",
        str(profile["genesis_hash"]),
        "--scope",
        "0",
        stdin_text=identity.seed.hex() + "\n",
    )
    if signed.get("verifying_key") != signer:
        raise RuntimeError("signed transaction differs from the local payout identity")
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




def compute_root(
    workload: WorkloadSpec,
    seed: int,
    start: int,
    units: int,
    rounds: int,
    threads: int,
) -> str:
    limits = workload.limits
    if (
        not isinstance(threads, int)
        or isinstance(threads, bool)
        or threads < 1
        or not 1 <= units <= limits["max_units"]
        or not 1 <= rounds <= limits["max_unit_size"]
        or units * rounds > limits["max_operations"]
    ):
        raise ValueError("workload bounds exceeded")
    return mix32_root(workload.result_domain, seed, start, units, rounds)


def get_payload(
    market: str,
    job_id: str,
    policy: SandboxPolicy,
    budget: JobNetworkBudget,
) -> tuple[dict, int]:
    with urllib.request.urlopen(f"{market.rstrip('/')}/api/payload/{job_id}", timeout=10) as response:
        body = response.read(policy.max_payload_bytes + 1)
    if not body or len(body) > policy.max_payload_bytes:
        raise RuntimeError("market payload response exceeds the local sandbox policy")
    budget.consume(len(body), "payload response")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("market returned malformed payload JSON") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"job_id", "seed", "start", "units", "rounds"}
        or value.get("job_id") != job_id
    ):
        raise RuntimeError("market returned malformed or mismatched payload")
    return ({name: value[name] for name in ("seed", "start", "units", "rounds")}, len(body))


def validate_payload(
    registry: VerifiedRegistry,
    job: dict,
    payload: dict,
    height: int | None,
    max_operations: int,
) -> tuple[WorkloadSpec, int, int, int, int]:
    """Bind coordinator bytes to the signed workload, on-chain job, and local meter."""
    return validate_registered_payload(
        registry,
        job,
        payload,
        height=height,
        max_operations=max_operations,
    )


def notify_result(
    market: str,
    job_id: str,
    result_root: str,
    policy: SandboxPolicy,
    budget: JobNetworkBudget,
) -> dict:
    encoded = json.dumps(
        {"job_id": job_id, "result_root": result_root},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    budget.consume(len(encoded), "result request")
    request = urllib.request.Request(
        f"{market.rstrip('/')}/api/result",
        method="POST",
        data=encoded,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        body = response.read(policy.max_result_bytes + 1)
    if not body or len(body) > policy.max_result_bytes:
        raise RuntimeError("market result response exceeds the local sandbox policy")
    budget.consume(len(body), "result response")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("market returned malformed result JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("market returned malformed result")
    return value


def register(
    args: argparse.Namespace,
    profile: dict,
    identity: WorkerIdentity,
    policy: SandboxPolicy,
) -> dict:
    endpoint = hashlib.sha256(
        b"NOOS/COMPUTE/WORKER-ENDPOINT/V1\0"
        + args.market.rstrip("/").encode("utf-8")
        + b"\0"
        + bytes.fromhex(policy.policy_id)
    ).hexdigest()
    action = {
        "type": "register_compute_worker",
        "worker": identity.payout_account,
        "capabilities": 1,
        "cpu_threads": policy.cpu_threads,
        "memory_mb": policy.memory_mb,
        "gpu_memory_mb": 0,
        "price_per_unit": str(args.price_per_unit),
        "endpoint_commitment": endpoint,
        "bond": str(args.bond),
    }
    return submit_action(profile, identity, action)


def run_worker(
    args: argparse.Namespace,
    profile: dict,
    identity: WorkerIdentity,
    registry: VerifiedRegistry,
    policy: SandboxPolicy,
) -> None:
    worker = identity.payout_account
    print(
        json.dumps(
            {
                "worker": worker,
                "payout_account": worker,
                "custody": "LOCAL_PASSWORD_ENCRYPTED",
                "browser_storage_used": False,
                "coordinator_storage_used": False,
                "platform": platform.platform(),
                "threads": policy.cpu_threads,
                "memory_mb": policy.memory_mb,
                "market": args.market,
                "bond": args.bond,
                "workload_registry": registry.registry_id,
                "registry_signer_key_id": registry.signer_key_id,
                "sandbox_policy": policy.summary(),
            },
            indent=2,
        ),
        flush=True,
    )
    while True:
        try:
            policy.enforce_host(probe_host())
            height = int(live_status(profile)["unsafe_head"]["height"])
            jobs = api_json(str(profile["api_base_url"]), "/api/v1/jobs").get("items", [])
            due = [
                job for job in jobs
                if job.get("state") == 2
                and job.get("worker") == worker
                and height > int(job.get("review_deadline_height", "0"))
            ]
            if due:
                job = min(due, key=lambda item: item["job_id"])
                job_id = str(job["job_id"])
                budget = JobNetworkBudget(policy)
                payload, _ = get_payload(args.market, job_id, policy, budget)
                _, workload_seed, start, _, _ = validate_payload(
                    registry, job, payload, None, policy.max_operations
                )
                finalized = submit_action(
                    profile,
                    identity,
                    {
                        "type": "finalize_compute_result",
                        "worker": worker,
                        "job_id": job_id,
                        "seed": workload_seed,
                        "start": start,
                    },
                )
                print(
                    json.dumps(
                        {"job_id": job_id, "settlement": finalized, "resolution": "OBJECTIVE_FINALIZE"},
                        indent=2,
                    ),
                    flush=True,
                )
                continue
            workload = registry.require_active(0, height)
            workers = api_json(str(profile["api_base_url"]), "/api/v1/workers").get("items", [])
            worker_record = next((item for item in workers if item.get("worker") == worker), None)
            if worker_record is None or worker_record.get("active") != 1:
                time.sleep(args.poll)
                continue
            available_bond = int(worker_record.get("bond_available", "0"))
            candidates = [
                job for job in jobs
                if job.get("state") == 0
                and job.get("workload_kind") == workload.workload_kind
                and int(job.get("max_price_per_unit", "0")) >= args.price_per_unit
                and int(job.get("escrow", "0")) <= available_bond
            ]
            if not candidates:
                time.sleep(args.poll)
                continue
            job = min(candidates, key=lambda item: item["job_id"])
            job_id = str(job["job_id"])
            try:
                submit_action(
                    profile,
                    identity,
                    {"type": "claim_compute_job", "worker": worker, "job_id": job_id},
                )
            except RuntimeError:
                time.sleep(0.5)
                continue
            budget = JobNetworkBudget(policy)
            payload, payload_bytes = get_payload(args.market, job_id, policy, budget)
            workload, workload_seed, start, units, rounds = validate_payload(
                registry, job, payload, height, policy.max_operations
            )
            started = time.perf_counter()
            execution = execute_mix32(
                policy,
                workload_id=workload.workload_id,
                result_domain=workload.result_domain,
                seed=workload_seed,
                start=start,
                units=units,
                rounds=rounds,
                payload_bytes=payload_bytes,
            )
            elapsed = time.perf_counter() - started
            submit_action(
                profile,
                identity,
                {
                    "type": "submit_compute_result",
                    "worker": worker,
                    "job_id": job_id,
                    "result_root": execution.result_root,
                    "completed_units": int(payload["units"]),
                },
            )
            accepted = notify_result(
                args.market,
                job_id,
                execution.result_root,
                policy,
                budget,
            )
            print(
                json.dumps(
                    {
                        "job_id": job_id,
                        "units": payload["units"],
                        "seconds": elapsed,
                        "units_per_second": int(payload["units"]) / elapsed,
                        "result_root": execution.result_root,
                        "settlement": accepted,
                        "sandbox": execution.evidence,
                        "coordinator_network_bytes": budget.consumed_bytes,
                    },
                    indent=2,
                ),
                flush=True,
            )
        except (OSError, urllib.error.URLError, RuntimeError, ValueError) as exc:
            print(f"worker error: {exc}", file=sys.stderr, flush=True)
            time.sleep(args.poll)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--market", required=True)
    parser.add_argument("--workload-registry", type=Path, required=True)
    parser.add_argument("--registry-public-key", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--identity-password-file", type=Path)
    parser.add_argument("--sandbox-policy", type=Path, required=True)
    parser.add_argument("--price-per-unit", type=int, default=1)
    parser.add_argument("--bond", type=int, default=100_000)
    parser.add_argument("--poll", type=float, default=2)
    parser.add_argument("command", choices=("register", "run", "register-and-run"))
    args = parser.parse_args()
    if args.price_per_unit <= 0:
        parser.error("--price-per-unit must be positive")
    if args.bond <= 0:
        parser.error("--bond must be positive")
    if args.poll <= 0:
        parser.error("--poll must be positive")
    policy = load_policy(args.sandbox_policy)
    profile = load_profile(args.profile)
    exe = cargo_binary("noos-cli")
    password = read_password(args.identity_password_file)
    try:
        identity = open_identity(
            args.identity_file,
            password,
            str(profile["chain_id"]),
            str(profile["genesis_hash"]),
            exe,
        )
    finally:
        password[:] = b"\x00" * len(password)
    with identity:
        registry = load_registry(
            args.workload_registry,
            trusted_public_key=read_public_key(args.registry_public_key),
            expected_chain_id=str(profile["chain_id"]),
            expected_genesis_hash=str(profile["genesis_hash"]),
            height=int(live_status(profile)["unsafe_head"]["height"]),
        )
        if args.command in {"register", "register-and-run"}:
            print(json.dumps(register(args, profile, identity, policy), indent=2), flush=True)
        if args.command in {"run", "register-and-run"}:
            run_worker(args, profile, identity, registry, policy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
