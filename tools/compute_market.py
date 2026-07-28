#!/usr/bin/env python3
"""LAN compute-rental marketplace backed by native MindChain escrow actions.

The requester key stays in this process. Workers retain their own keys and use
compute_worker.py. The service stores only deterministic workload payloads,
verifies submitted roots independently, and signs acceptance or objective
challenge settlement after exact recomputation. Worker submission alone never
releases escrow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compute_workload_registry import (  # noqa: E402
    VerifiedRegistry,
    commit_input,
    load_registry,
    read_public_key,
    validate_payload as validate_registered_payload,
)
from compute_worker import compute_root, live_status, submit_action  # noqa: E402
from wallet_transfer import api_json, cargo_binary, derive, load_profile, read_seed  # noqa: E402
from worker_payout_identity import WorkerIdentity  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps" / "compute-market"
MAX_BODY = 64 * 1024
MAX_DISPUTE_OPERATIONS = 1_000_000


class Market:
    def __init__(
        self,
        profile: dict,
        seed: str,
        account: int,
        index: int,
        db_path: Path,
        admin_token: str,
        registry: VerifiedRegistry,
    ):
        self.profile = profile
        self.account = account
        self.index = index
        self.requester = str(derive(cargo_binary("noos-cli"), seed, account, index)["verifying_key"])
        self.identity = WorkerIdentity(
            chain_id=str(profile["chain_id"]),
            genesis_hash=str(profile["genesis_hash"]),
            account=account,
            index=index,
            payout_account=self.requester,
            seed=bytearray.fromhex(seed),
        )
        self.registry = registry
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS payloads (
            job_id TEXT PRIMARY KEY, seed INTEGER NOT NULL, start INTEGER NOT NULL,
            units INTEGER NOT NULL, rounds INTEGER NOT NULL, created_ms INTEGER NOT NULL,
            accepted_txid TEXT, result_root TEXT
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS helper_claims (
            job_id TEXT PRIMARY KEY, claimed_ms INTEGER NOT NULL
        )""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS payload_inputs (
            input_root TEXT PRIMARY KEY, seed INTEGER NOT NULL, start INTEGER NOT NULL,
            units INTEGER NOT NULL, rounds INTEGER NOT NULL, created_ms INTEGER NOT NULL
        )""")
        self.db.commit()
        self.lock = threading.Lock()

    def chain(self, path: str) -> dict:
        if path == "/api/status":
            return live_status(self.profile)
        return api_json(str(self.profile["api_base_url"]), path)

    def create_jobs(self, value: dict) -> dict:
        shard_count = int(value.get("shard_count", 1))
        units = int(value.get("units_per_shard", 256))
        rounds = int(value.get("rounds", 2048))
        max_price = int(value.get("max_price_per_unit", 1))
        deadline_blocks = int(value.get("deadline_blocks", 1000))
        seed = int(value.get("seed", secrets.randbits(31)))
        status = self.chain("/api/status")
        height = int(status["unsafe_head"]["height"])
        workload = self.registry.require_active(0, height)
        limits = workload.limits
        if not 1 <= shard_count <= 64:
            raise ValueError("shard_count outside bounds")
        if (
            not 1 <= units <= limits["max_units"]
            or not 1 <= rounds <= limits["max_unit_size"]
            or units * rounds > limits["max_operations"]
            or units * rounds > MAX_DISPUTE_OPERATIONS
        ):
            raise ValueError("workload exceeds signed registry bounds")
        if not 1 <= max_price <= 10**18:
            raise ValueError("price outside bounds")
        if not 1 <= deadline_blocks <= 1_000_000:
            raise ValueError("deadline_blocks outside bounds")
        deadline = height + deadline_blocks
        created: list[dict] = []
        for shard in range(shard_count):
            payload = {"seed": seed, "start": shard * units, "units": units, "rounds": rounds}
            input_root = commit_input(workload, payload)
            with self.lock:
                self.db.execute(
                    "INSERT OR REPLACE INTO payload_inputs(input_root,seed,start,units,rounds,created_ms) VALUES(?,?,?,?,?,?)",
                    (input_root, seed, shard * units, units, rounds, int(time.time() * 1000)),
                )
                self.db.commit()
            result = submit_action(self.profile, self.identity, {
                "type": "open_compute_job", "requester": self.requester,
                "workload_kind": workload.workload_kind, "input_root": input_root, "units": units,
                "unit_size": rounds, "max_price_per_unit": str(max_price),
                "deadline_height": deadline,
            })
            jobs = result["built"].get("created_compute_jobs", [])
            if len(jobs) != 1:
                raise RuntimeError("open transaction did not derive exactly one compute job")
            job_id = str(jobs[0]["job_id"])
            with self.lock:
                self.db.execute(
                    "INSERT OR REPLACE INTO payloads(job_id,seed,start,units,rounds,created_ms) VALUES(?,?,?,?,?,?)",
                    (job_id, seed, shard * units, units, rounds, int(time.time() * 1000)),
                )
                self.db.commit()
            created.append({
                "job_id": job_id,
                "txid": result["txid"],
                "workload_id": workload.workload_id,
                **payload,
            })
        return {
            "requester": self.requester,
            "workload_registry_id": self.registry.registry_id,
            "workload_id": workload.workload_id,
            "jobs": created,
            "total_units": shard_count * units,
            "maximum_escrow": str(shard_count * units * max_price),
        }

    def payload(self, job_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute(
                "SELECT seed,start,units,rounds FROM payloads WHERE job_id=?", (job_id,)
            ).fetchone()
        if row is not None:
            return {"job_id": job_id, "seed": row[0], "start": row[1], "units": row[2], "rounds": row[3]}

        # Crash recovery: the input commitment is persisted before the open
        # transaction leaves this process. Rebuild a missing job-id mapping
        # from the consensus job's immutable input root.
        jobs = self.chain("/api/v1/jobs").get("items", [])
        job = next((item for item in jobs if item.get("job_id") == job_id), None)
        if job is None:
            return None
        with self.lock:
            row = self.db.execute(
                "SELECT seed,start,units,rounds FROM payload_inputs WHERE input_root=?",
                (job.get("input_root"),),
            ).fetchone()
            if row is not None:
                self.db.execute(
                    "INSERT OR REPLACE INTO payloads(job_id,seed,start,units,rounds,created_ms) VALUES(?,?,?,?,?,?)",
                    (job_id, row[0], row[1], row[2], row[3], int(time.time() * 1000)),
                )
                self.db.commit()
        if row is None:
            return None
        return {"job_id": job_id, "seed": row[0], "start": row[1], "units": row[2], "rounds": row[3]}

    def accept(self, value: dict) -> dict:
        job_id = str(value.get("job_id", ""))
        claimed_root = str(value.get("result_root", ""))
        stored = self.payload(job_id)
        if stored is None:
            raise ValueError("unknown job")
        jobs = self.chain("/api/v1/jobs").get("items", [])
        job = next((item for item in jobs if item.get("job_id") == job_id), None)
        if job is None or job.get("state") != 2:
            raise ValueError("chain job is not a submitted result")
        payload = {name: stored[name] for name in ("seed", "start", "units", "rounds")}
        workload, seed, start, units, rounds = validate_registered_payload(
            self.registry,
            job,
            payload,
            height=None,
            max_operations=None,
        )
        expected = compute_root(
            workload,
            seed,
            start,
            units,
            rounds,
            max(1, min(32, units)),
        )
        chain_root = str(job.get("result_root", ""))
        if chain_root != expected:
            result = submit_action(self.profile, self.identity, {
                "type": "challenge_compute_result",
                "requester": self.requester,
                "job_id": job_id,
                "seed": seed,
                "start": start,
            })
            resolution = "INVALID_RESULT_REFUNDED_AND_SLASHED"
        else:
            if claimed_root != expected:
                raise ValueError("result notification differs from the verified on-chain result")
            result = submit_action(self.profile, self.identity, {
                "type": "accept_compute_result", "requester": self.requester, "job_id": job_id,
            })
            resolution = "REQUESTER_ACCEPTED"
        with self.lock:
            self.db.execute("UPDATE payloads SET accepted_txid=?, result_root=? WHERE job_id=?",
                            (result["txid"], chain_root, job_id))
            self.db.commit()
        return {
            "job_id": job_id,
            "result_root": expected,
            "submitted_result_root": chain_root,
            "settlement_txid": result["txid"],
            "state": result["state"],
            "resolution": resolution,
            "workload_id": workload.workload_id,
        }

    def ensure_helper_worker(self, minimum_available_bond: int) -> None:
        if minimum_available_bond <= 0:
            raise ValueError("helper bond requirement must be positive")
        minimum_available_bond = max(100_000, minimum_available_bond)
        workers = self.chain("/api/v1/workers").get("items", [])
        record = next((item for item in workers if item.get("worker") == self.requester), None)
        available = int(record.get("bond_available", "0")) if record else 0
        locked = int(record.get("bond_locked", "0")) if record else 0
        if record is not None and record.get("active") == 1 and available >= minimum_available_bond:
            return
        desired_bond = max(available + locked, locked + minimum_available_bond)
        submit_action(self.profile, self.identity, {
            "type": "register_compute_worker", "worker": self.requester,
            "capabilities": 3, "cpu_threads": 1, "memory_mb": 1024,
            "gpu_memory_mb": 1, "price_per_unit": "1",
            "endpoint_commitment": hashlib.sha256(b"NOOS/BROWSER/HELPER/V1").hexdigest(),
            "bond": str(desired_bond),
        })

    def helper_claim(self) -> dict:
        height = int(self.chain("/api/status")["unsafe_head"]["height"])
        workload = self.registry.require_active(0, height)
        jobs = self.chain("/api/v1/jobs").get("items", [])
        for job in sorted(jobs, key=lambda item: item.get("job_id", "")):
            if job.get("state") != 0 or job.get("workload_kind") != workload.workload_kind:
                continue
            job_id = str(job["job_id"])
            stored = self.payload(job_id)
            if stored is None:
                continue
            payload = {name: stored[name] for name in ("seed", "start", "units", "rounds")}
            validate_registered_payload(
                self.registry,
                job,
                payload,
                height=height,
                max_operations=None,
            )
            self.ensure_helper_worker(int(job.get("escrow", "0")))
            with self.lock:
                if self.db.execute("SELECT 1 FROM helper_claims WHERE job_id=?", (job_id,)).fetchone():
                    continue
                self.db.execute("INSERT INTO helper_claims(job_id,claimed_ms) VALUES(?,?)",
                                (job_id, int(time.time() * 1000)))
                self.db.commit()
            try:
                submit_action(self.profile, self.identity, {
                    "type": "claim_compute_job", "worker": self.requester, "job_id": job_id,
                })
                return {
                    "job_id": job_id,
                    "workload_id": workload.workload_id,
                    **payload,
                }
            except Exception:
                with self.lock:
                    self.db.execute("DELETE FROM helper_claims WHERE job_id=?", (job_id,))
                    self.db.commit()
        return {"idle": True}

    def helper_result(self, value: dict) -> dict:
        job_id = str(value.get("job_id", ""))
        claimed_root = str(value.get("result_root", ""))
        stored = self.payload(job_id)
        if stored is None:
            raise ValueError("unknown helper job")
        jobs = self.chain("/api/v1/jobs").get("items", [])
        job = next((item for item in jobs if item.get("job_id") == job_id), None)
        if job is None or job.get("state") != 1:
            raise ValueError("chain helper job is not claimed")
        payload = {name: stored[name] for name in ("seed", "start", "units", "rounds")}
        workload, seed, start, units, rounds = validate_registered_payload(
            self.registry,
            job,
            payload,
            height=None,
            max_operations=None,
        )
        expected = compute_root(
            workload,
            seed,
            start,
            units,
            rounds,
            max(1, min(32, units)),
        )
        if expected != claimed_root:
            raise ValueError("helper result failed independent recomputation")
        submit_action(self.profile, self.identity, {
            "type": "submit_compute_result", "worker": self.requester, "job_id": job_id,
            "result_root": expected, "completed_units": units,
        })
        return self.accept({"job_id": job_id, "result_root": expected})


class Handler(BaseHTTPRequestHandler):
    server_version = "MindCompute/0.4"

    @property
    def market(self) -> Market:
        return self.server.market  # type: ignore[attr-defined]

    def reply(self, status: int, value: dict | bytes, content_type: str = "application/json") -> None:
        body = value if isinstance(value, bytes) else json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= MAX_BODY:
            raise ValueError("invalid request size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        try:
            if path == "/api/health":
                self.reply(200, {"ok": True, "version": "0.4", "operator_head": bool(self.market.profile.get("_operator_node")),
                                 "workload_registry_id": self.market.registry.registry_id})
            elif path == "/api/config":
                self.reply(200, {
                    "requester": self.market.requester,
                    "chain_id": self.market.profile["chain_id"],
                    "api_base_url": self.market.profile["api_base_url"],
                    "workload_registry": self.market.registry.summary(),
                })
            elif path == "/api/workers":
                self.reply(200, self.market.chain("/api/v1/workers"))
            elif path == "/api/jobs":
                self.reply(200, self.market.chain("/api/v1/jobs"))
            elif path.startswith("/api/payload/"):
                value = self.market.payload(path.rsplit("/", 1)[-1])
                self.reply(200, value) if value else self.reply(404, {"error": "not_found"})
            else:
                relative = "index.html" if path in {"", "/"} else path.lstrip("/")
                file = (APP / relative).resolve()
                if APP.resolve() not in file.parents and file != APP.resolve():
                    self.reply(404, {"error": "not_found"})
                    return
                if not file.is_file():
                    self.reply(404, {"error": "not_found"})
                    return
                content_type = "text/html" if file.suffix == ".html" else "text/css" if file.suffix == ".css" else "text/javascript"
                self.reply(200, file.read_bytes(), content_type)
        except Exception as exc:
            self.reply(503, {"error": "unavailable", "detail": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        try:
            value = self.json_body()
            if path == "/api/jobs":
                if self.headers.get("Authorization") != f"Bearer {self.market.admin_token}":
                    self.reply(401, {"error": "unauthorized"})
                    return
                self.reply(202, self.market.create_jobs(value))
            elif path == "/api/result":
                self.reply(202, self.market.accept(value))
            elif path == "/api/helper/claim":
                self.reply(200, self.market.helper_claim())
            elif path == "/api/helper/result":
                self.reply(202, self.market.helper_result(value))
            else:
                self.reply(404, {"error": "not_found"})
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self.reply(400, {"error": "invalid_request", "detail": str(exc)})
        except SystemExit as exc:
            self.reply(503, {"error": "unavailable", "detail": str(exc)})
        except Exception as exc:
            self.reply(503, {"error": "unavailable", "detail": str(exc)})

    def log_message(self, pattern: str, *args: object) -> None:
        sys.stderr.write("compute-market " + pattern % args + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--workload-registry", type=Path, required=True)
    parser.add_argument("--registry-public-key", type=Path, required=True)
    parser.add_argument("--seed-file")
    parser.add_argument("--account", type=int, default=0)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--listen", default="0.0.0.0:18110")
    parser.add_argument("--database", default=str(Path.home() / ".mindchain-compute-market.sqlite3"))
    parser.add_argument("--admin-token-file", required=True)
    parser.add_argument("--operator-node")
    parser.add_argument("--operator-token-file")
    args = parser.parse_args()
    token = Path(args.admin_token_file).read_text(encoding="utf-8").strip()
    if len(token) < 24:
        raise SystemExit("admin token must contain at least 24 characters")
    profile = load_profile(args.profile)
    if bool(args.operator_node) != bool(args.operator_token_file):
        raise SystemExit("--operator-node and --operator-token-file must be supplied together")
    if args.operator_node:
        encoded_token = Path(args.operator_token_file).read_text(encoding="utf-8").strip()
        try:
            token_value = json.loads(encoded_token)
            operator_token = str(token_value["rpc_token"])
        except (json.JSONDecodeError, KeyError, TypeError):
            operator_token = encoded_token
        if len(operator_token) < 24:
            raise SystemExit("operator token must contain at least 24 characters")
        profile["_operator_node"] = args.operator_node
        profile["_operator_token"] = operator_token
    registry = load_registry(
        args.workload_registry,
        trusted_public_key=read_public_key(args.registry_public_key),
        expected_chain_id=str(profile["chain_id"]),
        expected_genesis_hash=str(profile["genesis_hash"]),
        height=int(live_status(profile)["unsafe_head"]["height"]),
    )
    market = Market(
        profile,
        read_seed(args.seed_file),
        args.account,
        args.index,
        Path(args.database),
        token,
        registry,
    )
    host, port_text = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    server.market = market  # type: ignore[attr-defined]
    print(json.dumps({
        "listen": args.listen,
        "requester": market.requester,
        "chain": market.profile["chain_id"],
        "workload_registry": registry.registry_id,
        "registry_signer_key_id": registry.signer_key_id,
    }, indent=2), flush=True)
    try:
        server.serve_forever()
    finally:
        market.identity.close()
        market.db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
