#!/usr/bin/env python3
"""MindChain network, consensus, compute, and node-fleet dashboard service."""

from __future__ import annotations

import argparse
import json
import mimetypes
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps" / "network-dashboard"
EPOCH_LENGTH = 256
SAMPLE_SECONDS = 3.0
MAX_HISTORY = 2_880


def http_json(url: str, token: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError(f"{url} returned a non-object response")
    return value


def source_result(url: str, token: str | None = None) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return http_json(url, token), None
    except (OSError, ValueError, urllib.error.HTTPError, urllib.error.URLError) as error:
        return None, str(error)


def int_value(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class DashboardData:
    def __init__(self, operator: str, operator_token: str, indexer: str, compute: str, database: Path):
        self.operator = operator.rstrip("/")
        self.operator_token = operator_token
        self.indexer = indexer.rstrip("/")
        self.compute = compute.rstrip("/")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(database, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS samples (
                observed_ms INTEGER PRIMARY KEY,
                height INTEGER NOT NULL,
                slot INTEGER,
                block_transactions INTEGER NOT NULL,
                mempool_transactions INTEGER NOT NULL,
                mempool_bytes INTEGER NOT NULL,
                justified_epoch INTEGER NOT NULL,
                finalized_epoch INTEGER NOT NULL,
                active_workers INTEGER NOT NULL,
                total_worker_threads INTEGER NOT NULL,
                completed_units INTEGER NOT NULL,
                settled_jobs INTEGER NOT NULL,
                active_escrow TEXT NOT NULL
            )"""
        )
        self.db.commit()
        self.latest: dict[str, Any] | None = None
        self.latest_errors: dict[str, str] = {}
        self.blocks_cache: tuple[int, float, list[dict[str, Any]]] | None = None
        self.stop = threading.Event()

    def operator_json(self, path: str) -> dict[str, Any]:
        return http_json(self.operator + path, self.operator_token)

    def indexer_json(self, path: str) -> dict[str, Any]:
        return http_json(self.indexer + path)

    def compute_json(self, path: str) -> dict[str, Any]:
        return http_json(self.compute + path)

    def collect(self) -> dict[str, Any]:
        errors: dict[str, str] = {}
        status, error = source_result(self.operator + "/status", self.operator_token)
        if error:
            errors["operator"] = error
        status = status or {}
        height = int_value((status.get("unsafe_head") or {}).get("height"))
        block: dict[str, Any] = {}
        if height:
            block, error = source_result(self.operator + f"/block/{height}", self.operator_token)
            if error:
                errors["block"] = error
            block = block or {}

        workers, error = source_result(self.indexer + "/api/v1/workers")
        if error:
            errors["workers"] = error
        jobs, error = source_result(self.indexer + "/api/v1/jobs")
        if error:
            errors["jobs"] = error
        indexer_status, error = source_result(self.indexer + "/api/status")
        if error:
            errors["indexer"] = error
        compute_health, error = source_result(self.compute + "/api/health")
        if error:
            errors["compute"] = error

        worker_items = (workers or {}).get("items", [])
        job_items = (jobs or {}).get("items", [])
        if not isinstance(worker_items, list):
            worker_items = []
        if not isinstance(job_items, list):
            job_items = []
        active_workers = [item for item in worker_items if int_value(item.get("active")) == 1]
        completed_units = sum(int_value(item.get("units_completed")) for item in worker_items)
        settled_jobs = sum(1 for item in job_items if int_value(item.get("state"), -1) == 3)
        active_escrow = sum(int_value(item.get("escrow")) for item in job_items if int_value(item.get("state"), -1) < 3)
        justified_epoch = int_value((status.get("justified") or {}).get("epoch"))
        finalized_epoch = int_value((status.get("finalized") or {}).get("epoch"))
        mempool = status.get("mempool") if isinstance(status.get("mempool"), dict) else {}
        observed_ms = int(time.time() * 1000)
        sample = {
            "observed_ms": observed_ms,
            "height": height,
            "slot": int_value(block.get("slot")) if block else None,
            "block_transactions": len(block.get("txids", [])) if isinstance(block.get("txids"), list) else 0,
            "mempool_transactions": int_value(mempool.get("txs")),
            "mempool_bytes": int_value(mempool.get("bytes")),
            "justified_epoch": justified_epoch,
            "finalized_epoch": finalized_epoch,
            "active_workers": len(active_workers),
            "total_worker_threads": sum(int_value(item.get("cpu_threads")) for item in active_workers),
            "completed_units": completed_units,
            "settled_jobs": settled_jobs,
            "active_escrow": str(active_escrow),
        }
        if height:
            with self.lock:
                self.db.execute(
                    "INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(sample.values()),
                )
                self.db.execute(
                    "DELETE FROM samples WHERE observed_ms NOT IN (SELECT observed_ms FROM samples ORDER BY observed_ms DESC LIMIT ?)",
                    (MAX_HISTORY,),
                )
                self.db.commit()
        snapshot = {
            "schema": "noos/network-dashboard-snapshot/v1",
            "sample": sample,
            "operator": status,
            "block": block,
            "workers": worker_items,
            "jobs": job_items,
            "indexer_status": indexer_status,
            "compute_health": compute_health,
            "errors": errors,
        }
        with self.lock:
            self.latest = snapshot
            self.latest_errors = errors
        return snapshot

    def sampler(self) -> None:
        while not self.stop.is_set():
            started = time.monotonic()
            self.collect()
            self.stop.wait(max(0.1, SAMPLE_SECONDS - (time.monotonic() - started)))

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            value = self.latest
        return value or self.collect()

    def history(self, limit: int = 240) -> list[dict[str, Any]]:
        limit = max(1, min(MAX_HISTORY, limit))
        with self.lock:
            rows = self.db.execute(
                """SELECT observed_ms,height,slot,block_transactions,mempool_transactions,mempool_bytes,
                          justified_epoch,finalized_epoch,active_workers,total_worker_threads,
                          completed_units,settled_jobs,active_escrow
                   FROM samples ORDER BY observed_ms DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        keys = [
            "observed_ms", "height", "slot", "block_transactions", "mempool_transactions",
            "mempool_bytes", "justified_epoch", "finalized_epoch", "active_workers",
            "total_worker_threads", "completed_units", "settled_jobs", "active_escrow",
        ]
        return [dict(zip(keys, row)) for row in reversed(rows)]

    def recent_blocks(self, limit: int = 64) -> list[dict[str, Any]]:
        limit = max(1, min(64, limit))
        snapshot = self.snapshot()
        head = int_value(snapshot["sample"].get("height"))
        if not head:
            return []
        now = time.monotonic()
        with self.lock:
            cached = self.blocks_cache
            if cached and cached[0] == head and now - cached[1] < 5:
                return cached[2][-limit:]
        start = max(1, head - limit + 1)
        blocks: list[dict[str, Any]] = []
        for height in range(start, head + 1):
            value, _ = source_result(self.operator + f"/block/{height}", self.operator_token)
            if value:
                blocks.append(value)
        with self.lock:
            self.blocks_cache = (head, now, blocks)
        return blocks

    def overview(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        sample = snapshot["sample"]
        history = self.history()
        current_epoch = sample["height"] // EPOCH_LENGTH if sample["height"] else 0
        services = [
            {"name": "Producer RPC", "state": "online" if snapshot["operator"] else "offline", "detail": self.operator},
            {"name": "Public indexer", "state": "degraded" if "indexer" in snapshot["errors"] or int_value(((snapshot.get("indexer_status") or {}).get("unsafe_head") or {}).get("height")) < sample["height"] else "online", "detail": self.indexer},
            {"name": "Compute coordinator", "state": "online" if (snapshot.get("compute_health") or {}).get("ok") else "upgrade_required" if snapshot.get("compute_health") else "offline", "detail": self.compute},
            {
                "name": "Consensus finality",
                "state": "stalled" if current_epoch >= 2 and sample["finalized_epoch"] == 0 else "online",
                "detail": f"justified E{sample['justified_epoch']} · finalized E{sample['finalized_epoch']}",
            },
        ]
        return {
            "schema": "noos/network-dashboard-overview/v1",
            "observed_ms": sample["observed_ms"],
            "chain": {
                "height": sample["height"], "slot": sample["slot"], "current_epoch": current_epoch,
                "justified_epoch": sample["justified_epoch"], "finalized_epoch": sample["finalized_epoch"],
                "justification_lag": max(0, current_epoch - sample["justified_epoch"]),
                "finalization_lag": max(0, current_epoch - sample["finalized_epoch"]),
                "mempool_transactions": sample["mempool_transactions"],
                "mempool_bytes": sample["mempool_bytes"],
                "chain_id": snapshot["operator"].get("chain_id"),
                "genesis_hash": snapshot["operator"].get("genesis_hash"),
            },
            "history": history,
            "services": services,
            "topology": {
                "nodes": [
                    {"id": "producer", "label": "Producer", "role": "producer / witness 0", "state": services[0]["state"]},
                    {"id": "indexer", "label": "Indexer", "role": "public query", "state": services[1]["state"]},
                    {"id": "compute", "label": "Compute", "role": "escrow coordinator", "state": services[2]["state"]},
                    {"id": "peers", "label": "Peer telemetry", "role": "awaiting central reports", "state": "unreported"},
                ],
                "edges": [["producer", "indexer"], ["indexer", "compute"], ["producer", "peers"]],
            },
            "errors": snapshot["errors"],
        }

    def consensus(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        sample = snapshot["sample"]
        blocks = self.recent_blocks()
        current_epoch = sample["height"] // EPOCH_LENGTH if sample["height"] else 0
        cadences = [
            max(0, int_value(right.get("timestamp_ms")) - int_value(left.get("timestamp_ms")))
            for left, right in zip(blocks, blocks[1:])
            if int_value(right.get("timestamp_ms")) >= int_value(left.get("timestamp_ms"))
        ]
        return {
            "schema": "noos/network-dashboard-consensus/v1",
            "observed_ms": sample["observed_ms"],
            "height": sample["height"],
            "slot": sample["slot"],
            "current_epoch": current_epoch,
            "epoch_progress": (sample["height"] % EPOCH_LENGTH) / EPOCH_LENGTH if sample["height"] else 0,
            "justified_epoch": sample["justified_epoch"],
            "finalized_epoch": sample["finalized_epoch"],
            "justification_lag": max(0, current_epoch - sample["justified_epoch"]),
            "finalization_lag": max(0, current_epoch - sample["finalized_epoch"]),
            "unsafe_head": snapshot["operator"].get("unsafe_head"),
            "justified": snapshot["operator"].get("justified"),
            "finalized": snapshot["operator"].get("finalized"),
            "blocks": blocks,
            "median_block_cadence_ms": sorted(cadences)[len(cadences) // 2] if cadences else None,
            "quorum_telemetry": {"state": "unavailable", "reason": "central vote participation telemetry is not reported"},
            "chain_id": snapshot["operator"].get("chain_id"),
            "genesis_hash": snapshot["operator"].get("genesis_hash"),
            "errors": snapshot["errors"],
        }

    def compute_economy(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        workers = snapshot["workers"]
        jobs = snapshot["jobs"]
        states = Counter(int_value(job.get("state"), -1) for job in jobs)
        active = [worker for worker in workers if int_value(worker.get("active")) == 1]
        settled_value = sum(
            int_value(job.get("agreed_price_per_unit")) * int_value(job.get("completed_units"))
            for job in jobs if int_value(job.get("state"), -1) == 3
        )
        return {
            "schema": "noos/network-dashboard-compute/v1",
            "observed_ms": snapshot["sample"]["observed_ms"],
            "supply": {
                "active_workers": len(active),
                "cpu_threads": sum(int_value(worker.get("cpu_threads")) for worker in active),
                "memory_mb": sum(int_value(worker.get("memory_mb")) for worker in active),
                "gpu_workers": sum(1 for worker in active if int_value(worker.get("capabilities")) & 2),
                "completed_units": sum(int_value(worker.get("units_completed")) for worker in workers),
            },
            "jobs_by_state": {
                "open": states[0], "claimed": states[1], "submitted": states[2], "settled": states[3], "cancelled": states[4],
            },
            "active_escrow": str(sum(int_value(job.get("escrow")) for job in jobs if int_value(job.get("state"), -1) < 3)),
            "settled_value": str(settled_value),
            "workers": workers,
            "jobs": jobs,
            "history": self.history(),
            "currency": "micro-NOOS_TEST",
            "disclosure": "Engineering test-token accounting; browser helper identity is coordinator-custodial.",
            "errors": snapshot["errors"],
        }

    def node_fleet(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        status = snapshot["operator"]
        producer = {
            "id": "producer",
            "label": "LAN producer",
            "role": "producer / witness 0",
            "state": "online" if status else "offline",
            "height": snapshot["sample"]["height"],
            "head_hash": (status.get("unsafe_head") or {}).get("hash"),
            "observer": status.get("observer"),
            "last_report_ms": snapshot["sample"]["observed_ms"],
            "architecture": None,
            "capacity": None,
            "telemetry_state": "operator_status_only",
        }
        worker_nodes = [
            {
                "id": worker.get("worker"), "label": str(worker.get("worker", ""))[:12],
                "role": "compute worker", "state": "online" if int_value(worker.get("active")) else "offline",
                "height": None, "head_hash": None, "last_report_ms": None,
                "architecture": None,
                "capacity": {
                    "cpu_threads": int_value(worker.get("cpu_threads")),
                    "memory_mb": int_value(worker.get("memory_mb")),
                    "gpu_memory_mb": int_value(worker.get("gpu_memory_mb")),
                    "capabilities": int_value(worker.get("capabilities")),
                },
                "telemetry_state": "on_chain_capability_only",
            }
            for worker in snapshot["workers"]
        ]
        sample = snapshot["sample"]
        current_epoch = sample["height"] // EPOCH_LENGTH if sample["height"] else 0
        incidents = [
            {"source": source, "state": "active", "detail": detail}
            for source, detail in snapshot["errors"].items()
        ]
        if current_epoch >= 2 and sample["finalized_epoch"] == 0:
            incidents.append({
                "source": "finality",
                "state": "active",
                "detail": f"finalized checkpoint remains at genesis while head is in epoch {current_epoch}",
            })
        return {
            "schema": "noos/network-dashboard-nodes/v1",
            "observed_ms": snapshot["sample"]["observed_ms"],
            "nodes": [producer, *worker_nodes],
            "unreported": {
                "count": None,
                "message": "The Mac node is online locally but does not yet publish central fleet telemetry.",
            },
            "incidents": incidents,
            "errors": snapshot["errors"],
        }


class Handler(BaseHTTPRequestHandler):
    @property
    def data(self) -> DashboardData:
        return self.server.data  # type: ignore[attr-defined]

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, value: dict[str, Any], status: int = 200) -> None:
        self.send_body(status, json.dumps(value, separators=(",", ":")).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        try:
            if path == "/api/health":
                self.json_response({"ok": True, "schema": "noos/network-dashboard-health/v1"})
            elif path == "/api/overview":
                self.json_response(self.data.overview())
            elif path == "/api/consensus":
                self.json_response(self.data.consensus())
            elif path == "/api/compute":
                self.json_response(self.data.compute_economy())
            elif path == "/api/nodes":
                self.json_response(self.data.node_fleet())
            elif path.startswith("/api/"):
                self.json_response({"error": "not_found"}, 404)
            else:
                relative = "index.html" if path in {"", "/"} else path.lstrip("/")
                file = (APP / relative).resolve()
                if APP.resolve() not in file.parents or not file.is_file():
                    self.json_response({"error": "not_found"}, 404)
                    return
                content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                self.send_body(200, file.read_bytes(), content_type)
        except Exception as error:
            self.json_response({"error": "unavailable", "detail": str(error)}, 503)

    def log_message(self, pattern: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-node", required=True)
    parser.add_argument("--operator-secret", required=True)
    parser.add_argument("--indexer", required=True)
    parser.add_argument("--compute", required=True)
    parser.add_argument("--database", default=str(Path.home() / ".mindchain-network-dashboard.sqlite3"))
    parser.add_argument("--listen", default="127.0.0.1:18120")
    args = parser.parse_args()
    secret = json.loads(Path(args.operator_secret).read_text(encoding="utf-8"))
    token = str(secret.get("rpc_token", ""))
    if len(token) < 24:
        raise SystemExit("operator secret is malformed")
    data = DashboardData(args.operator_node, token, args.indexer, args.compute, Path(args.database))
    thread = threading.Thread(target=data.sampler, name="network-dashboard-sampler", daemon=True)
    thread.start()
    host, port_text = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    server.data = data  # type: ignore[attr-defined]
    print(json.dumps({"listen": args.listen, "schema": "noos/network-dashboard/v1"}), flush=True)
    try:
        server.serve_forever()
    finally:
        data.stop.set()
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
