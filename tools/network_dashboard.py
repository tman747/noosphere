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
VALIDATOR_STATUS_SCHEMA = "noos/network-dashboard-validator-status/v1"
VALIDATOR_CONFIG_SCHEMA = "noos/network-dashboard-validator-config/v1"


def http_json(url: str, token: str | None = None, timeout: float = 3.0) -> dict[str, Any]:
    headers = {"Accept": "application/json", "User-Agent": "MindChain-Network-Dashboard/1.0"}
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

def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_secret_token(path: Path) -> str:
    raw = path.read_text(encoding="utf-8").strip()
    if raw.startswith("{"):
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError(f"{path} must contain an object or a raw token")
        raw = str(value.get("rpc_token", "")).strip()
    if len(raw) < 24 or any(character.isspace() for character in raw):
        raise ValueError(f"{path} contains a malformed RPC token")
    return raw


def source_label(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or "source"


class DashboardData:
    def __init__(
        self,
        operator: str,
        operator_token: str,
        indexer: str,
        compute: str | None,
        database: Path,
        *,
        deployment: dict[str, Any] | None = None,
        local_validators: list[dict[str, Any]] | None = None,
        public_base_url: str | None = None,
    ):
        self.operator = operator.rstrip("/")
        self.operator_token = operator_token
        self.indexer = indexer.rstrip("/")
        self.compute = (compute or "").rstrip("/")
        self.deployment = deployment or {}
        self.public_base_url = (public_base_url or "").rstrip("/")
        configured_seeds = self.deployment.get("public_seeds")
        seeds = configured_seeds if isinstance(configured_seeds, list) else []
        self.expected_validators = {
            int_value(seed.get("witness_index"), -1): {
                key: seed.get(key)
                for key in ("witness_index", "role", "machine", "region", "zone", "vm_size", "hostname")
            }
            for seed in seeds
            if isinstance(seed, dict) and int_value(seed.get("witness_index"), -1) >= 0
        }
        configured_indexers = self.deployment.get("public_indexers")
        endpoints = configured_indexers.get("endpoints") if isinstance(configured_indexers, dict) else []
        self.indexer_endpoints = [endpoint for endpoint in endpoints if isinstance(endpoint, dict)]
        configured_public = self.deployment.get("public_endpoints")
        self.gateway = str(configured_public.get("read_gateway", "")).rstrip("/") if isinstance(configured_public, dict) else ""
        self.local_validators = local_validators or [{
            "witness_index": 0,
            "role": "producer-witness",
            "machine": "operator",
            "rpc": self.operator,
            "token": self.operator_token,
        }]
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
        self.latest_local_validator_status: dict[str, Any] | None = None
        self.stop = threading.Event()

    def operator_json(self, path: str) -> dict[str, Any]:
        return http_json(self.operator + path, self.operator_token)

    def indexer_json(self, path: str) -> dict[str, Any]:
        return http_json(self.indexer + path)

    def compute_json(self, path: str) -> dict[str, Any]:
        return http_json(self.compute + path)

    def _chain_binding(self) -> tuple[str | None, str | None]:
        binding = self.deployment.get("chain_binding")
        if not isinstance(binding, dict):
            return None, None
        return str(binding.get("chain_id") or "") or None, str(binding.get("genesis_hash") or "") or None

    def local_validator_status(self, *, refresh: bool = False) -> dict[str, Any]:
        if not refresh:
            with self.lock:
                cached = self.latest_local_validator_status
            if cached is not None:
                return cached
        chain_id, genesis_hash = self._chain_binding()
        observed_ms = int(time.time() * 1000)
        validators: list[dict[str, Any]] = []
        for source in self.local_validators:
            index = int_value(source.get("witness_index"), -1)
            metadata = dict(self.expected_validators.get(index, {}))
            metadata.update({
                key: source.get(key)
                for key in ("witness_index", "role", "machine", "region", "zone", "vm_size", "hostname")
                if source.get(key) is not None
            })
            status, error = source_result(
                str(source.get("rpc", "")).rstrip("/") + "/status",
                str(source.get("token", "")),
            )
            valid = bool(status)
            if status and chain_id and status.get("chain_id") != chain_id:
                valid = False
                error = "chain binding mismatch"
            if status and genesis_hash and status.get("genesis_hash") != genesis_hash:
                valid = False
                error = "genesis binding mismatch"
            validator = {
                **metadata,
                "witness_index": index,
                "state": "online" if valid else "offline",
                "observed_ms": observed_ms,
            }
            if valid and status:
                for key in ("unsafe_head", "justified", "finalized", "mempool", "finality_gossip", "observer"):
                    validator[key] = status.get(key)
            elif error:
                validator["error"] = "operator status unavailable"
            validators.append(validator)
        document = {
            "schema": VALIDATOR_STATUS_SCHEMA,
            "environment": "public-testnet",
            "production": False,
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "observed_ms": observed_ms,
            "validators": validators,
        }
        with self.lock:
            self.latest_local_validator_status = document
        return document

    def validator_fleet(self, errors: dict[str, str]) -> list[dict[str, Any]]:
        local_document = self.local_validator_status(refresh=True)
        documents = [local_document]
        for endpoint in self.indexer_endpoints:
            base_url = str(endpoint.get("base_url", "")).rstrip("/")
            if not base_url or base_url == self.public_base_url:
                continue
            document, error = source_result(base_url + "/validator-status.json")
            label = source_label(base_url).replace(".", "_")
            if error:
                errors[f"validator_feed_{label}"] = "unavailable"
                continue
            if (
                not document
                or document.get("schema") != VALIDATOR_STATUS_SCHEMA
                or document.get("production") is not False
                or document.get("chain_id") != local_document.get("chain_id")
                or document.get("genesis_hash") != local_document.get("genesis_hash")
            ):
                errors[f"validator_feed_{label}"] = "invalid response"
                continue
            documents.append(document)

        merged: dict[int, dict[str, Any]] = {}
        for document in documents:
            validators = document.get("validators")
            if not isinstance(validators, list):
                continue
            for validator in validators:
                if not isinstance(validator, dict):
                    continue
                index = int_value(validator.get("witness_index"), -1)
                if index < 0:
                    continue
                previous = merged.get(index)
                if previous is None or int_value(validator.get("observed_ms")) >= int_value(previous.get("observed_ms")):
                    merged[index] = validator
        for index, metadata in self.expected_validators.items():
            if index not in merged:
                merged[index] = {
                    **metadata,
                    "witness_index": index,
                    "state": "unreported",
                    "observed_ms": None,
                }
        fleet = [dict(merged[index]) for index in sorted(merged)]
        maximum_height = max(
            (
                int_value((validator.get("unsafe_head") or {}).get("height"))
                for validator in fleet
                if validator.get("state") == "online" and isinstance(validator.get("unsafe_head"), dict)
            ),
            default=0,
        )
        for validator in fleet:
            unsafe_head = validator.get("unsafe_head")
            if validator.get("state") != "online" or not isinstance(unsafe_head, dict):
                continue
            head_lag = max(0, maximum_height - int_value(unsafe_head.get("height")))
            validator["head_lag"] = head_lag
            if head_lag > EPOCH_LENGTH:
                validator["state"] = "catching_up"
        return fleet

    def indexer_fleet(
        self,
        local_status: dict[str, Any] | None,
        errors: dict[str, str],
    ) -> list[dict[str, Any]]:
        if not self.indexer_endpoints:
            return [{
                "base_url": self.indexer,
                "state": "online" if local_status else "offline",
                "ready": bool((local_status or {}).get("ready")),
                "unsafe_height": int_value(((local_status or {}).get("unsafe_head") or {}).get("height")),
                "finalized_height": int_value(((local_status or {}).get("finalized") or {}).get("height")),
            }]
        chain_id, genesis_hash = self._chain_binding()
        fleet: list[dict[str, Any]] = []
        for endpoint in self.indexer_endpoints:
            base_url = str(endpoint.get("base_url", "")).rstrip("/")
            status = local_status if base_url == self.public_base_url else None
            if status is None:
                status, error = source_result(base_url + "/api/status")
                if error:
                    errors[f"indexer_{source_label(base_url).replace('.', '_')}"] = "unavailable"
            valid = bool(status)
            if status and chain_id and status.get("chain_id") != chain_id:
                valid = False
            if status and genesis_hash and status.get("genesis_hash") != genesis_hash:
                valid = False
            freshness_ms = int_value((status or {}).get("freshness_ms"), -1)
            if freshness_ms >= 2**63:
                freshness_ms = -1
            fleet.append({
                "base_url": base_url,
                "endpoint_id": endpoint.get("endpoint_id"),
                "failure_domain": endpoint.get("failure_domain"),
                "state": "online" if valid and status.get("ready") is True else "catching_up" if valid else "offline",
                "ready": bool(valid and status.get("ready") is True),
                "readiness": status.get("readiness") if valid else None,
                "unsafe_height": int_value(((status or {}).get("unsafe_head") or {}).get("height")),
                "justified_height": int_value(((status or {}).get("justified") or {}).get("height")),
                "finalized_height": int_value(((status or {}).get("finalized") or {}).get("height")),
                "freshness_ms": freshness_ms,
            })
        return fleet

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
        compute_health: dict[str, Any] | None = None
        if self.compute:
            compute_health, error = source_result(self.compute + "/api/health")
            if error:
                errors["compute"] = error
        gateway_health: dict[str, Any] | None = None
        if self.gateway:
            gateway_health, error = source_result(self.gateway + "/healthz")
            if error:
                errors["gateway"] = "unavailable"
        validators = self.validator_fleet(errors)
        indexers = self.indexer_fleet(indexer_status, errors)

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
            "gateway_health": gateway_health,
            "validators": validators,
            "indexers": indexers,
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
        validators = snapshot.get("validators") or []
        indexers = snapshot.get("indexers") or []
        gateway = snapshot.get("gateway_health") or {}
        current_epoch = sample["height"] // EPOCH_LENGTH if sample["height"] else 0
        online_validators = sum(validator.get("state") == "online" for validator in validators)
        producer_online = any(
            int_value(validator.get("witness_index"), -1) == 0 and validator.get("state") == "online"
            for validator in validators
        )
        expected_validators = len(self.expected_validators) or len(validators)
        quorum_threshold = 3 if expected_validators >= 4 else max(1, expected_validators)
        ready_indexers = sum(indexer.get("ready") is True for indexer in indexers)
        public_indexers = self.deployment.get("public_indexers")
        indexer_quorum = int_value(
            public_indexers.get("minimum_control_cluster_quorum") if isinstance(public_indexers, dict) else None,
            1,
        )
        finality_lag = max(0, current_epoch - sample["finalized_epoch"])
        gateway_unsafe = gateway.get("unsafe_head") if isinstance(gateway.get("unsafe_head"), dict) else {}
        gateway_height = int_value(gateway_unsafe.get("height"), -1)
        gateway_lag = (
            max(0, sample["height"] - gateway_height)
            if sample["height"] and gateway_height >= 0
            else None
        )
        gateway_ready = gateway.get("status") == "ok"
        gateway_current = gateway_ready and (gateway_lag is None or gateway_lag <= EPOCH_LENGTH)
        services = [
            {
                "name": "Validator quorum",
                "state": "online" if online_validators >= quorum_threshold else "offline" if online_validators == 0 else "degraded",
                "detail": f"{online_validators}/{expected_validators or '—'} reporters · threshold {quorum_threshold}",
            },
            {
                "name": "Public indexer quorum",
                "state": "online" if ready_indexers >= indexer_quorum else "degraded",
                "detail": f"{ready_indexers}/{len(indexers)} ready · threshold {indexer_quorum}",
            },
            {
                "name": "Observer read gateway",
                "state": "online" if gateway_current else "unreported" if not self.gateway else "degraded",
                "detail": (
                    f"{self.gateway} · H{gateway_height:,} · {gateway_lag:,} blocks behind"
                    if gateway_ready and gateway_lag is not None
                    else self.gateway or "not configured"
                ),
            },
            {
                "name": "Compute coordinator",
                "state": "online" if (snapshot.get("compute_health") or {}).get("ok") else "unreported" if not self.compute else "degraded",
                "detail": self.compute or "not centrally reported",
            },
            {
                "name": "Consensus finality",
                "state": "stalled" if not producer_online or (current_epoch >= 2 and (sample["finalized_epoch"] == 0 or finality_lag > 3)) else "online",
                "detail": f"{'producer unavailable · ' if not producer_online else ''}justified E{sample['justified_epoch']} · finalized E{sample['finalized_epoch']}",
            },
        ]
        topology_nodes = [{
            "id": f"validator-{validator.get('witness_index')}",
            "label": f"W{validator.get('witness_index')}",
            "role": validator.get("role"),
            "state": validator.get("state"),
        } for validator in validators]
        topology_nodes.extend({
            "id": f"indexer-{index}",
            "label": f"IDX {index + 1}",
            "role": "public indexer",
            "state": indexer.get("state"),
        } for index, indexer in enumerate(indexers))
        topology_nodes.extend([
            {"id": "finality", "label": "Finality", "role": "3-of-4 quorum", "state": services[4]["state"]},
            {"id": "gateway", "label": "Observer", "role": "public read gateway", "state": services[2]["state"]},
        ])
        topology_edges = [
            [node["id"], "finality"]
            for node in topology_nodes
            if str(node["id"]).startswith("validator-")
        ]
        topology_edges.extend(
            [["finality", node["id"]]
             for node in topology_nodes
             if str(node["id"]).startswith("indexer-")]
        )
        topology_edges.append(["finality", "gateway"])
        return {
            "schema": "noos/network-dashboard-overview/v1",
            "observed_ms": sample["observed_ms"],
            "environment": "public-testnet",
            "production": False,
            "chain": {
                "height": sample["height"], "slot": sample["slot"], "current_epoch": current_epoch,
                "justified_epoch": sample["justified_epoch"], "finalized_epoch": sample["finalized_epoch"],
                "justification_lag": max(0, current_epoch - sample["justified_epoch"]),
                "finalization_lag": finality_lag,
                "mempool_transactions": sample["mempool_transactions"],
                "mempool_bytes": sample["mempool_bytes"],
                "chain_id": snapshot["operator"].get("chain_id"),
                "genesis_hash": snapshot["operator"].get("genesis_hash"),
            },
            "history": history,
            "services": services,
            "validators": validators,
            "indexers": indexers,
            "gateway": gateway,
            "topology": {"nodes": topology_nodes, "edges": topology_edges},
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
        gossip = snapshot["operator"].get("finality_gossip")
        validators = snapshot.get("validators") or []
        if isinstance(gossip, dict):
            quorum_telemetry = {
                "state": "reported",
                "threshold": 3,
                "total_validators": len(self.expected_validators) or len(validators),
                "online_validators": sum(validator.get("state") == "online" for validator in validators),
                "pending_votes": int_value(gossip.get("pending_votes")),
                "pending_certificates": int_value(gossip.get("pending_certificates")),
                "accepted": int_value(gossip.get("accepted")),
                "rejected": int_value(gossip.get("rejected")),
            }
        else:
            quorum_telemetry = {
                "state": "unavailable",
                "reason": "This node binary does not report finality gossip counters.",
            }
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
            "quorum_telemetry": quorum_telemetry,
            "chain_id": snapshot["operator"].get("chain_id"),
            "genesis_hash": snapshot["operator"].get("genesis_hash"),
            "environment": "public-testnet",
            "production": False,
            "validators": validators,
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
        validator_nodes = []
        for validator in snapshot.get("validators") or []:
            index = int_value(validator.get("witness_index"), -1)
            unsafe_head = validator.get("unsafe_head") if isinstance(validator.get("unsafe_head"), dict) else {}
            justified = validator.get("justified") if isinstance(validator.get("justified"), dict) else {}
            finalized = validator.get("finalized") if isinstance(validator.get("finalized"), dict) else {}
            validator_nodes.append({
                "id": f"validator-{index}",
                "kind": "validator",
                "label": validator.get("machine") or f"Witness {index}",
                "role": validator.get("role") or f"witness {index}",
                "witness_index": index,
                "state": validator.get("state") or "unreported",
                "height": int_value(unsafe_head.get("height")) if unsafe_head else None,
                "head_hash": unsafe_head.get("hash"),
                "head_lag": validator.get("head_lag"),
                "justified_epoch": int_value(justified.get("epoch")) if justified else None,
                "finalized_epoch": int_value(finalized.get("epoch")) if finalized else None,
                "observer": validator.get("observer"),
                "last_report_ms": validator.get("observed_ms") if validator.get("state") in {"online", "catching_up"} else None,
                "region": validator.get("region"),
                "zone": validator.get("zone"),
                "vm_size": validator.get("vm_size"),
                "architecture": None,
                "capacity": None,
                "finality_gossip": validator.get("finality_gossip"),
                "telemetry_state": "sanitized_operator_status",
            })
        observer_nodes: list[dict[str, Any]] = []
        gateway = snapshot.get("gateway_health") or {}
        if self.gateway:
            unsafe_head = gateway.get("unsafe_head") if isinstance(gateway.get("unsafe_head"), dict) else {}
            finalized = gateway.get("finalized") if isinstance(gateway.get("finalized"), dict) else {}
            gateway_height = int_value(unsafe_head.get("height"), -1)
            network_height = int_value(snapshot["sample"].get("height"))
            gateway_lag = max(0, network_height - gateway_height) if network_height and gateway_height >= 0 else None
            gateway_ready = gateway.get("status") == "ok"
            gateway_state = (
                "online"
                if gateway_ready and (gateway_lag is None or gateway_lag <= EPOCH_LENGTH)
                else "catching_up" if gateway_ready else "degraded"
            )
            observer_nodes.append({
                "id": "public-observer",
                "kind": "observer",
                "label": "Public read gateway",
                "role": "non-voting observer",
                "state": gateway_state,
                "height": gateway_height if gateway_height >= 0 else None,
                "head_hash": unsafe_head.get("hash"),
                "finalized_epoch": int_value(finalized.get("epoch")) if finalized else None,
                "head_lag": gateway_lag,
                "last_report_ms": snapshot["sample"]["observed_ms"] if gateway.get("status") == "ok" else None,
                "capacity": None,
                "telemetry_state": "public_gateway_health",
            })
        worker_nodes = [
            {
                "id": worker.get("worker"), "kind": "compute", "label": str(worker.get("worker", ""))[:12],
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
        incidents.extend({
            "source": f"witness_{node['witness_index']}",
            "state": "active",
            "detail": f"{node['label']} status is {node['state']}",
        } for node in validator_nodes if node["state"] != "online")
        incidents.extend({
            "source": f"indexer_{index + 1}",
            "state": "active",
            "detail": f"{indexer.get('base_url')} is {indexer.get('state')}",
        } for index, indexer in enumerate(snapshot.get("indexers") or []) if indexer.get("state") != "online")
        incidents.extend({
            "source": "observer",
            "state": "active",
            "detail": f"{node['label']} is {node['state']} · {node['head_lag']:,} blocks behind",
        } for node in observer_nodes if node["state"] != "online" and node["head_lag"] is not None)
        if current_epoch >= 2 and sample["finalized_epoch"] == 0:
            incidents.append({
                "source": "finality",
                "state": "active",
                "detail": f"finalized checkpoint remains at genesis while head is in epoch {current_epoch}",
            })
        missing = sum(node["state"] != "online" for node in validator_nodes)
        return {
            "schema": "noos/network-dashboard-nodes/v1",
            "observed_ms": snapshot["sample"]["observed_ms"],
            "environment": "public-testnet",
            "production": False,
            "nodes": [*validator_nodes, *observer_nodes, *worker_nodes],
            "validators": validator_nodes,
            "indexers": snapshot.get("indexers") or [],
            "unreported": {
                "count": missing,
                "message": "Missing validator reports remain explicit; no state is inferred from topology.",
            },
            "incidents": incidents,
            "errors": snapshot["errors"],
        }


class Handler(BaseHTTPRequestHandler):
    @property
    def data(self) -> DashboardData:
        return self.server.data  # type: ignore[attr-defined]

    @property
    def app_dir(self) -> Path:
        return self.server.app_dir  # type: ignore[attr-defined]

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def json_response(self, value: dict[str, Any], status: int = 200) -> None:
        self.send_body(status, json.dumps(value, separators=(",", ":")).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlsplit(self.path).path
        try:
            if path == "/api/health":
                self.json_response({"ok": True, "schema": "noos/network-dashboard-health/v1"})
            elif path == "/validator-status.json":
                self.json_response(self.data.local_validator_status())
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
                file = (self.app_dir / relative).resolve()
                if self.app_dir.resolve() not in file.parents or not file.is_file():
                    self.json_response({"error": "not_found"}, 404)
                    return
                content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                self.send_body(200, file.read_bytes(), content_type)
        except Exception as error:
            self.json_response({"error": "unavailable", "detail": str(error)}, 503)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def log_message(self, pattern: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operator-node", required=True)
    parser.add_argument("--operator-secret", type=Path, required=True)
    parser.add_argument("--indexer", required=True)
    parser.add_argument("--compute", default="")
    parser.add_argument("--deployment", type=Path)
    parser.add_argument("--validator-config", type=Path)
    parser.add_argument("--app-dir", type=Path, default=APP)
    parser.add_argument("--database", type=Path, default=Path.home() / ".mindchain-network-dashboard.sqlite3")
    parser.add_argument("--listen", default="127.0.0.1:18120")
    args = parser.parse_args()
    token = load_secret_token(args.operator_secret)
    deployment = load_json_object(args.deployment) if args.deployment else None
    local_validators: list[dict[str, Any]] | None = None
    public_base_url: str | None = None
    if args.validator_config:
        validator_config = load_json_object(args.validator_config)
        if validator_config.get("schema") != VALIDATOR_CONFIG_SCHEMA:
            raise SystemExit("validator config schema is unsupported")
        public_base_url = str(validator_config.get("public_base_url", "")).rstrip("/")
        configured = validator_config.get("validators")
        if not isinstance(configured, list) or not configured:
            raise SystemExit("validator config must define at least one validator")
        local_validators = []
        for validator in configured:
            if not isinstance(validator, dict):
                raise SystemExit("validator config entries must be objects")
            rpc = str(validator.get("rpc", "")).rstrip("/")
            parsed_rpc = urllib.parse.urlsplit(rpc)
            if (
                parsed_rpc.scheme != "http"
                or parsed_rpc.hostname not in {"127.0.0.1", "::1", "localhost"}
                or parsed_rpc.path
                or parsed_rpc.query
                or parsed_rpc.fragment
            ):
                raise SystemExit("validator RPC endpoints must be exact loopback HTTP origins")
            token_file = Path(str(validator.get("token_file", "")))
            local_validators.append({
                **{
                    key: validator.get(key)
                    for key in ("witness_index", "role", "machine", "region", "zone", "vm_size", "hostname")
                },
                "rpc": rpc,
                "token": load_secret_token(token_file),
            })
    app_dir = args.app_dir.resolve(strict=True)
    database = args.database.resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    data = DashboardData(
        args.operator_node,
        token,
        args.indexer,
        args.compute,
        database,
        deployment=deployment,
        local_validators=local_validators,
        public_base_url=public_base_url,
    )
    thread = threading.Thread(target=data.sampler, name="network-dashboard-sampler", daemon=True)
    thread.start()
    host, port_text = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    server.data = data  # type: ignore[attr-defined]
    server.app_dir = app_dir  # type: ignore[attr-defined]
    print(json.dumps({"listen": args.listen, "schema": "noos/network-dashboard/v1"}), flush=True)
    try:
        server.serve_forever()
    finally:
        data.stop.set()
        thread.join(timeout=5)
        data.db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
