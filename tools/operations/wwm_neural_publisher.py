#!/usr/bin/env python3
"""Publish resumable, finalized Bonsai inference pulses to the neural explorer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import wwm_hosted_model_demo as demo

STATE_SCHEMA = "noos/wwm-neural-publisher-state/v1"
EVIDENCE_SCHEMA = "noos/wwm-neural-pulse-evidence/v1"
MANIFEST_SCHEMA = "noos/neural-explorer-manifest/v3"
MAX_MANIFEST_BYTES = 1_048_576
MAX_STATE_BYTES = 4_194_304
MAX_ACTIVITY = 32
PROMPT_INPUT_TOKENS = 4


class PublisherError(RuntimeError):
    """Fail-closed neural publisher error."""


@dataclass(frozen=True)
class PublisherConfig:
    hosted_config: Path
    manifest: Path
    state: Path
    evidence_dir: Path
    minimum_seconds: int
    minimum_finalized_advance: int
    poll_seconds: int


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise PublisherError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PublisherError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise PublisherError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def bounded_object(path: Path, maximum: int, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PublisherError(f"{label} is missing or symbolic: {path}")
    size = path.stat().st_size
    if size <= 0 or size > maximum:
        raise PublisherError(f"{label} size is outside the accepted bound")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise PublisherError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise PublisherError(f"{label} must be a JSON object")
    return value


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    demo.atomic_write(path, (json.dumps(value, indent=2, sort_keys=False) + "\n").encode())


def canonical_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or demo.HEX32.fullmatch(value) is None:
        raise PublisherError(f"{label} must be canonical lowercase hex32")
    return value


def positive_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PublisherError(f"{label} must be a positive integer")
    return value


def validate_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != MANIFEST_SCHEMA:
        raise PublisherError("unsupported neural explorer manifest schema")
    if (
        value.get("environment") != "public-testnet"
        or value.get("production") is not False
        or value.get("promotion_effect") != "NONE"
    ):
        raise PublisherError("neural manifest crossed its public-testnet safety boundary")
    chain_id = canonical_hex(value.get("chain_id"), "manifest chain_id")
    genesis_hash = canonical_hex(value.get("genesis_hash"), "manifest genesis_hash")
    model = value.get("model")
    if not isinstance(model, dict):
        raise PublisherError("neural manifest model binding is missing")
    expected_model = {
        "artifact_id": demo.ARTIFACT_ID,
        "artifact_sha256": demo.MODEL_SHA256,
        "manifest_root": demo.MANIFEST_ROOT,
    }
    for key, expected in expected_model.items():
        if model.get(key) != expected:
            raise PublisherError(f"neural manifest model binding changed: {key}")
    for key in (
        "capsule_id",
        "execution_profile_id",
        "query_policy_id",
        "availability_certificate_id",
        "fund_profile_id",
    ):
        canonical_hex(model.get(key), f"manifest model {key}")
    activity = value.get("activity")
    if not isinstance(activity, list) or not activity or len(activity) > MAX_ACTIVITY:
        raise PublisherError("neural manifest activity must contain 1..32 entries")
    previous_sequence: int | None = None
    previous_height: int | None = None
    unique_fields = {key: set() for key in ("transaction_id", "job_id", "receipt_id", "settlement_id")}
    for index, item in enumerate(activity):
        if not isinstance(item, dict):
            raise PublisherError(f"neural activity {index} is not an object")
        sequence = positive_int(item.get("sequence"), f"neural activity {index} sequence")
        height = positive_int(item.get("included_height"), f"neural activity {index} height")
        if previous_sequence is not None and sequence >= previous_sequence:
            raise PublisherError("neural activity is not newest-first by sequence")
        if previous_height is not None and height > previous_height:
            raise PublisherError("neural activity is not newest-first by inclusion height")
        previous_sequence = sequence
        previous_height = height
        for key, seen in unique_fields.items():
            identifier = canonical_hex(item.get(key), f"neural activity {index} {key}")
            if identifier in seen:
                raise PublisherError(f"neural activity contains duplicate {key}")
            seen.add(identifier)
        for key in ("included_block", "prompt_commitment", "output_root", "token_history_root"):
            canonical_hex(item.get(key), f"neural activity {index} {key}")
        positive_int(item.get("input_tokens"), f"neural activity {index} input_tokens")
        positive_int(item.get("output_tokens"), f"neural activity {index} output_tokens")
        positive_int(item.get("output_bytes"), f"neural activity {index} output_bytes")
        positive_int(item.get("duration_milliseconds"), f"neural activity {index} duration")
        fee = item.get("fee_charged")
        if not isinstance(fee, str) or not fee.isdigit():
            raise PublisherError(f"neural activity {index} fee is invalid")
    origins = value.get("indexer_origins")
    if (
        not isinstance(origins, list)
        or len(origins) != 3
        or len(set(origins)) != 3
        or not all(isinstance(origin, str) and origin.startswith("https://") for origin in origins)
    ):
        raise PublisherError("neural manifest must bind three distinct HTTPS indexers")
    return {**value, "chain_id": chain_id, "genesis_hash": genesis_hash}


def finalized_height(status: Mapping[str, Any]) -> int:
    finalized = status.get("finalized")
    if not isinstance(finalized, dict):
        raise PublisherError("node status lacks finalized state")
    epoch = finalized.get("epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise PublisherError("node status finalized epoch is invalid")
    return epoch * 256


def validate_resolution(
    resolution: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    active = resolution.get("active")
    model = manifest.get("model")
    if not isinstance(active, dict) or not isinstance(model, dict):
        raise PublisherError("verified Bonsai resolution is missing")
    if (
        resolution.get("registration_state") != "ACTIVE_TESTNET"
        or resolution.get("production_effect") != "NONE"
        or resolution.get("proofs_verified") is not True
        or active.get("artifact_id") != demo.ARTIFACT_ID
        or active.get("manifest_root") != demo.MANIFEST_ROOT
        or active.get("artifact_sha256") != demo.MODEL_SHA256
        or active.get("artifact_bytes") != demo.MODEL_BYTES
    ):
        raise PublisherError("node resolution is not the verified Bonsai test graph")
    for key in (
        "capsule_id",
        "execution_profile_id",
        "query_policy_id",
        "availability_certificate_id",
        "fund_profile_id",
    ):
        if active.get(key) != model.get(key):
            raise PublisherError(f"node resolution and manifest disagree on {key}")
    return dict(resolution)


def initial_state(manifest: Mapping[str, Any], observed_at: str) -> dict[str, Any]:
    latest = manifest["activity"][0]
    return {
        "schema": STATE_SCHEMA,
        "chain_id": manifest["chain_id"],
        "genesis_hash": manifest["genesis_hash"],
        "updated_at": observed_at,
        "last_completed": {
            "sequence": latest["sequence"],
            "completed_at": observed_at,
            "finalized_height": latest["included_height"],
            "transaction_id": latest["transaction_id"],
        },
        "active": None,
        "last_error": None,
    }


def validate_state(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("schema") != STATE_SCHEMA:
        raise PublisherError("unsupported neural publisher state schema")
    if value.get("chain_id") != manifest.get("chain_id") or value.get("genesis_hash") != manifest.get("genesis_hash"):
        raise PublisherError("neural publisher state belongs to another chain")
    parse_utc(value.get("updated_at"), "publisher updated_at")
    last = value.get("last_completed")
    if not isinstance(last, dict):
        raise PublisherError("publisher state lacks last_completed")
    positive_int(last.get("sequence"), "publisher last sequence")
    positive_int(last.get("finalized_height"), "publisher last finalized height")
    canonical_hex(last.get("transaction_id"), "publisher last transaction")
    parse_utc(last.get("completed_at"), "publisher last completed_at")
    active = value.get("active")
    if active is not None:
        if not isinstance(active, dict):
            raise PublisherError("publisher active run is not an object")
        positive_int(active.get("sequence"), "publisher active sequence")
        run_id = active.get("run_id")
        if not isinstance(run_id, str) or len(run_id) != 24 or any(character not in "0123456789abcdef" for character in run_id):
            raise PublisherError("publisher active run id is invalid")
        plan = active.get("plan")
        if not isinstance(plan, dict) or plan.get("schema") != "noos/wwm-chain-bound-inference-plan/v1":
            raise PublisherError("publisher active plan is invalid")
    error = value.get("last_error")
    if error is not None and not isinstance(error, dict):
        raise PublisherError("publisher last_error is invalid")
    return dict(value)


class SingleInstance(AbstractContextManager["SingleInstance"]):
    def __init__(self, path: Path):
        self.path = path
        self.handle: Any = None

    def __enter__(self) -> "SingleInstance":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"\0")
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.handle.close()
            self.handle = None
            raise PublisherError("another neural publisher already holds the state lock") from error
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.handle is None:
            return
        self.handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()
        self.handle = None


class NeuralPublisher:
    def __init__(
        self,
        config: PublisherConfig,
        hosted: Mapping[str, Any],
        paths: demo.Paths,
        network: demo.Network,
        *,
        now: Callable[[], str] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self.hosted = hosted
        self.paths = paths
        self.network = network
        self.now = now
        self.sleep = sleep
        self.manifest = validate_manifest(
            bounded_object(config.manifest, MAX_MANIFEST_BYTES, "neural manifest")
        )
        if config.state.exists():
            self.state = validate_state(
                bounded_object(config.state, MAX_STATE_BYTES, "publisher state"),
                self.manifest,
            )
        else:
            self.state = initial_state(self.manifest, self.now())
            self._save_state()

    def _save_state(self) -> None:
        self.state["updated_at"] = self.now()
        atomic_json(self.config.state, self.state)

    def _emit(self, event: str, **detail: Any) -> None:
        print(
            json.dumps(
                {"schema": STATE_SCHEMA, "event": event, "observed_at": self.now(), **detail},
                separators=(",", ":"),
            ),
            flush=True,
        )

    def record_error(self, error: BaseException) -> None:
        self.state["last_error"] = {
            "observed_at": self.now(),
            "message": str(error)[:2048],
        }
        self._save_state()
        self._emit("error", message=str(error)[:2048])

    def _reload_manifest(self) -> None:
        self.manifest = validate_manifest(
            bounded_object(self.config.manifest, MAX_MANIFEST_BYTES, "neural manifest")
        )

    def _preflight(self) -> tuple[dict[str, Any], dict[str, Any]]:
        status = demo.http_json(f"{self.network.node_rpc}/status", self.network.node_token)
        if status.get("chain_id") != self.manifest["chain_id"] or status.get("genesis_hash") != self.manifest["genesis_hash"]:
            raise PublisherError("transaction node belongs to another chain")
        resolution = validate_resolution(
            demo.http_json(
                f"{self.network.node_rpc}/model-resolution/bonsai-q1",
                self.network.node_token,
                timeout=180,
            ),
            self.manifest,
        )
        ready = demo.http_json(f"{self.network.sidecar_url}/health/ready", self.network.sidecar_token_hex)
        if ready.get("ready") is not True:
            raise PublisherError("Bonsai executor is not ready")
        return status, resolution

    def _is_due(self, status: Mapping[str, Any], force: bool) -> bool:
        if force or self.state.get("active") is not None:
            return True
        last = self.state["last_completed"]
        elapsed = datetime.now(timezone.utc) - parse_utc(last["completed_at"], "publisher last completed_at")
        return (
            elapsed.total_seconds() >= self.config.minimum_seconds
            and finalized_height(status) >= last["finalized_height"] + self.config.minimum_finalized_advance
        )

    def _reconcile_completed_manifest(self) -> bool:
        active = self.state.get("active")
        if not isinstance(active, dict):
            return False
        plan = active["plan"]
        matches = [item for item in self.manifest["activity"] if item["job_id"] == plan["job_id"]]
        if not matches:
            return False
        item = matches[0]
        if item["receipt_id"] != plan["receipt_id"] or item["settlement_id"] != plan["settlement_id"]:
            raise PublisherError("manifest contains a conflicting resumed neural run")
        self.state["last_completed"] = {
            "sequence": item["sequence"],
            "completed_at": self.now(),
            "finalized_height": item["included_height"],
            "transaction_id": item["transaction_id"],
        }
        self.state["active"] = None
        self.state["last_error"] = None
        self._save_state()
        self._emit("reconciled", sequence=item["sequence"], transaction_id=item["transaction_id"])
        return True

    def _begin(self, resolution: Mapping[str, Any]) -> dict[str, Any]:
        sequence = self.manifest["activity"][0]["sequence"] + 1
        run_id = hashlib.sha256(
            f"{self.manifest['chain_id']}:{self.manifest['genesis_hash']}:neural-pulse:{sequence}".encode()
        ).hexdigest()[:24]
        plan = demo.prepare_chain_bound_inference(
            self.network,
            resolution,
            run_id,
            demo.quote(self.network),
        )
        active = {
            "sequence": sequence,
            "run_id": run_id,
            "phase": "planned",
            "started_at": self.now(),
            "plan": plan,
        }
        self.state["active"] = active
        self.state["last_error"] = None
        self._save_state()
        self._emit("planned", sequence=sequence, job_id=plan["job_id"])
        return active

    @staticmethod
    def _missing_record(error: demo.DemoError) -> bool:
        return "HTTP 404" in str(error)

    def _ensure_open(self, active: dict[str, Any]) -> dict[str, Any]:
        plan = active["plan"]
        try:
            record = demo.verify_chain_bound_job(self.network, plan)
        except demo.DemoError as error:
            if not self._missing_record(error):
                raise
        else:
            active["job_record"] = record
            active["phase"] = "open_finalized"
            self._save_state()
            self._emit("open_finalized", sequence=active["sequence"], job_id=plan["job_id"])
            return record

        open_txid = active.get("open_txid")
        if isinstance(open_txid, str):
            demo.finalize_wwm_submission(self.network, open_txid)
            record = demo.verify_chain_bound_job(self.network, plan)
        else:
            def submitted(txid: str) -> None:
                active["open_txid"] = txid
                active["phase"] = "open_submitted"
                self._save_state()
                self._emit("open_submitted", sequence=active["sequence"], transaction_id=txid)

            opened = demo.submit_chain_bound_job(
                self.hosted,
                self.paths,
                self.network,
                plan,
                submitted,
            )
            active["open_txid"] = opened["submission"]["txid"]
            record = opened["record"]
        active["job_record"] = record
        active["phase"] = "open_finalized"
        self._save_state()
        self._emit("open_finalized", sequence=active["sequence"], job_id=plan["job_id"])
        return record

    def _ensure_inference(self, active: dict[str, Any]) -> dict[str, Any]:
        existing = active.get("inference")
        if isinstance(existing, dict):
            canonical_hex(existing.get("output_root"), "resumed inference output root")
            canonical_hex(existing.get("token_history_root"), "resumed inference token history root")
            return existing
        deadline = time.monotonic() + 120
        while True:
            try:
                inference = demo.run_inference(
                    self.paths,
                    self.network,
                    active["plan"]["job_id"],
                    demo.required_text(self.hosted, "tokenizer_executable_sha256"),
                )
                break
            except demo.DemoError as error:
                if "HTTP 409" not in str(error) or time.monotonic() >= deadline:
                    raise
                self.sleep(1)
        active["inference"] = inference
        active["phase"] = "inference_completed"
        self._save_state()
        self._emit(
            "inference_completed",
            sequence=active["sequence"],
            output_root=inference["output_root"],
            output_tokens=inference["output_tokens"],
        )
        return inference

    def _ensure_close(
        self,
        active: dict[str, Any],
        job_record: Mapping[str, Any],
        inference: Mapping[str, Any],
    ) -> dict[str, Any]:
        close_plan = active.get("close_plan")
        if not isinstance(close_plan, dict):
            close_plan = demo.prepare_chain_bound_close(active["plan"], job_record, inference)
            active["close_plan"] = close_plan
            active["phase"] = "close_prepared"
            self._save_state()

        try:
            records = demo.verify_chain_bound_close(
                self.network,
                active["plan"],
                close_plan,
                job_record,
                inference,
            )
        except demo.DemoError as error:
            if not self._missing_record(error):
                raise
        else:
            if not isinstance(active.get("close_txid"), str):
                raise PublisherError("close records finalized without a durable transaction id")
            active["close_records"] = records
            active["phase"] = "close_finalized"
            self._save_state()
            return records

        close_txid = active.get("close_txid")
        if isinstance(close_txid, str):
            demo.finalize_wwm_submission(self.network, close_txid)
            records = demo.verify_chain_bound_close(
                self.network,
                active["plan"],
                close_plan,
                job_record,
                inference,
            )
        else:
            def submitted(txid: str) -> None:
                active["close_txid"] = txid
                active["phase"] = "close_submitted"
                self._save_state()
                self._emit("close_submitted", sequence=active["sequence"], transaction_id=txid)

            closed = demo.submit_chain_bound_close(
                self.hosted,
                self.paths,
                self.network,
                active["plan"],
                close_plan,
                job_record,
                inference,
                submitted,
            )
            active["close_txid"] = closed["submission"]["txid"]
            records = {"receipt": closed["receipt"], "settlement": closed["settlement"]}
        active["close_records"] = records
        active["phase"] = "close_finalized"
        self._save_state()
        self._emit(
            "close_finalized",
            sequence=active["sequence"],
            transaction_id=active["close_txid"],
        )
        return records

    @staticmethod
    def _indexed_transaction(origin: str, txid: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{origin.rstrip('/')}/api/v1/transactions/{txid}",
            headers={"Accept": "application/vnd.noos.v1+json", "User-Agent": "noos-neural-publisher/1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                value = json.loads(response.read())
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, json.JSONDecodeError) as error:
            raise PublisherError(f"indexer transaction lookup failed at {origin}: {error}") from error
        if not isinstance(value, dict):
            raise PublisherError(f"indexer transaction response at {origin} is not an object")
        return value

    def _wait_indexers(self, txid: str, timeout: float = 900) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        last_error: PublisherError | None = None
        origins = self.manifest["indexer_origins"]
        while time.monotonic() < deadline:
            try:
                values = [self._indexed_transaction(origin, txid) for origin in origins]
                canonical = [
                    json.dumps(
                        {key: value.get(key) for key in ("txid", "state", "fee", "inclusion")},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    for value in values
                ]
                if len(set(canonical)) != 1:
                    raise PublisherError("public indexers disagree on the pulse transaction")
                value = values[0]
                inclusion = value.get("inclusion")
                if value.get("txid") != txid or value.get("state") != "INCLUDED" or not isinstance(inclusion, dict):
                    raise PublisherError("public indexers have not included the pulse transaction")
                canonical_hex(inclusion.get("hash"), "indexed inclusion hash")
                height = inclusion.get("height")
                if not isinstance(height, str) or not height.isdigit() or int(height) <= 0:
                    raise PublisherError("indexed inclusion height is invalid")
                fee = value.get("fee")
                if not isinstance(fee, str) or not fee.isdigit():
                    raise PublisherError("indexed fee is invalid")
                return values
            except PublisherError as error:
                last_error = error
                self.sleep(2)
        raise last_error or PublisherError("public indexers did not confirm the pulse transaction")

    def _activity_entry(
        self,
        active: Mapping[str, Any],
        indexed: Mapping[str, Any],
    ) -> dict[str, Any]:
        inclusion = indexed["inclusion"]
        inference = active["inference"]
        duration = inference.get("duration_seconds")
        if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration <= 0:
            raise PublisherError("inference duration is invalid")
        return {
            "sequence": active["sequence"],
            "label": f"Neural pulse {active['sequence']:02d}",
            "transaction_id": active["close_txid"],
            "included_height": int(inclusion["height"]),
            "included_block": inclusion["hash"],
            "fee_charged": indexed["fee"],
            "job_id": active["plan"]["job_id"],
            "receipt_id": active["plan"]["receipt_id"],
            "settlement_id": active["plan"]["settlement_id"],
            "prompt_commitment": active["plan"]["prompt_commitment"],
            "input_tokens": PROMPT_INPUT_TOKENS,
            "output_tokens": positive_int(inference.get("output_tokens"), "inference output tokens"),
            "output_bytes": positive_int(inference.get("output_bytes"), "inference output bytes"),
            "duration_milliseconds": max(1, round(float(duration) * 1000)),
            "output_root": canonical_hex(inference.get("output_root"), "inference output root"),
            "token_history_root": canonical_hex(
                inference.get("token_history_root"), "inference token history root"
            ),
        }

    def _publish_manifest(
        self,
        active: dict[str, Any],
        records: Mapping[str, Any],
        indexers: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._reload_manifest()
        existing = [item for item in self.manifest["activity"] if item["job_id"] == active["plan"]["job_id"]]
        if existing:
            return existing[0]
        expected_sequence = self.manifest["activity"][0]["sequence"] + 1
        if active["sequence"] != expected_sequence:
            raise PublisherError("neural sequence changed while a pulse was in progress")
        entry = self._activity_entry(active, indexers[0])
        if entry["included_height"] < self.manifest["activity"][0]["included_height"]:
            raise PublisherError("new pulse inclusion height regressed")
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "generated_at": self.now(),
            "environment": "public-testnet",
            "production": False,
            "promotion_effect": "NONE",
            "chain_id": self.manifest["chain_id"],
            "genesis_hash": self.manifest["genesis_hash"],
            "run_id": active["run_id"],
            "activity": entry,
            "open_transaction_id": active.get("open_txid"),
            "close_transaction_id": active["close_txid"],
            "finalized_job": active["job_record"],
            "finalized_receipt": records["receipt"],
            "finalized_settlement": records["settlement"],
            "indexer_confirmations": [
                {"origin": origin, "transaction": value}
                for origin, value in zip(self.manifest["indexer_origins"], indexers, strict=True)
            ],
            "claims": {
                "model_execution_off_chain": True,
                "job_receipt_settlement_finalized_on_chain": True,
                "three_indexers_agree": True,
                "production_claimed": False,
            },
        }
        self.config.evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = self.config.evidence_dir / f"pulse-{active['sequence']:04d}-{active['run_id']}.json"
        atomic_json(evidence_path, evidence)
        self.manifest["activity"] = [entry, *self.manifest["activity"]][:MAX_ACTIVITY]
        validate_manifest(self.manifest)
        atomic_json(self.config.manifest, self.manifest)
        active["evidence_path"] = str(evidence_path)
        return entry

    def publish(self, *, force: bool = False) -> dict[str, Any]:
        self._reload_manifest()
        if self._reconcile_completed_manifest():
            return {"published": False, "reason": "reconciled"}
        status, resolution = self._preflight()
        if not self._is_due(status, force):
            self._emit(
                "not_due",
                last_sequence=self.state["last_completed"]["sequence"],
                finalized_height=finalized_height(status),
            )
            return {"published": False, "reason": "not_due"}
        active = self.state.get("active")
        if not isinstance(active, dict):
            active = self._begin(resolution)
        job_record = self._ensure_open(active)
        inference = self._ensure_inference(active)
        records = self._ensure_close(active, job_record, inference)
        txid = canonical_hex(active.get("close_txid"), "close transaction id")
        indexers = self._wait_indexers(txid)
        active["phase"] = "indexed"
        self._save_state()
        entry = self._publish_manifest(active, records, indexers)
        finalized_status = demo.http_json(f"{self.network.node_rpc}/status", self.network.node_token)
        self.state["last_completed"] = {
            "sequence": entry["sequence"],
            "completed_at": self.now(),
            "finalized_height": finalized_height(finalized_status),
            "transaction_id": entry["transaction_id"],
        }
        self.state["active"] = None
        self.state["last_error"] = None
        self._save_state()
        self._emit(
            "published",
            sequence=entry["sequence"],
            transaction_id=entry["transaction_id"],
            finalized_height=self.state["last_completed"]["finalized_height"],
        )
        return {"published": True, "activity": entry}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hosted-config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--minimum-seconds", type=int, default=21_600)
    parser.add_argument("--minimum-finalized-advance", type=int, default=256)
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.force and not args.once:
        parser.error("--force is accepted only with --once")
    if not 300 <= args.minimum_seconds <= 604_800:
        parser.error("--minimum-seconds must be in [300, 604800]")
    if not 256 <= args.minimum_finalized_advance <= 65_536:
        parser.error("--minimum-finalized-advance must be in [256, 65536]")
    if not 10 <= args.poll_seconds <= 3_600:
        parser.error("--poll-seconds must be in [10, 3600]")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    config = PublisherConfig(
        hosted_config=args.hosted_config.resolve(),
        manifest=args.manifest.resolve(),
        state=args.state.resolve(),
        evidence_dir=args.evidence_dir.resolve(),
        minimum_seconds=args.minimum_seconds,
        minimum_finalized_advance=args.minimum_finalized_advance,
        poll_seconds=args.poll_seconds,
    )
    try:
        hosted = bounded_object(config.hosted_config, MAX_MANIFEST_BYTES, "hosted-model config")
        paths, network = demo.validate_contract(hosted)
        demo.verify_prerequisites(hosted, paths)
        with SingleInstance(config.state.with_suffix(config.state.suffix + ".lock")):
            publisher = NeuralPublisher(config, hosted, paths, network)
            if args.once:
                publisher.publish(force=args.force)
                return 0
            while True:
                try:
                    publisher.publish()
                except (PublisherError, demo.DemoError, OSError) as error:
                    publisher.record_error(error)
                time.sleep(config.poll_seconds)
    except KeyboardInterrupt:
        return 0
    except (PublisherError, demo.DemoError, OSError) as error:
        print(f"neural publisher failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
