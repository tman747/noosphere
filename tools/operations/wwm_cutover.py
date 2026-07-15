#!/usr/bin/env python3
"""Execute the frozen WWM service-discovery/DNS cutover in strict order.

Planning is side-effect free. Every advancing invocation requires a trusted
threshold Ed25519 authorization over the exact cutover identity. Advancing past
a completed stage additionally requires a threshold-signed healthy observation
covering its full minimum interval. The journal is append-only and bound to the
authorization digest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STAGES = ROOT / "deploy" / "cutover" / "wwm-cutover-stages.json"
AUTH_DOMAIN = b"NOOS/SIG/WWM-CUTOVER-AUTHORIZATION/V1\0"
OBS_DOMAIN = b"NOOS/SIG/WWM-CUTOVER-OBSERVATION/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9.-]{7,127}$")


class CutoverError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CutoverError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise CutoverError(f"{path} must contain an object")
    return value


def validate_stages(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("schema") != "noos/wwm-cutover-stages/v1":
        raise CutoverError("unsupported cutover stage schema")
    stages = document.get("stages")
    expected = [
        ("preflight", 0, 0),
        ("service_discovery_1", 1, 1800),
        ("service_discovery_5", 5, 3600),
        ("service_discovery_25", 25, 7200),
        ("service_discovery_50", 50, 14400),
        ("service_discovery_100", 100, 86400),
        ("dns_cutover", 100, 0),
        ("cutover_complete", 100, 0),
    ]
    if not isinstance(stages, list) or len(stages) != len(expected):
        raise CutoverError("cutover stage count is invalid")
    observed: list[tuple[Any, Any, Any]] = []
    for stage in stages:
        if not isinstance(stage, dict) or set(stage) != {
            "stage_id",
            "traffic_percent",
            "minimum_observation_seconds",
            "action",
        }:
            raise CutoverError("cutover stage row is malformed")
        observed.append(
            (
                stage["stage_id"],
                stage["traffic_percent"],
                stage["minimum_observation_seconds"],
            )
        )
    if observed != expected:
        raise CutoverError("cutover stage ordering or duration differs from the frozen law")
    if document.get("production_ttl_precondition_seconds") != 300 or document.get("ttl_precondition_lead_seconds") != 172800:
        raise CutoverError("production TTL precondition differs from 300 seconds for 48 hours")
    return stages


def key_map_and_threshold(keyring: dict[str, Any], environment: str) -> tuple[dict[str, bytes], set[str], int]:
    if keyring.get("schema") != "noos/wwm-cutover-keyring/v1" or keyring.get("environment") != environment:
        raise CutoverError("trusted cutover keyring schema or environment mismatch")
    if environment == "production" and keyring.get("production_authority") is not True:
        raise CutoverError("production keyring is not explicitly authorized for production")
    threshold = keyring.get("threshold")
    allowed = keyring.get("authorized_key_ids")
    keys = keyring.get("keys")
    if not isinstance(threshold, int) or threshold < 1 or not isinstance(allowed, list) or threshold > len(set(allowed)) or not isinstance(keys, list):
        raise CutoverError("trusted cutover threshold is invalid")
    key_map: dict[str, bytes] = {}
    for row in keys:
        if not isinstance(row, dict) or set(row) != {"key_id", "public_key_base64"}:
            raise CutoverError("trusted cutover key row is malformed")
        try:
            public = base64.b64decode(row["public_key_base64"], validate=True)
        except (TypeError, ValueError) as error:
            raise CutoverError("trusted cutover key is not canonical base64") from error
        if len(public) != 32 or sha256(public) != row["key_id"]:
            raise CutoverError("trusted cutover key ID is invalid")
        key_map[row["key_id"]] = public
    allowed_set = set(allowed)
    if len(allowed_set) != len(allowed) or not allowed_set.issubset(key_map):
        raise CutoverError("trusted cutover signer set is invalid")
    return key_map, allowed_set, threshold


def verify_signatures(
    body: dict[str, Any],
    signatures: Any,
    *,
    domain: bytes,
    keyring: dict[str, Any],
    environment: str,
) -> list[str]:
    key_map, allowed, threshold = key_map_and_threshold(keyring, environment)
    if not isinstance(signatures, list):
        raise CutoverError("signature list is invalid")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise CutoverError("cryptography with Ed25519 support is required") from error
    message = domain + canonical_json(body)
    verified: set[str] = set()
    for row in signatures:
        if not isinstance(row, dict) or set(row) != {"key_id", "signature_base64"}:
            raise CutoverError("signature row is malformed")
        key_id = row["key_id"]
        if key_id in verified or key_id not in allowed:
            raise CutoverError("signature signer is duplicate or untrusted")
        try:
            signature = base64.b64decode(row["signature_base64"], validate=True)
            Ed25519PublicKey.from_public_bytes(key_map[key_id]).verify(signature, message)
        except (TypeError, ValueError, InvalidSignature) as error:
            raise CutoverError("cutover signature is invalid") from error
        verified.add(key_id)
    if len(verified) < threshold:
        raise CutoverError("cutover signature threshold is not met")
    return sorted(verified)


def verify_authorization(
    document: dict[str, Any],
    keyring: dict[str, Any],
    stages_document: dict[str, Any],
    now: int,
) -> tuple[dict[str, Any], str, list[str]]:
    if set(document) != {"schema", "body", "signatures"} or document.get("schema") != "noos/wwm-cutover-authorization/v2":
        raise CutoverError("cutover authorization envelope is invalid")
    body = document.get("body")
    required = {
        "environment",
        "authorization_state",
        "exact_revision",
        "chain_id",
        "genesis_hash",
        "release_root",
        "g5_ledger_root",
        "capsule_id",
        "service_directory_root",
        "runway_root",
        "cutover_root",
        "static_target_sha256",
        "g5_authorization_id",
        "activation_height",
        "production_transition_finalized",
        "static_target_published",
        "ttl_seconds",
        "ttl_lowered_at_unix",
        "issued_at_unix",
        "expires_at_unix",
        "nonce",
        "stages_sha256",
    }
    if not isinstance(body, dict) or set(body) != required:
        raise CutoverError("cutover authorization body fields are invalid")
    environment = body.get("environment")
    if environment not in {"devnet", "production"}:
        raise CutoverError("cutover environment is invalid")
    expected_state = "FINALIZED_G5" if environment == "production" else "DEVNET_AUTHORIZED"
    if body.get("authorization_state") != expected_state:
        raise CutoverError("cutover authorization state is not executable")
    if not HEX40.fullmatch(str(body.get("exact_revision", ""))):
        raise CutoverError("cutover exact revision is invalid")
    identity_fields = [
        "chain_id",
        "genesis_hash",
        "release_root",
        "g5_ledger_root",
        "capsule_id",
        "service_directory_root",
        "runway_root",
        "cutover_root",
        "static_target_sha256",
        "g5_authorization_id",
    ]
    for field in identity_fields:
        value = str(body.get(field, ""))
        if not HEX64.fullmatch(value) or (environment == "production" and value == "0" * 64):
            raise CutoverError(f"cutover {field} is invalid or blocked")
    if body.get("stages_sha256") != sha256(canonical_json(stages_document)):
        raise CutoverError("cutover authorization binds different stages")
    if body.get("production_transition_finalized") is not True or body.get("static_target_published") is not True:
        raise CutoverError("production transition and static target must already be finalized")
    if not isinstance(body.get("activation_height"), int) or body["activation_height"] < 1:
        raise CutoverError("activation height is invalid")
    for field in ("issued_at_unix", "expires_at_unix", "ttl_lowered_at_unix"):
        if not isinstance(body.get(field), int):
            raise CutoverError(f"{field} is invalid")
    if not body["issued_at_unix"] <= now <= body["expires_at_unix"]:
        raise CutoverError("cutover authorization is not currently valid")
    if not TOKEN.fullmatch(str(body.get("nonce", ""))):
        raise CutoverError("cutover nonce is invalid")
    if environment == "production":
        if body.get("ttl_seconds") != 300 or body["issued_at_unix"] - body["ttl_lowered_at_unix"] < 172800:
            raise CutoverError("production TTL was not 300 seconds for at least 48 hours")
    signers = verify_signatures(
        body,
        document["signatures"],
        domain=AUTH_DOMAIN,
        keyring=keyring,
        environment=environment,
    )
    return body, sha256(canonical_json(document)), signers


def verify_observation(
    document: dict[str, Any],
    keyring: dict[str, Any],
    environment: str,
    prior: dict[str, Any],
    authorization_sha256: str,
    now: int,
) -> dict[str, Any]:
    if set(document) != {"schema", "body", "signatures"} or document.get("schema") != "noos/wwm-cutover-observation/v1":
        raise CutoverError("cutover observation envelope is invalid")
    body = document.get("body")
    required = {
        "stage_id",
        "authorization_sha256",
        "started_at_unix",
        "observed_at_unix",
        "healthy",
        "identity_match",
        "paid_job_rpo_zero",
        "old_origin_requests",
        "evidence_sha256",
    }
    if not isinstance(body, dict) or set(body) != required:
        raise CutoverError("cutover observation fields are invalid")
    if body.get("stage_id") != prior["stage_id"] or body.get("authorization_sha256") != authorization_sha256 or body.get("started_at_unix") != prior["started_at_unix"]:
        raise CutoverError("cutover observation is bound to a different stage")
    minimum = prior["minimum_observation_seconds"]
    if not isinstance(body.get("observed_at_unix"), int) or body["observed_at_unix"] < prior["started_at_unix"] + minimum or body["observed_at_unix"] > now:
        raise CutoverError("cutover observation interval is incomplete or future-dated")
    if body.get("healthy") is not True or body.get("identity_match") is not True or body.get("paid_job_rpo_zero") is not True:
        raise CutoverError("cutover health, identity, or paid-job RPO observation failed")
    if not isinstance(body.get("old_origin_requests"), int) or body["old_origin_requests"] < 0 or not HEX64.fullmatch(str(body.get("evidence_sha256", ""))):
        raise CutoverError("cutover observation counters or evidence root are invalid")
    verify_signatures(body, document["signatures"], domain=OBS_DOMAIN, keyring=keyring, environment=environment)
    return body


def empty_journal(authorization_sha256: str) -> dict[str, Any]:
    return {
        "schema": "noos/wwm-cutover-journal/v1",
        "authorization_sha256": authorization_sha256,
        "next_stage_index": 0,
        "completed_stages": [],
    }


def load_journal(path: Path, authorization_sha256: str) -> dict[str, Any]:
    if not path.exists():
        return empty_journal(authorization_sha256)
    journal = load_object(path)
    if set(journal) != {"schema", "authorization_sha256", "next_stage_index", "completed_stages"} or journal.get("schema") != "noos/wwm-cutover-journal/v1":
        raise CutoverError("cutover journal is malformed")
    if journal.get("authorization_sha256") != authorization_sha256:
        raise CutoverError("cutover journal belongs to a different authorization")
    if not isinstance(journal.get("next_stage_index"), int) or not isinstance(journal.get("completed_stages"), list) or journal["next_stage_index"] != len(journal["completed_stages"]):
        raise CutoverError("cutover journal ordering is invalid")
    return journal


def persist_journal(path: Path, journal: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json(journal))
    os.replace(temporary, path)


def run_adapter(adapter: Path, stage: dict[str, Any], authorization_sha256: str) -> None:
    if not adapter.is_file():
        raise CutoverError("cutover adapter command is not an existing file")
    completed = subprocess.run(
        [
            str(adapter),
            "apply",
            "--stage",
            stage["stage_id"],
            "--traffic-percent",
            str(stage["traffic_percent"]),
            "--authorization-sha256",
            authorization_sha256,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        raise CutoverError(f"cutover adapter failed: {(completed.stdout + completed.stderr).strip()}")


def plan_report(stages: list[dict[str, Any]], stages_sha256: str) -> dict[str, Any]:
    return {
        "schema": "noos/wwm-cutover-plan/v1",
        "verdict": "PLAN_ONLY_AUTHORIZATION_REQUIRED",
        "stages_sha256": stages_sha256,
        "stages": stages,
        "execution_authorized": False,
        "promotion_effect": "NONE",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stages", type=Path, default=DEFAULT_STAGES)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--adapter-command", type=Path)
    parser.add_argument("--now", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        stages_document = load_object(args.stages)
        stages = validate_stages(stages_document)
        stages_digest = sha256(canonical_json(stages_document))
        if args.plan and not args.execute:
            print(json.dumps(plan_report(stages, stages_digest), sort_keys=True, separators=(",", ":")))
            return 0
        if not args.execute:
            raise CutoverError("choose --plan or --execute")
        if args.authorization is None or args.keyring is None or args.journal is None or args.adapter_command is None:
            raise CutoverError("execution requires authorization, trusted keyring, journal, and adapter command")
        now = args.now if args.now is not None else int(time.time())
        authorization_document = load_object(args.authorization)
        keyring = load_object(args.keyring)
        body, authorization_sha256, signers = verify_authorization(
            authorization_document, keyring, stages_document, now
        )
        journal = load_journal(args.journal, authorization_sha256)
        index = journal["next_stage_index"]
        if index >= len(stages):
            raise CutoverError("cutover is already complete; authorization cannot replay")
        observation_body = None
        if index > 0:
            if args.observation is None:
                raise CutoverError("advancing requires a signed observation for the prior stage")
            observation_body = verify_observation(
                load_object(args.observation),
                keyring,
                body["environment"],
                journal["completed_stages"][-1],
                authorization_sha256,
                now,
            )
        stage = stages[index]
        if stage["stage_id"] in {"dns_cutover", "cutover_complete"}:
            if observation_body is None or observation_body["old_origin_requests"] != 0:
                raise CutoverError("DNS/completion requires signed proof of zero old-origin traffic")
        run_adapter(args.adapter_command, stage, authorization_sha256)
        journal["completed_stages"].append(
            {
                "stage_id": stage["stage_id"],
                "traffic_percent": stage["traffic_percent"],
                "minimum_observation_seconds": stage["minimum_observation_seconds"],
                "started_at_unix": now,
            }
        )
        journal["next_stage_index"] = index + 1
        persist_journal(args.journal, journal)
        report = {
            "schema": "noos/wwm-cutover-advance/v1",
            "verdict": "STAGE_APPLIED",
            "authorization_sha256": authorization_sha256,
            "authorization_signers": signers,
            "applied_stage": stage["stage_id"],
            "next_stage_index": journal["next_stage_index"],
            "complete": journal["next_stage_index"] == len(stages),
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except CutoverError as error:
        print(json.dumps({"verdict": "BLOCKED", "error": str(error), "execution_authorized": False}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
