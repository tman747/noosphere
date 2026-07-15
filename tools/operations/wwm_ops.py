#!/usr/bin/env python3
"""Fail-closed WWM backup, restore, incident, rotation, rollback, and drill driver.

Dry runs validate preconditions and emit the exact ordered adapter actions. Real
execution requires a trusted external keyring, unexpired threshold Ed25519
authorization over the request digest, and a non-shell adapter command.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "deploy" / "wwm" / "runbooks.json"
DOMAIN = b"NOOS/SIG/WWM-OPERATION-AUTHORIZATION/V1\0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{7,127}$")
DRILLS = {
    "artifact_corruption",
    "artifact_crash",
    "artifact_full_disk",
    "artifact_restore",
    "availability_12_9_8_7",
    "chain_reorg",
    "chain_restart",
    "custodian_four_loss",
    "custodian_one_loss",
    "custodian_two_loss",
    "database_failover",
    "dns_forward_rollback",
    "evidence_outage",
    "executor_disagreement",
    "executor_largest_domain_loss",
    "executor_process_loss",
    "gateway_process_loss",
    "gateway_region_loss",
    "key_revocation",
    "key_rotation",
    "publisher_blackout",
    "sponsor_exhaustion",
    "state_reader_byzantine_minority",
    "total_blackout",
    "upgrade_rollback",
}


class OperationError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise OperationError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise OperationError(f"{path} must contain an object")
    return value


def request_digest(request: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(request)).hexdigest()


def require_bool(preconditions: dict[str, Any], name: str, expected: bool = True) -> None:
    if preconditions.get(name) is not expected:
        raise OperationError(f"precondition {name} must be {str(expected).lower()}")


def validate_request(request: dict[str, Any], catalog: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema",
        "request_id",
        "operation",
        "environment",
        "chain_id",
        "genesis_hash",
        "authorized_config_id",
        "preconditions",
        "parameters",
    }
    if set(request) != required or request.get("schema") != "noos/wwm-operation/v1":
        raise OperationError("operation request fields or schema are invalid")
    operation = request.get("operation")
    definitions = catalog.get("operations")
    if not isinstance(definitions, dict) or operation not in definitions:
        raise OperationError("operation is not registered in the runbook catalog")
    if not REQUEST_ID.fullmatch(str(request.get("request_id", ""))):
        raise OperationError("request_id is not canonical")
    if request.get("environment") not in {"local", "devnet", "production"}:
        raise OperationError("environment is invalid")
    for field in ("chain_id", "genesis_hash", "authorized_config_id"):
        if not HEX64.fullmatch(str(request.get(field, ""))):
            raise OperationError(f"{field} must be 64 lowercase hex characters")
    preconditions = request.get("preconditions")
    parameters = request.get("parameters")
    if not isinstance(preconditions, dict) or not isinstance(parameters, dict):
        raise OperationError("preconditions and parameters must be objects")
    if operation == "backup":
        require_bool(preconditions, "finalized_coordinates_captured")
        require_bool(preconditions, "worm_evidence_store_available")
        if not parameters.get("backup_destination"):
            raise OperationError("backup_destination is required")
    elif operation == "restore":
        require_bool(preconditions, "admission_disabled")
        require_bool(preconditions, "restore_target_empty")
        require_bool(preconditions, "backup_manifest_verified")
        if not parameters.get("backup_manifest"):
            raise OperationError("backup_manifest is required")
    elif operation in {"publisher_blackout", "total_blackout"}:
        require_bool(preconditions, "ordinary_finality_expected")
        require_bool(preconditions, "refund_path_ready")
    elif operation == "disable":
        if preconditions.get("expected_state") not in {"Canary", "Production"}:
            raise OperationError("disable requires Canary or Production prestate")
        require_bool(preconditions, "armed_action_validated")
        if not HEX64.fullmatch(str(parameters.get("incident_root", ""))):
            raise OperationError("disable incident_root is invalid")
    elif operation == "recovery":
        require_bool(preconditions, "admission_disabled")
        require_bool(preconditions, "fresh_finalized_prestate")
        if preconditions.get("publication_days", 0) < 7:
            raise OperationError("recovery authorization was not public for seven days")
        if parameters.get("target_tier") != preconditions.get("direct_prior_live_tier"):
            raise OperationError("recovery target is not the direct prior live tier")
        if not HEX64.fullmatch(str(parameters.get("recovery_authorization_id", ""))):
            raise OperationError("recovery authorization ID is invalid")
    elif operation == "rotate":
        require_bool(preconditions, "successor_published")
        require_bool(preconditions, "stale_key_rejection_tested")
        if not parameters.get("roles") or parameters.get("overlap_end_height", 0) <= parameters.get("activation_height", 0):
            raise OperationError("rotation requires roles and a positive overlap")
    elif operation == "rollback":
        require_bool(preconditions, "admission_disabled")
        require_bool(preconditions, "old_job_reads_available")
        if not HEX64.fullmatch(str(parameters.get("rollback_authorization_id", ""))):
            raise OperationError("rollback authorization ID is invalid")
        if not parameters.get("signed_static_target"):
            raise OperationError("rollback requires the signed static target")
    elif operation == "drill":
        if parameters.get("kind") not in DRILLS:
            raise OperationError("drill kind is not registered")
        require_bool(preconditions, "cleanup_plan_ready")
        require_bool(preconditions, "ordinary_finality_expected")
    return definitions[operation]


def verify_authorization(
    authorization: dict[str, Any],
    keyring: dict[str, Any],
    request: dict[str, Any],
    definition: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    if set(authorization) != {"schema", "body", "signatures"} or authorization.get("schema") != "noos/wwm-operation-authorization/v1":
        raise OperationError("authorization envelope is invalid")
    body = authorization.get("body")
    signatures = authorization.get("signatures")
    if not isinstance(body, dict) or not isinstance(signatures, list):
        raise OperationError("authorization body or signatures are invalid")
    expected_body_keys = {
        "request_sha256",
        "operation",
        "scope",
        "issued_at_unix",
        "expires_at_unix",
        "nonce",
    }
    if set(body) != expected_body_keys:
        raise OperationError("authorization body fields are invalid")
    if body.get("request_sha256") != request_digest(request):
        raise OperationError("authorization is bound to a different request")
    if body.get("operation") != request["operation"] or body.get("scope") != definition.get("authorization_scope"):
        raise OperationError("authorization operation or scope mismatch")
    if not isinstance(body.get("issued_at_unix"), int) or not isinstance(body.get("expires_at_unix"), int):
        raise OperationError("authorization times are invalid")
    if not body["issued_at_unix"] <= now <= body["expires_at_unix"]:
        raise OperationError("authorization is not currently valid")
    if not REQUEST_ID.fullmatch(str(body.get("nonce", ""))):
        raise OperationError("authorization nonce is invalid")
    if keyring.get("schema") != "noos/wwm-operation-keyring/v1" or keyring.get("environment") != request["environment"]:
        raise OperationError("trusted keyring schema or environment mismatch")
    scopes = keyring.get("scopes")
    keys = keyring.get("keys")
    scope = body["scope"]
    if not isinstance(scopes, dict) or not isinstance(keys, list) or scope not in scopes:
        raise OperationError("trusted keyring does not authorize this scope")
    threshold = scopes[scope].get("threshold") if isinstance(scopes[scope], dict) else None
    allowed = scopes[scope].get("key_ids") if isinstance(scopes[scope], dict) else None
    if not isinstance(threshold, int) or threshold < 1 or not isinstance(allowed, list) or threshold > len(set(allowed)):
        raise OperationError("trusted scope threshold is invalid")
    key_map = {
        row.get("key_id"): row.get("public_key_base64")
        for row in keys
        if isinstance(row, dict) and set(row) == {"key_id", "public_key_base64"}
    }
    message = DOMAIN + canonical_json(body)
    valid: set[str] = set()
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise OperationError("cryptography with Ed25519 support is required") from error
    for row in signatures:
        if not isinstance(row, dict) or set(row) != {"key_id", "signature_base64"}:
            raise OperationError("authorization signature row is malformed")
        key_id = row["key_id"]
        if key_id in valid or key_id not in allowed or key_id not in key_map:
            raise OperationError("authorization contains a duplicate or untrusted signer")
        try:
            public = base64.b64decode(key_map[key_id], validate=True)
            signature = base64.b64decode(row["signature_base64"], validate=True)
            if len(public) != 32 or hashlib.sha256(public).hexdigest() != key_id:
                raise OperationError("trusted key material is invalid")
            Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        except (ValueError, InvalidSignature) as error:
            raise OperationError("authorization signature is invalid") from error
        valid.add(key_id)
    if len(valid) < threshold:
        raise OperationError("authorization signature threshold is not met")
    return {"scope": scope, "signers": sorted(valid), "threshold": threshold, "nonce": body["nonce"]}


def operation_plan(request: dict[str, Any], definition: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "sequence": index,
            "action": action,
            "adapter_arguments": [
                "apply",
                "--operation",
                request["operation"],
                "--request-id",
                request["request_id"],
                "--step",
                action,
            ],
        }
        for index, action in enumerate(definition["steps"], start=1)
    ]


def execute_plan(adapter: Path, plan: list[dict[str, Any]]) -> None:
    if not adapter.is_file():
        raise OperationError("adapter command is not an existing file")
    for row in plan:
        completed = subprocess.run(
            [str(adapter), *row["adapter_arguments"]],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if completed.returncode != 0:
            raise OperationError(f"adapter failed at {row['action']}: {(completed.stdout + completed.stderr).strip()}")


def reserve_execution(
    state_dir: Path,
    request: dict[str, Any],
    authorization: dict[str, Any],
) -> tuple[Path, bool]:
    request_hash = request_digest(request)
    requests_dir = state_dir / "requests"
    nonces_dir = state_dir / "nonces"
    requests_dir.mkdir(parents=True, exist_ok=True)
    nonces_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = requests_dir / f"{request['request_id']}.json"
    if receipt_path.exists():
        receipt = load_object(receipt_path)
        if (
            receipt.get("request_sha256") == request_hash
            and receipt.get("status") == "EXECUTED"
        ):
            return receipt_path, True
        raise OperationError(
            "operation request has an incomplete/conflicting receipt; reconcile before retry"
        )
    nonce_path = nonces_dir / f"{authorization['nonce']}.json"
    reservation = {
        "schema": "noos/wwm-operation-execution/v1",
        "request_id": request["request_id"],
        "request_sha256": request_hash,
        "authorization_nonce": authorization["nonce"],
        "status": "STARTED",
    }
    try:
        with nonce_path.open("xb") as stream:
            stream.write(canonical_json(reservation))
        with receipt_path.open("xb") as stream:
            stream.write(canonical_json(reservation))
    except FileExistsError as error:
        raise OperationError("authorization nonce or request was already consumed") from error
    return receipt_path, False


def complete_execution(
    receipt_path: Path,
    request: dict[str, Any],
    authorization: dict[str, Any],
) -> None:
    completed = {
        "schema": "noos/wwm-operation-execution/v1",
        "request_id": request["request_id"],
        "request_sha256": request_digest(request),
        "authorization_nonce": authorization["nonce"],
        "status": "EXECUTED",
    }
    temporary = receipt_path.with_suffix(".tmp")
    temporary.write_bytes(canonical_json(completed))
    os.replace(temporary, receipt_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("request", type=Path)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--adapter-command", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--now", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        request = load_object(args.request)
        catalog = load_object(args.catalog)
        definition = validate_request(request, catalog)
        plan = operation_plan(request, definition)
        report: dict[str, Any] = {
            "schema": "noos/wwm-operation-report/v1",
            "request_id": request["request_id"],
            "operation": request["operation"],
            "request_sha256": request_digest(request),
            "mode": "EXECUTE" if args.execute else "DRY_RUN",
            "verdict": "DRY_RUN_VALID",
            "plan": plan,
            "evidence_effect": "NONE",
            "promotion_effect": "NONE",
        }
        if args.execute:
            if (
                args.authorization is None
                or args.keyring is None
                or args.adapter_command is None
                or args.state_dir is None
            ):
                raise OperationError(
                    "execution requires authorization, trusted keyring, adapter command, and state directory"
                )
            authorization = verify_authorization(
                load_object(args.authorization),
                load_object(args.keyring),
                request,
                definition,
                args.now if args.now is not None else int(time.time()),
            )
            receipt_path, already_executed = reserve_execution(
                args.state_dir, request, authorization
            )
            report["authorization"] = authorization
            if already_executed:
                report["verdict"] = "ALREADY_EXECUTED"
            else:
                execute_plan(args.adapter_command, plan)
                complete_execution(receipt_path, request, authorization)
                report["verdict"] = "EXECUTED"
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except OperationError as error:
        print(json.dumps({"verdict": "BLOCKED", "error": str(error), "evidence_effect": "NONE", "promotion_effect": "NONE"}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
