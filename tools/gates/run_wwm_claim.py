#!/usr/bin/env python3
"""Validate and execute World Wide Mind evidence claims without fake passes."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import wwm_evidence_bundle as evidence

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = ROOT / "protocol" / "claims" / "wwm-registry.json"
DEFAULT_EXPERIMENTS = ROOT / "protocol" / "claims" / "wwm-experiments.json"
EVIDENCE_ROOT = ROOT / "evidence" / "wwm"
VALID_STATUSES = {"NOT_STARTED", "PARTIAL", "IMPLEMENTED"}
VALID_EVIDENCE = {
    "UNMEASURED",
    "MEASURED_LAB",
    "INDEPENDENTLY_REPRODUCED",
    "AUDITED",
    "KILLED",
}


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def load_registry(path: Path, experiments_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    registry, experiments, _ = evidence.load_contracts(path, experiments_path)
    for claim in registry["claims"]:
        claim_id = claim["claim_id"]
        if claim.get("enabled") is not False:
            raise ValueError(f"{claim_id}:enabled_must_be_false")
        if claim.get("implementation_status") not in VALID_STATUSES:
            raise ValueError(f"{claim_id}:bad_implementation_status")
        if claim.get("evidence_status") not in VALID_EVIDENCE:
            raise ValueError(f"{claim_id}:bad_evidence_status")
        if not claim.get("pass_threshold") or not claim.get("kill_threshold"):
            raise ValueError(f"{claim_id}:missing_threshold")
        expected_command = f"python tools/gates/run_wwm_claim.py --claim {claim_id}"
        if claim.get("command") != expected_command:
            raise ValueError(f"{claim_id}:command_mismatch")
    return registry, experiments


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def run_claim(
    claim: dict[str, Any],
    evidence_root: Path,
    registry_path: Path,
    experiments_path: Path,
    revision: str,
) -> tuple[dict[str, Any], int]:
    claim_id = claim["claim_id"]
    bundle_dir = evidence_root / claim_id.lower()
    if not (bundle_dir / "bundle.json").is_file() or not (bundle_dir / "result.json").is_file():
        return (
            {
                "claim": claim_id,
                "verdict": "BLOCKED",
                "reason": "sealed_evidence_bundle_missing",
                "pass_threshold_sha256": evidence.threshold_digest(claim),
                "rollback": claim["rollback"],
                "controls_enabled": False,
                "promotion_effect": "NONE",
            },
            2,
        )
    try:
        observed = evidence.verify_bundle_directory(
            bundle_dir,
            registry_path=registry_path,
            experiments_path=experiments_path,
            expected_revision=revision,
            require_sealed=True,
            enforce_pass_policy=None,
        )
    except evidence.EvidenceError as error:
        return (
            {
                "claim": claim_id,
                "verdict": "INVALID_EVIDENCE",
                "error": str(error),
                "rollback": claim["rollback"],
                "controls_enabled": False,
                "promotion_effect": "NONE",
            },
            1,
        )
    result = observed["result"]
    if observed["bundle"]["claim_id"] != claim_id:
        return (
            {
                "claim": claim_id,
                "verdict": "INVALID_EVIDENCE",
                "error": "bundle_claim_identity_mismatch",
                "controls_enabled": False,
                "promotion_effect": "NONE",
            },
            1,
        )
    payload = {
        "claim": claim_id,
        "verdict": result["verdict"],
        "bundle_id": observed["bundle"]["bundle_id"],
        "independent_reproduction": result["independent_reproduction"],
        "attestations": len(observed["bundle"]["attestations"]),
        "measured": result["measured"],
        "raw_artifact_roots": result["raw_artifact_roots"],
        "rollback": claim["rollback"],
        "controls_enabled": False,
        "promotion_effect": "NONE_REQUIRES_SEPARATE_SIGNED_DECISION",
    }
    if result["verdict"] == "PASS":
        return payload, 0
    if result["verdict"] == "KILLED":
        return payload, 3
    return payload, 4


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--experiments", type=Path, default=DEFAULT_EXPERIMENTS)
    parser.add_argument("--evidence-root", type=Path, default=EVIDENCE_ROOT)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()

    try:
        registry, experiments = load_registry(args.registry, args.experiments)
    except (OSError, ValueError, json.JSONDecodeError, evidence.EvidenceError) as error:
        emit({"verdict": "INVALID_REGISTRY", "error": str(error)})
        return 1

    if args.validate_only:
        emit(
            {
                "verdict": "VALID",
                "claims": len(registry["claims"]),
                "experiment_policies": len(experiments["claim_policies"]),
                "controls_enabled": registry["controls_enabled"],
                "registry_sha256": hashlib.sha256(canonical_json(registry)).hexdigest(),
                "experiments_sha256": hashlib.sha256(canonical_json(experiments)).hexdigest(),
            }
        )
        return 0

    if args.all and args.claim:
        emit({"verdict": "INVALID_REQUEST", "error": "claim_and_all_are_mutually_exclusive"})
        return 1
    if not args.all and not args.claim:
        emit({"verdict": "INVALID_REQUEST", "error": "claim_or_all_required"})
        return 1
    selected = registry["claims"] if args.all else [
        claim for claim in registry["claims"] if claim["claim_id"] == args.claim
    ]
    if not selected:
        emit({"verdict": "UNKNOWN_CLAIM", "claim": args.claim})
        return 1
    try:
        revision = evidence.current_revision()
    except evidence.EvidenceError as error:
        emit({"verdict": "INVALID_ENVIRONMENT", "error": str(error)})
        return 1
    results: list[dict[str, Any]] = []
    codes: list[int] = []
    for claim in selected:
        result, code = run_claim(
            claim,
            args.evidence_root,
            args.registry,
            args.experiments,
            revision,
        )
        results.append(result)
        codes.append(code)
    if not args.all:
        emit(results[0])
        return codes[0]
    counts: dict[str, int] = {}
    for result in results:
        verdict = str(result["verdict"])
        counts[verdict] = counts.get(verdict, 0) + 1
    emit(
        {
            "verdict": "PASS" if all(code == 0 for code in codes) else "BLOCKED",
            "source_revision": revision,
            "counts": counts,
            "claims": results,
            "controls_enabled": False,
            "promotion_effect": "NONE",
        }
    )
    return 0 if all(code == 0 for code in codes) else 2


if __name__ == "__main__":
    raise SystemExit(main())
