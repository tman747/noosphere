#!/usr/bin/env python3
"""Aggregate exact-revision WWM evidence under a frozen applicability profile.

The Bonsai public-text release requires PASS evidence only for claims disposed as
MANDATORY. Every E-WWM claim remains explicitly represented in the release
manifest; disabled lanes are DISABLED_NOT_CLAIMED and never count as PASS.
This gate cannot enable controls or promote a release.
"""

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
DEFAULT_EVIDENCE_ROOT = ROOT / "evidence" / "wwm"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def assess_release(
    *,
    registry_path: Path,
    experiments_path: Path,
    evidence_root: Path,
    revision: str,
    profile_id: str = evidence.BONSAI_PROFILE,
) -> tuple[int, dict[str, Any], dict[str, Any] | None]:
    registry, experiments, _ = evidence.load_contracts(registry_path, experiments_path)
    if not evidence.HEX40.fullmatch(revision):
        raise evidence.EvidenceError("release revision must be canonical 40-hex")
    profile = evidence.applicability_profile(registry, profile_id)
    dispositions = dict(sorted(profile["claim_dispositions"].items()))
    mandatory = [claim_id for claim_id, value in dispositions.items() if value == "MANDATORY"]
    disabled = [
        claim_id
        for claim_id, value in dispositions.items()
        if value == "DISABLED_NOT_CLAIMED"
    ]
    blockers: list[dict[str, str]] = []
    bundles: dict[str, str] = {}
    control_clusters: set[str] = set()
    artifact_roots: set[str] = set()
    claims = {claim["claim_id"]: claim for claim in registry["claims"]}
    for claim_id in mandatory:
        bundle_dir = evidence_root / claim_id.lower()
        if not (bundle_dir / "bundle.json").is_file():
            blockers.append({"claim": claim_id, "reason": "sealed_evidence_bundle_missing"})
            continue
        try:
            observed = evidence.verify_bundle_directory(
                bundle_dir,
                registry_path=registry_path,
                experiments_path=experiments_path,
                expected_revision=revision,
                require_sealed=True,
                enforce_pass_policy=True,
            )
        except evidence.EvidenceError as error:
            blockers.append({"claim": claim_id, "reason": str(error)})
            continue
        if observed["result"]["verdict"] != "PASS":
            blockers.append(
                {
                    "claim": claim_id,
                    "reason": f"verdict_{observed['result']['verdict'].lower()}",
                }
            )
            continue
        if observed["bundle"]["claim_id"] != claims[claim_id]["claim_id"]:
            blockers.append({"claim": claim_id, "reason": "bundle_claim_identity_mismatch"})
            continue
        bundles[claim_id] = observed["bundle"]["bundle_id"]
        control_clusters.update(observed["attestation_control_clusters"])
        artifact_roots.update(
            build["artifact_sha256"]
            for build in observed["bundle"]["reproducible_builds"]
            if build["bit_identical"]
        )
    report: dict[str, Any] = {
        "verdict": "BLOCKED" if blockers else "PASS",
        "source_revision": revision,
        "applicability_profile": profile_id,
        "claim_dispositions": dispositions,
        "mandatory_claims": mandatory,
        "disabled_not_claimed": disabled,
        "passed_mandatory_claims": len(bundles),
        "required_mandatory_claims": len(mandatory),
        "blockers": blockers,
        "controls_enabled": False,
        "promotion_effect": "NONE",
    }
    if blockers:
        return 2, report, None
    if set(bundles) != set(mandatory):
        raise evidence.EvidenceError("release aggregate omitted a mandatory claim")
    if len(control_clusters) < 3 or len(artifact_roots) < 2:
        raise evidence.EvidenceError(
            "release aggregate lacks independent clusters or reproducible artifacts"
        )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "source_revision": revision,
        "wwm_registry_sha256": hashlib.sha256(canonical_json(registry)).hexdigest(),
        "experiment_registry_sha256": hashlib.sha256(canonical_json(experiments)).hexdigest(),
        "applicability_profile": profile_id,
        "claim_dispositions": dispositions,
        "claim_bundle_ids": dict(sorted(bundles.items())),
        "independent_control_clusters": sorted(control_clusters),
        "reproducible_artifact_roots": sorted(artifact_roots),
        "unresolved_severity1_findings": 0,
        "controls_enabled": False,
        "promotion_effect": "NONE_REQUIRES_SEPARATE_SIGNED_DECISION",
        "manifest_id": None,
    }
    manifest["manifest_id"] = f"sha256:{hashlib.sha256(canonical_json(manifest)).hexdigest()}"
    return 0, report, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--experiments", type=Path, default=DEFAULT_EXPERIMENTS)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--revision")
    parser.add_argument("--applicability", default=evidence.BONSAI_PROFILE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        revision = args.revision or evidence.current_revision()
        code, report, manifest = assess_release(
            registry_path=args.registry,
            experiments_path=args.experiments,
            evidence_root=args.evidence_root,
            revision=revision,
            profile_id=args.applicability,
        )
        if manifest is None:
            emit(report)
            return code
        if args.output is not None:
            if args.output.exists():
                raise evidence.EvidenceError("release manifest output already exists")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical_json(manifest))
        emit({"verdict": "PASS", **manifest})
        return 0
    except evidence.EvidenceError as error:
        emit(
            {
                "verdict": "INVALID_EVIDENCE",
                "error": str(error),
                "controls_enabled": False,
                "promotion_effect": "NONE",
            }
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
