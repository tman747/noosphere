#!/usr/bin/env python3
"""Require all 22 exact-revision WWM evidence bundles before release packaging.

This gate only emits a content-addressed evidence manifest. Its promotion effect
is always NONE; enabling any WWM control requires a separate reviewed and signed
control change after this gate.
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--experiments", type=Path, default=DEFAULT_EXPERIMENTS)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--revision")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        registry, experiments, _ = evidence.load_contracts(args.registry, args.experiments)
        revision = args.revision or evidence.current_revision()
        if not evidence.HEX40.fullmatch(revision):
            raise evidence.EvidenceError("release revision must be canonical 40-hex")
        blockers: list[dict[str, str]] = []
        bundles: dict[str, str] = {}
        control_clusters: set[str] = set()
        artifact_roots: set[str] = set()
        for claim in registry["claims"]:
            claim_id = claim["claim_id"]
            bundle_dir = args.evidence_root / claim_id.lower()
            if not (bundle_dir / "bundle.json").is_file():
                blockers.append({"claim": claim_id, "reason": "sealed_evidence_bundle_missing"})
                continue
            try:
                observed = evidence.verify_bundle_directory(
                    bundle_dir,
                    registry_path=args.registry,
                    experiments_path=args.experiments,
                    expected_revision=revision,
                    require_sealed=True,
                    enforce_pass_policy=True,
                )
            except evidence.EvidenceError as error:
                blockers.append({"claim": claim_id, "reason": str(error)})
                continue
            if observed["result"]["verdict"] != "PASS":
                blockers.append({"claim": claim_id, "reason": f"verdict_{observed['result']['verdict'].lower()}"})
                continue
            bundles[claim_id] = observed["bundle"]["bundle_id"]
            control_clusters.update(observed["attestation_control_clusters"])
            artifact_roots.update(build["artifact_sha256"] for build in observed["bundle"]["reproducible_builds"])
        if blockers:
            emit(
                {
                    "verdict": "BLOCKED",
                    "source_revision": revision,
                    "passed_claims": len(bundles),
                    "required_claims": 22,
                    "blockers": blockers,
                    "controls_enabled": False,
                    "promotion_effect": "NONE",
                }
            )
            return 2
        if len(bundles) != 22 or len(control_clusters) < 3 or len(artifact_roots) < 2:
            raise evidence.EvidenceError("release aggregate lacks required claims, independent clusters, or reproducible artifacts")
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "source_revision": revision,
            "wwm_registry_sha256": hashlib.sha256(canonical_json(registry)).hexdigest(),
            "experiment_registry_sha256": hashlib.sha256(canonical_json(experiments)).hexdigest(),
            "claim_bundle_ids": dict(sorted(bundles.items())),
            "independent_control_clusters": sorted(control_clusters),
            "reproducible_artifact_roots": sorted(artifact_roots),
            "unresolved_severity1_findings": 0,
            "controls_enabled": False,
            "promotion_effect": "NONE_REQUIRES_SEPARATE_SIGNED_DECISION",
            "manifest_id": None,
        }
        manifest["manifest_id"] = f"sha256:{hashlib.sha256(canonical_json(manifest)).hexdigest()}"
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
