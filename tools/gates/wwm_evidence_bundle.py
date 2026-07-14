#!/usr/bin/env python3
"""Prepare, attest, seal, and verify exact-revision WWM evidence bundles.

A bundle is content-addressed and immutable after ``seal``. A PASS bundle must
carry three Ed25519 attestations from distinct declared control clusters, two
independent reproduction records, every dependency receipt, zero unresolved
severity-1 findings, and every claim-specific artifact/drill requirement.
Signature verification proves key control; organizational independence remains
external evidence and is never inferred from key count alone.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY = ROOT / "protocol" / "claims" / "wwm-registry.json"
DEFAULT_EXPERIMENTS = ROOT / "protocol" / "claims" / "wwm-experiments.json"
DEFAULT_SCHEMA = ROOT / "protocol" / "release" / "wwm-evidence-bundle.schema.json"
SIGNATURE_DOMAIN = b"NOOS/SIG/WWM/V1\0D-WWM-EVIDENCE-BUNDLE\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
CLAIM_ID = re.compile(r"^E-WWM-(0[1-9]|1[0-9]|2[0-2])$")
VALID_VERDICTS = {"PASS", "PARTIAL", "KILLED"}
ATTESTATION_ROLES = {
    "experiment_operator",
    "independent_reproducer",
    "independent_verifier",
}
RESULT_KEYS = {
    "schema_version",
    "claim_id",
    "source_revision",
    "environment_root",
    "raw_artifact_roots",
    "pass_threshold_sha256",
    "verdict",
    "measured",
    "independent_reproduction",
    "preregistration_sha256",
}
BUNDLE_KEYS = {
    "schema_version",
    "claim_id",
    "source_revision",
    "preregistration_sha256",
    "environment",
    "result",
    "artifacts",
    "dependency_receipts",
    "reproductions",
    "second_client_vectors",
    "reproducible_builds",
    "red_team_engagements",
    "drills",
    "promotion_record",
    "severity1_open_findings",
    "attestations",
    "sealed",
    "bundle_id",
}
METADATA_KEYS = {
    "verdict",
    "raw_artifacts",
    "dependency_receipts",
    "reproductions",
    "second_client_vectors",
    "reproducible_builds",
    "red_team_engagements",
    "drills",
    "promotion_record",
    "severity1_open_findings",
}
ATTESTATION_KEYS = {
    "operator_id",
    "control_cluster_id",
    "role",
    "external_to_release_owner",
    "public_key_base64",
    "key_id",
    "payload_sha256",
    "signature_base64",
}


class EvidenceError(RuntimeError):
    """Evidence is missing, malformed, stale, or fails a registered policy."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot load JSON {path}: {error}") from error


def current_revision() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvidenceError(f"cannot resolve source revision: {error}") from error
    revision = completed.stdout.strip()
    if not HEX40.fullmatch(revision):
        raise EvidenceError("source revision is not a canonical 40-hex Git object")
    return revision


def load_contracts(
    registry_path: Path = DEFAULT_REGISTRY,
    experiments_path: Path = DEFAULT_EXPERIMENTS,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]]]:
    registry = load_json(registry_path)
    experiments = load_json(experiments_path)
    if registry.get("schema_version") != "1.0.0" or registry.get("controls_enabled") is not False:
        raise EvidenceError("invalid or enabled WWM claim registry")
    claims = registry.get("claims")
    if not isinstance(claims, list) or [row.get("claim_id") for row in claims] != [
        f"E-WWM-{index:02d}" for index in range(1, 23)
    ]:
        raise EvidenceError("claim registry must contain sorted E-WWM-01 through E-WWM-22")
    if experiments.get("schema_version") != 1 or experiments.get("controls_enabled") is not False:
        raise EvidenceError("invalid or enabled WWM experiment registry")
    common = experiments.get("common_policy")
    policies = experiments.get("claim_policies")
    if not isinstance(common, dict) or not isinstance(policies, list):
        raise EvidenceError("experiment registry policy is missing")
    expected_roles = sorted(ATTESTATION_ROLES)
    if sorted(common.get("required_attestation_roles", [])) != expected_roles:
        raise EvidenceError("experiment registry must require all independent evidence roles")
    if common.get("minimum_independent_attestations") != 3:
        raise EvidenceError("experiment registry must require three attestations")
    if common.get("minimum_distinct_control_clusters") != 3:
        raise EvidenceError("experiment registry must require three control clusters")
    if common.get("minimum_independent_reproductions") != 2:
        raise EvidenceError("experiment registry must require two reproductions")
    if common.get("maximum_unresolved_severity_1_findings") != 0:
        raise EvidenceError("severity-1 findings must block release")
    policy_map: dict[str, dict[str, Any]] = {}
    for policy in policies:
        if not isinstance(policy, dict):
            raise EvidenceError("claim policy must be an object")
        claim_id = policy.get("claim_id")
        if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id) or claim_id in policy_map:
            raise EvidenceError("claim policies must have unique canonical IDs")
        kinds = policy.get("required_artifact_kinds")
        drills = policy.get("required_drills")
        builders = policy.get("minimum_independent_builders")
        if (
            not isinstance(kinds, list)
            or len(kinds) < 3
            or len(set(kinds)) != len(kinds)
            or not all(isinstance(item, str) and item for item in kinds)
            or not isinstance(drills, list)
            or not drills
            or len(set(drills)) != len(drills)
            or not isinstance(builders, int)
            or builders < 0
            or builders > 8
            or not isinstance(policy.get("second_client_vectors_required"), bool)
            or not isinstance(policy.get("red_team_required"), bool)
        ):
            raise EvidenceError(f"{claim_id}: malformed experiment policy")
        policy_map[claim_id] = policy
    if sorted(policy_map) != [f"E-WWM-{index:02d}" for index in range(1, 23)]:
        raise EvidenceError("experiment registry must cover every WWM claim")
    schema = load_json(DEFAULT_SCHEMA)
    if schema.get("title") != "World Wide Mind immutable evidence bundle":
        raise EvidenceError("WWM evidence bundle schema is missing or wrong")
    return registry, experiments, policy_map


def claim_by_id(registry: dict[str, Any], claim_id: str) -> dict[str, Any]:
    for claim in registry["claims"]:
        if claim["claim_id"] == claim_id:
            return claim
    raise EvidenceError(f"unknown claim: {claim_id}")


def threshold_digest(claim: dict[str, Any]) -> str:
    return sha256_bytes(claim["pass_threshold"].encode("utf-8"))


def preregistration_record(
    registry: dict[str, Any],
    experiments: dict[str, Any],
    policy_map: dict[str, dict[str, Any]],
    claim_id: str,
) -> dict[str, Any]:
    claim = claim_by_id(registry, claim_id)
    return {
        "schema_version": 1,
        "claim_id": claim_id,
        "protected_property": claim["protected_property"],
        "adversary": claim["adversary"],
        "dependencies": claim["dependencies"],
        "metric": claim["metric"],
        "pass_threshold": claim["pass_threshold"],
        "kill_threshold": claim["kill_threshold"],
        "canonical_ref": claim["canonical_ref"],
        "command": claim["command"],
        "common_policy": experiments["common_policy"],
        "claim_policy": policy_map[claim_id],
    }


def preregistration_digest(
    registry: dict[str, Any],
    experiments: dict[str, Any],
    policy_map: dict[str, dict[str, Any]],
    claim_id: str,
) -> str:
    return sha256_bytes(canonical_json(preregistration_record(registry, experiments, policy_map, claim_id)))


def safe_submission_path(submission: Path, relative: str) -> Path:
    candidate = (submission / relative).resolve()
    root = submission.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise EvidenceError(f"submission path escapes root: {relative}") from error
    if not candidate.is_file():
        raise EvidenceError(f"submission artifact is missing: {relative}")
    return candidate


def artifact_descriptor(output: Path, kind: str, data: bytes) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9_][a-z0-9_.-]{0,63}", kind):
        raise EvidenceError(f"invalid artifact kind: {kind}")
    if not data:
        raise EvidenceError(f"empty artifact: {kind}")
    digest = sha256_bytes(data)
    relative = Path("artifacts") / kind / digest
    destination = output / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.read_bytes() != data:
        raise EvidenceError(f"content-address collision: {relative.as_posix()}")
    destination.write_bytes(data)
    return {
        "kind": kind,
        "path": relative.as_posix(),
        "sha256": digest,
        "bytes": len(data),
    }


def sort_records(records: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise EvidenceError("evidence records must be an array of objects")
    return sorted(records, key=lambda row: tuple(str(row.get(key, "")) for key in keys))


def prepare_bundle(
    claim_id: str,
    submission: Path,
    output: Path,
    revision: str,
    registry_path: Path = DEFAULT_REGISTRY,
    experiments_path: Path = DEFAULT_EXPERIMENTS,
) -> dict[str, Any]:
    registry, experiments, policy_map = load_contracts(registry_path, experiments_path)
    claim = claim_by_id(registry, claim_id)
    policy = policy_map[claim_id]
    if not HEX40.fullmatch(revision):
        raise EvidenceError("revision must be canonical 40-hex")
    if output.exists():
        raise EvidenceError("output path must not already exist")
    output.mkdir(parents=True, exist_ok=True)
    metadata = load_json(submission / "metadata.json")
    environment = load_json(submission / "environment.json")
    measured = load_json(submission / "measured.json")
    if not isinstance(metadata, dict) or set(metadata) != METADATA_KEYS:
        raise EvidenceError("metadata.json fields do not match the evidence contract")
    if not isinstance(environment, dict) or not environment:
        raise EvidenceError("environment.json must be a nonempty object")
    if not isinstance(measured, dict) or not measured:
        raise EvidenceError("measured.json must be a nonempty object")
    verdict = metadata["verdict"]
    if verdict not in VALID_VERDICTS:
        raise EvidenceError("invalid result verdict")
    raw_specs = metadata["raw_artifacts"]
    vector_specs = metadata["second_client_vectors"]
    if not isinstance(raw_specs, list) or not raw_specs:
        raise EvidenceError("at least one raw artifact is required")
    if not isinstance(vector_specs, list):
        raise EvidenceError("second_client_vectors must be an array")
    artifacts: list[dict[str, Any]] = []
    for spec in raw_specs:
        if not isinstance(spec, dict) or set(spec) != {"kind", "path"}:
            raise EvidenceError("raw artifact descriptor fields are invalid")
        source = safe_submission_path(submission, spec["path"])
        artifacts.append(artifact_descriptor(output, spec["kind"], source.read_bytes()))
    vectors: list[dict[str, Any]] = []
    for spec in vector_specs:
        if not isinstance(spec, dict) or set(spec) != {"kind", "path"}:
            raise EvidenceError("second-client vector descriptor fields are invalid")
        source = safe_submission_path(submission, spec["path"])
        vectors.append(artifact_descriptor(output, spec["kind"], source.read_bytes()))
    artifacts = sort_records(artifacts, ("kind", "sha256"))
    vectors = sort_records(vectors, ("kind", "sha256"))
    environment_data = canonical_json(environment)
    environment_descriptor = artifact_descriptor(output, "environment", environment_data)
    reproductions = metadata["reproductions"]
    if not isinstance(reproductions, list):
        raise EvidenceError("reproductions must be an array")
    successful_reproduction_clusters = {
        item.get("control_cluster_id")
        for item in reproductions
        if isinstance(item, dict) and item.get("verdict") == "PASS"
    }
    independent_reproduction = (
        len(successful_reproduction_clusters)
        >= experiments["common_policy"]["minimum_independent_reproductions"]
    )
    preregistration_sha256 = preregistration_digest(
        registry, experiments, policy_map, claim_id
    )
    result = {
        "schema_version": 1,
        "claim_id": claim_id,
        "source_revision": revision,
        "environment_root": f"sha256:{environment_descriptor['sha256']}",
        "raw_artifact_roots": [f"sha256:{row['sha256']}" for row in artifacts],
        "pass_threshold_sha256": threshold_digest(claim),
        "verdict": verdict,
        "measured": measured,
        "independent_reproduction": independent_reproduction,
        "preregistration_sha256": preregistration_sha256,
    }
    result_data = canonical_json(result)
    (output / "result.json").write_bytes(result_data)
    result_descriptor = artifact_descriptor(output, "result", result_data)
    bundle = {
        "schema_version": 1,
        "claim_id": claim_id,
        "source_revision": revision,
        "preregistration_sha256": preregistration_sha256,
        "environment": environment_descriptor,
        "result": result_descriptor,
        "artifacts": artifacts,
        "dependency_receipts": sort_records(metadata["dependency_receipts"], ("requirement_id",)),
        "reproductions": sort_records(reproductions, ("operator_id",)),
        "second_client_vectors": vectors,
        "reproducible_builds": sort_records(metadata["reproducible_builds"], ("builder_id",)),
        "red_team_engagements": sort_records(metadata["red_team_engagements"], ("engagement_id",)),
        "drills": sort_records(metadata["drills"], ("kind",)),
        "promotion_record": metadata["promotion_record"],
        "severity1_open_findings": metadata["severity1_open_findings"],
        "attestations": [],
        "sealed": False,
        "bundle_id": None,
    }
    (output / "bundle.json").write_bytes(canonical_json(bundle))
    verify_bundle_directory(
        output,
        registry_path=registry_path,
        experiments_path=experiments_path,
        require_sealed=False,
        enforce_pass_policy=False,
    )
    return bundle


def attestation_payload(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in bundle.items()
        if key not in {"attestations", "sealed", "bundle_id"}
    }


def attestation_message(bundle: dict[str, Any]) -> bytes:
    return SIGNATURE_DOMAIN + canonical_json(attestation_payload(bundle))


def verify_attestation(bundle: dict[str, Any], attestation: dict[str, Any]) -> None:
    if not isinstance(attestation, dict) or set(attestation) != ATTESTATION_KEYS:
        raise EvidenceError("attestation fields do not match the contract")
    if (
        not isinstance(attestation["operator_id"], str)
        or not attestation["operator_id"]
        or not HEX64.fullmatch(str(attestation["control_cluster_id"]))
        or attestation["role"] not in ATTESTATION_ROLES
        or attestation["external_to_release_owner"] is not True
        or not HEX64.fullmatch(str(attestation["key_id"]))
        or not HEX64.fullmatch(str(attestation["payload_sha256"]))
    ):
        raise EvidenceError("attestation identity or policy fields are invalid")
    message = attestation_message(bundle)
    payload_sha256 = sha256_bytes(message)
    if attestation["payload_sha256"] != payload_sha256:
        raise EvidenceError("attestation payload digest mismatch")
    try:
        public = base64.b64decode(attestation["public_key_base64"], validate=True)
        signature = base64.b64decode(attestation["signature_base64"], validate=True)
    except (ValueError, TypeError) as error:
        raise EvidenceError("attestation key/signature is not canonical base64") from error
    if len(public) != 32 or len(signature) != 64 or sha256_bytes(public) != attestation["key_id"]:
        raise EvidenceError("attestation key/signature length or key ID is invalid")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise EvidenceError("cryptography with Ed25519 support is required") from error
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
    except (ValueError, InvalidSignature) as error:
        raise EvidenceError("attestation Ed25519 signature is invalid") from error


def attach_attestation(bundle_dir: Path, attestation_path: Path) -> dict[str, Any]:
    bundle_path = bundle_dir / "bundle.json"
    bundle = load_json(bundle_path)
    if bundle.get("sealed") is not False or bundle.get("bundle_id") is not None:
        raise EvidenceError("sealed bundles are immutable")
    attestation = load_json(attestation_path)
    verify_attestation(bundle, attestation)
    existing = bundle["attestations"]
    if any(
        row["operator_id"] == attestation["operator_id"]
        or row["key_id"] == attestation["key_id"]
        for row in existing
    ):
        raise EvidenceError("duplicate attestation identity or key")
    existing.append(attestation)
    existing.sort(key=lambda row: (row["role"], row["operator_id"]))
    bundle_path.write_bytes(canonical_json(bundle))
    return bundle


def descriptor_hashes(bundle: dict[str, Any]) -> set[str]:
    descriptors = [bundle["environment"], bundle["result"], *bundle["artifacts"], *bundle["second_client_vectors"]]
    return {descriptor["sha256"] for descriptor in descriptors}


def validate_descriptor(bundle_dir: Path, descriptor: Any) -> None:
    if not isinstance(descriptor, dict) or set(descriptor) != {"kind", "path", "sha256", "bytes"}:
        raise EvidenceError("artifact descriptor fields are invalid")
    kind = descriptor["kind"]
    digest = descriptor["sha256"]
    relative = descriptor["path"]
    if (
        not isinstance(kind, str)
        or not re.fullmatch(r"[a-z0-9_][a-z0-9_.-]{0,63}", kind)
        or not isinstance(digest, str)
        or not HEX64.fullmatch(digest)
        or relative != f"artifacts/{kind}/{digest}"
        or not isinstance(descriptor["bytes"], int)
        or descriptor["bytes"] <= 0
    ):
        raise EvidenceError("artifact descriptor value is invalid")
    path = (bundle_dir / relative).resolve()
    try:
        path.relative_to(bundle_dir.resolve())
    except ValueError as error:
        raise EvidenceError("artifact path escapes bundle") from error
    if not path.is_file() or path.stat().st_size != descriptor["bytes"] or sha256_file(path) != digest:
        raise EvidenceError(f"artifact integrity mismatch: {relative}")


def require_hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise EvidenceError(f"{field} must be a lowercase SHA-256 digest")
    return value


def validate_evidence_records(
    bundle: dict[str, Any],
    claim: dict[str, Any],
    policy: dict[str, Any],
    common: dict[str, Any],
    available_hashes: set[str],
    enforce_pass_policy: bool,
) -> None:
    dependencies = bundle["dependency_receipts"]
    reproductions = bundle["reproductions"]
    builds = bundle["reproducible_builds"]
    engagements = bundle["red_team_engagements"]
    drills = bundle["drills"]
    for name, values in (
        ("dependency_receipts", dependencies),
        ("reproductions", reproductions),
        ("reproducible_builds", builds),
        ("red_team_engagements", engagements),
        ("drills", drills),
    ):
        if not isinstance(values, list):
            raise EvidenceError(f"{name} must be an array")
    dependency_ids: list[str] = []
    for receipt in dependencies:
        if not isinstance(receipt, dict) or set(receipt) != {
            "requirement_id", "source_revision", "verdict", "evidence_sha256"
        }:
            raise EvidenceError("dependency receipt fields are invalid")
        dependency_ids.append(receipt["requirement_id"])
        if receipt["source_revision"] != bundle["source_revision"] or receipt["verdict"] != "PASS":
            raise EvidenceError("dependency receipt is stale or not PASS")
        if require_hash(receipt["evidence_sha256"], "dependency evidence") not in available_hashes:
            raise EvidenceError("dependency evidence is not embedded in the bundle")
    if dependency_ids != sorted(set(dependency_ids)):
        raise EvidenceError("dependency receipts must be unique and sorted")
    reproduction_ids: list[str] = []
    successful_clusters: set[str] = set()
    for reproduction in reproductions:
        if not isinstance(reproduction, dict) or set(reproduction) != {
            "operator_id", "control_cluster_id", "source_revision", "environment_sha256", "artifact_sha256", "verdict"
        }:
            raise EvidenceError("reproduction fields are invalid")
        reproduction_ids.append(reproduction["operator_id"])
        cluster = require_hash(reproduction["control_cluster_id"], "reproduction control cluster")
        if reproduction["source_revision"] != bundle["source_revision"]:
            raise EvidenceError("reproduction source revision is stale")
        for field in ("environment_sha256", "artifact_sha256"):
            if require_hash(reproduction[field], field) not in available_hashes:
                raise EvidenceError("reproduction evidence is not embedded in the bundle")
        if reproduction["verdict"] not in VALID_VERDICTS:
            raise EvidenceError("invalid reproduction verdict")
        if reproduction["verdict"] == "PASS":
            successful_clusters.add(cluster)
    if reproduction_ids != sorted(set(reproduction_ids)):
        raise EvidenceError("reproductions must be unique and sorted")
    builder_ids: list[str] = []
    builder_clusters: set[str] = set()
    for build in builds:
        if not isinstance(build, dict) or set(build) != {
            "builder_id", "control_cluster_id", "source_revision", "artifact_sha256", "bit_identical"
        }:
            raise EvidenceError("reproducible build fields are invalid")
        builder_ids.append(build["builder_id"])
        builder_clusters.add(require_hash(build["control_cluster_id"], "builder control cluster"))
        if build["source_revision"] != bundle["source_revision"]:
            raise EvidenceError("reproducible build source revision is stale")
        if require_hash(build["artifact_sha256"], "build artifact") not in available_hashes:
            raise EvidenceError("reproducible build artifact is not embedded")
        if not isinstance(build["bit_identical"], bool):
            raise EvidenceError("bit_identical must be boolean")
    if builder_ids != sorted(set(builder_ids)):
        raise EvidenceError("reproducible builders must be unique and sorted")
    engagement_ids: list[str] = []
    engagement_severity1 = 0
    for engagement in engagements:
        if not isinstance(engagement, dict) or set(engagement) != {
            "engagement_id", "control_cluster_id", "funding_proof_sha256", "report_sha256", "severity1_open"
        }:
            raise EvidenceError("red-team engagement fields are invalid")
        engagement_ids.append(engagement["engagement_id"])
        require_hash(engagement["control_cluster_id"], "red-team control cluster")
        for field in ("funding_proof_sha256", "report_sha256"):
            if require_hash(engagement[field], field) not in available_hashes:
                raise EvidenceError("red-team evidence is not embedded")
        if not isinstance(engagement["severity1_open"], int) or engagement["severity1_open"] < 0:
            raise EvidenceError("red-team severity count is invalid")
        engagement_severity1 += engagement["severity1_open"]
    if engagement_ids != sorted(set(engagement_ids)):
        raise EvidenceError("red-team engagements must be unique and sorted")
    drill_kinds: list[str] = []
    for drill in drills:
        if not isinstance(drill, dict) or set(drill) != {"kind", "artifact_sha256", "verdict"}:
            raise EvidenceError("drill fields are invalid")
        drill_kinds.append(drill["kind"])
        if require_hash(drill["artifact_sha256"], "drill artifact") not in available_hashes:
            raise EvidenceError("drill evidence is not embedded")
        if drill["verdict"] not in {"PASS", "FAIL"}:
            raise EvidenceError("invalid drill verdict")
    if drill_kinds != sorted(set(drill_kinds)):
        raise EvidenceError("drills must be unique and sorted")
    if not isinstance(bundle["severity1_open_findings"], int) or bundle["severity1_open_findings"] < 0:
        raise EvidenceError("severity1_open_findings must be a nonnegative integer")
    promotion = bundle["promotion_record"]
    if promotion is not None:
        if not isinstance(promotion, dict) or set(promotion) != {
            "decision", "record_sha256", "approver_control_clusters"
        }:
            raise EvidenceError("promotion record fields are invalid")
        if promotion["decision"] not in {"HOLD", "ELIGIBLE_FOR_SEPARATE_PROMOTION"}:
            raise EvidenceError("invalid promotion decision")
        if require_hash(promotion["record_sha256"], "promotion record") not in available_hashes:
            raise EvidenceError("promotion record is not embedded")
        approvers = promotion["approver_control_clusters"]
        if (
            not isinstance(approvers, list)
            or len(set(approvers)) < 2
            or sorted(set(approvers)) != approvers
        ):
            raise EvidenceError("promotion record lacks two sorted independent approver clusters")
        for cluster in approvers:
            require_hash(cluster, "promotion approver control cluster")
    if not enforce_pass_policy:
        return
    if dependency_ids != sorted(claim["dependencies"]):
        raise EvidenceError("PASS bundle does not contain every exact dependency receipt")
    if len(successful_clusters) < common["minimum_independent_reproductions"]:
        raise EvidenceError("PASS bundle lacks independent reproductions")
    if policy["minimum_independent_builders"] > 0:
        if len(builder_clusters) < policy["minimum_independent_builders"] or any(
            not build["bit_identical"] for build in builds
        ):
            raise EvidenceError("PASS bundle lacks bit-identical independent builders")
    if policy["red_team_required"] and not engagements:
        raise EvidenceError("PASS bundle lacks a funded red-team engagement")
    if engagement_severity1 != 0 or bundle["severity1_open_findings"] != 0:
        raise EvidenceError("unresolved severity-1 finding blocks PASS")
    drills_by_kind = {drill["kind"]: drill["verdict"] for drill in drills}
    if any(drills_by_kind.get(kind) != "PASS" for kind in policy["required_drills"]):
        raise EvidenceError("required install/update/rollback or failure drill did not pass")
    if promotion is None:
        raise EvidenceError("PASS bundle lacks a promotion decision record")


def verify_bundle_directory(
    bundle_dir: Path,
    *,
    registry_path: Path = DEFAULT_REGISTRY,
    experiments_path: Path = DEFAULT_EXPERIMENTS,
    expected_revision: str | None = None,
    require_sealed: bool = True,
    enforce_pass_policy: bool | None = None,
) -> dict[str, Any]:
    registry, experiments, policy_map = load_contracts(registry_path, experiments_path)
    bundle = load_json(bundle_dir / "bundle.json")
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_KEYS:
        raise EvidenceError("bundle manifest fields do not match the contract")
    claim_id = bundle.get("claim_id")
    if not isinstance(claim_id, str) or not CLAIM_ID.fullmatch(claim_id):
        raise EvidenceError("bundle claim ID is invalid")
    claim = claim_by_id(registry, claim_id)
    policy = policy_map[claim_id]
    if bundle.get("schema_version") != 1 or not HEX40.fullmatch(str(bundle.get("source_revision"))):
        raise EvidenceError("bundle schema version or source revision is invalid")
    if expected_revision is not None and bundle["source_revision"] != expected_revision:
        raise EvidenceError("bundle source revision is stale")
    expected_preregistration = preregistration_digest(registry, experiments, policy_map, claim_id)
    if bundle.get("preregistration_sha256") != expected_preregistration:
        raise EvidenceError("bundle preregistration digest is stale")
    for field in (
        "artifacts",
        "dependency_receipts",
        "reproductions",
        "second_client_vectors",
        "reproducible_builds",
        "red_team_engagements",
        "drills",
        "attestations",
    ):
        if not isinstance(bundle[field], list):
            raise EvidenceError(f"{field} must be an array")
    if not bundle["artifacts"]:
        raise EvidenceError("bundle must contain raw artifacts")
    descriptors = [bundle["environment"], bundle["result"], *bundle["artifacts"], *bundle["second_client_vectors"]]
    descriptor_paths: set[str] = set()
    for descriptor in descriptors:
        validate_descriptor(bundle_dir, descriptor)
        if descriptor["path"] in descriptor_paths:
            raise EvidenceError("duplicate artifact descriptor")
        descriptor_paths.add(descriptor["path"])
    if bundle["environment"]["kind"] != "environment" or bundle["result"]["kind"] != "result":
        raise EvidenceError("environment/result descriptor kind is invalid")
    top_result = bundle_dir / "result.json"
    if not top_result.is_file():
        raise EvidenceError("top-level result.json is missing")
    if top_result.read_bytes() != (bundle_dir / bundle["result"]["path"]).read_bytes():
        raise EvidenceError("top-level result.json differs from its content-addressed artifact")
    result = load_json(bundle_dir / "result.json")
    if not isinstance(result, dict) or set(result) != RESULT_KEYS:
        raise EvidenceError("result.json fields do not match the contract")
    raw_roots = [f"sha256:{row['sha256']}" for row in bundle["artifacts"]]
    if (
        result["schema_version"] != 1
        or result["claim_id"] != claim_id
        or result["source_revision"] != bundle["source_revision"]
        or result["environment_root"] != f"sha256:{bundle['environment']['sha256']}"
        or result["raw_artifact_roots"] != raw_roots
        or result["pass_threshold_sha256"] != threshold_digest(claim)
        or result["verdict"] not in VALID_VERDICTS
        or not isinstance(result["measured"], dict)
        or not result["measured"]
        or not isinstance(result["independent_reproduction"], bool)
        or result["preregistration_sha256"] != expected_preregistration
    ):
        raise EvidenceError("result identity, threshold, roots, or measured values are invalid")
    artifact_kinds = {descriptor["kind"] for descriptor in bundle["artifacts"]}
    if not set(policy["required_artifact_kinds"]).issubset(artifact_kinds):
        raise EvidenceError("bundle lacks claim-specific raw artifact kinds")
    if policy["second_client_vectors_required"] and not bundle["second_client_vectors"]:
        raise EvidenceError("bundle lacks required second-client vectors")
    available_hashes = descriptor_hashes(bundle)
    if enforce_pass_policy is None:
        enforce_pass_policy = result["verdict"] == "PASS"
    validate_evidence_records(
        bundle,
        claim,
        policy,
        experiments["common_policy"],
        available_hashes,
        enforce_pass_policy,
    )
    attestations = bundle["attestations"]
    if not isinstance(attestations, list):
        raise EvidenceError("attestations must be an array")
    operator_ids: set[str] = set()
    key_ids: set[str] = set()
    attestation_clusters: set[str] = set()
    roles: set[str] = set()
    for attestation in attestations:
        verify_attestation(bundle, attestation)
        if attestation["operator_id"] in operator_ids or attestation["key_id"] in key_ids:
            raise EvidenceError("attestation operator/key is duplicated")
        operator_ids.add(attestation["operator_id"])
        key_ids.add(attestation["key_id"])
        attestation_clusters.add(attestation["control_cluster_id"])
        roles.add(attestation["role"])
    common = experiments["common_policy"]
    if enforce_pass_policy:
        if (
            len(attestations) < common["minimum_independent_attestations"]
            or len(attestation_clusters) < common["minimum_distinct_control_clusters"]
            or roles != set(common["required_attestation_roles"])
            or result["independent_reproduction"] is not True
        ):
            raise EvidenceError("PASS bundle lacks independently controlled signed attestations")
    if require_sealed:
        if bundle["sealed"] is not True or not isinstance(bundle["bundle_id"], str):
            raise EvidenceError("bundle is not sealed")
        unsigned_id = dict(bundle)
        observed_bundle_id = unsigned_id.pop("bundle_id")
        unsigned_id["bundle_id"] = None
        expected_bundle_id = f"sha256:{sha256_bytes(canonical_json(unsigned_id))}"
        if observed_bundle_id != expected_bundle_id:
            raise EvidenceError("sealed bundle ID mismatch")
    elif bundle["sealed"] is not False or bundle["bundle_id"] is not None:
        raise EvidenceError("open bundle has invalid seal fields")
    return {
        "bundle": bundle,
        "result": result,
        "claim": claim,
        "policy": policy,
        "attestation_control_clusters": sorted(attestation_clusters),
        "available_hashes": sorted(available_hashes),
    }


def seal_bundle(
    bundle_dir: Path,
    registry_path: Path = DEFAULT_REGISTRY,
    experiments_path: Path = DEFAULT_EXPERIMENTS,
) -> dict[str, Any]:
    observed = verify_bundle_directory(
        bundle_dir,
        registry_path=registry_path,
        experiments_path=experiments_path,
        require_sealed=False,
        enforce_pass_policy=None,
    )
    bundle = observed["bundle"]
    bundle["sealed"] = True
    bundle["bundle_id"] = None
    bundle["bundle_id"] = f"sha256:{sha256_bytes(canonical_json(bundle))}"
    (bundle_dir / "bundle.json").write_bytes(canonical_json(bundle))
    verify_bundle_directory(
        bundle_dir,
        registry_path=registry_path,
        experiments_path=experiments_path,
        require_sealed=True,
        enforce_pass_policy=None,
    )
    return bundle


def emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--experiments", type=Path, default=DEFAULT_EXPERIMENTS)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate-contract")

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--claim", required=True)
    prepare.add_argument("--submission", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--revision", default=None)

    payload = subparsers.add_parser("attestation-payload")
    payload.add_argument("--bundle", type=Path, required=True)
    payload.add_argument("--output", type=Path, required=True)

    attach = subparsers.add_parser("attach-attestation")
    attach.add_argument("--bundle", type=Path, required=True)
    attach.add_argument("--attestation", type=Path, required=True)

    seal = subparsers.add_parser("seal")
    seal.add_argument("--bundle", type=Path, required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--expected-revision")

    args = parser.parse_args()
    try:
        if args.command == "validate-contract":
            registry, experiments, policies = load_contracts(args.registry, args.experiments)
            emit(
                {
                    "verdict": "VALID",
                    "claims": len(registry["claims"]),
                    "experiment_policies": len(policies),
                    "controls_enabled": experiments["controls_enabled"],
                    "experiments_sha256": sha256_bytes(canonical_json(experiments)),
                }
            )
            return 0
        if args.command == "prepare":
            revision = args.revision or current_revision()
            bundle = prepare_bundle(
                args.claim,
                args.submission,
                args.output,
                revision,
                args.registry,
                args.experiments,
            )
            emit(
                {
                    "verdict": "PREPARED_UNSEALED",
                    "claim": bundle["claim_id"],
                    "source_revision": bundle["source_revision"],
                    "attestations": 0,
                    "promotion_effect": "NONE",
                }
            )
            return 0
        if args.command == "attestation-payload":
            bundle = load_json(args.bundle / "bundle.json")
            if bundle.get("sealed") is not False:
                raise EvidenceError("sealed bundle cannot accept attestations")
            message = attestation_message(bundle)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(message)
            emit(
                {
                    "verdict": "PAYLOAD_READY",
                    "path": str(args.output),
                    "payload_sha256": sha256_bytes(message),
                    "bytes": len(message),
                }
            )
            return 0
        if args.command == "attach-attestation":
            bundle = attach_attestation(args.bundle, args.attestation)
            emit(
                {
                    "verdict": "ATTESTATION_ATTACHED",
                    "claim": bundle["claim_id"],
                    "attestations": len(bundle["attestations"]),
                    "promotion_effect": "NONE",
                }
            )
            return 0
        if args.command == "seal":
            bundle = seal_bundle(args.bundle, args.registry, args.experiments)
            emit(
                {
                    "verdict": "SEALED",
                    "claim": bundle["claim_id"],
                    "bundle_id": bundle["bundle_id"],
                    "promotion_effect": "NONE",
                }
            )
            return 0
        observed = verify_bundle_directory(
            args.bundle,
            registry_path=args.registry,
            experiments_path=args.experiments,
            expected_revision=args.expected_revision,
        )
        emit(
            {
                "verdict": observed["result"]["verdict"],
                "claim": observed["bundle"]["claim_id"],
                "bundle_id": observed["bundle"]["bundle_id"],
                "attestations": len(observed["bundle"]["attestations"]),
                "independent_reproduction": observed["result"]["independent_reproduction"],
                "promotion_effect": "NONE",
            }
        )
        return 0 if observed["result"]["verdict"] == "PASS" else 4
    except EvidenceError as error:
        emit({"verdict": "INVALID_EVIDENCE", "error": str(error), "promotion_effect": "NONE"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
