#!/usr/bin/env python3
"""Record and compare raw mobile release outputs from independent builders."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from tools.operations import mobile_release_supply as supply
except ModuleNotFoundError:
    import mobile_release_supply as supply

REGISTRY_SCHEMA = "noos/mobile-independent-builder-registry/v1"
ENVIRONMENT_SCHEMA = "noos/mobile-independent-build-environment/v1"
OBSERVATION_SCHEMA = "noos/mobile-independent-build-observation/v1"
COMPARISON_SCHEMA = "noos/mobile-independent-reproduction-comparison/v1"
OBSERVATION_DOMAIN = b"NOOS/SIG/MOBILE-INDEPENDENT-BUILD-OBSERVATION/V1\0"
COMPARISON_DOMAIN = b"NOOS/SIG/MOBILE-INDEPENDENT-REPRODUCTION/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_BUILDERS = 16
MAX_DIFFERENCES = 100_000
REGISTRY_KEYS = {"schema", "source_revision", "verifier_key_id", "builders"}
BUILDER_KEYS = {"builder_id", "organization", "control_cluster_id", "public_key_base64", "key_id"}
ENVIRONMENT_KEYS = {
    "schema",
    "builder_id",
    "source_revision",
    "host_os",
    "host_arch",
    "host_fingerprint_sha256",
    "source_archive_sha256",
    "build_commands_sha256",
    "toolchains",
    "clean_checkout",
    "generated_outputs_unmodified",
}
OBSERVATION_BODY_KEYS = {
    "observation_id",
    "builder_id",
    "control_cluster_id",
    "source_revision",
    "subject_manifest_id",
    "subject_manifest_sha256",
    "checksums_sha256",
    "environment_sha256",
    "environment",
    "subjects",
    "normalization_applied",
    "observed_at_utc",
    "production",
    "promotion_effect",
}
SIGNATURE_KEYS = {"suite", "domain", "key_id", "public_key_base64", "signature_base64"}


class ReproductionError(RuntimeError):
    """Independent-build evidence is malformed, untrusted, or overstated."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        if path.stat().st_size > maximum_bytes:
            raise ReproductionError(f"{path} exceeds the bounded evidence size")
        value = json.loads(path.read_text(encoding="utf-8"))
    except ReproductionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReproductionError(f"cannot load JSON object {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReproductionError(f"{path} must contain a JSON object")
    return value


def atomic_create(path: Path, value: Mapping[str, Any]) -> None:
    if path.exists():
        raise ReproductionError(f"refusing to overwrite evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(canonical_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ReproductionError(f"refusing to overwrite evidence: {path}") from error
        except OSError as error:
            raise ReproductionError(f"cannot publish insert-once evidence {path}: {error}") from error
        temporary.unlink()
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def decode_public(value: Any, key_id: Any) -> bytes:
    try:
        public = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise ReproductionError("builder public key is not canonical base64") from error
    if len(public) != 32 or not isinstance(key_id, str) or HEX64.fullmatch(key_id) is None or sha256_bytes(public) != key_id:
        raise ReproductionError("builder key ID does not bind one Ed25519 public key")
    return public


def load_private(path: Path) -> Ed25519PrivateKey:
    try:
        encoded = path.read_bytes()
        raw = encoded if len(encoded) == 32 else base64.b64decode(encoded.strip(), validate=True)
    except (OSError, TypeError, ValueError) as error:
        raise ReproductionError("Ed25519 seed must be 32 raw bytes or canonical base64") from error
    if len(raw) != 32:
        raise ReproductionError("Ed25519 seed must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_identity(private: Ed25519PrivateKey) -> tuple[str, str]:
    public = private.public_key().public_bytes_raw()
    return base64.b64encode(public).decode("ascii"), sha256_bytes(public)


def signature_record(private: Ed25519PrivateKey, domain: bytes, body: Mapping[str, Any]) -> dict[str, str]:
    public, key_id = public_identity(private)
    return {
        "suite": "Ed25519",
        "domain": domain.rstrip(b"\0").decode("ascii"),
        "key_id": key_id,
        "public_key_base64": public,
        "signature_base64": base64.b64encode(private.sign(domain + canonical_json(body))).decode("ascii"),
    }


def verify_signature(record: Any, domain: bytes, body: Mapping[str, Any], expected_key_id: str, expected_public: str | None = None) -> None:
    if not isinstance(record, dict) or set(record) != SIGNATURE_KEYS:
        raise ReproductionError("signature fields do not match the closed contract")
    public = decode_public(record["public_key_base64"], record["key_id"])
    if record["suite"] != "Ed25519" or record["domain"] != domain.rstrip(b"\0").decode("ascii") or record["key_id"] != expected_key_id or (expected_public is not None and record["public_key_base64"] != expected_public):
        raise ReproductionError("signature identity differs from the preregistered signer")
    try:
        signature = base64.b64decode(record["signature_base64"], validate=True)
        if len(signature) != 64:
            raise ValueError("wrong signature length")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, domain + canonical_json(body))
    except (TypeError, ValueError, InvalidSignature) as error:
        raise ReproductionError("Ed25519 evidence signature is forged or invalid") from error


def validate_registry(registry: Any, expected_sha256: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not isinstance(registry, dict) or set(registry) != REGISTRY_KEYS or registry.get("schema") != REGISTRY_SCHEMA:
        raise ReproductionError("independent builder registry fields do not match the closed contract")
    if sha256_bytes(canonical_json(registry)) != expected_sha256 or HEX64.fullmatch(expected_sha256) is None:
        raise ReproductionError("independent builder registry differs from its preregistered digest")
    revision = registry["source_revision"]
    if not isinstance(revision, str) or HEX40.fullmatch(revision) is None or HEX64.fullmatch(str(registry["verifier_key_id"])) is None:
        raise ReproductionError("independent builder registry release or verifier identity is invalid")
    builders = registry["builders"]
    if not isinstance(builders, list) or not 2 <= len(builders) <= MAX_BUILDERS:
        raise ReproductionError("independent builder registry requires 2..=16 builders")
    by_id: dict[str, dict[str, Any]] = {}
    clusters: set[str] = set()
    keys: set[str] = set()
    for builder in builders:
        if not isinstance(builder, dict) or set(builder) != BUILDER_KEYS:
            raise ReproductionError("builder registry row fields do not match the closed contract")
        builder_id = builder["builder_id"]
        organization = builder["organization"]
        cluster = builder["control_cluster_id"]
        if TOKEN.fullmatch(str(builder_id)) is None or not isinstance(organization, str) or not organization or len(organization.encode("utf-8")) > 128 or HEX64.fullmatch(str(cluster)) is None:
            raise ReproductionError("builder identity, organization, or control cluster is invalid")
        decode_public(builder["public_key_base64"], builder["key_id"])
        if builder_id in by_id or cluster in clusters or builder["key_id"] in keys:
            raise ReproductionError("independent builders reuse identity, control, or signing keys")
        by_id[builder_id] = builder
        clusters.add(cluster)
        keys.add(builder["key_id"])
    if [row["builder_id"] for row in builders] != sorted(by_id):
        raise ReproductionError("independent builder registry must be sorted by builder ID")
    return registry, by_id


def validate_environment(environment: Any, builder_id: str, revision: str) -> dict[str, Any]:
    if not isinstance(environment, dict) or set(environment) != ENVIRONMENT_KEYS or environment.get("schema") != ENVIRONMENT_SCHEMA:
        raise ReproductionError("independent build environment fields do not match the closed contract")
    if environment["builder_id"] != builder_id or environment["source_revision"] != revision:
        raise ReproductionError("independent build environment belongs to another builder or revision")
    if environment["clean_checkout"] is not True or environment["generated_outputs_unmodified"] is not True:
        raise ReproductionError("independent build was not clean or changed generated outputs")
    for field in ("host_fingerprint_sha256", "source_archive_sha256", "build_commands_sha256"):
        if HEX64.fullmatch(str(environment[field])) is None:
            raise ReproductionError(f"independent build environment {field} is invalid")
    for field in ("host_os", "host_arch"):
        if TOKEN.fullmatch(str(environment[field])) is None:
            raise ReproductionError(f"independent build environment {field} is invalid")
    toolchains = environment["toolchains"]
    if not isinstance(toolchains, dict) or not toolchains or len(toolchains) > 32 or not all(TOKEN.fullmatch(str(key)) and isinstance(value, str) and value and len(value) <= 128 for key, value in toolchains.items()):
        raise ReproductionError("independent build toolchain inventory is invalid or unbounded")
    return environment


def observation_id(body: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json({key: value for key, value in body.items() if key != "observation_id"}))


def record_observation(
    manifest_path: Path,
    checksums_path: Path,
    environment_path: Path,
    registry_path: Path,
    registry_sha256: str,
    builder_id: str,
    seed_path: Path,
    output: Path,
    *,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    registry, builders = validate_registry(load_object(registry_path), registry_sha256)
    builder = builders.get(builder_id)
    if builder is None:
        raise ReproductionError("builder is not present in the preregistered registry")
    try:
        manifest = supply.verify(manifest_path, checksums_path)
    except supply.SupplyError as error:
        raise ReproductionError(f"mobile subject manifest rejected: {error}") from error
    revision = registry["source_revision"]
    if manifest["source_revision"] != revision:
        raise ReproductionError("mobile subject manifest revision differs from the builder registry")
    environment = validate_environment(load_object(environment_path), builder_id, revision)
    private = load_private(seed_path)
    _, key_id = public_identity(private)
    if key_id != builder["key_id"]:
        raise ReproductionError("builder seed does not match the preregistered signing key")
    observed = observed_at or datetime.now(timezone.utc)
    body: dict[str, Any] = {
        "observation_id": "0" * 64,
        "builder_id": builder_id,
        "control_cluster_id": builder["control_cluster_id"],
        "source_revision": revision,
        "subject_manifest_id": manifest["manifest_id"],
        "subject_manifest_sha256": sha256_file(manifest_path),
        "checksums_sha256": sha256_file(checksums_path),
        "environment_sha256": sha256_bytes(canonical_json(environment)),
        "environment": environment,
        "subjects": manifest["subjects"],
        "normalization_applied": False,
        "observed_at_utc": observed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "production": False,
        "promotion_effect": "NONE",
    }
    body["observation_id"] = observation_id(body)
    envelope = {"schema": OBSERVATION_SCHEMA, "body": body, "signature": signature_record(private, OBSERVATION_DOMAIN, body)}
    atomic_create(output, envelope)
    return envelope


def verify_observation(document: Any, registry: Mapping[str, Any], builders: Mapping[str, Mapping[str, Any]], *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {"schema", "body", "signature"} or document.get("schema") != OBSERVATION_SCHEMA:
        raise ReproductionError("independent build observation envelope is malformed")
    body = document["body"]
    if not isinstance(body, dict) or set(body) != OBSERVATION_BODY_KEYS or body.get("observation_id") != observation_id(body):
        raise ReproductionError("independent build observation body or ID is malformed")
    builder = builders.get(body["builder_id"])
    if builder is None or body["control_cluster_id"] != builder["control_cluster_id"] or body["source_revision"] != registry["source_revision"]:
        raise ReproductionError("independent build observation is unregistered or stale")
    if body["normalization_applied"] is not False or body["production"] is not False or body["promotion_effect"] != "NONE":
        raise ReproductionError("independent build observation was normalized or crosses assurance boundaries")
    environment = validate_environment(body["environment"], body["builder_id"], body["source_revision"])
    if body["environment_sha256"] != sha256_bytes(canonical_json(environment)):
        raise ReproductionError("independent build environment digest is stale")
    if HEX64.fullmatch(str(body["subject_manifest_id"])) is None or HEX64.fullmatch(str(body["subject_manifest_sha256"])) is None or HEX64.fullmatch(str(body["checksums_sha256"])) is None:
        raise ReproductionError("independent build subject identity is invalid")
    subjects = body["subjects"]
    if not isinstance(subjects, list) or not subjects or len(subjects) > supply.MAX_FILES:
        raise ReproductionError("independent build subject inventory is malformed")
    prior: tuple[str, str] | None = None
    labels: set[str] = set()
    for row in subjects:
        if not isinstance(row, dict) or set(row) != {"label", "path", "bytes", "sha256"} or row["label"] not in supply.REQUIRED_LABELS or not isinstance(row["path"], str):
            raise ReproductionError("independent build subject descriptor is malformed")
        supply.safe_relative(row["path"])
        key = (row["label"], row["path"])
        if prior is not None and key <= prior:
            raise ReproductionError("independent build subjects are unsorted or duplicated")
        prior = key
        labels.add(row["label"])
        if not isinstance(row["bytes"], int) or isinstance(row["bytes"], bool) or row["bytes"] < 0 or HEX64.fullmatch(str(row["sha256"])) is None:
            raise ReproductionError("independent build subject size or digest is invalid")
    if labels != supply.REQUIRED_LABELS:
        raise ReproductionError("independent build does not cover every supported release label")
    observed = body["observed_at_utc"]
    if not isinstance(observed, str) or UTC.fullmatch(observed) is None:
        raise ReproductionError("independent build observation timestamp is not canonical UTC")
    parsed = datetime.strptime(observed, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed > (now or datetime.now(timezone.utc)):
        raise ReproductionError("independent build observation is future-dated")
    verify_signature(document["signature"], OBSERVATION_DOMAIN, body, builder["key_id"], builder["public_key_base64"])
    return body


def comparison_id(body: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json({key: value for key, value in body.items() if key != "comparison_id"}))


def compare(
    observation_paths: list[Path],
    registry_path: Path,
    registry_sha256: str,
    expected_verifier_key_id: str,
    verifier_seed_path: Path,
    output: Path,
    *,
    compared_at: datetime | None = None,
) -> dict[str, Any]:
    registry, builders = validate_registry(load_object(registry_path), registry_sha256)
    compared = compared_at or datetime.now(timezone.utc)
    observations = [verify_observation(load_object(path), registry, builders, now=compared) for path in observation_paths]
    by_builder = {row["builder_id"]: row for row in observations}
    if set(by_builder) != set(builders) or len(by_builder) != len(observations):
        raise ReproductionError("comparison requires one signed observation from every preregistered builder")
    baseline_id = sorted(by_builder)[0]
    baseline = {(row["label"], row["path"]): row for row in by_builder[baseline_id]["subjects"]}
    differences: list[dict[str, Any]] = []
    for builder_id in sorted(by_builder):
        if builder_id == baseline_id:
            continue
        candidate = {(row["label"], row["path"]): row for row in by_builder[builder_id]["subjects"]}
        for label, path in sorted(set(baseline) | set(candidate)):
            left = baseline.get((label, path))
            right = candidate.get((label, path))
            if left != right:
                differences.append(
                    {
                        "label": label,
                        "path": path,
                        "baseline_builder_id": baseline_id,
                        "baseline_bytes": None if left is None else left["bytes"],
                        "baseline_sha256": None if left is None else left["sha256"],
                        "compared_builder_id": builder_id,
                        "compared_bytes": None if right is None else right["bytes"],
                        "compared_sha256": None if right is None else right["sha256"],
                    }
                )
                if len(differences) > MAX_DIFFERENCES:
                    raise ReproductionError("independent build differences exceed the bounded evidence size")
    private = load_private(verifier_seed_path)
    _, verifier_key_id = public_identity(private)
    if verifier_key_id != expected_verifier_key_id or verifier_key_id != registry["verifier_key_id"]:
        raise ReproductionError("comparison seed does not match the preregistered verifier")
    bit_identical = not differences
    body: dict[str, Any] = {
        "comparison_id": "0" * 64,
        "source_revision": registry["source_revision"],
        "registry_sha256": registry_sha256,
        "builder_ids": sorted(by_builder),
        "control_cluster_ids": sorted(row["control_cluster_id"] for row in by_builder.values()),
        "observation_ids": sorted(row["observation_id"] for row in by_builder.values()),
        "baseline_builder_id": baseline_id,
        "subject_count_per_builder": {builder_id: len(by_builder[builder_id]["subjects"]) for builder_id in sorted(by_builder)},
        "differences": differences,
        "bit_identical": bit_identical,
        "normalization_applied": False,
        "verdict": "PASS_BIT_IDENTICAL" if bit_identical else "DIFFERENCES_RECORDED",
        "independent_reproduction_verified": bit_identical,
        "compared_at_utc": compared.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "production": False,
        "promotion_effect": "NONE",
    }
    body["comparison_id"] = comparison_id(body)
    envelope = {"schema": COMPARISON_SCHEMA, "body": body, "signature": signature_record(private, COMPARISON_DOMAIN, body)}
    atomic_create(output, envelope)
    return envelope


def verify_comparison(document: Any, registry_path: Path, registry_sha256: str, expected_verifier_key_id: str) -> dict[str, Any]:
    registry, builders = validate_registry(load_object(registry_path), registry_sha256)
    if not isinstance(document, dict) or set(document) != {"schema", "body", "signature"} or document.get("schema") != COMPARISON_SCHEMA:
        raise ReproductionError("independent reproduction comparison envelope is malformed")
    body = document["body"]
    required = {"comparison_id", "source_revision", "registry_sha256", "builder_ids", "control_cluster_ids", "observation_ids", "baseline_builder_id", "subject_count_per_builder", "differences", "bit_identical", "normalization_applied", "verdict", "independent_reproduction_verified", "compared_at_utc", "production", "promotion_effect"}
    if not isinstance(body, dict) or set(body) != required or body["comparison_id"] != comparison_id(body):
        raise ReproductionError("independent reproduction comparison body or ID is malformed")
    expected_builders = sorted(builders)
    expected_clusters = sorted(row["control_cluster_id"] for row in builders.values())
    if body["source_revision"] != registry["source_revision"] or body["registry_sha256"] != registry_sha256 or body["builder_ids"] != expected_builders or body["control_cluster_ids"] != expected_clusters or body["baseline_builder_id"] != expected_builders[0]:
        raise ReproductionError("independent reproduction comparison is stale or has incomplete builders")
    differences = body["differences"]
    if not isinstance(differences, list) or len(differences) > MAX_DIFFERENCES or any(not isinstance(row, dict) or set(row) != {"label", "path", "baseline_builder_id", "baseline_bytes", "baseline_sha256", "compared_builder_id", "compared_bytes", "compared_sha256"} for row in differences):
        raise ReproductionError("independent reproduction difference records are malformed")
    bit_identical = not differences
    if body["bit_identical"] is not bit_identical or body["independent_reproduction_verified"] is not bit_identical or body["verdict"] != ("PASS_BIT_IDENTICAL" if bit_identical else "DIFFERENCES_RECORDED") or body["normalization_applied"] is not False or body["production"] is not False or body["promotion_effect"] != "NONE":
        raise ReproductionError("independent reproduction verdict overclaims raw outputs")
    if registry["verifier_key_id"] != expected_verifier_key_id:
        raise ReproductionError("comparison verifier differs from the expected trust anchor")
    verify_signature(document["signature"], COMPARISON_DOMAIN, body, expected_verifier_key_id)
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("record")
    record.add_argument("--manifest", type=Path, required=True)
    record.add_argument("--checksums", type=Path, required=True)
    record.add_argument("--environment", type=Path, required=True)
    record.add_argument("--registry", type=Path, required=True)
    record.add_argument("--registry-sha256", required=True)
    record.add_argument("--builder-id", required=True)
    record.add_argument("--seed", type=Path, required=True)
    record.add_argument("--output", type=Path, required=True)
    compare_command = commands.add_parser("compare")
    compare_command.add_argument("--observation", type=Path, action="append", required=True)
    compare_command.add_argument("--registry", type=Path, required=True)
    compare_command.add_argument("--registry-sha256", required=True)
    compare_command.add_argument("--verifier-key-id", required=True)
    compare_command.add_argument("--verifier-seed", type=Path, required=True)
    compare_command.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--comparison", type=Path, required=True)
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--registry-sha256", required=True)
    verify.add_argument("--verifier-key-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            envelope = record_observation(args.manifest, args.checksums, args.environment, args.registry, args.registry_sha256, args.builder_id, args.seed, args.output)
            summary = {"verdict": "RECORDED", "observation_id": envelope["body"]["observation_id"], "builder_id": envelope["body"]["builder_id"]}
        elif args.command == "compare":
            envelope = compare(args.observation, args.registry, args.registry_sha256, args.verifier_key_id, args.verifier_seed, args.output)
            summary = {"verdict": envelope["body"]["verdict"], "comparison_id": envelope["body"]["comparison_id"], "difference_count": len(envelope["body"]["differences"]), "promotion_effect": "NONE"}
        else:
            body = verify_comparison(load_object(args.comparison), args.registry, args.registry_sha256, args.verifier_key_id)
            summary = {"verdict": body["verdict"], "comparison_id": body["comparison_id"], "difference_count": len(body["differences"]), "promotion_effect": "NONE"}
        sys.stdout.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except ReproductionError as error:
        sys.stdout.write(json.dumps({"verdict": "INVALID_EVIDENCE", "error": str(error), "promotion_effect": "NONE"}, sort_keys=True, separators=(",", ":")) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
