from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from tools.operations import wwm_public_testnet_monitor as monitor
    from tools.operations import wwm_release_drill as release_drill
except ModuleNotFoundError:
    import wwm_public_testnet_monitor as monitor
    import wwm_release_drill as release_drill

SCHEMA = "noos/wwm-exact-release-evidence-bundle/v1"
SIGNATURE_DOMAIN = b"NOOS/SIG/WWM-EXACT-RELEASE-EVIDENCE/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MINIMUM_BURN_IN_SECONDS = 24 * 60 * 60
ARTIFACT_FILENAMES = {
    "release_manifest": "artifacts/release-manifest.json",
    "release_archive": "artifacts/linux-release.tgz",
    "ci_release_result": "artifacts/ci-release-result.json",
    "release_test_result": "artifacts/release-test-result.json",
    "fleet_convergence": "artifacts/fleet-convergence.json",
    "burn_in": "artifacts/burn-in.json",
    "rolling_restart": "artifacts/rolling-restart.json",
    "rollback": "artifacts/rollback.json",
    "monitor_ledger": "artifacts/monitor-samples.jsonl",
}
JSON_KINDS = frozenset(ARTIFACT_FILENAMES) - {"release_archive", "monitor_ledger"}


class EvidenceError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path, maximum_bytes: int = MAX_JSON_BYTES) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > maximum_bytes:
            raise EvidenceError(f"JSON artifact size is outside the accepted bound: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise EvidenceError(f"cannot load JSON artifact {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"JSON artifact must contain an object: {path}")
    return value


def load_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read signing seed: {error}") from error
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise EvidenceError("signing seed must contain 32 raw bytes or 64 hex characters") from error
    elif len(raw) == 32:
        seed = raw
    else:
        raise EvidenceError("signing seed must contain 32 raw bytes or 64 hex characters")
    if seed == bytes(32):
        raise EvidenceError("all-zero signing seed is forbidden")
    return seed


def decode_public(value: Any) -> bytes:
    if not isinstance(value, str):
        raise EvidenceError("attestation public key must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise EvidenceError("attestation public key is not canonical base64") from error
    if len(decoded) != 32:
        raise EvidenceError("attestation public key must be 32 bytes")
    return decoded


def decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise EvidenceError("attestation signature must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise EvidenceError("attestation signature is not canonical base64") from error
    if len(decoded) != 64:
        raise EvidenceError("attestation signature must be 64 bytes")
    return decoded


def release_identity(document: dict[str, Any], revision: str) -> None:
    expected_version = f"0.1.0+git.{revision}"
    release = document.get("release")
    if not isinstance(release, dict) or release.get("source_revision") != revision or release.get("release_version") != expected_version:
        raise EvidenceError("artifact release identity does not match the exact revision")


def validate_release_manifest(document: dict[str, Any], revision: str, chain_id: str, genesis_hash: str) -> str:
    if document.get("schema") != "noos/wwm-public-testnet-release-bundle/v1":
        raise EvidenceError("release manifest schema mismatch")
    source = document.get("source")
    chain = document.get("chain_binding")
    boundary = document.get("boundary")
    build = document.get("build")
    if not isinstance(source, dict) or source.get("revision") != revision:
        raise EvidenceError("release manifest revision mismatch")
    if not isinstance(chain, dict) or chain.get("chain_id") != chain_id or chain.get("genesis_hash") != genesis_hash:
        raise EvidenceError("release manifest chain identity mismatch")
    if not isinstance(boundary, dict) or boundary.get("production") is not False or boundary.get("promotion_effect") != "NONE":
        raise EvidenceError("release manifest crosses the non-production boundary")
    if not isinstance(build, dict) or build.get("source_revision_env") != revision or build.get("release_version_env") != f"0.1.0+git.{revision}":
        raise EvidenceError("release manifest build identity mismatch")
    bundle_id = document.get("bundle_id")
    if not isinstance(bundle_id, str) or not HEX64.fullmatch(bundle_id):
        raise EvidenceError("release manifest bundle id is invalid")
    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise EvidenceError("release manifest file inventory is empty")
    paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256", "component"}:
            raise EvidenceError("release manifest file descriptor is malformed")
        path = entry["path"]
        if not isinstance(path, str) or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts or path in paths:
            raise EvidenceError("release manifest contains an unsafe or duplicate path")
        paths.add(path)
        if not isinstance(entry["bytes"], int) or isinstance(entry["bytes"], bool) or entry["bytes"] < 0:
            raise EvidenceError("release manifest file size is invalid")
        if not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
            raise EvidenceError("release manifest file hash is invalid")
        if not isinstance(entry["component"], str) or not entry["component"]:
            raise EvidenceError("release manifest file component is invalid")
    return bundle_id


def validate_release_archive(path: Path, manifest_path: Path, manifest: dict[str, Any]) -> None:
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if any(member.issym() or member.islnk() or member.isdev() or member.name.startswith("/") or ".." in PurePosixPath(member.name).parts for member in members):
                raise EvidenceError("release archive contains an unsafe member")
            regular = {member.name: member for member in members if member.isfile()}
            expected = {entry["path"] for entry in manifest["files"]} | {"release-manifest.json"}
            if set(regular) != expected:
                raise EvidenceError("release archive file set does not match the manifest")
            archived_manifest = archive.extractfile(regular["release-manifest.json"])
            if archived_manifest is None or archived_manifest.read() != manifest_path.read_bytes():
                raise EvidenceError("release archive manifest bytes do not match the sealed manifest")
            for entry in manifest["files"]:
                handle = archive.extractfile(regular[entry["path"]])
                if handle is None:
                    raise EvidenceError("release archive member cannot be read")
                digest = hashlib.sha256()
                count = 0
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    count += len(block)
                    digest.update(block)
                if count != entry["bytes"] or digest.hexdigest() != entry["sha256"]:
                    raise EvidenceError(f"release archive member integrity mismatch: {entry['path']}")
    except (OSError, tarfile.TarError) as error:
        raise EvidenceError(f"cannot validate release archive: {error}") from error


def validate_ci_result(document: dict[str, Any], revision: str, bundle_id: str) -> None:
    if document.get("schema") != "noos/wwm-ci-release-result/v1" or document.get("result") != "PASS":
        raise EvidenceError("CI release result did not pass")
    workflow = document.get("workflow")
    artifact = document.get("artifact")
    reproducibility = document.get("reproducibility")
    if not isinstance(workflow, dict) or workflow.get("head_sha") != revision or workflow.get("conclusion") != "success":
        raise EvidenceError("CI release workflow identity or conclusion mismatch")
    if not isinstance(artifact, dict) or artifact.get("bundle_id") != bundle_id or artifact.get("verified_locally") is not True:
        raise EvidenceError("CI release artifact is not bound to the release manifest")
    digest = artifact.get("archive_digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise EvidenceError("CI release artifact digest is invalid")
    if not isinstance(reproducibility, dict) or reproducibility.get("independent_reproduction_claimed") is not False:
        raise EvidenceError("CI result overstates independent reproduction")


def validate_release_test(document: dict[str, Any], revision: str) -> None:
    if document.get("schema") != "noos/wwm-release-test-result/v1" or document.get("result") != "PASS":
        raise EvidenceError("exact release test result did not pass")
    release_identity(document, revision)
    acceptance = document.get("acceptance")
    if not isinstance(acceptance, dict) or not acceptance or any(value is not True for value in acceptance.values()):
        raise EvidenceError("exact release test acceptance is incomplete")


def validate_fleet(document: dict[str, Any], revision: str) -> None:
    if document.get("schema") != "noos/exact-public-testnet-fleet-convergence-result/v1" or document.get("result") != "PASS":
        raise EvidenceError("fleet convergence result did not pass")
    release_identity(document, revision)
    acceptance = document.get("acceptance")
    required = {
        "exact_release_identity_on_all_nodes",
        "finalized_checkpoint_converged",
        "justified_checkpoint_converged",
        "memory_within_all_envelopes",
        "service_restart_counts_clean",
        "unsafe_heads_converged",
    }
    if not isinstance(acceptance, dict) or any(acceptance.get(field) is not True for field in required):
        raise EvidenceError("fleet convergence acceptance is incomplete")


def ledger_samples(path: Path) -> list[dict[str, Any]]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_LEDGER_BYTES:
            raise EvidenceError("monitor ledger size is outside the accepted bound")
        samples: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as source:
            for number, line in enumerate(source, 1):
                if not line.endswith("\n"):
                    raise EvidenceError("monitor ledger has a truncated final record")
                try:
                    sample = json.loads(line)
                except json.JSONDecodeError as error:
                    raise EvidenceError(f"monitor ledger line {number} is malformed") from error
                if not isinstance(sample, dict):
                    raise EvidenceError(f"monitor ledger line {number} is not an object")
                samples.append(sample)
    except (OSError, UnicodeDecodeError) as error:
        raise EvidenceError(f"cannot read monitor ledger: {error}") from error
    return samples


def validate_burn_in(document: dict[str, Any], ledger_path: Path, revision: str) -> None:
    if document.get("schema") != "noos/wwm-signed-monitor-burn-in-result/v1" or document.get("result") != "PASS":
        raise EvidenceError("signed monitor burn-in did not pass")
    release_identity(document, revision)
    if not isinstance(document.get("observed_span_seconds"), int) or document["observed_span_seconds"] < MINIMUM_BURN_IN_SECONDS:
        raise EvidenceError("signed monitor burn-in did not cover 24 continuous hours")
    maximum_gap = document.get("maximum_sample_gap_seconds")
    if (
        not isinstance(maximum_gap, (int, float))
        or isinstance(maximum_gap, bool)
        or maximum_gap < 0
        or maximum_gap > 90
    ):
        raise EvidenceError("signed monitor burn-in sample-gap bound is invalid")
    acceptance = document.get("acceptance")
    if not isinstance(acceptance, dict) or not acceptance or any(value is not True for value in acceptance.values()):
        raise EvidenceError("signed monitor burn-in acceptance is incomplete")
    ledger = document.get("ledger")
    if not isinstance(ledger, dict) or ledger.get("bytes") != ledger_path.stat().st_size or ledger.get("sha256") != sha256_file(ledger_path):
        raise EvidenceError("burn-in ledger descriptor does not match the sealed ledger")
    samples = ledger_samples(ledger_path)
    if document.get("sample_count") != len(samples) or not samples:
        raise EvidenceError("burn-in sample count does not match the sealed ledger")
    if document.get("first_sample_id") != samples[0].get("sample_id") or document.get("last_sample_id") != samples[-1].get("sample_id"):
        raise EvidenceError("burn-in endpoint sample ids do not match the sealed ledger")
    release = document["release"]
    signer_key_id = document.get("signer_key_id")
    monitor_source_sha256 = release.get("monitor_source_sha256")
    if not isinstance(monitor_source_sha256, str) or not HEX64.fullmatch(
        monitor_source_sha256
    ):
        raise EvidenceError("burn-in does not bind the executing monitor source")
    check_names = document.get("check_names")
    previous: str | None = None
    prior_observed: datetime | None = None
    first_observed: datetime | None = None
    computed_maximum_gap = 0.0
    first_observed_text: str | None = None
    last_observed_text: str | None = None
    observed_names: list[str] | None = None
    for index, sample in enumerate(samples):
        expected = {
            "schema": monitor.SAMPLE_SCHEMA,
            "environment": "public-testnet",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "source_revision": revision,
            "release_version": f"0.1.0+git.{revision}",
            "deployment_sha256": release.get("deployment_sha256"),
            "signer_key_id": signer_key_id,
            "monitor_source_sha256": monitor_source_sha256,
            "status": "ok",
        }
        if any(sample.get(field) != value for field, value in expected.items()):
            raise EvidenceError(f"monitor ledger sample {index} exact-release identity mismatch")
        try:
            monitor.verify_envelope(sample, monitor.SAMPLE_DOMAIN, "sample_id")
        except monitor.MonitorError as error:
            raise EvidenceError(f"monitor ledger sample {index} signature is invalid: {error}") from error
        if previous is not None and sample.get("previous_sample_id") != previous:
            raise EvidenceError("monitor ledger hash chain is discontinuous")
        previous = sample.get("sample_id")
        checks = sample.get("checks")
        if not isinstance(checks, list) or any(not isinstance(check, dict) or check.get("ok") is not True for check in checks):
            raise EvidenceError("monitor ledger contains a failed check")
        names = sorted(str(check.get("name")) for check in checks)
        if observed_names is None:
            observed_names = names
        elif names != observed_names:
            raise EvidenceError("monitor check set changed during burn-in")
        observed_text = sample.get("observed_at_utc")
        if not isinstance(observed_text, str) or not observed_text.endswith("Z"):
            raise EvidenceError("monitor observation timestamp is malformed")
        try:
            observed = datetime.fromisoformat(observed_text[:-1] + "+00:00").astimezone(
                timezone.utc
            )
        except ValueError as error:
            raise EvidenceError("monitor observation timestamp is malformed") from error
        if prior_observed is not None:
            gap = (observed - prior_observed).total_seconds()
            if gap <= 0 or gap > maximum_gap:
                raise EvidenceError(
                    "monitor observation timestamps are discontinuous or exceed the gap bound"
                )
            computed_maximum_gap = max(computed_maximum_gap, gap)
        else:
            first_observed = observed
            first_observed_text = observed_text
        prior_observed = observed
        last_observed_text = observed_text
    if first_observed is None or prior_observed is None:
        raise EvidenceError("burn-in monitor ledger is empty")
    observed_span = int((prior_observed - first_observed).total_seconds())
    if (
        observed_span != document["observed_span_seconds"]
        or first_observed_text != document.get("first_observed_at_utc")
        or last_observed_text != document.get("last_observed_at_utc")
        or computed_maximum_gap != float(maximum_gap)
    ):
        raise EvidenceError("burn-in timing summary does not match the monitor ledger")
    if observed_names != check_names:
        raise EvidenceError("burn-in check-name summary does not match the ledger")


def validate_drill(document: dict[str, Any], kind: str, revision: str, chain_id: str, genesis_hash: str) -> None:
    try:
        body = release_drill.verify_result(document)
    except release_drill.DrillError as error:
        raise EvidenceError(f"release drill evidence is invalid: {error}") from error
    expected_kind = "ROLLING_RESTART" if kind == "rolling_restart" else "PRESERVED_BUILD_ROLLBACK"
    if body.get("kind") != expected_kind or body.get("current_revision") != revision:
        raise EvidenceError(f"{kind} evidence identity mismatch")
    if body.get("chain_id") != chain_id or body.get("genesis_hash") != genesis_hash:
        raise EvidenceError(f"{kind} chain identity mismatch")
    if any(step.get("replay") != body.get("replay_baseline") for step in body.get("steps", [])):
        raise EvidenceError(f"{kind} replay evidence is not byte-equivalent")


def semantic_validate(paths: dict[str, Path], revision: str, chain_id: str, genesis_hash: str) -> None:
    manifest = load_json(paths["release_manifest"])
    bundle_id = validate_release_manifest(manifest, revision, chain_id, genesis_hash)
    validate_release_archive(paths["release_archive"], paths["release_manifest"], manifest)
    validate_ci_result(load_json(paths["ci_release_result"]), revision, bundle_id)
    validate_release_test(load_json(paths["release_test_result"]), revision)
    validate_fleet(load_json(paths["fleet_convergence"]), revision)
    validate_burn_in(load_json(paths["burn_in"]), paths["monitor_ledger"], revision)
    validate_drill(load_json(paths["rolling_restart"]), "rolling_restart", revision, chain_id, genesis_hash)
    validate_drill(load_json(paths["rollback"]), "rollback", revision, chain_id, genesis_hash)


def descriptor(kind: str, path: Path) -> dict[str, Any]:
    schema: str | None = None
    if kind in JSON_KINDS:
        schema_value = load_json(path).get("schema")
        if not isinstance(schema_value, str) or not schema_value:
            raise EvidenceError(f"{kind} artifact lacks a schema")
        schema = schema_value
    return {
        "kind": kind,
        "path": ARTIFACT_FILENAMES[kind],
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "schema": schema,
    }


def bundle_id(body: dict[str, Any]) -> str:
    unsigned = dict(body)
    unsigned.pop("bundle_id", None)
    return sha256_bytes(canonical_json(unsigned))


def safe_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts:
        raise EvidenceError("bundle descriptor path is unsafe")
    candidate = (root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise EvidenceError("bundle descriptor escapes its root") from error
    return candidate


def seal(
    sources: dict[str, Path],
    output: Path,
    revision: str,
    chain_id: str,
    genesis_hash: str,
    seed: bytes,
) -> dict[str, Any]:
    if not HEX40.fullmatch(revision):
        raise EvidenceError("revision must be lowercase hex40")
    for field, value in (("chain_id", chain_id), ("genesis_hash", genesis_hash)):
        if not HEX64.fullmatch(value):
            raise EvidenceError(f"{field} must be lowercase hex64")
    if set(sources) != set(ARTIFACT_FILENAMES):
        raise EvidenceError("exact release evidence source set is incomplete")
    for kind, path in sources.items():
        if not path.is_file():
            raise EvidenceError(f"{kind} artifact does not exist: {path}")
    semantic_validate(sources, revision, chain_id, genesis_hash)
    if output.exists():
        raise EvidenceError("evidence bundle output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        copied: dict[str, Path] = {}
        for kind, source in sources.items():
            destination = safe_path(temporary, ARTIFACT_FILENAMES[kind])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            copied[kind] = destination
        artifacts = [descriptor(kind, copied[kind]) for kind in sorted(copied)]
        burn_in = load_json(copied["burn_in"])
        body = {
            "bundle_id": "0" * 64,
            "source_revision": revision,
            "release_version": f"0.1.0+git.{revision}",
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "observed_at_utc": burn_in.get("observed_at_utc"),
            "artifacts": artifacts,
            "acceptance": {
                "exact_release_bound": True,
                "release_archive_verified": True,
                "fleet_converged": True,
                "continuous_signed_24h_burn_in": True,
                "observer_first_rolling_restart": True,
                "preserved_build_rollback": True,
                "historical_replay_equal": True,
                "production_boundary_fail_closed": True,
            },
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "independent_reproduction_claimed": False,
        }
        body["bundle_id"] = bundle_id(body)
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes_raw()
        manifest = {
            "schema": SCHEMA,
            "body": body,
            "attestation": {
                "key_id": sha256_bytes(public),
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "signature_base64": base64.b64encode(private.sign(SIGNATURE_DOMAIN + canonical_json(body))).decode("ascii"),
            },
        }
        (temporary / "bundle.json").write_bytes(canonical_json(manifest) + b"\n")
        verify_directory(temporary)
        os.replace(temporary, output)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_directory(root: Path) -> dict[str, Any]:
    manifest = load_json(root / "bundle.json")
    if set(manifest) != {"schema", "body", "attestation"} or manifest.get("schema") != SCHEMA:
        raise EvidenceError("exact release evidence envelope is malformed")
    body = manifest["body"]
    attestation = manifest["attestation"]
    if not isinstance(body, dict) or not isinstance(attestation, dict):
        raise EvidenceError("exact release evidence body or attestation is malformed")
    required = {
        "bundle_id",
        "source_revision",
        "release_version",
        "chain_id",
        "genesis_hash",
        "observed_at_utc",
        "artifacts",
        "acceptance",
        "production",
        "production_authorized",
        "promotion_effect",
        "independent_reproduction_claimed",
    }
    if set(body) != required or body.get("bundle_id") != bundle_id(body):
        raise EvidenceError("exact release evidence body or bundle id is malformed")
    revision = body.get("source_revision")
    chain_id = body.get("chain_id")
    genesis_hash = body.get("genesis_hash")
    if not isinstance(revision, str) or not HEX40.fullmatch(revision) or body.get("release_version") != f"0.1.0+git.{revision}":
        raise EvidenceError("exact release evidence revision is invalid")
    if not isinstance(chain_id, str) or not HEX64.fullmatch(chain_id) or not isinstance(genesis_hash, str) or not HEX64.fullmatch(genesis_hash):
        raise EvidenceError("exact release evidence chain identity is invalid")
    if body.get("production") is not False or body.get("production_authorized") is not False or body.get("promotion_effect") != "NONE" or body.get("independent_reproduction_claimed") is not False:
        raise EvidenceError("exact release evidence crosses an assurance boundary")
    acceptance = body.get("acceptance")
    if not isinstance(acceptance, dict) or set(acceptance) != {
        "exact_release_bound",
        "release_archive_verified",
        "fleet_converged",
        "continuous_signed_24h_burn_in",
        "observer_first_rolling_restart",
        "preserved_build_rollback",
        "historical_replay_equal",
        "production_boundary_fail_closed",
    } or any(value is not True for value in acceptance.values()):
        raise EvidenceError("exact release evidence acceptance is incomplete")
    artifacts = body.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_FILENAMES):
        raise EvidenceError("exact release evidence artifact inventory is incomplete")
    paths: dict[str, Path] = {}
    expected_files = {"bundle.json"}
    for entry in artifacts:
        if not isinstance(entry, dict) or set(entry) != {"kind", "path", "bytes", "sha256", "schema"}:
            raise EvidenceError("exact release evidence descriptor is malformed")
        kind = entry["kind"]
        if kind not in ARTIFACT_FILENAMES or kind in paths or entry["path"] != ARTIFACT_FILENAMES[kind]:
            raise EvidenceError("exact release evidence descriptor kind or path is invalid")
        path = safe_path(root, entry["path"])
        if not path.is_file() or path.stat().st_size != entry["bytes"] or sha256_file(path) != entry["sha256"]:
            raise EvidenceError(f"exact release evidence artifact integrity mismatch: {kind}")
        if kind in JSON_KINDS:
            if load_json(path).get("schema") != entry["schema"]:
                raise EvidenceError(f"exact release evidence artifact schema mismatch: {kind}")
        elif entry["schema"] is not None:
            raise EvidenceError(f"binary evidence artifact must not claim a JSON schema: {kind}")
        paths[kind] = path
        expected_files.add(entry["path"])
    actual_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual_files != expected_files:
        raise EvidenceError("exact release evidence directory contains unsealed files")
    if set(attestation) != {"key_id", "public_key_base64", "signature_base64"}:
        raise EvidenceError("exact release evidence attestation is malformed")
    public = decode_public(attestation["public_key_base64"])
    if attestation["key_id"] != sha256_bytes(public):
        raise EvidenceError("exact release evidence key id does not match its public key")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(attestation["signature_base64"]),
            SIGNATURE_DOMAIN + canonical_json(body),
        )
    except InvalidSignature as error:
        raise EvidenceError("exact release evidence signature is invalid") from error
    semantic_validate(paths, revision, chain_id, genesis_hash)
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal or verify an immutable exact-release operational evidence bundle")
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--revision", required=True)
    seal_parser.add_argument("--chain-id", required=True)
    seal_parser.add_argument("--genesis-hash", required=True)
    for kind in ARTIFACT_FILENAMES:
        seal_parser.add_argument(f"--{kind.replace('_', '-')}", type=Path, required=True)
    seal_parser.add_argument("--signing-seed-file", type=Path, required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            sources = {kind: getattr(args, kind) for kind in ARTIFACT_FILENAMES}
            value = seal(sources, args.output, args.revision, args.chain_id, args.genesis_hash, load_seed(args.signing_seed_file))
        else:
            value = verify_directory(args.bundle)
    except EvidenceError as error:
        print(f"exact release evidence failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
