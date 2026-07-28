from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from tools.operations.wwm_signed_monitor_burn_in import (
        BurnInConfig,
        BurnInError,
        request_sample,
        validate_sample,
    )
except ModuleNotFoundError:
    from wwm_signed_monitor_burn_in import (
        BurnInConfig,
        BurnInError,
        request_sample,
        validate_sample,
    )

PLAN_SCHEMA = "noos/wwm-exact-release-drill-plan/v1"
RESULT_SCHEMA = "noos/wwm-exact-release-drill-result/v1"
ADAPTER_SCHEMA = "noos/wwm-release-drill-adapter-result/v1"
AUTH_DOMAIN = b"NOOS/SIG/WWM-RELEASE-DRILL-AUTHORIZATION/V1\0"
EVIDENCE_DOMAIN = b"NOOS/SIG/WWM-RELEASE-DRILL-EVIDENCE/V1\0"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_PROBE_BYTES = 8 * 1024 * 1024


class DrillError(RuntimeError):
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


def load_object(path: Path, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> dict[str, Any]:
    try:
        if path.stat().st_size > maximum_bytes:
            raise DrillError(f"document exceeds {maximum_bytes} bytes: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DrillError(f"cannot load JSON document {path}: {error}") from error
    if not isinstance(value, dict):
        raise DrillError(f"JSON document must be an object: {path}")
    return value


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(canonical_json(value) + b"\n")
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise DrillError(f"cannot atomically write {path}: {error}") from error


def decode_public_key(value: Any) -> bytes:
    if not isinstance(value, str):
        raise DrillError("public key must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise DrillError("public key is not canonical base64") from error
    if len(decoded) != 32:
        raise DrillError("Ed25519 public key must be 32 bytes")
    return decoded


def decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise DrillError("signature must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise DrillError("signature is not canonical base64") from error
    if len(decoded) != 64:
        raise DrillError("Ed25519 signature must be 64 bytes")
    return decoded


def load_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise DrillError(f"cannot read signing seed: {error}") from error
    stripped = raw.strip()
    if len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise DrillError("signing seed file must contain 32 raw bytes or 64 lowercase hex characters") from error
    elif len(raw) == 32:
        seed = raw
    else:
        raise DrillError("signing seed file must contain 32 raw bytes or 64 lowercase hex characters")
    if seed == bytes(32):
        raise DrillError("all-zero signing seed is forbidden")
    return seed


def public_identity(private: Ed25519PrivateKey) -> tuple[str, str]:
    public = private.public_key().public_bytes_raw()
    return base64.b64encode(public).decode("ascii"), sha256_bytes(public)


def plan_body(document: dict[str, Any]) -> dict[str, Any]:
    if set(document) != {"schema", "body", "authorization"} or document.get("schema") != PLAN_SCHEMA:
        raise DrillError("drill plan envelope is malformed")
    body = document.get("body")
    if not isinstance(body, dict):
        raise DrillError("drill plan body must be an object")
    return body


def validate_plan_body(body: dict[str, Any]) -> None:
    required = {
        "drill_id",
        "kind",
        "chain_id",
        "genesis_hash",
        "current_revision",
        "current_release_version",
        "prior_revision",
        "monitor",
        "steps",
        "replay_probes",
        "maximum_step_seconds",
    }
    if set(body) != required:
        raise DrillError(f"drill plan fields mismatch: {sorted(set(body) ^ required)}")
    if not isinstance(body["drill_id"], str) or not HEX64.fullmatch(body["drill_id"]):
        raise DrillError("drill_id must be a lowercase SHA-256 digest")
    if body["kind"] not in {"ROLLING_RESTART", "PRESERVED_BUILD_ROLLBACK"}:
        raise DrillError("unsupported drill kind")
    for field in ("chain_id", "genesis_hash"):
        if not isinstance(body[field], str) or not HEX64.fullmatch(body[field]):
            raise DrillError(f"{field} must be a lowercase SHA-256 digest")
    current = body["current_revision"]
    if not isinstance(current, str) or not HEX40.fullmatch(current):
        raise DrillError("current_revision must be a lowercase Git revision")
    if body["current_release_version"] != f"0.1.0+git.{current}":
        raise DrillError("current release version is not revision-bound")
    prior = body["prior_revision"]
    if body["kind"] == "PRESERVED_BUILD_ROLLBACK":
        if not isinstance(prior, str) or not HEX40.fullmatch(prior) or prior == current:
            raise DrillError("rollback plan requires a distinct prior revision")
    elif prior is not None:
        raise DrillError("rolling restart plan must not name a prior revision")
    maximum_step_seconds = body["maximum_step_seconds"]
    if not isinstance(maximum_step_seconds, int) or isinstance(maximum_step_seconds, bool) or not 10 <= maximum_step_seconds <= 3600:
        raise DrillError("maximum_step_seconds must be in 10..3600")

    monitor = body["monitor"]
    monitor_fields = {
        "url",
        "signer_public_key_base64",
        "signer_key_id",
        "deployment_sha256",
        "maximum_gap_seconds",
        "expected_checks",
    }
    if not isinstance(monitor, dict) or set(monitor) != monitor_fields:
        raise DrillError("monitor binding is malformed")
    decode_public_key(monitor["signer_public_key_base64"])
    for field in ("signer_key_id", "deployment_sha256"):
        if not isinstance(monitor[field], str) or not HEX64.fullmatch(monitor[field]):
            raise DrillError(f"monitor {field} must be a lowercase SHA-256 digest")
    if sha256_bytes(decode_public_key(monitor["signer_public_key_base64"])) != monitor["signer_key_id"]:
        raise DrillError("monitor signer key id does not match its public key")
    if not isinstance(monitor["url"], str) or not monitor["url"].startswith("https://"):
        raise DrillError("monitor URL must use HTTPS")
    if not isinstance(monitor["maximum_gap_seconds"], int) or not 60 <= monitor["maximum_gap_seconds"] <= 900:
        raise DrillError("monitor maximum gap must be in 60..900")
    if not isinstance(monitor["expected_checks"], int) or not 1 <= monitor["expected_checks"] <= 64:
        raise DrillError("monitor expected check count must be in 1..64")

    steps = body["steps"]
    if not isinstance(steps, list) or not steps or len(steps) > 16:
        raise DrillError("drill must contain 1..16 steps")
    identifiers: set[str] = set()
    actions: list[str] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) != {
            "step_id",
            "participant_id",
            "role",
            "action",
            "adapter",
            "adapter_sha256",
            "arguments",
            "expected_binary_sha256",
            "minimum_live_validators",
        }:
            raise DrillError(f"step {index} is malformed")
        for field in ("step_id", "participant_id", "role"):
            if not isinstance(step[field], str) or not TOKEN.fullmatch(step[field]):
                raise DrillError(f"step {index} {field} is invalid")
        if step["step_id"] in identifiers:
            raise DrillError("drill step identifiers must be unique")
        identifiers.add(step["step_id"])
        action = step["action"]
        if action not in {"RESTART", "ACTIVATE_PRIOR", "ACTIVATE_CURRENT"}:
            raise DrillError(f"step {index} has unsupported action")
        actions.append(action)
        adapter = Path(step["adapter"])
        if not adapter.is_absolute() or not adapter.is_file():
            raise DrillError(f"step {index} adapter must be an existing absolute file")
        if not isinstance(step["adapter_sha256"], str) or sha256_file(adapter) != step["adapter_sha256"]:
            raise DrillError(f"step {index} adapter hash mismatch")
        arguments = step["arguments"]
        if not isinstance(arguments, list) or len(arguments) > 32 or any(
            not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value for value in arguments
        ):
            raise DrillError(f"step {index} arguments are invalid")
        if not isinstance(step["expected_binary_sha256"], str) or not HEX64.fullmatch(step["expected_binary_sha256"]):
            raise DrillError(f"step {index} expected binary hash is invalid")
        minimum = step["minimum_live_validators"]
        if not isinstance(minimum, int) or isinstance(minimum, bool) or not 3 <= minimum <= 64:
            raise DrillError(f"step {index} minimum live validators is invalid")
    if body["kind"] == "ROLLING_RESTART":
        if actions != ["RESTART"] * len(actions) or steps[0]["role"] != "observer":
            raise DrillError("rolling restart must be observer-first and contain only RESTART steps")
        witness_ids = [step["participant_id"] for step in steps if step["role"] == "witness"]
        if len(witness_ids) != len(set(witness_ids)) or len(witness_ids) < 3:
            raise DrillError("rolling restart requires at least three distinct witnesses")
    elif actions != ["ACTIVATE_PRIOR", "ACTIVATE_CURRENT"]:
        raise DrillError("preserved rollback must activate the prior build then return to current")

    probes = body["replay_probes"]
    if not isinstance(probes, list) or not probes or len(probes) > 32:
        raise DrillError("drill requires 1..32 replay probes")
    probe_ids: set[str] = set()
    for probe in probes:
        if not isinstance(probe, dict) or set(probe) != {"probe_id", "url"}:
            raise DrillError("replay probe is malformed")
        if not isinstance(probe["probe_id"], str) or not TOKEN.fullmatch(probe["probe_id"]) or probe["probe_id"] in probe_ids:
            raise DrillError("replay probe identifier is invalid or duplicated")
        probe_ids.add(probe["probe_id"])
        if not isinstance(probe["url"], str) or not probe["url"].startswith("https://"):
            raise DrillError("replay probe URL must use HTTPS")


def verify_authorization(document: dict[str, Any]) -> dict[str, Any]:
    body = plan_body(document)
    validate_plan_body(body)
    authorization = document["authorization"]
    if not isinstance(authorization, dict) or set(authorization) != {
        "key_id",
        "public_key_base64",
        "signature_base64",
    }:
        raise DrillError("drill authorization is malformed")
    public = decode_public_key(authorization["public_key_base64"])
    if authorization["key_id"] != sha256_bytes(public):
        raise DrillError("authorization key id does not match its public key")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(authorization["signature_base64"]),
            AUTH_DOMAIN + canonical_json(body),
        )
    except InvalidSignature as error:
        raise DrillError("drill authorization signature is invalid") from error
    return body


def authorize(unsigned_path: Path, seed_path: Path, output: Path) -> dict[str, Any]:
    unsigned = load_object(unsigned_path)
    if set(unsigned) != {"schema", "body"} or unsigned.get("schema") != PLAN_SCHEMA:
        raise DrillError("unsigned plan must contain only schema and body")
    body = unsigned["body"]
    if not isinstance(body, dict):
        raise DrillError("unsigned plan body must be an object")
    validate_plan_body(body)
    private = Ed25519PrivateKey.from_private_bytes(load_seed(seed_path))
    public, key_id = public_identity(private)
    document = {
        "schema": PLAN_SCHEMA,
        "body": body,
        "authorization": {
            "key_id": key_id,
            "public_key_base64": public,
            "signature_base64": base64.b64encode(private.sign(AUTH_DOMAIN + canonical_json(body))).decode("ascii"),
        },
    }
    atomic_write(output, document)
    return document


def monitor_config(body: dict[str, Any]) -> BurnInConfig:
    binding = body["monitor"]
    config = BurnInConfig(
        url=binding["url"],
        release_version=body["current_release_version"],
        source_revision=body["current_revision"],
        deployment_sha256=binding["deployment_sha256"],
        signer_key_id=binding["signer_key_id"],
        duration_seconds=60,
        poll_seconds=1,
        maximum_sample_gap_seconds=binding["maximum_gap_seconds"],
        maximum_observation_gap_seconds=binding["maximum_gap_seconds"],
        expected_check_count=binding["expected_checks"],
        output=Path("unused"),
    )
    config.validate()
    return config


def validate_bound_sample(
    config: BurnInConfig, binding: dict[str, Any], sample: dict[str, Any]
) -> None:
    try:
        validate_sample(config, sample)
    except BurnInError as error:
        raise DrillError(str(error)) from error
    if sample.get("public_key_base64") != binding["signer_public_key_base64"]:
        raise DrillError("monitor sample public key does not match the authorized signer")


def check_detail(sample: dict[str, Any], name: str) -> dict[str, Any]:
    checks = sample.get("checks")
    if not isinstance(checks, list):
        raise DrillError("monitor sample checks are malformed")
    for check in checks:
        if isinstance(check, dict) and check.get("name") == name and check.get("ok") is True:
            detail = check.get("detail")
            if isinstance(detail, dict):
                return detail
    raise DrillError(f"signed monitor sample lacks passing {name} detail")


def coordinates(sample: dict[str, Any], minimum_validators: int) -> dict[str, int]:
    detail = check_detail(sample, "network_coherence")
    required = ("validator_count", "validator_min_height", "validator_max_height", "finalized_epoch")
    if any(not isinstance(detail.get(field), int) or isinstance(detail.get(field), bool) for field in required):
        raise DrillError("network coherence coordinates are malformed")
    if detail["validator_count"] < minimum_validators:
        raise DrillError("validator quorum dropped below the authorized minimum")
    if detail["validator_max_height"] - detail["validator_min_height"] > 8:
        raise DrillError("validator height spread exceeded eight blocks")
    return {field: detail[field] for field in required}


def probe_url(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "mindchain-release-drill/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise DrillError(f"replay probe returned HTTP {response.status}")
            payload = response.read(MAX_PROBE_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise DrillError(f"replay probe failed for {url}: {error}") from error
    if len(payload) > MAX_PROBE_BYTES:
        raise DrillError("replay probe response exceeds size bound")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise DrillError("replay probe response is not JSON") from error
    return {"bytes": len(payload), "canonical_sha256": sha256_bytes(canonical_json(value))}


@dataclass(frozen=True)
class RunnerResult:
    returncode: int
    stdout: str
    stderr: str


AdapterRunner = Callable[[list[str], int], RunnerResult]
SampleRequester = Callable[[str], dict[str, Any]]
ProbeRequester = Callable[[str], dict[str, Any]]


def run_adapter(command: list[str], timeout_seconds: int) -> RunnerResult:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise DrillError(f"drill adapter failed to execute: {error}") from error
    return RunnerResult(completed.returncode, completed.stdout, completed.stderr)


def validate_adapter_result(
    step: dict[str, Any],
    body: dict[str, Any],
    value: dict[str, Any],
    authorization_sha256: str,
) -> dict[str, Any]:
    required = {"schema", "step_id", "participant_id", "action", "process", "release", "durable_state", "authorization_sha256"}
    if set(value) != required or value.get("schema") != ADAPTER_SCHEMA:
        raise DrillError("adapter result envelope is malformed")
    for field in ("step_id", "participant_id", "action"):
        if value[field] != step[field]:
            raise DrillError(f"adapter result {field} does not match plan")
    process = value["process"]
    if not isinstance(process, dict) or set(process) != {"identity", "pid_before", "pid_after", "peak_rss_bytes"}:
        raise DrillError("adapter process evidence is malformed")
    if not isinstance(process["identity"], str) or not process["identity"]:
        raise DrillError("adapter process identity is empty")
    for field in ("pid_before", "pid_after", "peak_rss_bytes"):
        if not isinstance(process[field], int) or isinstance(process[field], bool) or process[field] <= 0:
            raise DrillError(f"adapter process {field} must be positive")
    if process["pid_before"] == process["pid_after"]:
        raise DrillError("adapter did not demonstrate a process replacement")
    release = value["release"]
    if not isinstance(release, dict) or set(release) != {"before_revision", "after_revision", "binary_sha256"}:
        raise DrillError("adapter release evidence is malformed")
    expected_before = body["current_revision"]
    expected_after = body["current_revision"]
    if step["action"] == "ACTIVATE_PRIOR":
        expected_after = body["prior_revision"]
    elif step["action"] == "ACTIVATE_CURRENT":
        expected_before = body["prior_revision"]
    if release["before_revision"] != expected_before or release["after_revision"] != expected_after:
        raise DrillError("adapter revision transition does not match plan")
    if release["binary_sha256"] != step["expected_binary_sha256"]:
        raise DrillError("adapter binary hash does not match plan")
    state = value["durable_state"]
    if not isinstance(state, dict) or set(state) != {"identity_sha256", "reset", "deleted"}:
        raise DrillError("adapter durable-state evidence is malformed")
    if not isinstance(state["identity_sha256"], str) or not HEX64.fullmatch(state["identity_sha256"]):
        raise DrillError("durable-state identity is invalid")
    if state["reset"] is not False or state["deleted"] is not False:
        raise DrillError("adapter reset or deleted durable state")
    authorization = value["authorization_sha256"]
    if step["action"] == "RESTART":
        if authorization is not None:
            raise DrillError("restart adapter must not invent rollback authorization")
    elif authorization != authorization_sha256:
        raise DrillError("release activation does not bind the authorized rollback")
    return value


def observed_at(sample: dict[str, Any]) -> datetime:
    raw = sample.get("observed_at_utc")
    if not isinstance(raw, str) or not raw.endswith("Z"):
        raise DrillError("monitor observed_at_utc is malformed")
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError as error:
        raise DrillError("monitor observed_at_utc is malformed") from error
    return parsed.astimezone(timezone.utc)


def execute(
    document: dict[str, Any],
    evidence_seed: bytes,
    *,
    sample_requester: SampleRequester = request_sample,
    probe_requester: ProbeRequester = probe_url,
    adapter_runner: AdapterRunner = run_adapter,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    body = verify_authorization(document)
    config = monitor_config(body)
    plan_sha256 = sha256_bytes(canonical_json(document))
    authorization_sha256 = sha256_bytes(canonical_json(document["authorization"]))

    baseline = sample_requester(config.url)
    validate_bound_sample(config, body["monitor"], baseline)
    baseline_coordinates = coordinates(baseline, min(step["minimum_live_validators"] for step in body["steps"]))
    replay_baseline = {probe["probe_id"]: probe_requester(probe["url"]) for probe in body["replay_probes"]}
    state_identities: dict[str, str] = {}
    step_results: list[dict[str, Any]] = []
    prior_sample = baseline
    prior_coordinates = baseline_coordinates

    for step in body["steps"]:
        command = [
            step["adapter"],
            *step["arguments"],
            "--step-id",
            step["step_id"],
            "--action",
            step["action"],
        ]
        if step["action"] != "RESTART":
            command.extend(["--authorization-sha256", authorization_sha256])
        result = adapter_runner(command, body["maximum_step_seconds"])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:2048]
            raise DrillError(f"adapter {step['step_id']} failed: {detail}")
        try:
            adapter_value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise DrillError(f"adapter {step['step_id']} did not return one JSON object") from error
        if not isinstance(adapter_value, dict):
            raise DrillError(f"adapter {step['step_id']} result must be an object")
        adapter_value = validate_adapter_result(
            step, body, adapter_value, authorization_sha256
        )
        observed_identity = adapter_value["durable_state"]["identity_sha256"]
        participant_id = step["participant_id"]
        prior_identity = state_identities.setdefault(participant_id, observed_identity)
        if prior_identity != observed_identity:
            raise DrillError("participant durable-state identity changed between drill steps")

        deadline = time.monotonic() + body["maximum_step_seconds"]
        post_sample: dict[str, Any] | None = None
        post_coordinates: dict[str, int] | None = None
        while time.monotonic() < deadline:
            candidate = sample_requester(config.url)
            validate_bound_sample(config, body["monitor"], candidate)
            candidate_coordinates = coordinates(candidate, step["minimum_live_validators"])
            if candidate_coordinates["finalized_epoch"] < prior_coordinates["finalized_epoch"]:
                raise DrillError("finalized epoch regressed during drill")
            if candidate_coordinates["validator_min_height"] >= prior_coordinates["validator_min_height"]:
                post_sample = candidate
                post_coordinates = candidate_coordinates
                break
            sleeper(1.0)
        if post_sample is None or post_coordinates is None:
            raise DrillError(f"step {step['step_id']} did not recover before its deadline")
        gap = int((observed_at(post_sample) - observed_at(prior_sample)).total_seconds())
        if gap < 0 or gap > body["monitor"]["maximum_gap_seconds"]:
            raise DrillError("signed monitor observation gap is outside the authorized bound")
        replay_after = {probe["probe_id"]: probe_requester(probe["url"]) for probe in body["replay_probes"]}
        if replay_after != replay_baseline:
            raise DrillError("historical replay probe changed across release drill")
        step_results.append(
            {
                "step_id": step["step_id"],
                "participant_id": step["participant_id"],
                "role": step["role"],
                "action": step["action"],
                "adapter": adapter_value,
                "pre_coordinates": prior_coordinates,
                "post_coordinates": post_coordinates,
                "pre_sample_id": prior_sample["sample_id"],
                "post_sample_id": post_sample["sample_id"],
                "observation_gap_seconds": gap,
                "replay": replay_after,
            }
        )
        prior_sample = post_sample
        prior_coordinates = post_coordinates

    result_body = {
        "drill_id": body["drill_id"],
        "kind": body["kind"],
        "plan_sha256": plan_sha256,
        "chain_id": body["chain_id"],
        "genesis_hash": body["genesis_hash"],
        "current_revision": body["current_revision"],
        "prior_revision": body["prior_revision"],
        "authorization_key_id": document["authorization"]["key_id"],
        "authorization_sha256": authorization_sha256,
        "baseline_sample_id": baseline["sample_id"],
        "final_sample_id": prior_sample["sample_id"],
        "durable_state_identities": state_identities,
        "replay_baseline": replay_baseline,
        "steps": step_results,
        "verdict": "PASS",
        "production": False,
        "promotion_effect": "NONE",
    }
    private = Ed25519PrivateKey.from_private_bytes(evidence_seed)
    public, key_id = public_identity(private)
    envelope = {
        "schema": RESULT_SCHEMA,
        "body": result_body,
        "attestation": {
            "key_id": key_id,
            "public_key_base64": public,
            "signature_base64": base64.b64encode(private.sign(EVIDENCE_DOMAIN + canonical_json(result_body))).decode("ascii"),
        },
    }
    verify_result(envelope)
    return envelope


def verify_replay_summary(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or not value
        or any(
            not isinstance(probe_id, str)
            or not TOKEN.fullmatch(probe_id)
            or not isinstance(probe, dict)
            or set(probe) != {"bytes", "canonical_sha256"}
            or not isinstance(probe["bytes"], int)
            or isinstance(probe["bytes"], bool)
            or probe["bytes"] < 0
            or not isinstance(probe["canonical_sha256"], str)
            or not HEX64.fullmatch(probe["canonical_sha256"])
            for probe_id, probe in value.items()
        )
    ):
        raise DrillError("drill result replay evidence is malformed")


def verify_coordinate_summary(value: Any) -> None:
    fields = {
        "validator_count",
        "validator_min_height",
        "validator_max_height",
        "finalized_epoch",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or any(
            not isinstance(value[field], int)
            or isinstance(value[field], bool)
            or value[field] < 0
            for field in fields
        )
        or value["validator_count"] < 3
        or value["validator_max_height"] < value["validator_min_height"]
        or value["validator_max_height"] - value["validator_min_height"] > 8
    ):
        raise DrillError("drill result network coordinates are malformed")


def verify_result_steps(body: dict[str, Any]) -> None:
    steps = body["steps"]
    if not isinstance(steps, list) or not steps:
        raise DrillError("drill result lacks step evidence")
    state_identities = body["durable_state_identities"]
    expected_step_fields = {
        "step_id",
        "participant_id",
        "role",
        "action",
        "adapter",
        "pre_coordinates",
        "post_coordinates",
        "pre_sample_id",
        "post_sample_id",
        "observation_gap_seconds",
        "replay",
    }
    seen_steps: set[str] = set()
    participants: set[str] = set()
    prior_sample_id = body["baseline_sample_id"]
    prior_coordinates: dict[str, int] | None = None
    actions: list[str] = []
    roles: list[str] = []
    for step in steps:
        if not isinstance(step, dict) or set(step) != expected_step_fields:
            raise DrillError("drill result step envelope is malformed")
        for field in ("step_id", "participant_id", "role"):
            if not isinstance(step[field], str) or not TOKEN.fullmatch(step[field]):
                raise DrillError(f"drill result step {field} is malformed")
        if step["step_id"] in seen_steps:
            raise DrillError("drill result step identifiers are duplicated")
        seen_steps.add(step["step_id"])
        participants.add(step["participant_id"])
        actions.append(step["action"])
        roles.append(step["role"])
        if step["pre_sample_id"] != prior_sample_id:
            raise DrillError("drill result sample sequence is discontinuous")
        if not isinstance(step["post_sample_id"], str) or not HEX64.fullmatch(
            step["post_sample_id"]
        ):
            raise DrillError("drill result post sample id is malformed")
        prior_sample_id = step["post_sample_id"]
        gap = step["observation_gap_seconds"]
        if (
            not isinstance(gap, int)
            or isinstance(gap, bool)
            or gap < 0
            or gap > 900
        ):
            raise DrillError("drill result observation gap is malformed")
        verify_replay_summary(step["replay"])
        if step["replay"] != body["replay_baseline"]:
            raise DrillError("drill result historical replay changed")
        verify_coordinate_summary(step["pre_coordinates"])
        verify_coordinate_summary(step["post_coordinates"])
        pre = step["pre_coordinates"]
        post = step["post_coordinates"]
        if (
            post["finalized_epoch"] < pre["finalized_epoch"]
            or post["validator_min_height"] < pre["validator_min_height"]
            or (
                prior_coordinates is not None
                and pre != prior_coordinates
            )
        ):
            raise DrillError("drill result network coordinates regressed or disconnected")
        prior_coordinates = post
        adapter = step["adapter"]
        if (
            not isinstance(adapter, dict)
            or set(adapter)
            != {
                "schema",
                "step_id",
                "participant_id",
                "action",
                "process",
                "release",
                "durable_state",
                "authorization_sha256",
            }
            or adapter.get("schema") != ADAPTER_SCHEMA
            or adapter.get("step_id") != step["step_id"]
            or adapter.get("participant_id") != step["participant_id"]
            or adapter.get("action") != step["action"]
        ):
            raise DrillError("drill result adapter binding is malformed")
        process = adapter["process"]
        if (
            not isinstance(process, dict)
            or set(process)
            != {"identity", "pid_before", "pid_after", "peak_rss_bytes"}
            or not isinstance(process["identity"], str)
            or not process["identity"]
            or any(
                not isinstance(process[field], int)
                or isinstance(process[field], bool)
                or process[field] <= 0
                for field in ("pid_before", "pid_after", "peak_rss_bytes")
            )
            or process["pid_before"] == process["pid_after"]
        ):
            raise DrillError("drill result process evidence is malformed")
        state = adapter["durable_state"]
        if (
            not isinstance(state, dict)
            or set(state) != {"identity_sha256", "reset", "deleted"}
            or state.get("identity_sha256")
            != state_identities.get(step["participant_id"])
            or state.get("reset") is not False
            or state.get("deleted") is not False
        ):
            raise DrillError("drill result durable-state evidence is malformed")
        release = adapter["release"]
        if (
            not isinstance(release, dict)
            or set(release)
            != {"before_revision", "after_revision", "binary_sha256"}
            or not isinstance(release["binary_sha256"], str)
            or not HEX64.fullmatch(release["binary_sha256"])
        ):
            raise DrillError("drill result release evidence is malformed")
        expected_before = body["current_revision"]
        expected_after = body["current_revision"]
        if step["action"] == "ACTIVATE_PRIOR":
            expected_after = body["prior_revision"]
        elif step["action"] == "ACTIVATE_CURRENT":
            expected_before = body["prior_revision"]
        elif step["action"] != "RESTART":
            raise DrillError("drill result action is unsupported")
        if (
            release["before_revision"] != expected_before
            or release["after_revision"] != expected_after
        ):
            raise DrillError("drill result release transition is invalid")
        if step["action"] == "RESTART":
            if adapter["authorization_sha256"] is not None:
                raise DrillError("restart evidence invents a rollback authorization")
        elif adapter["authorization_sha256"] != body["authorization_sha256"]:
            raise DrillError("rollback evidence is not authorization-bound")
    if prior_sample_id != body["final_sample_id"]:
        raise DrillError("drill result final sample id is disconnected")
    if participants != set(state_identities):
        raise DrillError("drill result state identity inventory is incomplete")
    if body["kind"] == "ROLLING_RESTART":
        witness_ids = {
            step["participant_id"]
            for step in steps
            if step["role"] == "witness"
        }
        if (
            actions != ["RESTART"] * len(steps)
            or roles[0] != "observer"
            or len(witness_ids) < 3
        ):
            raise DrillError("rolling restart result is not observer-first 3-of-4 evidence")
    elif (
        actions != ["ACTIVATE_PRIOR", "ACTIVATE_CURRENT"]
        or len(participants) != 1
    ):
        raise DrillError("rollback result does not return the same participant to current")


def verify_result(document: dict[str, Any]) -> dict[str, Any]:
    if set(document) != {"schema", "body", "attestation"} or document.get("schema") != RESULT_SCHEMA:
        raise DrillError("drill result envelope is malformed")
    body = document["body"]
    attestation = document["attestation"]
    if not isinstance(body, dict) or not isinstance(attestation, dict):
        raise DrillError("drill result body or attestation is malformed")
    required = {
        "drill_id",
        "kind",
        "plan_sha256",
        "chain_id",
        "genesis_hash",
        "current_revision",
        "prior_revision",
        "authorization_key_id",
        "authorization_sha256",
        "baseline_sample_id",
        "final_sample_id",
        "durable_state_identities",
        "replay_baseline",
        "steps",
        "verdict",
        "production",
        "promotion_effect",
    }
    if set(body) != required or body.get("verdict") != "PASS" or body.get("production") is not False or body.get("promotion_effect") != "NONE":
        raise DrillError("drill result body is malformed or promoting")
    for field in (
        "drill_id",
        "plan_sha256",
        "chain_id",
        "genesis_hash",
        "authorization_key_id",
        "authorization_sha256",
        "baseline_sample_id",
        "final_sample_id",
    ):
        if not isinstance(body[field], str) or not HEX64.fullmatch(body[field]):
            raise DrillError(f"drill result {field} is invalid")
    if not isinstance(body["current_revision"], str) or not HEX40.fullmatch(body["current_revision"]):
        raise DrillError("drill result current revision is invalid")
    if body["kind"] == "PRESERVED_BUILD_ROLLBACK":
        if not isinstance(body["prior_revision"], str) or not HEX40.fullmatch(body["prior_revision"]):
            raise DrillError("rollback result prior revision is invalid")
    elif body["kind"] == "ROLLING_RESTART":
        if body["prior_revision"] is not None:
            raise DrillError("rolling restart result has a prior revision")
    else:
        raise DrillError("drill result kind is invalid")
    state_identities = body["durable_state_identities"]
    if (
        not isinstance(state_identities, dict)
        or not state_identities
        or any(
            not isinstance(participant, str)
            or not TOKEN.fullmatch(participant)
            or not isinstance(identity, str)
            or not HEX64.fullmatch(identity)
            for participant, identity in state_identities.items()
        )
    ):
        raise DrillError("drill result durable-state identities are malformed")
    verify_replay_summary(body["replay_baseline"])
    verify_result_steps(body)
    if set(attestation) != {"key_id", "public_key_base64", "signature_base64"}:
        raise DrillError("drill evidence attestation is malformed")
    public = decode_public_key(attestation["public_key_base64"])
    if attestation["key_id"] != sha256_bytes(public):
        raise DrillError("drill evidence key id does not match its public key")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(attestation["signature_base64"]),
            EVIDENCE_DOMAIN + canonical_json(body),
        )
    except InvalidSignature as error:
        raise DrillError("drill evidence signature is invalid") from error
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authorize, execute, and verify exact-release restart/rollback drills")
    subparsers = parser.add_subparsers(dest="command", required=True)
    authorize_parser = subparsers.add_parser("authorize")
    authorize_parser.add_argument("--unsigned-plan", type=Path, required=True)
    authorize_parser.add_argument("--signing-seed-file", type=Path, required=True)
    authorize_parser.add_argument("--output", type=Path, required=True)
    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--plan", type=Path, required=True)
    execute_parser.add_argument("--evidence-signing-seed-file", type=Path, required=True)
    execute_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "authorize":
            result = authorize(args.unsigned_plan, args.signing_seed_file, args.output)
        elif args.command == "execute":
            result = execute(load_object(args.plan), load_seed(args.evidence_signing_seed_file))
            atomic_write(args.output, result)
        else:
            result = verify_result(load_object(args.result))
    except DrillError as error:
        print(f"release drill failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
