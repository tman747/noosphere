#!/usr/bin/env python3
"""Fail-closed WWM model-improvement evidence and activation operator.

This module produces signed, immutable off-chain evidence for the existing
noos-training/noos-species object graph. It does not add WWM v2 actions or turn
Q1 inference weights into a training parent. A real candidate can advance only
when the exact licensed F16 parent, pinned toolchain, deterministic runtime
reproduction, independent evaluation, challenge period, and every canary stage
have all passed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "noos/wwm-model-improvement-gate/v1"
REQUEST_SCHEMA = "noos/wwm-model-improvement-request/v1"
EVIDENCE_SCHEMA = "noos.wwm.model-improvement-evidence.v1"
DATASET_SCHEMA = "noos.wwm.dataset-snapshot-evidence.v1"
RECIPE_SCHEMA = "noos.wwm.training-recipe-evidence.v1"
JOB_SCHEMA = "noos.wwm.adapter-job-evidence.v1"
UPDATE_SCHEMA = "noos.wwm.adapter-update-packet-evidence.v1"
RECEIPT_SCHEMA = "noos.wwm.trainer-receipt-evidence.v1"
EVALUATION_SCHEMA = "noos.wwm.evaluation-report-evidence.v1"
SUCCESSOR_SCHEMA = "noos.wwm.immutable-successor-evidence.v1"
ROUNDTRIP_SCHEMA = "noos.wwm.real-parent-roundtrip-gate.v1"
ACTIVATION_SCHEMA = "noos.wwm.activation-evidence.v1"

FROZEN_V2_SHA256 = "eb6fbd2bb818c60b922d607b7e9a82989d11319e7eb847841b18025af6e01d51"
FROZEN_Q1_SHA256 = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
FROZEN_Q1_BYTES = 3_803_452_480
REAL_PARENT_NAME = "Bonsai-27B-F16.gguf"
REAL_PARENT_BYTES = 53_808_280_640
REAL_PARENT_SHA256 = "d4a381a6d07131c34af888607bdbda49fc885c97673a0d22aa3e0f0284bba566"
PRISM_RUNTIME_REVISION = "62061f91088281e65071cc38c5f69ee95c39f14e"
PRISM_RUNTIME_ROOT = "690d9bbd8d44631fb971e0b0677e10c8d0bb1e08a743bb720eeaab728e30ba27"
PRISM_BUILD_ROOT = "72b5b1514a6fdf64a275d9ae660cda4db3cb2ce64e37a7ca7e97899729dc3b05"
BONSAI_TOKENIZER_ROOT = "58f310f0412514cea1a31757c9cc9714666b64fb67127914ab08554c4e0b4d56"
CANARY_CEILINGS = (1, 5, 25, 50, 100)
DIMENSIONS = ("capability", "safety", "privacy", "rights", "conformance", "performance")
MAX_DATASET_ITEMS = 1_000_000
MAX_ADAPTER_RANK = 256
MAX_ADAPTER_PARAMETERS = 50_000_000
MAX_TRAINING_STEPS = 10_000_000
MAX_CHECKPOINTS = 4_096
HEX32 = re.compile(r"^[0-9a-f]{64}$")
FEATURE_FLAGS = (
    "WWM_MINDLINK_REGISTRY_ENABLED",
    "WWM_KNOWLEDGE_SNAPSHOTS_ENABLED",
    "WWM_PUBLIC_RETRIEVAL_ENABLED",
    "WWM_TRAINING_PROMOTION_ENABLED",
)


class ImprovementError(RuntimeError):
    """A fail-closed model-improvement validation error."""


@dataclass(frozen=True)
class GateResult:
    passed: bool
    code: str
    detail: str
    evidence: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def domain_id(domain: str, body: Mapping[str, Any]) -> str:
    return sha256_bytes(domain.encode("ascii") + b"\0" + canonical_json(body))


def require_hex32(value: Any, label: str, *, nonzero: bool = True) -> str:
    if not isinstance(value, str) or HEX32.fullmatch(value) is None:
        raise ImprovementError(f"{label} must be canonical lowercase hex32")
    if nonzero and value == "0" * 64:
        raise ImprovementError(f"{label} cannot be zero")
    return value


def require_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ImprovementError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def require_sorted_unique(values: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(values, list) or (not allow_empty and not values):
        raise ImprovementError(f"{label} must be a{' possibly empty' if allow_empty else ' non-empty'} list")
    checked = [require_hex32(value, f"{label} item") for value in values]
    if checked != sorted(set(checked)):
        raise ImprovementError(f"{label} must be strictly sorted and unique")
    return checked


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ImprovementError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise ImprovementError(f"{path} must contain a JSON object")
    return value


def feature_flags_false(config: Mapping[str, Any]) -> dict[str, bool]:
    flags = config.get("feature_flags")
    if not isinstance(flags, dict) or set(flags) != set(FEATURE_FLAGS):
        raise ImprovementError("feature_flags must contain exactly the four registered WWM flags")
    if any(flags[name] is not False for name in FEATURE_FLAGS):
        raise ImprovementError("all WWM knowledge/training/promotion flags must remain false")
    return {name: False for name in FEATURE_FLAGS}


def verify_frozen_v2(path: Path = ROOT / "protocol" / "schemas" / "wwm-v2.md") -> str:
    if not path.is_file():
        raise ImprovementError(f"frozen WWM v2 schema is missing: {path}")
    actual = sha256_file(path)
    if actual != FROZEN_V2_SHA256:
        raise ImprovementError(f"frozen WWM v2 hash mismatch: expected {FROZEN_V2_SHA256}, got {actual}")
    return actual


def signed_record(domain: str, body: Mapping[str, Any], seed_hex: str) -> dict[str, Any]:
    seed = bytes.fromhex(require_hex32(seed_hex, "signing seed"))
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = key.public_key().public_bytes_raw().hex()
    payload = dict(body)
    payload["signer_key"] = public_key
    object_id = domain_id(domain, payload)
    signature = key.sign(bytes.fromhex(object_id) + canonical_json(payload)).hex()
    return {**payload, "object_id": object_id, "signature": signature}


def verify_signed_record(domain: str, record: Mapping[str, Any]) -> None:
    public_key = require_hex32(record.get("signer_key"), "signer_key")
    object_id = require_hex32(record.get("object_id"), "object_id")
    signature = record.get("signature")
    if not isinstance(signature, str) or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
        raise ImprovementError("signature must be canonical lowercase Ed25519 hex")
    body = {key: value for key, value in record.items() if key not in {"object_id", "signature"}}
    if domain_id(domain, body) != object_id:
        raise ImprovementError("signed object identity mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(signature), bytes.fromhex(object_id) + canonical_json(body)
        )
    except (ValueError, InvalidSignature) as error:
        raise ImprovementError("invalid object signature") from error


class ImmutableEvidenceStore:
    """Content-addressed insert-once JSON evidence store."""

    def __init__(self, root: Path):
        self.root = root

    def insert(self, kind: str, record: Mapping[str, Any]) -> Path:
        if not re.fullmatch(r"[a-z0-9-]+", kind):
            raise ImprovementError("invalid immutable evidence kind")
        object_id = require_hex32(record.get("object_id"), "object_id")
        directory = self.root / kind
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{object_id}.json"
        body = canonical_json(record) + b"\n"
        try:
            with target.open("xb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError as error:
            raise ImprovementError(f"duplicate immutable object: {object_id}") from error
        return target


def build_dataset_snapshot(spec: Mapping[str, Any], seed_hex: str) -> dict[str, Any]:
    train = require_sorted_unique(spec.get("train_ids"), "train_ids")
    evaluation = require_sorted_unique(spec.get("evaluation_ids"), "evaluation_ids")
    exclusion = require_sorted_unique(spec.get("exclusion_ids"), "exclusion_ids", allow_empty=True)
    if len(train) + len(evaluation) > MAX_DATASET_ITEMS:
        raise ImprovementError("dataset exceeds MAX_DATASET_ITEMS")
    if set(train) & set(evaluation) or set(train) & set(exclusion) or set(evaluation) & set(exclusion):
        raise ImprovementError("train/evaluation/exclusion splits must be disjoint")

    rights = spec.get("rights_records")
    if not isinstance(rights, list):
        raise ImprovementError("rights_records must be a list")
    by_id: dict[str, Mapping[str, Any]] = {}
    revoked: set[str] = set()
    for index, value in enumerate(rights):
        if not isinstance(value, dict):
            raise ImprovementError(f"rights_records[{index}] must be an object")
        item_id = require_hex32(value.get("item_id"), f"rights_records[{index}].item_id")
        require_hex32(value.get("rights_root"), f"rights_records[{index}].rights_root")
        if item_id in by_id:
            raise ImprovementError("duplicate rights record")
        if value.get("revoked") is True:
            revoked.add(item_id)
        by_id[item_id] = value
    for item_id in train + evaluation:
        record = by_id.get(item_id)
        if record is None:
            raise ImprovementError(f"missing rights record for selected item {item_id}")
        if record.get("revoked") is not False or record.get("training_permission") is not True or record.get("derivative_model_permission") is not True:
            raise ImprovementError(f"rights leakage: selected item {item_id} is not eligible for training and derivatives")
    if not revoked.issubset(exclusion):
        raise ImprovementError("every revoked item must be in exclusion_ids")

    dedup = spec.get("deduplication_evidence")
    if not isinstance(dedup, dict) or dedup.get("schema") != "noos/wwm-deduplication-evidence/v1":
        raise ImprovementError("deduplication_evidence is missing or has the wrong schema")
    selected = sorted(train + evaluation)
    dedup_inputs = sorted(train + evaluation + exclusion)
    if dedup.get("input_ids") != dedup_inputs:
        raise ImprovementError("deduplication input_ids must exactly equal all split IDs")
    if dedup.get("unresolved_duplicate_ids") != []:
        raise ImprovementError("deduplication evidence contains unresolved duplicates")
    groups = dedup.get("duplicate_groups")
    if not isinstance(groups, list):
        raise ImprovementError("duplicate_groups must be a list")
    prior: str | None = None
    for group in groups:
        checked = require_sorted_unique(group, "duplicate group")
        if len(checked) < 2:
            raise ImprovementError("duplicate groups must contain at least two IDs")
        if not set(checked).issubset(dedup_inputs):
            raise ImprovementError("duplicate group contains an ID outside the dataset splits")
        if prior is not None and checked[0] <= prior:
            raise ImprovementError("duplicate groups must be strictly sorted by first ID")
        prior = checked[0]
        if len(set(checked) & set(selected)) > 1:
            raise ImprovementError("deduplication failure: multiple duplicates remain selected")
    dedup_root = domain_id("NOOS-WWM-DEDUP-EVIDENCE-V1", dedup)

    canary = spec.get("private_canary_evidence")
    if not isinstance(canary, dict) or canary.get("schema") != "noos/wwm-private-canary-commitment/v1":
        raise ImprovementError("private_canary_evidence is missing or has the wrong schema")
    forbidden = {"raw_canaries", "canary_text", "canary_ids"} & set(canary)
    if forbidden:
        raise ImprovementError("private canary evidence must contain commitments, never raw canaries")
    require_int(canary.get("count"), "private canary count", 1, 1_000_000)
    require_hex32(canary.get("salted_canary_root"), "salted_canary_root")
    require_hex32(canary.get("holdout_ids_root"), "holdout_ids_root")
    canary_root = domain_id("NOOS-WWM-PRIVATE-CANARY-V1", canary)

    body = {
        "schema": DATASET_SCHEMA,
        "parent_dataset_id": spec.get("parent_dataset_id"),
        "knowledge_snapshot_id": require_hex32(spec.get("knowledge_snapshot_id"), "knowledge_snapshot_id"),
        "train_ids": train,
        "evaluation_ids": evaluation,
        "exclusion_ids": exclusion,
        "rights_policy_root": require_hex32(spec.get("rights_policy_root"), "rights_policy_root"),
        "deduplication_report_root": dedup_root,
        "private_canary_commitment": canary_root,
        "split_commitment": domain_id("NOOS-WWM-DATASET-SPLIT-V1", {
            "knowledge_snapshot_id": spec.get("knowledge_snapshot_id"),
            "train_ids": train,
            "evaluation_ids": evaluation,
            "exclusion_ids": exclusion,
            "deduplication_report_root": dedup_root,
            "private_canary_commitment": canary_root,
        }),
        "builder_control_cluster": require_hex32(spec.get("builder_control_cluster"), "builder_control_cluster"),
        "created_height": require_int(spec.get("created_height"), "created_height", 1, 2**63 - 1),
    }
    if body["parent_dataset_id"] is not None:
        body["parent_dataset_id"] = require_hex32(body["parent_dataset_id"], "parent_dataset_id")
    return signed_record("NOOS-WWM-DATASET-SNAPSHOT-V1", body, seed_hex)


def build_training_recipe(spec: Mapping[str, Any], dataset_id: str, seed_hex: str) -> dict[str, Any]:
    if require_hex32(spec.get("dataset_id"), "dataset_id") != dataset_id:
        raise ImprovementError("recipe dataset_id does not bind the dataset snapshot")
    parent = require_hex32(spec.get("parent_revision_id"), "parent_revision_id")
    if parent == FROZEN_Q1_SHA256:
        raise ImprovementError("the Q1 inference artifact cannot be used as a training parent")
    if require_hex32(spec.get("rollback_parent_id"), "rollback_parent_id") != parent:
        raise ImprovementError("rollback_parent_id must equal parent_revision_id")
    evaluators = require_sorted_unique(spec.get("evaluator_control_clusters"), "evaluator_control_clusters")
    sponsor_cluster = require_hex32(spec.get("sponsor_control_cluster"), "sponsor_control_cluster")
    if sponsor_cluster in evaluators:
        raise ImprovementError("sponsor and evaluator control clusters must be distinct")
    budget = spec.get("budget")
    if not isinstance(budget, dict):
        raise ImprovementError("budget must be an object")
    require_int(budget.get("maximum_compute_seconds"), "maximum_compute_seconds", 1, 31_536_000)
    require_int(budget.get("maximum_gpu_seconds"), "maximum_gpu_seconds", 1, 31_536_000)
    require_int(budget.get("maximum_cost_microunits"), "maximum_cost_microunits", 1, 2**63 - 1)
    body = {
        "schema": RECIPE_SCHEMA,
        "parent_revision_id": parent,
        "dataset_id": dataset_id,
        "tokenizer_root": require_hex32(spec.get("tokenizer_root"), "tokenizer_root"),
        "numeric_profile_root": require_hex32(spec.get("numeric_profile_root"), "numeric_profile_root"),
        "optimizer_root": require_hex32(spec.get("optimizer_root"), "optimizer_root"),
        "sampling_profile_root": require_hex32(spec.get("sampling_profile_root"), "sampling_profile_root"),
        "randomness_commitment": require_hex32(spec.get("randomness_commitment"), "randomness_commitment"),
        "intended_capability_root": require_hex32(spec.get("intended_capability_root"), "intended_capability_root"),
        "evaluator_policy_root": require_hex32(spec.get("evaluator_policy_root"), "evaluator_policy_root"),
        "rollback_parent_id": parent,
        "budget_root": domain_id("NOOS-WWM-TRAINING-BUDGET-V1", budget),
        "budget": dict(budget),
        "adapter_rank": require_int(spec.get("adapter_rank"), "adapter_rank", 1, MAX_ADAPTER_RANK),
        "trainable_parameter_count": require_int(spec.get("trainable_parameter_count"), "trainable_parameter_count", 1, MAX_ADAPTER_PARAMETERS),
        "maximum_steps": require_int(spec.get("maximum_steps"), "maximum_steps", 1, MAX_TRAINING_STEPS),
        "batch_size": require_int(spec.get("batch_size"), "batch_size", 1, 2**32 - 1),
        "learning_rate_q32": require_int(spec.get("learning_rate_q32"), "learning_rate_q32", 1, 2**64 - 1),
        "clipping_norm_q20": require_int(spec.get("clipping_norm_q20"), "clipping_norm_q20", 1, 2**64 - 1),
        "lane": "AUDITABLE",
        "sponsor_control_cluster": sponsor_cluster,
        "evaluator_control_clusters": evaluators,
        "created_height": require_int(spec.get("created_height"), "created_height", 1, 2**63 - 1),
    }
    return signed_record("NOOS-WWM-TRAINING-RECIPE-V1", body, seed_hex)


def build_adapter_job(spec: Mapping[str, Any], recipe: Mapping[str, Any], seed_hex: str) -> dict[str, Any]:
    trainer_cluster = require_hex32(spec.get("trainer_control_cluster"), "trainer_control_cluster")
    forbidden = {recipe["sponsor_control_cluster"], *recipe["evaluator_control_clusters"]}
    if trainer_cluster in forbidden:
        raise ImprovementError("trainer control cluster conflicts with sponsor/evaluator cluster")
    accepted = require_int(spec.get("accepted_height"), "accepted_height", 1, 2**63 - 1)
    deadline = require_int(spec.get("deadline_height"), "deadline_height", 1, 2**63 - 1)
    if accepted >= deadline:
        raise ImprovementError("adapter job deadline must be after acceptance")
    body = {
        "schema": JOB_SCHEMA,
        "recipe_id": recipe["object_id"],
        "dataset_id": recipe["dataset_id"],
        "work_loom_assignment_id": require_hex32(spec.get("work_loom_assignment_id"), "work_loom_assignment_id"),
        "trainer_control_cluster": trainer_cluster,
        "accepted_height": accepted,
        "deadline_height": deadline,
    }
    return signed_record("NOOS-WWM-ADAPTER-JOB-V1", body, seed_hex)


def build_update_and_receipt(
    spec: Mapping[str, Any], recipe: Mapping[str, Any], dataset: Mapping[str, Any], job: Mapping[str, Any],
    candidate_revision_id: str, adapter_path: Path, seed_hex: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    verify_signed_record("NOOS-WWM-DATASET-SNAPSHOT-V1", dataset)
    verify_signed_record("NOOS-WWM-TRAINING-RECIPE-V1", recipe)
    verify_signed_record("NOOS-WWM-ADAPTER-JOB-V1", job)
    if recipe.get("dataset_id") != dataset.get("object_id") or job.get("recipe_id") != recipe.get("object_id"):
        raise ImprovementError("dataset/recipe/job linkage mismatch")
    if not adapter_path.is_file() or adapter_path.stat().st_size == 0:
        raise ImprovementError("real adapter output is missing or empty")
    checkpoints = spec.get("checkpoints")
    if not isinstance(checkpoints, list) or not 1 <= len(checkpoints) <= MAX_CHECKPOINTS:
        raise ImprovementError("checkpoints must contain between 1 and MAX_CHECKPOINTS entries")
    checked: list[dict[str, Any]] = []
    prior: str | None = None
    for index, checkpoint in enumerate(checkpoints):
        if not isinstance(checkpoint, dict) or checkpoint.get("sequence") != index:
            raise ImprovementError("checkpoints must be contiguous and start at sequence zero")
        root = require_hex32(checkpoint.get("checkpoint_root"), "checkpoint_root")
        if checkpoint.get("parent_checkpoint_root") != prior:
            raise ImprovementError("checkpoint parent chain is invalid")
        checked.append({
            "sequence": index,
            "checkpoint_root": root,
            "parent_checkpoint_root": prior,
            "optimizer_state_root": require_hex32(checkpoint.get("optimizer_state_root"), "optimizer_state_root"),
            "examples_seen": require_int(checkpoint.get("examples_seen"), "examples_seen", 1, 2**63 - 1),
        })
        prior = root
    adapter_sha = sha256_file(adapter_path)
    if checked[-1]["checkpoint_root"] != adapter_sha:
        raise ImprovementError("final checkpoint root must equal the real adapter SHA-256")
    candidate = require_hex32(candidate_revision_id, "candidate_revision_id")
    update_body = {
        "schema": UPDATE_SCHEMA,
        "parent_revision_id": recipe["parent_revision_id"],
        "candidate_revision_id": candidate,
        "recipe_id": recipe["object_id"],
        "dataset_id": dataset["object_id"],
        "adapter_sha256": adapter_sha,
        "adapter_bytes": adapter_path.stat().st_size,
        "checkpoints": checked,
        "adapter_rank": recipe["adapter_rank"],
        "trainable_parameter_count": recipe["trainable_parameter_count"],
        "lane": "AUDITABLE",
        "shadow_only": True,
    }
    update = signed_record("NOOS-WWM-ADAPTER-UPDATE-PACKET-V1", update_body, seed_hex)
    if update["signer_key"] != job["signer_key"]:
        raise ImprovementError("adapter update signer must equal the accepted trainer")
    steps = require_int(spec.get("steps_completed"), "steps_completed", 1, recipe["maximum_steps"])
    receipt_body = {
        "schema": RECEIPT_SCHEMA,
        "job_id": job["object_id"],
        "recipe_id": recipe["object_id"],
        "dataset_id": dataset["object_id"],
        "update_packet_id": update["object_id"],
        "candidate_revision_id": candidate,
        "trainer_control_cluster": job["trainer_control_cluster"],
        "initial_checkpoint_root": checked[0]["checkpoint_root"],
        "final_checkpoint_root": checked[-1]["checkpoint_root"],
        "resource_receipt_root": require_hex32(spec.get("resource_receipt_root"), "resource_receipt_root"),
        "deterministic_fidelity_audit_root": require_hex32(spec.get("deterministic_fidelity_audit_root"), "deterministic_fidelity_audit_root"),
        "sampled_fidelity_audit_root": require_hex32(spec.get("sampled_fidelity_audit_root"), "sampled_fidelity_audit_root"),
        "execution_implementation_root": require_hex32(spec.get("execution_implementation_root"), "execution_implementation_root"),
        "steps_completed": steps,
        "one_step_roundtrip_completed": steps == 1,
        "examples_seen": checked[-1]["examples_seen"],
        "started_height": require_int(spec.get("started_height"), "started_height", 1, 2**63 - 1),
        "completed_height": require_int(spec.get("completed_height"), "completed_height", 1, 2**63 - 1),
        "shadow_only": True,
    }
    if receipt_body["started_height"] >= receipt_body["completed_height"]:
        raise ImprovementError("trainer receipt completion must follow its start")
    receipt = signed_record("NOOS-WWM-TRAINER-RECEIPT-V1", receipt_body, seed_hex)
    if receipt["signer_key"] != job["signer_key"]:
        raise ImprovementError("trainer receipt signer must equal the accepted trainer")
    return update, receipt


def validate_toolchain(toolchain: Mapping[str, Any]) -> dict[str, Path]:
    if toolchain.get("prism_source_revision") != PRISM_RUNTIME_REVISION:
        raise ImprovementError("wrong pinned Prism source revision")
    expected_bindings = {
        "runtime_root": PRISM_RUNTIME_ROOT,
        "build_root": PRISM_BUILD_ROOT,
        "tokenizer_root": BONSAI_TOKENIZER_ROOT,
    }
    for label, expected in expected_bindings.items():
        if toolchain.get(label) != expected:
            raise ImprovementError(f"wrong pinned Prism {label}")
    if toolchain.get("network_allowed") is not False:
        raise ImprovementError("model-improvement toolchain must declare network_allowed=false")
    executables: dict[str, Path] = {}
    for role in ("train", "merge", "quantize", "runtime"):
        item = toolchain.get(role)
        if not isinstance(item, dict):
            raise ImprovementError(f"missing {role} tool binding")
        path = Path(str(item.get("path", "")))
        expected = require_hex32(item.get("sha256"), f"{role} executable sha256")
        if not path.is_file():
            raise ImprovementError(f"{role} executable is missing: {path}")
        if sha256_file(path) != expected:
            raise ImprovementError(f"{role} executable hash mismatch")
        executables[role] = path.resolve()
    return executables


def validate_real_parent(parent: Mapping[str, Any]) -> Path:
    if parent.get("name") != REAL_PARENT_NAME or parent.get("bytes") != REAL_PARENT_BYTES or parent.get("sha256") != REAL_PARENT_SHA256:
        raise ImprovementError("unsupported training parent; exact Bonsai-27B-F16 binding required")
    path = Path(str(parent.get("path", "")))
    if not path.is_file():
        raise ImprovementError(f"MISSING_REAL_PARENT: {path} is unavailable; expected {REAL_PARENT_BYTES} bytes and SHA-256 {REAL_PARENT_SHA256}")
    if path.stat().st_size != REAL_PARENT_BYTES:
        raise ImprovementError(f"WRONG_REAL_PARENT_LENGTH: expected {REAL_PARENT_BYTES}, got {path.stat().st_size}")
    actual = sha256_file(path)
    if actual != REAL_PARENT_SHA256:
        raise ImprovementError(f"WRONG_REAL_PARENT_SHA256: expected {REAL_PARENT_SHA256}, got {actual}")
    license_info = parent.get("license")
    if not isinstance(license_info, dict) or license_info.get("spdx") != "Apache-2.0":
        raise ImprovementError("real parent must bind the Apache-2.0 license")
    for label in ("license", "notice"):
        file_path = Path(str(license_info.get(f"{label}_path", "")))
        expected = require_hex32(license_info.get(f"{label}_sha256"), f"{label}_sha256")
        if not file_path.is_file() or sha256_file(file_path) != expected:
            raise ImprovementError(f"real parent {label} file is missing or mismatched")
    return path.resolve()


def _render_command(template: Any, values: Mapping[str, str], executable: Path, label: str, required: Iterable[str]) -> list[str]:
    if not isinstance(template, list) or not template or not all(isinstance(item, str) and item for item in template):
        raise ImprovementError(f"{label}_command must be a non-empty argv list")
    used = {name for name in values if any("{" + name + "}" in item for item in template)}
    missing = set(required) - used
    if missing:
        raise ImprovementError(f"{label}_command is missing required bindings: {sorted(missing)}")
    rendered = [item.format_map(values) for item in template]
    if Path(rendered[0]).resolve() != executable:
        raise ImprovementError(f"{label}_command must invoke its pinned executable directly")
    return rendered


def _run_command(argv: Sequence[str], cwd: Path, timeout_seconds: int) -> None:
    environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
    environment["NOOS_WWM_NETWORK_ALLOWED"] = "0"
    try:
        result = subprocess.run(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout_seconds, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ImprovementError(f"toolchain command failed to execute: {error}") from error
    if result.returncode != 0:
        tail = result.stdout[-4096:].decode("utf-8", errors="replace")
        raise ImprovementError(f"toolchain command exited {result.returncode}: {tail}")


def run_real_roundtrip(config: Mapping[str, Any], work_root: Path) -> tuple[dict[str, Any], dict[str, Path]]:
    parent_config = config.get("real_parent")
    toolchain = config.get("toolchain")
    if not isinstance(parent_config, dict) or not isinstance(toolchain, dict):
        raise ImprovementError("real_parent and toolchain bindings are required")
    parent = validate_real_parent(parent_config)
    executables = validate_toolchain(toolchain)
    if config.get("one_step") is not True:
        raise ImprovementError("real-parent gate requires an explicit one_step=true run")
    timeout_seconds = require_int(config.get("command_timeout_seconds"), "command_timeout_seconds", 1, 7 * 24 * 3600)
    reproduction = config.get("reproduction")
    if not isinstance(reproduction, dict):
        raise ImprovementError("reproduction binding is required")
    expected_output = require_hex32(reproduction.get("expected_output_sha256"), "expected_output_sha256")

    work_root.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="wwm-model-improvement-", dir=work_root))
    paths = {
        "parent": parent,
        "adapter": temporary / "candidate.lora",
        "merged": temporary / "candidate-f16.gguf",
        "successor": temporary / "candidate-q1.gguf",
        "output": temporary / "runtime-output-1.bin",
    }
    values = {name: str(path) for name, path in paths.items()}
    try:
        commands = (
            ("train", {"parent", "adapter"}),
            ("merge", {"parent", "adapter", "merged"}),
            ("quantize", {"merged", "successor"}),
            ("runtime", {"successor", "output"}),
        )
        for label, required in commands:
            command = _render_command(config.get(f"{label}_command"), values, executables[label], label, required)
            _run_command(command, temporary, timeout_seconds)
            produced = paths[{"train": "adapter", "merge": "merged", "quantize": "successor", "runtime": "output"}[label]]
            if not produced.is_file() or produced.stat().st_size == 0:
                raise ImprovementError(f"{label} did not produce its required non-empty output")
        first_output_hash = sha256_file(paths["output"])
        if first_output_hash != expected_output:
            raise ImprovementError(f"runtime output reproduction mismatch: expected {expected_output}, got {first_output_hash}")
        second_output = temporary / "runtime-output-2.bin"
        values["output"] = str(second_output)
        runtime_command = _render_command(config.get("runtime_command"), values, executables["runtime"], "runtime", {"successor", "output"})
        _run_command(runtime_command, temporary, timeout_seconds)
        if not second_output.is_file() or sha256_file(second_output) != first_output_hash:
            raise ImprovementError("pinned runtime output was not deterministic across two loads")
        evidence = {
            "schema": ROUNDTRIP_SCHEMA,
            "passed": True,
            "parent_name": REAL_PARENT_NAME,
            "parent_bytes": REAL_PARENT_BYTES,
            "parent_sha256": REAL_PARENT_SHA256,
            "q1_used_as_training_parent": False,
            "prism_source_revision": PRISM_RUNTIME_REVISION,
            "one_step_completed": True,
            "adapter_sha256": sha256_file(paths["adapter"]),
            "merged_sha256": sha256_file(paths["merged"]),
            "successor_sha256": sha256_file(paths["successor"]),
            "successor_bytes": paths["successor"].stat().st_size,
            "runtime_output_sha256": first_output_hash,
            "runtime_reproduction_count": 2,
            "network_allowed": False,
        }
        return evidence, paths
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def probe_gate(config: Mapping[str, Any]) -> GateResult:
    if config.get("schema") != SCHEMA:
        raise ImprovementError("unsupported gate configuration schema")
    if config.get("environment") not in {"local", "devnet", "testnet"} or config.get("production") is not False:
        raise ImprovementError("real-parent probe is restricted to explicit non-production environments")
    flags = feature_flags_false(config)
    frozen = verify_frozen_v2()
    evidence: dict[str, Any] = {
        "schema": ROUNDTRIP_SCHEMA,
        "passed": False,
        "weight_training_enabled": False,
        "promotion_enabled": False,
        "feature_flags": flags,
        "frozen_wwm_v2_sha256": frozen,
        "expected_parent": {"name": REAL_PARENT_NAME, "bytes": REAL_PARENT_BYTES, "sha256": REAL_PARENT_SHA256},
        "q1_training_parent_forbidden": {"bytes": FROZEN_Q1_BYTES, "sha256": FROZEN_Q1_SHA256},
        "required_prism_source_revision": PRISM_RUNTIME_REVISION,
        "required_runtime_root": PRISM_RUNTIME_ROOT,
        "required_build_root": PRISM_BUILD_ROOT,
        "required_tokenizer_root": BONSAI_TOKENIZER_ROOT,
        "future_v3_required_for_direct_canonical_training_objects": True,
    }
    parent = config.get("real_parent")
    if not isinstance(parent, dict):
        detail = "MISSING_REAL_PARENT_BINDING: real_parent configuration is required"
        return GateResult(False, "MISSING_REAL_PARENT_BINDING", detail, {**evidence, "failure": detail})
    try:
        validate_real_parent(parent)
    except ImprovementError as error:
        detail = str(error)
        code = detail.split(":", 1)[0] if ":" in detail else "REAL_PARENT_REJECTED"
        return GateResult(False, code, detail, {**evidence, "failure": detail})
    toolchain = config.get("toolchain")
    if not isinstance(toolchain, dict):
        detail = "MISSING_PINNED_TOOLCHAIN: toolchain configuration is required"
        return GateResult(False, "MISSING_PINNED_TOOLCHAIN", detail, {**evidence, "failure": detail})
    try:
        validate_toolchain(toolchain)
    except ImprovementError as error:
        detail = str(error)
        return GateResult(False, "PINNED_TOOLCHAIN_REJECTED", detail, {**evidence, "failure": detail})
    return GateResult(False, "ROUNDTRIP_NOT_EXECUTED", "real parent and tools verify, but the one-step round trip has not been executed", evidence)


def export_immutable_successor_bundle(
    successor_path: Path, export_root: Path, license_path: Path, notice_path: Path,
    expected_license_sha256: str, expected_notice_sha256: str,
) -> tuple[Path, dict[str, Any]]:
    if not successor_path.is_file() or successor_path.stat().st_size == 0:
        raise ImprovementError("successor GGUF is missing or empty")
    license_sha = require_hex32(expected_license_sha256, "license_sha256")
    notice_sha = require_hex32(expected_notice_sha256, "notice_sha256")
    if not license_path.is_file() or sha256_file(license_path) != license_sha:
        raise ImprovementError("successor LICENSE.txt is missing or mismatched")
    if not notice_path.is_file() or sha256_file(notice_path) != notice_sha:
        raise ImprovementError("successor NOTICE.txt is missing or mismatched")
    successor_sha = sha256_file(successor_path)
    bundle = export_root / successor_sha
    try:
        bundle.mkdir(parents=True, exist_ok=False)
    except FileExistsError as error:
        raise ImprovementError(f"immutable successor bundle already exists: {successor_sha}") from error
    model_target = bundle / "model.gguf"
    try:
        for source, target in (
            (successor_path, model_target),
            (license_path, bundle / "LICENSE.txt"),
            (notice_path, bundle / "NOTICE.txt"),
        ):
            with source.open("rb") as input_file, target.open("xb") as output:
                shutil.copyfileobj(input_file, output, length=8 * 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
        manifest = {
            "schema": "noos/wwm-immutable-successor-bundle/v1",
            "successor_sha256": successor_sha,
            "successor_bytes": successor_path.stat().st_size,
            "license_sha256": license_sha,
            "notice_sha256": notice_sha,
        }
        manifest["bundle_root"] = domain_id("NOOS-WWM-SUCCESSOR-BUNDLE-V1", manifest)
        manifest_path = bundle / "manifest.json"
        with manifest_path.open("xb") as output:
            output.write(canonical_json(manifest) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        if sha256_file(model_target) != successor_sha:
            raise ImprovementError("immutable successor export changed model bytes")
        for target in (model_target, bundle / "LICENSE.txt", bundle / "NOTICE.txt", manifest_path):
            target.chmod(0o444)
        return model_target, manifest
    except Exception:
        shutil.rmtree(bundle, ignore_errors=True)
        raise


def build_successor_evidence(spec: Mapping[str, Any], successor_path: Path, bindings: Mapping[str, str], seed_hex: str) -> dict[str, Any]:
    if not successor_path.is_file() or successor_path.stat().st_size == 0:
        raise ImprovementError("successor GGUF is missing or empty")
    successor_sha = sha256_file(successor_path)
    if successor_sha in {REAL_PARENT_SHA256, FROZEN_Q1_SHA256}:
        raise ImprovementError("successor must be a new immutable artifact")
    license_sha = require_hex32(spec.get("license_sha256"), "license_sha256")
    notice_sha = require_hex32(spec.get("notice_sha256"), "notice_sha256")
    bundle_root = require_hex32(spec.get("bundle_root"), "bundle_root")
    required = (
        "parent_revision_id", "dataset_id", "recipe_id", "adapter_update_packet_id", "trainer_receipt_id",
        "evaluation_set_root", "license_root", "rights_root", "provenance_root", "runtime_root", "tokenizer_root",
        "quantization_toolchain_root",
    )
    roots = {name: require_hex32(bindings.get(name), name) for name in required}
    body = {
        "schema": SUCCESSOR_SCHEMA,
        **roots,
        "successor_artifact_id": domain_id("NOOS-WWM-SUCCESSOR-ARTIFACT-V1", {
            "sha256": successor_sha, "bytes": successor_path.stat().st_size,
            "parent_revision_id": roots["parent_revision_id"], "recipe_id": roots["recipe_id"],
        }),
        "successor_sha256": successor_sha,
        "successor_bytes": successor_path.stat().st_size,
        "license_sha256": license_sha,
        "notice_sha256": notice_sha,
        "immutable_bundle_root": bundle_root,
        "capsule_root": domain_id("NOOS-WWM-SUCCESSOR-CAPSULE-V1", {
            **roots, "successor_sha256": successor_sha, "successor_bytes": successor_path.stat().st_size,
            "license_sha256": license_sha, "notice_sha256": notice_sha, "bundle_root": bundle_root,
        }),
        "immutable": True,
        "overwrites_parent": False,
        "frozen_v2_action_added": False,
        "direct_canonical_training_objects_require_reviewed_wwm_v3": True,
        "eligible_path": "existing operational reconfiguration after all gates",
        "created_height": require_int(spec.get("created_height"), "created_height", 1, 2**63 - 1),
    }
    return signed_record("NOOS-WWM-IMMUTABLE-SUCCESSOR-V1", body, seed_hex)


class EvaluationRegistry:
    def __init__(self, candidate_revision_id: str, parent_revision_id: str, trainer_control_cluster: str):
        self.candidate = require_hex32(candidate_revision_id, "candidate_revision_id")
        self.parent = require_hex32(parent_revision_id, "parent_revision_id")
        self.trainer_cluster = require_hex32(trainer_control_cluster, "trainer_control_cluster")
        self.reports: dict[str, dict[str, Any]] = {}

    def insert(self, spec: Mapping[str, Any], seed_hex: str) -> dict[str, Any]:
        cluster = require_hex32(spec.get("evaluator_control_cluster"), "evaluator_control_cluster")
        scores = spec.get("scores_q20")
        if not isinstance(scores, dict) or set(scores) != set(DIMENSIONS):
            raise ImprovementError(f"scores_q20 must contain exactly the dimensions {DIMENSIONS}")
        checked_scores = {name: require_int(scores[name], f"{name} score", -(2**63), 2**63 - 1) for name in DIMENSIONS}
        critical = spec.get("critical_failures")
        if not isinstance(critical, list) or any(name not in DIMENSIONS for name in critical) or critical != sorted(set(critical), key=DIMENSIONS.index):
            raise ImprovementError("critical_failures must be unique and in canonical dimension order")
        body = {
            "schema": EVALUATION_SCHEMA,
            "candidate_revision_id": self.candidate,
            "parent_revision_id": self.parent,
            "evaluator_control_cluster": cluster,
            "public_suite_root": require_hex32(spec.get("public_suite_root"), "public_suite_root"),
            "hidden_suite_commitment": require_hex32(spec.get("hidden_suite_commitment"), "hidden_suite_commitment"),
            "hidden_suite_reveal_root": require_hex32(spec.get("hidden_suite_reveal_root"), "hidden_suite_reveal_root"),
            "scores_q20": checked_scores,
            "critical_failures": critical,
            "conflict_disclosure_root": require_hex32(spec.get("conflict_disclosure_root"), "conflict_disclosure_root"),
            "conflict_detected": spec.get("conflict_detected") is True,
            "artifact_root": require_hex32(spec.get("artifact_root"), "artifact_root"),
            "evaluated_height": require_int(spec.get("evaluated_height"), "evaluated_height", 1, 2**63 - 1),
            "favorable": not critical and all(value >= 0 for value in checked_scores.values()),
            "insert_once": True,
        }
        record = signed_record("NOOS-WWM-EVALUATION-REPORT-V1", body, seed_hex)
        if record["object_id"] in self.reports:
            raise ImprovementError("duplicate evaluation report")
        self.reports[record["object_id"]] = record
        return record

    def hard_floor_gate(self, floors: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(floors, dict) or set(floors) != set(DIMENSIONS):
            raise ImprovementError("hard floors must contain every dimension")
        checked = {name: require_int(floors[name], f"{name} floor", -(2**63), 2**63 - 1) for name in DIMENSIONS}
        if len(self.reports) < 2:
            raise ImprovementError("at least two independent evaluation reports are required")
        clusters = {report["evaluator_control_cluster"] for report in self.reports.values()}
        if len(clusters) < 2 or self.trainer_cluster in clusters:
            raise ImprovementError("trainer/evaluator clusters are not independent")
        failures: list[str] = []
        for report_id, report in self.reports.items():
            if report["conflict_detected"]:
                failures.append(f"{report_id}:evaluator-conflict")
            if report["critical_failures"]:
                failures.append(f"{report_id}:critical-failure")
            for dimension, floor in checked.items():
                if report["scores_q20"][dimension] < floor:
                    failures.append(f"{report_id}:{dimension}-below-floor")
        return {
            "passed": not failures,
            "hard_floor_policy_root": domain_id("NOOS-WWM-HARD-FLOORS-V1", checked),
            "report_ids": sorted(self.reports),
            "evaluation_set_root": domain_id("NOOS-WWM-EVALUATION-SET-V1", {"report_ids": sorted(self.reports)}),
            "failures": failures,
        }


class CanaryController:
    """Bounded shadow-canary state machine with immediate parent rollback."""

    def __init__(self, candidate: str, parent: str, proposal_height: int, challenge_end_height: int, hard_floors: Mapping[str, int]):
        self.candidate = require_hex32(candidate, "candidate")
        self.parent = require_hex32(parent, "parent")
        if self.candidate == self.parent:
            raise ImprovementError("candidate must differ from rollback parent")
        self.proposal_height = require_int(proposal_height, "proposal_height", 1, 2**63 - 1)
        self.challenge_end_height = require_int(challenge_end_height, "challenge_end_height", 1, 2**63 - 1)
        if self.proposal_height >= self.challenge_end_height:
            raise ImprovementError("challenge timelock must end after proposal height")
        if set(hard_floors) != set(DIMENSIONS):
            raise ImprovementError("hard floors must use exactly the canonical dimensions")
        self.floors = {name: hard_floors[name] for name in DIMENSIONS}
        self.state = "AWAITING_TIMELOCK"
        self.stage = -1
        self.shadow_revision = self.parent
        self.observations: dict[int, dict[str, Any]] = {}
        self.transitions: list[dict[str, Any]] = []

    def begin(self, height: int, evaluation_gate: Mapping[str, Any]) -> None:
        if self.state != "AWAITING_TIMELOCK":
            raise ImprovementError("canary has already begun or is terminal")
        if evaluation_gate.get("passed") is not True:
            raise ImprovementError("independent evaluation hard-floor gate has not passed")
        if height < self.challenge_end_height:
            raise ImprovementError("challenge timelock is still open")
        self.state, self.stage, self.shadow_revision = "RUNNING", 0, self.candidate
        self.transitions.append(self._transition("SHADOW_CANARY_START", height, 0, self.parent, self.candidate, evaluation_gate["evaluation_set_root"]))

    def observe(self, spec: Mapping[str, Any]) -> str:
        if self.state != "RUNNING":
            raise ImprovementError("canary is not running")
        if spec.get("stage_index") != self.stage or self.stage in self.observations:
            raise ImprovementError("wrong or duplicate canary stage")
        ceiling = CANARY_CEILINGS[self.stage]
        total = require_int(spec.get("total_requests"), "total_requests", 1, 2**63 - 1)
        candidate_requests = require_int(spec.get("candidate_requests"), "candidate_requests", 0, total)
        if candidate_requests * 100 > total * ceiling:
            raise ImprovementError("candidate traffic exceeded the canary ceiling")
        scores = spec.get("scores_q20")
        if not isinstance(scores, dict) or set(scores) != set(DIMENSIONS):
            raise ImprovementError("canary scores must use exactly the canonical dimensions")
        critical = spec.get("critical_failures")
        if (
            not isinstance(critical, list)
            or any(name not in DIMENSIONS for name in critical)
            or critical != sorted(set(critical), key=DIMENSIONS.index)
        ):
            raise ImprovementError("canary critical_failures must be unique and in canonical dimension order")
        checked_scores = {
            name: require_int(scores[name], f"canary {name} score", -(2**63), 2**63 - 1)
            for name in DIMENSIONS
        }
        trigger_bitset = require_int(spec.get("rollback_trigger_bitset"), "rollback_trigger_bitset", 0, 2**64 - 1)
        passed = trigger_bitset == 0 and not critical and all(checked_scores[name] >= self.floors[name] for name in DIMENSIONS)
        observation = {
            "stage_index": self.stage,
            "traffic_ceiling_percent": ceiling,
            "total_requests": total,
            "candidate_requests": candidate_requests,
            "scores_q20": checked_scores,
            "critical_failures": list(critical),
            "rollback_trigger_bitset": trigger_bitset,
            "artifact_root": require_hex32(spec.get("artifact_root"), "canary artifact_root"),
            "observed_height": require_int(spec.get("observed_height"), "observed_height", self.challenge_end_height, 2**63 - 1),
            "passed": passed,
        }
        observation["object_id"] = domain_id("NOOS-WWM-CANARY-OBSERVATION-V1", observation)
        self.observations[self.stage] = observation
        prior = self.shadow_revision
        if not passed:
            self.shadow_revision = self.parent
            self.state = "ROLLED_BACK"
            self.transitions.append(self._transition("AUTOMATIC_ROLLBACK", observation["observed_height"], self.stage, prior, self.parent, observation["object_id"]))
            return self.state
        if self.stage == len(CANARY_CEILINGS) - 1:
            self.state = "CANARY_COMPLETE"
            self.transitions.append(self._transition("CANARY_COMPLETE", observation["observed_height"], self.stage, prior, self.candidate, observation["object_id"]))
        else:
            self.stage += 1
            self.transitions.append(self._transition("SHADOW_CANARY_ADVANCE", observation["observed_height"], self.stage, prior, self.candidate, observation["object_id"]))
        return self.state

    @staticmethod
    def _transition(kind: str, height: int, stage: int, prior: str, next_revision: str, evidence: str) -> dict[str, Any]:
        body = {"kind": kind, "height": height, "stage_index": stage, "prior_revision_id": prior,
                "next_revision_id": next_revision, "authorizing_evidence_id": evidence}
        return {**body, "object_id": domain_id("NOOS-WWM-ALIAS-TRANSITION-V1", body)}

    def evidence(self) -> dict[str, Any]:
        return {
            "schema": ACTIVATION_SCHEMA,
            "state": self.state,
            "canary_ceilings_percent": list(CANARY_CEILINGS),
            "production_alias_revision_id": self.parent,
            "shadow_alias_revision_id": self.shadow_revision,
            "rollback_parent_id": self.parent,
            "observations": [self.observations[index] for index in sorted(self.observations)],
            "alias_transitions": list(self.transitions),
            "automatic_parent_rollback": True,
        }


def run_workflow(config: Mapping[str, Any], evidence_root: Path) -> dict[str, Any]:
    if config.get("schema") != REQUEST_SCHEMA:
        raise ImprovementError("unsupported model-improvement request schema")
    if config.get("environment") not in {"local", "devnet", "testnet"} or config.get("production") is not False:
        raise ImprovementError("model improvement is restricted to explicit non-production environments")
    flags = feature_flags_false(config)
    frozen = verify_frozen_v2()
    seeds = config.get("signing_seeds")
    if not isinstance(seeds, dict):
        raise ImprovementError("signing_seeds are required")
    store = ImmutableEvidenceStore(evidence_root)

    dataset_spec = config.get("dataset")
    recipe_spec = config.get("recipe")
    job_spec = config.get("job")
    if not all(isinstance(value, dict) for value in (dataset_spec, recipe_spec, job_spec)):
        raise ImprovementError("dataset, recipe, and job specifications are required")
    dataset = build_dataset_snapshot(dataset_spec, str(seeds.get("builder", "")))
    recipe_spec = dict(recipe_spec)
    recipe_spec["dataset_id"] = dataset["object_id"]
    recipe = build_training_recipe(recipe_spec, dataset["object_id"], str(seeds.get("sponsor", "")))
    job = build_adapter_job(job_spec, recipe, str(seeds.get("trainer", "")))
    for kind, record in (("datasets", dataset), ("recipes", recipe), ("jobs", job)):
        store.insert(kind, record)

    roundtrip_spec = config.get("roundtrip")
    if not isinstance(roundtrip_spec, dict):
        raise ImprovementError("roundtrip specification is required")
    work_root = Path(str(roundtrip_spec.get("work_root", evidence_root / "work")))
    roundtrip, paths = run_real_roundtrip(roundtrip_spec, work_root)
    candidate_revision_id = roundtrip["successor_sha256"]
    update_spec = config.get("update")
    if not isinstance(update_spec, dict):
        raise ImprovementError("update specification is required")
    update, receipt = build_update_and_receipt(update_spec, recipe, dataset, job, candidate_revision_id,
                                               paths["adapter"], str(seeds.get("trainer", "")))
    store.insert("updates", update)
    store.insert("receipts", receipt)

    evaluations = config.get("evaluations")
    if not isinstance(evaluations, list):
        raise ImprovementError("evaluations must be a list")
    registry = EvaluationRegistry(candidate_revision_id, recipe["parent_revision_id"], job["trainer_control_cluster"])
    evaluator_seeds = seeds.get("evaluators")
    if not isinstance(evaluator_seeds, list) or len(evaluator_seeds) != len(evaluations):
        raise ImprovementError("one evaluator signing seed is required per report")
    reports = [registry.insert(spec, seed) for spec, seed in zip(evaluations, evaluator_seeds, strict=True)]
    for report in reports:
        store.insert("evaluations", report)
    floors = config.get("hard_floors_q20")
    if not isinstance(floors, dict):
        raise ImprovementError("hard_floors_q20 is required")
    evaluation_gate = registry.hard_floor_gate(floors)
    if not evaluation_gate["passed"]:
        raise ImprovementError(f"independent evaluation gate failed: {evaluation_gate['failures']}")

    successor_bindings = {
        "parent_revision_id": recipe["parent_revision_id"], "dataset_id": dataset["object_id"],
        "recipe_id": recipe["object_id"], "adapter_update_packet_id": update["object_id"],
        "trainer_receipt_id": receipt["object_id"], "evaluation_set_root": evaluation_gate["evaluation_set_root"],
        **dict(config.get("successor_roots", {})),
    }
    successor_spec = config.get("successor")
    if not isinstance(successor_spec, dict):
        raise ImprovementError("successor specification is required")
    exported_path, bundle_manifest = export_immutable_successor_bundle(
        paths["successor"],
        evidence_root / "successor-artifacts",
        Path(str(successor_spec.get("license_path", ""))),
        Path(str(successor_spec.get("notice_path", ""))),
        str(successor_spec.get("license_sha256", "")),
        str(successor_spec.get("notice_sha256", "")),
    )
    successor_spec = {**successor_spec, "bundle_root": bundle_manifest["bundle_root"]}
    successor = build_successor_evidence(successor_spec, exported_path, successor_bindings,
                                         str(seeds.get("successor", "")))
    store.insert("successors", successor)

    activation = config.get("activation")
    if not isinstance(activation, dict):
        raise ImprovementError("activation specification is required")
    controller = CanaryController(candidate_revision_id, recipe["parent_revision_id"],
                                  activation.get("proposal_height"), activation.get("challenge_end_height"), floors)
    controller.begin(require_int(activation.get("begin_height"), "begin_height", 1, 2**63 - 1), evaluation_gate)
    observations = activation.get("observations")
    if not isinstance(observations, list):
        raise ImprovementError("activation observations must be a list")
    for observation in observations:
        if not isinstance(observation, dict):
            raise ImprovementError("activation observation must be an object")
        controller.observe(observation)
        if controller.state == "ROLLED_BACK":
            break
    activation_evidence = signed_record("NOOS-WWM-ACTIVATION-EVIDENCE-V1", controller.evidence(),
                                        str(seeds.get("activator", "")))
    store.insert("activations", activation_evidence)

    final_pass = controller.state == "CANARY_COMPLETE"
    summary = {
        "schema": EVIDENCE_SCHEMA,
        "passed": final_pass,
        "shadow_training_workflow_passed": True,
        "shadow_canary_passed": final_pass,
        "production_promotion_authorized": False,
        "feature_flags": flags,
        "frozen_wwm_v2_sha256": frozen,
        "dataset_id": dataset["object_id"], "recipe_id": recipe["object_id"], "job_id": job["object_id"],
        "update_packet_id": update["object_id"], "trainer_receipt_id": receipt["object_id"],
        "successor_id": successor["object_id"], "candidate_revision_id": candidate_revision_id,
        "evaluation_gate": evaluation_gate, "activation": controller.evidence(),
        "future_v3_gate": "directly queryable canonical training objects require a reviewed WWM v3 upgrade",
        "frozen_v2_action_added": False,
    }
    summary_signed = signed_record("NOOS-WWM-MODEL-IMPROVEMENT-EVIDENCE-V1", summary,
                                   str(seeds.get("activator", "")))
    store.insert("summaries", summary_signed)
    return summary_signed


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("wb") as output:
        output.write(canonical_json(value) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    probe = subparsers.add_parser("probe", help="truthfully probe the real-parent gate without training")
    probe.add_argument("--config", type=Path, required=True)
    probe.add_argument("--evidence", type=Path)
    run = subparsers.add_parser("run", help="execute the full one-step/evaluation/canary workflow")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--evidence-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = load_object(args.config)
        if args.command == "probe":
            if config.get("schema") != SCHEMA:
                raise ImprovementError("unsupported gate configuration schema")
            result = probe_gate(config)
            if args.evidence:
                _write_json(args.evidence, result.evidence)
            print(json.dumps(result.evidence, sort_keys=True))
            return 0 if result.passed else 2
        summary = run_workflow(config, args.evidence_root)
        print(json.dumps(summary, sort_keys=True))
        return 0 if summary["passed"] else 2
    except ImprovementError as error:
        print(json.dumps({"schema": EVIDENCE_SCHEMA, "passed": False, "weight_training_enabled": False,
                          "promotion_enabled": False, "feature_flags": {name: False for name in FEATURE_FLAGS},
                          "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
