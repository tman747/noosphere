#!/usr/bin/env python3
"""Shared, fail-closed evidence writer for NOOSPHERE experimental gates."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence" / "claim-matrix"
RESULTS = {"IMPLEMENTED", "PASSED", "KILLED", "DISABLED", "PARTIAL", "EXTERNAL_BLOCKED"}
PROMOTABLE_RESULTS = {"IMPLEMENTED", "PASSED", "KILLED", "DISABLED"}
CHECK_FIELDS = {"id", "kind", "passed", "detail"}
CHECK_KINDS = {"implementation", "falsifier", "rollback", "disabled_control", "external_requirement"}
MANDATORY_CHECK_KINDS = {
    "IMPLEMENTED": {"implementation", "falsifier", "rollback"},
    "PASSED": {"implementation", "falsifier", "rollback"},
    "KILLED": {"falsifier", "rollback"},
    "DISABLED": {"disabled_control", "falsifier", "rollback"},
}
BASE_FILES = (
    "evidence/base-base-transfer-contract.json",
    "evidence/base-ai-blackout.json",
    "evidence/base-crash-matrix.json",
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _git(*args: str, binary: bool = False) -> str | bytes:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode:
        raise SystemExit(completed.stderr.decode("utf-8", errors="replace").strip())
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def source_binding(paths: Iterable[str]) -> dict[str, object]:
    revision = str(_git("rev-parse", "HEAD^{commit}"))
    tree = str(_git("rev-parse", f"{revision}^{{tree}}"))
    required = {
        "protocol/claims/experimental-evidence-schema-v2.json",
        "tools/gates/experimental_gate.py",
        "tools/gates/run_claim_matrix.py",
    }
    invoked = Path(sys.argv[0])
    try:
        required.add(invoked.resolve().relative_to(ROOT).as_posix())
    except ValueError:
        pass
    entries: list[dict[str, object]] = []
    for rel in sorted(set(paths) | required):
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(f"required source missing: {rel}")
        raw = str(_git("ls-tree", revision, "--", rel))
        try:
            metadata, listed = raw.split("\t", 1)
            mode, object_type, blob = metadata.split(" ", 2)
        except ValueError as exc:
            raise SystemExit(f"required source is not tracked at {revision}: {rel}") from exc
        if listed != rel or object_type != "blob":
            raise SystemExit(f"required source is not a tracked blob: {rel}")
        committed = bytes(_git("show", f"{revision}:{rel}", binary=True))
        dirty = subprocess.run(
            ["git", "diff", "--quiet", revision, "--", rel], cwd=ROOT, check=False
        )
        if dirty.returncode != 0:
            raise SystemExit(f"relevant source is dirty/replaced relative to {revision}: {rel}")
        entries.append({
            "path": rel,
            "git_mode": mode,
            "git_blob": blob,
            "bytes": len(committed),
            "sha256": hashlib.sha256(committed).hexdigest(),
        })
    manifest_hash = canonical_hash(entries)
    return {
        "source_revision": revision,
        "source_tree": tree,
        "manifest_sha256": manifest_hash,
        "entries": entries,
    }


def evidence_check(check_id: str, kind: str, passed: bool, detail: object) -> dict[str, object]:
    return {
        "id": check_id,
        "kind": kind,
        "passed": passed,
        "detail": detail if isinstance(detail, str) else json.dumps(detail, sort_keys=True, separators=(",", ":")),
    }


def validate_checks(result: str, checks: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(checks, list) or not checks:
        return ["checks must be a non-empty list"]
    seen: set[str] = set()
    kinds: set[str] = set()
    outcomes: list[bool] = []
    for index, item in enumerate(checks):
        if not isinstance(item, dict) or set(item) != CHECK_FIELDS:
            errors.append(f"check {index} has missing or unknown fields")
            continue
        check_id = item["id"]
        kind = item["kind"]
        passed = item["passed"]
        detail = item["detail"]
        if not isinstance(check_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,79}", check_id):
            errors.append(f"check {index} has invalid id")
        elif check_id in seen:
            errors.append(f"duplicate check id: {check_id}")
        else:
            seen.add(check_id)
        if kind not in CHECK_KINDS:
            errors.append(f"check {index} has unknown kind")
        else:
            kinds.add(kind)
        if type(passed) is not bool:
            errors.append(f"check {index} passed must be boolean")
        else:
            outcomes.append(passed)
        if not isinstance(detail, str) or not detail.strip():
            errors.append(f"check {index} detail must be a non-empty string")
    mandatory = MANDATORY_CHECK_KINDS.get(result, set())
    missing = sorted(mandatory - kinds)
    if missing:
        errors.append("missing mandatory check kinds: " + ", ".join(missing))
    if result in PROMOTABLE_RESULTS and outcomes and not all(outcomes):
        errors.append(f"{result} evidence contains a failed check")
    if result in {"PARTIAL", "EXTERNAL_BLOCKED"} and outcomes and all(outcomes):
        errors.append(f"{result} evidence must preserve at least one unmet check")
    if result == "EXTERNAL_BLOCKED" and "external_requirement" not in kinds:
        errors.append("EXTERNAL_BLOCKED evidence lacks an external requirement check")
    return errors


def base_continuity() -> dict[str, object]:
    files: dict[str, str] = {}
    observations: dict[str, object] = {}
    for rel in BASE_FILES:
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(f"base continuity evidence missing: {rel}")
        doc = json.loads(path.read_text(encoding="utf-8"))
        runs = doc.get("observations", {}).get("runs", [])
        if not runs or any(run.get("verdict") != "PASS" for run in runs):
            raise SystemExit(f"base continuity evidence is not PASS: {rel}")
        for run in runs:
            safety = run.get("safety", {})
            roots = run.get("roots", {})
            if safety.get("conflicting_finalizations", 0) or roots.get("state_divergences", 0) or roots.get("fork_divergences", 0):
                raise SystemExit(f"base safety/root divergence in {rel}")
        rollback = doc.get("rollback", {})
        if rollback.get("verdict") != "PASS" or rollback.get("ordinary_base_live") is not True:
            raise SystemExit(f"rollback/base continuity is not proven: {rel}")
        files[rel] = sha256(path)
        observations[rel] = {"runs": len(runs), "rollback": "PASS"}
    return {"ordinary_base_live": True, "rollback_verified": True, "files": files, "observations": observations}


def cargo_test(packages: Iterable[str]) -> dict[str, object]:
    package_list = list(packages)
    command = ["cargo", "test", "--locked"]
    for package in package_list:
        command += ["-p", package]
    # Some package-scoped node integration tests contend when the Rust test
    # harness runs them concurrently. Serial execution preserves the complete
    # assertion set while keeping claim evidence generation deterministic.
    command += ["--", "--test-threads=1"]
    completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if completed.returncode:
        digest = hashlib.sha256(completed.stdout.encode()).hexdigest()
        sys.stderr.write(completed.stdout)
        raise SystemExit(f"experimental crate check failed ({completed.returncode}); log_sha256={digest}")
    return {"command": command, "exit_code": completed.returncode, "packages": package_list}


FINGERPRINT_FIELDS = (
    "claim_id", "mechanism_id", "canonical_statement_ref", "implementation_hashes",
    "verifier_hashes", "metric", "statistical_power", "pass_threshold", "kill_threshold",
    "gate", "result", "enabled", "date", "command", "expected_result", "rollback_command",
)


def claim_fingerprint(row: dict[str, object]) -> str:
    return canonical_hash({key: row.get(key) for key in FINGERPRINT_FIELDS})


def emit(*, gate: str, claims: list[str], result: str, expected: str, checks: list[dict[str, object]], sources: Iterable[str], limitations: list[str] | None = None, command: list[str] | None = None) -> tuple[Path, str]:
    if result not in RESULTS or expected not in RESULTS:
        raise SystemExit("invalid experimental result")
    if result != expected:
        raise SystemExit(f"observed {result}, preregistered expected result is {expected}")
    continuity = base_continuity()
    checks = list(checks) + [
        evidence_check(
            "ordinary-base-rollback",
            "rollback",
            True,
            {"ordinary_base_live": continuity["ordinary_base_live"], "rollback_verified": continuity["rollback_verified"]},
        )
    ]
    check_errors = validate_checks(result, checks)
    if check_errors:
        raise SystemExit("invalid evidence checks: " + "; ".join(check_errors))
    registry = json.loads((ROOT / "protocol/claims/registry.json").read_text(encoding="utf-8"))
    known = {c["claim_id"] for c in registry["claims"]}
    unknown = sorted(set(claims) - known)
    if unknown:
        raise SystemExit(f"unregistered claims: {unknown}")
    by_id = {c["claim_id"]: c for c in registry["claims"]}
    evidence = {
        "schema_version": "noos.experimental-evidence.v2",
        "registry_schema_version": registry["schema_version"],
        "gate": gate,
        "claims": sorted(claims),
        "claim_fingerprints": {claim: claim_fingerprint(by_id[claim]) for claim in sorted(claims)},
        "command": command or sys.argv,
        "result": result,
        "expected_result": expected,
        "checks": checks,
        "limitations": limitations or [],
        "source_binding": source_binding(sources),
        "base_continuity": continuity,
    }
    digest = canonical_hash(evidence)
    evidence["evidence_sha256"] = digest
    target = EVIDENCE / gate / f"{digest}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if target.exists() and target.read_text(encoding="utf-8") != encoded:
        raise SystemExit(f"immutable evidence collision: {target}")
    target.write_text(encoded, encoding="utf-8", newline="\n")
    rel = target.relative_to(ROOT).as_posix()
    print(f"RESULT {gate}={result}")
    print(f"EVIDENCE {rel} sha256={sha256(target)} content_sha256={digest}")
    return target, sha256(target)


def require_disabled_controls(names: Iterable[str]) -> dict[str, object]:
    constants = (ROOT / "protocol/spec/constants-v1.toml").read_text(encoding="utf-8")
    missing = [name for name in names if f"{name} = false" not in constants and f"{name} = 0" not in constants]
    if missing:
        raise SystemExit(f"required disabled controls absent: {missing}")
    return evidence_check(
        "activation-controls-disabled",
        "disabled_control",
        True,
        {"controls": list(names)},
    )
