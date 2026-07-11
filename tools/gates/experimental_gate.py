#!/usr/bin/env python3
"""Shared, fail-closed evidence writer for NOOSPHERE experimental gates."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence" / "claim-matrix"
RESULTS = {"IMPLEMENTED", "PASSED", "KILLED", "DISABLED", "EXTERNAL_BLOCKED"}
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


def source_hashes(paths: Iterable[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in sorted(set(paths)):
        path = ROOT / rel
        if not path.is_file():
            raise SystemExit(f"required source missing: {rel}")
        out[rel] = sha256(path)
    return out


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
    registry = json.loads((ROOT / "protocol/claims/registry.json").read_text(encoding="utf-8"))
    known = {c["claim_id"] for c in registry["claims"]}
    unknown = sorted(set(claims) - known)
    if unknown:
        raise SystemExit(f"unregistered claims: {unknown}")
    by_id = {c["claim_id"]: c for c in registry["claims"]}
    evidence = {
        "schema_version": "noos.experimental-evidence.v1",
        "registry_schema_version": registry["schema_version"],
        "gate": gate,
        "claims": sorted(claims),
        "claim_fingerprints": {claim: claim_fingerprint(by_id[claim]) for claim in sorted(claims)},
        "command": command or sys.argv,
        "result": result,
        "expected_result": expected,
        "checks": checks,
        "limitations": limitations or [],
        "source_sha256": source_hashes(sources),
        "base_continuity": base_continuity(),
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
    return {"name": "activation controls remain off", "controls": list(names), "passed": True}
