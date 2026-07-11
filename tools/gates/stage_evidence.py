#!/usr/bin/env python3
"""Run commands into immutable stage bundles and validate retained raw evidence.

The runner never decides whether a protocol threshold passed: the caller must supply
thresholds, measurements, verdict and basis. Output creation is exclusive (O_EXCL).
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

STAGES = {"G0", "G1", "G2", "G3", "GENESIS", "G4", "G5"}
VERDICTS = {"PASS", "FAIL", "BLOCKED", "KILLED"}
ROLLBACK_OUTCOMES = {"NOT_REQUIRED", "SUCCEEDED", "FAILED", "BLOCKED", "NOT_RUN"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hashed_file(root: Path, path: Path) -> dict:
    resolved = path.resolve()
    try:
        rel = resolved.relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"artifact must be inside repository: {resolved}") from exc
    return {"path": rel, "bytes": resolved.stat().st_size, "sha256": sha256(resolved)}


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp lacks UTC offset")
    return parsed.astimezone(dt.timezone.utc)


def validate_bundle(root: Path, path: Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path}: parse failed: {exc}"]
    top = {"schema_version", "bundle_id", "stage", "protocol_binding", "execution", "inputs", "raw_artifacts", "evaluation", "rollback", "producer", "signatures"}
    if set(doc) != top or doc.get("schema_version") != 1:
        errors.append(f"{path}: top-level schema fields/version mismatch")
    if not BUNDLE_ID.fullmatch(str(doc.get("bundle_id", ""))) or doc.get("stage") not in STAGES:
        errors.append(f"{path}: bundle_id/stage invalid")
    binding = doc.get("protocol_binding", {})
    if set(binding) != {"revision", "protocol_version", "api_version", "release_version", "chain_id", "genesis_hash"} or any(not isinstance(v, str) or not v for v in binding.values()):
        errors.append(f"{path}: protocol binding incomplete")
    execution = doc.get("execution", {})
    required_execution = {"command", "cwd", "toolchain_environment", "started_at_utc", "ended_at_utc", "exit_code"}
    if set(execution) != required_execution:
        errors.append(f"{path}: execution fields mismatch")
    if not isinstance(execution.get("command"), list) or not execution.get("command") or any(not isinstance(x, str) for x in execution.get("command", [])):
        errors.append(f"{path}: exact command array absent")
    if not isinstance(execution.get("cwd"), str) or not execution.get("cwd") or not Path(execution.get("cwd", ".")).is_dir():
        errors.append(f"{path}: cwd missing or unavailable")
    if not isinstance(execution.get("toolchain_environment"), dict) or not execution.get("toolchain_environment"):
        errors.append(f"{path}: toolchain/environment must be a non-empty exact object")
    if not isinstance(execution.get("exit_code"), int) or isinstance(execution.get("exit_code"), bool):
        errors.append(f"{path}: exit code invalid")
    try:
        if parse_time(execution["ended_at_utc"]) < parse_time(execution["started_at_utc"]):
            errors.append(f"{path}: end precedes start")
    except (KeyError, TypeError, ValueError) as exc:
        errors.append(f"{path}: timestamps invalid: {exc}")
    inputs = doc.get("inputs", {})
    if set(inputs) != {"fixtures", "seeds"} or not isinstance(inputs.get("fixtures"), list) or not isinstance(inputs.get("seeds"), list):
        errors.append(f"{path}: fixtures/seeds fields invalid")
    artifacts = doc.get("raw_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) < 2:
        errors.append(f"{path}: stdout/stderr raw artifacts absent")
        artifacts = []
    for item in list(inputs.get("fixtures", [])) + artifacts:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            errors.append(f"{path}: hashed artifact fields invalid")
            continue
        artifact = root / str(item.get("path", ""))
        if not artifact.is_file():
            errors.append(f"{path}: retained artifact missing: {item.get('path')}")
            continue
        if item.get("bytes") != artifact.stat().st_size or item.get("sha256") != sha256(artifact):
            errors.append(f"{path}: retained artifact hash/size mismatch: {item.get('path')}")
    evaluation = doc.get("evaluation", {})
    required_evaluation = {"thresholds", "measurements", "verdict", "verdict_basis", "exclusions", "conflicts"}
    if set(evaluation) != required_evaluation or not isinstance(evaluation.get("thresholds"), dict) or not evaluation.get("thresholds"):
        errors.append(f"{path}: thresholds/evaluation fields invalid")
    if evaluation.get("verdict") not in VERDICTS or not isinstance(evaluation.get("verdict_basis"), str) or not evaluation.get("verdict_basis"):
        errors.append(f"{path}: actual verdict and basis invalid")
    if not isinstance(evaluation.get("measurements"), dict) or not isinstance(evaluation.get("exclusions"), list) or not isinstance(evaluation.get("conflicts"), list):
        errors.append(f"{path}: measurements/exclusions/conflicts invalid")
    if evaluation.get("verdict") == "PASS" and execution.get("exit_code") != 0:
        errors.append(f"{path}: PASS with nonzero exit code prohibited")
    rollback = doc.get("rollback", {})
    required_rollback = {"triggered", "target", "action", "outcome", "evidence_refs"}
    if set(rollback) != required_rollback or not isinstance(rollback.get("triggered"), bool) or rollback.get("outcome") not in ROLLBACK_OUTCOMES:
        errors.append(f"{path}: rollback fields invalid")
    if any(not isinstance(rollback.get(k), str) or not rollback.get(k) for k in ("target", "action")) or not isinstance(rollback.get("evidence_refs"), list):
        errors.append(f"{path}: rollback target/action/evidence invalid")
    if rollback.get("triggered") and rollback.get("outcome") in {"NOT_REQUIRED", "NOT_RUN"}:
        errors.append(f"{path}: triggered rollback must report an actual outcome")
    if doc.get("producer", {}).get("orchestrator") != "tools/gates/stage_evidence.py":
        errors.append(f"{path}: producer/orchestrator invalid")
    if not isinstance(doc.get("signatures"), list):
        errors.append(f"{path}: signatures must be an array (empty is honest before signing)")
    return errors


def validate_all(root: Path, selected: list[str]) -> list[str]:
    if selected:
        paths = [(root / item).resolve() if not Path(item).is_absolute() else Path(item) for item in selected]
    else:
        bundles = root / "evidence/stages/bundles"
        paths = sorted(bundles.glob("*.json")) if bundles.exists() else []
    errors: list[str] = []
    schema_path = root / "evidence/stages/stage-evidence-schema-v1.json"
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        if schema.get("$id") != "urn:noos:stage-evidence:v1" or schema.get("additionalProperties") is not False:
            errors.append("stage evidence schema identity or closed-object policy mismatch")
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"stage evidence schema missing or invalid: {exc}")
    for path in paths:
        errors.extend(validate_bundle(root, path))
    print(f"Stage evidence validation: checked {len(paths)} immutable bundle(s)")
    return errors


def json_object(value: str, name: str) -> dict:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} is not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{name} must be a JSON object")
    return parsed


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def run_bundle(root: Path, args: argparse.Namespace) -> Path:
    if not BUNDLE_ID.fullmatch(args.bundle_id) or args.stage not in STAGES:
        raise ValueError("invalid bundle ID or stage")
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        raise ValueError("exact command is required after --")
    cwd = Path(args.cwd).resolve()
    if not cwd.is_dir():
        raise ValueError(f"cwd is not a directory: {cwd}")
    toolchain = json_object(args.toolchain_environment, "--toolchain-environment")
    thresholds = json_object(args.thresholds, "--thresholds")
    measurements = json_object(args.measurements, "--measurements")
    rollback = json_object(args.rollback, "--rollback")
    if not toolchain or not thresholds:
        raise ValueError("toolchain/environment and thresholds must be non-empty")
    if set(rollback) != {"triggered", "target", "action", "outcome", "evidence_refs"}:
        raise ValueError("rollback JSON fields mismatch")
    docs = json.loads((root / "docs/v1/bundle.json").read_text(encoding="utf-8"))
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()
    out_dir = root / "evidence/stages/bundles" / args.bundle_id
    out_dir.mkdir(parents=True, exist_ok=False)
    stdout_path, stderr_path = out_dir / "stdout.raw", out_dir / "stderr.raw"
    started = utc_now()
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        result = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, shell=False)
    ended = utc_now()
    fixtures = [hashed_file(root, Path(x)) for x in args.fixture]
    bundle = {
        "schema_version": 1, "bundle_id": args.bundle_id, "stage": args.stage,
        "protocol_binding": {"revision": revision, "protocol_version": docs["protocol_version"], "api_version": docs["api_version"], "release_version": docs["release_version"], "chain_id": docs["chain_id"], "genesis_hash": docs["genesis_hash"]},
        "execution": {"command": command, "cwd": str(cwd), "toolchain_environment": toolchain, "started_at_utc": started, "ended_at_utc": ended, "exit_code": result.returncode},
        "inputs": {"fixtures": fixtures, "seeds": json.loads(args.seeds)},
        "raw_artifacts": [hashed_file(root, stdout_path), hashed_file(root, stderr_path)],
        "evaluation": {"thresholds": thresholds, "measurements": measurements, "verdict": args.verdict, "verdict_basis": args.verdict_basis, "exclusions": args.exclusion, "conflicts": args.conflict},
        "rollback": rollback,
        "producer": {"orchestrator": "tools/gates/stage_evidence.py", "host_class": args.host_class},
        "signatures": []
    }
    bundle_path = root / "evidence/stages/bundles" / f"{args.bundle_id}.json"
    with bundle_path.open("x", encoding="utf-8", newline="\n") as dest:
        json.dump(bundle, dest, indent=2, sort_keys=True)
        dest.write("\n")
    validation = validate_bundle(root, bundle_path)
    if validation:
        raise ValueError("generated bundle failed validation: " + "; ".join(validation))
    return bundle_path


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    check = sub.add_parser("validate")
    check.add_argument("bundles", nargs="*")
    run = sub.add_parser("run")
    run.add_argument("--bundle-id", required=True); run.add_argument("--stage", required=True, choices=sorted(STAGES))
    run.add_argument("--cwd", required=True); run.add_argument("--toolchain-environment", required=True)
    run.add_argument("--fixture", action="append", default=[]); run.add_argument("--seeds", default="[]")
    run.add_argument("--thresholds", required=True); run.add_argument("--measurements", default="{}")
    run.add_argument("--verdict", required=True, choices=sorted(VERDICTS)); run.add_argument("--verdict-basis", required=True)
    run.add_argument("--exclusion", action="append", default=[]); run.add_argument("--conflict", action="append", default=[])
    run.add_argument("--rollback", required=True); run.add_argument("--host-class", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    return p


def main(argv: list[str]) -> int:
    args = parser().parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    try:
        if args.action == "validate":
            errors = validate_all(root, args.bundles)
            if errors:
                for error in errors: print(f"ERROR: {error}")
                print(f"Stage evidence gate: FAIL ({len(errors)} error(s))")
                return 1
            print("Stage evidence gate: PASS")
            return 0
        path = run_bundle(root, args)
        print(f"Immutable stage evidence bundle created: {path.relative_to(root).as_posix()}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
