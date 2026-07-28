#!/usr/bin/env python3
"""Run the deterministic local cross-language promotion laboratory.

The laboratory binds one clean Git revision, runs frozen vectors through the
Rust and Go implementations, exercises deterministic differential campaigns,
and preserves immutable per-lane logs plus one machine-readable result. It can
prove local implementation agreement. It cannot prove organizational
independence, vendor diversity, or production authorization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "noos/cross-language-lab-result/v1"
REVISION_RE = re.compile(r"[0-9a-f]{40}")
PROFILES = {"smoke", "qualification"}


class LabError(ValueError):
    pass


@dataclass(frozen=True)
class LaneSpec:
    lane_id: str
    area: str
    command: tuple[str, ...]
    cwd: str = "."
    timeout_seconds: int = 1_800
    artifact: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(root: Path, pattern: str = "*") -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob(pattern) if path.is_file())
    total_bytes = 0
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        total_bytes += len(payload)
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest(), len(files), total_bytes


def qualification_counts(profile: str) -> dict[str, int]:
    if profile not in PROFILES:
        raise LabError(f"unknown profile: {profile}")
    if profile == "qualification":
        return {
            "transition": 100_000,
            "admission": 10_000,
            "grain": 100_000,
            "weft": 100_000,
        }
    return {
        "transition": 512,
        "admission": 512,
        "grain": 1_024,
        "weft": 512,
    }


def lane_specs(profile: str, seed: int) -> tuple[LaneSpec, ...]:
    counts = qualification_counts(profile)
    seed_text = hex(seed)
    restart_every = max(1, counts["transition"] // 4)
    return (
        LaneSpec(
            "frozen-vector-shape",
            "frozen_vectors",
            ("python", "tools/gates/check_vectors.py", "protocol/vectors", "--strict"),
            timeout_seconds=180,
        ),
        LaneSpec(
            "wwm-schema-runtime-vectors",
            "schema_runtime",
            (
                "python",
                "-m",
                "unittest",
                "-q",
                "tools.operations.test_wwm_web_capacity_vectors",
            ),
            timeout_seconds=300,
        ),
        LaneSpec(
            "go-reference-vectors",
            "go_reference",
            ("go", "test", "-count=1", "./conformance"),
            cwd="go",
            timeout_seconds=600,
        ),
        LaneSpec(
            "rust-reference-vectors",
            "rust_reference",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-codec",
                "-p",
                "noos-lumen",
                "-p",
                "noos-braid",
                "-p",
                "noos-ground",
                "-p",
                "noos-grain",
                "-p",
                "noos-witness",
            ),
        ),
        LaneSpec(
            "transition-small-state",
            "small_state_differential",
            (
                "python",
                "tools/gates/differential_transitions.py",
                "--generated",
                str(counts["transition"]),
                "--parameterized-max",
                "10000000",
                "--seed",
                seed_text,
                "--restart-every",
                str(restart_every),
            ),
        ),
        LaneSpec(
            "admission-mutations",
            "authorization_differential",
            (
                "python",
                "tools/gates/differential_admission.py",
                "--generated",
                str(counts["admission"]),
                "--seed",
                seed_text,
                "--out",
                "{artifact}",
            ),
            artifact=True,
        ),
        LaneSpec(
            "grain-generated-differential",
            "mutation_fuzz",
            (
                "python",
                "tools/gates/differential_grain.py",
                "--vectors",
                "protocol/vectors/grain",
                "--generated",
                str(counts["grain"]),
                "--shards",
                "4",
                "--seed-base",
                seed_text,
            ),
        ),
        LaneSpec(
            "weft-generated-differential",
            "mutation_fuzz",
            (
                "python",
                "tools/gates/differential_weft.py",
                "--cases",
                str(counts["weft"]),
                "--seed",
                str(seed),
            ),
        ),
        LaneSpec(
            "nel-model-runtime",
            "model_runtime",
            ("cargo", "test", "--locked", "-p", "noos-nel"),
        ),
        LaneSpec(
            "authorization-contracts",
            "authorization",
            (
                "python",
                "-m",
                "unittest",
                "-q",
                "tools.genesis.test_production_authorization",
                "tools.gates.test_protocol_v2_release",
                "tools.gates.test_repro_build",
            ),
            timeout_seconds=900,
        ),
        LaneSpec(
            "genesis-reproduction",
            "cross_language_genesis",
            ("python", "tools/genesis/ceremony.py", "--self-test"),
        ),
    )


def validate_lane_plan(lanes: Sequence[LaneSpec]) -> None:
    identifiers = [lane.lane_id for lane in lanes]
    if len(identifiers) != len(set(identifiers)):
        raise LabError("lane identifiers must be unique")
    required_areas = {
        "frozen_vectors",
        "schema_runtime",
        "go_reference",
        "rust_reference",
        "small_state_differential",
        "authorization_differential",
        "mutation_fuzz",
        "model_runtime",
        "authorization",
        "cross_language_genesis",
    }
    missing = sorted(required_areas - {lane.area for lane in lanes})
    if missing:
        raise LabError(f"lane plan is missing required areas: {missing}")
    for lane in lanes:
        if not lane.command or lane.timeout_seconds < 1:
            raise LabError(f"invalid lane: {lane.lane_id}")


def git_output(arguments: Sequence[str]) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode:
        raise LabError(
            f"git {' '.join(arguments)} failed: {completed.stdout.strip()}"
        )
    return completed.stdout.strip()


def verify_clean_revision(source_revision: str) -> None:
    if REVISION_RE.fullmatch(source_revision) is None:
        raise LabError("source revision must be forty lowercase hexadecimal characters")
    actual = git_output(("rev-parse", "HEAD"))
    if actual != source_revision:
        raise LabError(f"source revision mismatch: checkout={actual} requested={source_revision}")
    for arguments, label in (
        (("diff", "--quiet", "--"), "tracked worktree"),
        (("diff", "--cached", "--quiet", "--"), "index"),
    ):
        completed = subprocess.run(["git", *arguments], cwd=ROOT, check=False)
        if completed.returncode != 0:
            raise LabError(f"{label} is not clean")
    if git_output(("ls-files", "--others", "--exclude-standard")):
        raise LabError("untracked files are present")


def tool_version(command: Sequence[str], cwd: Path) -> dict[str, object]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": list(command), "available": False, "detail": str(exc)}
    return {
        "command": list(command),
        "available": completed.returncode == 0,
        "detail": completed.stdout.strip(),
    }


def write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
    except FileExistsError as exc:
        raise LabError(f"refusing to overwrite {path}") from exc


def run_lane(
    lane: LaneSpec,
    artifacts_root: Path,
    environment: dict[str, str],
) -> dict[str, object]:
    lane_artifact = artifacts_root / "lane-evidence" / f"{lane.lane_id}.json"
    if lane.artifact:
        lane_artifact.parent.mkdir(parents=True, exist_ok=True)
    replacements = {
        "{artifact}": lane_artifact.as_posix(),
        "{artifact_root}": artifacts_root.as_posix(),
    }
    displayed_command = [replacements.get(item, item) for item in lane.command]
    execution_command = [
        sys.executable if item == "python" else item for item in displayed_command
    ]
    started = time.perf_counter()
    output = b""
    return_code: int | None = None
    timed_out = False
    error: str | None = None
    try:
        completed = subprocess.run(
            execution_command,
            cwd=ROOT / lane.cwd,
            env=environment,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=lane.timeout_seconds,
        )
        output = completed.stdout
        return_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        if isinstance(exc.stdout, bytes):
            output = exc.stdout
        elif isinstance(exc.stdout, str):
            output = exc.stdout.encode("utf-8", errors="replace")
        error = f"timed out after {lane.timeout_seconds} seconds"
    except OSError as exc:
        error = str(exc)
        output = (str(exc) + "\n").encode("utf-8", errors="replace")
    elapsed_ms = int((time.perf_counter() - started) * 1_000)
    log_path = artifacts_root / "logs" / f"{lane.lane_id}.log"
    write_exclusive(log_path, output)
    attached: dict[str, object] | None = None
    if lane.artifact and lane_artifact.is_file():
        attached = {
            "path": lane_artifact.as_posix(),
            "bytes": lane_artifact.stat().st_size,
            "sha256": sha256_file(lane_artifact),
        }
    passed = return_code == 0 and not timed_out and error is None
    if lane.artifact and attached is None:
        passed = False
        error = error or "lane did not write its required evidence artifact"
    return {
        "lane_id": lane.lane_id,
        "area": lane.area,
        "command": displayed_command,
        "cwd": lane.cwd,
        "timeout_seconds": lane.timeout_seconds,
        "return_code": return_code,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "passed": passed,
        "error": error,
        "log": {
            "path": log_path.as_posix(),
            "bytes": len(output),
            "sha256": sha256_bytes(output),
        },
        "attached_evidence": attached,
    }


def build_result(
    *,
    source_revision: str,
    profile: str,
    seed: int,
    started_at_utc: str,
    completed_at_utc: str,
    versions: dict[str, object],
    vector_tree: dict[str, object],
    lanes: list[dict[str, object]],
    artifacts_root: Path,
) -> dict[str, object]:
    failed = [str(lane["lane_id"]) for lane in lanes if not lane["passed"]]
    blockers = [
        "INDEPENDENT_REPRODUCTION_REQUIRED",
        "INDEPENDENT_AUTHORSHIP_AND_CONTROL_NOT_MACHINE_VERIFIED",
        "REAL_MODEL_VENDOR_AND_HARDWARE_MATRIX_REQUIRED",
    ]
    if profile == "smoke":
        blockers.append("QUALIFICATION_SCALE_NOT_RUN")
    blockers.extend(f"LANE_FAILED:{lane_id}" for lane_id in failed)
    artifact_digest, artifact_files, artifact_bytes = tree_digest(artifacts_root)
    report: dict[str, object] = {
        "schema": SCHEMA,
        "source_revision": source_revision,
        "profile": profile.upper(),
        "seed": seed,
        "started_at_utc": started_at_utc,
        "completed_at_utc": completed_at_utc,
        "tool_versions": versions,
        "frozen_vector_tree": vector_tree,
        "qualification_counts": qualification_counts(profile),
        "lanes": lanes,
        "lane_count": len(lanes),
        "passed_lane_count": len(lanes) - len(failed),
        "failed_lane_ids": failed,
        "control_contract_passed": not failed,
        "qualification_scale_completed": profile == "qualification" and not failed,
        "external_independence_established": False,
        "artifacts": {
            "root": artifacts_root.as_posix(),
            "files": artifact_files,
            "bytes": artifact_bytes,
            "sha256": artifact_digest,
        },
        "blockers": sorted(blockers),
        "production_authorized": False,
        "promotion_effect": "NONE",
    }
    report["result_id"] = sha256_bytes(canonical_bytes(report))
    return report


def run_lab(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise LabError(f"refusing to overwrite {args.output}")
    artifacts_root = args.output.parent / f"{args.output.stem}-artifacts"
    if artifacts_root.exists():
        raise LabError(f"refusing to reuse artifact directory {artifacts_root}")
    verify_clean_revision(args.source_revision)
    lanes = lane_specs(args.profile, args.seed)
    validate_lane_plan(lanes)
    artifacts_root.mkdir(parents=True)
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    if args.cargo_target_dir is not None:
        args.cargo_target_dir.mkdir(parents=True, exist_ok=True)
        environment["CARGO_TARGET_DIR"] = str(args.cargo_target_dir.resolve())
    versions = {
        "python": {
            "available": True,
            "detail": sys.version.replace("\n", " "),
            "executable": sys.executable,
        },
        "rustc": tool_version(("rustc", "-vV"), ROOT),
        "cargo": tool_version(("cargo", "--version"), ROOT),
        "go": tool_version(("go", "version"), ROOT / "go"),
    }
    vector_hash, vector_files, vector_bytes = tree_digest(
        ROOT / "protocol" / "vectors"
    )
    vector_tree = {
        "path": "protocol/vectors",
        "files": vector_files,
        "bytes": vector_bytes,
        "sha256": vector_hash,
    }
    started = utc_now()
    lane_results = [run_lane(lane, artifacts_root, environment) for lane in lanes]
    completed = utc_now()
    result = build_result(
        source_revision=args.source_revision,
        profile=args.profile,
        seed=args.seed,
        started_at_utc=started,
        completed_at_utc=completed,
        versions=versions,
        vector_tree=vector_tree,
        lanes=lane_results,
        artifacts_root=artifacts_root,
    )
    write_exclusive(args.output, canonical_bytes(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["control_contract_passed"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan", help="print the frozen lane plan")
    plan.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    plan.add_argument("--seed", type=lambda value: int(value, 0), default=0x4E4F4F53)
    run = subparsers.add_parser("run", help="execute the laboratory")
    run.add_argument("--source-revision", required=True)
    run.add_argument("--profile", choices=sorted(PROFILES), default="smoke")
    run.add_argument("--seed", type=lambda value: int(value, 0), default=0x4E4F4F53)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--cargo-target-dir", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            lanes = lane_specs(args.profile, args.seed)
            validate_lane_plan(lanes)
            print(
                json.dumps(
                    {
                        "schema": "noos/cross-language-lab-plan/v1",
                        "profile": args.profile.upper(),
                        "seed": args.seed,
                        "qualification_counts": qualification_counts(args.profile),
                        "lanes": [
                            {
                                "lane_id": lane.lane_id,
                                "area": lane.area,
                                "command": list(lane.command),
                                "cwd": lane.cwd,
                                "timeout_seconds": lane.timeout_seconds,
                            }
                            for lane in lanes
                        ],
                        "production_authorized": False,
                        "promotion_effect": "NONE",
                    },
                    sort_keys=True,
                )
            )
            return 0
        return run_lab(args)
    except LabError as exc:
        print(f"CROSS_LANGUAGE_LAB_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
