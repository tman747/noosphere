#!/usr/bin/env python3
"""Re-execute and bind every locally implemented actionable claim gate.

The runner executes negative results and rollback/falsifier commands, updates
only evidence hashes/states in the canonical registry, verifies every fresh
source-bound record, and writes an immutable non-promoting summary. Locally
incomplete and external claims remain explicit blockers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Sequence

if __package__:
    from . import cross_language_lab as lab
    from . import run_claim_matrix as matrix
else:
    import cross_language_lab as lab
    import run_claim_matrix as matrix


ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "noos/claim-rebaseline-result/v1"
MATRIX_RESULT_RE = re.compile(
    r"RESULT claim_matrix=(?P<status>PASSED|BLOCKED) claims=(?P<claims>\d+) "
    r"commands=(?P<commands>\d+) audit=(?P<audit>\{[^\n]+\})"
)
UPDATED_RE = re.compile(r"UPDATED (?P<count>\d+) freshly executed evidence bindings")
NEGATIVE_RESULTS = {"KILLED", "DISABLED"}


class RebaselineError(ValueError):
    pass


def canonical_digest(entries: object) -> str:
    return lab.sha256_bytes(lab.canonical_bytes(entries))


def find_bound_evidence(row: dict[str, object]) -> Path:
    expected = row.get("evidence_sha256")
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise RebaselineError(f"{row.get('claim_id')}: evidence hash is not bound")
    root_value = row.get("evidence_root")
    if not isinstance(root_value, str):
        raise RebaselineError(f"{row.get('claim_id')}: evidence root is missing")
    root = (ROOT / root_value).resolve()
    if not root.is_relative_to(ROOT.resolve()) or not root.is_dir():
        raise RebaselineError(f"{row.get('claim_id')}: evidence root is invalid")
    matches = [
        path
        for path in root.rglob("*.json")
        if path.is_file() and lab.sha256_file(path) == expected
    ]
    if len(matches) != 1:
        raise RebaselineError(
            f"{row.get('claim_id')}: expected one bound evidence file, found {len(matches)}"
        )
    return matches[0]


def verify_fresh_registry(
    registry_path: Path,
    source_revision: str,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RebaselineError(f"cannot read updated registry: {exc}") from exc
    if not isinstance(registry, dict) or registry.get("schema_version") != "1.2.0":
        raise RebaselineError("updated registry has the wrong schema")
    rows = registry.get("claims")
    if not isinstance(rows, list) or len(rows) != 136:
        raise RebaselineError("updated registry must contain exactly 136 claims")
    if any(not isinstance(row, dict) for row in rows):
        raise RebaselineError("updated registry contains a non-object claim")
    audit_errors = [error for row in rows for error in matrix.audit_row(row)]
    if audit_errors:
        raise RebaselineError("updated registry audit failed: " + "; ".join(audit_errors))

    implemented = [
        row for row in rows if row.get("actionable") and row.get("local_implementation_state") == "IMPLEMENTED"
    ]
    if len(implemented) != 71:
        raise RebaselineError(f"implemented actionable count changed: {len(implemented)}")
    evidence_records: list[dict[str, object]] = []
    for row in implemented:
        path = find_bound_evidence(row)
        expected_sha = str(row["evidence_sha256"])
        errors = matrix.validate_evidence(
            path,
            row,
            expected_sha,
            str(registry["schema_version"]),
            True,
            False,
            source_revision,
        )
        if errors:
            raise RebaselineError("; ".join(errors))
        document = json.loads(path.read_text(encoding="utf-8"))
        binding = document.get("source_binding")
        if not isinstance(binding, dict) or binding.get("source_revision") != source_revision:
            raise RebaselineError(f"{row['claim_id']}: evidence is not from the requested revision")
        result = document.get("result")
        if result != row.get("expected_result"):
            raise RebaselineError(f"{row['claim_id']}: evidence result mismatch")
        evidence_records.append(
            {
                "claim_id": row["claim_id"],
                "result": result,
                "path": path.relative_to(ROOT).as_posix(),
                "file_sha256": expected_sha,
                "content_sha256": document.get("evidence_sha256"),
                "source_revision": source_revision,
            }
        )
    return registry, evidence_records


def build_report(
    *,
    source_revision: str,
    registry_path: Path,
    matrix_command: list[str],
    matrix_return_code: int,
    matrix_output: bytes,
    matrix_log_path: Path,
    registry: dict[str, object] | None,
    evidence_records: list[dict[str, object]],
    verification_errors: list[str],
) -> dict[str, object]:
    matrix_text = matrix_output.decode("utf-8", errors="replace")
    matrix_match = MATRIX_RESULT_RE.search(matrix_text)
    updated_match = UPDATED_RE.search(matrix_text)
    matrix_summary = None
    if matrix_match is not None:
        matrix_summary = {
            "status": matrix_match.group("status"),
            "claims": int(matrix_match.group("claims")),
            "commands": int(matrix_match.group("commands")),
            "audit": json.loads(matrix_match.group("audit")),
            "updated_bindings": int(updated_match.group("count")) if updated_match else 0,
        }
    rows = registry.get("claims", []) if isinstance(registry, dict) else []
    local_counts = Counter(
        str(row.get("local_implementation_state")) for row in rows if isinstance(row, dict)
    )
    evidence_counts = Counter(
        str(row.get("local_evidence_state")) for row in rows if isinstance(row, dict)
    )
    outcome_counts = Counter(
        str(row.get("expected_result")) for row in rows if isinstance(row, dict)
    )
    negative_records = sorted(
        (record for record in evidence_records if record["result"] in NEGATIVE_RESULTS),
        key=lambda record: str(record["claim_id"]),
    )
    unique_records = {
        str(record["file_sha256"]): {
            "path": record["path"],
            "content_sha256": record["content_sha256"],
            "source_revision": record["source_revision"],
        }
        for record in evidence_records
    }
    passed = (
        matrix_return_code == 0
        and matrix_summary is not None
        and matrix_summary["status"] == "PASSED"
        and matrix_summary["claims"] == 71
        and matrix_summary["updated_bindings"] == 71
        and len(evidence_records) == 71
        and not verification_errors
    )
    blockers = [
        "LOCAL_INCOMPLETE_CLAIMS_REMAIN",
        "EXTERNAL_AND_OWNER_PREREQUISITES_REMAIN",
        "REBASELINE_HAS_NO_PROMOTION_EFFECT",
    ]
    blockers.extend(f"VERIFICATION_ERROR:{error}" for error in verification_errors)
    report: dict[str, object] = {
        "schema": SCHEMA,
        "source_revision": source_revision,
        "registry": {
            "path": registry_path.relative_to(ROOT).as_posix(),
            "sha256": lab.sha256_file(registry_path) if registry_path.is_file() else None,
            "schema_version": registry.get("schema_version") if isinstance(registry, dict) else None,
            "claim_count": len(rows),
        },
        "matrix": {
            "command": matrix_command,
            "return_code": matrix_return_code,
            "summary": matrix_summary,
            "log": {
                "path": matrix_log_path.as_posix(),
                "bytes": len(matrix_output),
                "sha256": lab.sha256_bytes(matrix_output),
            },
        },
        "claim_counts": {
            "local_implementation": dict(sorted(local_counts.items())),
            "local_evidence": dict(sorted(evidence_counts.items())),
            "expected_result": dict(sorted(outcome_counts.items())),
        },
        "fresh_claim_records": sorted(evidence_records, key=lambda record: str(record["claim_id"])),
        "fresh_claim_count": len(evidence_records),
        "unique_evidence_file_count": len(unique_records),
        "unique_evidence_manifest_sha256": canonical_digest(unique_records),
        "negative_results_preserved": negative_records,
        "negative_result_count": len(negative_records),
        "local_incomplete_claim_ids": sorted(
            str(row["claim_id"])
            for row in rows
            if isinstance(row, dict) and row.get("local_implementation_state") != "IMPLEMENTED"
        ),
        "all_implemented_actionable_falsifiers_executed": passed,
        "control_contract_passed": passed,
        "promotion_readiness": "BLOCKED",
        "blockers": sorted(blockers),
        "production_authorized": False,
        "promotion_effect": "NONE",
    }
    report["result_id"] = canonical_digest(report)
    return report


def run_rebaseline(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise RebaselineError(f"refusing to overwrite {args.output}")
    log_path = args.output.parent / f"{args.output.stem}.matrix.log"
    if log_path.exists():
        raise RebaselineError(f"refusing to overwrite {log_path}")
    try:
        lab.verify_clean_revision(args.source_revision)
    except lab.LabError as exc:
        raise RebaselineError(str(exc)) from exc
    registry_path = args.registry if args.registry.is_absolute() else ROOT / args.registry
    command = [
        sys.executable,
        "tools/gates/run_claim_matrix.py",
        "--registry",
        registry_path.relative_to(ROOT).as_posix(),
        "--all-actionable",
        "--include-negative-results",
        "--require-command",
        "--require-evidence",
        "--require-rollback",
        "--implemented-only",
        "--update-evidence-hashes",
    ]
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    if args.cargo_target_dir is not None:
        args.cargo_target_dir.mkdir(parents=True, exist_ok=True)
        environment["CARGO_TARGET_DIR"] = str(args.cargo_target_dir.resolve())
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=args.timeout_seconds,
    )
    matrix_output = completed.stdout
    lab.write_exclusive(log_path, matrix_output)
    registry: dict[str, object] | None = None
    evidence_records: list[dict[str, object]] = []
    verification_errors: list[str] = []
    if completed.returncode == 0:
        try:
            registry, evidence_records = verify_fresh_registry(
                registry_path, args.source_revision
            )
        except RebaselineError as exc:
            verification_errors.append(str(exc))
    else:
        verification_errors.append(f"claim matrix exited {completed.returncode}")
    report = build_report(
        source_revision=args.source_revision,
        registry_path=registry_path,
        matrix_command=["python", *command[1:]],
        matrix_return_code=completed.returncode,
        matrix_output=matrix_output,
        matrix_log_path=log_path,
        registry=registry,
        evidence_records=evidence_records,
        verification_errors=verification_errors,
    )
    lab.write_exclusive(args.output, lab.canonical_bytes(report) + b"\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["control_contract_passed"] else 1


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--source-revision", required=True)
    value.add_argument("--registry", type=Path, default=Path("protocol/claims/registry.json"))
    value.add_argument("--cargo-target-dir", type=Path)
    value.add_argument("--timeout-seconds", type=int, default=7_200)
    value.add_argument("--output", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.timeout_seconds < 1:
        print("CLAIM_REBASELINE_REFUSED: timeout must be positive", file=sys.stderr)
        return 2
    try:
        return run_rebaseline(args)
    except (RebaselineError, lab.LabError, subprocess.TimeoutExpired) as exc:
        print(f"CLAIM_REBASELINE_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
