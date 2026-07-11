#!/usr/bin/env python3
"""Execute claim-specific gates while blocking release on every local claim gap."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from experimental_gate import ROOT, canonical_hash, claim_fingerprint, sha256

EVIDENCE_RE = re.compile(r"^EVIDENCE (?P<path>\S+) sha256=(?P<sha>[0-9a-f]{64}) content_sha256=(?P<content>[0-9a-f]{64})$", re.M)
RESULTS = {"IMPLEMENTED", "PASSED", "KILLED", "DISABLED", "EXTERNAL_BLOCKED", "LOCAL_MISSING"}
LOCAL_STATES = {"IMPLEMENTED", "PARTIAL", "MISSING"}
EVIDENCE_STATES = {"VERIFIED", "PARTIAL", "MISSING"}
GENERIC_PROGRAMS = {"echo", "printf", "write-output"}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--registry", type=Path, required=True)
    p.add_argument("--all-actionable", action="store_true")
    p.add_argument("--include-negative-results", action="store_true")
    p.add_argument("--require-command", action="store_true")
    p.add_argument("--require-evidence", action="store_true")
    p.add_argument("--require-rollback", action="store_true")
    p.add_argument("--fail-on-missing", action="store_true")
    p.add_argument("--implemented-only", action="store_true", help="engineering-only gate; excludes release completeness")
    p.add_argument("--update-evidence-hashes", action="store_true", help="bind only freshly executed evidence")
    return p


def command_problem(command: object) -> str | None:
    if not isinstance(command, str) or not command.strip():
        return "missing claim-specific command"
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        return f"unparseable command: {exc}"
    lowered = [token.lower() for token in argv]
    if "reproduce_claim.py" in " ".join(lowered):
        return "generic disposition replay is prohibited"
    if argv and Path(argv[0]).name.lower() in GENERIC_PROGRAMS:
        return "status-echo command is prohibited"
    if any(token in {"write-host", "write-output"} for token in lowered):
        return "status-echo command is prohibited"
    return None


def run(command: str) -> subprocess.CompletedProcess[str]:
    argv = shlex.split(command, posix=True)
    if argv and argv[0].lower() in {"python", "python3"}:
        argv[0] = sys.executable
    return subprocess.run(argv, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def audit_row(row: dict) -> list[str]:
    cid = row.get("claim_id", "<missing>")
    errors: list[str] = []
    local = row.get("local_implementation_state")
    evidence = row.get("local_evidence_state")
    if local not in LOCAL_STATES:
        errors.append(f"{cid}: invalid local_implementation_state")
    if evidence not in EVIDENCE_STATES:
        errors.append(f"{cid}: invalid local_evidence_state")
    for field in ("owner_blockers", "external_blockers"):
        if not isinstance(row.get(field), list) or any(not isinstance(v, str) or not v.strip() for v in row.get(field, [])):
            errors.append(f"{cid}: {field} must be a list of non-empty strings")
    expected = row.get("expected_result")
    if expected not in RESULTS:
        errors.append(f"{cid}: invalid expected_result")
    if local != "IMPLEMENTED":
        if expected != "LOCAL_MISSING":
            errors.append(f"{cid}: local {str(local).lower()} claim must expect LOCAL_MISSING")
        if row.get("external_blockers") and expected == "EXTERNAL_BLOCKED":
            errors.append(f"{cid}: external blocker masks a local implementation gap")
        if row.get("command"):
            problem = command_problem(row["command"])
            if problem:
                errors.append(f"{cid}: {problem}")
    else:
        problem = command_problem(row.get("command"))
        if problem:
            errors.append(f"{cid}: {problem}")
        if expected == "LOCAL_MISSING":
            errors.append(f"{cid}: implemented claim cannot expect LOCAL_MISSING")
    if expected in {"KILLED", "DISABLED"}:
        reproduction = row.get("reproduction_command")
        problem = command_problem(reproduction)
        if problem:
            errors.append(f"{cid}: negative result lacks executable falsifier: {problem}")
    return errors


def validate_evidence(
    path: Path,
    row: dict,
    expected_file_sha: str,
    registry_version: str,
    require_binding: bool,
    allow_rebind: bool,
) -> list[str]:
    cid = row["claim_id"]
    errors: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{cid}: unreadable evidence {path}: {exc}"]
    actual_file_sha = sha256(path)
    if actual_file_sha != expected_file_sha:
        errors.append(f"{cid}: command-reported evidence hash mismatch")
    binding = row.get("evidence_sha256")
    if not allow_rebind:
        if require_binding and binding in {None, "PENDING"}:
            errors.append(f"{cid}: freshly executed evidence is not bound in registry")
        elif isinstance(binding, str) and binding != "PENDING" and actual_file_sha != binding:
            errors.append(f"{cid}: immutable evidence hash differs from registry")
    if doc.get("registry_schema_version") != registry_version:
        errors.append(f"{cid}: stale registry schema version")
    if cid not in doc.get("claims", []):
        errors.append(f"{cid}: evidence is unregistered for this claim")
    if doc.get("result") != row.get("expected_result") or doc.get("expected_result") != doc.get("result"):
        errors.append(f"{cid}: observed/expected evidence result mismatch")
    if doc.get("claim_fingerprints", {}).get(cid) != claim_fingerprint(row):
        errors.append(f"{cid}: stale exact-version claim fingerprint")
    content = dict(doc)
    embedded = content.pop("evidence_sha256", None)
    if embedded != canonical_hash(content):
        errors.append(f"{cid}: evidence content hash invalid")
    checks = doc.get("checks")
    if not isinstance(checks, list) or not checks or all(c.get("name") == "registered disposition" for c in checks if isinstance(c, dict)):
        errors.append(f"{cid}: evidence contains no substantive implementation/falsifier check")
    if row.get("expected_result") == "KILLED" and not any("falsifier" in str(c.get("name", "")).lower() or "regression" in str(c.get("name", "")).lower() for c in checks if isinstance(c, dict)):
        errors.append(f"{cid}: KILLED evidence did not execute a falsifier")
    for rel, digest in doc.get("source_sha256", {}).items():
        source = ROOT / rel
        if not source.is_file() or sha256(source) != digest:
            errors.append(f"{cid}: stale/missing source {rel}")
    continuity = doc.get("base_continuity", {})
    if continuity.get("ordinary_base_live") is not True or continuity.get("rollback_verified") is not True:
        errors.append(f"{cid}: ordinary base continuity/rollback not proven")
    return errors


def main() -> int:
    args = parser().parse_args()
    registry_path = args.registry if args.registry.is_absolute() else ROOT / args.registry
    doc = json.loads(registry_path.read_text(encoding="utf-8"))
    rows = doc["claims"]
    errors: list[str] = []
    if len(rows) != 136:
        errors.append(f"registry claim count changed: expected 136, got {len(rows)}")
    selected = [r for r in rows if r.get("actionable")] if args.all_actionable else list(rows)
    if not args.include_negative_results:
        selected = [r for r in selected if r.get("expected_result") != "KILLED"]
    for row in selected:
        errors.extend(audit_row(row))
    if args.implemented_only:
        selected = [r for r in selected if r.get("local_implementation_state") == "IMPLEMENTED"]
    command_cache: dict[str, subprocess.CompletedProcess[str]] = {}
    rollback_cache: dict[str, subprocess.CompletedProcess[str]] = {}
    bindings: dict[str, str] = {}
    local_missing = 0
    for row in selected:
        cid = row["claim_id"]
        if row.get("local_implementation_state") != "IMPLEMENTED":
            local_missing += 1
            print(f"RESULT claim={cid} outcome=LOCAL_MISSING local_implementation_state={row.get('local_implementation_state')} local_evidence_state={row.get('local_evidence_state')}")
            continue
        problem = command_problem(row.get("command"))
        if problem:
            continue
        command = row["command"]
        if command not in command_cache:
            command_cache[command] = run(command)
        cp = command_cache[command]
        if cp.returncode:
            errors.append(f"{cid}: command exited {cp.returncode}: {cp.stdout[-1000:]}")
            continue
        matches = list(EVIDENCE_RE.finditer(cp.stdout))
        if not matches:
            errors.append(f"{cid}: command emitted no raw immutable EVIDENCE record")
            continue
        match = matches[-1]
        evidence_path = ROOT / match.group("path")
        expected_root = (ROOT / row["evidence_root"]).resolve()
        try:
            evidence_path.resolve().relative_to(expected_root)
        except ValueError:
            errors.append(f"{cid}: evidence outside registered root")
            continue
        before_validation = len(errors)
        errors.extend(
            validate_evidence(
                evidence_path,
                row,
                match.group("sha"),
                doc["schema_version"],
                args.require_evidence,
                args.update_evidence_hashes,
            )
        )
        if len(errors) == before_validation:
            bindings[cid] = match.group("sha")
        if args.require_rollback:
            rollback = row.get("rollback_command")
            rb_problem = command_problem(rollback)
            if rb_problem:
                errors.append(f"{cid}: invalid rollback command: {rb_problem}")
            else:
                if rollback not in rollback_cache:
                    rollback_cache[rollback] = run(rollback)
                rb = rollback_cache[rollback]
                negative_ok = row["expected_result"] in {"KILLED", "DISABLED"} and f"={row['expected_result']}" in rb.stdout
                if rb.returncode or ("RESULT rollback=PASSED" not in rb.stdout and not negative_ok):
                    errors.append(f"{cid}: rollback/falsifier command failed")
        if not args.implemented_only and row.get("local_evidence_state") != "VERIFIED":
            errors.append(f"{cid}: release evidence is {str(row.get('local_evidence_state')).lower()}")
    if local_missing and not args.implemented_only:
        errors.append(f"release blocked by {local_missing} local incomplete claim(s)")
    if args.update_evidence_hashes:
        for row in rows:
            if row["claim_id"] in bindings:
                row["evidence_sha256"] = bindings[row["claim_id"]]
                row["local_evidence_state"] = "VERIFIED"
        registry_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
        print(f"UPDATED {len(bindings)} freshly executed evidence bindings")
    counts = {state.lower(): sum(1 for r in rows if r.get("local_implementation_state") == state) for state in sorted(LOCAL_STATES)}
    counts["external"] = sum(1 for r in rows if r.get("external_blockers"))
    if errors:
        print("\n".join("ERROR " + error for error in errors), file=sys.stderr)
        print(f"RESULT claim_matrix=BLOCKED claims={len(selected)} commands={len(command_cache)} audit={json.dumps(counts, sort_keys=True)}")
        return 1
    print(f"RESULT claim_matrix=PASSED claims={len(selected)} commands={len(command_cache)} audit={json.dumps(counts, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
