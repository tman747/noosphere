#!/usr/bin/env python3
"""Execute claim-specific gates while blocking release on every local claim gap."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from experimental_gate import (
    PROMOTABLE_RESULTS,
    ROOT,
    canonical_hash,
    claim_fingerprint,
    sha256,
    validate_checks,
)

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
    if evidence == "VERIFIED" and expected not in PROMOTABLE_RESULTS:
        errors.append(f"{cid}: {expected} evidence cannot be VERIFIED")
    if evidence == "VERIFIED" and local != "IMPLEMENTED":
        errors.append(f"{cid}: incomplete local claim cannot have VERIFIED evidence")
    return errors


def _git(*args: str, binary: bool = False, repo: Path = ROOT) -> str | bytes:
    completed = subprocess.run(
        ["git", *args], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"git {' '.join(args)} failed: {detail}")
    return completed.stdout if binary else completed.stdout.decode("utf-8").strip()


def _tree_entry(revision: str, rel: str, repo: Path = ROOT) -> tuple[str, str, str]:
    raw = str(_git("ls-tree", revision, "--", rel, repo=repo))
    metadata, listed = raw.split("\t", 1)
    mode, object_type, blob = metadata.split(" ", 2)
    if listed != rel or object_type != "blob":
        raise ValueError(f"{rel} is not an exact Git blob")
    return mode, object_type, blob


def validate_source_binding(binding: object, trusted_revision: str, repo: Path = ROOT) -> list[str]:
    errors: list[str] = []
    if not isinstance(binding, dict) or set(binding) != {
        "source_revision", "source_tree", "manifest_sha256", "entries"
    }:
        return ["source binding has missing or unknown fields"]
    revision = binding["source_revision"]
    tree = binding["source_tree"]
    entries = binding["entries"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        return ["source revision is not a full Git commit"]
    try:
        if str(_git("rev-parse", f"{revision}^{{commit}}", repo=repo)) != revision:
            errors.append("source revision does not resolve exactly")
        if str(_git("rev-parse", f"{revision}^{{tree}}", repo=repo)) != tree:
            errors.append("source tree mismatch")
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, trusted_revision], cwd=repo, check=False
        )
        if ancestor.returncode != 0:
            errors.append("source revision is not an ancestor of trusted revision")
    except ValueError as exc:
        return [str(exc)]
    if not isinstance(entries, list) or not entries:
        return errors + ["source manifest entries must be non-empty"]
    if binding["manifest_sha256"] != canonical_hash(entries):
        errors.append("source manifest fingerprint invalid")
    seen: set[str] = set()
    required = {
        "protocol/claims/experimental-evidence-schema-v2.json",
        "tools/gates/experimental_gate.py",
        "tools/gates/run_claim_matrix.py",
    }
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"path", "git_mode", "git_blob", "bytes", "sha256"}:
            errors.append(f"source entry {index} has missing or unknown fields")
            continue
        rel = entry["path"]
        if (
            not isinstance(rel, str)
            or not rel
            or "\\" in rel
            or Path(rel).is_absolute()
            or ".." in Path(rel).parts
            or rel in seen
        ):
            errors.append(f"source entry {index} has unsafe/duplicate path")
            continue
        seen.add(rel)
        if not isinstance(entry["bytes"], int) or isinstance(entry["bytes"], bool) or entry["bytes"] < 0:
            errors.append(f"source entry {rel} has invalid byte count")
            continue
        try:
            old_mode, _, old_blob = _tree_entry(revision, rel, repo)
            trusted_mode, _, trusted_blob = _tree_entry(trusted_revision, rel, repo)
            data = bytes(_git("show", f"{revision}:{rel}", binary=True, repo=repo))
            trusted_data = bytes(_git("show", f"{trusted_revision}:{rel}", binary=True, repo=repo))
        except (ValueError, UnicodeError) as exc:
            errors.append(str(exc))
            continue
        if (entry["git_mode"], entry["git_blob"]) != (old_mode, old_blob):
            errors.append(f"source Git identity mismatch: {rel}")
        if entry["bytes"] != len(data) or entry["sha256"] != hashlib.sha256(data).hexdigest():
            errors.append(f"source size/hash mismatch: {rel}")
        if (trusted_mode, trusted_blob, trusted_data) != (old_mode, old_blob, data):
            errors.append(f"stale relevant source at trusted revision: {rel}")
        working = repo / rel
        dirty = subprocess.run(
            ["git", "diff", "--quiet", trusted_revision, "--", rel], cwd=repo, check=False
        )
        if not working.is_file() or dirty.returncode != 0:
            errors.append(f"dirty/replaced relevant source: {rel}")
    missing = sorted(required - seen)
    if missing:
        errors.append("source manifest omits evidence infrastructure: " + ", ".join(missing))
    return errors


def validate_evidence(
    path: Path,
    row: dict,
    expected_file_sha: str,
    registry_version: str,
    require_binding: bool,
    allow_rebind: bool,
    trusted_revision: str,
) -> list[str]:
    cid = row["claim_id"]
    errors: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{cid}: unreadable evidence {path}: {exc}"]
    expected_fields = {
        "schema_version", "registry_schema_version", "gate", "claims", "claim_fingerprints",
        "command", "result", "expected_result", "checks", "limitations", "source_binding",
        "base_continuity", "evidence_sha256",
    }
    if set(doc) != expected_fields or doc.get("schema_version") != "noos.experimental-evidence.v2":
        errors.append(f"{cid}: evidence record has wrong schema or unknown fields")
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
    for error in validate_checks(str(doc.get("result")), doc.get("checks")):
        errors.append(f"{cid}: {error}")
    for error in validate_source_binding(doc.get("source_binding"), trusted_revision):
        errors.append(f"{cid}: {error}")
    continuity = doc.get("base_continuity", {})
    if continuity.get("ordinary_base_live") is not True or continuity.get("rollback_verified") is not True:
        errors.append(f"{cid}: ordinary base continuity/rollback not proven")
    return errors


def write_bindings_if_valid(
    registry_path: Path,
    doc: dict,
    bindings: dict[str, str],
    errors: list[str],
) -> bool:
    if errors:
        return False
    for row in doc["claims"]:
        if row["claim_id"] in bindings:
            row["evidence_sha256"] = bindings[row["claim_id"]]
            row["local_evidence_state"] = "VERIFIED"
    registry_path.write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return True


def main() -> int:
    args = parser().parse_args()
    registry_path = args.registry if args.registry.is_absolute() else ROOT / args.registry
    doc = json.loads(registry_path.read_text(encoding="utf-8"))
    rows = doc["claims"]
    trusted_revision = str(_git("rev-parse", "HEAD^{commit}"))
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
                trusted_revision,
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
    if args.update_evidence_hashes and write_bindings_if_valid(registry_path, doc, bindings, errors):
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
