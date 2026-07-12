#!/usr/bin/env python3
"""Merge per-agent claim updates into the registry and package bindings.

Agents never edit protocol/claims/registry.json or claim-packages.json
directly; they drop update manifests under evidence/claim-updates/ with:

    {"claims": {"<CLAIM-ID>": {
        "local_implementation_state": "IMPLEMENTED" | "PARTIAL",
        "packages": ["crate", ...],
        "command": "...",
        "rollback_command": "...",
        "evidence_root": "evidence/claim-matrix/implementation-...",
        "notes": "..."
    }}}

This tool applies them fail-closed: unknown claim ids, invalid states, and
regressions from IMPLEMENTED back to PARTIAL are rejected. It never touches
evidence hashes (run_claim_matrix.py --update-evidence-hashes owns those)
and never flips expected_result for negative (KILLED/DISABLED) claims.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "protocol/claims/registry.json"
BINDINGS = ROOT / "protocol/claims/claim-packages.json"
UPDATES = ROOT / "evidence/claim-updates"
STATES = {"IMPLEMENTED", "PARTIAL"}
NEGATIVE = {"KILLED", "DISABLED"}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=isinstance(value, dict) and path == BINDINGS) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    doc = load(REGISTRY)
    rows = {row["claim_id"]: row for row in doc["claims"]}
    bindings = load(BINDINGS)
    errors: list[str] = []
    applied: list[str] = []
    manifest_paths = sorted(UPDATES.glob("*.json"))
    batch_implemented: set[str] = set()
    for manifest_path in manifest_paths:
        try:
            manifest = load(manifest_path)
        except (OSError, json.JSONDecodeError):
            continue
        batch_implemented.update(
            cid
            for cid, update in (manifest.get("claims") or {}).items()
            if update.get("local_implementation_state") == "IMPLEMENTED"
        )

    for manifest_path in manifest_paths:
        agent = manifest_path.stem
        try:
            manifest = load(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{agent}: unreadable manifest: {exc}")
            continue
        for cid, update in (manifest.get("claims") or {}).items():
            label = f"{agent}:{cid}"
            row = rows.get(cid)
            if row is None:
                errors.append(f"{label}: unknown claim id")
                continue
            state = update.get("local_implementation_state")
            if state not in STATES:
                errors.append(f"{label}: invalid state {state!r}")
                continue
            if row.get("local_implementation_state") == "IMPLEMENTED" and state != "IMPLEMENTED":
                if cid in batch_implemented:
                    # A later manifest in this same deterministic batch owns
                    # the IMPLEMENTED upgrade. Preserve the stronger state so
                    # rerunning the merger is idempotent.
                    applied.append(label)
                    continue
                errors.append(f"{label}: cannot regress an IMPLEMENTED claim")
                continue
            if row.get("expected_result") in NEGATIVE:
                errors.append(f"{label}: negative-result claims are owned by their falsifier gates")
                continue
            packages = update.get("packages") or []
            if state == "IMPLEMENTED":
                command = update.get("command")
                rollback = update.get("rollback_command")
                if not isinstance(command, str) or not command.strip():
                    errors.append(f"{label}: IMPLEMENTED requires a command")
                    continue
                if not isinstance(rollback, str) or not rollback.strip():
                    errors.append(f"{label}: IMPLEMENTED requires a rollback_command")
                    continue
                if "run_implementation_claim.py" in command and not packages:
                    errors.append(f"{label}: generic runner requires a packages binding")
                    continue
                missing = [p for p in packages if not (ROOT / "crates" / p / "Cargo.toml").is_file()]
                if missing:
                    errors.append(f"{label}: unknown packages {missing}")
                    continue
                row["local_implementation_state"] = "IMPLEMENTED"
                row["implementation_status"] = "IMPLEMENTED"
                row["expected_result"] = "IMPLEMENTED"
                row["command"] = command
                row["rollback_command"] = rollback
                row.setdefault("evidence_sha256", "PENDING")
                evidence_root = update.get("evidence_root")
                if evidence_root is not None:
                    if not isinstance(evidence_root, str) or not evidence_root.strip():
                        errors.append(f"{label}: evidence_root must be a non-empty string")
                        continue
                    candidate = (ROOT / evidence_root).resolve()
                    allowed = (ROOT / "evidence" / "claim-matrix").resolve()
                    try:
                        relative = candidate.relative_to(allowed)
                    except ValueError:
                        errors.append(f"{label}: evidence_root must stay under evidence/claim-matrix")
                        continue
                    if not relative.parts:
                        errors.append(f"{label}: evidence_root must name a claim-specific directory")
                        continue
                    row["evidence_root"] = candidate.relative_to(ROOT).as_posix()
                elif not isinstance(row.get("evidence_root"), str) or not row["evidence_root"].strip() or row["evidence_root"] == "NOT_EXECUTABLE_LOCAL_GAP":
                    slug = cid.lower().replace(".", "-")
                    row["evidence_root"] = f"evidence/claim-matrix/implementation-{slug}"
                if packages:
                    bindings[cid] = list(packages)
            else:
                row["local_implementation_state"] = "PARTIAL"
                if row.get("implementation_status") == "NOT_STARTED":
                    row["implementation_status"] = "PARTIAL"
                row["expected_result"] = "LOCAL_MISSING"
            notes = update.get("notes")
            if isinstance(notes, str) and notes.strip():
                hashes = row.setdefault("implementation_hashes", {})
                hashes["audit"] = f"{state}: {notes.strip()} [{agent}]"
            applied.append(label)

    if errors:
        print("\n".join("ERROR " + e for e in errors), file=sys.stderr)
        print(f"RESULT apply_claim_updates=FAIL applied=0 rejected={len(errors)}")
        return 1
    if not args.dry_run:
        dump(REGISTRY, doc)
        dump(BINDINGS, bindings)
    print(f"RESULT apply_claim_updates=PASS applied={len(applied)} manifests={len(manifest_paths)}")
    for label in applied:
        print(f"APPLIED {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
