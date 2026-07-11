#!/usr/bin/env python3
"""Verify crypto-domains-v1.csv: closed, duplicate-free, prefix-free.

Checks (CI-enforced, plan §3.3):
  1. Every row has all six columns non-empty and a unique domain_id.
  2. No two registered context strings are identical.
  3. No registered context string is a byte-prefix of another (prefix collision).
     HKDF salt strings declared in notes (salt="...") join the checked universe.
  4. Every context string starts with the frozen wire namespace ("NOOS").

Exit 0 and print RESULT domain_check=PASS row_count=N only when all checks pass.
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

DEFAULT_CSV = Path(__file__).resolve().parents[2] / "protocol" / "spec" / "crypto-domains-v1.csv"
COLUMNS = ["domain_id", "kind", "context_string", "algorithm", "consumer", "notes"]
SALT_RE = re.compile(r'salt="([^"]+)"')


def main(path: Path) -> int:
    errors: list[str] = []
    rows: list[dict[str, str]] = []

    with path.open(newline="", encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.startswith("#")]
    reader = csv.DictReader(lines)
    if reader.fieldnames != COLUMNS:
        errors.append(f"header mismatch: {reader.fieldnames!r} != {COLUMNS!r}")
    else:
        rows = list(reader)

    ids: dict[str, int] = {}
    universe: dict[str, str] = {}  # context/salt string -> origin description

    for i, row in enumerate(rows, start=1):
        for col in COLUMNS:
            if not (row.get(col) or "").strip():
                errors.append(f"row {i} ({row.get('domain_id')}): empty column {col!r}")
        did = row["domain_id"].strip()
        if did in ids:
            errors.append(f"duplicate domain_id {did!r} (rows {ids[did]} and {i})")
        ids[did] = i

        ctx = row["context_string"].strip()
        if not ctx.startswith("NOOS"):
            errors.append(f"{did}: context {ctx!r} outside NOOS namespace")
        if ctx in universe:
            errors.append(f"duplicate context string {ctx!r} ({universe[ctx]} and {did})")
        universe[ctx] = did

        for salt in SALT_RE.findall(row["notes"]):
            if salt in universe:
                errors.append(f"duplicate string {salt!r} ({universe[salt]} and {did} salt)")
            universe[salt] = f"{did} salt"

    strings = sorted(universe)
    for a, b in zip(strings, strings[1:]):
        if b.startswith(a):
            errors.append(
                f"prefix collision: {a!r} ({universe[a]}) is a prefix of {b!r} ({universe[b]})"
            )

    if errors:
        for e in errors:
            print(f"FAIL {e}", file=sys.stderr)
        print("RESULT domain_check=FAIL")
        return 1
    print(f"RESULT domain_check=PASS row_count={len(rows)} checked_strings={len(strings)}")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CSV
    sys.exit(main(target))
