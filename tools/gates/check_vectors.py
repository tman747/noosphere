#!/usr/bin/env python3
"""check_vectors.py — canonical conformance-vector gate.

Usage:
    python tools/gates/check_vectors.py protocol/vectors [--strict]

Walks the vector directory recursively. Every *.json file must:
  * parse as JSON
  * be an object declaring {"schema": <non-empty string>, "cases": [...]}
  * contain at least one case
  * give each case a unique (per-file) non-empty "name",
    a "kind" in {"positive", "negative"}, and
    a "bytes" field of even-length lowercase hex ("" allowed: empty payload)

An empty vector directory (no *.json files) is a WARN at this stage of the
program (exit 0); pass --strict to make it a hard error once the first
frozen vectors exist.

Exit codes: 0 ok (possibly with WARN), 1 validation errors, 2 bad usage.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HEX_RE = re.compile(r"^(?:[0-9a-f]{2})*$")
KINDS = {"positive", "negative"}


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse: {exc}"]

    if not isinstance(doc, dict):
        return ["top level must be an object with 'schema' and 'cases'"]

    schema = doc.get("schema")
    if not isinstance(schema, str) or not schema.strip():
        errors.append("missing or empty 'schema' string")

    cases = doc.get("cases")
    if not isinstance(cases, list):
        errors.append("'cases' must be a list")
        return errors
    if not cases:
        errors.append("'cases' is empty; a vector file must carry cases")

    seen: dict[str, int] = {}
    for idx, case in enumerate(cases):
        label = f"cases[{idx}]"
        if not isinstance(case, dict):
            errors.append(f"{label}: case must be an object")
            continue
        name = case.get("name")
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label}: missing or empty 'name'")
        else:
            label = f"cases[{idx}] ({name})"
            if name in seen:
                errors.append(
                    f"{label}: duplicate case name (first at cases[{seen[name]}])"
                )
            else:
                seen[name] = idx
        kind = case.get("kind")
        if kind not in KINDS:
            errors.append(f"{label}: 'kind' must be one of {sorted(KINDS)}, got {kind!r}")
        raw = case.get("bytes")
        if not isinstance(raw, str):
            errors.append(f"{label}: missing 'bytes' hex string")
        elif not HEX_RE.fullmatch(raw):
            errors.append(
                f"{label}: 'bytes' must be even-length lowercase hex"
                f" (got {raw[:40]!r}{'...' if len(raw) > 40 else ''})"
            )
    return errors


def main(argv) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    strict = "--strict" in argv[1:]
    if len(args) != 1:
        print("usage: check_vectors.py <vectors-dir> [--strict]", file=sys.stderr)
        return 2
    root = Path(args[0])
    if not root.is_dir():
        print(f"ERROR: vector directory not found: {root}", file=sys.stderr)
        return 1 if strict else 2

    files = sorted(root.rglob("*.json"))
    if not files:
        if strict:
            print(f"FAIL: {root}: no vector files (--strict)", file=sys.stderr)
            return 1
        print(f"WARN: {root}: no vector files yet (acceptable pre-freeze)")
        return 0

    total_errors = 0
    total_cases = 0
    for path in files:
        errors = check_file(path)
        rel = path.relative_to(root)
        if errors:
            total_errors += len(errors)
            print(f"FAIL: {rel}: {len(errors)} error(s)", file=sys.stderr)
            for msg in errors:
                print(f"  - {msg}", file=sys.stderr)
        else:
            try:
                n = len(json.loads(path.read_text(encoding="utf-8"))["cases"])
            except Exception:  # unreachable after check_file passed
                n = 0
            total_cases += n
            print(f"OK: {rel}: {n} case(s)")

    if total_errors:
        print(f"FAIL: {total_errors} error(s) across {len(files)} file(s)", file=sys.stderr)
        return 1
    print(f"OK: {len(files)} vector file(s), {total_cases} case(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
