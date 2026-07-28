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
    a schema-specific canonical payload. Legacy vectors use an even-length
    lowercase-hex "bytes" field; RISC Zero proof vectors bind every context,
    image, guest-input, journal, and execution-result field explicitly.

An empty vector directory (no *.json files) is a WARN at this stage of the
program (exit 0); pass --strict to make it a hard error once the first
frozen vectors exist.

Exit codes: 0 ok (possibly with WARN), 1 validation errors, 2 bad usage.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HEX_RE = re.compile(r"^(?:[0-9a-f]{2})*$")
KINDS = {"positive", "negative"}
RISC0_SCHEMA = "noos/jet/risc0-proof-v1"
WWM_VECTOR_FORMAT = "noos/wwm-web-capacity/v1/vectors/v1"
WWM_MANIFEST_FORMAT = "noos/wwm-web-capacity/v1/vector-manifest/v1"


def check_wwm_document(doc: dict, path: Path) -> list[str]:
    """Validate the alternate, schema-backed WWM conformance envelope."""
    errors: list[str] = []
    if doc.get("format") == WWM_MANIFEST_FORMAT:
        counts = doc.get("counts")
        if not isinstance(counts, dict) or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts.values()
        ):
            errors.append("'counts' must be an object of non-negative integers")
        references = (
            ("files.vectors.json", doc.get("files", {}).get("vectors.json") if isinstance(doc.get("files"), dict) else None, path.parent / "vectors.json"),
            ("schema", doc.get("schema"), path.parent / "../../schemas/wwm-web-capacity-v1.schema.json"),
        )
        for label, metadata, referenced_path in references:
            if not isinstance(metadata, dict):
                errors.append(f"'{label}' metadata must be an object")
                continue
            expected_bytes = metadata.get("bytes")
            expected_hash = metadata.get("sha256")
            if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 1:
                errors.append(f"'{label}.bytes' must be a positive integer")
            if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
                errors.append(f"'{label}.sha256' must be a lowercase SHA-256 digest")
            try:
                payload = referenced_path.resolve().read_bytes()
            except OSError as exc:
                errors.append(f"cannot read referenced {label}: {exc}")
                continue
            if isinstance(expected_bytes, int) and not isinstance(expected_bytes, bool) and len(payload) != expected_bytes:
                errors.append(f"'{label}.bytes' does not match referenced bytes")
            if isinstance(expected_hash, str) and hashlib.sha256(payload).hexdigest() != expected_hash:
                errors.append(f"'{label}.sha256' does not match referenced bytes")
        return errors

    positives = doc.get("positives")
    negatives = doc.get("negatives")
    if not isinstance(positives, list) or not positives:
        errors.append("'positives' must be a non-empty list")
        positives = []
    if not isinstance(negatives, list) or not negatives:
        errors.append("'negatives' must be a non-empty list")
        negatives = []
    seen: set[str] = set()
    observed_categories: set[str] = set()
    for kind, rows, verdict in (("positive", positives, "ACCEPT"), ("negative", negatives, "REJECT")):
        for index, row in enumerate(rows):
            label = f"{kind}s[{index}]"
            if not isinstance(row, dict):
                errors.append(f"{label}: case must be an object")
                continue
            case_id = row.get("id")
            if not isinstance(case_id, str) or not case_id:
                errors.append(f"{label}: missing non-empty 'id'")
            elif case_id in seen:
                errors.append(f"{label}: duplicate id {case_id!r}")
            else:
                seen.add(case_id)
            expected = row.get("expected")
            if not isinstance(expected, dict) or expected.get("verdict") != verdict:
                errors.append(f"{label}: expected.verdict must be {verdict}")
            if "instance" not in row:
                errors.append(f"{label}: missing 'instance'")
            else:
                try:
                    canonical = json.dumps(
                        row["instance"],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                    digest = hashlib.sha256(canonical).hexdigest()
                except (TypeError, ValueError) as exc:
                    errors.append(f"{label}: instance is not canonical I-JSON: {exc}")
                else:
                    if row.get("canonical_sha256") != digest:
                        errors.append(f"{label}: canonical_sha256 mismatch")
            if kind == "negative":
                category = row.get("category")
                if not isinstance(category, str) or not category:
                    errors.append(f"{label}: missing non-empty 'category'")
                else:
                    observed_categories.add(category)
    required_categories = doc.get("required_negative_categories")
    if not isinstance(required_categories, list) or any(
        not isinstance(category, str) or not category for category in required_categories
    ):
        errors.append("'required_negative_categories' must contain non-empty strings")
    elif len(required_categories) != len(set(required_categories)):
        errors.append("'required_negative_categories' must not contain duplicates")
    elif set(required_categories) != observed_categories:
        errors.append("'required_negative_categories' does not match negative cases")
    return errors


def check_hex(case: dict, field: str, label: str, errors: list[str], *, bytes_len: int | None = None) -> None:
    value = case.get(field)
    if not isinstance(value, str) or not HEX_RE.fullmatch(value):
        errors.append(f"{label}: '{field}' must be even-length lowercase hex")
    elif bytes_len is not None and len(value) != bytes_len * 2:
        errors.append(f"{label}: '{field}' must encode exactly {bytes_len} bytes")


def check_risc0_case(case: dict, label: str, errors: list[str]) -> None:
    for field in (
        "chain_id", "domain", "profile_id", "jet_id", "semantics_hash",
        "cert_digest", "rv32_image_id", "guest_input_blake3", "journal_blake3",
    ):
        check_hex(case, field, label, errors, bytes_len=32)
    for field in ("rv32_image_bytes", "guest_input", "journal"):
        check_hex(case, field, label, errors)
        if case.get(field) == "":
            errors.append(f"{label}: '{field}' must not be empty")
    leaves = case.get("leaves")
    if not isinstance(leaves, list) or not leaves or any(
        not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= (1 << 64) - 1
        for value in leaves
    ):
        errors.append(f"{label}: 'leaves' must be a non-empty array of unsigned 64-bit integers")
    leaf_count = case.get("leaf_count")
    if not isinstance(leaf_count, int) or isinstance(leaf_count, bool) or not 1 <= leaf_count <= 24:
        errors.append(f"{label}: 'leaf_count' must be an integer in 1..=24")
    elif isinstance(leaves, list) and leaf_count != len(leaves):
        errors.append(f"{label}: 'leaf_count' must match the number of leaves")
    for field in ("status", "value", "steps"):
        value = case.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            errors.append(f"{label}: '{field}' must be a non-negative integer")


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot parse: {exc}"]

    if not isinstance(doc, dict):
        return ["top level must be an object with 'schema' and 'cases'"]


    if doc.get("format") in {WWM_VECTOR_FORMAT, WWM_MANIFEST_FORMAT}:
        return check_wwm_document(doc, path)
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
        if schema == RISC0_SCHEMA:
            check_risc0_case(case, label, errors)
        else:
            raw = case.get("bytes")
            if not isinstance(raw, str):
                errors.append(f"{label}: missing 'bytes' hex string")
            elif not HEX_RE.fullmatch(raw):
                errors.append(
                    f"{label}: 'bytes' must be even-length lowercase hex"
                    f" (got {raw[:40]!r}{'...' if len(raw) > 40 else ''})"
                )
    if schema == RISC0_SCHEMA:
        if doc.get("claim_version") != 2:
            errors.append("'claim_version' must be 2")
        if doc.get("receipt_kind") not in {"composite", "succinct"}:
            errors.append("'receipt_kind' must be composite or succinct")
        words = doc.get("method_id_words")
        if not isinstance(words, list) or len(words) != 8 or any(
            not isinstance(word, int) or isinstance(word, bool) or not 0 <= word <= (1 << 32) - 1
            for word in words
        ):
            errors.append("'method_id_words' must contain exactly eight unsigned 32-bit integers")
        guest_elf = doc.get("guest_elf_blake3")
        if not isinstance(guest_elf, str) or len(guest_elf) != 64 or not re.fullmatch(r"[0-9a-f]{64}", guest_elf):
            errors.append("'guest_elf_blake3' must be a 32-byte lowercase hex digest")
        for field in ("sdk_version", "guest_build"):
            if not isinstance(doc.get(field), str) or not doc[field].strip():
                errors.append(f"missing or empty '{field}' string")
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
