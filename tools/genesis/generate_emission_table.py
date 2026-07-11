#!/usr/bin/env python3
"""Canonical NOOS production emission range-table generator and verifier.

The table is exact for every height without materializing 525,600,000 rows.
Its canonical binary commitment is:

  BLAKE3-256(
    ASCII "NOOS/EMISSION/RANGE-TABLE/V1" ||
    schema_version:u32-LE || terminal_height:u64-LE || row_count:u32-LE ||
    repeated(start_height:u64-LE || end_height:u64-LE ||
             emission_micro_noos:u128-LE)
  )

Rows must be contiguous, start at height 1, and follow the integer era law in
mainnet-parameters.proposal.toml. Height 0 and heights after terminal emit 0.
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
PROPOSAL = ROOT / "protocol/genesis/mainnet-parameters.proposal.toml"
TABLE = ROOT / "protocol/genesis/emission-table-v1.csv"
DOMAIN = b"NOOS/EMISSION/RANGE-TABLE/V1"


@dataclass(frozen=True)
class RangeRow:
    start_height: int
    end_height: int
    emission_micro_noos: int

    @property
    def count(self) -> int:
        return self.end_height - self.start_height + 1


def read_proposal(path: Path = PROPOSAL) -> dict:
    return tomllib.loads(path.read_text("utf-8"))


def expected_rows(doc: dict) -> list[RangeRow]:
    p = doc["emission"]
    start = 1
    emission = int(p["initial_per_height_micro_noos"])
    rows: list[RangeRow] = []
    while start <= int(p["emission_terminal_height"]):
        end = min(start + int(p["era_length_heights"]) - 1, int(p["emission_terminal_height"]))
        rows.append(RangeRow(start, end, emission))
        emission = emission * int(p["decay_numerator"]) // int(p["decay_denominator"])
        start = end + 1
    return rows


def read_rows(path: Path = TABLE) -> list[RangeRow]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["start_height", "end_height", "emission_micro_noos"]:
            raise ValueError(f"noncanonical CSV header: {reader.fieldnames}")
        rows = [RangeRow(*(int(row[k]) for k in reader.fieldnames)) for row in reader]
    return rows


def canonical_blob(rows: list[RangeRow], terminal_height: int) -> bytes:
    if not rows or rows[0].start_height != 1 or rows[-1].end_height != terminal_height:
        raise ValueError("range table must cover exactly heights 1..terminal")
    previous = 0
    out = bytearray(DOMAIN)
    out.extend((1).to_bytes(4, "little"))
    out.extend(terminal_height.to_bytes(8, "little"))
    out.extend(len(rows).to_bytes(4, "little"))
    for row in rows:
        if row.start_height != previous + 1 or row.end_height < row.start_height:
            raise ValueError("range rows must be ordered, contiguous, and nonempty")
        if row.emission_micro_noos < 0 or row.emission_micro_noos >= 1 << 128:
            raise ValueError("emission does not fit u128")
        out.extend(row.start_height.to_bytes(8, "little"))
        out.extend(row.end_height.to_bytes(8, "little"))
        out.extend(row.emission_micro_noos.to_bytes(16, "little"))
        previous = row.end_height
    return bytes(out)


def table_root(rows: list[RangeRow], terminal_height: int) -> str:
    import blake3

    return blake3.blake3(canonical_blob(rows, terminal_height)).hexdigest()


def scheduled_total(rows: list[RangeRow]) -> int:
    return sum(row.count * row.emission_micro_noos for row in rows)


def verify(proposal: Path = PROPOSAL, table: Path = TABLE) -> tuple[str, int, int]:
    doc = read_proposal(proposal)
    actual = read_rows(table)
    expected = expected_rows(doc)
    if actual != expected:
        raise ValueError(f"table differs from integer era law: expected={expected!r} actual={actual!r}")
    terminal = int(doc["emission"]["emission_terminal_height"])
    root = table_root(actual, terminal)
    declared = doc["emission"]["emission_table_root"]
    if declared != "TO_BE_GENERATED" and root != declared:
        raise ValueError(f"emission root mismatch: declared={declared} computed={root}")
    total = scheduled_total(actual)
    if total > int(doc["emission"]["scheduled_emission_limit_micro_noos"]):
        raise ValueError("scheduled total exceeds its envelope")
    return root, total, terminal


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal", type=Path, default=PROPOSAL)
    parser.add_argument("--table", type=Path, default=TABLE)
    parser.add_argument("--print-root", action="store_true")
    args = parser.parse_args()
    root, total, terminal = verify(args.proposal, args.table)
    if args.print_root:
        print(root)
    else:
        print(f"RESULT emission_table=PASS root={root} total_micro_noos={total} terminal_height={terminal}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
