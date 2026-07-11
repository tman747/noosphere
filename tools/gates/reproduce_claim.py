#!/usr/bin/env python3
"""Inspect one claim's audited local state; never replay registry dispositions as evidence."""
from __future__ import annotations

import argparse
import json
from experimental_gate import ROOT

RESULTS = {"PASSED", "KILLED", "DISABLED", "EXTERNAL_BLOCKED", "LOCAL_MISSING"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True)
    parser.add_argument("--expected-result", choices=sorted(RESULTS))
    parser.add_argument("--shadow-only", action="store_true")
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    registry = json.loads((ROOT / "protocol/claims/registry.json").read_text(encoding="utf-8"))
    row = next((claim for claim in registry["claims"] if claim["claim_id"] == args.claim), None)
    if row is None:
        raise SystemExit(f"unregistered claim: {args.claim}")
    if args.rollback_check:
        raise SystemExit("generic rollback replay is prohibited; run the claim-specific rollback_command")
    local = row.get("local_implementation_state")
    evidence = row.get("local_evidence_state")
    if local != "IMPLEMENTED":
        print(f"RESULT claim={args.claim} outcome=LOCAL_MISSING local_implementation_state={local} local_evidence_state={evidence}")
        return 2
    raise SystemExit(
        "implemented claims must be reproduced with their claim-specific command; "
        "reproduce_claim.py cannot create evidence"
    )


if __name__ == "__main__":
    raise SystemExit(main())
