#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/gates"))
SPEC = importlib.util.spec_from_file_location("run_claim_matrix", ROOT / "tools/gates/run_claim_matrix.py")
assert SPEC and SPEC.loader
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class ClaimIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = json.loads((ROOT / "protocol/claims/registry.json").read_text(encoding="utf-8"))

    def test_full_audit_counts_and_no_disposition_replay(self) -> None:
        rows = self.registry["claims"]
        self.assertEqual(len(rows), 136)
        self.assertEqual(
            Counter(row["local_implementation_state"] for row in rows),
            {"IMPLEMENTED": 63, "PARTIAL": 73},
        )
        self.assertEqual(sum(bool(row["external_blockers"]) for row in rows), 36)
        self.assertFalse([row["claim_id"] for row in rows if isinstance(row.get("command"), str) and "reproduce_claim.py" in row["command"]])
        self.assertFalse([error for row in rows for error in MATRIX.audit_row(row)])

    def test_local_gap_cannot_be_external_blocked(self) -> None:
        row = {
            "claim_id": "X",
            "local_implementation_state": "MISSING",
            "local_evidence_state": "MISSING",
            "owner_blockers": [],
            "external_blockers": ["outside dependency"],
            "expected_result": "EXTERNAL_BLOCKED",
            "command": "python tools/gates/reproduce_claim.py --claim X",
        }
        errors = MATRIX.audit_row(row)
        self.assertTrue(any("must expect LOCAL_MISSING" in error for error in errors))
        self.assertTrue(any("generic disposition replay" in error for error in errors))

    def test_status_echo_commands_are_rejected(self) -> None:
        self.assertIn("status-echo", MATRIX.command_problem("echo PASSED"))
        self.assertIn("generic disposition replay", MATRIX.command_problem("python tools/gates/reproduce_claim.py --claim A-GROUND"))
        self.assertIsNone(MATRIX.command_problem("cargo test -p noos-ground"))

    def test_negative_results_bind_real_falsifiers(self) -> None:
        negative = [row for row in self.registry["claims"] if row["expected_result"] in {"KILLED", "DISABLED"}]
        self.assertEqual({row["claim_id"] for row in negative}, {"A-CLASS-GATE.v1", "E-DEMAND-WASH-01"})
        for row in negative:
            self.assertEqual(row["command"], row["reproduction_command"])
            self.assertIn("run_negative_claim.py", row["command"])

    def test_reproducer_reports_local_incomplete_without_evidence(self) -> None:
        missing = next(row for row in self.registry["claims"] if row["local_implementation_state"] == "PARTIAL")
        completed = subprocess.run(
            [sys.executable, "tools/gates/reproduce_claim.py", "--claim", missing["claim_id"]],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("outcome=LOCAL_MISSING", completed.stdout)
        self.assertNotIn("EVIDENCE ", completed.stdout)


if __name__ == "__main__":
    unittest.main()
