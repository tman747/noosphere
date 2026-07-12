#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

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
            {"IMPLEMENTED": 69, "PARTIAL": 67},
        )
        self.assertEqual(sum(bool(row["external_blockers"]) for row in rows), 40)
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
        self.assertEqual(
            {row["claim_id"] for row in negative},
            {"A-CLASS-GATE.v1", "E-DEMAND-WASH-01", "M-HDF", "S-HDF"},
        )
        for row in negative:
            self.assertEqual(row["command"], row["reproduction_command"])
            self.assertTrue(
                "run_negative_claim.py" in row["command"]
                or "run_tensor_hdf_claim.py" in row["command"]
            )

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

    def _evidence(self, row: dict, checks: list[dict]) -> dict:
        value = {
            "schema_version": "noos.experimental-evidence.v2",
            "registry_schema_version": self.registry["schema_version"],
            "gate": "test-gate",
            "claims": [row["claim_id"]],
            "claim_fingerprints": {row["claim_id"]: MATRIX.claim_fingerprint(row)},
            "command": ["test-zero-exit-command"],
            "result": row["expected_result"],
            "expected_result": row["expected_result"],
            "checks": checks,
            "limitations": ["TEST FIXTURE ONLY"],
            "source_binding": {},
            "base_continuity": {"ordinary_base_live": True, "rollback_verified": True},
        }
        value["evidence_sha256"] = MATRIX.canonical_hash(value)
        return value

    @staticmethod
    def _check(check_id: str, kind: str, passed: object = True, **extra: object) -> dict:
        value = {"id": check_id, "kind": kind, "passed": passed, "detail": "test detail"}
        value.update(extra)
        return value

    def test_adversarial_evidence_rejections_are_atomic_and_valid_all_pass_is_accepted(self) -> None:
        row = next(row for row in self.registry["claims"] if row["expected_result"] == "IMPLEMENTED")
        all_pass = [
            self._check("implementation-check", "implementation"),
            self._check("mandatory-falsifier", "falsifier"),
            self._check("ordinary-base-rollback", "rollback"),
        ]
        adversaries = {
            "zero-exit implemented with false": [*all_pass[:1], self._check("mandatory-falsifier", "falsifier", False), all_pass[2]],
            "omitted mandatory falsifier": [all_pass[0], all_pass[2]],
            "string true": [all_pass[0], self._check("mandatory-falsifier", "falsifier", "true"), all_pass[2]],
            "duplicate check": [all_pass[0], all_pass[1], self._check("mandatory-falsifier", "rollback")],
            "unknown check field": [all_pass[0], self._check("mandatory-falsifier", "falsifier", unexpected=True), all_pass[2]],
            "unknown check kind": [all_pass[0], self._check("mandatory-falsifier", "invented"), all_pass[2]],
        }
        with tempfile.TemporaryDirectory(prefix="noos-claim-evidence-") as temporary:
            root = Path(temporary)
            registry_path = root / "registry.json"
            original = (ROOT / "protocol/claims/registry.json").read_bytes()
            for label, checks in adversaries.items():
                with self.subTest(label=label):
                    registry_path.write_bytes(original)
                    evidence = self._evidence(row, checks)
                    evidence_path = root / "evidence.json"
                    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
                    with mock.patch.object(MATRIX, "validate_source_binding", return_value=[]):
                        errors = MATRIX.validate_evidence(
                            evidence_path,
                            row,
                            MATRIX.sha256(evidence_path),
                            self.registry["schema_version"],
                            False,
                            True,
                            subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                        )
                    self.assertTrue(errors)
                    doc = json.loads(original)
                    self.assertFalse(MATRIX.write_bindings_if_valid(registry_path, doc, {row["claim_id"]: "0" * 64}, errors))
                    self.assertEqual(registry_path.read_bytes(), original)

            valid = self._evidence(row, all_pass)
            valid_path = root / "valid.json"
            valid_path.write_text(json.dumps(valid), encoding="utf-8")
            with mock.patch.object(MATRIX, "validate_source_binding", return_value=[]):
                self.assertEqual(
                    MATRIX.validate_evidence(
                        valid_path, row, MATRIX.sha256(valid_path), self.registry["schema_version"],
                        False, True, subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    ),
                    [],
                )

    def test_source_binding_rejects_stale_and_dirty_but_ignores_unrelated_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-source-binding-") as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test Fixture"], cwd=repo, check=True)
            paths = [
                "protocol/claims/experimental-evidence-schema-v2.json",
                "protocol/claims/registry.json",
                "tools/gates/experimental_gate.py",
                "tools/gates/run_claim_matrix.py",
                "src/relevant.rs",
            ]
            for rel in paths:
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"original {rel}\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "fixture"], cwd=repo, check=True)
            revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            entries = []
            for rel in sorted(paths):
                mode, _, blob = MATRIX._tree_entry(revision, rel, repo)
                data = subprocess.check_output(["git", "show", f"{revision}:{rel}"], cwd=repo)
                entries.append({"path": rel, "git_mode": mode, "git_blob": blob, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            binding = {
                "source_revision": revision,
                "source_tree": subprocess.check_output(["git", "rev-parse", f"{revision}^{{tree}}"], cwd=repo, text=True).strip(),
                "manifest_sha256": MATRIX.canonical_hash(entries),
                "entries": entries,
            }
            unrelated = repo / "evidence/other.json"
            unrelated.parent.mkdir(parents=True)
            unrelated.write_text("mutated unrelated evidence", encoding="utf-8")
            self.assertEqual(MATRIX.validate_source_binding(binding, revision, repo), [])

            relevant = repo / "src/relevant.rs"
            relevant.write_text("dirty replacement\n", encoding="utf-8")
            self.assertTrue(any("dirty/replaced" in error for error in MATRIX.validate_source_binding(binding, revision, repo)))
            relevant.write_text("original src/relevant.rs\n", encoding="utf-8")
            relevant.write_text("new committed source\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/relevant.rs"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "replace relevant"], cwd=repo, check=True)
            trusted = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            self.assertTrue(any("stale relevant source" in error for error in MATRIX.validate_source_binding(binding, trusted, repo)))


if __name__ == "__main__":
    unittest.main()
