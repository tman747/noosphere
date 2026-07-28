from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "gates"))

import rebaseline_claims as rebaseline
import run_claim_matrix as matrix
import run_dream_chorus_claim as dream
import run_agent_commerce_claim as agent
import run_economics_claim as economics
import run_species_reaction_claim as species


class ClaimRebaselineTests(unittest.TestCase):
    def test_repaired_claim_mappings_cover_market_and_artifact(self) -> None:
        self.assertIn("A-LOOM-MARKET", economics.CLAIMS)
        self.assertEqual(economics.PACKAGES["A-LOOM-MARKET"], ("noos-work-loom",))
        self.assertIn("crates/noos-work-loom/src/tests.rs", economics.CLAIM_SOURCES["A-LOOM-MARKET"])
        self.assertNotIn("protocol/claims/registry.json", economics.COMMON_SOURCES)
        self.assertEqual(species.CLAIMS["S-ARTIFACT"]["filter"], "artifact::tests::")

    def test_negative_dream_rollbacks_emit_preserved_dispositions(self) -> None:
        for claim, expected in (("S-DREAM-LANE", "DISABLED"), ("E-DREAM-02", "KILLED")):
            stdout = io.StringIO()
            with (
                patch.object(dream, "cargo_test", return_value={"passed": True}),
                patch.object(
                    dream,
                    "base_continuity",
                    return_value={"ordinary_base_live": True, "rollback_verified": True},
                ),
                patch.object(dream, "require_disabled_controls", return_value={}),
                contextlib.redirect_stdout(stdout),
            ):
                status = dream.rollback_check(claim)
            self.assertEqual(status, 0)
            self.assertIn(f"RESULT rollback={expected}", stdout.getvalue())
            self.assertIn("base_continuity=PASSED", stdout.getvalue())

    def test_dream_projection_is_portable_and_hash_bound(self) -> None:
        sweep = dream.load_dream_sweep()
        self.assertEqual(sweep["verdict"], "KILLED")
        self.assertEqual(len(sweep["rows"]), 5)
        self.assertEqual(sweep["eligible_passes"], [])
        self.assertEqual(
            sweep["projection"]["sha256"],
            dream.DREAM_SWEEP_PROJECTION_SHA256,
        )
        with tempfile.TemporaryDirectory(prefix="noos-dream-projection-") as directory:
            tampered = Path(directory) / "sweep.json"
            tampered.write_bytes(dream.DREAM_SWEEP_PROJECTION.read_bytes() + b" ")
            with (
                patch.object(dream, "DREAM_SWEEP_PROJECTION", tampered),
                self.assertRaisesRegex(SystemExit, "projection hash changed"),
            ):
                dream.load_dream_sweep()

    def test_agent_fixtures_execute_from_repository(self) -> None:
        for fixture in agent.FIXTURES:
            directory = fixture[0]
            self.assertTrue(directory.is_relative_to(ROOT))
            result = agent.run_fixture(*fixture)
            self.assertIs(result["passed"], True)
            self.assertEqual(len(result["output_sha256"]), 64)

    def test_binding_update_keeps_external_evidence_partial(self) -> None:
        document = {
            "claims": [
                {
                    "claim_id": "implemented",
                    "expected_result": "IMPLEMENTED",
                    "evidence_sha256": "PENDING",
                    "local_evidence_state": "MISSING",
                },
                {
                    "claim_id": "external",
                    "expected_result": "EXTERNAL_BLOCKED",
                    "evidence_sha256": "PENDING",
                    "local_evidence_state": "MISSING",
                },
            ]
        }
        with tempfile.TemporaryDirectory(prefix="noos-rebaseline-") as directory:
            path = Path(directory) / "registry.json"
            self.assertTrue(
                matrix.write_bindings_if_valid(
                    path,
                    document,
                    {"implemented": "1" * 64, "external": "2" * 64},
                    [],
                )
            )
            updated = json.loads(path.read_text(encoding="utf-8"))
        by_id = {row["claim_id"]: row for row in updated["claims"]}
        self.assertEqual(by_id["implemented"]["local_evidence_state"], "VERIFIED")
        self.assertEqual(by_id["external"]["local_evidence_state"], "PARTIAL")
        self.assertEqual(by_id["external"]["evidence_sha256"], "2" * 64)

    def test_report_requires_all_seventy_one_fresh_bindings(self) -> None:
        records = [
            {
                "claim_id": f"claim-{index:02d}",
                "result": "KILLED" if index == 0 else "IMPLEMENTED",
                "path": f"evidence/{index}.json",
                "file_sha256": f"{index + 1:064x}",
                "content_sha256": f"{index + 2:064x}",
                "source_revision": "1" * 40,
            }
            for index in range(71)
        ]
        registry = {
            "schema_version": "1.2.0",
            "claims": [
                {
                    "claim_id": f"claim-{index:03d}",
                    "local_implementation_state": "IMPLEMENTED" if index < 71 else "PARTIAL",
                    "local_evidence_state": "VERIFIED" if index < 71 else "MISSING",
                    "expected_result": "IMPLEMENTED" if index < 71 else "LOCAL_MISSING",
                }
                for index in range(136)
            ],
        }
        output = (
            b"UPDATED 71 freshly executed evidence bindings\n"
            b'RESULT claim_matrix=PASSED claims=71 commands=68 audit={"external": 40, "implemented": 71, "missing": 0, "partial": 65}\n'
        )
        report = rebaseline.build_report(
            source_revision="1" * 40,
            registry_path=ROOT / "protocol/claims/registry.json",
            matrix_command=["python", "matrix"],
            matrix_return_code=0,
            matrix_output=output,
            matrix_log_path=Path("E:/evidence/matrix.log"),
            registry=registry,
            evidence_records=records,
            verification_errors=[],
        )
        self.assertTrue(report["control_contract_passed"])
        self.assertTrue(report["all_implemented_actionable_falsifiers_executed"])
        self.assertEqual(report["fresh_claim_count"], 71)
        self.assertEqual(report["negative_result_count"], 1)
        self.assertEqual(report["promotion_readiness"], "BLOCKED")
        self.assertFalse(report["production_authorized"])
        self.assertEqual(report["promotion_effect"], "NONE")

        failed = rebaseline.build_report(
            source_revision="1" * 40,
            registry_path=ROOT / "protocol/claims/registry.json",
            matrix_command=["python", "matrix"],
            matrix_return_code=1,
            matrix_output=b"RESULT claim_matrix=BLOCKED claims=71 commands=68 audit={}\n",
            matrix_log_path=Path("E:/evidence/failed.log"),
            registry=registry,
            evidence_records=records[:-1],
            verification_errors=["matrix failed"],
        )
        self.assertFalse(failed["control_contract_passed"])
        self.assertTrue(any("VERIFICATION_ERROR" in item for item in failed["blockers"]))

    def test_bound_evidence_lookup_rejects_missing_hash(self) -> None:
        with self.assertRaisesRegex(rebaseline.RebaselineError, "not bound"):
            rebaseline.find_bound_evidence(
                {
                    "claim_id": "fixture",
                    "evidence_sha256": "PENDING",
                    "evidence_root": "evidence/claim-matrix/fixture",
                }
            )


if __name__ == "__main__":
    unittest.main()
