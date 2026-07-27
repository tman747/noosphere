from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from tools.gates import cross_language_lab as lab


class CrossLanguageLabTests(unittest.TestCase):
    def test_lane_plan_covers_every_required_area_and_profile_scale(self) -> None:
        smoke = lab.lane_specs("smoke", 7)
        qualification = lab.lane_specs("qualification", 7)
        lab.validate_lane_plan(smoke)
        lab.validate_lane_plan(qualification)
        self.assertEqual(len(smoke), 11)
        self.assertEqual(
            [lane.lane_id for lane in smoke], [lane.lane_id for lane in qualification]
        )
        self.assertEqual(lab.qualification_counts("smoke")["transition"], 512)
        self.assertEqual(
            lab.qualification_counts("qualification")["transition"], 100_000
        )
        self.assertNotEqual(smoke[4].command, qualification[4].command)

    def test_duplicate_lane_and_unknown_profile_fail_closed(self) -> None:
        lane = lab.LaneSpec("duplicate", "frozen_vectors", ("python", "--version"))
        with self.assertRaisesRegex(lab.LabError, "identifiers"):
            lab.validate_lane_plan((lane, lane))
        with self.assertRaisesRegex(lab.LabError, "unknown profile"):
            lab.qualification_counts("other")

    def test_run_lane_captures_log_and_required_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-cross-lab-") as directory:
            root = Path(directory)
            lane = lab.LaneSpec(
                "fixture",
                "fixture",
                (
                    "python",
                    "-c",
                    "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('{}\\n'); print('PASS')",
                    "{artifact}",
                ),
                artifact=True,
            )
            result = lab.run_lane(lane, root, os.environ.copy())
            self.assertTrue(result["passed"])
            self.assertEqual(result["return_code"], 0)
            self.assertIsNotNone(result["attached_evidence"])
            self.assertEqual((root / "logs" / "fixture.log").read_text().strip(), "PASS")

    def test_run_lane_records_nonzero_and_timeout_without_laundering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-cross-lab-") as directory:
            failed = lab.run_lane(
                lab.LaneSpec(
                    "failed", "fixture", ("python", "-c", "raise SystemExit(3)")
                ),
                Path(directory),
                os.environ.copy(),
            )
            self.assertFalse(failed["passed"])
            self.assertEqual(failed["return_code"], 3)

        with tempfile.TemporaryDirectory(prefix="noos-cross-lab-") as directory:
            timeout = subprocess.TimeoutExpired(["fixture"], 1, output=b"partial")
            with patch.object(lab.subprocess, "run", side_effect=timeout):
                timed_out = lab.run_lane(
                    lab.LaneSpec("timeout", "fixture", ("fixture",), timeout_seconds=1),
                    Path(directory),
                    os.environ.copy(),
                )
            self.assertFalse(timed_out["passed"])
            self.assertTrue(timed_out["timed_out"])
            self.assertEqual((Path(directory) / "logs" / "timeout.log").read_bytes(), b"partial")

    def test_result_never_promotes_and_preserves_scale_and_failure_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-cross-lab-") as directory:
            root = Path(directory)
            (root / "log.txt").write_text("fixture", encoding="utf-8")
            result = lab.build_result(
                source_revision="1" * 40,
                profile="smoke",
                seed=7,
                started_at_utc="2026-07-01T00:00:00Z",
                completed_at_utc="2026-07-01T00:00:01Z",
                versions={},
                vector_tree={"sha256": "2" * 64},
                lanes=[{"lane_id": "ok", "passed": True}, {"lane_id": "bad", "passed": False}],
                artifacts_root=root,
            )
        self.assertFalse(result["control_contract_passed"])
        self.assertFalse(result["qualification_scale_completed"])
        self.assertFalse(result["external_independence_established"])
        self.assertIn("LANE_FAILED:bad", result["blockers"])
        self.assertIn("QUALIFICATION_SCALE_NOT_RUN", result["blockers"])
        self.assertFalse(result["production_authorized"])
        self.assertEqual(result["promotion_effect"], "NONE")
        self.assertRegex(result["result_id"], r"^[0-9a-f]{64}$")

    def test_bad_revision_refuses_before_git_access(self) -> None:
        with patch.object(lab, "git_output") as git_output:
            with self.assertRaisesRegex(lab.LabError, "forty lowercase"):
                lab.verify_clean_revision("not-a-revision")
        git_output.assert_not_called()

    def test_exclusive_write_and_existing_run_output_refuse(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-cross-lab-") as directory:
            output = Path(directory) / "result.json"
            lab.write_exclusive(output, b"one")
            with self.assertRaisesRegex(lab.LabError, "overwrite"):
                lab.write_exclusive(output, b"two")
            args = Namespace(
                output=output,
                source_revision="1" * 40,
                profile="smoke",
                seed=7,
                cargo_target_dir=None,
            )
            with self.assertRaisesRegex(lab.LabError, "overwrite"):
                lab.run_lab(args)

    def test_plan_cli_is_machine_readable_and_nonauthorizing(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = lab.main(["plan", "--profile", "smoke", "--seed", "7"])
        self.assertEqual(status, 0)
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["schema"], "noos/cross-language-lab-plan/v1")
        self.assertEqual(document["profile"], "SMOKE")
        self.assertEqual(len(document["lanes"]), 11)
        self.assertFalse(document["production_authorized"])
        self.assertEqual(document["promotion_effect"], "NONE")


if __name__ == "__main__":
    unittest.main()
