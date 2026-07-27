from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from tools.e2e import run_network
from tools.gates import cross_language_lab as lab
from tools.gates import two_client_devnet_campaign as campaign


REVISION = "1" * 40
MATRIX_TEXT = "matrix=AA=PASS;AB=PASS;BA=PASS;BB=PASS\n"


class TwoClientDevnetCampaignTests(unittest.TestCase):
    def signed_bundle(self, lane_id: str, root: Path) -> tuple[dict[str, object], Path]:
        raw = f"raw-{lane_id}".encode("utf-8")
        raw_path = root / f"{lane_id}.raw.log"
        raw_path.write_bytes(raw)
        document: dict[str, object] = {
            "schema_version": "noos.base-g2-evidence.v1",
            "scenario": campaign.SIMULATION_SCENARIOS[lane_id],
            "verdict": "PASS",
            "revision": {"git_head": REVISION},
            "parameters": {"clients": ["rust", "go"]},
            "observations": {
                "client_pairs": sorted(campaign.REQUIRED_PAIRS),
                "runs": [{"verdict": "PASS"}],
            },
            "raw_log": {
                "path": raw_path.as_posix(),
                "bytes": len(raw),
                "sha256": lab.sha256_bytes(raw),
            },
        }
        document["bundle_sha256"] = lab.sha256_bytes(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        path = root / f"{lane_id}.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return document, path

    def passing_results(self, root: Path) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        for lane_id in campaign.SIMULATION_SCENARIOS:
            _, path = self.signed_bundle(lane_id, root)
            results.append(
                {
                    "lane_id": lane_id,
                    "passed": True,
                    "attached_evidence": {"path": path.as_posix()},
                }
            )
        for lane_id in sorted(campaign.REQUIRED_CONTRACT_LANES):
            result: dict[str, object] = {"lane_id": lane_id, "passed": True}
            if lane_id in {"process-transition-matrix", "process-admission-matrix"}:
                log_path = root / f"{lane_id}.log"
                log_path.write_text(MATRIX_TEXT, encoding="utf-8")
                result["log"] = {"path": log_path.as_posix()}
            results.append(result)
        return results

    def test_plan_covers_all_pairing_and_failure_scenarios(self) -> None:
        smoke = campaign.campaign_specs("smoke", 7)
        qualification = campaign.campaign_specs("qualification", 7)
        campaign.validate_plan(smoke)
        campaign.validate_plan(qualification)
        self.assertEqual(len(smoke), 14)
        self.assertEqual([lane.lane_id for lane in smoke], [lane.lane_id for lane in qualification])
        by_id_smoke = {lane.lane_id: lane for lane in smoke}
        by_id_qualification = {lane.lane_id: lane for lane in qualification}
        self.assertIn("6m", by_id_smoke["simulation-base-transfer"].command)
        self.assertIn("90m", by_id_qualification["simulation-base-transfer"].command)
        self.assertIn("--max-faults", by_id_smoke["simulation-crash"].command)
        self.assertNotIn("--max-faults", by_id_qualification["simulation-crash"].command)
        self.assertIn("{artifact_root}", by_id_smoke["simulation-wan"].command)

    def test_complete_synthetic_evidence_validates_every_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            coverage = campaign.validate_campaign_evidence(
                self.passing_results(root), root, REVISION
            )
        self.assertEqual(set(coverage["required_client_pairs"]), campaign.REQUIRED_PAIRS)
        self.assertEqual(
            set(coverage["simulation_scenarios"]),
            set(campaign.SIMULATION_SCENARIOS.values()),
        )
        self.assertEqual(coverage["process_matrix"]["AB"], "PASS")

    def test_missing_pair_and_raw_log_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            results = self.passing_results(root)
            target = next(
                result for result in results if result["lane_id"] == "simulation-wan"
            )
            path = Path(target["attached_evidence"]["path"])
            document = json.loads(path.read_text(encoding="utf-8"))
            document["observations"]["client_pairs"].remove("rust->go")
            unsigned = dict(document)
            del unsigned["bundle_sha256"]
            document["bundle_sha256"] = lab.sha256_bytes(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(campaign.CampaignError, "incomplete pair matrix"):
                campaign.validate_campaign_evidence(results, root, REVISION)

        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            results = self.passing_results(root)
            target = next(
                result for result in results if result["lane_id"] == "simulation-ai-off"
            )
            document = json.loads(
                Path(target["attached_evidence"]["path"]).read_text(encoding="utf-8")
            )
            Path(document["raw_log"]["path"]).write_text("tamper", encoding="utf-8")
            with self.assertRaisesRegex(campaign.CampaignError, "raw log bytes or digest"):
                campaign.validate_campaign_evidence(results, root, REVISION)

    def test_process_matrix_and_bundle_hash_mutations_fail(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            results = self.passing_results(root)
            process = next(
                result
                for result in results
                if result["lane_id"] == "process-transition-matrix"
            )
            Path(process["log"]["path"]).write_text("AA only", encoding="utf-8")
            with self.assertRaisesRegex(campaign.CampaignError, "process matrix missing"):
                campaign.validate_campaign_evidence(results, root, REVISION)

        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            results = self.passing_results(root)
            target = next(
                result
                for result in results
                if result["lane_id"] == "simulation-base-transfer"
            )
            path = Path(target["attached_evidence"]["path"])
            document = json.loads(path.read_text(encoding="utf-8"))
            document["bundle_sha256"] = "0" * 64
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(campaign.CampaignError, "bundle hash mismatch"):
                campaign.validate_campaign_evidence(results, root, REVISION)

    def test_result_is_local_nonpromoting_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            (root / "fixture.log").write_text("ok", encoding="utf-8")
            result = campaign.build_result(
                source_revision=REVISION,
                profile="smoke",
                seed=7,
                started_at_utc="2026-07-01T00:00:00Z",
                completed_at_utc="2026-07-01T00:00:01Z",
                lanes=[{"lane_id": "fixture", "passed": True}],
                coverage={"process_matrix": {"AA": "PASS"}},
                validation_errors=[],
                artifacts_root=root,
            )
        self.assertTrue(result["control_contract_passed"])
        self.assertFalse(result["qualification_scale_completed"])
        self.assertFalse(result["independent_management_established"])
        self.assertFalse(result["public_devnet_evidence"])
        self.assertIn("QUALIFICATION_SCALE_NOT_RUN", result["blockers"])
        self.assertFalse(result["production_authorized"])
        self.assertEqual(result["promotion_effect"], "NONE")

    def test_run_network_accepts_external_raw_log_directory(self) -> None:
        parsed = run_network.parser().parse_args(
            [
                "--scenario",
                "client-matrix",
                "--pairs",
                "AA,AB,BA,BB",
                "--raw-log-dir",
                "E:/evidence/raw",
            ]
        )
        self.assertEqual(parsed.raw_log_dir, Path("E:/evidence/raw"))

    def test_shared_lane_runner_expands_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-two-client-") as directory:
            root = Path(directory)
            result = lab.run_lane(
                lab.LaneSpec(
                    "root-token",
                    "fixture",
                    (
                        "python",
                        "-c",
                        "import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve())",
                        "{artifact_root}",
                    ),
                ),
                root,
                os.environ.copy(),
            )
            self.assertTrue(result["passed"])
            self.assertIn(str(root.resolve()), (root / "logs" / "root-token.log").read_text())

    def test_plan_cli_is_machine_readable_and_nonauthorizing(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = campaign.main(["plan", "--profile", "smoke", "--seed", "7"])
        self.assertEqual(status, 0)
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["schema"], "noos/two-client-devnet-campaign-plan/v1")
        self.assertEqual(len(document["lanes"]), 14)
        self.assertFalse(document["independent_management_established"])
        self.assertFalse(document["production_authorized"])
        self.assertEqual(document["promotion_effect"], "NONE")


if __name__ == "__main__":
    unittest.main()
