from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_independence_drills as drills


class OperatorIndependenceDrillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.now = datetime(2026, 1, 1, 0, 2, tzinfo=timezone.utc)
        self.authorization_private = Ed25519PrivateKey.generate()
        self.evidence_private = Ed25519PrivateKey.generate()
        self.authorization_seed = self.root / "authorization.seed"
        self.evidence_seed = self.root / "evidence.seed"
        self.authorization_seed.write_bytes(
            self.authorization_private.private_bytes_raw()
        )
        self.evidence_seed.write_bytes(self.evidence_private.private_bytes_raw())
        _, self.authorization_key_id = drills.public_identity(
            self.authorization_private
        )
        _, self.evidence_key_id = drills.public_identity(self.evidence_private)
        self.adapter = self.root / "adapter.py"
        self.adapter.write_text("# registered drill adapter\n", encoding="utf-8")
        adapter_sha256 = drills.sha256_file(self.adapter)
        body: dict[str, object] = {
            "plan_id": "",
            "source_revision": "a" * 40,
            "deployment_sha256": "b" * 64,
            "cohort_id": "c" * 64,
            "evidence_scope": "OWNER_CONTROLLED_NONPRODUCTION_DEVNET",
            "authorized_at_utc": "2025-12-31T00:00:00Z",
            "expires_at_utc": "2026-12-31T00:00:00Z",
            "authorization_signer_key_id": self.authorization_key_id,
            "evidence_signer_key_id": self.evidence_key_id,
            "non_promoting_policy": drills.NON_PROMOTING_POLICY,
            "drills": [
                {
                    "drill_id": drill_id,
                    "adapter_path": str(self.adapter),
                    "adapter_sha256": adapter_sha256,
                    "argv": [drill_id],
                    "timeout_seconds": 30,
                }
                for drill_id in drills.REQUIRED_DRILLS
            ],
        }
        body["plan_id"] = drills.plan_id(body)
        self.plan_body = body
        self.signed_plan = self.authorize(body, "plan")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authorize(self, body: dict[str, object], stem: str) -> dict[str, object]:
        unsigned = self.root / f"{stem}-unsigned.json"
        unsigned.write_bytes(
            drills.canonical_json({"schema": drills.PLAN_SCHEMA, "body": body})
        )
        return drills.authorize(
            unsigned,
            self.authorization_seed,
            self.root / f"{stem}-signed.json",
            now=self.now,
        )

    def observation(self, drill_id: str) -> dict[str, object]:
        content_root = "d" * 64
        if drill_id == "largest_provider_loss":
            metrics: dict[str, object] = {
                "lost_provider": "provider-a",
                "lost_scope_rank": 1,
                "lost_operators": 4,
                "remaining_providers": 3,
                "base_finality_advanced": True,
                "executor_quorum_preserved": True,
                "read_quorum_preserved": True,
                "reconstruction_admitted": True,
                "repair_receipts": 4,
                "unrelated_job_failures": 0,
            }
        elif drill_id == "largest_region_loss":
            metrics = {
                "lost_region": "region-a",
                "lost_scope_rank": 1,
                "lost_operators": 5,
                "remaining_regions": 3,
                "base_finality_advanced": True,
                "executor_quorum_preserved": True,
                "read_quorum_preserved": True,
                "reconstruction_admitted": True,
                "repair_receipts": 5,
                "unrelated_job_failures": 0,
            }
        elif drill_id == "model_share_poison":
            metrics = {
                "injected_corrupt_shares": 8,
                "rejected_corrupt_shares": 8,
                "accepted_corrupt_shares": 0,
                "quarantine_activated": True,
                "repair_receipts": 8,
                "reconstructed_content_root": content_root,
                "jobs_scheduled_below_threshold": 0,
                "unrelated_job_failures": 0,
            }
        elif drill_id == "model_share_replay_withhold":
            metrics = {
                "replayed_shares": 4,
                "accepted_replays": 0,
                "stale_shares": 4,
                "accepted_stale_shares": 0,
                "withheld_positions": 3,
                "threshold_unschedulable_observed": True,
                "restored_schedulability": True,
                "repair_receipts": 7,
                "unrelated_job_failures": 0,
            }
        else:
            self.fail(f"unknown fixture drill {drill_id}")
        return {
            "schema": drills.OBSERVATION_SCHEMA,
            "drill_id": drill_id,
            "source_revision": self.plan_body["source_revision"],
            "deployment_sha256": self.plan_body["deployment_sha256"],
            "cohort_id": self.plan_body["cohort_id"],
            "started_at_utc": "2026-01-01T00:00:00Z",
            "ended_at_utc": "2026-01-01T00:01:00Z",
            "verdict": "PASS",
            "before_content_root": content_root,
            "after_content_root": content_root,
            "automatic_recovery": True,
            "manual_repair": False,
            "non_promoting_policy": drills.NON_PROMOTING_POLICY,
            "metrics": metrics,
        }

    def runner(
        self, command: object, timeout_seconds: int
    ) -> drills.RunnerResult:
        command_parts = list(command)  # type: ignore[arg-type]
        self.assertEqual(timeout_seconds, 30)
        self.assertEqual(command_parts[0], drills.sys.executable)
        self.assertEqual(command_parts[1], str(self.adapter))
        drill_id = command_parts[-1]
        return drills.RunnerResult(
            0,
            drills.canonical_json(self.observation(drill_id)),
            b"bounded diagnostic\n",
        )

    def execute(self, output: str = "result.json") -> dict[str, object]:
        return drills.execute(
            self.signed_plan,
            self.authorization_key_id,
            self.evidence_seed,
            self.root / output,
            runner=self.runner,
            now=self.now,
        )

    def test_signed_run_covers_loss_poison_replay_and_withholding(self) -> None:
        result = self.execute()
        body = drills.verify_result(
            result,
            self.signed_plan,
            self.authorization_key_id,
            self.evidence_key_id,
            now=self.now,
        )
        self.assertEqual(
            tuple(step["drill_id"] for step in body["steps"]),
            drills.REQUIRED_DRILLS,
        )
        self.assertEqual(body["verdict"], "PASS")
        self.assertEqual(body["non_promoting_policy"], drills.NON_PROMOTING_POLICY)
        with self.assertRaisesRegex(drills.IndependenceDrillError, "overwrite"):
            self.execute()

    def test_every_drill_rejects_a_plausible_false_pass(self) -> None:
        mutations = {
            "largest_provider_loss": lambda row: row["metrics"].update(
                base_finality_advanced=False
            ),
            "largest_region_loss": lambda row: row["metrics"].update(
                lost_scope_rank=2
            ),
            "model_share_poison": lambda row: row["metrics"].update(
                accepted_corrupt_shares=1
            ),
            "model_share_replay_withhold": lambda row: row["metrics"].update(
                accepted_replays=1
            ),
        }
        registered = {
            row["drill_id"]: row for row in self.plan_body["drills"]
        }
        for drill_id, mutate in mutations.items():
            with self.subTest(drill_id=drill_id):
                observation = self.observation(drill_id)
                mutate(observation)
                with self.assertRaises(drills.IndependenceDrillError):
                    drills.validate_observation(
                        observation,
                        self.plan_body,
                        registered[drill_id],
                        now=self.now,
                    )

    def test_plan_and_execution_reject_missing_drill_wrong_scope_and_tamper(self) -> None:
        missing = copy.deepcopy(self.plan_body)
        missing["drills"].pop()
        missing["plan_id"] = drills.plan_id(missing)
        with self.assertRaisesRegex(
            drills.IndependenceDrillError, "every registered"
        ):
            drills.validate_plan_body(missing, now=self.now)

        promoting = copy.deepcopy(self.plan_body)
        promoting["non_promoting_policy"]["rewards"] = True
        promoting["plan_id"] = drills.plan_id(promoting)
        with self.assertRaisesRegex(drills.IndependenceDrillError, "non-promoting"):
            drills.validate_plan_body(promoting, now=self.now)

        self.adapter.write_text("# tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(drills.IndependenceDrillError, "digest differs"):
            self.execute("tampered-result.json")

    def test_result_signature_and_trust_anchors_fail_closed(self) -> None:
        result = self.execute()
        tampered = copy.deepcopy(result)
        tampered["body"]["steps"][0]["observation"]["metrics"][
            "unrelated_job_failures"
        ] = 1
        with self.assertRaises(drills.IndependenceDrillError):
            drills.verify_result(
                tampered,
                self.signed_plan,
                self.authorization_key_id,
                self.evidence_key_id,
                now=self.now,
            )
        with self.assertRaisesRegex(drills.IndependenceDrillError, "trust anchor"):
            drills.verify_result(
                result,
                self.signed_plan,
                self.authorization_key_id,
                "9" * 64,
                now=self.now,
            )

    def test_real_python_adapter_path_runs_without_a_shell(self) -> None:
        observations = {
            drill_id: self.observation(drill_id)
            for drill_id in drills.REQUIRED_DRILLS
        }
        self.adapter.write_text(
            "import json,sys\n"
            f"OBSERVATIONS={json.dumps(observations, sort_keys=True)!r}\n"
            "print(json.dumps(json.loads(OBSERVATIONS)[sys.argv[1]],sort_keys=True,separators=(',',':')))\n",
            encoding="utf-8",
        )
        body = copy.deepcopy(self.plan_body)
        digest = drills.sha256_file(self.adapter)
        for row in body["drills"]:
            row["adapter_sha256"] = digest
        body["plan_id"] = drills.plan_id(body)
        signed = self.authorize(body, "real-adapter")
        result = drills.execute(
            signed,
            self.authorization_key_id,
            self.evidence_seed,
            self.root / "real-adapter-result.json",
            now=self.now,
        )
        verified = drills.verify_result(
            result,
            signed,
            self.authorization_key_id,
            self.evidence_key_id,
            now=self.now,
        )
        self.assertEqual(verified["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
