from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_web_capacity_resilience as resilience


class WebCapacityResilienceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc)
        self.authorization_private = Ed25519PrivateKey.generate()
        self.evidence_private = Ed25519PrivateKey.generate()
        self.authorization_seed = self.root / "authorization.seed"
        self.evidence_seed = self.root / "evidence.seed"
        self.authorization_seed.write_bytes(self.authorization_private.private_bytes_raw())
        self.evidence_seed.write_bytes(self.evidence_private.private_bytes_raw())
        _, self.authorization_key_id = resilience.public_identity(self.authorization_private)
        _, self.evidence_key_id = resilience.public_identity(self.evidence_private)
        self.adapter = self.root / "adapter.bin"
        self.adapter.write_bytes(b"registered resilience adapter\n")
        adapter_sha256 = resilience.sha256_file(self.adapter)
        body: dict[str, object] = {
            "plan_id": "",
            "source_revision": "a" * 40,
            "deployment_sha256": "b" * 64,
            "evidence_scope": "OWNER_CONTROLLED_NONPRODUCTION_DEVNET",
            "authorized_at_utc": "2025-12-31T00:00:00Z",
            "expires_at_utc": "2026-12-31T00:00:00Z",
            "consent_version": "consent-v1",
            "authorization_signer_key_id": self.authorization_key_id,
            "evidence_signer_key_id": self.evidence_key_id,
            "non_promoting_policy": resilience.NON_PROMOTING_POLICY,
            "drills": [
                {
                    "drill_id": drill_id,
                    "adapter_path": str(self.adapter),
                    "adapter_sha256": adapter_sha256,
                    "argv": ["--drill", drill_id],
                    "timeout_seconds": 60,
                }
                for drill_id in resilience.REQUIRED_DRILLS
            ],
        }
        body["plan_id"] = resilience.plan_id(body)
        self.plan_body = body
        self.unsigned = self.root / "unsigned.json"
        self.unsigned.write_bytes(
            resilience.canonical_json({"schema": resilience.PLAN_SCHEMA, "body": body})
        )
        self.signed_plan_path = self.root / "plan.json"
        self.signed_plan = resilience.authorize(
            self.unsigned,
            self.authorization_seed,
            self.signed_plan_path,
            now=self.now,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def observation(self, drill_id: str) -> dict[str, object]:
        stable_root = "c" * 64
        before = stable_root
        after = stable_root
        if drill_id == "queue_saturation":
            metrics: dict[str, object] = {
                "queue_limit": 16,
                "max_queue_depth": 16,
                "rejected_requests": 7,
                "lost_records": 0,
                "duplicate_records": 0,
                "drained": True,
            }
        elif drill_id == "key_rotation":
            metrics = {
                "previous_key_id": "1" * 64,
                "new_key_id": "2" * 64,
                "overlap_verified": True,
                "stale_key_rejected": True,
                "new_key_accepted": True,
                "old_key_disabled": True,
            }
        elif drill_id == "backup":
            metrics = {
                "backup_sha256": "d" * 64,
                "source_state_root": stable_root,
                "backup_state_root": stable_root,
                "consistent_snapshot": True,
            }
        elif drill_id == "restore":
            before = "0" * 64
            metrics = {
                "backup_sha256": "d" * 64,
                "source_state_root": stable_root,
                "restored_state_root": stable_root,
                "empty_destination": True,
                "stale_state_records": 0,
            }
        elif drill_id == "retention_deletion":
            after = "e" * 64
            metrics = {
                "expired_candidates": 11,
                "deleted_records": 11,
                "remaining_expired_records": 0,
                "retained_unexpired_records": 5,
                "raw_identity_fields": 0,
            }
        elif drill_id == "telemetry_outage":
            metrics = {
                "successful_core_requests": 30,
                "telemetry_deliveries_during_outage": 0,
                "telemetry_queue_limit": 32,
                "max_telemetry_queue": 32,
                "recovery_flush_complete": True,
                "raw_identity_fields": 0,
            }
        elif drill_id == "incident_recovery":
            metrics = {
                "recovery_seconds": 12.5,
                "recovery_limit_seconds": 30,
                "health_restored": True,
                "replay_equal": True,
                "manual_intervention_count": 0,
            }
        else:
            self.fail(f"unknown drill fixture: {drill_id}")
        return {
            "schema": resilience.OBSERVATION_SCHEMA,
            "drill_id": drill_id,
            "source_revision": self.plan_body["source_revision"],
            "deployment_sha256": self.plan_body["deployment_sha256"],
            "started_at_utc": "2026-01-01T00:00:00Z",
            "ended_at_utc": "2026-01-01T00:00:30Z",
            "verdict": "PASS",
            "before_data_root": before,
            "after_data_root": after,
            "automatic_recovery": True,
            "manual_repair": False,
            "non_promoting_policy": resilience.NON_PROMOTING_POLICY,
            "metrics": metrics,
        }

    def runner(self, command: object, timeout_seconds: int) -> resilience.RunnerResult:
        command_parts = list(command)  # type: ignore[arg-type]
        self.assertEqual(timeout_seconds, 60)
        self.assertEqual(command_parts[0], str(self.adapter))
        drill_id = command_parts[-1]
        return resilience.RunnerResult(
            0,
            resilience.canonical_json(self.observation(drill_id)),
            b"bounded adapter diagnostic\n",
        )

    def execute(self, output_name: str = "result.json") -> dict[str, object]:
        return resilience.execute(
            self.signed_plan,
            self.authorization_key_id,
            self.evidence_seed,
            self.root / output_name,
            runner=self.runner,
            now=self.now,
        )

    def test_signed_execution_covers_every_required_recovery_drill(self) -> None:
        result = self.execute()
        body = resilience.verify_result(
            result,
            self.signed_plan,
            self.authorization_key_id,
            self.evidence_key_id,
            now=self.now,
        )
        self.assertEqual(
            tuple(step["drill_id"] for step in body["steps"]),
            resilience.REQUIRED_DRILLS,
        )
        self.assertEqual(body["non_promoting_policy"], resilience.NON_PROMOTING_POLICY)
        self.assertEqual(body["verdict"], "PASS")
        with self.assertRaisesRegex(resilience.ResilienceError, "overwrite"):
            self.execute()

    def test_each_drill_rejects_a_plausible_false_pass(self) -> None:
        mutations = {
            "queue_saturation": lambda row: row["metrics"].update(max_queue_depth=17),
            "key_rotation": lambda row: row["metrics"].update(stale_key_rejected=False),
            "backup": lambda row: row["metrics"].update(backup_state_root="f" * 64),
            "restore": lambda row: row["metrics"].update(stale_state_records=1),
            "retention_deletion": lambda row: row["metrics"].update(remaining_expired_records=1),
            "telemetry_outage": lambda row: row["metrics"].update(telemetry_deliveries_during_outage=1),
            "incident_recovery": lambda row: row["metrics"].update(recovery_seconds=31),
        }
        drills = {row["drill_id"]: row for row in self.plan_body["drills"]}
        for drill_id, mutate in mutations.items():
            with self.subTest(drill_id=drill_id):
                observation = self.observation(drill_id)
                mutate(observation)
                with self.assertRaises(resilience.ResilienceError):
                    resilience.validate_observation(
                        observation,
                        self.plan_body,
                        drills[drill_id],
                        now=self.now,
                    )

    def test_plan_rejects_missing_drills_expiry_wrong_anchor_and_adapter_tamper(self) -> None:
        missing = copy.deepcopy(self.plan_body)
        missing["drills"].pop()
        missing["plan_id"] = resilience.plan_id(missing)
        with self.assertRaisesRegex(resilience.ResilienceError, "every required drill"):
            resilience.validate_plan_body(missing, now=self.now)

        with self.assertRaisesRegex(resilience.ResilienceError, "expected trust anchor"):
            resilience.verify_plan(self.signed_plan, "f" * 64, now=self.now)

        expired = copy.deepcopy(self.plan_body)
        expired["expires_at_utc"] = "2025-12-31T23:59:59Z"
        expired["plan_id"] = resilience.plan_id(expired)
        with self.assertRaisesRegex(resilience.ResilienceError, "expired"):
            resilience.validate_plan_body(expired, now=self.now)

        self.adapter.write_bytes(b"tampered adapter\n")
        with self.assertRaisesRegex(resilience.ResilienceError, "digest differs"):
            self.execute("tampered-result.json")

    def test_result_signature_and_backup_restore_binding_fail_closed(self) -> None:
        result = self.execute()
        tampered = copy.deepcopy(result)
        tampered["body"]["steps"][0]["observation"]["metrics"]["lost_records"] = 1
        with self.assertRaises(resilience.ResilienceError):
            resilience.verify_result(
                tampered,
                self.signed_plan,
                self.authorization_key_id,
                self.evidence_key_id,
                now=self.now,
            )

        cross_bound = copy.deepcopy(result)
        restore = cross_bound["body"]["steps"][3]["observation"]["metrics"]
        restore["backup_sha256"] = "9" * 64
        cross_bound["attestation"] = resilience.signature_record(
            self.evidence_private,
            resilience.EVIDENCE_DOMAIN,
            cross_bound["body"],
        )
        with self.assertRaisesRegex(resilience.ResilienceError, "bind"):
            resilience.verify_result(
                cross_bound,
                self.signed_plan,
                self.authorization_key_id,
                self.evidence_key_id,
                now=self.now,
            )

        with self.assertRaisesRegex(resilience.ResilienceError, "trust anchor"):
            resilience.verify_result(
                result,
                self.signed_plan,
                self.authorization_key_id,
                "8" * 64,
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
