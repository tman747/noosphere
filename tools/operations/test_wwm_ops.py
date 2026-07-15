from __future__ import annotations

import json
import tempfile
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_ops as ops


class WwmOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = ops.load_object(ops.CATALOG)

    def request(self, operation: str) -> dict[str, object]:
        base: dict[str, object] = {
            "schema": "noos/wwm-operation/v1",
            "request_id": f"test-{operation.replace('_', '-')}-0001",
            "operation": operation,
            "environment": "devnet",
            "chain_id": "1" * 64,
            "genesis_hash": "2" * 64,
            "authorized_config_id": "3" * 64,
            "preconditions": {},
            "parameters": {},
        }
        preconditions = base["preconditions"]
        parameters = base["parameters"]
        assert isinstance(preconditions, dict)
        assert isinstance(parameters, dict)
        if operation == "backup":
            preconditions.update(finalized_coordinates_captured=True, worm_evidence_store_available=True)
            parameters["backup_destination"] = "D:/external/wwm-backup"
        elif operation == "restore":
            preconditions.update(admission_disabled=True, restore_target_empty=True, backup_manifest_verified=True)
            parameters["backup_manifest"] = "D:/external/wwm-backup/manifest.json"
        elif operation in {"publisher_blackout", "total_blackout"}:
            preconditions.update(ordinary_finality_expected=True, refund_path_ready=True)
        elif operation == "disable":
            preconditions.update(expected_state="Canary", armed_action_validated=True)
            parameters["incident_root"] = "4" * 64
        elif operation == "recovery":
            preconditions.update(
                admission_disabled=True,
                fresh_finalized_prestate=True,
                publication_days=7,
                direct_prior_live_tier="Canary",
            )
            parameters.update(target_tier="Canary", recovery_authorization_id="5" * 64)
        elif operation == "rotate":
            preconditions.update(successor_published=True, stale_key_rejection_tested=True)
            parameters.update(roles=["gateway", "executor"], activation_height=100, overlap_end_height=200)
        elif operation == "rollback":
            preconditions.update(admission_disabled=True, old_job_reads_available=True)
            parameters.update(rollback_authorization_id="6" * 64, signed_static_target="static.example")
        elif operation == "drill":
            preconditions.update(cleanup_plan_ready=True, ordinary_finality_expected=True)
            parameters["kind"] = "artifact_restore"
        return base

    def test_restore_blackout_disable_recovery_rotation_rollback_and_drill_plans(self) -> None:
        operations = [
            "backup",
            "restore",
            "publisher_blackout",
            "total_blackout",
            "disable",
            "recovery",
            "rotate",
            "rollback",
            "drill",
        ]
        for operation in operations:
            with self.subTest(operation=operation):
                request = self.request(operation)
                definition = ops.validate_request(request, self.catalog)
                plan = ops.operation_plan(request, definition)
                self.assertTrue(plan)
                self.assertEqual([row["sequence"] for row in plan], list(range(1, len(plan) + 1)))
                self.assertEqual(plan[0]["adapter_arguments"][1:3], ["--operation", operation])

    def test_restore_requires_admission_disabled_and_verified_manifest(self) -> None:
        request = self.request("restore")
        request["preconditions"]["admission_disabled"] = False  # type: ignore[index]
        with self.assertRaisesRegex(ops.OperationError, "admission_disabled"):
            ops.validate_request(request, self.catalog)

    def test_recovery_rejects_tier_jump_and_short_publication(self) -> None:
        request = self.request("recovery")
        request["parameters"]["target_tier"] = "Production"  # type: ignore[index]
        with self.assertRaisesRegex(ops.OperationError, "direct prior"):
            ops.validate_request(request, self.catalog)
        request = self.request("recovery")
        request["preconditions"]["publication_days"] = 6  # type: ignore[index]
        with self.assertRaisesRegex(ops.OperationError, "seven days"):
            ops.validate_request(request, self.catalog)

    def test_execute_is_cryptographically_blocked_without_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            request_path = Path(temp) / "request.json"
            request_path.write_bytes(ops.canonical_json(self.request("disable")))
            output = StringIO()
            with redirect_stdout(output):
                code = ops.main([str(request_path), "--execute"])
        self.assertEqual(code, 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertIn("authorization", report["error"])
        self.assertEqual(report["evidence_effect"], "NONE")

    def test_execution_receipt_is_idempotent_and_nonce_is_non_replayable(self) -> None:
        request = self.request("disable")
        authorization = {"nonce": "authority-nonce-0001"}
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            receipt, already = ops.reserve_execution(state, request, authorization)
            self.assertFalse(already)
            ops.complete_execution(receipt, request, authorization)
            same_receipt, already = ops.reserve_execution(state, request, authorization)
            self.assertTrue(already)
            self.assertEqual(same_receipt, receipt)
            replay = self.request("restore")
            with self.assertRaisesRegex(ops.OperationError, "nonce"):
                ops.reserve_execution(state, replay, authorization)


if __name__ == "__main__":
    unittest.main()
