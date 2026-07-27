from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from tools.operations import wwm_inference_metrics as metrics


def hex32(index: int) -> str:
    return index.to_bytes(32, "big").hex()


class InferenceMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "inference.sqlite3"
        self.base_input = self.root / "base-impact.json"
        self.seed = self.root / "signing-seed.hex"
        self.source_revision = "a" * 40
        self.deployment_sha256 = "b" * 64
        self.seed.write_text("17" * 32 + "\n", encoding="ascii")
        self._create_database()
        self._write_base_input()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def receipt(
        job_id: str,
        status: str,
        completed_at_ms: int,
        *,
        duration_ms: int | None = None,
        settlement_state: str,
        settled_at_ms: int | None = None,
    ) -> str:
        value = {
            "schema": "noos/wwm-receipt/v2",
            "job_id": job_id,
            "terminal_status": status,
            "completed_at_ms": completed_at_ms,
            "settlement_state": settlement_state,
        }
        if duration_ms is not None:
            value["duration_ms"] = duration_ms
        if settled_at_ms is not None:
            value["settled_at_ms"] = settled_at_ms
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _create_database(self) -> None:
        with sqlite3.connect(self.database) as db:
            db.executescript(
                """
                CREATE TABLE inference_jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    receipt_json TEXT,
                    created_ms INTEGER NOT NULL,
                    started_ms INTEGER,
                    deadline_at_ms INTEGER NOT NULL,
                    queue_depth_at_submit INTEGER NOT NULL
                );
                CREATE TABLE inference_events (
                    job_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE inference_settlements (
                    job_id TEXT PRIMARY KEY,
                    request_json TEXT NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    result_json TEXT
                );
                """
            )
            rows = [
                (
                    hex32(1),
                    "COMPLETED",
                    self.receipt(
                        hex32(1),
                        "COMPLETED",
                        1_100,
                        duration_ms=80,
                        settlement_state="FINALIZED_PAID",
                        settled_at_ms=1_200,
                    ),
                    1_000,
                    1_010,
                    2_000,
                    1,
                ),
                (
                    hex32(2),
                    "CANCELLED",
                    self.receipt(
                        hex32(2),
                        "CANCELLED",
                        2_050,
                        settlement_state="FINALIZED_REFUNDED",
                        settled_at_ms=2_100,
                    ),
                    2_000,
                    None,
                    3_000,
                    2,
                ),
                (
                    hex32(3),
                    "FAILED",
                    self.receipt(
                        hex32(3),
                        "FAILED",
                        3_300,
                        settlement_state="FINALIZED_REFUNDED",
                        settled_at_ms=3_400,
                    ),
                    3_000,
                    3_010,
                    4_000,
                    2,
                ),
                (
                    hex32(4),
                    "FAILED",
                    self.receipt(
                        hex32(4),
                        "FAILED",
                        4_100,
                        settlement_state="PENDING_CHAIN",
                    ),
                    4_000,
                    4_020,
                    5_000,
                    1,
                ),
                (hex32(5), "RUNNING", None, 5_000, 5_030, 6_000, 0),
            ]
            db.executemany(
                """
                INSERT INTO inference_jobs(
                    job_id,status,receipt_json,created_ms,started_ms,deadline_at_ms,
                    queue_depth_at_submit
                ) VALUES(?,?,?,?,?,?,?)
                """,
                rows,
            )
            for job_id, *_ in rows:
                db.execute(
                    "INSERT INTO inference_events(job_id,payload_json) VALUES(?,?)",
                    (job_id, "enc:v1:ciphertext"),
                )
            for job_id, status, *_ in rows[:4]:
                db.execute(
                    "INSERT INTO inference_settlements(job_id,request_json,checkpoint_json,result_json) VALUES(?,?,?,?)",
                    (
                        job_id,
                        '{"request":"sealed"}',
                        '{"phase":"done"}',
                        None if status == "FAILED" and job_id == hex32(4) else '{"proof":"sealed"}',
                    ),
                )

    def _write_base_input(self) -> None:
        self.base_input.write_text(
            json.dumps(
                {
                    "schema": metrics.BASE_IMPACT_SCHEMA,
                    "source_revision": self.source_revision,
                    "deployment_sha256": self.deployment_sha256,
                    "baseline": {
                        "start_height": 100,
                        "end_height": 110,
                        "finality_latency_us": list(range(100, 110)),
                    },
                    "stressed": {
                        "start_height": 110,
                        "end_height": 120,
                        "finality_latency_us": list(range(105, 115)),
                    },
                    "production": False,
                    "promotion_effect": "NONE",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

    def collect(self) -> dict:
        return metrics.collect_report(
            database=self.database,
            base_input_path=self.base_input,
            source_revision=self.source_revision,
            deployment_sha256=self.deployment_sha256,
            window_start_ms=0,
            window_end_ms=10_000,
            declared_concurrency=4,
            failure_modes=[
                "success",
                "cancellation",
                "timeout",
                "gateway_restart",
                "worker_restart",
                "invalid_proof",
            ],
        )

    def test_collects_exact_distributions_refunds_queue_and_evidence_bytes(self) -> None:
        body = self.collect()
        self.assertEqual(body["jobs"]["admitted"], 5)
        self.assertEqual(body["jobs"]["terminal"], 4)
        self.assertEqual(body["jobs"]["terminal_rate_basis_points"], 8_000)
        self.assertEqual(body["jobs"]["success_rate_basis_points"], 2_000)
        self.assertEqual(body["jobs"]["finalized_refunds"], 2)
        self.assertEqual(body["jobs"]["pending_refunds"], 1)
        self.assertEqual(body["jobs"]["maximum_observed_queue_depth"], 2)
        self.assertEqual(body["jobs"]["legacy_queue_depth_unknown"], 1)
        self.assertEqual(body["latency_ms"]["end_to_end"]["raw_samples"], [50, 100, 100, 300])
        self.assertEqual(body["latency_ms"]["end_to_end"]["p95"], 300)
        self.assertEqual(body["latency_ms"]["execution"]["raw_samples"], [80])
        self.assertEqual(body["latency_ms"]["queue"]["raw_samples"], [10, 10, 20, 30])
        self.assertEqual(body["latency_ms"]["settlement"]["raw_samples"], [50, 100, 100])
        self.assertGreater(body["evidence_bytes"]["total"], 0)
        self.assertEqual(body["base_finality"]["p95_difference_us"], 5)
        self.assertEqual(body["base_finality"]["p95_degradation_basis_points"], 458)
        self.assertNotIn("prompt", metrics.canonical_json(body).decode("utf-8"))

    def test_signed_report_rejects_tampering_and_forged_percentiles(self) -> None:
        envelope = metrics.sign_report(self.collect(), bytes.fromhex("17" * 32))
        validated = metrics.validate_envelope(envelope)
        self.assertEqual(validated["jobs"]["admitted"], 5)

        tampered = copy.deepcopy(envelope)
        tampered["body"]["jobs"]["terminal"] = 3
        with self.assertRaises(metrics.MetricsError):
            metrics.validate_envelope(tampered)

        forged = copy.deepcopy(envelope)
        forged["body"]["latency_ms"]["end_to_end"]["p95"] = 1
        with self.assertRaisesRegex(metrics.MetricsError, "raw samples"):
            metrics.validate_envelope(forged)

    def test_base_input_and_database_fail_closed(self) -> None:
        malformed = json.loads(self.base_input.read_text(encoding="utf-8"))
        malformed["stressed"]["start_height"] = 109
        self.base_input.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaisesRegex(metrics.MetricsError, "overlaps"):
            self.collect()

        self._write_base_input()
        with sqlite3.connect(self.database) as db:
            db.execute("UPDATE inference_jobs SET deadline_at_ms=created_ms WHERE job_id=?", (hex32(1),))
        db.close()
        with self.assertRaisesRegex(metrics.MetricsError, "deadline_at_ms"):
            self.collect()

    def test_cli_creates_immutable_report_and_verifies_it(self) -> None:
        output = self.root / "metrics.json"
        arguments = [
            "collect",
            "--database",
            str(self.database),
            "--base-input",
            str(self.base_input),
            "--source-revision",
            self.source_revision,
            "--deployment-sha256",
            self.deployment_sha256,
            "--window-start-ms",
            "0",
            "--window-end-ms",
            "10000",
            "--declared-concurrency",
            "4",
            "--failure-mode",
            "success",
            "--failure-mode",
            "timeout",
            "--signing-seed",
            str(self.seed),
            "--output",
            str(output),
        ]
        self.assertEqual(metrics.main(arguments), 0)
        self.assertTrue(output.is_file())
        self.assertEqual(metrics.main(["verify", "--input", str(output)]), 0)
        self.assertEqual(metrics.main(arguments), 1)


if __name__ == "__main__":
    unittest.main()
