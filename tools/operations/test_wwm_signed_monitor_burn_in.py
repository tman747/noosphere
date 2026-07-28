from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_public_testnet_monitor as monitor
from tools.operations import wwm_signed_monitor_burn_in as burn_in


class SignedMonitorBurnInTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        public = monitor.public_key_bytes(self.key)
        self.signer_key_id = hashlib.sha256(public).hexdigest()
        self.source_revision = "49" * 20
        self.release_version = f"0.1.0+git.{self.source_revision}"
        self.deployment_sha256 = "81" * 32
        self.monitor_source_sha256 = "82" * 32
        self.start = datetime(2026, 7, 27, 0, 0, tzinfo=timezone.utc)

    def config(self, **overrides: object) -> burn_in.BurnInConfig:
        values: dict[str, object] = {
            "url": "https://status.example/status.json",
            "source_revision": self.source_revision,
            "release_version": self.release_version,
            "deployment_sha256": self.deployment_sha256,
            "signer_key_id": self.signer_key_id,
            "monitor_source_sha256": self.monitor_source_sha256,
            "duration_seconds": 60,
            "poll_seconds": 1,
            "maximum_sample_gap_seconds": 90,
            "maximum_observation_gap_seconds": 90,
            "expected_check_count": 2,
            "output": self.root / "burn-in-result.json",
        }
        values.update(overrides)
        return burn_in.BurnInConfig(**values)  # type: ignore[arg-type]

    def sample(
        self,
        observed: datetime,
        *,
        previous_sample_id: str | None,
        checks: list[dict[str, object]] | None = None,
        source_revision: str | None = None,
        monitor_source_sha256: str | None = None,
        status: str = "ok",
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": monitor.SAMPLE_SCHEMA,
            "environment": "public-testnet",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "source_revision": source_revision or self.source_revision,
            "release_version": self.release_version,
            "deployment_sha256": self.deployment_sha256,
            "monitor_source_sha256": (
                monitor_source_sha256 or self.monitor_source_sha256
            ),
            "status": status,
            "observed_at_utc": burn_in.format_utc(observed),
            "previous_sample_id": previous_sample_id,
            "checks": checks
            if checks is not None
            else [
                {"name": "network", "ok": True, "latency_ms": 12, "detail": {}},
                {"name": "inference", "ok": True, "latency_ms": 18, "detail": {}},
            ],
        }
        return monitor.sign_payload(payload, self.key, monitor.SAMPLE_DOMAIN, "sample_id")

    def test_continuous_samples_finalize_with_hashed_ledger(self) -> None:
        config = self.config()
        evidence = burn_in.BurnInEvidence(config, started_at_utc=self.start)
        first = self.sample(self.start, previous_sample_id=None)
        self.assertFalse(evidence.accept(first, now=self.start))
        second_time = self.start + timedelta(seconds=60)
        second = self.sample(second_time, previous_sample_id=str(first["sample_id"]))
        self.assertTrue(evidence.accept(second, now=second_time))

        result = evidence.finalize(observed_at_utc=second_time, wall_elapsed_seconds=61)

        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["sample_count"], 2)
        self.assertEqual(result["observed_span_seconds"], 60)
        self.assertEqual(result["first_sample_id"], first["sample_id"])
        self.assertEqual(result["last_sample_id"], second["sample_id"])
        self.assertEqual(
            result["release"]["monitor_source_sha256"],  # type: ignore[index]
            self.monitor_source_sha256,
        )
        self.assertTrue(result["acceptance"]["restart_recovery_supported"])  # type: ignore[index]
        self.assertTrue(config.output.exists())
        self.assertTrue(config.ledger_path.exists())
        self.assertFalse(config.checkpoint_path.exists())
        ledger = config.ledger_path.read_bytes()
        self.assertEqual(result["ledger"]["sha256"], hashlib.sha256(ledger).hexdigest())  # type: ignore[index]

    def test_restart_recovers_ledger_and_continues_hash_chain(self) -> None:
        config = self.config()
        first_evidence = burn_in.BurnInEvidence(config, started_at_utc=self.start)
        first = self.sample(self.start, previous_sample_id=None)
        first_evidence.accept(first, now=self.start)

        recovered = burn_in.BurnInEvidence(config)
        self.assertEqual(recovered.state.sample_count, 1)
        self.assertEqual(recovered.state.last_sample_id, first["sample_id"])
        second_time = self.start + timedelta(seconds=60)
        second = self.sample(second_time, previous_sample_id=str(first["sample_id"]))
        self.assertTrue(recovered.accept(second, now=second_time))
        result = recovered.finalize(observed_at_utc=second_time)
        self.assertEqual(result["sample_count"], 2)

    def test_recovery_repairs_checkpoint_lag_after_fsynced_append(self) -> None:
        config = self.config()
        first_evidence = burn_in.BurnInEvidence(config, started_at_utc=self.start)
        first = self.sample(self.start, previous_sample_id=None)
        first_evidence.accept(first, now=self.start)
        second_time = self.start + timedelta(seconds=60)
        second = self.sample(second_time, previous_sample_id=str(first["sample_id"]))
        burn_in.append_ledger(config.ledger_path, second)

        recovered = burn_in.BurnInEvidence(config)

        self.assertEqual(recovered.state.sample_count, 2)
        self.assertEqual(recovered.state.last_sample_id, second["sample_id"])
        checkpoint = json.loads(config.checkpoint_path.read_text(encoding="utf-8"))
        self.assertEqual(checkpoint["sample_count"], 2)
        self.assertEqual(checkpoint["last_sample_id"], second["sample_id"])

    def test_wrong_release_identity_and_failed_check_reject(self) -> None:
        config = self.config()
        evidence = burn_in.BurnInEvidence(config, started_at_utc=self.start)
        wrong_source = self.sample(self.start, previous_sample_id=None, source_revision="aa" * 20)
        with self.assertRaisesRegex(burn_in.BurnInError, "source_revision mismatch"):
            evidence.accept(wrong_source, now=self.start)
        wrong_monitor = self.sample(
            self.start,
            previous_sample_id=None,
            monitor_source_sha256="aa" * 32,
        )
        with self.assertRaisesRegex(
            burn_in.BurnInError, "monitor_source_sha256 mismatch"
        ):
            evidence.accept(wrong_monitor, now=self.start)

        failed = self.sample(
            self.start,
            previous_sample_id=None,
            checks=[
                {"name": "network", "ok": False, "latency_ms": 12, "detail": {}},
                {"name": "inference", "ok": True, "latency_ms": 18, "detail": {}},
            ],
        )
        with self.assertRaisesRegex(burn_in.BurnInError, "failed check"):
            evidence.accept(failed, now=self.start)

    def test_hash_chain_break_and_sample_gap_reject(self) -> None:
        config = self.config()
        evidence = burn_in.BurnInEvidence(config, started_at_utc=self.start)
        first = self.sample(self.start, previous_sample_id=None)
        evidence.accept(first, now=self.start)
        broken = self.sample(self.start + timedelta(seconds=60), previous_sample_id="00" * 32)
        with self.assertRaisesRegex(burn_in.BurnInError, "hash chain is discontinuous"):
            evidence.accept(broken, now=self.start + timedelta(seconds=60))

        gap_config = self.config(output=self.root / "gap-result.json")
        gap_evidence = burn_in.BurnInEvidence(gap_config, started_at_utc=self.start)
        gap_first = self.sample(self.start, previous_sample_id=None)
        gap_evidence.accept(gap_first, now=self.start)
        late_time = self.start + timedelta(seconds=91)
        late = self.sample(late_time, previous_sample_id=str(gap_first["sample_id"]))
        with self.assertRaisesRegex(burn_in.BurnInError, "sample gap exceeded"):
            gap_evidence.accept(late, now=late_time)

    def test_stale_observation_and_partial_evidence_reject(self) -> None:
        config = self.config()
        evidence = burn_in.BurnInEvidence(config, started_at_utc=self.start)
        stale = self.sample(self.start, previous_sample_id=None)
        with self.assertRaisesRegex(burn_in.BurnInError, "freshness exceeded"):
            evidence.accept(stale, now=self.start + timedelta(seconds=91))

        partial_config = self.config(output=self.root / "partial-result.json")
        partial_config.ledger_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(burn_in.BurnInError, "must exist together"):
            burn_in.BurnInEvidence(partial_config)

    def test_run_fails_immediately_and_seals_the_failing_sample(self) -> None:
        config = self.config()
        live_start = datetime.now(timezone.utc)
        first = self.sample(live_start, previous_sample_id=None)
        failed = self.sample(
            live_start + timedelta(seconds=1),
            previous_sample_id=str(first["sample_id"]),
            checks=[
                {"name": "artifact_range", "ok": False, "latency_ms": 30_001, "detail": {}},
                {"name": "inference", "ok": True, "latency_ms": 18, "detail": {}},
            ],
            status="degraded",
        )
        samples = iter((first, failed))
        request_count = 0

        def requester(_url: str) -> dict[str, object]:
            nonlocal request_count
            request_count += 1
            return next(samples)

        with patch.object(burn_in.time, "sleep", return_value=None):
            with self.assertRaisesRegex(
                burn_in.BurnInError, "failed check artifact_range"
            ):
                burn_in.run(config, requester=requester)

        self.assertEqual(request_count, 2)
        result = json.loads(config.output.read_text(encoding="utf-8"))
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(
            result["failure"]["reason"],  # type: ignore[index]
            "monitor sample contains failed check artifact_range",
        )
        self.assertEqual(result["sample_count"], 1)
        self.assertTrue(config.failure_sample_path.exists())
        checkpoint = json.loads(config.checkpoint_path.read_text(encoding="utf-8"))
        self.assertEqual(checkpoint["status"], "FAILED")

    def test_configuration_rejects_non_exact_release_and_insecure_url(self) -> None:
        with self.assertRaisesRegex(burn_in.BurnInError, "release identity is not exact"):
            self.config(release_version="0.1.0").validate()
        with self.assertRaisesRegex(burn_in.BurnInError, "exact HTTPS"):
            self.config(url="http://status.example/status.json").validate()


if __name__ == "__main__":
    unittest.main()
