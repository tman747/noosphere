from __future__ import annotations

import argparse
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tools.operations import wwm_public_testnet_monitor as monitor


class PublicTestnetMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private_key = self.root / "secrets" / "monitor.seed"
        self.public_key = self.root / "evidence" / "monitor-public-key.json"
        self.key_document = monitor.generate_key(self.private_key, self.public_key)
        self.deployment = self.root / "public-testnet.json"
        self.r2_report = self.root / "r2-report.json"
        self.deployment_document = {
            "schema": "noos/wwm-public-testnet/v1",
            "environment": "public-testnet",
            "production": False,
            "production_capable": False,
            "promotion_effect": "NONE",
            "chain_binding": {"chain_id": "11" * 32, "genesis_hash": "22" * 32},
            "model_binding": {"artifact_id": "33" * 32, "manifest_root": "44" * 32},
            "public_endpoints": {
                "site": "https://wwm.example",
                "read_gateway": "https://rpc.example",
                "status": "https://status.example",
                "artifacts": "https://artifacts.example",
            },
        }
        self.deployment.write_text(json.dumps(self.deployment_document), encoding="utf-8")
        self.r2_report.write_text(
            json.dumps(
                {
                    "schema": "noos/wwm-r2-static-bundle-sync/v1",
                    "verdict": "PASS",
                    "bucket": monitor.EXPECTED_R2_BUCKET,
                    "production": False,
                    "production_custody": False,
                }
            ),
            encoding="utf-8",
        )

    def arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            listen="127.0.0.1:29901",
            deployment=self.deployment,
            evidence_dir=self.root / "evidence",
            signing_key=self.private_key,
            r2_report=self.r2_report,
            source_revision="55" * 20,
            interval_seconds=60,
            request_timeout_seconds=5.0,
            seed_hostname="seed.example",
            seed_ip="203.0.113.9",
            seed2_hostname="seed-2.example",
            seed2_ip="203.0.113.10",
            seed_rpc_port=29652,
        )

    def test_key_generation_is_insert_once_and_public_only(self) -> None:
        self.assertEqual(self.key_document["environment"], "public-testnet")
        self.assertFalse(self.key_document["production"])
        self.assertEqual(len(self.private_key.read_bytes()), 32)
        public = json.loads(self.public_key.read_bytes())
        self.assertEqual(public["key_id"], self.key_document["key_id"])
        self.assertNotIn(self.private_key.read_bytes().hex(), self.public_key.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(monitor.MonitorError, "insert-once"):
            monitor.generate_key(self.private_key, self.public_key)

    def test_config_requires_fail_closed_exact_bindings(self) -> None:
        config = monitor.load_config(self.arguments())
        self.assertEqual(config.chain_id, "11" * 32)
        self.assertEqual(config.artifact_origin, "https://artifacts.example")

        self.deployment_document["production"] = True
        self.deployment.write_text(json.dumps(self.deployment_document), encoding="utf-8")
        with self.assertRaisesRegex(monitor.MonitorError, "fail-closed public testnet"):
            monitor.load_config(self.arguments())

    def test_sample_ledger_is_signed_chained_and_summarized_immutably(self) -> None:
        key = monitor.load_signing_key(self.private_key)
        store = monitor.EvidenceStore(self.root / "ledger", key, "55" * 20, "66" * 32)
        checks = [monitor.CheckResult("gateway", True, 12, {"status": 200})]
        first = store.append(checks, "2026-07-15T00:00:00Z")
        second = store.append(checks, "2026-07-15T00:01:00Z")
        monitor.verify_envelope(first, monitor.SAMPLE_DOMAIN, "sample_id")
        monitor.verify_envelope(second, monitor.SAMPLE_DOMAIN, "sample_id")
        self.assertEqual(second["previous_sample_id"], first["sample_id"])

        summary = store.summarize("2026-07-15")
        monitor.verify_envelope(summary, monitor.SUMMARY_DOMAIN, "summary_id")
        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(summary["passing_samples"], 2)
        self.assertFalse(summary["formal_e_wwm_23_evidence"])
        self.assertEqual(store.summarize("2026-07-15"), summary)

        tampered = dict(second)
        tampered["status"] = "degraded"
        with self.assertRaisesRegex(monitor.MonitorError, "identity is invalid"):
            monitor.verify_envelope(tampered, monitor.SAMPLE_DOMAIN, "sample_id")

    def test_status_server_exposes_fail_closed_metrics_and_signed_sample(self) -> None:
        config = monitor.load_config(self.arguments())
        state = monitor.MonitorState(config)
        key = monitor.load_signing_key(self.private_key)
        payload = {
            "schema": monitor.SAMPLE_SCHEMA,
            "environment": "public-testnet",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "source_revision": config.source_revision,
            "deployment_sha256": "66" * 32,
            "observed_at_utc": "2026-07-15T00:00:00Z",
            "previous_sample_id": None,
            "status": "ok",
            "checks": [monitor.CheckResult("gateway", True, 2, {"status": 200}).document()],
        }
        with state.lock:
            state.latest = monitor.sign_payload(payload, key, monitor.SAMPLE_DOMAIN, "sample_id")
        server = monitor.MonitorServer(state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 5)
        base = f"http://127.0.0.1:{server.server_port}"

        with urllib.request.urlopen(base + "/status.json", timeout=5) as response:
            status = json.loads(response.read())
            self.assertEqual(response.status, 200)
            self.assertEqual(status["status"], "ok")
            self.assertFalse(status["production_authorized"])
        with urllib.request.urlopen(base + "/metrics", timeout=5) as response:
            metrics = response.read().decode("ascii")
            self.assertIn("mindchain_wwm_public_testnet_up 1", metrics)
            self.assertIn("mindchain_wwm_production_authorized 0", metrics)
            self.assertIn('mindchain_wwm_public_check_up{check="gateway"} 1', metrics)
        request = urllib.request.Request(base + "/status.json", data=b"{}", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(failure.exception.code, 405)


if __name__ == "__main__":
    unittest.main()
