from __future__ import annotations

import argparse
from dataclasses import replace
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from unittest import mock

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
        self.workerd_config = self.root / "secrets" / "workerd.toml"
        self.worker_token = "77" * 32
        self.workerd_config.parent.mkdir(parents=True, exist_ok=True)
        self.workerd_config.write_text(
            f'[worker]\nsidecar_token_hex = "{self.worker_token}"\n[engine]\nkind = "mock"\n',
            encoding="utf-8",
        )
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
            "monitoring": {
                "validator_status_endpoints": [
                    "https://seed.example/validator-status.json",
                    "https://seed-2.example/validator-status.json",
                    "https://seed-3.example/validator-status.json",
                ],
            },
            "public_seeds": [
                {
                    "hostname": "seed.example",
                    "ipv4": "203.0.113.9",
                    "operator_rpc": "loopback-only",
                },
                {
                    "hostname": "seed-2.example",
                    "ipv4": "203.0.113.10",
                    "operator_rpc": "loopback-only",
                },
                {
                    "hostname": "seed-3.example",
                    "ipv4": "203.0.113.11",
                    "operator_rpc": "loopback-only",
                },
                {
                    "hostname": "seed-3.example",
                    "ipv4": "203.0.113.11",
                    "operator_rpc": "loopback-only:29653",
                },
            ],
            "public_indexers": {
                "endpoints": [
                    {"base_url": "https://indexer-a.example"},
                    {"base_url": "https://indexer-b.example"},
                    {"base_url": "https://indexer-c.example"},
                ],
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
            worker_config=self.workerd_config,
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
        self.assertEqual(config.worker_bearer_token, self.worker_token)
        self.assertEqual(len(config.validator_status_urls), 3)
        self.assertEqual(len(config.indexer_origins), 3)
        self.assertEqual(
            [(seed.hostname, seed.ipv4, seed.rpc_ports) for seed in config.seed_hosts],
            [
                ("seed.example", "203.0.113.9", (29652,)),
                ("seed-2.example", "203.0.113.10", (29652,)),
                ("seed-3.example", "203.0.113.11", (29652, 29653)),
            ],
        )

        validator_urls = self.deployment_document["monitoring"]["validator_status_endpoints"]
        validator_urls[2] = "https://unbound.example/validator-status.json"
        self.deployment.write_text(json.dumps(self.deployment_document), encoding="utf-8")
        with self.assertRaisesRegex(monitor.MonitorError, "cover every public seed host"):
            monitor.load_config(self.arguments())
        validator_urls[2] = "https://seed-3.example/validator-status.json"

        self.deployment_document["production"] = True
        self.deployment.write_text(json.dumps(self.deployment_document), encoding="utf-8")
        with self.assertRaisesRegex(monitor.MonitorError, "fail-closed public testnet"):
            monitor.load_config(self.arguments())

    def test_worker_probe_authenticates_without_exposing_token(self) -> None:
        config = monitor.load_config(self.arguments())
        with mock.patch.object(
            monitor,
            "request_json",
            return_value=(200, {}, {"ready": True}),
        ) as request:
            detail = monitor.worker_probe(config, 5.0)
        request.assert_called_once_with(
            "http://127.0.0.1:29807/health/ready",
            5.0,
            headers={"Authorization": f"Bearer {self.worker_token}"},
        )
        self.assertNotIn(self.worker_token, json.dumps(detail))

    def test_network_probe_requires_a_coherent_validator_and_indexer_fleet(self) -> None:
        config = monitor.load_config(self.arguments())

        def validator(witness_index: int, height: int) -> dict[str, object]:
            return {
                "witness_index": witness_index,
                "state": "online",
                "unsafe_head": {"height": height},
                "justified": {"epoch": 4, "hash": "aa" * 32},
                "finalized": {"epoch": 3, "hash": "bb" * 32},
            }

        validator_entries = [
            validator(0, 1_000),
            validator(1, 999),
            validator(2, 998),
            validator(3, 997),
        ]
        responses: dict[str, dict[str, object]] = {}
        for url, entries in zip(
            config.validator_status_urls,
            (validator_entries[:1], validator_entries[1:2], validator_entries[2:]),
        ):
            responses[url] = {
                "schema": monitor.VALIDATOR_STATUS_SCHEMA,
                "environment": "public-testnet",
                "production": False,
                "chain_id": config.chain_id,
                "genesis_hash": config.genesis_hash,
                "validators": entries,
            }
        for offset, origin in enumerate(config.indexer_origins):
            responses[origin + "/api/status"] = {
                "chain_id": config.chain_id,
                "genesis_hash": config.genesis_hash,
                "ready": True,
                "unsafe_head": {"height": str(1_000 - offset)},
                "finalized": {"height": "768", "hash": "bb" * 32},
            }

        def response(url: str, _timeout: float) -> tuple[int, object, dict[str, object]]:
            return 200, {}, responses[url]

        with mock.patch.object(monitor, "request_json", side_effect=response):
            detail = monitor.network_probe(config, 5.0)
            self.assertEqual(detail["validator_count"], 4)
            self.assertEqual(detail["finalized_epoch"], 3)
            first_indexer = responses[config.indexer_origins[0] + "/api/status"]
            first_indexer["finalized"] = {"height": "768", "hash": "cc" * 32}
            with self.assertRaisesRegex(monitor.MonitorError, "finalized checkpoint disagrees"):
                monitor.network_probe(config, 5.0)
            first_indexer["finalized"] = {"height": "768", "hash": "bb" * 32}


            validator_entries[3]["unsafe_head"] = {"height": 700}
            with self.assertRaisesRegex(monitor.MonitorError, "exceed one epoch"):
                monitor.network_probe(config, 5.0)

            validator_entries[3]["unsafe_head"] = {"height": 997}
            validator_entries[1]["state"] = "catching_up"
            with self.assertRaisesRegex(monitor.MonitorError, "validator 1 is catching_up"):
                monitor.network_probe(config, 5.0)

            third_indexer = responses[config.indexer_origins[2] + "/api/status"]
            third_indexer["ready"] = False
            with self.assertRaises(monitor.MonitorError) as caught:
                monitor.network_probe(config, 5.0)
            message = str(caught.exception)
            self.assertIn("validator 1 is catching_up", message)
            self.assertIn(f"indexer endpoint {config.indexer_origins[2]}", message)

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
        config = replace(monitor.load_config(self.arguments()), listen_port=0)
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
