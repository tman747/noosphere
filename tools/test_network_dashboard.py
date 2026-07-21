import tempfile
import sys
import unittest
import threading
import urllib.request
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import network_dashboard


STATUS = {
    "chain_id": "chain-1",
    "genesis_hash": "aa" * 32,
    "release_version": "0.1.0",
    "source_revision": "55" * 20,
    "unsafe_head": {"height": 520, "hash": "bb" * 32},
    "justified": {"epoch": 1, "hash": "cc" * 32},
    "finalized": {"epoch": 1, "hash": "dd" * 32},
    "mempool": {"txs": 2, "bytes": 144},
    "observer": False,
    "finality_gossip": {
        "pending_votes": 1,
        "pending_certificates": 0,
        "accepted": 24,
        "rejected": 3,
    },
}
WORKER = {
    "worker": "ee" * 32,
    "active": 1,
    "capabilities": 3,
    "cpu_threads": 4,
    "memory_mb": 2048,
    "gpu_memory_mb": 512,
    "jobs_completed": "1",
    "units_completed": "8",
}
JOB = {
    "job": "ff" * 32,
    "state": 3,
    "agreed_price_per_unit": "7",
    "completed_units": "8",
    "escrow": "0",
}


class DashboardDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = network_dashboard.DashboardData(
            "http://operator", "secret-token", "http://indexer", "http://compute",
            Path(self.temp.name) / "samples.sqlite3",
        )

    def tearDown(self):
        self.data.db.close()
        self.temp.cleanup()

    def test_static_routes_support_head(self):
        app_dir = Path(self.temp.name) / "app"
        app_dir.mkdir()
        index = b"<h1>live</h1>"
        (app_dir / "index.html").write_bytes(index)
        server = network_dashboard.ThreadingHTTPServer(("127.0.0.1", 0), network_dashboard.Handler)
        server.app_dir = app_dir
        server.data = self.data
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/", method="HEAD")
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(int(response.headers["Content-Length"]), len(index))
                self.assertEqual(response.read(), b"")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())

    @staticmethod
    def source(url, _token=None):
        if url.endswith("/status") and "operator" in url:
            return STATUS, None
        if url.endswith("/block/520"):
            return {"height": 520, "slot": 77, "timestamp_ms": 5_200, "txids": ["tx-1"]}, None
        if "/block/" in url:
            height = int(url.rsplit("/", 1)[1])
            return {
                "height": height,
                "slot": height,
                "timestamp_ms": height * 1_000,
                "hash": f"{height:064x}",
                "parent_hash": f"{height - 1:064x}",
                "txids": [],
            }, None
        if url.endswith("/api/v1/workers"):
            return {"items": [WORKER]}, None
        if url.endswith("/api/v1/jobs"):
            return {"items": [JOB]}, None
        if url.endswith("/api/status"):
            return {"unsafe_head": {"height": 0}}, None
        if url.endswith("/api/health"):
            return {"ok": True, "version": "0.2"}, None
        raise AssertionError(f"unexpected URL {url}")

    @patch("network_dashboard.source_result", side_effect=source.__func__)
    def test_dashboard_contracts_derive_only_reported_values(self, _source):
        self.data.collect()
        calls_after_collection = _source.call_count
        self.data.local_validator_status()
        self.data.local_validator_status()
        self.assertEqual(_source.call_count, calls_after_collection)

        overview = self.data.overview()
        self.assertEqual(overview["chain"]["height"], 520)
        self.assertEqual(overview["chain"]["current_epoch"], 2)
        self.assertEqual(overview["chain"]["finalization_lag"], 1)
        self.assertEqual(overview["chain"]["mempool_transactions"], 2)
        self.assertEqual(overview["services"][1]["state"], "degraded")
        self.assertEqual(overview["topology"]["nodes"][-1]["state"], "unreported")

        consensus = self.data.consensus()
        self.assertEqual(len(consensus["blocks"]), 64)
        self.assertEqual(consensus["median_block_cadence_ms"], 1_000)
        self.assertEqual(consensus["quorum_telemetry"]["state"], "reported")
        self.assertEqual(consensus["quorum_telemetry"]["accepted"], 24)

        compute = self.data.compute_economy()
        self.assertEqual(compute["supply"]["cpu_threads"], 4)
        self.assertEqual(compute["supply"]["gpu_workers"], 1)
        self.assertEqual(compute["jobs_by_state"]["settled"], 1)
        self.assertEqual(compute["settled_value"], "56")
        self.assertEqual(compute["currency"], "micro-NOOS_TEST")

        nodes = self.data.node_fleet()
        self.assertEqual(len(nodes["nodes"]), 2)
        self.assertEqual(nodes["unreported"]["count"], 0)
        self.assertEqual(nodes["nodes"][1]["telemetry_state"], "on_chain_capability_only")

    def test_public_fleet_merges_four_sanitized_validator_reports(self):
        deployment = {
            "chain_binding": {"chain_id": "chain-1", "genesis_hash": "aa" * 32},
            "public_endpoints": {"read_gateway": "https://gateway"},
            "public_seeds": [
                {
                    "witness_index": index,
                    "role": "producer-witness" if index == 0 else "witness",
                    "machine": f"seed-{1 if index == 0 else 2 if index == 1 else 3}",
                    "hostname": f"seed-{1 if index == 0 else 2 if index == 1 else 3}",
                    "region": "centralus" if index < 2 else "eastus",
                    "vm_size": "Standard_D4ads_v7",
                }
                for index in range(4)
            ],
            "public_indexers": {
                "minimum_control_cluster_quorum": 2,
                "endpoints": [
                    {"base_url": f"https://seed-{index}", "failure_domain": f"vm-{index}"}
                    for index in range(1, 4)
                ],
            },
        }

        def validator_document(*indices):
            return {
                "schema": network_dashboard.VALIDATOR_STATUS_SCHEMA,
                "environment": "public-testnet",
                "production": False,
                "chain_id": "chain-1",
                "genesis_hash": "aa" * 32,
                "observed_ms": 9_000,
                "validators": [{
                    "witness_index": index,
                    "role": "witness",
                    "state": "online",
                    "observed_ms": 9_000,
                    "release_version": "0.1.0",
                    "source_revision": "55" * 20,
                    "unsafe_head": {"height": 100 if index == 3 else 520, "hash": f"{index + 1:064x}"},
                    "justified": {"epoch": 1},
                    "finalized": {"epoch": 1},
                } for index in indices],
            }

        def public_source(url, _token=None):
            if url == "http://operator/status":
                return STATUS, None
            if "/block/" in url:
                height = int(url.rsplit("/", 1)[1])
                return {
                    "height": height,
                    "slot": height,
                    "timestamp_ms": height * 1_000,
                    "hash": f"{height:064x}",
                    "parent_hash": f"{height - 1:064x}",
                    "txids": [],
                }, None
            if url.endswith("/api/v1/workers"):
                return {"items": [WORKER]}, None
            if url.endswith("/api/v1/jobs"):
                return {"items": [JOB]}, None
            if url == "http://indexer/api/status" or url.endswith("/api/status"):
                return {
                    "chain_id": "chain-1",
                    "genesis_hash": "aa" * 32,
                    "ready": True,
                    "readiness": "ready",
                    "unsafe_head": {"height": "520"},
                    "justified": {"height": "256"},
                    "finalized": {"height": "256"},
                    "freshness_ms": str((1 << 64) - 1) if url == "http://indexer/api/status" else "12",
                }, None
            if url == "https://seed-2/validator-status.json":
                return validator_document(1), None
            if url == "https://seed-3/validator-status.json":
                return validator_document(2, 3), None
            if url == "https://gateway/healthz":
                return {
                    "status": "ok",
                    "unsafe_head": {"height": 100, "hash": "11" * 32},
                    "finalized": {"epoch": 1},
                }, None
            if url.endswith("/api/health"):
                return {"ok": True}, None
            raise AssertionError(f"unexpected URL {url}")

        deployed = network_dashboard.DashboardData(
            "http://operator",
            "secret-token",
            "http://indexer",
            "http://compute",
            Path(self.temp.name) / "deployed.sqlite3",
            deployment=deployment,
            local_validators=[{
                "witness_index": 0,
                "rpc": "http://operator",
                "token": "secret-token",
            }],
            public_base_url="https://seed-1",
        )
        try:
            with patch("network_dashboard.source_result", side_effect=public_source):
                deployed.collect()
                overview = deployed.overview()
                consensus = deployed.consensus()
                nodes = deployed.node_fleet()
                local_status = deployed.local_validator_status()
            self.assertEqual([item["witness_index"] for item in overview["validators"]], [0, 1, 2, 3])
            self.assertEqual(local_status["validators"][0]["source_revision"], "55" * 20)
            self.assertEqual([item["state"] for item in overview["validators"]], ["online", "online", "online", "catching_up"])
            self.assertEqual(sum(item["ready"] for item in overview["indexers"]), 3)
            self.assertEqual(overview["indexers"][0]["freshness_ms"], -1)
            self.assertEqual(overview["services"][0]["state"], "online")
            self.assertEqual(overview["services"][2]["state"], "degraded")
            self.assertEqual(consensus["quorum_telemetry"]["threshold"], 3)
            self.assertEqual(consensus["quorum_telemetry"]["online_validators"], 3)
            self.assertEqual(len(nodes["validators"]), 4)
            self.assertEqual(len(nodes["nodes"]), 6)
            self.assertEqual(nodes["validators"][3]["state"], "catching_up")
            self.assertEqual(nodes["validators"][3]["head_lag"], 420)
            self.assertEqual(nodes["nodes"][4]["state"], "catching_up")
            self.assertEqual(nodes["nodes"][4]["head_lag"], 420)
            self.assertEqual({incident["source"] for incident in nodes["incidents"]}, {"witness_3", "observer"})
            self.assertNotIn("rpc", local_status["validators"][0])
            self.assertNotIn("token", local_status["validators"][0])
        finally:
            deployed.db.close()

    def test_secret_loader_accepts_raw_and_json_tokens(self):
        raw = Path(self.temp.name) / "raw-token"
        document = Path(self.temp.name) / "token.json"
        raw.write_text("a" * 32 + "\n", encoding="utf-8")
        document.write_text('{"rpc_token":"' + "b" * 32 + '"}', encoding="utf-8")
        self.assertEqual(network_dashboard.load_secret_token(raw), "a" * 32)
        self.assertEqual(network_dashboard.load_secret_token(document), "b" * 32)

    @patch("network_dashboard.source_result")
    def test_source_failures_remain_visible_without_fake_metrics(self, source):
        source.return_value = (None, "connection refused")
        self.data.collect()

        overview = self.data.overview()
        self.assertEqual(overview["chain"]["height"], 0)
        self.assertEqual(overview["history"], [])
        self.assertEqual(overview["services"][0]["state"], "offline")
        self.assertEqual(overview["services"][4]["state"], "stalled")
        self.assertIn("operator", overview["errors"])

        nodes = self.data.node_fleet()
        self.assertEqual(nodes["nodes"][0]["state"], "offline")
        self.assertGreater(len(nodes["incidents"]), 0)


if __name__ == "__main__":
    unittest.main()
