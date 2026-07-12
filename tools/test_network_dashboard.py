import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import network_dashboard


STATUS = {
    "chain_id": "chain-1",
    "genesis_hash": "aa" * 32,
    "unsafe_head": {"height": 520, "hash": "bb" * 32},
    "justified": {"epoch": 1, "hash": "cc" * 32},
    "finalized": {"epoch": 1, "hash": "dd" * 32},
    "mempool": {"txs": 2, "bytes": 144},
    "observer": False,
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
        self.assertEqual(consensus["quorum_telemetry"]["state"], "unavailable")

        compute = self.data.compute_economy()
        self.assertEqual(compute["supply"]["cpu_threads"], 4)
        self.assertEqual(compute["supply"]["gpu_workers"], 1)
        self.assertEqual(compute["jobs_by_state"]["settled"], 1)
        self.assertEqual(compute["settled_value"], "56")
        self.assertEqual(compute["currency"], "micro-NOOS_TEST")

        nodes = self.data.node_fleet()
        self.assertEqual(len(nodes["nodes"]), 2)
        self.assertIsNone(nodes["unreported"]["count"])
        self.assertEqual(nodes["nodes"][1]["telemetry_state"], "on_chain_capability_only")

    @patch("network_dashboard.source_result")
    def test_source_failures_remain_visible_without_fake_metrics(self, source):
        source.return_value = (None, "connection refused")
        self.data.collect()

        overview = self.data.overview()
        self.assertEqual(overview["chain"]["height"], 0)
        self.assertEqual(overview["history"], [])
        self.assertEqual(overview["services"][0]["state"], "offline")
        self.assertIn("operator", overview["errors"])

        nodes = self.data.node_fleet()
        self.assertEqual(nodes["nodes"][0]["state"], "offline")
        self.assertGreater(len(nodes["incidents"]), 0)


if __name__ == "__main__":
    unittest.main()
