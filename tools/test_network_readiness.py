import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import network_readiness


class NetworkReadinessTests(unittest.TestCase):
    def fixtures(self):
        identity = {
            "chain_id": "11" * 32,
            "genesis_hash": "22" * 32,
            "unsafe_head": {"height": "100"},
            "justified": {"height": "96"},
            "finalized": {"height": "90"},
        }
        operator = dict(identity)
        indexer = dict(identity, ready=True, readiness="ready")
        mindscan = dict(identity)
        compute = {"ok": True, "operator_head": True}
        dashboard = {"ok": True, "schema": "noos/network-dashboard-health/v1"}
        return operator, indexer, mindscan, compute, dashboard

    def test_complete_aligned_stack_is_ready(self):
        result = network_readiness.inspect_stack(*self.fixtures(), maximum_head_lag=8)
        self.assertTrue(result["ok"])
        self.assertEqual(result["errors"], [])

    def test_identity_and_stale_index_fail_closed(self):
        operator, indexer, mindscan, compute, dashboard = self.fixtures()
        operator["unsafe_head"] = {"height": "120"}
        mindscan["chain_id"] = "33" * 32
        result = network_readiness.inspect_stack(
            operator, indexer, mindscan, compute, dashboard, maximum_head_lag=8
        )
        self.assertFalse(result["ok"])
        self.assertIn("identity_mismatch", result["errors"])
        self.assertIn("indexer_head_lag", result["errors"])

    def test_finality_order_and_service_health_are_enforced(self):
        operator, indexer, mindscan, compute, dashboard = self.fixtures()
        indexer["finalized"] = {"height": "101"}
        compute["operator_head"] = False
        dashboard["ok"] = False
        result = network_readiness.inspect_stack(
            operator, indexer, mindscan, compute, dashboard, maximum_head_lag=8
        )
        self.assertFalse(result["ok"])
        self.assertIn("invalid_finality_order", result["errors"])
        self.assertIn("compute_not_ready", result["errors"])
        self.assertIn("dashboard_not_ready", result["errors"])


if __name__ == "__main__":
    unittest.main()
