import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fleet_telemetry


class FleetTelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.seed = self.root / "node.seed"
        identity = fleet_telemetry.keygen(self.seed)
        self.roster = {identity["node_id"]: identity["public_key"]}
        self.status = {
            "chain_id": "11" * 32,
            "genesis_hash": "22" * 32,
            "version": "0.1.0",
            "sync": {"height": 9, "ready": True},
            "peers": 3,
            "bootstrap": "tailscale",
            "capacity": {"cpu_threads": 8},
            "worker_policy": {"max_operations": 1000},
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_signed_sequence_is_accepted_once(self) -> None:
        report = fleet_telemetry.sign_report(self.seed, 1, self.status, observed_ms=1_000)
        database = self.root / "fleet.sqlite"
        fleet_telemetry.verify_report(report, self.roster, database, now_ms=1_010)
        with self.assertRaisesRegex(ValueError, "replayed or regressed"):
            fleet_telemetry.verify_report(report, self.roster, database, now_ms=1_020)

    def test_tampering_untrusted_nodes_and_stale_reports_fail_closed(self) -> None:
        report = fleet_telemetry.sign_report(self.seed, 1, self.status, observed_ms=1_000)
        tampered = copy.deepcopy(report)
        tampered["peers"] = 99
        with self.assertRaisesRegex(ValueError, "signature"):
            fleet_telemetry.verify_report(tampered, self.roster, self.root / "a.sqlite", now_ms=1_010)
        with self.assertRaisesRegex(ValueError, "trusted roster"):
            fleet_telemetry.verify_report(report, {}, self.root / "b.sqlite", now_ms=1_010)
        with self.assertRaisesRegex(ValueError, "stale"):
            fleet_telemetry.verify_report(report, self.roster, self.root / "c.sqlite", now_ms=200_000, freshness_ms=10)


if __name__ == "__main__":
    unittest.main()
