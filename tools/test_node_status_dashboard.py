import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import node_status_dashboard as dashboard


class MonitorTests(unittest.TestCase):
    def test_online_snapshot_reports_chain_capacity_and_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            invite = Path(temp) / "invite.json"
            invite.write_text(
                json.dumps(
                    {
                        "chain_id": "01" * 32,
                        "genesis_hash": "02" * 32,
                        "witness_index": 2,
                        "validator_host": "192.168.1.158",
                        "validator_p2p_port": 21701,
                        "compute_market_url": "http://192.168.1.158:18110",
                    }
                ),
                encoding="utf-8",
            )
            monitor = dashboard.Monitor(
                {
                    "rpc_status_url": "http://127.0.0.1:19632/status",
                    "rpc_token": "local-secret",
                    "invite_path": str(invite),
                }
            )
            operator = {
                "chain_id": "01" * 32,
                "genesis_hash": "02" * 32,
                "unsafe_head": {"height": 481},
                "justified": {"epoch": 1, "hash": "03" * 32},
                "finalized": {"epoch": 0, "hash": "04" * 32},
            }
            process = {"pid": 731, "cpu_percent": 8.7, "rss_bytes": 1_073_741_824, "uptime": "02h 14m"}
            disk = types.SimpleNamespace(total=1_000_000, used=400_000, free=600_000)

            with (
                patch.object(dashboard, "operator_status", return_value=operator) as status,
                patch.object(dashboard, "node_process", return_value=process),
                patch.object(dashboard, "mac_memory", return_value=(16_000_000, 6_800_000)),
                patch.object(dashboard, "host_cpu_percent", return_value=23.4),
                patch.object(dashboard.os, "cpu_count", return_value=10),
                patch.object(dashboard.shutil, "disk_usage", return_value=disk),
                patch.object(dashboard.platform, "machine", return_value="arm64"),
                patch.object(dashboard.platform, "platform", return_value="macOS-14-arm64"),
            ):
                first = monitor.snapshot()
                second = monitor.snapshot()

            self.assertTrue(first["online"])
            self.assertEqual(first["chain"]["head"], 481)
            self.assertEqual(first["chain"]["justified_epoch"], 1)
            self.assertEqual(first["node"]["witness_index"], 2)
            self.assertEqual(first["system"]["architecture"], "arm64")
            self.assertEqual(first["system"]["cpu_percent"], 23.4)
            self.assertEqual(first["process"]["rss_bytes"], 1_073_741_824)
            self.assertIn({"name": "Compute helper", "state": "Available"}, first["capabilities"])
            self.assertIs(first, second)
            status.assert_called_once_with("http://127.0.0.1:19632/status", "local-secret")

    def test_elapsed_time_is_human_readable(self) -> None:
        self.assertEqual(dashboard.parse_elapsed("3-07:05:44"), "3d 07h 05m")
        self.assertEqual(dashboard.parse_elapsed("12:09"), "00h 12m")


if __name__ == "__main__":
    unittest.main()
