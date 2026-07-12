import sys
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lan_testnet


class ValidatorLaunchTests(unittest.TestCase):
    def args(self, standalone_finality: bool) -> Namespace:
        return Namespace(
            manifest="manifest.json",
            operator_secret="operator-secret.json",
            data_dir="validator-data",
            standalone_finality=standalone_finality,
        )

    def run_command(self, standalone_finality: bool) -> list[str]:
        manifest = {
            "ports": {"p2p": 21701, "operator_rpc": 21632},
            "produce_interval_ms": 1000,
        }
        with (
            patch.object(lan_testnet, "load_manifest", return_value=manifest),
            patch.object(lan_testnet, "common_node", return_value=["noosd"]),
            patch.object(lan_testnet, "local_ip", return_value="192.168.1.158"),
            patch.object(lan_testnet.Path, "read_text", return_value='{"rpc_token":"secret"}'),
            patch.object(lan_testnet.subprocess, "call", return_value=0) as call,
        ):
            with self.assertRaises(SystemExit) as stopped:
                lan_testnet.run_validator(self.args(standalone_finality))
            self.assertEqual(stopped.exception.code, 0)
        return call.call_args.args[0]

    def test_standalone_host_drives_test_only_fixture_quorum(self) -> None:
        command = self.run_command(True)
        self.assertIn("--validator", command)
        self.assertNotIn("--devnet-producer", command)
        self.assertNotIn("--devnet-witness", command)

    def test_distributed_host_keeps_independent_witness_mode(self) -> None:
        command = self.run_command(False)
        self.assertNotIn("--validator", command)
        self.assertIn("--devnet-producer", command)
        witness = command.index("--devnet-witness")
        self.assertEqual(command[witness + 1], "0")


if __name__ == "__main__":
    unittest.main()
