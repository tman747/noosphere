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
            "throughput": {
                "produce_interval_ms": 1000,
                "mempool_max_transactions": 65_536,
                "mempool_max_bytes": 67_108_864,
                "mempool_per_source_pending": 65_536,
                "mempool_per_account_pending": 65_536,
                "template_byte_budget": 33_554_432,
                "template_max_transactions": 32_768,
            },
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

    def test_validator_binds_manifest_throughput_profile(self) -> None:
        command = self.run_command(False)
        expected = {
            "--produce-interval-ms": "1000",
            "--mempool-max-transactions": "65536",
            "--mempool-max-bytes": "67108864",
            "--mempool-per-source-pending": "65536",
            "--mempool-per-account-pending": "65536",
            "--template-byte-budget": "33554432",
            "--template-max-transactions": "32768",
        }
        for flag, value in expected.items():
            index = command.index(flag)
            self.assertEqual(command[index + 1], value)



class ThroughputProfileTests(unittest.TestCase):
    def profile(self) -> dict[str, int]:
        return {
            "produce_interval_ms": 1000,
            "mempool_max_transactions": 65_536,
            "mempool_max_bytes": 67_108_864,
            "mempool_per_source_pending": 65_536,
            "mempool_per_account_pending": 65_536,
            "template_byte_budget": 33_554_432,
            "template_max_transactions": 32_768,
        }

    def test_profile_accepts_bounded_high_capacity_values(self) -> None:
        self.assertEqual(lan_testnet.validate_throughput(self.profile()), self.profile())

    def test_profile_rejects_template_larger_than_pool(self) -> None:
        profile = self.profile()
        profile["template_max_transactions"] = 65_537
        with self.assertRaisesRegex(SystemExit, "fit inside"):
            lan_testnet.validate_throughput(profile)

    def test_profile_rejects_unknown_fields(self) -> None:
        profile = self.profile()
        profile["unbounded"] = 1
        with self.assertRaisesRegex(SystemExit, "wrong fields"):
            lan_testnet.validate_throughput(profile)

if __name__ == "__main__":
    unittest.main()
