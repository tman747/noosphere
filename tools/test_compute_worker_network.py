import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compute_worker
import compute_workload_registry as workload_registry


class ComputeNetworkTests(unittest.TestCase):
    def setUp(self) -> None:
        seed = bytes(range(1, 33))
        chain_id = "01" * 32
        genesis_hash = "02" * 32
        envelope = workload_registry.freeze_registry(
            chain_id=chain_id,
            genesis_hash=genesis_hash,
            sequence=1,
            previous_registry_id=None,
            valid_from_height=0,
            expires_at_height=100,
            activate_at_height=0,
            retire_at_height=100,
            max_units=1_000,
            max_unit_size=1_000,
            max_operations=4_096,
            private_seed=seed,
        )
        self.registry = workload_registry.verify_registry(
            envelope,
            trusted_public_key=workload_registry.public_from_seed(seed),
            expected_chain_id=chain_id,
            expected_genesis_hash=genesis_hash,
            height=1,
        )

    def test_operator_head_is_identity_checked(self) -> None:
        profile = {
            "chain_id": "01" * 32,
            "genesis_hash": "02" * 32,
            "api_base_url": "http://127.0.0.1:18080",
            "_operator_node": "127.0.0.1:18632",
            "_operator_token": "private-token",
        }
        response = io.BytesIO(
            json.dumps(
                {
                    "chain_id": profile["chain_id"],
                    "genesis_hash": profile["genesis_hash"],
                    "unsafe_head": {"height": 4912, "hash": "03" * 32},
                }
            ).encode()
        )
        with patch("urllib.request.urlopen", return_value=response) as request:
            status = compute_worker.live_status(profile)
        self.assertEqual(status["unsafe_head"]["height"], 4912)
        sent = request.call_args.args[0]
        self.assertEqual(sent.get_header("Authorization"), "Bearer private-token")

    def test_receipt_fallback_settles_when_index_record_is_missing(self) -> None:
        profile = {"api_base_url": "http://127.0.0.1:18080"}
        receipt = {
            "receipt": {"txid": "ab" * 32, "status": 0, "fee_charged": "544"},
            "state": {"settled_height": 4914, "status_code": 0},
        }
        with patch.object(
            compute_worker,
            "api_json",
            side_effect=[SystemExit("HTTP Error 404: not found"), receipt],
        ):
            record = compute_worker.settlement_record(profile, "ab" * 32)
        self.assertEqual(record["state"], "INCLUDED")
        self.assertEqual(record["receipt"]["state"]["settled_height"], 4914)

    def test_payload_is_bound_to_on_chain_commitment_and_meter(self) -> None:
        payload = {"seed": 7, "start": 11, "units": 32, "rounds": 64}
        commitment = workload_registry.commit_input(
            self.registry.require_active(0, 1),
            payload,
        )
        job = {
            "workload_kind": 0,
            "input_root": commitment,
            "units": "32",
            "unit_size": "64",
        }
        validated = compute_worker.validate_payload(
            self.registry, job, payload, 1, 2_048
        )
        self.assertEqual(validated[1:], (7, 11, 32, 64))

        tampered = dict(payload, seed=8)
        with self.assertRaisesRegex(ValueError, "commitment mismatch"):
            compute_worker.validate_payload(
                self.registry, job, tampered, 1, 2_048
            )

    def test_unregistered_or_over_budget_workload_is_refused(self) -> None:
        payload = {"seed": 1, "start": 0, "units": 10, "rounds": 10}
        job = {
            "workload_kind": 9,
            "input_root": "00" * 32,
            "units": "10",
            "unit_size": "10",
        }
        with self.assertRaisesRegex(ValueError, "unregistered"):
            compute_worker.validate_payload(
                self.registry, job, payload, 1, 100
            )
        job["workload_kind"] = 0
        with self.assertRaisesRegex(ValueError, "operation budget"):
            compute_worker.validate_payload(
                self.registry, job, payload, 1, 99
            )



if __name__ == "__main__":
    unittest.main()
