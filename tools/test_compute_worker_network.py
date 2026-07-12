import io
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compute_worker


class ComputeNetworkTests(unittest.TestCase):
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
        commitment = hashlib.sha256(
            b"NOOS/COMPUTE/MIX32/INPUT/V1"
            + json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        job = {
            "workload_kind": 0,
            "input_root": commitment,
            "units": "32",
            "unit_size": "64",
        }
        self.assertEqual(
            compute_worker.validate_payload(job, payload, 2_048),
            (7, 11, 32, 64),
        )

        tampered = dict(payload, seed=8)
        with self.assertRaisesRegex(ValueError, "commitment mismatch"):
            compute_worker.validate_payload(job, tampered, 2_048)

    def test_unregistered_or_over_budget_workload_is_refused(self) -> None:
        payload = {"seed": 1, "start": 0, "units": 10, "rounds": 10}
        job = {
            "workload_kind": 9,
            "input_root": "00" * 32,
            "units": "10",
            "unit_size": "10",
        }
        with self.assertRaisesRegex(ValueError, "unregistered"):
            compute_worker.validate_payload(job, payload, 100)
        job["workload_kind"] = 0
        with self.assertRaisesRegex(ValueError, "operation budget"):
            compute_worker.validate_payload(job, payload, 99)



if __name__ == "__main__":
    unittest.main()
