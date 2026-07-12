import io
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


if __name__ == "__main__":
    unittest.main()
