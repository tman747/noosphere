import io
import json
import unittest
import urllib.error
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unittest.mock import patch

import bench_tps


class TransactionRecordTests(unittest.TestCase):
    def test_falls_back_to_public_receipt_when_index_record_is_missing(self) -> None:
        missing = urllib.error.HTTPError(
            "http://127.0.0.1/api/v1/transactions/abc", 404, "not found", {}, None
        )
        receipt = io.BytesIO(
            json.dumps(
                {
                    "receipt": {"txid": "abc", "status": 0, "fee_charged": "544"},
                    "state": {"settled_height": 42, "status_code": 0},
                }
            ).encode()
        )

        with patch("urllib.request.urlopen", side_effect=[missing, receipt]) as urlopen:
            record = bench_tps.tx_record("http://127.0.0.1", "abc")

        self.assertEqual(record["state"], "INCLUDED")
        self.assertEqual(record["inclusion"], {"height": 42})
        self.assertEqual(record["receipt"]["fee_charged"], "544")
        for call in urlopen.call_args_list:
            self.assertEqual(call.args[0].get_header("User-agent"), bench_tps.USER_AGENT)


if __name__ == "__main__":
    unittest.main()
