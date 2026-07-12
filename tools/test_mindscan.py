import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mindscan


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class MindScanGatewayTests(unittest.TestCase):
    def test_routes_only_canonical_identifiers(self) -> None:
        data = mindscan.ExplorerData("http://127.0.0.1:8080")
        with self.assertRaisesRegex(ValueError, "invalid block"):
            data.block("01")
        with self.assertRaisesRegex(ValueError, "invalid transaction"):
            data.transaction("../status")
        with self.assertRaisesRegex(ValueError, "1..50"):
            data.blocks(51)

    def test_indexer_response_is_forwarded_without_operator_credentials(self) -> None:
        payload = {"items": [{"height": "12", "hash": "ab" * 32}]}
        with patch("urllib.request.urlopen", return_value=Response(json.dumps(payload).encode())) as opened:
            value = mindscan.ExplorerData("http://127.0.0.1:8080").blocks(18)
        self.assertEqual(value, payload)
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8080/api/v1/blocks?limit=18")
        self.assertIsNone(request.get_header("Authorization"))

    def test_indexer_origin_rejects_credentials_and_non_http_schemes(self) -> None:
        for origin in ("file:///tmp/index", "http://user:secret@127.0.0.1:8080"):
            with self.subTest(origin=origin), self.assertRaisesRegex(ValueError, "absolute HTTP"):
                mindscan.ExplorerData(origin)


if __name__ == "__main__":
    unittest.main()
