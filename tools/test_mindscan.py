from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mindscan

CHAIN_ID = "a" * 64
GENESIS_HASH = "b" * 64


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def response(value: dict[str, object]) -> Response:
    return Response(json.dumps(value).encode())


def point(height: int, byte: str) -> dict[str, str]:
    return {"height": str(height), "hash": byte * 64, "state_root": "f" * 64}


def status(
    *,
    chain_id: str = CHAIN_ID,
    genesis_hash: str = GENESIS_HASH,
    unsafe: int = 12,
    justified: int = 10,
    finalized: int = 8,
) -> dict[str, object]:
    return {
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "protocol_version": "v1",
        "api_version": "v1",
        "release_version": "0.1.0+git." + "1" * 40,
        "readiness": "ready",
        "ready": True,
        "indexed_generation": "7",
        "unsafe_head": point(unsafe, "c"),
        "justified": point(justified, "d"),
        "finalized": point(finalized, "e"),
        "freshness_ms": "12",
    }


def block(height: int, byte: str) -> dict[str, str]:
    return {
        "height": str(height),
        "hash": byte * 64,
        "parent_hash": "1" * 64,
        "slot": str(height),
        "epoch": str(height // 4),
        "timestamp_ms": str(1_000 + height),
        "execution_receipt_root": "2" * 64,
        "lumen_receipts_state_root": "3" * 64,
        "transaction_count": "1",
    }


class MindScanGatewayTests(unittest.TestCase):
    def data(self) -> mindscan.ExplorerData:
        return mindscan.ExplorerData("http://127.0.0.1:8080", CHAIN_ID, GENESIS_HASH)

    def test_routes_only_canonical_identifiers(self) -> None:
        data = self.data()
        with self.assertRaisesRegex(ValueError, "invalid block"):
            data.block("01")
        with self.assertRaisesRegex(ValueError, "invalid transaction"):
            data.transaction("../status")
        with self.assertRaisesRegex(ValueError, "1..50"):
            data.blocks(51)

    def test_indexer_page_is_identity_bound_finality_labeled_and_credential_free(self) -> None:
        page = {"items": [block(12, "4"), block(8, "5")], "next_cursor": None}
        with patch(
            "urllib.request.urlopen",
            side_effect=[response(status()), response(page)],
        ) as opened:
            value = self.data().blocks(18)
        self.assertEqual([row["finality"] for row in value["items"]], ["unsafe", "finalized"])
        self.assertEqual(value["chain_id"], CHAIN_ID)
        self.assertEqual(value["genesis_hash"], GENESIS_HASH)
        self.assertEqual(value["indexed_generation"], "7")
        self.assertEqual(
            [call.args[0].full_url for call in opened.call_args_list],
            [
                "http://127.0.0.1:8080/api/status",
                "http://127.0.0.1:8080/api/v1/blocks?limit=18",
            ],
        )
        for call in opened.call_args_list:
            self.assertIsNone(call.args[0].get_header("Authorization"))

    def test_wrong_identity_finality_order_and_block_order_fail_closed(self) -> None:
        with patch("urllib.request.urlopen", return_value=response(status(chain_id="c" * 64))):
            with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                self.data().status()
        with patch(
            "urllib.request.urlopen",
            return_value=response(status(unsafe=8, justified=10, finalized=9)),
        ):
            with self.assertRaisesRegex(RuntimeError, "finality order"):
                self.data().status()
        page = {"items": [block(8, "4"), block(12, "5")], "next_cursor": None}
        with patch(
            "urllib.request.urlopen",
            side_effect=[response(status()), response(page)],
        ):
            with self.assertRaisesRegex(RuntimeError, "order is not canonical"):
                self.data().blocks(18)

    def test_transaction_is_bound_to_validated_identity_without_overwriting_upstream(self) -> None:
        record = {"txid": "6" * 64, "state": "FINALIZED"}
        with patch(
            "urllib.request.urlopen",
            side_effect=[response(status()), response(record)],
        ):
            value = self.data().transaction("6" * 64)
        self.assertEqual(value["mindscan_identity"]["chain_id"], CHAIN_ID)
        self.assertEqual(value["mindscan_identity"]["indexed_generation"], "7")

        reserved = {**record, "mindscan_identity": {}}
        with patch(
            "urllib.request.urlopen",
            side_effect=[response(status()), response(reserved)],
        ):
            with self.assertRaisesRegex(RuntimeError, "reserved field"):
                self.data().transaction("6" * 64)

    def test_restart_is_stateless_and_returns_the_same_index_generation(self) -> None:
        page = {"items": [block(12, "4")], "next_cursor": None}
        first_responses = [response(status()), response(page)]
        second_responses = [response(status()), response(page)]
        with patch("urllib.request.urlopen", side_effect=first_responses):
            before = self.data().blocks(18)
        with patch("urllib.request.urlopen", side_effect=second_responses):
            after = self.data().blocks(18)
        self.assertEqual(before, after)

    def test_indexer_origin_and_expected_identity_reject_unsafe_configuration(self) -> None:
        for origin in ("file:///tmp/index", "http://user:secret@127.0.0.1:8080"):
            with self.subTest(origin=origin), self.assertRaisesRegex(ValueError, "absolute HTTP"):
                mindscan.ExplorerData(origin, CHAIN_ID, GENESIS_HASH)
        with self.assertRaisesRegex(ValueError, "canonical hashes"):
            mindscan.ExplorerData("http://127.0.0.1:8080", "not-a-hash", GENESIS_HASH)
