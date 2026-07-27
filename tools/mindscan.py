#!/usr/bin/env python3
"""Serve the public MindScan explorer through a bounded indexer gateway."""
from __future__ import annotations

import argparse
import json
import mimetypes
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps" / "mindscan"
HASH = re.compile(r"^[0-9a-f]{64}$")
HEIGHT = re.compile(r"^(0|[1-9][0-9]{0,19})$")
MAX_UPSTREAM = 2 * 1024 * 1024


class ExplorerData:
    def __init__(self, indexer: str, chain_id: str, genesis_hash: str):
        parsed = urllib.parse.urlsplit(indexer)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("indexer URL must be an absolute HTTP(S) origin")
        if not HASH.fullmatch(chain_id) or not HASH.fullmatch(genesis_hash):
            raise ValueError("expected chain identity must use canonical hashes")
        self.indexer = indexer.rstrip("/")
        self.chain_id = chain_id
        self.genesis_hash = genesis_hash

    @staticmethod
    def _height(value: Any, field: str) -> int:
        if not isinstance(value, str) or not HEIGHT.fullmatch(value):
            raise RuntimeError(f"indexer returned invalid {field}")
        parsed = int(value)
        if parsed > 2**64 - 1:
            raise RuntimeError(f"indexer returned invalid {field}")
        return parsed

    @staticmethod
    def _hash(value: Any, field: str) -> str:
        if not isinstance(value, str) or not HASH.fullmatch(value):
            raise RuntimeError(f"indexer returned invalid {field}")
        return value

    def get(self, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            self.indexer + path,
            headers={"Accept": "application/vnd.noos.v1+json, application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status != 200:
                    raise RuntimeError(f"indexer returned {response.status}")
                raw = response.read(MAX_UPSTREAM + 1)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            if isinstance(error, urllib.error.HTTPError) and error.code in {400, 404}:
                raise LookupError("record not found") from error
            raise RuntimeError("indexer unavailable") from error
        if len(raw) > MAX_UPSTREAM:
            raise RuntimeError("indexer response exceeded limit")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise RuntimeError("indexer returned malformed JSON")
        return value

    def status(self) -> dict[str, Any]:
        value = self.get("/api/status")
        required = {
            "chain_id",
            "genesis_hash",
            "protocol_version",
            "api_version",
            "release_version",
            "readiness",
            "ready",
            "indexed_generation",
            "unsafe_head",
            "justified",
            "finalized",
            "freshness_ms",
        }
        if not required.issubset(value):
            raise RuntimeError("indexer status omitted required identity or durability fields")
        if value["chain_id"] != self.chain_id or value["genesis_hash"] != self.genesis_hash:
            raise RuntimeError("indexer protocol identity mismatch")
        if value["protocol_version"] != "v1" or value["api_version"] != "v1":
            raise RuntimeError("indexer protocol version mismatch")
        if not isinstance(value["release_version"], str) or not value["release_version"]:
            raise RuntimeError("indexer release identity is missing")
        if value["readiness"] not in {"starting", "catching_up", "ready"}:
            raise RuntimeError("indexer readiness is invalid")
        if value["ready"] is not (value["readiness"] == "ready"):
            raise RuntimeError("indexer readiness fields disagree")
        self._height(value["indexed_generation"], "indexed generation")
        self._height(value["freshness_ms"], "freshness")
        heights: dict[str, int] = {}
        for name in ("unsafe_head", "justified", "finalized"):
            point = value[name]
            if not isinstance(point, dict):
                raise RuntimeError(f"indexer returned invalid {name}")
            heights[name] = self._height(point.get("height"), f"{name} height")
            self._hash(point.get("hash"), f"{name} hash")
            self._hash(point.get("state_root"), f"{name} state root")
        if not heights["finalized"] <= heights["justified"] <= heights["unsafe_head"]:
            raise RuntimeError("indexer finality order is invalid")
        return value

    def _annotate_block(self, block: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
        required = {
            "hash",
            "height",
            "parent_hash",
            "slot",
            "epoch",
            "timestamp_ms",
            "execution_receipt_root",
            "lumen_receipts_state_root",
            "transaction_count",
        }
        if not required.issubset(block) or "finality" in block:
            raise RuntimeError("indexer returned malformed block")
        height = self._height(block["height"], "block height")
        self._hash(block["hash"], "block hash")
        self._hash(block["parent_hash"], "block parent hash")
        self._hash(block["execution_receipt_root"], "block receipt root")
        self._hash(block["lumen_receipts_state_root"], "block Lumen root")
        for field in ("slot", "epoch", "timestamp_ms", "transaction_count"):
            self._height(block[field], f"block {field}")
        finalized = self._height(status["finalized"]["height"], "finalized height")
        justified = self._height(status["justified"]["height"], "justified height")
        finality = "finalized" if height <= finalized else "justified" if height <= justified else "unsafe"
        return {**block, "finality": finality}

    def blocks(self, limit: int) -> dict[str, Any]:
        if not 1 <= limit <= 50:
            raise ValueError("limit must be 1..50")
        status = self.status()
        page = self.get(f"/api/v1/blocks?limit={limit}")
        if set(page) != {"items", "next_cursor"} or not isinstance(page["items"], list):
            raise RuntimeError("indexer returned malformed block page")
        if len(page["items"]) > limit or any(not isinstance(item, dict) for item in page["items"]):
            raise RuntimeError("indexer returned oversized or malformed block page")
        items = [self._annotate_block(item, status) for item in page["items"]]
        heights = [self._height(item["height"], "block height") for item in items]
        if heights != sorted(heights, reverse=True) or len(heights) != len(set(heights)):
            raise RuntimeError("indexer block order is not canonical")
        return {
            "items": items,
            "next_cursor": page["next_cursor"],
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "indexed_generation": status["indexed_generation"],
            "heads": {
                "unsafe": status["unsafe_head"],
                "justified": status["justified"],
                "finalized": status["finalized"],
            },
        }

    def block(self, identifier: str) -> dict[str, Any]:
        if not (HASH.fullmatch(identifier) or HEIGHT.fullmatch(identifier)):
            raise ValueError("invalid block identifier")
        status = self.status()
        block = self.get("/api/v1/blocks/" + identifier)
        return self._annotate_block(block, status)

    def transaction(self, txid: str) -> dict[str, Any]:
        if not HASH.fullmatch(txid):
            raise ValueError("invalid transaction identifier")
        status = self.status()
        record = self.get("/api/v1/transactions/" + txid)
        if "mindscan_identity" in record:
            raise RuntimeError("indexer transaction used a reserved field")
        return {
            **record,
            "mindscan_identity": {
                "chain_id": self.chain_id,
                "genesis_hash": self.genesis_hash,
                "indexed_generation": status["indexed_generation"],
            },
        }


class Handler(BaseHTTPRequestHandler):
    @property
    def data(self) -> ExplorerData:
        return self.server.data  # type: ignore[attr-defined]

    def send_body(self, status: int, body: bytes, content_type: str, *, cache: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", cache)
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def json_response(self, value: dict[str, Any], status: int = 200) -> None:
        self.send_body(status, json.dumps(value, separators=(",", ":")).encode(), "application/json")

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        try:
            if path == "/api/health":
                status = self.data.status()
                self.json_response({
                    "ok": status["ready"],
                    "schema": "noos/mindscan-health/v1",
                    "chain_id": status["chain_id"],
                    "genesis_hash": status["genesis_hash"],
                    "indexed_generation": status["indexed_generation"],
                })
            elif path == "/api/status":
                self.json_response(self.data.status())
            elif path == "/api/blocks":
                query = urllib.parse.parse_qs(parsed.query, strict_parsing=False)
                if set(query) - {"limit"}:
                    raise ValueError("unsupported query parameter")
                limit = int(query.get("limit", ["18"])[0])
                self.json_response(self.data.blocks(limit))
            elif path.startswith("/api/block/"):
                self.json_response(self.data.block(path.removeprefix("/api/block/")))
            elif path.startswith("/api/transaction/"):
                self.json_response(self.data.transaction(path.removeprefix("/api/transaction/")))
            elif path.startswith("/api/"):
                self.json_response({"error": "not_found"}, 404)
            else:
                relative = "index.html" if path in {"", "/"} else path.lstrip("/")
                file = (APP / relative).resolve()
                if APP.resolve() not in file.parents or not file.is_file():
                    self.json_response({"error": "not_found"}, 404)
                    return
                content_type = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                self.send_body(200, file.read_bytes(), content_type, cache="public, max-age=300")
        except ValueError as error:
            self.json_response({"error": "invalid_request", "detail": str(error)}, 400)
        except LookupError:
            self.json_response({"error": "not_found"}, 404)
        except (RuntimeError, json.JSONDecodeError) as error:
            self.json_response({"error": "unavailable", "detail": str(error)}, 503)

    def log_message(self, pattern: str, *args: object) -> None:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indexer", required=True)
    parser.add_argument("--chain-id", required=True)
    parser.add_argument("--genesis-hash", required=True)
    parser.add_argument("--listen", default="127.0.0.1:18130")
    args = parser.parse_args()
    host, port_text = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    server.data = ExplorerData(args.indexer, args.chain_id, args.genesis_hash)  # type: ignore[attr-defined]
    print(
        json.dumps({
            "listen": args.listen,
            "schema": "noos/mindscan/v1",
            "chain_id": args.chain_id,
            "genesis_hash": args.genesis_hash,
        }),
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
