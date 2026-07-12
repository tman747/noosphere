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
    def __init__(self, indexer: str):
        parsed = urllib.parse.urlsplit(indexer)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("indexer URL must be an absolute HTTP(S) origin")
        self.indexer = indexer.rstrip("/")

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
        return self.get("/api/status")

    def blocks(self, limit: int) -> dict[str, Any]:
        if not 1 <= limit <= 50:
            raise ValueError("limit must be 1..50")
        return self.get(f"/api/v1/blocks?limit={limit}")

    def block(self, identifier: str) -> dict[str, Any]:
        if not (HASH.fullmatch(identifier) or HEIGHT.fullmatch(identifier)):
            raise ValueError("invalid block identifier")
        return self.get("/api/v1/blocks/" + identifier)

    def transaction(self, txid: str) -> dict[str, Any]:
        if not HASH.fullmatch(txid):
            raise ValueError("invalid transaction identifier")
        return self.get("/api/v1/transactions/" + txid)


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
                self.json_response({"ok": True, "schema": "noos/mindscan-health/v1"})
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
    parser.add_argument("--listen", default="127.0.0.1:18130")
    args = parser.parse_args()
    host, port_text = args.listen.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port_text)), Handler)
    server.data = ExplorerData(args.indexer)  # type: ignore[attr-defined]
    print(json.dumps({"listen": args.listen, "schema": "noos/mindscan/v1"}), flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
