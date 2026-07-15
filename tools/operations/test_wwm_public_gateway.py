from __future__ import annotations

import argparse
import http.client
import http.server
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tools.operations import wwm_public_gateway as gateway


class UpstreamHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    expected_token = "fixture-token-that-is-longer-than-thirty-two-bytes"
    seen: list[tuple[str, str | None]] = []

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        authorization = self.headers.get("Authorization")
        type(self).seen.append((self.path, authorization))
        if authorization != f"Bearer {self.expected_token}":
            self._reply(401, {"error": "unauthorized"})
            return
        if self.path == "/status":
            self._reply(
                200,
                {
                    "chain_id": "11" * 32,
                    "genesis_hash": "22" * 32,
                    "unsafe_head": {"height": 513, "hash": "33" * 32},
                    "justified": {"epoch": 2, "hash": "44" * 32},
                    "finalized": {"epoch": 1, "hash": "55" * 32},
                },
            )
            return
        if self.path == "/model-resolution/bonsai-q1":
            self._reply(200, {"registration_state": "ACTIVE_TESTNET", "production_effect": "NONE"})
            return
        if self.path == f"/wwm-record/job/{'66' * 32}":
            self._reply(200, {"kind": "job", "id": "66" * 32})
            return
        self._reply(404, {"error": "not_found"})

    def _reply(self, status: int, value: object) -> None:
        body = gateway.canonical_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PublicGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        UpstreamHandler.seen = []
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.site = self.root / "site"
        self.site.mkdir()
        (self.site / "query.html").write_text("<title>MindChain WWM</title>\n", encoding="utf-8")
        (self.site / "app.js").write_text("globalThis.mindchain = true;\n", encoding="utf-8")
        self.token_path = self.root / "rpc-token.txt"
        self.token_path.write_text(UpstreamHandler.expected_token + "\n", encoding="ascii")

        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
        self.upstream_thread = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self.upstream_thread.start()
        self.addCleanup(self._stop_upstream)

        config = gateway.GatewayConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            node_rpc=f"http://127.0.0.1:{self.upstream.server_port}",
            node_token=UpstreamHandler.expected_token,
            site_root=self.site.resolve(),
            allowed_origins=frozenset({"https://mindchain.network", "https://wwm.mindchain.network"}),
        )
        self.public = gateway.GatewayServer(config)
        self.public_thread = threading.Thread(target=self.public.serve_forever, daemon=True)
        self.public_thread.start()
        self.addCleanup(self._stop_public)
        self.base = f"http://127.0.0.1:{self.public.server_port}"

    def _stop_upstream(self) -> None:
        self.upstream.shutdown()
        self.upstream.server_close()
        self.upstream_thread.join(timeout=5)

    def _stop_public(self) -> None:
        self.public.shutdown()
        self.public.server_close()
        self.public_thread.join(timeout=5)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            self.base + path,
            data=body,
            headers=headers or {},
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers.items()), error.read()

    def test_health_and_read_routes_are_testnet_only_and_inject_private_auth(self) -> None:
        status, headers, body = self.request("/healthz")
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["environment"], "public-testnet")
        self.assertFalse(health["production"])
        self.assertEqual(health["promotion_effect"], "NONE")
        self.assertEqual(health["finalized"]["epoch"], 1)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn(UpstreamHandler.expected_token.encode(), body)

        status, _, model = self.request("/api/model-resolution/bonsai-q1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(model)["registration_state"], "ACTIVE_TESTNET")

        record_id = "66" * 32
        status, _, record = self.request(f"/api/wwm-record/job/{record_id}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(record)["id"], record_id)
        self.assertTrue(
            all(auth == f"Bearer {UpstreamHandler.expected_token}" for _, auth in UpstreamHandler.seen)
        )

    def test_gateway_is_read_only_and_static_paths_are_bounded_to_site_root(self) -> None:
        status, _, body = self.request("/api/status", method="POST")
        self.assertEqual(status, 405)
        self.assertEqual(json.loads(body)["error"]["code"], "METHOD_NOT_ALLOWED")
        self.assertEqual(UpstreamHandler.seen, [])

        status, _, index = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn(b"MindChain WWM", index)

        status, headers, javascript = self.request("/app.js")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "public, max-age=300")
        self.assertIn(b"mindchain", javascript)

        status, _, body = self.request("/../rpc-token.txt")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"]["code"], "NOT_FOUND")
        self.assertNotIn(UpstreamHandler.expected_token.encode(), body)

    def test_cors_is_exact_and_rejected_writes_close_the_connection(self) -> None:
        status, headers, _ = self.request(
            "/api/status",
            headers={"Origin": "https://mindchain.network"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://mindchain.network")
        self.assertEqual(headers["Vary"], "Origin")
        self.assertEqual(headers["Strict-Transport-Security"], "max-age=31536000; includeSubDomains")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

        status, _, body = self.request(
            "/api/status",
            headers={"Origin": "https://untrusted.example"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["code"], "ORIGIN_NOT_ALLOWED")

        status, headers, body = self.request(
            "/api/status",
            method="OPTIONS",
            headers={
                "Origin": "https://wwm.mindchain.network",
                "Access-Control-Request-Method": "GET",
            },
        )
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://wwm.mindchain.network")
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, HEAD, OPTIONS")

        connection = http.client.HTTPConnection("127.0.0.1", self.public.server_port, timeout=5)
        self.addCleanup(connection.close)
        connection.request("POST", "/api/status", body=b"{}")
        rejected = connection.getresponse()
        self.assertEqual(rejected.status, 405)
        self.assertEqual(rejected.getheader("Connection"), "close")
        rejected.read()
        connection.request("GET", "/api/status")
        resumed = connection.getresponse()
        self.assertEqual(resumed.status, 200)
        resumed.read()

    def test_config_requires_loopback_origins_and_nontrivial_secret_file(self) -> None:
        arguments = argparse.Namespace(
            listen="0.0.0.0:29680",
            node_rpc="http://127.0.0.1:29652",
            node_token_file=self.token_path,
            site_root=self.site,
            allow_origin=[],
        )
        with self.assertRaisesRegex(gateway.GatewayError, "loopback"):
            gateway.load_config(arguments)

        arguments.listen = "127.0.0.1:29680"
        arguments.node_rpc = "https://rpc.example"
        with self.assertRaisesRegex(gateway.GatewayError, "loopback HTTP"):
            gateway.load_config(arguments)

        arguments.node_rpc = "http://127.0.0.1:29652"
        self.token_path.write_text("short\n", encoding="ascii")
        with self.assertRaisesRegex(gateway.GatewayError, "invalid token"):
            gateway.load_config(arguments)

        self.token_path.write_text(UpstreamHandler.expected_token + "\n", encoding="ascii")
        arguments.allow_origin = ["https://mindchain.network/path"]
        with self.assertRaisesRegex(gateway.GatewayError, "exact HTTPS origins"):
            gateway.load_config(arguments)


if __name__ == "__main__":
    unittest.main()
