from __future__ import annotations

import argparse
import http.client
import http.server
import json
import socket
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
    unsafe_height = 513
    finalized_epoch = 1
    finalized_hash = "55" * 32

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        authorization = self.headers.get("Authorization")
        type(self).seen.append((self.path, authorization))
        if self.path == "/status.json":
            self._reply(
                200,
                {
                    "schema": "noos/wwm-public-testnet-monitor-sample/v1",
                    "status": "ok",
                    "checks": [
                        {
                            "name": "inference_worker",
                            "ok": True,
                            "detail": {"ready": True},
                        }
                    ],
                },
            )
            return
        if authorization != f"Bearer {self.expected_token}":
            self._reply(401, {"error": "unauthorized"})
            return
        if self.path == "/status":
            self._reply(
                200,
                {
                    "chain_id": "11" * 32,
                    "genesis_hash": "22" * 32,
                    "unsafe_head": {"height": type(self).unsafe_height, "hash": "33" * 32},
                    "justified": {"epoch": 2, "hash": "44" * 32},
                    "finalized": {
                        "epoch": type(self).finalized_epoch,
                        "hash": type(self).finalized_hash,
                    },
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


class FakeWalletService:
    def __init__(self, wallet_root: Path):
        self.wallet_root = wallet_root
        self.posts: list[tuple[str, dict, str]] = []

    @staticmethod
    def is_get_route(path: str) -> bool:
        return path == "/api/config"

    @staticmethod
    def is_post_route(path: str) -> bool:
        return path == "/api/wallet/build"

    def get(self, path: str, query: str) -> gateway.WalletReply:
        if path != "/api/config" or query:
            raise gateway.WalletError(400, "INVALID_REQUEST", "invalid wallet read")
        return gateway.WalletReply(200, {"chain_id": "11" * 32, "production": False})

    def post(self, path: str, body: dict, client: str) -> gateway.WalletReply:
        self.posts.append((path, body, client))
        return gateway.WalletReply(200, {"txid": "77" * 32})


class FakeInferenceService:
    job_id = "88" * 32

    def __init__(self):
        self.posts: list[tuple[str, dict, str, str | None]] = []
        self.closed = False

    @staticmethod
    def is_get_route(path: str) -> bool:
        return path in {
            "/api/wwm/v2/state",
            f"/api/wwm/v2/jobs/{FakeInferenceService.job_id}/stream",
            f"/api/wwm/v2/jobs/{FakeInferenceService.job_id}/receipt",
        }

    @staticmethod
    def is_post_route(path: str) -> bool:
        return path in {
            "/api/wwm/v2/quotes",
            "/api/wwm/v2/jobs",
            f"/api/wwm/v2/jobs/{FakeInferenceService.job_id}/cancel",
        }

    @staticmethod
    def is_stream_route(path: str) -> bool:
        return path.endswith("/stream")

    def get(self, path: str, query: str, client: str) -> gateway.InferenceReply:
        if path == "/api/wwm/v2/state":
            return gateway.InferenceReply(
                200,
                {
                    "schema": "noos/wwm-gateway/v2",
                    "enabled": True,
                    "client": client,
                },
            )
        return gateway.InferenceReply(
            200,
            {
                "schema": "noos/wwm-receipt/v2",
                "job_id": self.job_id,
                "terminal_status": "COMPLETED",
            },
        )

    def post(
        self,
        path: str,
        body: dict,
        client: str,
        idempotency_key: str | None,
    ) -> gateway.InferenceReply:
        self.posts.append((path, body, client, idempotency_key))
        return gateway.InferenceReply(
            202,
            {
                "schema": "noos/wwm-job/v2",
                "job_id": self.job_id,
                "status": "QUEUED",
                "replayed": False,
            },
        )

    def validate_stream(self, path: str, last_event_id: str | None) -> None:
        if path != f"/api/wwm/v2/jobs/{self.job_id}/stream" or last_event_id not in {None, "0"}:
            raise gateway.InferenceError(400, "INVALID_STREAM", "invalid fixture stream")

    def stream(self, path: str, last_event_id: str | None):
        yield {
            "id": 1,
            "type": "receipt.completed",
            "data": {
                "schema": "noos/wwm-receipt/v2",
                "job_id": self.job_id,
                "terminal_status": "COMPLETED",
            },
            "signature": "fixture-signature",
        }

    def close(self) -> None:
        self.closed = True


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
        self.wallet = self.root / "wallet"
        self.wallet.mkdir()
        (self.wallet / "index.html").write_text("<title>Harbor iPhone Wallet</title>\n", encoding="utf-8")
        self.wallet_service = FakeWalletService(self.wallet.resolve())
        self.inference_service = FakeInferenceService()
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
            monitor_url=f"http://127.0.0.1:{self.upstream.server_port}",
            site_root=self.site.resolve(),
            allowed_origins=frozenset({"https://mindchain.network", "https://wwm.mindchain.network"}),
            connect_origins=frozenset({
                "https://wwm-artifacts.mindchain.network",
                "https://wwm-rpc.mindchain.network",
            }),
            wallet_service=self.wallet_service,
            inference_service=self.inference_service,
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
        self.assertEqual(health["node_source"], "primary")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertNotIn(UpstreamHandler.expected_token.encode(), body)

        status, _, model = self.request("/api/model-resolution/bonsai-q1")
        self.assertEqual(status, 200)

        status, _, network_status = self.request("/api/network-status")
        self.assertEqual(status, 200)
        signed_sample = json.loads(network_status)
        self.assertEqual(
            signed_sample["schema"],
            "noos/wwm-public-testnet-monitor-sample/v1",
        )
        self.assertTrue(signed_sample["checks"][0]["detail"]["ready"])
        self.assertEqual(json.loads(model)["registration_state"], "ACTIVE_TESTNET")


        record_id = "66" * 32
        status, _, record = self.request(f"/api/wwm-record/job/{record_id}")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(record)["id"], record_id)
        protected_requests = [
            authorization
            for path, authorization in UpstreamHandler.seen
            if path != "/status.json"
        ]
        self.assertTrue(
            all(
                authorization == f"Bearer {UpstreamHandler.expected_token}"
                for authorization in protected_requests
            )
        )

    def test_unavailable_primary_uses_separately_authenticated_fallback(self) -> None:
        closed_listener = socket.socket()
        closed_listener.bind(("127.0.0.1", 0))
        closed_port = closed_listener.getsockname()[1]
        closed_listener.close()
        config = gateway.GatewayConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            node_rpc=f"http://127.0.0.1:{closed_port}",
            node_token="unreachable-primary-token-that-is-long-enough",
            site_root=self.site.resolve(),
            allowed_origins=frozenset(),
            connect_origins=frozenset(),
            fallback_node_rpc=f"http://127.0.0.1:{self.upstream.server_port}",
            fallback_node_token=UpstreamHandler.expected_token,
        )
        fallback_public = gateway.GatewayServer(config)
        fallback_thread = threading.Thread(target=fallback_public.serve_forever, daemon=True)
        fallback_thread.start()

        def stop_fallback() -> None:
            fallback_public.shutdown()
            fallback_public.server_close()
            fallback_thread.join(timeout=5)

        self.addCleanup(stop_fallback)
        UpstreamHandler.seen = []
        with urllib.request.urlopen(
            f"http://127.0.0.1:{fallback_public.server_port}/healthz",
            timeout=5,
        ) as response:
            self.assertEqual(response.status, 200)
            health = json.load(response)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["node_source"], "fallback")
        self.assertGreaterEqual(len(UpstreamHandler.seen), 2)
        self.assertEqual(
            set(UpstreamHandler.seen),
            {("/status", f"Bearer {UpstreamHandler.expected_token}")},
        )

    def test_reachable_but_stale_primary_keeps_fresher_fallback_selected(self) -> None:
        class StaleUpstreamHandler(UpstreamHandler):
            expected_token = "stale-primary-token-that-is-longer-than-thirty-two-bytes"
            seen: list[tuple[str, str | None]] = []
            unsafe_height = 100

        stale_upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StaleUpstreamHandler)
        stale_thread = threading.Thread(target=stale_upstream.serve_forever, daemon=True)
        stale_thread.start()

        config = gateway.GatewayConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            node_rpc=f"http://127.0.0.1:{stale_upstream.server_port}",
            node_token=StaleUpstreamHandler.expected_token,
            site_root=self.site.resolve(),
            allowed_origins=frozenset(),
            connect_origins=frozenset(),
            fallback_node_rpc=f"http://127.0.0.1:{self.upstream.server_port}",
            fallback_node_token=UpstreamHandler.expected_token,
        )
        fallback_public = gateway.GatewayServer(config)
        fallback_thread = threading.Thread(target=fallback_public.serve_forever, daemon=True)
        fallback_thread.start()

        def stop_servers() -> None:
            fallback_public.shutdown()
            fallback_public.server_close()
            fallback_thread.join(timeout=5)
            stale_upstream.shutdown()
            stale_upstream.server_close()
            stale_thread.join(timeout=5)

        self.addCleanup(stop_servers)
        UpstreamHandler.seen = []
        base = f"http://127.0.0.1:{fallback_public.server_port}"
        with urllib.request.urlopen(base + "/healthz", timeout=5) as response:
            self.assertEqual(json.load(response)["node_source"], "fallback")
        with urllib.request.urlopen(base + "/api/model-resolution/bonsai-q1", timeout=5) as response:
            self.assertEqual(json.load(response)["registration_state"], "ACTIVE_TESTNET")
        self.assertNotIn("/model-resolution/bonsai-q1", [path for path, _ in StaleUpstreamHandler.seen])
        self.assertIn("/model-resolution/bonsai-q1", [path for path, _ in UpstreamHandler.seen])

        StaleUpstreamHandler.unsafe_height = 514
        with fallback_public._selection_lock:
            fallback_public._selection_expires_at = 0
        with urllib.request.urlopen(base + "/healthz", timeout=5) as response:
            self.assertEqual(json.load(response)["node_source"], "primary")

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
        self.assertEqual(headers["Cross-Origin-Resource-Policy"], "same-site")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn(
            "connect-src 'self' https://wwm-artifacts.mindchain.network https://wwm-rpc.mindchain.network",
            headers["Content-Security-Policy"],
        )

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

    def test_scoped_wallet_routes_are_writable_without_opening_generic_gateway_writes(self) -> None:
        status, _, wallet_page = self.request("/wallet/")
        self.assertEqual(status, 200)
        self.assertIn(b"Harbor iPhone Wallet", wallet_page)

        status, _, config = self.request("/api/config")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(config)["production"])

        status, _, built = self.request(
            "/api/wallet/build",
            method="POST",
            body=b'{"amount":"1"}',
            headers={"Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.5"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(built)["txid"], "77" * 32)
        self.assertEqual(self.wallet_service.posts, [
            ("/api/wallet/build", {"amount": "1"}, "203.0.113.5")
        ])

        status, headers, _ = self.request(
            "/api/wallet/build",
            method="OPTIONS",
            headers={
                "Origin": "https://wwm.mindchain.network",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, HEAD, POST, OPTIONS")

        status, _, body = self.request(
            "/api/wallet/build",
            method="POST",
            body=b"{}",
            headers={"Content-Type": "application/json", "Origin": "https://untrusted.example"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body)["error"]["code"], "ORIGIN_NOT_ALLOWED")

    def test_scoped_public_inference_routes_support_json_sse_and_idempotency(self) -> None:
        status, _, state = self.request(
            "/api/wwm/v2/state",
            headers={"CF-Connecting-IP": "203.0.113.8"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(state)["enabled"])
        self.assertEqual(json.loads(state)["client"], "203.0.113.8")

        status, _, job = self.request(
            "/api/wwm/v2/jobs",
            method="POST",
            body=b'{"quote_id":"fixture"}',
            headers={
                "Content-Type": "application/json",
                "Idempotency-Key": "99" * 16,
                "CF-Connecting-IP": "203.0.113.8",
            },
        )
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(job)["job_id"], FakeInferenceService.job_id)
        self.assertEqual(
            self.inference_service.posts,
            [
                (
                    "/api/wwm/v2/jobs",
                    {"quote_id": "fixture"},
                    "203.0.113.8",
                    "99" * 16,
                )
            ],
        )

        status, headers, body = self.request(
            f"/api/wwm/v2/jobs/{FakeInferenceService.job_id}/stream",
            headers={"Accept": "text/event-stream", "Last-Event-ID": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream; charset=utf-8")
        self.assertIn(b"id: 1\nevent: receipt.completed\ndata: ", body)
        self.assertIn(b'"type":"receipt.completed"', body)

        status, headers, _ = self.request(
            "/api/wwm/v2/jobs",
            method="OPTIONS",
            headers={
                "Origin": "https://wwm.mindchain.network",
                "Access-Control-Request-Method": "POST",
            },
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, HEAD, POST, OPTIONS")
        self.assertIn("Idempotency-Key", headers["Access-Control-Allow-Headers"])

    def test_config_requires_loopback_origins_and_nontrivial_secret_file(self) -> None:
        arguments = argparse.Namespace(
            listen="0.0.0.0:29680",
            node_rpc="http://127.0.0.1:29652",
            node_token_file=self.token_path,
            site_root=self.site,
            allow_origin=[],
            connect_origin=[],
            fallback_node_rpc=None,
            fallback_node_token_file=None,
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
        arguments.fallback_node_rpc = "http://127.0.0.1:39652"
        with self.assertRaisesRegex(gateway.GatewayError, "configured together"):
            gateway.load_config(arguments)
        arguments.fallback_node_token_file = self.token_path
        loaded = gateway.load_config(arguments)
        self.assertEqual(loaded.fallback_node_rpc, "http://127.0.0.1:39652")
        self.assertEqual(loaded.fallback_node_token, UpstreamHandler.expected_token)
        self.assertTrue(
            gateway.NEURAL_EXPLORER_BROWSER_ORIGINS <= loaded.allowed_origins
        )
        self.assertTrue(
            gateway.NEURAL_EXPLORER_CONNECT_ORIGINS <= loaded.connect_origins
        )
        arguments.fallback_node_rpc = None
        arguments.fallback_node_token_file = None

        self.token_path.write_text(UpstreamHandler.expected_token + "\n", encoding="ascii")
        arguments.allow_origin = ["https://mindchain.network/path"]
        with self.assertRaisesRegex(gateway.GatewayError, "exact HTTPS origins"):
            gateway.load_config(arguments)

        arguments.allow_origin = []
        arguments.connect_origin = ["https://artifacts.example/path"]
        with self.assertRaisesRegex(gateway.GatewayError, "exact HTTPS origins"):
            gateway.load_config(arguments)


if __name__ == "__main__":
    unittest.main()
