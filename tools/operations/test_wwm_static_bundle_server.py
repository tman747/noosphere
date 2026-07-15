from __future__ import annotations

import argparse
import http.server
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tools.operations import wwm_static_bundle_server as static_host


class StaticBundleServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "bundle"
        (self.root / ".well-known" / "noos").mkdir(parents=True)
        (self.root / "shares" / "000000").mkdir(parents=True)
        self.origin = "https://artifacts.test"
        self.share = bytes((index % 251 for index in range(static_host.SHARE_BYTES)))
        (self.root / "shares" / "000000" / "00.share").write_bytes(self.share)
        (self.root / "LICENSE.txt").write_text("license\n", encoding="utf-8")
        (self.root / "NOTICE.txt").write_text("notice\n", encoding="utf-8")
        manifest = {
            "canonical_origin": self.origin,
            "expires_at": 2_000_000_000,
            "inventory": {"url": self.origin + static_host.INVENTORY_PATH},
        }
        inventory = {
            "canonical_origin": self.origin,
            "rows": [
                {
                    "stripe": 0,
                    "position": 0,
                    "bytes": static_host.SHARE_BYTES,
                    "url": self.origin + "/shares/000000/00.share",
                }
            ],
        }
        (self.root / ".well-known" / "noos" / "wwm-web-capacity-v1.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (self.root / "inventory-v1.json").write_text(json.dumps(inventory), encoding="utf-8")
        self.config = static_host.load_config(
            argparse.Namespace(listen="127.0.0.1:29681", bundle_root=self.root, origin=self.origin)
        )
        self.config = static_host.StaticHostConfig(
            listen_host=self.config.listen_host,
            listen_port=0,
            bundle_root=self.config.bundle_root,
            canonical_origin=self.config.canonical_origin,
            share_count=self.config.share_count,
            share_bytes=self.config.share_bytes,
            expires_at=self.config.expires_at,
        )
        self.server = static_host.StaticHostServer(self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

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

    def test_health_and_static_metadata_are_non_production_and_cors_readable(self) -> None:
        status, headers, body = self.request("/healthz")
        self.assertEqual(status, 200)
        health = json.loads(body)
        self.assertFalse(health["production"])
        self.assertFalse(health["production_custody"])
        self.assertEqual(health["share_count"], 1)
        self.assertEqual(health["share_bytes"], static_host.SHARE_BYTES)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")

        status, headers, manifest = self.request(static_host.HOST_MANIFEST_PATH)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(manifest)["canonical_origin"], self.origin)
        self.assertEqual(headers["Cache-Control"], "public, max-age=60, must-revalidate")
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")
        self.assertNotIn("Content-Encoding", headers)

        status, headers, body = self.request(
            static_host.INVENTORY_PATH,
            method="OPTIONS",
            headers={"Access-Control-Request-Method": "GET"},
        )
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Access-Control-Allow-Methods"], "GET, HEAD, OPTIONS")

    def test_share_get_head_and_single_range_match_static_transport_contract(self) -> None:
        route = "/shares/000000/00.share"
        status, headers, body = self.request(route, method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Length"], str(static_host.SHARE_BYTES))
        self.assertEqual(headers["Accept-Ranges"], "bytes")
        self.assertIn("immutable", headers["Cache-Control"])

        status, headers, body = self.request(route, headers={"Range": "bytes=100-199"})
        self.assertEqual(status, 206)
        self.assertEqual(headers["Content-Range"], f"bytes 100-199/{static_host.SHARE_BYTES}")
        self.assertEqual(headers["Content-Length"], "100")
        self.assertEqual(body, self.share[100:200])

        status, headers, body = self.request(route, headers={"Range": "bytes=9999999-"})
        self.assertEqual(status, 416)
        self.assertEqual(headers["Content-Range"], f"bytes */{static_host.SHARE_BYTES}")
        self.assertEqual(json.loads(body)["error"]["code"], "RANGE_NOT_SATISFIABLE")

    def test_paths_and_mutations_fail_closed_and_config_rejects_origin_mismatch(self) -> None:
        status, headers, body = self.request("/shares/../../LICENSE.txt")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"]["code"], "NOT_FOUND")

        status, headers, body = self.request("/inventory-v1.json", method="POST", body=b"{}")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Connection"], "close")
        self.assertEqual(json.loads(body)["error"]["code"], "METHOD_NOT_ALLOWED")

        with self.assertRaisesRegex(static_host.StaticHostError, "canonical origin"):
            static_host.load_config(
                argparse.Namespace(
                    listen="127.0.0.1:29681",
                    bundle_root=self.root,
                    origin="https://wrong.test",
                )
            )
        with self.assertRaisesRegex(static_host.StaticHostError, "loopback"):
            static_host.load_config(
                argparse.Namespace(
                    listen="0.0.0.0:29681",
                    bundle_root=self.root,
                    origin=self.origin,
                )
            )


if __name__ == "__main__":
    unittest.main()
