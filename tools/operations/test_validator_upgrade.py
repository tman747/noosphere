from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import validator_upgrade as upgrade


CHAIN_ID = "11" * 32
GENESIS_HASH = "22" * 32


class StatusServer:
    def __init__(self, height: int = 10) -> None:
        body = json.dumps({
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "unsafe_head": {"height": height, "hash": "33" * 32},
        }).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/status" or self.headers.get("Authorization") != "Bearer token":
                    self.send_response(401)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def address(self) -> str:
        host, port = self.server.server_address
        return f"{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class ValidatorUpgradeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.install = self.root / "install"
        self.state = self.root / "state"
        self.data = self.root / "data"
        for path in (self.source, self.install, self.state, self.data):
            path.mkdir()
        (self.data / "ledger.bin").write_bytes(b"durable-ledger")
        installed = self.install / "bin" / "noosd.py"
        installed.parent.mkdir()
        installed.write_text("print('noosd 1.0.0')\n", encoding="utf-8")
        self.hook = self.root / "hook.py"
        self.hook.write_text(
            "from pathlib import Path\n"
            "import sys\n"
            "Path(sys.argv[2]).write_text(sys.argv[1], encoding='utf-8')\n",
            encoding="utf-8",
        )
        self.server = StatusServer()
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        self.keyring = {
            "schema": upgrade.KEYRING_SCHEMA,
            "keys": {"operator-2026": public},
        }

    def tearDown(self) -> None:
        self.server.close()
        self.temp.cleanup()

    def manifest(self, version: str = "2.0.0") -> dict:
        binary = self.source / "noosd.py"
        binary.write_text(f"import sys\nprint('noosd {version}')\n", encoding="utf-8")
        marker = self.root / "service-state"
        command = lambda action: [sys.executable, str(self.hook), action, str(marker)]
        value = {
            "schema": upgrade.MANIFEST_SCHEMA,
            "release_id": "release-2.0.0",
            "release_version": "2.0.0",
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "activation_height": 100,
            "throughput": {
                "produce_interval_ms": 100,
                "template_byte_budget": 900_000,
                "template_max_transactions": 4_096,
            },
            "restart_buffer_blocks": 12,
            "artifacts": {"noosd.py": upgrade.sha256_file(binary)},
            "binary": {"artifact": "noosd.py", "install_path": "bin/noosd.py"},
            "drain_command": command("drained"),
            "stop_command": command("stopped"),
            "start_command": command("started"),
            "version_command": [sys.executable, "{install_path}", "--version"],
            "signatures": [],
        }
        signature = self.key.sign(upgrade.DOMAIN + upgrade.canonical_json(value)).hex()
        value["signatures"] = [{
            "role": "release-operator",
            "key_id": "operator-2026",
            "signature_ed25519_hex": signature,
        }]
        return value

    def prepare(self, manifest: dict) -> dict:
        upgrade.verify_manifest(manifest, self.keyring)
        return upgrade.prepare(
            manifest,
            self.source,
            self.install,
            self.state,
            self.server.address,
            "token",
        )

    def test_signed_prepare_binds_identity_height_and_artifact_bytes(self) -> None:
        manifest = self.manifest()
        journal = self.prepare(manifest)
        self.assertEqual(journal["phase"], "PREPARED")
        self.assertEqual(journal["prepared_at_height"], 10)
        self.assertEqual(journal["throughput"]["produce_interval_ms"], 100)
        staged = Path(journal["release_dir"]) / "noosd.py"
        self.assertEqual(upgrade.sha256_file(staged), manifest["artifacts"]["noosd.py"])
        persisted = upgrade.read_json(upgrade.journal_path(self.state, manifest["release_id"]))
        self.assertEqual(persisted["manifest_sha256"], journal["manifest_sha256"])

    def test_manifest_tampering_and_path_escape_fail_before_staging(self) -> None:
        manifest = self.manifest()
        manifest["activation_height"] = 101
        with self.assertRaisesRegex(upgrade.UpgradeError, "signature verification"):
            upgrade.verify_manifest(manifest, self.keyring)

        manifest = self.manifest()
        manifest["artifacts"] = {"../noosd.py": manifest["artifacts"]["noosd.py"]}
        manifest["binary"]["artifact"] = "../noosd.py"
        unsigned = upgrade.unsigned_manifest(manifest)
        manifest["signatures"][0]["signature_ed25519_hex"] = self.key.sign(
            upgrade.DOMAIN + upgrade.canonical_json(unsigned)
        ).hex()
        upgrade.verify_manifest(manifest, self.keyring)
        with self.assertRaisesRegex(upgrade.UpgradeError, "escapes managed root"):
            upgrade.prepare(
                manifest, self.source, self.install, self.state, self.server.address, "token"
            )

    def test_activation_snapshots_installs_checks_version_and_becomes_active(self) -> None:
        manifest = self.manifest()
        installed = self.install / "bin" / "noosd.py"
        self.prepare(manifest)
        journal = upgrade.activate(
            manifest,
            self.install,
            self.data,
            self.state,
            self.server.address,
            "token",
            2,
        )
        self.assertEqual(journal["phase"], "ACTIVE")
        self.assertEqual(upgrade.sha256_file(installed), manifest["artifacts"]["noosd.py"])
        self.assertTrue(Path(journal["snapshot_path"]).is_file())
        self.assertEqual((self.root / "service-state").read_text("utf-8"), "started")

    def test_failed_version_check_restores_prior_binary_and_records_rollback(self) -> None:
        manifest = self.manifest(version="wrong-version")
        installed = self.install / "bin" / "noosd.py"
        old_bytes = b"print('noosd 1.0.0')\n"
        installed.write_bytes(old_bytes)
        self.prepare(manifest)
        with self.assertRaisesRegex(upgrade.UpgradeError, "rolled back"):
            upgrade.activate(
                manifest,
                self.install,
                self.data,
                self.state,
                self.server.address,
                "token",
                2,
            )
        self.assertEqual(installed.read_bytes(), old_bytes)
        journal = upgrade.read_json(upgrade.journal_path(self.state, manifest["release_id"]))
        self.assertEqual(journal["phase"], "ROLLED_BACK")
        self.assertIn("version", journal["rollback_reason"])


if __name__ == "__main__":
    unittest.main()
