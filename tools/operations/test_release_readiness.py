from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import patch

import release_readiness as readiness


REVISION = "11" * 20
TREE = "22" * 20
CHAIN_ID = "33" * 32
GENESIS_HASH = "44" * 32


class RuntimeServer:
    def __init__(self, node_height: int = 100, indexer_height: int = 99) -> None:
        node = {
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "unsafe_head": {"height": node_height, "hash": "55" * 32},
            "observer": False,
        }
        indexer = {
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "unsafe_head": {"height": indexer_height, "hash": "66" * 32},
            "ready": True,
            "readiness": "Ready",
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/status":
                    if self.headers.get("Authorization") != "Bearer token":
                        self.send_response(401)
                        self.end_headers()
                        return
                    value = node
                elif self.path == "/api/status":
                    value = indexer
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                encoded = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

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


class ReleaseReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def create_bundle(self, status: str = "CANDIDATE_ONLY") -> dict:
        contents = {
            "noosd.exe": b"validator-binary",
            "build-details.json": b"{}",
            "sbom.cdx.json": b'{"bomFormat":"CycloneDX"}',
            "provenance.intoto.jsonl": b'{"_type":"https://in-toto.io/Statement/v1"}',
        }
        for relative, value in contents.items():
            (self.bundle / relative).write_bytes(value)
        files = {relative: readiness.sha256_file(self.bundle / relative) for relative in contents}
        sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
        (self.bundle / "SHA256SUMS").write_text(sums, encoding="ascii", newline="\n")
        manifest = {
            "schema": "noos/repro-candidate-bundle/v1",
            "candidate_status": status,
            "promotion_effect": "NONE",
            "independent_builder_evidence": False,
            "source": {"revision": REVISION, "tree": TREE},
            "files": files,
            "checksums_sha256": readiness.sha256_file(self.bundle / "SHA256SUMS"),
        }
        (self.bundle / "bundle-manifest.json").write_bytes(readiness.canonical_json(manifest))
        return manifest

    def promotion_ledger(self, passed: bool) -> Path:
        state = "PASS" if passed else "BLOCKED"
        status = "SATISFIED" if passed else "UNSATISFIED"
        verdict = "PASS" if passed else "NOT_RUN"
        path = self.root / "promotion.json"
        path.write_text(json.dumps({
            "gates": [{
                "gate": "G0",
                "state": state,
                "requirements": [{
                    "requirement_id": "G0.EXAMPLE",
                    "status": status,
                    "verdict": verdict,
                }],
            }],
        }), encoding="utf-8")
        return path

    def candidate_args(self, ledger: Path) -> SimpleNamespace:
        return SimpleNamespace(
            mode="candidate",
            bundle_dir=self.bundle,
            promotion_ledger=ledger,
            upgrade_manifest=None,
            upgrade_keyring=None,
            node_rpc=None,
            node_token=None,
            indexer_url=None,
            max_indexer_lag=2,
            minimum_activation_lead=64,
            release_manifest=None,
            release_keyring=None,
            final_freeze=None,
            final_freeze_signatures=None,
            repro_assurance=None,
        )

    def test_candidate_bundle_requires_exact_hash_and_checksum_coverage(self) -> None:
        manifest = self.create_bundle()
        observed = readiness.verify_candidate_bundle(self.bundle, production=False)
        self.assertEqual(observed["files"], manifest["files"])
        (self.bundle / "noosd.exe").write_bytes(b"tampered")
        with self.assertRaisesRegex(readiness.ReadinessError, "hash mismatch"):
            readiness.verify_candidate_bundle(self.bundle, production=False)

    def test_smoke_bundle_is_explicitly_refused_for_production(self) -> None:
        self.create_bundle("SMOKE_ONLY")
        with self.assertRaisesRegex(readiness.ReadinessError, "smoke-only"):
            readiness.verify_candidate_bundle(self.bundle, production=True)

    def test_candidate_report_is_ready_without_misrepresenting_blocked_promotion(self) -> None:
        self.create_bundle()
        args = self.candidate_args(self.promotion_ledger(False))
        with patch.object(readiness, "git_source_state", return_value={"revision": REVISION, "tree": TREE, "clean": True}):
            code, report = readiness.assess(args)
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "CANDIDATE_READY")
        self.assertEqual(report["checks"]["promotion"]["status"], "BLOCKED")
        self.assertEqual(report["checks"]["runtime"]["status"], "NOT_REQUESTED")

    def test_production_promotion_requires_every_gate_and_requirement(self) -> None:
        blocked = readiness.verify_promotion_ledger(self.promotion_ledger(False))
        self.assertFalse(blocked["pass"])
        self.assertEqual(blocked["blocked"], ["G0.EXAMPLE", "G0:BLOCKED"])
        passed = readiness.verify_promotion_ledger(self.promotion_ledger(True))
        self.assertTrue(passed["pass"])

    def test_runtime_requires_same_identity_readiness_and_bounded_lag(self) -> None:
        server = RuntimeServer()
        try:
            result = readiness.verify_runtime(
                server.address,
                "token",
                f"http://{server.address}",
                CHAIN_ID,
                GENESIS_HASH,
                2,
            )
            self.assertEqual(result["indexer_lag"], 1)
            with self.assertRaisesRegex(readiness.ReadinessError, "exceeds limit"):
                readiness.verify_runtime(
                    server.address,
                    "token",
                    f"http://{server.address}",
                    CHAIN_ID,
                    GENESIS_HASH,
                    0,
                )
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
