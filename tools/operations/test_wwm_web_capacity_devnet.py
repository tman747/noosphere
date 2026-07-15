from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "operations" / "wwm_web_capacity_devnet.py"
SPEC = importlib.util.spec_from_file_location("wwm_web_capacity_devnet", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
smoke = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = smoke
SPEC.loader.exec_module(smoke)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def create_tls(root: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WWM loopback test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = root / "leaf.pem"
    key_path = root / "leaf-key.pem"
    ca_path = root / "ca.pem"
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path, ca_path


def make_bundle(root: Path, origin: str, chain: dict[str, str], share_seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = []
    for stripe in range(2):
        share = bytes([(share_seed + stripe) % 256]) * smoke.SHARE_BYTES
        share_path = root / "shares" / f"{stripe:06d}" / "00.share"
        share_path.parent.mkdir(parents=True, exist_ok=True)
        share_path.write_bytes(share)
        rows.append(
            {
                "stripe": stripe,
                "position": 0,
                "bytes": smoke.SHARE_BYTES,
                "transport_sha256": hashlib.sha256(share).hexdigest(),
                "protocol_share_digest": f"{share_seed + stripe:02x}" * 32,
                "probe_root": f"{share_seed + stripe + 2:02x}" * 32,
                "url": f"{origin}/shares/{stripe:06d}/00.share",
            }
        )
    inventory = {
        "schema": smoke.WEB_SCHEMA,
        "record_kind": "STATIC_INVENTORY",
        "canonical_origin": origin,
        "chain_binding": chain,
        "generated_at": int(time.time()) - 1,
        "expires_at": int(time.time()) + 3600,
        "rows": rows,
        "inventory_root": f"{share_seed + 4:02x}" * 32,
    }
    inventory_raw = canonical(inventory)
    (root / "inventory-v1.json").write_bytes(inventory_raw)
    (root / "LICENSE.txt").write_text("fixture license", encoding="utf-8")
    (root / "NOTICE.txt").write_text("fixture notice", encoding="utf-8")
    manifest = {
        "schema": smoke.WEB_SCHEMA,
        "record_kind": "STATIC_HOST_MANIFEST",
        "participant_class": "STATIC_HOST_SEEDER",
        "admission_class": "StatelessReissueable",
        "canonical_origin": origin,
        "chain_binding": chain,
        "host_signing_key": "11" * 32,
        "valid_from": inventory["generated_at"],
        "expires_at": inventory["expires_at"],
        "revocation_url": f"{origin}/.well-known/noos/wwm-web-capacity-v1.json",
        "inventory": {
            "url": f"{origin}/inventory-v1.json",
            "bytes": len(inventory_raw),
            "sha256": hashlib.sha256(inventory_raw).hexdigest(),
            "inventory_root": inventory["inventory_root"],
        },
        "license": {
            "spdx": "Apache-2.0",
            "license_url": f"{origin}/LICENSE.txt",
            "license_sha256": hashlib.sha256(b"fixture license").hexdigest(),
            "notice_url": f"{origin}/NOTICE.txt",
            "notice_sha256": hashlib.sha256(b"fixture notice").hexdigest(),
        },
        "transport_policy": {
            "cors_allow_origin": "*",
            "credentials": "omit",
            "redirects": "reject",
            "range_requests": True,
            "immutable_cache": True,
            "content_encoding": "identity",
        },
        "production_custody": False,
        "rewards": False,
        "signature": {
            "suite": "Ed25519",
            "domain": "NOOS/SIG/WWM-WEB-HOST-MANIFEST/V1",
            "public_key": "11" * 32,
            "signature": "22" * 64,
        },
    }
    manifest_path = root / ".well-known" / "noos" / "wwm-web-capacity-v1.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(canonical(manifest))
    return manifest, inventory


class FakeCoordinator:
    def __init__(self, rows: list[dict[str, Any]], quarantine: Path):
        self.rows = []
        for row in rows:
            assigned = dict(row)
            assigned["source_origin"] = assigned["url"].split("/shares/", 1)[0]
            self.rows.append(assigned)
        self.row = self.rows[0]
        self.quarantine = quarantine
        self.registered: list[str] = []
        self.valid_restores = 0
        self.corrupt_restores = 0
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/api/wwm-web-capacity/v1/config":
                    self.send_error(404); return
                self.reply(200, {"schema": smoke.WEB_SCHEMA, "record_kind": "COORDINATOR_CONFIG", "chain_binding": parent.chain, "geometry": {"source_bytes": 2, "encoded_bytes": 2 * smoke.SHARE_BYTES, "stripes": 2, "positions": 12, "reconstruction_threshold": 8, "schedulable_minimum": 9, "share_bytes": smoke.SHARE_BYTES, "position_bytes": 2 * smoke.SHARE_BYTES, "coordinate_count": 24}, "coordinator_key": "77" * 32, "production_custody": False, "rewards": False})

            def do_POST(self) -> None:  # noqa: N802
                body = self.json_body()
                if self.path.endswith("/hosts"):
                    parent.registered.append(body["canonical_origin"])
                    self.reply(201, {"schema": smoke.WEB_SCHEMA, "record_kind": "HOST_REGISTRATION_RESPONSE", "canonical_origin": body["canonical_origin"], "host_id": "33" * 32, "participant_class": "STATIC_HOST_SEEDER", "admission_class": "StatelessReissueable", "inventory_root": "44" * 32, "verified_rows": 2, "expires_at": int(time.time()) + 3600, "production_custody": False, "rewards": False}); return
                if self.path.endswith("/offers"):
                    self.reply(201, {"schema": smoke.WEB_SCHEMA, "record_kind": "BROWSER_SESSION", "participant_class": "BROWSER_ADVISORY_CACHE", "admission_class": "ChorusAdvisory", "session_token": "a" * 64, "participant_id": "55" * 32, "canonical_origin": body["canonical_origin"], "quota_shares": 256, "effective_bytes": 256 * smoke.SHARE_BYTES, "storage_class": "OPFS", "upload_policy": body["upload_policy"], "issued_at": int(time.time()), "expires_at": int(time.time()) + 3600, "production_custody": False, "rewards": False}); return
                if self.path.endswith("/heartbeat"):
                    self.reply(200, {"schema": smoke.WEB_SCHEMA, "record_kind": "HEARTBEAT_RESPONSE", "server_time": int(time.time()), "assignment": {"schema": smoke.WEB_SCHEMA, "record_kind": "SHARE_ASSIGNMENT", "assignment_id": "66" * 32, "participant_id": "55" * 32, "canonical_origin": body["canonical_origin"], "chain_binding": parent.chain, "issued_at": int(time.time()), "expires_at": int(time.time()) + 300, "rows": parent.rows, "signature": {"suite": "Ed25519", "domain": "NOOS/SIG/WWM-WEB-ASSIGNMENT/V1", "public_key": "77" * 32, "signature": "88" * 64}}, "restore_task": None}); return
                self.send_error(404)

            def do_PUT(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                if hashlib.sha256(body).hexdigest() not in {row["transport_sha256"] for row in parent.rows}:
                    parent.corrupt_restores += 1
                    self.reply(422, {"error": "CANONICAL_VERIFICATION_FAILED"}); return
                parent.quarantine.mkdir(parents=True, exist_ok=True)
                (parent.quarantine / f"restore-{parent.valid_restores}.share").write_bytes(body)
                parent.valid_restores += 1
                self.reply(201, {"schema": smoke.WEB_SCHEMA, "record_kind": "RESTORE_RECEIPT", "task_id": self.path.rsplit("/", 1)[-1], "coordinate_digest": "99" * 32, "bytes": smoke.SHARE_BYTES, "quarantine_id": "aa" * 32, "canonical_verified": True, "accepted_at": int(time.time())})

            def json_body(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0"))
                return json.loads(self.rfile.read(length))

            def reply(self, status: int, value: dict[str, Any]) -> None:
                data = canonical(value)
                self.send_response(status)
                self.send_header("Content-Type", smoke.MEDIA_TYPE)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.chain: dict[str, str] = {}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> "FakeCoordinator":
        self.thread.start(); return self

    def __exit__(self, *_args: Any) -> None:
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)


class MultiOriginDevnetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"; self.workspace.mkdir()
        self.store = self.root / "store"; self.store.mkdir()
        self.consensus = self.root / "consensus"; self.consensus.mkdir()
        self.quarantine = self.root / "quarantine"; self.quarantine.mkdir()
        self.replacement = self.root / "replacement"; self.replacement.mkdir()
        self.replacement_consensus = self.root / "replacement-consensus"; self.replacement_consensus.mkdir()
        self.cert, self.key, self.ca = create_tls(self.root)
        self.chain = {"chain_id": "01" * 32, "genesis_hash": "02" * 32, "artifact_id": "03" * 32, "manifest_root": "04" * 32}
        self.origin_values = [f"https://127.0.0.1:{free_port()}", f"https://127.0.0.1:{free_port()}"]
        self.bundles = []
        self.inventories = []
        for index, origin in enumerate(self.origin_values):
            root = self.root / f"bundle-{index}"
            _, inventory = make_bundle(root, origin, self.chain, 16 + index * 8)
            self.bundles.append(root); self.inventories.append(inventory)
        self.fake_cli = self.root / "fake_cli.py"
        self.fake_cli.write_text(
            """import hashlib
import json
import pathlib
import sys
import time

args = sys.argv[1:]
command = args[0]
if command == "verify-web-bundle":
    print(json.dumps({"schema": "fixture", "signature_verified": True, "noos_da_verified": True, "production_custody": False, "rewards": False}))
elif command == "export-restored-position":
    output = pathlib.Path(args[args.index("--output") + 1])
    value = {
        "schema": "noos/wwm-web-capacity/v1",
        "record_kind": "WEB_RESTORED_POSITION_IMPORT_INDEX",
        "coordinator_public_key": "77" * 32,
        "chain_binding": {"chain_id": "01" * 32, "genesis_hash": "02" * 32, "artifact_id": "03" * 32, "manifest_root": "04" * 32},
        "target_position": int(args[args.index("--position") + 1]),
        "generated_at": int(time.time()),
        "expires_at": int(args[args.index("--expires-at") + 1]),
        "rows": [{}, {}],
        "signature": {"suite": "Ed25519", "domain": "NOOS/SIG/WWM-WEB-RESTORE-IMPORT-INDEX/V1", "public_key": "77" * 32, "signature": "88" * 64},
    }
    output.write_text(json.dumps(value))
    print("wrote signed test index")
elif command == "import-web-restored-position":
    report = pathlib.Path(args[args.index("--report") + 1])
    value = {"schema": "fixture-import", "production_custody": False, "availability_certificate_effect": False, "rewards": False, "insert_once": True}
    report.write_text(json.dumps(value))
    print(json.dumps(value))
elif command == "queue-restore":
    request_path = pathlib.Path(args[args.index("--request") + 1])
    request = json.loads(request_path.read_text())
    task = {
        "schema": "noos/wwm-web-capacity/v1",
        "record_kind": "RESTORE_TASK",
        "task_id": hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "participant_id": "55" * 32,
        "canonical_origin": request["canonical_origin"],
        "chain_binding": {"chain_id": "01" * 32, "genesis_hash": "02" * 32, "artifact_id": "03" * 32, "manifest_root": "04" * 32},
        "coordinate": request["coordinate"],
        "expected_bytes": 1047552,
        "issued_at": int(time.time()),
        "expires_at": request["expires_at"],
        "signature": {"suite": "Ed25519", "domain": "NOOS/SIG/WWM-WEB-RESTORE-TASK/V1", "public_key": "77" * 32, "signature": "88" * 64},
    }
    value = {"schema": "noos/wwm-web-capacity/v1", "record_kind": "QUEUE_RESTORE_REPORT", "task": task, "source_origin": request["source_origin"], "production_custody": False, "rewards": False, "insert_once": True}
    pathlib.Path(args[args.index("--report") + 1]).write_text(json.dumps(value))
    print("queued signed test restore")
elif command == "release-restored-position":
    report = pathlib.Path(args[args.index("--report") + 1])
    value = {"schema": "fixture-release", "artifact_id": "03" * 32, "manifest_root": "04" * 32, "import_index_sha256": "99" * 32, "target_position": 0, "released_share_count": 2, "released_bytes": 2 * 1047552, "released_at": int(time.time()), "production_custody": False, "availability_certificate_effect": False, "rewards": False, "insert_once": True}
    report.write_text(json.dumps(value))
    print("released signed test position")
else:
    raise SystemExit(2)
""",
            encoding="utf-8",
        )
        self.coordinator_config = self.root / "coordinator.json"; self.coordinator_config.write_text("{}", encoding="utf-8")
        self.index_path = self.root / "signed-index.json"
        self.seed_name = "WWM_MULTI_ORIGIN_TEST_SEED"; os.environ[self.seed_name] = "ab" * 32

    def tearDown(self) -> None:
        os.environ.pop(self.seed_name, None)
        self.temporary.cleanup()

    def config_document(self, coordinator_url: str, *, import_enabled: bool = False) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema": smoke.SCHEMA,
            "activation_scope": "OWNER_CONTROLLED_LOOPBACK_DEVNET",
            "production": False,
            "rewards": False,
            "production_custody": False,
            "availability_certificate_effect": False,
            "public_scanning": False,
            "default_upload": False,
            "workspace_root": str(self.workspace),
            "run_root": str(self.workspace / "run-once"),
            "evidence_path": str(self.root / "evidence.json"),
            "tls_certificate": str(self.cert),
            "tls_private_key": str(self.key),
            "tls_ca_certificate": str(self.ca),
            "coordinator_url": coordinator_url,
            "coordinator_config": str(self.coordinator_config),
            "mutation_origin": f"https://127.0.0.1:{free_port()}",
            "consent_version": "fixture-consent-v1",
            "evidence_signing_seed_env": self.seed_name,
            "chain_binding": self.chain,
            "artifact_store": {"store_root": str(self.store), "consensus_root": str(self.consensus), "quota_bytes": 20_000_000},
            "commands": {"artifact_service": [sys.executable, str(self.fake_cli)], "coordinator": [sys.executable, str(self.fake_cli)]},
            "manage_coordinator_process": False,
            "origins": [
                {"origin": origin, "bundle_root": str(bundle), "operator_authorized": True, "provider": f"provider-{index}", "region": f"region-{index}", "failure_domain": f"failure-{index}"}
                for index, (origin, bundle) in enumerate(zip(self.origin_values, self.bundles, strict=True))
            ],
            "browser_restore_upload_opt_in": True,
            "corruption_rejection_probe": True,
        }
        if import_enabled:
            document["artifact_import"] = {"enabled": True, "quarantine_root": str(self.quarantine), "index_path": str(self.index_path), "target_position": 0, "coordinator_public_key": "77" * 32, "replacement_root": str(self.replacement), "replacement_consensus_root": str(self.replacement_consensus), "replacement_quota_bytes": 20_000_000, "report_path": str(self.root / "import-report.json"), "release_report_path": str(self.root / "release-report.json")}
        return document

    def write_config(self, document: dict[str, Any]) -> Path:
        coordinator_document = {
            "activation_scope": "EXPERIMENTAL_TEST_ONLY",
            "experiment_state": "LOCAL_FIXTURE",
            "production": False,
            "rewards": False,
            "listen": "127.0.0.1:9770",
            "loopback_test_transport": {
                "enabled": True,
                "ca_certificate_path": str(self.ca),
                "full_position_repair": "artifact_import" in document,
            },
            "source_allowlist": [
                {
                    "origin": row["origin"],
                    "provider": row["provider"],
                    "region": row["region"],
                    "control_cluster": row["failure_domain"],
                }
                for row in document["origins"]
            ],
            "registered_origins": [document["mutation_origin"]],
            "max_quarantine_bytes": 475_588_608 if "artifact_import" in document else 268_173_312,
            "rate_limit_per_minute": 10_000 if "artifact_import" in document else 60,
            "restore_lifetime_seconds": smoke.FULL_POSITION_RESTORE_LIFETIME_SECONDS,
            "isolation": {
                "validator_key_path": None,
                "consensus_store_path": None,
                "model_execution_path": None,
                "authority_to_issue_custody_certificates": False,
            },
        }
        self.coordinator_config.write_bytes(canonical(coordinator_document))
        path = self.root / "config.json"
        path.write_bytes(canonical(document))
        return path

    def test_validate_only_proves_distinct_authorized_https_origins_without_mutation(self) -> None:
        config_path = self.write_config(self.config_document(f"http://127.0.0.1:{free_port()}"))
        code = smoke.main(["--config", str(config_path), "--validate-only"])
        self.assertEqual(code, 0)
        self.assertFalse((self.workspace / "run-once").exists())
        self.assertFalse((self.root / "evidence.json").exists())
        config = smoke.validate_config(config_path)
        reports = smoke.verify_bundles(config)
        self.assertEqual([row["origin"] for row in reports], self.origin_values)
        self.assertEqual({row["provider"] for row in reports}, {"provider-0", "provider-1"})
        self.assertTrue(all(row["artifact_service_report"]["noos_da_verified"] for row in reports))

    def test_https_transport_assignment_restore_corruption_and_import_are_non_promoting(self) -> None:
        rows = [self.inventories[0]["rows"][0], self.inventories[1]["rows"][1]]
        with FakeCoordinator(rows, self.quarantine) as coordinator:
            coordinator.chain = self.chain
            config_path = self.write_config(self.config_document(coordinator.url, import_enabled=True))
            config = smoke.validate_config(config_path)
            verification = smoke.verify_bundles(config)
            evidence = smoke.run_smoke(config, verification)
        self.assertEqual(coordinator.registered, self.origin_values)
        self.assertEqual(coordinator.valid_restores, 2)
        self.assertEqual(coordinator.corrupt_restores, 1)
        self.assertTrue(evidence["assignment_observed"])
        self.assertTrue(evidence["restore_receipt"]["canonical_verified"])
        self.assertTrue(evidence["corruption_rejected"])
        self.assertTrue(evidence["artifact_import_exercised"])
        self.assertEqual(evidence["restored_share_count"], 2)
        self.assertEqual(evidence["assigned_origin_count"], 2)
        self.assertTrue(self.index_path.is_file())
        self.assertEqual(evidence["artifact_import_report"]["release"]["released_share_count"], 2)
        self.assertTrue((self.root / "release-report.json").is_file())
        corrupt_task = json.loads((config.run_root / "queue-restore-corrupt-report.json").read_bytes())["task"]
        valid_task = json.loads((config.run_root / "queue-restore-0-0-report.json").read_bytes())["task"]
        self.assertNotEqual(corrupt_task["task_id"], valid_task["task_id"])
        self.assertFalse(evidence["synthetic_workload_distribution"])
        for field in ("real_public_pilot", "production_custody", "availability_certificate_effect", "rewards", "promotion_authorized", "browser_upload_default"):
            self.assertFalse(evidence[field])
        self.assertTrue(evidence["insert_once"])
        self.assertEqual(evidence["signature"]["domain"], "NOOS/SIG/WWM-WEB-MULTI-ORIGIN-DEVNET/V1")
        evidence_path = self.root / "evidence.json"
        self.assertEqual(json.loads(evidence_path.read_bytes()), evidence)
        with self.assertRaises(smoke.DevnetError):
            smoke.write_new(evidence_path, b"replacement")

    def test_cleanup_is_marker_bound_and_preserves_inputs_and_evidence(self) -> None:
        config_path = self.write_config(self.config_document(f"http://127.0.0.1:{free_port()}"))
        config = smoke.validate_config(config_path)
        smoke.create_workspace(config)
        (config.run_root / "temporary.bin").write_bytes(b"temporary")
        (self.root / "evidence.json").write_bytes(b"preserve")
        result = smoke.cleanup(config)
        self.assertTrue(result["bounded_to_workspace"])
        self.assertFalse(config.run_root.exists())
        self.assertTrue(all(bundle.exists() for bundle in self.bundles))
        self.assertEqual((self.root / "evidence.json").read_bytes(), b"preserve")
        config.run_root.mkdir()
        (config.run_root / ".wwm-web-capacity-devnet-workspace.json").write_bytes(canonical({"schema": smoke.MARKER_SCHEMA, "config_sha256": "00" * 32, "run_root": str(config.run_root)}))
        with self.assertRaises(smoke.DevnetError):
            smoke.cleanup(config)

    def test_coordinator_fixture_requires_explicit_loopback_ca_and_bounded_repair_profile(self) -> None:
        document = self.config_document(f"http://127.0.0.1:{free_port()}")
        config_path = self.write_config(document)
        coordinator = json.loads(self.coordinator_config.read_bytes())
        coordinator.pop("loopback_test_transport")
        self.coordinator_config.write_bytes(canonical(coordinator))
        with self.assertRaisesRegex(smoke.DevnetError, "explicitly enable"):
            smoke.validate_config(config_path)

        config_path = self.write_config(document)
        coordinator = json.loads(self.coordinator_config.read_bytes())
        coordinator["listen"] = "0.0.0.0:9770"
        self.coordinator_config.write_bytes(canonical(coordinator))
        with self.assertRaisesRegex(smoke.DevnetError, "loopback"):
            smoke.validate_config(config_path)

        import_document = self.config_document(
            f"http://127.0.0.1:{free_port()}", import_enabled=True
        )
        config_path = self.write_config(import_document)
        coordinator = json.loads(self.coordinator_config.read_bytes())
        coordinator["max_quarantine_bytes"] = 475_588_609
        self.coordinator_config.write_bytes(canonical(coordinator))
        with self.assertRaisesRegex(smoke.DevnetError, "exact 475,588,608"):
            smoke.validate_config(config_path)

    def test_rejects_unauthorized_public_or_duplicate_bundle_inputs(self) -> None:
        document = self.config_document(f"http://127.0.0.1:{free_port()}")
        document["origins"][0]["operator_authorized"] = False
        with self.assertRaisesRegex(smoke.DevnetError, "not explicitly operator-authorized"):
            smoke.validate_config(self.write_config(document))
        document = self.config_document(f"http://127.0.0.1:{free_port()}")
        document["origins"][0]["origin"] = "https://example.com:443"
        with self.assertRaisesRegex(smoke.DevnetError, "literal 127"):
            smoke.validate_config(self.write_config(document))
        document = self.config_document(f"http://127.0.0.1:{free_port()}")
        document["origins"][1]["bundle_root"] = document["origins"][0]["bundle_root"]
        with self.assertRaisesRegex(smoke.DevnetError, "distinct"):
            smoke.validate_config(self.write_config(document))


if __name__ == "__main__":
    unittest.main()
