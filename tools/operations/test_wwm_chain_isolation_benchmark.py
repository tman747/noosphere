from __future__ import annotations

import copy
import hashlib
import http.server
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_chain_isolation_benchmark as bench

CHAIN_ID = "11" * 32
GENESIS_HASH = "22" * 32
ARTIFACT_ID = "33" * 32
MANIFEST_ROOT = "44" * 32
COORDINATOR_KEY = "55" * 32
TOKEN = "fixture-auth-token"


class FixtureState:
    def __init__(self, sentinel: Path) -> None:
        self.sentinel = sentinel
        self.delays = {"01": 0.030, "02": 0.010, "03": 0.010}
        self.fail_submit_prefix: str | None = None
        self.submitted: dict[str, int] = {}
        self.receipt_polls: dict[str, int] = {}
        self.lock = threading.Lock()
        self.next_height = 1
        self.node_requests = 0
        self.coordinator_requests = 0


class FixtureServers:
    def __init__(self, root: Path) -> None:
        self.state = FixtureState(root / "coordinator.offline")
        state = self.state

        class NodeHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, _format: str, *args: object) -> None:
                del args

            def _json(self, status: int, value: dict[str, Any]) -> None:
                raw = bench.canonical_json(value)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authorized(self) -> bool:
                with state.lock:
                    state.node_requests += 1
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self._json(401, {"code": "unauthorized"})
                    return False
                return True

            def do_GET(self) -> None:
                if not self._authorized():
                    return
                if self.path == "/status":
                    with state.lock:
                        finalized = max(10_240, state.next_height)
                    self._json(200, {
                        "chain_id": CHAIN_ID,
                        "genesis_hash": GENESIS_HASH,
                        "unsafe_head": {"height": finalized},
                        "finalized": {"height": finalized},
                    })
                    return
                if self.path.startswith("/receipt/"):
                    txid = self.path.removeprefix("/receipt/")
                    with state.lock:
                        height = state.submitted.get(txid)
                        polls = state.receipt_polls.get(txid, 0)
                        state.receipt_polls[txid] = polls + 1
                    if height is None:
                        self._json(404, {"code": "not_found"})
                    elif polls == 0:
                        self._json(200, {"state": {"pending": True}, "receipt": None})
                    else:
                        self._json(200, {"state": {"settled_height": height, "status_code": 0}, "receipt": {"txid": txid, "status": 0, "fee_charged": "1"}})
                    return
                self._json(404, {"code": "not_found"})

            def do_POST(self) -> None:
                if not self._authorized():
                    return
                if self.path != "/submit_tx":
                    self._json(404, {"code": "not_found"})
                    return
                length = int(self.headers.get("Content-Length", "0"))
                try:
                    body = json.loads(self.rfile.read(length))
                    tx = body["tx"]
                    bytes.fromhex(tx)
                except (ValueError, KeyError, json.JSONDecodeError):
                    self._json(400, {"code": "malformed"})
                    return
                prefix = tx[:2]
                time.sleep(state.delays.get(prefix, 0.0))
                if prefix == state.fail_submit_prefix:
                    self._json(500, {"code": "fixture_error"})
                    return
                txid = hashlib.sha256(bytes.fromhex(tx)).hexdigest()
                with state.lock:
                    height = state.next_height
                    state.next_height += 1
                    state.submitted[txid] = height
                self._json(200, {"accepted": True, "txid": txid})

        class CoordinatorHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, _format: str, *args: object) -> None:
                del args

            def do_GET(self) -> None:
                with state.lock:
                    state.coordinator_requests += 1
                if state.sentinel.exists():
                    raw = b'{"code":"offline"}'
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                if self.path != "/api/wwm-web-capacity/v1/config":
                    self.send_response(404)
                    self.end_headers()
                    return
                time.sleep(0.001)
                raw = bench.canonical_json({
                    "schema": "noos/wwm-web-capacity/v1",
                    "record_kind": "COORDINATOR_CONFIG",
                    "chain_binding": {
                        "chain_id": CHAIN_ID,
                        "genesis_hash": GENESIS_HASH,
                        "artifact_id": ARTIFACT_ID,
                        "manifest_root": MANIFEST_ROOT,
                    },
                    "experiment_state": "DEVNET",
                    "coordinator_key": COORDINATOR_KEY,
                    "participant_classes": ["STATIC_HOST_SEEDER", "BROWSER_ADVISORY_CACHE"],
                    "production_custody": False,
                    "rewards": False,
                })
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.node = http.server.ThreadingHTTPServer(("127.0.0.1", 0), NodeHandler)
        self.coordinator = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CoordinatorHandler)
        self.threads = [
            threading.Thread(target=self.node.serve_forever, daemon=True),
            threading.Thread(target=self.coordinator.serve_forever, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    @property
    def node_url(self) -> str:
        return f"http://127.0.0.1:{self.node.server_address[1]}"

    @property
    def coordinator_url(self) -> str:
        return f"http://127.0.0.1:{self.coordinator.server_address[1]}"

    def close(self) -> None:
        self.node.shutdown()
        self.coordinator.shutdown()
        self.node.server_close()
        self.coordinator.server_close()
        for thread in self.threads:
            thread.join(timeout=2)


class ChainIsolationBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.servers = FixtureServers(self.root)
        self.token = self.root / "node.token"
        self.token.write_text(TOKEN, encoding="utf-8")
        self.seed = self.root / "evidence.seed"
        self.seed.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
        self.transactions = self.root / "transactions.jsonl"
        rows = []
        for prefix in ("01", "02", "03"):
            for index in range(bench.HARD_MIN_SAMPLE_FLOOR):
                rows.append({"tx": prefix + f"{index:062x}", "witnesses": f"{index + 1:064x}"})
        self.transactions.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows), encoding="utf-8")
        self.distribution = self.root / "distribution.json"
        self.write_distribution()
        self.controller = self.root / "controller.py"
        self.controller.write_text(
            "import pathlib,sys\np=pathlib.Path(sys.argv[2])\n"
            "p.write_text('offline') if sys.argv[1]=='stop' else p.unlink(missing_ok=True)\n",
            encoding="utf-8",
        )
        self.outage = self.root / "outage.json"
        self.outage.write_text(json.dumps({
            "schema": bench.OUTAGE_CONTROL_SCHEMA,
            "stop_argv": [sys.executable, str(self.controller), "stop", str(self.servers.state.sentinel)],
            "start_argv": [sys.executable, str(self.controller), "start", str(self.servers.state.sentinel)],
        }), encoding="utf-8")
        self.output = self.root / "evidence.json"

    def tearDown(self) -> None:
        self.servers.close()
        self.temp.cleanup()

    def write_distribution(self, **extra: Any) -> None:
        value = {
            "schema": bench.DISTRIBUTION_SCHEMA,
            "scope": bench.SYNTHETIC_SCOPE,
            "requests": [{
                "name": "config",
                "method": "GET",
                "path": "/api/wwm-web-capacity/v1/config",
                "weight": 1,
                "expected_statuses": [200],
                "headers": {},
                "body": None,
            }],
            **extra,
        }
        self.distribution.write_text(json.dumps(value), encoding="utf-8")

    def args(self) -> Any:
        return bench.build_parser().parse_args([
            "--environment", "DEVNET",
            "--node-url", self.servers.node_url,
            "--node-token-file", str(self.token),
            "--coordinator-url", self.servers.coordinator_url,
            "--chain-id", CHAIN_ID,
            "--genesis-hash", GENESIS_HASH,
            "--transactions", str(self.transactions),
            "--distribution", str(self.distribution),
            "--outage-control", str(self.outage),
            "--signing-key", str(self.seed),
            "--output", str(self.output),
            "--repository-revision", "66" * 20,
            "--repository-tree-sha256", "77" * 32,
            "--node-process-sha256", "88" * 32,
            "--coordinator-process-sha256", "99" * 32,
            "--sample-floor", str(bench.HARD_MIN_SAMPLE_FLOOR),
            "--samples", str(bench.HARD_MIN_SAMPLE_FLOOR),
            "--load-workers", "4",
            "--max-coordinator-requests", "10000",
            "--http-timeout", "1",
            "--poll-interval", "0.001",
            "--phase-timeout", "10",
            "--control-timeout", "5",
        ])

    def test_exact_nearest_rank_and_five_percent_boundary(self) -> None:
        values = list(range(1, 21))
        self.assertEqual(bench.nearest_rank_p95(values), 19)
        self.assertFalse(bench.degradation(100_000, 105_000)["passed"])
        self.assertTrue(bench.degradation(100_000, 104_999)["passed"])

    def test_phase_submits_batch_before_polling_finality(self) -> None:
        payloads = [f"ordinary-{index}".encode() for index in range(bench.HARD_MIN_SAMPLE_FLOOR)]

        class BatchRecorder:
            base_url = "http://127.0.0.1:1"

            def __init__(self) -> None:
                self.submitted: dict[str, int] = {}

            def require_json(
                self, method: str, path: str, body: bytes | None = None
            ) -> tuple[dict[str, Any], int]:
                if method == "POST" and path == "/submit_tx" and body is not None:
                    txid = hashlib.sha256(body).hexdigest()
                    self.submitted[txid] = len(self.submitted) + 1
                    return {"accepted": True, "txid": txid}, 1
                if method == "GET" and path == "/status":
                    self._require_complete_batch()
                    height = len(payloads)
                    return {
                        "chain_id": CHAIN_ID,
                        "genesis_hash": GENESIS_HASH,
                        "unsafe_head": {"height": height},
                        "finalized": {"height": height},
                    }, 1
                raise AssertionError(f"unexpected request: {method} {path}")

            def request(self, method: str, path: str, body: bytes | None = None) -> bench.HttpResult:
                del body
                if method != "GET" or not path.startswith("/receipt/"):
                    raise AssertionError(f"unexpected request: {method} {path}")
                self._require_complete_batch()
                txid = path.removeprefix("/receipt/")
                height = self.submitted[txid]
                response = {
                    "state": {"settled_height": height, "status_code": 0},
                    "receipt": {"txid": txid, "status": 0, "fee_charged": "1"},
                }
                return bench.HttpResult(200, bench.canonical_json(response), 1, None)

            def _require_complete_batch(self) -> None:
                if len(self.submitted) != len(payloads):
                    raise AssertionError("phase polled before submitting the complete transaction batch")

        report = bench.run_node_phase(
            "batched",
            BatchRecorder(),
            payloads,
            CHAIN_ID,
            GENESIS_HASH,
            phase_timeout=1,
            poll_interval=0.001,
        )
        self.assertEqual(report["sample_count"], len(payloads))
        self.assertEqual([row["sequence"] for row in report["raw_samples"]], list(range(len(payloads))))

    def test_live_success_is_signed_non_promoting_insert_once_evidence(self) -> None:
        evidence = bench.run_benchmark(self.args())
        bench.verify_evidence(evidence)
        payload = evidence["payload"]
        self.assertEqual(payload["transaction_set"]["count"], 30)
        self.assertGreaterEqual(payload["coordinator_load"]["total_requests"], 10)
        self.assertGreaterEqual(payload["coordinator_outage"]["classifications"]["EXPECTED_OUTAGE_ERROR"], 10)
        self.assertEqual(payload["coordinator_load"]["error_count"], 0)
        self.assertFalse(payload["promotion"]["production"])
        self.assertEqual(payload["operator_supplied_hashes"]["provenance"], "SUPPLIED_BY_OPERATOR_NOT_RECOMPUTED_BY_BENCHMARK")
        self.assertGreater(self.servers.state.node_requests, 90)
        self.assertGreater(self.servers.state.coordinator_requests, 20)
        bench.write_create_new(self.output, evidence)
        with self.assertRaisesRegex(bench.BenchmarkError, "insert-once"):
            bench.write_create_new(self.output, evidence)

    def test_forged_evidence_is_rejected(self) -> None:
        evidence = bench.run_benchmark(self.args())
        forged = copy.deepcopy(evidence)
        forged["payload"]["ordinary_rpc_phases"]["loaded"]["raw_samples"][0]["finality_latency_us"] += 1
        with self.assertRaisesRegex(bench.BenchmarkError, "forged|invalid"):
            bench.verify_evidence(forged)

    def test_prefilled_metrics_and_ambiguous_or_too_small_runs_are_rejected(self) -> None:
        self.write_distribution(prefilled_metrics={"baseline_p95_ms": 1})
        with self.assertRaisesRegex(bench.BenchmarkError, "fields are closed"):
            bench.load_distribution(self.distribution)
        args = self.args()
        args.sample_floor = bench.HARD_MIN_SAMPLE_FLOOR - 1
        with self.assertRaisesRegex(bench.BenchmarkError, "sample floor"):
            bench.run_benchmark(args)
        args = self.args()
        args.node_url = args.node_url.replace("127.0.0.1", "localhost")
        with self.assertRaisesRegex(bench.BenchmarkError, "ambiguous"):
            bench.run_benchmark(args)

    def test_missing_coordinator_live_traffic_is_rejected(self) -> None:
        self.servers.state.sentinel.write_text("offline", encoding="utf-8")
        with self.assertRaisesRegex(bench.BenchmarkError, "no live HTTP 200"):
            bench.run_benchmark(self.args())

    def test_node_rpc_error_is_rejected_and_no_evidence_is_written(self) -> None:
        self.servers.state.fail_submit_prefix = "02"
        with self.assertRaisesRegex(bench.BenchmarkError, "node RPC POST /submit_tx"):
            bench.run_benchmark(self.args())
        self.assertFalse(self.output.exists())

    def test_five_percent_or_higher_loaded_degradation_is_sealed_as_blocked(self) -> None:
        self.servers.state.delays = {"01": 0.005, "02": 0.050, "03": 0.005}
        evidence = bench.run_benchmark(self.args())
        payload = evidence["payload"]
        self.assertEqual(payload["verdict"], "BLOCKED")
        self.assertFalse(payload["proof_claim"])
        self.assertIn(bench.LOADED_THRESHOLD_BLOCKER, payload["blockers"])
        bench.verify_blocked_evidence(evidence)
        bench.write_create_new(self.output, evidence)

    def test_resigned_forged_blocked_evidence_is_rejected(self) -> None:
        self.servers.state.delays = {"01": 0.005, "02": 0.050, "03": 0.005}
        evidence = bench.run_benchmark(self.args())
        forged_payload = copy.deepcopy(evidence["payload"])
        forged_payload["blockers"] = []
        key = Ed25519PrivateKey.from_private_bytes(self.seed.read_bytes())
        forged = bench.sign_evidence(forged_payload, key)
        with self.assertRaisesRegex(bench.BenchmarkError, "blockers"):
            bench.verify_blocked_evidence(forged)

    def test_transaction_prefilled_fields_and_duplicates_are_rejected(self) -> None:
        rows = self.transactions.read_text(encoding="utf-8").splitlines()
        forged = json.loads(rows[0])
        forged["finality_latency_us"] = 1
        rows[0] = json.dumps(forged)
        self.transactions.write_text("\n".join(rows) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(bench.BenchmarkError, "fields are closed"):
            bench.load_transactions(self.transactions, 30)
        first = json.loads(rows[1])
        rows[0] = json.dumps(first)
        self.transactions.write_text("\n".join(rows) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(bench.BenchmarkError, "duplicate"):
            bench.load_transactions(self.transactions, 30)


if __name__ == "__main__":
    unittest.main()
