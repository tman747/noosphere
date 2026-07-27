from __future__ import annotations

import hashlib
import http.server
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_continuous_learning as learning
import wwm_model_improvement as improvement


def hx(value: int) -> str:
    return f"{value:064x}"


class ContinuousLearningTests(unittest.TestCase):
    def make_config(
        self,
        root: Path,
        *,
        execution_enabled: bool = False,
        maximum_queued_cycles: int = 4,
    ) -> tuple[Path, dict[str, object], list[str]]:
        (root / "gate.json").write_text("{}\n", encoding="utf-8")
        seeds: list[str] = []
        role_key_files: dict[str, object] = {}
        if execution_enabled:
            bindings: dict[str, object] = {}
            for index, role in enumerate(
                ("builder", "sponsor", "trainer", "successor", "activator"), start=101
            ):
                seed = hx(index)
                seeds.append(seed)
                key_path = root / f"{role}.key"
                key_path.write_text(seed + "\n", encoding="ascii")
                key_path.chmod(0o600)
                bindings[role] = key_path.name
            evaluator_paths: list[str] = []
            for index in (201, 202):
                seed = hx(index)
                seeds.append(seed)
                key_path = root / f"evaluator-{index}.key"
                key_path.write_text(seed + "\n", encoding="ascii")
                key_path.chmod(0o600)
                evaluator_paths.append(key_path.name)
            bindings["evaluators"] = evaluator_paths
            role_key_files = bindings

        value: dict[str, object] = {
            "schema": learning.CONFIG_SCHEMA,
            "environment": "local",
            "production": False,
            "monitoring_enabled": True,
            "execution_enabled": execution_enabled,
            "chain_id": hx(1),
            "genesis_hash": hx(2),
            "status_endpoints": [
                {
                    "url": f"http://127.0.0.1:{19000 + index}/status",
                    "control_cluster": hx(10 + index),
                }
                for index in range(3)
            ],
            "request_dir": "requests",
            "evidence_root": "evidence",
            "state_db": "state/coordinator.sqlite3",
            "status_file": "state/status.json",
            "gate_config": "gate.json",
            "role_key_files": role_key_files,
            "poll_seconds": 10,
            "request_timeout_seconds": 1,
            "minimum_finalized_advance": 256,
            "maximum_queued_cycles": maximum_queued_cycles,
            "listen": {"host": "127.0.0.1", "port": 19100},
        }
        path = root / "continuous-learning.json"
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path, value, seeds

    def write_request(
        self,
        root: Path,
        *,
        marker: int = 1,
        not_before: int = 0,
        required_hash: str | None = None,
        signing_seeds: object | None = None,
    ) -> tuple[Path, dict[str, object]]:
        body: dict[str, object] = {
            "schema": improvement.REQUEST_SCHEMA,
            "environment": "local",
            "production": False,
            "chain_binding": {"chain_id": hx(1), "genesis_hash": hx(2)},
            "not_before_finalized_height": not_before,
            "request_marker": marker,
        }
        if required_hash is not None:
            body["required_finalized_hash"] = required_hash
        if signing_seeds is not None:
            body["signing_seeds"] = signing_seeds
        request_id = hashlib.sha256(improvement.canonical_json(body)).hexdigest()
        value = {**body, "request_id": request_id}
        request_dir = root / "requests"
        request_dir.mkdir(parents=True, exist_ok=True)
        path = request_dir / f"request-{marker}.json"
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
        return path, value

    @staticmethod
    def ready_probe(_gate: object) -> improvement.GateResult:
        return improvement.GateResult(
            False,
            "ROUNDTRIP_NOT_EXECUTED",
            "pinned parent and toolchain verified; cycle may execute",
            {},
        )

    @staticmethod
    def blocked_probe(_gate: object) -> improvement.GateResult:
        return improvement.GateResult(False, "MISSING_REAL_PARENT", "parent unavailable", {})

    @staticmethod
    def status_fetcher(epoch: int = 2, checkpoint_hash: str | None = None):
        finalized_hash = checkpoint_hash or hx(3 + epoch)

        def fetch(_endpoint: learning.StatusEndpoint, _timeout: int) -> dict[str, object]:
            return {
                "chain_id": hx(1),
                "genesis_hash": hx(2),
                "finalized": {"epoch": epoch, "hash": finalized_hash},
            }

        return fetch

    def test_config_is_nonproduction_loopback_and_secret_transport_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, value, _ = self.make_config(root)

            value["production"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(learning.ContinuousLearningError, "non-production"):
                learning.load_config(path)

            value["production"] = False
            value["role_key_files"] = {"builder": "builder.key"}
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(learning.ContinuousLearningError, "must be absent"):
                learning.load_config(path)

            value["role_key_files"] = {}
            value["status_endpoints"][0]["url"] = "http://node.example/status"
            value["status_endpoints"][0]["bearer_token_file"] = "token"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(learning.ContinuousLearningError, "require HTTPS"):
                learning.load_config(path)

    def test_finality_requires_one_unambiguous_two_cluster_quorum(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _, _ = self.make_config(root)
            config = learning.load_config(path)

            def one_diverges(endpoint: learning.StatusEndpoint, _timeout: int) -> dict[str, object]:
                checkpoint = hx(9) if endpoint.control_cluster == hx(12) else hx(8)
                return {
                    "chain_id": hx(1),
                    "genesis_hash": hx(2),
                    "finalized": {"epoch": 7, "hash": checkpoint},
                }

            anchor = learning.observe_finalized(config, one_diverges, lambda: 1234.0)
            self.assertEqual(anchor.height, 7 * learning.EPOCH_LENGTH)
            self.assertEqual(anchor.checkpoint_hash, hx(8))
            self.assertEqual(anchor.control_clusters, (hx(10), hx(11)))
            self.assertEqual(anchor.observed_at, 1234)

            def all_diverge(endpoint: learning.StatusEndpoint, _timeout: int) -> dict[str, object]:
                index = config.status_endpoints.index(endpoint)
                return {
                    "chain_id": hx(1),
                    "genesis_hash": hx(2),
                    "finalized": {"epoch": 7, "hash": hx(20 + index)},
                }

            with self.assertRaisesRegex(learning.ContinuousLearningError, "quorum unavailable"):
                learning.observe_finalized(config, all_diverge)

    def test_lagging_finalized_status_uses_verified_historical_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _, _ = self.make_config(root)
            config = learning.load_config(path)
            statuses = {
                hx(10): (7, hx(70)),
                hx(11): (8, hx(80)),
                hx(12): (9, hx(90)),
            }

            def fetch(endpoint: learning.StatusEndpoint, _timeout: int) -> dict[str, object]:
                epoch, checkpoint_hash = statuses[endpoint.control_cluster]
                return {
                    "chain_id": hx(1),
                    "genesis_hash": hx(2),
                    "finalized": {"epoch": epoch, "hash": checkpoint_hash},
                }

            history = {
                (hx(11), 7 * learning.EPOCH_LENGTH): hx(70),
                (hx(12), 7 * learning.EPOCH_LENGTH): hx(70),
                (hx(12), 8 * learning.EPOCH_LENGTH): hx(80),
            }

            def checkpoint(
                endpoint: learning.StatusEndpoint, height: int, _timeout: int
            ) -> str:
                return history[(endpoint.control_cluster, height)]

            anchor = learning.observe_finalized(
                config,
                fetch,
                lambda: 2_000.0,
                checkpoint,
            )
            self.assertEqual(anchor.epoch, 8)
            self.assertEqual(anchor.checkpoint_hash, hx(80))
            self.assertEqual(anchor.control_clusters, (hx(11), hx(12)))
            self.assertEqual(anchor.observed_endpoints, 3)

            store = learning.CoordinatorStore(config.state_db)
            try:
                store.record_anchor(anchor)
                regressed = learning.FinalizedAnchor(
                    chain_id=hx(1),
                    genesis_hash=hx(2),
                    epoch=7,
                    height=7 * learning.EPOCH_LENGTH,
                    checkpoint_hash=hx(70),
                    control_clusters=(hx(10), hx(11)),
                    observed_endpoints=2,
                    observed_at=2_001,
                )
                with self.assertRaisesRegex(
                    learning.ContinuousLearningError, "regressed"
                ):
                    store.record_anchor(regressed)
            finally:
                store.close()


    def test_request_identity_and_embedded_signing_seeds_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _ = self.make_config(root)
            config = learning.load_config(config_path)
            request_path, request = self.write_request(root)
            queued, parsed = learning.parse_request(request_path, config)
            self.assertEqual(parsed, request)
            self.assertEqual(queued.request_id, request["request_id"])

            seeded_path, _ = self.write_request(root, marker=2, signing_seeds={"builder": hx(91)})
            with self.assertRaisesRegex(learning.ContinuousLearningError, "must not contain signing seeds"):
                learning.parse_request(seeded_path, config)

            request["request_marker"] = 99
            request_path.write_text(json.dumps(request), encoding="utf-8")
            with self.assertRaisesRegex(learning.ContinuousLearningError, "canonical request bytes"):
                learning.parse_request(request_path, config)

    def test_monitoring_mode_anchors_and_queues_without_running_training(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _ = self.make_config(root)
            self.write_request(root)
            calls: list[object] = []
            coordinator = learning.ContinuousLearningCoordinator(
                learning.load_config(config_path),
                status_fetcher=self.status_fetcher(),
                workflow_runner=lambda request, evidence: calls.append((request, evidence)) or {},
                prerequisite_probe=self.blocked_probe,
                clock=lambda: 1_000.0,
            )
            try:
                status = coordinator.tick()
                self.assertEqual(status["mode"], "MONITORING_EXECUTION_DISABLED")
                self.assertEqual(status["queue"]["QUEUED"], 1)
                self.assertEqual(calls, [])
                self.assertTrue(coordinator.healthy())
                self.assertFalse(status["canonical_training_enabled"])
                self.assertFalse(status["automatic_promotion_enabled"])
                persisted = json.loads((root / "state/status.json").read_text(encoding="utf-8"))
                self.assertEqual(persisted, status)
            finally:
                coordinator.close()

    def test_missing_prerequisite_never_consumes_a_queued_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _ = self.make_config(root, execution_enabled=True)
            self.write_request(root)
            calls: list[object] = []
            coordinator = learning.ContinuousLearningCoordinator(
                learning.load_config(config_path),
                status_fetcher=self.status_fetcher(),
                workflow_runner=lambda request, evidence: calls.append((request, evidence)) or {},
                prerequisite_probe=self.blocked_probe,
                clock=lambda: 1_000.0,
            )
            try:
                status = coordinator.tick()
                self.assertEqual(status["mode"], "EXECUTION_PREREQUISITE_UNAVAILABLE")
                self.assertEqual(status["queue"]["QUEUED"], 1)
                self.assertEqual(status["queue"]["RUNNING"], 0)
                self.assertEqual(calls, [])
                self.assertFalse(coordinator.healthy())
            finally:
                coordinator.close()

    def test_successful_shadow_handoff_is_signed_nonpromoting_and_cadenced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, seeds = self.make_config(root, execution_enabled=True)
            self.write_request(root, marker=1)
            epoch = [2]
            calls: list[tuple[dict[str, object], Path]] = []

            def fetch(_endpoint: learning.StatusEndpoint, _timeout: int) -> dict[str, object]:
                return {
                    "chain_id": hx(1),
                    "genesis_hash": hx(2),
                    "finalized": {"epoch": epoch[0], "hash": hx(30 + epoch[0])},
                }

            def run(request: dict[str, object], evidence_root: Path) -> dict[str, object]:
                self.assertIn("signing_seeds", request)
                calls.append((request, evidence_root))
                marker = int(request["request_marker"])
                return {
                    "passed": True,
                    "object_id": hx(40 + marker),
                    "candidate_revision_id": hx(50 + marker),
                    "successor_id": hx(60 + marker),
                }

            coordinator = learning.ContinuousLearningCoordinator(
                learning.load_config(config_path),
                status_fetcher=fetch,
                workflow_runner=run,
                prerequisite_probe=self.ready_probe,
                clock=lambda: 2_000.0,
            )
            try:
                first = coordinator.tick()
                self.assertEqual(first["mode"], "READY")
                self.assertEqual(first["queue"]["SHADOW_CANDIDATE_READY"], 1)
                self.assertEqual(len(calls), 1)
                handoff_path = calls[0][1] / "handoff.json"
                handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                improvement.verify_signed_record(
                    "NOOS-WWM-CONTINUAL-LEARNING-HANDOFF-V1", handoff
                )
                self.assertEqual(handoff["promotion_effect"], "NONE")
                self.assertFalse(handoff["serving_alias_mutated"])
                self.assertFalse(handoff["control_state_mutated"])
                self.assertTrue(handoff["operational_reconfiguration_required"])

                self.write_request(root, marker=2)
                same_anchor = coordinator.tick()
                self.assertEqual(same_anchor["mode"], "READY")
                self.assertEqual(same_anchor["queue"]["FINALITY_BLOCKED"], 1)
                self.assertEqual(len(calls), 1)

                epoch[0] = 3
                advanced = coordinator.tick()
                self.assertEqual(advanced["queue"]["SHADOW_CANDIDATE_READY"], 2)
                self.assertEqual(len(calls), 2)

                persisted_paths = [
                    root / "state/coordinator.sqlite3",
                    root / "state/coordinator.sqlite3-wal",
                    root / "state/status.json",
                    calls[0][1] / "handoff.json",
                    calls[1][1] / "handoff.json",
                ]
                persisted = b"".join(path.read_bytes() for path in persisted_paths if path.exists())
                for seed in seeds:
                    self.assertNotIn(seed.encode("ascii"), persisted)
            finally:
                coordinator.close()

    def test_reformatted_duplicate_cannot_mutate_durably_admitted_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _ = self.make_config(root, execution_enabled=True)
            request_path, request = self.write_request(root)
            admitted_bytes = request_path.read_bytes()
            calls: list[dict[str, object]] = []

            def run(value: dict[str, object], _evidence: Path) -> dict[str, object]:
                calls.append(value)
                return {
                    "passed": True,
                    "object_id": hx(41),
                    "candidate_revision_id": hx(51),
                    "successor_id": hx(61),
                }

            coordinator = learning.ContinuousLearningCoordinator(
                learning.load_config(config_path),
                status_fetcher=self.status_fetcher(),
                workflow_runner=run,
                prerequisite_probe=self.ready_probe,
            )
            try:
                coordinator._scan_requests()
                request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
                status = coordinator.tick()
                self.assertEqual(status["mode"], "READY")
                self.assertEqual(status["queue"]["SHADOW_CANDIDATE_READY"], 1)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]["request_marker"], 1)
                archived = root / "requests/admitted" / f"{request['request_id']}.json"
                self.assertEqual(archived.read_bytes(), admitted_bytes)
                self.assertIn(request_path.name, status["invalid_requests"])
                self.assertIn("collision with different request bytes", status["invalid_requests"][request_path.name])
            finally:
                coordinator.close()

    def test_restart_interrupts_running_cycle_and_preserves_attempt_cadence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _ = self.make_config(root)
            config = learning.load_config(config_path)
            request_path, _ = self.write_request(root)
            queued, _ = learning.parse_request(request_path, config)
            anchor = learning.FinalizedAnchor(
                chain_id=hx(1),
                genesis_hash=hx(2),
                epoch=2,
                height=512,
                checkpoint_hash=hx(5),
                control_clusters=(hx(10), hx(11)),
                observed_endpoints=2,
                observed_at=1_000,
            )
            store = learning.CoordinatorStore(config.state_db)
            self.assertTrue(store.insert_request(queued, config.maximum_queued_cycles))
            selected = store.next_request(anchor, config.minimum_finalized_advance)
            self.assertIsNotNone(selected)
            store.mark_running(queued.request_id, anchor)
            store.close()

            recovered = learning.CoordinatorStore(config.state_db)
            try:
                self.assertEqual(recovered.latest_request()["state"], "INTERRUPTED")
                self.assertEqual(recovered.last_attempted_anchor_height(), 512)
                self.assertIsNone(recovered.next_request(anchor, config.minimum_finalized_advance))
            finally:
                recovered.close()

    def test_deployment_manifest_seals_a_monitoring_only_bundle(self) -> None:
        root = HERE.parents[1]
        config = learning.load_config(root / "deploy/wwm/continuous-learning.testnet.json")
        self.assertEqual(config.environment, "testnet")
        self.assertFalse(config.production)
        self.assertTrue(config.monitoring_enabled)
        self.assertFalse(config.execution_enabled)
        self.assertEqual(len({endpoint.url for endpoint in config.status_endpoints}), 3)
        self.assertEqual(len({endpoint.control_cluster for endpoint in config.status_endpoints}), 3)

        manifest = json.loads(
            (root / "deploy/wwm/continuous-learning-manifest.testnet.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            manifest["schema"],
            "noos/wwm-continuous-learning-deployment-manifest/v1",
        )
        self.assertFalse(manifest["production"])
        self.assertFalse(manifest["execution_enabled"])
        self.assertEqual(manifest["promotion_effect"], "NONE")
        for relative, expected_sha256 in manifest["files"].items():
            payload = (root / relative).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), expected_sha256)

    def test_loopback_http_status_health_and_metrics_are_live(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _ = self.make_config(root)
            coordinator = learning.ContinuousLearningCoordinator(
                learning.load_config(config_path),
                status_fetcher=self.status_fetcher(),
                prerequisite_probe=self.blocked_probe,
                clock=lambda: 1_000.0,
            )
            coordinator.tick()
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), learning._handler(coordinator))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                base = f"http://127.0.0.1:{server.server_address[1]}"
                with urllib.request.urlopen(base + "/healthz", timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(json.loads(response.read()), {"healthy": True})
                with urllib.request.urlopen(base + "/status", timeout=2) as response:
                    self.assertEqual(json.loads(response.read())["schema"], learning.STATUS_SCHEMA)
                with urllib.request.urlopen(base + "/metrics", timeout=2) as response:
                    metrics = response.read().decode("utf-8")
                    self.assertIn("noos_wwm_learning_polls_total 1", metrics)
                    self.assertIn('state="QUEUED"', metrics)
                with self.assertRaises(urllib.error.HTTPError) as missing:
                    urllib.request.urlopen(base + "/missing", timeout=2)
                self.assertEqual(missing.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)
                coordinator.close()


if __name__ == "__main__":
    unittest.main()
