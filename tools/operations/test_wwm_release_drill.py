from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_public_testnet_monitor as monitor
from tools.operations import wwm_release_drill as drill


class ReleaseDrillTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adapter = (self.root / "adapter.exe").resolve()
        self.adapter.write_bytes(b"fixture adapter\n")
        self.adapter_sha256 = drill.sha256_file(self.adapter)
        self.current_revision = "49" * 20
        self.prior_revision = "2b" * 20
        self.monitor_key = Ed25519PrivateKey.generate()
        public = monitor.public_key_bytes(self.monitor_key)
        self.monitor_public = base64.b64encode(public).decode("ascii")
        self.monitor_key_id = hashlib.sha256(public).hexdigest()
        self.authorization_seed = bytes.fromhex("31" * 32)
        self.evidence_seed = bytes.fromhex("41" * 32)
        self.started = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)

    def step(
        self,
        step_id: str,
        participant_id: str,
        role: str,
        action: str,
        binary: str,
    ) -> dict[str, object]:
        return {
            "step_id": step_id,
            "participant_id": participant_id,
            "role": role,
            "action": action,
            "adapter": str(self.adapter),
            "adapter_sha256": self.adapter_sha256,
            "arguments": ["--participant", participant_id],
            "expected_binary_sha256": binary,
            "minimum_live_validators": 3,
        }

    def body(self, kind: str = "ROLLING_RESTART") -> dict[str, object]:
        if kind == "ROLLING_RESTART":
            steps = [
                self.step("restart-observer", "observer-1", "observer", "RESTART", "a1" * 32),
                self.step("restart-witness-1", "witness-1", "witness", "RESTART", "a2" * 32),
                self.step("restart-witness-2", "witness-2", "witness", "RESTART", "a3" * 32),
                self.step("restart-witness-3", "witness-3", "witness", "RESTART", "a4" * 32),
            ]
            prior: str | None = None
        else:
            steps = [
                self.step("activate-prior", "witness-3", "witness", "ACTIVATE_PRIOR", "b1" * 32),
                self.step("activate-current", "witness-3", "witness", "ACTIVATE_CURRENT", "b2" * 32),
            ]
            prior = self.prior_revision
        return {
            "drill_id": "11" * 32 if kind == "ROLLING_RESTART" else "12" * 32,
            "kind": kind,
            "chain_id": "21" * 32,
            "genesis_hash": "22" * 32,
            "current_revision": self.current_revision,
            "current_release_version": f"0.1.0+git.{self.current_revision}",
            "prior_revision": prior,
            "monitor": {
                "url": "https://status.example/status.json",
                "signer_public_key_base64": self.monitor_public,
                "signer_key_id": self.monitor_key_id,
                "deployment_sha256": "81" * 32,
                "maximum_gap_seconds": 90,
                "expected_checks": 2,
            },
            "steps": steps,
            "replay_probes": [
                {"probe_id": "finalized-receipt", "url": "https://rpc.example/receipt/1"},
                {"probe_id": "finalized-transfer", "url": "https://rpc.example/transaction/2"},
            ],
            "maximum_step_seconds": 30,
        }

    def authorize(self, body: dict[str, object]) -> dict[str, object]:
        unsigned = self.root / "unsigned.json"
        seed = self.root / "authorization.seed"
        output = self.root / "authorized.json"
        unsigned.write_text(json.dumps({"schema": drill.PLAN_SCHEMA, "body": body}), encoding="utf-8")
        seed.write_bytes(self.authorization_seed)
        return drill.authorize(unsigned, seed, output)

    def sample(self, index: int, previous: str | None = None) -> dict[str, object]:
        height = 300_000 + index
        payload: dict[str, object] = {
            "schema": monitor.SAMPLE_SCHEMA,
            "environment": "public-testnet",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "source_revision": self.current_revision,
            "release_version": f"0.1.0+git.{self.current_revision}",
            "deployment_sha256": "81" * 32,
            "status": "ok",
            "observed_at_utc": (self.started + timedelta(seconds=index * 10)).isoformat().replace("+00:00", "Z"),
            "previous_sample_id": previous,
            "checks": [
                {
                    "name": "network_coherence",
                    "ok": True,
                    "latency_ms": 5,
                    "detail": {
                        "validator_count": 4,
                        "validator_min_height": height,
                        "validator_max_height": height + 1,
                        "finalized_epoch": 1200 + index // 3,
                    },
                },
                {
                    "name": "gateway",
                    "ok": True,
                    "latency_ms": 2,
                    "detail": {"unsafe_height": height, "release_version": f"0.1.0+git.{self.current_revision}"},
                },
            ],
        }
        return monitor.sign_payload(payload, self.monitor_key, monitor.SAMPLE_DOMAIN, "sample_id")

    def sample_requester(self, count: int):
        samples: list[dict[str, object]] = []
        previous: str | None = None
        for index in range(count):
            sample = self.sample(index, previous)
            samples.append(sample)
            previous = str(sample["sample_id"])
        iterator = iter(samples)
        return lambda _url: next(iterator)

    def runner(self, body: dict[str, object], *, reset: bool = False):
        steps = {str(step["step_id"]): step for step in body["steps"]}  # type: ignore[index]
        calls = 0

        def run(command: list[str], _timeout: int) -> drill.RunnerResult:
            nonlocal calls
            calls += 1
            step_id = command[command.index("--step-id") + 1]
            action = command[command.index("--action") + 1]
            step = steps[step_id]
            participant = str(step["participant_id"])
            before = self.current_revision
            after = self.current_revision
            authorization = None
            if action == "ACTIVATE_PRIOR":
                after = self.prior_revision
                authorization = command[command.index("--authorization-sha256") + 1]
            elif action == "ACTIVATE_CURRENT":
                before = self.prior_revision
                authorization = command[command.index("--authorization-sha256") + 1]
            result = {
                "schema": drill.ADAPTER_SCHEMA,
                "step_id": step_id,
                "participant_id": participant,
                "action": action,
                "process": {
                    "identity": f"system-service:{participant}",
                    "pid_before": 1000 + calls * 2,
                    "pid_after": 1001 + calls * 2,
                    "peak_rss_bytes": 64 * 1024 * 1024,
                },
                "release": {
                    "before_revision": before,
                    "after_revision": after,
                    "binary_sha256": step["expected_binary_sha256"],
                },
                "durable_state": {
                    "identity_sha256": hashlib.sha256(participant.encode()).hexdigest(),
                    "reset": reset,
                    "deleted": False,
                },
                "authorization_sha256": authorization,
            }
            return drill.RunnerResult(0, json.dumps(result), "")

        return run

    @staticmethod
    def stable_probe(_url: str) -> dict[str, object]:
        return {"bytes": 100, "canonical_sha256": "55" * 32}

    def test_authorized_observer_first_rolling_restart_seals_evidence(self) -> None:
        body = self.body()
        plan = self.authorize(body)
        result = drill.execute(
            plan,
            self.evidence_seed,
            sample_requester=self.sample_requester(5),
            probe_requester=self.stable_probe,
            adapter_runner=self.runner(body),
        )
        verified = drill.verify_result(result)
        self.assertEqual(verified["verdict"], "PASS")
        self.assertEqual(len(verified["steps"]), 4)
        self.assertEqual(set(verified["durable_state_identities"]), {"observer-1", "witness-1", "witness-2", "witness-3"})
        self.assertTrue(all(step["post_coordinates"]["validator_count"] == 4 for step in verified["steps"]))

    def test_preserved_build_rollback_binds_authorization_and_state(self) -> None:
        body = self.body("PRESERVED_BUILD_ROLLBACK")
        plan = self.authorize(body)
        result = drill.execute(
            plan,
            self.evidence_seed,
            sample_requester=self.sample_requester(3),
            probe_requester=self.stable_probe,
            adapter_runner=self.runner(body),
        )
        verified = drill.verify_result(result)
        self.assertEqual(verified["prior_revision"], self.prior_revision)
        self.assertEqual(list(verified["durable_state_identities"]), ["witness-3"])
        self.assertEqual([step["action"] for step in verified["steps"]], ["ACTIVATE_PRIOR", "ACTIVATE_CURRENT"])
        self.assertTrue(all(step["adapter"]["authorization_sha256"] == verified["authorization_sha256"] for step in verified["steps"]))

    def test_plan_rejects_non_observer_first_and_bad_authorization(self) -> None:
        body = self.body()
        body["steps"] = list(reversed(body["steps"]))  # type: ignore[index]
        with self.assertRaisesRegex(drill.DrillError, "observer-first"):
            drill.validate_plan_body(body)

        valid_body = self.body()
        plan = self.authorize(valid_body)
        plan["body"]["maximum_step_seconds"] = 31  # type: ignore[index]
        with self.assertRaisesRegex(drill.DrillError, "authorization signature"):
            drill.verify_authorization(plan)

    def test_execution_rejects_state_reset_replay_change_and_wrong_monitor_key(self) -> None:
        body = self.body()
        plan = self.authorize(body)
        with self.assertRaisesRegex(drill.DrillError, "reset or deleted"):
            drill.execute(
                plan,
                self.evidence_seed,
                sample_requester=self.sample_requester(5),
                probe_requester=self.stable_probe,
                adapter_runner=self.runner(body, reset=True),
            )

        probe_calls = 0

        def changing_probe(_url: str) -> dict[str, object]:
            nonlocal probe_calls
            probe_calls += 1
            return {"bytes": 100, "canonical_sha256": ("55" if probe_calls <= 2 else "56") * 32}

        with self.assertRaisesRegex(drill.DrillError, "replay probe changed"):
            drill.execute(
                plan,
                self.evidence_seed,
                sample_requester=self.sample_requester(5),
                probe_requester=changing_probe,
                adapter_runner=self.runner(body),
            )

        wrong_plan = copy.deepcopy(plan)
        wrong_plan["body"]["monitor"]["signer_public_key_base64"] = base64.b64encode(bytes.fromhex("77" * 32)).decode("ascii")  # type: ignore[index]
        wrong_plan["body"]["monitor"]["signer_key_id"] = hashlib.sha256(bytes.fromhex("77" * 32)).hexdigest()  # type: ignore[index]
        private = Ed25519PrivateKey.from_private_bytes(self.authorization_seed)
        wrong_plan["authorization"] = {
            "key_id": hashlib.sha256(private.public_key().public_bytes_raw()).hexdigest(),
            "public_key_base64": base64.b64encode(private.public_key().public_bytes_raw()).decode("ascii"),
            "signature_base64": base64.b64encode(private.sign(drill.AUTH_DOMAIN + drill.canonical_json(wrong_plan["body"]))).decode("ascii"),
        }
        with self.assertRaisesRegex(drill.DrillError, "signer_key_id mismatch"):
            drill.execute(
                wrong_plan,
                self.evidence_seed,
                sample_requester=self.sample_requester(5),
                probe_requester=self.stable_probe,
                adapter_runner=self.runner(body),
            )

    def test_result_signature_tampering_rejects(self) -> None:
        body = self.body("PRESERVED_BUILD_ROLLBACK")
        result = drill.execute(
            self.authorize(body),
            self.evidence_seed,
            sample_requester=self.sample_requester(3),
            probe_requester=self.stable_probe,
            adapter_runner=self.runner(body),
        )
        tampered = copy.deepcopy(result)
        tampered["body"]["verdict"] = "FAIL"  # type: ignore[index]
        with self.assertRaisesRegex(drill.DrillError, "malformed or promoting"):
            drill.verify_result(tampered)


if __name__ == "__main__":
    unittest.main()
