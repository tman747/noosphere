from __future__ import annotations

import base64
import json
import tempfile
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_cutover as cutover


class WwmCutoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stages_document = cutover.load_object(cutover.DEFAULT_STAGES)
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = cutover.sha256(public)
        self.keyring = {
            "schema": "noos/wwm-cutover-keyring/v1",
            "environment": "devnet",
            "production_authority": False,
            "threshold": 1,
            "authorized_key_ids": [self.key_id],
            "keys": [
                {
                    "key_id": self.key_id,
                    "public_key_base64": base64.b64encode(public).decode("ascii"),
                }
            ],
        }
        self.authorization_body = {
            "environment": "devnet",
            "authorization_state": "DEVNET_AUTHORIZED",
            "exact_revision": "a" * 40,
            "chain_id": "1" * 64,
            "genesis_hash": "2" * 64,
            "release_root": "3" * 64,
            "g5_ledger_root": "4" * 64,
            "capsule_id": "5" * 64,
            "service_directory_root": "6" * 64,
            "runway_root": "7" * 64,
            "cutover_root": "8" * 64,
            "static_target_sha256": "9" * 64,
            "g5_authorization_id": "a" * 64,
            "activation_height": 100,
            "production_transition_finalized": True,
            "static_target_published": True,
            "ttl_seconds": 300,
            "ttl_lowered_at_unix": 100,
            "issued_at_unix": 900_000,
            "expires_at_unix": 2_000_000,
            "nonce": "nonce-0001",
            "stages_sha256": cutover.sha256(cutover.canonical_json(self.stages_document)),
        }
        self.authorization = self.sign_envelope(
            "noos/wwm-cutover-authorization/v2",
            self.authorization_body,
            cutover.AUTH_DOMAIN,
        )

    def sign_envelope(self, schema: str, body: dict[str, object], domain: bytes) -> dict[str, object]:
        signature = self.private.sign(domain + cutover.canonical_json(body))
        return {
            "schema": schema,
            "body": body,
            "signatures": [
                {
                    "key_id": self.key_id,
                    "signature_base64": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_bytes(cutover.canonical_json(value))

    def test_frozen_stage_order_and_durations(self) -> None:
        stages = cutover.validate_stages(self.stages_document)
        self.assertEqual(
            [stage["traffic_percent"] for stage in stages],
            [0, 1, 5, 25, 50, 100, 100, 100],
        )
        self.assertEqual(
            [stage["minimum_observation_seconds"] for stage in stages],
            [0, 1800, 3600, 7200, 14400, 86400, 0, 0],
        )

    def test_execute_without_authorization_is_blocked(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = cutover.main(["--execute"])
        self.assertEqual(code, 2)
        self.assertIn("authorization", json.loads(output.getvalue())["error"])

    def test_signed_authorization_advances_in_order_and_rejects_short_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            authorization_path = root / "authorization.json"
            keyring_path = root / "keyring.json"
            journal_path = root / "journal.json"
            adapter_path = root / "adapter.exe"
            adapter_path.write_bytes(b"test-only")
            self.write_json(authorization_path, self.authorization)
            self.write_json(keyring_path, self.keyring)
            common = [
                "--execute",
                "--authorization",
                str(authorization_path),
                "--keyring",
                str(keyring_path),
                "--journal",
                str(journal_path),
                "--adapter-command",
                str(adapter_path),
            ]
            with patch("wwm_cutover.run_adapter") as adapter:
                with redirect_stdout(StringIO()):
                    self.assertEqual(cutover.main([*common, "--now", "1000000"]), 0)
                adapter.assert_called_once()
            journal = cutover.load_object(journal_path)
            self.assertEqual(journal["completed_stages"][0]["stage_id"], "preflight")
            auth_digest = cutover.sha256(cutover.canonical_json(self.authorization))
            preflight_observation = self.sign_envelope(
                "noos/wwm-cutover-observation/v1",
                {
                    "stage_id": "preflight",
                    "authorization_sha256": auth_digest,
                    "started_at_unix": 1_000_000,
                    "observed_at_unix": 1_000_001,
                    "healthy": True,
                    "identity_match": True,
                    "paid_job_rpo_zero": True,
                    "old_origin_requests": 0,
                    "evidence_sha256": "b" * 64,
                },
                cutover.OBS_DOMAIN,
            )
            observation_path = root / "observation.json"
            self.write_json(observation_path, preflight_observation)
            with patch("wwm_cutover.run_adapter"):
                with redirect_stdout(StringIO()):
                    self.assertEqual(
                        cutover.main([*common, "--observation", str(observation_path), "--now", "1000001"]),
                        0,
                    )
            journal = cutover.load_object(journal_path)
            self.assertEqual(
                [row["stage_id"] for row in journal["completed_stages"]],
                ["preflight", "service_discovery_1"],
            )
            short_observation = self.sign_envelope(
                "noos/wwm-cutover-observation/v1",
                {
                    "stage_id": "service_discovery_1",
                    "authorization_sha256": auth_digest,
                    "started_at_unix": 1_000_001,
                    "observed_at_unix": 1_001_800,
                    "healthy": True,
                    "identity_match": True,
                    "paid_job_rpo_zero": True,
                    "old_origin_requests": 0,
                    "evidence_sha256": "c" * 64,
                },
                cutover.OBS_DOMAIN,
            )
            self.write_json(observation_path, short_observation)
            output = StringIO()
            with patch("wwm_cutover.run_adapter"), redirect_stdout(output):
                code = cutover.main(
                    [*common, "--observation", str(observation_path), "--now", "1001800"]
                )
            self.assertEqual(code, 2)
            self.assertIn("interval", json.loads(output.getvalue())["error"])
            self.assertEqual(cutover.load_object(journal_path)["next_stage_index"], 2)

    def test_authorization_rejects_bad_signature(self) -> None:
        bad = json.loads(json.dumps(self.authorization))
        bad["body"]["capsule_id"] = "f" * 64
        with self.assertRaisesRegex(cutover.CutoverError, "signature"):
            cutover.verify_authorization(
                bad, self.keyring, self.stages_document, 1_000_000
            )

    def test_repository_authorization_template_is_non_executable(self) -> None:
        template = cutover.load_object(
            cutover.ROOT / "deploy" / "cutover" / "cutover-authorization.template.json"
        )
        production_keyring = dict(self.keyring)
        production_keyring["environment"] = "production"
        production_keyring["production_authority"] = True
        with self.assertRaises(cutover.CutoverError):
            cutover.verify_authorization(
                template, production_keyring, self.stages_document, 1_000_000
            )


if __name__ == "__main__":
    unittest.main()
