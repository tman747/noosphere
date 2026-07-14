from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_evidence_bundle as gate


class WwmEvidenceBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "environment.json").write_text(
            json.dumps({"os": "test", "hardware": "test-only", "runtime": "test"}),
            encoding="utf-8",
        )
        (self.submission / "measured.json").write_text(
            json.dumps({"fixture_contract_checks": 3}),
            encoding="utf-8",
        )
        self.artifacts = []
        for kind in ("usability_protocol", "accessibility_results", "consent_comprehension_report"):
            path = self.submission / f"{kind}.txt"
            path.write_text(f"TEST_ONLY {kind}\n", encoding="utf-8")
            self.artifacts.append({"kind": kind, "path": path.name})

    def tearDown(self) -> None:
        self.temp.cleanup()

    def metadata(self, verdict: str = "PARTIAL") -> dict[str, object]:
        return {
            "verdict": verdict,
            "raw_artifacts": self.artifacts,
            "dependency_receipts": [],
            "reproductions": [],
            "second_client_vectors": [],
            "reproducible_builds": [],
            "red_team_engagements": [],
            "drills": [],
            "promotion_record": None,
            "severity1_open_findings": 0,
        }

    def prepare(self, verdict: str = "PARTIAL") -> Path:
        (self.submission / "metadata.json").write_text(
            json.dumps(self.metadata(verdict)), encoding="utf-8"
        )
        output = self.root / f"bundle-{verdict.lower()}"
        gate.prepare_bundle("E-WWM-16", self.submission, output, "a" * 40)
        return output

    @staticmethod
    def attestation(bundle: dict[str, object]) -> dict[str, object]:
        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        message = gate.attestation_message(bundle)
        return {
            "operator_id": "external-fixture-operator",
            "control_cluster_id": "b" * 64,
            "role": "independent_verifier",
            "external_to_release_owner": True,
            "public_key_base64": base64.b64encode(public).decode("ascii"),
            "key_id": gate.sha256_bytes(public),
            "payload_sha256": gate.sha256_bytes(message),
            "signature_base64": base64.b64encode(private.sign(message)).decode("ascii"),
        }

    def test_partial_bundle_attests_seals_and_detects_artifact_tamper(self) -> None:
        output = self.prepare()
        bundle = gate.load_json(output / "bundle.json")
        attestation_path = self.root / "attestation.json"
        attestation_path.write_text(json.dumps(self.attestation(bundle)), encoding="utf-8")
        gate.attach_attestation(output, attestation_path)
        sealed = gate.seal_bundle(output)
        self.assertTrue(sealed["sealed"])
        self.assertTrue(sealed["bundle_id"].startswith("sha256:"))
        observed = gate.verify_bundle_directory(output, expected_revision="a" * 40)
        self.assertEqual(observed["result"]["verdict"], "PARTIAL")
        with self.assertRaisesRegex(gate.EvidenceError, "sealed bundles are immutable"):
            gate.attach_attestation(output, attestation_path)

        artifact = output / sealed["artifacts"][0]["path"]
        artifact.write_bytes(b"tampered")
        with self.assertRaisesRegex(gate.EvidenceError, "artifact integrity mismatch"):
            gate.verify_bundle_directory(output, expected_revision="a" * 40)

    def test_pass_cannot_seal_without_dependencies_reproduction_roles_and_drills(self) -> None:
        output = self.prepare("PASS")
        with self.assertRaises(gate.EvidenceError):
            gate.seal_bundle(output)
        bundle = gate.load_json(output / "bundle.json")
        self.assertFalse(bundle["sealed"])
        self.assertIsNone(bundle["bundle_id"])

    def test_preregistration_digest_binds_threshold_and_policy(self) -> None:
        output = self.prepare()
        bundle_path = output / "bundle.json"
        bundle = gate.load_json(bundle_path)
        bundle["preregistration_sha256"] = "0" * 64
        bundle_path.write_bytes(gate.canonical_json(bundle))
        with self.assertRaisesRegex(gate.EvidenceError, "preregistration digest is stale"):
            gate.verify_bundle_directory(output, require_sealed=False)

    def test_contract_covers_exactly_twenty_two_disabled_claims(self) -> None:
        registry, experiments, policies = gate.load_contracts()
        self.assertEqual(len(registry["claims"]), 22)
        self.assertEqual(len(policies), 22)
        self.assertFalse(experiments["controls_enabled"])
        self.assertEqual(
            experiments["common_policy"]["required_attestation_roles"],
            ["experiment_operator", "independent_reproducer", "independent_verifier"],
        )


if __name__ == "__main__":
    unittest.main()
