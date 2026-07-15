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
    def e23_lab_report() -> dict[str, object]:
        report: dict[str, object] = {
            "schema": gate.E23_LAB_REPORT_SCHEMA,
            "experiment_id": "E-WWM-23",
            "status": gate.E23_LAB_STATUS,
            "evidence_scope": gate.E23_LAB_SCOPE,
            "production_claim": False,
            "promotion_authorized": False,
            "browser_disposition": gate.E23_LOCAL_CACHE_ONLY,
            "gates": [
                {
                    "id": "real-duration",
                    "passed": False,
                    "evidence_class": "REAL_PUBLIC_PILOT_REQUIRED",
                }
            ],
        }
        report["evidence_sha256"] = gate.sha256_bytes(gate.canonical_json(report) + b"\n")
        return report

    def prepare_e23(
        self,
        verdict: str = "PARTIAL",
        promotion_decision: str | None = None,
    ) -> Path:
        self.artifacts = []
        lab_bytes = gate.canonical_json(self.e23_lab_report())
        for kind in sorted(gate.E23_REQUIRED_ARTIFACT_KINDS):
            path = self.submission / f"{kind}.json"
            data = lab_bytes if kind == "bounded_synthetic_load_report" else b'{"test_only":true}'
            path.write_bytes(data)
            self.artifacts.append({"kind": kind, "path": path.name})
        vector_path = self.submission / "e23-second-client.vec"
        vector_path.write_bytes(b"TEST_ONLY E23 SECOND CLIENT")
        metadata = self.metadata(verdict)
        metadata["second_client_vectors"] = [
            {"kind": "e23_second_client_vector", "path": vector_path.name}
        ]
        if promotion_decision is not None:
            metadata["promotion_record"] = {
                "decision": promotion_decision,
                "record_sha256": gate.sha256_bytes(lab_bytes),
                "approver_control_clusters": ["1" * 64, "2" * 64],
            }
        (self.submission / "metadata.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        output = self.root / f"e23-{verdict.lower()}-{promotion_decision or 'none'}"
        gate.prepare_bundle("E-WWM-23", self.submission, output, "a" * 40)
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
        self.assertEqual(observed["bundle"]["applicability_profile"], "BONSAI_PUBLIC_TEXT_V1")
        self.assertEqual(observed["bundle"]["claim_disposition"], "MANDATORY")
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

    def test_contract_covers_exactly_twenty_three_disabled_claims(self) -> None:
        registry, experiments, policies = gate.load_contracts()
        self.assertEqual(
            tuple(claim["claim_id"] for claim in registry["claims"]),
            gate.EXPECTED_CLAIM_IDS,
        )
        self.assertEqual(tuple(sorted(policies)), gate.EXPECTED_CLAIM_IDS)
        self.assertFalse(experiments["controls_enabled"])
        self.assertTrue(
            experiments["common_policy"]["controls_remain_disabled_after_pass"]
        )
        self.assertEqual(
            experiments["common_policy"]["required_attestation_roles"],
            ["experiment_operator", "independent_reproducer", "independent_verifier"],
        )
        profile = gate.applicability_profile(registry)
        self.assertEqual(profile["profile_id"], "BONSAI_PUBLIC_TEXT_V1")
        mandatory = {
            claim_id
            for claim_id, disposition in profile["claim_dispositions"].items()
            if disposition == "MANDATORY"
        }
        self.assertEqual(mandatory, gate.BONSAI_MANDATORY_CLAIMS)
        self.assertEqual(len(profile["claim_dispositions"]), 23)
        self.assertEqual(
            profile["claim_dispositions"]["E-WWM-23"], "DISABLED_NOT_CLAIMED"
        )
        self.assertEqual(
            set(policies["E-WWM-23"]["required_artifact_kinds"]),
            gate.E23_REQUIRED_ARTIFACT_KINDS,
        )
        self.assertEqual(
            set(policies["E-WWM-23"]["required_drills"]),
            gate.E23_REQUIRED_DRILLS,
        )

    def test_applicability_rejects_a_missing_or_weakened_mandatory_claim(self) -> None:
        registry = gate.load_json(gate.DEFAULT_REGISTRY)
        registry["applicability_profiles"][0]["claim_dispositions"]["E-WWM-02"] = (
            "DISABLED_NOT_CLAIMED"
        )
        path = self.root / "weakened-registry.json"
        path.write_bytes(gate.canonical_json(registry))
        with self.assertRaisesRegex(gate.EvidenceError, "mandatory claim set"):
            gate.load_contracts(path, gate.DEFAULT_EXPERIMENTS)


    def test_contract_rejects_missing_e23_and_weakened_controls(self) -> None:
        registry = gate.load_json(gate.DEFAULT_REGISTRY)
        registry["claims"].pop()
        registry["applicability_profiles"][0]["claim_dispositions"].pop("E-WWM-23")
        missing_registry = self.root / "missing-e23-registry.json"
        missing_registry.write_bytes(gate.canonical_json(registry))
        with self.assertRaisesRegex(gate.EvidenceError, "through E-WWM-23"):
            gate.load_contracts(missing_registry, gate.DEFAULT_EXPERIMENTS)
        missing_policy = gate.load_json(gate.DEFAULT_EXPERIMENTS)
        missing_policy["claim_policies"].pop()
        missing_policy_path = self.root / "missing-e23-policy.json"
        missing_policy_path.write_bytes(gate.canonical_json(missing_policy))
        with self.assertRaisesRegex(gate.EvidenceError, "through E-WWM-23"):
            gate.load_contracts(gate.DEFAULT_REGISTRY, missing_policy_path)

        weakened_policy = gate.load_json(gate.DEFAULT_EXPERIMENTS)
        weakened_policy["claim_policies"][-1]["required_drills"].pop()
        weakened_policy_path = self.root / "weakened-e23-policy.json"
        weakened_policy_path.write_bytes(gate.canonical_json(weakened_policy))
        with self.assertRaisesRegex(gate.EvidenceError, "promotion safeguards"):
            gate.load_contracts(gate.DEFAULT_REGISTRY, weakened_policy_path)


        experiments = gate.load_json(gate.DEFAULT_EXPERIMENTS)
        experiments["common_policy"]["controls_remain_disabled_after_pass"] = False
        weakened_experiments = self.root / "weakened-controls.json"
        weakened_experiments.write_bytes(gate.canonical_json(experiments))
        with self.assertRaisesRegex(gate.EvidenceError, "controls must remain disabled"):
            gate.load_contracts(gate.DEFAULT_REGISTRY, weakened_experiments)

    def test_registry_schema_is_closed_at_e23(self) -> None:
        schema = gate.load_json(gate.ROOT / "protocol" / "claims" / "wwm-registry.schema.json")
        self.assertEqual(schema["properties"]["claims"]["minItems"], 23)
        self.assertEqual(schema["properties"]["claims"]["maxItems"], 23)
        pattern = schema["$defs"]["claim"]["properties"]["claim_id"]["pattern"]
        self.assertIsNotNone(gate.re.fullmatch(pattern, "E-WWM-23"))
        self.assertIsNone(gate.re.fullmatch(pattern, "E-WWM-24"))
        disposition_pattern = next(
            iter(
                schema["$defs"]["applicability_profile"]["properties"][
                    "claim_dispositions"
                ]["patternProperties"]
            )
        )
        command_pattern = schema["$defs"]["claim"]["properties"]["command"]["pattern"]
        self.assertIsNotNone(gate.re.fullmatch(disposition_pattern, "E-WWM-23"))
        self.assertIsNone(gate.re.fullmatch(disposition_pattern, "E-WWM-24"))
        self.assertIsNotNone(
            gate.re.fullmatch(
                command_pattern,
                "python tools/gates/run_wwm_claim.py --claim E-WWM-23",
            )
        )
        self.assertIsNone(
            gate.re.fullmatch(
                command_pattern,
                "python tools/gates/run_wwm_claim.py --claim E-WWM-24",
            )
        )

    def test_e23_lab_report_is_partial_local_evidence_only(self) -> None:
        output = self.prepare_e23()
        observed = gate.verify_bundle_directory(output, require_sealed=False)
        self.assertEqual(observed["result"]["verdict"], "PARTIAL")
        self.assertEqual(
            observed["bundle"]["claim_disposition"], "DISABLED_NOT_CLAIMED"
        )
        attestation_path = self.root / "e23-lab-attestation.json"
        attestation_path.write_text(
            json.dumps(self.attestation(observed["bundle"])), encoding="utf-8"
        )
        gate.attach_attestation(output, attestation_path)
        sealed = gate.seal_bundle(output)
        self.assertTrue(sealed["sealed"])
        signed_observed = gate.verify_bundle_directory(output)
        self.assertEqual(signed_observed["result"]["verdict"], "PARTIAL")
        self.assertIsNone(signed_observed["bundle"]["promotion_record"])
        with self.assertRaisesRegex(gate.EvidenceError, "cannot satisfy real-pilot"):
            self.prepare_e23("PASS")
        with self.assertRaisesRegex(gate.EvidenceError, "cannot satisfy real-pilot"):
            self.prepare_e23("PARTIAL", "ELIGIBLE_FOR_SEPARATE_PROMOTION")

if __name__ == "__main__":
    unittest.main()
