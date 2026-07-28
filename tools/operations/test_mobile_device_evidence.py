from __future__ import annotations

import copy
import unittest

from tools.operations import mobile_device_evidence as evidence


class MobileDeviceEvidenceTests(unittest.TestCase):
    def body(self, marker: int, platform: str, security_mode: str) -> dict[str, object]:
        observed = "2026-07-15T00:05:00Z"
        return {
            "observation_id": "",
            "source_revision": "a" * 40,
            "release_artifact_sha256": "b" * 64,
            "release_manifest_sha256": "c" * 64,
            "platform": platform,
            "security_mode": security_mode,
            "physical_device": True,
            "simulator": False,
            "device_fingerprint_sha256": f"{marker:064x}",
            "manufacturer": "Apple" if platform == "IOS" else "Android Vendor",
            "model": f"physical-model-{marker}",
            "os_version": "18.2" if platform == "IOS" else "15",
            "os_build": f"build-{marker}",
            "security_patch": "2026-07-01",
            "hardware_attestation_sha256": f"{marker + 100:064x}",
            "lab_organization_root": ("1" if marker < 3 else "2") * 64,
            "lab_control_cluster_id": ("3" if marker < 3 else "4") * 64,
            "started_at_utc": "2026-07-15T00:00:00Z",
            "completed_at_utc": "2026-07-15T00:10:00Z",
            "scenarios": [
                {
                    "scenario": scenario,
                    "verdict": "PASS",
                    "evidence_sha256": evidence.sha256(f"{marker}:{scenario}".encode()),
                    "evidence_bytes": 128 + marker,
                    "observed_at_utc": observed,
                }
                for scenario in sorted(evidence.SCENARIOS)
            ],
            "production": False,
            "promotion_effect": "NONE",
        }

    def observations(self) -> list[dict[str, object]]:
        return [
            evidence.sign_observation(self.body(1, "ANDROID", "STRONGBOX"), bytes.fromhex("11" * 32)),
            evidence.sign_observation(self.body(2, "ANDROID", "TEE"), bytes.fromhex("22" * 32)),
            evidence.sign_observation(self.body(3, "IOS", "SECURE_ENCLAVE"), bytes.fromhex("22" * 32)),
        ]

    def test_exact_physical_profile_bundle_seals_and_verifies(self) -> None:
        observations = self.observations()
        bundle = evidence.seal_bundle(observations, bytes.fromhex("33" * 32))
        body = evidence.validate_bundle(bundle)
        self.assertEqual(body["verdict"], "PASS")
        self.assertEqual(
            body["profile_classes"],
            {
                "ANDROID_STRONGBOX": True,
                "ANDROID_NON_STRONGBOX": True,
                "IOS_SECURE_ENCLAVE": True,
            },
        )
        self.assertEqual(body["independent_organization_count"], 2)
        self.assertEqual(body["independent_control_cluster_count"], 2)
        self.assertEqual(body["independent_signer_count"], 2)

    def test_simulator_and_incomplete_scenario_evidence_fail_closed(self) -> None:
        simulator = self.body(1, "ANDROID", "STRONGBOX")
        simulator["simulator"] = True
        with self.assertRaisesRegex(evidence.DeviceEvidenceError, "cannot satisfy"):
            evidence.sign_observation(simulator, bytes.fromhex("11" * 32))

        incomplete = self.body(1, "ANDROID", "STRONGBOX")
        incomplete["scenarios"] = incomplete["scenarios"][:-1]
        with self.assertRaisesRegex(evidence.DeviceEvidenceError, "every exact scenario"):
            evidence.sign_observation(incomplete, bytes.fromhex("11" * 32))

    def test_bundle_requires_strongbox_non_strongbox_secure_enclave_and_independence(self) -> None:
        observations = self.observations()
        with self.assertRaisesRegex(evidence.DeviceEvidenceError, "lacks StrongBox"):
            evidence.seal_bundle(observations[:2] + [copy.deepcopy(observations[1])], bytes.fromhex("33" * 32))

        one_lab = []
        for index, observation in enumerate(observations):
            body = copy.deepcopy(observation["body"])
            body["lab_organization_root"] = "1" * 64
            body["lab_control_cluster_id"] = "3" * 64
            body["device_fingerprint_sha256"] = f"{index + 10:064x}"
            one_lab.append(evidence.sign_observation(body, bytes.fromhex("11" * 32)))
        with self.assertRaisesRegex(evidence.DeviceEvidenceError, "independent lab"):
            evidence.seal_bundle(one_lab, bytes.fromhex("33" * 32))

    def test_release_mismatch_and_signature_tampering_are_rejected(self) -> None:
        observations = self.observations()
        changed_body = copy.deepcopy(observations[0]["body"])
        changed_body["source_revision"] = "d" * 40
        observations[0] = evidence.sign_observation(changed_body, bytes.fromhex("11" * 32))
        with self.assertRaisesRegex(evidence.DeviceEvidenceError, "one exact release"):
            evidence.seal_bundle(observations, bytes.fromhex("33" * 32))

        tampered = self.observations()[0]
        tampered["body"]["model"] = "different-model"
        with self.assertRaisesRegex(evidence.DeviceEvidenceError, "signature is invalid"):
            evidence.validate_observation(tampered)


if __name__ == "__main__":
    unittest.main()
