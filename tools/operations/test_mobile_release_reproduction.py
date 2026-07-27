from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import mobile_release_reproduction as reproduction
from tools.operations import mobile_release_supply as supply


class MobileReleaseReproductionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.revision = "a" * 40
        self.builder_keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        self.verifier_key = Ed25519PrivateKey.generate()
        self.builder_seeds: list[Path] = []
        builders = []
        for index, private in enumerate(self.builder_keys):
            seed = self.root / f"builder-{index}.seed"
            seed.write_bytes(private.private_bytes_raw())
            self.builder_seeds.append(seed)
            public, key_id = reproduction.public_identity(private)
            builders.append(
                {
                    "builder_id": f"builder-{index}",
                    "organization": f"Independent Builder {index}",
                    "control_cluster_id": str(index + 1) * 64,
                    "public_key_base64": public,
                    "key_id": key_id,
                }
            )
        self.verifier_seed = self.root / "verifier.seed"
        self.verifier_seed.write_bytes(self.verifier_key.private_bytes_raw())
        _, self.verifier_key_id = reproduction.public_identity(self.verifier_key)
        self.registry = {
            "schema": reproduction.REGISTRY_SCHEMA,
            "source_revision": self.revision,
            "verifier_key_id": self.verifier_key_id,
            "builders": builders,
        }
        self.registry_sha256 = reproduction.sha256_bytes(reproduction.canonical_json(self.registry))
        self.registry_path = self.root / "registry.json"
        self.registry_path.write_bytes(reproduction.canonical_json(self.registry))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def subject_document(self, changed: bool = False) -> tuple[dict[str, object], str]:
        subjects = []
        for index, label in enumerate(sorted(supply.REQUIRED_LABELS)):
            digest_byte = index + (20 if changed and label == "ios" else 1)
            path = {
                "android-linux": "app-release.apk",
                "android-windows": "app-release.apk",
                "ios": "MindChain.app/main",
                "native-macos": "noosd",
                "native-windows": "noosd.exe",
            }[label]
            subjects.append(
                {
                    "label": label,
                    "path": path,
                    "bytes": 100 + index,
                    "sha256": f"{digest_byte:02x}" * 32,
                }
            )
        body: dict[str, object] = {
            "manifest_id": "0" * 64,
            "source_revision": self.revision,
            "release_version": f"0.1.0+git.{self.revision}",
            "subjects": subjects,
            "binding_manifests": {
                "android-linux": {},
                "android-windows": {},
                "ios": {},
            },
            "android_cross_builder_comparison": {
                "schema": "noos/mobile-cross-builder-comparison/v1",
                "builders": ["github-ubuntu-24.04", "github-windows-2025"],
                "independent_builders": False,
                "normalized": False,
                "all_subjects_equal": True,
                "subjects": [],
            },
            "attestation": {
                "mode": "GITHUB_OIDC_DSSE_EXTERNAL",
                "subjects": ["subject-manifest.json", "SHA256SUMS"],
                "embedded_signature": False,
            },
            "production": False,
            "promotion_effect": "NONE",
            "independent_reproduction_claimed": False,
        }
        body["manifest_id"] = supply.manifest_id(body)
        document = {"schema": supply.SCHEMA, "body": body}
        checksums = "".join(
            f"{row['sha256']}  {row['label']}/{row['path']}\n" for row in subjects
        )
        return document, checksums

    def write_subjects(self, builder_id: str, changed: bool = False) -> tuple[Path, Path]:
        document, checksums = self.subject_document(changed)
        manifest = self.root / f"{builder_id}-manifest.json"
        sums = self.root / f"{builder_id}-SHA256SUMS"
        manifest.write_bytes(supply.canonical_json(document) + b"\n")
        sums.write_text(checksums, encoding="ascii", newline="\n")
        return manifest, sums

    def write_environment(self, builder_id: str, index: int, *, clean: bool = True) -> Path:
        environment = {
            "schema": reproduction.ENVIRONMENT_SCHEMA,
            "builder_id": builder_id,
            "source_revision": self.revision,
            "host_os": "linux",
            "host_arch": "x86_64",
            "host_fingerprint_sha256": f"{10 + index:02x}" * 32,
            "source_archive_sha256": "30" * 32,
            "build_commands_sha256": "40" * 32,
            "toolchains": {"rust": "1.96.1", "python": "3.13.5"},
            "clean_checkout": clean,
            "generated_outputs_unmodified": True,
        }
        path = self.root / f"{builder_id}-environment.json"
        path.write_bytes(reproduction.canonical_json(environment))
        return path

    def record(self, index: int, *, changed: bool = False, clean: bool = True) -> tuple[Path, dict[str, object]]:
        builder_id = f"builder-{index}"
        manifest, sums = self.write_subjects(builder_id, changed)
        output = self.root / f"{builder_id}-observation.json"
        envelope = reproduction.record_observation(
            manifest,
            sums,
            self.write_environment(builder_id, index, clean=clean),
            self.registry_path,
            self.registry_sha256,
            builder_id,
            self.builder_seeds[index],
            output,
            observed_at=self.now,
        )
        return output, envelope

    def test_two_independent_raw_builds_verify_bit_identical_without_normalization(self) -> None:
        observations = [self.record(index)[0] for index in (0, 1)]
        output = self.root / "comparison.json"
        comparison = reproduction.compare(
            observations,
            self.registry_path,
            self.registry_sha256,
            self.verifier_key_id,
            self.verifier_seed,
            output,
            compared_at=self.now,
        )
        body = reproduction.verify_comparison(
            comparison,
            self.registry_path,
            self.registry_sha256,
            self.verifier_key_id,
        )
        self.assertEqual(body["verdict"], "PASS_BIT_IDENTICAL")
        self.assertTrue(body["independent_reproduction_verified"])
        self.assertFalse(body["normalization_applied"])
        self.assertEqual(body["differences"], [])
        with self.assertRaisesRegex(reproduction.ReproductionError, "overwrite"):
            reproduction.compare(
                observations,
                self.registry_path,
                self.registry_sha256,
                self.verifier_key_id,
                self.verifier_seed,
                output,
                compared_at=self.now,
            )

    def test_raw_difference_is_recorded_and_never_relabelled_as_reproduction(self) -> None:
        observations = [self.record(0)[0], self.record(1, changed=True)[0]]
        comparison = reproduction.compare(
            observations,
            self.registry_path,
            self.registry_sha256,
            self.verifier_key_id,
            self.verifier_seed,
            self.root / "different.json",
            compared_at=self.now,
        )
        body = comparison["body"]
        self.assertEqual(body["verdict"], "DIFFERENCES_RECORDED")
        self.assertFalse(body["bit_identical"])
        self.assertFalse(body["independent_reproduction_verified"])
        self.assertEqual(len(body["differences"]), 1)
        self.assertEqual(body["differences"][0]["label"], "ios")
        self.assertFalse(body["normalization_applied"])

    def test_registry_control_independence_signatures_and_complete_cohort_fail_closed(self) -> None:
        same_control = copy.deepcopy(self.registry)
        same_control["builders"][1]["control_cluster_id"] = same_control["builders"][0]["control_cluster_id"]
        digest = reproduction.sha256_bytes(reproduction.canonical_json(same_control))
        with self.assertRaisesRegex(reproduction.ReproductionError, "reuse"):
            reproduction.validate_registry(same_control, digest)

        first_path, first = self.record(0)
        tampered = copy.deepcopy(first)
        tampered["body"]["subjects"][0]["sha256"] = "ff" * 32
        with self.assertRaises(reproduction.ReproductionError):
            _, builders = reproduction.validate_registry(self.registry, self.registry_sha256)
            reproduction.verify_observation(tampered, self.registry, builders, now=self.now)

        with self.assertRaisesRegex(reproduction.ReproductionError, "every preregistered builder"):
            reproduction.compare(
                [first_path],
                self.registry_path,
                self.registry_sha256,
                self.verifier_key_id,
                self.verifier_seed,
                self.root / "incomplete.json",
                compared_at=self.now,
            )

    def test_dirty_build_and_wrong_builder_key_reject_before_evidence(self) -> None:
        with self.assertRaisesRegex(reproduction.ReproductionError, "not clean"):
            self.record(0, clean=False)
        manifest, sums = self.write_subjects("builder-0")
        wrong_seed = self.root / "wrong.seed"
        wrong_seed.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
        with self.assertRaisesRegex(reproduction.ReproductionError, "does not match"):
            reproduction.record_observation(
                manifest,
                sums,
                self.write_environment("builder-0", 0),
                self.registry_path,
                self.registry_sha256,
                "builder-0",
                wrong_seed,
                self.root / "wrong-observation.json",
                observed_at=self.now,
            )


if __name__ == "__main__":
    unittest.main()
