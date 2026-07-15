"""Focused release-signature trust-root and payload-binding regressions."""
from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
GENESIS = HERE.parent / "genesis"
for path in (HERE, GENESIS):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import verify_release
from production_authorization import RoleKey


class ReleaseAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private = {}
        self.keyring = {}
        for index, role in enumerate(("release-owner", "independent-build-reviewer"), 1):
            private = Ed25519PrivateKey.from_private_bytes(bytes([index]) * 32)
            raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.private[role] = private
            self.keyring[role] = RoleKey(role, f"fixture-key-{index}", private.public_key(), raw.hex())
        self.manifest = {
            "schema_version": 1, "manifest_kind": "noosphere-release-manifest",
            "source": {"repo_revision": "1" * 40},
            "identity": {"chain_id": "2" * 64, "genesis_hash": "3" * 64},
            "artifact_hashes": {"release/artifacts/a": "4" * 64},
            "signatures": [],
        }

    def sign(self, manifest):
        unsigned = dict(manifest); unsigned["signatures"] = []
        payload = verify_release.json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode()
        message = b"NOOS/RELEASE/MANIFEST/V2\x00" + payload
        return [{
            "role": role, "key_id": self.keyring[role].key_id,
            "signature_ed25519_hex": self.private[role].sign(message).hex(),
        } for role in ("release-owner", "independent-build-reviewer")]

    def test_external_pinned_keys_verify_and_artifact_hash_mutation_fails(self):
        self.manifest["signatures"] = self.sign(self.manifest)
        errors, blocked = [], []
        verify_release.verify_signatures(self.manifest, errors, blocked, self.keyring, schema_version=1, test_mode=True)
        self.assertEqual((errors, blocked), ([], []))
        mutated = copy.deepcopy(self.manifest); mutated["artifact_hashes"]["release/artifacts/a"] = "5" * 64
        errors = []; blocked = []
        verify_release.verify_signatures(mutated, errors, blocked, self.keyring, schema_version=1, test_mode=True)
        self.assertTrue(any("invalid" in error for error in errors))

    def test_embedded_or_dummy_keys_cannot_nominate_trust(self):
        self.manifest["signatures"] = [{
            "role": "release-owner", "key_id": "dummy", "public_key_base64": "AA==",
            "signature_base64": "AA==",
        }]
        errors, blocked = [], []
        verify_release.verify_signatures(self.manifest, errors, blocked, None, schema_version=1, test_mode=True)
        self.assertIn("signed release manifest requires externally supplied pinned role keyring", errors)

    def test_repro_assurance_requires_exact_shipped_builder_bytes_and_paths(self):
        original_root = verify_release.ROOT
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                verify_release.ROOT = root
                artifacts = root / "artifacts"
                artifacts.mkdir()
                artifact = artifacts / "a"
                artifact.write_bytes(b"A")
                digest = verify_release.sha(artifact)
                artifact_map = {"artifacts/a": digest}
                report = {
                    "schema": "noos/repro-assurance-report/v2",
                    "verdict": "QUALIFYING_EXTERNAL_ATTESTATIONS_VERIFIED",
                    "source": {"revision": self.manifest["source"]["repo_revision"], "tree": "4" * 40},
                    "trusted_repro_builders_sha256": "5" * 64,
                    "artifact_hashes_by_target": {"linux-x86_64": artifact_map},
                    "builder_artifact_hashes": [
                        {"key_id": "builder-a", "target": "linux-x86_64", "artifact_hashes": artifact_map},
                        {"key_id": "builder-b", "target": "linux-x86_64", "artifact_hashes": artifact_map},
                    ],
                }
                report_path = root / "assurance.json"
                report_path.write_text(verify_release.json.dumps(report), encoding="utf-8")
                manifest = copy.deepcopy(self.manifest)
                manifest["artifact_hashes"] = artifact_map
                manifest["reproducibility"] = {
                    "target": "linux-x86_64",
                    "trusted_repro_builders_sha256": "5" * 64,
                    "assurance_report_sha256": verify_release.sha(report_path),
                }
                errors: list[str] = []
                verify_release.verify_repro_assurance(manifest, report_path, errors)
                self.assertEqual(errors, [])

                cases = {}
                ships_b = copy.deepcopy(manifest)
                ships_b["artifact_hashes"]["artifacts/a"] = "6" * 64
                cases["substituted-bytes"] = ships_b
                missing = copy.deepcopy(manifest)
                missing["artifact_hashes"] = {}
                cases["missing"] = missing
                renamed = copy.deepcopy(manifest)
                renamed["artifact_hashes"] = {"artifacts/renamed": digest}
                cases["renamed"] = renamed
                for name, mutated in cases.items():
                    with self.subTest(name=name):
                        errors = []
                        verify_release.verify_repro_assurance(mutated, report_path, errors)
                        self.assertTrue(errors)
                extra = artifacts / "extra"
                extra.write_bytes(b"extra")
                errors = []
                verify_release.verify_repro_assurance(manifest, report_path, errors)
                self.assertTrue(any("extra" in error for error in errors))
        finally:
            verify_release.ROOT = original_root



if __name__ == "__main__":
    unittest.main()
