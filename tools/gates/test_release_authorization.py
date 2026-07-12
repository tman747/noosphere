"""Focused release-signature trust-root and payload-binding regressions."""
from __future__ import annotations

import copy
import sys
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
        verify_release.verify_signatures(self.manifest, errors, blocked, self.keyring, test_mode=True)
        self.assertEqual((errors, blocked), ([], []))
        mutated = copy.deepcopy(self.manifest); mutated["artifact_hashes"]["release/artifacts/a"] = "5" * 64
        errors = []; blocked = []
        verify_release.verify_signatures(mutated, errors, blocked, self.keyring, test_mode=True)
        self.assertTrue(any("invalid" in error for error in errors))

    def test_embedded_or_dummy_keys_cannot_nominate_trust(self):
        self.manifest["signatures"] = [{
            "role": "release-owner", "key_id": "dummy", "public_key_base64": "AA==",
            "signature_base64": "AA==",
        }]
        errors, blocked = [], []
        verify_release.verify_signatures(self.manifest, errors, blocked, None, test_mode=True)
        self.assertIn("signed release manifest requires externally supplied pinned role keyring", errors)


if __name__ == "__main__":
    unittest.main()
