#!/usr/bin/env python3
"""Mutation tests for reproducible-build attestation assurance.

All generated keys are explicitly test-only. A successful fixture can produce
only SMOKE_ONLY_TEST_KEYS, never a production or external-gate verdict.
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repro_build


SOURCE = repro_build.source_identity()
REVISION = SOURCE["revision"]
SOURCE_TREE = SOURCE["tree"]


class AttestationFixture:
    def __init__(self, root: Path):
        self.root = root
        self.attestations = root / "attestations"
        self.attestations.mkdir()
        self.builders: list[tuple[Ed25519PrivateKey, dict]] = []
        for index in ("a", "b"):
            private = Ed25519PrivateKey.generate()
            public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            key_id = repro_build.sha256_bytes(public)
            trust = {
                "key_id": key_id,
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "operator": f"test-only-operator-{index}",
                "control_plane_identity": f"test-only-control-plane-{index}",
                "host_identity": f"test-only-host-fleet-{index}",
                "toolchain_installation": f"test-only-toolchain-installation-{index}",
                "authorized_targets": sorted(repro_build.REQUIRED_TARGETS),
                "external_to_release_owner": True,
                "test_only": True,
            }
            self.builders.append((private, trust))
        self.trust_path = root / "trust.json"
        self.trust_path.write_bytes(repro_build.canonical_json({
            "schema": "noos/trusted-repro-builders/v1", "builders": [builder[1] for builder in self.builders]
        }))
        self.payloads: dict[tuple[int, str], dict] = {}
        locks = repro_build.load_toolchains()
        tools = repro_build.locked_toolchain_identities(locks)
        for builder_index, (_, trust) in enumerate(self.builders):
            for target in sorted(repro_build.REQUIRED_TARGETS):
                payload = {
                    "schema": "noos/repro-build-attestation/v1",
                    "builder": {field: trust[field] for field in ("operator", "control_plane_identity", "host_identity", "toolchain_installation")},
                    "build": {
                        "source_revision": REVISION,
                        "source_tree": SOURCE_TREE,
                        "target": target,
                        "host_architecture": "aarch64" if target == "linux-aarch64" else "x86_64",
                        "toolchain_lock_sha256": repro_build.sha256_file(repro_build.TOOLCHAINS),
                        "toolchains": tools,
                        "source_date_epoch": SOURCE["source_date_epoch"],
                    },
                    "artifact_hashes": {
                        name: repro_build.sha256_bytes(f"{target}:{name}".encode("ascii"))
                        for name in repro_build._required_binary_names(target)
                    },
                }
                self.payloads[(builder_index, target)] = payload
        self.write_all()

    def write_all(self) -> None:
        for old in self.attestations.iterdir():
            old.unlink()
        for (builder_index, target), payload in self.payloads.items():
            private, trust = self.builders[builder_index]
            stem = f"builder-{builder_index}-{target}"
            raw = repro_build.canonical_json(payload)
            (self.attestations / f"{stem}.attestation.json").write_bytes(raw)
            signature = {
                "schema": "noos/detached-ed25519-signature/v1",
                "algorithm": "ed25519",
                "key_id": trust["key_id"],
                "payload_sha256": repro_build.sha256_bytes(raw),
                "signature_base64": base64.b64encode(private.sign(raw)).decode("ascii"),
            }
            (self.attestations / f"{stem}.signature.json").write_bytes(repro_build.canonical_json(signature))

    def verify(self, *, allow_test_keys: bool = True) -> dict:
        return repro_build.verify_attestation_set(
            self.attestations, self.trust_path, REVISION, allow_test_keys=allow_test_keys
        )


class ReproBuildMutationTests(unittest.TestCase):
    def test_external_input_template_is_blocked_not_malformed(self):
        with tempfile.TemporaryDirectory() as directory:
            report = repro_build.verify_attestation_set(
                Path(directory),
                repro_build.ROOT / "protocol/release/trusted-repro-builders-template.json",
                REVISION,
            )
            self.assertEqual(report["verdict"], "EXTERNAL_BLOCKED")
            self.assertTrue(any("external public key is required" in error for error in report["errors"]))

    def test_complete_fixture_is_permanently_smoke_only(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AttestationFixture(Path(directory))
            report = fixture.verify()
            self.assertEqual(report["verdict"], "SMOKE_ONLY_TEST_KEYS")
            self.assertIn("test keys are not production signatures", report["errors"][0])

    def test_test_keys_are_rejected_by_production_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AttestationFixture(Path(directory))
            report = fixture.verify(allow_test_keys=False)
            self.assertEqual(report["verdict"], "EXTERNAL_BLOCKED")
            self.assertTrue(any("untrusted or production-ineligible key" in error for error in report["errors"]))

    def test_altered_binary_toolchain_source_revision_target_and_signature_fail(self):
        mutations = {
            "binary": lambda fixture: fixture.payloads[(1, "linux-x86_64")]["artifact_hashes"].update({"artifacts/noos-transition-rust": "f" * 64}),
            "toolchain": lambda fixture: fixture.payloads[(1, "linux-x86_64")]["build"]["toolchains"].update({"go": "go0.0.0"}),
            "source": lambda fixture: fixture.payloads[(1, "linux-x86_64")]["build"].update({"source_tree": "3" * 40}),
            "revision": lambda fixture: fixture.payloads[(1, "linux-x86_64")]["build"].update({"source_revision": "4" * 40}),
            "target": lambda fixture: fixture.payloads[(1, "linux-aarch64")]["build"].update({"target": "windows-x86_64", "host_architecture": "x86_64"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                fixture = AttestationFixture(Path(directory))
                mutate(fixture)
                fixture.write_all()
                report = fixture.verify()
                self.assertEqual(report["verdict"], "EXTERNAL_BLOCKED", report)

        with self.subTest(name="signature"), tempfile.TemporaryDirectory() as directory:
            fixture = AttestationFixture(Path(directory))
            path = next(fixture.attestations.glob("*.signature.json"))
            signature = json.loads(path.read_text("utf-8"))
            raw = bytearray(base64.b64decode(signature["signature_base64"]))
            raw[0] ^= 1
            signature["signature_base64"] = base64.b64encode(raw).decode("ascii")
            path.write_bytes(repro_build.canonical_json(signature))
            self.assertEqual(fixture.verify()["verdict"], "EXTERNAL_BLOCKED")

    def test_one_ci_control_plane_cannot_form_quorum(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = AttestationFixture(Path(directory))
            shared = "github-actions:one-repository-identity"
            for _, trust in fixture.builders:
                trust["control_plane_identity"] = shared
            for payload in fixture.payloads.values():
                payload["builder"]["control_plane_identity"] = shared
            fixture.trust_path.write_bytes(repro_build.canonical_json({
                "schema": "noos/trusted-repro-builders/v1", "builders": [builder[1] for builder in fixture.builders]
            }))
            fixture.write_all()
            report = fixture.verify()
            self.assertEqual(report["verdict"], "EXTERNAL_BLOCKED")
            self.assertIn("complete builders do not have two distinct control_plane_identity values", report["errors"])


if __name__ == "__main__":
    unittest.main()
