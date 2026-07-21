from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.operations import wwm_release_bundle as release


class PublicTestnetReleaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.revision = "11" * 20
        self.release_version = f"0.1.0+git.{self.revision}"
        entries: list[dict[str, object]] = []
        for relative in sorted(release.REQUIRED_BINARY_PATHS):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"fixture:{relative}\n".encode("ascii"))
            entries.append(release.file_entry(path, relative, "fixture-binary"))
        source = self.root / "tools/operations/wwm_public_gateway.py"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("# exact fixture\n", encoding="utf-8")
        entries.append(
            release.file_entry(
                source,
                "tools/operations/wwm_public_gateway.py",
                "runtime-source",
            )
        )

        api_files: dict[str, bytes] = {
            relative: f"fixture:{relative}\n".encode("utf-8")
            for relative in release.API_CONTRACT_FILES
        }
        api_hashes: dict[str, str] = {}
        for relative, content in api_files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            api_hashes[relative] = release.sha256_file(path)
            entries.append(release.file_entry(path, relative, "api-contract"))
        vector_paths = tuple(
            relative
            for relative in release.API_CONTRACT_FILES
            if relative != "protocol/api/openapi-v1.yaml"
        )
        api_root = self.root / "protocol/api/contract-root-v1.json"
        api_root.write_text(
            json.dumps(
                {
                    "contract": "NOOS/API/V1",
                    "files": api_hashes,
                    "vector_root": release.frozen_root(self.root, vector_paths),
                    "contract_root": release.frozen_root(
                        self.root,
                        release.API_CONTRACT_FILES,
                    ),
                }
            )
            + "\n",
            encoding="utf-8",
        )
        entries.append(
            release.file_entry(
                api_root,
                "protocol/api/contract-root-v1.json",
                "api-contract",
            )
        )
        self.api_contract = release.api_contract_identity(self.root)

        self.manifest = {
            "schema": release.SCHEMA,
            "bundle_id": "",
            "boundary": release.BOUNDARY,
            "source": {
                "revision": self.revision,
                "tree": "22" * 20,
                "source_date_epoch": 1_784_000_000,
            },
            "toolchain": {
                "rustc_verbose": "rustc fixture",
                "cargo_version": "cargo fixture",
                "rust_toolchain_sha256": "33" * 32,
                "cargo_lock_sha256": "44" * 32,
            },
            "chain_binding": {
                "chain_id": "55" * 32,
                "genesis_hash": "66" * 32,
            },
            "api_contract": self.api_contract,
            "build": {
                "target": release.TARGET,
                "profile": "release",
                "cargo_locked": True,
                "incremental": False,
                "source_revision_env": self.revision,
                "release_version_env": self.release_version,
            },
            "files": sorted(entries, key=lambda entry: str(entry["path"])),
            "version_probes": {
                relative: (
                    f"{Path(relative).name} {self.release_version} "
                    f"source_revision={self.revision}"
                )
                for relative in sorted(release.REVISION_PROBE_PATHS)
            },
            "rollout": {
                "order": ["observer-read-gateway", "witness-3", "witness-2", "witness-1", "producer-witness-0"],
                "minimum_finality_quorum": 3,
                "rollback_artifact_required": True,
                "durable_state_deletion_permitted": False,
                "stop_conditions": ["chain_or_genesis_mismatch"],
            },
        }
        self.write_manifest()

    def write_manifest(self) -> None:
        self.manifest["bundle_id"] = release.manifest_bundle_id(self.manifest)
        (self.root / release.MANIFEST_NAME).write_bytes(
            release.canonical_json(self.manifest) + b"\n"
        )

    def test_revision_bound_version_comes_from_all_probed_packages(self) -> None:
        self.assertEqual(
            release.revision_bound_release_version(self.revision),
            self.release_version,
        )

    def test_exact_bundle_verifies_and_mutated_bytes_fail(self) -> None:
        verified = release.verify_bundle(self.root)
        self.assertEqual(verified["source"]["revision"], self.revision)
        mutated = self.root / "bin/noosd"
        mutated.write_bytes(mutated.read_bytes() + b"mutation")
        with self.assertRaisesRegex(release.ReleaseBundleError, "file evidence mismatch"):
            release.verify_bundle(self.root)

    def test_api_contract_identity_rejects_mutated_vector(self) -> None:
        vector = self.root / "protocol/api/vectors/positive.json"
        vector.write_bytes(vector.read_bytes() + b"mutation")
        with self.assertRaisesRegex(release.ReleaseBundleError, "contract hash mismatch"):
            release.api_contract_identity(self.root)

    def test_unmanifested_file_and_unbound_probe_fail_closed(self) -> None:
        extra = self.root / "unmanifested.txt"
        extra.write_text("not allowed", encoding="utf-8")
        with self.assertRaisesRegex(release.ReleaseBundleError, "unmanifested"):
            release.verify_bundle(self.root)
        extra.unlink()

        self.manifest["version_probes"]["bin/noosd"] = "noosd 0.1.0 source_revision=UNBOUND"
        self.write_manifest()
        with self.assertRaisesRegex(release.ReleaseBundleError, "not exact"):
            release.verify_bundle(self.root)

    def test_manifest_cannot_escape_bundle_root(self) -> None:
        self.manifest["files"][0]["path"] = "../outside"
        self.write_manifest()
        with self.assertRaisesRegex(release.ReleaseBundleError, "escapes its root"):
            release.verify_bundle(self.root)


if __name__ == "__main__":
    unittest.main()
